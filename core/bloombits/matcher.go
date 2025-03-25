// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package bloombits

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// 在以太坊中，布隆过滤器常用于日志（Logs）或事件（Events）的索引和查询。
// 以太坊的区块头（Block Header）包含一个 logsBloom 字段，这是一个 2048 位（256 字节）的布隆过滤器，用于快速判断某个交易的日志是否可能包含特定的事件或地址。
// 每个日志条目（Log Entry）会将其地址和主题（Topics）通过哈希函数（如 Keccak-256）映射到布隆过滤器的若干位上，通常是 3 个位（与 [3]uint 对应）。
// 根据以太坊的实现（参考 EIP-234 等），每个键通过哈希后取低位的一部分（如 11 位，范围 0-2047）生成 3 个独立的位索引。
// 这种设计平衡了误报率和存储效率。

// EIP-234：定义了以太坊日志布隆过滤器的标准，每个键生成 3 个位索引。
// 布隆过滤器原理：一种概率数据结构，通过多个哈希函数将元素映射到位数组中，用于快速查询是否存在（可能有误报，但无漏报）。

// bloomIndexes represents the bit indexes inside the bloom filter that belong
// to some key.
// bloomIndexes 表示布隆过滤器中属于某个键的位索引。
type bloomIndexes [3]uint

// 在以太坊中，布隆过滤器用于高效查询日志或事件的存在性。这个函数将输入键映射到 2048 位布隆过滤器的 3 个具体位。
// 以太坊的 logsBloom 字段是 2048 位（256 字节）的布隆过滤器。

// calcBloomIndexes returns the bloom filter bit indexes belonging to the given key.
// calcBloomIndexes 返回属于给定键的布隆过滤器位索引。
func calcBloomIndexes(b []byte) bloomIndexes {
	b = crypto.Keccak256(b) // 使用 Keccak256 哈希函数对输入字节进行哈希处理

	var idxs bloomIndexes
	for i := 0; i < len(idxs); i++ { // 遍历 idxs 的长度（即 3），计算每个索引
		// (uint(b[2*i])<<8)&2047 + uint(b[2*i+1]) 表示从哈希结果的第 0-1、2-3、4-5 字节对中提取 11 位数据。
		// 索引计算 (uint(b[2*i])<<8)&2047 + uint(b[2*i+1])：
		// b[2*i] 和 b[2*i+1] 是哈希结果中的一对字节（例如 i=0 时取第 0 和第 1 字节）。
		// uint(b[2*i])<<8：将第一个字节左移 8 位，变成高 8 位。
		// &2047：与 2047（二进制 11111111111）进行位与操作，保留低 11 位。
		// + uint(b[2*i+1])：加上第二个字节（低 8 位，字节为uint8），形成一个 11 位整数（0-2047）。
		idxs[i] = (uint(b[2*i])<<8)&2047 + uint(b[2*i+1]) // 从哈希结果中提取位索引，限制在 0-2047 范围内。每个键通过 Keccak-256 哈希后，取其低 11 位（0-2047）生成 3 个索引。
	}
	return idxs // 表示布隆过滤器中的 3 个位索引。
}

// partialMatches with a non-nil vector represents a section in which some sub-
// matchers have already found potential matches. Subsequent sub-matchers will
// binary AND their matches with this vector. If vector is nil, it represents a
// section to be processed by the first sub-matcher.
//
// partialMatches 如果 vector 不为 nil，则表示某些子匹配器已经找到潜在匹配的区段。
// 后续的子匹配器将对它们的匹配结果与此 vector 进行二进制与操作。如果 vector 为 nil，
// 则表示该区段将由第一个子匹配器处理。
//
// 用于表示布隆过滤器匹配过程中的部分匹配状态。
// 该结构体用于在多阶段匹配过程中跟踪部分匹配结果，尤其是在处理布隆过滤器时。它支持多个子匹配器（sub-matchers）逐步过滤数据。
// 如果 bitset 为 nil，表示这是初始区段，由第一个子匹配器处理。
// 如果 bitset 不为 nil，表示已有部分匹配结果，后续子匹配器会将其匹配结果与此 bitset 进行二进制与（AND）操作，进一步缩小匹配范围。
type partialMatches struct {
	section uint64 // 表示区段的编号
	bitset  []byte // 存储位集合的字节数组，用于匹配操作。存储位集合（bitset），用于表示匹配状态。
}

// Retrieval represents a request for retrieval task assignments for a given
// bit with the given number of fetch elements, or a response for such a request.
// It can also have the actual results set to be used as a delivery data struct.
//
// The context and error fields are used by the light client to terminate matching
// early if an error is encountered on some path of the pipeline.
//
// Retrieval 表示对给定位（bit）和给定获取元素数量的检索任务分配请求，
// 或者是对这类请求的响应。它还可以包含实际结果集，用作交付数据结构。
//
// context 和 error 字段由轻客户端使用，以便在管道的某些路径上遇到错误时提前终止匹配。
//
// 用于表示以太坊轻客户端中与布隆过滤器相关的检索任务请求或响应。
// 作为请求：指定要检索的位（Bit）、区段（Sections）和可能的匹配条件（Bitsets）。
// 作为响应：携带实际的检索结果（Bitsets）。
//
// 以太坊轻客户端不存储完整区块链数据，而是依赖全节点提供数据。
// 以太坊的轻客户端通过 LES（Light Ethereum Subprotocol）与全节点通信，请求区块头、交易或日志数据。
type Retrieval struct {
	Bit      uint     // 表示要检索的位索引
	Sections []uint64 // 存储多个区段的编号
	Bitsets  [][]byte // 存储多个位集合的字节数组，用于匹配或交付结果

	Context context.Context // 用于控制任务的上下文，可能用于取消操作
	Error   error           // 存储检索过程中遇到的错误
}

// Matcher is a pipelined system of schedulers and logic matchers which perform
// binary AND/OR operations on the bit-streams, creating a stream of potential
// blocks to inspect for data content.
// Matcher 是一个由调度器和逻辑匹配器组成的管道系统，对位流执行二进制与/或操作，
// 创建一个潜在的区块流，以便检查数据内容。
//
// 对位流（布隆过滤器数据）执行二进制与（AND）或或（OR）操作，筛选出可能包含目标数据的区块。
type Matcher struct {
	sectionSize uint64 // Size of the data batches to filter on 要过滤的数据批次的大小 表示每个数据批次的大小（例如多少个区块作为一个单位），用于分段处理。

	filters    [][]bloomIndexes    // Filter the system is matching for 系统正在匹配的过滤器  存储多个 bloomIndexes（每个是 [3]uint），表示查询的布隆过滤器索引。
	schedulers map[uint]*scheduler // Retrieval schedulers for loading bloom bits 用于加载布隆位的检索调度器 从位索引（uint）到调度器（*scheduler）的指针。每个调度器负责加载特定位的布隆数据。

	retrievers chan chan uint       // Retriever processes waiting for bit allocations 等待位分配的检索进程
	counters   chan chan uint       // Retriever processes waiting for task count reports 等待任务计数报告的检索进程
	retrievals chan chan *Retrieval // Retriever processes waiting for task allocations 等待任务分配的检索进程
	deliveries chan *Retrieval      // Retriever processes waiting for task response deliveries 等待任务响应交付的检索进程

	running atomic.Bool // Atomic flag whether a session is live or not 表示会话是否活跃的原子标志
}

// NewMatcher creates a new pipeline for retrieving bloom bit streams and doing
// address and topic filtering on them. Setting a filter component to `nil` is
// allowed and will result in that filter rule being skipped (OR 0x11...1).
//
// NewMatcher 创建一个新的管道，用于检索布隆位流并对其进行地址和主题过滤。
// 将过滤器组件设置为 `nil` 是允许的，这将导致跳过该过滤规则（相当于 OR 0x11...1）。
//
// 布隆过滤器与过滤规则：
//
//	filters 表示查询条件，可能包含多个组（例如 [ [地址], [主题1, 主题2] ]），每个组内的条件通过 AND 操作组合，不同组间通过 OR 操作组合。
//	nil 规则表示跳过该条件，相当于“全匹配”（布隆过滤器中所有位为 1）。
func NewMatcher(sectionSize uint64, filters [][][]byte) *Matcher {
	// Create the matcher instance
	// 创建 Matcher 实例
	m := &Matcher{
		sectionSize: sectionSize, // 设置数据批次大小
		schedulers:  make(map[uint]*scheduler),
		retrievers:  make(chan chan uint),
		counters:    make(chan chan uint),
		retrievals:  make(chan chan *Retrieval),
		deliveries:  make(chan *Retrieval),
	}
	// Calculate the bloom bit indexes for the groups we're interested in
	// 计算我们感兴趣的组的布隆位索引
	m.filters = nil

	for _, filter := range filters {
		// Gather the bit indexes of the filter rule, special casing the nil filter
		// 收集过滤规则的位索引，特殊处理 nil 过滤器
		if len(filter) == 0 {
			continue
		}
		bloomBits := make([]bloomIndexes, len(filter))
		for i, clause := range filter {
			if clause == nil {
				bloomBits = nil
				break
			}
			bloomBits[i] = calcBloomIndexes(clause) // 计算该子句的布隆索引
		}
		// Accumulate the filter rules if no nil rule was within
		// 如果没有 nil 规则，则累积过滤规则
		if bloomBits != nil {
			m.filters = append(m.filters, bloomBits)
		}
	}
	// For every bit, create a scheduler to load/download the bit vectors
	// 为每个位创建调度器以加载/下载位向量
	for _, bloomIndexLists := range m.filters {
		for _, bloomIndexList := range bloomIndexLists {
			for _, bloomIndex := range bloomIndexList {
				m.addScheduler(bloomIndex) // 为每个布隆索引添加调度器
			}
		}
	}
	return m
}

// addScheduler adds a bit stream retrieval scheduler for the given bit index if
// it has not existed before. If the bit is already selected for filtering, the
// existing scheduler can be used.
//
// addScheduler 为给定的位索引添加一个位流检索调度器，如果之前不存在该调度器。
// 如果该位已经被选中用于过滤，则可以使用现有的调度器。
func (m *Matcher) addScheduler(idx uint) {
	if _, ok := m.schedulers[idx]; ok { // 检查该位索引是否已有调度器
		return
	}
	m.schedulers[idx] = newScheduler(idx) // 为该位索引创建并添加新的调度器
}

// Start starts the matching process and returns a stream of bloom matches in
// a given range of blocks. If there are no more matches in the range, the result
// channel is closed.
//
// Start 启动匹配过程，并返回给定区块范围内布隆匹配的流。
// 如果范围内没有更多匹配，结果通道将被关闭。
func (m *Matcher) Start(ctx context.Context, begin, end uint64, results chan uint64) (*MatcherSession, error) {
	// Make sure we're not creating concurrent sessions
	// 确保不会创建并发会话
	if m.running.Swap(true) { // 如果 matcher 已在运行，返回错误
		return nil, errors.New("matcher already running")
	}
	defer m.running.Store(false) // 在函数结束时重置 running 标志

	// Initiate a new matching round
	// 初始化一个新的匹配轮次
	session := &MatcherSession{
		matcher: m,
		quit:    make(chan struct{}), // 用于退出信号的通道
		ctx:     ctx,                 // 保存上下文
	}
	for _, scheduler := range m.schedulers {
		scheduler.reset() // 重置所有调度器
	}
	sink := m.run(begin, end, cap(results), session) // 运行匹配逻辑，返回结果通道

	// Read the output from the result sink and deliver to the user
	// 从结果接收器读取输出并交付给用户
	session.pend.Add(1)
	go func() {
		defer session.pend.Done()
		defer close(results) // 在 goroutine 结束时关闭结果通道

		for {
			select {
			case <-session.quit: // 如果收到退出信号，返回
				return

			case res, ok := <-sink: // 从 sink 接收匹配结果
				// New match result found
				// 找到新的匹配结果
				if !ok { // 如果 sink 关闭，返回
					return
				}
				// Calculate the first and last blocks of the section
				// 计算区段的第一个和最后一个区块
				sectionStart := res.section * m.sectionSize // 计算区段起始区块。

				first := sectionStart // 调整区段范围，确保在 begin 和 end 内。
				if begin > first {
					first = begin
				}
				last := sectionStart + m.sectionSize - 1 // 调整区段范围，确保在 begin 和 end 内。
				if end < last {
					last = end
				}
				// Iterate over all the blocks in the section and return the matching ones
				// 遍历区段中的所有区块，返回匹配的区块
				for i := first; i <= last; i++ {
					// Skip the entire byte if no matches are found inside (and we're processing an entire byte!)
					// 如果整个字节没有匹配（且正在处理整个字节），跳过
					next := res.bitset[(i-sectionStart)/8] // 从 bitset 获取字节，每个字节表示 8 个区块。
					if next == 0 {                         // 跳过无匹配的字节。
						if i%8 == 0 {
							i += 7
						}
						continue
					}
					// Some bit it set, do the actual submatching
					// 如果某个位被置位，执行实际的子匹配
					// next & (1<<bit) 检查具体位的值，若置位则发送区块号。
					if bit := 7 - i%8; next&(1<<bit) != 0 {
						select {
						case <-session.quit:
							return
						case results <- i: // 将匹配的区块号发送到结果通道
						}
					}
				}
			}
		}
	}()
	return session, nil
}

// run creates a daisy-chain of sub-matchers, one for the address set and one
// for each topic set, each sub-matcher receiving a section only if the previous
// ones have all found a potential match in one of the blocks of the section,
// then binary AND-ing its own matches and forwarding the result to the next one.
//
// The method starts feeding the section indexes into the first sub-matcher on a
// new goroutine and returns a sink channel receiving the results.
//
// run 创建一个子匹配器的菊花链，一个用于地址集，一个用于每个主题集，每个子匹配器仅在之前的子匹配器在区段的某个区块中找到潜在匹配时接收该区段，
// 然后对其自身的匹配结果执行二进制与操作，并将结果转发给下一个子匹配器。
//
// 该方法在一个新的 goroutine 上开始将区段索引馈送到第一个子匹配器，并返回一个接收结果的接收通道。
//
// 构建一个管道，依次应用多个子匹配器（subMatch），每个子匹配器处理一组过滤条件。
// 只有当所有前置条件匹配时，才将结果传递给下一个子匹配器。
//
// 菊花链设计：
//
//	每个 subMatch 处理一组布隆索引（例如地址或主题），通过 AND 操作逐步缩小匹配范围。
//	这反映了以太坊日志过滤的逻辑：多个条件依次应用。
//
// run 是轻客户端匹配管道的入口，协调布隆数据的检索和过滤。
func (m *Matcher) run(begin, end uint64, buffer int, session *MatcherSession) chan *partialMatches {
	// Create the source channel and feed section indexes into
	// 创建源通道并将区段索引馈送到其中
	source := make(chan *partialMatches, buffer)

	session.pend.Add(1)
	go func() {
		defer session.pend.Done() // 在 goroutine 结束时减少等待计数
		defer close(source)       // 关闭源通道

		for i := begin / m.sectionSize; i <= end/m.sectionSize; i++ { // 遍历区段范围
			select {
			case <-session.quit: // 如果收到退出信号，返回
				return
			case source <- &partialMatches{i, bytes.Repeat([]byte{0xff}, int(m.sectionSize/8))}: // 发送区段和全 1 位集合
			}
		}
	}()
	// Assemble the daisy-chained filtering pipeline
	// 组装菊花链过滤管道
	next := source
	dist := make(chan *request, buffer)

	for _, bloom := range m.filters { // 为每个过滤器创建子匹配器
		next = m.subMatch(next, dist, bloom, session) // 将前一个输出作为下一个输入
	}
	// Start the request distribution
	// 启动请求分发
	session.pend.Add(1)
	go m.distributor(dist, session) // 运行分发器

	return next // 返回最终结果通道
}

// subMatch creates a sub-matcher that filters for a set of addresses or topics, binary OR-s those matches, then
// binary AND-s the result to the daisy-chain input (source) and forwards it to the daisy-chain output.
// The matches of each address/topic are calculated by fetching the given sections of the three bloom bit indexes belonging to
// that address/topic, and binary AND-ing those vectors together.
//
// subMatch 创建一个子匹配器，针对一组地址或主题进行过滤，对这些匹配结果执行二进制或操作，
// 然后将结果与菊花链输入（source）进行二进制与操作，并转发到菊花链输出。
// 每个地址/主题的匹配通过获取属于该地址/主题的三个布隆位索引的给定区段，并对这些向量执行二进制与操作来计算。
//
// 对一组地址或主题的布隆索引执行匹配，计算 AND（每个条件内部）和 OR（条件间）的结果。
// 将结果与源输入结合，生成最终匹配。
//
// 布隆过滤器逻辑：
//
//	每个地址/主题映射到 3 个布隆位（bloomIndexes），匹配时需要对这 3 个位向量执行 AND 操作。
//	多个条件间使用 OR 操作，符合以太坊事件查询的逻辑（例如“地址 A AND 主题 T1 OR 主题 T2”）。
func (m *Matcher) subMatch(source chan *partialMatches, dist chan *request, bloom []bloomIndexes, session *MatcherSession) chan *partialMatches {
	// Start the concurrent schedulers for each bit required by the bloom filter
	// 为布隆过滤器所需的每个位启动并发调度器
	sectionSources := make([][3]chan uint64, len(bloom))
	sectionSinks := make([][3]chan []byte, len(bloom))
	for i, bits := range bloom {
		for j, bit := range bits {
			sectionSources[i][j] = make(chan uint64, cap(source)) // 创建区段源通道
			sectionSinks[i][j] = make(chan []byte, cap(source))   // 创建区段接收通道

			m.schedulers[bit].run(sectionSources[i][j], dist, sectionSinks[i][j], session.quit, &session.pend) // 启动调度器运行
		}
	}

	process := make(chan *partialMatches, cap(source)) // entries from source are forwarded here after fetches have been initiated // 从 source 转发到此通道以发起获取
	results := make(chan *partialMatches, cap(source)) // 最终结果通道

	session.pend.Add(2)
	go func() {
		// Tear down the goroutine and terminate all source channels
		// 清理 goroutine 并终止所有源通道
		defer session.pend.Done()
		defer close(process)

		defer func() {
			for _, bloomSources := range sectionSources {
				for _, bitSource := range bloomSources {
					close(bitSource) // 关闭所有位源通道
				}
			}
		}()
		// Read sections from the source channel and multiplex into all bit-schedulers
		// 从 source 通道读取区段并多路复用到所有位调度器
		for {
			select {
			case <-session.quit:
				return

			case subres, ok := <-source:
				// New subresult from previous link
				// 从之前的链接接收新的子结果
				if !ok {
					return
				}
				// Multiplex the section index to all bit-schedulers
				// 将区段索引多路复用到所有位调度器
				for _, bloomSources := range sectionSources {
					for _, bitSource := range bloomSources {
						select {
						case <-session.quit:
							return
						case bitSource <- subres.section: // 发送区段号
						}
					}
				}
				// Notify the processor that this section will become available
				// 通知处理器此区段将可用
				select {
				case <-session.quit:
					return
				case process <- subres: // 转发到处理通道
				}
			}
		}
	}()

	go func() {
		// Tear down the goroutine and terminate the final sink channel
		// 清理 goroutine 并终止最终接收通道
		defer session.pend.Done()
		defer close(results)

		// Read the source notifications and collect the delivered results
		// 读取源通知并收集交付的结果
		for {
			select {
			case <-session.quit:
				return

			case subres, ok := <-process:
				// Notified of a section being retrieved
				// 收到区段检索的通知
				if !ok {
					return
				}
				// Gather all the sub-results and merge them together
				// 收集所有子结果并合并
				var orVector []byte
				for _, bloomSinks := range sectionSinks {
					var andVector []byte
					for _, bitSink := range bloomSinks {
						var data []byte
						select {
						case <-session.quit:
							return
						case data = <-bitSink: // 从位接收通道获取数据
						}
						if andVector == nil {
							andVector = make([]byte, int(m.sectionSize/8))
							copy(andVector, data)
						} else {
							bitutil.ANDBytes(andVector, andVector, data) // 对位向量执行与操作
						}
					}
					if orVector == nil {
						orVector = andVector
					} else {
						bitutil.ORBytes(orVector, orVector, andVector) // 对结果执行或操作
					}
				}

				if orVector == nil {
					orVector = make([]byte, int(m.sectionSize/8)) // 如果无结果，初始化为空向量
				}
				if subres.bitset != nil {
					bitutil.ANDBytes(orVector, orVector, subres.bitset) // 与源位集合执行与操作
				}
				if bitutil.TestBytes(orVector) { // 检查是否有匹配位
					select {
					case <-session.quit:
						return
					case results <- &partialMatches{subres.section, orVector}: // 发送匹配结果
					}
				}
			}
		}
	}()
	return results
}

// distributor receives requests from the schedulers and queues them into a set
// of pending requests, which are assigned to retrievers wanting to fulfil them.
//
// distributor 从调度器接收请求，并将它们排入一组待处理请求队列中，这些请求将被分配给希望完成它们的检索者。
func (m *Matcher) distributor(dist chan *request, session *MatcherSession) {
	defer session.pend.Done() // 在函数结束时减少等待计数

	var (
		requests   = make(map[uint][]uint64) // Per-bit list of section requests, ordered by section number // 按位存储的区段请求列表，按区段号排序
		unallocs   = make(map[uint]struct{}) // Bits with pending requests but not allocated to any retriever  // 有待处理请求但未分配给检索者的位
		retrievers chan chan uint            // Waiting retrievers (toggled to nil if unallocs is empty) // 等待的检索者（如果 unallocs 为空则置为 nil）
		allocs     int                       // Number of active allocations to handle graceful shutdown requests // 当前活跃分配的数量，用于优雅关闭
		shutdown   = session.quit            // Shutdown request channel, will gracefully wait for pending requests // 关闭请求通道，会优雅地等待待处理请求完成
	)

	// assign is a helper method to try to assign a pending bit an actively
	// listening servicer, or schedule it up for later when one arrives.
	//
	// assign 是尝试将待处理位分配给活跃监听的服务者，或在服务者到达时安排后续分配的辅助方法
	assign := func(bit uint) {
		select {
		case fetcher := <-m.retrievers: // 从检索者通道获取一个服务者
			allocs++
			fetcher <- bit // 分配位给服务者
		default:
			// No retrievers active, start listening for new ones
			// 没有活跃的检索者，开始监听新到达的检索者
			retrievers = m.retrievers
			unallocs[bit] = struct{}{} // 将位标记为未分配
		}
	}

	for {
		select {
		case <-shutdown:
			// Shutdown requested. No more retrievers can be allocated,
			// but we still need to wait until all pending requests have returned.
			// 收到关闭信号
			// 不再分配新检索者，但等待现有请求完成
			shutdown = nil
			if allocs == 0 {
				return
			}

		case req := <-dist:
			// New retrieval request arrived to be distributed to some fetcher process
			// 新检索请求到达，分配给某个获取进程
			queue := requests[req.bit]
			index := sort.Search(len(queue), func(i int) bool { return queue[i] >= req.section })
			requests[req.bit] = append(queue[:index], append([]uint64{req.section}, queue[index:]...)...)

			// If it's a new bit and we have waiting fetchers, allocate to them
			// 如果是新位且有等待的检索者，分配给它们
			if len(queue) == 0 {
				assign(req.bit)
			}

		case fetcher := <-retrievers:
			// New retriever arrived, find the lowest section-ed bit to assign
			// 新检索者到达，分配最低区段的位
			bit, best := uint(0), uint64(math.MaxUint64)
			for idx := range unallocs {
				if requests[idx][0] < best {
					bit, best = idx, requests[idx][0]
				}
			}
			// Stop tracking this bit (and alloc notifications if no more work is available)
			// 移除已分配的位
			delete(unallocs, bit)
			if len(unallocs) == 0 {
				retrievers = nil // 如果没有未分配的位，停止监听
			}
			allocs++
			fetcher <- bit // 分配位给检索者

		case fetcher := <-m.counters:
			// New task count request arrives, return number of items
			// 新任务计数请求，返回请求项数量
			fetcher <- uint(len(requests[<-fetcher]))

		case fetcher := <-m.retrievals:
			// New fetcher waiting for tasks to retrieve, assign
			// 新检索者等待任务分配
			task := <-fetcher
			if want := len(task.Sections); want >= len(requests[task.Bit]) {
				task.Sections = requests[task.Bit]
				delete(requests, task.Bit) // 如果请求全部分配，移除位
			} else {
				task.Sections = append(task.Sections[:0], requests[task.Bit][:want]...)
				requests[task.Bit] = append(requests[task.Bit][:0], requests[task.Bit][want:]...)
			}
			fetcher <- task // 返回分配的任务

			// If anything was left unallocated, try to assign to someone else
			// 如果仍有未分配的请求，尝试分配给其他检索者
			if len(requests[task.Bit]) > 0 {
				assign(task.Bit)
			}

		case result := <-m.deliveries:
			// New retrieval task response from fetcher, split out missing sections and
			// deliver complete ones
			// 新检索任务响应到达，处理结果
			var (
				sections = make([]uint64, 0, len(result.Sections))
				bitsets  = make([][]byte, 0, len(result.Bitsets))
				missing  = make([]uint64, 0, len(result.Sections))
			)
			for i, bitset := range result.Bitsets {
				if len(bitset) == 0 {
					missing = append(missing, result.Sections[i]) // 记录缺失的区段
					continue
				}
				sections = append(sections, result.Sections[i])
				bitsets = append(bitsets, bitset) // 收集完整结果
			}
			m.schedulers[result.Bit].deliver(sections, bitsets) // 交付结果给调度器
			allocs--

			// Reschedule missing sections and allocate bit if newly available
			// 重新调度缺失的区段并分配位
			if len(missing) > 0 {
				queue := requests[result.Bit]
				for _, section := range missing {
					index := sort.Search(len(queue), func(i int) bool { return queue[i] >= section })
					queue = append(queue[:index], append([]uint64{section}, queue[index:]...)...)
				}
				requests[result.Bit] = queue

				if len(queue) == len(missing) {
					assign(result.Bit)
				}
			}

			// End the session when all pending deliveries have arrived.
			// 当所有待处理交付完成后结束会话
			if shutdown == nil && allocs == 0 {
				return
			}
		}
	}
}

// MatcherSession is returned by a started matcher to be used as a terminator
// for the actively running matching operation.
//
// MatcherSession 是由已启动的匹配器返回的，用于作为活动匹配操作的终止器。
//
// 用于管理正在运行的匹配操作的生命周期和状态。
type MatcherSession struct {
	matcher *Matcher // 指向关联的 Matcher 实例

	closer sync.Once     // Sync object to ensure we only ever close once // 同步对象，确保只关闭一次
	quit   chan struct{} // Quit channel to request pipeline termination // 请求管道终止的退出通道

	ctx     context.Context // Context used by the light client to abort filtering 轻客户端用于中止过滤的上下文
	err     error           // Global error to track retrieval failures deep in the chain 全局错误，用于跟踪链深处的检索失败
	errLock sync.Mutex

	pend sync.WaitGroup
}

// Close stops the matching process and waits for all subprocesses to terminate
// before returning. The timeout may be used for graceful shutdown, allowing the
// currently running retrievals to complete before this time.
//
// Close 停止匹配过程，并等待所有子进程终止后返回。超时可用于优雅关闭，允许当前正在运行的检索在此时间之前完成。
func (s *MatcherSession) Close() {
	s.closer.Do(func() {
		// Signal termination and wait for all goroutines to tear down
		// 发送终止信号并等待所有 goroutine 结束
		close(s.quit) // 关闭退出通道以通知所有监听的 goroutine
		s.pend.Wait() // 等待所有待处理任务完成
	})
}

// Error returns any failure encountered during the matching session.
// Error 返回匹配会话期间遇到的任何失败。
func (s *MatcherSession) Error() error {
	s.errLock.Lock()
	defer s.errLock.Unlock()

	return s.err
}

// allocateRetrieval assigns a bloom bit index to a client process that can either
// immediately request and fetch the section contents assigned to this bit or wait
// a little while for more sections to be requested.
//
// allocateRetrieval 将一个布隆位索引分配给客户端进程，该进程可以立即请求并获取分配给此位的内容，
// 或者等待一段时间以请求更多区段。
//
// 在以太坊轻客户端中，布隆位索引（0-2047）对应 logsBloom 的位。
// allocateRetrieval 是将某个位分配给检索进程的第一步，以便加载相关布隆数据。
func (s *MatcherSession) allocateRetrieval() (uint, bool) {
	fetcher := make(chan uint) // 创建一个通道用于接收位索引

	select {
	case <-s.quit: // 如果会话已终止，返回 false
		return 0, false
	case s.matcher.retrievers <- fetcher: // 将 fetcher 发送到 retrievers 通道
		bit, ok := <-fetcher // 从 fetcher 接收分配的位索引
		return bit, ok       // 返回位索引和成功标志
	}
}

// pendingSections returns the number of pending section retrievals belonging to
// the given bloom bit index.
//
// pendingSections 返回属于给定布隆位索引的待处理区段检索数量。
// 用于查询特定布隆位索引的待处理区段检索数量。
func (s *MatcherSession) pendingSections(bit uint) int {
	fetcher := make(chan uint) // 创建一个通道用于接收计数

	select {
	case <-s.quit: // 如果会话已终止，返回 0
		return 0
	case s.matcher.counters <- fetcher: // 将 fetcher 发送到 counters 通道
		fetcher <- bit        // 发送位索引
		return int(<-fetcher) // 接收并返回待处理区段数量
	}
}

// allocateSections assigns all or part of an already allocated bit-task queue
// to the requesting process.
// allocateSections 将已分配的位任务队列的全部或部分分配给请求进程。
// 用于将某个布隆位索引的待处理区段任务分配给请求进程。
func (s *MatcherSession) allocateSections(bit uint, count int) []uint64 {
	fetcher := make(chan *Retrieval) // 创建一个通道用于接收 Retrieval 对象

	select {
	case <-s.quit: // 如果会话已终止，返回 nil
		return nil
	case s.matcher.retrievals <- fetcher: // 将 fetcher 发送到 retrievals 通道
		task := &Retrieval{
			Bit:      bit,                   // 设置任务的位索引
			Sections: make([]uint64, count), // 初始化指定数量的区段切片
		}
		fetcher <- task             // 发送任务给 fetcher
		return (<-fetcher).Sections // 接收并返回分配的区段
	}
}

// deliverSections delivers a batch of section bit-vectors for a specific bloom
// bit index to be injected into the processing pipeline.
// deliverSections 为特定的布隆位索引交付一批区段位向量，以便注入处理管道。
// 用于将一批区段的布隆位向量交付给匹配管道进行处理。
func (s *MatcherSession) deliverSections(bit uint, sections []uint64, bitsets [][]byte) {
	s.matcher.deliveries <- &Retrieval{Bit: bit, Sections: sections, Bitsets: bitsets} // 将检索到的布隆位数据（bitsets）与对应的区段（sections）和位索引（bit）打包为 Retrieval 对象，注入 Matcher 的处理管道。
}

// Multiplex polls the matcher session for retrieval tasks and multiplexes it into
// the requested retrieval queue to be serviced together with other sessions.
//
// This method will block for the lifetime of the session. Even after termination
// of the session, any request in-flight need to be responded to! Empty responses
// are fine though in that case.
//
// Multiplex 从匹配器会话中轮询检索任务，并将其多路复用到请求的检索队列中，与其他会话一起被服务。
//
// 此方法将在会话的整个生命周期内阻塞。即使在会话终止后，任何正在进行的请求也需要得到响应！在这种情况下，空响应也是可以的。
//
// 用于轮询检索任务并将其多路复用到外部队列中，与其他会话共享服务。
// 从会话中获取布隆位任务，分配区段，发送到外部队列，并在结果返回后交付。
// 在会话生命周期内持续运行，支持优雅终止。
func (s *MatcherSession) Multiplex(batch int, wait time.Duration, mux chan chan *Retrieval) {
	waitTimer := time.NewTimer(wait) // 创建等待定时器
	defer waitTimer.Stop()           // 在函数结束时停止定时器

	for {
		// Allocate a new bloom bit index to retrieve data for, stopping when done
		// 分配一个新的布隆位索引以检索数据，完成后停止
		bit, ok := s.allocateRetrieval()
		if !ok {
			return
		}
		// Bit allocated, throttle a bit if we're below our batch limit
		// 分配了位，如果待处理区段少于批次限制，则稍作节流
		if s.pendingSections(bit) < batch {
			waitTimer.Reset(wait) // 重置等待时间
			select {
			case <-s.quit:
				// Session terminating, we can't meaningfully service, abort
				// 会话终止，无法有效服务，中止
				s.allocateSections(bit, 0)                     // 分配空区段
				s.deliverSections(bit, []uint64{}, [][]byte{}) // 交付空结果
				return

			case <-waitTimer.C:
				// Throttling up, fetch whatever is available
				// 等待超时，获取可用内容
			}
		}
		// Allocate as much as we can handle and request servicing
		// 分配我们能处理的最大数量并请求服务
		sections := s.allocateSections(bit, batch)
		request := make(chan *Retrieval) // 创建请求通道

		select {
		case <-s.quit:
			// Session terminating, we can't meaningfully service, abort
			// 会话终止，无法有效服务，中止
			s.deliverSections(bit, sections, make([][]byte, len(sections))) // 交付空位向量
			return

		case mux <- request: // 将请求发送到多路复用队列
			// Retrieval accepted, something must arrive before we're aborting
			// 检索被接受，必须在中止前返回结果
			request <- &Retrieval{Bit: bit, Sections: sections, Context: s.ctx} // 发送任务

			result := <-request // 接收服务结果

			// Deliver a result before s.Close() to avoid a deadlock
			// 在 s.Close() 前交付结果以避免死锁
			s.deliverSections(result.Bit, result.Sections, result.Bitsets)

			if result.Error != nil { // 如果有错误，记录并关闭会话
				s.errLock.Lock()
				s.err = result.Error
				s.errLock.Unlock()
				s.Close()
			}
		}
	}
}
