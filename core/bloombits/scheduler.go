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
	"sync"
)

// request represents a bloom retrieval task to prioritize and pull from the local
// database or remotely from the network.
// request 表示一个布隆检索任务，用于优先级排序并从本地数据库或网络远程拉取。
type request struct {
	section uint64 // Section index to retrieve the bit-vector from 要从中检索位向量的段索引
	bit     uint   // Bit index within the section to retrieve the vector of 段内要检索向量对应的位索引
}

// response represents the state of a requested bit-vector through a scheduler.
// response 表示通过调度器请求的位向量的状态。
type response struct {
	cached []byte        // Cached bits to dedup multiple requests 缓存的位数据，用于去重多个请求；存储检索到的位向量，用于缓存以避免重复请求。
	done   chan struct{} // Channel to allow waiting for completion 通道，用于等待完成
}

// scheduler handles the scheduling of bloom-filter retrieval operations for
// entire section-batches belonging to a single bloom bit. Beside scheduling the
// retrieval operations, this struct also deduplicates the requests and caches
// the results to minimize network/database overhead even in complex filtering
// scenarios.
//
// scheduler 处理属于单个布隆位的整个段批次的布隆过滤器检索操作的调度。
// 除了调度检索操作外，此结构体还对请求去重并缓存结果，以在复杂过滤场景中最小化网络/数据库开销。
//
// 用于管理以太坊中布隆过滤器某一位（bit）的检索操作调度。
// 它负责处理多个段（section）的批量请求，去重重复请求，并缓存结果以优化性能。
type scheduler struct {
	bit       uint                 // Index of the bit in the bloom filter this scheduler is responsible for  此调度器负责的布隆过滤器中的位索引,指定调度器负责的布隆过滤器位索引（0 到 2047）。
	responses map[uint64]*response // Currently pending retrieval requests or already cached responses        当前挂起的检索请求或已缓存的响应
	lock      sync.Mutex           // Lock protecting the responses from concurrent access                    保护响应免受并发访问的锁
}

// newScheduler creates a new bloom-filter retrieval scheduler for a specific
// bit index.
// newScheduler 为特定的位索引创建一个新的布隆过滤器检索调度器。
func newScheduler(idx uint) *scheduler {
	return &scheduler{
		bit:       idx,                        // 设置负责的位索引
		responses: make(map[uint64]*response), // 初始化响应映射
	}
}

// run creates a retrieval pipeline, receiving section indexes from sections and
// returning the results in the same order through the done channel. Concurrent
// runs of the same scheduler are allowed, leading to retrieval task deduplication.
//
// run 创建一个检索管道，从sections接收段索引，并通过done通道按相同顺序返回结果。
// 允许同一调度器的并发运行，从而实现检索任务的去重。
//
// 用于创建并启动一个布隆过滤器检索管道。它从 sections 通道接收段索引，通过 dist 分发任务，最终将结果按顺序通过 done 通道返回。
// 它通过 scheduleRequests 和 scheduleDeliveries 协作实现完整的请求-交付流程。
func (s *scheduler) run(sections chan uint64, dist chan *request, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Create a forwarder channel between requests and responses of the same size as
	// the distribution channel (since that will block the pipeline anyway).
	// 创建一个与分发通道相同大小的转发通道，位于请求和响应之间（因为分发通道无论如何都会阻塞管道）。
	pend := make(chan uint64, cap(dist)) // 创建一个与分发通道相同大小的转发通道

	// Start the pipeline schedulers to forward between user -> distributor -> user
	// 启动管道调度器，在用户 -> 分发者 -> 用户之间转发
	wg.Add(2)
	go s.scheduleRequests(sections, dist, pend, quit, wg) // 启动请求调度器
	go s.scheduleDeliveries(pend, done, quit, wg)         // 启动交付调度器
}

// reset cleans up any leftovers from previous runs. This is required before a
// restart to ensure the no previously requested but never delivered state will
// cause a lockup.
func (s *scheduler) reset() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for section, res := range s.responses {
		if res.cached == nil {
			delete(s.responses, section)
		}
	}
}

// scheduleRequests reads section retrieval requests from the input channel,
// deduplicates the stream and pushes unique retrieval tasks into the distribution
// channel for a database or network layer to honour.
// scheduleRequests 从输入通道读取段检索请求，对流进行去重，并将唯一的检索任务推送到分发通道，供数据库或网络层处理。
//
// 负责从输入通道（reqs）读取段检索请求，去重后将唯一任务发送到分发通道（dist），并通知挂起通道（pend）。它通过并发安全的方式管理请求调度。
func (s *scheduler) scheduleRequests(reqs chan uint64, dist chan *request, pend chan uint64, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	// 在完成后清理goroutine和管道
	defer wg.Done()
	defer close(pend)

	// Keep reading and scheduling section requests
	// 持续读取和调度段请求
	for {
		select {
		case <-quit:
			return

		case section, ok := <-reqs: // 从请求通道读取段
			// New section retrieval requested
			// 请求了一个新的段检索
			if !ok {
				return
			}
			// Deduplicate retrieval requests
			// 对检索请求进行去重
			unique := false // 初始化去重标志

			s.lock.Lock()
			if s.responses[section] == nil { // 检查是否为新请求
				s.responses[section] = &response{
					done: make(chan struct{}), // 创建新的响应
				}
				unique = true // 标记为唯一请求
			}
			s.lock.Unlock()

			// Schedule the section for retrieval and notify the deliverer to expect this section
			// 调度该段进行检索，并通知分发者期待此段
			if unique { // 如果是唯一请求，分发任务
				select {
				case <-quit:
					return
				case dist <- &request{bit: s.bit, section: section}: // 发送请求到分发通道
				}
			}
			select {
			case <-quit:
				return
			case pend <- section: // 通知挂起通道
			}
		}
	}
}

// scheduleDeliveries reads section acceptance notifications and waits for them
// to be delivered, pushing them into the output data buffer.
//
// scheduleDeliveries 读取段接受通知并等待它们被交付，将其推送到输出数据缓冲区。
//
// 负责从挂起通道（pend）读取段索引，等待对应的检索请求完成，然后将结果推送到输出通道（done）。它与 scheduleRequests 配合，完成从请求到交付的流程。
// pend 通道连接 scheduleRequests 和 scheduleDeliveries，done 通道则连接调度器和外部消费者。
func (s *scheduler) scheduleDeliveries(pend chan uint64, done chan []byte, quit chan struct{}, wg *sync.WaitGroup) {
	// Clean up the goroutine and pipeline when done
	// 在完成后清理goroutine和管道
	defer wg.Done()
	defer close(done)

	// Keep reading notifications and scheduling deliveries
	// 持续读取通知并调度交付
	for {
		select {
		case <-quit:
			return

		case idx, ok := <-pend: // 从挂起通道读取段索引
			// New section retrieval pending
			// 新的段检索正在挂起
			if !ok {
				return
			}
			// Wait until the request is honoured
			// 等待请求被处理完成
			s.lock.Lock()
			res := s.responses[idx]
			s.lock.Unlock()

			select {
			case <-quit:
				return
			case <-res.done: // 等待请求完成
			}
			// Deliver the result
			// 交付结果
			select {
			case <-quit:
				return
			case done <- res.cached: // 将缓存结果发送到完成通道
			}
		}
	}
}

// deliver is called by the request distributor when a reply to a request arrives.
// deliver 在请求分发者收到请求回复时被调用。
//
// 由请求分发者调用，用于将检索到的布隆位向量数据（data）与对应的段索引（sections）关联起来。它更新 responses 中的缓存并通知请求完成。
//
// 布隆位向量交付
//   - 在以太坊轻客户端（如 LES 协议）中，deliver 处理从网络或数据库返回的布隆位向量（由 Generator.Bitset 生成）。sections 表示段索引，data 是对应的位向量数据，用于日志查询或事件验证。
//
// 分发者角色
//   - 请求分发者（可能是网络层或数据库代理）负责执行 dist 通道中的任务，deliver 则是结果的接收点，完成请求-响应的闭环。
func (s *scheduler) deliver(sections []uint64, data [][]byte) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i, section := range sections { // 遍历段和对应的数据
		if res := s.responses[section]; res != nil && res.cached == nil { // Avoid non-requests and double deliveries // 避免非请求和重复交付
			res.cached = data[i] // 设置缓存数据
			close(res.done)      // 关闭完成通道
		}
	}
}
