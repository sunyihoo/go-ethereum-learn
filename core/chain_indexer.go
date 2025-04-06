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

package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

// 1. ChainIndexer 的作用与以太坊白皮书
// ChainIndexer 是 go-ethereum 中用于对规范链进行后处理的组件，主要服务于 BloomBits（布隆过滤器位图）和 CHT（Canonical Hash Trie，规范哈希树）。以太坊白皮书提到，区块链节点需要高效查询历史数据（如交易日志），而全节点存储所有数据会占用大量资源。ChainIndexer 通过将链分成固定大小的段（sectionSize）并生成索引，优化了轻客户端和快速同步的性能。这与白皮书中“轻客户端友好”的设计理念一致，允许节点仅下载部分数据即可验证交易。
//
// 2. BloomBits 和日志过滤
// ChainIndexerBackend 的接口设计（如 Reset、Process、Commit）支持生成 BloomBits。以太坊黄皮书定义了布隆过滤器（Bloom Filter）用于快速查询区块中的日志事件（Logs）。每个区块头部包含一个 LogsBloom 字段，ChainIndexer 将多个区块的布隆过滤器聚合为段索引（BloomBits），便于客户端高效检索特定事件。这在以太坊的智能合约生态中尤为重要，例如查询 ERC-20 代币转账事件。
//
// 3. CHT 与轻客户端同步
// ChainIndexer 还支持 CHT 结构（见 ChainIndexerBackend 的注释），这是以太坊轻客户端同步的关键技术。CHT 是一种 Merkle 树，存储特定段的规范哈希和状态根，允许轻客户端验证链的完整性而无需下载所有区块。processSection 方法逐个处理段内头部并提交结果，体现了 CHT 的构建过程。EIP-2481（Les 协议改进）进一步优化了这种机制，ChainIndexer 是其底层实现。
//
// 4. 重组（Reorg）与 GHOST 协议
// newHead 和 eventLoop 方法处理链头部更新和重组。以太坊使用 GHOST 协议（Greedy Heaviest Observed SubTree）选择最重链（基于总难度），但短时分叉和叔块（Uncle Blocks）会导致重组。ChainIndexer 通过 verifyLastHead 和 newHead 的 reorg 参数检测并回滚无效段，确保索引与规范链一致。这与白皮书中提到的分叉处理和一致性保证密切相关。
//
// 5. 检查点（Checkpoint）与同步优化
// AddCheckpoint 方法引入检查点机制，假设链在检查点之前已完整且无需处理。这是快速同步（Fast Sync）的重要优化，节点可以跳过早期区块的验证，直接从检查点开始构建索引。EIP-2364 定义了类似的同步检查点，ChainIndexer 的设计支持这种策略，减少了同步时间和资源消耗。
//
// 6. 节流（Throttling）与性能平衡
// throttling 参数通过延迟更新（time.AfterFunc）防止数据库过载。以太坊节点运行在不同硬件上，频繁的磁盘 I/O 可能导致性能瓶颈。ChainIndexer 的节流机制平衡了索引生成速度和系统资源使用，体现了以太坊客户端对多样化运行环境的支持。

// ChainIndexerBackend defines the methods needed to process chain segments in
// the background and write the segment results into the database. These can be
// used to create filter blooms or CHTs.
// ChainIndexerBackend 定义了在后台处理链段并将段结果写入数据库所需的方法。这些方法可用于创建过滤器布隆或 CHT。
type ChainIndexerBackend interface {
	// Reset initiates the processing of a new chain segment, potentially terminating
	// any partially completed operations (in case of a reorg).
	// Reset 初始化新链段的处理，可能会终止任何部分完成的操作（在发生重组的情况下）。
	Reset(ctx context.Context, section uint64, prevHead common.Hash) error

	// Process crunches through the next header in the chain segment. The caller
	// will ensure a sequential order of headers.
	// Process 处理链段中的下一个头部。调用者将确保头部的顺序。
	Process(ctx context.Context, header *types.Header) error

	// Commit finalizes the section metadata and stores it into the database.
	// Commit 完成段元数据的最终处理并将其存储到数据库中。
	Commit() error

	// Prune deletes the chain index older than the given threshold.
	// Prune 删除早于给定阈值的链索引。
	Prune(threshold uint64) error
}

// ChainIndexerChain interface is used for connecting the indexer to a blockchain
// ChainIndexerChain 接口用于将索引器连接到区块链
type ChainIndexerChain interface {
	// CurrentHeader retrieves the latest locally known header.
	// CurrentHeader 检索本地已知的最新头部。
	CurrentHeader() *types.Header

	// SubscribeChainHeadEvent subscribes to new head header notifications.
	// SubscribeChainHeadEvent 订阅新的头部通知。
	SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription
}

// ChainIndexer does a post-processing job for equally sized sections of the
// canonical chain (like BlooomBits and CHT structures). A ChainIndexer is
// connected to the blockchain through the event system by starting a
// ChainHeadEventLoop in a goroutine.
//
// Further child ChainIndexers can be added which use the output of the parent
// section indexer. These child indexers receive new head notifications only
// after an entire section has been finished or in case of rollbacks that might
// affect already finished sections.
// ChainIndexer 为规范链的等大小段（如 BlooomBits 和 CHT 结构）执行后处理任务。ChainIndexer 通过在 goroutine 中启动 ChainHeadEventLoop 与区块链的事件系统连接。
//
// 可以添加更多的子 ChainIndexer，它们使用父段索引器的输出。这些子索引器仅在整个段完成后或在可能影响已完成段的回滚情况下接收新的头部通知。
type ChainIndexer struct {
	chainDb ethdb.Database // Chain database to index the data from
	// 链数据库，用于索引数据
	indexDb ethdb.Database // Prefixed table-view of the db to write index metadata into
	// 数据库的前缀表视图，用于写入索引元数据
	backend ChainIndexerBackend // Background processor generating the index data content
	// 后台处理器，生成索引数据内容
	children []*ChainIndexer // Child indexers to cascade chain updates to
	// 子索引器，用于级联链更新

	active atomic.Bool // Flag whether the event loop was started
	// 标志事件循环是否已启动
	update chan struct{} // Notification channel that headers should be processed
	// 通知通道，表示应处理头部
	quit chan chan error // Quit channel to tear down running goroutines
	// 退出通道，用于终止运行的 goroutine
	ctx       context.Context // 上下文，用于控制生命周期
	ctxCancel func()          // 取消上下文的函数

	sectionSize uint64 // Number of blocks in a single chain segment to process
	// 单个链段中要处理的区块数
	confirmsReq uint64 // Number of confirmations before processing a completed segment
	// 处理已完成段之前的确认数

	storedSections uint64 // Number of sections successfully indexed into the database
	// 已成功索引到数据库的段数
	knownSections uint64 // Number of sections known to be complete (block wise)
	// 已知完成的段数（按区块计）
	cascadedHead uint64 // Block number of the last completed section cascaded to subindexers
	// 级联到子索引器的最后一个完成段的区块号

	checkpointSections uint64 // Number of sections covered by the checkpoint
	// 检查点覆盖的段数
	checkpointHead common.Hash // Section head belonging to the checkpoint
	// 检查点所属的段头部

	throttling time.Duration // Disk throttling to prevent a heavy upgrade from hogging resources
	// 磁盘节流，防止繁重的升级占用过多资源

	log  log.Logger // 日志记录器
	lock sync.Mutex // 互斥锁
}

// NewChainIndexer creates a new chain indexer to do background processing on
// chain segments of a given size after certain number of confirmations passed.
// The throttling parameter might be used to prevent database thrashing.
// NewChainIndexer 创建一个新的链索引器，在一定数量的确认通过后对给定大小的链段进行后台处理。
// 节流参数可用于防止数据库过载。
func NewChainIndexer(chainDb ethdb.Database, indexDb ethdb.Database, backend ChainIndexerBackend, section, confirm uint64, throttling time.Duration, kind string) *ChainIndexer {
	c := &ChainIndexer{
		chainDb:     chainDb,
		indexDb:     indexDb,
		backend:     backend,
		update:      make(chan struct{}, 1),
		quit:        make(chan chan error),
		sectionSize: section,
		confirmsReq: confirm,
		throttling:  throttling,
		log:         log.New("type", kind),
	}
	// Initialize database dependent fields and start the updater
	// 初始化依赖数据库的字段并启动更新器
	c.loadValidSections()                                         // 加载有效段数
	c.ctx, c.ctxCancel = context.WithCancel(context.Background()) // 初始化上下文

	go c.updateLoop() // 启动更新循环

	return c
}

// 代码逻辑注解：
// 1. 初始化 ChainIndexer 结构体，设置数据库、后台处理器、通道等。
// 2. 从数据库加载已存储的有效段数。
// 3. 创建带取消功能的上下文并启动后台更新循环。

// AddCheckpoint adds a checkpoint. Sections are never processed and the chain
// is not expected to be available before this point. The indexer assumes that
// the backend has sufficient information available to process subsequent sections.
//
// Note: knownSections == 0 and storedSections == checkpointSections until
// syncing reaches the checkpoint
// AddCheckpoint 添加一个检查点。在此点之前不会处理段，且链预计不可用。索引器假定后台有足够的信息来处理后续段。
//
// 注意：在同步到达检查点之前，knownSections == 0 且 storedSections == checkpointSections
func (c *ChainIndexer) AddCheckpoint(section uint64, shead common.Hash) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Short circuit if the given checkpoint is below than local's.
	// 如果给定的检查点低于本地的，直接返回
	if c.checkpointSections >= section+1 || section < c.storedSections {
		return
	}
	c.checkpointSections = section + 1 // 更新检查点段数
	c.checkpointHead = shead           // 更新检查点头部

	c.setSectionHead(section, shead) // 设置段头部
	c.setValidSections(section + 1)  // 设置有效段数
}

// 代码逻辑注解：
// 1. 加锁保护并发访问。
// 2. 检查检查点是否有效，若无效则返回。
// 3. 更新检查点段数和头部，并存储到数据库。

// Start creates a goroutine to feed chain head events into the indexer for
// cascading background processing. Children do not need to be started, they
// are notified about new events by their parents.
// Start 创建一个 goroutine 将链头部事件送入索引器以进行级联后台处理。子索引器无需启动，它们由父索引器通知新事件。
func (c *ChainIndexer) Start(chain ChainIndexerChain) {
	events := make(chan ChainHeadEvent, 10)      // 创建事件通道
	sub := chain.SubscribeChainHeadEvent(events) // 订阅头部事件

	go c.eventLoop(chain.CurrentHeader(), events, sub) // 启动事件循环
}

// 代码逻辑注解：
// 1. 创建事件通道并订阅链头部事件。
// 2. 在 goroutine 中启动事件循环，处理头部更新。

// Close tears down all goroutines belonging to the indexer and returns any error
// that might have occurred internally.
// Close 终止索引器所属的所有 goroutine 并返回可能发生的内部错误。
func (c *ChainIndexer) Close() error {
	var errs []error

	c.ctxCancel() // 取消上下文

	// Tear down the primary update loop
	// 终止主更新循环
	errc := make(chan error)
	c.quit <- errc
	if err := <-errc; err != nil {
		errs = append(errs, err) // 收集错误
	}
	// If needed, tear down the secondary event loop
	// 如果需要，终止次级事件循环
	if c.active.Load() {
		c.quit <- errc
		if err := <-errc; err != nil {
			errs = append(errs, err) // 收集错误
		}
	}
	// Close all children
	// 关闭所有子索引器
	for _, child := range c.children {
		if err := child.Close(); err != nil {
			errs = append(errs, err) // 收集错误
		}
	}
	// Return any failures
	// 返回任何失败
	switch {
	case len(errs) == 0:
		return nil
	case len(errs) == 1:
		return errs[0]
	default:
		return fmt.Errorf("%v", errs)
	}
}

// 代码逻辑注解：
// 1. 取消上下文以通知所有 goroutine。
// 2. 依次关闭主更新循环、次级事件循环和子索引器，收集所有错误。
// 3. 根据错误数量返回相应结果。

// eventLoop is a secondary - optional - event loop of the indexer which is only
// started for the outermost indexer to push chain head events into a processing
// queue.
// eventLoop 是索引器的次级 - 可选 - 事件循环，仅为最外层索引器启动，以将链头部事件推入处理队列。
func (c *ChainIndexer) eventLoop(currentHeader *types.Header, events chan ChainHeadEvent, sub event.Subscription) {
	// Mark the chain indexer as active, requiring an additional teardown
	// 将链索引器标记为活动状态，需要额外的终止处理
	c.active.Store(true)

	defer sub.Unsubscribe() // 延迟取消订阅

	// Fire the initial new head event to start any outstanding processing
	// 触发初始新头部事件以启动任何未完成处理
	c.newHead(currentHeader.Number.Uint64(), false)

	var (
		prevHeader = currentHeader        // 前一个头部
		prevHash   = currentHeader.Hash() // 前一个头部哈希
	)
	for {
		select {
		case errc := <-c.quit:
			// Chain indexer terminating, report no failure and abort
			// 链索引器终止，不报告失败并中止
			errc <- nil
			return

		case ev, ok := <-events:
			// Received a new event, ensure it's not nil (closing) and update
			// 接收到新事件，确保它不为空（关闭）并更新
			if !ok {
				errc := <-c.quit
				errc <- nil
				return
			}
			if ev.Header.ParentHash != prevHash {
				// Reorg to the common ancestor if needed (might not exist in light sync mode, skip reorg then)
				// 如果需要，重组到共同祖先（在轻同步模式下可能不存在，则跳过重组）
				// TODO(karalabe, zsfelfoldi): This seems a bit brittle, can we detect this case explicitly?
				// TODO(karalabe, zsfelfoldi): 这看起来有点脆弱，我们能明确检测这种情况吗？

				if rawdb.ReadCanonicalHash(c.chainDb, prevHeader.Number.Uint64()) != prevHash {
					if h := rawdb.FindCommonAncestor(c.chainDb, prevHeader, ev.Header); h != nil {
						c.newHead(h.Number.Uint64(), true) // 重组到共同祖先
					}
				}
			}
			c.newHead(ev.Header.Number.Uint64(), false) // 处理新头部

			prevHeader, prevHash = ev.Header, ev.Header.Hash() // 更新前一个头部和哈希
		}
	}
}

// 代码逻辑注解：
// 1. 标记索引器为活动状态并延迟取消订阅。
// 2. 触发初始头部事件。
// 3. 循环监听退出信号或新事件，若发生重组则回退到共同祖先，否则处理新头部。

// newHead notifies the indexer about new chain heads and/or reorgs.
// newHead 通知索引器关于新的链头部和/或重组。
func (c *ChainIndexer) newHead(head uint64, reorg bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// If a reorg happened, invalidate all sections until that point
	// 如果发生重组，使该点之前的所有段无效
	if reorg {
		// Revert the known section number to the reorg point
		// 将已知段数回退到重组点
		known := (head + 1) / c.sectionSize
		stored := known
		if known < c.checkpointSections {
			known = 0 // 如果低于检查点，设为 0
		}
		if stored < c.checkpointSections {
			stored = c.checkpointSections // 确保不低于检查点
		}
		if known < c.knownSections {
			c.knownSections = known // 更新已知段数
		}
		// Revert the stored sections from the database to the reorg point
		// 将数据库中的存储段回退到重组点
		if stored < c.storedSections {
			c.setValidSections(stored)
		}
		// Update the new head number to the finalized section end and notify children
		// 更新新头部编号到已完成段的末尾并通知子索引器
		head = known * c.sectionSize

		if head < c.cascadedHead {
			c.cascadedHead = head
			for _, child := range c.children {
				child.newHead(c.cascadedHead, true) // 级联通知子索引器
			}
		}
		return
	}
	// No reorg, calculate the number of newly known sections and update if high enough
	// 无重组，计算新已知段数并在足够高时更新
	var sections uint64
	if head >= c.confirmsReq {
		sections = (head + 1 - c.confirmsReq) / c.sectionSize
		if sections < c.checkpointSections {
			sections = 0 // 如果低于检查点，设为 0
		}
		if sections > c.knownSections {
			if c.knownSections < c.checkpointSections {
				// syncing reached the checkpoint, verify section head
				// 同步到达检查点，验证段头部
				syncedHead := rawdb.ReadCanonicalHash(c.chainDb, c.checkpointSections*c.sectionSize-1)
				if syncedHead != c.checkpointHead {
					c.log.Error("Synced chain does not match checkpoint", "number", c.checkpointSections*c.sectionSize-1, "expected", c.checkpointHead, "synced", syncedHead)
					return
				}
			}
			c.knownSections = sections // 更新已知段数

			select {
			case c.update <- struct{}{}: // 通知更新
			default:
			}
		}
	}
}

// 代码逻辑注解：
// 1. 加锁保护并发访问。
// 2. 若发生重组，回退已知段数和存储段数，并通知子索引器。
// 3. 若无重组，计算新段数并在满足条件时更新已知段数并触发更新。

// updateLoop is the main event loop of the indexer which pushes chain segments
// down into the processing backend.
// updateLoop 是索引器的主事件循环，将链段推送到处理后台。
func (c *ChainIndexer) updateLoop() {
	var (
		updating bool      // 是否正在更新
		updated  time.Time // 上次更新时间
	)

	for {
		select {
		case errc := <-c.quit:
			// Chain indexer terminating, report no failure and abort
			// 链索引器终止，不报告失败并中止
			errc <- nil
			return

		case <-c.update:
			// Section headers completed (or rolled back), update the index
			// 段头部完成（或回滚），更新索引
			c.lock.Lock()
			if c.knownSections > c.storedSections {
				// Periodically print an upgrade log message to the user
				// 定期打印升级日志消息给用户
				if time.Since(updated) > 8*time.Second {
					if c.knownSections > c.storedSections+1 {
						updating = true
						c.log.Info("Upgrading chain index", "percentage", c.storedSections*100/c.knownSections)
					}
					updated = time.Now()
				}
				// Cache the current section count and head to allow unlocking the mutex
				// 缓存当前段数和头部以允许解锁互斥锁
				c.verifyLastHead() // 验证最后一个头部
				section := c.storedSections
				var oldHead common.Hash
				if section > 0 {
					oldHead = c.SectionHead(section - 1) // 获取前一段头部
				}
				// Process the newly defined section in the background
				// 在后台处理新定义的段
				c.lock.Unlock()
				newHead, err := c.processSection(section, oldHead) // 处理段
				if err != nil {
					select {
					case <-c.ctx.Done():
						<-c.quit <- nil
						return
					default:
					}
					c.log.Error("Section processing failed", "error", err)
				}
				c.lock.Lock()

				// If processing succeeded and no reorgs occurred, mark the section completed
				// 如果处理成功且未发生重组，标记段为已完成
				if err == nil && (section == 0 || oldHead == c.SectionHead(section-1)) {
					c.setSectionHead(section, newHead) // 设置段头部
					c.setValidSections(section + 1)    // 更新有效段数
					if c.storedSections == c.knownSections && updating {
						updating = false
						c.log.Info("Finished upgrading chain index")
					}
					c.cascadedHead = c.storedSections*c.sectionSize - 1 // 更新级联头部
					for _, child := range c.children {
						c.log.Trace("Cascading chain index update", "head", c.cascadedHead)
						child.newHead(c.cascadedHead, false) // 通知子索引器
					}
				} else {
					// If processing failed, don't retry until further notification
					// 如果处理失败，在进一步通知前不重试
					c.log.Debug("Chain index processing failed", "section", section, "err", err)
					c.verifyLastHead()
					c.knownSections = c.storedSections // 回退已知段数
				}
			}
			// If there are still further sections to process, reschedule
			// 如果还有更多段要处理，重新调度
			if c.knownSections > c.storedSections {
				time.AfterFunc(c.throttling, func() {
					select {
					case c.update <- struct{}{}: // 延迟触发更新
					default:
					}
				})
			}
			c.lock.Unlock()
		}
	}
}

// 代码逻辑注解：
// 1. 监听退出信号或更新信号。
// 2. 若收到更新信号，检查是否有新段需要处理，定期记录进度。
// 3. 处理新段，若成功则更新状态并通知子索引器，若失败则回退。
// 4. 若仍有段未处理，使用节流机制重新调度。

// processSection processes an entire section by calling backend functions while
// ensuring the continuity of the passed headers. Since the chain mutex is not
// held while processing, the continuity can be broken by a long reorg, in which
// case the function returns with an error.
// processSection 通过调用后台函数处理整个段，同时确保传入头部的连续性。由于处理时未持有链互斥锁，长时间重组可能破坏连续性，此时函数返回错误。
func (c *ChainIndexer) processSection(section uint64, lastHead common.Hash) (common.Hash, error) {
	c.log.Trace("Processing new chain section", "section", section)

	// Reset and partial processing
	// 重置和部分处理
	if err := c.backend.Reset(c.ctx, section, lastHead); err != nil {
		c.setValidSections(0) // 重置有效段数
		return common.Hash{}, err
	}

	for number := section * c.sectionSize; number < (section+1)*c.sectionSize; number++ {
		hash := rawdb.ReadCanonicalHash(c.chainDb, number) // 读取规范哈希
		if hash == (common.Hash{}) {
			return common.Hash{}, fmt.Errorf("canonical block #%d unknown", number)
		}
		header := rawdb.ReadHeader(c.chainDb, hash, number) // 读取头部
		if header == nil {
			return common.Hash{}, fmt.Errorf("block #%d [%x..] not found", number, hash[:4])
		} else if header.ParentHash != lastHead {
			return common.Hash{}, errors.New("chain reorged during section processing") // 检测到重组
		}
		if err := c.backend.Process(c.ctx, header); err != nil {
			return common.Hash{}, err
		}
		lastHead = header.Hash() // 更新最后一个头部哈希
	}
	if err := c.backend.Commit(); err != nil {
		return common.Hash{}, err // 提交失败
	}
	return lastHead, nil
}

// 代码逻辑注解：
// 1. 重置后台处理器以处理新段。
// 2. 遍历段内所有区块，验证连续性并逐个处理头部。
// 3. 提交处理结果，返回最后一个头部哈希或错误。

// verifyLastHead compares last stored section head with the corresponding block hash in the
// actual canonical chain and rolls back reorged sections if necessary to ensure that stored
// sections are all valid
// verifyLastHead 比较最后存储的段头部与实际规范链中的对应区块哈希，必要时回滚重组的段以确保存储的段都有效
func (c *ChainIndexer) verifyLastHead() {
	for c.storedSections > 0 && c.storedSections > c.checkpointSections {
		if c.SectionHead(c.storedSections-1) == rawdb.ReadCanonicalHash(c.chainDb, c.storedSections*c.sectionSize-1) {
			return // 如果匹配，直接返回
		}
		c.setValidSections(c.storedSections - 1) // 回滚一段
	}
}

// Sections returns the number of processed sections maintained by the indexer
// and also the information about the last header indexed for potential canonical
// verifications.
// Sections 返回索引器维护的已处理段数以及最后一个索引头部的相关信息，以供可能的规范验证。
func (c *ChainIndexer) Sections() (uint64, uint64, common.Hash) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.verifyLastHead() // 验证最后一个头部
	return c.storedSections, c.storedSections*c.sectionSize - 1, c.SectionHead(c.storedSections - 1)
}

// AddChildIndexer adds a child ChainIndexer that can use the output of this one
// AddChildIndexer 添加一个子 ChainIndexer，它可以使用此索引器的输出
func (c *ChainIndexer) AddChildIndexer(indexer *ChainIndexer) {
	if indexer == c {
		panic("can't add indexer as a child of itself") // 防止自引用
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	c.children = append(c.children, indexer) // 添加子索引器

	// Cascade any pending updates to new children too
	// 也将任何待处理的更新级联到新子索引器
	sections := c.storedSections
	if c.knownSections < sections {
		// if a section is "stored" but not "known" then it is a checkpoint without
		// available chain data so we should not cascade it yet
		// 如果一个段是“存储的”但不是“已知的”，则它是检查点，没有可用的链数据，因此我们还不应级联它
		sections = c.knownSections
	}
	if sections > 0 {
		indexer.newHead(sections*c.sectionSize-1, false) // 通知子索引器
	}
}

// Prune deletes all chain data older than given threshold.
// Prune 删除早于给定阈值的所有链数据。
func (c *ChainIndexer) Prune(threshold uint64) error {
	return c.backend.Prune(threshold) // 调用后台修剪方法
}

// loadValidSections reads the number of valid sections from the index database
// and caches is into the local state.
// loadValidSections 从索引数据库读取有效段数并缓存到本地状态。
func (c *ChainIndexer) loadValidSections() {
	data, _ := c.indexDb.Get([]byte("count"))
	if len(data) == 8 {
		c.storedSections = binary.BigEndian.Uint64(data) // 从数据库加载段数
	}
}

// setValidSections writes the number of valid sections to the index database
// setValidSections 将有效段数写入索引数据库
func (c *ChainIndexer) setValidSections(sections uint64) {
	// Set the current number of valid sections in the database
	// 设置数据库中的当前有效段数
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], sections)
	c.indexDb.Put([]byte("count"), data[:])

	// Remove any reorged sections, caching the valids in the mean time
	// 删除任何重组的段，同时缓存有效段
	for c.storedSections > sections {
		c.storedSections--
		c.removeSectionHead(c.storedSections) // 删除段头部
	}
	c.storedSections = sections // needed if new > old 更新存储段数
}

// SectionHead retrieves the last block hash of a processed section from the
// index database.
// SectionHead 从索引数据库检索已处理段的最后一个区块哈希。
func (c *ChainIndexer) SectionHead(section uint64) common.Hash {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	hash, _ := c.indexDb.Get(append([]byte("shead"), data[:]...))
	if len(hash) == len(common.Hash{}) {
		return common.BytesToHash(hash) // 返回哈希
	}
	return common.Hash{}
}

// setSectionHead writes the last block hash of a processed section to the index
// database.
// setSectionHead 将已处理段的最后一个区块哈希写入索引数据库。
func (c *ChainIndexer) setSectionHead(section uint64, hash common.Hash) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	c.indexDb.Put(append([]byte("shead"), data[:]...), hash.Bytes()) // 存储哈希
}

// removeSectionHead removes the reference to a processed section from the index
// database.
// removeSectionHead 从索引数据库中删除对已处理段的引用。
func (c *ChainIndexer) removeSectionHead(section uint64) {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], section)

	c.indexDb.Delete(append([]byte("shead"), data[:]...)) // 删除哈希
}
