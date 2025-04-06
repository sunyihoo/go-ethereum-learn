// Copyright 2020 The go-ethereum Authors
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

package state

import (
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// 以太坊的状态存储在 Merkle Patricia Trie（MPT）中，包括账户 trie 和存储 trie。访问状态涉及从数据库加载 trie 节点，这可能导致延迟。白皮书中提到状态是所有账户的集合，黄皮书定义了 trie 的结构。triePrefetcher 通过预加载账户和存储数据到缓存中，减少了 EVM 执行时的等待时间。

var (
	// triePrefetchMetricsPrefix is the prefix under which to publish the metrics.
	// triePrefetchMetricsPrefix 是发布指标的前缀。
	triePrefetchMetricsPrefix = "trie/prefetch/"

	// errTerminated is returned if a fetcher is attempted to be operated after it
	// has already terminated.
	// errTerminated 如果在提取器终止后尝试操作它，则返回此错误。
	errTerminated = errors.New("fetcher is already terminated")
)

// triePrefetcher is an active prefetcher, which receives accounts or storage
// items and does trie-loading of them. The goal is to get as much useful content
// into the caches as possible.
//
// Note, the prefetcher's API is not thread safe.
// triePrefetcher 是一个主动预取器，接收账户或存储项并对其进行 trie 加载。
// 目标是尽可能将有用的内容加载到缓存中。
//
// 注意，预取器的 API 不是线程安全的。
type triePrefetcher struct {
	verkle   bool                   // Flag whether the prefetcher is in verkle mode 标志预取器是否处于 verkle 模式
	db       Database               // Database to fetch trie nodes through 用于获取 trie 节点的数据库
	root     common.Hash            // Root hash of the account trie for metrics 账户 trie 的根哈希，用于指标
	fetchers map[string]*subfetcher // Subfetchers for each trie 每个 trie 的子提取器
	term     chan struct{}          // Channel to signal interruption 信号中断的通道
	noreads  bool                   // Whether to ignore state-read-only prefetch requests 是否忽略仅读取状态的预取请求

	deliveryMissMeter *metrics.Meter // 交付缺失计数器

	accountLoadReadMeter  *metrics.Meter // 账户加载读取计数器
	accountLoadWriteMeter *metrics.Meter // 账户加载写入计数器
	accountDupReadMeter   *metrics.Meter // 账户重复读取计数器
	accountDupWriteMeter  *metrics.Meter // 账户重复写入计数器
	accountDupCrossMeter  *metrics.Meter // 账户读写交叉重复计数器
	accountWasteMeter     *metrics.Meter // 账户浪费计数器

	storageLoadReadMeter  *metrics.Meter // 存储加载读取计数器
	storageLoadWriteMeter *metrics.Meter // 存储加载写入计数器
	storageDupReadMeter   *metrics.Meter // 存储重复读取计数器
	storageDupWriteMeter  *metrics.Meter // 存储重复写入计数器
	storageDupCrossMeter  *metrics.Meter // 存储读写交叉重复计数器
	storageWasteMeter     *metrics.Meter // 存储浪费计数器
}

// newTriePrefetcher creates a new trie prefetcher instance.
// newTriePrefetcher 创建一个新的 trie 预取器实例。
func newTriePrefetcher(db Database, root common.Hash, namespace string, noreads bool) *triePrefetcher {
	prefix := triePrefetchMetricsPrefix + namespace // 构造指标前缀
	return &triePrefetcher{
		verkle:   db.TrieDB().IsVerkle(),       // 判断是否为 verkle 模式
		db:       db,                           // 设置数据库
		root:     root,                         // 设置根哈希
		fetchers: make(map[string]*subfetcher), // Active prefetchers use the fetchers map 初始化子提取器映射
		term:     make(chan struct{}),          // 初始化终止通道
		noreads:  noreads,                      // 设置是否忽略读取请求

		deliveryMissMeter: metrics.GetOrRegisterMeter(prefix+"/deliverymiss", nil), // 注册交付缺失指标

		accountLoadReadMeter:  metrics.GetOrRegisterMeter(prefix+"/account/load/read", nil),  // 账户读取加载
		accountLoadWriteMeter: metrics.GetOrRegisterMeter(prefix+"/account/load/write", nil), // 账户写入加载
		accountDupReadMeter:   metrics.GetOrRegisterMeter(prefix+"/account/dup/read", nil),   // 账户重复读取
		accountDupWriteMeter:  metrics.GetOrRegisterMeter(prefix+"/account/dup/write", nil),  // 账户重复写入
		accountDupCrossMeter:  metrics.GetOrRegisterMeter(prefix+"/account/dup/cross", nil),  // 账户读写交叉重复
		accountWasteMeter:     metrics.GetOrRegisterMeter(prefix+"/account/waste", nil),      // 账户浪费

		storageLoadReadMeter:  metrics.GetOrRegisterMeter(prefix+"/storage/load/read", nil),  // 存储读取加载
		storageLoadWriteMeter: metrics.GetOrRegisterMeter(prefix+"/storage/load/write", nil), // 存储写入加载
		storageDupReadMeter:   metrics.GetOrRegisterMeter(prefix+"/storage/dup/read", nil),   // 存储重复读取
		storageDupWriteMeter:  metrics.GetOrRegisterMeter(prefix+"/storage/dup/write", nil),  // 存储重复写入
		storageDupCrossMeter:  metrics.GetOrRegisterMeter(prefix+"/storage/dup/cross", nil),  // 存储读写交叉重复
		storageWasteMeter:     metrics.GetOrRegisterMeter(prefix+"/storage/waste", nil),      // 存储浪费
	}
}

// terminate iterates over all the subfetchers and issues a termination request
// to all of them. Depending on the async parameter, the method will either block
// until all subfetchers spin down, or return immediately.
// terminate 遍历所有子提取器并向它们发出终止请求。根据 async 参数，方法将阻塞直到所有子提取器停止，或立即返回。
func (p *triePrefetcher) terminate(async bool) {
	// Short circuit if the fetcher is already closed
	// 如果提取器已关闭，则短路返回
	select {
	case <-p.term:
		return
	default:
	}
	// Terminate all sub-fetchers, sync or async, depending on the request
	// 终止所有子提取器，根据请求选择同步或异步
	for _, fetcher := range p.fetchers {
		fetcher.terminate(async)
	}
	close(p.term) // 关闭终止通道
}

// report aggregates the pre-fetching and usage metrics and reports them.
// report 聚合预取和使用指标并报告它们。
func (p *triePrefetcher) report() {
	if !metrics.Enabled() { // 如果指标未启用，直接返回
		return
	}
	for _, fetcher := range p.fetchers {
		fetcher.wait() // ensure the fetcher's idle before poking in its internals 确保子提取器空闲后再访问其内部数据

		if fetcher.root == p.root { // 处理账户 trie
			p.accountLoadReadMeter.Mark(int64(len(fetcher.seenReadAddr)))   // 已读取账户数
			p.accountLoadWriteMeter.Mark(int64(len(fetcher.seenWriteAddr))) // 已写入账户数

			p.accountDupReadMeter.Mark(int64(fetcher.dupsRead))   // 重复读取数
			p.accountDupWriteMeter.Mark(int64(fetcher.dupsWrite)) // 重复写入数
			p.accountDupCrossMeter.Mark(int64(fetcher.dupsCross)) // 读写交叉重复数

			for _, key := range fetcher.usedAddr {
				delete(fetcher.seenReadAddr, key)  // 从已读取中移除已使用项
				delete(fetcher.seenWriteAddr, key) // 从已写入中移除已使用项
			}
			p.accountWasteMeter.Mark(int64(len(fetcher.seenReadAddr) + len(fetcher.seenWriteAddr))) // 未使用的浪费项
		} else { // 处理存储 trie
			p.storageLoadReadMeter.Mark(int64(len(fetcher.seenReadSlot)))   // 已读取存储数
			p.storageLoadWriteMeter.Mark(int64(len(fetcher.seenWriteSlot))) // 已写入存储数

			p.storageDupReadMeter.Mark(int64(fetcher.dupsRead))   // 重复读取数
			p.storageDupWriteMeter.Mark(int64(fetcher.dupsWrite)) // 重复写入数
			p.storageDupCrossMeter.Mark(int64(fetcher.dupsCross)) // 读写交叉重复数

			for _, key := range fetcher.usedSlot {
				delete(fetcher.seenReadSlot, key)  // 从已读取中移除已使用项
				delete(fetcher.seenWriteSlot, key) // 从已写入中移除已使用项
			}
			p.storageWasteMeter.Mark(int64(len(fetcher.seenReadSlot) + len(fetcher.seenWriteSlot))) // 未使用的浪费项
		}
	}
}

// prefetch schedules a batch of trie items to prefetch. After the prefetcher is
// closed, all the following tasks scheduled will not be executed and an error
// will be returned.
//
// prefetch is called from two locations:
//  1. Finalize of the state-objects storage roots. This happens at the end
//     of every transaction, meaning that if several transactions touches
//     upon the same contract, the parameters invoking this method may be
//     repeated.
//  2. Finalize of the main account trie. This happens only once per block.
//
// prefetch 调度一批 trie 项进行预取。在预取器关闭后，所有后续调度的任务将不执行并返回错误。
//
// prefetch 从两个位置调用：
//  1. 状态对象的存储根的 Finalize，在每个交易结束时发生，意味着如果多个交易触及同一合约，调用此方法的参数可能重复。
//  2. 主账户 trie 的 Finalize，每区块仅发生一次。
func (p *triePrefetcher) prefetch(owner common.Hash, root common.Hash, addr common.Address, addrs []common.Address, slots []common.Hash, read bool) error {
	// If the state item is only being read, but reads are disabled, return
	// 如果状态项仅被读取，但读取被禁用，则返回
	if read && p.noreads {
		return nil
	}
	// Ensure the subfetcher is still alive
	// 确保子提取器仍存活
	select {
	case <-p.term:
		return errTerminated // 已终止，返回错误
	default:
	}
	id := p.trieID(owner, root) // 生成 trie 的唯一 ID
	fetcher := p.fetchers[id]
	if fetcher == nil { // 如果子提取器不存在，则创建
		fetcher = newSubfetcher(p.db, p.root, owner, root, addr)
		p.fetchers[id] = fetcher
	}
	return fetcher.schedule(addrs, slots, read) // 调度预取任务
}

// trie returns the trie matching the root hash, blocking until the fetcher of
// the given trie terminates. If no fetcher exists for the request, nil will be
// returned.
// trie 返回与根哈希匹配的 trie，阻塞直到给定 trie 的提取器终止。如果请求的提取器不存在，则返回 nil。
func (p *triePrefetcher) trie(owner common.Hash, root common.Hash) Trie {
	// Bail if no trie was prefetched for this root
	// 如果没有为此根预取 trie，则退出
	fetcher := p.fetchers[p.trieID(owner, root)]
	if fetcher == nil {
		log.Error("Prefetcher missed to load trie", "owner", owner, "root", root)
		p.deliveryMissMeter.Mark(1) // 记录交付缺失
		return nil
	}
	// Subfetcher exists, retrieve its trie
	// 子提取器存在，检索其 trie
	return fetcher.peek()
}

// used marks a batch of state items used to allow creating statistics as to
// how useful or wasteful the fetcher is.
// used 标记一批已使用的状态项，以便创建统计数据，了解提取器的有用性或浪费程度。
func (p *triePrefetcher) used(owner common.Hash, root common.Hash, usedAddr []common.Address, usedSlot []common.Hash) {
	if fetcher := p.fetchers[p.trieID(owner, root)]; fetcher != nil {
		fetcher.wait() // 确保子提取器空闲后再访问其内部数据

		fetcher.usedAddr = append(fetcher.usedAddr, usedAddr...) // 添加已使用的账户
		fetcher.usedSlot = append(fetcher.usedSlot, usedSlot...) // 添加已使用的存储槽
	}
}

// trieID returns an unique trie identifier consists the trie owner and root hash.
// trieID 返回由 trie 拥有者和根哈希组成的唯一 trie 标识符。
func (p *triePrefetcher) trieID(owner common.Hash, root common.Hash) string {
	// The trie in verkle is only identified by state root
	// 在 verkle 模式下，trie 仅由状态根标识
	if p.verkle {
		return p.root.Hex()
	}
	// The trie in merkle is either identified by state root (account trie),
	// or identified by the owner and trie root (storage trie)
	// 在 merkle 模式下，trie 由状态根（账户 trie）或拥有者和 trie 根（存储 trie）标识
	trieID := make([]byte, common.HashLength*2)
	copy(trieID, owner.Bytes())
	copy(trieID[common.HashLength:], root.Bytes())
	return string(trieID)
}

// subfetcher is a trie fetcher goroutine responsible for pulling entries for a
// single trie. It is spawned when a new root is encountered and lives until the
// main prefetcher is paused and either all requested items are processed or if
// the trie being worked on is retrieved from the prefetcher.
// subfetcher 是一个负责为单个 trie 提取条目的 trie 提取器 goroutine。
// 当遇到新根时启动，持续运行直到主预取器暂停，并且所有请求的项都处理完毕或正在处理的 trie 从预取器中检索。
type subfetcher struct {
	db    Database       // Database to load trie nodes through 用于加载 trie 节点的数据库
	state common.Hash    // Root hash of the state to prefetch要预取的状态根哈希
	owner common.Hash    // Owner of the trie, usually account hash trie 的拥有者，通常是账户哈希
	root  common.Hash    // Root hash of the trie to prefetch 要预取的 trie 根哈希
	addr  common.Address // Address of the account that the trie belongs to trie 所属的账户地址
	trie  Trie           // Trie being populated with nodes 正在填充节点的 trie

	tasks []*subfetcherTask //  Items queued up for retrieval 排队等待检索的任务
	lock  sync.Mutex        //  Lock protecting the task queue保护任务队列的锁

	wake chan struct{} // Wake channel if a new task is scheduled 新任务调度时的唤醒通道
	stop chan struct{} // Channel to interrupt processing 中断处理的通道
	term chan struct{} // Channel to signal interruption 信号中断的通道

	seenReadAddr  map[common.Address]struct{} // Tracks the accounts already loaded via read operations 通过读取操作已加载的账户
	seenWriteAddr map[common.Address]struct{} // Tracks the accounts already loaded via write operations 通过写入操作已加载的账户
	seenReadSlot  map[common.Hash]struct{}    // Tracks the storage already loaded via read operations 通过读取操作已加载的存储
	seenWriteSlot map[common.Hash]struct{}    // Tracks the storage already loaded via write operations 通过写入操作已加载的存储

	dupsRead  int // Number of duplicate preload tasks via reads only仅通过读取的重复预加载任务数
	dupsWrite int // Number of duplicate preload tasks via writes only 仅通过写入的重复预加载任务数
	dupsCross int // Number of duplicate preload tasks via read-write-crosses 读写交叉的重复预加载任务数

	usedAddr []common.Address // Tracks the accounts used in the end 最终使用的账户
	usedSlot []common.Hash    // Tracks the storage used in the end 最终使用的存储槽
}

// subfetcherTask is a trie path to prefetch, tagged with whether it originates
// from a read or a write request.
// subfetcherTask 是要预取的 trie 路径，标记其来源于读取还是写入请求。
type subfetcherTask struct {
	read bool            // 是否为读取请求
	addr *common.Address // 账户地址（可选）
	slot *common.Hash    // 存储槽（可选）
}

// newSubfetcher creates a goroutine to prefetch state items belonging to a
// particular root hash.
// newSubfetcher 创建一个 goroutine 以预取属于特定根哈希的状态项。
func newSubfetcher(db Database, state common.Hash, owner common.Hash, root common.Hash, addr common.Address) *subfetcher {
	sf := &subfetcher{
		db:            db,
		state:         state,
		owner:         owner,
		root:          root,
		addr:          addr,
		wake:          make(chan struct{}, 1), // 容量为 1 的唤醒通道
		stop:          make(chan struct{}),
		term:          make(chan struct{}),
		seenReadAddr:  make(map[common.Address]struct{}),
		seenWriteAddr: make(map[common.Address]struct{}),
		seenReadSlot:  make(map[common.Hash]struct{}),
		seenWriteSlot: make(map[common.Hash]struct{}),
	}
	go sf.loop() // 启动后台循环
	return sf
}

// schedule adds a batch of trie keys to the queue to prefetch.
// schedule 将一批 trie 键添加到预取队列中。
func (sf *subfetcher) schedule(addrs []common.Address, slots []common.Hash, read bool) error {
	// Ensure the subfetcher is still alive
	// 确保子提取器仍存活
	select {
	case <-sf.term:
		return errTerminated // 已终止，返回错误
	default:
	}
	// Append the tasks to the current queue
	// 将任务追加到当前队列
	sf.lock.Lock()
	for _, addr := range addrs {
		sf.tasks = append(sf.tasks, &subfetcherTask{read: read, addr: &addr})
	}
	for _, slot := range slots {
		sf.tasks = append(sf.tasks, &subfetcherTask{read: read, slot: &slot})
	}
	sf.lock.Unlock()

	// Notify the background thread to execute scheduled tasks
	// 通知后台线程执行调度的任务
	select {
	case sf.wake <- struct{}{}: // 发送唤醒信号
		// Wake signal sent
	default: // 如果通道已满，则不发送（已有待处理信号）
		// Wake signal not sent as a previous one is already queued
	}
	return nil
}

// wait blocks until the subfetcher terminates. This method is used to block on
// an async termination before accessing internal fields from the fetcher.
// wait 阻塞直到子提取器终止。此方法用于在访问提取器内部字段前等待异步终止。
func (sf *subfetcher) wait() {
	<-sf.term // 等待终止信号
}

// peek retrieves the fetcher's trie, populated with any pre-fetched data. The
// returned trie will be a shallow copy, so modifying it will break subsequent
// peeks for the original data. The method will block until all the scheduled
// data has been loaded and the fetcher terminated.
// peek 检索提取器的 trie，填充了所有预取数据。返回的 trie 是浅拷贝，修改它会破坏对原始数据的后续查看。
// 该方法将阻塞，直到所有调度的数据加载完成且提取器终止。
func (sf *subfetcher) peek() Trie {
	// Block until the fetcher terminates, then retrieve the trie
	// 阻塞直到提取器终止，然后检索 trie
	sf.wait()
	return sf.trie
}

// terminate requests the subfetcher to stop accepting new tasks and spin down
// as soon as everything is loaded. Depending on the async parameter, the method
// will either block until all disk loads finish or return immediately.
// terminate 请求子提取器停止接受新任务并在所有内容加载完成后停止。
// 根据 async 参数，该方法将阻塞直到所有磁盘加载完成，或立即返回。
func (sf *subfetcher) terminate(async bool) {
	select {
	case <-sf.stop:
	default:
		close(sf.stop) // 关闭停止通道
	}
	if async {
		return // 异步模式立即返回
	}
	<-sf.term // 同步模式等待终止
}

// openTrie resolves the target trie from database for prefetching.
// openTrie 从数据库解析目标 trie 以进行预取。
func (sf *subfetcher) openTrie() error {
	// Open the verkle tree if the sub-fetcher is in verkle mode. Note, there is
	// only a single fetcher for verkle.
	// 如果子提取器处于 verkle 模式，则打开 verkle 树。注意，verkle 模式下只有一个提取器。
	if sf.db.TrieDB().IsVerkle() {
		tr, err := sf.db.OpenTrie(sf.state)
		if err != nil {
			log.Warn("Trie prefetcher failed opening verkle trie", "root", sf.root, "err", err)
			return err
		}
		sf.trie = tr
		return nil
	}
	// Open the merkle tree if the sub-fetcher is in merkle mode
	// 如果子提取器处于 merkle 模式，则打开 merkle 树
	if sf.owner == (common.Hash{}) { // 账户 trie
		tr, err := sf.db.OpenTrie(sf.state)
		if err != nil {
			log.Warn("Trie prefetcher failed opening account trie", "root", sf.root, "err", err)
			return err
		}
		sf.trie = tr
		return nil
	}
	// 存储 trie
	tr, err := sf.db.OpenStorageTrie(sf.state, sf.addr, sf.root, nil)
	if err != nil {
		log.Warn("Trie prefetcher failed opening storage trie", "root", sf.root, "err", err)
		return err
	}
	sf.trie = tr
	return nil
}

// loop loads newly-scheduled trie tasks as they are received and loads them, stopping
// when requested.
// loop 加载新调度的 trie 任务，并在收到时加载它们，按请求停止。
func (sf *subfetcher) loop() {
	// No matter how the loop stops, signal anyone waiting that it's terminated
	// 无论循环如何停止，都会向等待者发送终止信号
	defer close(sf.term)

	if err := sf.openTrie(); err != nil { // 打开 trie 失败则退出
		return
	}
	for {
		select {
		case <-sf.wake: // 收到唤醒信号
			// Execute all remaining tasks in a single run
			// 在单次运行中执行所有剩余任务
			sf.lock.Lock()
			tasks := sf.tasks
			sf.tasks = nil // 清空任务队列
			sf.lock.Unlock()

			for _, task := range tasks {
				if task.addr != nil { // 处理账户
					key := *task.addr
					if task.read { // 读取任务
						if _, ok := sf.seenReadAddr[key]; ok {
							sf.dupsRead++ // 重复读取
							continue
						}
						if _, ok := sf.seenWriteAddr[key]; ok {
							sf.dupsCross++ // 读写交叉重复
							continue
						}
					} else { // 写入任务
						if _, ok := sf.seenReadAddr[key]; ok {
							sf.dupsCross++ // 读写交叉重复
							continue
						}
						if _, ok := sf.seenWriteAddr[key]; ok {
							sf.dupsWrite++ // 重复写入
							continue
						}
					}
				} else { // 处理存储槽
					key := *task.slot
					if task.read { // 读取任务
						if _, ok := sf.seenReadSlot[key]; ok {
							sf.dupsRead++ // 重复读取
							continue
						}
						if _, ok := sf.seenWriteSlot[key]; ok {
							sf.dupsCross++ // 读写交叉重复
							continue
						}
					} else { // 写入任务
						if _, ok := sf.seenReadSlot[key]; ok {
							sf.dupsCross++ // 读写交叉重复
							continue
						}
						if _, ok := sf.seenWriteSlot[key]; ok {
							sf.dupsWrite++ // 重复写入
							continue
						}
					}
				}
				// 执行预取
				if task.addr != nil {
					sf.trie.GetAccount(*task.addr) // 获取账户
				} else {
					sf.trie.GetStorage(sf.addr, (*task.slot)[:]) // 获取存储
				}
				// 记录已加载项
				if task.read {
					if task.addr != nil {
						sf.seenReadAddr[*task.addr] = struct{}{}
					} else {
						sf.seenReadSlot[*task.slot] = struct{}{}
					}
				} else {
					if task.addr != nil {
						sf.seenWriteAddr[*task.addr] = struct{}{}
					} else {
						sf.seenWriteSlot[*task.slot] = struct{}{}
					}
				}
			}

		case <-sf.stop: // 收到停止信号
			// Termination is requested, abort if no more tasks are pending. If
			// there are some, exhaust them first.
			// 请求终止，如果没有待处理任务则退出。如果有任务，先耗尽它们。
			sf.lock.Lock()
			done := sf.tasks == nil
			sf.lock.Unlock()

			if done {
				return
			}
			// Some tasks are pending, loop and pick them up (that wake branch
			// will be selected eventually, whilst stop remains closed to this
			// branch will also run afterwards).
			// 有任务待处理，继续循环并处理它们（最终会选择 wake 分支，而 stop 分支保持关闭）。
		}
	}
}
