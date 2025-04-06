// Copyright 2019 The go-ethereum Authors
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

// Package snapshot implements a journalled, dynamic state dump.
package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
)

// Tree 是快照系统的核心管理结构：
//
// 磁盘层（diskLayer）：持久化基础层，由键值存储（diskdb）支持，代表已提交的状态。
// 差异层（diffLayer）：内存中的增量修改，堆叠在磁盘层之上，形成树状结构。
// 方法功能：
// New：加载或重建快照树。
// Update：添加新差异层。
// Cap：限制差异层数量并展平超出的层。
// Journal：将差异层序列化为日志，持久化到磁盘。
// Rebuild：擦除并重建快照。

var (
	snapshotCleanAccountHitMeter   = metrics.NewRegisteredMeter("state/snapshot/clean/account/hit", nil)   // 用于记录干净账户查询命中的仪表
	snapshotCleanAccountMissMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/miss", nil)  // 用于记录干净账户查询未命中的仪表
	snapshotCleanAccountInexMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/inex", nil)  // 用于记录干净账户查询不存在的仪表
	snapshotCleanAccountReadMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/account/read", nil)  // 用于记录干净账户读取数据量的仪表
	snapshotCleanAccountWriteMeter = metrics.NewRegisteredMeter("state/snapshot/clean/account/write", nil) // 用于记录干净账户写入数据量的仪表

	snapshotCleanStorageHitMeter   = metrics.NewRegisteredMeter("state/snapshot/clean/storage/hit", nil)   // 用于记录干净存储查询命中的仪表
	snapshotCleanStorageMissMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/miss", nil)  // 用于记录干净存储查询未命中的仪表
	snapshotCleanStorageInexMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/inex", nil)  // 用于记录干净存储查询不存在的仪表
	snapshotCleanStorageReadMeter  = metrics.NewRegisteredMeter("state/snapshot/clean/storage/read", nil)  // 用于记录干净存储读取数据量的仪表
	snapshotCleanStorageWriteMeter = metrics.NewRegisteredMeter("state/snapshot/clean/storage/write", nil) // 用于记录干净存储写入数据量的仪表

	snapshotDirtyAccountHitMeter   = metrics.NewRegisteredMeter("state/snapshot/dirty/account/hit", nil)   // 用于记录脏账户查询命中的仪表
	snapshotDirtyAccountMissMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/miss", nil)  // 用于记录脏账户查询未命中的仪表
	snapshotDirtyAccountInexMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/inex", nil)  // 用于记录脏账户查询不存在的仪表
	snapshotDirtyAccountReadMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/account/read", nil)  // 用于记录脏账户读取数据量的仪表
	snapshotDirtyAccountWriteMeter = metrics.NewRegisteredMeter("state/snapshot/dirty/account/write", nil) // 用于记录脏账户写入数据量的仪表

	snapshotDirtyStorageHitMeter   = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/hit", nil)   // 用于记录脏存储查询命中的仪表
	snapshotDirtyStorageMissMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/miss", nil)  // 用于记录脏存储查询未命中的仪表
	snapshotDirtyStorageInexMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/inex", nil)  // 用于记录脏存储查询不存在的仪表
	snapshotDirtyStorageReadMeter  = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/read", nil)  // 用于记录脏存储读取数据量的仪表
	snapshotDirtyStorageWriteMeter = metrics.NewRegisteredMeter("state/snapshot/dirty/storage/write", nil) // 用于记录脏存储写入数据量的仪表

	snapshotDirtyAccountHitDepthHist = metrics.NewRegisteredHistogram("state/snapshot/dirty/account/hit/depth", nil, metrics.NewExpDecaySample(1028, 0.015)) // 用于记录脏账户命中深度的直方图，采用指数衰减采样
	snapshotDirtyStorageHitDepthHist = metrics.NewRegisteredHistogram("state/snapshot/dirty/storage/hit/depth", nil, metrics.NewExpDecaySample(1028, 0.015)) // 用于记录脏存储命中深度的直方图，采用指数衰减采样

	snapshotFlushAccountItemMeter = metrics.NewRegisteredMeter("state/snapshot/flush/account/item", nil) // 用于记录刷新账户条目数量的仪表
	snapshotFlushAccountSizeMeter = metrics.NewRegisteredMeter("state/snapshot/flush/account/size", nil) // 用于记录刷新账户数据大小的仪表
	snapshotFlushStorageItemMeter = metrics.NewRegisteredMeter("state/snapshot/flush/storage/item", nil) // 用于记录刷新存储条目数量的仪表
	snapshotFlushStorageSizeMeter = metrics.NewRegisteredMeter("state/snapshot/flush/storage/size", nil) // 用于记录刷新存储数据大小的仪表

	snapshotBloomIndexTimer = metrics.NewRegisteredResettingTimer("state/snapshot/bloom/index", nil) // 用于记录布隆索引时间的重置计时器
	snapshotBloomErrorGauge = metrics.NewRegisteredGaugeFloat64("state/snapshot/bloom/error", nil)   // 用于记录布隆过滤器误报率的浮点仪表

	snapshotBloomAccountTrueHitMeter  = metrics.NewRegisteredMeter("state/snapshot/bloom/account/truehit", nil)  // 用于记录账户布隆过滤器真实命中的仪表
	snapshotBloomAccountFalseHitMeter = metrics.NewRegisteredMeter("state/snapshot/bloom/account/falsehit", nil) // 用于记录账户布隆过滤器假命中的仪表
	snapshotBloomAccountMissMeter     = metrics.NewRegisteredMeter("state/snapshot/bloom/account/miss", nil)     // 用于记录账户布隆过滤器未命中的仪表

	snapshotBloomStorageTrueHitMeter  = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/truehit", nil)  // 用于记录存储布隆过滤器真实命中的仪表
	snapshotBloomStorageFalseHitMeter = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/falsehit", nil) // 用于记录存储布隆过滤器假命中的仪表
	snapshotBloomStorageMissMeter     = metrics.NewRegisteredMeter("state/snapshot/bloom/storage/miss", nil)     // 用于记录存储布隆过滤器未命中的仪表

	// ErrSnapshotStale is returned from data accessors if the underlying snapshot
	// layer had been invalidated due to the chain progressing forward far enough
	// to not maintain the layer's original state.
	// ErrSnapshotStale 如果底层快照层因链向前推进足够远而无法维持原始状态，则从数据访问器返回。
	ErrSnapshotStale = errors.New("snapshot stale") // 快照陈旧错误

	// ErrNotCoveredYet is returned from data accessors if the underlying snapshot
	// is being generated currently and the requested data item is not yet in the
	// range of accounts covered.
	// ErrNotCoveredYet 如果底层快照当前正在生成且请求的数据项尚未在覆盖的账户范围内，则从数据访问器返回。
	ErrNotCoveredYet = errors.New("not covered yet") // 未覆盖错误

	// ErrNotConstructed is returned if the callers want to iterate the snapshot
	// while the generation is not finished yet.
	// ErrNotConstructed 如果调用者在快照生成未完成时想要迭代快照，则返回。
	ErrNotConstructed = errors.New("snapshot is not constructed") // 未构造错误

	// errSnapshotCycle is returned if a snapshot is attempted to be inserted
	// that forms a cycle in the snapshot tree.
	// errSnapshotCycle 如果尝试插入一个在快照树中形成循环的快照，则返回。
	errSnapshotCycle = errors.New("snapshot cycle") // 快照循环错误
)

// Snapshot represents the functionality supported by a snapshot storage layer.
// Snapshot 表示快照存储层支持的功能。
type Snapshot interface {
	// Root returns the root hash for which this snapshot was made.
	// Root 返回为此快照创建的根哈希。
	Root() common.Hash

	// Account directly retrieves the account associated with a particular hash in
	// the snapshot slim data format.
	// Account 直接检索与特定哈希关联的账户，使用快照瘦数据格式。
	Account(hash common.Hash) (*types.SlimAccount, error)

	// AccountRLP directly retrieves the account RLP associated with a particular
	// hash in the snapshot slim data format.
	// AccountRLP 直接检索与特定哈希关联的账户 RLP 数据，使用快照瘦数据格式。
	AccountRLP(hash common.Hash) ([]byte, error)

	// Storage directly retrieves the storage data associated with a particular hash,
	// within a particular account.
	// Storage 直接检索与特定账户中特定哈希关联的存储数据。
	Storage(accountHash, storageHash common.Hash) ([]byte, error)
}

// snapshot is the internal version of the snapshot data layer that supports some
// additional methods compared to the public API.
// snapshot 是快照数据层的内部版本，与公共 API 相比支持一些额外方法。
type snapshot interface {
	Snapshot // 继承公共 Snapshot 接口

	// Parent returns the subsequent layer of a snapshot, or nil if the base was
	// reached.
	//
	// Note, the method is an internal helper to avoid type switching between the
	// disk and diff layers. There is no locking involved.
	// Parent 返回快照的后续层，如果到达基础层则返回 nil。
	//
	// 注意，此方法是内部助手方法，用于避免在磁盘层和差异层之间进行类型切换。不涉及锁。
	Parent() snapshot

	// Update creates a new layer on top of the existing snapshot diff tree with
	// the specified data items.
	//
	// Note, the maps are retained by the method to avoid copying everything.
	// Update 在现有快照差异树之上使用指定数据项创建一个新层。
	//
	// 注意，该方法保留映射以避免复制所有内容。
	Update(blockRoot common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer

	// Journal commits an entire diff hierarchy to disk into a single journal entry.
	// This is meant to be used during shutdown to persist the snapshot without
	// flattening everything down (bad for reorgs).
	// Journal 将整个差异层次结构提交到磁盘上的单个日志条目中。这旨在关闭时使用，以在不展平所有内容（对重组不利）的情况下持久化快照。
	Journal(buffer *bytes.Buffer) (common.Hash, error)

	// Stale return whether this layer has become stale (was flattened across) or
	// if it's still live.
	// Stale 返回此层是否已变得陈旧（被展平）或是否仍有效。
	Stale() bool

	// AccountIterator creates an account iterator over an arbitrary layer.
	// AccountIterator 在任意层上创建账户迭代器。
	AccountIterator(seek common.Hash) AccountIterator

	// StorageIterator creates a storage iterator over an arbitrary layer.
	// StorageIterator 在任意层上创建存储迭代器。
	StorageIterator(account common.Hash, seek common.Hash) StorageIterator
}

// Config includes the configurations for snapshots.
// Config 包括快照的配置。
type Config struct {
	CacheSize int // Megabytes permitted to use for read caches
	// CacheSize 允许用于读取缓存的兆字节数
	Recovery bool // Indicator that the snapshots is in the recovery mode
	// Recovery 指示快照是否处于恢复模式
	NoBuild bool // Indicator that the snapshots generation is disallowed
	// NoBuild 指示是否禁止快照生成
	AsyncBuild bool // The snapshot generation is allowed to be constructed asynchronously
	// AsyncBuild 快照生成是否允许异步构建
}

// Tree is an Ethereum state snapshot tree. It consists of one persistent base
// layer backed by a key-value store, on top of which arbitrarily many in-memory
// diff layers are topped. The memory diffs can form a tree with branching, but
// the disk layer is singleton and common to all. If a reorg goes deeper than the
// disk layer, everything needs to be deleted.
//
// The goal of a state snapshot is twofold: to allow direct access to account and
// storage data to avoid expensive multi-level trie lookups; and to allow sorted,
// cheap iteration of the account/storage tries for sync aid.
// Tree 是以太坊状态快照树。它由一个持久化的基础层组成，由键值存储支持，其上可以堆叠任意多个内存差异层。内存差异可以形成带分支的树，但磁盘层是单一的且对所有层通用。如果重组深度超过磁盘层，则需要删除所有内容。
//
// 状态快照的目标有两个：允许直接访问账户和存储数据，以避免昂贵的多级 trie 查找；以及允许对账户/存储 trie 进行排序、廉价的迭代以辅助同步。
type Tree struct {
	config Config // Snapshots configurations
	// config 快照配置
	diskdb ethdb.KeyValueStore // Persistent database to store the snapshot
	// diskdb 用于存储快照的持久化数据库
	triedb *triedb.Database // In-memory cache to access the trie through
	// triedb 通过内存缓存访问 trie 的数据库
	layers map[common.Hash]snapshot // Collection of all known layers
	// layers 所有已知层的集合
	lock sync.RWMutex // 读写锁，保护对 Tree 的并发访问

	// Test hooks
	onFlatten func() // Hook invoked when the bottom most diff layers are flattened
	// onFlatten 当最底层的差异层被展平时调用的钩子函数
}

// New attempts to load an already existing snapshot from a persistent key-value
// store (with a number of memory layers from a journal), ensuring that the head
// of the snapshot matches the expected one.
//
// If the snapshot is missing or the disk layer is broken, the snapshot will be
// reconstructed using both the existing data and the state trie.
// The repair happens on a background thread.
//
// If the memory layers in the journal do not match the disk layer (e.g. there is
// a gap) or the journal is missing, there are two repair cases:
//
//   - if the 'recovery' parameter is true, memory diff-layers and the disk-layer
//     will all be kept. This case happens when the snapshot is 'ahead' of the
//     state trie.
//   - otherwise, the entire snapshot is considered invalid and will be recreated on
//     a background thread.
//
// New 尝试从持久键值存储加载已存在的快照（带有来自日志的多个内存层），确保快照的头部与预期一致。
//
// 如果快照缺失或磁盘层损坏，将使用现有数据和状态 trie 重建快照。
// 修复将在后台线程上进行。
//
// 如果日志中的内存层与磁盘层不匹配（例如存在间隙）或日志缺失，有两种修复情况：
//
//   - 如果 'recovery' 参数为 true，则内存差异层和磁盘层都将被保留。这种情况发生在快照“领先”状态 trie 时。
//   - 否则，整个快照被视为无效，并将在后台线程上重新创建。
func New(config Config, diskdb ethdb.KeyValueStore, triedb *triedb.Database, root common.Hash) (*Tree, error) {
	// Create a new, empty snapshot tree
	// 创建一个新的、空的状态快照树
	snap := &Tree{
		config: config,                         // 设置配置
		diskdb: diskdb,                         // 设置持久化数据库
		triedb: triedb,                         // 设置 trie 数据库
		layers: make(map[common.Hash]snapshot), // 初始化层集合
	}
	// Attempt to load a previously persisted snapshot and rebuild one if failed
	// 尝试加载之前持久化的快照，如果失败则重建
	head, disabled, err := loadSnapshot(diskdb, triedb, root, config.CacheSize, config.Recovery, config.NoBuild)
	if disabled {
		log.Warn("Snapshot maintenance disabled (syncing)") // 日志警告快照维护被禁用
		return snap, nil                                    // 返回空的快照树
	}
	// Create the building waiter iff the background generation is allowed
	// 如果允许后台生成，则创建构建等待器
	if !config.NoBuild && !config.AsyncBuild {
		defer snap.waitBuild() // 延迟等待构建完成
	}
	if err != nil {
		log.Warn("Failed to load snapshot", "err", err) // 日志警告加载快照失败
		if !config.NoBuild {
			snap.Rebuild(root) // 如果允许重建，则重建快照
			return snap, nil   // 返回快照树
		}
		return nil, err // Bail out the error, don't rebuild automatically.返回错误，不自动重建
	}
	// Existing snapshot loaded, seed all the layers
	// 已加载现有快照，填充所有层
	for head != nil {
		snap.layers[head.Root()] = head // 将层添加到集合中
		head = head.Parent()            // 获取父层，继续循环
	}
	return snap, nil // 返回快照树
}

// waitBuild blocks until the snapshot finishes rebuilding. This method is meant
// to be used by tests to ensure we're testing what we believe we are.
// waitBuild 阻塞直到快照重建完成。此方法旨在用于测试，以确保我们测试的是我们认为的内容。
func (t *Tree) waitBuild() {
	// Find the rebuild termination channel
	// 查找重建终止通道
	var done chan struct{}

	t.lock.RLock() // 加读锁
	for _, layer := range t.layers {
		if layer, ok := layer.(*diskLayer); ok {
			done = layer.genPending // 如果是磁盘层，获取等待通道
			break
		}
	}
	t.lock.RUnlock() // 解锁

	// Wait until the snapshot is generated
	// 等待快照生成完成
	if done != nil {
		<-done // 阻塞直到通道关闭
	}
}

// Disable interrupts any pending snapshot generator, deletes all the snapshot
// layers in memory and marks snapshots disabled globally. In order to resume
// the snapshot functionality, the caller must invoke Rebuild.
// Disable 中断任何待处理的快照生成器，删除内存中的所有快照层，并全局标记快照为禁用。要恢复快照功能，调用者必须调用 Rebuild。
func (t *Tree) Disable() {
	// Interrupt any live snapshot layers
	// 中断任何活动快照层
	t.lock.Lock()         // 加写锁
	defer t.lock.Unlock() // 延迟解锁

	for _, layer := range t.layers {
		switch layer := layer.(type) {
		case *diskLayer:
			// TODO this function will hang if it's called twice. Will
			// fix it in the following PRs.
			// TODO 如果此函数被调用两次会挂起，将在后续 PR 中修复。
			layer.stopGeneration() // 停止生成
			layer.markStale()      // 标记为陈旧
			layer.Release()        // 释放资源

		case *diffLayer:
			// If the layer is a simple diff, simply mark as stale
			// 如果层是简单差异层，仅标记为陈旧
			layer.lock.Lock()       // 加写锁
			layer.stale.Store(true) // 设置陈旧标志
			layer.lock.Unlock()     // 解锁

		default:
			panic(fmt.Sprintf("unknown layer type: %T", layer)) // 未知层类型，抛出异常
		}
	}
	t.layers = map[common.Hash]snapshot{} // 清空层集合

	// Delete all snapshot liveness information from the database
	// 从数据库中删除所有快照活跃信息
	batch := t.diskdb.NewBatch() // 创建批量写入对象

	rawdb.WriteSnapshotDisabled(batch)        // 写入快照禁用标志
	rawdb.DeleteSnapshotRoot(batch)           // 删除快照根
	rawdb.DeleteSnapshotJournal(batch)        // 删除快照日志
	rawdb.DeleteSnapshotGenerator(batch)      // 删除快照生成器
	rawdb.DeleteSnapshotRecoveryNumber(batch) // 删除快照恢复编号
	// Note, we don't delete the sync progress
	// 注意，不删除同步进度

	if err := batch.Write(); err != nil {
		log.Crit("Failed to disable snapshots", "err", err) // 如果写入失败，记录严重错误
	}
}

// Snapshot retrieves a snapshot belonging to the given block root, or nil if no
// snapshot is maintained for that block.
// Snapshot 检索属于给定块根的快照，如果没有为该块维护快照则返回 nil。
func (t *Tree) Snapshot(blockRoot common.Hash) Snapshot {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	return t.layers[blockRoot] // 返回指定根的快照
}

// Snapshots returns all visited layers from the topmost layer with specific
// root and traverses downward. The layer amount is limited by the given number.
// If nodisk is set, then disk layer is excluded.
// Snapshots 从具有特定根的最顶层开始向下遍历，返回所有访问过的层。层数受给定数量限制。如果设置了 nodisk，则排除磁盘层。
func (t *Tree) Snapshots(root common.Hash, limits int, nodisk bool) []Snapshot {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	if limits == 0 {
		return nil // 如果限制为 0，返回 nil
	}
	layer := t.layers[root] // 获取指定根的层
	if layer == nil {
		return nil // 如果层不存在，返回 nil
	}
	var ret []Snapshot // 初始化返回切片
	for {
		if _, isdisk := layer.(*diskLayer); isdisk && nodisk { // 如果是磁盘层且排除磁盘层
			break // 跳出循环
		}
		ret = append(ret, layer) // 添加当前层到返回切片
		limits -= 1              // 减少限制计数
		if limits == 0 {         // 如果达到限制
			break // 跳出循环
		}
		parent := layer.Parent() // 获取父层
		if parent == nil {       // 如果没有父层
			break // 跳出循环
		}
		layer = parent // 更新当前层为父层
	}
	return ret // 返回快照切片
}

// Update adds a new snapshot into the tree, if that can be linked to an existing
// old parent. It is disallowed to insert a disk layer (the origin of all).
// Update 将新快照添加到树中，如果它可以链接到现有的旧父层。不允许插入磁盘层（所有层的起源）。
func (t *Tree) Update(blockRoot common.Hash, parentRoot common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) error {
	// Reject noop updates to avoid self-loops in the snapshot tree. This is a
	// special case that can only happen for Clique networks where empty blocks
	// don't modify the state (0 block subsidy).
	//
	// Although we could silently ignore this internally, it should be the caller's
	// responsibility to avoid even attempting to insert such a snapshot.
	// 拒绝空更新以避免快照树中的自循环。这是一个特殊情况，仅在 Clique 网络中可能发生，其中空块不会修改状态（0 块补贴）。
	//
	// 虽然我们可以在内部默默忽略这一点，但调用者有责任避免甚至尝试插入这样的快照。
	if blockRoot == parentRoot {
		return errSnapshotCycle // 如果块根等于父根，返回循环错误
	}
	// Generate a new snapshot on top of the parent
	// 在父层之上生成新快照
	parent := t.Snapshot(parentRoot) // 获取父快照
	if parent == nil {
		return fmt.Errorf("parent [%#x] snapshot missing", parentRoot) // 如果父快照缺失，返回错误
	}
	snap := parent.(snapshot).Update(blockRoot, accounts, storage) // 创建新差异层

	// Save the new snapshot for later
	// 保存新快照以供后续使用
	t.lock.Lock()         // 加写锁
	defer t.lock.Unlock() // 延迟解锁

	t.layers[snap.root] = snap // 将新快照添加到层集合
	return nil                 // 返回成功
}

// Cap traverses downwards the snapshot tree from a head block hash until the
// number of allowed layers are crossed. All layers beyond the permitted number
// are flattened downwards.
//
// Note, the final diff layer count in general will be one more than the amount
// requested. This happens because the bottom-most diff layer is the accumulator
// which may or may not overflow and cascade to disk. Since this last layer's
// survival is only known *after* capping, we need to omit it from the count if
// we want to ensure that *at least* the requested number of diff layers remain.
// Cap 从头部块哈希向下遍历快照树，直到超过允许的层数。超出允许数量的所有层将被向下展平。
//
// 注意，最终差异层计数通常比请求的数量多一个。这是因为最底层的差异层是累加器，可能会溢出并级联到磁盘。由于最后一层的存活情况只有在限制后才知道，如果我们想确保至少保留请求的差异层数，则需要从计数中省略它。
func (t *Tree) Cap(root common.Hash, layers int) error {
	// Retrieve the head snapshot to cap from
	// 检索要限制的头部快照
	snap := t.Snapshot(root) // 获取指定根的快照
	if snap == nil {
		return fmt.Errorf("snapshot [%#x] missing", root) // 如果快照缺失，返回错误
	}
	diff, ok := snap.(*diffLayer) // 检查是否为差异层
	if !ok {
		return fmt.Errorf("snapshot [%#x] is disk layer", root) // 如果是磁盘层，返回错误
	}
	// If the generator is still running, use a more aggressive cap
	// 如果生成器仍在运行，使用更激进的限制
	diff.origin.lock.RLock() // 加读锁
	if diff.origin.genMarker != nil && layers > 8 {
		layers = 8 // 如果生成器运行且层数超过 8，限制为 8
	}
	diff.origin.lock.RUnlock() // 解锁

	// Run the internal capping and discard all stale layers
	// 执行内部限制并丢弃所有陈旧层
	t.lock.Lock()         // 加写锁
	defer t.lock.Unlock() // 延迟解锁

	// Flattening the bottom-most diff layer requires special casing since there's
	// no child to rewire to the grandparent. In that case we can fake a temporary
	// child for the capping and then remove it.
	// 展平最底层的差异层需要特殊处理，因为没有子层可以重定向到祖父层。在这种情况下，我们可以为限制伪造一个临时子层，然后移除它。
	if layers == 0 {
		// If full commit was requested, flatten the diffs and merge onto disk
		// 如果请求完全提交，则展平差异并合并到磁盘
		diff.lock.RLock()                               // 加读锁
		base := diffToDisk(diff.flatten().(*diffLayer)) // 展平并转换为磁盘层
		diff.lock.RUnlock()                             // 解锁

		// Replace the entire snapshot tree with the flat base
		// 用展平的基础层替换整个快照树
		t.layers = map[common.Hash]snapshot{base.root: base} // 更新层集合
		return nil                                           // 返回成功
	}
	persisted := t.cap(diff, layers) // 执行限制操作，返回持久化的磁盘层

	// Remove any layer that is stale or links into a stale layer
	// 移除任何陈旧层或链接到陈旧层的层
	children := make(map[common.Hash][]common.Hash) // 创建子层映射
	for root, snap := range t.layers {
		if diff, ok := snap.(*diffLayer); ok {
			parent := diff.parent.Root()                      // 获取父层根
			children[parent] = append(children[parent], root) // 添加子层关系
		}
	}
	var remove func(root common.Hash) // 定义递归移除函数
	remove = func(root common.Hash) {
		delete(t.layers, root)                 // 删除当前层
		for _, child := range children[root] { // 递归移除子层
			remove(child)
		}
		delete(children, root) // 删除子层映射
	}
	for root, snap := range t.layers {
		if snap.Stale() { // 如果层陈旧
			remove(root) // 移除该层及其子层
		}
	}
	// If the disk layer was modified, regenerate all the cumulative blooms
	// 如果磁盘层被修改，重新生成所有累积布隆过滤器
	if persisted != nil {
		var rebloom func(root common.Hash) // 定义递归重建布隆函数
		rebloom = func(root common.Hash) {
			if diff, ok := t.layers[root].(*diffLayer); ok {
				diff.rebloom(persisted) // 重建布隆过滤器
			}
			for _, child := range children[root] { // 递归处理子层
				rebloom(child)
			}
		}
		rebloom(persisted.root) // 从持久化层开始重建
	}
	return nil // 返回成功
}

// cap traverses downwards the diff tree until the number of allowed layers are
// crossed. All diffs beyond the permitted number are flattened downwards. If the
// layer limit is reached, memory cap is also enforced (but not before).
//
// The method returns the new disk layer if diffs were persisted into it.
//
// Note, the final diff layer count in general will be one more than the amount
// requested. This happens because the bottom-most diff layer is the accumulator
// which may or may not overflow and cascade to disk. Since this last layer's
// survival is only known *after* capping, we need to omit it from the count if
// we want to ensure that *at least* the requested number of diff layers remain.
// cap 向下遍历差异树，直到超过允许的层数。超出允许数量的所有差异将被向下展平。如果达到层限制，也会强制执行内存限制（但不是之前）。
//
// 该方法如果差异被持久化到磁盘层，则返回新的磁盘层。
//
// 注意，最终差异层计数通常比请求的数量多一个。这是因为最底层的差异层是累加器，可能会溢出并级联到磁盘。由于最后一层的存活情况只有在限制后才知道，如果我们想确保至少保留请求的差异层数，则需要从计数中省略它。
func (t *Tree) cap(diff *diffLayer, layers int) *diskLayer {
	// Dive until we run out of layers or reach the persistent database
	// 向下遍历直到层耗尽或到达持久化数据库
	for i := 0; i < layers-1; i++ {
		// If we still have diff layers below, continue down
		// 如果下方仍有差异层，继续向下
		if parent, ok := diff.parent.(*diffLayer); ok {
			diff = parent // 更新当前层为父层
		} else {
			// Diff stack too shallow, return without modifications
			// 差异堆栈太浅，无修改返回
			return nil
		}
	}
	// We're out of layers, flatten anything below, stopping if it's the disk or if
	// the memory limit is not yet exceeded.
	// 我们层耗尽，展平下方任何内容，如果是磁盘或内存限制尚未超过则停止。
	switch parent := diff.parent.(type) {
	case *diskLayer:
		return nil // 如果父层是磁盘层，返回 nil

	case *diffLayer:
		// Hold the write lock until the flattened parent is linked correctly.
		// Otherwise, the stale layer may be accessed by external reads in the
		// meantime.
		// 在展平的父层正确链接之前持有写锁。否则，陈旧层可能在此期间被外部读取访问。
		diff.lock.Lock()         // 加写锁
		defer diff.lock.Unlock() // 延迟解锁

		// Flatten the parent into the grandparent. The flattening internally obtains a
		// write lock on grandparent.
		// 将父层展平到祖父层。展平内部会对祖父层获取写锁。
		flattened := parent.flatten().(*diffLayer) // 展平父层
		t.layers[flattened.root] = flattened       // 更新层集合

		// Invoke the hook if it's registered. Ugly hack.
		// 如果钩子已注册，则调用它。丑陋的 hack。
		if t.onFlatten != nil {
			t.onFlatten() // 调用展平钩子
		}
		diff.parent = flattened                       // 更新父层为展平后的层
		if flattened.memory < aggregatorMemoryLimit { // 如果内存小于限制
			// Accumulator layer is smaller than the limit, so we can abort, unless
			// there's a snapshot being generated currently. In that case, the trie
			// will move from underneath the generator so we **must** merge all the
			// partial data down into the snapshot and restart the generation.
			// 累加器层小于限制，因此可以中止，除非当前正在生成快照。在那种情况下，trie 将从生成器下方移动，因此我们必须将所有部分数据合并到快照中并重新开始生成。
			if flattened.parent.(*diskLayer).genAbort == nil {
				return nil // 如果没有生成中止信号，返回 nil
			}
		}
	default:
		panic(fmt.Sprintf("unknown data layer: %T", parent)) // 未知数据层类型，抛出异常
	}
	// If the bottom-most layer is larger than our memory cap, persist to disk
	// 如果最底层大于内存限制，则持久化到磁盘
	bottom := diff.parent.(*diffLayer) // 获取最底层

	bottom.lock.RLock()        // 加读锁
	base := diffToDisk(bottom) // 将差异转换为磁盘层
	bottom.lock.RUnlock()      // 解锁

	t.layers[base.root] = base // 更新层集合
	diff.parent = base         // 更新父层为新磁盘层
	return base                // 返回新磁盘层
}

// diffToDisk merges a bottom-most diff into the persistent disk layer underneath
// it. The method will panic if called onto a non-bottom-most diff layer.
//
// The disk layer persistence should be operated in an atomic way. All updates should
// be discarded if the whole transition if not finished.
// diffToDisk 将最底层的差异合并到其下的持久磁盘层中。如果调用到非最底层的差异层，该方法将抛出异常。
//
// 磁盘层持久化应以原子方式操作。如果整个转换未完成，所有更新都应丢弃。
func diffToDisk(bottom *diffLayer) *diskLayer {
	var (
		base  = bottom.parent.(*diskLayer) // 获取底层磁盘层
		batch = base.diskdb.NewBatch()     // 创建批量写入对象
		stats *generatorStats              // 生成统计对象
	)
	// If the disk layer is running a snapshot generator, abort it
	// 如果磁盘层正在运行快照生成器，中止它
	if base.genAbort != nil {
		abort := make(chan *generatorStats) // 创建中止通道
		base.genAbort <- abort              // 发送中止信号
		stats = <-abort                     // 接收统计数据
	}
	// Put the deletion in the batch writer, flush all updates in the final step.
	// 将删除操作放入批量写入器，在最后一步刷新所有更新。
	rawdb.DeleteSnapshotRoot(batch) // 删除快照根

	// Mark the original base as stale as we're going to create a new wrapper
	// 将原始基础层标记为陈旧，因为我们将创建一个新包装器
	base.lock.Lock() // 加写锁
	if base.stale {
		panic("parent disk layer is stale") // we've committed into the same base from two children, boo
	}
	base.stale = true  // 标记为陈旧
	base.lock.Unlock() // 解锁

	// Push all updated accounts into the database
	// 将所有更新的账户推送到数据库
	for hash, data := range bottom.accountData {
		// Skip any account not covered yet by the snapshot
		// 跳过快照尚未覆盖的任何账户
		if base.genMarker != nil && bytes.Compare(hash[:], base.genMarker) > 0 {
			continue // 如果哈希大于生成标记，跳过
		}
		// Push the account to disk
		// 将账户推送到磁盘
		if len(data) != 0 {
			rawdb.WriteAccountSnapshot(batch, hash, data)         // 写入账户快照
			base.cache.Set(hash[:], data)                         // 更新缓存
			snapshotCleanAccountWriteMeter.Mark(int64(len(data))) // 记录写入数据量
		} else {
			rawdb.DeleteAccountSnapshot(batch, hash) // 删除账户快照
			base.cache.Set(hash[:], nil)             // 更新缓存
		}
		snapshotFlushAccountItemMeter.Mark(1)                // 记录刷新条目数
		snapshotFlushAccountSizeMeter.Mark(int64(len(data))) // 记录刷新数据大小

		// Ensure we don't write too much data blindly. It's ok to flush, the
		// root will go missing in case of a crash and we'll detect and regen
		// the snapshot.
		// 确保我们不会盲目写入过多数据。可以刷新，如果崩溃根将丢失，我们将检测并重新生成快照。
		if batch.ValueSize() > 64*1024*1024 { // 如果批量大小超过 64MB
			if err := batch.Write(); err != nil {
				log.Crit("Failed to write state changes", "err", err) // 如果写入失败，记录严重错误
			}
			batch.Reset() // 重置批量写入器
		}
	}
	// Push all the storage slots into the database
	// 将所有存储槽推送到数据库
	for accountHash, storage := range bottom.storageData {
		// Skip any account not covered yet by the snapshot
		// 跳过快照尚未覆盖的任何账户
		if base.genMarker != nil && bytes.Compare(accountHash[:], base.genMarker) > 0 {
			continue // 如果账户哈希大于生成标记，跳过
		}
		// Generation might be mid-account, track that case too
		// 生成可能在账户中间，也跟踪这种情况
		midAccount := base.genMarker != nil && bytes.Equal(accountHash[:], base.genMarker[:common.HashLength])

		for storageHash, data := range storage {
			// Skip any slot not covered yet by the snapshot
			// 跳过快照尚未覆盖的任何槽
			if midAccount && bytes.Compare(storageHash[:], base.genMarker[common.HashLength:]) > 0 {
				continue // 如果存储哈希大于生成标记后部分，跳过
			}
			if len(data) > 0 {
				rawdb.WriteStorageSnapshot(batch, accountHash, storageHash, data) // 写入存储快照
				base.cache.Set(append(accountHash[:], storageHash[:]...), data)   // 更新缓存
				snapshotCleanStorageWriteMeter.Mark(int64(len(data)))             // 记录写入数据量
			} else {
				rawdb.DeleteStorageSnapshot(batch, accountHash, storageHash)   // 删除存储快照
				base.cache.Set(append(accountHash[:], storageHash[:]...), nil) // 更新缓存
			}
			snapshotFlushStorageItemMeter.Mark(1)                // 记录刷新条目数
			snapshotFlushStorageSizeMeter.Mark(int64(len(data))) // 记录刷新数据大小

			// Ensure we don't write too much data blindly. It's ok to flush, the
			// root will go missing in case of a crash and we'll detect and regen
			// the snapshot.
			// 确保我们不会盲目写入过多数据。可以刷新，如果崩溃根将丢失，我们将检测并重新生成快照。
			if batch.ValueSize() > 64*1024*1024 { // 如果批量大小超过 64MB
				if err := batch.Write(); err != nil {
					log.Crit("Failed to write state changes", "err", err) // 如果写入失败，记录严重错误
				}
				batch.Reset() // 重置批量写入器
			}
		}
	}
	// Update the snapshot block marker and write any remainder data
	// 更新快照块标记并写入任何剩余数据
	rawdb.WriteSnapshotRoot(batch, bottom.root) // 写入快照根

	// Write out the generator progress marker and report
	// 写入生成器进度标记并报告
	journalProgress(batch, base.genMarker, stats) // 日志进度

	// Flush all the updates in the single db operation. Ensure the
	// disk layer transition is atomic.
	// 在单一数据库操作中刷新所有更新。确保磁盘层转换是原子的。
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write leftover snapshot", "err", err) // 如果写入失败，记录严重错误
	}
	log.Debug("Journalled disk layer", "root", bottom.root, "complete", base.genMarker == nil) // 记录调试日志
	res := &diskLayer{
		root:       bottom.root,     // 设置根哈希
		cache:      base.cache,      // 设置缓存
		diskdb:     base.diskdb,     // 设置数据库
		triedb:     base.triedb,     // 设置 trie 数据库
		genMarker:  base.genMarker,  // 设置生成标记
		genPending: base.genPending, // 设置待处理通道
	}
	// If snapshot generation hasn't finished yet, port over all the starts and
	// continue where the previous round left off.
	//
	// Note, the `base.genAbort` comparison is not used normally, it's checked
	// to allow the tests to play with the marker without triggering this path.
	// 如果快照生成尚未完成，则移植所有开始点并从上一轮结束处继续。
	//
	// 注意，`base.genAbort` 比较通常不使用，它被检查以允许测试在不触发此路径的情况下使用标记。
	if base.genMarker != nil && base.genAbort != nil {
		res.genMarker = base.genMarker                 // 设置生成标记
		res.genAbort = make(chan chan *generatorStats) // 创建中止通道
		go res.generate(stats)                         // 启动生成协程
	}
	return res // 返回新磁盘层
}

// Release releases resources
// Release 释放资源
func (t *Tree) Release() {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	if dl := t.disklayer(); dl != nil { // 获取磁盘层并检查是否为空
		dl.Release() // 释放磁盘层资源
	}
}

// Journal commits an entire diff hierarchy to disk into a single journal entry.
// This is meant to be used during shutdown to persist the snapshot without
// flattening everything down (bad for reorgs).
//
// The method returns the root hash of the base layer that needs to be persisted
// to disk as a trie too to allow continuing any pending generation op.
// Journal 将整个差异层次结构提交到磁盘上的单个日志条目中。这旨在关闭时使用，以在不展平所有内容（对重组不利）的情况下持久化快照。
//
// 该方法返回需要作为 trie 持久化到磁盘的基础层的根哈希，以允许继续任何待处理的生成操作。
func (t *Tree) Journal(root common.Hash) (common.Hash, error) {
	// Retrieve the head snapshot to journal from var snap snapshot
	// 检索要记录日志的头部快照
	snap := t.Snapshot(root) // 获取指定根的快照
	if snap == nil {
		return common.Hash{}, fmt.Errorf("snapshot [%#x] missing", root) // 如果快照缺失，返回错误
	}
	// Run the journaling
	// 执行日志记录
	t.lock.Lock()         // 加写锁
	defer t.lock.Unlock() // 延迟解锁

	// Firstly write out the metadata of journal
	// 首先写出日志的元数据
	journal := new(bytes.Buffer)                                       // 创建日志缓冲区
	if err := rlp.Encode(journal, journalCurrentVersion); err != nil { // 编码当前日志版本
		return common.Hash{}, err // 如果编码失败，返回错误
	}
	diskroot := t.diskRoot() // 获取磁盘层根
	if diskroot == (common.Hash{}) {
		return common.Hash{}, errors.New("invalid disk root") // 如果磁盘根无效，返回错误
	}
	// Secondly write out the disk layer root, ensure the
	// diff journal is continuous with disk.
	// 其次写出磁盘层根，确保差异日志与磁盘连续。
	if err := rlp.Encode(journal, diskroot); err != nil { // 编码磁盘根
		return common.Hash{}, err // 如果编码失败，返回错误
	}
	// Finally write out the journal of each layer in reverse order.
	// 最后按逆序写出每层的日志。
	base, err := snap.(snapshot).Journal(journal) // 执行快照日志记录
	if err != nil {
		return common.Hash{}, err // 如果日志记录失败，返回错误
	}
	// Store the journal into the database and return
	// 将日志存储到数据库并返回
	rawdb.WriteSnapshotJournal(t.diskdb, journal.Bytes()) // 写入快照日志
	return base, nil                                      // 返回基础层根哈希
}

// Rebuild wipes all available snapshot data from the persistent database and
// discard all caches and diff layers. Afterwards, it starts a new snapshot
// generator with the given root hash.
// Rebuild 擦除持久数据库中的所有可用快照数据，并丢弃所有缓存和差异层。之后，它以给定的根哈希启动一个新的快照生成器。
func (t *Tree) Rebuild(root common.Hash) {
	t.lock.Lock()         // 加写锁
	defer t.lock.Unlock() // 延迟解锁

	// Firstly delete any recovery flag in the database. Because now we are
	// building a brand new snapshot. Also reenable the snapshot feature.
	// 首先删除数据库中的任何恢复标志。因为现在我们要构建一个全新的快照。同时重新启用快照功能。
	rawdb.DeleteSnapshotRecoveryNumber(t.diskdb) // 删除快照恢复编号
	rawdb.DeleteSnapshotDisabled(t.diskdb)       // 删除快照禁用标志

	// Iterate over and mark all layers stale
	// 遍历并标记所有层为陈旧
	for _, layer := range t.layers {
		switch layer := layer.(type) {
		case *diskLayer:
			// TODO this function will hang if it's called twice. Will
			// fix it in the following PRs.
			// TODO 如果此函数被调用两次会挂起，将在后续 PR 中修复。
			layer.stopGeneration() // 停止生成
			layer.markStale()      // 标记为陈旧
			layer.Release()        // 释放资源

		case *diffLayer:
			// If the layer is a simple diff, simply mark as stale
			// 如果层是简单差异层，仅标记为陈旧
			layer.lock.Lock()       // 加写锁
			layer.stale.Store(true) // 设置陈旧标志
			layer.lock.Unlock()     // 解锁

		default:
			panic(fmt.Sprintf("unknown layer type: %T", layer)) // 未知层类型，抛出异常
		}
	}
	// Start generating a new snapshot from scratch on a background thread. The
	// generator will run a wiper first if there's not one running right now.
	// 在后台线程上从头开始生成新快照。如果当前没有运行擦除器，生成器将首先运行擦除器。
	log.Info("Rebuilding state snapshot") // 记录信息日志
	t.layers = map[common.Hash]snapshot{
		root: generateSnapshot(t.diskdb, t.triedb, t.config.CacheSize, root), // 生成新快照并更新层集合
	}
}

// AccountIterator creates a new account iterator for the specified root hash and
// seeks to a starting account hash.
// AccountIterator 为指定的根哈希创建一个新的账户迭代器，并定位到起始账户哈希。
func (t *Tree) AccountIterator(root common.Hash, seek common.Hash) (AccountIterator, error) {
	ok, err := t.generating() // 检查是否正在生成
	if err != nil {
		return nil, err // 如果检查失败，返回错误
	}
	if ok {
		return nil, ErrNotConstructed // 如果正在生成，返回未构造错误
	}
	return newFastAccountIterator(t, root, seek) // 创建并返回快速账户迭代器
}

// StorageIterator creates a new storage iterator for the specified root hash and
// account. The iterator will be move to the specific start position.
// StorageIterator 为指定的根哈希和账户创建一个新的存储迭代器。迭代器将移动到特定起始位置。
func (t *Tree) StorageIterator(root common.Hash, account common.Hash, seek common.Hash) (StorageIterator, error) {
	ok, err := t.generating() // 检查是否正在生成
	if err != nil {
		return nil, err // 如果检查失败，返回错误
	}
	if ok {
		return nil, ErrNotConstructed // 如果正在生成，返回未构造错误
	}
	return newFastStorageIterator(t, root, account, seek) // 创建并返回快速存储迭代器
}

// Verify iterates the whole state(all the accounts as well as the corresponding storages)
// with the specific root and compares the re-computed hash with the original one.
// Verify 使用特定根迭代整个状态（所有账户及其对应的存储），并将重新计算的哈希与原始哈希进行比较。
func (t *Tree) Verify(root common.Hash) error {
	acctIt, err := t.AccountIterator(root, common.Hash{}) // 创建账户迭代器
	if err != nil {
		return err // 如果创建失败，返回错误
	}
	defer acctIt.Release() // 延迟释放迭代器

	got, err := generateTrieRoot(nil, "", acctIt, common.Hash{}, stackTrieGenerate, func(db ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, error) {
		storageIt, err := t.StorageIterator(root, accountHash, common.Hash{}) // 创建存储迭代器
		if err != nil {
			return common.Hash{}, err // 如果创建失败，返回错误
		}
		defer storageIt.Release() // 延迟释放迭代器

		hash, err := generateTrieRoot(nil, "", storageIt, accountHash, stackTrieGenerate, nil, stat, false) // 生成存储 trie 根
		if err != nil {
			return common.Hash{}, err // 如果生成失败，返回错误
		}
		return hash, nil // 返回存储根哈希
	}, newGenerateStats(), true) // 生成状态 trie 根

	if err != nil {
		return err // 如果生成失败，返回错误
	}
	if got != root {
		return fmt.Errorf("state root hash mismatch: got %x, want %x", got, root) // 如果根哈希不匹配，返回错误
	}
	return nil // 返回成功
}

// disklayer is an internal helper function to return the disk layer.
// The lock of snapTree is assumed to be held already.
// disklayer 是返回磁盘层的内部助手函数。假定 snapTree 的锁已被持有。
func (t *Tree) disklayer() *diskLayer {
	var snap snapshot
	for _, s := range t.layers {
		snap = s // 获取任意一层
		break
	}
	if snap == nil {
		return nil // 如果没有层，返回 nil
	}
	switch layer := snap.(type) {
	case *diskLayer:
		return layer // 如果是磁盘层，直接返回
	case *diffLayer:
		layer.lock.RLock()         // 加读锁
		defer layer.lock.RUnlock() // 延迟解锁
		return layer.origin        // 返回差异层的 origin（磁盘层）
	default:
		panic(fmt.Sprintf("%T: undefined layer", snap)) // 未知层类型，抛出异常
	}
}

// diskRoot is an internal helper function to return the disk layer root.
// The lock of snapTree is assumed to be held already.
// diskRoot 是返回磁盘层根的内部助手函数。假定 snapTree 的锁已被持有。
func (t *Tree) diskRoot() common.Hash {
	disklayer := t.disklayer() // 获取磁盘层
	if disklayer == nil {
		return common.Hash{} // 如果磁盘层为空，返回零哈希
	}
	return disklayer.Root() // 返回磁盘层根哈希
}

// generating is an internal helper function which reports whether the snapshot
// is still under the construction.
// generating 是报告快照是否仍在构建中的内部助手函数。
func (t *Tree) generating() (bool, error) {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	layer := t.disklayer() // 获取磁盘层
	if layer == nil {
		return false, errors.New("disk layer is missing") // 如果磁盘层缺失，返回错误
	}
	layer.lock.RLock()                 // 加读锁
	defer layer.lock.RUnlock()         // 延迟解锁
	return layer.genMarker != nil, nil // 返回是否正在生成
}

// DiskRoot is an external helper function to return the disk layer root.
// DiskRoot 是返回磁盘层根的外部助手函数。
func (t *Tree) DiskRoot() common.Hash {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	return t.diskRoot() // 调用内部函数返回磁盘根
}

// Size returns the memory usage of the diff layers above the disk layer and the
// dirty nodes buffered in the disk layer. Currently, the implementation uses a
// special diff layer (the first) as an aggregator simulating a dirty buffer, so
// the second return will always be 0. However, this will be made consistent with
// the pathdb, which will require a second return.
// Size 返回磁盘层之上差异层的内存使用量和磁盘层中缓冲的脏节点的内存使用量。目前，实现使用特殊差异层（第一个）作为模拟脏缓冲区的累加器，因此第二个返回值始终为 0。然而，这将与 pathdb 保持一致，后者将需要第二个返回值。
func (t *Tree) Size() (diffs common.StorageSize, buf common.StorageSize) {
	t.lock.RLock()         // 加读锁
	defer t.lock.RUnlock() // 延迟解锁

	var size common.StorageSize // 初始化差异层大小
	for _, layer := range t.layers {
		if layer, ok := layer.(*diffLayer); ok {
			size += common.StorageSize(layer.memory) // 累加差异层内存使用量
		}
	}
	return size, 0 // 返回差异层大小和缓冲区大小（当前始终为 0）
}
