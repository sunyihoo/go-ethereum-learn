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

package snapshot

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	bloomfilter "github.com/holiman/bloomfilter/v2"
	"golang.org/x/exp/maps"
)

// 主要用于实现以太坊的状态快照（State Snapshot）和差异层（diffLayer）。以太坊的状态存储在 Merkle Patricia Trie（MPT）中，而状态快照是优化后的数据结构，用于加速状态查询和同步。diffLayer 是快照系统中的一个关键组件，表示在某个区块执行后对状态的修改集合。
//
// 以太坊白皮书：白皮书中提到状态树（State Trie）存储所有账户的状态（余额、nonce、代码、存储等）。每次区块处理后，状态会发生变化，而快照系统通过分层设计（磁盘层 + 差异层）来高效管理这些变化。
// 黄皮书：黄皮书定义了状态树的结构和更新规则。diffLayer 的设计与黄皮书中描述的状态更新机制一致，即通过记录增量变化（账户和存储槽的修改）来避免每次都重建整个状态树。
// EIP-2929（Gas Cost Increases for State Access Opcodes）：此 EIP 提高了状态访问的 Gas 成本，促使开发者优化状态查询性能。快照和 diffLayer 的引入正是为了减少对底层 MPT 的直接访问，提升效率。
// 2. 布隆过滤器（Bloom Filter）在代码中的应用
// 代码中大量使用了布隆过滤器（bloomfilter.Filter），用于快速判断某个账户或存储槽是否可能存在于当前层。布隆过滤器的核心思想是：
//
// 使用多个哈希函数将元素映射到位数组中。
// 查询时检查所有相关位是否为 1，若否则元素一定不存在，若是则可能存在（存在误报）。
// 在 diffLayer 中：
//
// bloomSize 和 bloomFuncs 根据目标误报率（bloomTargetError）和最大条目数（aggregatorItemLimit）计算，确保过滤器大小和性能的平衡。
// accountBloomHash 和 storageBloomHash 通过哈希偏移量（bloomAccountHasherOffset 和 bloomStorageHasherOffset）生成 64 位迷你哈希，用于布隆过滤器的键。这种随机偏移的设计避免了所有节点生成相同的布隆行为，增强了去中心化特性。
// 3. diffLayer 的层次设计与状态管理
// diffLayer 是一个分层结构：
//
// 磁盘层（diskLayer）：底层持久化存储，直接访问 MPT。
// 差异层（diffLayer）：内存中的增量修改，堆叠在磁盘层或上一个差异层之上。
// 展平（flatten）：当差异层积累过多时，会向下合并到磁盘层，减少内存占用。
// 这种设计灵感来源于数据库的日志结构合并树（LSM Tree），通过分层管理写操作来优化性能。newDiffLayer 和 Update 方法创建新层，flatten 方法合并层，体现了以太坊对状态更新的动态管理

var (
	// aggregatorMemoryLimit is the maximum size of the bottom-most diff layer
	// that aggregates the writes from above until it's flushed into the disk
	// layer.
	// aggregatorMemoryLimit 是最底层 diff 层的最大大小，该层聚合上层的写入，直到将其刷新到磁盘层。
	//
	// Note, bumping this up might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	// 注意，增加这个值可能会显著增加每个 diff 层中存储的布隆过滤器的大小。在没有完全理解所有影响之前，不要这样做。
	aggregatorMemoryLimit = uint64(4 * 1024 * 1024)

	// aggregatorItemLimit is an approximate number of items that will end up
	// in the aggregator layer before it's flushed out to disk. A plain account
	// weighs around 14B (+hash), a storage slot 32B (+hash), a deleted slot
	// 0B (+hash). Slots are mostly set/unset in lockstep, so that average at
	// 16B (+hash). All in all, the average entry seems to be 15+32=47B. Use a
	// smaller number to be on the safe side.
	// aggregatorItemLimit 是在聚合层被刷新到磁盘之前，大约会结束的条目数量。一个普通账户大约占用 14 字节（+哈希），一个存储槽 32 字节（+哈希），一个删除的槽 0 字节（+哈希）。槽通常是同步设置/取消的，因此平均为 16 字节（+哈希）。总的来说，平均条目似乎是 15+32=47 字节。为安全起见，使用一个较小的数字。
	aggregatorItemLimit = aggregatorMemoryLimit / 42

	// bloomTargetError is the target false positive rate when the aggregator
	// layer is at its fullest. The actual value will probably move around up
	// and down from this number, it's mostly a ballpark figure.
	// bloomTargetError 是聚合层最满时的目标误报率。实际值可能会在这个数字上下波动，这主要是一个大致的数字。
	//
	// Note, dropping this down might drastically increase the size of the bloom
	// filters that's stored in every diff layer. Don't do that without fully
	// understanding all the implications.
	// 注意，降低这个值可能会显著增加每个 diff 层中存储的布隆过滤器的大小。在没有完全理解所有影响之前，不要这样做。
	bloomTargetError = 0.02

	// bloomSize is the ideal bloom filter size given the maximum number of items
	// it's expected to hold and the target false positive error rate.
	// bloomSize 是给定预期容纳的最大条目数和目标误报率时的理想布隆过滤器大小。
	bloomSize = math.Ceil(float64(aggregatorItemLimit) * math.Log(bloomTargetError) / math.Log(1/math.Pow(2, math.Log(2))))

	// bloomFuncs is the ideal number of bits a single entry should set in the
	// bloom filter to keep its size to a minimum (given it's size and maximum
	// entry count).
	// bloomFuncs 是一个条目在布隆过滤器中应设置的理想位数，以保持其大小最小（给定其大小和最大条目数）。
	bloomFuncs = math.Round((bloomSize / float64(aggregatorItemLimit)) * math.Log(2))

	// the bloom offsets are runtime constants which determines which part of the
	// account/storage hash the hasher functions looks at, to determine the
	// bloom key for an account/slot. This is randomized at init(), so that the
	// global population of nodes do not all display the exact same behaviour with
	// regards to bloom content
	// bloom 偏移量是运行时常量，决定了哈希函数查看账户/存储哈希的哪一部分，以确定账户/槽的布隆键。这在 init() 时随机化，以确保全球节点群体在布隆内容方面不会表现出完全相同的行为。
	bloomAccountHasherOffset = 0 // 账户布隆哈希偏移量，初始化为 0
	bloomStorageHasherOffset = 0 // 存储布隆哈希偏移量，初始化为 0
)

func init() {
	// Init the bloom offsets in the range [0:24] (requires 8 bytes)
	// 将布隆偏移量初始化在 [0:24] 范围内（需要 8 字节）。
	bloomAccountHasherOffset = rand.Intn(25) // 随机设置账户布隆哈希偏移量，范围 0-24
	bloomStorageHasherOffset = rand.Intn(25) // 随机设置存储布隆哈希偏移量，范围 0-24
}

// diffLayer represents a collection of modifications made to a state snapshot
// after running a block on top. It contains one sorted list for the account trie
// and one-one list for each storage tries.
// diffLayer 表示在状态快照上运行一个区块后所做的修改集合。它包含一个账户树的排序列表和每个存储树的单独列表。
//
// The goal of a diff layer is to act as a journal, tracking recent modifications
// made to the state, that have not yet graduated into a semi-immutable state.
// diffLayer 的目标是作为一个日志，跟踪最近对状态的修改，这些修改尚未进入半不可变状态。
type diffLayer struct {
	origin *diskLayer // Base disk layer to directly use on bloom misses
	// origin 是基础磁盘层，当布隆过滤器未命中时直接使用。
	parent snapshot // Parent snapshot modified by this one, never nil
	// parent 是被此层修改的父快照，永不为空。
	memory uint64 // Approximate guess as to how much memory we use
	// memory 是我们使用的大约内存量的猜测。

	root common.Hash // Root hash to which this snapshot diff belongs to
	// root 是此快照差异所属的根哈希。
	stale atomic.Bool // Signals that the layer became stale (state progressed)
	// stale 是一个原子布尔值，指示该层是否已变得陈旧（状态已进展）。

	accountData map[common.Hash][]byte // Keyed accounts for direct retrieval (nil means deleted)
	// accountData 是用于直接检索的键控账户数据（nil 表示已删除）。
	storageData map[common.Hash]map[common.Hash][]byte // Keyed storage slots for direct retrieval. one per account (nil means deleted)
	// storageData 是用于直接检索的键控存储槽数据，每个账户一个（nil 表示已删除）。
	accountList []common.Hash // List of account for iteration. If it exists, it's sorted, otherwise it's nil
	// accountList 是用于迭代的账户列表。如果存在，则已排序，否则为 nil。
	storageList map[common.Hash][]common.Hash // List of storage slots for iterated retrievals, one per account. Any existing lists are sorted if non-nil
	// storageList 是用于迭代检索的存储槽列表，每个账户一个。如果存在且非 nil，则已排序。

	diffed *bloomfilter.Filter // Bloom filter tracking all the diffed items up to the disk layer
	// diffed 是一个布隆过滤器，跟踪直到磁盘层的所有差异项。

	lock sync.RWMutex // 读写锁，用于保护 diffLayer 的并发访问
}

// accountBloomHash is used to convert an account hash into a 64 bit mini hash.
// accountBloomHash 用于将账户哈希转换为 64 位迷你哈希。
func accountBloomHash(h common.Hash) uint64 {
	// 从账户哈希中提取指定偏移量开始的 8 字节，并转换为 uint64
	return binary.BigEndian.Uint64(h[bloomAccountHasherOffset : bloomAccountHasherOffset+8])
}

// storageBloomHash is used to convert an account hash and a storage hash into a 64 bit mini hash.
// storageBloomHash 用于将账户哈希和存储哈希转换为 64 位迷你哈希。
func storageBloomHash(h0, h1 common.Hash) uint64 {
	// 对账户哈希和存储哈希的指定偏移量部分进行异或操作，生成 64 位哈希
	return binary.BigEndian.Uint64(h0[bloomStorageHasherOffset:bloomStorageHasherOffset+8]) ^
		binary.BigEndian.Uint64(h1[bloomStorageHasherOffset:bloomStorageHasherOffset+8])
}

// newDiffLayer creates a new diff on top of an existing snapshot, whether that's a low
// level persistent database or a hierarchical diff already.
// newDiffLayer 在现有快照之上创建一个新的 diff 层，无论是低级持久数据库还是已有的层次 diff。
func newDiffLayer(parent snapshot, root common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer {
	// Create the new layer with some pre-allocated data segments
	// 使用一些预分配的数据段创建新层。
	dl := &diffLayer{
		parent:      parent,                              // 设置父快照
		root:        root,                                // 设置根哈希
		accountData: accounts,                            // 设置账户数据
		storageData: storage,                             // 设置存储数据
		storageList: make(map[common.Hash][]common.Hash), // 初始化存储列表
	}
	// 根据父快照类型执行 rebloom 操作
	switch parent := parent.(type) {
	case *diskLayer:
		dl.rebloom(parent) // 如果父层是磁盘层，直接对其进行 rebloom
	case *diffLayer:
		dl.rebloom(parent.origin) // 如果父层是 diff 层，使用其 origin 进行 rebloom
	default:
		panic("unknown parent type") // 未知父类型，抛出异常
	}
	// Sanity check that accounts or storage slots are never nil
	// 健全性检查，确保账户或存储槽不为 nil
	for _, blob := range accounts {
		// Determine memory size and track the dirty writes
		// 确定内存大小并跟踪脏写入
		dl.memory += uint64(common.HashLength + len(blob))    // 更新内存使用量
		snapshotDirtyAccountWriteMeter.Mark(int64(len(blob))) // 记录脏账户写入
	}
	for accountHash, slots := range storage {
		if slots == nil {
			panic(fmt.Sprintf("storage %#x nil", accountHash)) // 如果存储槽为 nil，抛出异常
		}
		// Determine memory size and track the dirty writes
		// 确定内存大小并跟踪脏写入
		for _, data := range slots {
			dl.memory += uint64(common.HashLength + len(data))    // 更新内存使用量
			snapshotDirtyStorageWriteMeter.Mark(int64(len(data))) // 记录脏存储写入
		}
	}
	return dl // 返回新创建的 diffLayer
}

// rebloom discards the layer's current bloom and rebuilds it from scratch based
// on the parent's and the local diffs.
// rebloom 丢弃当前层的布隆过滤器，并根据父层和本地差异从头重建。
func (dl *diffLayer) rebloom(origin *diskLayer) {
	dl.lock.Lock()         // 加写锁
	defer dl.lock.Unlock() // 延迟解锁

	defer func(start time.Time) {
		snapshotBloomIndexTimer.Update(time.Since(start)) // 更新布隆索引计时器
	}(time.Now())

	// Inject the new origin that triggered the rebloom
	// 注入触发 rebloom 的新 origin
	dl.origin = origin

	// Retrieve the parent bloom or create a fresh empty one
	// 检索父布隆过滤器或创建一个新的空过滤器
	if parent, ok := dl.parent.(*diffLayer); ok {
		parent.lock.RLock()                 // 加读锁
		dl.diffed, _ = parent.diffed.Copy() // 复制父层的布隆过滤器
		parent.lock.RUnlock()               // 解锁
	} else {
		dl.diffed, _ = bloomfilter.New(uint64(bloomSize), uint64(bloomFuncs)) // 创建新的布隆过滤器
	}
	// 将本地账户数据添加到布隆过滤器
	for hash := range dl.accountData {
		dl.diffed.AddHash(accountBloomHash(hash))
	}
	// 将本地存储数据添加到布隆过滤器
	for accountHash, slots := range dl.storageData {
		for storageHash := range slots {
			dl.diffed.AddHash(storageBloomHash(accountHash, storageHash))
		}
	}
	// Calculate the current false positive rate and update the error rate meter.
	// This is a bit cheating because subsequent layers will overwrite it, but it
	// should be fine, we're only interested in ballpark figures.
	// 计算当前误报率并更新错误率仪表。这有点作弊，因为后续层会覆盖它，但没关系，我们只关心大致数字。
	k := float64(dl.diffed.K())                                                   // 获取哈希函数数量
	n := float64(dl.diffed.N())                                                   // 获取条目数
	m := float64(dl.diffed.M())                                                   // 获取位数组大小
	snapshotBloomErrorGauge.Update(math.Pow(1.0-math.Exp((-k)*(n+0.5)/(m-1)), k)) // 更新误报率仪表
}

// Root returns the root hash for which this snapshot was made.
// Root 返回为此快照创建的根哈希。
func (dl *diffLayer) Root() common.Hash {
	return dl.root // 直接返回根哈希
}

// Parent returns the subsequent layer of a diff layer.
// Parent 返回 diff 层的后续层。
func (dl *diffLayer) Parent() snapshot {
	dl.lock.RLock()         // 加读锁
	defer dl.lock.RUnlock() // 延迟解锁

	return dl.parent // 返回父快照
}

// Stale return whether this layer has become stale (was flattened across) or if
// it's still live.
// Stale 返回此层是否已变得陈旧（被展平）或是否仍有效。
func (dl *diffLayer) Stale() bool {
	return dl.stale.Load() // 返回陈旧状态
}

// Account directly retrieves the account associated with a particular hash in
// the snapshot slim data format.
// Account 直接检索与特定哈希关联的账户，使用快照瘦数据格式。
func (dl *diffLayer) Account(hash common.Hash) (*types.SlimAccount, error) {
	data, err := dl.AccountRLP(hash) // 获取账户 RLP 数据
	if err != nil {
		return nil, err // 返回错误
	}
	if len(data) == 0 { // can be both nil and []byte{}
		return nil, nil // 如果数据为空，返回 nil
	}
	account := new(types.SlimAccount) // 创建新的 SlimAccount
	if err := rlp.DecodeBytes(data, account); err != nil {
		panic(err) // 解码失败，抛出异常
	}
	return account, nil // 返回解码后的账户
}

// AccountRLP directly retrieves the account RLP associated with a particular
// hash in the snapshot slim data format.
// AccountRLP 直接检索与特定哈希关联的账户 RLP 数据，使用快照瘦数据格式。
//
// Note the returned account is not a copy, please don't modify it.
// 注意，返回的账户不是副本，请勿修改。
func (dl *diffLayer) AccountRLP(hash common.Hash) ([]byte, error) {
	// Check staleness before reaching further.
	// 在进一步操作前检查是否陈旧
	dl.lock.RLock() // 加读锁
	if dl.Stale() {
		dl.lock.RUnlock()
		return nil, ErrSnapshotStale // 如果陈旧，返回错误
	}
	// Check the bloom filter first whether there's even a point in reaching into
	// all the maps in all the layers below
	// 首先检查布隆过滤器，判断是否有必要深入下层的所有映射
	var origin *diskLayer
	hit := dl.diffed.ContainsHash(accountBloomHash(hash)) // 检查布隆过滤器是否命中
	if !hit {
		origin = dl.origin // 如果未命中，提取 origin
	}
	dl.lock.RUnlock() // 解锁

	// If the bloom filter misses, don't even bother with traversing the memory
	// diff layers, reach straight into the bottom persistent disk layer
	// 如果布隆过滤器未命中，不遍历内存 diff 层，直接访问底层持久磁盘层
	if origin != nil {
		snapshotBloomAccountMissMeter.Mark(1) // 记录布隆账户未命中
		return origin.AccountRLP(hash)        // 从磁盘层获取数据
	}
	// The bloom filter hit, start poking in the internal maps
	// 布隆过滤器命中，开始在内部映射中查找
	return dl.accountRLP(hash, 0) // 调用内部方法获取数据
}

// accountRLP is an internal version of AccountRLP that skips the bloom filter
// checks and uses the internal maps to try and retrieve the data. It's meant
// to be used if a higher layer's bloom filter hit already.
// accountRLP 是 AccountRLP 的内部版本，跳过布隆过滤器检查，使用内部映射尝试检索数据。适用于上层布隆过滤器已命中的情况。
func (dl *diffLayer) accountRLP(hash common.Hash, depth int) ([]byte, error) {
	dl.lock.RLock()         // 加读锁
	defer dl.lock.RUnlock() // 延迟解锁

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	// 如果该层被展平，视为无效（任何对原始层的实时引用都应标记为不可用）。
	if dl.Stale() {
		return nil, ErrSnapshotStale // 如果陈旧，返回错误
	}
	// If the account is known locally, return it
	// 如果账户在本地已知，返回它
	if data, ok := dl.accountData[hash]; ok {
		snapshotDirtyAccountHitMeter.Mark(1)                  // 记录脏账户命中
		snapshotDirtyAccountHitDepthHist.Update(int64(depth)) // 更新命中深度
		if n := len(data); n > 0 {
			snapshotDirtyAccountReadMeter.Mark(int64(n)) // 记录读取数据量
		} else {
			snapshotDirtyAccountInexMeter.Mark(1) // 记录不存在的情况
		}
		snapshotBloomAccountTrueHitMeter.Mark(1) // 记录布隆真实命中
		return data, nil                         // 返回数据
	}
	// Account unknown to this diff, resolve from parent
	// 此 diff 未知账户，从父层解析
	if diff, ok := dl.parent.(*diffLayer); ok {
		return diff.accountRLP(hash, depth+1) // 递归调用父层
	}
	// Failed to resolve through diff layers, mark a bloom error and use the disk
	// 通过 diff 层解析失败，标记布隆错误并使用磁盘层
	snapshotBloomAccountFalseHitMeter.Mark(1) // 记录布隆假命中
	return dl.parent.AccountRLP(hash)         // 从父层获取数据
}

// Storage directly retrieves the storage data associated with a particular hash,
// within a particular account. If the slot is unknown to this diff, it's parent
// is consulted.
// Storage 直接检索与特定账户中特定哈希关联的存储数据。如果此 diff 未知该槽，则查询其父层。
//
// Note the returned slot is not a copy, please don't modify it.
// 注意，返回的槽不是副本，请勿修改。
func (dl *diffLayer) Storage(accountHash, storageHash common.Hash) ([]byte, error) {
	// Check the bloom filter first whether there's even a point in reaching into
	// all the maps in all the layers below
	// 首先检查布隆过滤器，判断是否有必要深入下层的所有映射
	dl.lock.RLock() // 加读锁
	// Check staleness before reaching further.
	// 在进一步操作前检查是否陈旧
	if dl.Stale() {
		dl.lock.RUnlock()
		return nil, ErrSnapshotStale // 如果陈旧，返回错误
	}
	var origin *diskLayer
	hit := dl.diffed.ContainsHash(storageBloomHash(accountHash, storageHash)) // 检查布隆过滤器是否命中
	if !hit {
		origin = dl.origin // extract origin while holding the lock 如果未命中，提取 origin
	}
	dl.lock.RUnlock() // 解锁

	// If the bloom filter misses, don't even bother with traversing the memory
	// diff layers, reach straight into the bottom persistent disk layer
	// 如果布隆过滤器未命中，不遍历内存 diff 层，直接访问底层持久磁盘层
	if origin != nil {
		snapshotBloomStorageMissMeter.Mark(1)           // 记录布隆存储未命中
		return origin.Storage(accountHash, storageHash) // 从磁盘层获取数据
	}
	// The bloom filter hit, start poking in the internal maps
	// 布隆过滤器命中，开始在内部映射中查找
	return dl.storage(accountHash, storageHash, 0) // 调用内部方法获取数据
}

// storage is an internal version of Storage that skips the bloom filter checks
// and uses the internal maps to try and retrieve the data. It's meant  to be
// used if a higher layer's bloom filter hit already.
// storage 是 Storage 的内部版本，跳过布隆过滤器检查，使用内部映射尝试检索数据。适用于上层布隆过滤器已命中的情况。
func (dl *diffLayer) storage(accountHash, storageHash common.Hash, depth int) ([]byte, error) {
	dl.lock.RLock()         // 加读锁
	defer dl.lock.RUnlock() // 延迟解锁

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	// 如果该层被展平，视为无效（任何对原始层的实时引用都应标记为不可用）。
	if dl.Stale() {
		return nil, ErrSnapshotStale // 如果陈旧，返回错误
	}
	// If the account is known locally, try to resolve the slot locally
	// 如果账户在本地已知，尝试在本地解析槽
	if storage, ok := dl.storageData[accountHash]; ok {
		if data, ok := storage[storageHash]; ok {
			snapshotDirtyStorageHitMeter.Mark(1)                  // 记录脏存储命中
			snapshotDirtyStorageHitDepthHist.Update(int64(depth)) // 更新命中深度
			if n := len(data); n > 0 {
				snapshotDirtyStorageReadMeter.Mark(int64(n)) // 记录读取数据量
			} else {
				snapshotDirtyStorageInexMeter.Mark(1) // 记录不存在的情况
			}
			snapshotBloomStorageTrueHitMeter.Mark(1) // 记录布隆真实命中
			return data, nil                         // 返回数据
		}
	}
	// Storage slot unknown to this diff, resolve from parent
	// 此 diff 未知存储槽，从父层解析
	if diff, ok := dl.parent.(*diffLayer); ok {
		return diff.storage(accountHash, storageHash, depth+1) // 递归调用父层
	}
	// Failed to resolve through diff layers, mark a bloom error and use the disk
	// 通过 diff 层解析失败，标记布隆错误并使用磁盘层
	snapshotBloomStorageFalseHitMeter.Mark(1)          // 记录布隆假命中
	return dl.parent.Storage(accountHash, storageHash) // 从父层获取数据
}

// Update creates a new layer on top of the existing snapshot diff tree with
// the specified data items.
// Update 在现有快照 diff 树之上使用指定数据项创建一个新层。
func (dl *diffLayer) Update(blockRoot common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer {
	return newDiffLayer(dl, blockRoot, accounts, storage) // 调用 newDiffLayer 创建新层
}

// flatten pushes all data from this point downwards, flattening everything into
// a single diff at the bottom. Since usually the lowermost diff is the largest,
// the flattening builds up from there in reverse.
// flatten 将所有数据从此点向下推送，将所有内容展平到底部的一个 diff 中。由于通常最底层的 diff 是最大的，展平从那里逆向构建。
func (dl *diffLayer) flatten() snapshot {
	// If the parent is not diff, we're the first in line, return unmodified
	// 如果父层不是 diff 层，我们是第一个，直接返回未修改的层
	parent, ok := dl.parent.(*diffLayer)
	if !ok {
		return dl
	}
	// Parent is a diff, flatten it first (note, apart from weird corned cases,
	// flatten will realistically only ever merge 1 layer, so there's no need to
	// be smarter about grouping flattens together).
	// 父层是 diff 层，先展平它（注意，除了特殊情况，展平实际上只会合并一层，因此无需更智能地分组展平）。
	parent = parent.flatten().(*diffLayer)

	parent.lock.Lock()         // 加写锁
	defer parent.lock.Unlock() // 延迟解锁

	// Before actually writing all our data to the parent, first ensure that the
	// parent hasn't been 'corrupted' by someone else already flattening into it
	// 在将所有数据写入父层之前，首先确保父层未被其他人展平而“损坏”
	if parent.stale.Swap(true) {
		panic("parent diff layer is stale") // we've flattened into the same parent from two children, boo 如果父层已陈旧，抛出异常
	}
	// 将当前层的账户数据写入父层
	for hash, data := range dl.accountData {
		parent.accountData[hash] = data
	}
	// Overwrite all the updated storage slots (individually)
	// 逐个覆盖所有更新的存储槽
	for accountHash, storage := range dl.storageData {
		// If storage didn't exist (or was deleted) in the parent, overwrite blindly
		// 如果父层中存储不存在（或已删除），直接覆盖
		if _, ok := parent.storageData[accountHash]; !ok {
			parent.storageData[accountHash] = storage
			continue
		}
		// Storage exists in both parent and child, merge the slots
		// 父层和子层中存储都存在，合并槽
		maps.Copy(parent.storageData[accountHash], storage)
	}
	// Return the combo parent
	// 返回合并后的父层
	return &diffLayer{
		parent:      parent.parent,                       // 设置父快照
		origin:      parent.origin,                       // 设置 origin
		root:        dl.root,                             // 设置根哈希
		accountData: parent.accountData,                  // 设置账户数据
		storageData: parent.storageData,                  // 设置存储数据
		storageList: make(map[common.Hash][]common.Hash), // 初始化存储列表
		diffed:      dl.diffed,                           // 设置布隆过滤器
		memory:      parent.memory + dl.memory,           // 更新内存使用量
	}
}

// AccountList returns a sorted list of all accounts in this diffLayer, including
// the deleted ones.
// AccountList 返回此 diffLayer 中所有账户的排序列表，包括已删除的账户。
//
// Note, the returned slice is not a copy, so do not modify it.
// 注意，返回的切片不是副本，请勿修改。
func (dl *diffLayer) AccountList() []common.Hash {
	// If an old list already exists, return it
	// 如果已存在旧列表，返回它
	dl.lock.RLock() // 加读锁
	list := dl.accountList
	dl.lock.RUnlock() // 解锁

	if list != nil {
		return list // 返回现有列表
	}
	// No old sorted account list exists, generate a new one
	// 不存在旧的排序账户列表，生成一个新的
	dl.lock.Lock()         // 加写锁
	defer dl.lock.Unlock() // 延迟解锁

	dl.accountList = maps.Keys(dl.accountData)                   // 获取账户数据的键
	slices.SortFunc(dl.accountList, common.Hash.Cmp)             // 按哈希排序
	dl.memory += uint64(len(dl.accountList) * common.HashLength) // 更新内存使用量
	return dl.accountList                                        // 返回新列表
}

// StorageList returns a sorted list of all storage slot hashes in this diffLayer
// for the given account. If the whole storage is destructed in this layer, then
// an additional flag *destructed = true* will be returned, otherwise the flag is
// false. Besides, the returned list will include the hash of deleted storage slot.
// Note a special case is an account is deleted in a prior tx but is recreated in
// the following tx with some storage slots set. In this case the returned list is
// not empty but the flag is true.
// StorageList 返回此 diffLayer 中给定账户的所有存储槽哈希的排序列表。如果此层中整个存储被销毁，则返回附加标志 *destructed = true*，否则标志为 false。此外，返回的列表将包括已删除存储槽的哈希。注意一种特殊情况：账户在之前的交易中被删除，但在后续交易中重新创建并设置了一些存储槽，此时返回的列表不为空，但标志为 true。
//
// Note, the returned slice is not a copy, so do not modify it.
// 注意，返回的切片不是副本，请勿修改。
func (dl *diffLayer) StorageList(accountHash common.Hash) []common.Hash {
	dl.lock.RLock() // 加读锁
	if _, ok := dl.storageData[accountHash]; !ok {
		// Account not tracked by this layer
		// 此层未跟踪账户
		dl.lock.RUnlock()
		return nil // 返回 nil
	}
	// If an old list already exists, return it
	// 如果已存在旧列表，返回它
	if list, exist := dl.storageList[accountHash]; exist {
		dl.lock.RUnlock()
		return list // the cached list can't be nil 返回缓存列表（不会为 nil）
	}
	dl.lock.RUnlock() // 解锁

	// No old sorted account list exists, generate a new one
	// 不存在旧的排序账户列表，生成一个新的
	dl.lock.Lock()         // 加写锁
	defer dl.lock.Unlock() // 延迟解锁

	storageList := maps.Keys(dl.storageData[accountHash])                          // 获取存储数据的键
	slices.SortFunc(storageList, common.Hash.Cmp)                                  // 按哈希排序
	dl.storageList[accountHash] = storageList                                      // 缓存列表
	dl.memory += uint64(len(dl.storageList)*common.HashLength + common.HashLength) // 更新内存使用量
	return storageList                                                             // 返回新列表
}
