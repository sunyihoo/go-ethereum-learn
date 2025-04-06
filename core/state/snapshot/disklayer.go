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
	"bytes"
	"sync"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
)

// 背景知识：状态快照 (State Snapshot)
//
// 在以太坊中，每个区块都包含一个状态根 (state root)，这个状态根是通过对当前以太坊世界状态 (包括所有账户的余额、合约代码、存储等) 进行 Merkle Patricia Trie 计算得到的。为了提高同步速度和减少资源消耗，go-ethereum 引入了状态快照机制。
//
// 状态快照是将某个历史区块的状态完整地保存下来，这样新的节点在同步时，可以直接下载并验证这个快照，而不需要从创世区块开始逐个执行交易。
//
// diskLayer 的作用
//
// diskLayer 是状态快照机制中的一个关键组件。它代表了存储在磁盘上的一个完整的、持久化的状态快照。可以将其理解为一个只读的、不可变的以太坊状态在某个特定区块高度的完整映像。

// Merkle Patricia Trie: 虽然 diskLayer 直接存储扁平化的账户和存储数据，但它与以太坊的状态 Trie 息息相关。diskLayer 的 root 字段就是状态 Trie 的根哈希。在需要验证状态时，triedb 可能会被用来重建部分 Trie 结构。
// RLP (Recursive Length Prefix): 以太坊广泛使用 RLP 编码对数据进行序列化和反序列化，包括账户和存储数据。AccountRLP 方法就直接处理账户的 RLP 编码数据。
// 状态同步: diskLayer 是以太坊快速同步机制的关键组成部分。通过下载和验证 diskLayer，新节点可以快速地获得一个历史状态的快照，而不需要执行所有的历史交易。
// 分层存储: 以太坊的状态是分层存储的。diskLayer 是最底层，代表一个完整的快照。在其之上可以有多个 diffLayer，每个 diffLayer 代表在一个或多个区块执行后状态的变化。这种分层结构使得状态的管理和更新更加高效。
// EIP (Ethereum Improvement Proposals): 虽然这段代码本身并没有直接引用特定的 EIP，但状态快照机制的引入和优化是受到 EIP 启发和指导的，旨在解决以太坊同步慢、存储大的问题。

// diskLayer is a low level persistent snapshot built on top of a key-value store.
// diskLayer 是一个构建在键值存储之上的低级持久化快照。
type diskLayer struct {
	diskdb ethdb.KeyValueStore // Key-value store containing the base snapshot
	// diskdb 是包含基础快照的键值存储。
	triedb *triedb.Database // Trie node cache for reconstruction purposes
	// triedb 是用于重建目的的 Trie 节点缓存。
	cache *fastcache.Cache // Cache to avoid hitting the disk for direct access
	// cache 是一个用于避免直接访问磁盘的缓存。

	root common.Hash // Root hash of the base snapshot
	// root 是基础快照的根哈希。
	stale bool // Signals that the layer became stale (state progressed)
	// stale 标志着该层已过时（状态已进展）。

	genMarker []byte // Marker for the state that's indexed during initial layer generation
	// genMarker 是在初始层生成期间索引的状态标记。
	genPending chan struct{} // Notification channel when generation is done (test synchronicity)
	// genPending 是生成完成时的通知通道（用于测试同步性）。
	genAbort chan chan *generatorStats // Notification channel to abort generating the snapshot in this layer
	// genAbort 是一个通知通道，用于中止在此层中生成快照。

	lock sync.RWMutex
}

// Release releases underlying resources; specifically the fastcache requires
// Reset() in order to not leak memory.
// OBS: It does not invoke Close on the diskdb
// Release 释放底层资源；特别是 fastcache 需要 Reset() 以防止内存泄漏。
// 注意：它不会在 diskdb 上调用 Close。
func (dl *diskLayer) Release() error {
	// Release 方法释放 diskLayer 占用的资源。
	if dl.cache != nil {
		// 如果缓存存在，则重置缓存以释放内存。
		dl.cache.Reset()
	}
	return nil
}

// Root returns  root hash for which this snapshot was made.
// Root 返回创建此快照的根哈希。
func (dl *diskLayer) Root() common.Hash {
	// Root 方法返回 diskLayer 的根哈希值。
	return dl.root
}

// Parent always returns nil as there's no layer below the disk.
// Parent 总是返回 nil，因为在磁盘层之下没有其他层。
func (dl *diskLayer) Parent() snapshot {
	// Parent 方法返回 nil，表示磁盘层是快照的最底层。
	return nil
}

// Stale return whether this layer has become stale (was flattened across) or if
// it's still live.
// Stale 返回此层是否已过时（已被展平）或者是否仍然有效。
func (dl *diskLayer) Stale() bool {
	// Stale 方法检查 diskLayer 是否已过时。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	return dl.stale
}

// markStale sets the stale flag as true.
// markStale 将 stale 标志设置为 true。
func (dl *diskLayer) markStale() {
	// markStale 方法将 diskLayer 标记为过时。
	dl.lock.Lock()
	defer dl.lock.Unlock()

	dl.stale = true
}

// Account directly retrieves the account associated with a particular hash in
// the snapshot slim data format.
// Account 直接检索与特定哈希关联的账户，采用快照精简数据格式。
func (dl *diskLayer) Account(hash common.Hash) (*types.SlimAccount, error) {
	// Account 方法根据给定的哈希从快照中检索账户信息。
	data, err := dl.AccountRLP(hash)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 { // can be both nil and []byte{}
		// 数据长度为 0，表示账户不存在。
		return nil, nil
	}
	account := new(types.SlimAccount)
	if err := rlp.DecodeBytes(data, account); err != nil {
		// 使用 RLP 解码账户数据时发生错误。
		panic(err)
	}
	return account, nil
}

// AccountRLP directly retrieves the account RLP associated with a particular
// hash in the snapshot slim data format.
// AccountRLP 直接检索与特定哈希关联的账户 RLP 数据，采用快照精简数据格式。
func (dl *diskLayer) AccountRLP(hash common.Hash) ([]byte, error) {
	// AccountRLP 方法根据给定的哈希从快照中检索账户的 RLP 编码数据。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	// 如果该层已被展平，则认为其无效（对原始数据的任何活动引用都应标记为不可用）。
	if dl.stale {
		return nil, ErrSnapshotStale
	}
	// If the layer is being generated, ensure the requested hash has already been
	// covered by the generator.
	// 如果该层正在生成中，请确保请求的哈希已被生成器覆盖。
	if dl.genMarker != nil && bytes.Compare(hash[:], dl.genMarker) > 0 {
		return nil, ErrNotCoveredYet
	}
	// If we're in the disk layer, all diff layers missed
	// 如果我们处于磁盘层，则所有差异层都未命中。
	snapshotDirtyAccountMissMeter.Mark(1)

	// Try to retrieve the account from the memory cache
	// 尝试从内存缓存中检索账户。
	if blob, found := dl.cache.HasGet(nil, hash[:]); found {
		// 在缓存中找到账户。
		snapshotCleanAccountHitMeter.Mark(1)
		snapshotCleanAccountReadMeter.Mark(int64(len(blob)))
		return blob, nil
	}
	// Cache doesn't contain account, pull from disk and cache for later
	// 缓存中没有账户，从磁盘读取并缓存以供后续使用。
	blob := rawdb.ReadAccountSnapshot(dl.diskdb, hash)
	dl.cache.Set(hash[:], blob)

	snapshotCleanAccountMissMeter.Mark(1)
	if n := len(blob); n > 0 {
		// 如果从磁盘读取到账户数据，则记录写入缓存的大小。
		snapshotCleanAccountWriteMeter.Mark(int64(n))
	} else {
		// 如果从磁盘读取到的账户数据为空，则记录未找到。
		snapshotCleanAccountInexMeter.Mark(1)
	}
	return blob, nil
}

// Storage directly retrieves the storage data associated with a particular hash,
// within a particular account.
// Storage 直接检索与特定哈希关联的存储数据，该哈希位于特定账户内。
func (dl *diskLayer) Storage(accountHash, storageHash common.Hash) ([]byte, error) {
	// Storage 方法根据给定的账户哈希和存储哈希从快照中检索存储数据。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// If the layer was flattened into, consider it invalid (any live reference to
	// the original should be marked as unusable).
	// 如果该层已被展平，则认为其无效（对原始数据的任何活动引用都应标记为不可用）。
	if dl.stale {
		return nil, ErrSnapshotStale
	}
	key := append(accountHash[:], storageHash[:]...)

	// If the layer is being generated, ensure the requested hash has already been
	// covered by the generator.
	// 如果该层正在生成中，请确保请求的哈希已被生成器覆盖。
	if dl.genMarker != nil && bytes.Compare(key, dl.genMarker) > 0 {
		return nil, ErrNotCoveredYet
	}
	// If we're in the disk layer, all diff layers missed
	// 如果我们处于磁盘层，则所有差异层都未命中。
	snapshotDirtyStorageMissMeter.Mark(1)

	// Try to retrieve the storage slot from the memory cache
	// 尝试从内存缓存中检索存储槽。
	if blob, found := dl.cache.HasGet(nil, key); found {
		// 在缓存中找到存储槽。
		snapshotCleanStorageHitMeter.Mark(1)
		snapshotCleanStorageReadMeter.Mark(int64(len(blob)))
		return blob, nil
	}
	// Cache doesn't contain storage slot, pull from disk and cache for later
	// 缓存中没有存储槽，从磁盘读取并缓存以供后续使用。
	blob := rawdb.ReadStorageSnapshot(dl.diskdb, accountHash, storageHash)
	dl.cache.Set(key, blob)

	snapshotCleanStorageMissMeter.Mark(1)
	if n := len(blob); n > 0 {
		// 如果从磁盘读取到存储数据，则记录写入缓存的大小。
		snapshotCleanStorageWriteMeter.Mark(int64(n))
	} else {
		// 如果从磁盘读取到的存储数据为空，则记录未找到。
		snapshotCleanStorageInexMeter.Mark(1)
	}
	return blob, nil
}

// Update creates a new layer on top of the existing snapshot diff tree with
// the specified data items. Note, the maps are retained by the method to avoid
// copying everything.
// Update 在现有快照差异树的顶部创建一个新层，其中包含指定的数据项。注意，该方法保留了这些 map，以避免复制所有内容。
func (dl *diskLayer) Update(blockHash common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) *diffLayer {
	// Update 方法创建一个新的差异层 (diffLayer)，该层建立在当前磁盘层之上，包含了给定的账户和存储变更。
	return newDiffLayer(dl, blockHash, accounts, storage)
}

// stopGeneration aborts the state snapshot generation if it is currently running.
// stopGeneration 如果状态快照生成当前正在运行，则中止它。
func (dl *diskLayer) stopGeneration() {
	// stopGeneration 方法用于停止当前正在进行的状态快照生成过程。
	dl.lock.RLock()
	generating := dl.genMarker != nil
	dl.lock.RUnlock()
	if !generating {
		// 如果当前没有生成过程在运行，则直接返回。
		return
	}
	if dl.genAbort != nil {
		// 如果存在中止通道，则发送中止信号并等待生成器确认。
		abort := make(chan *generatorStats)
		dl.genAbort <- abort
		<-abort
	}
}
