// Copyright 2022 The go-ethereum Authors
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

package triedb

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// Merkle-Patricia Trie: 以太坊的状态（账户状态、存储状态）存储在 Merkle-Patricia Trie 这种数据结构中。Trie 的每个节点都通过其哈希值来引用。
// 节点哈希与原始数据: 在某些操作中，例如在验证 Merkle 证明时，需要知道一个节点哈希对应的原始数据内容（即 preimage）。
// 性能优化: 从磁盘读取数据通常比从内存读取要慢得多。preimageStore 通过在内存中缓存经常访问的 preimage，可以显著提高需要这些原始数据的操作的性能。
// rawdb 包: rawdb 包在 go-ethereum 中负责直接与底层数据库进行交互，包括读取和写入 preimage 数据。
// 内存管理: commit 方法中基于大小的刷新策略是一种常见的内存管理技术，用于防止缓存无限增长导致内存耗尽。定期将缓存的数据写入磁盘，可以释放内存空间。

// preimageStore is the store for caching preimages of node key.
// preimageStore 是用于缓存节点键 preimage 的存储。
type preimageStore struct {
	lock sync.RWMutex
	// 用于保护并发访问的读写锁。
	disk ethdb.KeyValueStore
	// 底层用于持久化存储的键值存储（例如 LevelDB 或 RocksDB）。
	preimages map[common.Hash][]byte // Preimages of nodes from the secure trie
	// 安全 trie 中节点的 preimage，键是节点的哈希，值是原始数据。
	preimagesSize common.StorageSize // Storage size of the preimages cache
	// preimage 缓存的存储大小。
}

// newPreimageStore initializes the store for caching preimages.
// newPreimageStore 初始化用于缓存 preimage 的存储。
func newPreimageStore(disk ethdb.KeyValueStore) *preimageStore {
	return &preimageStore{
		disk:      disk,
		preimages: make(map[common.Hash][]byte),
	}
}

// insertPreimage writes a new trie node pre-image to the memory database if it's
// yet unknown. The method will NOT make a copy of the slice, only use if the
// preimage will NOT be changed later on.
// insertPreimage 如果内存数据库中还不存在，则将新的 trie 节点 preimage 写入内存数据库。
// 此方法不会复制切片，只有在 preimage 之后不会更改的情况下才使用。
func (store *preimageStore) insertPreimage(preimages map[common.Hash][]byte) {
	store.lock.Lock()
	defer store.lock.Unlock()

	for hash, preimage := range preimages {
		if _, ok := store.preimages[hash]; ok {
			continue
		}
		store.preimages[hash] = preimage
		store.preimagesSize += common.StorageSize(common.HashLength + len(preimage))
	}
}

// preimage retrieves a cached trie node pre-image from memory. If it cannot be
// found cached, the method queries the persistent database for the content.
// preimage 从内存中检索缓存的 trie 节点 preimage。如果在缓存中找不到，该方法会查询持久化数据库以获取内容。
func (store *preimageStore) preimage(hash common.Hash) []byte {
	store.lock.RLock()
	preimage := store.preimages[hash]
	store.lock.RUnlock()

	if preimage != nil {
		return preimage
	}
	return rawdb.ReadPreimage(store.disk, hash)
}

// commit flushes the cached preimages into the disk.
// commit 将缓存的 preimage 刷新到磁盘。
func (store *preimageStore) commit(force bool) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if store.preimagesSize <= 4*1024*1024 && !force {
		return nil
	}
	batch := store.disk.NewBatch()
	rawdb.WritePreimages(batch, store.preimages)
	if err := batch.Write(); err != nil {
		return err
	}
	store.preimages, store.preimagesSize = make(map[common.Hash][]byte), 0
	return nil
}

// size returns the current storage size of accumulated preimages.
// size 返回当前累积的 preimage 的存储大小。
func (store *preimageStore) size() common.StorageSize {
	store.lock.RLock()
	defer store.lock.RUnlock()

	return store.preimagesSize
}
