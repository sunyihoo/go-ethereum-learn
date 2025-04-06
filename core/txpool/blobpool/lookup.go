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

package blobpool

import (
	"github.com/ethereum/go-ethereum/common"
)

// lookup maps blob versioned hashes to transaction hashes that include them,
// and transaction hashes to billy entries that include them.
// lookup 将 Blob 版本化哈希映射到包含它们的交易哈希，并将交易哈希映射到包含它们的 billy 条目。
type lookup struct {
	blobIndex map[common.Hash]map[common.Hash]struct{} // Maps blob versioned hash to a set of transaction hashes.
	// blobIndex 将 Blob 版本化哈希映射到包含该 Blob 的交易哈希集合。
	txIndex map[common.Hash]uint64 // Maps transaction hash to a datastore storage item id.
	// txIndex 将交易哈希映射到数据存储的条目 ID。
}

// newLookup creates a new index for tracking blob to tx; and tx to billy mappings.
// newLookup 创建一个新的索引，用于跟踪 Blob 到交易以及交易到 billy 映射。
func newLookup() *lookup {
	return &lookup{
		blobIndex: make(map[common.Hash]map[common.Hash]struct{}),
		txIndex:   make(map[common.Hash]uint64),
	}
}

// exists returns whether a transaction is already tracked or not.
// exists 返回一个交易是否已经被跟踪。
func (l *lookup) exists(txhash common.Hash) bool {
	_, exists := l.txIndex[txhash] // Check if the transaction hash exists in the txIndex.
	// 检查交易哈希是否存在于 txIndex 中。
	return exists
}

// storeidOfTx returns the datastore storage item id of a transaction.
// storeidOfTx 返回一个交易的数据存储条目 ID。
func (l *lookup) storeidOfTx(txhash common.Hash) (uint64, bool) {
	id, ok := l.txIndex[txhash] // Retrieve the storage ID associated with the transaction hash.
	// 检索与交易哈希关联的存储 ID。
	return id, ok
}

// storeidOfBlob returns the datastore storage item id of a blob.
// storeidOfBlob 返回一个 Blob 的数据存储条目 ID。
func (l *lookup) storeidOfBlob(vhash common.Hash) (uint64, bool) {
	// If the blob is unknown, return a miss
	// 如果 Blob 未知，则返回未命中。
	txs, ok := l.blobIndex[vhash] // Check if the blob versioned hash exists in the blobIndex.
	// 检查 Blob 版本化哈希是否存在于 blobIndex 中。
	if !ok {
		return 0, false
	}
	// If the blob is known, return any tx for it
	// 如果 Blob 已知，则返回它的任意一个交易的存储 ID。
	for tx := range txs {
		id, ok := l.storeidOfTx(tx) // Retrieve the storage ID of a transaction that includes this blob.
		// 检索包含此 Blob 的交易的存储 ID。
		return id, ok
	}
	return 0, false // Weird, don't choke
	// 奇怪的情况，不要阻塞。
}

// track inserts a new set of mappings from blob versioned hashes to transaction
// hashes; and from transaction hashes to datastore storage item ids.
// track 插入一组新的映射，从 Blob 版本化哈希到交易哈希，以及从交易哈希到数据存储条目 ID。
func (l *lookup) track(tx *blobTxMeta) {
	// Map all the blobs to the transaction hash
	// 将所有 Blob 映射到交易哈希。
	for _, vhash := range tx.vhashes {
		if _, ok := l.blobIndex[vhash]; !ok {
			l.blobIndex[vhash] = make(map[common.Hash]struct{}) // Initialize a set for the transaction hashes if the blob hash is new.
			// 如果 Blob 哈希是新的，则初始化一个用于存储交易哈希的集合。
		}
		l.blobIndex[vhash][tx.hash] = struct{}{} // may be double mapped if a tx contains the same blob twice
		// 如果一个交易包含同一个 Blob 两次，可能会被重复映射。
	}
	// Map the transaction hash to the datastore id
	// 将交易哈希映射到数据存储 ID。
	l.txIndex[tx.hash] = tx.id
}

// untrack removes a set of mappings from blob versioned hashes to transaction
// hashes from the blob index.
// untrack 从 Blob 索引中移除一组从 Blob 版本化哈希到交易哈希的映射。
func (l *lookup) untrack(tx *blobTxMeta) {
	// Unmap the transaction hash from the datastore id
	// 从数据存储 ID 中取消映射交易哈希。
	delete(l.txIndex, tx.hash)

	// Unmap all the blobs from the transaction hash
	// 从交易哈希中取消映射所有 Blob。
	for _, vhash := range tx.vhashes {
		delete(l.blobIndex[vhash], tx.hash) // may be double deleted if a tx contains the same blob twice
		// 如果一个交易包含同一个 Blob 两次，可能会被重复删除。
		if len(l.blobIndex[vhash]) == 0 {
			delete(l.blobIndex, vhash) // Remove the blob hash entry if no transactions are associated with it anymore.
			// 如果不再有任何交易与该 Blob 哈希关联，则移除该 Blob 哈希条目。
		}
	}
}
