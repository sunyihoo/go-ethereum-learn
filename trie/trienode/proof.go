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

package trienode

import (
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

// 在以太坊中，trie.Database 是一个接口，用于抽象 Trie 节点的存储和检索，通常由持久化数据库（如 LevelDB）实现。
// ProofSet 实现此接口，表明它可以作为内存中的节点存储，适用于临时数据或缓存。

// 证明集合（Proof Set）:
// 在以太坊中，证明集合通常用于生成 Merkle 证明（Merkle Proof），以验证某个键值对是否存在于 Trie 中。
// ProofSet 的设计（键值映射 + 顺序记录）适合收集构建证明所需的节点，例如状态证明或交易证明。

// Merkle 证明生成:
// 收集 Trie 路径上的节点，构建状态或交易的证明。

// ProofSet stores a set of trie nodes. It implements trie.Database and can also
// act as a cache for another trie.Database.
// ProofSet 存储一组 trie 节点。它实现了 trie.Database 接口，并且还可以作为另一个 trie.Database 的缓存。
// 实现 trie.Database 接口，作为 Trie 节点的内存存储或缓存。
type ProofSet struct {
	nodes map[string][]byte // 以字符串（路径或哈希）为键，存储节点的编码数据（[]byte）。key 通常是节点的哈希（如 Keccak-256），value 是 RLP 编码的节点内容。
	order []string          // 记录节点的插入顺序，可能是键的列表。

	dataSize int          // 表示存储的数据总大小（字节数），用于统计或限制。
	lock     sync.RWMutex // 读写锁，用于保护 nodes 和其他字段的并发访问。
}

// NewProofSet creates an empty node set
// NewProofSet 创建一个空的节点集合
func NewProofSet() *ProofSet {
	return &ProofSet{
		nodes: make(map[string][]byte),
	}
}

// Put stores a new node in the set
// Put 将一个新节点存储到集合中
// 添加新节点到集合，更新统计信息。
// 表明 ProofSet 更适合临时缓存或一次性证明收集，而非动态数据库。
func (db *ProofSet) Put(key []byte, value []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// 检查 key 是否已存在，若存在则直接返回（不覆盖）。
	if _, ok := db.nodes[string(key)]; ok {
		return nil
	}
	keystr := string(key)

	// 将 key 转为字符串，存储副本值（common.CopyBytes(value)）到 nodes。
	db.nodes[keystr] = common.CopyBytes(value)
	// 将 key 添加到 order 切片，记录插入顺序。
	db.order = append(db.order, keystr)
	// 累加 dataSize 为 value 的长度。
	db.dataSize += len(value)

	return nil
}

// Delete removes a node from the set
// Delete 从集合中移除一个节点
func (db *ProofSet) Delete(key []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	delete(db.nodes, string(key))
	return nil
}

// DeleteRange 表明 ProofSet 不支持批量删除。
func (db *ProofSet) DeleteRange(start, end []byte) error {
	panic("not supported")
}

// Get returns a stored node
// Get 返回存储的节点
func (db *ProofSet) Get(key []byte) ([]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	// 检查 key 是否存在于 nodes
	if entry, ok := db.nodes[string(key)]; ok {
		return entry, nil
	}
	return nil, errors.New("not found")
}

// Has returns true if the node set contains the given key
// Has 返回 true 如果节点集合包含给定的键
func (db *ProofSet) Has(key []byte) (bool, error) {
	_, err := db.Get(key)
	return err == nil, nil
}

// KeyCount returns the number of nodes in the set
// KeyCount 返回集合中的节点数量
func (db *ProofSet) KeyCount() int {
	db.lock.RLock()
	defer db.lock.RUnlock()

	return len(db.nodes)
}

// DataSize returns the aggregated data size of nodes in the set
// DataSize 返回集合中节点的总数据大小
func (db *ProofSet) DataSize() int {
	db.lock.RLock()
	defer db.lock.RUnlock()

	return db.dataSize
}

// List converts the node set to a slice of bytes.
// List 将节点集合转换为字节切片
// 将节点数据按插入顺序导出为字节数组。
func (db *ProofSet) List() [][]byte {
	db.lock.RLock()
	defer db.lock.RUnlock()

	values := make([][]byte, len(db.order))
	for i, key := range db.order {
		values[i] = db.nodes[key]
	}
	return values
}

// Store writes the contents of the set to the given database
// Store 将集合的内容写入给定的数据库
// 将内存中的节点集合持久化到外部数据库。
func (db *ProofSet) Store(target ethdb.KeyValueWriter) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	for key, value := range db.nodes {
		target.Put([]byte(key), value)
	}
}

// ProofList stores an ordered list of trie nodes. It implements ethdb.KeyValueWriter.
// ProofList 存储一个有序的 trie 节点列表。它实现了 ethdb.KeyValueWriter 接口。
//
// ProofList 设计为有序列表，适用于生成 Merkle 证明时按路径顺序收集节点。Store 将其写入数据库，Set 转换为更灵活的 ProofSet。
type ProofList []rlp.RawValue

// Store writes the contents of the list to the given database
// Store 将列表的内容写入给定的数据库
// 将列表内容持久化，键为节点内容的哈希。
func (n ProofList) Store(db ethdb.KeyValueWriter) {
	for _, node := range n {
		db.Put(crypto.Keccak256(node), node)
	}
}

// Set converts the node list to a ProofSet
// Set 将节点列表转换为 ProofSet
// 将 ProofList 转换为 ProofSet 格式。
func (n ProofList) Set() *ProofSet {
	db := NewProofSet()
	n.Store(db)
	return db
}

// Put stores a new node at the end of the list
// Put 在列表末尾存储一个新节点
func (n *ProofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

// Delete panics as there's no reason to remove a node from the list.
// Delete 抛出异常，因为没有理由从列表中移除节点。
func (n *ProofList) Delete(key []byte) error {
	panic("not supported")
}

// DataSize returns the aggregated data size of nodes in the list
// DataSize 返回列表中节点的总数据大小
func (n ProofList) DataSize() int {
	var size int
	for _, node := range n {
		size += len(node)
	}
	return size
}
