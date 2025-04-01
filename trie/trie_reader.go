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

package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// trieReader is a wrapper of the underlying node reader. It's not safe
// for concurrent usage.
// trieReader 是底层节点读取器的包装器。它不适合并发使用。
// 用于读取 Merkle Patricia Trie（MPT）节点的一个包装器。
type trieReader struct {
	owner  common.Hash         // 表示 trie 的所有者或标识符，通常是状态根哈希，用于标识特定的状态树。
	reader database.NodeReader // 用于从数据库中读取 trie 节点数据。
	banned map[string]struct{} // Marker to prevent node from being accessed, for tests. 用于标记禁止访问的节点（键是字符串，值是空结构体）。用于测试
}

// newTrieReader initializes the trie reader with the given node reader.
// newTrieReader 使用给定的节点读取器初始化 trie 读取器。
//
// stateRoot common.Hash：状态根哈希，标识目标状态树。stateRoot 是 MPT 的根哈希，标识某一时刻的全局状态。空状态根（EmptyRootHash）表示没有任何账户或存储数据的状态树，通常是创世块的状态。
// owner common.Hash：trie 的所有者标识，通常与状态根一致或为空。
// db database.NodeDatabase：状态数据库接口，提供节点读取器。db 是 NodeDatabase 接口的实例，负责根据状态根提供 NodeReader。它连接底层存储（如 LevelDB），加载 trie 节点数据。
func newTrieReader(stateRoot, owner common.Hash, db database.NodeDatabase) (*trieReader, error) {
	if stateRoot == (common.Hash{}) || stateRoot == types.EmptyRootHash { // 检查 stateRoot 是否为空或等于空状态根（types.EmptyRootHash）
		return &trieReader{owner: owner}, nil
	}
	reader, err := db.NodeReader(stateRoot) // 获取状态树的节点读取器
	if err != nil {
		return nil, &MissingNodeError{Owner: owner, NodeHash: stateRoot, err: err}
	}
	return &trieReader{owner: owner, reader: reader}, nil
}

// newEmptyReader initializes the pure in-memory reader. All read operations
// should be forbidden and returns the MissingNodeError.
// newEmptyReader 初始化纯内存读取器。所有读取操作都应被禁止，并返回 MissingNodeError。
func newEmptyReader() *trieReader {
	return &trieReader{}
}

// MPT 是以太坊的状态存储结构，node 方法用于检索其中的节点数据（shortNode、fullNode 或 leafNode）。

// node retrieves the rlp-encoded trie node with the provided trie node
// information. An MissingNodeError will be returned in case the node is
// not found or any error is encountered.
//
// Don't modify the returned byte slice since it's not deep-copied and
// still be referenced by database.
//
// node 使用提供的 trie 节点信息检索 RLP 编码的 trie 节点。如果节点未找到或遇到任何错误，将返回 MissingNodeError。
//
// 不要修改返回的字节切片，因为它没有被深拷贝，仍被数据库引用。
func (r *trieReader) node(path []byte, hash common.Hash) ([]byte, error) {
	// Perform the logics in tests for preventing trie node access.
	// 执行测试逻辑以防止访问 trie 节点
	if r.banned != nil {
		if _, ok := r.banned[string(path)]; ok {
			return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
		}
	}
	if r.reader == nil {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path}
	}
	blob, err := r.reader.Node(r.owner, path, hash)
	if err != nil || len(blob) == 0 {
		return nil, &MissingNodeError{Owner: r.owner, NodeHash: hash, Path: path, err: err}
	}
	return blob, nil
}
