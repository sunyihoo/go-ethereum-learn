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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package trie

import "github.com/ethereum/go-ethereum/common"

// 状态树访问：StateTrieID 用于全局状态查询。
// 存储树访问：StorageTrieID 用于合约数据查询。
// 测试与调试：TrieID 用于模拟或非标准 trie。

// 状态树（State Trie）：
//   以太坊使用 MPT 存储全局状态，StateRoot 是状态树的根哈希，存储在区块头中，表示所有账户的状态。
// 存储树（Storage Trie）：
//   每个合约账户拥有一个独立的 MPT，称为存储树，Owner 是合约地址的哈希，Root 是存储树的根哈希。

// ID is the identifier for uniquely identifying a trie.
// ID 是用于唯一标识 trie 的标识符。
type ID struct {
	StateRoot common.Hash // The root of the corresponding state(block.root)      对应状态的根（区块根），通常是区块头中的状态根（state root），标识全局状态。
	Owner     common.Hash // The contract address hash which the trie belongs to  trie 所属的合约地址哈希。对于存储 trie，表示合约账户；对于状态 trie，通常为空。
	Root      common.Hash // The root hash of trie							   // trie 的根哈希。trie 自身的根哈希，对于状态 trie，通常与 StateRoot 相同；对于存储 trie，是存储树的根。
}

// StateTrieID constructs an identifier for state trie with the provided state root.
// StateTrieID 使用提供的状态根构造状态 trie 的标识符。
// StateTrieID 用于标识全局状态树，StateRoot 和 Root 相同，Owner 为空，表示它不隶属于任何合约。
// 例如：查询某一区块的全局状态，例如账户余额或 nonce。
func StateTrieID(root common.Hash) *ID {
	return &ID{
		StateRoot: root,
		Owner:     common.Hash{}, // 表示此 trie 不属于特定合约，而是全局状态树。
		Root:      root,
	}
}

// 存储树：
// 存储树是合约账户的一部分，Owner 是合约地址的 Keccak-256 哈希，Root 是存储树的根哈希，存储在状态树中该账户的 Root 字段。
// StateRoot 提供上下文，表示此存储树属于某个全局状态。

// StorageTrieID constructs an identifier for storage trie which belongs to a certain
// state and contract specified by the stateRoot and owner.
// StorageTrieID 构造属于特定状态和合约的存储 trie 的标识符，由 stateRoot 和 owner 指定。
func StorageTrieID(stateRoot common.Hash, owner common.Hash, root common.Hash) *ID {
	return &ID{
		StateRoot: stateRoot, // 全局状态根。
		Owner:     owner,     // 合约地址哈希。
		Root:      root,      // 存储树根哈希。
	}
}

// 标准 trie：
//   TrieID 用于非第二层 trie（如状态树或存储树）的其他 trie，例如 CHT（Canonical Hash Trie，用于区块头存储）。
//   注释提到“测试和其他 trie”，表明它是通用标识符。
// CHT trie：
//   CHT 是以太坊轻客户端使用的结构，存储历史区块头的哈希，TrieID 可用于标识此类 trie。

// TrieID constructs an identifier for a standard trie(not a second-layer trie)
// with provided root. It's mostly used in tests and some other tries like CHT trie.
// TrieID 使用提供的根构造标准 trie（非第二层 trie）的标识符。主要用于测试和其他 trie，如 CHT trie。
func TrieID(root common.Hash) *ID {
	return &ID{
		StateRoot: root,
		Owner:     common.Hash{},
		Root:      root,
	}
}
