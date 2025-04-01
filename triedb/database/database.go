// Copyright 2024 The go-ethereum Authors
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

package database

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// 状态根（State Root）：
// owner common.Hash 参数通常是状态树的根哈希，标识特定的 trie 实例。以太坊的每个区块都有一个状态根，代表该区块的全局状态。
// 节点路径（Path）：
// MPT 使用键（通常是账户地址或存储槽的哈希）的紧凑编码形式作为路径。path []byte 表示从根节点到目标节点的导航路径，基于十六进制字符（0-f）。

// NodeReader wraps the Node method of a backing trie reader.
// NodeReader 封装了底层 trie 读取器的 Node 方法。
// 用于从以太坊的 Merkle Patricia Trie（MPT）中读取节点数据，通常用于访问底层数据库中的状态树节点。
type NodeReader interface {
	// Node retrieves the trie node blob with the provided trie identifier,
	// node path and the corresponding node hash. No error will be returned
	// if the node is not found.
	//
	// Don't modify the returned byte slice since it's not deep-copied and
	// still be referenced by database.
	//
	// Node 使用提供的 trie 标识符、节点路径和对应的节点哈希检索 trie 节点数据 blob。如果节点未找到，不会返回错误。
	//
	// 不要修改返回的字节切片，因为它没有被深拷贝，仍被数据库引用。
	//
	// owner common.Hash：trie 的标识符，通常是状态根哈希或某个子树的根哈希。用于标识 trie 的根或节点。
	// path []byte：节点路径，MPT 中键的字节表示，用于定位特定节点。MPT 中的路径，通常是键的紧凑编码形式，表示从根到目标节点的路径。
	// hash common.Hash：节点的哈希值，用于验证和检索。
	Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error)
}

// MPT 是以太坊的状态存储结构，每个状态树由一个状态根（stateRoot）标识。状态根存储在区块头中，代表该区块的账户状态、合约存储等数据的 Merkle 根。
// NodeDatabase 是访问 MPT 的数据库层接口，负责从底层存储（如 LevelDB）中加载特定状态树。
//
// 状态根（State Root）：
// stateRoot 是以太坊区块头的三大根之一（其他两个是交易根和收据根）。它通过递归计算 MPT 中所有节点的哈希生成，确保状态的完整性和可验证性。
// NodeDatabase 使用状态根来定位特定的状态树实例，适用于查询历史状态或验证区块。

// NodeDatabase wraps the methods of a backing trie store.
// NodeDatabase 封装了底层 trie 存储的方法。
type NodeDatabase interface {
	// NodeReader returns a node reader associated with the specific state.
	// An error will be returned if the specified state is not available.
	// NodeReader 返回与特定状态关联的节点读取器。如果指定的状态不可用，将返回错误。
	//
	// stateRoot common.Hash：状态根哈希，用于标识特定的状态树。以太坊中状态树的根哈希，32 字节的 Keccak-256 哈希值，唯一标识某一时刻的全局状态。
	// 该方法根据给定的状态根哈希，返回一个能够访问对应状态树节点的读取器。
	NodeReader(stateRoot common.Hash) (NodeReader, error)
}

// 状态树（State Trie）：
// 以太坊的状态存储在 MPT 中，账户信息和存储数据分别存储在不同的层级。StateReader 提供了直接访问这些数据的接口。
// 账户数据（如余额、nonce）存储在状态树的叶子节点中，键是账户地址的哈希。
// 存储数据（如智能合约的变量）存储在账户的存储树（Storage Trie）中，键是存储槽索引的哈希。

// 存储树（Storage Trie）：
// 每个合约账户拥有一个独立的 MPT，称为存储树，用于存储合约的状态变量。Storage 方法通过账户哈希和存储槽哈希定位具体数据。
// 存储槽的键（storageHash）通常由 solidity 变量索引经过 Keccak-256 计算生成。

// StateReader wraps the Account and Storage method of a backing state reader.
// StateReader 封装了底层状态读取器的 Account 和 Storage 方法。
//
// 用于从以太坊的状态存储中直接读取账户信息和存储数据。是状态访问层的一部分，通常用于查询账户状态或智能合约的存储槽。
type StateReader interface {
	// Account directly retrieves the account associated with a particular hash in
	// the slim data format. An error will be returned if the read operation exits
	// abnormally. Specifically, if the layer is already stale.
	//
	// Note:
	// - the returned account object is safe to modify
	// - no error will be returned if the requested account is not found in database
	//
	// Account 直接检索与特定哈希关联的账户数据，采用 slim 数据格式。如果读取操作异常退出，将返回错误。特别是如果层已经过期。
	//
	// 注意：
	// - 返回的账户对象可以安全修改
	// - 如果数据库中未找到请求的账户，不会返回错误
	Account(hash common.Hash) (*types.SlimAccount, error)

	// Storage directly retrieves the storage data associated with a particular hash,
	// within a particular account. An error will be returned if the read operation
	// exits abnormally.
	//
	// Note:
	// - the returned storage data is not a copy, please don't modify it
	// - no error will be returned if the requested slot is not found in database
	//
	// Storage 直接检索与特定账户内特定哈希关联的存储数据。如果读取操作异常退出，将返回错误。
	//
	// 注意：
	// - 返回的存储数据不是副本，请勿修改
	// - 如果数据库中未找到请求的存储槽，不会返回错误
	//
	// accountHash common.Hash：账户的哈希，标识目标账户。
	// storageHash common.Hash：存储槽的哈希，通常是存储键（key）经过 Keccak-256 计算后的值。
	Storage(accountHash, storageHash common.Hash) ([]byte, error)
}

// Merkle Patricia Trie（MPT）：
// MPT 是以太坊的状态存储结构，每个状态树由一个状态根（stateRoot）标识。状态根存储在区块头中，代表该区块的账户状态、合约存储等数据的 Merkle 根。
// StateDatabase 是访问 MPT 的高层接口，负责从底层存储（如 LevelDB）中加载特定状态树的数据。

// StateDatabase wraps the methods of a backing state store.
// StateDatabase 封装了底层状态存储的方法。
type StateDatabase interface {
	// StateReader returns a state reader associated with the specific state.
	// An error will be returned if the specified state is not available.
	// StateReader 返回与特定状态关联的状态读取器。如果指定的状态不可用，将返回错误。
	StateReader(stateRoot common.Hash) (StateReader, error)
}
