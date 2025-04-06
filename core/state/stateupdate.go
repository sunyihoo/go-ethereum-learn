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

package state

import (
	"maps"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
)

// Blob 交易 (Blob Transactions) 和 EIP-4844
//
// EIP-4844 引入了一种新的交易类型，允许交易携带额外的“blob”（二进制大对象）。这些 blob 与交易一起提交到链上，但它们的数据不是永久存储在以太坊的主执行层（Execution Layer）的状态中。相反，它们在相对较短的时间内（由共识层决定）在共识层（Consensus Layer）可用，并且可以通过被称为“数据可用性采样 (Data Availability Sampling, DAS)”的技术进行验证。
//
// Blob 交易的主要目的是为 Layer-2 扩展方案（如 Rollup）提供更便宜的数据存储方案。与将所有交易数据作为 calldata 存储在主链上相比，将数据存储在 blob 中可以显著降低 Gas 成本，从而降低 Rollup 的运营成本，并最终降低用户的交易费用。

// contractCode represents a contract code with associated metadata.
// contractCode 表示带有相关元数据的合约代码。
type contractCode struct {
	hash common.Hash // hash is the cryptographic hash of the contract code.
	// hash 是合约代码的加密哈希。
	blob []byte // blob is the binary representation of the contract code.
	// blob 是合约代码的二进制表示。
}

// accountDelete represents an operation for deleting an Ethereum account.
// accountDelete 表示删除以太坊账户的操作。
type accountDelete struct {
	address common.Address // address is the unique account identifier
	// address 是唯一的账户标识符。
	origin []byte // origin is the original value of account data in slim-RLP encoding.
	// origin 是账户数据的原始值，采用 slim-RLP 编码。
	storages map[common.Hash][]byte // storages stores mutated slots, the value should be nil.
	// storages 存储已更改的槽位，其值应为 nil。
	storagesOrigin map[common.Hash][]byte // storagesOrigin stores the original values of mutated slots in prefix-zero-trimmed RLP format.
	// storagesOrigin 存储已更改槽位的原始值，采用前缀零修剪的 RLP 格式。
}

// accountUpdate represents an operation for updating an Ethereum account.
// accountUpdate 表示更新以太坊账户的操作。
type accountUpdate struct {
	address common.Address // address is the unique account identifier
	// address 是唯一的账户标识符。
	data []byte // data is the slim-RLP encoded account data.
	// data 是账户数据，采用 slim-RLP 编码。
	origin []byte // origin is the original value of account data in slim-RLP encoding.
	// origin 是账户数据的原始值，采用 slim-RLP 编码。
	code *contractCode // code represents mutated contract code; nil means it's not modified.
	// code 表示已更改的合约代码；nil 表示未修改。
	storages map[common.Hash][]byte // storages stores mutated slots in prefix-zero-trimmed RLP format.
	// storages 存储已更改的槽位，采用前缀零修剪的 RLP 格式。
	storagesOrigin map[common.Hash][]byte // storagesOrigin stores the original values of mutated slots in prefix-zero-trimmed RLP format.
	// storagesOrigin 存储已更改槽位的原始值，采用前缀零修剪的 RLP 格式。
}

// stateUpdate represents the difference between two states resulting from state
// execution. It contains information about mutated contract codes, accounts,
// and storage slots, along with their original values.
// stateUpdate 表示状态执行后两个状态之间的差异。
// 它包含有关已更改的合约代码、账户和存储槽的信息，以及它们的原始值。
type stateUpdate struct {
	originRoot common.Hash // hash of the state before applying mutation
	// originRoot 应用更改前的状态哈希。
	root common.Hash // hash of the state after applying mutation
	// root 应用更改后的状态哈希。
	accounts map[common.Hash][]byte // accounts stores mutated accounts in 'slim RLP' encoding
	// accounts 存储已更改的账户，采用 'slim RLP' 编码。
	accountsOrigin map[common.Address][]byte // accountsOrigin stores the original values of mutated accounts in 'slim RLP' encoding
	// accountsOrigin 存储已更改账户的原始值，采用 'slim RLP' 编码。
	storages map[common.Hash]map[common.Hash][]byte // storages stores mutated slots in 'prefix-zero-trimmed' RLP format
	// storages 存储已更改的槽位，采用 'prefix-zero-trimmed' RLP 格式。
	storagesOrigin map[common.Address]map[common.Hash][]byte // storagesOrigin stores the original values of mutated slots in 'prefix-zero-trimmed' RLP format
	// storagesOrigin 存储已更改槽位的原始值，采用 'prefix-zero-trimmed' RLP 格式。
	codes map[common.Address]contractCode // codes contains the set of dirty codes
	// codes 包含已更改的代码集合。
	nodes *trienode.MergedNodeSet // Aggregated dirty nodes caused by state changes
	// nodes 由状态更改引起的聚合的脏节点。
}

// empty returns a flag indicating the state transition is empty or not.
// empty 返回一个标志，指示状态转换是否为空。
func (sc *stateUpdate) empty() bool {
	// empty 方法检查状态更新是否为空（原始根哈希和当前根哈希是否相同）。
	return sc.originRoot == sc.root
}

// newStateUpdate constructs a state update object, representing the differences
// between two states by performing state execution. It aggregates the given
// account deletions and account updates to form a comprehensive state update.
// newStateUpdate 构造一个状态更新对象，表示通过执行状态而产生的两个状态之间的差异。
// 它聚合给定的账户删除和账户更新以形成一个全面的状态更新。
func newStateUpdate(originRoot common.Hash, root common.Hash, deletes map[common.Hash]*accountDelete, updates map[common.Hash]*accountUpdate, nodes *trienode.MergedNodeSet) *stateUpdate {
	// newStateUpdate 函数创建一个新的 stateUpdate 实例。
	var (
		accounts       = make(map[common.Hash][]byte)
		accountsOrigin = make(map[common.Address][]byte)
		storages       = make(map[common.Hash]map[common.Hash][]byte)
		storagesOrigin = make(map[common.Address]map[common.Hash][]byte)
		codes          = make(map[common.Address]contractCode)
	)
	// Due to the fact that some accounts could be destructed and resurrected
	// within the same block, the deletions must be aggregated first.
	// 由于某些账户可能在同一区块内被销毁然后又被重建，因此必须首先聚合删除操作。
	for addrHash, op := range deletes {
		addr := op.address
		accounts[addrHash] = nil
		accountsOrigin[addr] = op.origin

		if len(op.storages) > 0 {
			storages[addrHash] = op.storages
		}
		if len(op.storagesOrigin) > 0 {
			storagesOrigin[addr] = op.storagesOrigin
		}
	}
	// Aggregate account updates then.
	// 然后聚合账户更新操作。
	for addrHash, op := range updates {
		// Aggregate dirty contract codes if they are available.
		// 如果存在脏合约代码，则聚合它们。
		addr := op.address
		if op.code != nil {
			codes[addr] = *op.code
		}
		accounts[addrHash] = op.data

		// Aggregate the account original value. If the account is already
		// present in the aggregated accountsOrigin set, skip it.
		// 聚合账户的原始值。如果账户已存在于聚合的 accountsOrigin 集合中，则跳过它。
		if _, found := accountsOrigin[addr]; !found {
			accountsOrigin[addr] = op.origin
		}
		// Aggregate the storage mutation list. If a slot in op.storages is
		// already present in aggregated storages set, the value will be
		// overwritten.
		// 聚合存储更改列表。如果 op.storages 中的一个槽位已存在于聚合的 storages 集合中，则其值将被覆盖。
		if len(op.storages) > 0 {
			if _, exist := storages[addrHash]; !exist {
				storages[addrHash] = op.storages
			} else {
				maps.Copy(storages[addrHash], op.storages)
			}
		}
		// Aggregate the storage original values. If the slot is already present
		// in aggregated storagesOrigin set, skip it.
		// 聚合存储的原始值。如果该槽位已存在于聚合的 storagesOrigin 集合中，则跳过它。
		if len(op.storagesOrigin) > 0 {
			origin, exist := storagesOrigin[addr]
			if !exist {
				storagesOrigin[addr] = op.storagesOrigin
			} else {
				for key, slot := range op.storagesOrigin {
					if _, found := origin[key]; !found {
						origin[key] = slot
					}
				}
			}
		}
	}
	return &stateUpdate{
		originRoot:     originRoot,
		root:           root,
		accounts:       accounts,
		accountsOrigin: accountsOrigin,
		storages:       storages,
		storagesOrigin: storagesOrigin,
		codes:          codes,
		nodes:          nodes,
	}
}

// stateSet converts the current stateUpdate object into a triedb.StateSet
// object. This function extracts the necessary data from the stateUpdate
// struct and formats it into the StateSet structure consumed by the triedb
// package.
// stateSet 将当前 stateUpdate 对象转换为 triedb.StateSet 对象。
// 此函数从 stateUpdate 结构体中提取必要的数据，并将其格式化为 triedb 包使用的 StateSet 结构。
func (sc *stateUpdate) stateSet() *triedb.StateSet {
	// stateSet 方法将 stateUpdate 转换为 triedb.StateSet 对象。
	return &triedb.StateSet{
		Accounts:       sc.accounts,
		AccountsOrigin: sc.accountsOrigin,
		Storages:       sc.storages,
		StoragesOrigin: sc.storagesOrigin,
	}
}
