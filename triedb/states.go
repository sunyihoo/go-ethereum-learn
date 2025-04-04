// Copyright 2023 The go-ethereum Authors
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

package triedb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// 状态转换: StateSet 的目的是在状态转换（例如，执行一个区块中的交易）期间收集所有发生变化的状态。
// 不同层级的抽象: 存在两个不同的 StateSet 结构体 (StateSet 和 pathdb.StateSetWithOrigin) 表明在 go-ethereum 的状态管理中存在不同层级的抽象。StateSet 可能是更高层级的抽象，用于在不同组件之间传递状态变化信息，而 pathdb.StateSetWithOrigin 则是路径模式数据库内部使用的特定格式。
// 数据编码格式: 代码中提到了 'slim RLP' 和 'prefix-zero-trimmed' RLP 这两种特定的编码格式。RLP (Recursive Length Prefix) 是以太坊中用于序列化数据的标准格式。这两种变体可能是在标准 RLP 的基础上进行了优化，以减少存储空间或提高处理效率。
// 路径模式数据库的内部表示: internal 函数的存在表明，当需要将状态变化应用到路径模式数据库时，需要将更高层级的 StateSet 转换为 pathdb.StateSetWithOrigin 这种特定的格式。这可能与路径模式数据库内部存储和管理状态历史的方式有关。
// 原始值的重要性: StateSet 中同时存储了变化后的状态和原始状态，这对于状态的回滚（例如，在发生区块链重组时）至关重要。路径模式数据库也需要这些原始值来实现其历史查询等功能。

// StateSet represents a collection of mutated states during a state transition.
// StateSet 表示状态转换期间发生变化的状态集合。
type StateSet struct {
	Accounts map[common.Hash][]byte // Mutated accounts in 'slim RLP' encoding
	// 以 'slim RLP' 编码格式存储的变化的账户数据。
	AccountsOrigin map[common.Address][]byte // Original values of mutated accounts in 'slim RLP' encoding
	// 以 'slim RLP' 编码格式存储的变化的账户数据的原始值。
	Storages map[common.Hash]map[common.Hash][]byte // Mutated storage slots in 'prefix-zero-trimmed' RLP format
	// 以 'prefix-zero-trimmed' RLP 格式存储的变化的存储槽数据。
	StoragesOrigin map[common.Address]map[common.Hash][]byte // Original values of mutated storage slots in 'prefix-zero-trimmed' RLP format
	// 以 'prefix-zero-trimmed' RLP 格式存储的变化的存储槽数据的原始值。
}

// NewStateSet initializes an empty state set.
// NewStateSet 初始化一个空的状态集合。
func NewStateSet() *StateSet {
	return &StateSet{
		Accounts:       make(map[common.Hash][]byte),
		AccountsOrigin: make(map[common.Address][]byte),
		Storages:       make(map[common.Hash]map[common.Hash][]byte),
		StoragesOrigin: make(map[common.Address]map[common.Hash][]byte),
	}
}

// internal returns a state set for path database internal usage.
// internal 返回一个供路径数据库内部使用的状态集合。
func (set *StateSet) internal() *pathdb.StateSetWithOrigin {
	// the nil state set is possible in tests.
	// 在测试中状态集合可能为 nil。
	if set == nil {
		return nil
	}
	return pathdb.NewStateSetWithOrigin(set.Accounts, set.Storages, set.AccountsOrigin, set.StoragesOrigin)
}
