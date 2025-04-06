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

package state

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// EIP-1153 引入了“瞬态存储”的概念到以太坊虚拟机 (EVM)。瞬态存储是一种仅在单个交易的执行上下文中存在的存储类型。与传统的持久性存储（通过 SSTORE 操作码访问）不同，瞬态存储在交易执行完成后会被自动清除。
//
// 引入瞬态存储的主要目的是为了降低某些操作的 Gas 成本。例如，在同一个交易中多次调用的合约可能需要在调用之间共享一些数据，但这些数据在交易结束后不再需要保留。使用瞬态存储可以避免将这些数据写入到昂贵的持久性存储中，从而节省 Gas。
//
// transientStorage 结构体的作用
//
// transientStorage 结构体在 go-ethereum 中用于表示和管理交易的瞬态存储。它是一个 map，其中键是 common.Address 类型的以太坊地址，值是 Storage 类型（假设 Storage 是一个 map，用于存储特定地址下的键值对）。

// EIP-1153: 这段代码直接实现了 EIP-1153 中定义的瞬态存储的概念。
// Gas 成本: 瞬态存储的主要优势在于其 Gas 成本比持久性存储低得多，因为它不会被写入到区块链的状态中，而只在交易执行期间存在于内存中。
// 交易上下文: 瞬态存储的作用域限定在单个交易的执行过程中。在交易结束后，所有存储在瞬态存储中的数据都会被自动丢弃。
// 用例: 瞬态存储适用于需要在同一个交易的多次合约调用之间共享临时数据的场景，例如在复杂的 DeFi 协议中，可能需要在不同的合约之间传递一些中间计算结果，但这些结果在交易完成后并不需要保留。

// transientStorage is a representation of EIP-1153 "Transient Storage".
// transientStorage 是 EIP-1153 “瞬态存储” 的表示。
type transientStorage map[common.Address]Storage

// newTransientStorage creates a new instance of a transientStorage.
// newTransientStorage 创建一个 transientStorage 的新实例。
func newTransientStorage() transientStorage {
	// newTransientStorage 函数创建一个新的 transientStorage map。
	return make(transientStorage)
}

// Set sets the transient-storage `value` for `key` at the given `addr`.
// Set 在给定的 `addr` 处为 `key` 设置瞬态存储 `value`。
func (t transientStorage) Set(addr common.Address, key, value common.Hash) {
	// Set 方法在瞬态存储中为给定的地址和键设置值。
	if value == (common.Hash{}) { // this is a 'delete'
		// 如果值为零哈希，则这是一个“删除”操作。
		if _, ok := t[addr]; ok {
			delete(t[addr], key)
			if len(t[addr]) == 0 {
				delete(t, addr)
			}
		}
	} else {
		if _, ok := t[addr]; !ok {
			t[addr] = make(Storage)
		}
		t[addr][key] = value
	}
}

// Get gets the transient storage for `key` at the given `addr`.
// Get 获取给定 `addr` 处 `key` 的瞬态存储。
func (t transientStorage) Get(addr common.Address, key common.Hash) common.Hash {
	// Get 方法从瞬态存储中检索给定地址和键的值。
	val, ok := t[addr]
	if !ok {
		return common.Hash{}
	}
	return val[key]
}

// Copy does a deep copy of the transientStorage
// Copy 对 transientStorage 进行深拷贝。
func (t transientStorage) Copy() transientStorage {
	// Copy 方法创建一个新的 transientStorage，其内容是原始 transientStorage 的深拷贝。
	storage := make(transientStorage)
	for key, value := range t {
		storage[key] = value.Copy()
	}
	return storage
}

// PrettyPrint prints the contents of the access list in a human-readable form
// PrettyPrint 以人类可读的形式打印访问列表的内容。
func (t transientStorage) PrettyPrint() string {
	// PrettyPrint 方法将 transientStorage 的内容格式化为易于阅读的字符串。
	out := new(strings.Builder)
	var sortedAddrs []common.Address
	for addr := range t {
		sortedAddrs = append(sortedAddrs, addr)
		slices.SortFunc(sortedAddrs, common.Address.Cmp)
	}

	for _, addr := range sortedAddrs {
		fmt.Fprintf(out, "%#x:", addr)
		var sortedKeys []common.Hash
		storage := t[addr]
		for key := range storage {
			sortedKeys = append(sortedKeys, key)
		}
		slices.SortFunc(sortedKeys, common.Hash.Cmp)
		for _, key := range sortedKeys {
			fmt.Fprintf(out, "  %X : %X\n", key, storage[key])
		}
	}
	return out.String()
}
