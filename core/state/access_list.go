// Copyright 2020 The go-ethereum Authors
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
	"maps"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// EIP-2930 和访问列表
//
// EIP-2930 引入了可选的交易访问列表 (Access List)。在以太坊的交易中，除了 to 字段指定接收者地址外，还可以包含一个访问列表。这个列表允许交易预先声明它计划访问的账户地址和存储槽位。
//
// 引入访问列表的主要目的是为了降低 Gas 成本，特别是在以太坊进行 Berlin 升级之后，首次访问一个不在访问列表中的账户或存储槽会比后续访问花费更多的 Gas。通过预先声明，交易可以享受更低的 Gas 费用。此外，访问列表也有助于提高交易的执行效率，因为客户端可以提前加载相关的数据。

// Gas 优化: 通过使用访问列表，交易可以预先声明其将要访问的资源，从而享受更低的 Gas 费用。
// 交易结构: 在支持 EIP-2930 的以太坊版本中，交易可以包含一个可选的 accessList 字段。
// 状态访问: 以太坊虚拟机 (EVM) 在执行交易时，会根据交易的访问列表来确定 Gas 的消耗。首次访问访问列表中的账户或存储槽的 Gas 成本低于首次访问不在列表中的资源。
// Journaling: 在 go-ethereum 中，交易执行过程中的状态变更会记录在 Journal 中，以便在发生错误或需要回滚时能够恢复到之前的状态。AddSlot 和 DeleteSlot 方法中关于 Journal 的注释表明了访问列表的操作也需要被记录下来。

type accessList struct {
	addresses map[common.Address]int // Mapping of addresses to their slot indices or -1 if no slots
	// addresses 是地址到其槽位索引的映射，如果没有任何槽位则为 -1。
	slots []map[common.Hash]struct{} // List of maps, where each map contains the slots for an address
	// slots 是 map 的列表，每个 map 包含一个地址的槽位。
}

// ContainsAddress returns true if the address is in the access list.
// ContainsAddress 如果地址在访问列表中则返回 true。
func (al *accessList) ContainsAddress(address common.Address) bool {
	// ContainsAddress 方法检查给定的地址是否存在于访问列表中。
	_, ok := al.addresses[address]
	return ok
}

// Contains checks if a slot within an account is present in the access list, returning
// separate flags for the presence of the account and the slot respectively.
// Contains 检查账户中的一个槽位是否存在于访问列表中，分别返回账户是否存在和槽位是否存在的标志。
func (al *accessList) Contains(address common.Address, slot common.Hash) (addressPresent bool, slotPresent bool) {
	// Contains 方法检查给定的地址和槽位是否都存在于访问列表中。
	idx, ok := al.addresses[address]
	if !ok {
		// no such address (and hence zero slots)
		// 没有这样的地址（因此也没有槽位）
		return false, false
	}
	if idx == -1 {
		// address yes, but no slots
		// 地址存在，但没有槽位
		return true, false
	}
	_, slotPresent = al.slots[idx][slot]
	return true, slotPresent
}

// newAccessList creates a new accessList.
// newAccessList 创建一个新的 accessList。
func newAccessList() *accessList {
	// newAccessList 函数创建一个新的 accessList 结构体实例。
	return &accessList{
		addresses: make(map[common.Address]int),
	}
}

// Copy creates an independent copy of an accessList.
// Copy 创建一个 accessList 的独立副本。
func (al *accessList) Copy() *accessList {
	// Copy 方法创建一个新的 accessList，其内容是原始 accessList 的深拷贝。
	cp := newAccessList()
	cp.addresses = maps.Clone(al.addresses)
	cp.slots = make([]map[common.Hash]struct{}, len(al.slots))
	for i, slotMap := range al.slots {
		cp.slots[i] = maps.Clone(slotMap)
	}
	return cp
}

// AddAddress adds an address to the access list, and returns 'true' if the operation
// caused a change (addr was not previously in the list).
// AddAddress 将一个地址添加到访问列表，如果操作导致了更改（地址之前不在列表中），则返回 'true'。
func (al *accessList) AddAddress(address common.Address) bool {
	// AddAddress 方法将给定的地址添加到访问列表中。
	if _, present := al.addresses[address]; present {
		return false
	}
	al.addresses[address] = -1
	return true
}

// AddSlot adds the specified (addr, slot) combo to the access list.
// Return values are:
// - address added
// - slot added
// For any 'true' value returned, a corresponding journal entry must be made.
// AddSlot 将指定的 (addr, slot) 组合添加到访问列表。
// 返回值：
// - 地址已添加
// - 槽位已添加
// 对于任何返回 'true' 的值，都必须创建一个相应的日志条目。
func (al *accessList) AddSlot(address common.Address, slot common.Hash) (addrChange bool, slotChange bool) {
	// AddSlot 方法将给定的地址和存储槽添加到访问列表中。
	idx, addrPresent := al.addresses[address]
	if !addrPresent || idx == -1 {
		// Address not present, or addr present but no slots there
		// 地址不存在，或者地址存在但没有槽位
		al.addresses[address] = len(al.slots)
		slotmap := map[common.Hash]struct{}{slot: {}}
		al.slots = append(al.slots, slotmap)
		return !addrPresent, true
	}
	// There is already an (address,slot) mapping
	// 已经存在 (address,slot) 的映射
	slotmap := al.slots[idx]
	if _, ok := slotmap[slot]; !ok {
		slotmap[slot] = struct{}{}
		// Journal add slot change
		// 记录添加槽位的更改
		return false, true
	}
	// No changes required
	// 无需更改
	return false, false
}

// DeleteSlot removes an (address, slot)-tuple from the access list.
// This operation needs to be performed in the same order as the addition happened.
// This method is meant to be used  by the journal, which maintains ordering of
// operations.
// DeleteSlot 从访问列表中删除一个 (address, slot) 元组。
// 此操作需要以与添加操作相同的顺序执行。
// 此方法旨在供日志使用，该日志维护操作的顺序。
func (al *accessList) DeleteSlot(address common.Address, slot common.Hash) {
	// DeleteSlot 方法从访问列表中删除指定的地址和存储槽。
	idx, addrOk := al.addresses[address]
	// There are two ways this can fail
	// 有两种情况可能失败
	if !addrOk {
		panic("reverting slot change, address not present in list")
	}
	slotmap := al.slots[idx]
	delete(slotmap, slot)
	// If that was the last (first) slot, remove it
	// Since additions and rollbacks are always performed in order,
	// we can delete the item without worrying about screwing up later indices
	// 如果那是最后一个（第一个）槽位，则删除它
	// 由于添加和回滚总是按顺序执行的，
	// 我们可以删除该项而不必担心会搞乱后面的索引
	if len(slotmap) == 0 {
		al.slots = al.slots[:idx]
		al.addresses[address] = -1
	}
}

// DeleteAddress removes an address from the access list. This operation
// needs to be performed in the same order as the addition happened.
// This method is meant to be used  by the journal, which maintains ordering of
// operations.
// DeleteAddress 从访问列表中删除一个地址。此操作需要以与添加操作相同的顺序执行。
// 此方法旨在供日志使用，该日志维护操作的顺序。
func (al *accessList) DeleteAddress(address common.Address) {
	// DeleteAddress 方法从访问列表中删除给定的地址。
	delete(al.addresses, address)
}

// Equal returns true if the two access lists are identical
// Equal 如果两个访问列表完全相同则返回 true。
func (al *accessList) Equal(other *accessList) bool {
	// Equal 方法比较当前的 accessList 和另一个 accessList 是否相等。
	if !maps.Equal(al.addresses, other.addresses) {
		return false
	}
	return slices.EqualFunc(al.slots, other.slots, maps.Equal)
}

// PrettyPrint prints the contents of the access list in a human-readable form
// PrettyPrint 以人类可读的形式打印访问列表的内容。
func (al *accessList) PrettyPrint() string {
	// PrettyPrint 方法将 accessList 的内容格式化为易于阅读的字符串。
	out := new(strings.Builder)
	var sortedAddrs []common.Address
	for addr := range al.addresses {
		sortedAddrs = append(sortedAddrs, addr)
	}
	slices.SortFunc(sortedAddrs, common.Address.Cmp)
	for _, addr := range sortedAddrs {
		idx := al.addresses[addr]
		fmt.Fprintf(out, "%#x : (idx %d)\n", addr, idx)
		if idx >= 0 {
			slotmap := al.slots[idx]
			for h := range slotmap {
				fmt.Fprintf(out, "    %#x\n", h)
			}
		}
	}
	return out.String()
}
