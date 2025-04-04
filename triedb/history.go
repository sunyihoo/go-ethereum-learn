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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package triedb

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// 历史状态: 在传统的基于哈希的 Merkle-Patricia Trie 中，要查询历史状态通常需要存储大量的历史区块数据和相应的状态 trie。路径模式数据库似乎通过不同的方式组织和存储状态数据，从而能够更方便地查询历史状态。
// State ID: 代码中提到了 "State ID"，这可能是在路径模式数据库中用于唯一标识不同历史状态的标识符。它可能与区块高度或其他排序机制相关联。
// 账户和存储历史: 这两个方法允许开发者查询特定账户或特定账户的存储槽在过去某个时间范围内的状态变化。这对于调试、审计或者分析智能合约的行为非常有用。
// 路径模式数据库的优势: 这些方法是路径模式数据库特有的，表明了其在提供高级查询功能方面的优势。传统的基于哈希的数据库通常不直接支持这种细粒度的历史查询。
// 数据结构差异: 路径模式数据库之所以能够支持这些历史查询，很可能采用了与基于哈希的数据库不同的底层数据结构和存储方式。

// AccountHistory inspects the account history within the specified range.
// AccountHistory 检查指定范围内的账户历史记录。
//
// Start: State ID of the first history object for the query. 0 implies the first
// available object is selected as the starting point.
// Start：查询的第一个历史对象的 State ID。0 表示选择第一个可用的对象作为起始点。
//
// End: State ID of the last history for the query. 0 implies the last available
// object is selected as the starting point. Note end is included for query.
// End：查询的最后一个历史对象的 State ID。0 表示选择最后一个可用的对象作为起始点。注意，查询包含结束点。
//
// This function is only supported by path mode database.
// 此功能仅受路径模式数据库支持。
func (db *Database) AccountHistory(address common.Address, start, end uint64) (*pathdb.HistoryStats, error) {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return nil, errors.New("not supported")
	}
	return pdb.AccountHistory(address, start, end)
}

// StorageHistory inspects the storage history within the specified range.
// StorageHistory 检查指定范围内的存储历史记录。
//
// Start: State ID of the first history object for the query. 0 implies the first
// available object is selected as the starting point.
// Start：查询的第一个历史对象的 State ID。0 表示选择第一个可用的对象作为起始点。
//
// End: State ID of the last history for the query. 0 implies the last available
// object is selected as the starting point. Note end is included for query.
// End：查询的最后一个历史对象的 State ID。0 表示选择最后一个可用的对象作为起始点。注意，查询包含结束点。
//
// Note, slot refers to the hash of the raw slot key.
// 注意，slot 指的是原始槽键的哈希。
//
// This function is only supported by path mode database.
// 此功能仅受路径模式数据库支持。
func (db *Database) StorageHistory(address common.Address, slot common.Hash, start uint64, end uint64) (*pathdb.HistoryStats, error) {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return nil, errors.New("not supported")
	}
	return pdb.StorageHistory(address, slot, start, end)
}

// HistoryRange returns the block numbers associated with earliest and latest
// state history in the local store.
// HistoryRange 返回本地存储中与最早和最新的状态历史记录关联的区块号。
//
// This function is only supported by path mode database.
// 此功能仅受路径模式数据库支持。
func (db *Database) HistoryRange() (uint64, uint64, error) {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return 0, 0, errors.New("not supported")
	}
	return pdb.HistoryRange()
}
