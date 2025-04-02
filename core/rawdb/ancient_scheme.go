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

package rawdb

import (
	"path/filepath"

	"github.com/ethereum/go-ethereum/ethdb"
)

// 冷冻存储（Ancient Store）: 用于在以太坊节点中持久化历史数据，确保在节点重新启动后能够快速加载历史状态并保持节点的一致性。
// Merkle Trie 和 Verkle Trie: 以太坊使用 Merkle Trie 储存帐户状态和交易数据，而 Verkle Trie 是一种改进的 Merkle Trie，能够更高效地存储和检索数据，采用了一种新的编码技术。
// 状态快照: 以太坊中，节点用冷冻存储来保持状态快照，以便快速恢复之前的块和状态。这种方法使得节点在面对不同的网络条件时依然快速且高效。

// The list of table names of chain freezer.
// 用于链冷冻存储的表名称列表。
const (
	// ChainFreezerHeaderTable indicates the name of the freezer header table.
	// ChainFreezerHeaderTable 表示冷冻存储头部表的名称。
	ChainFreezerHeaderTable = "headers"

	// ChainFreezerHashTable indicates the name of the freezer canonical hash table.
	// ChainFreezerHashTable 表示冷冻存储标准哈希表的名称。
	ChainFreezerHashTable = "hashes"

	// ChainFreezerBodiesTable indicates the name of the freezer block body table.
	// ChainFreezerBodiesTable 表示冷冻存储区块体表的名称。
	ChainFreezerBodiesTable = "bodies"

	// ChainFreezerReceiptTable indicates the name of the freezer receipts table.
	// ChainFreezerReceiptTable 表示冷冻存储收据表的名称。
	ChainFreezerReceiptTable = "receipts"

	// ChainFreezerDifficultyTable indicates the name of the freezer total difficulty table.
	// ChainFreezerDifficultyTable 表示冷冻存储总难度表的名称。
	ChainFreezerDifficultyTable = "diffs"
)

// chainFreezerNoSnappy configures whether compression is disabled for the ancient-tables.
// Hashes and difficulties don't compress well.
// chainFreezerNoSnappy 配置是否禁用古老表的压缩。
// 哈希和难度不适合压缩。
var chainFreezerNoSnappy = map[string]bool{
	ChainFreezerHeaderTable:     false, // 头部表不禁用压缩
	ChainFreezerHashTable:       true,  // 哈希表禁用压缩
	ChainFreezerBodiesTable:     false, // 区块体表不禁用压缩
	ChainFreezerReceiptTable:    false, // 收据表不禁用压缩
	ChainFreezerDifficultyTable: true,  // 难度表禁用压缩
}

const (
	// stateHistoryTableSize defines the maximum size of freezer data files.
	// stateHistoryTableSize 定义冷冻存储数据文件的最大大小。
	stateHistoryTableSize = 2 * 1000 * 1000 * 1000

	// stateHistoryAccountIndex indicates the name of the freezer state history table.
	// stateHistoryAccountIndex 表示冷冻存储状态历史表的名称。
	stateHistoryMeta         = "history.meta"
	stateHistoryAccountIndex = "account.index"
	stateHistoryStorageIndex = "storage.index"
	stateHistoryAccountData  = "account.data"
	stateHistoryStorageData  = "storage.data"
)

// stateFreezerNoSnappy 定义状态历史表的压缩设置。
var stateFreezerNoSnappy = map[string]bool{
	stateHistoryMeta:         true,  // 历史元数据禁用压缩
	stateHistoryAccountIndex: false, // 账户索引不禁用压缩
	stateHistoryStorageIndex: false, // 存储索引不禁用压缩
	stateHistoryAccountData:  false, // 账户数据不禁用压缩
	stateHistoryStorageData:  false, // 存储数据不禁用压缩
}

// The list of identifiers of ancient stores.
// 古老存储标识符的列表。
var (
	ChainFreezerName       = "chain"        // the folder name of chain segment ancient store.  // 链段古老存储的文件夹名称。
	MerkleStateFreezerName = "state"        // the folder name of state history ancient store. // 状态历史古老存储的文件夹名称。
	VerkleStateFreezerName = "state_verkle" // the folder name of state history ancient store. // 状态历史古老存储的文件夹名称（Verkle）。
)

// freezers the collections of all builtin freezers.
// freezers 是所有内置冷冻存储的集合。
var freezers = []string{ChainFreezerName, MerkleStateFreezerName, VerkleStateFreezerName}

// NewStateFreezer initializes the ancient store for state history.
//
//   - if the empty directory is given, initializes the pure in-memory
//     state freezer (e.g. dev mode).
//   - if non-empty directory is given, initializes the regular file-based
//     state freezer.
//
// NewStateFreezer 新建状态历史的古老存储。
//
//   - if the empty directory is given, initializes the pure in-memory
//     state freezer (e.g. dev mode).
//   - if non-empty directory is given, initializes the regular file-based
//     state freezer.
func NewStateFreezer(ancientDir string, verkle bool, readOnly bool) (ethdb.ResettableAncientStore, error) {
	// 如果提供的目录为空，则初始化纯内存状态冷冻存储（例如，开发模式）。
	if ancientDir == "" {
		return NewMemoryFreezer(readOnly, stateFreezerNoSnappy), nil
	}
	// 若提供非空目录，则初始化常规文件基础状态冷冻存储。
	var name string
	if verkle {
		name = filepath.Join(ancientDir, VerkleStateFreezerName) // 使用 Verkle 状态冷冻存储。
	} else {
		name = filepath.Join(ancientDir, MerkleStateFreezerName) // 使用 Merkle 状态冷冻存储。
	}
	return newResettableFreezer(name, "eth/db/state", readOnly, stateHistoryTableSize, stateFreezerNoSnappy)
}
