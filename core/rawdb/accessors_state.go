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

package rawdb

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// ReadPreimage retrieves a single preimage of the provided hash.
// 读取提供哈希的单个预映像。
func ReadPreimage(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(preimageKey(hash))
	return data
}

// WritePreimages writes the provided set of preimages to the database.
// 将提供的预映像集合写入数据库。
func WritePreimages(db ethdb.KeyValueWriter, preimages map[common.Hash][]byte) {
	for hash, preimage := range preimages {
		// 将每个预映像写入数据库，若失败则记录错误。
		if err := db.Put(preimageKey(hash), preimage); err != nil {
			log.Crit("Failed to store trie preimage", "err", err)
		}
	}
	preimageCounter.Inc(int64(len(preimages)))    // 增加预映像计数器。
	preimageHitCounter.Inc(int64(len(preimages))) // 增加预映像命中计数器。
}

// ReadCode retrieves the contract code of the provided code hash.
// 读取提供代码哈希的合约代码。
func ReadCode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	// Try with the prefixed code scheme first, if not then try with legacy
	// scheme.
	// 首先尝试使用带前缀的代码方案，如果失败则尝试使用遗留方案。
	data := ReadCodeWithPrefix(db, hash)
	if len(data) != 0 {
		return data
	}
	data, _ = db.Get(hash.Bytes())
	return data
}

// ReadCodeWithPrefix retrieves the contract code of the provided code hash.
// The main difference between this function and ReadCode is this function
// will only check the existence with latest scheme(with prefix).
//
// ReadCodeWithPrefix 读取提供代码哈希的合约代码。
// 此函数与 ReadCode 的主要区别在于它仅检查使用最新方案（带前缀）的存在性。
func ReadCodeWithPrefix(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(codeKey(hash))
	return data
}

// HasCode checks if the contract code corresponding to the
// provided code hash is present in the db.
// HasCode 检查数据库中是否存在与提供的代码哈希对应的合约代码。
func HasCode(db ethdb.KeyValueReader, hash common.Hash) bool {
	// Try with the prefixed code scheme first, if not then try with legacy
	// scheme.
	// 首先尝试使用带前缀的代码方案，如果失败则尝试使用遗留方案。
	if ok := HasCodeWithPrefix(db, hash); ok {
		return true
	}
	ok, _ := db.Has(hash.Bytes())
	return ok
}

// HasCodeWithPrefix checks if the contract code corresponding to the
// provided code hash is present in the db. This function will only check
// presence using the prefix-scheme.
// HasCodeWithPrefix 检查数据库中是否存在与提供的代码哈希对应的合约代码。
// 此函数仅使用前缀方案检查存在性。
func HasCodeWithPrefix(db ethdb.KeyValueReader, hash common.Hash) bool {
	ok, _ := db.Has(codeKey(hash))
	return ok
}

// WriteCode writes the provided contract code database.
// WriteCode 将提供的合约代码写入数据库。
func WriteCode(db ethdb.KeyValueWriter, hash common.Hash, code []byte) {
	if err := db.Put(codeKey(hash), code); err != nil {
		log.Crit("Failed to store contract code", "err", err)
	}
}

// DeleteCode deletes the specified contract code from the database.
// DeleteCode 从数据库中删除指定的合约代码。
func DeleteCode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(codeKey(hash)); err != nil {
		log.Crit("Failed to delete contract code", "err", err)
	}
}

// ReadStateID retrieves the state id with the provided state root.
// ReadStateID 读取提供状态根的状态 ID。
func ReadStateID(db ethdb.KeyValueReader, root common.Hash) *uint64 {
	data, err := db.Get(stateIDKey(root))
	if err != nil || len(data) == 0 {
		return nil
	}
	number := binary.BigEndian.Uint64(data) // 将数据转换为无符号整数。
	return &number
}

// WriteStateID writes the provided state lookup to database.
// WriteStateID 将提供的状态查找信息写入数据库。
func WriteStateID(db ethdb.KeyValueWriter, root common.Hash, id uint64) {
	var buff [8]byte
	binary.BigEndian.PutUint64(buff[:], id)
	if err := db.Put(stateIDKey(root), buff[:]); err != nil {
		log.Crit("Failed to store state ID", "err", err)
	}
}

// DeleteStateID deletes the specified state lookup from the database.
// DeleteStateID 从数据库中删除指定的状态查找信息。
func DeleteStateID(db ethdb.KeyValueWriter, root common.Hash) {
	if err := db.Delete(stateIDKey(root)); err != nil {
		log.Crit("Failed to delete state ID", "err", err)
	}
}

// ReadPersistentStateID retrieves the id of the persistent state from the database.
// ReadPersistentStateID 从数据库中读取持久状态的 ID。
func ReadPersistentStateID(db ethdb.KeyValueReader) uint64 {
	data, _ := db.Get(persistentStateIDKey)
	if len(data) != 8 { // 若数据长度不为 8，则返回 0。
		return 0
	}
	return binary.BigEndian.Uint64(data) // 将数据转换为无符号整数并返回。
}

// WritePersistentStateID stores the id of the persistent state into database.
// WritePersistentStateID 将持久状态的 ID 存储到数据库中。
func WritePersistentStateID(db ethdb.KeyValueWriter, number uint64) {
	if err := db.Put(persistentStateIDKey, encodeBlockNumber(number)); err != nil {
		log.Crit("Failed to store the persistent state ID", "err", err)
	}
}

// ReadTrieJournal retrieves the serialized in-memory trie nodes of layers saved at
// the last shutdown.
// ReadTrieJournal 读取上次关闭时保存的内存中树节点的序列化数据。
func ReadTrieJournal(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(trieJournalKey)
	return data
}

// WriteTrieJournal stores the serialized in-memory trie nodes of layers to save at
// shutdown.
// WriteTrieJournal 存储内存中树节点的序列化数据，以便在关闭时保存。
func WriteTrieJournal(db ethdb.KeyValueWriter, journal []byte) {
	if err := db.Put(trieJournalKey, journal); err != nil {
		log.Crit("Failed to store tries journal", "err", err)
	}
}

// DeleteTrieJournal deletes the serialized in-memory trie nodes of layers saved at
// the last shutdown.
// DeleteTrieJournal 删除上次关闭时保存的内存中树节点的序列化数据。
func DeleteTrieJournal(db ethdb.KeyValueWriter) {
	if err := db.Delete(trieJournalKey); err != nil {
		log.Crit("Failed to remove tries journal", "err", err)
	}
}

// ReadStateHistoryMeta retrieves the metadata corresponding to the specified
// state history. Compute the position of state history in freezer by minus
// one since the id of first state history starts from one(zero for initial
// state).
//
// ReadStateHistoryMeta 读取与指定状态历史相对应的元数据。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func ReadStateHistoryMeta(db ethdb.AncientReaderOp, id uint64) []byte {
	blob, err := db.Ancient(stateHistoryMeta, id-1)
	if err != nil {
		return nil
	}
	return blob
}

// ReadStateHistoryMetaList retrieves a batch of meta objects with the specified
// start position and count. Compute the position of state history in freezer by
// minus one since the id of first state history starts from one(zero for initial
// state).
// ReadStateHistoryMetaList 读取指定起始位置和计数的元对象批量数据。
// 由于第一个状态历史 ID 从 1 开始（初始状态为零），因此需要计算在冷冻存储中的位置。
func ReadStateHistoryMetaList(db ethdb.AncientReaderOp, start uint64, count uint64) ([][]byte, error) {
	return db.AncientRange(stateHistoryMeta, start-1, count, 0)
}

// ReadStateAccountIndex retrieves the state root corresponding to the specified
// state history. Compute the position of state history in freezer by minus one
// since the id of first state history starts from one(zero for initial state).
// ReadStateAccountIndex 读取与指定状态历史相对应的状态根。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func ReadStateAccountIndex(db ethdb.AncientReaderOp, id uint64) []byte {
	blob, err := db.Ancient(stateHistoryAccountIndex, id-1)
	if err != nil {
		return nil
	}
	return blob
}

// ReadStateStorageIndex retrieves the state root corresponding to the specified
// state history. Compute the position of state history in freezer by minus one
// since the id of first state history starts from one(zero for initial state).
// ReadStateStorageIndex 读取与指定状态历史相对应的状态根。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func ReadStateStorageIndex(db ethdb.AncientReaderOp, id uint64) []byte {
	blob, err := db.Ancient(stateHistoryStorageIndex, id-1)
	if err != nil {
		return nil
	}
	return blob
}

// ReadStateAccountHistory retrieves the state root corresponding to the specified
// state history. Compute the position of state history in freezer by minus one
// since the id of first state history starts from one(zero for initial state).
// ReadStateAccountHistory 读取与指定状态历史相对应的状态根。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func ReadStateAccountHistory(db ethdb.AncientReaderOp, id uint64) []byte {
	blob, err := db.Ancient(stateHistoryAccountData, id-1)
	if err != nil {
		return nil
	}
	return blob
}

// ReadStateStorageHistory retrieves the state root corresponding to the specified
// state history. Compute the position of state history in freezer by minus one
// since the id of first state history starts from one(zero for initial state).
//
// ReadStateStorageHistory 读取与指定状态历史相对应的状态根。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func ReadStateStorageHistory(db ethdb.AncientReaderOp, id uint64) []byte {
	blob, err := db.Ancient(stateHistoryStorageData, id-1)
	if err != nil {
		return nil
	}
	return blob
}

// ReadStateHistory retrieves the state history from database with provided id.
// Compute the position of state history in freezer by minus one since the id
// of first state history starts from one(zero for initial state).
//
// ReadStateHistory 根据提供的 ID 从数据库中读取状态历史。
// 由于第一个状态历史的 ID 从 1 开始（初始状态为零），因此需要计算在冷冻存储中的位置。
func ReadStateHistory(db ethdb.AncientReaderOp, id uint64) ([]byte, []byte, []byte, []byte, []byte, error) {
	meta, err := db.Ancient(stateHistoryMeta, id-1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	accountIndex, err := db.Ancient(stateHistoryAccountIndex, id-1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	storageIndex, err := db.Ancient(stateHistoryStorageIndex, id-1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	accountData, err := db.Ancient(stateHistoryAccountData, id-1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	storageData, err := db.Ancient(stateHistoryStorageData, id-1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return meta, accountIndex, storageIndex, accountData, storageData, nil
}

// WriteStateHistory writes the provided state history to database. Compute the
// position of state history in freezer by minus one since the id of first state
// history starts from one(zero for initial state).
// WriteStateHistory 将提供的状态历史写入数据库。由于第一个状态历史的 ID 从 1 开始（初始状态为零），
// 因此需要计算在冷冻存储中的位置。
func WriteStateHistory(db ethdb.AncientWriter, id uint64, meta []byte, accountIndex []byte, storageIndex []byte, accounts []byte, storages []byte) {
	db.ModifyAncients(func(op ethdb.AncientWriteOp) error {
		// 将相关的多个状态历史信息以原始数据形式追加
		op.AppendRaw(stateHistoryMeta, id-1, meta)
		op.AppendRaw(stateHistoryAccountIndex, id-1, accountIndex)
		op.AppendRaw(stateHistoryStorageIndex, id-1, storageIndex)
		op.AppendRaw(stateHistoryAccountData, id-1, accounts)
		op.AppendRaw(stateHistoryStorageData, id-1, storages)
		return nil
	})
}
