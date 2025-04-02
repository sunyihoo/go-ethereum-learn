// Copyright 2018 The go-ethereum Authors
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
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// 数据库版本兼容：支持多种格式，例如仅存块号(v6)、仅存哈希(v4-v5)，或存完整元数据(v3格式，RLP编码)。
// 数据格式：TxLookupEntry 数据表为检索特殊优化，避免在整个链上搜索，提高定位性能。

// ReadTxLookupEntry retrieves the positional metadata associated with a transaction
// hash to allow retrieving the transaction or receipt by hash.
// ReadTxLookupEntry 检索与交易哈希相关联的元数据信息，可以通过哈希找到交易或收据。
// 用于检索和管理交易元数据。每次交易都有其唯一的哈希值，
// 为了能够快速定位交易对应的块号(blockNumber)或偏移位置，以太坊会维护 TxLookupEntry 数据表。
func ReadTxLookupEntry(db ethdb.Reader, hash common.Hash) *uint64 {
	data, _ := db.Get(txLookupKey(hash))
	if len(data) == 0 {
		return nil
	}
	// Database v6 tx lookup just stores the block number
	// 数据库 v6：只存储块号信息
	if len(data) < common.HashLength {
		number := new(big.Int).SetBytes(data).Uint64()
		return &number
	}
	// Database v4-v5 tx lookup format just stores the hash
	// 数据库 v4-v5：只存储哈希信息
	if len(data) == common.HashLength {
		return ReadHeaderNumber(db, common.BytesToHash(data))
	}
	// Finally try database v3 tx lookup format
	// 数据库 v3：尝试用 RLP 格式存储的早期格式
	var entry LegacyTxLookupEntry
	if err := rlp.DecodeBytes(data, &entry); err != nil {
		log.Error("Invalid transaction lookup entry RLP", "hash", hash, "blob", data, "err", err)
		return nil
	}
	return &entry.BlockIndex
}

// writeTxLookupEntry stores a positional metadata for a transaction,
// enabling hash based transaction and receipt lookups.
//
// writeTxLookupEntry 为交易存储元数据，支持基于哈希的交易和收据查询。
func writeTxLookupEntry(db ethdb.KeyValueWriter, hash common.Hash, numberBytes []byte) {
	if err := db.Put(txLookupKey(hash), numberBytes); err != nil {
		log.Crit("Failed to store transaction lookup entry", "err", err)
	}
}

// WriteTxLookupEntries is identical to WriteTxLookupEntry, but it works on
// a list of hashes
// WriteTxLookupEntries 与 WriteTxLookupEntry 功能相同，但支持一组哈希操作。
func WriteTxLookupEntries(db ethdb.KeyValueWriter, number uint64, hashes []common.Hash) {
	numberBytes := new(big.Int).SetUint64(number).Bytes()
	for _, hash := range hashes {
		writeTxLookupEntry(db, hash, numberBytes)
	}
}

// WriteTxLookupEntriesByBlock stores a positional metadata for every transaction from
// a block, enabling hash based transaction and receipt lookups.
//
// WriteTxLookupEntriesByBlock 为一个区块中的所有交易存储元数据，支持基于哈希的交易和收据查询。
// 将区块中的每笔交易数据信息写入 TxLookupEntry。在区块内数据打包后，该过程是每次同步或写入的必做工作。
func WriteTxLookupEntriesByBlock(db ethdb.KeyValueWriter, block *types.Block) {
	numberBytes := block.Number().Bytes()
	for _, tx := range block.Transactions() {
		writeTxLookupEntry(db, tx.Hash(), numberBytes)
	}
}

// DeleteTxLookupEntry removes all transaction data associated with a hash.
//
// DeleteTxLookupEntry 删除与交易哈希相关的所有数据。
func DeleteTxLookupEntry(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(txLookupKey(hash)); err != nil {
		log.Crit("Failed to delete transaction lookup entry", "err", err)
	}
}

// DeleteTxLookupEntries removes all transaction lookups for a given block.
// DeleteTxLookupEntries 删除与给定的区块相关的所有交易数据。
func DeleteTxLookupEntries(db ethdb.KeyValueWriter, hashes []common.Hash) {
	for _, hash := range hashes {
		DeleteTxLookupEntry(db, hash)
	}
}

// ReadTransaction retrieves a specific transaction from the database, along with
// its added positional metadata.
// ReadTransaction 从数据库检索特定交易，同时返回其附加的元数据信息。
func ReadTransaction(db ethdb.Reader, hash common.Hash) (*types.Transaction, common.Hash, uint64, uint64) {
	blockNumber := ReadTxLookupEntry(db, hash)
	if blockNumber == nil {
		return nil, common.Hash{}, 0, 0
	}
	blockHash := ReadCanonicalHash(db, *blockNumber)
	if blockHash == (common.Hash{}) {
		return nil, common.Hash{}, 0, 0
	}
	body := ReadBody(db, blockHash, *blockNumber)
	if body == nil {
		log.Error("Transaction referenced missing", "number", *blockNumber, "hash", blockHash)
		return nil, common.Hash{}, 0, 0
	}
	for txIndex, tx := range body.Transactions {
		if tx.Hash() == hash {
			return tx, blockHash, *blockNumber, uint64(txIndex)
		}
	}
	log.Error("Transaction not found", "number", *blockNumber, "hash", blockHash, "txhash", hash)
	return nil, common.Hash{}, 0, 0
}

// ReadReceipt retrieves a specific transaction receipt from the database, along with
// its added positional metadata.
// ReadReceipt 从数据库检索特定交易的收据，同时返回其附加的元数据信息。
func ReadReceipt(db ethdb.Reader, hash common.Hash, config *params.ChainConfig) (*types.Receipt, common.Hash, uint64, uint64) {
	// Retrieve the context of the receipt based on the transaction hash
	blockNumber := ReadTxLookupEntry(db, hash)
	if blockNumber == nil {
		return nil, common.Hash{}, 0, 0
	}
	blockHash := ReadCanonicalHash(db, *blockNumber)
	if blockHash == (common.Hash{}) {
		return nil, common.Hash{}, 0, 0
	}
	blockHeader := ReadHeader(db, blockHash, *blockNumber)
	if blockHeader == nil {
		return nil, common.Hash{}, 0, 0
	}
	// Read all the receipts from the block and return the one with the matching hash
	receipts := ReadReceipts(db, blockHash, *blockNumber, blockHeader.Time, config)
	for receiptIndex, receipt := range receipts {
		if receipt.TxHash == hash {
			return receipt, blockHash, *blockNumber, uint64(receiptIndex)
		}
	}
	log.Error("Receipt not found", "number", *blockNumber, "hash", blockHash, "txhash", hash)
	return nil, common.Hash{}, 0, 0
}

// ReadBloomBits retrieves the compressed bloom bit vector belonging to the given
// section and bit index from the.
// ReadBloomBits 获取给定区段和比特索引的压缩布隆过滤器向量。
func ReadBloomBits(db ethdb.KeyValueReader, bit uint, section uint64, head common.Hash) ([]byte, error) {
	return db.Get(bloomBitsKey(bit, section, head))
}

// WriteBloomBits stores the compressed bloom bits vector belonging to the given
// section and bit index.
// WriteBloomBits 存储给定区段和比特索引的压缩布隆过滤器向量。
func WriteBloomBits(db ethdb.KeyValueWriter, bit uint, section uint64, head common.Hash, bits []byte) {
	if err := db.Put(bloomBitsKey(bit, section, head), bits); err != nil {
		log.Crit("Failed to store bloom bits", "err", err)
	}
}

// DeleteBloombits removes all compressed bloom bits vector belonging to the
// given section range and bit index.
// DeleteBloombits 删除给定区段范围和比特索引的所有压缩布隆过滤器向量。
func DeleteBloombits(db ethdb.Database, bit uint, from uint64, to uint64) {
	start, end := bloomBitsKey(bit, from, common.Hash{}), bloomBitsKey(bit, to, common.Hash{})
	it := db.NewIterator(nil, start)
	defer it.Release()

	for it.Next() {
		if bytes.Compare(it.Key(), end) >= 0 {
			break
		}
		if len(it.Key()) != len(bloomBitsPrefix)+2+8+32 {
			continue
		}
		db.Delete(it.Key())
	}
	if it.Error() != nil {
		log.Crit("Failed to delete bloom bits", "err", it.Error())
	}
}
