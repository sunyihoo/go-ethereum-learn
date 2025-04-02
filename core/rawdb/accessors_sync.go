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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// ReadSkeletonSyncStatus retrieves the serialized sync status saved at shutdown.
// 读取在关闭时保存的序列化同步状态。
func ReadSkeletonSyncStatus(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(skeletonSyncStatusKey)
	return data
}

// WriteSkeletonSyncStatus stores the serialized sync status to save at shutdown.
// 将序列化同步状态存储以便在关闭时保存。
func WriteSkeletonSyncStatus(db ethdb.KeyValueWriter, status []byte) {
	if err := db.Put(skeletonSyncStatusKey, status); err != nil {
		log.Crit("Failed to store skeleton sync status", "err", err)
	}
}

// DeleteSkeletonSyncStatus deletes the serialized sync status saved at the last
// shutdown
// 删除在上次关闭时保存的序列化同步状态。
func DeleteSkeletonSyncStatus(db ethdb.KeyValueWriter) {
	if err := db.Delete(skeletonSyncStatusKey); err != nil {
		log.Crit("Failed to remove skeleton sync status", "err", err)
	}
}

// ReadSkeletonHeader retrieves a block header from the skeleton sync store,
// 从骨架同步存储中读取区块头。
func ReadSkeletonHeader(db ethdb.KeyValueReader, number uint64) *types.Header {
	data, _ := db.Get(skeletonHeaderKey(number))
	if len(data) == 0 {
		return nil
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(data, header); err != nil {
		log.Error("Invalid skeleton header RLP", "number", number, "err", err)
		return nil
	}
	return header // 返回解码后的区块头。
}

// WriteSkeletonHeader stores a block header into the skeleton sync store.
// 将区块头存储到骨架同步存储中。
func WriteSkeletonHeader(db ethdb.KeyValueWriter, header *types.Header) {
	data, err := rlp.EncodeToBytes(header)
	if err != nil {
		log.Crit("Failed to RLP encode header", "err", err)
	}
	key := skeletonHeaderKey(header.Number.Uint64())
	if err := db.Put(key, data); err != nil {
		log.Crit("Failed to store skeleton header", "err", err)
	}
}

// DeleteSkeletonHeader removes all block header data associated with a hash.
// 删除与给定数字关联的所有区块头数据。
func DeleteSkeletonHeader(db ethdb.KeyValueWriter, number uint64) {
	if err := db.Delete(skeletonHeaderKey(number)); err != nil {
		log.Crit("Failed to delete skeleton header", "err", err)
	}
}

const (
	StateSyncUnknown  = uint8(0) // flags the state snap sync is unknown 状态快照同步未知
	StateSyncRunning  = uint8(1) // flags the state snap sync is not completed yet 状态快照同步尚未完成
	StateSyncFinished = uint8(2) // flags the state snap sync is completed 状态快照同步已完成
)

// ReadSnapSyncStatusFlag retrieves the state snap sync status flag.
// 读取状态快照同步状态标志。
func ReadSnapSyncStatusFlag(db ethdb.KeyValueReader) uint8 {
	blob, err := db.Get(snapSyncStatusFlagKey)
	if err != nil || len(blob) != 1 {
		return StateSyncUnknown
	}
	return blob[0]
}

// WriteSnapSyncStatusFlag stores the state snap sync status flag into database.
// 将状态快照同步状态标志存储到数据库中。
func WriteSnapSyncStatusFlag(db ethdb.KeyValueWriter, flag uint8) {
	if err := db.Put(snapSyncStatusFlagKey, []byte{flag}); err != nil {
		log.Crit("Failed to store sync status flag", "err", err)
	}
}
