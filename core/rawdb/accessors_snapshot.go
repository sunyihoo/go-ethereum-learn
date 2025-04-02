// Copyright 2019 The go-ethereum Authors
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

// 处理快照系统的各个部分，包括快照标志、存储的状态根、账户状态和存储状态等数据的读写和删除。

// SnapshotDisabled（快照禁用标记）
// 暂停快照维护的场景：
// 当快速链同步（Fast Sync）模式完成时，新快照可能还需要时间生成。
// 由于快照机制使用额外的存储资源，可能在某些场景下被暂停。

// ReadSnapshotDisabled retrieves if the snapshot maintenance is disabled.
// ReadSnapshotDisabled 检索快照维护是否被禁用。
func ReadSnapshotDisabled(db ethdb.KeyValueReader) bool {
	disabled, _ := db.Has(snapshotDisabledKey)
	return disabled
}

// WriteSnapshotDisabled stores the snapshot pause flag.
// WriteSnapshotDisabled 存储快照维护暂停的标记。
func WriteSnapshotDisabled(db ethdb.KeyValueWriter) {
	if err := db.Put(snapshotDisabledKey, []byte("42")); err != nil {
		log.Crit("Failed to store snapshot disabled flag", "err", err)
	}
}

// DeleteSnapshotDisabled deletes the flag keeping the snapshot maintenance disabled.
// DeleteSnapshotDisabled 删除快照维护暂停的标记。
func DeleteSnapshotDisabled(db ethdb.KeyValueWriter) {
	if err := db.Delete(snapshotDisabledKey); err != nil {
		log.Crit("Failed to remove snapshot disabled flag", "err", err)
	}
}

// SnapshotRoot（块状态根哈希）
// SnapshotRoot 是存储状态快照的逻辑入口，它标记当前快照保存的状态根对应的块号或哈希。
//
// 读快照根（ReadSnapshotRoot）：检索当前快照中保存状态的块根。
// 写快照根（WriteSnapshotRoot）：更新当前快照对应的区块状态，这通常在快照生成或更新之后调用。
// 删除快照根（DeleteSnapshotRoot）：
//  - 如果快照被中断（如故障或重启），此方法可用于将快照标记为不可用。
//  - 确保系统不会继续使用部分已被破坏的快照。

// ReadSnapshotRoot retrieves the root of the block whose state is contained in
// the persisted snapshot.
// ReadSnapshotRoot 检索快照保存的块状态的根哈希值。
func ReadSnapshotRoot(db ethdb.KeyValueReader) common.Hash {
	data, _ := db.Get(SnapshotRootKey)
	if len(data) != common.HashLength {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// WriteSnapshotRoot stores the root of the block whose state is contained in
// the persisted snapshot.
// WriteSnapshotRoot 存储快照保存的块状态的根哈希值。
func WriteSnapshotRoot(db ethdb.KeyValueWriter, root common.Hash) {
	if err := db.Put(SnapshotRootKey, root[:]); err != nil {
		log.Crit("Failed to store snapshot root", "err", err)
	}
}

// DeleteSnapshotRoot deletes the hash of the block whose state is contained in
// the persisted snapshot. Since snapshots are not immutable, this  method can
// be used during updates, so a crash or failure will mark the entire snapshot
// invalid.
//
// DeleteSnapshotRoot 删除快照保存的块状态根哈希值。
// 快照不是不可变的，因此这个方法在更新过程中可以被使用，崩溃或失败可能会标记整个快照为无效。
func DeleteSnapshotRoot(db ethdb.KeyValueWriter) {
	if err := db.Delete(SnapshotRootKey); err != nil {
		log.Crit("Failed to remove snapshot root", "err", err)
	}
}

// WriteAccountSnapshot: 保存账户树叶子节点条目的快照。
// WriteStorageSnapshot: 保存某个账户存储槽的数据。
//
// 与状态树相关的优化：
//
// 状态树（Merkle Patricia Trie）保存以太坊所有账户的状态和其存储（存储槽）。
// 快照保存不经压缩的状态直接取值，可以绕过状态树的递归。
// 快照存储方案能够提高性能10倍以上。

// ReadAccountSnapshot retrieves the snapshot entry of an account trie leaf.
// ReadAccountSnapshot 检索账户状态树（Trie）的快照条目。
func ReadAccountSnapshot(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, _ := db.Get(accountSnapshotKey(hash))
	return data
}

// WriteAccountSnapshot stores the snapshot entry of an account trie leaf.
// WriteAccountSnapshot 存储账户状态树（Trie）的快照条目。
func WriteAccountSnapshot(db ethdb.KeyValueWriter, hash common.Hash, entry []byte) {
	if err := db.Put(accountSnapshotKey(hash), entry); err != nil {
		log.Crit("Failed to store account snapshot", "err", err)
	}
}

// DeleteAccountSnapshot removes the snapshot entry of an account trie leaf.
// DeleteAccountSnapshot 删除账户 trie 叶子的快照条目。
func DeleteAccountSnapshot(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(accountSnapshotKey(hash)); err != nil {
		log.Crit("Failed to delete account snapshot", "err", err)
	}
}

// ReadStorageSnapshot retrieves the snapshot entry of a storage trie leaf.
// ReadStorageSnapshot 读取存储 trie 叶子的快照条目。
func ReadStorageSnapshot(db ethdb.KeyValueReader, accountHash, storageHash common.Hash) []byte {
	data, _ := db.Get(storageSnapshotKey(accountHash, storageHash))
	return data
}

// WriteStorageSnapshot stores the snapshot entry of a storage trie leaf.
// WriteStorageSnapshot 存储存储 trie 叶子的快照条目。
func WriteStorageSnapshot(db ethdb.KeyValueWriter, accountHash, storageHash common.Hash, entry []byte) {
	if err := db.Put(storageSnapshotKey(accountHash, storageHash), entry); err != nil {
		log.Crit("Failed to store storage snapshot", "err", err)
	}
}

// DeleteStorageSnapshot removes the snapshot entry of a storage trie leaf.
// DeleteStorageSnapshot 删除存储 trie 叶子的快照条目。
func DeleteStorageSnapshot(db ethdb.KeyValueWriter, accountHash, storageHash common.Hash) {
	if err := db.Delete(storageSnapshotKey(accountHash, storageHash)); err != nil {
		log.Crit("Failed to delete storage snapshot", "err", err)
	}
}

// IterateStorageSnapshots returns an iterator for walking the entire storage
// space of a specific account.
// IterateStorageSnapshots 返回用于遍历特定账户全部存储空间的迭代器。
func IterateStorageSnapshots(db ethdb.Iteratee, accountHash common.Hash) ethdb.Iterator {
	return NewKeyLengthIterator(db.NewIterator(storageSnapshotsKey(accountHash), nil), len(SnapshotStoragePrefix)+2*common.HashLength)
}

// SnapshotJournal
// 快照日志（Journal）负责在内存中的"差异快照层"（Diff Layer）序列化保存。
// 在客户端崩溃或维护时可以重建部分快照。
// 场景：
//  崩溃后从日志恢复。
//  差异层用于动态状态的快速查询。

// ReadSnapshotJournal retrieves the serialized in-memory diff layers saved at
// the last shutdown. The blob is expected to be max a few 10s of megabytes.
//
// ReadSnapshotJournal 读取在最后一次关机时保存的序列化内存差异层。
// 此数据块的大小预计为最多数十兆字节。
func ReadSnapshotJournal(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(snapshotJournalKey)
	return data
}

// WriteSnapshotJournal stores the serialized in-memory diff layers to save at
// shutdown. The blob is expected to be max a few 10s of megabytes.
//
// WriteSnapshotJournal 存储序列化的内存差异层以在关闭时保存。
// 此数据块的大小预计为最多数十兆字节。
func WriteSnapshotJournal(db ethdb.KeyValueWriter, journal []byte) {
	if err := db.Put(snapshotJournalKey, journal); err != nil {
		log.Crit("Failed to store snapshot journal", "err", err)
	}
}

// DeleteSnapshotJournal deletes the serialized in-memory diff layers saved at
// the last shutdown
// DeleteSnapshotJournal 删除在最后一次关机时保存的序列化内存差异层。
func DeleteSnapshotJournal(db ethdb.KeyValueWriter) {
	if err := db.Delete(snapshotJournalKey); err != nil {
		log.Crit("Failed to remove snapshot journal", "err", err)
	}
}

// ReadSnapshotGenerator retrieves the serialized snapshot generator saved at
// the last shutdown.
// ReadSnapshotGenerator 读取在最后一次关机时保存的序列化快照生成器。
func ReadSnapshotGenerator(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(snapshotGeneratorKey)
	return data
}

// WriteSnapshotGenerator stores the serialized snapshot generator to save at
// shutdown.
// WriteSnapshotGenerator 存储序列化快照生成器以在关闭时保存。
func WriteSnapshotGenerator(db ethdb.KeyValueWriter, generator []byte) {
	if err := db.Put(snapshotGeneratorKey, generator); err != nil {
		log.Crit("Failed to store snapshot generator", "err", err)
	}
}

// DeleteSnapshotGenerator deletes the serialized snapshot generator saved at
// the last shutdown
// DeleteSnapshotGenerator 删除在最后一次关机时保存的序列化快照生成器。
func DeleteSnapshotGenerator(db ethdb.KeyValueWriter) {
	if err := db.Delete(snapshotGeneratorKey); err != nil {
		log.Crit("Failed to remove snapshot generator", "err", err)
	}
}

// ReadSnapshotRecoveryNumber retrieves the block number of the last persisted
// snapshot layer.
// ReadSnapshotRecoveryNumber 读取最后一次持久化快照层的区块编号。
func ReadSnapshotRecoveryNumber(db ethdb.KeyValueReader) *uint64 {
	data, _ := db.Get(snapshotRecoveryKey)
	if len(data) == 0 {
		return nil
	}
	if len(data) != 8 {
		return nil
	}
	number := binary.BigEndian.Uint64(data) // 将数据解码为区块编号
	return &number
}

// WriteSnapshotRecoveryNumber stores the block number of the last persisted
// snapshot layer.
// WriteSnapshotRecoveryNumber 存储最后一次持久化快照层的区块编号。
func WriteSnapshotRecoveryNumber(db ethdb.KeyValueWriter, number uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], number)
	if err := db.Put(snapshotRecoveryKey, buf[:]); err != nil {
		log.Crit("Failed to store snapshot recovery number", "err", err)
	}
}

// DeleteSnapshotRecoveryNumber deletes the block number of the last persisted
// snapshot layer.
// DeleteSnapshotRecoveryNumber 删除最后一次持久化快照层的区块编号。
func DeleteSnapshotRecoveryNumber(db ethdb.KeyValueWriter) {
	if err := db.Delete(snapshotRecoveryKey); err != nil {
		log.Crit("Failed to remove snapshot recovery number", "err", err)
	}
}

// 快照同步状态 (ReadSnapshotSyncStatus, WriteSnapshotSyncStatus)
// 记录客户端在快照生成或同步过程中具体的状态信息。
// 保存此数据是为了确保在客户端启动时能够快速恢复同步任务。

// ReadSnapshotSyncStatus retrieves the serialized sync status saved at shutdown.
// ReadSnapshotSyncStatus 读取在关机时保存的序列化同步状态。
func ReadSnapshotSyncStatus(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(snapshotSyncStatusKey)
	return data
}

// WriteSnapshotSyncStatus stores the serialized sync status to save at shutdown.
// WriteSnapshotSyncStatus 存储序列化的同步状态以在关闭时保存。
func WriteSnapshotSyncStatus(db ethdb.KeyValueWriter, status []byte) {
	if err := db.Put(snapshotSyncStatusKey, status); err != nil {
		log.Crit("Failed to store snapshot sync status", "err", err)
	}
}

// 数据模型分离
// 数据分为多个逻辑模块：根哈希（SnapshotRoot）、账户快照（AccountSnapshot）、存储快照（StorageSnapshot）等，简化了快照管理的复杂度。
// 每组数据都有独立的键（例如 SnapshotRootKey）。
