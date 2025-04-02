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

// Package rawdb contains a collection of low level database accessors.
package rawdb

import (
	"bytes"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/metrics"
)

// The fields below define the low level database schema prefixing.
// 下面的字段定义了低级数据库模式的前缀。
var (
	// databaseVersionKey tracks the current database version.
	// databaseVersionKey 跟踪当前数据库版本。
	databaseVersionKey = []byte("DatabaseVersion")

	// headHeaderKey tracks the latest known header's hash.
	// headHeaderKey 跟踪最新已知区块头的哈希。
	headHeaderKey = []byte("LastHeader")

	// headBlockKey tracks the latest known full block's hash.
	// headBlockKey 跟踪最新已知完整区块的哈希。
	headBlockKey = []byte("LastBlock")

	// headFastBlockKey tracks the latest known incomplete block's hash during fast sync.
	// headFastBlockKey 在快速同步期间跟踪最新已知不完整区块的哈希。
	headFastBlockKey = []byte("LastFast")

	// headFinalizedBlockKey tracks the latest known finalized block hash.
	// headFinalizedBlockKey 跟踪最新已知最终确定区块的哈希。
	headFinalizedBlockKey = []byte("LastFinalized")

	// persistentStateIDKey tracks the id of latest stored state(for path-based only).
	// persistentStateIDKey 跟踪最新存储状态的ID（仅适用于基于路径的存储）。
	persistentStateIDKey = []byte("LastStateID")

	// lastPivotKey tracks the last pivot block used by fast sync (to reenable on sethead).
	// lastPivotKey 跟踪快速同步使用的最后一个枢轴区块（用于在 sethead 时重新启用）。
	lastPivotKey = []byte("LastPivot")

	// fastTrieProgressKey tracks the number of trie entries imported during fast sync.
	// fastTrieProgressKey 跟踪快速同步期间导入的 trie 条目数量。
	fastTrieProgressKey = []byte("TrieSync")

	// snapshotDisabledKey flags that the snapshot should not be maintained due to initial sync.
	// snapshotDisabledKey 标记由于初始同步而不应维护快照。
	snapshotDisabledKey = []byte("SnapshotDisabled")

	// SnapshotRootKey tracks the hash of the last snapshot.
	// SnapshotRootKey 跟踪最后一个快照的哈希。
	SnapshotRootKey = []byte("SnapshotRoot")

	// snapshotJournalKey tracks the in-memory diff layers across restarts.
	// snapshotJournalKey 跟踪跨重启的内存中差异层。
	snapshotJournalKey = []byte("SnapshotJournal")

	// snapshotGeneratorKey tracks the snapshot generation marker across restarts.
	// snapshotGeneratorKey 跟踪跨重启的快照生成标记。
	snapshotGeneratorKey = []byte("SnapshotGenerator")

	// snapshotRecoveryKey tracks the snapshot recovery marker across restarts.
	// snapshotRecoveryKey 跟踪跨重启的快照恢复标记。
	snapshotRecoveryKey = []byte("SnapshotRecovery")

	// snapshotSyncStatusKey tracks the snapshot sync status across restarts.
	// snapshotSyncStatusKey 跟踪跨重启的快照同步状态。
	snapshotSyncStatusKey = []byte("SnapshotSyncStatus")

	// skeletonSyncStatusKey tracks the skeleton sync status across restarts.
	// skeletonSyncStatusKey 跟踪跨重启的骨架同步状态。
	skeletonSyncStatusKey = []byte("SkeletonSyncStatus")

	// trieJournalKey tracks the in-memory trie node layers across restarts.
	// trieJournalKey 跟踪跨重启的内存中 trie 节点层。
	trieJournalKey = []byte("TrieJournal")

	// txIndexTailKey tracks the oldest block whose transactions have been indexed.
	// txIndexTailKey 跟踪其交易已被索引的最旧区块。
	txIndexTailKey = []byte("TransactionIndexTail")

	// fastTxLookupLimitKey tracks the transaction lookup limit during fast sync.
	// This flag is deprecated, it's kept to avoid reporting errors when inspect
	// database.
	// fastTxLookupLimitKey 跟踪快速同步期间的交易查找限制。
	// 此标志已弃用，保留它以避免在检查数据库时报告错误。
	fastTxLookupLimitKey = []byte("FastTransactionLookupLimit")

	// badBlockKey tracks the list of bad blocks seen by local
	// badBlockKey 跟踪本地看到的坏块列表。
	badBlockKey = []byte("InvalidBlock")

	// uncleanShutdownKey tracks the list of local crashes
	// uncleanShutdownKey 跟踪本地崩溃的列表。
	uncleanShutdownKey = []byte("unclean-shutdown") // config prefix for the db 数据库的配置前缀

	// transitionStatusKey tracks the eth2 transition status.
	// transitionStatusKey 跟踪 eth2 过渡状态。
	transitionStatusKey = []byte("eth2-transition")

	// snapSyncStatusFlagKey flags that status of snap sync.
	// snapSyncStatusFlagKey 标记快照同步的状态。
	snapSyncStatusFlagKey = []byte("SnapSyncStatus")

	// Data item prefixes (use single byte to avoid mixing data types, avoid `i`, used for indexes).
	// 数据项前缀（使用单字节以避免混合数据类型，避免使用“i”，因为它用于索引）。
	headerPrefix       = []byte("h") // headerPrefix + num (uint64 big endian) + hash -> header
	headerTDSuffix     = []byte("t") // headerPrefix + num (uint64 big endian) + hash + headerTDSuffix -> td
	headerHashSuffix   = []byte("n") // headerPrefix + num (uint64 big endian) + headerHashSuffix -> hash
	headerNumberPrefix = []byte("H") // headerNumberPrefix + hash -> num (uint64 big endian)

	blockBodyPrefix     = []byte("b") // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	blockReceiptsPrefix = []byte("r") // blockReceiptsPrefix + num (uint64 big endian) + hash -> block receipts

	txLookupPrefix        = []byte("l") // txLookupPrefix + hash -> transaction/receipt lookup metadata
	bloomBitsPrefix       = []byte("B") // bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash -> bloom bits
	SnapshotAccountPrefix = []byte("a") // SnapshotAccountPrefix + account hash -> account trie value
	SnapshotStoragePrefix = []byte("o") // SnapshotStoragePrefix + account hash + storage hash -> storage trie value
	CodePrefix            = []byte("c") // CodePrefix + code hash -> account code
	skeletonHeaderPrefix  = []byte("S") // skeletonHeaderPrefix + num (uint64 big endian) -> header

	// Path-based storage scheme of merkle patricia trie.
	// Merkle Patricia Trie 的基于路径的存储方案。
	TrieNodeAccountPrefix = []byte("A") // TrieNodeAccountPrefix + hexPath -> trie node
	TrieNodeStoragePrefix = []byte("O") // TrieNodeStoragePrefix + accountHash + hexPath -> trie node
	stateIDPrefix         = []byte("L") // stateIDPrefix + state root -> state id

	// VerklePrefix is the database prefix for Verkle trie data, which includes:
	// (a) Trie nodes
	// (b) In-memory trie node journal
	// (c) Persistent state ID
	// (d) State ID lookups, etc.
	//
	// VerklePrefix 是 Verkle trie 数据的数据库前缀，包括：
	// (a) Trie 节点
	// (b) 内存中的 trie 节点日志
	// (c) 持久化状态 ID
	// (d) 状态 ID 查找等。
	VerklePrefix = []byte("v")

	PreimagePrefix = []byte("secure-key-")       // PreimagePrefix + hash -> preimage
	configPrefix   = []byte("ethereum-config-")  // config prefix for the db
	genesisPrefix  = []byte("ethereum-genesis-") // genesis state prefix for the db

	// BloomBitsIndexPrefix is the data table of a chain indexer to track its progress
	// BloomBitsIndexPrefix 是链索引器的数据表，用于跟踪其进度
	BloomBitsIndexPrefix = []byte("iB")

	ChtPrefix           = []byte("chtRootV2-") // ChtPrefix + chtNum (uint64 big endian) -> trie root hash
	ChtTablePrefix      = []byte("cht-")
	ChtIndexTablePrefix = []byte("chtIndexV2-")

	BloomTriePrefix      = []byte("bltRoot-") // BloomTriePrefix + bloomTrieNum (uint64 big endian) -> trie root hash
	BloomTrieTablePrefix = []byte("blt-")
	BloomTrieIndexPrefix = []byte("bltIndex-")

	CliqueSnapshotPrefix = []byte("clique-")

	BestUpdateKey         = []byte("update-")    // bigEndian64(syncPeriod) -> RLP(types.LightClientUpdate)  (nextCommittee only referenced by root hash)
	FixedCommitteeRootKey = []byte("fixedRoot-") // bigEndian64(syncPeriod) -> committee root hash
	SyncCommitteeKey      = []byte("committee-") // bigEndian64(syncPeriod) -> serialized committee

	preimageCounter    = metrics.NewRegisteredCounter("db/preimage/total", nil)
	preimageHitCounter = metrics.NewRegisteredCounter("db/preimage/hits", nil)
)

// 交易查找（Transaction Lookup）
// 以太坊节点需要快速定位交易，LegacyTxLookupEntry 是早期实现的一部分，与 txLookupPrefix 前缀结合使用，映射交易哈希到其位置。
// 例如，键 txLookupPrefix + txHash -> 值 LegacyTxLookupEntry，提供区块和索引信息。
// LevelDB 存储：LegacyTxLookupEntry 通常与 txLookupPrefix 前缀结合，存储在键值数据库中，键值对形式为 l + txHash -> RLP(LegacyTxLookupEntry)。

// LegacyTxLookupEntry is the legacy TxLookupEntry definition with some unnecessary
// fields.
// LegacyTxLookupEntry 是旧版 TxLookupEntry 定义，包含一些不必要的字段。
type LegacyTxLookupEntry struct {
	BlockHash  common.Hash // 区块哈希
	BlockIndex uint64      // 区块索引
	Index      uint64      // 交易索引
}

// 共同逻辑：通过拼接前缀、块编号（大端序编码）和哈希（或后缀），生成数据库键。
// 函数列表：
// headerKeyPrefix：生成区块头键的前缀部分（headerPrefix + num）。
// headerKey：生成完整区块头键（headerPrefix + num + hash）。
// headerTDKey：生成总难度键（headerPrefix + num + hash + headerTDSuffix）。
// headerHashKey：生成块哈希键（headerPrefix + num + headerHashSuffix）。
// headerNumberKey：生成块编号键（headerNumberPrefix + hash）。
// blockBodyKey：生成区块体键（blockBodyPrefix + num + hash）。
// blockReceiptsKey：生成区块收据键（blockReceiptsPrefix + num + hash）。

// encodeBlockNumber：将 uint64 转换为固定 8 字节的大端序表示，例如 number=1 编码为 [0, 0, 0, 0, 0, 0, 0, 1]。
// 键拼接：
// headerKeyPrefix(1)：h + [0, 0, 0, 0, 0, 0, 0, 1]。
// headerKey(1, hash)：h + [0, 0, 0, 0, 0, 0, 0, 1] + hash.Bytes()。
// headerTDKey(1, hash)：h + [0, 0, 0, 0, 0, 0, 0, 1] + hash.Bytes() + t。

// encodeBlockNumber encodes a block number as big endian uint64
// encodeBlockNumber 将块编号编码为大端序 uint64
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerKeyPrefix = headerPrefix + num (uint64 big endian)
func headerKeyPrefix(number uint64) []byte {
	return append(headerPrefix, encodeBlockNumber(number)...)
}

// headerKey = headerPrefix + num (uint64 big endian) + hash
func headerKey(number uint64, hash common.Hash) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// headerTDKey = headerPrefix + num (uint64 big endian) + hash + headerTDSuffix
func headerTDKey(number uint64, hash common.Hash) []byte {
	return append(headerKey(number, hash), headerTDSuffix...)
}

// headerHashKey = headerPrefix + num (uint64 big endian) + headerHashSuffix
func headerHashKey(number uint64) []byte {
	return append(append(headerPrefix, encodeBlockNumber(number)...), headerHashSuffix...)
}

// headerNumberKey = headerNumberPrefix + hash
func headerNumberKey(hash common.Hash) []byte {
	return append(headerNumberPrefix, hash.Bytes()...)
}

// blockBodyKey = blockBodyPrefix + num (uint64 big endian) + hash
func blockBodyKey(number uint64, hash common.Hash) []byte {
	return append(append(blockBodyPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// blockReceiptsKey = blockReceiptsPrefix + num (uint64 big endian) + hash
func blockReceiptsKey(number uint64, hash common.Hash) []byte {
	return append(append(blockReceiptsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// txLookupKey = txLookupPrefix + hash
// 生成交易查找键，用于定位交易在链中的位置。
func txLookupKey(hash common.Hash) []byte {
	return append(txLookupPrefix, hash.Bytes()...)
}

// accountSnapshotKey = SnapshotAccountPrefix + hash
// 生成账户快照键，用于存储账户状态快照。
func accountSnapshotKey(hash common.Hash) []byte {
	return append(SnapshotAccountPrefix, hash.Bytes()...)
}

// storageSnapshotKey = SnapshotStoragePrefix + account hash + storage hash
// 生成存储快照键，用于存储账户的特定存储槽数据。
func storageSnapshotKey(accountHash, storageHash common.Hash) []byte {
	buf := make([]byte, len(SnapshotStoragePrefix)+common.HashLength+common.HashLength)
	n := copy(buf, SnapshotStoragePrefix)
	n += copy(buf[n:], accountHash.Bytes())
	copy(buf[n:], storageHash.Bytes())
	return buf
}

// storageSnapshotsKey = SnapshotStoragePrefix + account hash + storage hash
// 生成账户存储快照的前缀键
func storageSnapshotsKey(accountHash common.Hash) []byte {
	return append(SnapshotStoragePrefix, accountHash.Bytes()...)
}

// bloomBitsKey = bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash
// 生成布隆位键，用于布隆过滤器索引。
func bloomBitsKey(bit uint, section uint64, hash common.Hash) []byte {
	key := append(append(bloomBitsPrefix, make([]byte, 10)...), hash.Bytes()...)

	binary.BigEndian.PutUint16(key[1:], uint16(bit))
	binary.BigEndian.PutUint64(key[3:], section)

	return key
}

// skeletonHeaderKey = skeletonHeaderPrefix + num (uint64 big endian)
// 生成骨架区块头键，用于骨架同步。
func skeletonHeaderKey(number uint64) []byte {
	return append(skeletonHeaderPrefix, encodeBlockNumber(number)...)
}

// preimageKey = PreimagePrefix + hash
func preimageKey(hash common.Hash) []byte {
	return append(PreimagePrefix, hash.Bytes()...)
}

// codeKey = CodePrefix + hash
// 生成合约代码的键，用于存储或检索代码数据。
func codeKey(hash common.Hash) []byte {
	return append(CodePrefix, hash.Bytes()...)
}

// IsCodeKey reports whether the given byte slice is the key of contract code,
// if so return the raw code hash as well.
// IsCodeKey 报告给定的字节切片是否是合约代码的键，如果是，则同时返回原始代码哈希。
func IsCodeKey(key []byte) (bool, []byte) {
	if bytes.HasPrefix(key, CodePrefix) && len(key) == common.HashLength+len(CodePrefix) {
		return true, key[len(CodePrefix):]
	}
	return false, nil
}

// configKey = configPrefix + hash
// 生成配置数据的键。
func configKey(hash common.Hash) []byte {
	return append(configPrefix, hash.Bytes()...)
}

// genesisStateSpecKey = genesisPrefix + hash
// 生成创世状态规范的键。
func genesisStateSpecKey(hash common.Hash) []byte {
	return append(genesisPrefix, hash.Bytes()...)
}

// stateIDKey = stateIDPrefix + root (32 bytes)
// 生成状态 ID 的键，基于状态根。
func stateIDKey(root common.Hash) []byte {
	return append(stateIDPrefix, root.Bytes()...)
}

// accountTrieNodeKey = TrieNodeAccountPrefix + nodePath.
// 生成账户 Trie 节点的键。
func accountTrieNodeKey(path []byte) []byte {
	return append(TrieNodeAccountPrefix, path...)
}

// storageTrieNodeKey = TrieNodeStoragePrefix + accountHash + nodePath.
// 生成存储 Trie 节点的键。
func storageTrieNodeKey(accountHash common.Hash, path []byte) []byte {
	buf := make([]byte, len(TrieNodeStoragePrefix)+common.HashLength+len(path))
	n := copy(buf, TrieNodeStoragePrefix)
	n += copy(buf[n:], accountHash.Bytes())
	copy(buf[n:], path)
	return buf
}

// IsLegacyTrieNode reports whether a provided database entry is a legacy trie
// node. The characteristics of legacy trie node are:
// - the key length is 32 bytes
// - the key is the hash of val
//
// IsLegacyTrieNode 报告提供的数据库条目是否是遗留 trie 节点。遗留 trie 节点的特征是：
// - 键的长度为 32 字节
// - 键是 val 的哈希
func IsLegacyTrieNode(key []byte, val []byte) bool {
	if len(key) != common.HashLength {
		return false
	}
	return bytes.Equal(key, crypto.Keccak256(val))
}

// ResolveAccountTrieNodeKey reports whether a provided database entry is an
// account trie node in path-based state scheme, and returns the resolved
// node path if so.
//
// ResolveAccountTrieNodeKey 报告提供的数据库条目是否是基于路径状态方案中的账户 trie 节点，
// 如果是，则返回解析后的节点路径。
func ResolveAccountTrieNodeKey(key []byte) (bool, []byte) {
	if !bytes.HasPrefix(key, TrieNodeAccountPrefix) {
		return false, nil
	}
	// The remaining key should only consist a hex node path
	// whose length is in the range 0 to 64 (64 is excluded
	// since leaves are always wrapped with shortNode).
	// 剩余的键应仅包含一个十六进制节点路径，
	// 其长度在 0 到 64 之间（不包括 64，因为叶子节点总是用 shortNode 包装）。
	if len(key) >= len(TrieNodeAccountPrefix)+common.HashLength*2 {
		return false, nil
	}
	return true, key[len(TrieNodeAccountPrefix):]
}

// IsAccountTrieNode reports whether a provided database entry is an account
// trie node in path-based state scheme.
// IsAccountTrieNode 报告提供的数据库条目是否是基于路径状态方案中的账户 trie 节点。
func IsAccountTrieNode(key []byte) bool {
	ok, _ := ResolveAccountTrieNodeKey(key)
	return ok
}

// ResolveStorageTrieNode reports whether a provided database entry is a storage
// trie node in path-based state scheme, and returns the resolved account hash
// and node path if so.
// ResolveStorageTrieNode 报告提供的数据库条目是否是基于路径状态方案中的存储 trie 节点，
// 如果是，则返回解析后的账户哈希和节点路径。
func ResolveStorageTrieNode(key []byte) (bool, common.Hash, []byte) {
	if !bytes.HasPrefix(key, TrieNodeStoragePrefix) {
		return false, common.Hash{}, nil
	}
	// The remaining key consists of 2 parts:
	// - 32 bytes account hash
	// - hex node path whose length is in the range 0 to 64
	// 剩余的键由 2 部分组成：
	// - 32 字节的账户哈希
	// - 十六进制节点路径，长度在 0 到 64 之间
	if len(key) < len(TrieNodeStoragePrefix)+common.HashLength {
		return false, common.Hash{}, nil
	}
	if len(key) >= len(TrieNodeStoragePrefix)+common.HashLength+common.HashLength*2 {
		return false, common.Hash{}, nil
	}
	accountHash := common.BytesToHash(key[len(TrieNodeStoragePrefix) : len(TrieNodeStoragePrefix)+common.HashLength])
	return true, accountHash, key[len(TrieNodeStoragePrefix)+common.HashLength:]
}

// IsStorageTrieNode reports whether a provided database entry is a storage
// trie node in path-based state scheme.
// IsStorageTrieNode 报告提供的数据库条目是否是基于路径状态方案中的存储 trie 节点。
func IsStorageTrieNode(key []byte) bool {
	ok, _, _ := ResolveStorageTrieNode(key)
	return ok
}
