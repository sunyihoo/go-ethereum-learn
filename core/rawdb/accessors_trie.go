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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package rawdb

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// HashScheme is the legacy hash-based state scheme with which trie nodes are
// stored in the disk with node hash as the database key. The advantage of this
// scheme is that different versions of trie nodes can be stored in disk, which
// is very beneficial for constructing archive nodes. The drawback is it will
// store different trie nodes on the same path to different locations on the disk
// with no data locality, and it's unfriendly for designing state pruning.
//
// Now this scheme is still kept for backward compatibility, and it will be used
// for archive node and some other tries(e.g. light trie).
//
// HashScheme 是遗留的基于哈希的状态方案，其中 trie 节点以节点哈希作为数据库键存储在磁盘上。
// 这种方案的优点是可以将不同版本的 trie 节点存储在磁盘上，这对于构建归档节点非常有益。
// 缺点是它会将同一路径上的不同 trie 节点存储到磁盘上的不同位置，数据局部性差，并且不利于设计状态修剪。
//
// 现在，这种方案仍保留以向后兼容，并将用于归档节点和其他一些 trie（例如轻 trie）。
const HashScheme = "hash"

// PathScheme is the new path-based state scheme with which trie nodes are stored
// in the disk with node path as the database key. This scheme will only store one
// version of state data in the disk, which means that the state pruning operation
// is native. At the same time, this scheme will put adjacent trie nodes in the same
// area of the disk with good data locality property. But this scheme needs to rely
// on extra state diffs to survive deep reorg.
//
// PathScheme 是新的基于路径的状态方案，其中 trie 节点以节点路径作为数据库键存储在磁盘上。
// 这种方案只会将一个版本的状态数据存储在磁盘上，这意味着状态修剪操作是原生的。
// 同时，这种方案会将相邻的 trie 节点放在磁盘的同一区域，具有良好的数据局部性。
// 但这种方案需要依赖额外的状态差异来应对深层重组。
const PathScheme = "path"

// hasher is used to compute the sha256 hash of the provided data.
// hasher 用于计算提供数据的 sha256 哈希。
type hasher struct{ sha crypto.KeccakState }

var hasherPool = sync.Pool{
	New: func() interface{} { return &hasher{sha: crypto.NewKeccakState()} },
}

func newHasher() *hasher {
	return hasherPool.Get().(*hasher)
}

func (h *hasher) hash(data []byte) common.Hash {
	return crypto.HashData(h.sha, data)
}

func (h *hasher) release() {
	hasherPool.Put(h)
}

// ReadAccountTrieNode retrieves the account trie node with the specified node path.
// ReadAccountTrieNode 检索具有指定节点路径的账户 trie 节点。
func ReadAccountTrieNode(db ethdb.KeyValueReader, path []byte) []byte {
	data, _ := db.Get(accountTrieNodeKey(path))
	return data
}

// HasAccountTrieNode checks the presence of the account trie node with the
// specified node path, regardless of the node hash.
// HasAccountTrieNode 检查具有指定节点路径的账户 trie 节点的存在性，
// 而不考虑节点哈希。
func HasAccountTrieNode(db ethdb.KeyValueReader, path []byte) bool {
	has, err := db.Has(accountTrieNodeKey(path))
	if err != nil {
		return false
	}
	return has
}

// WriteAccountTrieNode writes the provided account trie node into database.
// WriteAccountTrieNode 将提供的账户 trie 节点写入数据库。
func WriteAccountTrieNode(db ethdb.KeyValueWriter, path []byte, node []byte) {
	if err := db.Put(accountTrieNodeKey(path), node); err != nil {
		log.Crit("Failed to store account trie node", "err", err)
	}
}

// DeleteAccountTrieNode deletes the specified account trie node from the database.
// DeleteAccountTrieNode 从数据库中删除指定的账户 trie 节点。
func DeleteAccountTrieNode(db ethdb.KeyValueWriter, path []byte) {
	if err := db.Delete(accountTrieNodeKey(path)); err != nil {
		log.Crit("Failed to delete account trie node", "err", err)
	}
}

// ReadStorageTrieNode retrieves the storage trie node with the specified node path.
// ReadStorageTrieNode 检索具有指定节点路径的存储 trie 节点。
func ReadStorageTrieNode(db ethdb.KeyValueReader, accountHash common.Hash, path []byte) []byte {
	data, _ := db.Get(storageTrieNodeKey(accountHash, path))
	return data
}

// HasStorageTrieNode checks the presence of the storage trie node with the
// specified account hash and node path, regardless of the node hash.
// HasStorageTrieNode 检查具有指定账户哈希和节点路径的存储 trie 节点的存在性，
// 而不考虑节点哈希。
func HasStorageTrieNode(db ethdb.KeyValueReader, accountHash common.Hash, path []byte) bool {
	has, err := db.Has(storageTrieNodeKey(accountHash, path))
	if err != nil {
		return false
	}
	return has
}

// WriteStorageTrieNode writes the provided storage trie node into database.
// WriteStorageTrieNode 将提供的存储 trie 节点写入数据库。
func WriteStorageTrieNode(db ethdb.KeyValueWriter, accountHash common.Hash, path []byte, node []byte) {
	if err := db.Put(storageTrieNodeKey(accountHash, path), node); err != nil {
		log.Crit("Failed to store storage trie node", "err", err)
	}
}

// DeleteStorageTrieNode deletes the specified storage trie node from the database.
// DeleteStorageTrieNode 从数据库中删除指定的存储 trie 节点。
func DeleteStorageTrieNode(db ethdb.KeyValueWriter, accountHash common.Hash, path []byte) {
	if err := db.Delete(storageTrieNodeKey(accountHash, path)); err != nil {
		log.Crit("Failed to delete storage trie node", "err", err)
	}
}

// ReadLegacyTrieNode retrieves the legacy trie node with the given
// associated node hash.
// ReadLegacyTrieNode 检索具有给定关联节点哈希的遗留 trie 节点。
func ReadLegacyTrieNode(db ethdb.KeyValueReader, hash common.Hash) []byte {
	data, err := db.Get(hash.Bytes())
	if err != nil {
		return nil
	}
	return data
}

// HasLegacyTrieNode checks if the trie node with the provided hash is present in db.
// HasLegacyTrieNode 检查具有提供哈希的 trie 节点是否存在于数据库中。
func HasLegacyTrieNode(db ethdb.KeyValueReader, hash common.Hash) bool {
	ok, _ := db.Has(hash.Bytes())
	return ok
}

// WriteLegacyTrieNode writes the provided legacy trie node to database.
// WriteLegacyTrieNode 将提供的遗留 trie 节点写入数据库。
func WriteLegacyTrieNode(db ethdb.KeyValueWriter, hash common.Hash, node []byte) {
	if err := db.Put(hash.Bytes(), node); err != nil {
		log.Crit("Failed to store legacy trie node", "err", err)
	}
}

// DeleteLegacyTrieNode deletes the specified legacy trie node from database.
// DeleteLegacyTrieNode 从数据库中删除指定的遗留 trie 节点。
func DeleteLegacyTrieNode(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(hash.Bytes()); err != nil {
		log.Crit("Failed to delete legacy trie node", "err", err)
	}
}

// HasTrieNode checks the trie node presence with the provided node info and
// the associated node hash.
// HasTrieNode 使用提供的节点信息和关联的节点哈希检查 trie 节点的存在性。
func HasTrieNode(db ethdb.KeyValueReader, owner common.Hash, path []byte, hash common.Hash, scheme string) bool {
	switch scheme {
	case HashScheme:
		return HasLegacyTrieNode(db, hash)
	case PathScheme:
		var blob []byte
		if owner == (common.Hash{}) {
			blob = ReadAccountTrieNode(db, path)
		} else {
			blob = ReadStorageTrieNode(db, owner, path)
		}
		if len(blob) == 0 {
			return false
		}
		h := newHasher()
		defer h.release()
		return h.hash(blob) == hash // exists but not match
	default:
		panic(fmt.Sprintf("Unknown scheme %v", scheme))
	}
}

// ReadTrieNode retrieves the trie node from database with the provided node info
// and associated node hash.
// ReadTrieNode 使用提供的节点信息和关联的节点哈希从数据库中检索 trie 节点。
func ReadTrieNode(db ethdb.KeyValueReader, owner common.Hash, path []byte, hash common.Hash, scheme string) []byte {
	switch scheme {
	case HashScheme:
		return ReadLegacyTrieNode(db, hash)
	case PathScheme:
		var blob []byte
		if owner == (common.Hash{}) {
			blob = ReadAccountTrieNode(db, path)
		} else {
			blob = ReadStorageTrieNode(db, owner, path)
		}
		if len(blob) == 0 {
			return nil
		}
		h := newHasher()
		defer h.release()
		if h.hash(blob) != hash {
			return nil // exists but not match
		}
		return blob
	default:
		panic(fmt.Sprintf("Unknown scheme %v", scheme))
	}
}

// WriteTrieNode writes the trie node into database with the provided node info.
//
// hash-scheme requires the node hash as the identifier.
// path-scheme requires the node owner and path as the identifier.
//
// WriteTrieNode 使用提供的节点信息将 trie 节点写入数据库。
//
// hash-scheme 需要节点哈希作为标识符。
// path-scheme 需要节点所有者和路径作为标识符。
func WriteTrieNode(db ethdb.KeyValueWriter, owner common.Hash, path []byte, hash common.Hash, node []byte, scheme string) {
	switch scheme {
	case HashScheme:
		WriteLegacyTrieNode(db, hash, node)
	case PathScheme:
		if owner == (common.Hash{}) {
			WriteAccountTrieNode(db, path, node)
		} else {
			WriteStorageTrieNode(db, owner, path, node)
		}
	default:
		panic(fmt.Sprintf("Unknown scheme %v", scheme))
	}
}

// DeleteTrieNode deletes the trie node from database with the provided node info.
//
// hash-scheme requires the node hash as the identifier.
// path-scheme requires the node owner and path as the identifier.
//
// DeleteTrieNode 使用提供的节点信息从数据库中删除 trie 节点。
//
// hash-scheme 需要节点哈希作为标识符。
// path-scheme 需要节点所有者和路径作为标识符。
func DeleteTrieNode(db ethdb.KeyValueWriter, owner common.Hash, path []byte, hash common.Hash, scheme string) {
	switch scheme {
	case HashScheme:
		DeleteLegacyTrieNode(db, hash)
	case PathScheme:
		if owner == (common.Hash{}) {
			DeleteAccountTrieNode(db, path)
		} else {
			DeleteStorageTrieNode(db, owner, path)
		}
	default:
		panic(fmt.Sprintf("Unknown scheme %v", scheme))
	}
}

// ReadStateScheme reads the state scheme of persistent state, or none
// if the state is not present in database.
// ReadStateScheme 读取持久状态的状态方案，如果数据库中不存在状态，则返回 none。
func ReadStateScheme(db ethdb.Database) string {
	// Check if state in path-based scheme is present.
	// 检查基于路径方案的状态是否存在。
	if HasAccountTrieNode(db, nil) {
		return PathScheme
	}
	// The root node might be deleted during the initial snap sync, check
	// the persistent state id then.
	// 在初始快照同步期间，根节点可能被删除，因此检查持久状态 ID。
	if id := ReadPersistentStateID(db); id != 0 {
		return PathScheme
	}
	// Check if verkle state in path-based scheme is present.
	// 检查基于路径方案的 verkle 状态是否存在。
	vdb := NewTable(db, string(VerklePrefix))
	if HasAccountTrieNode(vdb, nil) {
		return PathScheme
	}
	// The root node of verkle might be deleted during the initial snap sync,
	// check the persistent state id then.
	// 在初始快照同步期间，verkle 的根节点可能被删除，因此检查持久状态 ID。
	if id := ReadPersistentStateID(vdb); id != 0 {
		return PathScheme
	}
	// In a hash-based scheme, the genesis state is consistently stored
	// on the disk. To assess the scheme of the persistent state, it
	// suffices to inspect the scheme of the genesis state.
	// 在基于哈希的方案中，创世状态始终存储在磁盘上。
	// 要评估持久状态的方案，只需检查创世状态的方案。
	header := ReadHeader(db, ReadCanonicalHash(db, 0), 0)
	if header == nil {
		return "" // empty datadir
	}
	if !HasLegacyTrieNode(db, header.Root) {
		return "" // no state in disk
	}
	return HashScheme
}

// ParseStateScheme checks if the specified state scheme is compatible with
// the stored state.
//
//   - If the provided scheme is none, use the scheme consistent with persistent
//     state, or fallback to path-based scheme if state is empty.
//
//   - If the provided scheme is hash, use hash-based scheme or error out if not
//     compatible with persistent state scheme.
//
//   - If the provided scheme is path: use path-based scheme or error out if not
//     compatible with persistent state scheme.
//
// ParseStateScheme 检查指定的状态方案是否与存储的状态兼容。
//
//   - 如果提供的方案为 none，则使用与持久状态一致的方案，
//     如果状态为空，则回退到基于路径的方案。
//
//   - 如果提供的方案为 hash，则使用基于哈希的方案，
//     如果与持久状态方案不兼容，则报错。
//
//   - 如果提供的方案为 path，则使用基于路径的方案，
//     如果与持久状态方案不兼容，则报错。
func ParseStateScheme(provided string, disk ethdb.Database) (string, error) {
	// If state scheme is not specified, use the scheme consistent
	// with persistent state, or fallback to hash mode if database
	// is empty.
	// 如果未指定状态方案，则使用与持久状态一致的方案，
	// 如果数据库为空，则回退到哈希模式。
	stored := ReadStateScheme(disk)
	if provided == "" {
		if stored == "" {
			log.Info("State schema set to default", "scheme", "path")
			return PathScheme, nil // use default scheme for empty database
		}
		log.Info("State scheme set to already existing", "scheme", stored)
		return stored, nil // reuse scheme of persistent scheme
	}
	// If state scheme is specified, ensure it's valid.
	// 如果指定了状态方案，确保其有效。
	if provided != HashScheme && provided != PathScheme {
		return "", fmt.Errorf("invalid state scheme %s", provided)
	}
	// If state scheme is specified, ensure it's compatible with
	// persistent state.
	// 如果指定了状态方案，确保其与持久状态兼容。
	if stored == "" || provided == stored {
		log.Info("State scheme set by user", "scheme", provided)
		return provided, nil
	}
	return "", fmt.Errorf("incompatible state scheme, stored: %s, provided: %s", stored, provided)
}
