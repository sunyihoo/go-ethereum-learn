// Copyright 2017 The go-ethereum Authors
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-ethereum/triedb"
)

// 以太坊的状态存储在 Merkle Patricia Trie（MPT）中，这是一种结合 Merkle Tree 和 Patricia Trie 的数据结构，用于高效存储键值对并提供密码学证明。白皮书中提到状态包括所有账户的余额、合约代码和存储数据，黄皮书中定义了其具体结构：
//
// 账户状态：包含 nonce、余额、存储根（Storage Root）和代码哈希（Code Hash）。
// 存储状态：每个合约的存储槽，键值对形式。

// EIP-2929（Gas Cost Increases for State Access Opcodes）：
// 提高了状态访问的 Gas 成本，促使节点优化状态查询。CachingDB 的快照和缓存机制减少了对底层 MPT 的直接访问，与此目标一致。
// EIP-4444（Historical Data Expiry）：
// 提议过期历史数据，CachingDB 的快照支持（Snapshot）为未来实现提供了基础，可能用于快速恢复最新状态。
// Verkle Trie（EIP 未正式编号，仍在研究中）：
// Verkle Trie 是以太坊社区提出的下一代状态存储方案，使用向量承诺（Vector Commitment）替代 Merkle 树，提供更小的证明大小和更高的效率。代码中的 IsVerkle 和 NewVerkleTrie 是对这一过渡的支持。

// 状态膨胀：
// 以太坊状态持续增长（截至 2025 年可能超过 TB 级），CachingDB 的快照和缓存机制缓解了查询压力。
// 快照同步（Snap Sync）：
// snap 字段支持 Snap Sync，通过平面化状态加速节点同步。
// Verkle Trie 的意义：
// Verkle Trie 使用更小的证明（~100 字节 vs MPT 的 ~1 KB），适合无状态客户端（Stateless Ethereum），是未来以太坊扩展性的关键。

const (
	// Number of codehash->size associations to keep.
	// 保留的代码哈希到大小关联的数量。
	codeSizeCacheSize = 100000

	// Cache size granted for caching clean code.
	// 为缓存干净代码分配的缓存大小。
	codeCacheSize = 64 * 1024 * 1024 // 64 MB

	// Number of address->curve point associations to keep.
	// 保留的地址到曲线点关联的数量。
	pointCacheSize = 4096
)

// Database wraps access to tries and contract code.
// Database 封装了对 trie 和合约代码的访问。
type Database interface {
	// Reader returns a state reader associated with the specified state root.
	// Reader 返回与指定状态根关联的状态读取器。
	Reader(root common.Hash) (Reader, error)

	// OpenTrie opens the main account trie.
	// OpenTrie 打开主账户 trie。
	OpenTrie(root common.Hash) (Trie, error)

	// OpenStorageTrie opens the storage trie of an account.
	// OpenStorageTrie 打开账户的存储 trie。
	OpenStorageTrie(stateRoot common.Hash, address common.Address, root common.Hash, trie Trie) (Trie, error)

	// PointCache returns the cache holding points used in verkle tree key computation
	// PointCache 返回用于 verkle 树键计算的点缓存。
	PointCache() *utils.PointCache

	// TrieDB returns the underlying trie database for managing trie nodes.
	// TrieDB 返回用于管理 trie 节点的底层 trie 数据库。
	TrieDB() *triedb.Database

	// Snapshot returns the underlying state snapshot.
	// Snapshot 返回底层状态快照。
	Snapshot() *snapshot.Tree
}

// Trie is a Ethereum Merkle Patricia trie.
// Trie 是以太坊 Merkle Patricia trie。
type Trie interface {
	// GetKey returns the sha3 preimage of a hashed key that was previously used
	// to store a value.
	//
	// TODO(fjl): remove this when StateTrie is removed
	// GetKey 返回之前用于存储值的哈希键的 sha3 前像。
	//
	// TODO(fjl): 在 StateTrie 被移除时删除此方法
	GetKey([]byte) []byte

	// GetAccount abstracts an account read from the trie. It retrieves the
	// account blob from the trie with provided account address and decodes it
	// with associated decoding algorithm. If the specified account is not in
	// the trie, nil will be returned. If the trie is corrupted(e.g. some nodes
	// are missing or the account blob is incorrect for decoding), an error will
	// be returned.
	// GetAccount 从 trie 中抽象读取账户。它使用提供的账户地址从 trie 中检索账户数据 blob，
	// 并使用关联的解码算法解码。如果 trie 中没有指定账户，则返回 nil。
	// 如果 trie 损坏（例如缺少某些节点或账户 blob 无法正确解码），则返回错误。
	GetAccount(address common.Address) (*types.StateAccount, error)

	// GetStorage returns the value for key stored in the trie. The value bytes
	// must not be modified by the caller. If a node was not found in the database,
	// a trie.MissingNodeError is returned.
	// GetStorage 返回存储在 trie 中的键对应的值。调用者不得修改返回的值字节。
	// 如果在数据库中未找到节点，则返回 trie.MissingNodeError。
	GetStorage(addr common.Address, key []byte) ([]byte, error)

	// UpdateAccount abstracts an account write to the trie. It encodes the
	// provided account object with associated algorithm and then updates it
	// in the trie with provided address.
	// UpdateAccount 抽象向 trie 写入账户。它使用关联的算法编码提供的账户对象，
	// 然后使用提供的地址在 trie 中更新它。
	UpdateAccount(address common.Address, account *types.StateAccount, codeLen int) error

	// UpdateStorage associates key with value in the trie. If value has length zero,
	// any existing value is deleted from the trie. The value bytes must not be modified
	// by the caller while they are stored in the trie. If a node was not found in the
	// database, a trie.MissingNodeError is returned.
	// UpdateStorage 在 trie 中将键与值关联。如果值的长度为零，则从 trie 中删除任何现有值。
	// 在值存储在 trie 中时，调用者不得修改值字节。如果在数据库中未找到节点，
	// 则返回 trie.MissingNodeError。
	UpdateStorage(addr common.Address, key, value []byte) error

	// DeleteAccount abstracts an account deletion from the trie.
	// DeleteAccount 从 trie 中抽象删除账户。
	DeleteAccount(address common.Address) error

	// DeleteStorage removes any existing value for key from the trie. If a node
	// was not found in the database, a trie.MissingNodeError is returned.
	// DeleteStorage 从 trie 中移除键的任何现有值。如果在数据库中未找到节点，
	// 则返回 trie.MissingNodeError。
	DeleteStorage(addr common.Address, key []byte) error

	// UpdateContractCode abstracts code write to the trie. It is expected
	// to be moved to the stateWriter interface when the latter is ready.
	// UpdateContractCode 抽象向 trie 写入代码。预计在 stateWriter 接口准备好时移至该接口。
	UpdateContractCode(address common.Address, codeHash common.Hash, code []byte) error

	// Hash returns the root hash of the trie. It does not write to the database and
	// can be used even if the trie doesn't have one.
	// Hash 返回 trie 的根哈希。它不会写入数据库，即使 trie 没有根哈希也可以使用。
	Hash() common.Hash

	// Commit collects all dirty nodes in the trie and replace them with the
	// corresponding node hash. All collected nodes(including dirty leaves if
	// collectLeaf is true) will be encapsulated into a nodeset for return.
	// The returned nodeset can be nil if the trie is clean(nothing to commit).
	// Once the trie is committed, it's not usable anymore. A new trie must
	// be created with new root and updated trie database for following usage
	// Commit 收集 trie 中的所有脏节点，并用相应的节点哈希替换它们。
	// 所有收集的节点（如果 collectLeaf 为 true，则包括脏叶子）将被封装到一个节点集返回。
	// 如果 trie 是干净的（无需提交），返回的节点集可能为 nil。
	// 一旦 trie 被提交，它将不可再使用。必须使用新的根和更新的 trie 数据库创建新 trie 以供后续使用。
	Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet)

	// Witness returns a set containing all trie nodes that have been accessed.
	// The returned map could be nil if the witness is empty.
	// Witness 返回包含所有已访问 trie 节点的集合。如果 witness 为空，则返回的映射可能为 nil。
	Witness() map[string]struct{}

	// NodeIterator returns an iterator that returns nodes of the trie. Iteration
	// starts at the key after the given start key. And error will be returned
	// if fails to create node iterator.
	// NodeIterator 返回一个迭代器，该迭代器返回 trie 的节点。迭代从给定起始键之后的键开始。
	// 如果无法创建节点迭代器，则返回错误。
	NodeIterator(startKey []byte) (trie.NodeIterator, error)

	// Prove constructs a Merkle proof for key. The result contains all encoded nodes
	// on the path to the value at key. The value itself is also included in the last
	// node and can be retrieved by verifying the proof.
	//
	// If the trie does not contain a value for key, the returned proof contains all
	// nodes of the longest existing prefix of the key (at least the root), ending
	// with the node that proves the absence of the key.
	// Prove 为键构造 Merkle 证明。结果包含通往键值的路径上的所有编码节点。
	// 值本身也包含在最后一个节点中，可以通过验证证明检索。
	//
	// 如果 trie 不包含键的值，则返回的证明包含键的最长现有前缀的所有节点（至少是根），
	// 以证明键不存在的节点结束。
	Prove(key []byte, proofDb ethdb.KeyValueWriter) error

	// IsVerkle returns true if the trie is verkle-tree based
	// IsVerkle 如果 trie 是基于 verkle 树的，则返回 true。
	IsVerkle() bool
}

// CachingDB is an implementation of Database interface. It leverages both trie and
// state snapshot to provide functionalities for state access. It's meant to be a
// long-live object and has a few caches inside for sharing between blocks.
// CachingDB 是 Database 接口的实现。它利用 trie 和状态快照提供状态访问功能。
// 它旨在作为一个长期存在的对象，内部有几个缓存供区块间共享。
type CachingDB struct {
	disk          ethdb.KeyValueStore                            // 底层键值存储数据库
	triedb        *triedb.Database                               // trie 数据库，用于管理 trie 节点
	snap          *snapshot.Tree                                 // 状态快照树
	codeCache     *lru.SizeConstrainedCache[common.Hash, []byte] // 代码缓存，键为代码哈希，值为代码字节
	codeSizeCache *lru.Cache[common.Hash, int]                   // 代码大小缓存，键为代码哈希，值为代码长度
	pointCache    *utils.PointCache                              // 用于 verkle 树键计算的点缓存
}

// NewDatabase creates a state database with the provided data sources.
// NewDatabase 使用提供的数据源创建状态数据库。
func NewDatabase(triedb *triedb.Database, snap *snapshot.Tree) *CachingDB {
	// 初始化并返回 CachingDB 实例
	return &CachingDB{
		disk:          triedb.Disk(),                                                   // 获取底层磁盘数据库
		triedb:        triedb,                                                          // 设置 trie 数据库
		snap:          snap,                                                            // 设置快照树
		codeCache:     lru.NewSizeConstrainedCache[common.Hash, []byte](codeCacheSize), // 初始化代码缓存
		codeSizeCache: lru.NewCache[common.Hash, int](codeSizeCacheSize),               // 初始化代码大小缓存
		pointCache:    utils.NewPointCache(pointCacheSize),                             // 初始化点缓存
	}
}

// NewDatabaseForTesting is similar to NewDatabase, but it initializes the caching
// db by using an ephemeral memory db with default config for testing.
// NewDatabaseForTesting 类似于 NewDatabase，但它通过使用带有默认配置的临时内存数据库初始化缓存数据库，用于测试。
func NewDatabaseForTesting() *CachingDB {
	// 使用内存数据库创建测试用的 CachingDB
	return NewDatabase(triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil), nil)
}

// Reader returns a state reader associated with the specified state root.
// Reader 返回与指定状态根关联的状态读取器。
func (db *CachingDB) Reader(stateRoot common.Hash) (Reader, error) {
	var readers []StateReader // 存储多个状态读取器

	// Set up the state snapshot reader if available. This feature
	// is optional and may be partially useful if it's not fully
	// generated.
	// 如果快照可用，则设置状态快照读取器。此功能是可选的，如果未完全生成，可能部分有用。
	if db.snap != nil {
		// If standalone state snapshot is available (hash scheme),
		// then construct the legacy snap reader.
		// 如果独立的快照可用（哈希方案），则构造旧版快照读取器。
		snap := db.snap.Snapshot(stateRoot)
		if snap != nil {
			readers = append(readers, newFlatReader(snap)) // 添加快照读取器
		}
	} else {
		// If standalone state snapshot is not available, try to construct
		// the state reader with database.
		// 如果独立的状态快照不可用，则尝试使用数据库构造状态读取器。
		reader, err := db.triedb.StateReader(stateRoot)
		if err == nil {
			readers = append(readers, newFlatReader(reader)) // state reader is optional 添加数据库读取器（可选）
		}
	}
	// Set up the trie reader, which is expected to always be available
	// as the gatekeeper unless the state is corrupted.
	// 设置 trie 读取器，预期始终可用作为守门员，除非状态损坏。
	tr, err := newTrieReader(stateRoot, db.triedb, db.pointCache)
	if err != nil {
		return nil, err // 创建 trie 读取器失败，返回错误
	}
	readers = append(readers, tr) // 添加 trie 读取器

	// 创建组合状态读取器
	combined, err := newMultiStateReader(readers...)
	if err != nil {
		return nil, err // 创建组合读取器失败，返回错误
	}
	// 返回封装了代码读取器的最终读取器
	return newReader(newCachingCodeReader(db.disk, db.codeCache, db.codeSizeCache), combined), nil
}

// OpenTrie opens the main account trie at a specific root hash.
// OpenTrie 在特定根哈希下打开主账户 trie。
func (db *CachingDB) OpenTrie(root common.Hash) (Trie, error) {
	// 如果是 verkle 树，返回 verkle trie
	if db.triedb.IsVerkle() {
		return trie.NewVerkleTrie(root, db.triedb, db.pointCache)
	}
	// 否则返回传统的状态 trie
	tr, err := trie.NewStateTrie(trie.StateTrieID(root), db.triedb)
	if err != nil {
		return nil, err // 创建失败，返回错误
	}
	return tr, nil
}

// OpenStorageTrie opens the storage trie of an account.
// OpenStorageTrie 打开账户的存储 trie。
func (db *CachingDB) OpenStorageTrie(stateRoot common.Hash, address common.Address, root common.Hash, self Trie) (Trie, error) {
	// In the verkle case, there is only one tree. But the two-tree structure
	// is hardcoded in the codebase. So we need to return the same trie in this
	// case.
	// 在 verkle 情况下，只有一个树。但代码库中硬编码了双树结构。因此在这种情况下需要返回相同的 trie。
	if db.triedb.IsVerkle() {
		return self, nil // 返回传入的 trie
	}
	// 创建并返回存储 trie
	tr, err := trie.NewStateTrie(trie.StorageTrieID(stateRoot, crypto.Keccak256Hash(address.Bytes()), root), db.triedb)
	if err != nil {
		return nil, err // 创建失败，返回错误
	}
	return tr, nil
}

// ContractCodeWithPrefix retrieves a particular contract's code. If the
// code can't be found in the cache, then check the existence with **new**
// db scheme.
// ContractCodeWithPrefix 检索特定合约的代码。如果在缓存中找不到代码，则使用新的数据库方案检查存在性。
func (db *CachingDB) ContractCodeWithPrefix(address common.Address, codeHash common.Hash) []byte {
	// 先从缓存中获取代码
	code, _ := db.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code // 缓存命中，直接返回
	}
	// 从数据库中读取代码
	code = rawdb.ReadCodeWithPrefix(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Add(codeHash, code)          // 加入代码缓存
		db.codeSizeCache.Add(codeHash, len(code)) // 加入代码大小缓存
	}
	return code // 返回代码（可能为空）
}

// TrieDB retrieves any intermediate trie-node caching layer.
// TrieDB 检索任何中间 trie 节点缓存层。
func (db *CachingDB) TrieDB() *triedb.Database {
	return db.triedb // 返回 trie 数据库
}

// PointCache returns the cache of evaluated curve points.
// PointCache 返回已计算的曲线点缓存。
func (db *CachingDB) PointCache() *utils.PointCache {
	return db.pointCache // 返回点缓存
}

// Snapshot returns the underlying state snapshot.
// Snapshot 返回底层状态快照。
func (db *CachingDB) Snapshot() *snapshot.Tree {
	return db.snap // 返回快照树
}

// mustCopyTrie returns a deep-copied trie.
// mustCopyTrie 返回深拷贝的 trie。
func mustCopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.StateTrie:
		return t.Copy() // 拷贝状态 trie
	case *trie.VerkleTrie:
		return t.Copy() // 拷贝 verkle trie
	default:
		panic(fmt.Errorf("unknown trie type %T", t)) // 未知 trie 类型，抛出异常
	}
}
