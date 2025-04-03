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

package pathdb

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-verkle"
)

const (
	// defaultCleanSize is the default memory allowance of clean cache.
	// defaultCleanSize 是干净缓存的默认内存允许量。
	defaultCleanSize = 16 * 1024 * 1024

	// maxBufferSize is the maximum memory allowance of node buffer.
	// Too large buffer will cause the system to pause for a long
	// time when write happens. Also, the largest batch that pebble can
	// support is 4GB, node will panic if batch size exceeds this limit.
	// maxBufferSize 是节点缓冲区的最大内存允许量。
	// 缓冲区过大会导致写入时系统暂停时间过长。此外，Pebble 支持的最大批次大小为 4GB，如果批次大小超过此限制，节点会 panic。
	maxBufferSize = 256 * 1024 * 1024

	// defaultBufferSize is the default memory allowance of node buffer
	// that aggregates the writes from above until it's flushed into the
	// disk. It's meant to be used once the initial sync is finished.
	// Do not increase the buffer size arbitrarily, otherwise the system
	// pause time will increase when the database writes happen.
	// defaultBufferSize 是节点缓冲区的默认内存允许量，用于聚合上层的写入，直到刷新到磁盘。
	// 它旨在初始同步完成后使用。不要随意增加缓冲区大小，否则数据库写入时系统暂停时间会增加。
	defaultBufferSize = 64 * 1024 * 1024
)

var (
	// maxDiffLayers is the maximum diff layers allowed in the layer tree.
	// maxDiffLayers 是层树中允许的最大差异层数。
	maxDiffLayers = 128
)

// layer is the interface implemented by all state layers which includes some
// public methods and some additional methods for internal usage.
// layer 是所有状态层实现的接口，包括一些公共方法和一些内部使用的附加方法。
type layer interface {
	// node retrieves the trie node with the node info. An error will be returned
	// if the read operation exits abnormally. Specifically, if the layer is
	// already stale.
	//
	// Note:
	// - the returned node is not a copy, please don't modify it.
	// - no error will be returned if the requested node is not found in database.
	//
	// node 使用节点信息检索 trie 节点。如果读取操作异常退出，将返回错误。
	// 特别是如果层已经过时。
	//
	// 注意：
	// - 返回的节点不是副本，请勿修改它。
	// - 如果数据库中未找到请求的节点，不会返回错误。
	node(owner common.Hash, path []byte, depth int) ([]byte, common.Hash, *nodeLoc, error)

	// account directly retrieves the account RLP associated with a particular
	// hash in the slim data format. An error will be returned if the read
	// operation exits abnormally. Specifically, if the layer is already stale.
	//
	// Note:
	// - the returned account is not a copy, please don't modify it.
	// - no error will be returned if the requested account is not found in database.
	//
	// account 直接检索与特定哈希关联的账户 RLP（采用精简数据格式）。如果读取操作异常退出，将返回错误。
	// 特别是如果层已经过时。
	//
	// 注意：
	// - 返回的账户不是副本，请勿修改它。
	// - 如果数据库中未找到请求的账户，不会返回错误。
	account(hash common.Hash, depth int) ([]byte, error)

	// storage directly retrieves the storage data associated with a particular hash,
	// within a particular account. An error will be returned if the read operation
	// exits abnormally. Specifically, if the layer is already stale.
	//
	// Note:
	// - the returned storage data is not a copy, please don't modify it.
	// - no error will be returned if the requested slot is not found in database.
	//
	// storage 直接检索与特定账户内特定哈希关联的存储数据。如果读取操作异常退出，将返回错误。
	// 特别是如果层已经过时。
	//
	// 注意：
	// - 返回的存储数据不是副本，请勿修改它。
	// - 如果数据库中未找到请求的槽，不会返回错误。
	storage(accountHash, storageHash common.Hash, depth int) ([]byte, error)

	// rootHash returns the root hash for which this layer was made.
	// rootHash 返回为此层创建的根哈希。
	rootHash() common.Hash

	// stateID returns the associated state id of layer.
	// stateID 返回层的关联状态 ID。
	stateID() uint64

	// parentLayer returns the subsequent layer of it, or nil if the disk was reached.
	// parentLayer 返回其后续层，如果达到磁盘层则返回 nil。
	parentLayer() layer

	// update creates a new layer on top of the existing layer diff tree with
	// the provided dirty trie nodes along with the state change set.
	//
	// Note, the maps are retained by the method to avoid copying everything.
	//
	// update 在现有层差异树之上创建新层，带有提供的脏 trie 节点和状态变更集。
	//
	// 注意，该方法保留映射以避免复制所有内容。
	update(root common.Hash, id uint64, block uint64, nodes *nodeSet, states *StateSetWithOrigin) *diffLayer

	// journal commits an entire diff hierarchy to disk into a single journal entry.
	// This is meant to be used during shutdown to persist the layer without
	// flattening everything down (bad for reorgs).
	//
	// journal 将整个差异层次结构提交到磁盘，记录为单个日志条目。
	// 这旨在关闭时使用，以持久化层而无需将所有内容展平（对重组不利）。
	journal(w io.Writer) error
}

// Config contains the settings for database.
// Config 包含数据库的设置。
type Config struct {
	StateHistory    uint64 // Number of recent blocks to maintain state history for 维护状态历史的最近区块数
	CleanCacheSize  int    // Maximum memory allowance (in bytes) for caching clean nodes 缓存干净节点的最大内存允许量（字节）
	WriteBufferSize int    // Maximum memory allowance (in bytes) for write buffer 写入缓冲区的最大内存允许量（字节）
	ReadOnly        bool   // Flag whether the database is opened in read only mode. 数据库是否以只读模式打开的标志
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
// sanitize 检查提供的用户配置，并更改任何不合理或不可行的内容。
func (c *Config) sanitize() *Config {
	conf := *c
	if conf.WriteBufferSize > maxBufferSize {
		log.Warn("Sanitizing invalid node buffer size", "provided", common.StorageSize(conf.WriteBufferSize), "updated", common.StorageSize(maxBufferSize))
		conf.WriteBufferSize = maxBufferSize
	}
	return &conf
}

// fields returns a list of attributes of config for printing.
// fields 返回配置的属性列表以供打印。
func (c *Config) fields() []interface{} {
	var list []interface{}
	if c.ReadOnly {
		list = append(list, "readonly", true)
	}
	list = append(list, "cache", common.StorageSize(c.CleanCacheSize))
	list = append(list, "buffer", common.StorageSize(c.WriteBufferSize))
	list = append(list, "history", c.StateHistory)
	return list
}

// Defaults contains default settings for Ethereum mainnet.
// Defaults 包含以太坊主网的默认设置。
var Defaults = &Config{
	StateHistory:    params.FullImmutabilityThreshold,
	CleanCacheSize:  defaultCleanSize,
	WriteBufferSize: defaultBufferSize,
}

// ReadOnly is the config in order to open database in read only mode.
// ReadOnly 是以只读模式打开数据库的配置。
var ReadOnly = &Config{ReadOnly: true}

// nodeHasher is the function to compute the hash of supplied node blob.
// nodeHasher 是计算提供的节点 blob 哈希的函数。
type nodeHasher func([]byte) (common.Hash, error)

// merkleNodeHasher computes the hash of the given merkle node.
// merkleNodeHasher 计算给定 Merkle 节点的哈希。
func merkleNodeHasher(blob []byte) (common.Hash, error) {
	if len(blob) == 0 {
		return types.EmptyRootHash, nil
	}
	return crypto.Keccak256Hash(blob), nil
}

// verkleNodeHasher computes the hash of the given verkle node.
// verkleNodeHasher 计算给定 Verkle 节点的哈希。
func verkleNodeHasher(blob []byte) (common.Hash, error) {
	if len(blob) == 0 {
		return types.EmptyVerkleHash, nil
	}
	n, err := verkle.ParseNode(blob, 0)
	if err != nil {
		return common.Hash{}, err
	}
	return n.Commit().Bytes(), nil
}

// Database is a multiple-layered structure for maintaining in-memory states
// along with its dirty trie nodes. It consists of one persistent base layer
// backed by a key-value store, on top of which arbitrarily many in-memory diff
// layers are stacked. The memory diffs can form a tree with branching, but the
// disk layer is singleton and common to all. If a reorg goes deeper than the
// disk layer, a batch of reverse diffs can be applied to rollback. The deepest
// reorg that can be handled depends on the amount of state histories tracked
// in the disk.
//
// At most one readable and writable database can be opened at the same time in
// the whole system which ensures that only one database writer can operate the
// persistent state. Unexpected open operations can cause the system to panic.
//
// Database 是一个多层结构，用于维护内存中的状态及其脏 trie 节点。
// 它由一个由键值存储支持的持久基础层组成，其上堆叠了任意多个内存差异层。
// 内存差异可以形成带分支的树，但磁盘层是单一的且对所有层通用。
// 如果重组深度超过磁盘层，可以应用一批逆差异进行回滚。
// 可处理的最深重组取决于磁盘中跟踪的状态历史数量。
//
// 整个系统中最多只能同时打开一个可读写的数据库，以确保只有一个数据库写入者可以操作持久状态。
// 意外的打开操作可能导致系统 panic。
type Database struct {
	// readOnly is the flag whether the mutation is allowed to be applied.
	// It will be set automatically when the database is journaled during
	// the shutdown to reject all following unexpected mutations.
	// readOnly 是标志是否允许应用变更。
	// 在关闭期间记录日志时会自动设置为 true，以拒绝所有后续意外变更。
	readOnly bool       // Flag if database is opened in read only mode 是否以只读模式打开数据库的标志
	waitSync bool       // Flag if database is deactivated due to initial state sync 如果因初始状态同步而停用数据库的标志
	isVerkle bool       // Flag if database is used for verkle tree 如果数据库用于 Verkle 树的标志
	hasher   nodeHasher // Trie node hasher 节点哈希函数

	config  *Config                      // Configuration for database 数据库配置
	diskdb  ethdb.Database               // Persistent storage for matured trie nodes 成熟 trie 节点的持久存储
	tree    *layerTree                   // The group for all known layers 所有已知层的组
	freezer ethdb.ResettableAncientStore // Freezer for storing trie histories, nil possible in tests 存储 trie 历史的 freezer，测试中可能为 nil
	lock    sync.RWMutex                 // Lock to prevent mutations from happening at the same time 防止同时发生变更的锁
}

// New attempts to load an already existing layer from a persistent key-value
// store (with a number of memory layers from a journal). If the journal is not
// matched with the base persistent layer, all the recorded diff layers are discarded.
//
// New 尝试从持久键值存储加载已有层（带有从日志中加载的多个内存层）。
// 如果日志与基础持久层不匹配，所有记录的差异层将被丢弃。
func New(diskdb ethdb.Database, config *Config, isVerkle bool) *Database {
	if config == nil {
		config = Defaults
	}
	config = config.sanitize()

	db := &Database{
		readOnly: config.ReadOnly,
		isVerkle: isVerkle,
		config:   config,
		diskdb:   diskdb,
		hasher:   merkleNodeHasher,
	}
	// Establish a dedicated database namespace tailored for verkle-specific
	// data, ensuring the isolation of both verkle and merkle tree data. It's
	// important to note that the introduction of a prefix won't lead to
	// substantial storage overhead, as the underlying database will efficiently
	// compress the shared key prefix.
	//
	// 建立专为 Verkle 特定数据定制的数据库命名空间，确保 Verkle 和 Merkle 树数据的隔离。
	// 需要注意的是，引入前缀不会导致显著的存储开销，因为底层数据库会高效压缩共享键前缀。
	if isVerkle {
		db.diskdb = rawdb.NewTable(diskdb, string(rawdb.VerklePrefix))
		db.hasher = verkleNodeHasher
	}
	// Construct the layer tree by resolving the in-disk singleton state
	// and in-memory layer journal.
	// 通过解析磁盘中的单一状态和内存中的层日志构造层树。
	db.tree = newLayerTree(db.loadLayers())

	// Repair the state history, which might not be aligned with the state
	// in the key-value store due to an unclean shutdown.
	// 修复状态历史，由于非正常关闭可能与键值存储中的状态不一致。
	if err := db.repairHistory(); err != nil {
		log.Crit("Failed to repair state history", "err", err)
	}
	// Disable database in case node is still in the initial state sync stage.
	// 如果节点仍处于初始状态同步阶段，则禁用数据库。
	if rawdb.ReadSnapSyncStatusFlag(diskdb) == rawdb.StateSyncRunning && !db.readOnly {
		if err := db.Disable(); err != nil {
			log.Crit("Failed to disable database", "err", err) // impossible to happen
		}
	}
	fields := config.fields()
	if db.isVerkle {
		fields = append(fields, "verkle", true)
	}
	log.Info("Initialized path database", fields...)
	return db
}

// repairHistory truncates leftover state history objects, which may occur due
// to an unclean shutdown or other unexpected reasons.
// repairHistory 截断因非正常关闭或其他意外原因留下的状态历史对象。
func (db *Database) repairHistory() error {
	// Open the freezer for state history. This mechanism ensures that
	// only one database instance can be opened at a time to prevent
	// accidental mutation.
	// 打开状态历史的 freezer。此机制确保一次只能打开一个数据库实例，以防止意外变更。
	ancient, err := db.diskdb.AncientDatadir()
	if err != nil {
		// TODO error out if ancient store is disabled. A tons of unit tests
		// disable the ancient store thus the error here will immediately fail
		// all of them. Fix the tests first.
		// 如果古老存储被禁用，则报错。目前许多单元测试禁用了古老存储，因此这里的错误会立即使所有测试失败。先修复测试。
		return nil
	}
	freezer, err := rawdb.NewStateFreezer(ancient, db.isVerkle, db.readOnly)
	if err != nil {
		log.Crit("Failed to open state history freezer", "err", err)
	}
	db.freezer = freezer

	// Reset the entire state histories if the trie database is not initialized
	// yet. This action is necessary because these state histories are not
	// expected to exist without an initialized trie database.
	// 如果 trie 数据库尚未初始化，则重置整个状态历史。
	// 此操作是必要的，因为在未初始化的 trie 数据库下不应存在这些状态历史。
	id := db.tree.bottom().stateID()
	if id == 0 {
		frozen, err := db.freezer.Ancients()
		if err != nil {
			log.Crit("Failed to retrieve head of state history", "err", err)
		}
		if frozen != 0 {
			err := db.freezer.Reset()
			if err != nil {
				log.Crit("Failed to reset state histories", "err", err)
			}
			log.Info("Truncated extraneous state history")
		}
		return nil
	}
	// Truncate the extra state histories above in freezer in case it's not
	// aligned with the disk layer. It might happen after a unclean shutdown.
	// 截断 freezer 中超出磁盘层的额外状态历史，可能在非正常关闭后发生。
	pruned, err := truncateFromHead(db.diskdb, db.freezer, id)
	if err != nil {
		log.Crit("Failed to truncate extra state histories", "err", err)
	}
	if pruned != 0 {
		log.Warn("Truncated extra state histories", "number", pruned)
	}
	return nil
}

// Update adds a new layer into the tree, if that can be linked to an existing
// old parent. It is disallowed to insert a disk layer (the origin of all). Apart
// from that this function will flatten the extra diff layers at bottom into disk
// to only keep 128 diff layers in memory by default.
//
// The passed in maps(nodes, states) will be retained to avoid copying everything.
// Therefore, these maps must not be changed afterwards.
//
// The supplied parentRoot and root must be a valid trie hash value.
//
// Update 将新层添加到树中，如果它可以链接到现有的旧父层。
// 不允许插入磁盘层（所有层的起源）。
// 除此之外，此函数会将底部的额外差异层展平到磁盘，默认只在内存中保留 128 个差异层。
//
// 传入的映射（nodes, states）将被保留以避免复制所有内容。
// 因此，这些映射之后不得更改。
//
// 提供的 parentRoot 和 root 必须是有效的 trie 哈希值。
func (db *Database) Update(root common.Hash, parentRoot common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *StateSetWithOrigin) error {
	// Hold the lock to prevent concurrent mutations.
	// 持有锁以防止并发变更。
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the mutation is not allowed.
	// 如果不允许变更，则短路返回。
	if err := db.modifyAllowed(); err != nil {
		return err
	}
	if err := db.tree.add(root, parentRoot, block, nodes, states); err != nil {
		return err
	}
	// Keep 128 diff layers in the memory, persistent layer is 129th.
	// - head layer is paired with HEAD state
	// - head-1 layer is paired with HEAD-1 state
	// - head-127 layer(bottom-most diff layer) is paired with HEAD-127 state
	// - head-128 layer(disk layer) is paired with HEAD-128 state
	//
	// 在内存中保留 128 个差异层，第 129 层是持久层。
	// - 头部层与 HEAD 状态配对
	// - 头部-1 层与 HEAD-1 状态配对
	// - 头部-127 层（自定义最大差异层）与 HEAD-127 状态配对
	// - 头部-128 层（磁盘层）与 HEAD-128 状态配对
	return db.tree.cap(root, maxDiffLayers)
}

// Commit traverses downwards the layer tree from a specified layer with the
// provided state root and all the layers below are flattened downwards. It
// can be used alone and mostly for test purposes.
//
// Commit 从指定层向下遍历层树，使用提供的状态根，所有下层将被向下展平。
// 它可以单独使用，主要用于测试目的。
func (db *Database) Commit(root common.Hash, report bool) error {
	// Hold the lock to prevent concurrent mutations.
	// 持有锁以防止并发变更。
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the mutation is not allowed.
	// 如果不允许变更，则短路返回。
	if err := db.modifyAllowed(); err != nil {
		return err
	}
	return db.tree.cap(root, 0)
}

// Disable deactivates the database and invalidates all available state layers
// as stale to prevent access to the persistent state, which is in the syncing
// stage.
//
// Disable 停用数据库并将所有可用状态层标记为过时，以防止访问处于同步阶段的持久状态。
func (db *Database) Disable() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the database is in read only mode.
	// 如果数据库处于只读模式，则短路返回。
	if db.readOnly {
		return errDatabaseReadOnly
	}
	// Prevent duplicated disable operation.
	// 防止重复的禁用操作。
	if db.waitSync {
		log.Error("Reject duplicated disable operation")
		return nil
	}
	db.waitSync = true

	// Mark the disk layer as stale to prevent access to persistent state.
	// 将磁盘层标记为过时，以防止访问持久状态。
	db.tree.bottom().markStale()

	// Write the initial sync flag to persist it across restarts.
	// 写入初始同步标志以在重启后持久化。
	rawdb.WriteSnapSyncStatusFlag(db.diskdb, rawdb.StateSyncRunning)
	log.Info("Disabled trie database due to state sync")
	return nil
}

// Enable activates database and resets the state tree with the provided persistent
// state root once the state sync is finished.
//
// Enable 激活数据库并在状态同步完成后使用提供的持久状态根重置状态树。
func (db *Database) Enable(root common.Hash) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the database is in read only mode.
	// 如果数据库处于只读模式，则短路返回。
	if db.readOnly {
		return errDatabaseReadOnly
	}
	// Ensure the provided state root matches the stored one.
	// 确保提供的状态根与存储的根匹配。
	stored, err := db.hasher(rawdb.ReadAccountTrieNode(db.diskdb, nil))
	if err != nil {
		return err
	}
	if stored != root {
		return fmt.Errorf("state root mismatch: stored %x, synced %x", stored, root)
	}
	// Drop the stale state journal in persistent database and
	// reset the persistent state id back to zero.
	// 删除持久数据库中的过时状态日志并将持久状态 ID 重置为零。
	batch := db.diskdb.NewBatch()
	rawdb.DeleteTrieJournal(batch)
	rawdb.WritePersistentStateID(batch, 0)
	if err := batch.Write(); err != nil {
		return err
	}
	// Clean up all state histories in freezer. Theoretically
	// all root->id mappings should be removed as well. Since
	// mappings can be huge and might take a while to clear
	// them, just leave them in disk and wait for overwriting.
	//
	// 清理 freezer 中的所有状态历史。
	// 理论上，所有 root->id 映射也应被移除。
	// 由于映射可能很大且清理可能需要时间，仅将其留在磁盘上等待覆盖。
	if db.freezer != nil {
		if err := db.freezer.Reset(); err != nil {
			return err
		}
	}
	// Re-construct a new disk layer backed by persistent state
	// with **empty clean cache and node buffer**.
	// 使用持久状态重建新的磁盘层，带有空的干净缓存和节点缓冲区。
	db.tree.reset(newDiskLayer(root, 0, db, nil, newBuffer(db.config.WriteBufferSize, nil, nil, 0)))

	// Re-enable the database as the final step.
	// 重新启用数据库作为最后一步。
	db.waitSync = false
	rawdb.WriteSnapSyncStatusFlag(db.diskdb, rawdb.StateSyncFinished)
	log.Info("Rebuilt trie database", "root", root)
	return nil
}

// Recover rollbacks the database to a specified historical point.
// The state is supported as the rollback destination only if it's
// canonical state and the corresponding trie histories are existent.
//
// The supplied root must be a valid trie hash value.
//
// Recover 将数据库回滚到指定的历史点。
// 只有当状态是规范状态且相应的 trie 历史存在时，才支持将其作为回滚目标。
//
// 提供的根必须是有效的 trie 哈希值。
func (db *Database) Recover(root common.Hash) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if rollback operation is not supported
	// 如果不支持回滚操作，则短路返回。
	if err := db.modifyAllowed(); err != nil {
		return err
	}
	if db.freezer == nil {
		return errors.New("state rollback is non-supported")
	}
	// Short circuit if the target state is not recoverable
	// 如果目标状态不可恢复，则短路返回。
	if !db.Recoverable(root) {
		return errStateUnrecoverable
	}
	// Apply the state histories upon the disk layer in order
	// 按顺序在磁盘层上应用状态历史。
	var (
		start = time.Now()
		dl    = db.tree.bottom()
	)
	for dl.rootHash() != root {
		h, err := readHistory(db.freezer, dl.stateID())
		if err != nil {
			return err
		}
		dl, err = dl.revert(h)
		if err != nil {
			return err
		}
		// reset layer with newly created disk layer. It must be
		// done after each revert operation, otherwise the new
		// disk layer won't be accessible from outside.
		// 使用新创建的磁盘层重置层。
		// 每次回滚操作后必须执行此操作，否则新磁盘层无法从外部访问。
		db.tree.reset(dl)
	}
	rawdb.DeleteTrieJournal(db.diskdb)
	_, err := truncateFromHead(db.diskdb, db.freezer, dl.stateID())
	if err != nil {
		return err
	}
	log.Debug("Recovered state", "root", root, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}

// Recoverable returns the indicator if the specified state is recoverable.
//
// The supplied root must be a valid trie hash value.
//
// Recoverable 返回指定状态是否可恢复的指示器。
//
// 提供的根必须是有效的 trie 哈希值。
func (db *Database) Recoverable(root common.Hash) bool {
	// Ensure the requested state is a known state.
	// 确保请求的状态是已知状态。
	id := rawdb.ReadStateID(db.diskdb, root)
	if id == nil {
		return false
	}
	// Recoverable state must below the disk layer. The recoverable
	// state only refers the state that is currently not available,
	// but can be restored by applying state history.
	// 可恢复状态必须低于磁盘层。
	// 可恢复状态仅指当前不可用但可通过应用状态历史恢复的状态。
	dl := db.tree.bottom()
	if *id >= dl.stateID() {
		return false
	}
	// This is a temporary workaround for the unavailability of the freezer in
	// dev mode. As a consequence, the Pathdb loses the ability for deep reorg
	// in certain cases.
	// TODO(rjl493456442): Implement the in-memory ancient store.
	// 这是在开发模式下 freezer 不可用的临时解决方法。
	// 因此，在某些情况下，Pathdb 失去了深度重组的能力。
	// TODO(rjl493456442)：实现内存中的古老存储。
	if db.freezer == nil {
		return false
	}
	// Ensure the requested state is a canonical state and all state
	// histories in range [id+1, disklayer.ID] are present and complete.
	// 确保请求的状态是规范状态，并且范围 [id+1, disklayer.ID] 内的所有状态历史都存在且完整。
	return checkHistories(db.freezer, *id+1, dl.stateID()-*id, func(m *meta) error {
		if m.parent != root {
			return errors.New("unexpected state history")
		}
		root = m.root
		return nil
	}) == nil
}

// Close closes the trie database and the held freezer.
// Close 关闭 trie 数据库和持有的 freezer。
func (db *Database) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Set the database to read-only mode to prevent all
	// following mutations.
	// 将数据库设置为只读模式，以防止所有后续变更。
	db.readOnly = true

	// Release the memory held by clean cache.
	// 释放干净缓存持有的内存。
	db.tree.bottom().resetCache()

	// Close the attached state history freezer.
	// 关闭附加的状态历史 freezer。
	if db.freezer == nil {
		return nil
	}
	return db.freezer.Close()
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
// Size 返回持久数据库层前内存缓存的当前存储大小。
func (db *Database) Size() (diffs common.StorageSize, nodes common.StorageSize) {
	db.tree.forEach(func(layer layer) {
		if diff, ok := layer.(*diffLayer); ok {
			diffs += common.StorageSize(diff.size())
		}
		if disk, ok := layer.(*diskLayer); ok {
			nodes += disk.size()
		}
	})
	return diffs, nodes
}

// modifyAllowed returns the indicator if mutation is allowed. This function
// assumes the db.lock is already held.
// modifyAllowed 返回是否允许变更的指示器。此函数假设 db.lock 已被持有。
func (db *Database) modifyAllowed() error {
	if db.readOnly {
		return errDatabaseReadOnly
	}
	if db.waitSync {
		return errDatabaseWaitSync
	}
	return nil
}

// AccountHistory inspects the account history within the specified range.
//
// Start: State ID of the first history object for the query. 0 implies the first
// available object is selected as the starting point.
//
// End: State ID of the last history for the query. 0 implies the last available
// object is selected as the ending point. Note end is included in the query.
//
// AccountHistory 检查指定范围内的账户历史。
//
// Start：查询的第一个历史对象的状态 ID。0 表示选择第一个可用对象作为起点。
//
// End：查询的最后一个历史的状态 ID。0 表示选择最后一个可用对象作为终点。注意，终点包含在查询中。
func (db *Database) AccountHistory(address common.Address, start, end uint64) (*HistoryStats, error) {
	return accountHistory(db.freezer, address, start, end)
}

// StorageHistory inspects the storage history within the specified range.
//
// Start: State ID of the first history object for the query. 0 implies the first
// available object is selected as the starting point.
//
// End: State ID of the last history for the query. 0 implies the last available
// object is selected as the ending point. Note end is included in the query.
//
// Note, slot refers to the hash of the raw slot key.
//
// StorageHistory 检查指定范围内的存储历史。
//
// Start：查询的第一个历史对象的状态 ID。0 表示选择第一个可用对象作为起点。
//
// End：查询的最后一个历史的状态 ID。0 表示选择最后一个可用对象作为终点。注意，终点包含在查询中。
//
// 注意，slot 指的是原始槽键的哈希。
func (db *Database) StorageHistory(address common.Address, slot common.Hash, start uint64, end uint64) (*HistoryStats, error) {
	return storageHistory(db.freezer, address, slot, start, end)
}

// HistoryRange returns the block numbers associated with earliest and latest
// state history in the local store.
// HistoryRange 返回本地存储中与最早和最新状态历史关联的区块号。
func (db *Database) HistoryRange() (uint64, uint64, error) {
	return historyRange(db.freezer)
}

// AccountIterator creates a new account iterator for the specified root hash and
// seeks to a starting account hash.
// AccountIterator 为指定的根哈希创建新的账户迭代器，并定位到起始账户哈希。
func (db *Database) AccountIterator(root common.Hash, seek common.Hash) (AccountIterator, error) {
	return newFastAccountIterator(db, root, seek)
}

// StorageIterator creates a new storage iterator for the specified root hash and
// account. The iterator will be moved to the specific start position.
// StorageIterator 为指定的根哈希和账户创建新的存储迭代器。迭代器将被移动到特定起始位置。
func (db *Database) StorageIterator(root common.Hash, account common.Hash, seek common.Hash) (StorageIterator, error) {
	return newFastStorageIterator(db, root, account, seek)
}
