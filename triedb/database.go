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

package triedb

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb/database"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// 状态存储方案: 这段代码展示了 go-ethereum 对不同状态存储方案的支持，包括传统的 Merkle-Patricia Trie（通过 hashdb 实现）和更现代的基于路径的方案（通过 pathdb 实现），后者为未来支持 Verkle 树奠定了基础。
// 状态数据库配置: Config 结构体允许用户灵活地配置状态数据库的行为，例如是否启用 preimage 缓存以及选择使用哪种存储方案。
// 后端抽象: 使用 backend 接口可以方便地切换不同的状态存储实现，而无需修改上层代码。
// Preimage: Preimage 的概念在以太坊中用于优化某些需要知道节点哈希对应原始数据的操作。
// Verkle 树: 代码中对 IsVerkle 和 pathdb 的引用表明 go-ethereum 正在积极探索和实现更先进的状态存储技术。
// 状态读写分离: NodeReader 和 StateReader 接口提供了只读访问状态数据的能力，而 Update 和 Commit 方法则用于写入状态数据。

// Config defines all necessary options for database.
// Config 定义了数据库所需的所有选项。
type Config struct {
	Preimages bool // Flag whether the preimage of node key is recorded
	// 标记是否记录节点键的 preimage。
	IsVerkle bool // Flag whether the db is holding a verkle tree
	// 标记数据库是否持有 Verkle 树。
	HashDB *hashdb.Config // Configs for hash-based scheme
	// 基于哈希方案的配置。
	PathDB *pathdb.Config // Configs for experimental path-based scheme
	// 基于路径的实验性方案的配置。
}

// HashDefaults represents a config for using hash-based scheme with
// default settings.
// HashDefaults 表示使用默认设置的基于哈希方案的配置。
var HashDefaults = &Config{
	Preimages: false,
	IsVerkle:  false,
	HashDB:    hashdb.Defaults,
}

// VerkleDefaults represents a config for holding verkle trie data
// using path-based scheme with default settings.
// VerkleDefaults 表示使用默认设置的基于路径方案持有 Verkle trie 数据的配置。
var VerkleDefaults = &Config{
	Preimages: false,
	IsVerkle:  true,
	PathDB:    pathdb.Defaults,
}

// backend defines the methods needed to access/update trie nodes in different
// state scheme.
// backend 定义了在不同的状态方案中访问/更新 trie 节点所需的方法。
type backend interface {
	// NodeReader returns a reader for accessing trie nodes within the specified state.
	// An error will be returned if the specified state is not available.
	// NodeReader 返回一个用于访问指定状态内的 trie 节点的 reader。如果指定的状态不可用，将返回错误。
	NodeReader(root common.Hash) (database.NodeReader, error)

	// StateReader returns a reader for accessing flat states within the specified
	// state. An error will be returned if the specified state is not available.
	// StateReader 返回一个用于访问指定状态内的扁平状态的 reader。如果指定的状态不可用，将返回错误。
	StateReader(root common.Hash) (database.StateReader, error)

	// Size returns the current storage size of the diff layers on top of the
	// disk layer and the storage size of the nodes cached in the disk layer.
	// Size 返回磁盘层之上的差异层的当前存储大小以及磁盘层中缓存的节点的存储大小。
	//
	// For hash scheme, there is no differentiation between diff layer nodes
	// and dirty disk layer nodes, so both are merged into the second return.
	// 对于哈希方案，差异层节点和脏磁盘层节点之间没有区别，因此两者都合并到第二个返回值中。
	Size() (common.StorageSize, common.StorageSize)

	// Commit writes all relevant trie nodes belonging to the specified state
	// to disk. Report specifies whether logs will be displayed in info level.
	// Commit 将属于指定状态的所有相关 trie 节点写入磁盘。Report 指定是否在 info 级别显示日志。
	Commit(root common.Hash, report bool) error

	// Close closes the trie database backend and releases all held resources.
	// Close 关闭 trie 数据库后端并释放所有持有的资源。
	Close() error
}

// Database is the wrapper of the underlying backend which is shared by different
// types of node backend as an entrypoint. It's responsible for all interactions
// relevant with trie nodes and node preimages.
// Database 是底层后端（由不同类型的节点后端共享作为入口点）的包装器。
// 它负责所有与 trie 节点和节点 preimage 相关的交互。
type Database struct {
	disk ethdb.Database
	// 底层磁盘数据库。
	config *Config // Configuration for trie database
	// trie 数据库的配置。
	preimages *preimageStore // The store for caching preimages
	// 用于缓存 preimage 的存储。
	backend backend // The backend for managing trie nodes
	// 用于管理 trie 节点的后端接口实例。
}

// NewDatabase initializes the trie database with default settings, note
// the legacy hash-based scheme is used by default.
// NewDatabase 使用默认设置初始化 trie 数据库，注意默认使用传统的基于哈希的方案。
func NewDatabase(diskdb ethdb.Database, config *Config) *Database {
	// Sanitize the config and use the default one if it's not specified.
	// 清理配置，如果未指定则使用默认配置。
	if config == nil {
		config = HashDefaults
	}
	var preimages *preimageStore
	if config.Preimages {
		preimages = newPreimageStore(diskdb)
	}
	db := &Database{
		disk:      diskdb,
		config:    config,
		preimages: preimages,
	}
	if config.HashDB != nil && config.PathDB != nil {
		log.Crit("Both 'hash' and 'path' mode are configured")
	}
	if config.PathDB != nil {
		db.backend = pathdb.New(diskdb, config.PathDB, config.IsVerkle)
	} else {
		db.backend = hashdb.New(diskdb, config.HashDB)
	}
	return db
}

// NodeReader returns a reader for accessing trie nodes within the specified state.
// An error will be returned if the specified state is not available.
// NodeReader 返回一个用于访问指定状态内的 trie 节点的 reader。如果指定的状态不可用，将返回错误。
func (db *Database) NodeReader(blockRoot common.Hash) (database.NodeReader, error) {
	return db.backend.NodeReader(blockRoot)
}

// StateReader returns a reader that allows access to the state data associated
// with the specified state. An error will be returned if the specified state is
// not available.
// StateReader 返回一个允许访问与指定状态关联的状态数据的 reader。如果指定的状态不可用，将返回错误。
func (db *Database) StateReader(blockRoot common.Hash) (database.StateReader, error) {
	return db.backend.StateReader(blockRoot)
}

// Update performs a state transition by committing dirty nodes contained in the
// given set in order to update state from the specified parent to the specified
// root. The held pre-images accumulated up to this point will be flushed in case
// the size exceeds the threshold.
// Update 通过提交给定集合中包含的脏节点来执行状态转换，以便将状态从指定的父状态更新到指定的根状态。
// 如果大小超过阈值，将刷新到目前为止累积的 preimage。
//
// The passed in maps(nodes, states) will be retained to avoid copying everything.
// Therefore, these maps must not be changed afterwards.
// 传入的 map（nodes, states）将被保留以避免复制所有内容。因此，之后不得更改这些 map。
func (db *Database) Update(root common.Hash, parent common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *StateSet) error {
	if db.preimages != nil {
		db.preimages.commit(false)
	}
	switch b := db.backend.(type) {
	case *hashdb.Database:
		return b.Update(root, parent, block, nodes)
	case *pathdb.Database:
		return b.Update(root, parent, block, nodes, states.internal())
	}
	return errors.New("unknown backend")
}

// Commit iterates over all the children of a particular node, writes them out
// to disk. As a side effect, all pre-images accumulated up to this point are
// also written.
// Commit 迭代特定节点的所有子节点，并将它们写入磁盘。作为副作用，所有到目前为止累积的 preimage 也被写入。
func (db *Database) Commit(root common.Hash, report bool) error {
	if db.preimages != nil {
		db.preimages.commit(true)
	}
	return db.backend.Commit(root, report)
}

// Size returns the storage size of diff layer nodes above the persistent disk
// layer, the dirty nodes buffered within the disk layer, and the size of cached
// preimages.
// Size 返回持久磁盘层之上的差异层节点的存储大小、磁盘层中缓冲的脏节点以及缓存的 preimage 的大小。
func (db *Database) Size() (common.StorageSize, common.StorageSize, common.StorageSize) {
	var (
		diffs, nodes common.StorageSize
		preimages    common.StorageSize
	)
	diffs, nodes = db.backend.Size()
	if db.preimages != nil {
		preimages = db.preimages.size()
	}
	return diffs, nodes, preimages
}

// Scheme returns the node scheme used in the database.
// Scheme 返回数据库中使用的节点方案。
func (db *Database) Scheme() string {
	if db.config.PathDB != nil {
		return rawdb.PathScheme
	}
	return rawdb.HashScheme
}

// Close flushes the dangling preimages to disk and closes the trie database.
// It is meant to be called when closing the blockchain object, so that all
// resources held can be released correctly.
// Close 将悬挂的 preimage 刷新到磁盘并关闭 trie 数据库。它旨在在关闭区块链对象时调用，以便正确释放所有持有的资源。
func (db *Database) Close() error {
	db.WritePreimages()
	return db.backend.Close()
}

// WritePreimages flushes all accumulated preimages to disk forcibly.
// WritePreimages 强制将所有累积的 preimage 刷新到磁盘。
func (db *Database) WritePreimages() {
	if db.preimages != nil {
		db.preimages.commit(true)
	}
}

// Preimage retrieves a cached trie node pre-image from preimage store.
// Preimage 从 preimage 存储中检索缓存的 trie 节点 preimage。
func (db *Database) Preimage(hash common.Hash) []byte {
	if db.preimages == nil {
		return nil
	}
	return db.preimages.preimage(hash)
}

// InsertPreimage writes pre-images of trie node to the preimage store.
// InsertPreimage 将 trie 节点的 preimage 写入 preimage 存储。
func (db *Database) InsertPreimage(preimages map[common.Hash][]byte) {
	if db.preimages == nil {
		return
	}
	db.preimages.insertPreimage(preimages)
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold. The held pre-images accumulated
// up to this point will be flushed in case the size exceeds the threshold.
// Cap 迭代地刷新旧但仍被引用的 trie 节点，直到总内存使用量低于给定阈值。
// 如果大小超过阈值，将刷新到目前为止累积的 preimage。
//
// It's only supported by hash-based database and will return an error for others.
// 它仅受基于哈希的数据库支持，对于其他数据库将返回错误。
func (db *Database) Cap(limit common.StorageSize) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	if db.preimages != nil {
		db.preimages.commit(false)
	}
	return hdb.Cap(limit)
}

// Reference adds a new reference from a parent node to a child node. This function
// is used to add reference between internal trie node and external node(e.g. storage
// trie root), all internal trie nodes are referenced together by database itself.
// Reference 从父节点向子节点添加新的引用。此函数用于在内部 trie 节点和外部节点（例如，存储 trie 根）之间添加引用，
// 所有内部 trie 节点都由数据库本身一起引用。
//
// It's only supported by hash-based database and will return an error for others.
// 它仅受基于哈希的数据库支持，对于其他数据库将返回错误。
func (db *Database) Reference(root common.Hash, parent common.Hash) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	hdb.Reference(root, parent)
	return nil
}

// Dereference removes an existing reference from a root node. It's only
// supported by hash-based database and will return an error for others.
// Dereference 从根节点删除现有引用。它仅受基于哈希的数据库支持，对于其他数据库将返回错误。
func (db *Database) Dereference(root common.Hash) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	hdb.Dereference(root)
	return nil
}

// Recover rollbacks the database to a specified historical point. The state is
// supported as the rollback destination only if it's canonical state and the
// corresponding trie histories are existent. It's only supported by path-based
// database and will return an error for others.
// Recover 将数据库回滚到指定的历史点。只有当状态是规范状态且存在相应的 trie 历史记录时，才支持将该状态作为回滚目标。
// 它仅受基于路径的数据库支持，对于其他数据库将返回错误。
func (db *Database) Recover(target common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Recover(target)
}

// Recoverable returns the indicator if the specified state is enabled to be
// recovered. It's only supported by path-based database and will return an
// error for others.
// Recoverable 返回指示器，指示是否可以恢复指定状态。它仅受基于路径的数据库支持，对于其他数据库将返回错误。
func (db *Database) Recoverable(root common.Hash) (bool, error) {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return false, errors.New("not supported")
	}
	return pdb.Recoverable(root), nil
}

// Disable deactivates the database and invalidates all available state layers
// as stale to prevent access to the persistent state, which is in the syncing
// stage.
// Disable 禁用数据库并将所有可用的状态层标记为过时，以防止访问处于同步阶段的持久状态。
//
// It's only supported by path-based database and will return an error for others.
// 它仅受基于路径的数据库支持，对于其他数据库将返回错误。
func (db *Database) Disable() error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Disable()
}

// Enable activates database and resets the state tree with the provided persistent
// state root once the state sync is finished.
// Enable 激活数据库，并在状态同步完成后使用提供的持久状态根重置状态树。
func (db *Database) Enable(root common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Enable(root)
}

// Journal commits an entire diff hierarchy to disk into a single journal entry.
// This is meant to be used during shutdown to persist the snapshot without
// flattening everything down (bad for reorgs). It's only supported by path-based
// database and will return an error for others.
// Journal 将整个差异层级结构提交到磁盘上的单个日志条目中。这旨在在关闭期间使用，以持久化快照而不展平所有内容（对重组不利）。
// 它仅受基于路径的数据库支持，对于其他数据库将返回错误。
func (db *Database) Journal(root common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Journal(root)
}

// IsVerkle returns the indicator if the database is holding a verkle tree.
// IsVerkle 返回指示器，指示数据库是否持有 Verkle 树。
func (db *Database) IsVerkle() bool {
	return db.config.IsVerkle
}

// Disk returns the underlying disk database.
// Disk 返回底层的磁盘数据库。
func (db *Database) Disk() ethdb.Database {
	return db.disk
}
