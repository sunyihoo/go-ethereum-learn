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

package hashdb

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb/database"
)

var (
	memcacheCleanHitMeter   = metrics.NewRegisteredMeter("hashdb/memcache/clean/hit", nil)
	memcacheCleanMissMeter  = metrics.NewRegisteredMeter("hashdb/memcache/clean/miss", nil)
	memcacheCleanReadMeter  = metrics.NewRegisteredMeter("hashdb/memcache/clean/read", nil)
	memcacheCleanWriteMeter = metrics.NewRegisteredMeter("hashdb/memcache/clean/write", nil)

	memcacheDirtyHitMeter   = metrics.NewRegisteredMeter("hashdb/memcache/dirty/hit", nil)
	memcacheDirtyMissMeter  = metrics.NewRegisteredMeter("hashdb/memcache/dirty/miss", nil)
	memcacheDirtyReadMeter  = metrics.NewRegisteredMeter("hashdb/memcache/dirty/read", nil)
	memcacheDirtyWriteMeter = metrics.NewRegisteredMeter("hashdb/memcache/dirty/write", nil)

	memcacheFlushTimeTimer  = metrics.NewRegisteredResettingTimer("hashdb/memcache/flush/time", nil)
	memcacheFlushNodesMeter = metrics.NewRegisteredMeter("hashdb/memcache/flush/nodes", nil)
	memcacheFlushBytesMeter = metrics.NewRegisteredMeter("hashdb/memcache/flush/bytes", nil)

	memcacheGCTimeTimer  = metrics.NewRegisteredResettingTimer("hashdb/memcache/gc/time", nil)
	memcacheGCNodesMeter = metrics.NewRegisteredMeter("hashdb/memcache/gc/nodes", nil)
	memcacheGCBytesMeter = metrics.NewRegisteredMeter("hashdb/memcache/gc/bytes", nil)

	memcacheCommitTimeTimer  = metrics.NewRegisteredResettingTimer("hashdb/memcache/commit/time", nil)
	memcacheCommitNodesMeter = metrics.NewRegisteredMeter("hashdb/memcache/commit/nodes", nil)
	memcacheCommitBytesMeter = metrics.NewRegisteredMeter("hashdb/memcache/commit/bytes", nil)
)

// Config contains the settings for database.
// Config 包含数据库的设置。
type Config struct {
	CleanCacheSize int // Maximum memory allowance (in bytes) for caching clean nodes 缓存干净节点的最大内存允许值（以字节为单位）
}

// Defaults is the default setting for database if it's not specified.
// Notably, clean cache is disabled explicitly,
// Defaults 是数据库的默认设置，如果未指定则使用此设置。
// 值得注意的是，干净缓存被明确禁用，
var Defaults = &Config{
	// Explicitly set clean cache size to 0 to avoid creating fastcache,
	// otherwise database must be closed when it's no longer needed to
	// prevent memory leak.
	// 将干净缓存大小明确设置为 0，以避免创建 fastcache，
	// 否则当数据库不再需要时必须关闭，以防止内存泄漏。
	CleanCacheSize: 0,
}

// Database is an intermediate write layer between the trie data structures and
// the disk database. The aim is to accumulate trie writes in-memory and only
// periodically flush a couple tries to disk, garbage collecting the remainder.
//
// Database 是 trie 数据结构和磁盘数据库之间的中间写入层。其目的是在内存中累积 trie 的写入，
// 并仅定期将部分 trie 刷新到磁盘，同时对剩余部分进行垃圾回收。
type Database struct {
	diskdb  ethdb.Database              // Persistent storage for matured trie nodes  成熟 trie 节点的持久化存储
	cleans  *fastcache.Cache            // GC friendly memory cache of clean node RLPs 对垃圾回收友好的干净节点 RLP 的内存缓存
	dirties map[common.Hash]*cachedNode // Data and references relationships of dirty trie nodes  脏 trie 节点的数据和引用关系
	oldest  common.Hash                 // Oldest tracked node, flush-list head  最旧的跟踪节点，刷新列表的头部
	newest  common.Hash                 // Newest tracked node, flush-list tail 最新的跟踪节点，刷新列表的尾部

	gctime  time.Duration      // Time spent on garbage collection since last commit 自上次提交以来在垃圾回收上花费的时间
	gcnodes uint64             // Nodes garbage collected since last commit  自上次提交以来垃圾回收的节点数
	gcsize  common.StorageSize // Data storage garbage collected since last commit 自上次提交以来垃圾回收的数据存储大小

	flushtime  time.Duration      // Time spent on data flushing since last commit 自上次提交以来在数据刷新上花费的时间
	flushnodes uint64             // Nodes flushed since last commit 自上次提交以来刷新的节点数
	flushsize  common.StorageSize // Data storage flushed since last commit 自上次提交以来刷新的数据存储大小

	dirtiesSize  common.StorageSize // Storage size of the dirty node cache (exc. metadata) 脏节点缓存的存储大小（不包括元数据）
	childrenSize common.StorageSize // Storage size of the external children tracking 外部子节点跟踪的存储大小

	lock sync.RWMutex // 读写锁
}

// Trie 节点与状态管理
//  以太坊的 Merkle Patricia Trie（MPT）由多个节点组成，cachedNode 表示内存中的单个 trie 节点。node 字段存储 RLP 编码的节点数据，可能包含键值对或分支信息。
//  脏节点：cachedNode 通常用于表示已被修改但尚未持久化的节点，与 Database.dirties 对应。
//
// 引用计数与垃圾回收
//  parents 字段实现引用计数，当计数降为 0 时，节点可被垃圾回收。这是区块链状态管理中常见的优化手段，避免无用数据占用内存。
//  以太坊节点需要处理状态膨胀（state bloat），cachedNode 的设计支持高效清理。
//
// 双向链表与刷新机制
//  flushPrev 和 flushNext 构成的双向链表用于批量刷新节点到磁盘（如 LevelDB），这是以太坊客户端（如 go-ethereum）优化写入性能的关键技术。

// cachedNode is all the information we know about a single cached trie node
// in the memory database write layer.
// cachedNode 是我们在内存数据库写入层中了解的关于单个缓存 trie 节点的所有信息。
type cachedNode struct {
	node      []byte                   // Encoded node blob, immutable 编码后的节点数据块，不可变
	parents   uint32                   // Number of live nodes referencing this one 引用此节点的活动节点数量
	external  map[common.Hash]struct{} // The set of external children 外部子节点的集合
	flushPrev common.Hash              // Previous node in the flush-list 刷新列表中的前一个节点
	flushNext common.Hash              // Next node in the flush-list 刷新列表中的下一个节点
}

// cachedNodeSize is the raw size of a cachedNode data structure without any
// node data included. It's an approximate size, but should be a lot better
// than not counting them.
// cachedNodeSize 是 cachedNode 数据结构的原始大小，不包括任何节点数据。
// 这是一个近似大小，但应该比不计算它们要好得多
var cachedNodeSize = int(reflect.TypeOf(cachedNode{}).Size())

// forChildren invokes the callback for all the tracked children of this node,
// both the implicit ones from inside the node as well as the explicit ones
// from outside the node.
//
// forChildren 为此节点的所有被跟踪的子节点调用回调函数，
// 包括节点内部的隐式子节点以及节点外部的显式子节点。
//
// 在以太坊中，trie 节点的子节点可能是干净的（已持久化）或脏的（未持久化）。
// forChildren 方法同时处理两类子节点，确保状态管理的完整性。
// Trie 节点的子节点：在 MPT 中，分支节点最多有 16 个子节点（对应 16 进制字符），扩展节点有 1 个子节点。
// forChildren 的设计适应这种结构，确保所有子节点可被访问。
func (n *cachedNode) forChildren(onChild func(hash common.Hash)) {
	for child := range n.external { // 跟踪外部子节点，用于垃圾回收或状态更新时的引用检查。
		onChild(child)
	}
	trie.ForGatherChildren(n.node, onChild)
}

// New initializes the hash-based node database.
// New 初始化基于哈希的节点数据库。
func New(diskdb ethdb.Database, config *Config) *Database {
	if config == nil {
		config = Defaults
	}
	var cleans *fastcache.Cache
	if config.CleanCacheSize > 0 {
		cleans = fastcache.New(config.CleanCacheSize)
	}
	return &Database{
		diskdb:  diskdb,
		cleans:  cleans,
		dirties: make(map[common.Hash]*cachedNode),
	}
}

// insert inserts a trie node into the memory database. All nodes inserted by
// this function will be reference tracked. This function assumes the lock is
// already held.
// insert 将一个 trie 节点插入到内存数据库中。
// 通过此函数插入的所有节点都会被引用跟踪。此函数假设锁已经被持有。
func (db *Database) insert(hash common.Hash, node []byte) {
	// If the node's already cached, skip
	// 如果节点已经被缓存，则跳过
	if _, ok := db.dirties[hash]; ok {
		return
	}
	memcacheDirtyWriteMeter.Mark(int64(len(node)))

	// Create the cached entry for this node
	// 为此节点创建缓存条目
	entry := &cachedNode{
		node:      node,
		flushPrev: db.newest,
	}
	// 递归增加子节点的引用计数
	entry.forChildren(func(child common.Hash) {
		if c := db.dirties[child]; c != nil {
			c.parents++
		}
	})
	db.dirties[hash] = entry

	// Update the flush-list endpoints
	// 更新刷新列表的端点
	if db.oldest == (common.Hash{}) {
		db.oldest, db.newest = hash, hash
	} else {
		db.dirties[db.newest].flushNext, db.newest = hash, hash
	}
	db.dirtiesSize += common.StorageSize(common.HashLength + len(node))
}

// node retrieves an encoded cached trie node from memory. If it cannot be found
// cached, the method queries the persistent database for the content.
// node 从内存中检索一个编码的缓存 trie 节点。如果在缓存中找不到，该方法会查询持久化数据库以获取内容。
func (db *Database) node(hash common.Hash) ([]byte, error) {
	// It doesn't make sense to retrieve the metaroot
	// 检索元根（metaroot）没有意义
	if hash == (common.Hash{}) {
		return nil, errors.New("not found")
	}
	// Retrieve the node from the clean cache if available
	// 如果可用，从干净缓存中检索节点
	if db.cleans != nil {
		if enc := db.cleans.Get(nil, hash[:]); enc != nil {
			memcacheCleanHitMeter.Mark(1)
			memcacheCleanReadMeter.Mark(int64(len(enc)))
			return enc, nil
		}
	}
	// Retrieve the node from the dirty cache if available.
	// 如果可用，从脏缓存中检索节点
	db.lock.RLock()
	dirty := db.dirties[hash]
	db.lock.RUnlock()

	// Return the cached node if it's found in the dirty set.
	// The dirty.node field is immutable and safe to read it
	// even without lock guard.
	// 如果在脏集合中找到节点，则返回缓存的节点。
	// dirty.node 字段是不可变的，即使没有锁保护也可以安全读取。
	if dirty != nil {
		memcacheDirtyHitMeter.Mark(1)
		memcacheDirtyReadMeter.Mark(int64(len(dirty.node)))
		return dirty.node, nil
	}
	memcacheDirtyMissMeter.Mark(1)

	// Content unavailable in memory, attempt to retrieve from disk
	// 内存中内容不可用，尝试从磁盘检索
	enc := rawdb.ReadLegacyTrieNode(db.diskdb, hash)
	if len(enc) != 0 {
		if db.cleans != nil {
			db.cleans.Set(hash[:], enc)
			memcacheCleanMissMeter.Mark(1)
			memcacheCleanWriteMeter.Mark(int64(len(enc)))
		}
		return enc, nil
	}
	return nil, errors.New("not found")
}

// Reference adds a new reference from a parent node to a child node.
// This function is used to add reference between internal trie node
// and external node(e.g. storage trie root), all internal trie nodes
// are referenced together by database itself.
// Reference 从父节点到子节点添加一个新的引用。
// 此函数用于在内部 trie 节点和外部节点（例如存储 trie 根）之间添加引用，所有内部 trie 节点由数据库自身一起引用。
func (db *Database) Reference(child common.Hash, parent common.Hash) {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.reference(child, parent)
}

// reference is the private locked version of Reference.
// reference 是 Reference 的私有加锁版本。
func (db *Database) reference(child common.Hash, parent common.Hash) {
	// If the node does not exist, it's a node pulled from disk, skip
	// 如果节点不存在，则它是从磁盘拉取的节点，跳过
	node, ok := db.dirties[child]
	if !ok {
		return
	}
	// The reference is for state root, increase the reference counter.
	// 如果引用是针对状态根，增加引用计数器。
	if parent == (common.Hash{}) {
		node.parents += 1
		return
	}
	// The reference is for external storage trie, don't duplicate if
	// the reference is already existent.
	// 如果引用是针对外部存储 trie，如果引用已存在，则不重复。
	if db.dirties[parent].external == nil {
		db.dirties[parent].external = make(map[common.Hash]struct{})
	}
	if _, ok := db.dirties[parent].external[child]; ok {
		return
	}
	node.parents++
	db.dirties[parent].external[child] = struct{}{}
	db.childrenSize += common.HashLength
}

// Dereference removes an existing reference from a root node.
// Dereference 从根节点移除一个现有引用。
func (db *Database) Dereference(root common.Hash) {
	// Sanity check to ensure that the meta-root is not removed
	// 健全性检查以确保元根未被移除
	if root == (common.Hash{}) {
		log.Error("Attempted to dereference the trie cache meta root")
		return
	}
	db.lock.Lock()
	defer db.lock.Unlock()

	nodes, storage, start := len(db.dirties), db.dirtiesSize, time.Now()
	db.dereference(root)

	db.gcnodes += uint64(nodes - len(db.dirties))
	db.gcsize += storage - db.dirtiesSize
	db.gctime += time.Since(start)

	memcacheGCTimeTimer.Update(time.Since(start))
	memcacheGCBytesMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheGCNodesMeter.Mark(int64(nodes - len(db.dirties)))

	log.Debug("Dereferenced trie from memory database", "nodes", nodes-len(db.dirties), "size", storage-db.dirtiesSize, "time", time.Since(start),
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)
}

// dereference is the private locked version of Dereference.
// dereference 是 Dereference 的私有加锁版本。
func (db *Database) dereference(hash common.Hash) {
	// If the node does not exist, it's a previously committed node.
	// 如果节点不存在，则它是之前已提交的节点。
	node, ok := db.dirties[hash]
	if !ok {
		return
	}
	// If there are no more references to the node, delete it and cascade
	// 如果节点没有更多引用，删除它并级联
	if node.parents > 0 {
		// This is a special cornercase where a node loaded from disk (i.e. not in the
		// memcache any more) gets reinjected as a new node (short node split into full,
		// then reverted into short), causing a cached node to have no parents. That is
		// no problem in itself, but don't make maxint parents out of it.
		// 这是一个特殊情况，从磁盘加载的节点（即不再在内存缓存中）被重新注入为新节点（短节点分裂为完整节点，然后恢复为短节点），
		// 导致缓存节点没有父节点。这本身没有问题，但不要让父节点数达到最大值。
		node.parents--
	}
	if node.parents == 0 {
		// Remove the node from the flush-list
		// 从刷新列表中移除节点
		switch hash {
		case db.oldest:
			db.oldest = node.flushNext
			if node.flushNext != (common.Hash{}) {
				db.dirties[node.flushNext].flushPrev = common.Hash{}
			}
		case db.newest:
			db.newest = node.flushPrev
			if node.flushPrev != (common.Hash{}) {
				db.dirties[node.flushPrev].flushNext = common.Hash{}
			}
		default:
			db.dirties[node.flushPrev].flushNext = node.flushNext
			db.dirties[node.flushNext].flushPrev = node.flushPrev
		}
		// Dereference all children and delete the node
		// 取消引用所有子节点并删除该节点
		node.forChildren(func(child common.Hash) {
			db.dereference(child)
		})
		delete(db.dirties, hash)
		db.dirtiesSize -= common.StorageSize(common.HashLength + len(node.node))
		if node.external != nil {
			db.childrenSize -= common.StorageSize(len(node.external) * common.HashLength)
		}
	}
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold.
// Cap 迭代地刷新旧的但仍被引用的 trie 节点，直到总内存使用量低于给定阈值。
func (db *Database) Cap(limit common.StorageSize) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	// 创建一个数据库批次以刷新持久化数据。重要的是外部代码不会看到不一致的状态（在提交期间从内存缓存中移除的引用数据尚未在持久存储中）。
	// 这一点通过仅在数据库写入完成时取消缓存现有数据来保证。
	batch := db.diskdb.NewBatch()
	nodes, storage, start := len(db.dirties), db.dirtiesSize, time.Now()

	// db.dirtiesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted.
	// db.dirtiesSize 仅包含缓存中的有用数据，但在报告总内存消耗时，还需要计算维护元数据。
	size := db.dirtiesSize + common.StorageSize(len(db.dirties)*cachedNodeSize)
	size += db.childrenSize

	// Keep committing nodes from the flush-list until we're below allowance
	// 持续提交刷新列表中的节点，直到低于允许值
	oldest := db.oldest
	for size > limit && oldest != (common.Hash{}) {
		// Fetch the oldest referenced node and push into the batch
		// 获取最旧的被引用节点并推入批次
		node := db.dirties[oldest]
		rawdb.WriteLegacyTrieNode(batch, oldest, node.node)

		// If we exceeded the ideal batch size, commit and reset
		// 如果超过了理想的批次大小，提交并重置
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				log.Error("Failed to write flush list to disk", "err", err)
				return err
			}
			batch.Reset()
		}
		// Iterate to the next flush item, or abort if the size cap was achieved. Size
		// is the total size, including the useful cached data (hash -> blob), the
		// cache item metadata, as well as external children mappings.
		// 迭代到下一个刷新项，如果达到大小上限则中止。大小是总大小，包括有用的缓存数据（hash -> blob）、缓存项元数据以及外部子节点映射。
		size -= common.StorageSize(common.HashLength + len(node.node) + cachedNodeSize)
		if node.external != nil {
			size -= common.StorageSize(len(node.external) * common.HashLength)
		}
		oldest = node.flushNext
	}
	// Flush out any remainder data from the last batch
	// 刷新最后一批中的任何剩余数据
	if err := batch.Write(); err != nil {
		log.Error("Failed to write flush list to disk", "err", err)
		return err
	}
	// Write successful, clear out the flushed data
	// 写入成功，清除已刷新的数据
	for db.oldest != oldest {
		node := db.dirties[db.oldest]
		delete(db.dirties, db.oldest)
		db.oldest = node.flushNext

		db.dirtiesSize -= common.StorageSize(common.HashLength + len(node.node))
		if node.external != nil {
			db.childrenSize -= common.StorageSize(len(node.external) * common.HashLength)
		}
	}
	if db.oldest != (common.Hash{}) {
		db.dirties[db.oldest].flushPrev = common.Hash{}
	}
	db.flushnodes += uint64(nodes - len(db.dirties))
	db.flushsize += storage - db.dirtiesSize
	db.flushtime += time.Since(start)

	memcacheFlushTimeTimer.Update(time.Since(start))
	memcacheFlushBytesMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheFlushNodesMeter.Mark(int64(nodes - len(db.dirties)))

	log.Debug("Persisted nodes from memory database", "nodes", nodes-len(db.dirties), "size", storage-db.dirtiesSize, "time", time.Since(start),
		"flushnodes", db.flushnodes, "flushsize", db.flushsize, "flushtime", db.flushtime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	return nil
}

// Commit iterates over all the children of a particular node, writes them out
// to disk, forcefully tearing down all references in both directions. As a side
// effect, all pre-images accumulated up to this point are also written.
// Commit 迭代特定节点的所有子节点，将它们写入磁盘，强制拆除双向引用。作为副作用，到此为止积累的所有预映像也会被写入。
func (db *Database) Commit(node common.Hash, report bool) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Create a database batch to flush persistent data out. It is important that
	// outside code doesn't see an inconsistent state (referenced data removed from
	// memory cache during commit but not yet in persistent storage). This is ensured
	// by only uncaching existing data when the database write finalizes.
	// 创建一个数据库批次以刷新持久化数据。重要的是外部代码不会看到不一致的状态（在提交期间从内存缓存中移除的引用数据尚未在持久存储中）。
	// 这一点通过仅在数据库写入完成时取消缓存现有数据来保证。
	start := time.Now()
	batch := db.diskdb.NewBatch()

	// Move the trie itself into the batch, flushing if enough data is accumulated
	// 将 trie 本身移入批次，如果积累了足够的数据则刷新
	nodes, storage := len(db.dirties), db.dirtiesSize

	uncacher := &cleaner{db}
	if err := db.commit(node, batch, uncacher); err != nil {
		log.Error("Failed to commit trie from trie database", "err", err)
		return err
	}
	// Trie mostly committed to disk, flush any batch leftovers
	// Trie 大部分已提交到磁盘，刷新任何批次剩余数据
	if err := batch.Write(); err != nil {
		log.Error("Failed to write trie to disk", "err", err)
		return err
	}
	// Uncache any leftovers in the last batch
	// 取消缓存最后一批中的任何剩余数据
	if err := batch.Replay(uncacher); err != nil {
		return err
	}
	batch.Reset()

	// Reset the storage counters and bumped metrics
	// 重置存储计数器并更新指标
	memcacheCommitTimeTimer.Update(time.Since(start))
	memcacheCommitBytesMeter.Mark(int64(storage - db.dirtiesSize))
	memcacheCommitNodesMeter.Mark(int64(nodes - len(db.dirties)))

	logger := log.Info
	if !report {
		logger = log.Debug
	}
	logger("Persisted trie from memory database", "nodes", nodes-len(db.dirties)+int(db.flushnodes), "size", storage-db.dirtiesSize+db.flushsize, "time", time.Since(start)+db.flushtime,
		"gcnodes", db.gcnodes, "gcsize", db.gcsize, "gctime", db.gctime, "livenodes", len(db.dirties), "livesize", db.dirtiesSize)

	// Reset the garbage collection statistics
	// 重置垃圾回收统计数据
	db.gcnodes, db.gcsize, db.gctime = 0, 0, 0
	db.flushnodes, db.flushsize, db.flushtime = 0, 0, 0

	return nil
}

// commit is the private locked version of Commit.
// commit 是 Commit 的私有加锁版本。
func (db *Database) commit(hash common.Hash, batch ethdb.Batch, uncacher *cleaner) error {
	// If the node does not exist, it's a previously committed node
	// 如果节点不存在，则它是之前已提交的节点
	node, ok := db.dirties[hash]
	if !ok {
		return nil
	}
	var err error

	// Dereference all children and delete the node
	// 取消引用所有子节点并删除该节点
	node.forChildren(func(child common.Hash) {
		if err == nil {
			err = db.commit(child, batch, uncacher)
		}
	})
	if err != nil {
		return err
	}
	// If we've reached an optimal batch size, commit and start over
	// 如果达到了最佳批次大小，提交并重新开始
	rawdb.WriteLegacyTrieNode(batch, hash, node.node)
	if batch.ValueSize() >= ethdb.IdealBatchSize {
		if err := batch.Write(); err != nil {
			return err
		}
		err := batch.Replay(uncacher)
		if err != nil {
			return err
		}
		batch.Reset()
	}
	return nil
}

// cleaner is a database batch replayer that takes a batch of write operations
// and cleans up the trie database from anything written to disk.
// cleaner 是一个数据库批次重放器，接受一批写操作并清理已写入磁盘的 trie 数据库。
type cleaner struct {
	db *Database
}

// Put reacts to database writes and implements dirty data uncaching. This is the
// post-processing step of a commit operation where the already persisted trie is
// removed from the dirty cache and moved into the clean cache. The reason behind
// the two-phase commit is to ensure data availability while moving from memory
// to disk.
// Put 对数据库写入做出反应并实现脏数据的取消缓存。这是提交操作的后处理步骤，其中已持久化的 trie 从脏缓存中移除并移入干净缓存。
// 两阶段提交的原因是确保从内存到磁盘移动时数据的可用性。
func (c *cleaner) Put(key []byte, rlp []byte) error {
	hash := common.BytesToHash(key)

	// If the node does not exist, we're done on this path
	// 如果节点不存在，我们在此路径上完成
	node, ok := c.db.dirties[hash]
	if !ok {
		return nil
	}
	// Node still exists, remove it from the flush-list
	// 节点仍然存在，从刷新列表中移除它
	switch hash {
	case c.db.oldest:
		c.db.oldest = node.flushNext
		if node.flushNext != (common.Hash{}) {
			c.db.dirties[node.flushNext].flushPrev = common.Hash{}
		}
	case c.db.newest:
		c.db.newest = node.flushPrev
		if node.flushPrev != (common.Hash{}) {
			c.db.dirties[node.flushPrev].flushNext = common.Hash{}
		}
	default:
		c.db.dirties[node.flushPrev].flushNext = node.flushNext
		c.db.dirties[node.flushNext].flushPrev = node.flushPrev
	}
	// Remove the node from the dirty cache
	// 从脏缓存中移除节点
	delete(c.db.dirties, hash)
	c.db.dirtiesSize -= common.StorageSize(common.HashLength + len(node.node))
	if node.external != nil {
		c.db.childrenSize -= common.StorageSize(len(node.external) * common.HashLength)
	}
	// Move the flushed node into the clean cache to prevent insta-reloads
	// 将已刷新的节点移入干净缓存以防止即时重新加载
	if c.db.cleans != nil {
		c.db.cleans.Set(hash[:], rlp)
		memcacheCleanWriteMeter.Mark(int64(len(rlp)))
	}
	return nil
}

func (c *cleaner) Delete(key []byte) error {
	panic("not implemented")
}

// Update inserts the dirty nodes in provided nodeset into database and link the
// account trie with multiple storage tries if necessary.
// Update 将提供的节点集中的脏节点插入数据库，并在必要时将账户 trie 与多个存储 trie 链接。
func (db *Database) Update(root common.Hash, parent common.Hash, block uint64, nodes *trienode.MergedNodeSet) error {
	// Ensure the parent state is present and signal a warning if not.
	// 确保父状态存在，如果不存在则发出警告。
	if parent != types.EmptyRootHash {
		if blob, _ := db.node(parent); len(blob) == 0 {
			log.Error("parent state is not present")
		}
	}
	db.lock.Lock()
	defer db.lock.Unlock()

	// Insert dirty nodes into the database. In the same tree, it must be
	// ensured that children are inserted first, then parent so that children
	// can be linked with their parent correctly.
	//
	// Note, the storage tries must be flushed before the account trie to
	// retain the invariant that children go into the dirty cache first.
	//
	// 将脏节点插入数据库。在同一棵树中，必须确保先插入子节点，然后插入父节点，以便子节点可以正确链接到其父节点。
	//
	// 注意，必须在账户 trie 之前刷新存储 trie，以保持子节点首先进入脏缓存的不变性。
	var order []common.Hash
	for owner := range nodes.Sets {
		if owner == (common.Hash{}) {
			continue
		}
		order = append(order, owner)
	}
	if _, ok := nodes.Sets[common.Hash{}]; ok {
		order = append(order, common.Hash{})
	}
	for _, owner := range order {
		subset := nodes.Sets[owner]
		subset.ForEachWithOrder(func(path string, n *trienode.Node) {
			if n.IsDeleted() {
				return // ignore deletion
			}
			db.insert(n.Hash, n.Blob)
		})
	}
	// Link up the account trie and storage trie if the node points
	// to an account trie leaf.
	// 如果节点指向账户 trie 叶子，将账户 trie 和存储 trie 链接起来。
	if set, present := nodes.Sets[common.Hash{}]; present {
		for _, n := range set.Leaves {
			var account types.StateAccount
			if err := rlp.DecodeBytes(n.Blob, &account); err != nil {
				return err
			}
			if account.Root != types.EmptyRootHash {
				db.reference(account.Root, n.Parent)
			}
		}
	}
	return nil
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
//
// The first return will always be 0, representing the memory stored in unbounded
// diff layers above the dirty cache. This is only available in pathdb.
//
// Size 返回持久数据库层前内存缓存的当前存储大小。
//
// 第一个返回值始终为 0，表示存储在脏缓存之上无界差异层中的内存。这仅在 pathdb 中可用。
func (db *Database) Size() (common.StorageSize, common.StorageSize) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	// db.dirtiesSize only contains the useful data in the cache, but when reporting
	// the total memory consumption, the maintenance metadata is also needed to be
	// counted.
	// db.dirtiesSize 仅包含缓存中的有用数据，但在报告总内存消耗时，还需要计算维护元数据。
	var metadataSize = common.StorageSize(len(db.dirties) * cachedNodeSize)
	return 0, db.dirtiesSize + db.childrenSize + metadataSize
}

// Close closes the trie database and releases all held resources.
// Close 关闭 trie 数据库并释放所有持有的资源。
func (db *Database) Close() error {
	if db.cleans != nil {
		db.cleans.Reset()
	}
	return nil
}

// NodeReader returns a reader for accessing trie nodes within the specified state.
// An error will be returned if the specified state is not available.
// NodeReader 返回一个读取器，用于访问指定状态内的 trie 节点。如果指定状态不可用，将返回错误。
func (db *Database) NodeReader(root common.Hash) (database.NodeReader, error) {
	if _, err := db.node(root); err != nil {
		return nil, fmt.Errorf("state %#x is not available, %v", root, err)
	}
	return &reader{db: db}, nil
}

// reader is a state reader of Database which implements the Reader interface.
// reader 是 Database 的状态读取器，实现了 Reader 接口。
type reader struct {
	db *Database
}

// Node retrieves the trie node with the given node hash. No error will be
// returned if the node is not found.
// Node 检索具有给定节点哈希的 trie 节点。如果未找到节点，不会返回错误。
func (reader *reader) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	blob, _ := reader.db.node(hash)
	return blob, nil
}

// StateReader returns a reader that allows access to the state data associated
// with the specified state.
// StateReader 返回一个读取器，允许访问与指定状态关联的状态数据。
func (db *Database) StateReader(root common.Hash) (database.StateReader, error) {
	return nil, errors.New("not implemented")
}
