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
	"sync"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

// diskLayer is a low level persistent layer built on top of a key-value store.
// diskLayer 是基于键值存储构建的低级持久层。
type diskLayer struct {
	root   common.Hash      // Immutable, root hash to which this layer was made for. root 不可变，为此层创建的根哈希
	id     uint64           // Immutable, corresponding state id. id 不可变，对应的状态 ID
	db     *Database        // Path-based trie database 基于路径的 trie 数据库
	nodes  *fastcache.Cache // GC friendly memory cache of clean nodes. GC 友好的干净节点内存缓存
	buffer *buffer          // Dirty buffer to aggregate writes of nodes and states 聚合节点和状态写入的脏缓冲区
	stale  bool             // Signals that the layer became stale (state progressed) 标志该层是否已过时（状态已前进）
	lock   sync.RWMutex     // Lock used to protect stale flag 用于保护 stale 标志的锁
}

// 创建状态数据库的最底层，连接内存缓存和持久存储（如 LevelDB）。

// newDiskLayer creates a new disk layer based on the passing arguments.
// newDiskLayer 根据传入的参数创建新的磁盘层。
func newDiskLayer(root common.Hash, id uint64, db *Database, nodes *fastcache.Cache, buffer *buffer) *diskLayer {
	// Initialize a clean cache if the memory allowance is not zero
	// or reuse the provided cache if it is not nil (inherited from
	// the original disk layer).
	// 如果内存允许量不为零，则初始化干净缓存；
	// 如果提供的缓存不为 nil，则重用它（从原始磁盘层继承）。
	if nodes == nil && db.config.CleanCacheSize != 0 {
		nodes = fastcache.New(db.config.CleanCacheSize)
	}
	return &diskLayer{
		root:   root,
		id:     id,
		db:     db,
		nodes:  nodes,
		buffer: buffer,
	}
}

// rootHash implements the layer interface, returning root hash of corresponding state.
// rootHash 实现 layer 接口，返回对应状态的根哈希。
func (dl *diskLayer) rootHash() common.Hash {
	return dl.root
}

// stateID implements the layer interface, returning the state id of disk layer.
// stateID 实现 layer 接口，返回磁盘层的状态 ID。
func (dl *diskLayer) stateID() uint64 {
	return dl.id
}

// parentLayer implements the layer interface, returning nil as there's no layer
// below the disk.
// parentLayer 实现 layer 接口，返回 nil，因为磁盘层下方没有层。
func (dl *diskLayer) parentLayer() layer {
	return nil
}

// isStale return whether this layer has become stale (was flattened across) or if
// it's still live.
// isStale 返回此层是否已过时（已被展平）或是否仍有效。
func (dl *diskLayer) isStale() bool {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	return dl.stale
}

// markStale sets the stale flag as true.
// markStale 将 stale 标志设置为 true。
func (dl *diskLayer) markStale() {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	if dl.stale {
		panic("triedb disk layer is stale") // we've committed into the same base from two children, boom
	}
	dl.stale = true
}

// 实现 trie 节点的分层查询（脏缓冲区 -> 干净缓存 -> 磁盘），支持状态访问。

// node implements the layer interface, retrieving the trie node with the
// provided node info. No error will be returned if the node is not found.
// node 实现 layer 接口，使用提供的节点信息检索 trie 节点。如果未找到节点，不会返回错误。
func (dl *diskLayer) node(owner common.Hash, path []byte, depth int) ([]byte, common.Hash, *nodeLoc, error) {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.stale {
		return nil, common.Hash{}, nil, errSnapshotStale
	}
	// Try to retrieve the trie node from the not-yet-written
	// node buffer first. Note the buffer is lock free since
	// it's impossible to mutate the buffer before tagging the
	// layer as stale.
	// 首先尝试从尚未写入的节点缓冲区检索 trie 节点。
	// 注意，缓冲区是无锁的，因为在将层标记为过时之前无法变更缓冲区。
	n, found := dl.buffer.node(owner, path)
	if found {
		dirtyNodeHitMeter.Mark(1)
		dirtyNodeReadMeter.Mark(int64(len(n.Blob)))
		dirtyNodeHitDepthHist.Update(int64(depth))
		return n.Blob, n.Hash, &nodeLoc{loc: locDirtyCache, depth: depth}, nil
	}
	dirtyNodeMissMeter.Mark(1)

	// Try to retrieve the trie node from the clean memory cache
	// 尝试从干净内存缓存中检索 trie 节点
	h := newHasher()
	defer h.release()

	key := nodeCacheKey(owner, path)
	if dl.nodes != nil {
		if blob := dl.nodes.Get(nil, key); len(blob) > 0 {
			cleanNodeHitMeter.Mark(1)
			cleanNodeReadMeter.Mark(int64(len(blob)))
			return blob, h.hash(blob), &nodeLoc{loc: locCleanCache, depth: depth}, nil
		}
		cleanNodeMissMeter.Mark(1)
	}
	// Try to retrieve the trie node from the disk.
	// 尝试从磁盘检索 trie 节点。
	var blob []byte
	if owner == (common.Hash{}) {
		blob = rawdb.ReadAccountTrieNode(dl.db.diskdb, path)
	} else {
		blob = rawdb.ReadStorageTrieNode(dl.db.diskdb, owner, path)
	}
	if dl.nodes != nil && len(blob) > 0 {
		dl.nodes.Set(key, blob)
		cleanNodeWriteMeter.Mark(int64(len(blob)))
	}
	return blob, h.hash(blob), &nodeLoc{loc: locDiskLayer, depth: depth}, nil
}

// account directly retrieves the account RLP associated with a particular
// hash in the slim data format.
//
// Note the returned account is not a copy, please don't modify it.
//
// account 直接检索与特定哈希关联的账户 RLP（采用精简数据格式）。
//
// 注意，返回的账户不是副本，请勿修改它。
func (dl *diskLayer) account(hash common.Hash, depth int) ([]byte, error) {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.stale {
		return nil, errSnapshotStale
	}
	// Try to retrieve the account from the not-yet-written
	// node buffer first. Note the buffer is lock free since
	// it's impossible to mutate the buffer before tagging the
	// layer as stale.
	// 首先尝试从尚未写入的节点缓冲区检索账户。
	// 注意，缓冲区是无锁的，因为在将层标记为过时之前无法变更缓冲区。
	blob, found := dl.buffer.account(hash)
	if found {
		dirtyStateHitMeter.Mark(1)
		dirtyStateReadMeter.Mark(int64(len(blob)))
		dirtyStateHitDepthHist.Update(int64(depth))

		if len(blob) == 0 {
			stateAccountInexMeter.Mark(1)
		} else {
			stateAccountExistMeter.Mark(1)
		}
		return blob, nil
	}
	dirtyStateMissMeter.Mark(1)

	// TODO(rjl493456442) support persistent state retrieval 支持持久状态检索
	return nil, errors.New("not supported")
}

// storage directly retrieves the storage data associated with a particular hash,
// within a particular account.
//
// Note the returned account is not a copy, please don't modify it.
//
// storage 直接检索与特定账户内特定哈希关联的存储数据。
//
// 注意，返回的账户不是副本，请勿修改它。
func (dl *diskLayer) storage(accountHash, storageHash common.Hash, depth int) ([]byte, error) {
	// Hold the lock, ensure the parent won't be changed during the
	// state accessing.
	// 持有锁，确保在状态访问期间父层不会发生变化。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.stale {
		return nil, errSnapshotStale
	}
	// Try to retrieve the storage slot from the not-yet-written
	// node buffer first. Note the buffer is lock free since
	// it's impossible to mutate the buffer before tagging the
	// layer as stale.
	// 首先尝试从尚未写入的节点缓冲区检索存储槽。
	// 注意，缓冲区是无锁的，因为在将层标记为过时之前无法变更缓冲区。
	if blob, found := dl.buffer.storage(accountHash, storageHash); found {
		dirtyStateHitMeter.Mark(1)
		dirtyStateReadMeter.Mark(int64(len(blob)))
		dirtyStateHitDepthHist.Update(int64(depth))

		if len(blob) == 0 {
			stateStorageInexMeter.Mark(1)
		} else {
			stateStorageExistMeter.Mark(1)
		}
		return blob, nil
	}
	dirtyStateMissMeter.Mark(1)

	// TODO(rjl493456442) support persistent state retrieval 支持持久状态检索
	return nil, errors.New("not supported")
}

// update implements the layer interface, returning a new diff layer on top
// with the given state set.
// update 实现 layer 接口，返回带有给定状态集的新差异层。
func (dl *diskLayer) update(root common.Hash, id uint64, block uint64, nodes *nodeSet, states *StateSetWithOrigin) *diffLayer {
	return newDiffLayer(dl, root, id, block, nodes, states)
}

// commit merges the given bottom-most diff layer into the node buffer
// and returns a newly constructed disk layer. Note the current disk
// layer must be tagged as stale first to prevent re-access.
//
// commit 将给定的最底层差异层合并到节点缓冲区，并返回新构建的磁盘层。
// 注意，当前磁盘层必须首先标记为过时，以防止重新访问。
//
// 将内存差异层持久化到磁盘，支持状态提交。
func (dl *diskLayer) commit(bottom *diffLayer, force bool) (*diskLayer, error) {
	dl.lock.Lock()
	defer dl.lock.Unlock()

	// Construct and store the state history first. If crash happens after storing
	// the state history but without flushing the corresponding states(journal),
	// the stored state history will be truncated from head in the next restart.
	//
	// 首先构建并存储状态历史。如果在存储状态历史后但未刷新相应状态（日志）时发生崩溃，
	// 存储的状态历史将在下次重启时从头部截断。
	var (
		overflow bool
		oldest   uint64
	)
	if dl.db.freezer != nil {
		err := writeHistory(dl.db.freezer, bottom)
		if err != nil {
			return nil, err
		}
		// Determine if the persisted history object has exceeded the configured
		// limitation, set the overflow as true if so.
		// 判断持久化的历史对象是否超过配置限制，如果是，则将 overflow 设置为 true。
		tail, err := dl.db.freezer.Tail()
		if err != nil {
			return nil, err
		}
		limit := dl.db.config.StateHistory
		if limit != 0 && bottom.stateID()-tail > limit {
			overflow = true
			oldest = bottom.stateID() - limit + 1 // track the id of history **after truncation**
		}
	}
	// Mark the diskLayer as stale before applying any mutations on top.
	// 在应用任何变更之前将磁盘层标记为过时。
	dl.stale = true

	// Store the root->id lookup afterwards. All stored lookups are identified
	// by the **unique** state root. It's impossible that in the same chain
	// blocks are not adjacent but have the same root.
	// 之后存储 root->id 查找。所有存储的查找都由唯一的状态根标识。
	// 在同一链中，区块不可能不相邻但具有相同的根。
	if dl.id == 0 {
		rawdb.WriteStateID(dl.db.diskdb, dl.root, 0)
	}
	rawdb.WriteStateID(dl.db.diskdb, bottom.rootHash(), bottom.stateID())

	// In a unique scenario where the ID of the oldest history object (after tail
	// truncation) surpasses the persisted state ID, we take the necessary action
	// of forcibly committing the cached dirty states to ensure that the persisted
	// state ID remains higher.
	// 在一种独特场景中，如果最旧历史对象（尾部截断后）的 ID 超过持久状态 ID，
	// 我们采取强制提交缓存的脏状态的必要行动，以确保持久状态 ID 保持较高。
	if !force && rawdb.ReadPersistentStateID(dl.db.diskdb) < oldest {
		force = true
	}
	// Merge the trie nodes and flat states of the bottom-most diff layer into the
	// buffer as the combined layer.
	// 将最底层差异层的 trie 节点和平面状态合并到缓冲区作为组合层。
	combined := dl.buffer.commit(bottom.nodes, bottom.states.stateSet)
	if combined.full() || force {
		if err := combined.flush(dl.db.diskdb, dl.db.freezer, dl.nodes, bottom.stateID()); err != nil {
			return nil, err
		}
	}
	ndl := newDiskLayer(bottom.root, bottom.stateID(), dl.db, dl.nodes, combined)

	// To remove outdated history objects from the end, we set the 'tail' parameter
	// to 'oldest-1' due to the offset between the freezer index and the history ID.
	// 为了从末尾移除过时的历史对象，我们将“tail”参数设置为“oldest-1”，
	// 因为 freezer 索引和历史 ID 之间存在偏移。
	if overflow {
		pruned, err := truncateFromTail(ndl.db.diskdb, ndl.db.freezer, oldest-1)
		if err != nil {
			return nil, err
		}
		log.Debug("Pruned state history", "items", pruned, "tailid", oldest)
	}
	return ndl, nil
}

// revert applies the given state history and return a reverted disk layer.
// revert 应用给定的状态历史并返回回滚后的磁盘层。
func (dl *diskLayer) revert(h *history) (*diskLayer, error) {
	if h.meta.root != dl.rootHash() {
		return nil, errUnexpectedHistory
	}
	if dl.id == 0 {
		return nil, fmt.Errorf("%w: zero state id", errStateUnrecoverable)
	}
	var (
		buff     = crypto.NewKeccakState()
		hashes   = make(map[common.Address]common.Hash)
		accounts = make(map[common.Hash][]byte)
		storages = make(map[common.Hash]map[common.Hash][]byte)
	)
	for addr, blob := range h.accounts {
		hash := crypto.HashData(buff, addr.Bytes())
		hashes[addr] = hash
		accounts[hash] = blob
	}
	for addr, storage := range h.storages {
		hash, ok := hashes[addr]
		if !ok {
			panic(fmt.Errorf("storage history with no account %x", addr))
		}
		storages[hash] = storage
	}
	// Apply the reverse state changes upon the current state. This must
	// be done before holding the lock in order to access state in "this"
	// layer.
	// 在当前状态上应用逆状态变更。这必须在持有锁之前完成，以便访问“此”层中的状态。
	nodes, err := apply(dl.db, h.meta.parent, h.meta.root, h.accounts, h.storages)
	if err != nil {
		return nil, err
	}
	// Mark the diskLayer as stale before applying any mutations on top.
	// 在应用任何变更之前将磁盘层标记为过时。
	dl.lock.Lock()
	defer dl.lock.Unlock()

	dl.stale = true

	// State change may be applied to node buffer, or the persistent
	// state, depends on if node buffer is empty or not. If the node
	// buffer is not empty, it means that the state transition that
	// needs to be reverted is not yet flushed and cached in node
	// buffer, otherwise, manipulate persistent state directly.
	//
	// 状态变更可能应用于节点缓冲区或持久状态，取决于节点缓冲区是否为空。
	// 如果节点缓冲区不为空，意味着需要回滚的状态转换尚未刷新并缓存到节点缓冲区中，
	// 否则直接操作持久状态。
	if !dl.buffer.empty() {
		err := dl.buffer.revertTo(dl.db.diskdb, nodes, accounts, storages)
		if err != nil {
			return nil, err
		}
	} else {
		batch := dl.db.diskdb.NewBatch()
		writeNodes(batch, nodes, dl.nodes)
		rawdb.WritePersistentStateID(batch, dl.id-1)
		if err := batch.Write(); err != nil {
			log.Crit("Failed to write states", "err", err)
		}
	}
	return newDiskLayer(h.meta.parent, dl.id-1, dl.db, dl.nodes, dl.buffer), nil
}

// size returns the approximate size of cached nodes in the disk layer.
// size 返回磁盘层中缓存节点的近似大小。
func (dl *diskLayer) size() common.StorageSize {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.stale {
		return 0
	}
	return common.StorageSize(dl.buffer.size())
}

// resetCache releases the memory held by clean cache to prevent memory leak.
// resetCache 释放干净缓存持有的内存，以防止内存泄漏。
func (dl *diskLayer) resetCache() {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// Stale disk layer loses the ownership of clean caches.
	// 过时的磁盘层失去对干净缓存的所有权。
	if dl.stale {
		return
	}
	if dl.nodes != nil {
		dl.nodes.Reset()
	}
}

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
