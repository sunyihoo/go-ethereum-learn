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
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// diffLayer represents a collection of modifications made to the in-memory tries
// along with associated state changes after running a block on top.
//
// The goal of a diff layer is to act as a journal, tracking recent modifications
// made to the state, that have not yet graduated into a semi-immutable state.
//
// diffLayer 代表在内存 trie 上执行一个区块后所做的修改集合，以及相关的状态更改。
// diff layer 的目标是充当一个日志，跟踪最近对状态所做的修改，这些修改尚未变成半不可变状态。
type diffLayer struct {
	// Immutables
	// 该层 diff 所属的状态根哈希。在以太坊中，每个状态（账户状态、存储状态）都通过一个唯一的根哈希来标识，这个根哈希是 Merkle-Patricia Trie 的根。
	root common.Hash // Root hash to which this layer diff belongs to
	// 对应的状态 ID。用于唯一标识一个特定的状态版本。
	id uint64 // Corresponding state id
	// 关联的区块号。表示这个 diff layer 是在处理哪个区块后产生的状态变化。
	block uint64 // Associated block number
	// 缓存的 trie 节点集合，通过所有者（通常是合约地址或全局状态）和路径（trie 中的路径）进行索引。这用于快速访问最近修改过的 trie 节点，避免每次都从底层存储加载。
	nodes *nodeSet // Cached trie nodes indexed by owner and path
	// 关联的状态更改集合，包含原始值。这用于跟踪哪些账户或存储槽被修改，以及它们在修改之前的值。这对于回滚操作或者在内存中维护状态变化很有用。
	states *StateSetWithOrigin // Associated state changes along with origin value

	// 父层，表示这个 diff layer 是基于哪个状态层构建的。它永远不为空。注意，这个字段的值是可以被改变的，这在状态同步或合并时可能会发生。`layer` 是一个接口，定义了状态层的通用行为。
	parent layer // Parent layer modified by this one, never nil, **can be changed**
	// 读写锁，用于保护父层 `parent` 的并发访问。在访问或修改父层时需要加锁，以保证数据的一致性。
	lock sync.RWMutex // Lock used to protect parent
}

// newDiffLayer creates a new diff layer on top of an existing layer.
// newDiffLayer 在现有层之上创建一个新的 diff layer。
func newDiffLayer(parent layer, root common.Hash, id uint64, block uint64, nodes *nodeSet, states *StateSetWithOrigin) *diffLayer {
	dl := &diffLayer{
		root:   root,
		id:     id,
		block:  block,
		parent: parent,
		nodes:  nodes,
		states: states,
	}
	dirtyNodeWriteMeter.Mark(int64(nodes.size))
	dirtyStateWriteMeter.Mark(int64(states.size))
	log.Debug("Created new diff layer", "id", id, "block", block, "nodesize", common.StorageSize(nodes.size), "statesize", common.StorageSize(states.size))
	return dl
}

// rootHash implements the layer interface, returning the root hash of
// corresponding state.
// rootHash 实现了 layer 接口，返回对应状态的根哈希。
func (dl *diffLayer) rootHash() common.Hash {
	return dl.root
}

// stateID implements the layer interface, returning the state id of the layer.
// stateID 实现了 layer 接口，返回该层的状态 ID。
func (dl *diffLayer) stateID() uint64 {
	return dl.id
}

// parentLayer implements the layer interface, returning the subsequent
// layer of the diff layer.
// parentLayer 实现了 layer 接口，返回 diff layer 的父层。
func (dl *diffLayer) parentLayer() layer {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	return dl.parent
}

// node implements the layer interface, retrieving the trie node blob with the
// provided node information. No error will be returned if the node is not found.
//
// node 实现了 layer 接口，根据提供的节点信息检索 trie 节点数据块（blob）。如果找不到节点，不会返回错误。
func (dl *diffLayer) node(owner common.Hash, path []byte, depth int) ([]byte, common.Hash, *nodeLoc, error) {
	// Hold the lock, ensure the parent won't be changed during the
	// state accessing.
	// 持有读锁，确保在访问状态期间父层不会被更改。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// If the trie node is known locally, return it
	// 如果该 trie 节点在当前层已知，则返回它。
	n, ok := dl.nodes.node(owner, path)
	if ok {
		dirtyNodeHitMeter.Mark(1)
		dirtyNodeHitDepthHist.Update(int64(depth))
		dirtyNodeReadMeter.Mark(int64(len(n.Blob)))
		return n.Blob, n.Hash, &nodeLoc{loc: locDiffLayer, depth: depth}, nil
	}
	// Trie node unknown to this layer, resolve from parent
	// 如果当前层未知该 trie 节点，则从父层解析。
	return dl.parent.node(owner, path, depth+1)
}

// account directly retrieves the account RLP associated with a particular
// hash in the slim data format.
//
// Note the returned account is not a copy, please don't modify it.
//
// account 直接检索与特定哈希关联的账户 RLP 数据，以精简数据格式。
// 注意：返回的账户不是副本，请不要修改它。
func (dl *diffLayer) account(hash common.Hash, depth int) ([]byte, error) {
	// Hold the lock, ensure the parent won't be changed during the
	// state accessing.
	// 持有读锁，确保在访问状态期间父层不会被更改。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if blob, found := dl.states.account(hash); found {
		dirtyStateHitMeter.Mark(1)
		dirtyStateHitDepthHist.Update(int64(depth))
		dirtyStateReadMeter.Mark(int64(len(blob)))

		if len(blob) == 0 {
			stateAccountInexMeter.Mark(1)
		} else {
			stateAccountExistMeter.Mark(1)
		}
		return blob, nil
	}
	// Account is unknown to this layer, resolve from parent
	// 如果当前层未知该账户，则从父层解析。
	return dl.parent.account(hash, depth+1)
}

// storage directly retrieves the storage data associated with a particular hash,
// within a particular account.
//
// Note the returned storage slot is not a copy, please don't modify it.
//
// storage 直接检索与特定哈希关联的存储数据，该哈希位于特定账户内。
//
// 注意：返回的存储槽不是副本，请不要修改它。
func (dl *diffLayer) storage(accountHash, storageHash common.Hash, depth int) ([]byte, error) {
	// Hold the lock, ensure the parent won't be changed during the
	// state accessing.
	// 持有读锁，确保在访问状态期间父层不会被更改。
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if blob, found := dl.states.storage(accountHash, storageHash); found {
		dirtyStateHitMeter.Mark(1)
		dirtyStateHitDepthHist.Update(int64(depth))
		dirtyStateReadMeter.Mark(int64(len(blob)))

		if len(blob) == 0 {
			stateStorageInexMeter.Mark(1)
		} else {
			stateStorageExistMeter.Mark(1)
		}
		return blob, nil
	}
	// storage slot is unknown to this layer, resolve from parent
	// 如果当前层未知该存储槽，则从父层解析。
	return dl.parent.storage(accountHash, storageHash, depth+1)
}

// update implements the layer interface, creating a new layer on top of the
// existing layer tree with the specified data items.
// update 实现了 layer 接口，在现有的层树之上创建一个包含指定数据项的新层。
func (dl *diffLayer) update(root common.Hash, id uint64, block uint64, nodes *nodeSet, states *StateSetWithOrigin) *diffLayer {
	return newDiffLayer(dl, root, id, block, nodes, states)
}

// persist flushes the diff layer and all its parent layers to disk layer.
// persist 将该 diff layer 及其所有父层刷新到磁盘层。
func (dl *diffLayer) persist(force bool) (layer, error) {
	if parent, ok := dl.parentLayer().(*diffLayer); ok {
		// Hold the lock to prevent any read operation until the new
		// parent is linked correctly.
		// 持有写锁，防止在新的父层正确链接之前进行任何读取操作。
		dl.lock.Lock()

		// The merging of diff layers starts at the bottom-most layer,
		// therefore we recurse down here, flattening on the way up
		// (diffToDisk).
		// diff layer 的合并从最底层的 layer 开始，因此我们在此处进行递归调用，并在向上返回的过程中进行扁平化（通过 diffToDisk 函数）。
		result, err := parent.persist(force)
		if err != nil {
			dl.lock.Unlock()
			return nil, err
		}
		dl.parent = result
		dl.lock.Unlock()
	}
	return diffToDisk(dl, force)
}

// size returns the approximate memory size occupied by this diff layer.
// size 返回此 diff layer 占用的大致内存大小。
func (dl *diffLayer) size() uint64 {
	return dl.nodes.size + dl.states.size
}

// diffToDisk merges a bottom-most diff into the persistent disk layer underneath
// it. The method will panic if called onto a non-bottom-most diff layer.
// diffToDisk 将最底层的 diff 合并到其下方的持久化磁盘层。如果对非最底层的 diff layer 调用此方法，将会发生 panic。
func diffToDisk(layer *diffLayer, force bool) (layer, error) {
	disk, ok := layer.parentLayer().(*diskLayer)
	if !ok {
		panic(fmt.Sprintf("unknown layer type: %T", layer.parentLayer()))
	}
	return disk.commit(layer, force)
}
