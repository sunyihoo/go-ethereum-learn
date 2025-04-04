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

package pathdb

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// 历史状态 (Historical State): layerTree 中存储的多个状态层允许节点访问过去某个区块的状态。每个新的区块都可能导致一个新的状态层被添加到树中。
// 高效更新 (Efficient Updates): 通过在现有的状态层之上创建差异层，可以高效地存储和管理状态的更改。只有修改的部分才需要被记录在新的差异层中。
// 状态修剪 (State Pruning): cap 方法实现了状态修剪的功能。随着时间的推移，layerTree 中可能会积累大量的差异层，占用大量内存。通过将较旧的差异层展平到磁盘，可以减少内存使用，同时仍然保留访问历史状态的能力。
// 区块链重组 (Blockchain Reorganizations): 当区块链发生重组时，layerTree 的结构允许节点快速切换到不同的状态分支。通过简单地选择不同的头层，节点可以有效地回滚或切换到另一个链的历史。

// layerTree is a group of state layers identified by the state root.
// This structure defines a few basic operations for manipulating
// state layers linked with each other in a tree structure. It's
// thread-safe to use. However, callers need to ensure the thread-safety
// of the referenced layer by themselves.
// layerTree 是一组由状态根标识的状态层。
// 此结构定义了一些基本操作，用于操作以树状结构相互链接的状态层。
// 它是线程安全的。但是，调用者需要自行确保引用的层的线程安全性。
type layerTree struct {
	lock sync.RWMutex
	// 读写锁，用于保护对 layers 映射的并发访问。
	layers map[common.Hash]layer
	// 存储所有状态层的映射，键是状态根哈希，值是对应的 layer 接口实例。
}

// newLayerTree constructs the layerTree with the given head layer.
// newLayerTree 使用给定的头层构建 layerTree。
func newLayerTree(head layer) *layerTree {
	tree := new(layerTree)
	tree.reset(head)
	return tree
}

// reset initializes the layerTree by the given head layer.
// All the ancestors will be iterated out and linked in the tree.
// reset 通过给定的头层初始化 layerTree。
// 所有祖先层都将被迭代并链接到树中。
func (tree *layerTree) reset(head layer) {
	tree.lock.Lock()
	defer tree.lock.Unlock()

	var layers = make(map[common.Hash]layer)
	for head != nil {
		layers[head.rootHash()] = head
		head = head.parentLayer()
	}
	tree.layers = layers
}

// get retrieves a layer belonging to the given state root.
// get 检索属于给定状态根的层。
func (tree *layerTree) get(root common.Hash) layer {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	return tree.layers[root]
}

// forEach iterates the stored layers inside and applies the
// given callback on them.
// forEach 迭代内部存储的层，并对它们应用给定的回调函数。
func (tree *layerTree) forEach(onLayer func(layer)) {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	for _, layer := range tree.layers {
		onLayer(layer)
	}
}

// len returns the number of layers cached.
// len 返回缓存的层数。
func (tree *layerTree) len() int {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	return len(tree.layers)
}

// add inserts a new layer into the tree if it can be linked to an existing old parent.
// add 如果新层可以链接到现有的旧父层，则将其插入到树中。
func (tree *layerTree) add(root common.Hash, parentRoot common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *StateSetWithOrigin) error {
	// Reject noop updates to avoid self-loops. This is a special case that can
	// happen for clique networks and proof-of-stake networks where empty blocks
	// don't modify the state (0 block subsidy).
	// 拒绝无操作的更新以避免自循环。这在 clique 网络和权益证明网络中可能会发生，
	// 在这些网络中，空块不会修改状态（0 区块奖励）。
	//
	// Although we could silently ignore this internally, it should be the caller's
	// responsibility to avoid even attempting to insert such a layer.
	// 尽管我们可以在内部静默地忽略这一点，但避免尝试插入这样的层应该是调用者的责任。
	if root == parentRoot {
		return errors.New("layer cycle")
	}
	parent := tree.get(parentRoot)
	if parent == nil {
		return fmt.Errorf("triedb parent [%#x] layer missing", parentRoot)
	}
	l := parent.update(root, parent.stateID()+1, block, newNodeSet(nodes.Flatten()), states)

	tree.lock.Lock()
	tree.layers[l.rootHash()] = l
	tree.lock.Unlock()
	return nil
}

// cap traverses downwards the diff tree until the number of allowed diff layers
// are crossed. All diffs beyond the permitted number are flattened downwards.
// cap 向下遍历差异树，直到超过允许的差异层数。超出允许数量的所有差异都向下展平。
func (tree *layerTree) cap(root common.Hash, layers int) error {
	// Retrieve the head layer to cap from
	// 检索要限制的头层。
	l := tree.get(root)
	if l == nil {
		return fmt.Errorf("triedb layer [%#x] missing", root)
	}
	diff, ok := l.(*diffLayer)
	if !ok {
		return fmt.Errorf("triedb layer [%#x] is disk layer", root)
	}
	tree.lock.Lock()
	defer tree.lock.Unlock()

	// If full commit was requested, flatten the diffs and merge onto disk
	// 如果请求完全提交，则展平差异并合并到磁盘。
	if layers == 0 {
		base, err := diff.persist(true)
		if err != nil {
			return err
		}
		// Replace the entire layer tree with the flat base
		// 用扁平的基础层替换整个层树。
		tree.layers = map[common.Hash]layer{base.rootHash(): base}
		return nil
	}
	// Dive until we run out of layers or reach the persistent database
	// 向下深入，直到我们用完层数或到达持久化数据库。
	for i := 0; i < layers-1; i++ {
		// If we still have diff layers below, continue down
		// 如果我们下面还有差异层，则继续向下。
		if parent, ok := diff.parentLayer().(*diffLayer); ok {
			diff = parent
		} else {
			// Diff stack too shallow, return without modifications
			// 差异堆栈太浅，不进行修改直接返回。
			return nil
		}
	}
	// We're out of layers, flatten anything below, stopping if it's the disk or if
	// the memory limit is not yet exceeded.
	// 我们已经用完层数，展平下面的任何内容，如果它是磁盘层或者尚未超过内存限制则停止。
	switch parent := diff.parentLayer().(type) {
	case *diskLayer:
		return nil

	case *diffLayer:
		// Hold the lock to prevent any read operations until the new
		// parent is linked correctly.
		// 持有锁以防止任何读取操作，直到新的父层正确链接。
		diff.lock.Lock()

		base, err := parent.persist(false)
		if err != nil {
			diff.lock.Unlock()
			return err
		}
		tree.layers[base.rootHash()] = base
		diff.parent = base

		diff.lock.Unlock()

	default:
		panic(fmt.Sprintf("unknown data layer in triedb: %T", parent))
	}
	// Remove any layer that is stale or links into a stale layer
	// 移除任何过时或链接到过时层的层。
	children := make(map[common.Hash][]common.Hash)
	for root, layer := range tree.layers {
		if dl, ok := layer.(*diffLayer); ok {
			parent := dl.parentLayer().rootHash()
			children[parent] = append(children[parent], root)
		}
	}
	var remove func(root common.Hash)
	remove = func(root common.Hash) {
		delete(tree.layers, root)
		for _, child := range children[root] {
			remove(child)
		}
		delete(children, root)
	}
	for root, layer := range tree.layers {
		if dl, ok := layer.(*diskLayer); ok && dl.isStale() {
			remove(root)
		}
	}
	return nil
}

// bottom returns the bottom-most disk layer in this tree.
// bottom 返回此树中最底层的磁盘层。
func (tree *layerTree) bottom() *diskLayer {
	tree.lock.RLock()
	defer tree.lock.RUnlock()

	if len(tree.layers) == 0 {
		return nil // Shouldn't happen, empty tree
	}
	// pick a random one as the entry point
	// 选择一个随机的作为入口点。
	var current layer
	for _, layer := range tree.layers {
		current = layer
		break
	}
	for current.parentLayer() != nil {
		current = current.parentLayer()
	}
	return current.(*diskLayer)
}
