// Copyright 2020 The go-ethereum Authors
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

package trie

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// MPT 提交操作：
// 在以太坊中，状态树的提交（Commit）是将内存中的修改（脏节点）写入底层数据库（如 LevelDB）的过程。committer 负责收集这些节点。
// 脏节点（Dirty Nodes）：
// 脏节点是指自上次提交以来被修改的节点，包括插入、更新或删除的节点。nodes 按插入顺序存储，便于后续处理。
// 叶子节点（leafNode）：
// MPT 中的叶子节点存储实际数据（如账户状态或存储值）。collectLeaf 控制是否在提交中包含这些节点，可能与优化或特定用例相关。

// committer is the tool used for the trie Commit operation. The committer will
// capture all dirty nodes during the commit process and keep them cached in
// insertion order.
//
// committer 是用于 trie 提交操作的工具。committer 将在提交过程中捕获所有脏节点，并按插入顺序缓存它们。
// 用于在 Merkle Patricia Trie（MPT）的提交（Commit）操作中捕获和缓存脏节点。
// committer 在提交过程中记录所有修改过的节点（脏节点），通过 nodes 缓存，结合 tracer 跟踪变化，并根据 collectLeaf 决定是否包括叶子节点。
type committer struct {
	nodes       *trienode.NodeSet // 用于存储脏节点集合，按插入顺序缓存。
	tracer      *tracer           // 用于跟踪 trie 的变化（插入、删除和原始值）。
	collectLeaf bool              // 控制是否收集叶子节点（leafNode）。
}

// newCommitter creates a new committer or picks one from the pool.
// newCommitter 创建一个新的 committer 或从池中取一个。
func newCommitter(nodeset *trienode.NodeSet, tracer *tracer, collectLeaf bool) *committer {
	return &committer{
		nodes:       nodeset,
		tracer:      tracer,
		collectLeaf: collectLeaf,
	}
}

// Commit collapses a node down into a hash node.
// Commit 将节点折叠成一个 hashNode。
func (c *committer) Commit(n node, parallel bool) hashNode {
	return c.commit(nil, n, parallel).(hashNode)
}

// MPT 节点类型：
//  - shortNode：单路径节点，Val 可以是 fullNode、hashNode 或 valueNode。
//  - fullNode：分支节点，包含 17 个子节点。
//  - hashNode：已哈希的子树引用。

// 根据节点类型处理：
//  shortNode：
//   复制节点。
//   如果子节点是 fullNode，递归提交。
//   将键转换为紧凑编码（hexToCompact）。
//   调用 c.store 存储并返回结果。
//  fullNode：
//   提交所有子节点（commitChildren）。
//   复制节点并更新子节点。
//   调用 c.store 存储并返回结果。
//  hashNode：
//   直接返回。
//  其他类型（nil、valueNode）：
//   抛出异常。

// commit collapses a node down into a hash node and returns it.
// commit 将节点折叠成一个 hashNode 并返回。
// 用于将 Merkle Patricia Trie（MPT）的节点折叠为 hashNode，并将其提交到脏节点集合。
func (c *committer) commit(path []byte, n node, parallel bool) node {
	// if this path is clean, use available cached data
	// 如果此路径是干净的，使用可用的缓存数据
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash
	}
	// Commit children, then parent, and remove the dirty flag.
	// 提交子节点，然后是父节点，并移除脏标志。
	switch cn := n.(type) {
	case *shortNode:
		// Commit child
		// 提交子节点
		collapsed := cn.copy()

		// If the child is fullNode, recursively commit,
		// otherwise it can only be hashNode or valueNode.
		// 如果子节点是 fullNode，则递归提交，
		// 否则它只能是 hashNode 或 valueNode。
		if _, ok := cn.Val.(*fullNode); ok {
			collapsed.Val = c.commit(append(path, cn.Key...), cn.Val, false)
		}
		// The key needs to be copied, since we're adding it to the
		// modified nodeset.
		// 需要复制键，因为我们将其添加到修改的节点集中。
		collapsed.Key = hexToCompact(cn.Key)
		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn
		}
		return collapsed
	case *fullNode:
		hashedKids := c.commitChildren(path, cn, parallel)
		collapsed := cn.copy()
		collapsed.Children = hashedKids

		hashedNode := c.store(path, collapsed)
		if hn, ok := hashedNode.(hashNode); ok {
			return hn
		}
		return collapsed
	case hashNode:
		return cn
	default:
		// nil, valuenode shouldn't be committed
		// nil, valuenode 不应被提交
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// commitChildren commits the children of the given fullnode
// commitChildren 提交给定 fullNode 的子节点
//
// path []byte：当前节点的路径。
// n *fullNode：要处理的 fullNode。
// parallel bool：是否并行提交。
//
// [17]node：提交后的子节点数组。
func (c *committer) commitChildren(path []byte, n *fullNode, parallel bool) [17]node {
	var (
		wg       sync.WaitGroup
		nodesMu  sync.Mutex
		children [17]node
	)
	for i := 0; i < 16; i++ { // 遍历前 16 个子节点（索引 0-15）
		child := n.Children[i]
		if child == nil { // 如果子节点为 nil，跳过。
			continue
		}
		// If it's the hashed child, save the hash value directly.
		// Note: it's impossible that the child in range [0, 15]
		// is a valueNode.
		// 如果是已哈希的子节点，直接保存哈希值。
		// 注意：在 [0, 15] 范围内的子节点不可能是 valueNode。
		if hn, ok := child.(hashNode); ok { // 如果是 hashNode，直接保存哈希。
			children[i] = hn
			continue
		}
		// Commit the child recursively and store the "hashed" value.
		// Note the returned node can be some embedded nodes, so it's
		// possible the type is not hashNode.
		// 递归提交子节点并存储“哈希”值。
		// 注意：返回的节点可能是某些嵌入节点，因此类型可能不是 hashNode。
		if !parallel { // 根据 parallel：串行：调用 c.commit 提交子节点。
			children[i] = c.commit(append(path, byte(i)), child, false)
		} else { // 并行：启动 goroutine，使用独立的 committer 提交子节点，合并结果。
			wg.Add(1)
			go func(index int) {
				p := append(path, byte(index))
				childSet := trienode.NewNodeSet(c.nodes.Owner)
				childCommitter := newCommitter(childSet, c.tracer, c.collectLeaf)
				children[index] = childCommitter.commit(p, child, false)
				nodesMu.Lock()
				c.nodes.MergeSet(childSet)
				nodesMu.Unlock()
				wg.Done()
			}(i)
		}
	}
	if parallel {
		wg.Wait()
	}
	// For the 17th child, it's possible the type is valuenode.
	// 对于第 17 个子节点，其类型可能是 valueNode。
	if n.Children[16] != nil {
		children[16] = n.Children[16]
	}
	return children
}

// MPT 节点存储：
// 嵌入节点：小节点（通常小于 32 字节）嵌入父节点，不独立存储，hash == nil 表示这种情况。
// 独立节点：较大节点被哈希化并存储在数据库中，hash 是其 Keccak-256 哈希。
// 脏节点：
// nodes（trienode.NodeSet）收集修改过的节点，提交时写入数据库。
// 叶子节点：
// 在账户 trie 中，叶子节点存储账户状态（如余额）。collectLeaf 控制是否记录这些值。

// store hashes the node n and adds it to the modified nodeset. If leaf collection
// is enabled, leaf nodes will be tracked in the modified nodeset as well.
//
// store 对节点 n 进行哈希处理并将其添加到修改的节点集中。如果启用了叶子收集，叶子节点也将被跟踪在修改的节点集中。
func (c *committer) store(path []byte, n node) node {
	// Larger nodes are replaced by their hash and stored in the database.
	// 较大的节点被其哈希值替换并存储在数据库中。
	var hash, _ = n.cache()

	// This was not generated - must be a small node stored in the parent.
	// In theory, we should check if the node is leaf here (embedded node
	// usually is leaf node). But small value (less than 32bytes) is not
	// our target (leaves in account trie only).
	//
	// 这个节点未生成哈希 - 一定是存储在父节点中的小节点。
	// 理论上，我们应该在这里检查节点是否为叶子节点（嵌入节点通常是叶子节点）。
	// 但小值（小于 32 字节）不是我们的目标（仅针对账户 trie 中的叶子节点）。
	if hash == nil {
		// The node is embedded in its parent, in other words, this node
		// will not be stored in the database independently, mark it as
		// deleted only if the node was existent in database before.
		// 该节点嵌入在其父节点中，换句话说，此节点不会独立存储在数据库中，仅当该节点之前存在于数据库中时才标记为删除。
		_, ok := c.tracer.accessList[string(path)]
		if ok {
			c.nodes.AddNode(path, trienode.NewDeleted())
		}
		return n
	}
	// Collect the dirty node to nodeset for return.
	// 将脏节点收集到 nodeset 以返回。
	nhash := common.BytesToHash(hash)
	c.nodes.AddNode(path, trienode.New(nhash, nodeToBytes(n)))

	// Collect the corresponding leaf node if it's required. We don't check
	// full node since it's impossible to store value in fullNode. The key
	// length of leaves should be exactly same.
	// 如果需要，收集对应的叶子节点。我们不检查 fullNode，因为 fullNode 不可能存储值。
	// 叶子节点的键长度应完全相同。
	if c.collectLeaf {
		if sn, ok := n.(*shortNode); ok {
			if val, ok := sn.Val.(valueNode); ok {
				c.nodes.AddLeaf(nhash, val)
			}
		}
	}
	return hash
}

// ForGatherChildren decodes the provided node and traverses the children inside.
// ForGatherChildren 解码提供的节点并遍历其中的子节点。
func ForGatherChildren(node []byte, onChild func(common.Hash)) {
	forGatherChildren(mustDecodeNodeUnsafe(nil, node), onChild)
}

// MPT 节点类型：
// shortNode：表示单路径节点，包含一个键（Key）和值（Val），Val 可以是子节点。
// fullNode：表示分支节点，包含 16 个子节点（对应十六进制 0-f）。
// hashNode：表示未展开的子树引用，仅存储哈希。
// valueNode：存储实际数据（如账户状态），不包含子节点。

// forGatherChildren traverses the node hierarchy and invokes the callback
// for all the hashnode children.
// forGatherChildren 遍历节点层次结构，并为所有 hashnode 子节点调用回调函数。
// 收集 hashNode 以便后续加载完整子树，或验证 trie 结构。
// 从根节点开始，深度优先遍历所有子节点，直到遇到 hashNode 或终止节点（valueNode、nil）。
func forGatherChildren(n node, onChild func(hash common.Hash)) {
	switch n := n.(type) {
	case *shortNode:
		forGatherChildren(n.Val, onChild)
	case *fullNode:
		for i := 0; i < 16; i++ {
			forGatherChildren(n.Children[i], onChild)
		}
	case hashNode: // hashNode 是 MPT 的压缩形式，表示需要从数据库加载的子树。onChild 收集这些引用。
		onChild(common.BytesToHash(n))
	case valueNode, nil:
	default:
		panic(fmt.Sprintf("unknown node type: %T", n))
	}
}
