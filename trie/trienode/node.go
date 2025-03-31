// Copyright 2023 The go-ethereum Authors
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

package trienode

import (
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// 以太坊使用 Merkle Patricia Trie（MPT）来存储状态（State）、交易（Transactions）和收据（Receipts）。Node 结构体是 Trie 的基本构建块。
// 每个节点的哈希（Hash）是其内容的加密证明，用于确保数据的完整性和一致性。
// Blob 是节点内容的序列化形式，可能包含键值对、子节点引用等，具体取决于 Trie 的类型（例如账户节点、存储节点）。

// Node is a wrapper which contains the encoded blob of the trie node and its
// node hash. It is general enough that can be used to represent trie node
// corresponding to different trie implementations.
//
// Node 是一个封装器，包含了 trie 节点的编码 blob 及其节点哈希。
// 它足够通用，可以用来表示对应不同 trie 实现的 trie 节点。
//
// 用于表示以太坊中 Trie（前缀树）数据结构中的一个节点。
// Node 是一个通用的封装器，旨在存储 Trie 节点的序列化数据及其哈希。这种设计允许它适配不同的 Trie 实现（如 MPT 或 Verkle Tree），体现了代码的灵活性。
type Node struct {
	Hash common.Hash // Node hash, empty for deleted node // 节点哈希，对于删除的节点为空
	Blob []byte      // Encoded node blob, nil for the deleted node // 编码后的节点 blob，对于删除的节点为 nil
}

// Size returns the total memory size used by this node.
// Size 返回此节点使用的总内存大小。
func (n *Node) Size() int {
	return len(n.Blob) + common.HashLength
}

// 在以太坊状态 Trie 中，删除一个账户或存储槽并不会物理移除数据，而是通过标记（如置空或设为 nil）来表示。这种“软删除”设计是为了支持状态回滚和历史数据查询。

// IsDeleted returns the indicator if the node is marked as deleted.
// IsDeleted 返回该节点是否被标记为删除的指示器。
func (n *Node) IsDeleted() bool {
	// 检查 Blob 的长度是否为 0，若为 0，则认为节点被删除。
	return len(n.Blob) == 0
}

// 在以太坊的 Merkle Patricia Trie（MPT）中，节点的创建和更新是状态管理的核心操作。
// 例如，当一个账户的余额发生变化时，相关 Trie 节点会被更新，并生成新的哈希。

// New constructs a node with provided node information.
// New 使用提供的节点信息构造一个节点。
func New(hash common.Hash, blob []byte) *Node {
	return &Node{Hash: hash, Blob: blob}
}

// NewDeleted constructs a node which is deleted.
// NewDeleted 构造一个被删除的节点。
//
//	专门用于创建被标记为删除的节点，简化调用者代码，避免手动指定空值。
func NewDeleted() *Node { return New(common.Hash{}, nil) }

// trie 中的叶子节点:
// 在以太坊的 MPT 中，叶子节点（Leaf Node）存储实际的状态数据，例如账户的 nonce、余额、代码哈希和存储根。
// leaf 结构体的 Blob 包含这些数据的 RLP 编码，Parent 则维护了 Trie 的树形结构，确保可以通过哈希追溯到根节点。

// leaf represents a trie leaf node
// leaf 表示一个 trie 叶子节点
//
// leaf 封装了 Trie 的叶子节点信息，叶子节点通常存储实际数据（如账户余额、存储槽值等），而非指向其他节点的引用。
type leaf struct {
	Blob   []byte      // raw blob of leaf // 叶子节点的原始 blob 表示叶子节点的原始编码数据，通常是键值对的序列化形式（例如账户状态的 RLP 编码）。
	Parent common.Hash // the hash of parent node // 父节点的哈希 表示该叶子节点的父节点的哈希值，用于追溯 Trie 的层级结构。
}

// 提交操作（Commit Operation）:
// 以太坊客户端（如 Geth）在处理区块时，会更新状态 Trie，并将变更提交到数据库。NodeSet 正是为此设计的中间结构：
// Leaves 收集叶子节点的变更。
// Nodes 收集非叶子节点的变更（如分支节点或扩展节点）。
// updates 和 deletes 用于统计变更，便于优化或日志记录。
// 提交操作的目标是将内存中的 Trie 更新持久化到数据库，同时生成新的根哈希。

// 路径键（Path）:
// Nodes 使用 string 作为键，表示节点的路径。在 MPT 中，路径通常是键（key）的十六进制编码，反映了从根节点到目标节点的导航路线。路径是从根->目标节点的键的十六进制编码。
// 这种设计允许快速定位 Trie 中的节点，便于批量处理变更。

// NodeSet contains a set of nodes collected during the commit operation.
// Each node is keyed by path. It's not thread-safe to use.
//
// NodeSet 包含在提交操作期间收集的一组节点。
// 每个节点以路径作为键。它不是线程安全的。
// NodeSet 是一个临时数据结构，用于在 Trie 的提交（commit）操作中收集和跟踪所有变更的节点。
type NodeSet struct {
	Owner   common.Hash      // 表示该节点集合的所有者，通常是 Trie 根节点的哈希，用于标识特定的 Trie 实例。区分账户 Trie 和存储 Trie 的关键字段。
	Leaves  []*leaf          // 一个叶子节点指针的切片，收集了所有叶子节点。
	Nodes   map[string]*Node // 键是节点的路径（字符串形式），值是 *Node 类型指针，表示非叶子节点（如分支节点或扩展节点）。
	updates int              // the count of updated and inserted nodes  更新和插入的节点计数
	deletes int              // the count of deleted nodes  删除的节点计数
}

// 以太坊的状态 Trie 分为两类：
//   账户 Trie（Account Trie）:
//     存储所有账户的状态（如余额、nonce 等），其根哈希记录在区块链的区块头中。
//     NewNodeSet 的注释指出，对于账户 Trie，owner 为零（common.Hash{}），因为它没有特定的“拥有者”，而是全局状态的一部分。
//   存储 Trie（Storage Trie）:
//     每个账户有自己的存储 Trie，用于存储合约的存储槽数据，其根哈希记录在账户的 storageRoot 字段中。
//     对于存储 Trie，owner 是拥有账户的地址哈希（通常是对账户地址应用 Keccak-256 得到的哈希）。

// NewNodeSet initializes a node set. The owner is zero for the account trie and
// the owning account address hash for storage tries.
//
// NewNodeSet 初始化一个节点集合。所有者对于账户 trie 为零，对于存储 trie 则是拥有账户的地址哈希。
func NewNodeSet(owner common.Hash) *NodeSet {
	return &NodeSet{
		Owner: owner,
		Nodes: make(map[string]*Node),
	}
}

// ForEachWithOrder iterates the nodes with the order from bottom to top,
// right to left, nodes with the longest path will be iterated first.
//
// ForEachWithOrder 按照从下到上、从右到左的顺序迭代节点，路径最长的节点将首先被迭代。
// 用于按照特定顺序（从下到上、从右到左，路径最长优先）迭代 NodeSet 中的节点，并对每个节点执行回调函数。
// “从下到上”顺序适合 Trie 的提交或校验操作，因为叶子节点（存储实际数据）通常需要先处理，然后向上更新父节点的哈希。
//
// 在状态 Trie 的提交（commit）过程中，节点变更需要批量持久化到数据库。从底部开始处理（叶子节点优先）可以确保父节点的哈希计算依赖于已更新的子节点，保持一致性。
// “从右到左”的顺序可能与 MPT 的分支节点（Branch Node）处理顺序相关，确保路径字典序较大的分支优先处理。
func (set *NodeSet) ForEachWithOrder(callback func(path string, n *Node)) {
	paths := make([]string, 0, len(set.Nodes))
	for path := range set.Nodes {
		paths = append(paths, path)
	}
	// 排序规则:
	// 从下到上:
	//   在 Trie 中，路径长度反映节点深度，路径越长表示节点越靠近叶子（底部）。
	// 从右到左:
	//   在字符串排序中，字典序较大的路径靠右（如 "ff" > "00"）。
	// 路径最长优先:
	//   通过反转排序，确保最长路径（最底层的节点）首先被处理。

	// Bottom-up, the longest path first
	// 从下到上，最长路径优先
	//
	// 使用 sort.StringSlice 将 paths 转换为可排序类型。
	// 使用 sort.Reverse 反转排序顺序，使路径最长的节点排在前面。
	// 调用 sort.Sort 执行排序。
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	for _, path := range paths {
		callback(path, set.Nodes[path])
	}
}

// AddNode adds the provided node into set.
// AddNode 将提供的节点添加到集合中。
// 将非叶子节点（如分支或扩展节点）或标记为删除的节点添加到集合，并更新统计。
func (set *NodeSet) AddNode(path []byte, n *Node) {
	if n.IsDeleted() {
		set.deletes += 1
	} else {
		set.updates += 1
	}
	set.Nodes[string(path)] = n
}

// 在以太坊客户端（如 Geth）中，状态 Trie 的更新可能分布在多个线程或阶段（例如处理不同交易）。MergeSet 提供了将这些分散的变更集合合并为一个整体的能力。
// “不相交”假设可能源于并行处理的场景：每个线程负责 Trie 的不同子树，路径不会重叠
//
// Owner 表示 Trie 的标识（账户 Trie 为零，存储 Trie 为账户地址哈希）。检查 Owner 确保合并的集合属于同一 Trie，避免跨 Trie 混淆数据。
// 例如，合并两个存储 Trie 的 NodeSet 时，必须确保它们属于同一账户。

// MergeSet merges this 'set' with 'other'. It assumes that the sets are disjoint,
// and thus does not deduplicate data (count deletes, dedup leaves etc).
//
// MergeSet 将此 'set' 与 'other' 合并。它假设两个集合是不相交的，因此不会对数据进行去重（例如计数删除、去重叶子等）。
func (set *NodeSet) MergeSet(other *NodeSet) error {
	if set.Owner != other.Owner {
		return fmt.Errorf("nodesets belong to different owner are not mergeable %x-%x", set.Owner, other.Owner)
	}
	maps.Copy(set.Nodes, other.Nodes)

	set.deletes += other.deletes
	set.updates += other.updates

	// Since we assume the sets are disjoint, we can safely append leaves
	// like this without deduplication.
	// 由于我们假设两个集合是不相交的，因此可以安全地像这样追加叶子节点，而无需去重。
	set.Leaves = append(set.Leaves, other.Leaves...)
	return nil
}

// 在以太坊状态 Trie 中，节点更新可能来自多个来源（如交易执行或同步）。
// Merge 提供了一种灵活的方式，将外部节点集合融入当前 NodeSet，支持路径覆盖。
// 覆盖逻辑反映了 Trie 的状态演变：新节点替换旧节点，保持最新状态。

// Merge adds a set of nodes into the set.
// Merge 将一组节点添加到集合中。
func (set *NodeSet) Merge(owner common.Hash, nodes map[string]*Node) error {
	if set.Owner != owner {
		return fmt.Errorf("nodesets belong to different owner are not mergeable %x-%x", set.Owner, owner)
	}
	for path, node := range nodes {
		prev, ok := set.Nodes[path]
		if ok { // 根据原有节点状态撤销计数
			// overwrite happens, revoke the counter
			// 发生覆盖，撤销计数器
			if prev.IsDeleted() {
				set.deletes -= 1
			} else {
				set.updates -= 1
			}
		}
		// 根据新节点状态更新计数
		if node.IsDeleted() {
			set.deletes += 1
		} else {
			set.updates += 1
		}
		set.Nodes[path] = node
	}
	return nil
}

// AddLeaf adds the provided leaf node into set. TODO(rjl493456442) how can
// we get rid of it?
// AddLeaf 将提供的叶子节点添加到集合中。TODO(rjl493456442) 如何消除它？
//
// 添加叶子节点到集合，记录其原始数据和父节点关系。
func (set *NodeSet) AddLeaf(parent common.Hash, blob []byte) {
	set.Leaves = append(set.Leaves, &leaf{Blob: blob, Parent: parent})
}

// Size returns the number of dirty nodes in set.
// Size 返回集合中脏节点的数量。
// 提供“脏节点”（变更节点）的统计信息，用于性能分析或提交优化。
func (set *NodeSet) Size() (int, int) {
	return set.updates, set.deletes
}

// HashSet returns a set of trie nodes keyed by node hash.
// HashSet 返回以节点哈希为键的 trie 节点集合。
// 将节点集合转换为以哈希为键的格式，便于基于哈希查询或持久化。
func (set *NodeSet) HashSet() map[common.Hash][]byte {
	ret := make(map[common.Hash][]byte, len(set.Nodes))
	for _, n := range set.Nodes {
		ret[n.Hash] = n.Blob
	}
	return ret
}

// Summary returns a string-representation of the NodeSet.
// Summary 返回 NodeSet 的字符串表示形式。
// 用于生成一个字符串形式的概要，展示节点集合的状态。
func (set *NodeSet) Summary() string {
	var out = new(strings.Builder)
	fmt.Fprintf(out, "nodeset owner: %v\n", set.Owner)
	for path, n := range set.Nodes {
		// Deletion
		// 删除
		if n.IsDeleted() {
			fmt.Fprintf(out, "  [-]: %x\n", path)
			continue
		}
		// Insertion or update
		// 插入或更新
		fmt.Fprintf(out, "  [+/*]: %x -> %v \n", path, n.Hash)
	}
	for _, n := range set.Leaves {
		fmt.Fprintf(out, "[leaf]: %v\n", n)
	}
	return out.String()
}

// 以太坊状态包括账户 Trie（全局状态）和每个账户的存储 Trie。

// MergedNodeSet represents a merged node set for a group of tries.
// MergedNodeSet 表示一组 trie 的合并节点集合。
type MergedNodeSet struct {
	Sets map[common.Hash]*NodeSet // 以 Owner（Trie 标识）为键，映射到对应的 NodeSet。表示多个 Trie（如账户 Trie 和多个存储 Trie）的合并节点集合。
}

// NewMergedNodeSet initializes an empty merged set.
// NewMergedNodeSet 初始化一个空的合并集合。
func NewMergedNodeSet() *MergedNodeSet {
	return &MergedNodeSet{Sets: make(map[common.Hash]*NodeSet)}
}

// NewWithNodeSet constructs a merged nodeset with the provided single set.
// NewWithNodeSet 使用提供的单个集合构造一个合并节点集合。
func NewWithNodeSet(set *NodeSet) *MergedNodeSet {
	merged := NewMergedNodeSet()
	merged.Merge(set)
	return merged
}

// Merge merges the provided dirty nodes of a trie into the set. The assumption
// is held that no duplicated set belonging to the same trie will be merged twice.
// Merge 将提供的 trie 的脏节点合并到集合中。假设不会重复合并属于同一 trie 的重复集合。
func (set *MergedNodeSet) Merge(other *NodeSet) error {
	// 检查 set.Sets 是否已有 other.Owner 对应的子集
	subset, present := set.Sets[other.Owner]
	if present {
		// 如果存在（present 为真），调用子集的 Merge 方法，合并 other.Nodes。
		return subset.Merge(other.Owner, other.Nodes)
	}
	set.Sets[other.Owner] = other
	return nil
}

// Flatten returns a two-dimensional map for internal nodes.
// Flatten 返回内部节点的二维映射。
// 将合并集合展平为二维结构，便于按 Trie 访问节点。
func (set *MergedNodeSet) Flatten() map[common.Hash]map[string]*Node {
	nodes := make(map[common.Hash]map[string]*Node, len(set.Sets))
	for owner, set := range set.Sets {
		nodes[owner] = set.Nodes
	}
	return nodes
}
