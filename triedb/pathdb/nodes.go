// Copyright 2024 The go-ethereum Authors
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
	"bytes"
	"fmt"
	"io"
	"maps"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// Merkle-Patricia Trie: nodeSet 直接与以太坊中用于存储状态的 Merkle-Patricia Trie 相关。每次状态发生变化时，都会产生一组修改过的 trie 节点，这些节点被存储在 nodeSet 中。
// 状态转换 (State Transition): 当一个区块被处理时，执行该区块中的交易会导致以太坊状态发生变化。nodeSet 用于捕获这些变化，以便更新状态 trie。
// 数据库批处理 (Database Batching): 为了提高性能，go-ethereum 通常会将多个小的数据库写入操作合并成一个大的批处理写入。nodeSet 允许将一个区块或多个区块的状态变化相关的 trie 节点集中起来，然后一次性写入数据库。
// 状态日志 (State Journaling): encode 和 decode 方法使得 nodeSet 可以被序列化和反序列化，这是状态日志机制的关键部分。状态日志用于在节点崩溃后恢复状态或在区块链重组时回滚状态。
// 状态回滚 (State Reversion): revertTo 方法支持状态的回滚操作，这在处理区块链重组时非常重要。当一个区块被从链中移除时，其对应的状态变化也需要被撤销。
// 缓存管理 (Cache Management): size 字段和相关的更新方法有助于 go-ethereum 管理其状态缓存的大小，避免过度使用内存。

// nodeSet represents a collection of modified trie nodes resulting from a state
// transition, typically corresponding to a block execution. It can also represent
// the combined trie node set from several aggregated state transitions.
// nodeSet 表示由状态转换产生的一组修改过的 trie 节点，通常对应于一个区块的执行。
// 它也可以表示来自多个聚合状态转换的组合 trie 节点集。
type nodeSet struct {
	size uint64 // aggregated size of the trie node
	// trie 节点的聚合大小。
	nodes map[common.Hash]map[string]*trienode.Node // node set, mapped by owner and path
	// 节点集合，按所有者（账户哈希或空哈希表示主 trie）和路径映射。
}

// newNodeSet constructs the set with the provided dirty trie nodes.
// newNodeSet 使用提供的脏 trie 节点构造集合。
func newNodeSet(nodes map[common.Hash]map[string]*trienode.Node) *nodeSet {
	// Don't panic for the lazy callers, initialize the nil map instead
	// 为了方便调用者，如果传入 nil，则初始化一个空的 map。
	if nodes == nil {
		nodes = make(map[common.Hash]map[string]*trienode.Node)
	}
	s := &nodeSet{nodes: nodes}
	s.computeSize()
	return s
}

// computeSize calculates the database size of the held trie nodes.
// computeSize 计算持有的 trie 节点的数据库大小。
func (s *nodeSet) computeSize() {
	var size uint64
	for owner, subset := range s.nodes {
		var prefix int
		if owner != (common.Hash{}) {
			prefix = common.HashLength // owner (32 bytes) for storage trie nodes
			// 对于存储 trie 节点，前缀是所有者哈希的长度（32 字节）。
		}
		for path, n := range subset {
			size += uint64(prefix + len(n.Blob) + len(path))
			// 累加大小：前缀（如果存在）+ 节点数据的长度 + 路径的长度。
		}
	}
	s.size = size
}

// updateSize updates the total cache size by the given delta.
// updateSize 按给定的增量更新总缓存大小。
func (s *nodeSet) updateSize(delta int64) {
	size := int64(s.size) + delta
	if size >= 0 {
		s.size = uint64(size)
		return
	}
	log.Error("Nodeset size underflow", "prev", common.StorageSize(s.size), "delta", common.StorageSize(delta))
	s.size = 0
}

// node retrieves the trie node with node path and its trie identifier.
// node 检索具有节点路径及其 trie 标识符的 trie 节点。
func (s *nodeSet) node(owner common.Hash, path []byte) (*trienode.Node, bool) {
	subset, ok := s.nodes[owner]
	if !ok {
		return nil, false
	}
	n, ok := subset[string(path)]
	if !ok {
		return nil, false
	}
	return n, true
}

// merge integrates the provided dirty nodes into the set. The provided nodeset
// will remain unchanged, as it may still be referenced by other layers.
// merge 将提供的脏节点集成到集合中。提供的节点集将保持不变，因为它可能仍被其他层引用。
func (s *nodeSet) merge(set *nodeSet) {
	var (
		delta int64 // size difference resulting from node merging
		// 由于节点合并导致的大小差异。
		overwrite counter // counter of nodes being overwritten
		// 被覆盖的节点计数器。
	)
	for owner, subset := range set.nodes {
		var prefix int
		if owner != (common.Hash{}) {
			prefix = common.HashLength
		}
		current, exist := s.nodes[owner]
		if !exist {
			for path, n := range subset {
				delta += int64(prefix + len(n.Blob) + len(path))
			}
			// Perform a shallow copy of the map for the subset instead of claiming it
			// directly from the provided nodeset to avoid potential concurrent map
			// read/write issues. The nodes belonging to the original diff layer remain
			// accessible even after merging. Therefore, ownership of the nodes map
			// should still belong to the original layer, and any modifications to it
			// should be prevented.
			// 对子集执行 map 的浅拷贝，而不是直接从提供的节点集中获取，以避免潜在的并发 map 读/写问题。
			// 属于原始差异层的节点在合并后仍然可以访问。因此，节点 map 的所有权仍然应该属于原始层，
			// 并且应该防止对其进行任何修改。
			s.nodes[owner] = maps.Clone(subset)
			continue
		}
		for path, n := range subset {
			if orig, exist := current[path]; !exist {
				delta += int64(prefix + len(n.Blob) + len(path))
			} else {
				delta += int64(len(n.Blob) - len(orig.Blob))
				overwrite.add(prefix + len(orig.Blob) + len(path))
			}
			current[path] = n
		}
		s.nodes[owner] = current
	}
	overwrite.report(gcTrieNodeMeter, gcTrieNodeBytesMeter)
	s.updateSize(delta)
}

// revertTo merges the provided trie nodes into the set. This should reverse the
// changes made by the most recent state transition.
// revertTo 将提供的 trie 节点合并到集合中。这应该撤销最近一次状态转换所做的更改。
func (s *nodeSet) revertTo(db ethdb.KeyValueReader, nodes map[common.Hash]map[string]*trienode.Node) {
	var delta int64
	for owner, subset := range nodes {
		current, ok := s.nodes[owner]
		if !ok {
			panic(fmt.Sprintf("non-existent subset (%x)", owner))
		}
		for path, n := range subset {
			orig, ok := current[path]
			if !ok {
				// There is a special case in merkle tree that one child is removed
				// from a fullNode which only has two children, and then a new child
				// with different position is immediately inserted into the fullNode.
				// In this case, the clean child of the fullNode will also be marked
				// as dirty because of node collapse and expansion. In case of database
				// rollback, don't panic if this "clean" node occurs which is not
				// present in buffer.
				// 在 Merkle 树中存在一种特殊情况：从一个只有两个子节点的 fullNode 中移除一个子节点，
				// 然后立即将一个具有不同位置的新子节点插入到该 fullNode 中。
				// 在这种情况下，由于节点折叠和展开，fullNode 的干净子节点也会被标记为脏。
				// 在数据库回滚的情况下，如果出现缓冲区中不存在的这个“干净”节点，不要 panic。
				var blob []byte
				if owner == (common.Hash{}) {
					blob = rawdb.ReadAccountTrieNode(db, []byte(path))
				} else {
					blob = rawdb.ReadStorageTrieNode(db, owner, []byte(path))
				}
				// Ignore the clean node in the case described above.
				// 在上述情况下忽略干净节点。
				if bytes.Equal(blob, n.Blob) {
					continue
				}
				panic(fmt.Sprintf("non-existent node (%x %v) blob: %v", owner, path, crypto.Keccak256Hash(n.Blob).Hex()))
			}
			current[path] = n
			delta += int64(len(n.Blob)) - int64(len(orig.Blob))
		}
	}
	s.updateSize(delta)
}

// journalNode represents a trie node persisted in the journal.
// journalNode 表示持久化在日志中的一个 trie 节点。
type journalNode struct {
	Path []byte // Path of the node in the trie
	// 节点在 trie 中的路径。
	Blob []byte // RLP-encoded trie node blob, nil means the node is deleted
	// RLP 编码的 trie 节点数据，nil 表示节点被删除。
}

// journalNodes represents a list trie nodes belong to a single account
// or the main account trie.
// journalNodes 表示属于单个账户或主账户 trie 的 trie 节点列表。
type journalNodes struct {
	Owner common.Hash
	// 拥有此节点的账户哈希（对于存储 trie）或空哈希（对于主账户 trie）。
	Nodes []journalNode
	// 属于此所有者的 trie 节点列表。
}

// encode serializes the content of trie nodes into the provided writer.
// encode 将 trie 节点的内容序列化到提供的 writer 中。
func (s *nodeSet) encode(w io.Writer) error {
	nodes := make([]journalNodes, 0, len(s.nodes))
	for owner, subset := range s.nodes {
		entry := journalNodes{Owner: owner}
		for path, node := range subset {
			entry.Nodes = append(entry.Nodes, journalNode{
				Path: []byte(path),
				Blob: node.Blob,
			})
		}
		nodes = append(nodes, entry)
	}
	return rlp.Encode(w, nodes)
}

// decode deserializes the content from the rlp stream into the nodeset.
// decode 从 rlp 流中反序列化内容到 nodeset 中。
func (s *nodeSet) decode(r *rlp.Stream) error {
	var encoded []journalNodes
	if err := r.Decode(&encoded); err != nil {
		return fmt.Errorf("load nodes: %v", err)
	}
	nodes := make(map[common.Hash]map[string]*trienode.Node)
	for _, entry := range encoded {
		subset := make(map[string]*trienode.Node)
		for _, n := range entry.Nodes {
			if len(n.Blob) > 0 {
				subset[string(n.Path)] = trienode.New(crypto.Keccak256Hash(n.Blob), n.Blob)
			} else {
				subset[string(n.Path)] = trienode.NewDeleted()
			}
		}
		nodes[entry.Owner] = subset
	}
	s.nodes = nodes
	s.computeSize()
	return nil
}

// write flushes nodes into the provided database batch as a whole.
// write 将节点作为一个整体刷新到提供的数据库批处理中。
func (s *nodeSet) write(batch ethdb.Batch, clean *fastcache.Cache) int {
	return writeNodes(batch, s.nodes, clean)
}

// reset clears all cached trie node data.
// reset 清除所有缓存的 trie 节点数据。
func (s *nodeSet) reset() {
	s.nodes = make(map[common.Hash]map[string]*trienode.Node)
	s.size = 0
}

// dbsize returns the approximate size of db write.
// dbsize 返回数据库写入的近似大小。
func (s *nodeSet) dbsize() int {
	var m int
	for owner, nodes := range s.nodes {
		if owner == (common.Hash{}) {
			m += len(nodes) * len(rawdb.TrieNodeAccountPrefix) // database key prefix
			// 对于主账户 trie，数据库键前缀的长度。
		} else {
			m += len(nodes) * (len(rawdb.TrieNodeStoragePrefix)) // database key prefix
			// 对于存储 trie，数据库键前缀的长度。
		}
	}
	return m + int(s.size)
}
