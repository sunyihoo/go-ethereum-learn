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

package trie

import (
	"maps"

	"github.com/ethereum/go-ethereum/common"
)

// MPT 是以太坊的状态存储结构，包含叶子节点（leafNode）和中间节点（shortNode、fullNode）。tracer 跟踪这些节点的变化，但不跟踪 valueNode（仅存储值的节点）。
// trie.Hasher 计算 MPT 的哈希，trie.Committer 将变化提交到数据库。但删除的节点可能未被标记，导致磁盘中保留冗余数据。tracer 弥补这一不足。
// 叶子节点与中间节点：
// 叶子节点存储实际数据（如账户状态），由调用者直接操作；中间节点维护 trie 结构，自动调整。tracer 统一跟踪两类节点。

// tracer tracks the changes of trie nodes. During the trie operations,
// some nodes can be deleted from the trie, while these deleted nodes
// won't be captured by trie.Hasher or trie.Committer. Thus, these deleted
// nodes won't be removed from the disk at all. Tracer is an auxiliary tool
// used to track all insert and delete operations of trie and capture all
// deleted nodes eventually.
//
// The changed nodes can be mainly divided into two categories: the leaf
// node and intermediate node. The former is inserted/deleted by callers
// while the latter is inserted/deleted in order to follow the rule of trie.
// This tool can track all of them no matter the node is embedded in its
// parent or not, but valueNode is never tracked.
//
// Besides, it's also used for recording the original value of the nodes
// when they are resolved from the disk. The pre-value of the nodes will
// be used to construct trie history in the future.
//
// Note tracer is not thread-safe, callers should be responsible for handling
// the concurrency issues by themselves.
//
// tracer 跟踪 trie 节点的变化。在 trie 操作期间，一些节点可能从 trie 中删除，
// 而这些被删除的节点不会被 trie.Hasher 或 trie.Committer 捕获。
// 因此，这些被删除的节点根本不会从磁盘中移除。Tracer 是一个辅助工具，
// 用于跟踪 trie 的所有插入和删除操作，并最终捕获所有被删除的节点。
//
// 变化的节点主要分为两类：叶子节点和中间节点。
// 前者由调用者插入/删除，后者为了遵循 trie 的规则而插入/删除。
// 此工具可以跟踪所有这些节点，无论节点是否嵌入其父节点，但 valueNode 从不被跟踪。
//
// 此外，它还用于记录节点从磁盘解析时的原始值。节点的预值将用于将来构造 trie 历史。
//
// 注意 tracer 不是线程安全的，调用者应自行负责处理并发问题。
type tracer struct {
	inserts    map[string]struct{} // 记录插入的节点，键是节点标识（可能是哈希或路径的字符串形式），值为空结构体（仅标记存在性）。
	deletes    map[string]struct{} // 记录删除的节点，键是节点标识（可能是哈希或路径的字符串形式），值为空结构体（仅标记存在性）。
	accessList map[string][]byte   // 记录节点的原始值（从磁盘解析时），键是节点标识，值是节点的字节数据（RLP 编码）。accessList 记录原始值，为将来构建 trie 历史提供数据，与状态回溯或快照相关。
}

// newTracer initializes the tracer for capturing trie changes.
// newTracer 初始化 tracer 以捕获 trie 变化。
func newTracer() *tracer {
	return &tracer{
		inserts:    make(map[string]struct{}),
		deletes:    make(map[string]struct{}),
		accessList: make(map[string][]byte),
	}
}

// onRead tracks the newly loaded trie node and caches the rlp-encoded
// blob internally. Don't change the value outside of function since
// it's not deep-copied.
//
// onRead 跟踪新加载的 trie 节点，并在内部缓存 RLP 编码的 blob。不要在函数外部修改值，因为它未被深拷贝。
// 在状态树遍历或同步时，记录节点的初始状态。
// val 是节点的 RLP（Recursive Length Prefix）编码数据，记录从磁盘加载的原始值，用于后续历史重建。
func (t *tracer) onRead(path []byte, val []byte) {
	t.accessList[string(path)] = val
}

// onInsert tracks the newly inserted trie node. If it's already
// in the deletion set (resurrected node), then just wipe it from
// the deletion set as it's "untouched".
//
// onInsert 跟踪新插入的 trie 节点。如果它已在删除集中（复活节点），则将其从删除集中清除，因为它“未被触及”。
// 状态树更新涉及节点的删除和重新插入，onInsert 确保状态一致性，避免冗余记录。
// 跟踪账户或存储槽的插入操作。
func (t *tracer) onInsert(path []byte) {
	if _, present := t.deletes[string(path)]; present {
		delete(t.deletes, string(path))
		return
	}
	t.inserts[string(path)] = struct{}{}
}

// onDelete tracks the newly deleted trie node. If it's already
// in the addition set, then just wipe it from the addition set
// as it's untouched.
//
// onDelete 跟踪新删除的 trie 节点。如果它已在插入集中，则将其从插入集中清除，因为它“未被触及”。
// MPT 的删除操作可能未被 Committer 捕获，onDelete 确保所有删除节点被记录。
func (t *tracer) onDelete(path []byte) {
	if _, present := t.inserts[string(path)]; present {
		delete(t.inserts, string(path))
		return
	}
	t.deletes[string(path)] = struct{}{}
}

// reset clears the content tracked by tracer.
// reset 清除 tracer 跟踪的内容。
// 清除所有跟踪数据，恢复初始状态。
// 在新一轮状态更新前重置 tracer，避免数据累积。
func (t *tracer) reset() {
	t.inserts = make(map[string]struct{})
	t.deletes = make(map[string]struct{})
	t.accessList = make(map[string][]byte)
}

// copy returns a deep copied tracer instance.
// copy 返回一个深拷贝的 tracer 实例。
func (t *tracer) copy() *tracer {
	accessList := make(map[string][]byte, len(t.accessList))
	for path, blob := range t.accessList {
		accessList[path] = common.CopyBytes(blob)
	}
	return &tracer{
		inserts:    maps.Clone(t.inserts),
		deletes:    maps.Clone(t.deletes),
		accessList: accessList,
	}
}

// deletedNodes returns a list of node paths which are deleted from the trie.
// deletedNodes 返回从 trie 中删除的节点路径列表。
func (t *tracer) deletedNodes() []string {
	var paths []string
	for path := range t.deletes {
		// It's possible a few deleted nodes were embedded
		// in their parent before, the deletions can be no
		// effect by deleting nothing, filter them out.
		// 一些被删除的节点可能之前嵌入在父节点中，删除操作可能无效（未删除任何内容），过滤掉这些节点。
		_, ok := t.accessList[path]
		if !ok {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}
