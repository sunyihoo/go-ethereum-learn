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
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// buffer is a collection of modified states along with the modified trie nodes.
// They are cached here to aggregate the disk write. The content of the buffer
// must be checked before diving into disk (since it basically is not yet written
// data).
// buffer 是一个包含修改状态和修改 trie 节点的集合。
// 它们在这里被缓存以聚合磁盘写入。在深入磁盘之前必须检查缓冲区内容（因为这些基本上是尚未写入的数据）。
type buffer struct {
	layers uint64    // The number of diff layers aggregated inside  内部聚合的差异层数量
	limit  uint64    // The maximum memory allowance in bytes  最大内存允许量（字节
	nodes  *nodeSet  // Aggregated trie node set   聚合的 trie 节点集合
	states *stateSet // Aggregated state set  聚合的状态集合
}

// newBuffer initializes the buffer with the provided states and trie nodes.
// newBuffer 使用提供的状态和 trie 节点初始化缓冲区。
func newBuffer(limit int, nodes *nodeSet, states *stateSet, layers uint64) *buffer {
	// Don't panic for lazy users if any provided set is nil
	// 如果提供的任何集合为 nil，不要为懒惰用户引发 panic
	if nodes == nil {
		nodes = newNodeSet(nil)
	}
	if states == nil {
		states = newStates(nil, nil)
	}
	return &buffer{
		layers: layers,
		limit:  uint64(limit),
		nodes:  nodes,
		states: states,
	}
}

// account retrieves the account blob with account address hash.
// account 使用账户地址哈希检索账户 blob。
func (b *buffer) account(hash common.Hash) ([]byte, bool) {
	return b.states.account(hash)
}

// storage retrieves the storage slot with account address hash and slot key.
// storage 使用账户地址哈希和槽键检索存储槽。
func (b *buffer) storage(addrHash common.Hash, storageHash common.Hash) ([]byte, bool) {
	return b.states.storage(addrHash, storageHash)
}

// node retrieves the trie node with node path and its trie identifier.
// node 使用节点路径及其 trie 标识符检索 trie 节点。
func (b *buffer) node(owner common.Hash, path []byte) (*trienode.Node, bool) {
	return b.nodes.node(owner, path)
}

// commit merges the provided states and trie nodes into the buffer.
// commit 将提供的状态和 trie 节点合并到缓冲区中。
func (b *buffer) commit(nodes *nodeSet, states *stateSet) *buffer {
	b.layers++
	b.nodes.merge(nodes)
	b.states.merge(states)
	return b
}

// revertTo is the reverse operation of commit. It also merges the provided states
// and trie nodes into the buffer. The key difference is that the provided state
// set should reverse the changes made by the most recent state transition.
// revertTo 是 commit 的逆操作。它也将提供的状态和 trie 节点合并到缓冲区中。
// 关键区别在于提供的状态集应逆转最近状态转换所做的更改。
func (b *buffer) revertTo(db ethdb.KeyValueReader, nodes map[common.Hash]map[string]*trienode.Node, accounts map[common.Hash][]byte, storages map[common.Hash]map[common.Hash][]byte) error {
	// Short circuit if no embedded state transition to revert
	// 如果没有要回滚的嵌入状态转换，直接返回
	if b.layers == 0 {
		return errStateUnrecoverable
	}
	b.layers--

	// Reset the entire buffer if only a single transition left
	// 如果只剩下一个转换，重置整个缓冲区
	if b.layers == 0 {
		b.reset()
		return nil
	}
	b.nodes.revertTo(db, nodes)
	b.states.revertTo(accounts, storages)
	return nil
}

// reset cleans up the disk cache.
// reset 清理磁盘缓存。
func (b *buffer) reset() {
	b.layers = 0
	b.nodes.reset()
	b.states.reset()
}

// empty returns an indicator if buffer is empty.
// empty 返回缓冲区是否为空的指示器。
func (b *buffer) empty() bool {
	return b.layers == 0
}

// full returns an indicator if the size of accumulated content exceeds the
// configured threshold.
// full 返回累积内容大小是否超过配置阈值的指示器。
func (b *buffer) full() bool {
	return b.size() > b.limit
}

// size returns the approximate memory size of the held content.
// size 返回持有内容的近似内存大小。
func (b *buffer) size() uint64 {
	return b.states.size + b.nodes.size
}

// flush persists the in-memory dirty trie node into the disk if the configured
// memory threshold is reached. Note, all data must be written atomically.
// flush 如果达到配置的内存阈值，将内存中的脏 trie 节点持久化到磁盘。
// 注意，所有数据必须原子性地写入。
func (b *buffer) flush(db ethdb.KeyValueStore, freezer ethdb.AncientWriter, nodesCache *fastcache.Cache, id uint64) error {
	// Ensure the target state id is aligned with the internal counter.
	// 确保目标状态 ID 与内部计数器对齐。
	head := rawdb.ReadPersistentStateID(db)
	if head+b.layers != id {
		return fmt.Errorf("buffer layers (%d) cannot be applied on top of persisted state id (%d) to reach requested state id (%d)", b.layers, head, id)
	}
	// Terminate the state snapshot generation if it's active
	// 如果状态快照生成处于活动状态，则终止它
	var (
		start = time.Now()
		batch = db.NewBatchWithSize(b.nodes.dbsize() * 11 / 10) // extra 10% for potential pebble internal stuff 使用节点数据库大小的 11/10 初始化批次（额外 10% 用于可能的 Pebble 内部处理）
	)
	// Explicitly sync the state freezer, ensuring that all written
	// data is transferred to disk before updating the key-value store.
	// 显式同步状态 freezer，确保在更新键值存储之前所有写入数据都传输到磁盘。
	if freezer != nil {
		if err := freezer.Sync(); err != nil {
			return err
		}
	}
	nodes := b.nodes.write(batch, nodesCache)
	rawdb.WritePersistentStateID(batch, id)

	// Flush all mutations in a single batch
	// 将所有变更刷新到单个批次中
	size := batch.ValueSize()
	if err := batch.Write(); err != nil {
		return err
	}
	commitBytesMeter.Mark(int64(size))
	commitNodesMeter.Mark(int64(nodes))
	commitTimeTimer.UpdateSince(start)
	b.reset()
	log.Debug("Persisted buffer content", "nodes", nodes, "bytes", common.StorageSize(size), "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}
