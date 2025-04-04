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
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	errMissJournal = errors.New("journal not found")
	// errMissJournal 表示找不到日志文件。
	errMissVersion = errors.New("version not found")
	// errMissVersion 表示在日志文件中找不到版本信息。
	errUnexpectedVersion = errors.New("unexpected journal version")
	// errUnexpectedVersion 表示日志文件的版本与预期版本不符。
	errMissDiskRoot = errors.New("disk layer root not found")
	// errMissDiskRoot 表示在日志文件中找不到磁盘层的根哈希。
	errUnmatchedJournal = errors.New("unmatched journal")
	// errUnmatchedJournal 表示日志文件与当前的持久化状态不匹配。
)

// journalVersion ensures that an incompatible journal is detected and discarded.
// journalVersion 确保检测到不兼容的日志并将其丢弃。
//
// Changelog:
//
// - Version 0: initial version
// - Version 1: storage.Incomplete field is removed
// - Version 2: add post-modification state values
//
// - Version 0: 初始版本。
// - Version 1: 移除了 storage.Incomplete 字段。
// - Version 2: 添加了修改后的状态值。
const journalVersion uint64 = 2

// loadJournal tries to parse the layer journal from the disk.
// loadJournal 尝试从磁盘解析层日志。
func (db *Database) loadJournal(diskRoot common.Hash) (layer, error) {
	// 从磁盘数据库读取 trie 日志。
	journal := rawdb.ReadTrieJournal(db.diskdb)
	// 如果日志为空，则返回错误。
	if len(journal) == 0 {
		return nil, errMissJournal
	}
	// 创建一个 RLP 流来解码日志数据。
	r := rlp.NewStream(bytes.NewReader(journal), 0)

	// Firstly, resolve the first element as the journal version
	// 首先，解析第一个元素作为日志版本。
	version, err := r.Uint64()
	if err != nil {
		return nil, errMissVersion
	}
	// 如果日志版本与预期版本不符，则返回错误。
	if version != journalVersion {
		return nil, fmt.Errorf("%w want %d got %d", errUnexpectedVersion, journalVersion, version)
	}
	// Secondly, resolve the disk layer root, ensure it's continuous
	// with disk layer. Note now we can ensure it's the layer journal
	// correct version, so we expect everything can be resolved properly.
	// 其次，解析磁盘层的根哈希，确保它与磁盘层是连续的。
	// 注意，现在我们可以确保它是正确版本的层日志，所以我们期望一切都可以正确解析。
	var root common.Hash
	if err := r.Decode(&root); err != nil {
		return nil, errMissDiskRoot
	}
	// The journal is not matched with persistent state, discard them.
	// It can happen that geth crashes without persisting the journal.
	// 日志与持久化状态不匹配，丢弃它们。
	// 这种情况可能发生在 geth 在持久化日志之前崩溃时。
	if !bytes.Equal(root.Bytes(), diskRoot.Bytes()) {
		return nil, fmt.Errorf("%w want %x got %x", errUnmatchedJournal, root, diskRoot)
	}
	// Load the disk layer from the journal
	// 从日志加载磁盘层。
	base, err := db.loadDiskLayer(r)
	if err != nil {
		return nil, err
	}
	// Load all the diff layers from the journal
	// 从日志加载所有差异层。
	head, err := db.loadDiffLayer(base, r)
	if err != nil {
		return nil, err
	}
	log.Debug("Loaded layer journal", "diskroot", diskRoot, "diffhead", head.rootHash())
	return head, nil
}

// loadLayers loads a pre-existing state layer backed by a key-value store.
// loadLayers 加载由键值存储支持的预先存在的状态层。
func (db *Database) loadLayers() layer {
	// Retrieve the root node of persistent state.
	// 检索持久化状态的根节点。
	root, err := db.hasher(rawdb.ReadAccountTrieNode(db.diskdb, nil))
	if err != nil {
		log.Crit("Failed to compute node hash", "err", err)
	}
	// Load the layers by resolving the journal
	// 通过解析日志加载层。
	head, err := db.loadJournal(root)
	if err == nil {
		return head
	}
	// journal is not matched(or missing) with the persistent state, discard
	// it. Display log for discarding journal, but try to avoid showing
	// useless information when the db is created from scratch.
	// 日志与持久化状态不匹配（或丢失），丢弃它。
	// 显示丢弃日志的日志，但在从头创建数据库时尽量避免显示无用的信息。
	if !(root == types.EmptyRootHash && errors.Is(err, errMissJournal)) {
		log.Info("Failed to load journal, discard it", "err", err)
	}
	// Return single layer with persistent state.
	// 返回带有持久化状态的单层。
	return newDiskLayer(root, rawdb.ReadPersistentStateID(db.diskdb), db, nil, newBuffer(db.config.WriteBufferSize, nil, nil, 0))
}

// loadDiskLayer reads the binary blob from the layer journal, reconstructing
// a new disk layer on it.
// loadDiskLayer 从层日志中读取二进制 blob，并在其上重建一个新的磁盘层。
func (db *Database) loadDiskLayer(r *rlp.Stream) (layer, error) {
	// Resolve disk layer root
	// 解析磁盘层根哈希。
	var root common.Hash
	if err := r.Decode(&root); err != nil {
		return nil, fmt.Errorf("load disk root: %v", err)
	}
	// Resolve the state id of disk layer, it can be different
	// with the persistent id tracked in disk, the id distance
	// is the number of transitions aggregated in disk layer.
	// 解析磁盘层的状态 ID，它可能与磁盘中跟踪的持久 ID 不同，
	// ID 之间的距离是聚合在磁盘层中的转换次数。
	var id uint64
	if err := r.Decode(&id); err != nil {
		return nil, fmt.Errorf("load state id: %v", err)
	}
	stored := rawdb.ReadPersistentStateID(db.diskdb)
	if stored > id {
		return nil, fmt.Errorf("invalid state id: stored %d resolved %d", stored, id)
	}
	// Resolve nodes cached in aggregated buffer
	// 解析聚合缓冲区中缓存的节点。
	var nodes nodeSet
	if err := nodes.decode(r); err != nil {
		return nil, err
	}
	// Resolve flat state sets in aggregated buffer
	// 解析聚合缓冲区中的扁平状态集。
	var states stateSet
	if err := states.decode(r); err != nil {
		return nil, err
	}
	return newDiskLayer(root, id, db, nil, newBuffer(db.config.WriteBufferSize, &nodes, &states, id-stored)), nil
}

// loadDiffLayer reads the next sections of a layer journal, reconstructing a new
// diff and verifying that it can be linked to the requested parent.
// loadDiffLayer 读取层日志的后续部分，重建一个新的差异层并验证它是否可以链接到请求的父层。
func (db *Database) loadDiffLayer(parent layer, r *rlp.Stream) (layer, error) {
	// Read the next diff journal entry
	// 读取下一个差异日志条目。
	var root common.Hash
	if err := r.Decode(&root); err != nil {
		// The first read may fail with EOF, marking the end of the journal
		// 第一次读取可能会因 EOF 失败，表示日志结束。
		if err == io.EOF {
			return parent, nil
		}
		return nil, fmt.Errorf("load diff root: %v", err)
	}
	var block uint64
	if err := r.Decode(&block); err != nil {
		return nil, fmt.Errorf("load block number: %v", err)
	}
	// Read in-memory trie nodes from journal
	// 从日志读取内存中的 trie 节点。
	var nodes nodeSet
	if err := nodes.decode(r); err != nil {
		return nil, err
	}
	// Read flat states set (with original value attached) from journal
	// 从日志读取扁平状态集（带有原始值）。
	var stateSet StateSetWithOrigin
	if err := stateSet.decode(r); err != nil {
		return nil, err
	}
	return db.loadDiffLayer(newDiffLayer(parent, root, parent.stateID()+1, block, &nodes, &stateSet), r)
}

// journal implements the layer interface, marshaling the un-flushed trie nodes
// along with layer meta data into provided byte buffer.
// journal 实现了 layer 接口，将未刷新的 trie 节点以及层元数据编组到提供的字节缓冲区中。
func (dl *diskLayer) journal(w io.Writer) error {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// Ensure the layer didn't get stale
	// 确保层没有变得陈旧。
	if dl.stale {
		return errSnapshotStale
	}
	// Step one, write the disk root into the journal.
	// 第一步，将磁盘根哈希写入日志。
	if err := rlp.Encode(w, dl.root); err != nil {
		return err
	}
	// Step two, write the corresponding state id into the journal
	// 第二步，将对应的状态 ID 写入日志。
	if err := rlp.Encode(w, dl.id); err != nil {
		return err
	}
	// Step three, write the accumulated trie nodes into the journal
	// 第三步，将累积的 trie 节点写入日志。
	if err := dl.buffer.nodes.encode(w); err != nil {
		return err
	}
	// Step four, write the accumulated flat states into the journal
	// 第四步，将累积的扁平状态写入日志。
	if err := dl.buffer.states.encode(w); err != nil {
		return err
	}
	log.Debug("Journaled pathdb disk layer", "root", dl.root)
	return nil
}

// journal implements the layer interface, writing the memory layer contents
// into a buffer to be stored in the database as the layer journal.
// journal 实现了 layer 接口，将内存层的内容写入缓冲区以存储在数据库中作为层日志。
func (dl *diffLayer) journal(w io.Writer) error {
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	// journal the parent first
	// 首先记录父层的日志。
	if err := dl.parent.journal(w); err != nil {
		return err
	}
	// Everything below was journaled, persist this layer too
	// 下面的所有内容都已记录，也持久化这一层。
	if err := rlp.Encode(w, dl.root); err != nil {
		return err
	}
	if err := rlp.Encode(w, dl.block); err != nil {
		return err
	}
	// Write the accumulated trie nodes into buffer
	// 将累积的 trie 节点写入缓冲区。
	if err := dl.nodes.encode(w); err != nil {
		return err
	}
	// Write the associated flat state set into buffer
	// 将关联的扁平状态集写入缓冲区。
	if err := dl.states.encode(w); err != nil {
		return err
	}
	log.Debug("Journaled pathdb diff layer", "root", dl.root, "parent", dl.parent.rootHash(), "id", dl.stateID(), "block", dl.block)
	return nil
}

// Journal commits an entire diff hierarchy to disk into a single journal entry.
// This is meant to be used during shutdown to persist the layer without
// flattening everything down (bad for reorgs). And this function will mark the
// database as read-only to prevent all following mutation to disk.
// Journal 将整个差异层级结构作为一个单独的日志条目提交到磁盘。
// 这旨在在关闭期间用于持久化层，而无需将所有内容展平（对重组不利）。
// 此函数会将数据库标记为只读，以防止所有后续的磁盘修改。
//
// The supplied root must be a valid trie hash value.
// 提供的根哈希必须是有效的 trie 哈希值。
func (db *Database) Journal(root common.Hash) error {
	// Retrieve the head layer to journal from.
	// 检索要记录日志的头层。
	l := db.tree.get(root)
	if l == nil {
		return fmt.Errorf("triedb layer [%#x] missing", root)
	}
	disk := db.tree.bottom()
	if l, ok := l.(*diffLayer); ok {
		log.Info("Persisting dirty state to disk", "head", l.block, "root", root, "layers", l.id-disk.id+disk.buffer.layers)
	} else { // disk layer only on noop runs (likely) or deep reorgs (unlikely)
		log.Info("Persisting dirty state to disk", "root", root, "layers", disk.buffer.layers)
	}
	start := time.Now()

	// Run the journaling
	// 运行日志记录。
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the database is in read only mode.
	// 如果数据库处于只读模式，则短路返回。
	if db.readOnly {
		return errDatabaseReadOnly
	}
	// Firstly write out the metadata of journal
	// 首先写入日志的元数据。
	journal := new(bytes.Buffer)
	if err := rlp.Encode(journal, journalVersion); err != nil {
		return err
	}
	// Secondly write out the state root in disk, ensure all layers
	// on top are continuous with disk.
	// 其次写入磁盘中的状态根哈希，确保其上的所有层都与磁盘连续。
	diskRoot, err := db.hasher(rawdb.ReadAccountTrieNode(db.diskdb, nil))
	if err != nil {
		return err
	}
	if err := rlp.Encode(journal, diskRoot); err != nil {
		return err
	}
	// Finally write out the journal of each layer in reverse order.
	// 最后按相反的顺序写出每一层的日志。
	if err := l.journal(journal); err != nil {
		return err
	}
	// Store the journal into the database and return
	// 将日志存储到数据库并返回。
	rawdb.WriteTrieJournal(db.diskdb, journal.Bytes())

	// Set the db in read only mode to reject all following mutations
	// 将数据库设置为只读模式，以拒绝所有后续的修改。
	db.readOnly = true
	log.Info("Persisted dirty state to disk", "size", common.StorageSize(journal.Len()), "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}
