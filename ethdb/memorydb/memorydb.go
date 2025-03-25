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

// Package memorydb implements the key-value database layer based on memory maps.
// Package memorydb 实现了基于内存映射的键值数据库层。
package memorydb

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

var (
	// errMemorydbClosed is returned if a memory database was already closed at the
	// invocation of a data access operation.
	//
	// errMemorydbClosed 如果在调用数据访问操作时内存数据库已经关闭，则返回此错误。
	errMemorydbClosed = errors.New("database closed")

	// errMemorydbNotFound is returned if a key is requested that is not found in
	// the provided memory database.
	//
	// errMemorydbNotFound 如果请求的键在提供的内存数据库中未找到，则返回此错误。
	errMemorydbNotFound = errors.New("not found")
)

// memorydb.Database 通常实现 ethdb.KeyValueStore 接口，用于模拟 LevelDB 的行为。
// 用于单元测试状态树操作、批量写入或迭代功能。

// Database is an ephemeral key-value store. Apart from basic data storage
// functionality it also supports batch writes and iterating over the keyspace in
// binary-alphabetical order.
//
// Database 是一个临时的键值存储。除了基本的数据存储功能外，
// 它还支持批量写入和按二进制字母顺序迭代键空间。
//
// 以太坊的状态树（state trie）依赖键值存储管理账户状态，memorydb 是测试中的轻量替代品。
// 键通常是哈希（如账户地址或状态根），值是 RLP 编码的数据。
type Database struct {
	db   map[string][]byte
	lock sync.RWMutex
}

// New returns a wrapped map with all the required database interface methods
// implemented.
// 返回一个封装的映射，实现了所有必需的数据库接口方法。
func New() *Database {
	return &Database{
		db: make(map[string][]byte),
	}
}

// NewWithCap returns a wrapped map pre-allocated to the provided capacity with
// all the required database interface methods implemented.
func NewWithCap(size int) *Database {
	return &Database{
		db: make(map[string][]byte, size),
	}
}

// Close deallocates the internal map and ensures any consecutive data access op
// fails with an error.
// 释放内部映射并确保任何后续的数据访问操作以错误失败。
func (db *Database) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	db.db = nil
	return nil
}

// Has retrieves if a key is present in the key-value store.
// 检索键值存储中是否包含某个键。
func (db *Database) Has(key []byte) (bool, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.db == nil {
		return false, errMemorydbClosed
	}
	_, ok := db.db[string(key)]
	return ok, nil
}

// Get retrieves the given key if it's present in the key-value store.
// 检索键值存储中是否存在给定的键。
func (db *Database) Get(key []byte) ([]byte, error) {
	db.lock.RLock()
	defer db.lock.RUnlock()

	if db.db == nil {
		return nil, errMemorydbClosed
	}
	if entry, ok := db.db[string(key)]; ok {
		return common.CopyBytes(entry), nil
	}
	return nil, errMemorydbNotFound
}

// Put inserts the given value into the key-value store.
// Put 将给定的值插入到键值存储中。
func (db *Database) Put(key []byte, value []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	if db.db == nil {
		return errMemorydbClosed
	}
	db.db[string(key)] = common.CopyBytes(value)
	return nil
}

// Delete removes the key from the key-value store.
// Delete 从键值存储中移除键。
func (db *Database) Delete(key []byte) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	if db.db == nil {
		return errMemorydbClosed
	}
	delete(db.db, string(key))
	return nil
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
// DeleteRange 删除范围 [start,end) 中的所有键（及值）
// （包含 start，不包含 end）。
func (db *Database) DeleteRange(start, end []byte) error {
	it := db.NewIterator(nil, start)
	defer it.Release()

	for it.Next() && bytes.Compare(end, it.Key()) > 0 {
		if err := db.Delete(it.Key()); err != nil {
			return err
		}
	}
	return nil
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
// NewBatch 创建一个只写的键值存储，将更改缓冲到其宿主数据库，直到调用最终写入。
//
// 实现了 ethdb.Batcher 接口，用于创建批量写入对象。
// 支持将多个写操作（如 Put 和 Delete）缓冲在内存中，直到调用 Write 方法提交到宿主数据库。
// 在以太坊中，批量写入优化了状态更新性能，减少直接 I/O 开销。
func (db *Database) NewBatch() ethdb.Batch {
	return &batch{
		db: db,
	}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
// NewBatchWithSize 创建一个带有预分配缓冲区的只写数据库批次。
func (db *Database) NewBatchWithSize(size int) ethdb.Batch {
	return &batch{
		db: db,
	}
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
//
// NewIterator 创建一个按二进制字母顺序排列的迭代器，遍历数据库内容的子集，
// 该子集具有特定的键前缀，从特定的初始键开始（如果该键不存在，则从之后开始）。
func (db *Database) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	db.lock.RLock()
	defer db.lock.RUnlock()

	var (
		pr     = string(prefix)
		st     = string(append(prefix, start...))
		keys   = make([]string, 0, len(db.db))
		values = make([][]byte, 0, len(db.db))
	)
	// Collect the keys from the memory database corresponding to the given prefix
	// and start
	// 从内存数据库中收集与给定前缀和起始键对应的键
	for key := range db.db {
		if !strings.HasPrefix(key, pr) {
			continue
		}
		if key >= st {
			keys = append(keys, key)
		}
	}
	// Sort the items and retrieve the associated values
	// 对键进行排序并检索相关的值
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, db.db[key])
	}
	return &iterator{
		index:  -1,
		keys:   keys,
		values: values,
	}
}

// Stat returns the statistic data of the database.
// Stat 返回数据库的统计数据。
func (db *Database) Stat() (string, error) {
	return "", nil
}

// Compact is not supported on a memory database, but there's no need either as
// a memory database doesn't waste space anyway.
// Compact 在内存数据库上不受支持，但也没有必要，因为内存数据库无论如何都不会浪费空间。
func (db *Database) Compact(start []byte, limit []byte) error {
	return nil
}

// Len returns the number of entries currently present in the memory database.
//
// Note, this method is only used for testing (i.e. not public in general) and
// does not have explicit checks for closed-ness to allow simpler testing code.
//
// Len 返回内存数据库中当前存在的条目数量。
//
// 注意，此方法仅用于测试（即通常不是公开的），并且没有显式检查关闭状态，
// 以允许更简单的测试代码。
func (db *Database) Len() int {
	db.lock.RLock()
	defer db.lock.RUnlock()

	return len(db.db)
}

// keyvalue is a key-value tuple tagged with a deletion field to allow creating
// memory-database write batches.
//
// keyvalue 是一个带有删除标记的键值对，用于创建内存数据库的写入批次。
type keyvalue struct {
	key    string
	value  []byte // 值内容（RLP 编码后的数据，符合以太坊存储格式）
	delete bool
}

// batch is a write-only memory batch that commits changes to its host
// database when Write is called. A batch cannot be used concurrently.
//
// batch 是一个只写的内存批次，当调用 Write 时将更改提交到其宿主数据库。
// 批次不能并发使用。
type batch struct {
	db     *Database
	writes []keyvalue
	size   int
}

// Put inserts the given value into the batch for later committing.
//
// Put 将给定的值插入到批次中，以便稍后提交。
func (b *batch) Put(key, value []byte) error {
	b.writes = append(b.writes, keyvalue{string(key), common.CopyBytes(value), false})
	b.size += len(key) + len(value)
	return nil
}

// Delete inserts the key removal into the batch for later committing.
// Delete 将键的移除操作插入到批次中，以便稍后提交。
func (b *batch) Delete(key []byte) error {
	b.writes = append(b.writes, keyvalue{string(key), nil, true})
	b.size += len(key)
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
// ValueSize 检索排队等待写入的数据量。
func (b *batch) ValueSize() int {
	return b.size
}

// Write flushes any accumulated data to the memory database.
// Write 将累积的数据刷新到内存数据库。
func (b *batch) Write() error {
	b.db.lock.Lock()
	defer b.db.lock.Unlock()

	if b.db.db == nil {
		return errMemorydbClosed
	}
	for _, keyvalue := range b.writes {
		if keyvalue.delete {
			delete(b.db.db, keyvalue.key)
			continue
		}
		b.db.db[keyvalue.key] = keyvalue.value
	}
	return nil
}

// Reset resets the batch for reuse.
// Reset 重置批次以供重用。
func (b *batch) Reset() {
	b.writes = b.writes[:0]
	b.size = 0
}

// Replay replays the batch contents.
// Replay 重放批次内容。
func (b *batch) Replay(w ethdb.KeyValueWriter) error {
	for _, keyvalue := range b.writes {
		if keyvalue.delete {
			if err := w.Delete([]byte(keyvalue.key)); err != nil {
				return err
			}
			continue
		}
		if err := w.Put([]byte(keyvalue.key), keyvalue.value); err != nil {
			return err
		}
	}
	return nil
}

// iterator can walk over the (potentially partial) keyspace of a memory key
// value store. Internally it is a deep copy of the entire iterated state,
// sorted by keys.
//
// iterator 可以遍历内存键值存储的（可能部分的）键空间。内部它是整个迭代状态的深拷贝，
// 按键排序。
type iterator struct {
	index  int
	keys   []string
	values [][]byte
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
//
// Next 将迭代器移动到下一个键值对。它返回迭代器是否已耗尽。
func (it *iterator) Next() bool {
	// Short circuit if iterator is already exhausted in the forward direction.
	// 如果迭代器在前进方向上已经耗尽，则短路返回。
	if it.index >= len(it.keys) {
		return false
	}
	it.index += 1
	return it.index < len(it.keys)
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error. A memory iterator cannot encounter errors.
// Error 返回任何累积的错误。耗尽所有键值对不视为错误。内存迭代器不会遇到错误。
func (it *iterator) Error() error {
	return nil
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
//
// Key 返回当前键值对的键，如果完成则返回 nil。调用者不应修改返回切片的内容，
// 其内容可能在下一次调用 Next 时发生变化。
func (it *iterator) Key() []byte {
	// Short circuit if iterator is not in a valid position
	// 如果迭代器不在有效位置，则短路返回。
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	return []byte(it.keys[it.index])
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
//
// Value 返回当前键值对的值，如果完成则返回 nil。调用者不应修改返回切片的内容，
// 其内容可能在下一次调用 Next 时发生变化。
func (it *iterator) Value() []byte {
	// Short circuit if iterator is not in a valid position
	// 如果迭代器不在有效位置，则短路返回。
	if it.index < 0 || it.index >= len(it.keys) {
		return nil
	}
	return it.values[it.index]
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
//
// Release 释放关联的资源。Release 应始终成功，并且可以多次调用而不引发错误。
func (it *iterator) Release() {
	it.index, it.keys, it.values = -1, nil, nil
}
