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

package rawdb

import (
	"github.com/ethereum/go-ethereum/ethdb"
)

// table is a wrapper around a database that prefixes each key access with a pre-
// configured string.
// table 是一个数据库的包装器，它为每个键访问添加一个预配置的字符串前缀。
// 它的目的是为所有键操作（读、写、删除等）自动添加一个前缀，以便在数据库中隔离或组织数据。
// 在以太坊中，这种机制常用于将不同类型的数据（如区块、交易、状态）存储在同一数据库中，但通过前缀区分，避免键冲突。
type table struct {
	db     ethdb.Database
	prefix string
}

// NewTable returns a database object that prefixes all keys with a given string.
// NewTable 返回一个数据库对象，该对象为所有键添加一个给定的字符串前缀。
func NewTable(db ethdb.Database, prefix string) ethdb.Database {
	return &table{
		db:     db,
		prefix: prefix,
	}
}

// Close is a noop to implement the Database interface.
// Close 是一个空操作，用于实现 Database 接口。
func (t *table) Close() error {
	return nil
}

// Has retrieves if a prefixed version of a key is present in the database.
// Has 检索数据库中是否存在键的带前缀版本。
func (t *table) Has(key []byte) (bool, error) {
	return t.db.Has(append([]byte(t.prefix), key...))
}

// Get retrieves the given prefixed key if it's present in the database.
// Get 检索数据库中给定的带前缀键。
func (t *table) Get(key []byte) ([]byte, error) {
	return t.db.Get(append([]byte(t.prefix), key...))
}

// HasAncient is a noop passthrough that just forwards the request to the underlying
// database.
// HasAncient 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) HasAncient(kind string, number uint64) (bool, error) {
	return t.db.HasAncient(kind, number)
}

// Ancient is a noop passthrough that just forwards the request to the underlying
// database.
// Ancient 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) Ancient(kind string, number uint64) ([]byte, error) {
	return t.db.Ancient(kind, number)
}

// AncientRange is a noop passthrough that just forwards the request to the underlying
// database.
// AncientRange 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	return t.db.AncientRange(kind, start, count, maxBytes)
}

// Ancients is a noop passthrough that just forwards the request to the underlying
// database.
// Ancients 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) Ancients() (uint64, error) {
	return t.db.Ancients()
}

// Tail is a noop passthrough that just forwards the request to the underlying
// database.
// Tail 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) Tail() (uint64, error) {
	return t.db.Tail()
}

// AncientSize is a noop passthrough that just forwards the request to the underlying
// database.
// AncientSize 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) AncientSize(kind string) (uint64, error) {
	return t.db.AncientSize(kind)
}

// ModifyAncients runs an ancient write operation on the underlying database.
// ModifyAncients 在底层数据库上运行一个“Ancient”写入操作。
func (t *table) ModifyAncients(fn func(ethdb.AncientWriteOp) error) (int64, error) {
	return t.db.ModifyAncients(fn)
}

// ReadAncients 在底层数据库上运行一个“Ancient”读取操作。
func (t *table) ReadAncients(fn func(reader ethdb.AncientReaderOp) error) (err error) {
	return t.db.ReadAncients(fn)
}

// TruncateHead is a noop passthrough that just forwards the request to the underlying
// database.
// TruncateHead 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) TruncateHead(items uint64) (uint64, error) {
	return t.db.TruncateHead(items)
}

// TruncateTail is a noop passthrough that just forwards the request to the underlying
// database.
// TruncateTail 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) TruncateTail(items uint64) (uint64, error) {
	return t.db.TruncateTail(items)
}

// Sync is a noop passthrough that just forwards the request to the underlying
// database.
// Sync 是一个空操作的传递，仅将请求转发到底层数据库。
func (t *table) Sync() error {
	return t.db.Sync()
}

// AncientDatadir returns the ancient datadir of the underlying database.
// AncientDatadir 返回底层数据库的“Ancient”数据目录。
func (t *table) AncientDatadir() (string, error) {
	return t.db.AncientDatadir()
}

// Put inserts the given value into the database at a prefixed version of the
// provided key.
// Put 将给定的值插入到数据库中，使用提供的键的带前缀版本。
func (t *table) Put(key []byte, value []byte) error {
	return t.db.Put(append([]byte(t.prefix), key...), value)
}

// Delete removes the given prefixed key from the database.
// Delete 从数据库中删除给定的带前缀键。
func (t *table) Delete(key []byte) error {
	return t.db.Delete(append([]byte(t.prefix), key...))
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
// DeleteRange 删除[start, end)范围内的所有键（和值）（start 包含，end 不包含）。
func (t *table) DeleteRange(start, end []byte) error {
	return t.db.DeleteRange(append([]byte(t.prefix), start...), append([]byte(t.prefix), end...))
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
// NewIterator 创建一个二进制字母顺序的迭代器，遍历数据库内容的子集，
// 该子集具有特定的键前缀，从特定的初始键开始（或在其后，如果不存在）。
func (t *table) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	innerPrefix := append([]byte(t.prefix), prefix...)
	iter := t.db.NewIterator(innerPrefix, start)
	return &tableIterator{
		iter:   iter,
		prefix: t.prefix,
	}
}

// Stat returns the statistic data of the database.
// Stat 返回数据库的统计数据。
func (t *table) Stat() (string, error) {
	return t.db.Stat()
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
//
// Compact 对给定的键范围压实底层数据存储。本质上，删除和覆盖的版本被丢弃，
// 数据被重新排列以减少访问它们所需的操作成本。
//
// 如果 start 为 nil，则视为数据存储中所有键之前的一个键；如果 limit 为 nil，
// 则视为数据存储中所有键之后的一个键。如果两者都为 nil，则将压实整个数据存储。
func (t *table) Compact(start []byte, limit []byte) error {
	// If no start was specified, use the table prefix as the first value
	if start == nil {
		start = []byte(t.prefix)
	} else {
		start = append([]byte(t.prefix), start...)
	}
	// If no limit was specified, use the first element not matching the prefix
	// as the limit
	if limit == nil {
		limit = []byte(t.prefix)
		for i := len(limit) - 1; i >= 0; i-- {
			// Bump the current character, stopping if it doesn't overflow
			limit[i]++
			if limit[i] > 0 {
				break
			}
			// Character overflown, proceed to the next or nil if the last
			if i == 0 {
				limit = nil
			}
		}
	} else {
		limit = append([]byte(t.prefix), limit...)
	}
	// Range correctly calculated based on table prefix, delegate down
	return t.db.Compact(start, limit)
}

// NewBatch creates a write-only database that buffers changes to its host db
// until a final write is called, each operation prefixing all keys with the
// pre-configured string.
// NewBatch 创建一个只写数据库，它将更改缓冲到其主机数据库，
// 直到调用最终写入，每个操作都为所有键添加预配置的字符串前缀。
func (t *table) NewBatch() ethdb.Batch {
	return &tableBatch{t.db.NewBatch(), t.prefix}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
// NewBatchWithSize 创建一个带有预分配缓冲区的只写数据库批处理。
func (t *table) NewBatchWithSize(size int) ethdb.Batch {
	return &tableBatch{t.db.NewBatchWithSize(size), t.prefix}
}

// tableBatch is a wrapper around a database batch that prefixes each key access
// with a pre-configured string.
// tableBatch 是一个数据库批处理的包装器，它为每个键访问添加一个预配置的字符串前缀。
type tableBatch struct {
	batch  ethdb.Batch
	prefix string
}

// Put inserts the given value into the batch for later committing.
// Put 将给定的值插入到批处理中以供稍后提交。
func (b *tableBatch) Put(key, value []byte) error {
	return b.batch.Put(append([]byte(b.prefix), key...), value)
}

// Delete inserts a key removal into the batch for later committing.
// Delete 将键删除操作插入到批处理中以供稍后提交。
func (b *tableBatch) Delete(key []byte) error {
	return b.batch.Delete(append([]byte(b.prefix), key...))
}

// ValueSize retrieves the amount of data queued up for writing.
// ValueSize 检索排队等待写入的数据量。
func (b *tableBatch) ValueSize() int {
	return b.batch.ValueSize()
}

// Write flushes any accumulated data to disk.
// Write 将累积的任何数据刷新到磁盘。
func (b *tableBatch) Write() error {
	return b.batch.Write()
}

// Reset resets the batch for reuse.
// Reset 重置批处理以供重用。
func (b *tableBatch) Reset() {
	b.batch.Reset()
}

// tableReplayer is a wrapper around a batch replayer which truncates
// the added prefix.
// tableReplayer 是一个批处理重放器的包装器，它截断添加的前缀。
type tableReplayer struct {
	w      ethdb.KeyValueWriter
	prefix string
}

// Put implements the interface KeyValueWriter.
// Put 实现 KeyValueWriter 接口。
func (r *tableReplayer) Put(key []byte, value []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Put(trimmed, value)
}

// Delete implements the interface KeyValueWriter.
// Delete 实现 KeyValueWriter 接口。
func (r *tableReplayer) Delete(key []byte) error {
	trimmed := key[len(r.prefix):]
	return r.w.Delete(trimmed)
}

// Replay replays the batch contents.
// Replay 重放批处理内容。
func (b *tableBatch) Replay(w ethdb.KeyValueWriter) error {
	return b.batch.Replay(&tableReplayer{w: w, prefix: b.prefix})
}

// tableIterator is a wrapper around a database iterator that prefixes each key access
// with a pre-configured string.
// tableIterator 是一个数据库迭代器的包装器，它为每个键访问添加一个预配置的字符串前缀。
type tableIterator struct {
	iter   ethdb.Iterator
	prefix string
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
// Next 将迭代器移动到下一个键/值对。它返回迭代器是否已耗尽。
func (iter *tableIterator) Next() bool {
	return iter.iter.Next()
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
// Error 返回任何累积的错误。耗尽所有键/值对不被视为错误。
func (iter *tableIterator) Error() error {
	return iter.iter.Error()
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
// Key 返回当前键/值对的键，如果完成则返回 nil。调用者不应修改返回的切片内容，
// 其内容可能在下一次调用 Next 时更改。
func (iter *tableIterator) Key() []byte {
	key := iter.iter.Key()
	if key == nil {
		return nil
	}
	return key[len(iter.prefix):]
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
// Value 返回当前键/值对的值，如果完成则返回 nil。调用者不应修改返回的切片内容，
// 其内容可能在下一次调用 Next 时更改。
func (iter *tableIterator) Value() []byte {
	return iter.iter.Value()
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
// Release 释放关联的资源。Release 应始终成功，并且可以多次调用而不会导致错误。
func (iter *tableIterator) Release() {
	iter.iter.Release()
}
