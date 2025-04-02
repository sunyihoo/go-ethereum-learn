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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// memoryTable is used to store a list of sequential items in memory.
// memoryTable 用于在内存中存储一系列顺序项。
type memoryTable struct {
	name   string   // Table name  表名
	items  uint64   // Number of stored items in the table, including the deleted ones 表中存储的项的数量（包括已删除的项）
	offset uint64   // Number of deleted items from the table  从表中删除的项的数量
	data   [][]byte // List of rlp-encoded items, sort in order RLP 编码项的列表，按顺序排序
	size   uint64   // Total memory size occupied by the table 表占用的总内存大小
	lock   sync.RWMutex
}

// newMemoryTable initializes the memory table.
// newMemoryTable 初始化内存表。
func newMemoryTable(name string) *memoryTable {
	return &memoryTable{name: name}
}

// has returns an indicator whether the specified data exists.
// has 返回指定数据是否存在的指示器。
func (t *memoryTable) has(number uint64) bool {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return number >= t.offset && number < t.items // 检查编号是否在有效范围内
}

// retrieve retrieves multiple items in sequence, starting from the index 'start'.
// It will return:
//   - at most 'count' items,
//   - if maxBytes is specified: at least 1 item (even if exceeding the maxByteSize),
//     but will otherwise return as many items as fit into maxByteSize.
//   - if maxBytes is not specified, 'count' items will be returned if they are present
//
// retrieve 以顺序方式检索多个项目，从索引 'start' 开始。
// 返回：
//   - 至多 'count' 项,
//   - 如果指定了 maxBytes: 至少 1 项（即使超过 maxByteSize），
//     但如果没有，也会返回适合 maxByteSize 的尽可能多的项目。
//   - 如果未指定 maxBytes，则会返回 'count' 项如果它们存在。
func (t *memoryTable) retrieve(start uint64, count, maxBytes uint64) ([][]byte, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	var (
		size  uint64
		batch [][]byte // 存储结果的切片
	)
	// Ensure the start is written, not deleted from the tail, and that the
	// caller actually wants something.
	// 确保起始项已写入，未从尾部删除，并且调用者确实需要数据。
	if t.items <= start || t.offset > start || count == 0 {
		return nil, errOutOfBounds
	}
	// Cap the item count if the retrieval is out of bound.
	// 如果检索超出范围，则限制项数。
	if start+count > t.items {
		count = t.items - start // 调整项数
	}
	for n := start; n < start+count; n++ {
		index := n - t.offset // 计算数据索引
		if len(batch) != 0 && maxBytes != 0 && size+uint64(len(t.data[index])) > maxBytes {
			return batch, nil // 检查是否超出最大字节数
		}
		batch = append(batch, t.data[index]) // 将数据添加到结果中
		size += uint64(len(t.data[index]))   // 更新已读取的大小
	}
	return batch, nil // 返回找到的项目
}

// truncateHead discards any recent data above the provided threshold number.
// truncateHead 丢弃提供阈值编号以上的最近数据。
func (t *memoryTable) truncateHead(items uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Short circuit if nothing to delete.
	// 如果没有东西可删除，则直接返回。
	if t.items <= items {
		return nil
	}
	if items < t.offset {
		return errors.New("truncation below tail")
	}
	t.data = t.data[:items-t.offset] // 截断内存表
	t.items = items                  // 更新项目数
	return nil
}

// truncateTail discards any recent data before the provided threshold number.
// truncateTail 丢弃提供阈值编号之前的任何最近数据。
func (t *memoryTable) truncateTail(items uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Short circuit if nothing to delete.
	// 如果没有东西可删除，则直接返回。
	if t.offset >= items {
		return nil
	}
	if t.items < items {
		return errors.New("truncation above head")
	}
	t.data = t.data[items-t.offset:] // 截断内存表
	t.offset = items                 // 更新删除项计数
	return nil
}

// commit merges the given item batch into table. It's presumed that the
// batch is ordered and continuous with table.
// commit 将给定的项批量合并到表中。假定批量是有序的，并与表紧密相连。
func (t *memoryTable) commit(batch [][]byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, item := range batch {
		t.size += uint64(len(item)) // 更新内存表的大小
	}
	t.data = append(t.data, batch...) // 将项追加到内存表
	t.items += uint64(len(batch))     // 更新表的项数
	return nil
}

// memoryBatch is the singleton batch used for ancient write.
// memoryBatch 是用于古老事务写入的单例批次。
type memoryBatch struct {
	data map[string][][]byte // 存储 RLP 编码的事务
	next map[string]uint64   // 指向下一个事务的计数器
	size map[string]int64    // 各表的大小
}

// newMemoryBatch 初始化一个新的 memoryBatch 实例。
func newMemoryBatch() *memoryBatch {
	return &memoryBatch{
		data: make(map[string][][]byte),
		next: make(map[string]uint64),
		size: make(map[string]int64),
	}
}

// reset 清空批处理并为给定的冷冻存储实例重新初始化它。
func (b *memoryBatch) reset(freezer *MemoryFreezer) {
	b.data = make(map[string][][]byte)
	b.next = make(map[string]uint64)
	b.size = make(map[string]int64)

	for name, table := range freezer.tables {
		b.next[name] = table.items // 初始化每个表的下一个事务
	}
}

// Append adds an RLP-encoded item.
// Append 添加一个 RLP 编码的项目。
func (b *memoryBatch) Append(kind string, number uint64, item interface{}) error {
	if b.next[kind] != number { // 检查事务是否按顺序
		return errOutOrderInsertion
	}
	blob, err := rlp.EncodeToBytes(item) // 编码为 RLP
	if err != nil {
		return err
	}
	b.data[kind] = append(b.data[kind], blob) // 添加到当前表的事务列表
	b.next[kind]++                            // 更新下一个事务编号
	b.size[kind] += int64(len(blob))          // 更新大小
	return nil
}

// AppendRaw adds an item without RLP-encoding it.
// AppendRaw 添加一个未经 RLP 编码的项目。
func (b *memoryBatch) AppendRaw(kind string, number uint64, blob []byte) error {
	if b.next[kind] != number { // 检查事务是否按顺序
		return errOutOrderInsertion
	}
	b.data[kind] = append(b.data[kind], common.CopyBytes(blob)) // 添加原始数据
	b.next[kind]++                                              // 更新下一个事务编号
	b.size[kind] += int64(len(blob))                            // 更新大小
	return nil
}

// commit is called at the end of a write operation and writes all remaining
// data to tables.
// commit 在写操作结束时调用，并将所有剩余数据写入表中。
func (b *memoryBatch) commit(freezer *MemoryFreezer) (items uint64, writeSize int64, err error) {
	// Check that count agrees on all batches.
	// 检查所有批的计数是否一致
	items = math.MaxUint64 // 假定最大无符号整数
	for name, next := range b.next {
		if items < math.MaxUint64 && next != items { // 检查是否有序
			return 0, 0, fmt.Errorf("table %s is at item %d, want %d", name, next, items)
		}
		items = next // 更新项目计数
	}
	// Commit all table batches.
	// 提交所有表的批处理
	for name, batch := range b.data {
		table := freezer.tables[name] // 提取目标表
		if err := table.commit(batch); err != nil {
			return 0, 0, err
		}
		writeSize += b.size[name] // 更新写入大小
	}
	return items, writeSize, nil // 返回项目数和写入大小
}

// MemoryFreezer is an ephemeral ancient store. It implements the ethdb.AncientStore
// interface and can be used along with ephemeral key-value store.
//
// MemoryFreezer 是一个短暂的古老存储。它实现了 ethdb.AncientStore 接口，
// 并可以与临时键值存储一起使用。
type MemoryFreezer struct {
	items      uint64                  // Number of items stored 存储的项目数量
	tail       uint64                  // Number of the first stored item in the freezer 冷冻存储中第一个存储项目的数量
	readonly   bool                    // Flag if the freezer is only for reading  冷冻存储是否为只读的标志
	lock       sync.RWMutex            // Lock to protect fields 保护字段的互斥锁
	tables     map[string]*memoryTable // Tables for storing everything 存储所有数据的表
	writeBatch *memoryBatch            // Pre-allocated write batch 预分配的写批次
}

// NewMemoryFreezer initializes an in-memory freezer instance.
// NewMemoryFreezer 初始化一个内存中的冷冻存储实例。
func NewMemoryFreezer(readonly bool, tableName map[string]bool) *MemoryFreezer {
	tables := make(map[string]*memoryTable)
	for name := range tableName {
		tables[name] = newMemoryTable(name) // 创建新的内存表
	}
	return &MemoryFreezer{
		writeBatch: newMemoryBatch(), // 创建新的写批次
		readonly:   readonly,         // 设置为只读
		tables:     tables,           // 更新表
	}
}

// HasAncient returns an indicator whether the specified data exists.
// HasAncient 返回指示指定数据是否存在的标志。
func (f *MemoryFreezer) HasAncient(kind string, number uint64) (bool, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	if table := f.tables[kind]; table != nil {
		return table.has(number), nil // 检查项目是否存在
	}
	return false, nil
}

// Ancient retrieves an ancient binary blob from the in-memory freezer.
// Ancient 从内存中的冷冻存储中检索古老的二进制数据。
func (f *MemoryFreezer) Ancient(kind string, number uint64) ([]byte, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	t := f.tables[kind] // 获取表
	if t == nil {
		return nil, errUnknownTable
	}
	data, err := t.retrieve(number, 1, 0) // 检索单个项目
	if err != nil {
		return nil, err
	}
	return data[0], nil
}

// AncientRange retrieves multiple items in sequence, starting from the index 'start'.
// It will return
//   - at most 'count' items,
//   - if maxBytes is specified: at least 1 item (even if exceeding the maxByteSize),
//     but will otherwise return as many items as fit into maxByteSize.
//   - if maxBytes is not specified, 'count' items will be returned if they are present
//
// AncientRange 以顺序方式检索多个项目，从索引 'start' 开始。
// 返回：
//   - 至多 'count' 项,
//   - 如果指定了 maxBytes: 至少 1 项（即使超过 maxByteSize），
//     但如果没有，也会返回适合 maxByteSize 的尽可能多的项目。
//   - 如果未指定 maxBytes，则会返回 'count' 项如果它们存在。
func (f *MemoryFreezer) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	t := f.tables[kind]
	if t == nil {
		return nil, errUnknownTable
	}
	return t.retrieve(start, count, maxBytes) // 检索项目
}

// Ancients returns the ancient item numbers in the freezer.
// Ancients 返回冷冻存储中的古老项编号。
func (f *MemoryFreezer) Ancients() (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.items, nil // 返回已存储项目的数量
}

// Tail returns the number of first stored item in the freezer.
// This number can also be interpreted as the total deleted item numbers.
// Tail 返回冷冻存储中第一个存储项目的编号。
// 此数字也可以被解释为已删除项目的总数。
func (f *MemoryFreezer) Tail() (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.tail, nil // 返回尾部编号
}

// AncientSize returns the ancient size of the specified category.
// AncientSize 返回指定类别的古老大小。
func (f *MemoryFreezer) AncientSize(kind string) (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	if table := f.tables[kind]; table != nil {
		return table.size, nil // 返回表的大小
	}
	return 0, errUnknownTable
}

// ReadAncients runs the given read operation while ensuring that no writes take place
// on the underlying freezer.
// ReadAncients 执行给定的读取操作，同时确保不对底层冷冻存储进行写操作。
func (f *MemoryFreezer) ReadAncients(fn func(ethdb.AncientReaderOp) error) (err error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return fn(f)
}

// ModifyAncients runs the given write operation.
// ModifyAncients 执行给定的写操作。
func (f *MemoryFreezer) ModifyAncients(fn func(ethdb.AncientWriteOp) error) (writeSize int64, err error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.readonly {
		return 0, errReadOnly
	}
	// Roll back all tables to the starting position in case of error.
	// 在发生错误时，将所有表回滚到起始位置。
	defer func(old uint64) {
		if err == nil {
			return
		}
		// The write operation has failed. Go back to the previous item position.
		// 写入操作失败。返回到上一个项目位置。
		for name, table := range f.tables {
			err := table.truncateHead(old) // 回滚清理
			if err != nil {
				log.Error("Freezer table roll-back failed", "table", name, "index", old, "err", err)
			}
		}
	}(f.items) // 在函数结束时进行回滚

	// Modify the ancients in batch.
	// 修改批量的古老数据。
	f.writeBatch.reset(f) // 重新初始化写批次
	if err := fn(f.writeBatch); err != nil {
		return 0, err
	}
	item, writeSize, err := f.writeBatch.commit(f) // 提交写批次
	if err != nil {
		return 0, err
	}
	f.items = item // 更新项目数
	return writeSize, nil
}

// TruncateHead discards any recent data above the provided threshold number.
// It returns the previous head number.
// TruncateHead 丢弃阈值编号以上的所有数据。返回之前的头部编号。
func (f *MemoryFreezer) TruncateHead(items uint64) (uint64, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.readonly {
		return 0, errReadOnly // 返回只读错误
	}
	old := f.items
	if old <= items {
		return old, nil
	}
	for _, table := range f.tables { // 遍历所有表
		if err := table.truncateHead(items); err != nil {
			return 0, err
		}
	}
	f.items = items // 更新项目数
	return old, nil
}

// TruncateTail discards any recent data below the provided threshold number.
// TruncateTail 丢弃阈值编号以下的所有数据。
func (f *MemoryFreezer) TruncateTail(tail uint64) (uint64, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.readonly {
		return 0, errReadOnly // 返回只读错误
	}
	old := f.tail // 保存当前尾部编号
	if old >= tail {
		return old, nil
	}
	for _, table := range f.tables { // 遍历所有表
		if err := table.truncateTail(tail); err != nil {
			return 0, err
		}
	}
	f.tail = tail // 更新尾部编号
	return old, nil
}

// Sync flushes all data tables to disk.
// Sync 将所有数据表刷入磁盘。
func (f *MemoryFreezer) Sync() error {
	return nil
}

// Close releases all the sources held by the memory freezer. It will panic if
// any following invocation is made to a closed freezer.
// Close 释放 memory freezer 持有的所有资源。如果后续调用已关闭的 freezer，会导致 panic。
func (f *MemoryFreezer) Close() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.tables = nil
	f.writeBatch = nil
	return nil
}

// Reset drops all the data cached in the memory freezer and reset itself
// back to default state.
// Reset 清空 memory freezer 中缓存的所有数据，并重置回默认状态。
func (f *MemoryFreezer) Reset() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	tables := make(map[string]*memoryTable) // 创建新的表映射
	for name := range f.tables {            // 遍历旧表
		tables[name] = newMemoryTable(name) // 创建新的内存表
	}
	f.tables = tables      // 更新表
	f.items, f.tail = 0, 0 // 重置项目和尾部计数
	return nil
}

// AncientDatadir returns the path of the ancient store.
// Since the memory freezer is ephemeral, an empty string is returned.
// AncientDatadir 返回古老存储的路径。
// 由于内存冷冻存储是短暂的，返回空字符串。
func (f *MemoryFreezer) AncientDatadir() (string, error) {
	return "", nil
}
