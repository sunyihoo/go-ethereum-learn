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

package ethdb

// IdealBatchSize defines the size of the data batches should ideally add in one
// write.
// IdealBatchSize 定义了数据批次在一次写入中理想应添加的大小。
const IdealBatchSize = 100 * 1024

// Batch is a write-only database that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
//
// Batch 是一个只写数据库，当调用 Write 时将其更改提交到宿主数据库。
// 一个批次不能并发使用。
type Batch interface {
	KeyValueWriter

	// ValueSize retrieves the amount of data queued up for writing.
	// ValueSize 检索排队等待写入的数据量。
	ValueSize() int

	// Write flushes any accumulated data to disk.
	// Write 将累积的数据刷新到磁盘。
	Write() error

	// Reset resets the batch for reuse.
	// Reset 重置批次以供重用。
	Reset()

	// Replay replays the batch contents.
	// Replay 重放批次内容。
	Replay(w KeyValueWriter) error
}

// Batcher wraps the NewBatch method of a backing data store.
// Batcher 封装了底层数据存储的 NewBatch 方法。
type Batcher interface {
	// NewBatch creates a write-only database that buffers changes to its host db
	// until a final write is called.
	// NewBatch 创建一个只写数据库，缓冲对其宿主数据库的更改，直到调用最终写入。
	NewBatch() Batch

	// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
	// NewBatchWithSize 创建一个带有预分配缓冲区的只写数据库批次。
	NewBatchWithSize(size int) Batch
}

// HookedBatch wraps an arbitrary batch where each operation may be hooked into
// to monitor from black box code.
// HookedBatch 封装了一个任意的批次，其中每个操作都可以被钩入，以便从黑盒代码中监控。
type HookedBatch struct {
	Batch

	OnPut    func(key []byte, value []byte) // Callback if a key is inserted 如果插入了一个键，则调用此回调
	OnDelete func(key []byte)               // Callback if a key is deleted 如果删除了一个键，则调用此回调
}

// Put inserts the given value into the key-value data store.
// Put 将给定的值插入到键值数据存储中。
func (b HookedBatch) Put(key []byte, value []byte) error {
	if b.OnPut != nil {
		b.OnPut(key, value)
	}
	return b.Batch.Put(key, value)
}

// Delete removes the key from the key-value data store.
// Delete 从键值数据存储中移除键。
func (b HookedBatch) Delete(key []byte) error {
	if b.OnDelete != nil {
		b.OnDelete(key)
	}
	return b.Batch.Delete(key)
}
