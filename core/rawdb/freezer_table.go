// Copyright 2019 The go-ethereum Authors
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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/golang/snappy"
)

var (
	// errClosed is returned if an operation attempts to read from or write to the
	// freezer table after it has already been closed.
	// errClosed 在尝试从冷冻表中读取或写入时，如果已经关闭，则返回此错误。
	errClosed = errors.New("closed")

	// errOutOfBounds is returned if the item requested is not contained within the
	// freezer table.
	// errOutOfBounds 如果请求的项不在冷冻存储表中，则返回此错误。
	errOutOfBounds = errors.New("out of bounds")

	// errNotSupported is returned if the database doesn't support the required operation.
	// errNotSupported 如果数据库不支持所需操作，则返回此错误。
	errNotSupported = errors.New("this operation is not supported")
)

// indexEntry contains the number/id of the file that the data resides in, as well as the
// offset within the file to the end of the data.
// In serialized form, the filenum is stored as uint16.
// indexEntry 结构体包含数据所在文件的编号/ID，以及数据在文件中的结束偏移量。
// 在序列化形式中，文件编号以 uint16 存储。
type indexEntry struct {
	filenum uint32 // stored as uint16 ( 2 bytes )  存储为 uint16 ( 2 bytes )
	offset  uint32 // stored as uint32 ( 4 bytes )  存储为 uint32 ( 4 bytes )
}

const indexEntrySize = 6 //  定义 indexEntry 的大小为 6 字节

// unmarshalBinary deserializes binary b into the rawIndex entry.
// unmarshalBinary 将二进制数据 b 反序列化为 rawIndex 条目。
func (i *indexEntry) unmarshalBinary(b []byte) {
	i.filenum = uint32(binary.BigEndian.Uint16(b[:2])) // 从字节到确定的文件编号
	i.offset = binary.BigEndian.Uint32(b[2:6])         // 从字节到偏移量
}

// append adds the encoded entry to the end of b.
// append 将编码的条目添加到 b 的末尾。
func (i *indexEntry) append(b []byte) []byte {
	offset := len(b)
	out := append(b, make([]byte, indexEntrySize)...)
	binary.BigEndian.PutUint16(out[offset:], uint16(i.filenum)) // 将文件编号放入字节数组
	binary.BigEndian.PutUint32(out[offset+2:], i.offset)        // 将偏移量放入字节数组
	return out                                                  // 返回扩展后的字节数组
}

// bounds returns the start- and end- offsets, and the file number of where to
// read there data item marked by the two index entries. The two entries are
// assumed to be sequential.
// bounds 返回起始和结束偏移量，以及读取两个索引条目标记的数据项的文件编号。
// 假定这两个条目是顺序的。
func (i *indexEntry) bounds(end *indexEntry) (startOffset, endOffset, fileId uint32) {
	if i.filenum != end.filenum { // 如果两个条目不在同一文件中
		// If a piece of data 'crosses' a data-file,
		// it's actually in one piece on the second data-file.
		// We return a zero-indexEntry for the second file as start
		// 如果数据跨越数据文件，则实际上在第二个数据文件中是一个整体。
		// 我们为第二个文件返回零索引条目作为起始。
		return 0, end.offset, end.filenum // 返回起始偏移量、结束偏移量和文件编号
	}
	return i.offset, end.offset, end.filenum // 返回起始偏移量、结束偏移量和文件编号
}

// freezerTable represents a single chained data table within the freezer (e.g. blocks).
// It consists of a data file (snappy encoded arbitrary data blobs) and an indexEntry
// file (uncompressed 64 bit indices into the data file).
// freezerTable 表示冷冻存储中的单独链式数据表（例如：区块）。
type freezerTable struct {
	items      atomic.Uint64 // Number of items stored in the table (including items removed from tail)  表中存储的项的数量（包括从末尾移除的项）
	itemOffset atomic.Uint64 // Number of items removed from the table 从表中删除的项的数量

	// itemHidden is the number of items marked as deleted. Tail deletion is
	// only supported at file level which means the actual deletion will be
	// delayed until the entire data file is marked as deleted. Before that
	// these items will be hidden to prevent being visited again. The value
	// should never be lower than itemOffset.
	// 标记为已删除的项的数量。尾部删除仅支持在文件级别，因此实际删除将延迟到整个数据文件被标记为删除。此值应始终不少于 itemOffset。
	itemHidden atomic.Uint64

	noCompression bool   // if true, disables snappy compression. Note: does not work retroactively 如果为真，则禁用 snappy 压缩。注意：不针对先前的数据生效。
	readonly      bool   // 是否为只读
	maxFileSize   uint32 // Max file size for data-files 数据文件的最大大小
	name          string // 表的名称
	path          string // 表的路径

	head   *os.File            // File descriptor for the data head of the table 数据表的头部文件描述符
	index  *os.File            // File descriptor for the indexEntry file of the table 表的索引条目的文件描述符
	meta   *os.File            // File descriptor for metadata of the table 表元数据的文件描述符
	files  map[uint32]*os.File // open files 打开的文件
	headId uint32              // number of the currently active head file 当前活动头文件的编号
	tailId uint32              // number of the earliest file 最早文件的编号

	headBytes  int64          // Number of bytes written to the head file 写入头文件的字节数
	readMeter  *metrics.Meter // Meter for measuring the effective amount of data read  测量读取有效数据量的计量器
	writeMeter *metrics.Meter // Meter for measuring the effective amount of data written 测量写入有效数据量的计量器
	sizeGauge  *metrics.Gauge // Gauge for tracking the combined size of all freezer tables 跟踪所有冷冻表总大小的表

	logger log.Logger   // Logger with database path and table name embedded 包含数据库路径和表名的日志记录器
	lock   sync.RWMutex // Mutex protecting the data file descriptors 保护数据文件描述符的互斥锁
}

// newFreezerTable opens the given path as a freezer table.
// newFreezerTable 打开给定路径作为冷冻表。
func newFreezerTable(path, name string, disableSnappy, readonly bool) (*freezerTable, error) {
	return newTable(path, name, metrics.NewInactiveMeter(), metrics.NewInactiveMeter(), metrics.NewGauge(), freezerTableSize, disableSnappy, readonly)
}

// newTable opens a freezer table, creating the data and index files if they are
// non-existent. Both files are truncated to the shortest common length to ensure
// they don't go out of sync.
// newTable 打开冷冻表，如果数据文件和索引文件不存在，则创建它们。
// 两个文件都被截断为最短的公共长度，以确保它们不会不同步。
func newTable(path string, name string, readMeter, writeMeter *metrics.Meter, sizeGauge *metrics.Gauge, maxFilesize uint32, noCompression, readonly bool) (*freezerTable, error) {
	// Ensure the containing directory exists and open the indexEntry file
	// 确保目录存在并打开索引文件
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, err
	}
	var idxName string
	if noCompression {
		idxName = fmt.Sprintf("%s.ridx", name) // raw index file  原始索引文件
	} else {
		idxName = fmt.Sprintf("%s.cidx", name) // compressed index file  压缩索引文件
	}
	var (
		err   error
		index *os.File
		meta  *os.File
	)
	if readonly {
		// Will fail if table index file or meta file is not existent
		// 如果表索引文件或元数据文件不存在则失败
		index, err = openFreezerFileForReadOnly(filepath.Join(path, idxName))
		if err != nil {
			return nil, err
		}
		meta, err = openFreezerFileForReadOnly(filepath.Join(path, fmt.Sprintf("%s.meta", name)))
		if err != nil {
			return nil, err
		}
	} else {
		index, err = openFreezerFileForAppend(filepath.Join(path, idxName))
		if err != nil {
			return nil, err
		}
		meta, err = openFreezerFileForAppend(filepath.Join(path, fmt.Sprintf("%s.meta", name)))
		if err != nil {
			return nil, err
		}
	}
	// Create the table and repair any past inconsistency
	tab := &freezerTable{
		index:         index,
		meta:          meta,
		files:         make(map[uint32]*os.File),
		readMeter:     readMeter,
		writeMeter:    writeMeter,
		sizeGauge:     sizeGauge,
		name:          name,
		path:          path,
		logger:        log.New("database", path, "table", name),
		noCompression: noCompression,
		readonly:      readonly,
		maxFileSize:   maxFilesize,
	}
	if err := tab.repair(); err != nil {
		tab.Close()
		return nil, err
	}
	// Initialize the starting size counter
	// 初始化起始大小计数器
	size, err := tab.sizeNolock()
	if err != nil {
		tab.Close()
		return nil, err
	}
	tab.sizeGauge.Inc(int64(size)) // 更新大小计量器

	return tab, nil
}

// repair cross-checks the head and the index file and truncates them to
// be in sync with each other after a potential crash / data loss.
// repair 检查头文件和索引文件，并在发生潜在崩溃或数据丢失后将它们截断为同步状态。
func (t *freezerTable) repair() error {
	// Create a temporary offset buffer to init files with and read indexEntry into
	buffer := make([]byte, indexEntrySize)

	// If we've just created the files, initialize the index with the 0 indexEntry
	// 如果刚刚创建这些文件，则使用 0 索引项初始化索引
	stat, err := t.index.Stat()
	if err != nil {
		return err
	}
	if stat.Size() == 0 {
		if _, err := t.index.Write(buffer); err != nil {
			return err
		}
	}
	// Ensure the index is a multiple of indexEntrySize bytes
	// 确保索引文件大小是 indexEntrySize 的倍数
	if overflow := stat.Size() % indexEntrySize; overflow != 0 {
		if t.readonly {
			return fmt.Errorf("index file(path: %s, name: %s) size is not a multiple of %d", t.path, t.name, indexEntrySize)
		}
		if err := truncateFreezerFile(t.index, stat.Size()-overflow); err != nil {
			return err
		} // New file can't trigger this path  新文件不能触发此路径
	}
	// Validate the index file as it might contain some garbage data after the
	// power failures.
	// 验证索引文件，因为在电源故障后可能包含一些垃圾数据。
	if err := t.repairIndex(); err != nil {
		return err
	}
	// Retrieve the file sizes and prepare for truncation. Note the file size
	// might be changed after index validation.
	// 获取文件大小并准备进行截断。注意索引文件大小可能在验证后发生变化。
	if stat, err = t.index.Stat(); err != nil {
		return err
	}
	offsetsSize := stat.Size()

	// Open the head file
	// 打开头文件
	var (
		firstIndex  indexEntry
		lastIndex   indexEntry
		contentSize int64
		contentExp  int64
		verbose     bool
	)
	// Read index zero, determine what file is the earliest
	// and what item offset to use
	// 读取索引零，确定哪个文件最早，使用哪个项偏移
	t.index.ReadAt(buffer, 0)
	firstIndex.unmarshalBinary(buffer)

	// Assign the tail fields with the first stored index.
	// The total removed items is represented with an uint32,
	// which is not enough in theory but enough in practice.
	// TODO: use uint64 to represent total removed items.
	// 用第一个存储的索引填充尾部字段。
	// 表示移除项目总数的字段是 uint32，理论上不够，但在实践中足够。
	t.tailId = firstIndex.filenum
	t.itemOffset.Store(uint64(firstIndex.offset))

	// Load metadata from the file
	// 从文件中加载元数据
	meta, err := loadMetadata(t.meta, t.itemOffset.Load())
	if err != nil {
		return err
	}
	t.itemHidden.Store(meta.VirtualTail)

	// Read the last index, use the default value in case the freezer is empty
	// 读取最后一个索引，如果冷冻存储为空则使用默认值
	if offsetsSize == indexEntrySize {
		lastIndex = indexEntry{filenum: t.tailId, offset: 0}
	} else {
		t.index.ReadAt(buffer, offsetsSize-indexEntrySize)
		lastIndex.unmarshalBinary(buffer)
	}
	// Print an error log if the index is corrupted due to an incorrect
	// last index item. While it is theoretically possible to have a zero offset
	// by storing all zero-size items, it is highly unlikely to occur in practice.
	// 如果由于最后一个索引条目不正确而导致索引损坏，则打印错误日志。
	// 理论上，可以通过存储所有零大小项目来获得零偏移，但在实践中不太可能发生。
	if lastIndex.offset == 0 && offsetsSize/indexEntrySize > 1 {
		log.Error("Corrupted index file detected", "lastOffset", lastIndex.offset, "indexes", offsetsSize/indexEntrySize)
	}
	if t.readonly {
		t.head, err = t.openFile(lastIndex.filenum, openFreezerFileForReadOnly) // 打开头文件为只读
	} else {
		t.head, err = t.openFile(lastIndex.filenum, openFreezerFileForAppend) // 打开头文件为可追加
	}
	if err != nil {
		return err
	}
	if stat, err = t.head.Stat(); err != nil {
		return err
	}
	contentSize = stat.Size() // 读取头文件的大小

	// Keep truncating both files until they come in sync
	// 保持截断两个文件直到它们同步
	contentExp = int64(lastIndex.offset)
	for contentExp != contentSize {
		if t.readonly {
			return fmt.Errorf("freezer table(path: %s, name: %s, num: %d) is corrupted", t.path, t.name, lastIndex.filenum)
		}
		verbose = true
		// Truncate the head file to the last offset pointer
		// 截断头文件到最后的偏移指针
		if contentExp < contentSize {
			t.logger.Warn("Truncating dangling head", "indexed", contentExp, "stored", contentSize)
			if err := truncateFreezerFile(t.head, contentExp); err != nil {
				return err
			}
			contentSize = contentExp // 更新文件大小
		}
		// Truncate the index to point within the head file
		// 截断索引以指向头文件
		if contentExp > contentSize {
			t.logger.Warn("Truncating dangling indexes", "indexes", offsetsSize/indexEntrySize, "indexed", contentExp, "stored", contentSize)
			if err := truncateFreezerFile(t.index, offsetsSize-indexEntrySize); err != nil {
				return err
			}
			offsetsSize -= indexEntrySize // 更新索引文件大小

			// Read the new head index, use the default value in case
			// the freezer is already empty.
			// 读取新的头索引，如果冷冻存储为空则使用默认值。
			var newLastIndex indexEntry
			if offsetsSize == indexEntrySize {
				newLastIndex = indexEntry{filenum: t.tailId, offset: 0}
			} else {
				t.index.ReadAt(buffer, offsetsSize-indexEntrySize)
				newLastIndex.unmarshalBinary(buffer)
			}
			// We might have slipped back into an earlier head-file here
			// 此时可能回退到了早期的头文件
			if newLastIndex.filenum != lastIndex.filenum {
				// Release earlier opened file
				// 释放之前打开的文件
				t.releaseFile(lastIndex.filenum)
				if t.head, err = t.openFile(newLastIndex.filenum, openFreezerFileForAppend); err != nil {
					return err
				}
				if stat, err = t.head.Stat(); err != nil {
					// TODO, anything more we can do here?
					// A data file has gone missing...
					return err
				}
				contentSize = stat.Size()
			}
			lastIndex = newLastIndex
			contentExp = int64(lastIndex.offset)
		}
	}
	// Sync() fails for read-only files on windows.
	// 在windows上，sync()会在只读文件上失败。
	if !t.readonly {
		// Ensure all reparation changes have been written to disk
		// 确保所有修复更改都已写入磁盘
		if err := t.index.Sync(); err != nil {
			return err
		}
		if err := t.head.Sync(); err != nil {
			return err
		}
		if err := t.meta.Sync(); err != nil {
			return err
		}
	}
	// Update the item and byte counters and return
	// 更新项目和字节计数器并返回
	t.items.Store(t.itemOffset.Load() + uint64(offsetsSize/indexEntrySize-1)) // last indexEntry points to the end of the data file  // 最后索引指向数据文件末尾
	t.headBytes = contentSize                                                 // 更新头文件的字节数
	t.headId = lastIndex.filenum                                              // 更新头文件编号

	// Delete the leftover files because of head deletion
	// 删除因头部删除而留下的文件
	t.releaseFilesAfter(t.headId, true)

	// Delete the leftover files because of tail deletion
	// 删除因尾部删除而留下的文件
	t.releaseFilesBefore(t.tailId, true)

	// Close opened files and preopen all files
	// 关闭打开的文件并预先打开所有文件
	if err := t.preopen(); err != nil {
		return err
	}
	if verbose {
		t.logger.Info("Chain freezer table opened", "items", t.items.Load(), "deleted", t.itemOffset.Load(), "hidden", t.itemHidden.Load(), "tailId", t.tailId, "headId", t.headId, "size", t.headBytes)
	} else {
		t.logger.Debug("Chain freezer table opened", "items", t.items.Load(), "size", common.StorageSize(t.headBytes))
	}
	return nil
}

// repairIndex validates the integrity of the index file. According to the design,
// the initial entry in the file denotes the earliest data file along with the
// count of deleted items. Following this, all subsequent entries in the file must
// be in order. This function identifies any corrupted entries and truncates items
// occurring after the corruption point.
//
// corruption can occur because of the power failure. In the Linux kernel, the
// file metadata update and data update are not necessarily performed at the
// same time. Typically, the metadata will be flushed/journalled ahead of the file
// data. Therefore, we make the pessimistic assumption that the file is first
// extended with invalid "garbage" data (normally zero bytes) and that afterwards
// the correct data replaces the garbage. As all the items in index file are
// supposed to be in-order, the leftover garbage must be truncated before the
// index data is utilized.
//
// It's important to note an exception that's unfortunately undetectable: when
// all index entries in the file are zero. Distinguishing whether they represent
// leftover garbage or if all items in the table have zero size is impossible.
// In such instances, the file will remain unchanged to prevent potential data
// loss or misinterpretation.
//
// repairIndex 验证索引文件的完整性。根据设计，
// 文件中的初始条目表示最早的数据文件以及已删除项目的数量。
// 此后，文件中的所有后续条目必须按顺序。此函数识别任何损坏的条目并截断在其后发生的条目。
func (t *freezerTable) repairIndex() error {
	// Retrieve the file sizes and prepare for validation
	// 获取文件大小并准备进行验证
	stat, err := t.index.Stat()
	if err != nil {
		return err
	}
	size := stat.Size() // 指定索引文件的大小

	// Move the read cursor to the beginning of the file
	// 将读取游标移动到文件开头
	_, err = t.index.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	fr := bufio.NewReader(t.index) // 使用 bufio 读取器

	var (
		start = time.Now()                   // 记录开始时间
		buff  = make([]byte, indexEntrySize) // 创建缓冲区以读取索引条目
		prev  indexEntry                     // 前一个索引条目
		head  indexEntry                     // 头索引条目

		// read 是辅助函数，用于读取单个数据项。
		read = func() (indexEntry, error) {
			n, err := io.ReadFull(fr, buff) // 从读取器中读取数据
			if err != nil {
				return indexEntry{}, err
			}
			if n != indexEntrySize {
				return indexEntry{}, fmt.Errorf("failed to read from index, n: %d", n)
			}
			var entry indexEntry
			entry.unmarshalBinary(buff) // 反序列化索引条目
			return entry, nil           // 返回索引条目
		}
		// truncate 是一个辅助函数，用于截断索引文件。
		truncate = func(offset int64) error {
			if t.readonly {
				return fmt.Errorf("index file is corrupted at %d, size: %d", offset, size)
			}
			if err := truncateFreezerFile(t.index, offset); err != nil {
				return err
			}
			log.Warn("Truncated index file", "offset", offset, "truncated", size-offset)
			return nil
		}
	)
	for offset := int64(0); offset < size; offset += indexEntrySize {
		entry, err := read() // 读取索引条目
		if err != nil {
			return err
		}
		if offset == 0 {
			head = entry // 第一个索引条目为头条目
			continue
		}
		// Ensure that the first non-head index refers to the earliest file,
		// or the next file if the earliest file has no space to place the
		// first item.
		// 确保第一个非头索引指向最早的文件，
		// 或下一个文件，如果最早的文件没有空间放置
		if offset == indexEntrySize {
			if entry.filenum != head.filenum && entry.filenum != head.filenum+1 {
				log.Error("Corrupted index item detected", "earliest", head.filenum, "filenumber", entry.filenum)
				return truncate(offset)
			}
			prev = entry // 更新前一个条目
			continue
		}
		// ensure two consecutive index items are in order
		// 确保两个连续的索引条目按顺序排列
		if err := t.checkIndexItems(prev, entry); err != nil {
			log.Error("Corrupted index item detected", "err", err)
			return truncate(offset)
		}
		prev = entry // 更新前一个条目
	}
	// Move the read cursor to the end of the file. While theoretically, the
	// cursor should reach the end by reading all the items in the file, perform
	// the seek operation anyway as a precaution.
	// 将读取游标移动到文件末尾。理论上，游标应该通过读取文件中的所有项目到达末尾，出于谨慎起见，执行 seek 操作。
	_, err = t.index.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	log.Debug("Verified index file", "items", size/indexEntrySize, "elapsed", common.PrettyDuration(time.Since(start))) // 记录已验证索引文件的信息
	return nil
}

// checkIndexItems validates the correctness of two consecutive index items based
// on the following rules:
//
//   - The file number of two consecutive index items must either be the same or
//     increase monotonically. If the file number decreases or skips in a
//     non-sequential manner, the index item is considered invalid.
//
//   - For index items with the same file number, the data offset must be in
//     non-decreasing order. Note: Two index items with the same file number
//     and the same data offset are permitted if the entry size is zero.
//
//   - The first index item in a new data file must not have a zero data offset.
//
// checkIndexItems 验证两个连续索引项的正确性，基于以下规则：
//
//   - The file number of two consecutive index items must either be the same or
//     increase monotonically. If the file number decreases or skips in a
//     non-sequential manner, the index item is considered invalid.
//
//   - 两个连续索引项的文件编号必须相同或单调增加。
//     如果文件编号递减或在非顺序中跳跃，则该索引项被视为无效。
//
//   - For index items with the same file number, the data offset must be in
//     non-decreasing order. Note: Two index items with the same file number
//     and the same data offset are permitted if the entry size is zero.
//
//   - 对于具有相同文件编号的索引项，数据偏移量必须是非递减的。
//     注意：如果条目大小为零，允许两个具有相同文件编号和相同数据偏移量的索引项。
//
//   - The first index item in a new data file must not have a zero data offset.
//
//   - 新数据文件中的第一个索引项的偏移量不可为零。
func (t *freezerTable) checkIndexItems(a, b indexEntry) error {
	if b.filenum != a.filenum && b.filenum != a.filenum+1 {
		return fmt.Errorf("index items with inconsistent file number, prev: %d, next: %d", a.filenum, b.filenum)
	}
	if b.filenum == a.filenum && b.offset < a.offset {
		return fmt.Errorf("index items with unordered offset, prev: %d, next: %d", a.offset, b.offset)
	}
	if b.filenum == a.filenum+1 && b.offset == 0 {
		return fmt.Errorf("index items with zero offset, file number: %d", b.filenum)
	}
	return nil
}

// preopen opens all files that the freezer will need. This method should be called from an init-context,
// since it assumes that it doesn't have to bother with locking
// The rationale for doing preopen is to not have to do it from within Retrieve, thus not needing to ever
// obtain a write-lock within Retrieve.
// preopen 打开冷冻存储所需的所有文件。此方法应在初始化上下文中调用，
// 因为它假定不必处理锁定问题。
func (t *freezerTable) preopen() (err error) {
	// The repair might have already opened (some) files
	// repair 可能已经打开了一些文件
	t.releaseFilesAfter(0, false)

	// Open all except head in RDONLY
	// 除头部外，以只读方式打开所有文件
	for i := t.tailId; i < t.headId; i++ {
		if _, err = t.openFile(i, openFreezerFileForReadOnly); err != nil {
			return err
		}
	}
	if t.readonly {
		t.head, err = t.openFile(t.headId, openFreezerFileForReadOnly) // 以只读打开头文件
	} else {
		// Open head in read/write
		// 以可读写方式打开头文件
		t.head, err = t.openFile(t.headId, openFreezerFileForAppend)
	}
	return err
}

// truncateHead discards any recent data above the provided threshold number.
// truncateHead 丢弃超出提供阈值编号的最近数据。
func (t *freezerTable) truncateHead(items uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Ensure the given truncate target falls in the correct range
	// 确保给定的截断目标在正确范围内
	existing := t.items.Load()
	if existing <= items { // 如果当前项数小于或等于目标项数，无需截断
		return nil
	}
	if items < t.itemHidden.Load() {
		return errors.New("truncation below tail")
	}
	// We need to truncate, save the old size for metrics tracking
	// 我们需要截断，保存旧大小，以便跟踪指标
	oldSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	// Something's out of sync, truncate the table's offset index
	// 同步出错，截断表的偏移索引
	log := t.logger.Debug
	if existing > items+1 {
		log = t.logger.Warn // Only loud warn if we delete multiple items// 多处删除时显示警告
	}
	log("Truncating freezer table", "items", existing, "limit", items)

	// Truncate the index file first, the tail position is also considered
	// when calculating the new freezer table length.
	// 首先截断索引文件，尾部位置在计算新冷冻表长度时也会被考虑。
	length := items - t.itemOffset.Load() // 计算长度
	if err := truncateFreezerFile(t.index, int64(length+1)*indexEntrySize); err != nil {
		return err
	}
	if err := t.index.Sync(); err != nil {
		return err
	}
	// Calculate the new expected size of the data file and truncate it
	// 计算数据文件的新预期大小并截断
	var expected indexEntry
	if length == 0 {
		expected = indexEntry{filenum: t.tailId, offset: 0} // 为空时设置预期
	} else {
		buffer := make([]byte, indexEntrySize)
		if _, err := t.index.ReadAt(buffer, int64(length*indexEntrySize)); err != nil {
			return err
		}
		expected.unmarshalBinary(buffer) // 反序列化预期索引
	}
	// We might need to truncate back to older files
	// 可能需要截断到旧文件
	if expected.filenum != t.headId {
		// If already open for reading, force-reopen for writing
		// 如果已经以只读打开，则强制重新以可写模式打开
		t.releaseFile(expected.filenum)
		newHead, err := t.openFile(expected.filenum, openFreezerFileForAppend)
		if err != nil {
			return err
		}
		// Release any files _after the current head -- both the previous head
		// and any files which may have been opened for reading
		// 释放当前头部之前的任何文件，包括之前的头部和任何可能已打开的读取文件
		t.releaseFilesAfter(expected.filenum, true)

		// Set back the historic head
		// 设置历史头部
		t.head = newHead
		t.headId = expected.filenum
	}
	if err := truncateFreezerFile(t.head, int64(expected.offset)); err != nil {
		return err
	}
	if err := t.head.Sync(); err != nil {
		return err
	}
	// All data files truncated, set internal counters and return
	// 所有数据文件已截断，设置内部计数器并返回
	t.headBytes = int64(expected.offset)
	t.items.Store(items) // 更新该项数

	// Retrieve the new size and update the total size counter
	// 获取新大小并更新总大小计数器
	newSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	t.sizeGauge.Dec(int64(oldSize - newSize)) // 更新大小计量器
	return nil
}

// sizeHidden returns the total data size of hidden items in the freezer table.
// This function assumes the lock is already held.
// sizeHidden 返回冷冻表中隐藏项的总数据大小。此函数假定锁已被持有。
func (t *freezerTable) sizeHidden() (uint64, error) {
	hidden, offset := t.itemHidden.Load(), t.itemOffset.Load() // 加载隐藏项和偏移项
	if hidden <= offset {
		return 0, nil
	}
	indices, err := t.getIndices(hidden-1, 1) // 获取索引
	if err != nil {
		return 0, err
	}
	return uint64(indices[1].offset), nil // 返回偏移量
}

// truncateTail discards any recent data before the provided threshold number.
// truncateTail 丢弃提供阈值编号之前的任何最近数据。
func (t *freezerTable) truncateTail(items uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Ensure the given truncate target falls in the correct range
	// 确保给定的截断目标在正确范围内
	if t.itemHidden.Load() >= items {
		return nil
	}
	if t.items.Load() < items {
		return errors.New("truncation above head")
	}
	// Load the new tail index by the given new tail position
	// 根据给定的新尾部位置加载新的尾部索引
	var (
		newTailId uint32
		buffer    = make([]byte, indexEntrySize) // 为读取索引条目分配缓冲区
	)
	if t.items.Load() == items {
		newTailId = t.headId
	} else {
		offset := items - t.itemOffset.Load() // 计算偏移
		if _, err := t.index.ReadAt(buffer, int64((offset+1)*indexEntrySize)); err != nil {
			return err
		}
		var newTail indexEntry
		newTail.unmarshalBinary(buffer) // 反序列化新尾索引
		newTailId = newTail.filenum
	}
	// Save the old size for metrics tracking. This needs to be done
	// before any updates to either itemHidden or itemOffset.
	// 保存旧大小以进行指标跟踪
	oldSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	// Update the virtual tail marker and hidden these entries in table.
	// 更新虚拟尾标记并在表中隐藏这些条目
	t.itemHidden.Store(items) // 更新隐藏数目
	if err := writeMetadata(t.meta, newMetadata(items)); err != nil {
		return err
	}
	// Hidden items still fall in the current tail file, no data file
	// can be dropped.

	if t.tailId == newTailId {
		return nil
	}
	// Hidden items fall in the incorrect range, returns the error.
	// 隐藏项超出了不正确的范围，返回错误。
	if t.tailId > newTailId {
		return fmt.Errorf("invalid index, tail-file %d, item-file %d", t.tailId, newTailId)
	}
	// Count how many items can be deleted from the file.
	// 统计可以从文件中删除多少项。
	var (
		newDeleted = items
		deleted    = t.itemOffset.Load()
	)
	// Hidden items exceed the current tail file, drop the relevant data files.
	// 隐藏项超出当前尾部文件，删除相关数据文件。
	for current := items - 1; current >= deleted; current -= 1 {
		if _, err := t.index.ReadAt(buffer, int64((current-deleted+1)*indexEntrySize)); err != nil {
			return err
		}
		var pre indexEntry
		pre.unmarshalBinary(buffer)
		if pre.filenum != newTailId {
			break // 如果超出当前尾部文件，停止删除
		}
		newDeleted = current // 更新可删除项数
	}
	// Commit the changes of metadata file first before manipulating
	// the indexes file.
	// 在处理索引文件之前，首先提交元数据文件的更改。
	if err := t.meta.Sync(); err != nil {
		return err
	}
	// Close the index file before shorten it.
	// 在缩短索引文件之前关闭它。
	if err := t.index.Close(); err != nil {
		return err
	}
	// Truncate the deleted index entries from the index file.
	// 从索引文件中截断已删除的索引条目。
	err = copyFrom(t.index.Name(), t.index.Name(), indexEntrySize*(newDeleted-deleted+1), func(f *os.File) error {
		tailIndex := indexEntry{
			filenum: newTailId,
			offset:  uint32(newDeleted),
		}
		_, err := f.Write(tailIndex.append(nil)) // 在文件末尾添加尾部索引
		return err
	})
	if err != nil {
		return err
	}
	// Reopen the modified index file to load the changes
	// 重新打开修改后的索引文件以加载更改
	t.index, err = openFreezerFileForAppend(t.index.Name())
	if err != nil {
		return err
	}
	// Sync the file to ensure changes are flushed to disk
	// 同步文件以确保更改已写入磁盘
	if err := t.index.Sync(); err != nil {
		return err
	}
	// Release any files before the current tail
	// 释放当前尾部之前的任何文件
	t.tailId = newTailId
	t.itemOffset.Store(newDeleted) // 更新偏移量
	t.releaseFilesBefore(t.tailId, true)

	// Retrieve the new size and update the total size counter
	// 获取新大小并更新总大小计数器
	newSize, err := t.sizeNolock()
	if err != nil {
		return err
	}
	t.sizeGauge.Dec(int64(oldSize - newSize)) // 更新大小计量器
	return nil
}

// Close closes all opened files.
func (t *freezerTable) Close() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	var errs []error
	doClose := func(f *os.File, sync bool, close bool) {
		if sync && !t.readonly {
			if err := f.Sync(); err != nil {
				errs = append(errs, err)
			}
		}
		if close {
			if err := f.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// Trying to fsync a file opened in rdonly causes "Access denied"
	// error on Windows.
	// 在只读模式下打开文件尝试 fsync 会导致“访问被拒绝”错误
	doClose(t.index, true, true)
	doClose(t.meta, true, true)

	// The preopened non-head data-files are all opened in readonly.
	// The head is opened in rw-mode, so we sync it here - but since it's also
	// part of t.files, it will be closed in the loop below.
	// 之前打开的非头数据文件都是只读打开的。
	// 头文件以读写模式打开，因此在这里同步它 - 但由于它也是t.files的一部分，它将在下面的循环中关闭。
	doClose(t.head, true, false) // sync but do not close // 同步但不关闭

	for _, f := range t.files {
		doClose(f, false, true) // close but do not sync // 关闭但不同步
	}
	t.index = nil // 清空索引
	t.meta = nil  // 清空元数据
	t.head = nil  // 清空头文件

	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// openFile assumes that the write-lock is held by the caller
// openFile 假设调用者持有写锁
func (t *freezerTable) openFile(num uint32, opener func(string) (*os.File, error)) (f *os.File, err error) {
	var exist bool
	if f, exist = t.files[num]; !exist {
		var name string
		if t.noCompression {
			name = fmt.Sprintf("%s.%04d.rdat", t.name, num) // 原始数据文件名
		} else {
			name = fmt.Sprintf("%s.%04d.cdat", t.name, num) // 压缩数据文件名
		}
		f, err = opener(filepath.Join(t.path, name)) // 打开文件
		if err != nil {
			return nil, err
		}
		t.files[num] = f // 添加到文件映射
	}
	return f, err // 返回文件和错误
}

// releaseFile closes a file, and removes it from the open file cache.
// Assumes that the caller holds the write lock
// releaseFile 关闭文件并将其从打开的文件缓存中移除。
func (t *freezerTable) releaseFile(num uint32) {
	if f, exist := t.files[num]; exist {
		delete(t.files, num) // 从映射中删除文件
		f.Close()            // 关闭文件
	}
}

// releaseFilesAfter closes all open files with a higher number, and optionally also deletes the files
// releaseFilesAfter 关闭所有文件编号大于给定编号的文件，并可选择删除这些文件
func (t *freezerTable) releaseFilesAfter(num uint32, remove bool) {
	for fnum, f := range t.files {
		if fnum > num {
			delete(t.files, fnum) // 从映射中删除文件
			f.Close()             // 关闭文件
			if remove {
				os.Remove(f.Name()) // 删除文件
			}
		}
	}
}

// releaseFilesBefore closes all open files with a lower number, and optionally also deletes the files
// releaseFilesBefore 关闭所有文件编号小于给定编号的文件，并可选择删除这些文件
func (t *freezerTable) releaseFilesBefore(num uint32, remove bool) {
	for fnum, f := range t.files {
		if fnum < num {
			delete(t.files, fnum) // 从映射中删除文件
			f.Close()             // 关闭文件
			if remove {
				os.Remove(f.Name()) // 删除文件
			}
		}
	}
}

// getIndices returns the index entries for the given from-item, covering 'count' items.
// N.B: The actual number of returned indices for N items will always be N+1 (unless an
// error is returned).
// OBS: This method assumes that the caller has already verified (and/or trimmed) the range
// so that the items are within bounds. If this method is used to read out of bounds,
// it will return error.
//
// getIndices 返回给定项目的索引条目，覆盖 'count' 项。
// 注意：返回 N 项的实际索引数量将始终为 N+1（除非返回错误）。
// 注意：此方法假定调用者已验证（和/或修剪）范围，以确保项目在范围内。
// 如果此方法用于读取超出范围，它将返回错误。
func (t *freezerTable) getIndices(from, count uint64) ([]*indexEntry, error) {
	// Apply the table-offset
	// 应用表偏移
	from = from - t.itemOffset.Load() // 从当前项目偏移量中减去

	// For reading N items, we need N+1 indices.
	// 读取 N 项时，需要 N+1 个索引。
	buffer := make([]byte, (count+1)*indexEntrySize)
	if _, err := t.index.ReadAt(buffer, int64(from*indexEntrySize)); err != nil {
		return nil, err
	}
	var (
		indices []*indexEntry
		offset  int // 读取偏移量
	)
	for i := from; i <= from+count; i++ {
		index := new(indexEntry)               // 创建新索引条目
		index.unmarshalBinary(buffer[offset:]) // 反序列化索引
		offset += indexEntrySize               // 更新读取偏移量
		indices = append(indices, index)       // 添加索引条目到列表
	}
	if from == 0 {
		// Special case if we're reading the first item in the freezer. We assume that
		// the first item always start from zero(regarding the deletion, we
		// only support deletion by files, so that the assumption is held).
		// This means we can use the first item metadata to carry information about
		// the 'global' offset, for the deletion-case
		// 如果我们读取了冷冻存储中的第一个项目，则为特殊情况。
		// 我们假设第一个项目总是从零开始（关于删除，我们只支持按文件删除，所以这个假设成立）。
		// 这意味着我们可以使用第一个项目的元数据来携带有关全局偏移的信息，以便删除
		indices[0].offset = 0                   // 将它的偏移设置为零
		indices[0].filenum = indices[1].filenum // 将文件编号设置成下一个索引的文件编号
	}
	return indices, nil // 返回索引列表
}

// Retrieve looks up the data offset of an item with the given number and retrieves
// the raw binary blob from the data file.
// Retrieve 查找带有给定编号的项目的数据偏移，并从数据文件中检索原始二进制 blob。
func (t *freezerTable) Retrieve(item uint64) ([]byte, error) {
	items, err := t.RetrieveItems(item, 1, 0) // 检索单个项目
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

// RetrieveItems returns multiple items in sequence, starting from the index 'start'.
// It will return at most 'max' items, but will abort earlier to respect the
// 'maxBytes' argument. However, if the 'maxBytes' is smaller than the size of one
// item, it _will_ return one element and possibly overflow the maxBytes.
// RetrieveItems 连续返回多个项目，从索引 'start' 开始。
// 它最多将返回 'max' 项，但会提前中止以尊重 'maxBytes' 参数。
// 但是，如果 'maxBytes' 小于单个项目的大小，则它将返回一个元素，并可能溢出 maxBytes。
func (t *freezerTable) RetrieveItems(start, count, maxBytes uint64) ([][]byte, error) {
	// First we read the 'raw' data, which might be compressed.
	// 首先读取原始数据，可能会被压缩
	diskData, sizes, err := t.retrieveItems(start, count, maxBytes)
	if err != nil {
		return nil, err
	}
	var (
		output     = make([][]byte, 0, count) // 用于存储输出数据的切片
		offset     int                        // offset for reading 读取偏移量
		outputSize int                        // size of uncompressed data 已解压的总大小
	)
	// Now slice up the data and decompress.
	for i, diskSize := range sizes { // 遍历读取的大小
		item := diskData[offset : offset+diskSize] // 数据块
		offset += diskSize                         // 更新偏移量
		decompressedSize := diskSize               // 初始化解压的大小
		if !t.noCompression {
			decompressedSize, _ = snappy.DecodedLen(item) // 如果未禁用压缩，计算解压后的大小
		}
		if i > 0 && maxBytes != 0 && uint64(outputSize+decompressedSize) > maxBytes { // 如果超出最大字节数
			break // 打破循环
		}
		if !t.noCompression {
			data, err := snappy.Decode(nil, item) // 解压缩
			if err != nil {
				return nil, err
			}
			output = append(output, data) // 将解压数据添加到输出
		} else {
			output = append(output, item) // 直接添加已压缩的数据
		}
		outputSize += decompressedSize // 更新解压缩大小
	}
	return output, nil
}

// retrieveItems reads up to 'count' items from the table. It reads at least
// one item, but otherwise avoids reading more than maxBytes bytes. Freezer
// will ignore the size limitation and continuously allocate memory to store
// data if maxBytes is 0. It returns the (potentially compressed) data, and
// the sizes.
//
// retrieveItems 从表中读取最多 'count' 项。它至少读取一项，
// 但避免读取超过 maxBytes 字节。如果 maxBytes 为 0，
// 冷冻存储将忽略大小限制，并持续分配内存来存储数据。
// 它返回（可能被压缩的）数据和大小。
func (t *freezerTable) retrieveItems(start, count, maxBytes uint64) ([]byte, []int, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	// Ensure the table and the item are accessible
	// 确保表和项目可访问
	if t.index == nil || t.head == nil || t.meta == nil {
		return nil, nil, errClosed
	}
	var (
		items  = t.items.Load()      // the total items(head + 1) // 总项数（头部 + 1）
		hidden = t.itemHidden.Load() // the number of hidden items // 隐藏项的数量
	)
	// Ensure the start is written, not deleted from the tail, and that the
	// caller actually wants something
	// 确保起始项已写入，不是从尾部删除的项，并且调用者确实需要一些数据
	if items <= start || hidden > start || count == 0 {
		return nil, nil, errOutOfBounds
	}
	if start+count > items {
		count = items - start // 更新 count
	}
	var output []byte // Buffer to read data into // 用于存储输出数据
	if maxBytes != 0 {
		output = make([]byte, 0, maxBytes)
	} else {
		output = make([]byte, 0, 1024) // initial buffer cap // 初始化缓冲区
	}
	// readData is a helper method to read a single data item from disk.
	// readData 是一个帮助函数，用于从磁盘读取单个数据项。
	readData := func(fileId, start uint32, length int) error {
		output = grow(output, length)      // 增长输出缓冲区
		dataFile, exist := t.files[fileId] // 获取数据文件
		if !exist {
			return fmt.Errorf("missing data file %d", fileId)
		}
		if _, err := dataFile.ReadAt(output[len(output)-length:], int64(start)); err != nil {
			return fmt.Errorf("%w, fileid: %d, start: %d, length: %d", err, fileId, start, length)
		}
		return nil
	}
	// Read all the indexes in one go
	// 一次读取所有索引
	indices, err := t.getIndices(start, count)
	if err != nil {
		return nil, nil, err
	}
	var (
		sizes      []int               // The sizes for each element // 用于存储每个元素的大小
		totalSize  = 0                 // The total size of all data read so far // 到目前为止已读取的所有数据的总大小
		readStart  = indices[0].offset // Where, in the file, to start reading // 从哪一点开始读取
		unreadSize = 0                 // The size of the as-yet-unread data  // 作为未读数据的大小
	)

	for i, firstIndex := range indices[:len(indices)-1] {
		secondIndex := indices[i+1]
		// Determine the size of the item.
		// 确定项的大小
		offset1, offset2, _ := firstIndex.bounds(secondIndex)
		size := int(offset2 - offset1)
		// Crossing a file boundary?
		// 跨越文件边界？
		if secondIndex.filenum != firstIndex.filenum {
			// If we have unread data in the first file, we need to do that read now.
			// 如果在第一个文件中有未读数据，现在需要读取
			if unreadSize > 0 {
				if err := readData(firstIndex.filenum, readStart, unreadSize); err != nil {
					return nil, nil, err
				}
				unreadSize = 0
			}
			readStart = 0
		}
		if i > 0 && uint64(totalSize+size) > maxBytes && maxBytes != 0 {
			// About to break out due to byte limit being exceeded. We don't
			// read this last item, but we need to do the deferred reads now.
			// 因为超过最大字节限制，即将中断。我们不读取最后一项，但需要立即进行延迟读取。
			if unreadSize > 0 {
				if err := readData(secondIndex.filenum, readStart, unreadSize); err != nil {
					return nil, nil, err
				}
			}
			break
		}
		// Defer the read for later
		// 延迟读取
		unreadSize += size          // 更新未读大小
		totalSize += size           // 更新已读大小
		sizes = append(sizes, size) // 将大小添加到列表
		if i == len(indices)-2 || (uint64(totalSize) > maxBytes && maxBytes != 0) {
			// Last item, need to do the read now
			// 最后一个项目，现在需要读取
			if err := readData(secondIndex.filenum, readStart, unreadSize); err != nil {
				return nil, nil, err
			}
			break
		}
	}

	// Update metrics.
	// 更新指标
	t.readMeter.Mark(int64(totalSize)) // 更新读取计量器
	return output, sizes, nil
}

// has returns an indicator whether the specified number data is still accessible
// in the freezer table.
// has 返回指示给定编号数据是否仍可在冷冻表中访问。
func (t *freezerTable) has(number uint64) bool {
	return t.items.Load() > number && t.itemHidden.Load() <= number // 根据条件返回布尔值
}

// size returns the total data size in the freezer table.
// size 返回冷冻表中的数据总大小。
func (t *freezerTable) size() (uint64, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.sizeNolock() // 返回无锁大小
}

// sizeNolock returns the total data size in the freezer table. This function
// assumes the lock is already held.
// sizeNolock 返回冷冻表中的数据总大小。此函数假设锁已经被持有。
func (t *freezerTable) sizeNolock() (uint64, error) {
	stat, err := t.index.Stat() // 检索索引状态
	if err != nil {
		return 0, err
	}
	hidden, err := t.sizeHidden() // 检索隐藏的大小
	if err != nil {
		return 0, err
	}
	total := uint64(t.maxFileSize)*uint64(t.headId-t.tailId) + uint64(t.headBytes) + uint64(stat.Size()) - hidden // 计算总大小
	return total, nil                                                                                             // 返回总大小
}

// advanceHead should be called when the current head file would outgrow the file limits,
// and a new file must be opened. The caller of this method must hold the write-lock
// before calling this method.
// advanceHead 当当前头文件超过文件限制时，应调用该方法，必须打开新的文件。
// 调用此方法的调用者必须持有写锁定。
func (t *freezerTable) advanceHead() error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// We open the next file in truncated mode -- if this file already
	// exists, we need to start over from scratch on it.
	// 我们以截断模式打开下一个文件 - 如果该文件已经存在，则需要从头开始。
	nextID := t.headId + 1                                       // 新文件编号
	newHead, err := t.openFile(nextID, openFreezerFileTruncated) // 打开新文件
	if err != nil {
		return err
	}
	// Commit the contents of the old file to stable storage and
	// tear it down. It will be re-opened in read-only mode.
	// 提交旧文件的内容到稳定存储并拆除。它将以只读模式重新打开。
	if err := t.head.Sync(); err != nil {
		return err
	}
	t.releaseFile(t.headId)                          // 释放旧文件
	t.openFile(t.headId, openFreezerFileForReadOnly) // 只读打开文件

	// Swap out the current head.
	// 交换当前头部
	t.head = newHead
	t.headBytes = 0   // 重置头部字节数
	t.headId = nextID // 更新头文件编号
	return nil
}

// Sync pushes any pending data from memory out to disk. This is an expensive
// operation, so use it with care.
// Sync 将内存中的任何待处理数据推送到磁盘。这是一个昂贵的操作，因此使用时要小心。
func (t *freezerTable) Sync() error {
	t.lock.Lock()
	defer t.lock.Unlock()
	if t.index == nil || t.head == nil || t.meta == nil {
		return errClosed
	}
	var err error
	trackError := func(e error) {
		if e != nil && err == nil {
			err = e
		}
	}

	trackError(t.index.Sync()) // 同步索引文件
	trackError(t.meta.Sync())  // 同步元数据文件
	trackError(t.head.Sync())  // 同步头文件
	return err
}

func (t *freezerTable) dumpIndexStdout(start, stop int64) {
	t.dumpIndex(os.Stdout, start, stop) // 以 stdout 输出索引
}

// dumpIndexString 将该冷冻表的索引转储到字符串。
func (t *freezerTable) dumpIndexString(start, stop int64) string {
	var out bytes.Buffer // 创建字节缓冲区
	out.WriteString("\n")
	t.dumpIndex(&out, start, stop) // 调用输出方法
	return out.String()            // 返回字符串
}

// dumpIndex 将该冷冻表的索引输出到提供的写入工具中。
func (t *freezerTable) dumpIndex(w io.Writer, start, stop int64) {
	meta, err := readMetadata(t.meta)
	if err != nil {
		fmt.Fprintf(w, "Failed to decode freezer table %v\n", err)
		return
	}
	fmt.Fprintf(w, "Version %d count %d, deleted %d, hidden %d\n", meta.Version,
		t.items.Load(), t.itemOffset.Load(), t.itemHidden.Load()) // 输出元数据统计信息

	buf := make([]byte, indexEntrySize) // 创建缓冲区

	fmt.Fprintf(w, "| number | fileno | offset |\n") // 输出表头
	fmt.Fprintf(w, "|--------|--------|--------|\n") // 输出分隔线

	for i := uint64(start); ; i++ { // 从 start 开始迭代
		if _, err := t.index.ReadAt(buf, int64((i+1)*indexEntrySize)); err != nil {
			break // 结束循环
		}
		var entry indexEntry
		entry.unmarshalBinary(buf)                                                           // 反序列化条目
		fmt.Fprintf(w, "|  %03d   |  %03d   |  %03d   | \n", i, entry.filenum, entry.offset) // 输出条目信息
		if stop > 0 && i >= uint64(stop) {
			break
		}
	}
	fmt.Fprintf(w, "|--------------------------|\n") // 输出结束标志
}
