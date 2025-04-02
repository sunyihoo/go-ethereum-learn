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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/gofrs/flock"
)

var (
	// errReadOnly is returned if the freezer is opened in read only mode. All the
	// mutations are disallowed.
	// errReadOnly 如果 freezer 以只读模式打开，则返回。所有修改操作均不允许。
	errReadOnly = errors.New("read only")

	// errUnknownTable is returned if the user attempts to read from a table that is
	// not tracked by the freezer.
	// errUnknownTable 如果用户尝试从 freezer 未跟踪的表中读取，则返回。
	errUnknownTable = errors.New("unknown table")

	// errOutOrderInsertion is returned if the user attempts to inject out-of-order
	// binary blobs into the freezer.
	// errOutOrderInsertion 如果用户尝试将乱序的二进制 blob 注入 freezer，则返回。
	errOutOrderInsertion = errors.New("the append operation is out-order")

	// errSymlinkDatadir is returned if the ancient directory specified by user
	// is a symbolic link.
	// errSymlinkDatadir 如果用户指定的 ancient 目录是符号链接，则返回。
	errSymlinkDatadir = errors.New("symbolic link datadir is not supported")
)

// freezerTableSize defines the maximum size of freezer data files.
// freezerTableSize 定义 freezer 数据文件的最大大小。
const freezerTableSize = 2 * 1000 * 1000 * 1000

// Freezer is an append-only database to store immutable ordered data into
// flat files:
//
// - The append-only nature ensures that disk writes are minimized.
// - The in-order data ensures that disk reads are always optimized.
//
// Freezer 是一个仅追加的数据库，用于将不可变的有序数据存储到平面文件中：
//
// - 仅追加的特性确保磁盘写入最小化。
// - 有序数据确保磁盘读取始终优化。
type Freezer struct {
	datadir string
	frozen  atomic.Uint64 // Number of items already frozen
	tail    atomic.Uint64 // Number of the first stored item in the freezer

	// This lock synchronizes writers and the truncate operation, as well as
	// the "atomic" (batched) read operations.
	// 此锁同步写入者和截断操作，以及“原子”（批量）读取操作。
	writeLock  sync.RWMutex
	writeBatch *freezerBatch

	readonly     bool
	tables       map[string]*freezerTable // Data tables for storing everything
	instanceLock *flock.Flock             // File-system lock to prevent double opens
	closeOnce    sync.Once
}

// NewFreezer creates a freezer instance for maintaining immutable ordered
// data according to the given parameters.
//
// The 'tables' argument defines the data tables. If the value of a map
// entry is true, snappy compression is disabled for the table.
//
// NewFreezer 根据给定参数创建 freezer 实例，用于维护不可变的有序数据。
//
// 'tables' 参数定义数据表。如果映射条目的值为 true，则禁用该表的 snappy 压缩。
func NewFreezer(datadir string, namespace string, readonly bool, maxTableSize uint32, tables map[string]bool) (*Freezer, error) {
	// Create the initial freezer object
	// 创建初始 freezer 对象
	var (
		readMeter  = metrics.NewRegisteredMeter(namespace+"ancient/read", nil)
		writeMeter = metrics.NewRegisteredMeter(namespace+"ancient/write", nil)
		sizeGauge  = metrics.NewRegisteredGauge(namespace+"ancient/size", nil)
	)
	// Ensure the datadir is not a symbolic link if it exists.
	// 确保 datadir（如果存在）不是符号链接。
	if info, err := os.Lstat(datadir); !os.IsNotExist(err) {
		if info == nil {
			log.Warn("Could not Lstat the database", "path", datadir)
			return nil, errors.New("lstat failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			log.Warn("Symbolic link ancient database is not supported", "path", datadir)
			return nil, errSymlinkDatadir
		}
	}
	flockFile := filepath.Join(datadir, "FLOCK")
	if err := os.MkdirAll(filepath.Dir(flockFile), 0755); err != nil {
		return nil, err
	}
	// Leveldb uses LOCK as the filelock filename. To prevent the
	// name collision, we use FLOCK as the lock name.
	// Leveldb 使用 LOCK 作为文件锁文件名。为防止名称冲突，我们使用 FLOCK 作为锁名。
	lock := flock.New(flockFile)
	tryLock := lock.TryLock
	if readonly {
		tryLock = lock.TryRLock
	}
	if locked, err := tryLock(); err != nil {
		return nil, err
	} else if !locked {
		return nil, errors.New("locking failed")
	}
	// Open all the supported data tables
	// 打开所有支持的数据表
	freezer := &Freezer{
		datadir:      datadir,
		readonly:     readonly,
		tables:       make(map[string]*freezerTable),
		instanceLock: lock,
	}

	// Create the tables.
	// 创建表
	for name, disableSnappy := range tables {
		table, err := newTable(datadir, name, readMeter, writeMeter, sizeGauge, maxTableSize, disableSnappy, readonly)
		if err != nil {
			for _, table := range freezer.tables {
				table.Close()
			}
			lock.Unlock()
			return nil, err
		}
		freezer.tables[name] = table
	}
	var err error
	if freezer.readonly {
		// In readonly mode only validate, don't truncate.
		// validate also sets `freezer.frozen`.
		// 在只读模式下，仅验证，不截断。
		// validate 还会设置 `freezer.frozen`。
		err = freezer.validate()
	} else {
		// Truncate all tables to common length.
		// 将所有表截断到共同长度。
		err = freezer.repair()
	}
	if err != nil {
		for _, table := range freezer.tables {
			table.Close()
		}
		lock.Unlock()
		return nil, err
	}

	// Create the write batch.
	// 创建写入批处理
	freezer.writeBatch = newFreezerBatch(freezer)

	log.Info("Opened ancient database", "database", datadir, "readonly", readonly)
	return freezer, nil
}

// Close terminates the chain freezer, closing all the data files.
// Close 终止 chain freezer，关闭所有数据文件。
func (f *Freezer) Close() error {
	f.writeLock.Lock()
	defer f.writeLock.Unlock()

	var errs []error
	f.closeOnce.Do(func() {
		for _, table := range f.tables {
			if err := table.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if err := f.instanceLock.Unlock(); err != nil {
			errs = append(errs, err)
		}
	})
	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// AncientDatadir returns the path of the ancient store.
// AncientDatadir 返回 ancient 存储的路径。
func (f *Freezer) AncientDatadir() (string, error) {
	return f.datadir, nil
}

// HasAncient returns an indicator whether the specified ancient data exists
// in the freezer.
// HasAncient 返回指定 ancient 数据是否存在于 freezer 中的指示器。
func (f *Freezer) HasAncient(kind string, number uint64) (bool, error) {
	if table := f.tables[kind]; table != nil {
		return table.has(number), nil
	}
	return false, nil
}

// Ancient retrieves an ancient binary blob from the append-only immutable files.
// Ancient 从仅追加的不可变文件中检索 ancient 二进制 blob。
func (f *Freezer) Ancient(kind string, number uint64) ([]byte, error) {
	if table := f.tables[kind]; table != nil {
		return table.Retrieve(number)
	}
	return nil, errUnknownTable
}

// AncientRange retrieves multiple items in sequence, starting from the index 'start'.
// It will return
//   - at most 'count' items,
//   - if maxBytes is specified: at least 1 item (even if exceeding the maxByteSize),
//     but will otherwise return as many items as fit into maxByteSize.
//   - if maxBytes is not specified, 'count' items will be returned if they are present.
//
// AncientRange 从索引 'start' 开始，检索多个连续的项。
// 它将返回：
//   - 最多 'count' 个项，
//   - 如果指定了 maxBytes：至少 1 个项（即使超过 maxByteSize），
//     否则返回适合 maxByteSize 的尽可能多的项。
//   - 如果未指定 maxBytes，如果存在，则返回 'count' 个项。
func (f *Freezer) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	if table := f.tables[kind]; table != nil {
		return table.RetrieveItems(start, count, maxBytes)
	}
	return nil, errUnknownTable
}

// Ancients returns the length of the frozen items.
// Ancients 返回已冻结项的长度。
func (f *Freezer) Ancients() (uint64, error) {
	return f.frozen.Load(), nil
}

// Tail returns the number of first stored item in the freezer.
// Tail 返回 freezer 中第一个存储项的编号。
func (f *Freezer) Tail() (uint64, error) {
	return f.tail.Load(), nil
}

// AncientSize returns the ancient size of the specified category.
// AncientSize 返回指定类别的 ancient 大小。
func (f *Freezer) AncientSize(kind string) (uint64, error) {
	// This needs the write lock to avoid data races on table fields.
	// Speed doesn't matter here, AncientSize is for debugging.
	// 这需要写锁以避免表字段上的数据竞争。
	// 速度在这里不重要，AncientSize 用于调试。
	f.writeLock.RLock()
	defer f.writeLock.RUnlock()

	if table := f.tables[kind]; table != nil {
		return table.size()
	}
	return 0, errUnknownTable
}

// ReadAncients runs the given read operation while ensuring that no writes take place
// on the underlying freezer.
// ReadAncients 运行给定的读取操作，同时确保在底层 freezer 上不发生写入。
func (f *Freezer) ReadAncients(fn func(ethdb.AncientReaderOp) error) (err error) {
	f.writeLock.RLock()
	defer f.writeLock.RUnlock()

	return fn(f)
}

// ModifyAncients runs the given write operation.
// ModifyAncients 运行给定的写入操作。
func (f *Freezer) ModifyAncients(fn func(ethdb.AncientWriteOp) error) (writeSize int64, err error) {
	if f.readonly {
		return 0, errReadOnly
	}
	f.writeLock.Lock()
	defer f.writeLock.Unlock()

	// Roll back all tables to the starting position in case of error.
	// 如果发生错误，将所有表回滚到起始位置。
	prevItem := f.frozen.Load()
	defer func() {
		if err != nil {
			// The write operation has failed. Go back to the previous item position.
			// 写入操作失败。回到之前的项位置。
			for name, table := range f.tables {
				err := table.truncateHead(prevItem)
				if err != nil {
					log.Error("Freezer table roll-back failed", "table", name, "index", prevItem, "err", err)
				}
			}
		}
	}()

	f.writeBatch.reset()
	if err := fn(f.writeBatch); err != nil {
		return 0, err
	}
	item, writeSize, err := f.writeBatch.commit()
	if err != nil {
		return 0, err
	}
	f.frozen.Store(item)
	return writeSize, nil
}

// TruncateHead discards any recent data above the provided threshold number.
// It returns the previous head number.
// TruncateHead 丢弃提供的阈值编号以上的任何最近数据。
// 它返回先前的头部编号。
func (f *Freezer) TruncateHead(items uint64) (uint64, error) {
	if f.readonly {
		return 0, errReadOnly
	}
	f.writeLock.Lock()
	defer f.writeLock.Unlock()

	oitems := f.frozen.Load()
	if oitems <= items {
		return oitems, nil
	}
	for _, table := range f.tables {
		if err := table.truncateHead(items); err != nil {
			return 0, err
		}
	}
	f.frozen.Store(items)
	return oitems, nil
}

// TruncateTail discards any recent data below the provided threshold number.
// TruncateTail 丢弃提供的阈值编号以下的任何最近数据。
func (f *Freezer) TruncateTail(tail uint64) (uint64, error) {
	if f.readonly {
		return 0, errReadOnly
	}
	f.writeLock.Lock()
	defer f.writeLock.Unlock()

	old := f.tail.Load()
	if old >= tail {
		return old, nil
	}
	for _, table := range f.tables {
		if err := table.truncateTail(tail); err != nil {
			return 0, err
		}
	}
	f.tail.Store(tail)
	return old, nil
}

// Sync flushes all data tables to disk.
// Sync 将所有数据表刷新到磁盘。
func (f *Freezer) Sync() error {
	var errs []error
	for _, table := range f.tables {
		if err := table.Sync(); err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// validate checks that every table has the same boundary.
// Used instead of `repair` in readonly mode.
// validate 检查每个表是否具有相同的边界。
// 在只读模式下使用，代替 `repair`。
func (f *Freezer) validate() error {
	if len(f.tables) == 0 {
		return nil
	}
	var (
		head uint64
		tail uint64
		name string
	)
	// Hack to get boundary of any table
	// 技巧：获取任意表的边界
	for kind, table := range f.tables {
		head = table.items.Load()
		tail = table.itemHidden.Load()
		name = kind
		break
	}
	// Now check every table against those boundaries.
	// 现在根据这些边界检查每个表。
	for kind, table := range f.tables {
		if head != table.items.Load() {
			return fmt.Errorf("freezer tables %s and %s have differing head: %d != %d", kind, name, table.items.Load(), head)
		}
		if tail != table.itemHidden.Load() {
			return fmt.Errorf("freezer tables %s and %s have differing tail: %d != %d", kind, name, table.itemHidden.Load(), tail)
		}
	}
	f.frozen.Store(head)
	f.tail.Store(tail)
	return nil
}

// repair truncates all data tables to the same length.
// repair 将所有数据表截断到相同的长度。
func (f *Freezer) repair() error {
	var (
		head = uint64(math.MaxUint64)
		tail = uint64(0)
	)
	for _, table := range f.tables {
		items := table.items.Load()
		if head > items {
			head = items
		}
		hidden := table.itemHidden.Load()
		if hidden > tail {
			tail = hidden
		}
	}
	for _, table := range f.tables {
		if err := table.truncateHead(head); err != nil {
			return err
		}
		if err := table.truncateTail(tail); err != nil {
			return err
		}
	}
	f.frozen.Store(head)
	f.tail.Store(tail)
	return nil
}
