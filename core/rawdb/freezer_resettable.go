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

package rawdb

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// 临时目录后缀
const tmpSuffix = ".tmp"

// freezerOpenFunc is the function used to open/create a freezer.
// freezerOpenFunc 是用于打开/创建 Freezer 的函数类型。
type freezerOpenFunc = func() (*Freezer, error)

// resettableFreezer is a wrapper of the freezer which makes the
// freezer resettable.
// resettableFreezer 是 freezer 的包装器，使得 freezer 可以被重置。
type resettableFreezer struct {
	readOnly bool            // 是否是只读模式
	freezer  *Freezer        // 实际的 Freezer 实例
	opener   freezerOpenFunc // 用于创建/打开 Freezer 的函数
	datadir  string          // 数据目录路径
	lock     sync.RWMutex    // 读写锁，用于并发安全
}

// newResettableFreezer creates a resettable freezer, note freezer is
// only resettable if the passed file directory is exclusively occupied
// by the freezer. And also the user-configurable ancient root directory
// is **not** supported for reset since it might be a mount and rename
// will cause a copy of hundreds of gigabyte into local directory. It
// needs some other file based solutions.
//
// The reset function will delete directory atomically and re-create the
// freezer from scratch.
//
// newResettableFreezer 创建一个可重置的 freezer。
// 注意：freezer 只在专有文件目录下可被重置。
// 用户配置的“ancient root”目录不被支持，因为它可能是挂载文件系统，执行重命名操作可能导致
// 数百 GB 的数据被复制到本地目录中。
func newResettableFreezer(datadir string, namespace string, readonly bool, maxTableSize uint32, tables map[string]bool) (*resettableFreezer, error) {
	// 清理数据目录中的临时文件
	if err := cleanup(datadir); err != nil {
		return nil, err
	}
	// 定义 Freezer 打开函数
	opener := func() (*Freezer, error) {
		return NewFreezer(datadir, namespace, readonly, maxTableSize, tables)
	}
	// 打开 Freezer
	freezer, err := opener()
	if err != nil {
		return nil, err
	}
	return &resettableFreezer{
		readOnly: readonly,
		freezer:  freezer,
		opener:   opener,
		datadir:  datadir,
	}, nil
}

// Reset deletes the file directory exclusively occupied by the freezer and
// recreate the freezer from scratch. The atomicity of directory deletion
// is guaranteed by the rename operation, the leftover directory will be
// cleaned up in next startup in case crash happens after rename.
//
// Reset 删除被 freezer 占用的文件目录，并从头开始重建 freezer。
// 通过重命名操作保证目录删除的原子性。如果在重命名后发生崩溃，遗留目录将在下次启动时被清除。
func (f *resettableFreezer) Reset() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.readOnly { // 只读模式下禁止 Reset 操作
		return errReadOnly
	}
	// 关闭当前 Freezer
	if err := f.freezer.Close(); err != nil {
		return err
	}
	// 将当前数据目录重命名为临时目录
	tmp := tmpName(f.datadir)
	if err := os.Rename(f.datadir, tmp); err != nil {
		return err
	}
	// 删除临时目录，用于清理原有数据
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	// 重新打开一个新的 Freezer
	freezer, err := f.opener()
	if err != nil {
		return err
	}
	f.freezer = freezer
	return nil
}

// Close terminates the chain freezer, unmapping all the data files.
// Close 关闭链 freezer，并解除所有数据文件的映射。
func (f *resettableFreezer) Close() error {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.Close()
}

// HasAncient returns an indicator whether the specified ancient data exists
// in the freezer
// HasAncient 返回指定的“古老数据”是否存在于 freezer 中。
func (f *resettableFreezer) HasAncient(kind string, number uint64) (bool, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.HasAncient(kind, number)
}

// Ancient retrieves an ancient binary blob from the append-only immutable files.
// Ancient 从“只追加”的不可变文件中检索“古老的二进制数据块”。
func (f *resettableFreezer) Ancient(kind string, number uint64) ([]byte, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.Ancient(kind, number)
}

// Freezer 的数据存储按顺序写入，每次追加是不可变的，所以读取时效率极高。通过按块范围读取多个条目，可以优化对于历史数据访问的性能，例如快速同步 (Fast Sync) 或验证历史区块。

// AncientRange retrieves multiple items in sequence, starting from the index 'start'.
// It will return
//   - at most 'count' items,
//   - if maxBytes is specified: at least 1 item (even if exceeding the maxByteSize),
//     but will otherwise return as many items as fit into maxByteSize.
//   - if maxBytes is not specified, 'count' items will be returned if they are present.
//
// AncientRange 按顺序检索多个条目，从索引 `start` 开始。
// 它将返回：
//   - 最多 'count' 个条目；
//   - 如果指定了 `maxBytes`，返回至少一个条目（即使超过了 `maxBytes` 限制），
//     否则返回尽可能多条目（总大小不超过 `maxBytes`）。
//   - 如果没有指定 `maxBytes`，将返回最多 `count` 个条目（如果存在）。
//
// 返回的结果是一个二维字节数组（[][]byte），每一项代表从 Freezer 中读取的历史条目。
// 针对特定存储类别（kind），可以检索多个块头、块体或状态数据。
func (f *resettableFreezer) AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.AncientRange(kind, start, count, maxBytes)
}

// Ancients returns the length of the frozen items.
// Ancients 返回 Freezer 中冻结的条目数量。
// 用于统计 Freezer 存储的头、体和其他古老条目的数量，用来动态调整存储容量或运行状态。
func (f *resettableFreezer) Ancients() (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.Ancients()
}

// Tail returns the number of first stored item in the freezer.
// Tail 返回 Freezer 中存储的第一个条目的编号。
// Freezer 中较早的条目会被逻辑清除，因此 Tail 提供的编号可以被用来检测数据是否符合释放策略。
func (f *resettableFreezer) Tail() (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.Tail()
}

// AncientSize returns the ancient size of the specified category.
// AncientSize 返回指定类别“古老数据”的总字节大小。
// AncientSize 返回 Freezer 中指定类别（kind）的冻结数据总大小。
func (f *resettableFreezer) AncientSize(kind string) (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.AncientSize(kind)
}

// ReadAncients runs the given read operation while ensuring that no writes take place
// on the underlying freezer.
// ReadAncients 在确保底层 Freezer 没有写操作的情况下运行给定的读取操作。
func (f *resettableFreezer) ReadAncients(fn func(ethdb.AncientReaderOp) error) (err error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.ReadAncients(fn)
}

// ModifyAncients runs the given write operation.
// ModifyAncients 运行给定的写入操作。
// 添加或修改特定历史数据，例如区块内的数据校正或完整性修复。
func (f *resettableFreezer) ModifyAncients(fn func(ethdb.AncientWriteOp) error) (writeSize int64, err error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.ModifyAncients(fn)
}

// TruncateHead discards any recent data above the provided threshold number.
// It returns the previous head number.
// TruncateHead 丢弃高于指定阈值的最近数据。
// 返回先前的数据头编号。
func (f *resettableFreezer) TruncateHead(items uint64) (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.TruncateHead(items)
}

// TruncateTail discards any recent data below the provided threshold number.
// It returns the previous value
// TruncateTail 丢弃低于指定阈值的最近数据。
// 返回先前的数据尾编号。
func (f *resettableFreezer) TruncateTail(tail uint64) (uint64, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.TruncateTail(tail)
}

// Sync flushes all data tables to disk.
// Sync 将所有数据表刷新到磁盘。
func (f *resettableFreezer) Sync() error {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.Sync()
}

// AncientDatadir returns the path of the ancient store.
// AncientDatadir 返回存储 Freezer 数据的路径。
func (f *resettableFreezer) AncientDatadir() (string, error) {
	f.lock.RLock()
	defer f.lock.RUnlock()

	return f.freezer.AncientDatadir()
}

// cleanup removes the directory located in the specified path
// has the name with deletion marker suffix.
// cleanup 移除带有临时删除标记后缀的目录。
func cleanup(path string) error {
	// 检查上级目录是否存在
	parent := filepath.Dir(path)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		return nil
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(0)
	if err != nil {
		return err
	}
	if cerr := dir.Close(); cerr != nil {
		return cerr
	}
	for _, name := range names {
		// 检查是否存在临时目录（带 `.tmp` 后缀）
		if name == filepath.Base(path)+tmpSuffix {
			log.Info("Removed leftover freezer directory", "name", name)
			return os.RemoveAll(filepath.Join(parent, name))
		}
	}
	return nil
}

// tmpName 为指定路径生成临时目录名称。
func tmpName(path string) string {
	return filepath.Join(filepath.Dir(path), filepath.Base(path)+tmpSuffix)
}
