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
	"io"
	"os"
	"path/filepath"
)

// Freezer 数据管理：
// Freezer 是以太坊 geth 的一种存储机制，用于存储不常使用的旧区块和状态数据。
// copyFrom 的设计可以用于 Freezer 数据文件的管理，比如合并多段数据文件或分块读取后重组。
// 区块重载/修复：在数据恢复或区块链同步时，可以利用 copyFrom 复制数据到修正后的目标路径。

// copyFrom copies data from 'srcPath' at offset 'offset' into 'destPath'.
// The 'destPath' is created if it doesn't exist, otherwise it is overwritten.
// Before the copy is executed, there is a callback can be registered to
// manipulate the dest file.
// It is perfectly valid to have destPath == srcPath.
//
// copyFrom 从 'srcPath' 的偏移量 'offset' 开始读取数据，复制到 'destPath' 中。
// 如果 'destPath' 文件不存在，则创建新文件；如果存在，则覆盖旧文件。
// 在复制数据前，可以注册一个回调函数 'before'，用于操作目标文件。
// 允许 srcPath 和 destPath 指向同一文件。
func copyFrom(srcPath, destPath string, offset uint64, before func(f *os.File) error) error {
	// Create a temp file in the same dir where we want it to wind up
	// 在目标目录中创建一个临时文件
	f, err := os.CreateTemp(filepath.Dir(destPath), "*")
	if err != nil {
		return err
	}
	fname := f.Name()

	// Clean up the leftover file
	// 清理临时文件
	defer func() {
		if f != nil {
			f.Close()
		}
		os.Remove(fname)
	}()
	// Apply the given function if it's not nil before we copy
	// the content from the src.
	// 在复制内容前，如果指定了回调函数，则应用它
	if before != nil {
		if err := before(f); err != nil {
			return err
		}
	}
	// Open the source file
	// 打开源文件
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	// 从源文件的偏移位置开始读取数据
	if _, err = src.Seek(int64(offset), 0); err != nil {
		src.Close()
		return err
	}
	// io.Copy uses 32K buffer internally.
	// 通过 io.Copy 将数据从源文件复制到目标临时文件中（内部使用 32K 缓冲区）
	_, err = io.Copy(f, src)
	if err != nil {
		src.Close()
		return err
	}
	// Rename the temporary file to the specified dest name.
	// src may be same as dest, so needs to be closed before
	// we do the final move.
	// 将临时文件重命名为目标文件名称
	src.Close()

	if err := f.Close(); err != nil {
		return err
	}
	f = nil
	return os.Rename(fname, destPath)
}

// Freezer 表文件简介
// Freezer 是以太坊中设计用于归档区块数据的模块，它通过表文件管理区块头、区块体和状态数据。Freezer 数据是追加写入的，且文件顺序非常严格。
//
// openFreezerFileForAppend：
// 以追加模式打开文件，并将指针移动到文件末尾，便于追加最新数据。
// 在追加操作中需要防止 O_APPEND 标志影响文件的截断操作，因为不同操作系统对此行为的实现不同。
//
// openFreezerFileForReadOnly：
// 以只读模式打开 Freezer 表文件，用于查询和分析离线存储的数据。
//
// openFreezerFileTruncated 和 truncateFreezerFile:
// 配合使用以清空或调整表文件大小，例如删除旧数据或恢复损坏的文件。
// 在区块链分叉后重写状态快照时非常有用。

// openFreezerFileForAppend opens a freezer table file and seeks to the end
// openFreezerFileForAppend 打开一个 freezer 表文件并将偏移设置到文件末尾，以便进行附加操作。
func openFreezerFileForAppend(filename string) (*os.File, error) {
	// Open the file without the O_APPEND flag
	// because it has differing behaviour during Truncate operations
	// on different OS's
	// 以非 O_APPEND 模式打开文件，因为在不同操作系统上 Truncate 操作行为有所不同
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	// Seek to end for append
	// 将文件指针移动到文件末尾
	if _, err = file.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return file, nil
}

// openFreezerFileForReadOnly opens a freezer table file for read only access
// openFreezerFileForReadOnly 以只读模式打开一个 freezer 表文件
func openFreezerFileForReadOnly(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_RDONLY, 0644)
}

// openFreezerFileTruncated opens a freezer table making sure it is truncated
// openFreezerFileTruncated 打开一个 freezer 表文件并将其内容清空 (Truncate)
func openFreezerFileTruncated(filename string) (*os.File, error) {
	return os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
}

// truncateFreezerFile resizes a freezer table file and seeks to the end
// truncateFreezerFile 调整 freezer 表文件的大小，并将文件指针移动到文件末尾
func truncateFreezerFile(file *os.File, size int64) error {
	if err := file.Truncate(size); err != nil {
		return err
	}
	// Seek to end for append
	// 将文件指针移动到文件末尾
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// grow prepares the slice space for new item, and doubles the slice capacity
// if space is not enough.
// grow 为切片扩展容量。如果容量不足，则容量自动翻倍。
func grow(buf []byte, n int) []byte {
	if cap(buf)-len(buf) < n {
		newcap := 2 * cap(buf)
		if newcap-len(buf) < n {
			newcap = len(buf) + n
		}
		nbuf := make([]byte, len(buf), newcap)
		copy(nbuf, buf)
		buf = nbuf
	}
	buf = buf[:len(buf)+n]
	return buf
}
