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

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// freezerVersion 是 freezer 表元数据的初始版本号。
const freezerVersion = 1 // The initial version tag of freezer table metadata

// Freezer 的元数据概念
// Freezer 是以太坊用来存储历史区块数据的只追加（append-only）存储，主要用于优化存储性能并减少冗余。
// 这些数据包括块头（block headers）、块体（block bodies）和状态差异（state diffs）。

// freezerTableMeta 封装了 freezer 表的所有元数据。
// freezerTableMeta wraps all the metadata of the freezer table.
type freezerTableMeta struct {
	// Version 是 freezer 表的版本描述符。
	// Version is the versioning descriptor of the freezer table.
	Version uint16

	// VirtualTail indicates how many items have been marked as deleted.
	// Its value is equal to the number of items removed from the table
	// plus the number of items hidden in the table, so it should never
	// be lower than the "actual tail".
	// VirtualTail 指示有多少条目被标记为已删除。
	// 它的值等于从表中移除的条目数加上表中隐藏的条目数，因此它的值永远不会低于实际尾部。
	VirtualTail uint64
}

// newMetadata 使用给定的虚拟尾部初始化元数据对象。
// newMetadata initializes the metadata object with the given virtual tail.
func newMetadata(tail uint64) *freezerTableMeta {
	return &freezerTableMeta{
		Version:     freezerVersion,
		VirtualTail: tail,
	}
}

// readMetadata 从传入的元数据文件中读取 freezer 表的元数据。
// readMetadata reads the metadata of the freezer table from the
// given metadata file.
func readMetadata(file *os.File) (*freezerTableMeta, error) {
	_, err := file.Seek(0, io.SeekStart) // 将文件指针移动到起始位置。
	if err != nil {
		return nil, err
	}
	var meta freezerTableMeta
	if err := rlp.Decode(file, &meta); err != nil { // 解码 RLP 格式的元数据。
		return nil, err
	}
	return &meta, nil
}

// writeMetadata 将 freezer 表的元数据写入传入的元数据文件中。
// writeMetadata writes the metadata of the freezer table into the
// given metadata file.
func writeMetadata(file *os.File, meta *freezerTableMeta) error {
	_, err := file.Seek(0, io.SeekStart) // 将文件指针移动到起始位置。
	if err != nil {
		return err
	}
	return rlp.Encode(file, meta) // 使用 RLP 编码将元数据写入文件。
}

// loadMetadata 从传入的元数据文件中加载元数据。
// 如果文件是空的，则使用给定的“实际尾部”初始化元数据文件。
// loadMetadata loads the metadata from the given metadata file.
// Initializes the metadata file with the given "actual tail" if
// it's empty.
//
// 负责加载元数据，并根据当前的存储状态决定是读取现有内容还是初始化新的元数据。
func loadMetadata(file *os.File, tail uint64) (*freezerTableMeta, error) {
	stat, err := file.Stat() // 获取文件的元信息。
	if err != nil {
		return nil, err
	}
	// Write the metadata with the given actual tail into metadata file
	// if it's non-existent. There are two possible scenarios here:
	// - the freezer table is empty
	// - the freezer table is legacy
	// In both cases, write the meta into the file with the actual tail
	// as the virtual tail.
	//
	// 如果元数据文件不存在，将使用提供的“实际尾部”写入元数据文件。
	// 可能有两种情况：
	// - freezer 表是空的。
	// - freezer 表是遗留版本。
	if stat.Size() == 0 {
		m := newMetadata(tail) // 使用实际尾部初始化元数据。
		if err := writeMetadata(file, m); err != nil {
			return nil, err
		}
		return m, nil
	}
	m, err := readMetadata(file) // 读取现有元数据。
	if err != nil {
		return nil, err
	}
	// Update the virtual tail with the given actual tail if it's even
	// lower than it. Theoretically it shouldn't happen at all, print
	// a warning here.
	// 如果虚拟尾部值低于实际尾部，更新虚拟尾部。
	// 理论上这种情况不应该发生，记录警告日志。
	if m.VirtualTail < tail {
		log.Warn("Updated virtual tail", "have", m.VirtualTail, "now", tail)
		m.VirtualTail = tail
		if err := writeMetadata(file, m); err != nil {
			return nil, err
		}
	}
	return m, nil
}
