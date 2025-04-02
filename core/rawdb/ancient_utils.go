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
	"fmt"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

type tableSize struct {
	name string             // 表的名称
	size common.StorageSize // 表的大小
}

// freezerInfo contains the basic information of the freezer.
// freezerInfo 包含冷冻存储的基本信息。
type freezerInfo struct {
	name  string      // The identifier of freezer 冷冻存储的标识符
	head  uint64      // The number of last stored item in the freezer 冷冻存储中最后一个存储项的编号
	tail  uint64      // The number of first stored item in the freezer 冷冻存储中第一个存储项的编号
	sizes []tableSize // The storage size per table 每个表的存储大小
}

// count returns the number of stored items in the freezer.
// 返回冷冻存储中存储项的数量。
func (info *freezerInfo) count() uint64 {
	return info.head - info.tail + 1
}

// size returns the storage size of the entire freezer.
// 返回整个冷冻存储的大小。
func (info *freezerInfo) size() common.StorageSize {
	var total common.StorageSize
	for _, table := range info.sizes {
		total += table.size // 累加每个表的大小
	}
	return total
}

func inspect(name string, order map[string]bool, reader ethdb.AncientReader) (freezerInfo, error) {
	info := freezerInfo{name: name} // 创建一个新的 freezerInfo 实例
	for t := range order {
		size, err := reader.AncientSize(t) // 获取每个表的大小
		if err != nil {
			return freezerInfo{}, err
		}
		info.sizes = append(info.sizes, tableSize{name: t, size: common.StorageSize(size)}) // 添加表和大小
	}
	// Retrieve the number of last stored item
	// 获取存储的项的数量
	ancients, err := reader.Ancients()
	if err != nil {
		return freezerInfo{}, err
	}
	info.head = ancients - 1 // 设置最后一个存储项的编号

	// Retrieve the number of first stored item
	// 获取第一个存储项的编号
	tail, err := reader.Tail()
	if err != nil {
		return freezerInfo{}, err
	}
	info.tail = tail // 设置第一个存储项的编号
	return info, nil
}

// inspectFreezers inspects all freezers registered in the system.
// 检查系统中注册的所有冷冻存储。
func inspectFreezers(db ethdb.Database) ([]freezerInfo, error) {
	var infos []freezerInfo
	for _, freezer := range freezers {
		switch freezer {
		case ChainFreezerName:
			info, err := inspect(ChainFreezerName, chainFreezerNoSnappy, db) // 检查链冷冻存储
			if err != nil {
				return nil, err
			}
			infos = append(infos, info) // 将信息添加到 infos 列表

		case MerkleStateFreezerName, VerkleStateFreezerName:
			datadir, err := db.AncientDatadir() // 获取古老存储的数据目录
			if err != nil {
				return nil, err
			}
			// 创建状态冷冻存储
			f, err := NewStateFreezer(datadir, freezer == VerkleStateFreezerName, true)
			if err != nil {
				continue // might be possible the state freezer is not existent // 如果状态冷冻存储不存在则继续检查下一个
			}
			defer f.Close()

			info, err := inspect(freezer, stateFreezerNoSnappy, f) // 检查状态冷冻存储
			if err != nil {
				return nil, err
			}
			infos = append(infos, info) // 将信息添加到 infos 列表

		default:
			return nil, fmt.Errorf("unknown freezer, supported ones: %v", freezers)
		}
	}
	return infos, nil
}

// InspectFreezerTable dumps out the index of a specific freezer table. The passed
// ancient indicates the path of root ancient directory where the chain freezer can
// be opened. Start and end specify the range for dumping out indexes.
// Note this function can only be used for debugging purposes.
//
// InspectFreezerTable 转储特定冷冻存储表的索引。
// 传入的 ancient 指示根古老目录的路径，在此路径下可以打开链冷冻存储。
// start 和 end 指定转储索引的范围。
// 请注意，此函数仅可用于调试目的。
func InspectFreezerTable(ancient string, freezerName string, tableName string, start, end int64) error {
	var (
		path   string
		tables map[string]bool
	)
	switch freezerName {
	case ChainFreezerName:
		path, tables = resolveChainFreezerDir(ancient), chainFreezerNoSnappy // 解析链冷冻存储目录
	case MerkleStateFreezerName, VerkleStateFreezerName:
		path, tables = filepath.Join(ancient, freezerName), stateFreezerNoSnappy // 解析状态冷冻存储目录
	default:
		return fmt.Errorf("unknown freezer, supported ones: %v", freezers)
	}
	noSnappy, exist := tables[tableName] // 检查表是否存在
	if !exist {
		var names []string
		for name := range tables {
			names = append(names, name) // 收集所有支持的表名称
		}
		return fmt.Errorf("unknown table, supported ones: %v", names)
	}
	table, err := newFreezerTable(path, tableName, noSnappy, true) // 创建新表
	if err != nil {
		return err
	}
	table.dumpIndexStdout(start, end) // 转储指定范围的索引到标准输出
	return nil
}
