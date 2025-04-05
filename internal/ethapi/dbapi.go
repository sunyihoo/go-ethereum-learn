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

package ethapi

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// DbGet returns the raw value of a key stored in the database.
// DbGet 返回存储在数据库中的键的原始值。
func (api *DebugAPI) DbGet(key string) (hexutil.Bytes, error) {
	blob, err := common.ParseHexOrString(key) // 将输入的 key 解析为十六进制或字符串格式的字节数组。
	if err != nil {                           // 如果解析失败，返回错误。
		return nil, err
	}
	return api.b.ChainDb().Get(blob) // 从区块链数据库中获取与 blob 对应的值。
}

// DbAncient retrieves an ancient binary blob from the append-only immutable files.
// It is a mapping to the `AncientReaderOp.Ancient` method
// DbAncient 从只追加的不可变文件中检索一个古代二进制数据块。
// 它是对 `AncientReaderOp.Ancient` 方法的映射。
func (api *DebugAPI) DbAncient(kind string, number uint64) (hexutil.Bytes, error) {
	return api.b.ChainDb().Ancient(kind, number) // 根据类型和编号从古代存储中获取数据。
}

// DbAncients returns the ancient item numbers in the ancient store.
// It is a mapping to the `AncientReaderOp.Ancients` method
// DbAncients 返回古代存储中的项目数量。
// 它是对 `AncientReaderOp.Ancients` 方法的映射。
func (api *DebugAPI) DbAncients() (uint64, error) {
	return api.b.ChainDb().Ancients() // 获取古代存储中的项目总数。
}
