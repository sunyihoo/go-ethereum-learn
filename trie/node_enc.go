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

package trie

import (
	"github.com/ethereum/go-ethereum/rlp"
)

// 将节点转换为字节数组
func nodeToBytes(n node) []byte {
	w := rlp.NewEncoderBuffer(nil) // 创建新的 RLP 编码缓冲区
	n.encode(w)                    // 编码节点到缓冲区
	result := w.ToBytes()          // 获取编码后的字节数组
	w.Flush()                      // 清空缓冲区
	return result                  // 返回字节数组
}

// 编码 fullNode 到 RLP 缓冲区
func (n *fullNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()             // 开始一个 RLP 列表
	for _, c := range n.Children { // 遍历所有子节点
		if c != nil {
			c.encode(w) // 编码非空子节点
		} else {
			w.Write(rlp.EmptyString) // 写入空字符串表示空子节点
		}
	}
	w.ListEnd(offset) // 结束 RLP 列表
}

// 编码 shortNode 到 RLP 缓冲区
func (n *shortNode) encode(w rlp.EncoderBuffer) {
	offset := w.List()  // 开始一个 RLP 列表
	w.WriteBytes(n.Key) // 写入键
	if n.Val != nil {
		n.Val.encode(w) // 编码值（子节点）
	} else {
		w.Write(rlp.EmptyString) // 写入空字符串表示空值
	}
	w.ListEnd(offset) // 结束 RLP 列表
}

// 编码 hashNode 到 RLP 缓冲区
func (n hashNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n) // 直接写入哈希字节
}

// 编码 valueNode 到 RLP 缓冲区
func (n valueNode) encode(w rlp.EncoderBuffer) {
	w.WriteBytes(n) // 直接写入值字节
}

// 编码 rawNode 到 RLP 缓冲区
func (n rawNode) encode(w rlp.EncoderBuffer) {
	w.Write(n) // 直接写入原始字节
}
