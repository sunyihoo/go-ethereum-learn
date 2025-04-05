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

// Package merkle implements proof verifications in binary merkle trees.
package merkle

import (
	"crypto/sha256"
	"errors"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Merkle 树: 是一种树状数据结构，其中每个非叶子节点是其子节点的哈希值。Merkle 树允许高效地验证大量数据的完整性。在以太坊中，每个区块头都包含了状态树、交易树和收据树的根哈希。
// Merkle 证明: 用于证明一个特定的数据块（叶子节点）包含在 Merkle 树中，而无需下载整个树。一个 Merkle 证明通常包含从叶子节点到根节点的路径上的一系列兄弟节点的哈希值。
// 广义树索引: index 参数在这里扮演着关键角色。它的二进制表示揭示了在 Merkle 树中从根节点到目标叶子节点的路径。每一位代表一个方向（左或右）。在验证过程中，通过检查 index 的每一位，可以确定兄弟节点应该与当前计算的哈希值以何种顺序进行哈希运算。

// Value represents either a 32 byte leaf value or hash node in a binary merkle tree/partial proof.
// Value 表示二叉 Merkle 树或部分证明中的一个 32 字节叶子值或哈希节点。
type Value [32]byte

// Values represent a series of merkle tree leaves/nodes.
// Values 表示一系列 Merkle 树的叶子或节点。
type Values []Value

var valueT = reflect.TypeOf(Value{})

// UnmarshalJSON parses a merkle value in hex syntax.
// UnmarshalJSON 解析以十六进制语法表示的 Merkle 值。
func (m *Value) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(valueT, input, m[:])
}

// VerifyProof verifies a Merkle proof branch for a single value in a
// binary Merkle tree (index is a generalized tree index).
// VerifyProof 验证二叉 Merkle 树中单个值的 Merkle 证明分支（索引是广义树索引）。
func VerifyProof(root common.Hash, index uint64, branch Values, value Value) error {
	hasher := sha256.New()
	for _, sibling := range branch {
		hasher.Reset()
		if index&1 == 0 {
			// 如果索引是偶数，当前值在左侧
			hasher.Write(value[:])
			hasher.Write(sibling[:])
		} else {
			// 如果索引是奇数，当前值在右侧
			hasher.Write(sibling[:])
			hasher.Write(value[:])
		}
		// 计算当前层的哈希值
		hasher.Sum(value[:0])
		// 将索引右移一位，表示向上移动一层
		if index >>= 1; index == 0 {
			return errors.New("branch has extra items") // 分支有多余项
		}
	}
	if index != 1 {
		return errors.New("branch is missing items") // 分支缺少项
	}
	if common.Hash(value) != root {
		return errors.New("root mismatch") // 根哈希不匹配
	}
	return nil
}
