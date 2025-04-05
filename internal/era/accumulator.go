// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package era

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ssz "github.com/ferranbt/fastssz"
)

// ComputeAccumulator calculates the SSZ hash tree root of the Era1
// accumulator of header records.
// ComputeAccumulator 计算 Era1 累加器的头记录的 SSZ 哈希树根。
func ComputeAccumulator(hashes []common.Hash, tds []*big.Int) (common.Hash, error) {
	if len(hashes) != len(tds) {
		return common.Hash{}, errors.New("must have equal number hashes as td values")
	}
	if len(hashes) > MaxEra1Size {
		return common.Hash{}, fmt.Errorf("too many records: have %d, max %d", len(hashes), MaxEra1Size)
	}
	hh := ssz.NewHasher()
	for i := range hashes {
		rec := headerRecord{hashes[i], tds[i]}
		root, err := rec.HashTreeRoot()
		if err != nil {
			return common.Hash{}, err
		}
		hh.Append(root[:])
	}
	hh.MerkleizeWithMixin(0, uint64(len(hashes)), uint64(MaxEra1Size))
	return hh.HashRoot()
}

// headerRecord is an individual record for a historical header.
//
// See https://github.com/ethereum/portal-network-specs/blob/master/history-network.md#the-header-accumulator
// for more information.
// headerRecord 是历史区块头的单个记录。
//
// 更多信息请参阅 https://github.com/ethereum/portal-network-specs/blob/master/history-network.md#the-header-accumulator。
type headerRecord struct {
	Hash common.Hash
	// Hash 是历史区块头的哈希值。
	TotalDifficulty *big.Int
	// TotalDifficulty 是历史区块头的总难度值。
}

// GetTree completes the ssz.HashRoot interface, but is unused.
// GetTree 完成了 ssz.HashRoot 接口，但在本上下文中未使用。
func (h *headerRecord) GetTree() (*ssz.Node, error) {
	return nil, nil
}

// HashTreeRoot ssz hashes the headerRecord object.
// HashTreeRoot 使用 SSZ 对 headerRecord 对象进行哈希。
func (h *headerRecord) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(h)
}

// HashTreeRootWith ssz hashes the headerRecord object with a hasher.
// HashTreeRootWith 使用提供的哈希器对 headerRecord 对象进行 SSZ 哈希。
func (h *headerRecord) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	hh.PutBytes(h.Hash[:])
	td := bigToBytes32(h.TotalDifficulty)
	hh.PutBytes(td[:])
	hh.Merkleize(0)
	return
}

// bigToBytes32 converts a big.Int into a little-endian 32-byte array.
// bigToBytes32 将 big.Int 转换为小端序的 32 字节数组。
func bigToBytes32(n *big.Int) (b [32]byte) {
	n.FillBytes(b[:])
	reverseOrder(b[:])
	return
}

// reverseOrder reverses the byte order of a slice.
// reverseOrder 反转字节切片的字节顺序。
func reverseOrder(b []byte) []byte {
	for i := 0; i < 16; i++ {
		b[i], b[32-i-1] = b[32-i-1], b[i]
	}
	return b
}
