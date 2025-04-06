// Copyright 2014 The go-ethereum Authors
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

package vm

import (
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// calcMemSize64 calculates the required memory size, and returns
// the size and whether the result overflowed uint64
// calcMemSize64 计算所需的内存大小，并返回大小以及结果是否溢出 uint64
func calcMemSize64(off, l *uint256.Int) (uint64, bool) {
	if !l.IsUint64() {
		return 0, true
	}
	return calcMemSize64WithUint(off, l.Uint64())
}

// calcMemSize64WithUint calculates the required memory size, and returns
// the size and whether the result overflowed uint64
// Identical to calcMemSize64, but length is a uint64
// calcMemSize64WithUint 计算所需的内存大小，并返回大小以及结果是否溢出 uint64
// 与 calcMemSize64 相同，但长度参数是 uint64 类型
func calcMemSize64WithUint(off *uint256.Int, length64 uint64) (uint64, bool) {
	// if length is zero, memsize is always zero, regardless of offset
	// 如果长度为零，则无论偏移量如何，内存大小始终为零
	if length64 == 0 {
		return 0, false
	}
	// Check that offset doesn't overflow
	// 检查偏移量是否溢出
	offset64, overflow := off.Uint64WithOverflow()
	if overflow {
		return 0, true
	}
	// 关键步骤：计算总值（偏移量 + 长度）
	val := offset64 + length64
	// if value < either of it's parts, then it overflowed
	// 如果总值小于任一部分（偏移量或长度），则说明溢出了
	return val, val < offset64
}

// getData returns a slice from the data based on the start and size and pads
// up to size with zero's. This function is overflow safe.
// getData 根据起始位置和大小从数据中返回一个切片，并用零填充到指定大小。此函数防止溢出。
func getData(data []byte, start uint64, size uint64) []byte {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	// 关键步骤：计算结束位置
	end := start + size
	if end > length {
		end = length
	}
	return common.RightPadBytes(data[start:end], int(size))
}

// getDataAndAdjustedBounds 返回调整后的数据切片、实际起始位置和未填充的大小
func getDataAndAdjustedBounds(data []byte, start uint64, size uint64) (codeCopyPadded []byte, actualStart uint64, sizeNonPadded uint64) {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	// 关键步骤：计算结束位置
	end := start + size
	if end > length {
		end = length
	}
	return common.RightPadBytes(data[start:end], int(size)), start, end - start
}

// toWordSize returns the ceiled word size required for memory expansion.
// toWordSize 返回内存扩展所需的向上取整的字大小。
func toWordSize(size uint64) uint64 {
	if size > math.MaxUint64-31 {
		return math.MaxUint64/32 + 1
	}

	return (size + 31) / 32
}

// allZero 检查字节切片是否全为零
func allZero(b []byte) bool {
	for _, byte := range b {
		if byte != 0 {
			return false
		}
	}
	return true
}
