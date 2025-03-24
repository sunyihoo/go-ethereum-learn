// Copyright 2017 The go-ethereum Authors
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

package bloombits

import (
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
)

// 在以太坊中，布隆过滤器常用于日志（Logs）或事件（Events）的索引和查询。
// 布隆过滤器是一个固定大小的位数组，用于高效检查元素是否存在。
//
// 以太坊使用布隆过滤器来优化日志查询。
// 每个区块头（Block Header）包含一个 LogsBloom 字段，这是一个 2048 位（256 字节）的布隆过滤器，用于快速判断某个区块是否包含特定的事件或日志。
// 交易收据（Receipt）中的日志也会生成布隆过滤器，最终汇总到区块头的 LogsBloom 中。
//
// 布隆过滤器的容量是固定的（2048 位），因此任何超出范围的操作都会导致错误。这与以太坊的 EIP-234（区块日志索引规范）相关，确保查询效率和数据一致性。

var (
	// errSectionOutOfBounds is returned if the user tried to add more bloom filters
	// to the batch than available space, or if tries to retrieve above the capacity.
	// 如果用户尝试向批次中添加超出可用空间的布隆过滤器，或者尝试检索超出容量的数据，则返回此错误。
	errSectionOutOfBounds = errors.New("section out of bounds")

	// errBloomBitOutOfBounds is returned if the user tried to retrieve specified
	// bit bloom above the capacity.
	// 如果用户尝试检索超出容量的指定位布隆数据，则返回此错误。
	errBloomBitOutOfBounds = errors.New("bloom bit out of bounds")
)

// 布隆过滤器（Bloom Filter）
// 在以太坊中，布隆过滤器用于区块头中的 LogsBloom 字段（256 字节，2048 位），以高效索引交易收据中的日志（Logs）。它通过哈希映射快速判断某个事件是否可能存在于区块中。
//
// 旋转布隆位的作用
// 普通布隆过滤器是按区块存储的，但查询多个区块时需要逐个检查。Generator 通过将多个过滤器按位重组（旋转），生成一个按位索引的数据结构，允许一次性对比所有相关区块的某一位，极大提升批量查询效率。
// 这种设计常见于 go-ethereum 的轻客户端或日志同步模块。
//
// 日志和布隆过滤器的使用源于 EIP-234，规范了事件日志的存储和查询方式。

// Generator takes a number of bloom filters and generates the rotated bloom bits
// to be used for batched filtering.
// Generator 接受多个布隆过滤器并生成用于批量过滤的旋转布隆位。
type Generator struct {
	// 存储按位重组后的布隆过滤器数据。数组的每个索引对应布隆过滤器的一位（bit），而 []byte 记录该位在不同段（sections）中的值。
	// 流程：接收原始布隆过滤器 → 按位旋转重组 → 存储到对应索引。
	blooms [types.BloomBitLength][]byte // Rotated blooms for per-bit matching 旋转的布隆过滤器，用于按位匹配
	// 定义批量处理的段数，即一次可以容纳的布隆过滤器数量。
	// 流程：初始化时设置上限 → 添加过滤器时检查是否超出。
	sections uint // Number of sections to batch together 要批量处理的段数
	// 记录下一个可用段的索引，用于动态添加布隆过滤器。
	// 流程：每次添加过滤器时递增 → 达到 sections 时停止。
	nextSec uint // Next section to set when adding a bloom 添加布隆过滤器时要设置的下一个段
}

// NewGenerator creates a rotated bloom generator that can iteratively fill a
// batched bloom filter's bits.
// NewGenerator 创建一个旋转布隆生成器，可以迭代填充批量布隆过滤器的位。
func NewGenerator(sections uint) (*Generator, error) {
	if sections%8 != 0 { // 检查 sections 是否为 8 的倍数。确保每个布隆位的存储空间（blooms[i]）可以按字节（8 bit）对齐，避免位操作复杂性。以太坊的布隆过滤器操作通常按字节处理（8 bit = 1 byte）
		return nil, errors.New("section count not multiple of 8")
	}
	b := &Generator{sections: sections}         // 初始化Generator结构体，设置段数，为后续添加布隆过滤器提供基础状态。
	for i := 0; i < types.BloomBitLength; i++ { // 为每个布隆位分配字节切片，预分配存储空间，每个切片表示某一位在所有段中的值。
		b.blooms[i] = make([]byte, sections/8)
	}
	return b, nil
}

// AddBloom takes a single bloom filter and sets the corresponding bit column
// in memory accordingly.
//
// AddBloom 接受一个布隆过滤器并在内存中相应地设置对应的位列。
//
// 用于将单个布隆过滤器（bloom）添加到内存中的旋转布隆位集合（b.blooms）。它通过按位操作将输入的布隆过滤器“旋转”并存储，以便后续批量查询。
func (b *Generator) AddBloom(index uint, bloom types.Bloom) error {
	// Make sure we're not adding more bloom filters than our capacity
	// 确保我们不会添加超出容量的布隆过滤器
	if b.nextSec >= b.sections {
		return errSectionOutOfBounds
	}
	if b.nextSec != index {
		return errors.New("bloom filter with unexpected index")
	}
	// Rotate the bloom and insert into our collection
	// 旋转布隆过滤器并插入到我们的集合中
	byteIndex := b.nextSec / 8                         // 计算字节索引
	bitIndex := byte(7 - b.nextSec%8)                  // 计算位索引
	for byt := 0; byt < types.BloomByteLength; byt++ { // 遍历布隆过滤器的每个字节
		bloomByte := bloom[types.BloomByteLength-1-byt] // 从末尾读取字节
		if bloomByte == 0 {                             // 如果字节为0，跳过
			continue
		}
		base := 8 * byt                                                   // 计算位的基础偏移
		b.blooms[base+7][byteIndex] |= ((bloomByte >> 7) & 1) << bitIndex // 设置第7位
		b.blooms[base+6][byteIndex] |= ((bloomByte >> 6) & 1) << bitIndex // 设置第6位
		b.blooms[base+5][byteIndex] |= ((bloomByte >> 5) & 1) << bitIndex // 设置第5位
		b.blooms[base+4][byteIndex] |= ((bloomByte >> 4) & 1) << bitIndex // 设置第4位
		b.blooms[base+3][byteIndex] |= ((bloomByte >> 3) & 1) << bitIndex // 设置第3位
		b.blooms[base+2][byteIndex] |= ((bloomByte >> 2) & 1) << bitIndex // 设置第2位
		b.blooms[base+1][byteIndex] |= ((bloomByte >> 1) & 1) << bitIndex // 设置第1位
		b.blooms[base][byteIndex] |= (bloomByte & 1) << bitIndex          // 设置第0位
	}
	b.nextSec++ // 增加下一个段索引
	return nil
}

// Bitset returns the bit vector belonging to the given bit index after all
// blooms have been added.
// Bitset 在所有布隆过滤器添加完成后，返回给定位索引对应的位向量。
//
// 用于在所有布隆过滤器添加完成后，返回指定位索引（idx）对应的位向量（b.blooms[idx]）。
// 它的主要目的是提供访问旋转布隆位数据的接口，以便进行批量查询或验证。
func (b *Generator) Bitset(idx uint) ([]byte, error) {
	if b.nextSec != b.sections { // 确保所有段都已填充布隆过滤器数据。
		return nil, errors.New("bloom not fully generated yet")
	}
	if idx >= types.BloomBitLength { // 防止访问超出布隆过滤器位长度的无效索引。
		return nil, errBloomBitOutOfBounds
	}
	return b.blooms[idx], nil // 提供指定位的向量数据，供外部使用。
}
