// Copyright 2015 The go-ethereum Authors
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
	"sync"

	"github.com/holiman/uint256"
)

// memoryPool 是用于重用 Memory 实例的同步池，以减少内存分配开销。
var memoryPool = sync.Pool{
	New: func() any {
		return &Memory{}
	},
}

// Memory implements a simple memory model for the ethereum virtual machine.
// Memory 实现了以太坊虚拟机的简单内存模型。
type Memory struct {
	store       []byte // 存储实际内存数据的字节切片
	lastGasCost uint64 // 上次操作的 gas 成本，用于追踪内存扩展的费用
}

// NewMemory returns a new memory model.
// NewMemory 返回一个新的内存模型。
func NewMemory() *Memory {
	// 从内存池中获取一个 Memory 实例，避免频繁分配
	return memoryPool.Get().(*Memory)
}

// Free returns the memory to the pool.
// Free 将内存返回到池中。
func (m *Memory) Free() {
	// To reduce peak allocation, return only smaller memory instances to the pool.
	// 为了减少峰值分配，仅将较小的内存实例返回到池中。
	const maxBufferSize = 16 << 10
	if cap(m.store) <= maxBufferSize {
		m.store = m.store[:0]
		m.lastGasCost = 0
		// 将实例放回内存池
		memoryPool.Put(m)
	}
}

// Set sets offset + size to value
// Set 将 offset + size 设置为 value。
func (m *Memory) Set(offset, size uint64, value []byte) {
	// It's possible the offset is greater than 0 and size equals 0. This is because
	// the calcMemSize (common.go) could potentially return 0 when size is zero (NO-OP)
	// offset 可能大于 0 且 size 等于 0，这是因为 calcMemSize (common.go) 在 size 为零时可能返回 0（无操作）。
	if size > 0 {
		// length of store may never be less than offset + size.
		// The store should be resized PRIOR to setting the memory
		// store 的长度绝不能小于 offset + size。
		// 在设置内存之前应调整 store 的大小。
		if offset+size > uint64(len(m.store)) {
			// 如果目标区域超出当前内存大小，抛出异常
			panic("invalid memory: store empty")
		}
		// 关键步骤：将 value 复制到内存的指定位置
		copy(m.store[offset:offset+size], value)
	}
}

// Set32 sets the 32 bytes starting at offset to the value of val, left-padded with zeroes to
// 32 bytes.
// Set32 将从 offset 开始的 32 个字节设置为 val 的值，左侧用零填充至 32 字节。
func (m *Memory) Set32(offset uint64, val *uint256.Int) {
	// length of store may never be less than offset + size.
	// The store should be resized PRIOR to setting the memory
	// store 的长度绝不能小于 offset + size。
	// 在设置内存之前应调整 store 的大小。
	if offset+32 > uint64(len(m.store)) {
		// 如果目标区域超出当前内存大小，抛出异常
		panic("invalid memory: store empty")
	}
	// Fill in relevant bits
	val.PutUint256(m.store[offset:])
}

// Resize resizes the memory to size
// Resize 将内存调整到指定大小。
func (m *Memory) Resize(size uint64) {
	if uint64(m.Len()) < size {
		// 关键步骤：如果当前内存小于目标大小，扩展内存并填充零
		m.store = append(m.store, make([]byte, size-uint64(m.Len()))...)
	}
}

// GetCopy returns offset + size as a new slice
func (m *Memory) GetCopy(offset, size uint64) (cpy []byte) {
	if size == 0 {
		return nil
	}

	// memory is always resized before being accessed, no need to check bounds
	// 内存总是在访问前调整大小，无需检查边界。
	// 关键步骤：创建新切片并复制数据
	cpy = make([]byte, size)
	copy(cpy, m.store[offset:offset+size])
	return
}

// GetPtr returns the offset + size
// GetPtr 返回 offset + size 的内存区域。
func (m *Memory) GetPtr(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}

	// memory is always resized before being accessed, no need to check bounds
	// 内存总是在访问前调整大小，无需检查边界。
	// 关键步骤：直接返回内存中的指定区域，不复制
	return m.store[offset : offset+size]
}

// Len returns the length of the backing slice
// Len 返回底层切片的长度。
func (m *Memory) Len() int {
	return len(m.store)
}

// Data returns the backing slice
// Data 返回底层切片。
func (m *Memory) Data() []byte {
	return m.store
}

// Copy copies data from the src position slice into the dst position.
// The source and destination may overlap.
// OBS: This operation assumes that any necessary memory expansion has already been performed,
// and this method may panic otherwise.
// Copy 将数据从 src 位置切片复制到 dst 位置。
// 源和目标可能重叠。
// 注意：此操作假设已执行任何必要的内存扩展，否则此方法可能会抛出异常。
func (m *Memory) Copy(dst, src, len uint64) {
	if len == 0 {
		return
	}
	// 关键步骤：将内存从 src 位置复制到 dst 位置，支持重叠
	copy(m.store[dst:], m.store[src:src+len])
}
