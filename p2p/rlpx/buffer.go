// Copyright 2021 The go-ethereum Authors
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

package rlpx

import (
	"io"
)

// RLPx 协议中的帧结构
// RLPx 协议使用帧来封装消息，每个帧包含一个 24 位的大小字段，指示帧数据的长度。readUint24 和 putUint24 函数用于处理这个大小字段。

// 缓冲区管理
//  在网络通信中，特别是在处理流式数据时，缓冲区管理至关重要。readBuffer 的设计允许在读取完整数据包之前保留部分数据，这在处理 TCP 流时尤为重要。
// 性能优化
//  通过重用缓冲区和避免不必要的内存分配，readBuffer 和 writeBuffer 提高了网络 I/O 的性能，这在高吞吐量的区块链节点中非常重要。

// readBuffer implements buffering for network reads. This type is similar to bufio.Reader,
// with two crucial differences: the buffer slice is exposed, and the buffer keeps all
// read data available until reset.
//
// How to use this type:
//
// Keep a readBuffer b alongside the underlying network connection. When reading a packet
// from the connection, first call b.reset(). This empties b.data. Now perform reads
// through b.read() until the end of the packet is reached. The complete packet data is
// now available in b.data.
//
// readBuffer 实现了网络读取的缓冲区。该类型类似于 bufio.Reader，
// 但有两个关键区别：缓冲区切片是公开的，并且缓冲区保留所有已读取的数据直到重置。
//
// 如何使用该类型：
//
// 在底层网络连接旁边保持一个 readBuffer b。当从连接中读取数据包时，
// 首先调用 b.reset()。这会清空 b.data。然后通过 b.read() 进行读取，
// 直到到达数据包的末尾。完整的数据包数据现在在 b.data 中可用。
type readBuffer struct {
	data []byte // 已处理的数据
	end  int    // 未处理数据的结束位置
}

// reset removes all processed data which was read since the last call to reset.
// After reset, len(b.data) is zero.
//
// reset 移除自上次调用 reset 以来已读取的所有已处理数据。
// 重置后，len(b.data) 为零。
func (b *readBuffer) reset() {
	// 未处理的缓冲数据
	unprocessed := b.end - len(b.data)
	// 拷贝未处理的数据到 data 的前面
	copy(b.data[:unprocessed], b.data[len(b.data):b.end])
	b.end = unprocessed
	b.data = b.data[:0]
}

// read reads at least n bytes from r, returning the bytes.
// The returned slice is valid until the next call to reset.
//
// read 从 r 中读取至少 n 个字节，并返回这些字节。
// 返回的切片在下一次调用 reset 之前有效。
func (b *readBuffer) read(r io.Reader, n int) ([]byte, error) {
	offset := len(b.data)
	have := b.end - len(b.data)

	// If n bytes are available in the buffer, there is no need to read from r at all.
	// 如果缓冲区中已有 n 个字节，则无需从 r 中读取。
	if have >= n {
		b.data = b.data[:offset+n]
		return b.data[offset : offset+n], nil
	}

	// Make buffer space available.
	// 确保缓冲区有足够的空间。
	need := n - have
	b.grow(need)

	// Read.
	// 读取数据。
	rn, err := io.ReadAtLeast(r, b.data[b.end:cap(b.data)], need)
	if err != nil {
		return nil, err
	}
	b.end += rn
	b.data = b.data[:offset+n]
	return b.data[offset : offset+n], nil
}

// grow ensures the buffer has at least n bytes of unused space.
// grow 确保缓冲区至少有 n 字节的未使用空间。
func (b *readBuffer) grow(n int) {
	if cap(b.data)-b.end >= n {
		return
	}
	need := n - (cap(b.data) - b.end)
	offset := len(b.data)
	b.data = append(b.data[:cap(b.data)], make([]byte, need)...)
	b.data = b.data[:offset]
}

// writeBuffer implements buffering for network writes. This is essentially
// a convenience wrapper around a byte slice.
//
// writeBuffer 实现了网络写入的缓冲区。这本质上是一个字节切片的便利包装。
type writeBuffer struct {
	data []byte // 待写入的数据
}

func (b *writeBuffer) reset() {
	b.data = b.data[:0]
}

func (b *writeBuffer) appendZero(n int) []byte {
	offset := len(b.data)
	b.data = append(b.data, make([]byte, n)...)
	return b.data[offset : offset+n]
}

func (b *writeBuffer) Write(data []byte) (int, error) {
	b.data = append(b.data, data...)
	return len(data), nil
}

const maxUint24 = int(^uint32(0) >> 8)

func readUint24(b []byte) uint32 {
	//     0        1        2
	// 11111111 11111111 111111111
	// uint32(b[2])     = 00000000 00000000 00000000 11111111
	// uint32(b[1])<<8  = 00000000 00000000 00000000 11111111 << 8  = 00000000 0000000 11111111 00000000
	// uint32(b[0])<<16 = 00000000 00000000 00000000 11111111 << 16 = 00000000 1111111 00000000 00000000
	// 00000000 11111111 11111111 11111111
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putUint24(v uint32, b []byte) {
	// 00000000 11111111 11111111 00000000
	// >> 16 = 00000000 00000000 00000000 11111111
	// >> 8  = 00000000 00000000 11111111 11111111
	// 00000000
	// 0: 11111111 1:11111111 2:00000000
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// growslice ensures b has the wanted length by either expanding it to its capacity
// or allocating a new slice if b has insufficient capacity.
//
// growslice 确保 b 具有所需的长度，要么将其扩展到其容量，
// 要么在 b 容量不足时分配一个新切片。
func growslice(b []byte, wantLength int) []byte {
	if len(b) >= wantLength {
		return b
	}
	if cap(b) >= wantLength {
		return b[:cap(b)]
	}
	return make([]byte, wantLength)
}
