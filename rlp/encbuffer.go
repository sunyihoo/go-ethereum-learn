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

package rlp

import (
	"encoding/binary"
	"io"
	"math/big"
	"reflect"
	"sync"

	"github.com/holiman/uint256"
)

// encBuffer 是用于存储编码数据的缓冲区
type encBuffer struct {
	str     []byte     // string data, contains everything except list headers（字符串数据，包含所有内容，但不包括列表头）
	lheads  []listhead // all list headers（所有的列表头）
	lhsize  int        // sum of sizes of all encoded list headers（所有编码后的列表头的大小之和）
	sizebuf [9]byte    // auxiliary buffer for uint encoding（辅助缓冲区，用于无符号整数的编码）
}

// The global encBuffer pool.
var encBufferPool = sync.Pool{
	New: func() interface{} { return new(encBuffer) },
}

// 获取一个新的编码缓冲区
func getEncBuffer() *encBuffer {
	buf := encBufferPool.Get().(*encBuffer)
	buf.reset()
	return buf
}

// 重置缓冲区，准备重新使用
func (buf *encBuffer) reset() {
	buf.lhsize = 0              // 将所有列表头的总大小设置为0
	buf.str = buf.str[:0]       // 清空字符串数据部分，使其容量保持不变，但长度归零
	buf.lheads = buf.lheads[:0] // 清空列表头切片，准备重新存储新的列表头信息
}

// size returns the length of the encoded data.
// size 返回编码数据的长度
func (buf *encBuffer) size() int {
	return len(buf.str) + buf.lhsize
}

// makeBytes creates the encoder output.
// makeBytes 创建编码器的输出
func (buf *encBuffer) makeBytes() []byte {
	out := make([]byte, buf.size())
	buf.copyTo(out)
	return out
}

// copyTo 将缓冲区内容复制到目标切片
// copyTo 函数将 encBuffer 中的数据复制到指定的字节切片 dst 中。
// 它遍历所有列表头，按顺序写入字符串数据和对应的头部编码，
// 然后将剩余的字符串数据写入到输出中。
func (buf *encBuffer) copyTo(dst []byte) {
	strpos := 0 // 当前处理到字符串数据的位置
	pos := 0    // 当前在 dst 中写入的位置

	// 遍历每一个列表头
	for _, head := range buf.lheads {
		// 写入当前列表头之前的所有字符串数据
		n := copy(dst[pos:], buf.str[strpos:head.offset])
		pos += n    // 更新 pos，表示已经写了 n 个字节
		strpos += n // 更新 strpos，表示已经处理了 n 个字节

		// 编码并写入当前列表头
		enc := head.encode(dst[pos:])
		pos += len(enc) // 更新 pos，加上编码的长度
	}

	// 处理最后一个列表头之后的剩余字符串数据
	// copy string data after the last list header
	copy(dst[pos:], buf.str[strpos:])
}

// writeTo writes the encoder output to w.
// writeTo 将编码器的输出写入到 w。
func (buf *encBuffer) writeTo(w io.Writer) (err error) {
	strpos := 0
	// 循环遍历每个列表头
	for _, head := range buf.lheads {
		// write string data before header
		// 检查是否需要写入字符串数据到头部之前的字符串数据
		if head.offset-strpos > 0 {
			// 将字符串数据写入到 writer
			n, err := w.Write(buf.str[strpos:head.offset])
			strpos += n
			if err != nil {
				return err
			}
		}
		// write the header
		// 写入列表头
		enc := head.encode(buf.sizebuf[:])
		// 写入编码后的列表头到 writer
		if _, err = w.Write(enc); err != nil {
			return err
		}
	}
	// 检查是否还有字符串数据需要写入，即最后一个列表头之后的字符串
	if strpos < len(buf.str) {
		// write string data after the last list header
		// 写入剩余的字符串数据到 writer
		_, err = w.Write(buf.str[strpos:])
	}
	return err
}

// Write implements io.Writer and appends b directly to the output.
// 写实现了 io.Writer 接口，并将 b 直接追加到输出中。
func (buf *encBuffer) Write(b []byte) (int, error) {
	buf.str = append(buf.str, b...)
	return len(b), nil
}

// writeBool 将布尔值 b 写入为整数 0（false）或 1（true）
// writeBool writes b as the integer 0 (false) or 1 (true).
func (buf *encBuffer) writeBool(b bool) {
	if b {
		buf.str = append(buf.str, 0x01)
	} else {
		buf.str = append(buf.str, 0x80)
	}
}

// writeUint64 将 uint64 类型的值编码写入
func (buf *encBuffer) writeUint64(i uint64) {
	if i == 0 {
		buf.str = append(buf.str, 0x80)
	} else if i < 128 {
		// fits single byte
		buf.str = append(buf.str, byte(i))
	} else {
		s := putint(buf.sizebuf[1:], i)
		buf.sizebuf[0] = 0x80 + byte(s)
		buf.str = append(buf.str, buf.sizebuf[:s+1]...)
	}
}

// writeBytes 将字节切片 b 编码为 RLP 字符串
func (buf *encBuffer) writeBytes(b []byte) {
	if len(b) == 1 && b[0] <= 0x7F {
		// fits single byte, no string header
		buf.str = append(buf.str, b[0])
	} else {
		buf.encodeStringHeader(len(b))
		buf.str = append(buf.str, b...)
	}
}

// writeString 将字符串 s 编码为 RLP 字符串
func (buf *encBuffer) writeString(s string) {
	buf.writeBytes([]byte(s))
}

// wordBytes is the number of bytes in a big.Word
const wordBytes = (32 << (uint64(^big.Word(0)) >> 63)) / 8

// writeBigInt writes i as an integer.
// writeBigInt 将 big.Int 类型的值编码为整数
func (buf *encBuffer) writeBigInt(i *big.Int) {
	bitlen := i.BitLen()
	// 如果整数的位长不超过 64，则直接编码为 uint64 并返回
	if bitlen <= 64 {
		buf.writeUint64(i.Uint64())
		return
	}
	// Integer is larger than 64 bits, encode from i.Bits().
	// The minimal byte length is bitlen rounded up to the next
	// multiple of 8, divided by 8.
	// 当整数的位长大于64时，计算所需的最小字节数。这个数字是通过将 bitlen 加上7然后取负数，再右移3位得到。
	length := ((bitlen + 7) & -8) >> 3
	// 在缓冲区中写入字节数标头，以指示后续数据的长度
	buf.encodeStringHeader(length)
	// 创建一个大小为 byteLength 的空字节缓冲区，并将其追加到现有的缓冲区中
	buf.str = append(buf.str, make([]byte, length)...)
	index := length
	bytesBuf := buf.str[len(buf.str)-length:]
	for _, d := range i.Bits() {
		for j := 0; j < wordBytes && index > 0; j++ {
			index--
			bytesBuf[index] = byte(d)
			d >>= 8
		}
	}
}

// writeUint256 writes z as an integer.
// writeUint256 将 z 作为整数写入。
func (buf *encBuffer) writeUint256(z *uint256.Int) {
	bitlen := z.BitLen()
	if bitlen <= 64 {
		buf.writeUint64(z.Uint64())
		return
	}
	nBytes := byte((bitlen + 7) / 8)
	var b [33]byte
	binary.BigEndian.PutUint64(b[1:9], z[3])
	binary.BigEndian.PutUint64(b[9:17], z[2])
	binary.BigEndian.PutUint64(b[17:25], z[1])
	binary.BigEndian.PutUint64(b[25:33], z[0])
	b[32-nBytes] = 0x80 + nBytes
	buf.str = append(buf.str, b[32-nBytes:]...)
}

// list 添加一个新的列表头到头部栈，返回头部索引
// list adds a new list header to the header stack. It returns the index of the header.
// Call listEnd with this index after encoding the content of the list.
func (buf *encBuffer) list() int {
	buf.lheads = append(buf.lheads, listhead{offset: len(buf.str), size: buf.lhsize})
	return len(buf.lheads) - 1
}

// listEnd 使用指定索引结束一个列表
func (buf *encBuffer) listEnd(index int) {
	lh := &buf.lheads[index]
	lh.size = buf.size() - lh.offset - lh.size
	if lh.size < 56 {
		buf.lhsize++ // length encoded into kind tag
	} else {
		buf.lhsize += 1 + intsize(uint64(lh.size))
	}
}

func (buf *encBuffer) encode(val interface{}) error {
	rval := reflect.ValueOf(val)
	writer, err := cachedWriter(rval.Type())
	if err != nil {
		return err
	}
	return writer(rval, buf)
}

// encodeStringHeader 编码字符串头部信息
func (buf *encBuffer) encodeStringHeader(size int) {
	if size < 56 {
		buf.str = append(buf.str, 0x80+byte(size))
	} else {
		sizesize := putint(buf.sizebuf[1:], uint64(size))
		buf.sizebuf[0] = 0xB7 + byte(sizesize)
		buf.str = append(buf.str, buf.sizebuf[:sizesize+1]...)
	}
}

// encReader is the io.Reader returned by EncodeToReader.
// It releases its encbuf at EOF.
// encReader 是由 EncodeToReader 返回的 io.Reader。
// 在 EOF 时释放其 encbuf。
type encReader struct {
	buf    *encBuffer // the buffer we're reading from. this is nil when we're at EOF. // 读取的缓冲区。在 EOF 时为 nil。
	lhpos  int        // index of list header that we're reading  // 当前处理的列表头索引
	strpos int        // current position in string buffer // 字符串缓冲区中的当前位置
	piece  []byte     // next piece to be read  // 下一个待读取的分片
}

// Read 从 encReader 中读取数据到 b 直到填满或 EOF。
func (r *encReader) Read(b []byte) (n int, err error) {
	for {
		if r.piece = r.next(); r.piece == nil {
			// Put the encode buffer back into the pool at EOF when it
			// is first encountered. Subsequent calls still return EOF
			// as the error but the buffer is no longer valid.
			if r.buf != nil {
				encBufferPool.Put(r.buf)
				r.buf = nil
			}
			return n, io.EOF
		}
		nn := copy(b[n:], r.piece)
		n += nn
		if nn < len(r.piece) {
			// piece didn't fit, see you next time.
			r.piece = r.piece[nn:]
			return n, nil
		}
		r.piece = nil
	}
}

// next returns the next piece of data to be read.
// it returns nil at EOF.
// next 获取下一个待读取的数据分片。
func (r *encReader) next() []byte {
	switch {
	case r.buf == nil:
		return nil

	case r.piece != nil:
		// There is still data available for reading.
		return r.piece

	case r.lhpos < len(r.buf.lheads):
		// We're before the last list header.
		head := r.buf.lheads[r.lhpos]
		sizebefore := head.offset - r.strpos
		if sizebefore > 0 {
			// String data before header.
			p := r.buf.str[r.strpos:head.offset]
			r.strpos += sizebefore
			return p
		}
		r.lhpos++
		return head.encode(r.buf.sizebuf[:])

	case r.strpos < len(r.buf.str):
		// String data at the end, after all list headers.
		p := r.buf.str[r.strpos:]
		r.strpos = len(r.buf.str)
		return p

	default:
		return nil
	}
}

func encBufferFromWriter(w io.Writer) *encBuffer {
	switch w := w.(type) {
	case EncoderBuffer:
		return w.buf
	case *EncoderBuffer:
		return w.buf
	case *encBuffer:
		return w
	default:
		return nil
	}
}

// EncoderBuffer is a buffer for incremental encoding.
//
// The zero value is NOT ready for use. To get a usable buffer,
// create it using NewEncoderBuffer or call Reset.
type EncoderBuffer struct {
	buf *encBuffer
	dst io.Writer

	ownBuffer bool
}

// NewEncoderBuffer creates an encoder buffer.
// 创建一个新的 EncoderBuffer 实例。
func NewEncoderBuffer(dst io.Writer) EncoderBuffer {
	var w EncoderBuffer
	w.Reset(dst)
	return w
}

// Reset truncates the buffer and sets the output destination.
// 重置 EncoderBuffer 状态，准备进行新的编码。
func (w *EncoderBuffer) Reset(dst io.Writer) {
	if w.buf != nil && !w.ownBuffer {
		panic("can't Reset derived EncoderBuffer")
	}

	// If the destination writer has an *encBuffer, use it.
	// Note that w.ownBuffer is left false here.
	if dst != nil {
		if outer := encBufferFromWriter(dst); outer != nil {
			*w = EncoderBuffer{outer, nil, false}
			return
		}
	}

	// Get a fresh buffer.
	if w.buf == nil {
		w.buf = encBufferPool.Get().(*encBuffer)
		w.ownBuffer = true
	}
	w.buf.reset()
	w.dst = dst
}

// Flush writes encoded RLP data to the output writer. This can only be called once.
// If you want to re-use the buffer after Flush, you must call Reset.
// 将缓冲区内容写入目标 io.Writer 并重置缓冲区。
func (w *EncoderBuffer) Flush() error {
	var err error
	if w.dst != nil {
		err = w.buf.writeTo(w.dst)
	}
	// Release the internal buffer.
	if w.ownBuffer {
		encBufferPool.Put(w.buf)
	}
	*w = EncoderBuffer{}
	return err
}

// ToBytes returns the encoded bytes.
// ToBytes 返回编码器缓冲区中的所有数据作为字节数组。
func (w *EncoderBuffer) ToBytes() []byte {
	return w.buf.makeBytes()
}

// AppendToBytes appends the encoded bytes to dst.
// AppendToBytes 将编码器缓冲区的数据附加到目标字节数组中。
func (w *EncoderBuffer) AppendToBytes(dst []byte) []byte {
	size := w.buf.size()
	out := append(dst, make([]byte, size)...)
	w.buf.copyTo(out[len(dst):])
	return out
}

// Write appends b directly to the encoder output.
// Write 直接将字节数据写入编码器缓冲区。
func (w EncoderBuffer) Write(b []byte) (int, error) {
	return w.buf.Write(b)
}

// WriteBool writes b as the integer 0 (false) or 1 (true).
// WriteBool 为 0（false）或 1（true）并写入缓冲区。
func (w EncoderBuffer) WriteBool(b bool) {
	w.buf.writeBool(b)
}

// WriteUint64 encodes an unsigned integer.
// WriteUint64 整数为 RLP 格式并写入缓冲区。
func (w EncoderBuffer) WriteUint64(i uint64) {
	w.buf.writeUint64(i)
}

// WriteBigInt encodes a big.Int as an RLP string.
// Note: Unlike with Encode, the sign of i is ignored.
// WriteBigInt 为 RLP 字符串并写入缓冲区，忽略符号位。
func (w EncoderBuffer) WriteBigInt(i *big.Int) {
	w.buf.writeBigInt(i)
}

// WriteUint256 encodes uint256.Int as an RLP string.
// WriteUint256 整数为 RLP 字符串并写入缓冲区。
func (w EncoderBuffer) WriteUint256(i *uint256.Int) {
	w.buf.writeUint256(i)
}

// WriteBytes encodes b as an RLP string.
// WriteBytes 为 RLP 字符串并写入缓冲区。
func (w EncoderBuffer) WriteBytes(b []byte) {
	w.buf.writeBytes(b)
}

// WriteString encodes s as an RLP string.
// WriteString 为 RLP 字符串并写入缓冲区。
func (w EncoderBuffer) WriteString(s string) {
	w.buf.writeString(s)
}

// List starts a list. It returns an internal index. Call EndList with
// this index after encoding the content to finish the list.
// 开始编码一个列表，返回当前列表的索引以便后续关闭该列表。
func (w EncoderBuffer) List() int {
	return w.buf.list()
}

// ListEnd finishes the given list.
// ListEnd 结束指定索引对应的列表。
func (w EncoderBuffer) ListEnd(index int) {
	w.buf.listEnd(index)
}
