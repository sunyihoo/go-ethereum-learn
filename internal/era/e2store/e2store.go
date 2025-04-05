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

package e2store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	headerSize = 8
	// 每个记录的头部大小为 8 字节。
	valueSizeLimit = 1024 * 1024 * 50
	// 单个值的最大大小限制为 50 MB。
)

// Entry is a variable-length-data record in an e2store.
// Entry 是 e2store 中的一个变长数据记录。
type Entry struct {
	Type uint16
	// 记录的类型，占 2 字节。
	Value []byte
	// 记录的实际数据，长度可变。
}

// Writer writes entries using e2store encoding.
// For more information on this format, see:
// https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md
// Writer 使用 e2store 编码写入记录。有关此格式的更多信息，请参阅上述链接。
type Writer struct {
	w io.Writer
	// 实际的数据写入器。
}

// NewWriter returns a new Writer that writes to w.
// NewWriter 返回一个新的 Writer，它将数据写入 w。
func NewWriter(w io.Writer) *Writer {
	return &Writer{w}
}

// Write writes a single e2store entry to w.
// An entry is encoded in a type-length-value format. The first 8 bytes of the
// record store the type (2 bytes), the length (4 bytes), and some reserved
// data (2 bytes). The remaining bytes store b.
// Write 将单个 e2store 记录写入 w。
// 记录以类型-长度-值（TLV）格式编码。前 8 字节存储类型（2 字节）、长度（4 字节）和保留字段（2 字节），其余字节存储实际数据。
func (w *Writer) Write(typ uint16, b []byte) (int, error) {
	buf := make([]byte, headerSize)
	binary.LittleEndian.PutUint16(buf, typ)
	// 将类型写入缓冲区的前 2 字节。
	binary.LittleEndian.PutUint32(buf[2:], uint32(len(b)))
	// 将数据长度写入缓冲区的第 3 到第 6 字节。

	// Write header.
	if n, err := w.w.Write(buf); err != nil {
		return n, err
	}
	// Write value, return combined write size.
	n, err := w.w.Write(b)
	// 写入实际数据，并返回总写入字节数（头部 + 数据）。
	return n + headerSize, err
}

// A Reader reads entries from an e2store-encoded file.
// For more information on this format, see
// https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md
// Reader 从 e2store 编码的文件中读取记录。有关此格式的更多信息，请参阅上述链接。
type Reader struct {
	r io.ReaderAt
	// 数据读取器，支持随机访问。
	offset int64
	// 当前读取位置的偏移量。
}

// NewReader returns a new Reader that reads from r.
// NewReader 返回一个新的 Reader，它从 r 中读取数据。
func NewReader(r io.ReaderAt) *Reader {
	return &Reader{r, 0}
}

// Read reads one Entry from r.
// Read 从 r 中读取一个记录。
func (r *Reader) Read() (*Entry, error) {
	var e Entry
	n, err := r.ReadAt(&e, r.offset)
	if err != nil {
		return nil, err
	}
	r.offset += int64(n)
	// 更新偏移量以指向下一个记录。
	return &e, nil
}

// ReadAt reads one Entry from r at the specified offset.
// ReadAt 从指定偏移量处读取一个记录。
func (r *Reader) ReadAt(entry *Entry, off int64) (int, error) {
	typ, length, err := r.ReadMetadataAt(off)
	if err != nil {
		return 0, err
	}
	entry.Type = typ

	// Check length bounds.
	if length > valueSizeLimit {
		return headerSize, fmt.Errorf("item larger than item size limit %d: have %d", valueSizeLimit, length)
	}
	// 如果记录长度超过限制，则返回错误。
	if length == 0 {
		return headerSize, nil
	}
	// 如果记录长度为 0，则直接返回头部大小。

	// Read value.
	val := make([]byte, length)
	if n, err := r.r.ReadAt(val, off+headerSize); err != nil {
		n += headerSize
		// An entry with a non-zero length should not return EOF when
		// reading the value.
		if err == io.EOF {
			return n, io.ErrUnexpectedEOF
		}
		return n, err
	}
	entry.Value = val
	return int(headerSize + length), nil
	// 返回记录的总大小（头部 + 数据）。
}

// ReaderAt returns an io.Reader delivering value data for the entry at
// the specified offset. If the entry type does not match the expected type, an
// error is returned.
// ReaderAt 返回一个 io.Reader，用于提供指定偏移量处记录的值数据。如果记录类型与预期类型不匹配，则返回错误。
func (r *Reader) ReaderAt(expectedType uint16, off int64) (io.Reader, int, error) {
	// problem = need to return length+headerSize not just value length via section reader
	typ, length, err := r.ReadMetadataAt(off)
	if err != nil {
		return nil, headerSize, err
	}
	if typ != expectedType {
		return nil, headerSize, fmt.Errorf("wrong type, want %d have %d", expectedType, typ)
	}
	if length > valueSizeLimit {
		return nil, headerSize, fmt.Errorf("item larger than item size limit %d: have %d", valueSizeLimit, length)
	}
	return io.NewSectionReader(r.r, off+headerSize, int64(length)), headerSize + int(length), nil
	// 返回 SectionReader 和记录的总大小。
}

// LengthAt reads the header at off and returns the total length of the entry,
// including header.
// LengthAt 读取指定偏移量处的头部，并返回记录的总长度（包括头部）。
func (r *Reader) LengthAt(off int64) (int64, error) {
	_, length, err := r.ReadMetadataAt(off)
	if err != nil {
		return 0, err
	}
	return int64(length) + headerSize, nil
}

// ReadMetadataAt reads the header metadata at the given offset.
// ReadMetadataAt 读取指定偏移量处的头部元数据。
func (r *Reader) ReadMetadataAt(off int64) (typ uint16, length uint32, err error) {
	b := make([]byte, headerSize)
	if n, err := r.r.ReadAt(b, off); err != nil {
		if err == io.EOF && n > 0 {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return 0, 0, err
	}
	typ = binary.LittleEndian.Uint16(b)
	length = binary.LittleEndian.Uint32(b[2:])
	// 解码类型和长度。

	// Check reserved bytes of header.
	if b[6] != 0 || b[7] != 0 {
		return 0, 0, errors.New("reserved bytes are non-zero")
	}
	// 检查保留字段是否为零。

	return typ, length, nil
}

// Find returns the first entry with the matching type.
// Find 返回第一个匹配类型的记录。
func (r *Reader) Find(want uint16) (*Entry, error) {
	var (
		off    int64
		typ    uint16
		length uint32
		err    error
	)
	for {
		typ, length, err = r.ReadMetadataAt(off)
		if err == io.EOF {
			return nil, io.EOF
		} else if err != nil {
			return nil, err
		}
		if typ == want {
			var e Entry
			if _, err := r.ReadAt(&e, off); err != nil {
				return nil, err
			}
			return &e, nil
		}
		off += int64(headerSize + length)
		// 移动到下一个记录。
	}
}

// FindAll returns all entries with the matching type.
// FindAll 返回所有匹配类型的记录。
func (r *Reader) FindAll(want uint16) ([]*Entry, error) {
	var (
		off     int64
		typ     uint16
		length  uint32
		entries []*Entry
		err     error
	)
	for {
		typ, length, err = r.ReadMetadataAt(off)
		if err == io.EOF {
			return entries, nil
		} else if err != nil {
			return entries, err
		}
		if typ == want {
			e := new(Entry)
			if _, err := r.ReadAt(e, off); err != nil {
				return entries, err
			}
			entries = append(entries, e)
		}
		off += int64(headerSize + length)
		// 移动到下一个记录。
	}
}
