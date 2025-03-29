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

package rlp

import (
	"io"
	"reflect"
)

// RLP 是以太坊协议的核心组成部分，用于序列化数据。它的设计目标是简单、高效，特别适合区块链场景。RLP 的规则如下：
//
// 对于单个字节，如果值在 [0x00, 0x7f] 范围内，直接编码为自身。
// 对于字节数组，如果长度小于 55 字节，前缀为 0x80 + 长度，后接数据；如果长度超过 55 字节，使用更复杂的前缀表示。
// 对于嵌套列表，前缀从 0xc0 开始，具体规则与字节数组类似。

// RawValue represents an encoded RLP value and can be used to delay
// RLP decoding or to precompute an encoding. Note that the decoder does
// not verify whether the content of RawValues is valid RLP.
// RawValue 表示一个已编码的 RLP 值，可用于延迟 RLP 解码或预计算编码。注意，解码器不会验证 RawValue 的内容是否为有效的 RLP。
//
// RawValue 允许开发者将 RLP 编码的数据存储为原始字节形式，推迟对其解码的时间。这在需要减少即时计算开销或按需解码时非常有用。
// 预计算编码：开发者可以提前将数据编码为 RLP 格式并存储在 RawValue 中，避免重复编码的开销。
type RawValue []byte

var rawValueType = reflect.TypeOf(RawValue{})

// RLP 是一种紧凑的编码方式，特别适合区块链数据存储和传输。
// 对于字符串，RLP 编码规则如下：
// 如果字符串长度为 0，返回一个单字节 [0x80]（占用 1 字节）。
// 如果字符串长度为 1 且字节值小于等于 0x7f，直接返回该字节（占用 1 字节）。
// 如果字符串长度为 1 且字节值大于 0x7f，返回 [0x81, 值]（占用 2 字节）。
// 如果字符串长度大于 1，返回 [0x80 + 长度字节数, 长度值, 数据]，其中长度值可能占用多个字节。

// StringSize returns the encoded size of a string.
// StringSize 返回字符串的编码大小。
func StringSize(s string) uint64 {
	switch n := len(s); n {
	case 0: // 如果 n == 0，即字符串为空，返回 1。这通常表示编码中需要至少 1 个字节来表示“空字符串”的标记。
		return 1
	case 1: // 如果 n == 1，检查字符串的第一个字节 s[0]：如果 s[0] <= 0x7f（即 ASCII 字符，值小于等于 127），返回 1，表示只需要 1 个字节。否则（例如 UTF-8 编码的非 ASCII 字符），返回 2，表示需要 2 个字节。
		if s[0] <= 0x7f {
			return 1
		} else {
			return 2
		}
	default: // 字符串长度大于 1
		return uint64(headsize(uint64(n)) + n)
	}
}

// 在 RLP 编码中，空字节数组编码为单个字节 0x80，因此编码大小为 1。这反映了以太坊中对空数据的处理规则。

// BytesSize returns the encoded size of a byte slice.
// BytesSize 返回字节切片的编码大小。
func BytesSize(b []byte) uint64 {
	switch n := len(b); n {
	case 0:
		return 1
	case 1:
		if b[0] <= 0x7f {
			return 1
		} else {
			return 2
		}
	default:
		return uint64(headsize(uint64(n)) + n)
	}
}

// ListSize returns the encoded size of an RLP list with the given
// content size.
//
// ListSize 返回具有给定内容大小的 RLP 列表的编码大小。
func ListSize(contentSize uint64) uint64 {
	return uint64(headsize(contentSize)) + contentSize
}

// IntSize returns the encoded size of the integer x. Note: The return type of this
// function is 'int' for backwards-compatibility reasons. The result is always positive.
//
// IntSize 返回整数 x 的编码大小。注意：由于向后兼容的原因，此函数的返回类型为 'int'。结果始终为正数。
func IntSize(x uint64) int {
	if x < 0x80 { // 如果整数 x 的值小于 128（即 0 到 127），则 RLP 编码只需要 1 个字节。
		return 1
	}
	// 如果整数 x 的值大于等于 128，则 RLP 编码需要一个或多个前缀字节来指示数值的长度，再加上表示数值本身的字节。这里：
	//	1: 表示长度前缀字节的大小。
	//	intsize(x): 调用 intsize 函数（该函数的定义未在此处给出）来计算表示整数 x 所需的字节数（不包括前缀）。
	return 1 + intsize(x)
}

// Split returns the content of first RLP value and any
// bytes after the value as subslices of b.
// Split 返回第一个 RLP 值的内容以及该值之后的任何字节，作为 b 的子切片。
func Split(b []byte) (k Kind, content, rest []byte, err error) {
	k, ts, cs, err := readKind(b)
	if err != nil {
		return 0, nil, b, err
	}
	// k: 返回解析得到的 RLP 数据类型。
	// b[ts : ts+cs]: 返回第一个 RLP 值的内容部分，即从标签结束后开始，长度为 cs 的字节切片。
	// b[ts+cs:]: 返回第一个 RLP 值之后剩余的字节切片。
	return k, b[ts : ts+cs], b[ts+cs:], nil
}

// SplitString splits b into the content of an RLP string
// and any remaining bytes after the string.
// SplitString 将 b 分割成 RLP 字符串的内容以及字符串之后的任何剩余字节。
func SplitString(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k == List { // 如果类型是 List，则说明输入的 RLP 值不是一个字符串（在 RLP 中，基本数据类型如字符串和字节数组不会被编码为列表）
		return nil, b, ErrExpectedString
	}
	return content, rest, nil
}

// SplitUint64 decodes an integer at the beginning of b.
// It also returns the remaining data after the integer in 'rest'.
// SplitUint64 解码 b 开头的整数。
// 它还在 'rest' 中返回整数后的剩余数据。
// 用于从 RLP 编码的字节切片 b 的开头解码一个无符号整数 (uint64)。它还会返回解码后的整数以及整数之后剩余的字节数据。
func SplitUint64(b []byte) (x uint64, rest []byte, err error) {
	content, rest, err := SplitString(b)
	if err != nil {
		return 0, b, err
	}
	switch n := len(content); n { // 函数根据 content 的长度 n 来进行不同的解码处理
	case 0: // 表示编码的是整数 0
		return 0, rest, nil
	case 1:
		if content[0] == 0 { // 违反了 RLP 的规范编码规则。按照 RLP 规范，单个字节的 0 应该直接编码为 0x00，或者零值应该编码为空字符串 0x80
			return 0, b, ErrCanonInt
		}
		return uint64(content[0]), rest, nil
	default:
		if n > 8 { // 检查是否溢出 uint64
			return 0, b, errUintOverflow
		}

		x, err = readSize(content, byte(n)) // 调用 readSize 函数将 content 中的 n 个字节解析为一个 uint64 类型的整数 x。
		if err != nil {
			return 0, b, ErrCanonInt
		}
		return x, rest, nil
	}
}

// SplitList splits b into the content of a list and any remaining
// bytes after the list.
// SplitList 将 b 分割成列表的内容和列表中剩余的任何字节。
//
// 将一个 RLP 编码的字节切片 b，如果它表示一个 RLP 列表，则将其分割为两部分：列表的内容部分（即列表内部编码的元素）以及列表结束后剩余的任何字节。
func SplitList(b []byte) (content, rest []byte, err error) {
	k, content, rest, err := Split(b)
	if err != nil {
		return nil, b, err
	}
	if k != List {
		return nil, b, ErrExpectedList
	}
	return content, rest, nil
}

// CountValues counts the number of encoded values in b.
// CountValues 统计 b 中编码值的数量。
// 用于计算给定 RLP 编码的字节切片 b 中包含的顶级 RLP 值的数量。它通过重复调用 readKind 函数来识别每个值的边界，而无需实际解码这些值。
func CountValues(b []byte) (int, error) {
	i := 0
	for ; len(b) > 0; i++ {
		_, tagsize, size, err := readKind(b)
		if err != nil {
			return 0, err
		}
		b = b[tagsize+size:] // 通过将 b 切片为从 tagsize + size 索引开始的部分，我们跳过了当前已经处理过的 RLP 值。
	}
	return i, nil
}

// readKind 是 RLP 解码过程中的第一步，它负责读取 RLP 编码数据的第一个字节，以确定数据的类型（单个字节、字符串或列表）以及后续内容的长度。
func readKind(buf []byte) (k Kind, tagsize, contentsize uint64, err error) {
	if len(buf) == 0 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}
	b := buf[0]
	switch {
	case b < 0x80: //  (0x00-0x7f): 单个字节
		k = Byte        // 数据类型为单个字节。
		tagsize = 0     //  没有标签大小。
		contentsize = 1 // 内容大小为 1 字节。
	case b < 0xB8: // (0x80-0xb7): 短字符串
		k = String                     // 数据类型为字符串。
		tagsize = 1                    // 标签大小为 1 字节（即第一个字节本身）
		contentsize = uint64(b - 0x80) // 内容大小为第一个字节减去 0x80。
		// Reject strings that should've been single bytes.
		if contentsize == 1 && len(buf) > 1 && buf[1] < 128 { //  如果字符串内容长度为 1 并且该字节的值小于 128 (0x80)，则说明本应该使用单个字节编码，违反了 RLP 的规范编码原则。
			return 0, 0, 0, ErrCanonSize
		}
	case b < 0xC0: // (0xb8-0xbf): 长字符串
		k = String                                   // 数据类型为字符串。
		tagsize = uint64(b-0xB7) + 1                 // 标签大小为第一个字节减去 0xb7 再加 1，表示标签占用的字节数。例如，如果 b 是 0xb8，标签大小为 1；如果是 0xb9，标签大小为 2，依此类推。
		contentsize, err = readSize(buf[1:], b-0xB7) // 内容大小从标签后面的 b - 0xb7 个字节中读取。
	case b < 0xF8: //  (0xc0-0xf7): 短列表
		k = List                       // 数据类型为列表。
		tagsize = 1                    // 标签大小为 1 字节。
		contentsize = uint64(b - 0xC0) // 内容大小为第一个字节减去 0xc0。
	default:
		k = List                                     // 数据类型为列表。
		tagsize = uint64(b-0xF7) + 1                 // 标签大小为第一个字节减去 0xf7 再加 1。
		contentsize, err = readSize(buf[1:], b-0xF7) // 内容大小从标签后面的 b - 0xf7 个字节中读取。
	}
	if err != nil {
		return 0, 0, 0, err
	}
	// Reject values larger than the input slice.
	if contentsize > uint64(len(buf))-tagsize { // 检查声明的内容大小是否超出了输入缓冲区剩余的长度（总长度减去标签大小）
		return 0, 0, 0, ErrValueTooLarge
	}
	return k, tagsize, contentsize, err
}

// 用于从给定的字节切片 b 中读取表示 RLP 内容长度的数值。这个函数在处理长度超过 55 字节的字符串和列表时被 readKind 函数调用。
// 根据指定的长度字节数 (slen)，从字节切片 b 中读取并返回一个 uint64 类型的长度值。
func readSize(b []byte, slen byte) (uint64, error) {
	// 首先检查指定的长度字节数 slen 是否超过了剩余字节切片 b 的长度。如果超过，说明数据不完整。
	if int(slen) > len(b) {
		return 0, io.ErrUnexpectedEOF
	}
	var s uint64
	// 根据 slen 的值（1 到 8）从字节切片 b 中读取相应数量的字节，并通过位运算 (<< 和 |) 将它们组合成一个 uint64 类型的长度值 s。
	// RLP 允许使用 1 到 8 个字节来表示长度，因此 slen 的取值范围是 1 到 8。
	switch slen {
	case 1:
		s = uint64(b[0])
	case 2:
		s = uint64(b[0])<<8 | uint64(b[1])
	case 3:
		s = uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	case 4:
		s = uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	case 5:
		s = uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	case 6:
		s = uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
	case 7:
		s = uint64(b[0])<<48 | uint64(b[1])<<40 | uint64(b[2])<<32 | uint64(b[3])<<24 | uint64(b[4])<<16 | uint64(b[5])<<8 | uint64(b[6])
	case 8:
		s = uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	}
	// Reject sizes < 56 (shouldn't have separate size) and sizes with
	// leading zero bytes.
	// 拒绝 sizes < 56（不应具有单独的大小）和前导零字节的大小。
	//
	// 长度小于 56： 如果读取到的长度 s 小于 56，这意味着该内容的长度本应该可以直接编码在第一个类型字节中（对于短字符串和短列表，长度范围是 0-55）。
	// 使用额外的长度字节来表示小于 56 的长度是冗余的，违反了 RLP 的规范编码规则，
	//
	// 如果表示长度的第一个字节 b[0] 是 0，这也违反了规范编码。长度不应该包含前导零字节，除非长度本身就是 0（但这种情况会被前面的短字符串或短列表规则处理）。
	if s < 56 || b[0] == 0 {
		return 0, ErrCanonSize
	}
	return s, nil
}

// AppendUint64 appends the RLP encoding of i to b, and returns the resulting slice.
// AppendUint64 将 i 的 RLP 编码追加到 b，并返回结果切片。
// 实现了将 uint64 类型的数据编码为 RLP 格式并追加到给定的字节切片 b 的功能。
func AppendUint64(b []byte, i uint64) []byte {
	if i == 0 { // 如果 i 的值为 0，则编码为单个字节 0x80，表示空字符串，在 RLP 中 0 被视为空字符串。
		return append(b, 0x80)
	} else if i < 128 { // (0x00 到 0x7f) 如果 i 的值在 0 到 127 之间（包括 0 和 127），则直接使用单个字节表示该值。
		return append(b, byte(i))
	}

	// RLP 区分短整数（0-127）和长整数（大于等于 128）。短整数直接编码为单个字节，而长整数需要一个长度前缀。

	switch {
	case i < (1 << 8): // (0x80 到 0xff) 如果 i 的值在 128 到 255 之间，则编码为两个字节：第一个字节是 0x81，表示后续有 1 个字节表示实际数值；第二个字节是 i 的值。
		return append(b, 0x81, byte(i))
	case i < (1 << 16): // (0x0100 到 0xffff)  如果 i 的值在 256 到 65535 之间，则编码为三个字节：第一个字节是 0x82，表示后续有 2 个字节表示实际数值；接下来的两个字节是 i 的大端（Big-Endian）表示。
		return append(b, 0x82,
			byte(i>>8),
			byte(i),
		)
	case i < (1 << 24):
		return append(b, 0x83,
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	case i < (1 << 32):
		return append(b, 0x84,
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	case i < (1 << 40):
		return append(b, 0x85,
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)

	case i < (1 << 48):
		return append(b, 0x86,
			byte(i>>40),
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	case i < (1 << 56):
		return append(b, 0x87,
			byte(i>>48),
			byte(i>>40),
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)

	default: // 大于等于 2^64，实际上，由于输入是 uint64 类型，所以值不可能大于或等于 2^64。default 分支处理的是 i 在 (1 << 56) 到 (1 << 64) - 1 之间的值，使用前缀 0x88 表示后续有 8 个字节。
		return append(b, 0x88,
			byte(i>>56),
			byte(i>>48),
			byte(i>>40),
			byte(i>>32),
			byte(i>>24),
			byte(i>>16),
			byte(i>>8),
			byte(i),
		)
	}
}
