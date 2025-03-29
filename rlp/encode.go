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

package rlp

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/rlp/internal/rlpstruct"
	"github.com/holiman/uint256"
)

var (
	// Common encoded values.
	// These are useful when implementing EncodeRLP.
	// 常见编码值。这些在实现 EncodeRLP 时很有用。

	// EmptyString is the encoding of an empty string.
	// EmptyString 是空字符串的 RLP 编码
	EmptyString = []byte{0x80}
	// EmptyList is the encoding of an empty list.
	// EmptyList 是空列表的 RLP 编码
	EmptyList = []byte{0xC0}
)

var ErrNegativeBigInt = errors.New("rlp: cannot encode negative big.Int")

// Encoder is implemented by types that require custom
// encoding rules or want to encode private fields.
// Encoder 接口由需要自定义编码规则或希望编码私有字段的类型实现。
type Encoder interface {
	// EncodeRLP should write the RLP encoding of its receiver to w.
	// If the implementation is a pointer method, it may also be
	// called for nil pointers.
	//
	// Implementations should generate valid RLP. The data written is
	// not verified at the moment, but a future version might. It is
	// recommended to write only a single value but writing multiple
	// values or no value at all is also permitted.
	// EncodeRLP 应将其接收者的RLP编码写入w。
	// 如果其实现是一个指针方法，它也可能被调用为nil指针。
	//
	// 实现应该生成有效的RLP。当前写入的数据尚未验证，
	// 但未来的版本可能会进行验证。建议只写一个值，
	// 但也允许写多个值或不写任何值。
	EncodeRLP(io.Writer) error
}

// Encode writes the RLP encoding of val to w. Note that Encode may
// perform many small writes in some cases. Consider making w
// buffered.
//
// Please see package-level documentation of encoding rules.
// Encode 将 val 的 RLP 编码写入 w 中。请注意，Encode 在某些情况下可能会进行多次小写操作。考虑将 w 缓冲化。
//
// 请参阅包级别的编码规则文档。
func Encode(w io.Writer, val interface{}) error {
	// Optimization: reuse *encBuffer when called by EncodeRLP.
	// 优化：当被 EncodeRLP 调用时，重用 *encBuffer。
	if buf := encBufferFromWriter(w); buf != nil {
		return buf.encode(val)
	}

	buf := getEncBuffer()
	defer encBufferPool.Put(buf)
	if err := buf.encode(val); err != nil {
		return err
	}
	return buf.writeTo(w)
}

// EncodeToBytes returns the RLP encoding of val.
// Please see package-level documentation for the encoding rules.
//
// EncodeToBytes 返回 val 的 RLP 编码。[请参阅包级别的文档以了解编码规则。]
func EncodeToBytes(val interface{}) ([]byte, error) {
	buf := getEncBuffer()
	defer encBufferPool.Put(buf)

	if err := buf.encode(val); err != nil {
		return nil, err
	}
	return buf.makeBytes(), nil
}

// EncodeToReader returns a reader from which the RLP encoding of val
// can be read. The returned size is the total size of the encoded
// data.
//
// Please see the documentation of Encode for the encoding rules.
//
// EncodeToReader 返回一个可以从中读取 val 的 RLP 编码的 io.Reader。返回的 size 是编码数据的总大小。[请参阅 Encode 的文档以了解编码规则。]
func EncodeToReader(val interface{}) (size int, r io.Reader, err error) {
	buf := getEncBuffer()
	if err := buf.encode(val); err != nil {
		encBufferPool.Put(buf)
		return 0, nil, err
	}
	// Note: can't put the reader back into the pool here
	// because it is held by encReader. The reader puts it
	// back when it has been fully consumed.
	// 如果编码成功，则获取编码数据的总大小（buf.size()），并创建一个新的 encReader 实例。
	// encReader 应该实现了 io.Reader 接口，允许以流的方式读取缓冲区中的 RLP 编码数据。
	// 这里需要注意的是，由于 encReader 持有对 encBuffer 的引用，因此不能立即将 encBuffer 放回池中，而是由 encReader 在数据读取完毕后负责放回。
	return buf.size(), &encReader{buf: buf}, nil
}

type listhead struct {
	offset int // index of this header in string data 头部在字符串数据中的索引,存储了列表头部在最终编码的字节流中的起始索引位置。
	size   int // total size of encoded data (including list headers) 编码数据的总大小（包括列表头部）,存储了整个 RLP 编码列表的总大小，包括列表头部自身的长度以及所有列表元素的编码长度之和。
}

// encode writes head to the given buffer, which must be at least
// 9 bytes long. It returns the encoded bytes.
// encode 将头部写入给定的缓冲区，该缓冲区必须至少有 9 个字节长。它返回编码后的字节。
func (head *listhead) encode(buf []byte) []byte {
	return buf[:puthead(buf, 0xC0, 0xF7, uint64(head.size))]
}

// headsize returns the size of a list or string header
// for a value of the given size.
// headsize 返回给定大小的值的列表或字符串头部的尺寸。
func headsize(size uint64) int {
	if size < 56 { // 短列表/字符串：如果数据大小 size 小于 56 字节，则 RLP 头部只需要 1 个字节。
		return 1
	}
	// 长列表/字符串：如果数据大小 size 大于等于 56 字节，则 RLP 头部需要 1 个字节来指示长度的长度，再加上编码实际长度所需的字节数。
	return 1 + intsize(size)
}

// puthead writes a list or string header to buf.
// buf must be at least 9 bytes long.
func puthead(buf []byte, smalltag, largetag byte, size uint64) int {
	if size < 56 {
		buf[0] = smalltag + byte(size)
		return 1
	}
	sizesize := putint(buf[1:], size)
	buf[0] = largetag + byte(sizesize)
	return sizesize + 1
}

var encoderInterface = reflect.TypeOf(new(Encoder)).Elem()

// makeWriter creates a writer function for the given type.
// makeWriter 为给定的类型创建一个写入器函数。
func makeWriter(typ reflect.Type, ts rlpstruct.Tags) (writer, error) {
	kind := typ.Kind()
	switch {
	case typ == rawValueType:
		return writeRawValue, nil
	case typ.AssignableTo(reflect.PointerTo(bigInt)):
		return writeBigIntPtr, nil
	case typ.AssignableTo(bigInt):
		return writeBigIntNoPtr, nil
	case typ == reflect.PointerTo(u256Int):
		return writeU256IntPtr, nil
	case typ == u256Int:
		return writeU256IntNoPtr, nil
	case kind == reflect.Ptr:
		return makePtrWriter(typ, ts)
	case reflect.PointerTo(typ).Implements(encoderInterface):
		return makeEncoderWriter(typ), nil
	case isUint(kind):
		return writeUint, nil
	case kind == reflect.Bool:
		return writeBool, nil
	case kind == reflect.String:
		return writeString, nil
	case kind == reflect.Slice && isByte(typ.Elem()):
		return writeBytes, nil
	case kind == reflect.Array && isByte(typ.Elem()):
		return makeByteArrayWriter(typ), nil
	case kind == reflect.Slice || kind == reflect.Array:
		return makeSliceWriter(typ, ts)
	case kind == reflect.Struct:
		return makeStructWriter(typ)
	case kind == reflect.Interface:
		return writeInterface, nil
	default:
		return nil, fmt.Errorf("rlp: type %v is not RLP-serializable", typ)
	}
}

// writeRawValue 直接将 reflect.Value 中的原始字节数据追加到编码缓冲区 w 中。它假设 val 已经包含了 RLP 编码的数据。
func writeRawValue(val reflect.Value, w *encBuffer) error {
	w.str = append(w.str, val.Bytes()...)
	return nil
}

// writeUint 从 reflect.Value 中获取一个无符号整数，并调用 encBuffer 的 writeUint64 方法将其编码为 RLP 格式。
func writeUint(val reflect.Value, w *encBuffer) error {
	w.writeUint64(val.Uint())
	return nil
}

// writeBool 从 reflect.Value 中获取一个布尔值，并调用 encBuffer 的 writeBool 方法将其编码为 RLP 格式。
func writeBool(val reflect.Value, w *encBuffer) error {
	w.writeBool(val.Bool())
	return nil
}

// writeBigIntPtr 处理指向 big.Int 的指针。如果指针为空，则编码为 RLP 空字符串 (0x80)。如果 big.Int 是负数，则返回 ErrNegativeBigInt 错误。
// 否则，调用 encBuffer 的 writeBigInt 方法进行编码。
func writeBigIntPtr(val reflect.Value, w *encBuffer) error {
	ptr := val.Interface().(*big.Int)
	if ptr == nil {
		w.str = append(w.str, 0x80)
		return nil
	}
	if ptr.Sign() == -1 {
		return ErrNegativeBigInt
	}
	w.writeBigInt(ptr)
	return nil
}

// writeBigIntNoPtr 处理 big.Int 类型的值（非指针）。如果 big.Int 是负数，则返回 ErrNegativeBigInt 错误。
// 否则，调用 encBuffer 的 writeBigInt 方法进行编码（注意传递的是指针）。
func writeBigIntNoPtr(val reflect.Value, w *encBuffer) error {
	i := val.Interface().(big.Int)
	if i.Sign() == -1 {
		return ErrNegativeBigInt
	}
	w.writeBigInt(&i)
	return nil
}

// writeU256IntPtr 处理指向 uint256.Int 的指针。如果指针为空，则编码为 RLP 空字符串 (0x80)。
// 否则，调用 encBuffer 的 writeUint256 方法进行编码。
func writeU256IntPtr(val reflect.Value, w *encBuffer) error {
	ptr := val.Interface().(*uint256.Int)
	if ptr == nil {
		w.str = append(w.str, 0x80)
		return nil
	}
	w.writeUint256(ptr)
	return nil
}

// writeU256IntNoPtr 处理 uint256.Int 类型的值（非指针），并调用 encBuffer 的 writeUint256 方法进行编码（注意传递的是指针）。
func writeU256IntNoPtr(val reflect.Value, w *encBuffer) error {
	i := val.Interface().(uint256.Int)
	w.writeUint256(&i)
	return nil
}

// writeBytes从 reflect.Value 中获取一个字节切片，并调用 encBuffer 的 writeBytes 方法将其编码为 RLP 字符串。
func writeBytes(val reflect.Value, w *encBuffer) error {
	w.writeBytes(val.Bytes())
	return nil
}

// 用于为固定长度的字节数组类型 typ 创建一个 RLP writer 函数。它根据字节数组的长度采取不同的编码策略
func makeByteArrayWriter(typ reflect.Type) writer {
	switch typ.Len() {
	case 0:
		return writeLengthZeroByteArray
	case 1:
		return writeLengthOneByteArray
	default:
		length := typ.Len()
		return func(val reflect.Value, w *encBuffer) error {
			if !val.CanAddr() {
				// Getting the byte slice of val requires it to be addressable. Make it
				// addressable by copying.
				// 获取 val 的字节切片需要它是可寻址的。通过复制使其可寻址。
				copy := reflect.New(val.Type()).Elem()
				copy.Set(val)
				val = copy
			}
			slice := byteArrayBytes(val, length)
			w.encodeStringHeader(len(slice))
			w.str = append(w.str, slice...)
			return nil
		}
	}
}

// 对长度为零的字节数组进行 RLP 编码。
func writeLengthZeroByteArray(val reflect.Value, w *encBuffer) error {
	w.str = append(w.str, 0x80) // 将 RLP 编码的空字符串 (0x80) 追加到编码缓冲区 w 的字节切片 str 中。在 RLP 中，长度为零的字节数组与空字符串的编码方式相同。
	return nil
}

// 对长度为一的字节数组进行 RLP 编码。
func writeLengthOneByteArray(val reflect.Value, w *encBuffer) error {
	b := byte(val.Index(0).Uint())
	if b <= 0x7f { // 字节值小于等于 127，则根据 RLP 的单字节编码规则，直接将该字节追加到编码缓冲区 w
		w.str = append(w.str, b)
	} else { // 按照 RLP 字符串的编码规则，添加一个长度为 1 的字符串头 (0x81)，然后追加该字节。
		w.str = append(w.str, 0x81, b)
	}
	return nil
}

// RLP 字符串编码规则： 在 RLP 中，字符串（字节数组）的编码方式取决于其长度。
// 对于长度为 0-55 字节的字符串，编码为 0x80 + length 作为前缀，后跟字符串本身。如果字符串长度为 0，则编码为 0x80。
// 对于长度大于 55 字节的字符串，编码为 0xb7 + length_of_length 作为前缀，后跟字符串长度的字节表示，再后跟字符串本身。

// 将 Go 字符串类型 (reflect.Value 为字符串) 的值编码成 RLP 格式。
//
// 对字符串类型的值进行 RLP 编码。
// 针对长度为 1 且 ASCII 值小于等于 127 的字符串，直接编码为单个字节。
// 对于其他字符串，编码时添加 RLP 字符串头。
func writeString(val reflect.Value, w *encBuffer) error {
	s := val.String()
	if len(s) == 1 && s[0] <= 0x7f {
		// fits single byte, no string header
		// 适合单个字节，没有字符串头
		w.str = append(w.str, s[0])
	} else { // 如果字符串长度大于 1 或者单个字符的 ASCII 值大于 127，则需要按照 RLP 字符串的规则进行编码。
		w.encodeStringHeader(len(s))
		w.str = append(w.str, s...)
	}
	return nil
}

func writeInterface(val reflect.Value, w *encBuffer) error {
	//首先检查传入的 reflect.Value 是否表示一个 nil 接口。如果是 nil，为了保持与之前 RLP 编码器行为的一致性，它会将一个空的 RLP 列表 (0xC0) 追加到编码缓冲区 w 中。
	if val.IsNil() {
		// Write empty list. This is consistent with the previous RLP
		// encoder that we had and should therefore avoid any
		// problems.
		// 写入空列表。这与我们之前的 RLP 编码器保持一致，因此应该避免任何问题。
		w.str = append(w.str, 0xC0)
		return nil
	}
	eval := val.Elem()                       //  获取接口中实际存储的值的 reflect.Value。
	writer, err := cachedWriter(eval.Type()) // 传入实际值的类型 (eval.Type())，从类型缓存中获取该类型对应的 RLP 编码器 (writer)。
	if err != nil {
		return err
	}
	return writer(eval, w)
}

func makeSliceWriter(typ reflect.Type, ts rlpstruct.Tags) (writer, error) {
	etypeinfo := theTC.infoWhileGenerating(typ.Elem(), rlpstruct.Tags{})
	if etypeinfo.writerErr != nil {
		return nil, etypeinfo.writerErr
	}

	var wfn writer
	if ts.Tail {
		// This is for struct tail slices.
		// w.list is not called for them.
		// 这是用于结构体尾部切片的。
		// 不会为它们调用 w.list。
		// 对于尾部切片，不会调用 w.list() 和 w.listEnd()，这意味着尾部切片的内容会直接被写入到当前的 RLP 列表或结构中，而不会被包裹在一个额外的 RLP 列表头中。这通常用于编码结构体末尾的可变长度列表。
		wfn = func(val reflect.Value, w *encBuffer) error {
			vlen := val.Len()
			for i := 0; i < vlen; i++ {
				if err := etypeinfo.writer(val.Index(i), w); err != nil {
					return err
				}
			}
			return nil
		}
	} else {
		// This is for regular slices and arrays.
		// 这是用于常规切片和数组的。
		wfn = func(val reflect.Value, w *encBuffer) error {
			vlen := val.Len()
			if vlen == 0 { // 如果长度为 0，则将 RLP 空列表的编码 (0xC0) 直接追加到编码缓冲区 w。
				w.str = append(w.str, 0xC0)
				return nil
			}
			listOffset := w.list()
			for i := 0; i < vlen; i++ {
				if err := etypeinfo.writer(val.Index(i), w); err != nil {
					return err
				}
			}
			w.listEnd(listOffset)
			return nil
		}
	}
	return wfn, nil
}

// 用于为结构体类型 typ 创建一个 RLP writer 函数。它会处理结构体中包含可选字段的情况。
func makeStructWriter(typ reflect.Type) (writer, error) {
	fields, err := structFields(typ) // 获取结构体 typ 中所有需要编码的字段的信息，包括字段的索引、类型信息 (typeinfo) 和是否为可选字段。
	if err != nil {
		return nil, err
	}
	for _, f := range fields { // 遍历获取到的字段列表
		if f.info.writerErr != nil { // 检查每个字段的编码器 (f.info.writer) 在创建时是否发生错误。
			return nil, structFieldError{typ, f.index, f.info.writerErr}
		}
	}

	var writer writer
	firstOptionalField := firstOptionalField(fields) // 调用 firstOptionalField 函数获取第一个带有 "optional" 标签的字段的索引
	if firstOptionalField == len(fields) {           // 如果该索引等于字段的总数，则说明结构体中没有任何可选字段。
		// This is the writer function for structs without any optional fields.
		// 这是没有任何可选字段的结构体的编写器函数。
		writer = func(val reflect.Value, w *encBuffer) error {
			lh := w.list()             // 开始编码一个 RLP 列表
			for _, f := range fields { // 遍历结构体的所有字段，并依次调用每个字段的编码器 (f.info.writer) 来编码字段的值。
				if err := f.info.writer(val.Field(f.index), w); err != nil {
					return err
				}
			}
			w.listEnd(lh) // 结束 RLP 列表的编码。
			return nil
		}
	} else { // 如果结构体包含可选字段
		// If there are any "optional" fields, the writer needs to perform additional
		// checks to determine the output list length.
		// 如果存在任何 "optional" 字段，编写器需要执行额外的检查以确定输出列表的长度。
		writer = func(val reflect.Value, w *encBuffer) error {
			lastField := len(fields) - 1
			// 从最后一个字段开始向前遍历，直到找到第一个非零的可选字段（或者遍历到第一个可选字段）。lastField 记录了需要编码的最后一个字段的索引。
			for ; lastField >= firstOptionalField; lastField-- {
				if !val.Field(fields[lastField].index).IsZero() {
					break
				}
			}
			lh := w.list()
			// 遍历从第一个字段到 lastField 的所有字段（包括可选字段），并依次调用每个字段的编码器来编码字段的值。这样，只会编码到最后一个有值的可选字段，省略了后续值为零的可选字段。
			for i := 0; i <= lastField; i++ {
				if err := fields[i].info.writer(val.Field(fields[i].index), w); err != nil {
					return err
				}
			}
			w.listEnd(lh)
			return nil
		}
	}
	return writer, nil
}

// 用于为指针类型 typ 创建一个 RLP writer 函数。它处理了指针为空的情况以及非空指针的编码。
func makePtrWriter(typ reflect.Type, ts rlpstruct.Tags) (writer, error) {
	nilEncoding := byte(0xC0) //  默认情况下，空指针编码为 RLP 空列表 0xC0。
	// 调用 typeNilKind 函数来获取指针指向的元素类型 (typ.Elem()) 在 RLP 中 nil 值的编码类型。如果该类型应该编码为 RLP 字符串（例如 String），则将 nilEncoding 设置为 RLP 空字符串 0x80。
	if typeNilKind(typ.Elem(), ts) == String {
		nilEncoding = 0x80
	}

	// 调用类型缓存 theTC 的 infoWhileGenerating 方法，获取指针指向的元素类型的 typeinfo。这将确保元素类型的编码器（writer）已经被创建或从缓存中获取。
	etypeinfo := theTC.infoWhileGenerating(typ.Elem(), rlpstruct.Tags{})
	if etypeinfo.writerErr != nil {
		return nil, etypeinfo.writerErr
	}

	writer := func(val reflect.Value, w *encBuffer) error {
		// 使用 val.Elem() 获取指针指向的值 ev。ev.IsValid() 用于检查指针是否为空（即 ev 是否有效）。
		// 如果 ev 有效（指针非空），则调用之前获取的元素类型的编码器 etypeinfo.writer 来编码指针指向的值，并将结果写入编码缓冲区 w。
		if ev := val.Elem(); ev.IsValid() {
			return etypeinfo.writer(ev, w)
		}
		// 如果 ev 无效（指针为空），则将之前确定的空指针编码 (nilEncoding) 追加到编码缓冲区 w 的字节切片 str 中。
		w.str = append(w.str, nilEncoding)
		return nil
	}
	return writer, nil
}

// 根据给定的反射类型 typ 创建一个 RLP writer 函数。这个 writer 函数负责将该类型的值编码成 RLP 格式并写入到 encBuffer 中。
func makeEncoderWriter(typ reflect.Type) writer {
	if typ.Implements(encoderInterface) { // 这通常意味着该类型的 EncodeRLP 方法是一个值接收者。
		return func(val reflect.Value, w *encBuffer) error {
			return val.Interface().(Encoder).EncodeRLP(w)
		}
	}
	// 处理指针接收者的 Encoder 接口
	w := func(val reflect.Value, w *encBuffer) error {
		// 在调用指针接收者的 EncodeRLP 方法之前，需要获取值的指针。
		// val.CanAddr() 用于检查 reflect.Value 是否可寻址（即是否可以获取其指针）。
		// 如果 val 不可寻址，则意味着无法获取其指针，因此无法调用指针接收者的 EncodeRLP 方法。
		// 在这种情况下，函数会返回一个错误，说明该类型的值是不可寻址的，并且 EncodeRLP 是一个指针方法。
		if !val.CanAddr() {
			// package json simply doesn't call MarshalJSON for this case, but encodes the
			// value as if it didn't implement the interface. We don't want to handle it that
			// way.
			// json 包在这种情况下不会调用 MarshalJSON，而是像该值没有实现该接口一样进行编码。我们不希望以这种方式处理。
			return fmt.Errorf("rlp: unaddressable value of type %v, EncodeRLP is pointer method", val.Type())
		}
		return val.Addr().Interface().(Encoder).EncodeRLP(w) // 获取指针并调用 EncodeRLP
	}
	return w
}

// 大端字节序是指高位字节存储在低地址，低位字节存储在高地址。
// 函数通过右移操作（>>）和类型转换（byte()）将 i 的各个字节提取出来，并按大端顺序写入 b。

// 如果 i = 300（二进制 1 0010 1100）：
// 300 < (1 << 16)（65536），进入 2 字节分支。
// b[0] = byte(300 >> 8) = 1（高位）。
// b[1] = byte(300) = 44（低位）。
// 返回 2，表示用了 2 字节，结果为 [0x01, 0x2c]。

// putint writes i to the beginning of b in big endian byte
// order, using the least number of bytes needed to represent i.
//
// putint 将 i 以大端字节序写入 b 的开头，使用表示 i 所需的最少字节数。
// 用于将一个 uint64 类型的值 i 以大端字节序（big-endian）写入字节切片 b，并使用最少的字节数来表示该值。返回值 size 表示实际使用的字节数。
//
// putint 的作用是实现整数的紧凑字节表示，去除前导零，与 RLP 的“值字节”部分一致。
func putint(b []byte, i uint64) (size int) {
	switch {
	case i < (1 << 8):
		b[0] = byte(i)
		return 1
	case i < (1 << 16):
		b[0] = byte(i >> 8)
		b[1] = byte(i)
		return 2
	case i < (1 << 24):
		b[0] = byte(i >> 16)
		b[1] = byte(i >> 8)
		b[2] = byte(i)
		return 3
	case i < (1 << 32):
		b[0] = byte(i >> 24)
		b[1] = byte(i >> 16)
		b[2] = byte(i >> 8)
		b[3] = byte(i)
		return 4
	case i < (1 << 40):
		b[0] = byte(i >> 32)
		b[1] = byte(i >> 24)
		b[2] = byte(i >> 16)
		b[3] = byte(i >> 8)
		b[4] = byte(i)
		return 5
	case i < (1 << 48):
		b[0] = byte(i >> 40)
		b[1] = byte(i >> 32)
		b[2] = byte(i >> 24)
		b[3] = byte(i >> 16)
		b[4] = byte(i >> 8)
		b[5] = byte(i)
		return 6
	case i < (1 << 56):
		b[0] = byte(i >> 48)
		b[1] = byte(i >> 40)
		b[2] = byte(i >> 32)
		b[3] = byte(i >> 24)
		b[4] = byte(i >> 16)
		b[5] = byte(i >> 8)
		b[6] = byte(i)
		return 7
	default:
		b[0] = byte(i >> 56)
		b[1] = byte(i >> 48)
		b[2] = byte(i >> 40)
		b[3] = byte(i >> 32)
		b[4] = byte(i >> 24)
		b[5] = byte(i >> 16)
		b[6] = byte(i >> 8)
		b[7] = byte(i)
		return 8
	}
}

// 假设 i = 258（十进制，十六进制为 0x0102）：
//
// size = 1，i = 258，右移 8 位后 i = 1（258 >> 8 = 1），i != 0。
// size = 2，右移后 i = 0（1 >> 8 = 0），返回 size = 2。 结果：258 需要 2 个字节存储（0x01 和 0x02）。
// 假设 i = 0：
//
// size = 1，右移后 i = 0，返回 size = 1。 结果：0 需要 1 个字节（尽管在某些场景下可能是空字节，但这里至少返回 1）。
//
// RLP:
// 对于 i = 258，intsize(258) = 2，编码为 [0x82, 0x01, 0x02]（0x82 表示长度为 2 的字节数组）。
// 对于 i = 15，intsize(15) = 1，编码为 [0x0f]（直接单字节）。

// intsize computes the minimum number of bytes required to store i.
// intsize 计算存储 i 所需的最小字节数。
// 表示将 i 表示为字节数组时需要的最小长度。
//
// 在以太坊的 RLP 编码中，整数的编码需要动态确定字节长度，以确保紧凑性和正确性。具体规则：
//
// 如果整数值在 [0x00, 0x7f] 范围内（即小于 128），直接编码为单字节。
// 如果值大于 127，则先计算其最小字节长度（去掉前导零），然后添加前缀（0x80 + 长度）并拼接字节。
func intsize(i uint64) (size int) {
	// 初始化 size = 1，假设至少需要 1 个字节。
	// 使用无限循环，每次将 i 右移 8 位（即除以 256，因为 1 字节 = 8 位）。
	for size = 1; ; size++ {
		if i >>= 8; i == 0 { // 如果 i == 0，说明所有有效位已移出，返回当前的 size。
			return size
		}
	}
}
