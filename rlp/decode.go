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
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/rlp/internal/rlpstruct"
	"github.com/holiman/uint256"
)

//lint:ignore ST1012 EOL is not an error.

// EOL is returned when the end of the current list
// has been reached during streaming.
// EOL 在流式处理期间到达当前列表末尾时返回。
var EOL = errors.New("rlp: end of list")

var (
	ErrExpectedString   = errors.New("rlp: expected String or Byte")                   // ErrExpectedString 在输入不是字符串或字节时返回。
	ErrExpectedList     = errors.New("rlp: expected List")                             // ErrExpectedList 在输入不是列表时返回。
	ErrCanonInt         = errors.New("rlp: non-canonical integer format")              // ErrCanonInt 在整数没有以规范格式编码时返回。
	ErrCanonSize        = errors.New("rlp: non-canonical size information")            // ErrCanonSize 在大小信息没有以规范格式编码时返回。
	ErrElemTooLarge     = errors.New("rlp: element is larger than containing list")    // ErrElemTooLarge 在列表中元素的尺寸大于包含该元素的列表剩余尺寸时返回。
	ErrValueTooLarge    = errors.New("rlp: value size exceeds available input length") // ErrValueTooLarge 在值的尺寸超过可用输入长度时返回。
	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")        // ErrMoreThanOneValue 在输入包含多个顶级 RLP 值时返回。

	// internal errors
	errNotInList     = errors.New("rlp: call of ListEnd outside of any list")         // errNotInList 在流式处理期间，于任何列表上下文之外调用 ListEnd 时返回。
	errNotAtEOL      = errors.New("rlp: call of ListEnd not positioned at EOL")       // errNotAtEOL 在调用 ListEnd 时，流尚未到达当前列表的末尾时返回。
	errUintOverflow  = errors.New("rlp: uint overflow")                               // errUintOverflow 在无符号整数运算导致溢出时返回。
	errNoPointer     = errors.New("rlp: interface given to Decode must be a pointer") // errNoPointer 在传递给 Decode 函数的值不是指针时返回。
	errDecodeIntoNil = errors.New("rlp: pointer given to Decode must not be nil")     // errDecodeIntoNil 在传递给 Decode 函数的指针为空时返回。
	errUint256Large  = errors.New("rlp: value too large for uint256")                 // errUint256Large 在值太大而无法表示为 uint256 时返回。

	// streamPool 是 Stream 对象的池，用于高效地重用。
	streamPool = sync.Pool{
		New: func() interface{} { return new(Stream) },
	}
)

// Decoder is implemented by types that require custom RLP decoding rules or need to decode
// into private fields.
//
// The DecodeRLP method should read one value from the given Stream. It is not forbidden to
// read less or more, but it might be confusing.
//
// Decoder 接口由需要自定义 RLP 解码规则或需要解码到私有字段的类型实现。
//
// DecodeRLP 方法应该从给定的 Stream 中读取一个值。读取更少或更多并没有被禁止，但这可能会引起混淆。
type Decoder interface {
	DecodeRLP(*Stream) error
}

// Decode parses RLP-encoded data from r and stores the result in the value pointed to by
// val. Please see package-level documentation for the decoding rules. Val must be a
// non-nil pointer.
//
// If r does not implement ByteReader, Decode will do its own buffering.
//
// Note that Decode does not set an input limit for all readers and may be vulnerable to
// panics cause by huge value sizes. If you need an input limit, use
//
//	NewStream(r, limit).Decode(val)
//
// Decode 从 r 解析 RLP 编码的数据，并将结果存储到 val 指向的值中。
// 请参阅包级别的文档以了解解码规则。Val 必须是一个非 nil 的指针。
//
// 如果 r 没有实现 ByteReader 接口，Decode 将自行进行缓冲。
//
// 注意，Decode 并未为所有 reader 设置输入限制，并且可能容易受到由巨大值大小引起的 panic 的影响。
// 如果需要输入限制，请使用
//
//	NewStream(r, limit).Decode(val)
func Decode(r io.Reader, val interface{}) error {
	stream := streamPool.Get().(*Stream)
	defer streamPool.Put(stream)

	// 使用提供的 reader 和 0 初始输入限制重置 Stream。
	stream.Reset(r, 0)
	// 调用 Stream 对象的 Decode 方法来执行实际的解码。
	return stream.Decode(val)
}

// DecodeBytes parses RLP data from b into val. Please see package-level documentation for
// the decoding rules. The input must contain exactly one value and no trailing data.
//
// DecodeBytes 从 b 解析 RLP 数据到 val 中。请参阅包级别的文档以了解解码规则。
// 输入必须只包含一个值，并且没有尾部数据。
//
// 解码单个 RLP 编码项： 在以太坊中，有时需要解码一个单独的 RLP 编码项，例如一个交易的签名、一个区块头的某个字段等。 DecodeBytes 非常适合这种场景。
// 处理来自特定来源的字节数据： 当从特定的数据源（例如数据库或文件）读取到 RLP 编码的字节切片时，可以使用 DecodeBytes 进行解码。
func DecodeBytes(b []byte, val interface{}) error {
	// 创建一个 sliceReader 以从字节切片中读取数据。
	// 提供了一种方便的方式来解码内存中的 RLP 编码数据。
	r := (*sliceReader)(&b)

	stream := streamPool.Get().(*Stream)
	defer streamPool.Put(stream)

	// 使用 sliceReader 和字节切片的长度作为输入限制来重置 Stream。
	stream.Reset(r, uint64(len(b)))
	// 将 RLP 数据解码到 val 中。
	if err := stream.Decode(val); err != nil {
		return err
	}
	// 检查解码后字节切片中是否还有剩余数据。
	if len(b) > 0 {
		return ErrMoreThanOneValue
	}
	return nil
}

type decodeError struct {
	msg string       // 存储具体的错误消息。
	typ reflect.Type // 存储解码失败的目标值的类型，这对于调试错误很有帮助。
	ctx []string     //  一个字符串切片，用于存储错误发生的上下文信息。例如，在解码嵌套结构时，可以记录当前正在解码的字段名称。
}

func (err *decodeError) Error() string {
	ctx := ""
	if len(err.ctx) > 0 {
		ctx = ", decoding into "
		for i := len(err.ctx) - 1; i >= 0; i-- {
			ctx += err.ctx[i]
		}
	}
	return fmt.Sprintf("rlp: %s for %v%s", err.msg, err.typ, ctx)
}

// 用于包装由底层的 Stream 对象返回的原始错误。它接收一个 error 和一个 reflect.Type 作为参数，并根据原始错误的类型返回一个更具描述性的 decodeError 实例。
func wrapStreamError(err error, typ reflect.Type) error {
	switch err {
	case ErrCanonInt:
		return &decodeError{msg: "non-canonical integer (leading zero bytes)", typ: typ}
	case ErrCanonSize:
		return &decodeError{msg: "non-canonical size information", typ: typ}
	case ErrExpectedList:
		return &decodeError{msg: "expected input list", typ: typ}
	case ErrExpectedString:
		return &decodeError{msg: "expected input string or byte", typ: typ}
	case errUintOverflow:
		return &decodeError{msg: "input string too long", typ: typ}
	case errNotAtEOL:
		return &decodeError{msg: "input list has too many elements", typ: typ}
	}
	return err
}

// 用于向一个已有的错误添加上下文信息。这在解码嵌套的数据结构时非常有用，可以追踪错误发生的具体位置。
func addErrorContext(err error, ctx string) error {
	if decErr, ok := err.(*decodeError); ok {
		decErr.ctx = append(decErr.ctx, ctx)
	}
	return err
}

var (
	decoderInterface = reflect.TypeOf(new(Decoder)).Elem() // Elem() 方法返回接口指针所指向的元素的类型。对于接口指针，Elem() 会返回接口自身的类型。因此，decoderInterface 最终存储的是 Decoder 接口的反射类型。
	bigInt           = reflect.TypeOf(big.Int{})
	u256Int          = reflect.TypeOf(uint256.Int{})
)

// 接收一个 Go 语言的类型 (reflect.Type) 和 RLP 结构体标签 (rlpstruct.Tags) 作为输入，并返回一个用于解码该类型的 RLP 数据的 decoder 函数。
func makeDecoder(typ reflect.Type, tags rlpstruct.Tags) (dec decoder, err error) {
	kind := typ.Kind()
	switch {
	case typ == rawValueType:
		return decodeRawValue, nil
	case typ.AssignableTo(reflect.PointerTo(bigInt)):
		return decodeBigInt, nil
	case typ.AssignableTo(bigInt):
		return decodeBigIntNoPtr, nil
	case typ == reflect.PointerTo(u256Int):
		return decodeU256, nil
	case typ == u256Int:
		return decodeU256NoPtr, nil
	case kind == reflect.Ptr:
		return makePtrDecoder(typ, tags)
	case reflect.PointerTo(typ).Implements(decoderInterface):
		return decodeDecoder, nil
	case isUint(kind):
		return decodeUint, nil
	case kind == reflect.Bool:
		return decodeBool, nil
	case kind == reflect.String:
		return decodeString, nil
	case kind == reflect.Slice || kind == reflect.Array:
		return makeListDecoder(typ, tags)
	case kind == reflect.Struct:
		return makeStructDecoder(typ)
	case kind == reflect.Interface:
		return decodeInterface, nil
	default:
		return nil, fmt.Errorf("rlp: type %v is not RLP-serializable", typ)
	}
}

// 解码原始的 RLP 编码值（包括类型信息）到一个字节切片。
func decodeRawValue(s *Stream, val reflect.Value) error {
	r, err := s.Raw()
	if err != nil {
		return err
	}
	val.SetBytes(r)
	return nil
}

// 解码一个无符号整数。
func decodeUint(s *Stream, val reflect.Value) error {
	typ := val.Type()              // 获取目标值 val 的类型，
	num, err := s.uint(typ.Bits()) // 并使用 typ.Bits() 获取其位大小。然后调用 s.uint() 方法读取相应位大小的无符号整数。
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetUint(num)
	return nil
}

// 解码一个布尔值。
func decodeBool(s *Stream, val reflect.Value) error {
	b, err := s.Bool()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetBool(b)
	return nil
}

// 解码一个字符串（RLP 编码的字节序列）。
func decodeString(s *Stream, val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetString(string(b))
	return nil
}

// 解码一个 math/big.Int 类型的值，该值可能不是指针类型。
func decodeBigIntNoPtr(s *Stream, val reflect.Value) error {
	return decodeBigInt(s, val.Addr())
}

// 解码一个 math/big.Int 类型的值。
func decodeBigInt(s *Stream, val reflect.Value) error {
	i := val.Interface().(*big.Int) // 获取 val 中存储的 big.Int 指针
	if i == nil {
		i = new(big.Int)
		val.Set(reflect.ValueOf(i))
	}

	err := s.decodeBigInt(i)
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	return nil
}

// 解码一个 github.com/holiman/uint256.Int 类型的值，该值可能不是指针类型。
func decodeU256NoPtr(s *Stream, val reflect.Value) error {
	return decodeU256(s, val.Addr())
}

// 解码一个 github.com/holiman/uint256.Int 类型的值。
func decodeU256(s *Stream, val reflect.Value) error {
	i := val.Interface().(*uint256.Int)
	if i == nil {
		i = new(uint256.Int)
		val.Set(reflect.ValueOf(i))
	}

	err := s.ReadUint256(i)
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	return nil
}

// 用于为切片 ([]T) 和数组 ([n]T) 类型创建 RLP 解码器。它根据元素类型和结构体标签采取不同的解码策略。
func makeListDecoder(typ reflect.Type, tag rlpstruct.Tags) (decoder, error) {
	etype := typ.Elem()
	if etype.Kind() == reflect.Uint8 && !reflect.PointerTo(etype).Implements(decoderInterface) {
		if typ.Kind() == reflect.Array {
			return decodeByteArray, nil
		}
		return decodeByteSlice, nil
	}
	etypeinfo := theTC.infoWhileGenerating(etype, rlpstruct.Tags{})
	if etypeinfo.decoderErr != nil {
		return nil, etypeinfo.decoderErr
	}
	var dec decoder
	switch {
	case typ.Kind() == reflect.Array:
		dec = func(s *Stream, val reflect.Value) error {
			return decodeListArray(s, val, etypeinfo.decoder)
		}
	case tag.Tail:
		// A slice with "tail" tag can occur as the last field
		// of a struct and is supposed to swallow all remaining
		// list elements. The struct decoder already called s.List,
		// proceed directly to decoding the elements.
		//
		// 带有 "tail" 标签的切片可以作为结构体的最后一个字段出现，
		// 并且应该吞噬所有剩余的列表元素。结构体解码器已经调用了 s.List，
		// 直接进行元素的解码。
		dec = func(s *Stream, val reflect.Value) error {
			return decodeSliceElems(s, val, etypeinfo.decoder)
		}
	default:
		dec = func(s *Stream, val reflect.Value) error {
			return decodeListSlice(s, val, etypeinfo.decoder)
		}
	}
	return dec, nil
}

// 将一个 RLP 列表解码到切片。
func decodeListSlice(s *Stream, val reflect.Value, elemdec decoder) error {
	size, err := s.List()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	if size == 0 {
		val.Set(reflect.MakeSlice(val.Type(), 0, 0))
		return s.ListEnd()
	}
	if err := decodeSliceElems(s, val, elemdec); err != nil {
		return err
	}
	return s.ListEnd()
}

// 实际解码 RLP 列表的元素到切片中。
func decodeSliceElems(s *Stream, val reflect.Value, elemdec decoder) error {
	i := 0
	for ; ; i++ {
		// grow slice if necessary
		if i >= val.Cap() { // 如果切片的容量不足以容纳新的元素，它会进行扩容，扩容策略是当前容量的 1.5 倍，最小为 4。
			newcap := val.Cap() + val.Cap()/2
			if newcap < 4 {
				newcap = 4
			}
			newv := reflect.MakeSlice(val.Type(), val.Len(), newcap)
			reflect.Copy(newv, val)
			val.Set(newv)
		}
		if i >= val.Len() {
			val.SetLen(i + 1)
		}
		// decode into element
		if err := elemdec(s, val.Index(i)); err == EOL {
			break
		} else if err != nil {
			return addErrorContext(err, fmt.Sprint("[", i, "]"))
		}
	}
	if i < val.Len() {
		val.SetLen(i)
	}
	return nil
}

// 将一个 RLP 列表解码到数组
func decodeListArray(s *Stream, val reflect.Value, elemdec decoder) error {
	if _, err := s.List(); err != nil {
		return wrapStreamError(err, val.Type())
	}
	vlen := val.Len()
	i := 0
	for ; i < vlen; i++ {
		if err := elemdec(s, val.Index(i)); err == EOL {
			break
		} else if err != nil {
			return addErrorContext(err, fmt.Sprint("[", i, "]"))
		}
	}
	if i < vlen {
		return &decodeError{msg: "input list has too few elements", typ: val.Type()}
	}
	return wrapStreamError(s.ListEnd(), val.Type())
}

// 将一个 RLP 字符串或字节解码到一个 []byte 类型的切片。
func decodeByteSlice(s *Stream, val reflect.Value) error {
	b, err := s.Bytes()
	if err != nil {
		return wrapStreamError(err, val.Type())
	}
	val.SetBytes(b)
	return nil
}

// 将一个 RLP 字符串或字节解码到字节数组 ([n]byte)。
func decodeByteArray(s *Stream, val reflect.Value) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}
	slice := byteArrayBytes(val, val.Len())
	switch kind {
	case Byte:
		if len(slice) == 0 {
			return &decodeError{msg: "input string too long", typ: val.Type()}
		} else if len(slice) > 1 {
			return &decodeError{msg: "input string too short", typ: val.Type()}
		}
		slice[0] = s.byteval
		s.kind = -1
	case String:
		if uint64(len(slice)) < size {
			return &decodeError{msg: "input string too long", typ: val.Type()}
		}
		if uint64(len(slice)) > size {
			return &decodeError{msg: "input string too short", typ: val.Type()}
		}
		if err := s.readFull(slice); err != nil {
			return err
		}
		// Reject cases where single byte encoding should have been used.
		if size == 1 && slice[0] < 128 {
			return wrapStreamError(ErrCanonSize, val.Type())
		}
	case List:
		return wrapStreamError(ErrExpectedString, val.Type())
	}
	return nil
}

func makeStructDecoder(typ reflect.Type) (decoder, error) {
	fields, err := structFields(typ)
	if err != nil {
		return nil, err
	}
	for _, f := range fields {
		if f.info.decoderErr != nil {
			return nil, structFieldError{typ, f.index, f.info.decoderErr}
		}
	}
	dec := func(s *Stream, val reflect.Value) (err error) {
		if _, err := s.List(); err != nil { // 调用 s.List() 检查输入流是否是一个 RLP 列表，如果不是则返回包装后的错误。
			return wrapStreamError(err, typ)
		}
		for i, f := range fields {
			err := f.info.decoder(s, val.Field(f.index))
			if err == EOL {
				if f.optional {
					// The field is optional, so reaching the end of the list before
					// reaching the last field is acceptable. All remaining undecoded
					// fields are zeroed.
					// 该字段是可选的，因此在到达最后一个字段之前到达列表末尾是可以接受的。
					// 所有剩余未解码的字段都将被置零。
					zeroFields(val, fields[i:])
					break
				}
				return &decodeError{msg: "too few elements", typ: typ}
			} else if err != nil {
				return addErrorContext(err, "."+typ.Field(f.index).Name)
			}
		}
		return wrapStreamError(s.ListEnd(), typ)
	}
	return dec, nil
}

// 将结构体 structval 中指定的 fields 设置为它们的零值。
func zeroFields(structval reflect.Value, fields []field) {
	for _, f := range fields {
		fv := structval.Field(f.index)  // 获取结构体中对应索引的字段的 reflect.Value。
		fv.Set(reflect.Zero(fv.Type())) // 将该字段的值设置为其类型的零值。reflect.Zero() 函数会返回给定类型的零值的 reflect.Value。
	}
}

// makePtrDecoder creates a decoder that decodes into the pointer's element type.
// makePtrDecoder 创建一个解码器，该解码器解码到指针的元素类型。
func makePtrDecoder(typ reflect.Type, tag rlpstruct.Tags) (decoder, error) {
	etype := typ.Elem()
	etypeinfo := theTC.infoWhileGenerating(etype, rlpstruct.Tags{})
	switch {
	case etypeinfo.decoderErr != nil:
		return nil, etypeinfo.decoderErr
	case !tag.NilOK:
		return makeSimplePtrDecoder(etype, etypeinfo), nil
	default:
		return makeNilPtrDecoder(etype, etypeinfo, tag), nil
	}
}

// 为非 nilable 的指针类型创建一个解码器函数。
func makeSimplePtrDecoder(etype reflect.Type, etypeinfo *typeinfo) decoder {
	return func(s *Stream, val reflect.Value) (err error) {
		newval := val
		if val.IsNil() {
			newval = reflect.New(etype)
		}
		if err = etypeinfo.decoder(s, newval.Elem()); err == nil {
			val.Set(newval)
		}
		return err
	}
}

// makeNilPtrDecoder creates a decoder that decodes empty values as nil. Non-empty
// values are decoded into a value of the element type, just like makePtrDecoder does.
//
// This decoder is used for pointer-typed struct fields with struct tag "nil".
//
// makeNilPtrDecoder 创建一个解码器，该解码器将空值解码为 nil。非空值像 makePtrDecoder 一样解码为元素类型的值。
//
// decoder 用于带有结构体标签 "nil" 的指针类型结构体字段。
func makeNilPtrDecoder(etype reflect.Type, etypeinfo *typeinfo, ts rlpstruct.Tags) decoder {
	typ := reflect.PointerTo(etype)
	nilPtr := reflect.Zero(typ)

	// Determine the value kind that results in nil pointer.
	// 确定导致 nil 指针的值类型。
	nilKind := typeNilKind(etype, ts)

	return func(s *Stream, val reflect.Value) (err error) {
		kind, size, err := s.Kind()
		if err != nil {
			val.Set(nilPtr)
			return wrapStreamError(err, typ)
		}
		// Handle empty values as a nil pointer.
		// 将空值处理为 nil 指针。
		if kind != Byte && size == 0 {
			if kind != nilKind {
				return &decodeError{
					msg: fmt.Sprintf("wrong kind of empty value (got %v, want %v)", kind, nilKind),
					typ: typ,
				}
			}
			// rearm s.Kind. This is important because the input
			// position must advance to the next value even though
			// we don't read anything.
			// 重新设置 s.Kind。这很重要，因为即使我们不读取任何内容，
			// 输入位置也必须前进到下一个值。
			s.kind = -1
			val.Set(nilPtr)
			return nil
		}
		newval := val
		if val.IsNil() {
			newval = reflect.New(etype)
		}
		if err = etypeinfo.decoder(s, newval.Elem()); err == nil {
			val.Set(newval)
		}
		return err
	}
}

var ifsliceType = reflect.TypeOf([]interface{}{})

// 用于将 RLP 编码的数据解码到 reflect.Value 表示的接口类型。它对不同类型的 RLP 数据（列表或字符串/字节）采取了不同的处理方式。
func decodeInterface(s *Stream, val reflect.Value) error {
	if val.Type().NumMethod() != 0 {
		return fmt.Errorf("rlp: type %v is not RLP-serializable", val.Type())
	}
	kind, _, err := s.Kind()
	if err != nil {
		return err
	}
	if kind == List {
		slice := reflect.New(ifsliceType).Elem()
		if err := decodeListSlice(s, slice, decodeInterface); err != nil {
			return err
		}
		val.Set(slice)
	} else {
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		val.Set(reflect.ValueOf(b))
	}
	return nil
}

// 用于处理实现了自定义 Decoder 接口的类型的解码器函数
func decodeDecoder(s *Stream, val reflect.Value) error {
	return val.Addr().Interface().(Decoder).DecodeRLP(s)
}

// Kind represents the kind of value contained in an RLP stream.
// Kind 表示 RLP 流中包含的值的类型。
type Kind int8

const (
	Byte   Kind = iota // Byte 通常指单个字节的值，特别是当该值小于 128 时，可以直接编码为该字节本身。
	String             // String 指的是字节序列（可以是一个字节，也可以是多个字节），其编码方式取决于字节序列的长度和内容。
	List               // List 指的是一个包含其他 RLP 编码的值（可以是 Byte、String 或其他的 List）的有序集合。
)

func (k Kind) String() string {
	switch k {
	case Byte:
		return "Byte"
	case String:
		return "String"
	case List:
		return "List"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// ByteReader must be implemented by any input reader for a Stream. It
// is implemented by e.g. bufio.Reader and bytes.Reader.
// ByteReader 必须由任何作为 Stream 的输入读取器实现。例如，bufio.Reader 和 bytes.Reader 就实现了它。
type ByteReader interface {
	io.Reader
	io.ByteReader
}

// Stream can be used for piecemeal decoding of an input stream. This
// is useful if the input is very large or if the decoding rules for a
// type depend on the input structure. Stream does not keep an
// internal buffer. After decoding a value, the input reader will be
// positioned just before the type information for the next value.
//
// When decoding a list and the input position reaches the declared
// length of the list, all operations will return error EOL.
// The end of the list must be acknowledged using ListEnd to continue
// reading the enclosing list.
//
// Stream is not safe for concurrent use.
//
// Stream 可用于输入流的逐段解码。当输入非常大或者类型的解码规则依赖于输入结构时，这非常有用。
// Stream 不保留内部缓冲区。解码一个值后，输入读取器将定位在下一个值的类型信息之前。
//
// 当解码列表且输入位置到达列表声明的长度时，所有操作都将返回错误 EOL。
// 必须使用 ListEnd 确认列表的结束，才能继续读取外层列表。
//
// Stream 不是并发安全的。
type Stream struct {
	r ByteReader // 从中读取数据的输入源，提供了读取字节序列和单个字节的能力。 Stream 可以处理来自不同来源的 RLP 数据，例如 bytes.Reader（内存中的字节数组）或 bufio.Reader（带缓冲的读取器，通常用于文件或网络）。

	// remaining 记录了从当前的 RLP 值中剩余需要读取的字节数。
	// 当解码一个已知长度的 RLP 编码时（例如一个定长的字符串或一个长度前缀明确的列表），remaining 会被设置，并在读取数据的过程中递减。
	// 当 remaining 变为 0 时，表示当前值已经完全读取完毕。
	remaining uint64 // number of bytes remaining to be read from r  从 r 中剩余要读取的字节数
	// size 存储了即将被解码的下一个 RLP 值的总大小（以字节为单位）。在读取类型标签后，Stream 会解析出后续数据的长度，并将其存储在 size 字段中。
	size uint64 // size of value ahead 前面值的尺寸
	// 用于存储在上次调用 readKind 方法时发生的错误。
	// readKind 方法是 Stream 内部用于读取和解析 RLP 类型标签的函数。
	kinderr error // error from last readKind 上次 readKind 操作产生的错误
	// stack 用于跟踪当前正在解码的嵌套列表的剩余长度。当开始解码一个列表时，该列表的长度会被压入栈中。
	// 当读取完列表中的所有元素后，需要调用 ListEnd 方法来将该长度从栈中弹出。
	// 如果尝试在列表结束前读取更多数据，或者在列表结束后不调用 ListEnd，可能会导致错误。这对于正确处理嵌套的 RLP 列表至关重要。
	stack []uint64 // list sizes   列表尺寸堆栈
	// uintbuf 辅助的字节数组，用作解码整数时的临时缓冲区。RLP 编码的整数可以直接嵌入类型标签中（对于较小的整数）或者作为后续的数据部分（对于较大的整数）。
	// 这个缓冲区用于存储从输入流中读取的整数的字节表示。
	uintbuf [32]byte // auxiliary buffer for integer decoding  用于整数解码的辅助缓冲区
	// kind 存储了即将被解码的下一个 RLP 值的类型。RLP 定义了几种基本类型：单个字节、短字符串、长字符串和列表。
	kind Kind // kind of value ahead 前面值的类型
	// 当下一个 RLP 值是单个字节时，这个字段会存储该字节的值。这通常用于编码 0 到 127 的整数。
	byteval byte // value of single byte in type tag 类型标签中单个字节的值
	// 表示是否启用了输入限制。在某些情况下，为了防止恶意构造的过长数据导致资源耗尽，可能会对输入流的大小进行限制。
	limited bool // true if input limit is in effect  如果输入限制生效则为 true
}

// NewStream creates a new decoding stream reading from r.
//
// If r implements the ByteReader interface, Stream will
// not introduce any buffering.
//
// For non-toplevel values, Stream returns ErrElemTooLarge
// for values that do not fit into the enclosing list.
//
// Stream supports an optional input limit. If a limit is set, the
// size of any toplevel value will be checked against the remaining
// input length. Stream operations that encounter a value exceeding
// the remaining input length will return ErrValueTooLarge. The limit
// can be set by passing a non-zero value for inputLimit.
//
// If r is a bytes.Reader or strings.Reader, the input limit is set to
// the length of r's underlying data unless an explicit limit is
// provided.
//
// NewStream 创建一个新的解码流，从 r 中读取数据。
//
// 如果 r 实现了 ByteReader 接口，Stream 将不会引入任何缓冲。
//
// 对于非顶层的值，如果值不适合放入封闭的列表中，Stream 将返回 ErrElemTooLarge。
//
// Stream 支持可选的输入限制。如果设置了限制，任何顶层值的大小都将根据剩余的输入长度进行检查。
// 遇到超出剩余输入长度的值的 Stream 操作将返回 ErrValueTooLarge。可以通过为 inputLimit 传递一个非零值来设置限制。
//
// 如果 r 是 bytes.Reader 或 strings.Reader，则输入限制将设置为 r 底层数据的长度，除非提供了显式限制。
func NewStream(r io.Reader, inputLimit uint64) *Stream {
	s := new(Stream)
	s.Reset(r, inputLimit)
	return s
}

// NewListStream creates a new stream that pretends to be positioned
// at an encoded list of the given length.
//
// NewListStream 创建一个新的流，该流假装位于给定长度的编码列表的开头。
func NewListStream(r io.Reader, len uint64) *Stream {
	s := new(Stream)
	s.Reset(r, len)
	s.kind = List
	s.size = len
	return s
}

// Bytes reads an RLP string and returns its contents as a byte slice.
// If the input does not contain an RLP string, the returned
// error will be ErrExpectedString.
//
// Bytes 读取一个 RLP 字符串并将其内容作为字节切片返回。
// 如果输入不包含 RLP 字符串，则返回的错误将是 ErrExpectedString。
func (s *Stream) Bytes() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	switch kind {
	case Byte:
		s.kind = -1 // rearm Kind
		return []byte{s.byteval}, nil
	case String:
		b := make([]byte, size)
		if err = s.readFull(b); err != nil {
			return nil, err
		}
		if size == 1 && b[0] < 128 { // 进行规范性检查。如果读取的字符串长度为 1 且该字节的值小于 128，则说明应该使用单个字节编码而不是长度为 1 的字符串编码
			return nil, ErrCanonSize
		}
		return b, nil
	default: // 如果下一个值的类型既不是 Byte 也不是 String
		return nil, ErrExpectedString
	}
}

// ReadBytes decodes the next RLP value and stores the result in b.
// The value size must match len(b) exactly.
//
// ReadBytes 解码下一个 RLP 值并将结果存储到 b 中。
// 该值的大小必须与 len(b) 完全匹配。
//
// 用于从 RLP 编码的数据流中读取下一个值，并将其存储到提供的字节切片 b 中。一个关键的要求是，RLP 编码的值的大小（以字节为单位）必须与 b 的长度完全一致。
//
// ReadBytes 方法非常适合用于解码这些固定长度的字节数据。例如，在解码以太坊交易时，可以使用 ReadBytes 来读取接收者地址、交易哈希等字段。
func (s *Stream) ReadBytes(b []byte) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}
	switch kind {
	case Byte:
		if len(b) != 1 { // 检查提供的字节切片 b 的长度是否为 1。
			return fmt.Errorf("input value has wrong size 1, want %d", len(b))
		}
		// 如果 b 的长度为 1，则将读取到的字节值 s.byteval 存储到 b 的第一个元素中。
		b[0] = s.byteval
		s.kind = -1 // rearm Kind
		return nil
	case String:
		if uint64(len(b)) != size { // 检查提供的字节切片 b 的长度是否为 1。
			return fmt.Errorf("input value has wrong size %d, want %d", size, len(b))
		}
		if err = s.readFull(b); err != nil {
			return err
		}
		if size == 1 && b[0] < 128 { // 如果读取的字符串长度为 1 且该字节的值小于 128，则说明应该使用单个字节编码而不是长度为 1 的字符串编码
			return ErrCanonSize
		}
		return nil
	default:
		return ErrExpectedString
	}
}

// Raw reads a raw encoded value including RLP type information.
// Raw 读取原始编码的值，包括 RLP 类型信息。
//
// Raw 用于读取输入流中下一个 RLP 编码的原始字节序列，包括其类型信息（即 RLP 头部）。这在需要直接操作 RLP 编码数据而无需完全解码时非常有用。
func (s *Stream) Raw() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind == Byte {
		s.kind = -1 // rearm Kind  重新准备 Kind
		return []byte{s.byteval}, nil
	}
	// The original header has already been read and is no longer
	// available. Read content and put a new header in front of it.
	//
	// 原始头部已被读取，不再可用。读取内容并在其前面放置一个新的头部。
	start := headsize(size)
	buf := make([]byte, uint64(start)+size)
	if err := s.readFull(buf[start:]); err != nil {
		return nil, err
	}
	if kind == String {
		puthead(buf, 0x80, 0xB7, size)
	} else {
		puthead(buf, 0xC0, 0xF7, size)
	}
	return buf, nil
}

// Uint reads an RLP string of up to 8 bytes and returns its contents
// as an unsigned integer. If the input does not contain an RLP string, the
// returned error will be ErrExpectedString.
//
// Deprecated: use s.Uint64 instead.
//
// Uint 读取一个最多 8 字节的 RLP 字符串，并将其内容作为无符号整数返回。
// 如果输入不包含 RLP 字符串，则返回的错误将是 ErrExpectedString。
//
// Deprecated: 请使用 s.Uint64 代替。
func (s *Stream) Uint() (uint64, error) {
	return s.uint(64)
}

func (s *Stream) Uint64() (uint64, error) {
	return s.uint(64)
}

func (s *Stream) Uint32() (uint32, error) {
	i, err := s.uint(32)
	return uint32(i), err
}

func (s *Stream) Uint16() (uint16, error) {
	i, err := s.uint(16)
	return uint16(i), err
}

func (s *Stream) Uint8() (uint8, error) {
	i, err := s.uint(8)
	return uint8(i), err
}

// uint 用于从 RLP 编码的数据流中读取一个指定最大比特数 (maxbits) 的无符号整数，并将其作为 uint64 类型返回。
func (s *Stream) uint(maxbits int) (uint64, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	switch kind {
	case Byte: // RLP 编码的无符号整数可以表示为单个字节（如果值小于 128）或字节字符串。
		if s.byteval == 0 { // 根据 RLP 规范，对于需要使用多字节编码的整数（实际上这里是所有大于等于 0 的整数，因为 0 可以编码为长度为 0 的字符串），不应该使用值为 0 的单个字节来表示。
			return 0, ErrCanonInt
		}
		s.kind = -1 // rearm Kind 重新准备 Kind
		return uint64(s.byteval), nil
	case String:
		if size > uint64(maxbits/8) { //  如果编码的字节数超过了 maxbits 所允许的最大字节数
			return 0, errUintOverflow
		}
		v, err := s.readUint(byte(size))
		switch {
		case err == ErrCanonSize: // 如果 s.readUint 返回了 ErrCanonSize 错误（表示读取的长度不规范，例如前导零），则将其转换为 ErrCanonInt 错误，因为当前上下文是在解码一个整数值。
			// Adjust error because we're not reading a size right now.
			// 调整错误，因为我们现在不是在读取尺寸。
			return 0, ErrCanonInt
		case err != nil:
			return 0, err
		case size > 0 && v < 128: // 检查是否使用了多字节编码来表示一个小于 128 的值。根据 RLP 规范，小于 128 的值应该直接编码为单个字节。
			return 0, ErrCanonSize
		default:
			return v, nil
		}
	default:
		return 0, ErrExpectedString
	}
}

// Bool reads an RLP string of up to 1 byte and returns its contents
// as a boolean. If the input does not contain an RLP string, the
// returned error will be ErrExpectedString.
//
// Bool 读取一个最多 1 字节的 RLP 字符串，并将其内容作为布尔值返回。
// 如果输入不包含 RLP 字符串，则返回的错误将是 ErrExpectedString。
//
// Bool 用于从 RLP 编码的数据流中读取一个布尔值。在 RLP 中，布尔值通常被编码为整数：0 代表 false，1 代表 true。
func (s *Stream) Bool() (bool, error) {
	// 读取一个无符号的 8 位整数（应该表示布尔值）。
	num, err := s.uint(8)
	if err != nil {
		return false, err
	}
	// 将整数值解释为布尔值。
	switch num {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("rlp: invalid boolean value: %d", num)
	}
}

// List starts decoding an RLP list. If the input does not contain a
// list, the returned error will be ErrExpectedList. When the list's
// end has been reached, any Stream operation will return EOL.
//
// List 开始解码一个 RLP 列表。如果输入不包含列表，则返回的错误将是 ErrExpectedList。
// 当到达列表的末尾时，任何 Stream 操作都将返回 EOL。
func (s *Stream) List() (size uint64, err error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	if kind != List { // 检查输入流的下一个 RLP 编码是否表示一个列表。
		return 0, ErrExpectedList
	}

	// Remove size of inner list from outer list before pushing the new size
	// onto the stack. This ensures that the remaining outer list size will
	// be correct after the matching call to ListEnd.
	// 在将新列表的大小压入堆栈之前，从外层列表中减去内层列表的大小。
	// 这确保在匹配调用 ListEnd 之后，外层列表的剩余大小是正确的。
	if inList, limit := s.listLimit(); inList {
		s.stack[len(s.stack)-1] = limit - size // 如果当前确实在一个外层列表中，则将外层列表的剩余长度更新为减去当前内层列表的大小。这是为了确保在解码完内层列表后，外层列表的剩余长度能够正确反映尚未解码的数据量。
	}
	s.stack = append(s.stack, size) // 将当前解码的列表的大小 size 压入 s.stack 中。这表示我们进入了一个新的列表解码上下文，并且这个列表的剩余大小是 size。
	s.kind = -1                     //  重置 s.kind 和 s.size 字段，以便在解码列表中的下一个元素时重新读取类型和大小信息。
	s.size = 0
	return size, nil
}

// ListEnd returns to the enclosing list.
// The input reader must be positioned at the end of a list.
// ListEnd 返回到外层列表。
// 输入读取器必须位于列表的末尾。
//
// 用于在解码 RLP 列表时，标记当前列表的结束，并返回到其外层列表的解码上下文中。
func (s *Stream) ListEnd() error {
	// Ensure that no more data is remaining in the current list.
	// 确保当前列表中没有剩余数据。
	if inList, listLimit := s.listLimit(); !inList { // 如果 inList 为 false，说明当前不在任何列表的上下文中
		return errNotInList
	} else if listLimit > 0 { // 如果当前在列表中 (inList 为 true)，但 listLimit 大于 0，则说明当前列表中还有未读取的数据，还没有到达列表的末尾。
		return errNotAtEOL
	}
	// 从 s.stack 中弹出最后一个元素，即当前已结束的列表的长度信息。这使得解码器能够返回到外层列表的上下文中。
	s.stack = s.stack[:len(s.stack)-1] // pop 弹出
	s.kind = -1
	s.size = 0
	return nil
}

// MoreDataInList reports whether the current list context contains
// more data to be read.
// MoreDataInList 报告当前的列表上下文中是否还有更多数据需要读取。
//
// 用于判断当前正在解码的 RLP 列表是否还有剩余元素需要读取的便捷方法. 它依赖于 listLimit 方法来获取当前列表的剩余长度。
func (s *Stream) MoreDataInList() bool {
	_, listLimit := s.listLimit()
	return listLimit > 0
}

// BigInt decodes an arbitrary-size integer value.
// BigInt 解码一个任意大小的整数值。
func (s *Stream) BigInt() (*big.Int, error) {
	// 创建一个新的 big.Int 来存储解码后的值。
	i := new(big.Int)
	// 调用 decodeBigInt 方法来填充 big.Int。
	if err := s.decodeBigInt(i); err != nil {
		return nil, err
	}
	return i, nil
}

func (s *Stream) decodeBigInt(dst *big.Int) error {
	var buffer []byte
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == List:
		return ErrExpectedString
	case kind == Byte:
		buffer = s.uintbuf[:1]
		buffer[0] = s.byteval
		s.kind = -1 // re-arm Kind 重新准备 Kind
	case size == 0:
		// Avoid zero-length read.
		// 避免零长度读取。
		s.kind = -1
	case size <= uint64(len(s.uintbuf)):
		// For integers smaller than s.uintbuf, allocating a buffer
		// can be avoided.
		// 对于小于 s.uintbuf 的整数，可以避免分配缓冲区。
		buffer = s.uintbuf[:size]
		if err := s.readFull(buffer); err != nil {
			return err
		}
		// Reject inputs where single byte encoding should have been used.
		// 拒绝应该使用单字节编码的输入。
		if size == 1 && buffer[0] < 128 {
			return ErrCanonSize
		}
	default:
		// For large integers, a temporary buffer is needed.
		// 对于大整数，需要一个临时缓冲区。
		buffer = make([]byte, size)
		if err := s.readFull(buffer); err != nil {
			return err
		}
	}

	// Reject leading zero bytes.
	// 拒绝前导零字节。
	if len(buffer) > 0 && buffer[0] == 0 {
		return ErrCanonInt
	}
	// Set the integer bytes.
	// 设置整数的字节。
	dst.SetBytes(buffer)
	return nil
}

// ReadUint256 decodes the next value as a uint256.
// ReadUint256 将下一个值解码为 uint256。
//
// 用于从 RLP 编码的数据流中解码一个 256 位的无符号整数，并将结果存储到传入的 uint256.Int 指针 dst 所指向的对象中。以太坊广泛使用 uint256 来表示账户余额、哈希值等大数值。
func (s *Stream) ReadUint256(dst *uint256.Int) error {
	var buffer []byte
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == List:
		return ErrExpectedString
	case kind == Byte: // 如果类型是单个字节 (Byte)，则将该字节存储到 s.uintbuf 的第一个字节中，并将 buffer 指向这个字节。之后，将 s.kind 重置为 -1，以便下次调用 Kind() 时重新读取类型信息。
		buffer = s.uintbuf[:1]
		buffer[0] = s.byteval
		s.kind = -1 // re-arm Kind  重新准备 Kind
	case size == 0: // 如果类型是字符串但大小为 0，则表示编码的是数值 0。将 s.kind 重置为 -1，避免后续的零长度读取。
		// Avoid zero-length read.
		// 避免零长度读取。
		s.kind = -1
	case size <= uint64(len(s.uintbuf)):
		// 如果类型是字符串且大小不超过 s.uintbuf 的容量（32 字节，足以存储任何 uint256），则将 buffer 指向 s.uintbuf 的前 size 个字节。
		// 然后调用 s.readFull(buffer) 从输入流中读取这 size 个字节到 buffer 中。
		// 如果读取过程中发生错误，则返回该错误。接着，进行规范性检查：
		// 如果 size 为 1 且读取到的字节小于 128，则说明应该使用单个字节编码而不是长度为 1 的字符串编码，返回 ErrCanonSize 错误。

		// All possible uint256 values fit into s.uintbuf.
		// 所有可能的 uint256 值都适合放入 s.uintbuf。
		buffer = s.uintbuf[:size]
		if err := s.readFull(buffer); err != nil {
			return err
		}
		// Reject inputs where single byte encoding should have been used.
		// 拒绝应该使用单字节编码的输入。
		if size == 1 && buffer[0] < 128 {
			return ErrCanonSize
		}
	default: // 如果类型是字符串且大小超过 s.uintbuf 的容量（大于 32 字节），则返回 errUint256Large 错误，因为这超出了 uint256 的表示范围。
		return errUint256Large
	}

	// Reject leading zero bytes.
	// 拒绝前导零字节。
	if len(buffer) > 0 && buffer[0] == 0 {
		return ErrCanonInt
	}
	// Set the integer bytes.
	// 设置整数的字节。
	dst.SetBytes(buffer)
	return nil
}

// Decode decodes a value and stores the result in the value pointed
// to by val. Please see the documentation for the Decode function
// to learn about the decoding rules.
//
// Decode 解码一个值并将结果存储到 val 指向的值中。
// 有关解码规则，请参阅 Decode 函数的文档。
func (s *Stream) Decode(val interface{}) error {
	if val == nil {
		return errDecodeIntoNil
	}
	// 获取目标的反射值和类型。
	rval := reflect.ValueOf(val)
	rtyp := rval.Type()
	// 目标必须是指针。
	if rtyp.Kind() != reflect.Ptr {
		return errNoPointer
	}
	// 指针不能为空。
	if rval.IsNil() {
		return errDecodeIntoNil
	}
	// 获取元素类型的缓存解码器函数。
	decoder, err := cachedDecoder(rtyp.Elem())
	if err != nil {
		return err
	}

	// 调用解码器函数。
	err = decoder(s, rval.Elem())
	// 向解码错误添加上下文。
	if decErr, ok := err.(*decodeError); ok && len(decErr.ctx) > 0 {
		// Add decode target type to error so context has more meaning.
		// 向错误添加解码目标类型，以便上下文更有意义。
		decErr.ctx = append(decErr.ctx, fmt.Sprint("(", rtyp.Elem(), ")"))
	}
	return err
}

// Reset discards any information about the current decoding context
// and starts reading from r. This method is meant to facilitate reuse
// of a preallocated Stream across many decoding operations.
//
// If r does not also implement ByteReader, Stream will do its own
// buffering.
//
// Reset 丢弃关于当前解码上下文的任何信息，并开始从 r 读取。
// 此方法旨在方便跨多个解码操作重用预先分配的 Stream。
//
// 如果 r 没有实现 ByteReader，Stream 将自行进行缓冲。
//
// 主要目的是为了能够重复使用同一个 Stream 结构体实例进行多次 RLP 解码操作，从而减少内存分配和垃圾回收的开销，提高性能。它会清除 Stream 的内部状态，并准备好从新的 io.Reader 中读取数据。
func (s *Stream) Reset(r io.Reader, inputLimit uint64) {
	// 如果提供了输入限制，则进行设置。
	if inputLimit > 0 {
		s.remaining = inputLimit
		s.limited = true
	} else {
		// Attempt to automatically discover
		// the limit when reading from a byte slice.
		// 尝试在从字节切片读取时自动发现限制。
		switch br := r.(type) {
		case *bytes.Reader:
			s.remaining = uint64(br.Len())
			s.limited = true
		case *bytes.Buffer:
			s.remaining = uint64(br.Len())
			s.limited = true
		case *strings.Reader:
			s.remaining = uint64(br.Len())
			s.limited = true
		default:
			s.limited = false
		}
	}
	// Wrap r with a buffer if it doesn't have one.
	// 如果 r 没有缓冲区，则用缓冲区包装它。
	bufr, ok := r.(ByteReader)
	if !ok {
		bufr = bufio.NewReader(r)
	}
	s.r = bufr
	// Reset the decoding context.
	// 重置解码上下文。
	s.stack = s.stack[:0]
	s.size = 0
	s.kind = -1
	s.kinderr = nil
	s.byteval = 0
	s.uintbuf = [32]byte{}
}

// Kind returns the kind and size of the next value in the
// input stream.
//
// The returned size is the number of bytes that make up the value.
// For kind == Byte, the size is zero because the value is
// contained in the type tag.
//
// The first call to Kind will read size information from the input
// reader and leave it positioned at the start of the actual bytes of
// the value. Subsequent calls to Kind (until the value is decoded)
// will not advance the input reader and return cached information.
//
// Kind 返回输入流中下一个值的类型和大小。
//
// 返回的大小是构成该值的字节数。
// 对于 kind == Byte，大小为零，因为该值包含在类型标签中。
//
// 第一次调用 Kind 将从输入读取器读取大小信息，并将其定位在值的实际字节的开头。
// 后续对 Kind 的调用（直到该值被解码）不会前进输入读取器，而是返回缓存的信息。
//
// 用于“窥视”输入流中下一个 RLP 编码值的类型和大小的关键方法，而不会实际消耗掉这部分输入。这对于需要预先知道下一个值的类型和大小才能进行正确解码的场景非常有用。
func (s *Stream) Kind() (kind Kind, size uint64, err error) {
	// 如果下一个值的类型已经被读取，则返回缓存的值。
	if s.kind >= 0 {
		return s.kind, s.size, s.kinderr
	}

	// Check for end of list. This needs to be done here because readKind
	// checks against the list size, and would return the wrong error.
	//
	// 检查列表的末尾。这需要在这里完成，因为 readKind 会根据列表大小进行检查，并可能返回错误的错误。
	// 如果我们在一个列表中并且已经到达列表的末尾，则返回 EOL。
	inList, listLimit := s.listLimit()
	if inList && listLimit == 0 {
		return 0, 0, EOL
	}
	// Read the actual size tag.
	// 读取实际的大小标签。
	s.kind, s.size, s.kinderr = s.readKind()
	// 如果在读取类型时没有发生错误，则执行进一步的检查。
	if s.kinderr == nil {
		// Check the data size of the value ahead against input limits. This
		// is done here because many decoders require allocating an input
		// buffer matching the value size. Checking it here protects those
		// decoders from inputs declaring very large value size.
		//
		// 根据输入限制检查前面值的数据大小。这样做是因为许多解码器需要分配一个与值大小匹配的输入缓冲区。
		// 在这里检查可以保护这些解码器免受声明非常大的值大小的输入的影响
		if inList && s.size > listLimit { // 如果当前在列表中，并且下一个值的大小 s.size 大于列表的剩余长度 listLimit，表示列表中的元素过大。
			s.kinderr = ErrElemTooLarge
		} else if s.limited && s.size > s.remaining { // 如果设置了全局输入限制 (s.limited 为 true)，并且下一个值的大小 s.size 大于剩余的可用输入长度 s.remaining，表示值的大小超出了输入限制。
			s.kinderr = ErrValueTooLarge
		}
	}
	return s.kind, s.size, s.kinderr
}

// 用于读取 RLP 编码值的类型和大小信息。
// RLP 编码的第一个字节决定了后续数据的类型和长度。readKind 方法通过读取并分析这个字节，来确定如何继续解码。
func (s *Stream) readKind() (kind Kind, size uint64, err error) {
	// 根据读取到的第一个字节的值，判断后续数据是单个字节、字符串还是列表。
	b, err := s.readByte()
	if err != nil {
		if len(s.stack) == 0 { // 当前处于顶层解码。在顶层，io.EOF 通常被用作表示输入流结束的信号。
			// At toplevel, Adjust the error to actual EOF. io.EOF is
			// used by callers to determine when to stop decoding.
			// 在顶层，将错误调整为实际的 EOF。调用者使用 io.EOF 来确定何时停止解码。
			switch err {
			case io.ErrUnexpectedEOF:
				err = io.EOF
			case ErrValueTooLarge:
				err = io.EOF
			}
		}
		return 0, 0, err
	}
	s.byteval = 0
	switch {
	case b < 0x80: //  (0x00-0x7F)： 表示一个值为 b 的单个字节。类型是 Byte，大小为 0。s.byteval 被设置为 b。
		// For a single byte whose value is in the [0x00, 0x7F] range, that byte
		// is its own RLP encoding.
		// 对于值在 [0x00, 0x7F] 范围内的单个字节，该字节本身就是其 RLP 编码。
		s.byteval = b
		return Byte, 0, nil
	case b < 0xB8: //  (0x80-0xB7)： 表示一个长度为 b - 0x80 的字符串，长度在 0 到 55 字节之间。类型是 String，大小是 uint64(b - 0x80)。
		// Otherwise, if a string is 0-55 bytes long, the RLP encoding consists
		// of a single byte with value 0x80 plus the length of the string
		// followed by the string. The range of the first byte is thus [0x80, 0xB7].
		// 否则，如果字符串长度为 0-55 字节，则 RLP 编码由一个值为 0x80 加上字符串长度的字节组成，
		// 后跟字符串。因此，第一个字节的范围是 [0x80, 0xB7]。
		return String, uint64(b - 0x80), nil
	case b < 0xC0: // (0xB8-0xBF)： 表示一个长度超过 55 字节的字符串。b - 0xB7 的值表示后续用于编码字符串长度的字节数（1 到 8 个字节）。
		// If a string is more than 55 bytes long, the RLP encoding consists of a
		// single byte with value 0xB7 plus the length of the length of the
		// string in binary form, followed by the length of the string, followed
		// by the string. For example, a length-1024 string would be encoded as
		// 0xB90400 followed by the string. The range of the first byte is thus
		// [0xB8, 0xBF].
		//
		// 如果字符串长度超过 55 字节，则 RLP 编码由一个值为 0xB7 加上字符串长度的二进制形式的长度的字节组成，
		// 后跟字符串的长度，后跟字符串。例如，长度为 1024 的字符串将被编码为 0xB90400，后跟字符串。
		// 因此，第一个字节的范围是 [0xB8, 0xBF]。
		size, err = s.readUint(b - 0xB7) // 调用 s.readUint(b - 0xB7) 读取字符串的实际长度。
		if err == nil && size < 56 {     // 如果读取长度没有发生错误，并且读取到的长度小于 56，则表示使用了非规范的长度编码
			err = ErrCanonSize
		}
		return String, size, err
	case b < 0xF8: // (0xC0-0xF7)： 表示一个包含的负载长度为 b - 0xC0 的列表，负载长度在 0 到 55 字节之间。类型是 List，大小是 uint64(b - 0xC0)。
		// If the total payload of a list (i.e. the combined length of all its
		// items) is 0-55 bytes long, the RLP encoding consists of a single byte
		// with value 0xC0 plus the length of the list followed by the
		// concatenation of the RLP encodings of the items. The range of the
		// first byte is thus [0xC0, 0xF7].
		//
		// 如果列表的总负载（即其所有项的组合长度）为 0-55 字节，则 RLP 编码由一个值为 0xC0 加上列表长度的字节组成，
		// 后跟列表项的 RLP 编码的串联。因此，第一个字节的范围是 [0xC0, 0xF7]。
		return List, uint64(b - 0xC0), nil
	default: // (0xF8-0xFF)： 表示一个包含的负载长度超过 55 字节的列表。b - 0xF7 的值表示后续用于编码列表负载长度的字节数（1 到 8 个字节）。
		// If the total payload of a list is more than 55 bytes long, the RLP
		// encoding consists of a single byte with value 0xF7 plus the length of
		// the length of the payload in binary form, followed by the length of
		// the payload, followed by the concatenation of the RLP encodings of
		// the items. The range of the first byte is thus [0xF8, 0xFF].
		// 如果列表的总负载超过 55 字节，则 RLP 编码由一个值为 0xF7 加上负载长度的二进制形式的长度的字节组成，
		// 后跟负载的长度，后跟列表项的 RLP 编码的串联。因此，第一个字节的范围是 [0xF8, 0xFF]。
		size, err = s.readUint(b - 0xF7) // 读取列表的实际负载长度
		if err == nil && size < 56 {     // 表示使用了非规范的长度编码
			err = ErrCanonSize
		}
		return List, size, err
	}
}

// RLP 整数编码： 在 RLP 中，整数的编码方式取决于其大小。
// 小于 128 的整数直接编码为单个字节。
// 大于等于 128 的整数，会先编码一个前缀字节来指示后续表示整数的字节数，然后再编码整数本身（大端序）。

// 读取不同大小的无符号整数： RLP 编码的无符号整数可以占用 0 到 8 个字节。readUint 方法根据 size 参数的值来处理这些不同的情况。
func (s *Stream) readUint(size byte) (uint64, error) {
	switch size {
	case 0:
		s.kind = -1 // rearm Kind  重新准备 Kind
		return 0, nil
	case 1: //  当 size 为 1 时，直接读取一个字节并将其转换为 uint64。
		b, err := s.readByte()
		return uint64(b), err
	default: //  当 size 大于 1 时，需要读取 size 个字节，并将这些字节按照大端序（Big Endian）转换为 uint64。
		buffer := s.uintbuf[:8] // 使用 Stream 结构体中的 uintbuf 字段的前 8 个字节作为缓冲区。由于要转换为 uint64，最多需要 8 个字节。
		clear(buffer)           // 清空缓冲区，以确保之前的数据不会影响本次读取。
		start := int(8 - size)  // 计算实际数据在缓冲区中的起始位置。由于 RLP 编码的整数是靠右对齐的，所以需要跳过缓冲区前面的 8 - size 个字节。
		if err := s.readFull(buffer[start:]); err != nil {
			return 0, err
		}
		// 检查非规范编码（前导零）。
		// 检查读取到的第一个字节（即实际数据的最高位字节）是否为 0。如果为 0，则表示存在冗余的前导零，违反了 RLP 的规范编码规则。
		if buffer[start] == 0 {
			// Note: readUint is also used to decode integer values.
			// The error needs to be adjusted to become ErrCanonInt in this case.
			// 注意：readUint 也用于解码整数值。
			// 在这种情况下，需要将错误调整为 ErrCanonInt。
			return 0, ErrCanonSize
		}
		return binary.BigEndian.Uint64(buffer[:]), nil
	}
}

// 在 RLP 解码过程中，经常需要读取固定长度的数据。例如，当解码一个长度前缀指示为 L 的字符串时，需要从输入流中读取接下来的 L 个字节。readFull 方法正是用于执行这种操作。
// 以太坊中的许多数据结构都包含固定长度的字段，例如哈希值（通常是 32 字节）、地址（通常是 20 字节）等。在解码这些字段的 RLP 编码时，会使用类似 readFull 的方法来确保读取到完整的字节数。
// 此外，对于长度前缀大于 55 的字符串或列表，RLP 编码会首先包含一个指示长度的字节序列。在解码这些长度信息之后，就需要使用 readFull 来读取实际的数据内容或列表元素。

// readFull reads into buf from the underlying stream.
// readFull 从底层流中读取数据到 buf 中。
//
// readFull 的目标是确保从输入流中读取到 len(buf) 个字节的数据。
func (s *Stream) readFull(buf []byte) (err error) {
	// 检查是否有足够的剩余字节可供读取。
	if err := s.willRead(uint64(len(buf))); err != nil {
		return err
	}
	var nn, n int
	// 循环直到缓冲区满或发生错误。
	for n < len(buf) && err == nil {
		nn, err = s.r.Read(buf[n:])
		n += nn
	}
	// 处理 io.EOF 错误。
	if err == io.EOF {
		// 如果在缓冲区满之前到达 EOF，则为意外的 EOF。
		if n < len(buf) {
			err = io.ErrUnexpectedEOF
		} else {
			// Readers are allowed to give EOF even though the read succeeded.
			// In such cases, we discard the EOF, like io.ReadFull() does.
			// 即使读取成功，读取器也可能给出 EOF。
			// 在这种情况下，我们像 io.ReadFull() 一样丢弃 EOF。
			err = nil
		}
	}
	return err
}

// RLP 类型标签： RLP 编码的第一个字节（类型标签）决定了后续数据的解释方式。例如：
// 如果第一个字节在 0x00 到 0x7f 范围内，则该字节本身就是数据。
// 如果第一个字节在 0x80 到 0xb7 范围内，则表示后续的 0 到 55 个字节是字符串数据。
// 如果第一个字节在 0xb8 到 0xbf 范围内，则表示后续的 1 到 8 个字节指示了字符串数据的长度，之后才是实际的字符串数据。
// 对于列表也有类似的规则。
// 因此，readByte 方法在解码 RLP 数据时首先被调用，以获取这个类型标签。
// RLP 编码指示后续数据的长度大于 55 字节时，长度信息本身会编码成一个或多个字节。readByte 可能会被多次调用来读取这些长度字节。

// readByte reads a single byte from the underlying stream.
// readByte 从底层流中读取单个字节。
//
// 在 RLP 编码中，每个编码值的第一个字节通常是类型标签，用于指示后续数据的类型（例如字符串、列表）和长度。readByte 方法用于读取这个关键的类型标签字节。
func (s *Stream) readByte() (byte, error) {
	// 检查是否有足够的剩余字节可供读取。
	if err := s.willRead(1); err != nil {
		return 0, err
	}
	// 如果在读取单个字节时遇到 EOF，则认为是意外的 EOF。
	// 如果期望读取一个类型标签或长度信息时遇到文件结束，通常意味着输入数据不完整或者格式错误，因此被认为是“意外的”。
	// 即使在 readFull 中，如果在期望读取多个字节时遇到 EOF 也会被认为是意外的。
	// 对于 readByte 来说，期望读取一个字节，如果流结束了，那自然是意外的情况。
	b, err := s.r.ReadByte()
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return b, err
}

// willRead is called before any read from the underlying stream. It checks
// n against size limits, and updates the limits if n doesn't overflow them.
// willRead 在从底层流中进行任何读取之前被调用。它根据大小限制检查 n，并在 n 不超过限制时更新限制。
//
// 在每次尝试从底层的 ByteReader 读取数据之前，都会先调用 willRead 来进行一系列的检查，以确保读取操作不会超出预定的限制，并相应地更新内部状态。这对于保证 RLP 解码的正确性和安全性至关重要。
func (s *Stream) willRead(n uint64) error {
	// 重置下一个值的类型。
	s.kind = -1 // rearm Kind  重新准备 Kind

	// 检查读取是否在当前列表的限制范围内（如果有）。
	if inList, limit := s.listLimit(); inList {
		// 如果读取超过了列表的剩余限制，则返回错误。
		if n > limit {
			return ErrElemTooLarge
		}
		// 更新当前列表的剩余限制。
		// 如果读取在列表限制内，则更新 s.stack 栈顶的值。s.stack 用于存储嵌套列表的剩余长度。这里将当前列表的剩余长度更新为减去即将读取的字节数 n 之后的值。
		s.stack[len(s.stack)-1] = limit - n
	}
	// 检查是否生效了整体输入大小限制。
	if s.limited {
		// 如果读取超过了剩余输入限制，则返回错误。
		if n > s.remaining {
			return ErrValueTooLarge
		}
		// 更新剩余输入限制。
		s.remaining -= n
	}
	return nil
}

// RLP 列表结构： RLP 编码使用特定的前缀来标识列表，并且会编码列表的总长度。
// 当解码一个列表时，解码器需要知道这个长度，以便在读取完所有列表元素后能够正确地结束列表的解码。

// 判断是否在列表中： 该方法首先判断 s.stack 的长度是否为 0。如果长度为 0，则表示当前解码器没有进入任何 RLP 列表，因此返回 false 和 0。
// 获取最内层列表剩余长度： 如果 s.stack 的长度大于 0，则表示当前解码器正处于至少一个 RLP 列表的内部。
// 由于 RLP 列表可以嵌套，s.stack 存储了所有尚未结束的列表的剩余长度。栈顶的元素总是代表当前最内层列表的剩余长度。
// 因此，方法返回 true 和 s.stack 栈顶的值。

// listLimit returns the amount of data remaining in the innermost list.
// listLimit 返回最内层列表中剩余的数据量。
// 用于查询当前解码器是否处于列表上下文中以及该最内层列表剩余长度的关键辅助方法。
func (s *Stream) listLimit() (inList bool, limit uint64) {
	// 如果列表尺寸堆栈为空，则表示我们当前不在任何列表中。
	if len(s.stack) == 0 {
		return false, 0
	}
	// 否则，我们至少在一个列表中。最内层列表的剩余尺寸是堆栈顶部的值。
	return true, s.stack[len(s.stack)-1]
}

// 处理内存中的 RLP 数据： 在以太坊应用中，经常需要处理已经存在于内存中的 RLP 编码数据。例如：
// 从网络接收到的消息可能包含 RLP 编码的数据。在解码之前，这些数据通常会先存储在字节切片中。
// 从本地存储（如数据库或文件）读取的以太坊数据也可能是 RLP 编码的字节切片。

// 可以作为 Stream 结构体的底层输入读取器 (ByteReader) 使用。这使得可以将内存中的字节切片当作一个可读取的流进行 RLP 解码。
type sliceReader []byte

func (sr *sliceReader) Read(b []byte) (int, error) {
	if len(*sr) == 0 {
		return 0, io.EOF
	}
	n := copy(b, *sr)
	*sr = (*sr)[n:] // 该切片从之前拷贝结束的位置开始，相当于“消费”掉了已经读取的部分。
	return n, nil
}

func (sr *sliceReader) ReadByte() (byte, error) {
	if len(*sr) == 0 {
		return 0, io.EOF
	}
	b := (*sr)[0]
	*sr = (*sr)[1:]
	return b, nil
}
