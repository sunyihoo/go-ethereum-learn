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

/*
Package rlp implements the RLP serialization format.

The purpose of RLP (Recursive Linear Prefix) is to encode arbitrarily nested arrays of
binary data, and RLP is the main encoding method used to serialize objects in Ethereum.
The only purpose of RLP is to encode structure; encoding specific atomic data types (eg.
strings, ints, floats) is left up to higher-order protocols. In Ethereum integers must be
represented in big endian binary form with no leading zeroes (thus making the integer
value zero equivalent to the empty string).

RLP values are distinguished by a type tag. The type tag precedes the value in the input
stream and defines the size and kind of the bytes that follow.

# Encoding Rules

Package rlp uses reflection and encodes RLP based on the Go type of the value.

If the type implements the Encoder interface, Encode calls EncodeRLP. It does not
call EncodeRLP on nil pointer values.

To encode a pointer, the value being pointed to is encoded. A nil pointer to a struct
type, slice or array always encodes as an empty RLP list unless the slice or array has
element type byte. A nil pointer to any other value encodes as the empty string.

Struct values are encoded as an RLP list of all their encoded public fields. Recursive
struct types are supported.

To encode slices and arrays, the elements are encoded as an RLP list of the value's
elements. Note that arrays and slices with element type uint8 or byte are always encoded
as an RLP string.

A Go string is encoded as an RLP string.

An unsigned integer value is encoded as an RLP string. Zero always encodes as an empty RLP
string. big.Int values are treated as integers. Signed integers (int, int8, int16, ...)
are not supported and will return an error when encoding.

Boolean values are encoded as the unsigned integers zero (false) and one (true).

An interface value encodes as the value contained in the interface.

Floating point numbers, maps, channels and functions are not supported.

# Decoding Rules

Decoding uses the following type-dependent rules:

If the type implements the Decoder interface, DecodeRLP is called.

To decode into a pointer, the value will be decoded as the element type of the pointer. If
the pointer is nil, a new value of the pointer's element type is allocated. If the pointer
is non-nil, the existing value will be reused. Note that package rlp never leaves a
pointer-type struct field as nil unless one of the "nil" struct tags is present.

To decode into a struct, decoding expects the input to be an RLP list. The decoded
elements of the list are assigned to each public field in the order given by the struct's
definition. The input list must contain an element for each decoded field. Decoding
returns an error if there are too few or too many elements for the struct.

To decode into a slice, the input must be a list and the resulting slice will contain the
input elements in order. For byte slices, the input must be an RLP string. Array types
decode similarly, with the additional restriction that the number of input elements (or
bytes) must match the array's defined length.

To decode into a Go string, the input must be an RLP string. The input bytes are taken
as-is and will not necessarily be valid UTF-8.

To decode into an unsigned integer type, the input must also be an RLP string. The bytes
are interpreted as a big endian representation of the integer. If the RLP string is larger
than the bit size of the type, decoding will return an error. Decode also supports
*big.Int. There is no size limit for big integers.

To decode into a boolean, the input must contain an unsigned integer of value zero (false)
or one (true).

To decode into an interface value, one of these types is stored in the value:

	[]interface{}, for RLP lists
	[]byte, for RLP strings

Non-empty interface types are not supported when decoding.
Signed integers, floating point numbers, maps, channels and functions cannot be decoded into.

# Struct Tags

As with other encoding packages, the "-" tag ignores fields.

	type StructWithIgnoredField struct{
	    Ignored uint `rlp:"-"`
	    Field   uint
	}

Go struct values encode/decode as RLP lists. There are two ways of influencing the mapping
of fields to list elements. The "tail" tag, which may only be used on the last exported
struct field, allows slurping up any excess list elements into a slice.

	type StructWithTail struct{
	    Field   uint
	    Tail    []string `rlp:"tail"`
	}

The "optional" tag says that the field may be omitted if it is zero-valued. If this tag is
used on a struct field, all subsequent public fields must also be declared optional.

When encoding a struct with optional fields, the output RLP list contains all values up to
the last non-zero optional field.

When decoding into a struct, optional fields may be omitted from the end of the input
list. For the example below, this means input lists of one, two, or three elements are
accepted.

	type StructWithOptionalFields struct{
	     Required  uint
	     Optional1 uint `rlp:"optional"`
	     Optional2 uint `rlp:"optional"`
	}

The "nil", "nilList" and "nilString" tags apply to pointer-typed fields only, and change
the decoding rules for the field type. For regular pointer fields without the "nil" tag,
input values must always match the required input length exactly and the decoder does not
produce nil values. When the "nil" tag is set, input values of size zero decode as a nil
pointer. This is especially useful for recursive types.

	type StructWithNilField struct {
	    Field *[3]byte `rlp:"nil"`
	}

In the example above, Field allows two possible input sizes. For input 0xC180 (a list
containing an empty string) Field is set to nil after decoding. For input 0xC483000000 (a
list containing a 3-byte string), Field is set to a non-nil array pointer.

RLP supports two kinds of empty values: empty lists and empty strings. When using the
"nil" tag, the kind of empty value allowed for a type is chosen automatically. A field
whose Go type is a pointer to an unsigned integer, string, boolean or byte array/slice
expects an empty RLP string. Any other pointer field type encodes/decodes as an empty RLP
list.

The choice of null value can be made explicit with the "nilList" and "nilString" struct
tags. Using these tags encodes/decodes a Go nil pointer value as the empty RLP value kind
defined by the tag.
*/
/*
Package rlp 实现了 RLP 序列化格式。

RLP（Recursive Linear Prefix，递归长度前缀）的目的是编码任意嵌套的二进制数据数组，RLP 是以太坊中用于序列化对象的主要编码方法。RLP 的唯一目的是编码结构；编码特定的原子数据类型（例如字符串、整数、浮点数）留给更高阶的协议处理。在以太坊中，整数必须以大端二进制形式表示，没有前导零（因此，整数值零等同于空字符串）。

RLP 值通过类型标签来区分。类型标签位于输入流中的值之前，并定义了后续字节的大小和类型。

# 编码规则

Package rlp 使用反射并基于 Go 值的类型进行 RLP 编码。

如果类型实现了 Encoder 接口，Encode 会调用 EncodeRLP。它不会在 nil 指针值上调用 EncodeRLP。

要编码指针，将编码指针所指向的值。指向结构体类型、切片或数组的 nil 指针总是编码为空 RLP 列表，除非切片或数组的元素类型是 byte。指向任何其他值的 nil 指针编码为空字符串。

结构体值被编码为包含其所有已编码的公开字段的 RLP 列表。支持递归结构体类型。

要编码切片和数组，元素被编码为包含该值元素的 RLP 列表。请注意，元素类型为 uint8 或 byte 的数组和切片总是编码为 RLP 字符串。

Go 字符串被编码为 RLP 字符串。

无符号整数值被编码为 RLP 字符串。零总是编码为空 RLP 字符串。big.Int 值被视为整数。不支持有符号整数（int、int8、int16 等），编码时会返回错误。

布尔值被编码为无符号整数零（false）和一（true）。

接口值被编码为接口中包含的值。

不支持浮点数、map、channel 和函数。

# 解码规则

解码使用以下类型相关的规则：

如果类型实现了 Decoder 接口，则调用 DecodeRLP。

要解码为指针，该值将被解码为指针的元素类型。如果指针为 nil，则会分配指针元素类型的新值。如果指针不为 nil，则会重用现有值。请注意，除非存在 "nil" 结构体标签之一，否则 package rlp 永远不会将指针类型的结构体字段保留为 nil。

要解码为结构体，解码期望输入为 RLP 列表。列表的已解码元素按照结构体定义给出的顺序分配给每个公开字段。输入列表必须包含每个已解码字段的元素。如果结构体的元素太少或太多，解码会返回错误。

要解码为切片，输入必须是列表，并且结果切片将按顺序包含输入元素。对于字节切片，输入必须是 RLP 字符串。数组类型的解码类似，但有一个额外的限制：输入元素（或字节）的数量必须与数组定义的长度匹配。

要解码为 Go 字符串，输入必须是 RLP 字符串。输入字节按原样获取，不一定需要是有效的 UTF-8。

要解码为无符号整数类型，输入也必须是 RLP 字符串。字节被解释为整数的大端表示。如果 RLP 字符串大于类型的位大小，解码将返回错误。Decode 也支持 *big.Int。对于大整数没有大小限制。

要解码为布尔值，输入必须包含值为零（false）或一（true）的无符号整数。

要解码为接口值，以下类型之一存储在该值中：

    []interface{}, 用于 RLP 列表
    []byte, 用于 RLP 字符串

解码时不支持非空接口类型。
不能解码为有符号整数、浮点数、map、channel 和函数。

# 结构体标签

与其他编码包一样，"-" 标签会忽略字段。

    type StructWithIgnoredField struct{
        Ignored uint `rlp:"-"`
        Field   uint
    }

Go 结构体值编码/解码为 RLP 列表。有两种方法可以影响字段到列表元素的映射。"tail" 标签只能用于最后一个导出的结构体字段，它允许将任何多余的列表元素吸收到切片中。

    type StructWithTail struct{
        Field   uint
        Tail    []string `rlp:"tail"`
    }

"optional" 标签表示如果字段的值为零值，则可以省略该字段。如果在结构体字段上使用此标签，则所有后续的公开字段也必须声明为 optional。

编码带有 optional 字段的结构体时，输出 RLP 列表包含所有值，直到最后一个非零值的 optional 字段。

解码为结构体时，可以从输入列表的末尾省略 optional 字段。对于下面的示例，这意味着接受包含一个、两个或三个元素的输入列表。

    type StructWithOptionalFields struct{
         Required  uint
         Optional1 uint `rlp:"optional"`
         Optional2 uint `rlp:"optional"`
    }

"nil"、"nilList" 和 "nilString" 标签仅适用于指针类型的字段，并更改该字段类型的解码规则。对于没有 "nil" 标签的常规指针字段，输入值必须始终与所需的输入长度完全匹配，并且解码器不会产生 nil 值。设置 "nil" 标签后，大小为零的输入值将解码为 nil 指针。这对于递归类型尤其有用。

    type StructWithNilField struct {
        Field *[3]byte `rlp:"nil"`
    }

在上面的示例中，Field 允许两种可能的输入大小。对于输入 0xC180（包含空字符串的列表），解码后 Field 设置为 nil。对于输入 0xC483000000（包含 3 字节字符串的列表），Field 设置为非 nil 的数组指针。

RLP 支持两种类型的空值：空列表和空字符串。使用 "nil" 标签时，会自动选择类型允许的空值类型。Go 类型是指向无符号整数、字符串、布尔值或字节数组/切片的指针的字段期望一个空的 RLP 字符串。任何其他指针字段类型都编码/解码为空的 RLP 列表。

可以使用 "nilList" 和 "nilString" 结构体标签显式选择空值类型。使用这些标签会将 Go 的 nil 指针值编码/解码为标签定义的空 RLP 值类型。
*/
package rlp

/*
RLP 的主要目的是编码任意嵌套的二进制数据数组，专注于编码数据的结构，而将原子数据类型的编码细节留给上层协议处理。

以太坊特定： 在以太坊中，整数必须以大端二进制形式表示，且没有前导零，零值等同于空字符串。

类型标签：
	RLP 值通过前置的类型标签来区分，标签指示了后续数据的类型和长度。

编码规则：
	使用反射基于 Go 类型进行编码。
	实现了 Encoder 接口的类型会调用 EncodeRLP 方法。
	指向结构体、切片或数组的 nil 指针编码为空 RLP 列表（字节切片/数组除外），其他 nil 指针编码为空字符串。
	结构体编码为包含其公开字段的 RLP 列表。
	切片和数组编码为包含其元素的 RLP 列表（uint8/byte 类型的切片/数组编码为 RLP 字符串）。
	Go 字符串编码为 RLP 字符串。
	无符号整数编码为 RLP 字符串，零编码为空字符串。big.Int 被视为整数。不支持有符号整数。
	布尔值编码为无符号整数 0 (false) 和 1 (true)。
	接口值编码为其包含的值。
	不支持浮点数、map、channel 和函数。

解码规则：
	实现了 Decoder 接口的类型会调用 DecodeRLP 方法。
	解码为指针时，会解码为指针的元素类型。如果指针为 nil，会分配新值。除非使用了 "nil" 标签，否则不会将指针类型的结构体字段保留为 nil。
	解码为结构体时，输入必须是 RLP 列表，列表元素按顺序赋给结构体的公开字段。输入列表的元素数量必须与结构体的字段数量匹配。
	解码为切片时，输入必须是列表，元素按顺序存储到切片中。字节切片的输入必须是 RLP 字符串。数组类似，但元素数量必须与数组长度匹配。
	解码为 Go 字符串时，输入必须是 RLP 字符串，字节按原样使用。
	解码为无符号整数时，输入必须是 RLP 字符串，字节被解释为大端表示。如果 RLP 字符串过大，会返回错误。支持 *big.Int，没有大小限制。
	解码为布尔值时，输入必须是值为 0 或 1 的无符号整数。
	解码为接口值时，RLP 列表解码为 []interface{}，RLP 字符串解码为 []byte。不支持非空接口类型的解码。
	不支持解码为有符号整数、浮点数、map、channel 和函数。

结构体标签：
-: 忽略字段。
	tail: 只能用于最后一个导出的结构体字段，将多余的列表元素吸收到切片中。
	optional: 表示如果字段值为零值可以省略。如果一个字段标记为 optional，则其后的所有公开字段也必须标记为 optional。编码时，输出列表包含直到最后一个非零 optional 字段的值。解码时，可以从输入列表末尾省略 optional 字段。
	nil: 仅适用于指针类型字段。当输入大小为零时，解码为 nil 指针。对于指向无符号整数、字符串、布尔值或字节切片/数组的指针，期望空的 RLP 字符串；对于其他指针类型，期望空的 RLP 列表。
	nilList: 显式指定 nil 指针值编码/解码为空 RLP 列表。
	nilString: 显式指定 nil 指针值编码/解码为空 RLP 字符串。
*/
