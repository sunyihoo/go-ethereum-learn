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

// Package rlpstruct implements struct processing for RLP encoding/decoding.
//
// In particular, this package handles all rules around field filtering,
// struct tags and nil value determination.
package rlpstruct

import (
	"fmt"
	"reflect"
	"strings"
)

// RLP 是以太坊中使用的一种紧凑的序列化格式，用于编码交易、区块头等数据

// Field represents a struct field.
// Field 表示一个结构体字段。
//
// 用于智能合约 ABI（Application Binary Interface）解析或事件日志解码。
type Field struct {
	Name     string // 字段名称
	Index    int    // 字段索引
	Exported bool   // 字段是否公开（首字母大写）
	Type     Type   // 字段的类型
	Tag      string // 字段的标签
}

// Type represents the attributes of a Go type.
// Type 表示 Go 类型的一些属性。
type Type struct {
	Name      string       // 类型名称
	Kind      reflect.Kind // 类型的种类
	IsEncoder bool         // whether type implements rlp.Encoder 类型是否实现了 rlp.Encoder 接口
	IsDecoder bool         // whether type implements rlp.Decoder 类型是否实现了 rlp.Decoder 接口
	Elem      *Type        // non-nil for Kind values of Ptr, Slice, Array 对于指针、切片、数组类型的元素类型，非 nil
}

// DefaultNilValue determines whether a nil pointer to t encodes/decodes
// as an empty string or empty list.
//
// DefaultNilValue 确定一个指向 t 的 nil 指针在编码/解码时是作为空字符串还是空列表。
func (t Type) DefaultNilValue() NilKind {
	k := t.Kind
	if isUint(k) || k == reflect.String || k == reflect.Bool || isByteArray(t) {
		return NilKindString
	}
	return NilKindList
}

// NilKind is the RLP value encoded in place of nil pointers.
type NilKind uint8

const (
	NilKindString NilKind = 0x80 // 表示 nil 指针编码为“空字符串”的情况
	NilKindList   NilKind = 0xC0 // 表示 nil 指针编码为“空列表”的情况
)

// Tags represents struct tags.
// Tags 表示结构体的标签。
type Tags struct {
	// rlp:"nil" controls whether empty input results in a nil pointer.
	// nilKind is the kind of empty value allowed for the field.
	// rlp:"nil" 控制空输入是否导致 nil 指针。
	// nilKind 是字段允许的空值类型。
	NilKind NilKind
	NilOK   bool

	// rlp:"optional" allows for a field to be missing in the input list.
	// If this is set, all subsequent fields must also be optional.
	// rlp:"optional" 允许字段在输入列表中缺失。
	// 如果设置了此选项，则所有后续字段也必须是可选的。
	Optional bool

	// rlp:"tail" controls whether this field swallows additional list elements. It can
	// only be set for the last field, which must be of slice type.
	// rlp:"tail" 控制该字段是否吸收额外的列表元素。它只能设置为最后一个字段，且该字段必须是切片类型。
	Tail bool

	// rlp:"-" ignores fields.
	// rlp:"-" 忽略字段。
	Ignored bool
}

// TagError is raised for invalid struct tags.
// TagError 是因无效的结构体标签而引发的错误。
type TagError struct {
	StructType string // 表示发生错误的结构体类型名称（可选）。

	// These are set by this package.
	// 这些是由本包设置的。
	Field string // 表示出错的字段名称。
	Tag   string // 表示导致错误的标签内容（如 rlp:"nil"）。
	Err   string // 表示具体的错误描述。
}

func (e TagError) Error() string {
	field := "field " + e.Field
	if e.StructType != "" {
		field = e.StructType + "." + e.Field
	}
	return fmt.Sprintf("rlp: invalid struct tag %q for %s (%s)", e.Tag, field, e.Err)
}

// ProcessFields filters the given struct fields, returning only fields
// that should be considered for encoding/decoding.
//
// ProcessFields 过滤给定的结构体字段，仅返回应考虑进行编码/解码的字段。
// 用于处理结构体的字段过滤和标签验证。
//
// 标签规则:
//
//	optional: 字段可以缺失，但一旦某个字段是可选的，其后所有字段必须是可选的（或 tail）。
//	tail: 仅限最后一个字段，且必须是切片类型，用于吸收额外元素。
//	-: 忽略字段，不参与编码/解码。
//
// RLP 规则:
//
//	结构体编码为列表，字段顺序固定。
//	可选字段和尾部字段是 go-ethereum 对标准 RLP 的扩展。
func ProcessFields(allFields []Field) ([]Field, []Tags, error) {
	lastPublic := lastPublicField(allFields)

	// Gather all exported fields and their tags.
	// 收集所有公开字段及其标签。
	var fields []Field // 存储过滤后的公开字段。
	var tags []Tags    // 存储每个字段的标签信息。
	for _, field := range allFields {
		if !field.Exported { // 如果字段不是公开的，跳过。
			continue
		}
		ts, err := parseTag(field, lastPublic) // 解析字段的 RLP 标签，返回 Tags 和可能的错误。
		if err != nil {
			return nil, nil, err
		}
		if ts.Ignored { // 如果标签标记为忽略（rlp:"-"），跳过。
			continue
		}
		// 将字段和标签添加到结果列表。
		fields = append(fields, field)
		tags = append(tags, ts)
	}

	// Verify optional field consistency. If any optional field exists,
	// all fields after it must also be optional. Note: optional + tail
	// is supported.
	// 验证可选字段的一致性。如果存在任何可选字段，则其后的所有字段也必须是可选的。注意：支持 optional + tail。
	var anyOptional bool         // 标记是否已有可选字段。
	var firstOptionalName string // 记录第一个可选字段的名称。
	for i, ts := range tags {
		name := fields[i].Name      // 获取字段名。
		if ts.Optional || ts.Tail { // 如果字段是 optional 或 tail，标记为可选。
			if !anyOptional {
				firstOptionalName = name // 如果是第一个可选字段，记录其名称。
			}
			anyOptional = true
		} else {
			if anyOptional { // 检查是否已有可选字段。如果是，则抛出 TagError，提示该字段必须是可选的，因为前面的字段已标记为可选。
				msg := fmt.Sprintf("must be optional because preceding field %q is optional", firstOptionalName)
				return nil, nil, TagError{Field: name, Err: msg}
			}
		}
	}
	return fields, tags, nil
}

// parseTag 解析字段的 RLP 标签并返回对应的 Tags 结构体。
func parseTag(field Field, lastPublic int) (Tags, error) {
	name := field.Name // 获取字段名，用于错误报告。
	tag := reflect.StructTag(field.Tag)
	var ts Tags
	for _, t := range strings.Split(tag.Get("rlp"), ",") { // 获取 rlp 标签并按逗号分割为多个子标签。
		switch t = strings.TrimSpace(t); t {
		case "":
			// empty tag is allowed for some reason
			// 允许空标签，原因未知
		case "-":
			// 表示忽略该字段。
			ts.Ignored = true
		case "nil", "nilString", "nilList":
			ts.NilOK = true                     // 表示允许空值。
			if field.Type.Kind != reflect.Ptr { // 如果字段不是指针类型，返回错误。
				return ts, TagError{Field: name, Tag: t, Err: "field is not a pointer"}
			}
			switch t {
			case "nil":
				ts.NilKind = field.Type.Elem.DefaultNilValue() // 设置默认空值类型。
			case "nilString":
				ts.NilKind = NilKindString
			case "nilList":
				ts.NilKind = NilKindList
			}
		case "optional":
			ts.Optional = true
			if ts.Tail { // 如果已有 tail 标签，返回错误（两者不能共存）。
				return ts, TagError{Field: name, Tag: t, Err: `also has "tail" tag`}
			}
		case "tail":
			ts.Tail = true
			if field.Index != lastPublic { // 如果不是最后一个字段，返回错误。
				return ts, TagError{Field: name, Tag: t, Err: "must be on last field"}
			}
			if ts.Optional { // 如果已有 optional 标签，返回错误。
				return ts, TagError{Field: name, Tag: t, Err: `also has "optional" tag`}
			}
			if field.Type.Kind != reflect.Slice { // 如果字段不是切片类型，返回错误。
				return ts, TagError{Field: name, Tag: t, Err: "field type is not slice"}
			}
		default:
			return ts, TagError{Field: name, Tag: t, Err: "unknown tag"}
		}
	}
	return ts, nil
}

// lastPublicField 返回结构体的最后一个公开字段的索引。
//
// RLP 编码结构体时，会将所有公开字段按顺序编码为一个列表。
// lastPublicField 可以帮助确定需要编码的字段范围，或者在某些优化场景中定位最后一个字段。
func lastPublicField(fields []Field) int {
	last := 0
	for _, f := range fields {
		if f.Exported {
			last = f.Index
		}
	}
	return last
}

// 以太坊 ABI:
// bytes: 动态字节数组，编码为长度前缀加数据。
// bytes<M>: 固定字节数组，填充到指定长度。
// Go 中，[]byte 映射到 bytes，[M]byte 映射到 bytes<M>。
// RLP 规则:
// 字节数组直接编码为字符串格式（0x80 + length + data）。

// isUint 检查给定的 reflect.Kind 是否为无符号整数类型。
// reflect.Kind 是 Go 反射包中定义的枚举类型，表示变量的基础类型（如 reflect.Int, reflect.Uint, reflect.String 等）。
// reflect.Uint: 表示无符号整数类型（如 uint, uint8, uint16, uint32, uint64）的起点。
// reflect.Uintptr: 表示 uintptr 类型，通常是无符号整数范围的终点。
func isUint(k reflect.Kind) bool {
	return k >= reflect.Uint && k <= reflect.Uintptr
}

// isByte 检查给定的 Type 是否为字节类型（uint8 且不是编码器）。
func isByte(typ Type) bool {
	// typ.Kind == reflect.Uint8: 检查类型是否为 uint8（8 位无符号整数，通常表示单个字节）。
	// !typ.IsEncoder: 额外条件，确保该类型不是“编码器”。
	return typ.Kind == reflect.Uint8 && !typ.IsEncoder
}

// isByteArray 检查给定的 Type 是否为字节数组或切片。
func isByteArray(typ Type) bool {
	// *typ.Elem 解引用获取元素类型，
	return (typ.Kind == reflect.Slice || typ.Kind == reflect.Array) && isByte(*typ.Elem)
}
