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
	"fmt"
	"maps"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/rlp/internal/rlpstruct"
)

// typeinfo is an entry in the type cache.
// typeinfo是类型缓存中的一个入口。
type typeinfo struct {
	decoder    decoder
	decoderErr error // error from makeDecoder // 解码器错误信息
	writer     writer
	writerErr  error // error from makeWriter // 编写器错误信息
}

// typekey is the key of a type in typeCache. It includes the struct tags because
// they might generate a different decoder.
// 类型键是类型缓存中的类型的键。它包括结构标签，因为它们可能会生成不同的解码器。
type typekey struct {
	reflect.Type // 这个字段表示类型缓存中的类型的实例，用于区分相同类型但不同结构体的类型
	// 说明：reflect.Type表示类型信息，是Go语言中反射机制的一部分，用于在运行时动态地操作数据和函数。
	rlpstruct.Tags // 结构标签，可能会生成不同的解码器
	// 解释：结构体标签（如`json`、`xml`等）可以影响编解码过程中的行为。这些标签可能导致产生不同的解码器，从而影响类型缓存的查找结果。
}

// decoder解码器的注释：
//
// - 从rlp数据流中读取数据并将其写入reflect.Value参数
// - 如果出现错误，则返回error
type decoder = func(*Stream, reflect.Value) error // 同上，为了保持一致性

// writer编写器的注释：
//
// - 从reflect.Value中读取数据并将其写入encBuffer参数
// - 如果出现错误，则返回error
type writer = func(reflect.Value, *encBuffer) error // 同上，为了保持一致性

var theTC = newTypeCache()

type typeCache struct {
	cur  atomic.Value          // 当前类型缓存的值使用原子值保证线程安全
	mu   sync.Mutex            // 锁确保在多个 goroutine 中不会同时写入或读取类型缓存
	next map[typekey]*typeinfo // 保存类型对应的解码器和编写器信息，键是 typekey 结构体
}

// 新建类型缓存实例
func newTypeCache() *typeCache {
	c := new(typeCache)
	c.cur.Store(make(map[typekey]*typeinfo))
	return c
}

// 从缓存中获取解码器或编写器，根据给定的反射类型。
// cachedDecoder函数从类型缓存中获取对应的解码器，如果不在缓存中，则生成一个新的。
func cachedDecoder(typ reflect.Type) (decoder, error) {
	info := theTC.info(typ)
	return info.decoder, info.decoderErr
}

// cachedWriter函数类似于cachedDecoder，返回编写器和可能的错误。
// 类似的，cachedWriter函数返回编写器和可能的错误。
func cachedWriter(typ reflect.Type) (writer, error) {
	info := theTC.info(typ)
	return info.writer, info.writerErr
}

// 从类型缓存中获取有关指定反射类型的信息。info函数会检查当前缓存是否存在该信息，如果不存在，则生成新的信息并存入缓存。
// func info从类型缓存中获取关于指定反射类型的信息。如果信息不在缓存中，则生成新信息，并将其存入缓存。
func (c *typeCache) info(typ reflect.Type) *typeinfo {
	key := typekey{Type: typ}
	if info := c.cur.Load().(map[typekey]*typeinfo)[key]; info != nil {
		return info
	}

	// Not in the cache, need to generate info for this type.
	// 缓存中不存在，需要为该类型生成信息。
	return c.generate(typ, rlpstruct.Tags{})
}

func (c *typeCache) generate(typ reflect.Type, tags rlpstruct.Tags) *typeinfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	cur := c.cur.Load().(map[typekey]*typeinfo)
	if info := cur[typekey{typ, tags}]; info != nil {
		return info
	}

	// Copy cur to next.
	// 将 cur 复制到 next。
	c.next = maps.Clone(cur)

	// Generate.
	info := c.infoWhileGenerating(typ, tags)

	// next -> cur
	// next 指向 cur。
	c.cur.Store(c.next)
	c.next = nil
	return info
}

func (c *typeCache) infoWhileGenerating(typ reflect.Type, tags rlpstruct.Tags) *typeinfo {
	key := typekey{typ, tags}
	if info := c.next[key]; info != nil {
		return info
	}
	// Put a dummy value into the cache before generating.
	// If the generator tries to lookup itself, it will get
	// the dummy value and won't call itself recursively.
	// 在生成之前将一个虚拟值放入缓存。
	// 如果生成器尝试查找自身，它将获得虚拟值，而不会递归调用自身。
	info := new(typeinfo)
	c.next[key] = info
	info.generate(typ, tags)
	return info
}

type field struct {
	index    int
	info     *typeinfo
	optional bool
}

// structFields resolves the typeinfo of all public fields in a struct type.
// structFields 解析结构体类型中所有公开字段的 typeinfo。
func structFields(typ reflect.Type) (fields []field, err error) {
	// Convert fields to rlpstruct.Field.
	// 将字段转换为 rlpstruct.Field。
	var allStructFields []rlpstruct.Field
	for i := 0; i < typ.NumField(); i++ {
		rf := typ.Field(i)
		allStructFields = append(allStructFields, rlpstruct.Field{
			Name:     rf.Name,
			Index:    i,
			Exported: rf.PkgPath == "",
			Tag:      string(rf.Tag),
			Type:     *rtypeToStructType(rf.Type, nil),
		})
	}

	// Filter/validate fields.
	// 过滤/验证字段。
	structFields, structTags, err := rlpstruct.ProcessFields(allStructFields)
	if err != nil {
		if tagErr, ok := err.(rlpstruct.TagError); ok {
			tagErr.StructType = typ.String()
			return nil, tagErr
		}
		return nil, err
	}

	// Resolve typeinfo.
	// 解析 typeinfo。
	for i, sf := range structFields {
		typ := typ.Field(sf.Index).Type
		tags := structTags[i]
		info := theTC.infoWhileGenerating(typ, tags)
		fields = append(fields, field{sf.Index, info, tags.Optional})
	}
	return fields, nil
}

// firstOptionalField returns the index of the first field with "optional" tag.
// firstOptionalField 返回第一个带有 "optional" 标签的字段的索引。
func firstOptionalField(fields []field) int {
	for i, f := range fields {
		if f.optional {
			return i
		}
	}
	return len(fields)
}

type structFieldError struct {
	typ   reflect.Type
	field int
	err   error
}

func (e structFieldError) Error() string {
	return fmt.Sprintf("%v (struct field %v.%s)", e.err, e.typ, e.typ.Field(e.field).Name)
}

func (i *typeinfo) generate(typ reflect.Type, tags rlpstruct.Tags) {
	i.decoder, i.decoderErr = makeDecoder(typ, tags)
	i.writer, i.writerErr = makeWriter(typ, tags)
}

// rtypeToStructType converts typ to rlpstruct.Type.
// 将一个输入类型 typ 转换为 rlpstruct.Type
func rtypeToStructType(typ reflect.Type, rec map[reflect.Type]*rlpstruct.Type) *rlpstruct.Type {
	k := typ.Kind()
	if k == reflect.Invalid {
		panic("invalid kind")
	}

	if prev := rec[typ]; prev != nil {
		return prev // short-circuit for recursive types 递归类型的短路处理
	}
	if rec == nil {
		rec = make(map[reflect.Type]*rlpstruct.Type)
	}

	t := &rlpstruct.Type{
		Name:      typ.String(),
		Kind:      k,
		IsEncoder: typ.Implements(encoderInterface),
		IsDecoder: typ.Implements(decoderInterface),
	}
	rec[typ] = t
	if k == reflect.Array || k == reflect.Slice || k == reflect.Ptr {
		t.Elem = rtypeToStructType(typ.Elem(), rec)
	}
	return t
}

// typeNilKind gives the RLP value kind for nil pointers to 'typ'.
// typeNilKind 给定反射类型' typ'和RLP标签'tags'，返回该类型对应的RLP值kind。
func typeNilKind(typ reflect.Type, tags rlpstruct.Tags) Kind {
	styp := rtypeToStructType(typ, nil)

	var nk rlpstruct.NilKind
	if tags.NilOK {
		nk = tags.NilKind // 从RLP标签中获取nil值kind。如果可以处理nil，则使用RLP提供的nil类型。
	} else {
		nk = styp.DefaultNilValue()
	}
	switch nk {
	case rlpstruct.NilKindString:
		return String
	case rlpstruct.NilKindList:
		return List
	default:
		panic("invalid nil kind value")
	}
}

// isUint(k reflect.Kind) 检查k是否是uint或UIntptr类型之一。
func isUint(k reflect.Kind) bool {
	return k >= reflect.Uint && k <= reflect.Uintptr
}

// isByte(typ reflect.Type) 检查typ是否表示一个字节类型，并且不实现Encoder接口。
func isByte(typ reflect.Type) bool {
	return typ.Kind() == reflect.Uint8 && !typ.Implements(encoderInterface)
}
