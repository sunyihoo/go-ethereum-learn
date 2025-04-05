// Copyright 2016 The go-ethereum Authors
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

package abi

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

// 在 ABI 解码中，数据类型可能不完全匹配（如 []byte 到 [32]byte），需要宽松的赋值规则。
// big.Int 是以太坊中常用的类型（表示 uint256 或 int256），此函数特别处理其指针形式。
// ABI 解码：以太坊智能合约的返回值以字节数组形式编码，需解码为 Go 类型。ConvertType 和 set 提供了灵活的转换机制。
// 大整数（big.Int）：以太坊中 uint256 和 int256 使用 big.Int 表示，此代码特别优化了对 big.Int 的处理。

// ConvertType converts an interface of a runtime type into an interface of the
// given type, e.g. turn this code:
//
//	var fields []reflect.StructField
//
//	fields = append(fields, reflect.StructField{
//			Name: "X",
//			Type: reflect.TypeOf(new(big.Int)),
//			Tag:  reflect.StructTag("json:\"" + "x" + "\""),
//	})
//
// into:
//
//	type TupleT struct { X *big.Int }
//
// ConvertType 将运行时类型的接口转换为给定类型的接口，例如将以下代码：
//
//	var fields []reflect.StructField
//
//	fields = append(fields, reflect.StructField{
//			Name: "X",
//			Type: reflect.TypeOf(new(big.Int)),
//			Tag:  reflect.StructTag("json:\"" + "x" + "\""),
//	})
//
// 转换为：
//
//	type TupleT struct { X *big.Int }
func ConvertType(in interface{}, proto interface{}) interface{} {
	protoType := reflect.TypeOf(proto)
	if reflect.TypeOf(in).ConvertibleTo(protoType) {
		return reflect.ValueOf(in).Convert(protoType).Interface()
	}
	// Use set as a last ditch effort
	// 作为最后的努力使用 set
	if err := set(reflect.ValueOf(proto), reflect.ValueOf(in)); err != nil {
		panic(err)
	}
	return proto
}

// indirect recursively dereferences the value until it either gets the value
// or finds a big.Int
// indirect 递归解引用值，直到获取到值或找到 big.Int
func indirect(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Ptr && v.Elem().Type() != reflect.TypeOf(big.Int{}) {
		return indirect(v.Elem())
	}
	return v
}

// reflectIntType returns the reflect using the given size and
// unsignedness.
// reflectIntType 根据给定的大小和无符号性返回反射类型。
func reflectIntType(unsigned bool, size int) reflect.Type {
	if unsigned {
		switch size {
		case 8:
			return reflect.TypeOf(uint8(0))
		case 16:
			return reflect.TypeOf(uint16(0))
		case 32:
			return reflect.TypeOf(uint32(0))
		case 64:
			return reflect.TypeOf(uint64(0))
		}
	}
	switch size {
	case 8:
		return reflect.TypeOf(int8(0))
	case 16:
		return reflect.TypeOf(int16(0))
	case 32:
		return reflect.TypeOf(int32(0))
	case 64:
		return reflect.TypeOf(int64(0))
	}
	return reflect.TypeOf(&big.Int{})
}

// mustArrayToByteSlice creates a new byte slice with the exact same size as value
// and copies the bytes in value to the new slice.
// mustArrayToByteSlice 创建一个与 value 大小完全相同的新字节切片，并将 value 中的字节复制到新切片中。
func mustArrayToByteSlice(value reflect.Value) reflect.Value {
	slice := reflect.MakeSlice(reflect.TypeOf([]byte{}), value.Len(), value.Len())
	reflect.Copy(slice, value)
	return slice
}

// set attempts to assign src to dst by either setting, copying or otherwise.
//
// set is a bit more lenient when it comes to assignment and doesn't force an as
// strict ruleset as bare `reflect` does.
// set 尝试通过设置、复制或其他方式将 src 赋值给 dst。
//
// set 在赋值时比纯粹的 `reflect` 更宽松，不强制执行严格的规则集。
func set(dst, src reflect.Value) error {
	dstType, srcType := dst.Type(), src.Type()
	switch {
	case dstType.Kind() == reflect.Interface && dst.Elem().IsValid() && (dst.Elem().Type().Kind() == reflect.Ptr || dst.Elem().CanSet()):
		return set(dst.Elem(), src)
	case dstType.Kind() == reflect.Ptr && dstType.Elem() != reflect.TypeOf(big.Int{}):
		return set(dst.Elem(), src)
	case srcType.AssignableTo(dstType) && dst.CanSet():
		dst.Set(src)
	case dstType.Kind() == reflect.Slice && srcType.Kind() == reflect.Slice && dst.CanSet():
		return setSlice(dst, src)
	case dstType.Kind() == reflect.Array:
		return setArray(dst, src)
	case dstType.Kind() == reflect.Struct:
		return setStruct(dst, src)
	default:
		return fmt.Errorf("abi: cannot unmarshal %v in to %v", src.Type(), dst.Type())
	}
	return nil
}

// setSlice attempts to assign src to dst when slices are not assignable by default
// e.g. src: [][]byte -> dst: [][15]byte
// setSlice ignores if we cannot copy all of src' elements.
// setSlice 在切片默认不可赋值时尝试将 src 赋值给 dst
// 例如 src: [][]byte -> dst: [][15]byte
// setSlice 如果无法复制 src 的所有元素，则忽略。
func setSlice(dst, src reflect.Value) error {
	slice := reflect.MakeSlice(dst.Type(), src.Len(), src.Len())
	for i := 0; i < src.Len(); i++ {
		if err := set(slice.Index(i), src.Index(i)); err != nil {
			return err
		}
	}
	if dst.CanSet() {
		dst.Set(slice)
		return nil
	}
	return errors.New("cannot set slice, destination not settable")
}

func setArray(dst, src reflect.Value) error {
	if src.Kind() == reflect.Ptr {
		return set(dst, indirect(src))
	}
	array := reflect.New(dst.Type()).Elem()
	min := src.Len()
	if src.Len() > dst.Len() {
		min = dst.Len()
	}
	for i := 0; i < min; i++ {
		if err := set(array.Index(i), src.Index(i)); err != nil {
			return err
		}
	}
	if dst.CanSet() {
		dst.Set(array)
		return nil
	}
	return errors.New("cannot set array, destination not settable")
}

func setStruct(dst, src reflect.Value) error {
	for i := 0; i < src.NumField(); i++ {
		srcField := src.Field(i)
		dstField := dst.Field(i)
		if !dstField.IsValid() || !srcField.IsValid() {
			return fmt.Errorf("could not find src field: %v value: %v in destination", srcField.Type().Name(), srcField)
		}
		if err := set(dstField, srcField); err != nil {
			return err
		}
	}
	return nil
}

// mapArgNamesToStructFields maps a slice of argument names to struct fields.
//
// first round: for each Exportable field that contains a `abi:""` tag and this field name
// exists in the given argument name list, pair them together.
//
// second round: for each argument name that has not been already linked, find what
// variable is expected to be mapped into, if it exists and has not been used, pair them.
//
// Note this function assumes the given value is a struct value.
// mapArgNamesToStructFields 将参数名称切片映射到结构体字段。
//
// 第一轮：对于每个包含 `abi:""` 标签的可导出字段，如果该字段名称存在于给定的参数名称列表中，将它们配对。
//
// 第二轮：对于每个尚未链接的参数名称，找到预期映射到的变量，如果它存在且未被使用，将它们配对。
//
// 注意，此函数假定给定的值是一个结构体值。
func mapArgNamesToStructFields(argNames []string, value reflect.Value) (map[string]string, error) {
	typ := value.Type()

	abi2struct := make(map[string]string)
	struct2abi := make(map[string]string)

	// first round ~~~
	// 第一轮 ~~~
	for i := 0; i < typ.NumField(); i++ {
		structFieldName := typ.Field(i).Name

		// skip private struct fields.
		// 跳过私有结构体字段。
		if structFieldName[:1] != strings.ToUpper(structFieldName[:1]) {
			continue
		}
		// skip fields that have no abi:"" tag.
		// 跳过没有 abi:"" 标签的字段。
		tagName, ok := typ.Field(i).Tag.Lookup("abi")
		if !ok {
			continue
		}
		// check if tag is empty.
		// 检查标签是否为空。
		if tagName == "" {
			return nil, fmt.Errorf("struct: abi tag in '%s' is empty", structFieldName)
		}
		// check which argument field matches with the abi tag.
		// 检查哪个参数字段与 abi 标签匹配。
		found := false
		for _, arg := range argNames {
			if arg == tagName {
				if abi2struct[arg] != "" {
					return nil, fmt.Errorf("struct: abi tag in '%s' already mapped", structFieldName)
				}
				// pair them
				// 将它们配对
				abi2struct[arg] = structFieldName
				struct2abi[structFieldName] = arg
				found = true
			}
		}
		// check if this tag has been mapped.
		// 检查此标签是否已映射。
		if !found {
			return nil, fmt.Errorf("struct: abi tag '%s' defined but not found in abi", tagName)
		}
	}

	// second round ~~~
	// 第二轮 ~~~
	for _, argName := range argNames {
		structFieldName := ToCamelCase(argName)

		if structFieldName == "" {
			return nil, errors.New("abi: purely underscored output cannot unpack to struct")
		}

		// this abi has already been paired, skip it... unless there exists another, yet unassigned
		// struct field with the same field name. If so, raise an error:
		//    abi: [ { "name": "value" } ]
		//    struct { Value  *big.Int , Value1 *big.Int `abi:"value"`}
		// 这个 abi 已经配对，跳过它……除非存在另一个尚未分配的同名结构体字段。如果是这样，抛出错误：
		//    abi: [ { "name": "value" } ]
		//    struct { Value  *big.Int , Value1 *big.Int `abi:"value"`}
		if abi2struct[argName] != "" {
			if abi2struct[argName] != structFieldName &&
				struct2abi[structFieldName] == "" &&
				value.FieldByName(structFieldName).IsValid() {
				return nil, fmt.Errorf("abi: multiple variables maps to the same abi field '%s'", argName)
			}
			continue
		}

		// return an error if this struct field has already been paired.
		// 如果此结构体字段已经配对，返回错误。
		if struct2abi[structFieldName] != "" {
			return nil, fmt.Errorf("abi: multiple outputs mapping to the same struct field '%s'", structFieldName)
		}

		if value.FieldByName(structFieldName).IsValid() {
			// pair them
			// 将它们配对
			abi2struct[argName] = structFieldName
			struct2abi[structFieldName] = argName
		} else {
			// not paired, but annotate as used, to detect cases like
			//   abi : [ { "name": "value" }, { "name": "_value" } ]
			//   struct { Value *big.Int }
			// 未配对，但标记为已使用，以检测类似以下情况：
			//   abi : [ { "name": "value" }, { "name": "_value" } ]
			//   struct { Value *big.Int }
			struct2abi[structFieldName] = argName
		}
	}
	return abi2struct, nil
}
