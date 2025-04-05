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

package abi

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
)

// Type enumerator
const (
	IntTy byte = iota
	UintTy
	BoolTy
	StringTy
	SliceTy
	ArrayTy
	TupleTy
	AddressTy
	FixedBytesTy
	BytesTy
	HashTy
	FixedPointTy
	FunctionTy
)

// Type is the reflection of the supported argument type.
// Type 是对支持的参数类型的反射。
type Type struct {
	Elem *Type // 嵌套类型（如数组或切片的元素类型）
	Size int   // 类型的大小（例如 uint256 的 256）
	T    byte  // 我们的自定义类型检查 Our own type checking

	stringKind string // 持有未解析的字符串，用于派生签名 holds the unparsed string for deriving signatures

	// Tuple relative fields
	TupleRawName  string       // 在源代码中定义的原始结构体名称，可能为空 Raw struct name defined in source code, may be empty.
	TupleElems    []*Type      // 所有元组字段的类型信息 Type information of all tuple fields
	TupleRawNames []string     // 所有元组字段的原始字段名称 Raw field name of all tuple fields
	TupleType     reflect.Type // 元组的底层结构体 Underlying struct of the tuple
}

var (
	// typeRegex parses the abi sub types
	// typeRegex 解析 ABI 子类型
	typeRegex = regexp.MustCompile("([a-zA-Z]+)(([0-9]+)(x([0-9]+))?)?")

	// sliceSizeRegex grab the slice size
	// sliceSizeRegex 获取切片大小
	sliceSizeRegex = regexp.MustCompile("[0-9]+")
)

// NewType creates a new reflection type of abi type given in t.
// NewType 根据给定的 t 创建一个新的 ABI 类型反射类型。
func NewType(t string, internalType string, components []ArgumentMarshaling) (typ Type, err error) {
	// check that array brackets are equal if they exist
	// 检查数组括号是否存在且数量相等
	if strings.Count(t, "[") != strings.Count(t, "]") {
		return Type{}, errors.New("invalid arg type in abi")
	}
	typ.stringKind = t

	// if there are brackets, get ready to go into slice/array mode and
	// recursively create the type
	// 如果有括号，准备进入切片/数组模式并递归创建类型
	if strings.Count(t, "[") != 0 {
		// Note internalType can be empty here.
		// 注意，此处 internalType 可以为空。
		subInternal := internalType
		if i := strings.LastIndex(internalType, "["); i != -1 {
			subInternal = subInternal[:i]
		}
		// recursively embed the type
		// 递归嵌入类型
		i := strings.LastIndex(t, "[")
		embeddedType, err := NewType(t[:i], subInternal, components)
		if err != nil {
			return Type{}, err
		}
		// grab the last cell and create a type from there
		// 获取最后一个单元并从中创建类型
		sliced := t[i:]
		// grab the slice size with regexp
		// 使用正则表达式获取切片大小
		intz := sliceSizeRegex.FindAllString(sliced, -1)

		if len(intz) == 0 {
			// is a slice
			// 是切片
			typ.T = SliceTy
			typ.Elem = &embeddedType
			typ.stringKind = embeddedType.stringKind + sliced
		} else if len(intz) == 1 {
			// is an array
			// 是数组
			typ.T = ArrayTy
			typ.Elem = &embeddedType
			typ.Size, err = strconv.Atoi(intz[0])
			if err != nil {
				return Type{}, fmt.Errorf("abi: error parsing variable size: %v", err)
			}
			typ.stringKind = embeddedType.stringKind + sliced
		} else {
			return Type{}, errors.New("invalid formatting of array type")
		}
		return typ, err
	}
	// parse the type and size of the abi-type.
	// 解析 ABI 类型的类型和大小。
	matches := typeRegex.FindAllStringSubmatch(t, -1)
	if len(matches) == 0 {
		return Type{}, fmt.Errorf("invalid type '%v'", t)
	}
	parsedType := matches[0]

	// varSize is the size of the variable
	// varSize 是变量的大小
	var varSize int
	if len(parsedType[3]) > 0 {
		var err error
		varSize, err = strconv.Atoi(parsedType[2])
		if err != nil {
			return Type{}, fmt.Errorf("abi: error parsing variable size: %v", err)
		}
	} else {
		if parsedType[0] == "uint" || parsedType[0] == "int" {
			// this should fail because it means that there's something wrong with
			// the abi type (the compiler should always format it to the size...always)
			// 这应该失败，因为这意味着 ABI 类型有问题（编译器应始终将其格式化为大小）
			return Type{}, fmt.Errorf("unsupported arg type: %s", t)
		}
	}
	// varType is the parsed abi type
	// varType 是解析后的 ABI 类型
	switch varType := parsedType[1]; varType {
	case "int":
		typ.Size = varSize
		typ.T = IntTy
	case "uint":
		typ.Size = varSize
		typ.T = UintTy
	case "bool":
		typ.T = BoolTy
	case "address":
		typ.Size = 20
		typ.T = AddressTy
	case "string":
		typ.T = StringTy
	case "bytes":
		if varSize == 0 {
			typ.T = BytesTy
		} else {
			if varSize > 32 {
				return Type{}, fmt.Errorf("unsupported arg type: %s", t)
			}
			typ.T = FixedBytesTy
			typ.Size = varSize
		}
	case "tuple":
		var (
			fields     []reflect.StructField   // 元组的反射字段
			elems      []*Type                 // 元组元素的类型
			names      []string                // 元组字段的名称
			expression string                  // 规范参数表达式 canonical parameter expression
			used       = make(map[string]bool) // 用于检查字段名冲突
		)
		expression += "("
		for idx, c := range components {
			cType, err := NewType(c.Type, c.InternalType, c.Components)
			if err != nil {
				return Type{}, err
			}
			name := ToCamelCase(c.Name)
			if name == "" {
				return Type{}, errors.New("abi: purely anonymous or underscored field is not supported")
			}
			fieldName := ResolveNameConflict(name, func(s string) bool { return used[s] })
			used[fieldName] = true
			if !isValidFieldName(fieldName) {
				return Type{}, fmt.Errorf("field %d has invalid name", idx)
			}
			fields = append(fields, reflect.StructField{
				Name: fieldName, // reflect.StructOf will panic for any exported field.
				Type: cType.GetType(),
				Tag:  reflect.StructTag("json:\"" + c.Name + "\""),
			})
			elems = append(elems, &cType)
			names = append(names, c.Name)
			expression += cType.stringKind
			if idx != len(components)-1 {
				expression += ","
			}
		}
		expression += ")"

		typ.TupleType = reflect.StructOf(fields)
		typ.TupleElems = elems
		typ.TupleRawNames = names
		typ.T = TupleTy
		typ.stringKind = expression

		const structPrefix = "struct "
		// After solidity 0.5.10, a new field of abi "internalType"
		// is introduced. From that we can obtain the struct name
		// user defined in the source code.
		// 在 Solidity 0.5.10 之后，引入了新的 ABI 字段 "internalType"，
		// 从中我们可以获取用户在源代码中定义的结构体名称。
		if internalType != "" && strings.HasPrefix(internalType, structPrefix) {
			// Foo.Bar type definition is not allowed in golang,
			// convert the format to FooBar
			// Foo.Bar 类型定义在 Go 中不允许，将其转换为 FooBar 格式
			typ.TupleRawName = strings.ReplaceAll(internalType[len(structPrefix):], ".", "")
		}

	case "function":
		typ.T = FunctionTy
		typ.Size = 24
	default:
		if strings.HasPrefix(internalType, "contract ") {
			typ.Size = 20
			typ.T = AddressTy
		} else {
			return Type{}, fmt.Errorf("unsupported arg type: %s", t)
		}
	}

	return
}

// GetType returns the reflection type of the ABI type.
// GetType 返回 ABI 类型的反射类型。
func (t Type) GetType() reflect.Type {
	switch t.T {
	case IntTy:
		return reflectIntType(false, t.Size)
	case UintTy:
		return reflectIntType(true, t.Size)
	case BoolTy:
		return reflect.TypeOf(false)
	case StringTy:
		return reflect.TypeOf("")
	case SliceTy:
		return reflect.SliceOf(t.Elem.GetType())
	case ArrayTy:
		return reflect.ArrayOf(t.Size, t.Elem.GetType())
	case TupleTy:
		return t.TupleType
	case AddressTy:
		return reflect.TypeOf(common.Address{})
	case FixedBytesTy:
		return reflect.ArrayOf(t.Size, reflect.TypeOf(byte(0)))
	case BytesTy:
		return reflect.SliceOf(reflect.TypeOf(byte(0)))
	case HashTy:
		// hashtype currently not used
		// 哈希类型当前未使用
		return reflect.ArrayOf(32, reflect.TypeOf(byte(0)))
	case FixedPointTy:
		// fixedpoint type currently not used
		// 定点类型当前未使用
		return reflect.ArrayOf(32, reflect.TypeOf(byte(0)))
	case FunctionTy:
		return reflect.ArrayOf(24, reflect.TypeOf(byte(0)))
	default:
		panic("Invalid type")
	}
}

// String implements Stringer.
// String 实现 Stringer 接口。
func (t Type) String() (out string) {
	return t.stringKind
}

func (t Type) pack(v reflect.Value) ([]byte, error) {
	// dereference pointer first if it's a pointer
	// 如果是指针，首先解引用
	v = indirect(v)
	if err := typeCheck(t, v); err != nil {
		return nil, err
	}

	switch t.T {
	case SliceTy, ArrayTy:
		var ret []byte

		if t.requiresLengthPrefix() {
			// append length
			// 添加长度
			ret = append(ret, packNum(reflect.ValueOf(v.Len()))...)
		}

		// calculate offset if any
		// 计算偏移量（如果有）
		offset := 0
		offsetReq := isDynamicType(*t.Elem)
		if offsetReq {
			offset = getTypeSize(*t.Elem) * v.Len()
		}
		var tail []byte
		for i := 0; i < v.Len(); i++ {
			val, err := t.Elem.pack(v.Index(i))
			if err != nil {
				return nil, err
			}
			if !offsetReq {
				ret = append(ret, val...)
				continue
			}
			ret = append(ret, packNum(reflect.ValueOf(offset))...)
			offset += len(val)
			tail = append(tail, val...)
		}
		return append(ret, tail...), nil
	case TupleTy:
		// (T1,...,Tk) for k >= 0 and any types T1, …, Tk
		// enc(X) = head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(k))
		// where X = (X(1), ..., X(k)) and head and tail are defined for Ti being a static
		// type as
		//     head(X(i)) = enc(X(i)) and tail(X(i)) = "" (the empty string)
		// and as
		//     head(X(i)) = enc(len(head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(i-1))))
		//     tail(X(i)) = enc(X(i))
		// otherwise, i.e. if Ti is a dynamic type.
		// (T1,...,Tk) 对于 k >= 0 和任何类型 T1, …, Tk
		// enc(X) = head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(k))
		// 其中 X = (X(1), ..., X(k))，对于静态类型 Ti，head 和 tail 定义为：
		//     head(X(i)) = enc(X(i)) 且 tail(X(i)) = ""（空字符串）
		// 对于动态类型 Ti，则定义为：
		//     head(X(i)) = enc(len(head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(i-1))))
		//     tail(X(i)) = enc(X(i))
		fieldmap, err := mapArgNamesToStructFields(t.TupleRawNames, v)
		if err != nil {
			return nil, err
		}
		// Calculate prefix occupied size.
		// 计算前缀占用的大小。
		offset := 0
		for _, elem := range t.TupleElems {
			offset += getTypeSize(*elem)
		}
		var ret, tail []byte
		for i, elem := range t.TupleElems {
			field := v.FieldByName(fieldmap[t.TupleRawNames[i]])
			if !field.IsValid() {
				return nil, fmt.Errorf("field %s for tuple not found in the given struct", t.TupleRawNames[i])
			}
			val, err := elem.pack(field)
			if err != nil {
				return nil, err
			}
			if isDynamicType(*elem) {
				ret = append(ret, packNum(reflect.ValueOf(offset))...)
				tail = append(tail, val...)
				offset += len(val)
			} else {
				ret = append(ret, val...)
			}
		}
		return append(ret, tail...), nil

	default:
		return packElement(t, v)
	}
}

// requiresLengthPrefix returns whether the type requires any sort of length
// prefixing.
// requiresLengthPrefix 返回该类型是否需要某种长度前缀。
func (t Type) requiresLengthPrefix() bool {
	return t.T == StringTy || t.T == BytesTy || t.T == SliceTy
}

// isDynamicType returns true if the type is dynamic.
// The following types are called “dynamic”:
// * bytes
// * string
// * T[] for any T
// * T[k] for any dynamic T and any k >= 0
// * (T1,...,Tk) if Ti is dynamic for some 1 <= i <= k
// isDynamicType 如果类型是动态的，则返回 true。
// 以下类型被称为“动态”：
// * bytes
// * string
// * T[] 对于任何 T
// * T[k] 对于任何动态 T 和任何 k >= 0
// * (T1,...,Tk) 如果对于某些 1 <= i <= k 的 Ti 是动态的
func isDynamicType(t Type) bool {
	if t.T == TupleTy {
		for _, elem := range t.TupleElems {
			if isDynamicType(*elem) {
				return true
			}
		}
		return false
	}
	return t.T == StringTy || t.T == BytesTy || t.T == SliceTy || (t.T == ArrayTy && isDynamicType(*t.Elem))
}

// getTypeSize returns the size that this type needs to occupy.
// We distinguish static and dynamic types. Static types are encoded in-place
// and dynamic types are encoded at a separately allocated location after the
// current block.
// So for a static variable, the size returned represents the size that the
// variable actually occupies.
// For a dynamic variable, the returned size is fixed 32 bytes, which is used
// to store the location reference for actual value storage.
// getTypeSize 返回此类型需要占用的空间大小。
// 我们区分了静态和动态类型。静态类型原地编码，
// 而动态类型在当前块之后单独分配的位置编码。
// 因此，对于静态变量，返回的大小表示变量实际占用的空间。
// 对于动态变量，返回的大小固定为 32 字节，用于存储实际值存储位置的引用。
func getTypeSize(t Type) int {
	if t.T == ArrayTy && !isDynamicType(*t.Elem) {
		// Recursively calculate type size if it is a nested array
		// 如果是嵌套数组，递归计算类型大小
		if t.Elem.T == ArrayTy || t.Elem.T == TupleTy {
			return t.Size * getTypeSize(*t.Elem)
		}
		return t.Size * 32
	} else if t.T == TupleTy && !isDynamicType(t) {
		total := 0
		for _, elem := range t.TupleElems {
			total += getTypeSize(*elem)
		}
		return total
	}
	return 32
}

// isLetter reports whether a given 'rune' is classified as a Letter.
// This method is copied from reflect/type.go
// isLetter 报告给定的 'rune' 是否被分类为字母。
// 此方法从 reflect/type.go 复制而来
func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

// isValidFieldName checks if a string is a valid (struct) field name or not.
//
// According to the language spec, a field name should be an identifier.
//
// identifier = letter { letter | unicode_digit } .
// letter = unicode_letter | "_" .
// This method is copied from reflect/type.go
// isValidFieldName 检查一个字符串是否是有效的（结构体）字段名称。
//
// 根据语言规范，字段名称应为标识符。
//
// 标识符 = 字母 { 字母 | unicode数字 } 。
// 字母 = unicode字母 | "_" 。
// 此方法从 reflect/type.go 复制而来
func isValidFieldName(fieldName string) bool {
	for i, c := range fieldName {
		if i == 0 && !isLetter(c) {
			return false
		}

		if !(isLetter(c) || unicode.IsDigit(c)) {
			return false
		}
	}

	return len(fieldName) > 0
}
