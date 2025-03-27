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

package main

import (
	"fmt"
	"go/types"
	"reflect"
)

// typeReflectKind gives the reflect.Kind that represents typ.
// typeReflectKind 返回表示 typ 的 reflect.Kind。
//
// typ 是 go/types 包中的 types.Type 接口，表示 Go 类型系统中的类型。
// 返回对应的 reflect.Kind，表示该类型的反射种类。
//
// 将 go/types 的类型映射到 reflect.Kind，以便在 RLP 编码或 ABI 处理中使用反射。
// 以太坊的 ABI 和 RLP 依赖 Go 的类型信息，reflect.Kind 是运行时反射的基础。
// RLP 编码/解码: 在 go-ethereum/rlp 中，确定字段类型以选择编码规则。
// RLP 需要知道字段的类型（如数组、切片、结构体），typeReflectKind 提供了这种映射。
// ABI 参数处理: 将静态类型映射到运行时类型，用于智能合约交互。
func typeReflectKind(typ types.Type) reflect.Kind {
	switch typ := typ.(type) {
	case *types.Basic: // 处理基本类型（如 int, bool, string）。
		k := typ.Kind()                               // 获取基本类型的种类（types.BasicKind）。
		if k >= types.Bool && k <= types.Complex128 { // 处理布尔、整数、浮点和复数类型。
			// value order matches for Bool..Complex128
			// 对于 Bool..Complex128，值的顺序匹配
			return reflect.Bool + reflect.Kind(k-types.Bool) // 将 types.BasicKind 映射到 reflect.Kind。
		}
		if k == types.String {
			return reflect.String
		}
		if k == types.UnsafePointer {
			return reflect.UnsafePointer
		}
		panic(fmt.Errorf("unhandled BasicKind %v", k))
	case *types.Array:
		return reflect.Array
	case *types.Chan:
		return reflect.Chan
	case *types.Interface:
		return reflect.Interface
	case *types.Map:
		return reflect.Map
	case *types.Pointer:
		return reflect.Ptr
	case *types.Signature:
		return reflect.Func
	case *types.Slice:
		return reflect.Slice
	case *types.Struct:
		return reflect.Struct
	default:
		panic(fmt.Errorf("unhandled type %T", typ))
	}
}

// nonZeroCheck returns the expression that checks whether 'v' is a non-zero value of type 'vtyp'.
// nonZeroCheck 返回检查 'v' 是否为类型 'vtyp' 的非零值的表达式。
//
// vtyp: go/types.Type 类型，表示变量的类型。
// qualify: types.Qualifier，用于格式化类型名称（可能为 nil）。
// 返回一个字符串，表示检查 v 是否为非零值的 Go 表达式。
func nonZeroCheck(v string, vtyp types.Type, qualify types.Qualifier) string {
	// Resolve type name.
	// 解析类型名称。
	typ := resolveUnderlying(vtyp)
	switch typ := typ.(type) {
	case *types.Basic: // 处理基本类型。
		k := typ.Kind()
		switch {
		case k == types.Bool:
			return v // （布尔值非零即为 true）
		case k >= types.Uint && k <= types.Complex128: // 返回 "v != 0"（整数、浮点、复数非零检查）。
			return fmt.Sprintf("%s != 0", v)
		case k == types.String:
			return fmt.Sprintf(`%s != ""`, v) // 返回 "v != ""（字符串非空检查）。
		default:
			panic(fmt.Errorf("unhandled BasicKind %v", k))
		}
	case *types.Array, *types.Struct: // 比较变量与零值结构体/数组。
		return fmt.Sprintf("%s != (%s{})", v, types.TypeString(vtyp, qualify)) // types.TypeString(vtyp, qualify) 生成类型名称（如 "MyStruct"）。
	case *types.Interface, *types.Pointer, *types.Signature:
		return fmt.Sprintf("%s != nil", v) // 返回 "v != nil"，检查是否为 nil。
	case *types.Slice, *types.Map:
		return fmt.Sprintf("len(%s) > 0", v) // 返回 "len(v) > 0"，检查长度是否大于 0。
	default:
		panic(fmt.Errorf("unhandled type %T", typ))
	}
}

// isBigInt checks whether 'typ' is "math/big".Int.
// isBigInt 检查 'typ' 是否为 "math/big".Int。
func isBigInt(typ types.Type) bool {
	named, ok := typ.(*types.Named) // 使用类型断言检查 typ 是否为 *types.Named（命名类型）。
	if !ok {
		return false
	}
	name := named.Obj() // 获取命名类型的对象（types.Object），表示类型名称和包信息。
	return name.Pkg().Path() == "math/big" && name.Name() == "Int"
}

// isUint256 checks whether 'typ' is "github.com/holiman/uint256".Int.
// isUint256 检查 'typ' 是否为 "github.com/holiman/uint256".Int。
func isUint256(typ types.Type) bool {
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	name := named.Obj()
	return name.Pkg().Path() == "github.com/holiman/uint256" && name.Name() == "Int"
}

// isByte checks whether the underlying type of 'typ' is uint8.
// isByte 检查 'typ' 的底层类型是否为 uint8。
func isByte(typ types.Type) bool {
	basic, ok := resolveUnderlying(typ).(*types.Basic)
	return ok && basic.Kind() == types.Uint8
}

// resolveUnderlying 返回类型的底层类型。
// 递归解析类型，获取其最底层的类型表示。
func resolveUnderlying(typ types.Type) types.Type {
	for {
		t := typ.Underlying()
		if t == typ {
			return t
		}
		typ = t
	}
}
