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
	"reflect"
)

var (
	// errBadBool is returned when a boolean value is improperly encoded.
	// errBadBool 在布尔值编码不正确时返回。
	errBadBool = errors.New("abi: improperly encoded boolean value")

	// errBadUint8 is returned when a uint8 value is improperly encoded.
	// errBadUint8 在 uint8 值编码不正确时返回。
	errBadUint8 = errors.New("abi: improperly encoded uint8 value")

	// errBadUint16 is returned when a uint16 value is improperly encoded.
	// errBadUint16 在 uint16 值编码不正确时返回。
	errBadUint16 = errors.New("abi: improperly encoded uint16 value")

	// errBadUint32 is returned when a uint32 value is improperly encoded.
	// errBadUint32 在 uint32 值编码不正确时返回。
	errBadUint32 = errors.New("abi: improperly encoded uint32 value")

	// errBadUint64 is returned when a uint64 value is improperly encoded.
	// errBadUint64 在 uint64 值编码不正确时返回。
	errBadUint64 = errors.New("abi: improperly encoded uint64 value")

	// errBadInt8 is returned when an int8 value is improperly encoded.
	// errBadInt8 在 int8 值编码不正确时返回。
	errBadInt8 = errors.New("abi: improperly encoded int8 value")

	// errBadInt16 is returned when an int16 value is improperly encoded.
	// errBadInt16 在 int16 值编码不正确时返回。
	errBadInt16 = errors.New("abi: improperly encoded int16 value")

	// errBadInt32 is returned when an int32 value is improperly encoded.
	// errBadInt32 在 int32 值编码不正确时返回。
	errBadInt32 = errors.New("abi: improperly encoded int32 value")

	// errBadInt64 is returned when an int64 value is improperly encoded.
	// errBadInt64 在 int64 值编码不正确时返回。
	errBadInt64 = errors.New("abi: improperly encoded int64 value")
)

// formatSliceString formats the reflection kind with the given slice size
// and returns a formatted string representation.
// formatSliceString 使用给定的切片大小格式化反射类型，并返回格式化的字符串表示。
func formatSliceString(kind reflect.Kind, sliceSize int) string {
	if sliceSize == -1 {
		// 动态大小的切片，例如 "[]int"
		return fmt.Sprintf("[]%v", kind)
	}
	// 固定大小的数组，例如 "[10]int"
	return fmt.Sprintf("[%d]%v", sliceSize, kind)
}

// sliceTypeCheck checks that the given slice can by assigned to the reflection
// type in t.
// sliceTypeCheck 检查给定的切片是否可以分配给反射类型 t。
func sliceTypeCheck(t Type, val reflect.Value) error {
	// 确保值是切片或数组类型
	if val.Kind() != reflect.Slice && val.Kind() != reflect.Array {
		return typeErr(formatSliceString(t.GetType().Kind(), t.Size), val.Type())
	}

	// 如果是固定大小的数组，检查长度是否匹配
	if t.T == ArrayTy && val.Len() != t.Size {
		return typeErr(formatSliceString(t.Elem.GetType().Kind(), t.Size), formatSliceString(val.Type().Elem().Kind(), val.Len()))
	}

	// 如果元素类型是切片或数组，递归检查第一个元素
	if t.Elem.T == SliceTy || t.Elem.T == ArrayTy {
		if val.Len() > 0 {
			return sliceTypeCheck(*t.Elem, val.Index(0))
		}
	}

	// 检查元素类型的反射种类是否匹配
	if val.Type().Elem().Kind() != t.Elem.GetType().Kind() {
		return typeErr(formatSliceString(t.Elem.GetType().Kind(), t.Size), val.Type())
	}
	return nil
}

// typeCheck checks that the given reflection value can be assigned to the reflection
// type in t.
// typeCheck 检查给定的反射值是否可以分配给反射类型 t。
func typeCheck(t Type, value reflect.Value) error {
	// 如果类型是切片或数组，调用 sliceTypeCheck 进行检查
	if t.T == SliceTy || t.T == ArrayTy {
		return sliceTypeCheck(t, value)
	}

	// Check base type validity. Element types will be checked later on. 检查基础类型的合法性。元素类型将在后续检查。
	if t.GetType().Kind() != value.Kind() {
		return typeErr(t.GetType().Kind(), value.Kind())
	} else if t.T == FixedBytesTy && t.Size != value.Len() {
		// 如果是固定字节数组，检查长度是否匹配
		return typeErr(t.GetType(), value.Type())
	} else {
		return nil
	}
}

// typeErr returns a formatted type casting error.
// typeErr 返回格式化的类型转换错误。
func typeErr(expected, got interface{}) error {
	return fmt.Errorf("abi: cannot use %v as type %v as argument", got, expected)
}
