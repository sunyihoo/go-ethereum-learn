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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
)

// ABI 规范 ：
// ABI（应用二进制接口）是以太坊中定义智能合约方法和事件的标准接口。
// 这些方法严格遵循 ABI 规范，确保编码和解码过程的一致性。
// 字节对齐 ：
// 以太坊 ABI 要求所有数据都必须对齐到 32 字节，因此需要左填充或右填充来满足这一要求。
// 动态与静态类型 ：
// 动态类型（如字符串和动态字节数组）需要额外的长度字段，而静态类型（如固定长度字节数组）则直接填充到 32 字节。

// packBytesSlice packs the given bytes as [L, V] as the canonical representation
// bytes slice.
// packBytesSlice 将给定的字节数据打包为 [L, V] 的规范表示形式。
// L 表示长度，V 表示右填充到 32 字节对齐的数据。
func packBytesSlice(bytes []byte, l int) []byte {
	// 打包长度 L
	len := packNum(reflect.ValueOf(l))
	// 返回长度 L 和右填充后的数据 V
	return append(len, common.RightPadBytes(bytes, (l+31)/32*32)...)
}

// packElement packs the given reflect value according to the abi specification in
// t.
// packElement 根据 ABI 规范中的类型 t 打包给定的反射值。
func packElement(t Type, reflectValue reflect.Value) ([]byte, error) {
	switch t.T {
	case IntTy, UintTy:
		// 对于整数类型（IntTy 或 UintTy），直接调用 packNum 打包
		return packNum(reflectValue), nil
	case StringTy:
		// 对于字符串类型，将其转换为字节数组并打包为 [L, V] 形式
		return packBytesSlice([]byte(reflectValue.String()), reflectValue.Len()), nil
	case AddressTy:
		// 对于地址类型，确保值是字节数组并左填充到 32 字节
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}

		return common.LeftPadBytes(reflectValue.Bytes(), 32), nil
	case BoolTy:
		// 对于布尔类型，根据值返回 32 字节填充的 1 或 0
		if reflectValue.Bool() {
			return math.PaddedBigBytes(common.Big1, 32), nil
		}
		return math.PaddedBigBytes(common.Big0, 32), nil
	case BytesTy:
		// 对于动态字节数组类型，确保值是字节数组并打包为 [L, V] 形式
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}
		if reflectValue.Type() != reflect.TypeOf([]byte{}) {
			return []byte{}, errors.New("bytes type is neither slice nor array")
		}
		return packBytesSlice(reflectValue.Bytes(), reflectValue.Len()), nil
	case FixedBytesTy, FunctionTy:
		// 对于固定长度字节数组或函数类型，确保值是字节数组并右填充到 32 字节
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}
		return common.RightPadBytes(reflectValue.Bytes(), 32), nil
	default:
		// 如果类型未知，返回错误
		return []byte{}, fmt.Errorf("could not pack element, unknown type: %v", t.T)
	}
}

// packNum packs the given number (using the reflect value) and will cast it to appropriate number representation.
// packNum 打包给定的数字（使用反射值）并将其转换为适当的数字表示形式。
func packNum(value reflect.Value) []byte {
	switch kind := value.Kind(); kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		// 对于无符号整数类型，使用 big.Int 转换并返回 32 字节表示
		return math.U256Bytes(new(big.Int).SetUint64(value.Uint()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// 对于有符号整数类型，使用 big.Int 转换并返回 32 字节表示
		return math.U256Bytes(big.NewInt(value.Int()))
	case reflect.Ptr:
		// 如果值是指针类型（如 *big.Int），直接使用其值
		return math.U256Bytes(new(big.Int).Set(value.Interface().(*big.Int)))
	default:
		// 如果类型不支持，抛出致命错误
		panic("abi: fatal error")
	}
}
