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
	"bytes"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Error represents an error defined in the ABI (Application Binary Interface).
// It includes the error name, input arguments, string representation, signature, and a unique ID.
// Error 表示在 ABI（应用二进制接口）中定义的错误。
// 它包括错误名称、输入参数、字符串表示、签名以及唯一标识符。
type Error struct {
	Name   string
	Inputs Arguments
	str    string

	// Sig contains the string signature according to the ABI spec.
	// e.g. error foo(uint32 a, int b) = "foo(uint32,int256)"
	// Please note that "int" is substitute for its canonical representation "int256"
	Sig string

	// ID returns the canonical representation of the error's signature used by the
	// abi definition to identify event names and types.
	ID common.Hash
}

// NewError creates a new Error instance with the given name and inputs.
// It sanitizes the inputs, precomputes the string and signature representations,
// and calculates the unique ID based on the signature.
// NewError 使用给定的名称和输入参数创建一个新的 Error 实例。
// 它会对输入进行清理，预计算字符串和签名表示，并根据签名计算唯一的 ID。
func NewError(name string, inputs Arguments) Error {
	// sanitize inputs to remove inputs without names
	// and precompute string and sig representation.
	// 清理输入以移除没有名称的输入，并预计算字符串和签名表示。
	names := make([]string, len(inputs))
	types := make([]string, len(inputs))
	for i, input := range inputs {
		if input.Name == "" {
			// 如果输入参数没有名称，则为其生成一个默认名称（如 "arg0", "arg1" 等）
			inputs[i] = Argument{
				Name:    fmt.Sprintf("arg%d", i),
				Indexed: input.Indexed,
				Type:    input.Type,
			}
		} else {
			// 否则保留原始输入
			inputs[i] = input
		}
		// string representation
		// 生成字符串表示形式，例如 "uint32 arg0" 或 "uint32 indexed arg0"
		names[i] = fmt.Sprintf("%v %v", input.Type, inputs[i].Name)
		if input.Indexed {
			names[i] = fmt.Sprintf("%v indexed %v", input.Type, inputs[i].Name)
		}
		// sig representation
		// 生成签名表示形式，例如 "uint32" 或 "int256"
		types[i] = input.Type.String()
	}

	// Generate the full string representation of the error
	// 生成错误的完整字符串表示形式，例如 "error foo(uint32 a, int256 b)"
	str := fmt.Sprintf("error %v(%v)", name, strings.Join(names, ", "))
	// Generate the signature string according to the ABI spec
	// 根据 ABI 规范生成签名字符串，例如 "foo(uint32,int256)"
	sig := fmt.Sprintf("%v(%v)", name, strings.Join(types, ","))
	// Calculate the unique ID using Keccak256 hash of the signature
	// 使用签名的 Keccak256 哈希值计算唯一 ID
	id := common.BytesToHash(crypto.Keccak256([]byte(sig)))

	return Error{
		Name:   name,
		Inputs: inputs,
		str:    str,
		Sig:    sig,
		ID:     id,
	}
}

// String returns the string representation of the error.
// String 返回错误的字符串表示形式。
func (e Error) String() string {
	return e.str
}

// Unpack decodes the provided data into the error's input arguments.
// It first checks if the data matches the error's identifier (first 4 bytes),
// then unpacks the remaining data into the error's inputs.
// Unpack 将提供的数据解码为错误的输入参数。
// 它首先检查数据是否匹配错误的标识符（前 4 字节），然后将剩余数据解码为错误的输入。
func (e *Error) Unpack(data []byte) (interface{}, error) {
	if len(data) < 4 {
		// 数据长度不足时返回错误
		return "", fmt.Errorf("insufficient data for unpacking: have %d, want at least 4", len(data))
	}
	if !bytes.Equal(data[:4], e.ID[:4]) {
		// 如果前 4 字节不匹配错误的 ID，返回错误
		return "", fmt.Errorf("invalid identifier, have %#x want %#x", data[:4], e.ID[:4])
	}
	// 解码剩余数据为错误的输入参数
	return e.Inputs.Unpack(data[4:])
}
