// Copyright 2019 The go-ethereum Authors
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

package fourbyte

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// decodedCallData is an internal type to represent a method call parsed according
// to an ABI method signature.
//
// decodedCallData 是一个内部类型，用于表示根据 ABI 方法签名解析的方法调用。
type decodedCallData struct {
	signature string            // 方法的 ABI 签名（例如 "transfer(address,uint256)"） 方法的 Keccak-256 哈希前 4 字节
	name      string            // 方法名称
	inputs    []decodedArgument // 方法参数的列表，每个参数解析自 ABI。
}

// decodedArgument is an internal type to represent an argument parsed according
// to an ABI method signature.
//
// decodedArgument 是一个内部类型，用于表示根据 ABI 方法签名解析的参数。
type decodedArgument struct {
	soltype abi.Argument // Solidity 类型（如 address、uint256），来自 go-ethereum 的 abi 包。
	value   interface{}  // 参数的实际值，类型动态，根据 soltype 解析。
}

// String implements stringer interface, tries to use the underlying value-type
// String 实现了 stringer 接口，尝试使用底层值类型。
func (arg decodedArgument) String() string {
	var value string
	switch val := arg.value.(type) {
	case fmt.Stringer:
		value = val.String()
	default:
		value = fmt.Sprintf("%v", val)
	}
	return fmt.Sprintf("%v: %v", arg.soltype.Type.String(), value)
}

// String implements stringer interface for decodedCallData
// String 为 decodedCallData 实现了 stringer 接口。
// 返回格式为 "方法名(参数1, 参数2)" 的字符串
func (cd decodedCallData) String() string {
	args := make([]string, len(cd.inputs))
	for i, arg := range cd.inputs {
		args[i] = arg.String()
	}
	return fmt.Sprintf("%s(%s)", cd.name, strings.Join(args, ",")) // "transfer(address: 0x123, uint256: 100)"
}

// verifySelector checks whether the ABI encoded data blob matches the requested
// function signature.
//
// verifySelector 检查 ABI 编码的数据块是否与请求的函数签名匹配。
func verifySelector(selector string, calldata []byte) (*decodedCallData, error) {
	// Parse the selector into an ABI JSON spec

	abidata, err := parseSelector(selector)
	if err != nil {
		return nil, err
	}
	// Parse the call data according to the requested selector
	return parseCallData(calldata, string(abidata))
}

// parseSelector converts a method selector into an ABI JSON spec. The returned
// data is a valid JSON string which can be consumed by the standard abi package.
//
// parseSelector 将方法选择器转换为 ABI JSON 规范。返回的数据是一个有效的 JSON 字符串，可以被标准的 abi 包使用。
func parseSelector(unescapedSelector string) ([]byte, error) {
	selector, err := abi.ParseSelector(unescapedSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to parse selector: %v", err)
	}

	return json.Marshal([]abi.SelectorMarshaling{selector})
}

// parseCallData matches the provided call data against the ABI definition and
// returns a struct containing the actual go-typed values.
//
// parseCallData 将提供的调用数据与 ABI 定义进行匹配，并返回一个包含实际 Go 类型值的结构体。
func parseCallData(calldata []byte, unescapedAbidata string) (*decodedCallData, error) {
	// Validate the call data that it has the 4byte prefix and the rest divisible by 32 bytes
	// 验证调用数据，确保它有 4 字节的前缀，其余部分可被 32 字节整除
	// 检查 calldata 长度是否至少为 4 字节（方法签名的前 4 字节）。以太坊调用数据以方法 ID（4 字节）开头。
	if len(calldata) < 4 {
		return nil, fmt.Errorf("invalid call data, incomplete method signature (%d bytes < 4)", len(calldata))
	}
	sigdata := calldata[:4]

	argdata := calldata[4:]
	//参数按 ABI 编码规则排列，每个参数占 32 字节（或其倍数）。
	if len(argdata)%32 != 0 {
		return nil, fmt.Errorf("invalid call data; length should be a multiple of 32 bytes (was %d)", len(argdata))
	}
	// Validate the called method and unpack the call data accordingly
	// 验证调用的方法并相应地解包调用数据
	abispec, err := abi.JSON(strings.NewReader(unescapedAbidata))
	if err != nil {
		return nil, fmt.Errorf("invalid method signature (%q): %v", unescapedAbidata, err)
	}
	method, err := abispec.MethodById(sigdata)
	if err != nil {
		return nil, err
	}
	values, err := method.Inputs.UnpackValues(argdata)
	if err != nil {
		return nil, fmt.Errorf("signature %q matches, but arguments mismatch: %v", method.String(), err)
	}
	// Everything valid, assemble the call infos for the signer
	// 一切有效，为签名者组装调用信息
	decoded := decodedCallData{signature: method.Sig, name: method.RawName}
	for i := 0; i < len(method.Inputs); i++ {
		decoded.inputs = append(decoded.inputs, decodedArgument{
			soltype: method.Inputs[i],
			value:   values[i],
		})
	}
	// We're finished decoding the data. At this point, we encode the decoded data
	// to see if it matches with the original data. If we didn't do that, it would
	// be possible to stuff extra data into the arguments, which is not detected
	// by merely decoding the data.
	encoded, err := method.Inputs.PackValues(values)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, argdata) {
		was := common.Bytes2Hex(encoded)
		exp := common.Bytes2Hex(argdata)
		return nil, fmt.Errorf("WARNING: Supplied data is stuffed with extra data. \nWant %s\nHave %s\nfor method %v", exp, was, method.Sig)
	}
	return &decoded, nil
}
