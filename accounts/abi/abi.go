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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The ABI holds information about a contract's context and available
// invocable methods. It will allow you to type check function calls and
// packs data accordingly.
// ABI 包含有关合同上下文和可用可调用方法的信息。它将允许您对函数调用进行类型检查并相应地打包数据。
type ABI struct {
	Constructor Method
	Methods     map[string]Method
	Events      map[string]Event
	Errors      map[string]Error

	// Additional "special" functions introduced in solidity v0.6.0.
	// It's separated from the original default fallback. Each contract
	// can only define one fallback and receive function.
	// Solidity v0.6.0 中引入的附加“特殊”函数。
	// 它与原始默认回退函数分开。每个合同只能定义一个回退和接收函数。
	Fallback Method // Note it's also used to represent legacy fallback before v0.6.0 注意，它也用于表示 v0.6.0 之前的遗留回退函数
	Receive  Method
}

// JSON returns a parsed ABI interface and error if it failed.
// JSON 返回解析后的 ABI 接口，如果失败则返回错误。
func JSON(reader io.Reader) (ABI, error) {
	dec := json.NewDecoder(reader)

	var abi ABI
	if err := dec.Decode(&abi); err != nil {
		return ABI{}, err
	}
	return abi, nil
}

// Pack the given method name to conform the ABI. Method call's data
// will consist of method_id, args0, arg1, ... argN. Method id consists
// of 4 bytes and arguments are all 32 bytes.
// Method ids are created from the first 4 bytes of the hash of the
// methods string signature. (signature = baz(uint32,string32))
// Pack 将给定的方法名称打包以符合 ABI。方法调用的数据将包括 method_id、args0、arg1 ... argN。
// 方法 ID 由 4 个字节组成，参数均为 32 个字节。
// 方法 ID 是从方法字符串签名哈希的前 4 个字节创建的。（签名 = baz(uint32,string32)）
func (abi ABI) Pack(name string, args ...interface{}) ([]byte, error) {
	// Fetch the ABI of the requested method
	// 获取所请求方法的 ABI
	if name == "" {
		// constructor
		// 构造函数
		arguments, err := abi.Constructor.Inputs.Pack(args...)
		if err != nil {
			return nil, err
		}
		return arguments, nil
	}
	method, exist := abi.Methods[name]
	if !exist {
		return nil, fmt.Errorf("method '%s' not found", name)
	}
	arguments, err := method.Inputs.Pack(args...)
	if err != nil {
		return nil, err
	}
	// Pack up the method ID too if not a constructor and return
	// 如果不是构造函数，也打包方法 ID 并返回
	return append(method.ID, arguments...), nil
}

func (abi ABI) getArguments(name string, data []byte) (Arguments, error) {
	// since there can't be naming collisions with contracts and events,
	// we need to decide whether we're calling a method, event or an error
	// 由于合同和事件之间不会有命名冲突，我们需要决定我们是在调用方法、事件还是错误
	var args Arguments
	if method, ok := abi.Methods[name]; ok {
		if len(data)%32 != 0 {
			return nil, fmt.Errorf("abi: improperly formatted output: %q - Bytes: %+v", data, data)
		}
		args = method.Outputs
	}
	if event, ok := abi.Events[name]; ok {
		args = event.Inputs
	}
	if err, ok := abi.Errors[name]; ok {
		args = err.Inputs
	}
	if args == nil {
		return nil, fmt.Errorf("abi: could not locate named method, event or error: %s", name)
	}
	return args, nil
}

// Unpack unpacks the output according to the abi specification.
// Unpack 根据 ABI 规范解包输出。
func (abi ABI) Unpack(name string, data []byte) ([]interface{}, error) {
	args, err := abi.getArguments(name, data)
	if err != nil {
		return nil, err
	}
	return args.Unpack(data)
}

// UnpackIntoInterface unpacks the output in v according to the abi specification.
// It performs an additional copy. Please only use, if you want to unpack into a
// structure that does not strictly conform to the abi structure (e.g. has additional arguments)
// UnpackIntoInterface 根据 ABI 规范将输出解包到 v 中。
// 它执行额外的复制。请仅在您想解包到不符合严格 ABI 结构的结构（例如有额外参数）时使用。
func (abi ABI) UnpackIntoInterface(v interface{}, name string, data []byte) error {
	args, err := abi.getArguments(name, data)
	if err != nil {
		return err
	}
	unpacked, err := args.Unpack(data)
	if err != nil {
		return err
	}
	return args.Copy(v, unpacked)
}

// UnpackIntoMap unpacks a log into the provided map[string]interface{}.
// UnpackIntoMap 将日志解包到提供的 map[string]interface{} 中。
func (abi ABI) UnpackIntoMap(v map[string]interface{}, name string, data []byte) (err error) {
	args, err := abi.getArguments(name, data)
	if err != nil {
		return err
	}
	return args.UnpackIntoMap(v, data)
}

// UnmarshalJSON implements json.Unmarshaler interface.
// UnmarshalJSON 实现 json.Unmarshaler 接口。
func (abi *ABI) UnmarshalJSON(data []byte) error {
	var fields []struct {
		Type    string
		Name    string
		Inputs  []Argument
		Outputs []Argument

		// Status indicator which can be: "pure", "view",
		// "nonpayable" or "payable".
		// 状态指示器，可以是："pure"、"view"、"nonpayable" 或 "payable"。
		StateMutability string

		// Deprecated Status indicators, but removed in v0.6.0.
		// 已废弃的状态指示器，但在 v0.6.0 中移除。
		Constant bool // True if function is either pure or view 如果函数是 pure 或 view，则为 True
		Payable  bool // True if function is payable 如果函数是 payable，则为 True

		// Event relevant indicator represents the event is
		// declared as anonymous.
		// 与事件相关的指示器，表示事件被声明为匿名的。
		Anonymous bool
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	abi.Methods = make(map[string]Method)
	abi.Events = make(map[string]Event)
	abi.Errors = make(map[string]Error)
	for _, field := range fields {
		switch field.Type {
		case "constructor":
			abi.Constructor = NewMethod("", "", Constructor, field.StateMutability, field.Constant, field.Payable, field.Inputs, nil)
		case "function":
			name := ResolveNameConflict(field.Name, func(s string) bool { _, ok := abi.Methods[s]; return ok })
			abi.Methods[name] = NewMethod(name, field.Name, Function, field.StateMutability, field.Constant, field.Payable, field.Inputs, field.Outputs)
		case "fallback":
			// New introduced function type in v0.6.0, check more detail
			// here https://solidity.readthedocs.io/en/v0.6.0/contracts.html#fallback-function
			// 在 v0.6.0 中引入的新函数类型，更多详情见此处
			// https://solidity.readthedocs.io/en/v0.6.0/contracts.html#fallback-function
			if abi.HasFallback() {
				return errors.New("only single fallback is allowed")
			}
			abi.Fallback = NewMethod("", "", Fallback, field.StateMutability, field.Constant, field.Payable, nil, nil)
		case "receive":
			// New introduced function type in v0.6.0, check more detail
			// here https://solidity.readthedocs.io/en/v0.6.0/contracts.html#fallback-function
			// 在 v0.6.0 中引入的新函数类型，更多详情见此处
			// https://solidity.readthedocs.io/en/v0.6.0/contracts.html#fallback-function
			if abi.HasReceive() {
				return errors.New("only single receive is allowed")
			}
			if field.StateMutability != "payable" {
				return errors.New("the statemutability of receive can only be payable")
			}
			abi.Receive = NewMethod("", "", Receive, field.StateMutability, field.Constant, field.Payable, nil, nil)
		case "event":
			name := ResolveNameConflict(field.Name, func(s string) bool { _, ok := abi.Events[s]; return ok })
			abi.Events[name] = NewEvent(name, field.Name, field.Anonymous, field.Inputs)
		case "error":
			// Errors cannot be overloaded or overridden but are inherited,
			// no need to resolve the name conflict here.
			// 错误不能被重载或覆盖，但可以被继承，此处无需解析名称冲突。
			abi.Errors[field.Name] = NewError(field.Name, field.Inputs)
		default:
			return fmt.Errorf("abi: could not recognize type %v of field %v", field.Type, field.Name)
		}
	}
	return nil
}

// MethodById looks up a method by the 4-byte id,
// returns nil if none found.
// MethodById 通过 4 字节 ID 查找方法，如果未找到则返回 nil。
func (abi *ABI) MethodById(sigdata []byte) (*Method, error) {
	if len(sigdata) < 4 {
		return nil, fmt.Errorf("data too short (%d bytes) for abi method lookup", len(sigdata))
	}
	for _, method := range abi.Methods {
		if bytes.Equal(method.ID, sigdata[:4]) {
			return &method, nil
		}
	}
	return nil, fmt.Errorf("no method with id: %#x", sigdata[:4])
}

// EventByID looks an event up by its topic hash in the
// ABI and returns nil if none found.
// EventByID 通过主题哈希在 ABI 中查找事件，如果未找到则返回 nil。
func (abi *ABI) EventByID(topic common.Hash) (*Event, error) {
	for _, event := range abi.Events {
		if bytes.Equal(event.ID.Bytes(), topic.Bytes()) {
			return &event, nil
		}
	}
	return nil, fmt.Errorf("no event with id: %#x", topic.Hex())
}

// ErrorByID looks up an error by the 4-byte id,
// returns nil if none found.
// ErrorByID 通过 4 字节 ID 查找错误，如果未找到则返回 nil。
func (abi *ABI) ErrorByID(sigdata [4]byte) (*Error, error) {
	for _, errABI := range abi.Errors {
		if bytes.Equal(errABI.ID[:4], sigdata[:]) {
			return &errABI, nil
		}
	}
	return nil, fmt.Errorf("no error with id: %#x", sigdata[:])
}

// HasFallback returns an indicator whether a fallback function is included.
// HasFallback 返回一个指示器，指示是否包含回退函数。
func (abi *ABI) HasFallback() bool {
	return abi.Fallback.Type == Fallback
}

// HasReceive returns an indicator whether a receive function is included.
// HasReceive 返回一个指示器，指示是否包含接收函数。
func (abi *ABI) HasReceive() bool {
	return abi.Receive.Type == Receive
}

// revertSelector is a special function selector for revert reason unpacking.
// revertSelector 是用于解包 revert 原因的特殊函数选择器。
var revertSelector = crypto.Keccak256([]byte("Error(string)"))[:4]

// panicSelector is a special function selector for panic reason unpacking.
// panicSelector 是用于解包 panic 原因的特殊函数选择器。
var panicSelector = crypto.Keccak256([]byte("Panic(uint256)"))[:4]

// panicReasons map is for readable panic codes
// see this linkage for the details
// https://docs.soliditylang.org/en/v0.8.21/control-structures.html#panic-via-assert-and-error-via-require
// the reason string list is copied from ether.js
// https://github.com/ethers-io/ethers.js/blob/fa3a883ff7c88611ce766f58bdd4b8ac90814470/src.ts/abi/interface.ts#L207-L218
// panicReasons 映射用于可读的 panic 代码
// 详情见此链接
// https://docs.soliditylang.org/en/v0.8.21/control-structures.html#panic-via-assert-and-error-via-require
// 原因字符串列表从 ether.js 复制
// https://github.com/ethers-io/ethers.js/blob/fa3a883ff7c88611ce766f58bdd4b8ac90814470/src.ts/abi/interface.ts#L207-L218
var panicReasons = map[uint64]string{
	0x00: "generic panic",                                         // 通用 panic
	0x01: "assert(false)",                                         // assert(false)
	0x11: "arithmetic underflow or overflow",                      // 算术下溢或溢出
	0x12: "division or modulo by zero",                            // 除以零或模零
	0x21: "enum overflow",                                         // 枚举溢出
	0x22: "invalid encoded storage byte array accessed",           // 访问无效编码的存储字节数组
	0x31: "out-of-bounds array access; popping on an empty array", // 数组越界访问；在空数组上弹出
	0x32: "out-of-bounds access of an array or bytesN",            // 数组或 bytesN 越界访问
	0x41: "out of memory",                                         // 内存不足
	0x51: "uninitialized function",                                // 未初始化函数
}

// UnpackRevert resolves the abi-encoded revert reason. According to the solidity
// spec https://solidity.readthedocs.io/en/latest/control-structures.html#revert,
// the provided revert reason is abi-encoded as if it were a call to function
// `Error(string)` or `Panic(uint256)`. So it's a special tool for it.
// UnpackRevert 解析 ABI 编码的 revert 原因。根据 Solidity 规范
// https://solidity.readthedocs.io/en/latest/control-structures.html#revert，
// 提供的 revert 原因被 ABI 编码为如同调用函数 `Error(string)` 或 `Panic(uint256)`。因此这是一个专用工具。
func UnpackRevert(data []byte) (string, error) {
	if len(data) < 4 {
		return "", errors.New("invalid data for unpacking")
	}
	switch {
	case bytes.Equal(data[:4], revertSelector):
		typ, err := NewType("string", "", nil)
		if err != nil {
			return "", err
		}
		unpacked, err := (Arguments{{Type: typ}}).Unpack(data[4:])
		if err != nil {
			return "", err
		}
		return unpacked[0].(string), nil
	case bytes.Equal(data[:4], panicSelector):
		typ, err := NewType("uint256", "", nil)
		if err != nil {
			return "", err
		}
		unpacked, err := (Arguments{{Type: typ}}).Unpack(data[4:])
		if err != nil {
			return "", err
		}
		pCode := unpacked[0].(*big.Int)
		// uint64 safety check for future
		// but the code is not bigger than MAX(uint64) now
		// 为未来进行 uint64 安全检查
		// 但目前代码不超过 MAX(uint64)
		if pCode.IsUint64() {
			if reason, ok := panicReasons[pCode.Uint64()]; ok {
				return reason, nil
			}
		}
		return fmt.Sprintf("unknown panic code: %#x", pCode), nil
	default:
		return "", errors.New("invalid data for unpacking")
	}
}
