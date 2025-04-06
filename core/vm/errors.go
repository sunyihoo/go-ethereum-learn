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

package vm

import (
	"errors"
	"fmt"
	"math"
)

// List evm execution errors
// 列出EVM执行错误
var (
	ErrOutOfGas                 = errors.New("out of gas")                                // Gas不足
	ErrCodeStoreOutOfGas        = errors.New("contract creation code storage out of gas") // 合约创建代码存储Gas不足
	ErrDepth                    = errors.New("max call depth exceeded")                   // 最大调用深度超出
	ErrInsufficientBalance      = errors.New("insufficient balance for transfer")         // 转账余额不足
	ErrContractAddressCollision = errors.New("contract address collision")                // 合约地址冲突
	ErrExecutionReverted        = errors.New("execution reverted")                        // 执行被回滚
	ErrMaxCodeSizeExceeded      = errors.New("max code size exceeded")                    // 最大代码大小超出
	ErrMaxInitCodeSizeExceeded  = errors.New("max initcode size exceeded")                // 最大初始化代码大小超出
	ErrInvalidJump              = errors.New("invalid jump destination")                  // 无效跳转目标
	ErrWriteProtection          = errors.New("write protection")                          // 写保护
	ErrReturnDataOutOfBounds    = errors.New("return data out of bounds")                 // 返回数据超出范围
	ErrGasUintOverflow          = errors.New("gas uint64 overflow")                       // Gas uint64溢出
	ErrInvalidCode              = errors.New("invalid code: must not begin with 0xef")    // 无效代码：不得以0xef开头
	ErrNonceUintOverflow        = errors.New("nonce uint64 overflow")                     // Nonce uint64溢出

	// errStopToken is an internal token indicating interpreter loop termination,
	// never returned to outside callers.
	// errStopToken 是一个内部标记，表示解释器循环终止，永不返回给外部调用者。
	errStopToken = errors.New("stop token") // 停止标记
)

// ErrStackUnderflow wraps an evm error when the items on the stack less
// than the minimal requirement.
// ErrStackUnderflow 封装了一个EVM错误，当栈上的项少于最小要求时触发。
type ErrStackUnderflow struct { // 定义栈下溢错误结构体
	stackLen int // 当前栈长度
	required int // 所需最小栈长度
}

func (e ErrStackUnderflow) Error() string { // 返回栈下溢错误的字符串描述
	return fmt.Sprintf("stack underflow (%d <=> %d)", e.stackLen, e.required) // 格式化输出当前栈长度与所需长度的对比
}

func (e ErrStackUnderflow) Unwrap() error { // 解包底层错误
	return errors.New("stack underflow") // 返回基础栈下溢错误
}

// ErrStackOverflow wraps an evm error when the items on the stack exceeds
// the maximum allowance.
// ErrStackOverflow 封装了一个EVM错误，当栈上的项超过最大允许值时触发。
type ErrStackOverflow struct { // 定义栈溢出错误结构体
	stackLen int // 当前栈长度
	limit    int // 栈最大限制
}

func (e ErrStackOverflow) Error() string { // 返回栈溢出错误的字符串描述
	return fmt.Sprintf("stack limit reached %d (%d)", e.stackLen, e.limit) // 格式化输出当前栈长度与限制的对比
}

func (e ErrStackOverflow) Unwrap() error { // 解包底层错误
	return errors.New("stack overflow") // 返回基础栈溢出错误
}

// ErrInvalidOpCode wraps an evm error when an invalid opcode is encountered.
// ErrInvalidOpCode 封装了一个EVM错误，当遇到无效操作码时触发。
type ErrInvalidOpCode struct { // 定义无效操作码错误结构体
	opcode OpCode // 无效的操作码
}

func (e *ErrInvalidOpCode) Error() string { return fmt.Sprintf("invalid opcode: %s", e.opcode) } // 返回无效操作码的字符串描述，包含操作码名称

// rpcError is the same interface as the one defined in rpc/errors.go
// but we do not want to depend on rpc package here so we redefine it.
//
// It's used to ensure that the VMError implements the RPC error interface.
// rpcError 与 rpc/errors.go 中定义的接口相同，
// 但我们不想在这里依赖rpc包，因此重新定义它。
//
// 它用于确保 VMError 实现了 RPC 错误接口。
type rpcError interface { // 定义RPC错误接口
	Error() string  // returns the message 返回错误消息
	ErrorCode() int // returns the code // 返回错误代码
}

var _ rpcError = (*VMError)(nil) // 验证 VMError 实现了 rpcError 接口

// VMError wraps a VM error with an additional stable error code. The error
// field is the original error that caused the VM error and must be one of the
// VM error defined at the top of this file.
//
// If the error is not one of the known error above, the error code will be
// set to VMErrorCodeUnknown.
// VMError 封装了一个带有额外稳定错误代码的VM错误。错误字段是导致VM错误的原始错误，
// 必须是文件中顶部定义的VM错误之一。
//
// 如果错误不是上述已知错误之一，错误代码将被设置为 VMErrorCodeUnknown。
type VMError struct { // 定义VM错误结构体
	error     // 原始错误
	code  int // 错误代码
}

func VMErrorFromErr(err error) error { // 从错误创建VMError
	if err == nil { // 如果输入错误为空
		return nil // 返回nil
	}

	return &VMError{ // 返回新的VMError实例
		error: err,                     // 设置原始错误
		code:  vmErrorCodeFromErr(err), // 设置错误代码
	}
}

func (e *VMError) Error() string { // 返回错误字符串
	return e.error.Error() // 调用原始错误的Error方法
}

func (e *VMError) Unwrap() error { // 解包底层错误
	return e.error // 返回原始错误
}

func (e *VMError) ErrorCode() int { // 返回错误代码
	return e.code // 返回存储的错误代码
}

const ( // 定义错误代码常量
	// We start the error code at 1 so that we can use 0 later for some possible extension. There
	// is no unspecified value for the code today because it should always be set to a valid value
	// that could be VMErrorCodeUnknown if the error is not mapped to a known error code.
	// 我们从1开始定义错误代码，以便将来可以使用0进行扩展。目前代码没有未指定的值，
	// 因为它应始终设置为有效值，如果错误未映射到已知错误代码，则可能为 VMErrorCodeUnknown。

	VMErrorCodeOutOfGas                 = 1 + iota // Gas不足的错误代码
	VMErrorCodeCodeStoreOutOfGas                   // 合约创建代码存储Gas不足的错误代码
	VMErrorCodeDepth                               // 最大调用深度超出的错误代码
	VMErrorCodeInsufficientBalance                 // 转账余额不足的错误代码
	VMErrorCodeContractAddressCollision            // 合约地址冲突的错误代码
	VMErrorCodeExecutionReverted                   // 执行被回滚的错误代码
	VMErrorCodeMaxCodeSizeExceeded                 // 最大代码大小超出的错误代码
	VMErrorCodeInvalidJump                         // 无效跳转目标的错误代码
	VMErrorCodeWriteProtection                     // 写保护的错误代码
	VMErrorCodeReturnDataOutOfBounds               // 返回数据超出范围的错误代码
	VMErrorCodeGasUintOverflow                     // Gas uint64溢出的错误代码
	VMErrorCodeInvalidCode                         // 无效代码的错误代码
	VMErrorCodeNonceUintOverflow                   // Nonce uint64溢出的错误代码
	VMErrorCodeStackUnderflow                      // 栈下溢的错误代码
	VMErrorCodeStackOverflow                       // 栈溢出的错误代码
	VMErrorCodeInvalidOpCode                       // 无效操作码的错误代码

	// VMErrorCodeUnknown explicitly marks an error as unknown, this is useful when error is converted
	// from an actual `error` in which case if the mapping is not known, we can use this value to indicate that.
	// VMErrorCodeUnknown 明确标记错误为未知，当错误从实际的`error`转换而来且映射未知时，此值很有用。
	VMErrorCodeUnknown = math.MaxInt - 1 // 未知错误的错误代码
)

func vmErrorCodeFromErr(err error) int { // 从错误获取错误代码
	switch { // 根据错误类型匹配
	case errors.Is(err, ErrOutOfGas): // 如果是Gas不足
		return VMErrorCodeOutOfGas // 返回对应代码
	case errors.Is(err, ErrCodeStoreOutOfGas): // 如果是合约创建代码存储Gas不足
		return VMErrorCodeCodeStoreOutOfGas // 返回对应代码
	case errors.Is(err, ErrDepth): // 如果是最大调用深度超出
		return VMErrorCodeDepth // 返回对应代码
	case errors.Is(err, ErrInsufficientBalance): // 如果是转账余额不足
		return VMErrorCodeInsufficientBalance // 返回对应代码
	case errors.Is(err, ErrContractAddressCollision): // 如果是合约地址冲突
		return VMErrorCodeContractAddressCollision // 返回对应代码
	case errors.Is(err, ErrExecutionReverted): // 如果是执行被回滚
		return VMErrorCodeExecutionReverted // 返回对应代码
	case errors.Is(err, ErrMaxCodeSizeExceeded): // 如果是最大代码大小超出
		return VMErrorCodeMaxCodeSizeExceeded // 返回对应代码
	case errors.Is(err, ErrInvalidJump): // 如果是无效跳转目标
		return VMErrorCodeInvalidJump // 返回对应代码
	case errors.Is(err, ErrWriteProtection): // 如果是写保护
		return VMErrorCodeWriteProtection // 返回对应代码
	case errors.Is(err, ErrReturnDataOutOfBounds): // 如果是返回数据超出范围
		return VMErrorCodeReturnDataOutOfBounds // 返回对应代码
	case errors.Is(err, ErrGasUintOverflow): // 如果是Gas uint64溢出
		return VMErrorCodeGasUintOverflow // 返回对应代码
	case errors.Is(err, ErrInvalidCode): // 如果是无效代码
		return VMErrorCodeInvalidCode // 返回对应代码
	case errors.Is(err, ErrNonceUintOverflow): // 如果是Nonce uint64溢出
		return VMErrorCodeNonceUintOverflow // 返回对应代码

	default:
		// Dynamic errors
		// 默认情况，处理动态错误
		if v := (*ErrStackUnderflow)(nil); errors.As(err, &v) { // 如果是栈下溢
			return VMErrorCodeStackUnderflow // 返回对应代码
		}

		if v := (*ErrStackOverflow)(nil); errors.As(err, &v) { // 如果是栈溢出
			return VMErrorCodeStackOverflow // 返回对应代码
		}

		if v := (*ErrInvalidOpCode)(nil); errors.As(err, &v) { // 如果是无效操作码
			return VMErrorCodeInvalidOpCode // 返回对应代码
		}

		return VMErrorCodeUnknown // 未知错误，返回未知代码
	}
}
