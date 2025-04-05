// Copyright 2024 The go-ethereum Authors
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

package ethapi

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
)

// revertError is an API error that encompasses an EVM revert with JSON error
// code and a binary data blob.
// revertError 是一个 API 错误，包含 EVM 回退的 JSON 错误代码和二进制数据块。
type revertError struct {
	error
	reason string // revert reason hex encoded 回退原因的十六进制编码
}

// ErrorCode returns the JSON error code for a revert.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
// ErrorCode 返回回退的 JSON 错误代码。
func (e *revertError) ErrorCode() int {
	return 3 // 根据 JSON-RPC 错误代码提案，返回错误代码 3。
}

// ErrorData returns the hex encoded revert reason.
// ErrorData 返回十六进制编码的回退原因。
func (e *revertError) ErrorData() interface{} {
	return e.reason // 返回回退原因的十六进制字符串。
}

// newRevertError creates a revertError instance with the provided revert data.
// newRevertError 使用提供的回退数据创建一个 revertError 实例。
func newRevertError(revert []byte) *revertError {
	err := vm.ErrExecutionReverted // 默认错误为执行回退。

	reason, errUnpack := abi.UnpackRevert(revert) // 尝试解码回退原因。
	if errUnpack == nil {
		err = fmt.Errorf("%w: %v", vm.ErrExecutionReverted, reason) // 如果解码成功，将原因附加到错误信息中。
	}
	return &revertError{
		error:  err,
		reason: hexutil.Encode(revert), // 将回退数据编码为十六进制字符串。
	}
}

// TxIndexingError is an API error that indicates the transaction indexing is not
// fully finished yet with JSON error code and a binary data blob.
// TxIndexingError 是一个 API 错误，表示交易索引尚未完全完成，并附带 JSON 错误代码和二进制数据块。
type TxIndexingError struct{}

// NewTxIndexingError creates a TxIndexingError instance.
// NewTxIndexingError 创建一个 TxIndexingError 实例。
func NewTxIndexingError() *TxIndexingError { return &TxIndexingError{} }

// Error implement error interface, returning the error message.
// Error 实现 error 接口，返回错误消息。
func (e *TxIndexingError) Error() string {
	return "transaction indexing is in progress" // 返回错误消息，表示交易索引正在进行中。
}

// ErrorCode returns the JSON error code for a revert.
// See: https://github.com/ethereum/wiki/wiki/JSON-RPC-Error-Codes-Improvement-Proposal
// ErrorCode 返回回退的 JSON 错误代码。
func (e *TxIndexingError) ErrorCode() int {
	return -32000 // 返回错误代码 -32000（待定）。
}

// ErrorData returns the hex encoded revert reason.
// ErrorData 返回十六进制编码的回退原因。
func (e *TxIndexingError) ErrorData() interface{} { return "transaction indexing is in progress" }

type callError struct {
	Message string `json:"message"`        // 错误消息
	Code    int    `json:"code"`           // 错误代码
	Data    string `json:"data,omitempty"` // 可选的附加数据
}

type invalidTxError struct {
	Message string `json:"message"` // 错误消息
	Code    int    `json:"code"`    // 错误代码
}

func (e *invalidTxError) Error() string  { return e.Message } // 返回错误消息。
func (e *invalidTxError) ErrorCode() int { return e.Code }    // 返回错误代码。

const (
	errCodeNonceTooHigh            = -38011 // 随机数过高错误代码
	errCodeNonceTooLow             = -38010 // 随机数过低错误代码
	errCodeIntrinsicGas            = -38013 // 内在 Gas 不足错误代码
	errCodeInsufficientFunds       = -38014 // 资金不足错误代码
	errCodeBlockGasLimitReached    = -38015 // 区块 Gas 上限已达到错误代码
	errCodeBlockNumberInvalid      = -38020 // 区块号无效错误代码
	errCodeBlockTimestampInvalid   = -38021 // 区块时间戳无效错误代码
	errCodeSenderIsNotEOA          = -38024 // 发送者不是外部账户错误代码
	errCodeMaxInitCodeSizeExceeded = -38025 // 初始化代码大小超出限制错误代码
	errCodeClientLimitExceeded     = -38026 // 客户端限制超出错误代码
	errCodeInternalError           = -32603 // 内部错误代码
	errCodeInvalidParams           = -32602 // 参数无效错误代码
	errCodeReverted                = -32000 // 回退错误代码
	errCodeVMError                 = -32015 // 虚拟机错误代码
)

// txValidationError maps Ethereum core errors to JSON-RPC invalid transaction errors.
// txValidationError 将 Ethereum 核心错误映射到 JSON-RPC 无效交易错误。
func txValidationError(err error) *invalidTxError {
	if err == nil {
		return nil // 如果没有错误，返回 nil。
	}
	switch {
	case errors.Is(err, core.ErrNonceTooHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeNonceTooHigh} // 随机数过高错误。
	case errors.Is(err, core.ErrNonceTooLow):
		return &invalidTxError{Message: err.Error(), Code: errCodeNonceTooLow} // 随机数过低错误。
	case errors.Is(err, core.ErrSenderNoEOA):
		return &invalidTxError{Message: err.Error(), Code: errCodeSenderIsNotEOA} // 发送者不是外部账户错误。
	case errors.Is(err, core.ErrFeeCapVeryHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams} // Gas 费用上限过高错误。
	case errors.Is(err, core.ErrTipVeryHigh):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams} // 小费过高错误。
	case errors.Is(err, core.ErrTipAboveFeeCap):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams} // 小费超过费用上限错误。
	case errors.Is(err, core.ErrFeeCapTooLow):
		return &invalidTxError{Message: err.Error(), Code: errCodeInvalidParams} // 费用上限过低错误。
	case errors.Is(err, core.ErrInsufficientFunds):
		return &invalidTxError{Message: err.Error(), Code: errCodeInsufficientFunds} // 资金不足错误。
	case errors.Is(err, core.ErrIntrinsicGas):
		return &invalidTxError{Message: err.Error(), Code: errCodeIntrinsicGas} // 内在 Gas 不足错误。
	case errors.Is(err, core.ErrInsufficientFundsForTransfer):
		return &invalidTxError{Message: err.Error(), Code: errCodeInsufficientFunds} // 转账资金不足错误。
	case errors.Is(err, core.ErrMaxInitCodeSizeExceeded):
		return &invalidTxError{Message: err.Error(), Code: errCodeMaxInitCodeSizeExceeded} // 初始化代码大小超出限制错误。
	}
	return &invalidTxError{
		Message: err.Error(),
		Code:    errCodeInternalError, // 默认返回内部错误。
	}
}

type invalidParamsError struct{ message string }

func (e *invalidParamsError) Error() string  { return e.message }            // 返回错误消息。
func (e *invalidParamsError) ErrorCode() int { return errCodeInvalidParams } // 返回参数无效错误代码。

type clientLimitExceededError struct{ message string }

func (e *clientLimitExceededError) Error() string  { return e.message }                  // 返回错误消息。
func (e *clientLimitExceededError) ErrorCode() int { return errCodeClientLimitExceeded } // 返回客户端限制超出错误代码。

type invalidBlockNumberError struct{ message string }

func (e *invalidBlockNumberError) Error() string  { return e.message }                 // 返回错误消息。
func (e *invalidBlockNumberError) ErrorCode() int { return errCodeBlockNumberInvalid } // 返回区块号无效错误代码。

type invalidBlockTimestampError struct{ message string }

func (e *invalidBlockTimestampError) Error() string  { return e.message }                    // 返回错误消息。
func (e *invalidBlockTimestampError) ErrorCode() int { return errCodeBlockTimestampInvalid } // 返回区块时间戳无效错误代码。

type blockGasLimitReachedError struct{ message string }

func (e *blockGasLimitReachedError) Error() string  { return e.message }                   // 返回错误消息。
func (e *blockGasLimitReachedError) ErrorCode() int { return errCodeBlockGasLimitReached } // 返回区块 Gas 上限已达到错误代码。
