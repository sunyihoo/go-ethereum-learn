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

package engine

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// EngineAPIError is a standardized error message between consensus and execution
// clients, also containing any custom error message Geth might include.
// EngineAPIError 是共识客户端和执行客户端之间的标准化错误消息，还包含 Geth 可能包含的任何自定义错误消息。
type EngineAPIError struct {
	code int    // 错误代码。
	msg  string // 错误消息。
	err  error  // 自定义错误（可选）。
}

func (e *EngineAPIError) ErrorCode() int { return e.code } // 返回错误代码。
func (e *EngineAPIError) Error() string  { return e.msg }  // 返回错误消息。
func (e *EngineAPIError) ErrorData() interface{} {
	if e.err == nil {
		return nil // 如果没有自定义错误，返回 nil。
	}
	return struct {
		Error string `json:"err"` // 自定义错误的 JSON 表示。
	}{e.err.Error()}
}

// With returns a copy of the error with a new embedded custom data field.
// With 返回一个带有新嵌入自定义数据字段的错误副本。
func (e *EngineAPIError) With(err error) *EngineAPIError {
	return &EngineAPIError{
		code: e.code,
		msg:  e.msg,
		err:  err,
	}
}

var (
	_ rpc.Error     = new(EngineAPIError) // 实现 rpc.Error 接口。
	_ rpc.DataError = new(EngineAPIError) // 实现 rpc.DataError 接口。
)

var (
	// VALID is returned by the engine API in the following calls:
	//   - newPayloadV1:       if the payload was already known or was just validated and executed
	//   - forkchoiceUpdateV1: if the chain accepted the reorg (might ignore if it's stale)
	// VALID 在以下引擎 API 调用中返回：
	//   - newPayloadV1:       如果负载已知或刚刚被验证并执行。
	//   - forkchoiceUpdateV1: 如果链接受了重组（如果过时可能会忽略）。
	VALID = "VALID"

	// INVALID is returned by the engine API in the following calls:
	//   - newPayloadV1:       if the payload failed to execute on top of the local chain
	//   - forkchoiceUpdateV1: if the new head is unknown, pre-merge, or reorg to it fails
	// INVALID 在以下引擎 API 调用中返回：
	//   - newPayloadV1:       如果负载在本地链上执行失败。
	//   - forkchoiceUpdateV1: 如果新头部未知、合并前或重组失败。
	INVALID = "INVALID"

	// SYNCING is returned by the engine API in the following calls:
	//   - newPayloadV1:       if the payload was accepted on top of an active sync
	//   - forkchoiceUpdateV1: if the new head was seen before, but not part of the chain
	// SYNCING 在以下引擎 API 调用中返回：
	//   - newPayloadV1:       如果负载在活动同步顶部被接受。
	//   - forkchoiceUpdateV1: 如果新头部之前见过，但不是链的一部分。
	SYNCING = "SYNCING"

	// ACCEPTED is returned by the engine API in the following calls:
	//   - newPayloadV1: if the payload was accepted, but not processed (side chain)
	// ACCEPTED 在以下引擎 API 调用中返回：
	//   - newPayloadV1: 如果负载被接受，但未处理（侧链）。
	ACCEPTED = "ACCEPTED"

	GenericServerError       = &EngineAPIError{code: -32000, msg: "Server error"}               // 通用服务器错误。
	UnknownPayload           = &EngineAPIError{code: -38001, msg: "Unknown payload"}            // 未知负载。
	InvalidForkChoiceState   = &EngineAPIError{code: -38002, msg: "Invalid forkchoice state"}   // 无效的分叉选择状态。
	InvalidPayloadAttributes = &EngineAPIError{code: -38003, msg: "Invalid payload attributes"} // 无效的负载属性。
	TooLargeRequest          = &EngineAPIError{code: -38004, msg: "Too large request"}          // 请求过大。
	InvalidParams            = &EngineAPIError{code: -32602, msg: "Invalid parameters"}         // 无效参数。
	UnsupportedFork          = &EngineAPIError{code: -38005, msg: "Unsupported fork"}           // 不支持的分叉。

	STATUS_INVALID         = ForkChoiceResponse{PayloadStatus: PayloadStatusV1{Status: INVALID}, PayloadID: nil} // 无效状态的叉选择响应。
	STATUS_SYNCING         = ForkChoiceResponse{PayloadStatus: PayloadStatusV1{Status: SYNCING}, PayloadID: nil} // 同步状态的叉选择响应。
	INVALID_TERMINAL_BLOCK = PayloadStatusV1{Status: INVALID, LatestValidHash: &common.Hash{}}                   // 无效终端区块状态。
)
