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

package p2p

import (
	"errors"
	"fmt"
)

const (
	errInvalidMsgCode = iota // Define error codes starting from 0
	errInvalidMsg            // 定义从0开始的错误代码
)

var errorToString = map[int]string{
	errInvalidMsgCode: "invalid message code", // 无效的消息代码
	errInvalidMsg:     "invalid message",      // 无效的消息
}

type peerError struct {
	code    int    // Error code / 错误代码
	message string // Error message / 错误信息
}

func newPeerError(code int, format string, v ...interface{}) *peerError {
	// Look up the error description from the map
	// 从映射中查找错误描述
	desc, ok := errorToString[code]
	if !ok {
		panic("invalid error code") // 如果错误代码无效，则抛出panic
	}
	err := &peerError{code, desc} // Create a new peerError instance
	if format != "" {
		// Append formatted message if provided
		// 如果提供了格式化字符串，则追加格式化消息
		err.message += ": " + fmt.Sprintf(format, v...)
	}
	return err
}

func (pe *peerError) Error() string {
	return pe.message //返回错误信息
}

var errProtocolReturned = errors.New("protocol returned") //定义协议返回错误

type DiscReason uint8 // 定义一个用于断开原因的类型

const (
	DiscRequested           DiscReason         = iota // 请求断开
	DiscNetworkError                                  // 网络错误
	DiscProtocolError                                 // 协议违反
	DiscUselessPeer                                   // 无用对等节点
	DiscTooManyPeers                                  // 过多对等节点
	DiscAlreadyConnected                              // 已连接
	DiscIncompatibleVersion                           // 版本不兼容
	DiscInvalidIdentity                               // 无效身份
	DiscQuitting                                      // 客户端退出
	DiscUnexpectedIdentity                            // 意外身份
	DiscSelf                                          // 连接到自身
	DiscReadTimeout                                   // 读取超时
	DiscSubprotocolError    = DiscReason(0x10)        // 子协议错误

	DiscInvalid = 0xff // 无效断开原因
)

var discReasonToString = [...]string{
	DiscRequested:           "disconnect requested",              // 请求断开
	DiscNetworkError:        "network error",                     // 网络错误
	DiscProtocolError:       "breach of protocol",                // 协议违反
	DiscUselessPeer:         "useless peer",                      // 无用对等节点
	DiscTooManyPeers:        "too many peers",                    // 过多对等节点
	DiscAlreadyConnected:    "already connected",                 // 已连接
	DiscIncompatibleVersion: "incompatible p2p protocol version", // 版本不兼容
	DiscInvalidIdentity:     "invalid node identity",             // 无效节点身份
	DiscQuitting:            "client quitting",                   // 客户端退出
	DiscUnexpectedIdentity:  "unexpected identity",               // 意外身份
	DiscSelf:                "connected to self",                 // 连接到自身
	DiscReadTimeout:         "read timeout",                      // 读取超时
	DiscSubprotocolError:    "subprotocol error",                 // 子协议错误
	DiscInvalid:             "invalid disconnect reason",         // 无效断开原因
}

// 返回断开原因的字符串表示
func (d DiscReason) String() string {
	if len(discReasonToString) <= int(d) || discReasonToString[d] == "" {
		return fmt.Sprintf("unknown disconnect reason %d", d) //未知原因
	}
	return discReasonToString[d]
}

// 将断开原因作为错误返回
func (d DiscReason) Error() string {
	return d.String()
}

// 将错误映射到断开原因
func discReasonForError(err error) DiscReason {
	if reason, ok := err.(DiscReason); ok {
		return reason // 直接的DiscReason类型
	}
	if errors.Is(err, errProtocolReturned) {
		return DiscQuitting // 协议返回映射到退出
	}
	peerError, ok := err.(*peerError)
	if ok {
		switch peerError.code {
		case errInvalidMsgCode, errInvalidMsg:
			return DiscProtocolError // 无效消息错误映射到协议错误
		default:
			return DiscSubprotocolError // 默认到子协议错误
		}
	}
	return DiscSubprotocolError // 回退到子协议错误
}
