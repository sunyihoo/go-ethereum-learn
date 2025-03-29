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

package rpc

import "fmt"

// 在与以太坊节点进行 HTTP RPC 调用时，如果请求失败（例如由于参数错误、节点内部错误等），节点通常会返回一个非 2xx 的 HTTP 状态码，并在响应体中包含错误信息。
// HTTPError 结构体可以用来捕获并表示这种错误情况，方便开发者进行错误处理和调试。

// HTTPError is returned by client operations when the HTTP status code of the
// response is not a 2xx status.
//
// HTTPError 由客户端操作在响应的 HTTP 状态码不是 2xx 状态时返回。
type HTTPError struct {
	StatusCode int    // 存储 HTTP 响应的状态码（例如 404, 500）。
	Status     string // 存储 HTTP 响应的状态文本描述（例如 "Not Found", "Internal Server Error"）。
	Body       []byte // 存储 HTTP 响应的响应体内容，通常是错误信息的详细说明。
}

func (err HTTPError) Error() string {
	if len(err.Body) == 0 {
		return err.Status
	}
	return fmt.Sprintf("%v: %s", err.Status, err.Body)
}

// Error wraps RPC errors, which contain an error code in addition to the message.
// Error 封装了 RPC 错误，这些错误除了消息之外还包含错误代码。
type Error interface {
	Error() string  // returns the message  返回错误消息
	ErrorCode() int // returns the code     返回错误代码
}

// 有些以太坊 RPC 错误除了错误代码和消息之外，还可能包含一些额外的数据，例如交易回执中的错误信息、合约执行失败的详细原因等。
// 定义 DataError 接口可以方便地获取和处理这些额外的数据。

// A DataError contains some data in addition to the error message.
// A DataError 除了错误消息之外还包含一些数据。
type DataError interface {
	Error() string          // returns the message     返回错误消息
	ErrorData() interface{} // returns the error data  返回错误数据
}

// Error types defined below are the built-in JSON-RPC errors.
// 下面定义的错误类型是内置的 JSON-RPC 错误。

var (
	_ Error = new(methodNotFoundError)
	_ Error = new(subscriptionNotFoundError)
	_ Error = new(parseError)
	_ Error = new(invalidRequestError)
	_ Error = new(invalidMessageError)
	_ Error = new(invalidParamsError)
	_ Error = new(internalServerError)
)

// 在 JSON-RPC 2.0 规范中，保留的服务器错误代码范围是从 -32768 到 -32000。

const (
	errcodeDefault          = -32000
	errcodeTimeout          = -32002 // 表示请求超时的错误代码。这通常发生在客户端等待服务器响应的时间超过了预设的阈值。
	errcodeResponseTooLarge = -32003 // 表示响应数据过大的错误代码。这可能发生在服务器返回的数据量超过了客户端能够或愿意处理的限制。
	errcodePanic            = -32603 // 表示服务器内部发生 panic 的错误代码。在 JSON-RPC 2.0 规范中，-32603 是保留用于 "Internal error" 的代码，通常表示服务器在处理请求时遇到了未知的或意外的错误。
	errcodeMarshalError     = -32603 // 表示数据序列化（marshal）错误的错误代码。这里它与 errcodePanic 的值相同，可能表示序列化错误被视为一种内部服务器错误。

	legacyErrcodeNotificationsUnsupported = -32001 // 表示服务器不支持通知（notifications）的错误代码。JSON-RPC 支持通知，这是一种不期望响应的请求。"legacy" 前缀可能意味着这个错误代码是为了兼容旧版本或特定的实现。
)

const (
	errMsgTimeout          = "request timed out"  // 表示请求已超时。
	errMsgResponseTooLarge = "response too large" // 表示响应数据过大。
	errMsgBatchTooLarge    = "batch too large"    // 表示批量请求过大的错误消息。JSON-RPC 允许将多个请求打包成一个批处理请求发送给服务器。这个错误表明批处理请求中的请求数量或总大小超过了服务器的限制。
)

// 当客户端尝试调用以太坊节点不支持的 JSON-RPC 方法时，节点会返回一个错误，其错误代码通常是 -32601。
type methodNotFoundError struct{ method string }

func (e *methodNotFoundError) ErrorCode() int { return -32601 }

func (e *methodNotFoundError) Error() string {
	return fmt.Sprintf("the method %s does not exist/is not available", e.method)
}

// 用于表示服务器不支持 JSON-RPC 通知（notifications）的错误。
type notificationsUnsupportedError struct{}

func (e notificationsUnsupportedError) Error() string {
	return "notifications not supported"
}

func (e notificationsUnsupportedError) ErrorCode() int { return -32601 }

// Is checks for equivalence to another error. Here we define that all errors with code
// -32601 (method not found) are equivalent to notificationsUnsupportedError. This is
// done to enable the following pattern:
//
//	sub, err := client.Subscribe(...)
//	if errors.Is(err, rpc.ErrNotificationsUnsupported) {
//		// server doesn't support subscriptions
//	}
//
// Is 检查是否与另一个错误等效。这里我们定义，所有错误代码为 -32601（方法未找到）的错误都等效于 notificationsUnsupportedError。这样做是为了启用以下模式：
//
//	sub, err := client.Subscribe(...)
//	if errors.Is(err, rpc.ErrNotificationsUnsupported) {
//	   // 服务器不支持订阅
//	}
func (e notificationsUnsupportedError) Is(other error) bool {
	if other == (notificationsUnsupportedError{}) {
		return true
	}
	rpcErr, ok := other.(Error)
	if ok {
		code := rpcErr.ErrorCode()
		return code == -32601 || code == legacyErrcodeNotificationsUnsupported
	}
	return false
}

type subscriptionNotFoundError struct{ namespace, subscription string }

func (e *subscriptionNotFoundError) ErrorCode() int { return -32601 }

func (e *subscriptionNotFoundError) Error() string {
	return fmt.Sprintf("no %q subscription in %s namespace", e.subscription, e.namespace)
}

// Invalid JSON was received by the server.
// 服务器接收到无效的 JSON。
type parseError struct{ message string }

func (e *parseError) ErrorCode() int { return -32700 }

func (e *parseError) Error() string { return e.message }

// received message isn't a valid request
// 接收到的消息不是一个有效的请求。
type invalidRequestError struct{ message string }

func (e *invalidRequestError) ErrorCode() int { return -32600 }

func (e *invalidRequestError) Error() string { return e.message }

// received message is invalid
// 接收到的消息无效。
type invalidMessageError struct{ message string }

func (e *invalidMessageError) ErrorCode() int { return -32700 }

func (e *invalidMessageError) Error() string { return e.message }

// unable to decode supplied params, or an invalid number of parameters
// 无法解码提供的参数，或者参数数量无效。
type invalidParamsError struct{ message string }

func (e *invalidParamsError) ErrorCode() int { return -32602 }

func (e *invalidParamsError) Error() string { return e.message }

// internalServerError is used for server errors during request processing.
// internalServerError 用于在请求处理期间发生的服务器错误。
type internalServerError struct {
	code    int
	message string
}

func (e *internalServerError) ErrorCode() int { return e.code }

func (e *internalServerError) Error() string { return e.message }
