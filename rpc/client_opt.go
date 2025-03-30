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

package rpc

import (
	"net/http"

	"github.com/gorilla/websocket"
)

// ClientOption is a configuration option for the RPC client.
// ClientOption 是 RPC 客户端的一个配置选项接口。
// 设计模式: 即“选项模式”或“函数式选项模式”，用于在创建或配置对象时提供灵活的配置方式。
type ClientOption interface {
	applyOption(*clientConfig)
}

type clientConfig struct {
	// HTTP settings
	// HTTP 设置
	httpClient  *http.Client // 用于发送 HTTP 请求的客户端
	httpHeaders http.Header  // 每个 HTTP 请求发送的自定义头部
	httpAuth    HTTPAuth     // 用于处理 HTTP 认证的函数

	// WebSocket options
	// WebSocket 选项
	wsDialer           *websocket.Dialer // 用于建立 WebSocket 连接的拨号器
	wsMessageSizeLimit *int64            // wsMessageSizeLimit nil = default, 0 = no limit  // WebSocket 消息大小限制，nil 表示默认，0 表示无限制

	// RPC handler options
	// RPC 处理程序选项
	idgen              func() ID // 用于生成 RPC 请求 ID 的函数
	batchItemLimit     int       // 批量 RPC 请求中允许的最大条目数
	batchResponseLimit int       // 批量 RPC 响应中允许的最大条目数
}

func (cfg *clientConfig) initHeaders() {
	if cfg.httpHeaders == nil {
		cfg.httpHeaders = make(http.Header)
	}
}

func (cfg *clientConfig) setHeader(key, value string) {
	cfg.initHeaders()
	cfg.httpHeaders.Set(key, value)
}

// 函数式选项模式： 这段代码是 Go 语言中实现“函数式选项模式”（Functional Options Pattern）的常见方式。
// 这种模式允许在创建或配置对象时，使用一系列可选的函数来设置配置项，而不是通过构造函数传递大量的可选参数。
type optionFunc func(*clientConfig)

func (fn optionFunc) applyOption(opt *clientConfig) {
	fn(opt)
}

// WithWebsocketDialer configures the websocket.Dialer used by the RPC client.
// WithWebsocketDialer 配置 RPC 客户端使用的 websocket.Dialer。
func WithWebsocketDialer(dialer websocket.Dialer) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.wsDialer = &dialer
	})
}

// WithWebsocketMessageSizeLimit configures the websocket message size limit used by the RPC
// client. Passing a limit of 0 means no limit.
// WithWebsocketMessageSizeLimit 配置 RPC 客户端使用的 websocket 消息大小限制。
// 传递 0 的限制表示没有限制。
func WithWebsocketMessageSizeLimit(messageSizeLimit int64) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.wsMessageSizeLimit = &messageSizeLimit
	})
}

// WithHeader configures HTTP headers set by the RPC client. Headers set using this option
// will be used for both HTTP and WebSocket connections.
// WithHeader 配置 RPC 客户端设置的 HTTP 头部。使用此选项设置的头部
// 将用于 HTTP 和 WebSocket 连接。
func WithHeader(key, value string) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.initHeaders() // 初始化 httpHeaders，如果尚未初始化
		cfg.httpHeaders.Set(key, value)
	})
}

// WithHeaders configures HTTP headers set by the RPC client. Headers set using this
// option will be used for both HTTP and WebSocket connections.
// WithHeaders 配置 RPC 客户端设置的 HTTP 头部。使用此选项设置的
// 头部将用于 HTTP 和 WebSocket 连接。
func WithHeaders(headers http.Header) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.initHeaders() // 初始化 httpHeaders，如果尚未初始化
		for k, vs := range headers {
			cfg.httpHeaders[k] = vs
		}
	})
}

// WithHTTPClient configures the http.Client used by the RPC client.
// WithHTTPClient 配置 RPC 客户端使用的 http.Client。
func WithHTTPClient(c *http.Client) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.httpClient = c
	})
}

// WithHTTPAuth configures HTTP request authentication. The given provider will be called
// whenever a request is made. Note that only one authentication provider can be active at
// any time.
// WithHTTPAuth 配置 HTTP 请求认证。给定的提供者将在每次发出请求时被调用。
// 注意，任何时候只能有一个认证提供者处于活动状态。
func WithHTTPAuth(a HTTPAuth) ClientOption {
	if a == nil {
		panic("nil auth") // 认证提供者不能为 nil
	}
	return optionFunc(func(cfg *clientConfig) {
		cfg.httpAuth = a
	})
}

// RPC 客户端认证： 在与以太坊节点进行交互时，某些节点可能需要客户端提供认证信息才能访问特定的 API 或执行某些操作。
// HTTP 头部认证： HTTP 头部是传递认证信息的一种常用方式。例如：
//  Basic Auth: 需要将用户名和密码进行 Base64 编码后放在 Authorization 头部，格式为 "Basic <base64_encoded_credentials>"。
//  Bearer Token: 需要将一个令牌（通常是 JWT）放在 Authorization 头部，格式为 "Bearer <token>"。
//  自定义头部： 有些节点可能使用自定义的头部字段进行认证，例如 X-API-Key: <your_api_key>。

// A HTTPAuth function is called by the client whenever a HTTP request is sent.
// The function must be safe for concurrent use.
//
// Usually, HTTPAuth functions will call h.Set("authorization", "...") to add
// auth information to the request.
//
// HTTPAuth 函数在客户端每次发送 HTTP 请求时被调用。
// 该函数必须是并发安全的。
//
// 通常，HTTPAuth 函数会调用 h.Set("authorization", "...") 来向请求添加认证信息。
type HTTPAuth func(h http.Header) error

// WithBatchItemLimit changes the maximum number of items allowed in batch requests.
//
// Note: this option applies when processing incoming batch requests. It does not affect
// batch requests sent by the client.
//
// WithBatchItemLimit 更改批量请求中允许的最大条目数。
//
// 注意：此选项适用于处理传入的批量请求。它不影响客户端发送的批量请求。
func WithBatchItemLimit(limit int) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.batchItemLimit = limit
	})
}

// WithBatchResponseSizeLimit changes the maximum number of response bytes that can be
// generated for batch requests. When this limit is reached, further calls in the batch
// will not be processed.
//
// Note: this option applies when processing incoming batch requests. It does not affect
// batch requests sent by the client.
//
// WithBatchResponseSizeLimit 更改可以为批量请求生成的最大响应字节数。
// 当达到此限制时，批处理中的后续调用将不会被处理。
//
// 注意：此选项适用于处理传入的批量请求。它不影响客户端发送的批量请求。
func WithBatchResponseSizeLimit(sizeLimit int) ClientOption {
	return optionFunc(func(cfg *clientConfig) {
		cfg.batchResponseLimit = sizeLimit
	})
}
