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
	"context"
	"net/http"
)

type mdHeaderKey struct{}

// NewContextWithHeaders wraps the given context, adding HTTP headers. These headers will
// be applied by Client when making a request using the returned context.
//
// NewContextWithHeaders 包装给定的上下文，添加 HTTP 头。这些头将在客户端使用返回的上下文发起请求时应用。
func NewContextWithHeaders(ctx context.Context, h http.Header) context.Context {
	if len(h) == 0 {
		// This check ensures the header map set in context will never be nil.
		// 此检查确保设置在上下文中的头映射永远不会为 nil。
		return ctx
	}

	var ctxh http.Header
	prev, ok := ctx.Value(mdHeaderKey{}).(http.Header)
	if ok {
		ctxh = setHeaders(prev.Clone(), h)
	} else {
		ctxh = h.Clone()
	}
	return context.WithValue(ctx, mdHeaderKey{}, ctxh)
}

// headersFromContext is used to extract http.Header from context.
// headersFromContext 用于从上下文中提取 http.Header。
func headersFromContext(ctx context.Context) http.Header {
	source, _ := ctx.Value(mdHeaderKey{}).(http.Header)
	return source
}

// setHeaders sets all headers from src in dst.
// setHeaders 将 src 中的所有头设置到 dst 中。
func setHeaders(dst http.Header, src http.Header) http.Header {
	// http.CanonicalHeaderKey(key):
	// 将键转换为规范形式（首字母大写，例如 "user-agent" 变为 "User-Agent"）。
	// 这是 HTTP 标准的要求，确保一致性。
	for key, values := range src {
		dst[http.CanonicalHeaderKey(key)] = values
	}
	return dst
}
