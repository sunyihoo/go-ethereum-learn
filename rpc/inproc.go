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

package rpc

import (
	"context"
	"net"
)

// DialInProc 的核心目的是在同一个 Go 进程内部创建一个 RPC 客户端，并将其直接连接到一个同样在该进程内运行的 RPC 服务器实例 (handler)。
// 它绕过了操作系统网络堆栈（如 TCP/IP 或 IPC 文件），实现了一种轻量级、低延迟的进程内通信机制。这主要用于测试或高度集成的组件间通信。

// DialInProc attaches an in-process connection to the given RPC server.
// DialInProc 将一个进程内连接附加到给定的 RPC 服务器。
func DialInProc(handler *Server) *Client {
	initctx := context.Background()
	cfg := new(clientConfig) // 创建一个新的客户端配置（可能为空或默认）
	// 创建一个新的客户端，关键在于其内部的 "dialer" 函数
	c, _ := newClient(initctx, cfg, func(context.Context) (ServerCodec, error) {
		// net.Pipe() 创建一对内存中的、同步的、全双工的网络连接模拟器
		// p1 用于服务器端读取/写入，p2 用于客户端读取/写入
		p1, p2 := net.Pipe()
		// 启动一个 goroutine 来运行 RPC 服务器的处理逻辑
		// 服务器使用 p1 端并通过指定的编解码器（NewCodec）来处理请求
		go handler.ServeCodec(NewCodec(p1), 0)
		// dialer 函数返回 p2 端（包装在编解码器中）给 newClient 函数
		// 客户端将使用这个 p2 端来发送请求和接收响应
		return NewCodec(p2), nil
	})
	// 返回配置好的、连接到内存管道另一端的客户端实例
	return c
}
