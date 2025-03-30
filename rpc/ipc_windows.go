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

//go:build windows
// +build windows

package rpc

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// This is used if the dialing context has no deadline. It is much smaller than the
// defaultDialTimeout because named pipes are local and there is no need to wait so long.
//
// defaultPipeDialTimeout 如果拨号上下文没有设置截止日期，则使用此常量。
// 它比默认的网络拨号超时（未显示）要小得多，因为命名管道是本地通信，预期响应更快。
const defaultPipeDialTimeout = 2 * time.Second

// ipcListen will create a named pipe on the given endpoint.
//
// ipcListen 在指定的端点（路径）创建一个 Windows 命名管道监听器。
// endpoint 参数通常是 "\\.\pipe\some-name" 的格式。
func ipcListen(endpoint string) (net.Listener, error) {
	return winio.ListenPipe(endpoint, nil)
}

// IPC (Inter-Process Communication): 这是以太坊节点（如 Geth）提供的一种主要的通信接口，与 HTTP 和 WebSocket 并列。IPC 允许运行在同一台机器上的其他应用程序直接与节点通信。
// IPC Endpoint: Geth 节点在启动时可以配置一个 IPC 端点。在 Windows 上，这个端点就是一个命名管道的路径 (e.g., \\.\pipe\geth.ipc)；
// 在 Linux/macOS 上，它通常是一个 Unix Domain Socket 文件 (e.g., /path/to/data/geth.ipc)。这些代码片段是处理 Windows 上 IPC 端点的具体实现。
// 使用场景:
// Geth 节点: Geth 在 Windows 上运行时，会使用类似 ipcListen 的逻辑来创建和监听其 IPC 命名管道，以便接受来自本地客户端的连接。
// 客户端工具: 像 geth attach 这样的命令行工具，或者用 Go 编写的需要与本地 Geth 节点交互的 DApp 后端或脚本，会使用类似 newIPCConnection 的逻辑来连接到 Geth 的 IPC 命名管道，然后通过这个连接发送 JSON-RPC 请求。

// newIPCConnection will connect to a named pipe with the given endpoint as name.
//
// newIPCConnection 尝试连接到一个已存在的 Windows 命名管道。
// endpoint 是目标管道的名称。
// ctx 用于传递取消信号和超时控制。
func newIPCConnection(ctx context.Context, endpoint string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultPipeDialTimeout)
	defer cancel()
	return winio.DialPipeContext(ctx, endpoint)
}
