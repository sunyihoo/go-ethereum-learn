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

//go:build darwin || dragonfly || freebsd || linux || nacl || netbsd || openbsd || solaris
// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris

package rpc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ethereum/go-ethereum/log"
)

const (
	// The limit of unix domain socket path diverse between OS, on Darwin it's 104 bytes
	// but on Linux it's 108 byte, so we should depend on syscall.RawSockaddrUnix's
	// definition dynamically
	// Unix 域套接字路径的限制因操作系统而异，在 Darwin (macOS) 上是 104 字节，
	// 但在 Linux 上是 108 字节，因此我们应该动态地依赖 syscall.RawSockaddrUnix 的定义。
	// len(syscall.RawSockaddrUnix{}.Path) 会在编译时根据目标操作系统获取正确的大小。
	maxPathSize = len(syscall.RawSockaddrUnix{}.Path)
)

// ipcListen will create a Unix socket on the given endpoint.
// ipcListen 在给定的文件系统路径（endpoint）创建一个 Unix 域套接字监听器。
func ipcListen(endpoint string) (net.Listener, error) {
	// account for null-terminator too
	// 检查路径长度是否可能超出系统限制（考虑到可能需要的空终止符）。
	if len(endpoint)+1 > maxPathSize {
		log.Warn(fmt.Sprintf("The ipc endpoint is longer than %d characters. ", maxPathSize-1),
			"endpoint", endpoint)
	}

	// Ensure the IPC path exists and remove any previous leftover
	// 确保 IPC 端点所在的目录存在。
	if err := os.MkdirAll(filepath.Dir(endpoint), 0751); err != nil {
		return nil, err
	}
	// 在监听之前，尝试移除任何可能残留的旧套接字文件。
	// 如果服务器上次未正常关闭，可能会留下这个文件，导致 Listen 失败。
	os.Remove(endpoint)
	// 使用 "unix" 网络类型在指定的文件路径上创建监听器。
	l, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, err
	}
	// 设置套接字文件的权限为 0600 (所有者可读写，其他用户无权限)。
	// 这是重要的安全措施，限制了谁可以连接到这个 IPC 端点。
	os.Chmod(endpoint, 0600)
	return l, nil
}

// IPC (Inter-Process Communication): 如前所述，是以太坊节点提供的一种本地通信接口。此代码片段展示了在类 Unix 系统（Linux, macOS）上的实现方式。
// IPC Endpoint (Unix): 在这些系统上，以太坊节点（如 Geth）的 IPC 端点是一个文件系统中的Unix Domain Socket 文件 (例如, ~/.ethereum/geth.ipc 或 Geth 数据目录下的 geth.ipc)。
// endpoint 参数就是这个文件的路径。

// newIPCConnection will connect to a Unix socket on the given endpoint.
// newIPCConnection 尝试连接到一个已存在的 Unix 域套接字。
// endpoint 是目标套接字的文件系统路径。
// ctx 用于传递取消信号和超时控制（通过 DialContext）。
func newIPCConnection(ctx context.Context, endpoint string) (net.Conn, error) {
	// 使用 DialContext 方法尝试连接。
	// "unix" 指定了网络类型。
	// endpoint 是目标套接字文件的路径。
	// ctx 允许调用者控制连接的超时或取消。
	return new(net.Dialer).DialContext(ctx, "unix", endpoint)
}
