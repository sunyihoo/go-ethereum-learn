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

//go:build windows
// +build windows

package netutil

import (
	"net"
	"os"
	"syscall"
)

// UDP 在以太坊中的应用：以太坊的节点发现协议（Discovery v4/v5，基于 EIP-778）使用 UDP 传输数据包。UDP 数据包大小通常受限于 MTU（最大传输单元，约 1280 字节），超过缓冲区大小会导致类似错误。

const _WSAEMSGSIZE = syscall.Errno(10040) // 定义 Windows 系统调用错误码 WSAEMSGSIZE，表示数据包过大
// "WSAEMSGSIZE" 是 Windows 系统中表示“消息过大”的错误码

// isPacketTooBig reports whether err indicates that a UDP packet didn't
// fit the receive buffer. On Windows, WSARecvFrom returns
// code WSAEMSGSIZE and no data if this happens.
// isPacketTooBig 报告错误 err 是否表示 UDP 数据包不适合接收缓冲区。
// 在 Windows 上，如果发生这种情况，WSARecvFrom 会返回错误码 WSAEMSGSIZE 且无数据。
func isPacketTooBig(err error) bool {
	if opErr, ok := err.(*net.OpError); ok { // 检查错误是否为网络操作错误
		if scErr, ok := opErr.Err.(*os.SyscallError); ok { // 检查网络操作错误的底层是否为系统调用错误
			return scErr.Err == _WSAEMSGSIZE // 如果系统调用错误是 WSAEMSGSIZE，返回 true
		}
		return opErr.Err == _WSAEMSGSIZE // 如果网络操作错误直接是 WSAEMSGSIZE，返回 true
	}
	return false // 如果不是上述情况，返回 false
}
