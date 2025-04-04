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

package netutil

// 在以太坊的 P2P 网络中，临时错误（如网络拥塞、连接中断）是常见的，客户端（如 go-ethereum）需要区分临时错误和永久错误以决定是否重试。
//
// isPacketTooBig  UDP 数据包大小限制相关。以太坊的节点发现协议（Discovery v4/v5）使用 UDP，数据包大小通常受限于 MTU（最大传输单元，约 1280 字节）。

// IsTemporaryError checks whether the given error should be considered temporary.
// IsTemporaryError 检查给定的错误是否应视为临时的。
func IsTemporaryError(err error) bool {
	tempErr, ok := err.(interface {
		Temporary() bool
	})
	return ok && tempErr.Temporary() || isPacketTooBig(err)
}

// IsTimeout checks whether the given error is a timeout.
// IsTimeout 检查给定的错误是否是超时。
func IsTimeout(err error) bool {
	timeoutErr, ok := err.(interface {
		Timeout() bool
	})
	return ok && timeoutErr.Timeout()
}
