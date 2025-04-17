// Copyright 2024 The go-ethereum Authors
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

package pipes

import "net"

// 这段代码出现在 Go-Ethereum 的测试代码中（如 p2p 或 eth 包的测试文件），用于模拟网络连接。TCPPipe 创建一对本地 TCP 连接，模拟客户端和服务器之间的通信，适用于单元测试或集成测试。
//
// 以太坊相关知识点：
// DevP2P 协议：以太坊的 P2P 网络依赖 TCP（如 RLPx 协议）进行数据传输，测试需要模拟这种连接。
// 测试需求：在开发和调试中，模拟节点间的 TCP 通信是验证协议实现的关键。
// 本地化：使用 "127.0.0.1" 确保测试在单机环境下运行，避免外部干扰。

// TCP 使用：以太坊节点通过 TCP 端口（如默认 30303）进行 RLPx 通信，TCPPipe 模拟这种连接。
// 全双工：TCP 的双向通信特性与以太坊 P2P 数据交换需求一致。
// 测试场景：可用于测试节点握手、消息传递等功能。

// TCPPipe creates an in process full duplex pipe based on a localhost TCP socket.
// TCPPipe 创建一个基于本地 TCP 套接字的进程内全双工管道。
func TCPPipe() (net.Conn, net.Conn, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0") // 在本地监听 TCP，端口为 0（系统分配）
	if err != nil {
		return nil, nil, err // 如果监听失败则返回错误
	}
	defer l.Close() // 延迟关闭监听器

	var aconn net.Conn          // 接受的连接
	aerr := make(chan error, 1) // 接受错误的通道
	go func() {
		var err error
		aconn, err = l.Accept() // 接受连接
		aerr <- err             // 将接受结果发送到通道
	}()

	dconn, err := net.Dial("tcp", l.Addr().String()) // 拨号连接监听地址
	if err != nil {
		<-aerr               // 等待接受结果（清理通道）
		return nil, nil, err // 如果拨号失败则返回错误
	}
	if err := <-aerr; err != nil { // 检查接受是否出错
		dconn.Close()        // 如果出错则关闭拨号连接
		return nil, nil, err // 返回错误 / Return error
	}
	return aconn, dconn, nil // 返回接受和拨号连接
}
