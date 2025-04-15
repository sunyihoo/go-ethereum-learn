// Copyright 2023 The go-ethereum Authors
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

package discover

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// TALKREQ 和 TALKRESP 是 Discovery v5（EIP-1459）定义的应用层消息，用于节点间自定义通信。
// talkHandlerLaunchTimeout（400ms）确保处理启动时间短，配合注释中的 200ms 响应预期，防止远程超时。
// enode.ID 是 256 位节点标识符，通常由公钥生成。
//
// Discovery v5（EIP-1459）：
//  以太坊 P2P 网络的节点发现协议，基于 UDP，支持 TALKREQ 和 TALKRESP 消息。
//  TALKREQ 允许节点发送应用层请求，TALKRESP 返回响应，协议字段（req.Protocol）定义具体用途。
// UDP 通信：
//  UDPv5 使用无连接的 UDP 协议，适合快速、低开销的 P2P 通信。
// 节点标识（enode.ID）：
//  256 位哈希值，通常由 ECDSA 公钥生成，用于唯一标识网络中的节点。

// This is a limit for the number of concurrent talk requests.
// 这是并发 TALK 请求的数量限制。
const maxActiveTalkRequests = 1024

// This is the timeout for acquiring a handler execution slot for a talk request.
// The timeout should be short enough to fit within the request timeout.
// 这是为 TALK 请求获取处理程序执行槽的超时时间。
// 超时时间应足够短，以适应请求超时。
const talkHandlerLaunchTimeout = 400 * time.Millisecond

// TalkRequestHandler callback processes a talk request and returns a response.
//
// Note that talk handlers are expected to come up with a response very quickly, within at
// most 200ms or so. If the handler takes longer than that, the remote end may time out
// and wont receive the response.
//
// TalkRequestHandler 回调处理 TALK 请求并返回响应。
//
// 请注意，TALK 处理程序预期会非常快地生成响应，最多大约 200 毫秒。如果处理程序耗时超过此时间，
// 远程端可能会超时，无法接收响应。
type TalkRequestHandler func(enode.ID, *net.UDPAddr, []byte) []byte

type talkSystem struct {
	transport *UDPv5 // UDPv5 传输层实例

	mutex     sync.Mutex                    // 互斥锁，用于保护 handlers 映射
	handlers  map[string]TalkRequestHandler // 协议到处理程序的映射
	slots     chan struct{}                 // 并发控制槽通道
	lastLog   time.Time                     // 上次记录丢弃请求的时间
	dropCount int                           // 丢弃的请求计数
}

func newTalkSystem(transport *UDPv5) *talkSystem {
	t := &talkSystem{
		transport: transport,                                  // 初始化传输层
		handlers:  make(map[string]TalkRequestHandler),        // 初始化协议处理程序映射
		slots:     make(chan struct{}, maxActiveTalkRequests), // 初始化并发控制槽通道
	}
	for i := 0; i < cap(t.slots); i++ {
		t.slots <- struct{}{} // 填充所有槽
	}
	return t
}

// register adds a protocol handler.
// register 添加一个协议处理程序。
func (t *talkSystem) register(protocol string, handler TalkRequestHandler) {
	t.mutex.Lock()                 // 加锁
	t.handlers[protocol] = handler // 注册协议和处理程序
	t.mutex.Unlock()               // 解锁
}

// handleRequest handles a talk request.
// handleRequest 处理一个 TALK 请求。
//
// 实现以太坊 Discovery v5 协议中 TALKREQ 消息的处理系统，支持动态注册协议处理程序，并通过并发控制和超时机制确保稳定性。
func (t *talkSystem) handleRequest(id enode.ID, addr netip.AddrPort, req *v5wire.TalkRequest) {
	t.mutex.Lock()                          // 加锁
	handler, ok := t.handlers[req.Protocol] // 查找协议对应的处理程序
	t.mutex.Unlock()                        // 解锁

	if !ok { // 如果没有找到处理程序
		resp := &v5wire.TalkResponse{ReqID: req.ReqID} // 创建空响应
		t.transport.sendResponse(id, addr, resp)       // 发送空响应
		return
	}

	// Wait for a slot to become available, then run the handler.
	// 等待一个槽变得可用，然后运行处理程序。
	timeout := time.NewTimer(talkHandlerLaunchTimeout) // 创建超时定时器
	defer timeout.Stop()                               // 延迟停止定时器
	select {
	case <-t.slots: // 获取到一个槽
		go func() { // 启动 goroutine 处理请求
			defer func() { t.slots <- struct{}{} }()                                   // 确保槽被归还
			udpAddr := &net.UDPAddr{IP: addr.Addr().AsSlice(), Port: int(addr.Port())} // 转换地址格式
			respMessage := handler(id, udpAddr, req.Message)                           // 调用处理程序生成响应
			resp := &v5wire.TalkResponse{ReqID: req.ReqID, Message: respMessage}       // 构造响应
			t.transport.sendFromAnotherThread(id, addr, resp)                          // 发送响应
		}()
	case <-timeout.C: // 超时未获取槽
		// Couldn't get it in time, drop the request.
		// 未能在时间内获取，丢弃请求。
		if time.Since(t.lastLog) > 5*time.Second { // 每 5 秒记录一次丢弃日志
			log.Warn("Dropping TALKREQ due to overload", "ndrop", t.dropCount) // 记录警告日志
			t.lastLog = time.Now()                                             // 更新上次日志时间
			t.dropCount++                                                      // 增加丢弃计数
		}
	case <-t.transport.closeCtx.Done(): // 传输层关闭
		// Transport closed, drop the request.
		// 传输层关闭，丢弃请求。
	}
}

// wait blocks until all active requests have finished, and prevents new request
// handlers from being launched.
//
// wait 阻塞直到所有活动请求完成，并阻止新的请求处理程序启动。
func (t *talkSystem) wait() {
	for i := 0; i < cap(t.slots); i++ {
		<-t.slots // 等待所有槽被归还
	}
}
