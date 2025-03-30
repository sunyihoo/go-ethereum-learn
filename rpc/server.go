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

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/log"
)

// 在以太坊的上下文中，"rpc" 通常指的是远程过程调用（Remote Procedure Call）的接口，
// 而 "engine" 可能与以太坊客户端（如 go-ethereum）的引擎 API 相关（例如在以太坊合并后引入的 Engine API，用于共识层和执行层的交互）。
// 自以太坊合并（The Merge）后，执行客户端（如 Geth）和共识客户端（如 Lighthouse）通过 Engine API 进行通信。
// Engine API 使用类似 RPC 的机制，支持方法调用和状态同步。这里的 EngineApi 常量可能用于标识这种接口。

const MetadataApi = "rpc"
const EngineApi = "engine"

// CodecOption specifies which type of messages a codec supports.
//
// Deprecated: this option is no longer honored by Server.
//
// CodecOption 指定了编解码器支持的消息类型。
//
// 已废弃：此选项在 Server 中不再被支持。
type CodecOption int

const (
	// OptionMethodInvocation is an indication that the codec supports RPC method calls
	// 表示编解码器支持 RPC 方法调用
	OptionMethodInvocation CodecOption = 1 << iota

	// OptionSubscriptions is an indication that the codec supports RPC notifications
	// 表示编解码器支持 RPC 通知
	OptionSubscriptions = 1 << iota // support pub sub  支持发布订阅
)

// EIP-1474：定义了以太坊的 RPC 接口规范，

// Server is an RPC server.
// Server 是一个 RPC 服务器。
type Server struct {
	services serviceRegistry // 存储和管理 RPC 服务，用于注册和查找不同的服务端点（如 eth_、web3_ 等命名空间）。
	idgen    func() ID       // 生成唯一的请求标识符，用于追踪 RPC 请求和响应的对应关系。

	mutex              sync.Mutex
	codecs             map[ServerCodec]struct{} // 跟踪当前活跃的编解码器实例，用于管理不同的客户端连接（如 JSON-RPC、WebSocket）。
	run                atomic.Bool              // 标记服务器是否正在运行，支持线程安全的读写。
	batchItemLimit     int                      // 限制批量请求中允许的最大条目数。
	batchResponseLimit int                      // 限制批量响应的最大条目数。
	httpBodyLimit      int                      // 限制 HTTP 请求体的最大字节数。
}

// NewServer creates a new server instance with no registered handlers.
// NewServer 创建一个没有注册处理程序的新服务器实例。
func NewServer() *Server {
	server := &Server{
		idgen:         randomIDGenerator(),
		codecs:        make(map[ServerCodec]struct{}),
		httpBodyLimit: defaultBodyLimit,
	}
	server.run.Store(true) // 将服务器的运行状态标记为 true，使用原子操作确保线程安全。
	// Register the default service providing meta information about the RPC service such
	// as the services and methods it offers.
	// 注册提供关于 RPC 服务的元信息的默认服务，例如它提供的服务和方法。
	rpcService := &RPCService{server}
	server.RegisterName(MetadataApi, rpcService) // 将 rpcService 注册到服务器的服务列表中，使用 MetadataApi（即 "rpc"）作为名称。
	return server
}

// SetBatchLimits sets limits applied to batch requests. There are two limits: 'itemLimit'
// is the maximum number of items in a batch. 'maxResponseSize' is the maximum number of
// response bytes across all requests in a batch.
//
// This method should be called before processing any requests via ServeCodec, ServeHTTP,
// ServeListener etc.
//
// SetBatchLimits 设置应用于批量请求的限制。有两个限制：“itemLimit”
// 是批量中项目的最大数量。“maxResponseSize”是批量中所有请求的响应字节的最大数量。
//
// 此方法应在通过 ServeCodec、ServeHTTP、ServeListener 等处理任何请求之前调用。
func (s *Server) SetBatchLimits(itemLimit, maxResponseSize int) {
	s.batchItemLimit = itemLimit
	s.batchResponseLimit = maxResponseSize
}

// SetHTTPBodyLimit sets the size limit for HTTP requests.
//
// This method should be called before processing any requests via ServeHTTP.
//
// SetHTTPBodyLimit 设置 HTTP 请求的大小限制。
//
// 此方法应在通过 ServeHTTP 处理任何请求之前调用。
func (s *Server) SetHTTPBodyLimit(limit int) {
	s.httpBodyLimit = limit
}

// RegisterName creates a service for the given receiver type under the given name. When no
// methods on the given receiver match the criteria to be either an RPC method or a
// subscription an error is returned. Otherwise a new service is created and added to the
// service collection this server provides to clients.
//
// RegisterName 为给定的接收者类型在给定名称下创建一个服务。当给定接收者上的方法
// 不符合作为 RPC 方法或订阅的条件时，将返回错误。否则，将创建一个新服务并添加到
// 此服务器提供给客户端的服务集合中。
func (s *Server) RegisterName(name string, receiver interface{}) error {
	return s.services.registerName(name, receiver)
}

// 编解码器（Codec）：在 go-ethereum 中，ServerCodec 表示一种通信协议的读写接口（如 JSON-RPC over HTTP、WebSocket 或 IPC）。ServeCodec 是处理单个连接的核心方法，适用于持久连接（如 WebSocket）。
// 阻塞行为：此方法阻塞直到连接关闭，适合 WebSocket 或 IPC 的长连接场景，而非 HTTP 的单次请求（后者由 serveSingleRequest 处理）。
// 订阅支持：与 HTTP 不同，ServeCodec 可支持订阅（如 eth_subscribe），因为它保持连接开放。

// ServeCodec reads incoming requests from codec, calls the appropriate callback and writes
// the response back using the given codec. It will block until the codec is closed or the
// server is stopped. In either case the codec is closed.
//
// Note that codec options are no longer supported.
//
// ServeCodec 从编解码器读取传入的请求，调用适当的回调并使用给定的编解码器写回响应。
// 它将阻塞，直到编解码器关闭或服务器停止。在任何情况下，编解码器都会被关闭。
//
// 注意，编解码器选项不再受支持。
//
// codec ServerCodec：编解码器实例，用于读写请求和响应。
// options CodecOption：编解码器选项（注释表明已废弃，未使用）。
//
// 从 codec 读取 RPC 请求，处理并返回响应，阻塞直到连接关闭或服务器停止。
func (s *Server) ServeCodec(codec ServerCodec, options CodecOption) {
	defer codec.close()

	if !s.trackCodec(codec) { // 调用 trackCodec 注册 codec，若失败（服务器已停止），直接返回。
		return
	}
	defer s.untrackCodec(codec) // 确保退出时移除 codec 的跟踪。

	cfg := &clientConfig{ // 初始化客户端配置，包括 ID 生成器和批量限制。
		idgen:              s.idgen,
		batchItemLimit:     s.batchItemLimit,
		batchResponseLimit: s.batchResponseLimit,
	}
	c := initClient(codec, &s.services, cfg)
	<-codec.closed() // 等待 codec 的关闭信号
	c.Close()        // 关闭客户端实例。
}

// 将指定的 codec 添加到 Server 的 codecs 映射中，用于跟踪活跃的编解码器实例，并返回是否成功。
//
// 在 go-ethereum 的 RPC 实现中，ServerCodec 可能表示一种通信协议的编解码器，例如 JSON-RPC over HTTP 或 WebSocket。
// trackCodec 用于注册新的客户端连接，确保服务器知道当前有哪些活跃连接。
func (s *Server) trackCodec(codec ServerCodec) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.run.Load() {
		return false // Don't serve if server is stopped. 不服务如果服务器已停止。
	}
	s.codecs[codec] = struct{}{}
	return true
}

// 从 Server 的 codecs 映射中移除指定的 codec，表示该连接已结束。
func (s *Server) untrackCodec(codec ServerCodec) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.codecs, codec)
}

// serveSingleRequest reads and processes a single RPC request from the given codec. This
// is used to serve HTTP connections. Subscriptions and reverse calls are not allowed in
// this mode.
// serveSingleRequest 从给定的编解码器读取并处理单个 RPC 请求。此方法用于服务 HTTP 连接。
// 在此模式下不允许订阅和反向调用。
//
// 在 go-ethereum 中，HTTP 是常见的 RPC 传输协议（如 Geth 的 --http 选项）。
// serveSingleRequest 专为 HTTP 设计，不支持订阅（订阅通常通过 WebSocket 实现，例如 eth_subscribe）。
func (s *Server) serveSingleRequest(ctx context.Context, codec ServerCodec) {
	// Don't serve if server is stopped.
	// 如果服务器已停止，则不提供服务。
	if !s.run.Load() {
		return
	}

	// 创建请求处理器，传入上下文、编解码器、ID 生成器、服务集合及批量限制参数。
	h := newHandler(ctx, codec, s.idgen, &s.services, s.batchItemLimit, s.batchResponseLimit)
	h.allowSubscribe = false   // 禁用订阅功能。
	defer h.close(io.EOF, nil) // 确保处理器在函数结束时关闭。

	reqs, batch, err := codec.readBatch() // 从 codec 读取请求，可能为批量请求。
	if err != nil {
		if msg := messageForReadError(err); msg != "" {
			resp := errorMessage(&invalidMessageError{msg})
			codec.writeJSON(ctx, resp, true)
		}
		return
	}
	// 若为批量请求，调用 h.handleBatch(reqs) 处理；否则，调用 h.handleMsg(reqs[0]) 处理单个请求。
	if batch {
		h.handleBatch(reqs)
	} else {
		h.handleMsg(reqs[0])
	}
}

// messageForReadError 根据读取错误返回相应的错误消息。
func messageForReadError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "read timeout"
		} else {
			return "read error"
		}
	} else if err != io.EOF {
		return "parse error"
	}
	return ""
}

// Stop stops reading new requests, waits for stopPendingRequestTimeout to allow pending
// requests to finish, then closes all codecs which will cancel pending requests and
// subscriptions.
//
// Stop 停止读取新请求，等待 stopPendingRequestTimeout 以允许未完成的请求完成，
// 然后关闭所有编解码器，这将取消未完成的请求和订阅。
func (s *Server) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 若当前值为 true，则改为 false 并返回 true；否则返回 false（表示已停止）。
	if s.run.CompareAndSwap(true, false) {
		log.Debug("RPC server shutting down")
		for codec := range s.codecs { // 遍历 codecs 映射中的所有编解码器。
			codec.close() // 关闭每个编解码器，取消其关联的请求和订阅。
		}
	}
}

// 元信息服务：在以太坊的 RPC 接口中，元信息服务（如 rpc_modules 方法）用于暴露服务器支持的功能模块。这在 go-ethereum 中常见，例如查询可用命名空间（如 eth、web3）。

// RPCService gives meta information about the server.
// e.g. gives information about the loaded modules.
// RPCService 提供关于服务器的元信息。
// 例如，提供关于加载模块的信息。
type RPCService struct {
	server *Server
}

// 模块查询：在 go-ethereum 中，rpc_modules 方法返回类似的结果，例如 {"eth": "1.0", "web3": "1.0", "net": "1.0"}。
// 这帮助客户端了解服务器支持的 API 集，例如 eth_getBlockByNumber（eth 模块）或 web3_clientVersion（web3 模块）。

// Modules returns the list of RPC services with their version number
// Modules 返回带有版本号的 RPC 服务列表
// 返回当前 RPC 服务器注册的所有服务（模块）及其版本号。
func (s *RPCService) Modules() map[string]string {
	s.server.services.mu.Lock()
	defer s.server.services.mu.Unlock()

	modules := make(map[string]string)
	for name := range s.server.services.services {
		modules[name] = "1.0"
	}
	return modules
}

// 连接协议：在 go-ethereum 中，RPC 服务支持多种协议：HTTP（--http）、WebSocket（--ws）和 IPC（进程间通信，--ipcpath）。Transport 字段反映了这些选项。
// 远程地址：RemoteAddr 可用于日志记录或安全检查，例如限制特定 IP 的访问（类似于 Geth 的 --http.vhosts）。
// HTTP 元数据：这些字段在以太坊节点的 HTTP 和 WebSocket 服务中非常有用。例如，UserAgent 可以识别客户端类型（如 MetaMask），Origin 用于跨域检查。

// PeerInfo contains information about the remote end of the network connection.
//
// This is available within RPC method handlers through the context. Call
// PeerInfoFromContext to get information about the client connection related to
// the current method call.
//
// PeerInfo 包含关于网络连接远程端的信息。
//
// 这在 RPC 方法处理程序中通过上下文可用。调用 PeerInfoFromContext 以获取与当前方法调用相关的客户端连接信息。
type PeerInfo struct {
	// Transport is name of the protocol used by the client.
	// This can be "http", "ws" or "ipc".
	// Transport 是客户端使用的协议名称。
	// 这可以是 "http"、"ws" 或 "ipc"。
	Transport string

	// Address of client. This will usually contain the IP address and port.
	// Address 是客户端的地址。这通常包含 IP 地址和端口。
	RemoteAddr string

	// Additional information for HTTP and WebSocket connections.
	// HTTP 和 WebSocket 连接的附加信息。
	HTTP struct {
		// Protocol version, i.e. "HTTP/1.1". This is not set for WebSocket.
		// 协议版本，例如 "HTTP/1.1"。这对 WebSocket 不设置。
		Version string
		// Header values sent by the client.
		// 客户端发送的头部值。
		UserAgent string // 客户端的用户代理字符串（如 "Geth/v1.10.0"）。
		Origin    string // HTTP 请求的来源头（如 "http://localhost"）
		Host      string // 请求的目标主机（如 "example.com"）。
	}
}

type peerInfoContextKey struct{}

// PeerInfoFromContext returns information about the client's network connection.
// Use this with the context passed to RPC method handler functions.
//
// The zero value is returned if no connection info is present in ctx.
//
// PeerInfoFromContext 返回关于客户端网络连接的信息。
// 将此与传递给 RPC 方法处理程序函数的上下文一起使用。
//
// 如果 ctx 中没有连接信息，则返回零值。
func PeerInfoFromContext(ctx context.Context) PeerInfo {
	info, _ := ctx.Value(peerInfoContextKey{}).(PeerInfo)
	return info
}
