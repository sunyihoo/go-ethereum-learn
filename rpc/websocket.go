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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/websocket"
)

// 以太坊客户端（如 Geth、Parity/OpenEthereum）通常支持通过 WebSocket 连接提供实时事件订阅功能（例如，新的区块头、待处理的交易等）。
// WebSocket 协议定义了 Ping 和 Pong 帧，用于检测连接的活跃性。服务器或客户端可以定期发送 Ping 消息，对方应回复 Pong 消息。
// 为了保持与以太坊节点的 WebSocket 连接的活跃性，客户端或节点可能会定期发送 Ping 消息。
// 如果在发送 Ping 消息后，客户端在 30 秒内没有收到以太坊节点的 Pong 响应，客户端可能会认为连接已失效，并尝试重新连接。
// 在以太坊客户端（如 Geth、Parity/OpenEthereum）中，WebSocket 连接通常用于实时推送数据，例如新的区块头、交易状态更新、合约事件等。

const (
	wsReadBuffer       = 1024             // WebSocket 读取缓冲区大小（字节）
	wsWriteBuffer      = 1024             // WebSocket 写入缓冲区大小（字节）
	wsPingInterval     = 30 * time.Second // WebSocket Ping 消息发送间隔（秒）
	wsPingWriteTimeout = 5 * time.Second  // WebSocket Ping 消息写入超时时间（秒）
	wsPongTimeout      = 30 * time.Second // WebSocket Pong 消息接收超时时间（秒）
	wsDefaultReadLimit = 32 * 1024 * 1024 // WebSocket 默认读取限制（字节）默认读取限制为 32 MB,这是一个安全措施，用于防止接收过大的消息导致内存溢出或拒绝服务攻击。
)

var wsBufferPool = new(sync.Pool) // 定义一个 WebSocket 缓冲区池

// WebsocketHandler returns a handler that serves JSON-RPC to WebSocket connections.
//
// allowedOrigins should be a comma-separated list of allowed origin URLs.
// To allow connections with any origin, pass "*".
func (s *Server) WebsocketHandler(allowedOrigins []string) http.Handler {
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  wsReadBuffer,
		WriteBufferSize: wsWriteBuffer,
		WriteBufferPool: wsBufferPool,
		CheckOrigin:     wsHandshakeValidator(allowedOrigins),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Debug("WebSocket upgrade failed", "err", err)
			return
		}
		codec := newWebsocketCodec(conn, r.Host, r.Header, wsDefaultReadLimit)
		s.ServeCodec(codec, 0)
	})
}

// wsHandshakeValidator returns a handler that verifies the origin during the
// websocket upgrade process. When a '*' is specified as an allowed origins all
// connections are accepted.
//
// wsHandshakeValidator 返回一个处理函数，该函数在 WebSocket 升级过程中验证来源（Origin）。
// 当允许的来源中指定了 '*' 时，所有连接都将被接受。
func wsHandshakeValidator(allowedOrigins []string) func(*http.Request) bool {
	origins := mapset.NewSet[string]()
	allowAllOrigins := false // 标记是否允许所有来源

	for _, origin := range allowedOrigins {
		if origin == "*" {
			allowAllOrigins = true // 如果来源是 "*"，则允许所有来源
		}
		if origin != "" {
			origins.Add(origin) // 将非空且非 "*" 的来源添加到集合中
		}
	}
	// allow localhost if no allowedOrigins are specified.
	// 如果没有指定允许的来源，则允许 localhost。
	if len(origins.ToSlice()) == 0 {
		origins.Add("http://localhost")
		if hostname, err := os.Hostname(); err == nil {
			origins.Add("http://" + hostname) // 如果能获取到主机名，则添加主机名作为来源
		}
	}
	log.Debug(fmt.Sprintf("Allowed origin(s) for WS RPC interface %v", origins.ToSlice()))

	f := func(req *http.Request) bool {
		// Skip origin verification if no Origin header is present. The origin check
		// is supposed to protect against browser based attacks. Browsers always set
		// Origin. Non-browser software can put anything in origin and checking it doesn't
		// provide additional security.
		// 如果不存在 Origin 头部，则跳过来源验证。来源检查旨在防止基于浏览器的攻击。
		// 浏览器总是设置 Origin。非浏览器软件可以在 Origin 中放置任何内容，检查它并不能提供额外的安全性。
		if _, ok := req.Header["Origin"]; !ok {
			return true
		}
		// Verify origin against allow list.
		// 根据允许列表验证来源。
		origin := strings.ToLower(req.Header.Get("Origin"))
		if allowAllOrigins || originIsAllowed(origins, origin) {
			return true // 如果允许所有来源或来源在允许列表中，则接受连接
		}
		log.Warn("Rejected WebSocket connection", "origin", origin) // 记录拒绝的 WebSocket 连接和来源
		return false                                                // 否则拒绝连接
	}

	return f
}

type wsHandshakeError struct {
	err    error
	status string
}

func (e wsHandshakeError) Error() string {
	s := e.err.Error()
	if e.status != "" {
		s += " (HTTP status " + e.status + ")"
	}
	return s
}

func (e wsHandshakeError) Unwrap() error {
	return e.err
}

// CORS 安全性： 在 Web 应用程序与以太坊节点或相关服务进行交互时，CORS 策略至关重要。浏览器会阻止来自不同源（协议、主机名或端口不同）的网页直接访问另一个源的资源，以防止恶意网站进行跨站攻击。
// Origin 头部： 浏览器在发起跨域请求时，会在请求头中包含 Origin 字段，指明请求的来源。
// 允许的来源列表： 以太坊节点或服务通常会配置一个允许的来源列表，只有来自这些列表中的来源的请求才会被接受。

// 此函数用于判断给定的浏览器来源是否被一组允许的来源规则中的任何一个所允许。
// allowedOrigins 一个字符串集合，包含了多个允许的来源规则。
func originIsAllowed(allowedOrigins mapset.Set[string], browserOrigin string) bool {
	it := allowedOrigins.Iterator()
	for origin := range it.C {
		if ruleAllowsOrigin(origin, browserOrigin) {
			return true
		}
	}
	return false
}

// 实现了检查给定的浏览器来源（browserOrigin）是否被允许的功能，通过比对一个或多个允许的来源规则（allowedOrigin 或 allowedOrigins）。这通常用于处理跨域资源共享 (CORS) 的安全策略。
func ruleAllowsOrigin(allowedOrigin string, browserOrigin string) bool {
	var (
		allowedScheme, allowedHostname, allowedPort string // 允许的来源的协议、主机名和端口
		browserScheme, browserHostname, browserPort string // 浏览器来源的协议、主机名和端口
		err                                         error
	)
	allowedScheme, allowedHostname, allowedPort, err = parseOriginURL(allowedOrigin) // 解析允许的来源 URL
	if err != nil {
		log.Warn("Error parsing allowed origin specification", "spec", allowedOrigin, "error", err)
		return false
	}
	browserScheme, browserHostname, browserPort, err = parseOriginURL(browserOrigin) // 解析浏览器 'Origin' 字段
	if err != nil {
		log.Warn("Error parsing browser 'Origin' field", "Origin", browserOrigin, "error", err)
		return false
	}
	if allowedScheme != "" && allowedScheme != browserScheme { // 如果允许的协议不为空且与浏览器协议不匹配
		return false
	}
	if allowedHostname != "" && allowedHostname != browserHostname { // 如果允许的主机名不为空且与浏览器主机名不匹配
		return false
	}
	if allowedPort != "" && allowedPort != browserPort { // 如果允许的端口不为空且与浏览器端口不匹配
		return false
	}
	return true // 所有非空且匹配的规则都通过，则允许来源
}

func parseOriginURL(origin string) (string, string, string, error) {
	parsedURL, err := url.Parse(strings.ToLower(origin)) // 将来源字符串转换为小写并解析为 URL
	if err != nil {
		return "", "", "", err
	}
	var scheme, hostname, port string    // 定义协议、主机名和端口变量
	if strings.Contains(origin, "://") { // 如果原始来源字符串包含 "://"，则认为是一个完整的 URL
		scheme = parsedURL.Scheme       // 从解析后的 URL 获取协议
		hostname = parsedURL.Hostname() // 从解析后的 URL 获取主机名
		port = parsedURL.Port()         // 从解析后的 URL 获取端口
	} else { // 如果原始来源字符串不包含 "://"，则可能只是主机名或主机名:端口
		scheme = ""                 // 协议为空
		hostname = parsedURL.Scheme // 将解析后的 Scheme 当作主机名（在没有协议的情况下，url.Parse 的行为）
		port = parsedURL.Opaque     // 将解析后的 Opaque 部分当作端口（用于处理没有协议的 "host:port" 形式）。Opaque 字段通常用于存储非标准的 URL 路径部分，这里可能用于捕获像 "localhost:8080" 这样的端口信息。
		if hostname == "" {
			hostname = origin // 则将原始来源字符串当作主机名
		}
	}
	return scheme, hostname, port, nil
}

// DialWebsocketWithDialer creates a new RPC client using WebSocket.
//
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
//
// Deprecated: use DialOptions and the WithWebsocketDialer option.
//
// DialWebsocketWithDialer 使用 WebSocket 创建一个新的 RPC 客户端。
//
// 上下文用于初始连接建立。它不影响与客户端的后续交互。
//
// Deprecated: 请使用 DialOptions 和 WithWebsocketDialer 选项。
func DialWebsocketWithDialer(ctx context.Context, endpoint, origin string, dialer websocket.Dialer) (*Client, error) {
	cfg := new(clientConfig)
	cfg.wsDialer = &dialer // 设置 WebSocket 拨号器
	if origin != "" {
		cfg.setHeader("origin", origin)
	}
	connect, err := newClientTransportWS(endpoint, cfg) // 使用 WebSocket 创建新的客户端传输
	if err != nil {
		return nil, err
	}
	return newClient(ctx, cfg, connect) // 创建并返回新的客户端
}

// DialWebsocket creates a new RPC client that communicates with a JSON-RPC server
// that is listening on the given endpoint.
//
// The context is used for the initial connection establishment. It does not
// affect subsequent interactions with the client.
//
// DialWebsocket 创建一个新的 RPC 客户端，该客户端与在给定端点监听的 JSON-RPC 服务器通信。
//
// 上下文用于初始连接建立。它不影响与客户端的后续交互。
func DialWebsocket(ctx context.Context, endpoint, origin string) (*Client, error) {
	cfg := new(clientConfig)
	if origin != "" {
		cfg.setHeader("origin", origin)
	}
	connect, err := newClientTransportWS(endpoint, cfg)
	if err != nil {
		return nil, err
	}
	return newClient(ctx, cfg, connect)
}

func newClientTransportWS(endpoint string, cfg *clientConfig) (reconnectFunc, error) {
	dialer := cfg.wsDialer // 从配置中获取 WebSocket 拨号器
	if dialer == nil {
		dialer = &websocket.Dialer{ // 如果配置中没有拨号器，则创建一个默认的拨号器
			ReadBufferSize:  wsReadBuffer,              // 设置读取缓冲区大小
			WriteBufferSize: wsWriteBuffer,             // 设置写入缓冲区大小
			WriteBufferPool: wsBufferPool,              // 设置写入缓冲区池
			Proxy:           http.ProxyFromEnvironment, // 使用环境变量中的代理
		}
	}

	dialURL, header, err := wsClientHeaders(endpoint, "") // 获取拨号 URL 和初始头部
	if err != nil {
		return nil, err
	}
	for key, values := range cfg.httpHeaders { // 将配置中的 HTTP 头部添加到请求头部中
		header[key] = values
	}

	connect := func(ctx context.Context) (ServerCodec, error) {
		header := header.Clone() // 克隆头部，避免修改原始头部
		if cfg.httpAuth != nil { // 如果配置了 HTTP 认证
			if err := cfg.httpAuth(header); err != nil { // 执行 HTTP 认证
				return nil, err
			}
		}
		conn, resp, err := dialer.DialContext(ctx, dialURL, header) // 使用拨号器连接到 WebSocket 端点
		if err != nil {
			hErr := wsHandshakeError{err: err} // 创建一个 WebSocket 握手错误
			if resp != nil {
				hErr.status = resp.Status // 如果有响应，则记录状态码
			}
			return nil, hErr
		}
		messageSizeLimit := int64(wsDefaultReadLimit) // 设置默认的消息大小限制
		if cfg.wsMessageSizeLimit != nil && *cfg.wsMessageSizeLimit >= 0 {
			messageSizeLimit = *cfg.wsMessageSizeLimit // 如果配置中指定了消息大小限制，则使用配置中的值
		}
		return newWebsocketCodec(conn, dialURL, header, messageSizeLimit), nil // 创建并返回新的 WebSocket 编解码器
	}
	return connect, nil // 返回连接函数
}

// 为 WebSocket 客户端连接准备 HTTP 头部
//
// 当 Web 应用程序（例如 DApp 前端）通过 WebSocket 连接到以太坊节点时，浏览器会发送带有 Origin 头的请求。服务器端（以太坊节点或相关服务）可以使用这个头部来判断是否允许来自该域的连接，以增强安全性。
func wsClientHeaders(endpoint, origin string) (string, http.Header, error) {
	endpointURL, err := url.Parse(endpoint) // 解析 WebSocket 端点 URL
	if err != nil {
		return endpoint, nil, err
	}
	header := make(http.Header) // 创建一个新的 HTTP 头部
	if origin != "" {
		header.Add("origin", origin) // 如果提供了来源，则添加到头部
	}
	if endpointURL.User != nil { // 如果端点 URL 包含用户信息（例如：wss://user:password@example.com）
		b64auth := base64.StdEncoding.EncodeToString([]byte(endpointURL.User.String())) // 将用户信息编码为 Base64 字符串
		header.Add("authorization", "Basic "+b64auth)                                   // 将 Base64 编码的凭据添加到 "authorization" 头部
		endpointURL.User = nil                                                          // 清空 URL 中的用户信息，避免在后续使用中暴露凭据
	}
	return endpointURL.String(), header, nil
}

type websocketCodec struct {
	*jsonCodec                 // 嵌入 jsonCodec，继承其 JSON 处理能力
	conn       *websocket.Conn // 底层的 WebSocket 连接
	info       PeerInfo        // 对等节点信息

	wg           sync.WaitGroup // 用于等待 ping 循环 Goroutine 结束
	pingReset    chan struct{}  // 用于重置 ping 定时器
	pongReceived chan struct{}  // 用于接收 pong 消息的信号
}

func newWebsocketCodec(conn *websocket.Conn, host string, req http.Header, readLimit int64) ServerCodec {
	conn.SetReadLimit(readLimit) // 设置从连接读取消息的最大大小
	encode := func(v interface{}, isErrorResponse bool) error {
		return conn.WriteJSON(v) // 使用 WebSocket 连接的 WriteJSON 方法进行编码
	}
	wc := &websocketCodec{
		jsonCodec:    NewFuncCodec(conn, encode, conn.ReadJSON).(*jsonCodec), // 创建并嵌入 jsonCodec，使用 WebSocket 连接的 ReadJSON 方法进行解码
		conn:         conn,
		pingReset:    make(chan struct{}, 1),
		pongReceived: make(chan struct{}),
		info: PeerInfo{
			Transport:  "ws",
			RemoteAddr: conn.RemoteAddr().String(), // 获取 WebSocket 连接的远程地址
		},
	}
	// Fill in connection details.
	// 填充连接详细信息。
	wc.info.HTTP.Host = host
	wc.info.HTTP.Origin = req.Get("Origin")
	wc.info.HTTP.UserAgent = req.Get("User-Agent")
	// Start pinger.
	// 启动 ping 机制。
	conn.SetPongHandler(func(appData string) error {
		select {
		case wc.pongReceived <- struct{}{}: // 接收到 pong 消息，向 pongReceived 通道发送信号
		case <-wc.closed(): // 如果连接已关闭，则退出
		}
		return nil
	})
	wc.wg.Add(1) // 在 Goroutine 中启动 ping 循环
	go wc.pingLoop()
	return wc
}

func (wc *websocketCodec) close() {
	wc.jsonCodec.close() // 关闭底层的 jsonCodec
	wc.wg.Wait()         // 等待 pingLoop Goroutine 结束
}

func (wc *websocketCodec) peerInfo() PeerInfo {
	return wc.info // 返回存储的对等节点信息
}

func (wc *websocketCodec) writeJSON(ctx context.Context, v interface{}, isError bool) error {
	err := wc.jsonCodec.writeJSON(ctx, v, isError) // 调用底层的 jsonCodec 的 writeJSON 方法
	if err == nil {
		// Notify pingLoop to delay the next idle ping.
		// 通知 pingLoop 延迟下一次空闲 ping。
		select {
		case wc.pingReset <- struct{}{}: // 向 pingReset 通道发送信号
		default:
		}
	}
	return err
}

// pingLoop sends periodic ping frames when the connection is idle.
// pingLoop 在连接空闲时发送周期性的 ping 帧。
func (wc *websocketCodec) pingLoop() {
	var pingTimer = time.NewTimer(wsPingInterval) // 创建一个新的定时器，用于发送 ping 消息
	defer wc.wg.Done()                            // 在函数退出时标记 pingLoop Goroutine 已完成
	defer pingTimer.Stop()                        // 在函数退出时停止定时器

	for {
		select {
		case <-wc.closed(): // 如果连接已关闭，则退出循环
			return

		case <-wc.pingReset: // 如果收到 pingReset 信号，则重置 ping 定时器
			if !pingTimer.Stop() {
				<-pingTimer.C
			}
			pingTimer.Reset(wsPingInterval)

		case <-pingTimer.C: // 如果 ping 定时器到期，则发送 ping 消息
			wc.jsonCodec.encMu.Lock()
			wc.conn.SetWriteDeadline(time.Now().Add(wsPingWriteTimeout)) // 设置写截止时间
			wc.conn.WriteMessage(websocket.PingMessage, nil)             // 发送 ping 消息
			wc.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))       // 设置读截止时间，等待 pong 响应
			wc.jsonCodec.encMu.Unlock()
			pingTimer.Reset(wsPingInterval) // 重置 ping 定时器

		case <-wc.pongReceived: // 如果收到 pong 消息，则清除读截止时间
			wc.conn.SetReadDeadline(time.Time{})
		}
	}
}
