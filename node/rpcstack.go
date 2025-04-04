// Copyright 2020 The go-ethereum Authors
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

package node

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/rs/cors"
)

// JSON-RPC：
// 以太坊标准协议（EIP-1474），用于与节点通信。
// 示例：eth_blockNumber 获取最新块高度。
// WebSocket：
// 支持订阅（如 eth_subscribe），实时接收新块或事件。
// 用例：DApp 监听交易确认。
// CORS 和 VHost：
// 防止未授权访问，符合以太坊节点安全最佳实践。
// JWT：
// 增强认证，保护私有节点免受未授权请求。
// IPC：
// 本地通信机制，常用于 Geth 客户端与控制台交互。

// JSON-RPC：以太坊节点通过 JSON-RPC 提供 API（如 eth_getBalance），start 方法启动了支持此类请求的服务器。
// WebSocket：支持实时数据推送（如新块通知），通过 wsAllowed() 检查并记录 WebSocket URL。
// 双协议支持：同时支持 HTTP 和 WebSocket，适应不同用例（HTTP 适合单次查询，WebSocket 适合订阅事件）。
// 路径前缀：通过 prefix 配置，允许节点运营商自定义 API 路径，增强灵活性。

// httpConfig is the JSON-RPC/HTTP configuration.
// httpConfig 是 JSON-RPC/HTTP 配置。
type httpConfig struct {
	Modules            []string // 可用的模块列表
	CorsAllowedOrigins []string // 允许的 CORS 来源
	Vhosts             []string // 允许的虚拟主机
	prefix             string   // path prefix on which to mount http handler // 挂载 http 处理程序的路径前缀
	rpcEndpointConfig           // RPC 端点配置
}

// wsConfig is the JSON-RPC/Websocket configuration
// wsConfig 是 JSON-RPC/Websocket 配置
type wsConfig struct {
	Origins           []string // 允许的 WebSocket 来源
	Modules           []string // 可用的模块列表
	prefix            string   // path prefix on which to mount ws handler // 挂载 ws 处理程序的路径前缀
	rpcEndpointConfig          // RPC 端点配置
}

type rpcEndpointConfig struct {
	jwtSecret              []byte // optional JWT secret // 可选的 JWT 密钥
	batchItemLimit         int    // 批处理请求项限制
	batchResponseSizeLimit int    // 批处理响应大小限制
	httpBodyLimit          int    // HTTP 请求体大小限制
}

type rpcHandler struct {
	http.Handler             // HTTP 处理接口
	server       *rpc.Server // RPC 服务器实例
}

type httpServer struct {
	log      log.Logger       // 日志记录器
	timeouts rpc.HTTPTimeouts // HTTP 超时配置
	mux      http.ServeMux    // registered handlers go here // 已注册的处理程序在此处

	mu       sync.Mutex   // 互斥锁，用于线程安全
	server   *http.Server // HTTP 服务器实例
	listener net.Listener // non-nil when server is running // 服务器运行时不为 nil

	// HTTP RPC handler things. // HTTP RPC 处理程序相关

	httpConfig  httpConfig   // HTTP 配置
	httpHandler atomic.Value // *rpcHandler // HTTP 处理程序，使用原子值存储

	// WebSocket handler things. // WebSocket 处理程序相关
	wsConfig  wsConfig     // WebSocket 配置
	wsHandler atomic.Value // *rpcHandler // WebSocket 处理程序，使用原子值存储

	// These are set by setListenAddr. // 这些由 setListenAddr 设置
	endpoint string // 监听端点
	host     string // 主机地址
	port     int    // 端口号

	handlerNames map[string]string // 处理程序名称映射
}

const (
	shutdownTimeout = 5 * time.Second // 关闭超时时间
)

func newHTTPServer(log log.Logger, timeouts rpc.HTTPTimeouts) *httpServer {
	h := &httpServer{log: log, timeouts: timeouts, handlerNames: make(map[string]string)}

	h.httpHandler.Store((*rpcHandler)(nil)) // 初始化 HTTP 处理程序为空
	h.wsHandler.Store((*rpcHandler)(nil))   // 初始化 WebSocket 处理程序为空
	return h
}

// setListenAddr configures the listening address of the server.
// The address can only be set while the server isn't running.
// setListenAddr 配置服务器的监听地址。
// 只有在服务器未运行时才能设置地址。
func (h *httpServer) setListenAddr(host string, port int) error {
	h.mu.Lock()         // 加锁，确保线程安全
	defer h.mu.Unlock() // 解锁

	if h.listener != nil && (host != h.host || port != h.port) {
		return fmt.Errorf("HTTP server already running on %s", h.endpoint) // 服务器已在运行，返回错误
	}

	h.host, h.port = host, port                                  // 设置主机和端口
	h.endpoint = net.JoinHostPort(host, fmt.Sprintf("%d", port)) // 构造端点地址
	return nil                                                   // 返回成功
}

// listenAddr returns the listening address of the server.
// listenAddr 返回服务器的监听地址。
func (h *httpServer) listenAddr() string {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁

	if h.listener != nil {
		return h.listener.Addr().String() // 返回实际监听地址
	}
	return h.endpoint // 返回配置的端点地址
}

// start starts the HTTP server if it is enabled and not already running.
// start 如果启用了 HTTP 服务器且未在运行，则启动它。
func (h *httpServer) start() error {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁

	if h.endpoint == "" || h.listener != nil {
		return nil // already running or not configured // 已经在运行或未配置
	}

	// Initialize the server. // 初始化服务器
	h.server = &http.Server{Handler: h} // 创建 HTTP 服务器实例
	if h.timeouts != (rpc.HTTPTimeouts{}) {
		CheckTimeouts(&h.timeouts)                                // 检查超时配置
		h.server.ReadTimeout = h.timeouts.ReadTimeout             // 设置读取超时
		h.server.ReadHeaderTimeout = h.timeouts.ReadHeaderTimeout // 设置读取头部超时
		h.server.WriteTimeout = h.timeouts.WriteTimeout           // 设置写入超时
		h.server.IdleTimeout = h.timeouts.IdleTimeout             // 设置空闲超时
	}

	// Start the server. // 启动服务器
	listener, err := net.Listen("tcp", h.endpoint) // 监听 TCP 地址
	if err != nil {
		// If the server fails to start, we need to clear out the RPC and WS
		// configuration so they can be configured another time.
		// 如果服务器启动失败，我们需要清除 RPC 和 WS 配置，以便下次可以重新配置。
		h.disableRPC() // 禁用 RPC
		h.disableWS()  // 禁用 WebSocket
		return err     // 返回错误
	}
	h.listener = listener       // 保存监听器
	go h.server.Serve(listener) // 异步启动服务器

	if h.wsAllowed() { // 如果 WebSocket 已启用
		url := fmt.Sprintf("ws://%v", listener.Addr()) // 构造 WebSocket URL
		if h.wsConfig.prefix != "" {
			url += h.wsConfig.prefix // 添加前缀
		}
		h.log.Info("WebSocket enabled", "url", url) // 记录 WebSocket 启用信息
	}
	// if server is websocket only, return after logging // 如果服务器仅为 WebSocket，则在记录后返回
	if !h.rpcAllowed() {
		return nil
	}
	// Log http endpoint. // 记录 HTTP 端点
	h.log.Info("HTTP server started",
		"endpoint", listener.Addr(), "auth", (h.httpConfig.jwtSecret != nil), // 是否启用 JWT 验证
		"prefix", h.httpConfig.prefix, // HTTP 前缀
		"cors", strings.Join(h.httpConfig.CorsAllowedOrigins, ","), // CORS 来源
		"vhosts", strings.Join(h.httpConfig.Vhosts, ","), // 虚拟主机
	)

	// Log all handlers mounted on server. // 记录服务器上挂载的所有处理程序
	var paths []string
	for path := range h.handlerNames {
		paths = append(paths, path) // 收集所有路径
	}
	sort.Strings(paths)                         // 排序路径
	logged := make(map[string]bool, len(paths)) // 记录已日志的处理程序
	for _, path := range paths {
		name := h.handlerNames[path]
		if !logged[name] {
			log.Info(name+" enabled", "url", "http://"+listener.Addr().String()+path) // 记录启用信息
			logged[name] = true
		}
	}
	return nil // 返回成功
}

func (h *httpServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check if ws request and serve if ws enabled
	// 检查是否为 WebSocket 请求，并在启用 WebSocket 时提供服务
	ws := h.wsHandler.Load().(*rpcHandler)
	if ws != nil && isWebsocket(r) { // 如果 WebSocket 处理程序存在且请求为 WebSocket
		if checkPath(r, h.wsConfig.prefix) { // 检查路径是否匹配
			ws.ServeHTTP(w, r) // 处理 WebSocket 请求
		}
		return
	}

	// if http-rpc is enabled, try to serve request
	// 如果启用了 HTTP-RPC，尝试提供请求服务
	rpc := h.httpHandler.Load().(*rpcHandler)
	if rpc != nil { // 如果 HTTP 处理程序存在
		// First try to route in the mux.
		// Requests to a path below root are handled by the mux,
		// which has all the handlers registered via Node.RegisterHandler.
		// These are made available when RPC is enabled.
		// 首先尝试在 mux 中路由。
		// 根路径以下的请求由 mux 处理，
		// mux 具有通过 Node.RegisterHandler 注册的所有处理程序。
		// 这些在启用 RPC 时可用。
		muxHandler, pattern := h.mux.Handler(r) // 获取 mux 处理程序
		if pattern != "" {                      // 如果匹配到模式
			muxHandler.ServeHTTP(w, r) // 处理请求
			return
		}

		if checkPath(r, h.httpConfig.prefix) { // 检查路径是否匹配 HTTP 前缀
			rpc.ServeHTTP(w, r) // 处理 HTTP RPC 请求
			return
		}
	}
	w.WriteHeader(http.StatusNotFound) // 未找到，返回 404
}

// checkPath checks whether a given request URL matches a given path prefix.
// checkPath 检查给定的请求 URL 是否与给定的路径前缀匹配。
func checkPath(r *http.Request, path string) bool {
	// if no prefix has been specified, request URL must be on root
	// 如果未指定前缀，请求 URL 必须在根路径上
	if path == "" {
		return r.URL.Path == "/"
	}
	// otherwise, check to make sure prefix matches
	// 否则，检查以确保前缀匹配
	return len(r.URL.Path) >= len(path) && r.URL.Path[:len(path)] == path
}

// validatePrefix checks if 'path' is a valid configuration value for the RPC prefix option.
// validatePrefix 检查 'path' 是否是 RPC 前缀选项的有效配置值。
func validatePrefix(what, path string) error {
	if path == "" {
		return nil // 空路径有效
	}
	if path[0] != '/' {
		return fmt.Errorf(`%s RPC path prefix %q does not contain leading "/"`, what, path) // 必须以 '/' 开头
	}
	if strings.ContainsAny(path, "?#") {
		// This is just to avoid confusion. While these would match correctly (i.e. they'd
		// match if URL-escaped into path), it's not easy to understand for users when
		// setting that on the command line.
		// 这只是为了避免混淆。虽然这些会正确匹配（即，如果 URL 转义到路径中，它们会匹配），
		// 但在命令行上设置时，用户不容易理解。
		return fmt.Errorf("%s RPC path prefix %q contains URL meta-characters", what, path) // 不能包含 URL 元字符
	}
	return nil
}

// stop shuts down the HTTP server.
// stop 关闭 HTTP 服务器。
func (h *httpServer) stop() {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁
	h.doStop()          // 执行停止逻辑
}

func (h *httpServer) doStop() {
	if h.listener == nil {
		return // not running // 未在运行
	}

	// Shut down the server. // 关闭服务器
	httpHandler := h.httpHandler.Load().(*rpcHandler)
	wsHandler := h.wsHandler.Load().(*rpcHandler)
	if httpHandler != nil {
		h.httpHandler.Store((*rpcHandler)(nil)) // 清空 HTTP 处理程序
		httpHandler.server.Stop()               // 停止 RPC 服务器
	}
	if wsHandler != nil {
		h.wsHandler.Store((*rpcHandler)(nil)) // 清空 WebSocket 处理程序
		wsHandler.server.Stop()               // 停止 WebSocket 服务器
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout) // 设置关闭超时上下文
	defer cancel()
	err := h.server.Shutdown(ctx) // 优雅关闭服务器
	if err != nil && err == ctx.Err() {
		h.log.Warn("HTTP server graceful shutdown timed out") // 超时警告
		h.server.Close()                                      // 强制关闭
	}

	h.listener.Close()                                               // 关闭监听器
	h.log.Info("HTTP server stopped", "endpoint", h.listener.Addr()) // 记录关闭信息

	// Clear out everything to allow re-configuring it later.
	// 清除所有内容以便稍后重新配置
	h.host, h.port, h.endpoint = "", 0, ""
	h.server, h.listener = nil, nil
}

// enableRPC turns on JSON-RPC over HTTP on the server.
// enableRPC 在服务器上启用 JSON-RPC over HTTP。
func (h *httpServer) enableRPC(apis []rpc.API, config httpConfig) error {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁

	if h.rpcAllowed() {
		return errors.New("JSON-RPC over HTTP is already enabled") // 已启用，返回错误
	}

	// Create RPC server and handler. // 创建 RPC 服务器和处理程序
	srv := rpc.NewServer()                                                   // 创建新的 RPC 服务器
	srv.SetBatchLimits(config.batchItemLimit, config.batchResponseSizeLimit) // 设置批处理限制
	if config.httpBodyLimit > 0 {
		srv.SetHTTPBodyLimit(config.httpBodyLimit) // 设置 HTTP 请求体限制
	}
	if err := RegisterApis(apis, config.Modules, srv); err != nil { // 注册 API
		return err
	}
	h.httpConfig = config // 保存配置
	h.httpHandler.Store(&rpcHandler{
		Handler: NewHTTPHandlerStack(srv, config.CorsAllowedOrigins, config.Vhosts, config.jwtSecret), // 创建处理栈
		server:  srv,
	})
	return nil // 返回成功
}

// disableRPC stops the HTTP RPC handler. This is internal, the caller must hold h.mu.
// disableRPC 停止 HTTP RPC 处理程序。这是内部函数，调用者必须持有 h.mu。
func (h *httpServer) disableRPC() bool {
	handler := h.httpHandler.Load().(*rpcHandler)
	if handler != nil {
		h.httpHandler.Store((*rpcHandler)(nil)) // 清空处理程序
		handler.server.Stop()                   // 停止服务器
	}
	return handler != nil // 返回是否禁用了处理程序
}

// enableWS turns on JSON-RPC over WebSocket on the server.
// enableWS 在服务器上启用 JSON-RPC over WebSocket。
func (h *httpServer) enableWS(apis []rpc.API, config wsConfig) error {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁

	if h.wsAllowed() {
		return errors.New("JSON-RPC over WebSocket is already enabled") // 已启用，返回错误
	}
	// Create RPC server and handler. // 创建 RPC 服务器和处理程序
	srv := rpc.NewServer()                                                   // 创建新的 RPC 服务器
	srv.SetBatchLimits(config.batchItemLimit, config.batchResponseSizeLimit) // 设置批处理限制
	if config.httpBodyLimit > 0 {
		srv.SetHTTPBodyLimit(config.httpBodyLimit) // 设置 HTTP 请求体限制
	}
	if err := RegisterApis(apis, config.Modules, srv); err != nil { // 注册 API
		return err
	}
	h.wsConfig = config // 保存配置
	h.wsHandler.Store(&rpcHandler{
		Handler: NewWSHandlerStack(srv.WebsocketHandler(config.Origins), config.jwtSecret), // 创建 WebSocket 处理栈
		server:  srv,
	})
	return nil // 返回成功
}

// stopWS disables JSON-RPC over WebSocket and also stops the server if it only serves WebSocket.
// stopWS 禁用 JSON-RPC over WebSocket，如果服务器仅服务 WebSocket，则也停止服务器。
func (h *httpServer) stopWS() {
	h.mu.Lock()         // 加锁
	defer h.mu.Unlock() // 解锁

	if h.disableWS() { // 禁用 WebSocket
		if !h.rpcAllowed() { // 如果没有 HTTP RPC
			h.doStop() // 停止服务器
		}
	}
}

// disableWS disables the WebSocket handler. This is internal, the caller must hold h.mu.
// disableWS 禁用 WebSocket 处理程序。这是内部函数，调用者必须持有 h.mu。
func (h *httpServer) disableWS() bool {
	ws := h.wsHandler.Load().(*rpcHandler)
	if ws != nil {
		h.wsHandler.Store((*rpcHandler)(nil)) // 清空处理程序
		ws.server.Stop()                      // 停止服务器
	}
	return ws != nil // 返回是否禁用了处理程序
}

// rpcAllowed returns true when JSON-RPC over HTTP is enabled.
// rpcAllowed 当启用了 JSON-RPC over HTTP 时返回 true。
func (h *httpServer) rpcAllowed() bool {
	return h.httpHandler.Load().(*rpcHandler) != nil
}

// wsAllowed returns true when JSON-RPC over WebSocket is enabled.
// wsAllowed 当启用了 JSON-RPC over WebSocket 时返回 true。
func (h *httpServer) wsAllowed() bool {
	return h.wsHandler.Load().(*rpcHandler) != nil
}

// isWebsocket checks the header of an http request for a websocket upgrade request.
// isWebsocket 检查 http 请求的标头以查看是否为 WebSocket 升级请求。
func isWebsocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// NewHTTPHandlerStack returns wrapped http-related handlers
// NewHTTPHandlerStack 返回包装的 HTTP 相关处理程序
func NewHTTPHandlerStack(srv http.Handler, cors []string, vhosts []string, jwtSecret []byte) http.Handler {
	// Wrap the CORS-handler within a host-handler
	// 在 host-handler 中包装 CORS-handler
	handler := newCorsHandler(srv, cors)       // 添加 CORS 处理
	handler = newVHostHandler(vhosts, handler) // 添加虚拟主机处理
	if len(jwtSecret) != 0 {
		handler = newJWTHandler(jwtSecret, handler) // 添加 JWT 验证
	}
	return newGzipHandler(handler) // 添加 Gzip 压缩
}

// NewWSHandlerStack returns a wrapped ws-related handler.
// NewWSHandlerStack 返回包装的 WebSocket 相关处理程序。
func NewWSHandlerStack(srv http.Handler, jwtSecret []byte) http.Handler {
	if len(jwtSecret) != 0 {
		return newJWTHandler(jwtSecret, srv) // 添加 JWT 验证
	}
	return srv // 直接返回服务器处理程序
}

func newCorsHandler(srv http.Handler, allowedOrigins []string) http.Handler {
	// disable CORS support if user has not specified a custom CORS configuration
	// 如果用户未指定自定义 CORS 配置，则禁用 CORS 支持
	if len(allowedOrigins) == 0 {
		return srv
	}
	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,                            // 允许的来源
		AllowedMethods: []string{http.MethodPost, http.MethodGet}, // 允许的方法
		AllowedHeaders: []string{"*"},                             // 允许的头部
		MaxAge:         600,                                       // 最大缓存时间
	})
	return c.Handler(srv) // 返回 CORS 处理程序
}

// virtualHostHandler is a handler which validates the Host-header of incoming requests.
// Using virtual hosts can help prevent DNS rebinding attacks, where a 'random' domain name points to
// the service ip address (but without CORS headers). By verifying the targeted virtual host, we can
// ensure that it's a destination that the node operator has defined.
// virtualHostHandler 是一个处理程序，用于验证传入请求的 Host 标头。
// 使用虚拟主机可以帮助防止 DNS 重新绑定攻击，其中“随机”域名指向服务 IP 地址（但没有 CORS 标头）。
// 通过验证目标虚拟主机，我们可以确保它是节点操作员定义的目的地。
type virtualHostHandler struct {
	vhosts map[string]struct{} // 允许的主机集合
	next   http.Handler        // 下一个处理程序
}

func newVHostHandler(vhosts []string, next http.Handler) http.Handler {
	vhostMap := make(map[string]struct{})
	for _, allowedHost := range vhosts {
		vhostMap[strings.ToLower(allowedHost)] = struct{}{} // 添加允许的主机
	}
	return &virtualHostHandler{vhostMap, next}
}

// ServeHTTP serves JSON-RPC requests over HTTP, implements http.Handler
// ServeHTTP 通过 HTTP 服务 JSON-RPC 请求，实现 http.Handler
func (h *virtualHostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// if r.Host is not set, we can continue serving since a browser would set the Host header
	// 如果 r.Host 未设置，我们可以继续服务，因为浏览器会设置 Host 标头
	if r.Host == "" {
		h.next.ServeHTTP(w, r)
		return
	}
	host, _, err := net.SplitHostPort(r.Host) // 分离主机和端口
	if err != nil {
		// Either invalid (too many colons) or no port specified
		// 无效（太多冒号）或未指定端口
		host = r.Host
	}
	if ipAddr := net.ParseIP(host); ipAddr != nil {
		// It's an IP address, we can serve that
		// 它是 IP 地址，我们可以服务
		h.next.ServeHTTP(w, r)
		return
	}
	// Not an IP address, but a hostname. Need to validate
	// 不是 IP 地址，而是主机名。需要验证
	if _, exist := h.vhosts["*"]; exist { // 通配符允许所有主机
		h.next.ServeHTTP(w, r)
		return
	}
	if _, exist := h.vhosts[host]; exist { // 检查主机是否在允许列表中
		h.next.ServeHTTP(w, r)
		return
	}
	http.Error(w, "invalid host specified", http.StatusForbidden) // 返回 403 错误
}

var gzPool = sync.Pool{
	New: func() interface{} {
		w := gzip.NewWriter(io.Discard)
		return w
	},
}

type gzipResponseWriter struct {
	resp http.ResponseWriter // 原始响应写入器

	gz            *gzip.Writer // Gzip 写入器
	contentLength uint64       // total length of the uncompressed response // 未压缩响应的总长度
	written       uint64       // amount of written bytes from the uncompressed response // 从未压缩响应写入的字节数
	hasLength     bool         // true if uncompressed response had Content-Length // 如果未压缩响应有 Content-Length 则为 true
	inited        bool         // true after init was called for the first time // 首次调用 init 后为 true
}

// init runs just before response headers are written. Among other things, this function
// also decides whether compression will be applied at all.
// init 在写入响应标头之前运行。除其他事项外，此函数还决定是否应用压缩。
func (w *gzipResponseWriter) init() {
	if w.inited {
		return
	}
	w.inited = true

	hdr := w.resp.Header()
	length := hdr.Get("content-length")
	if len(length) > 0 {
		if n, err := strconv.ParseUint(length, 10, 64); err != nil {
			w.hasLength = true
			w.contentLength = n // 设置内容长度
		}
	}

	// Setting Transfer-Encoding to "identity" explicitly disables compression. net/http
	// also recognizes this header value and uses it to disable "chunked" transfer
	// encoding, trimming the header from the response. This means downstream handlers can
	// set this without harm, even if they aren't wrapped by newGzipHandler.
	//
	// In go-ethereum, we use this signal to disable compression for certain error
	// responses which are flushed out close to the write deadline of the response. For
	// these cases, we want to avoid chunked transfer encoding and compression because
	// they require additional output that may not get written in time.
	// 将 Transfer-Encoding 设置为 "identity" 显式禁用压缩。net/http 也识别此标头值并使用它来禁用“分块”传输编码，从响应中修剪标头。
	// 这意味着下游处理程序可以设置此项而不会造成损害，即使它们未被 newGzipHandler 包装。
	//
	// 在 go-ethereum 中，我们使用此信号为某些错误响应禁用压缩，这些错误响应在响应的写入截止时间附近被刷新。
	// 对于这些情况，我们希望避免分块传输编码和压缩，因为它们需要可能无法及时写入的额外输出。
	passthrough := hdr.Get("transfer-encoding") == "identity"
	if !passthrough {
		w.gz = gzPool.Get().(*gzip.Writer)  // 从池中获取 Gzip 写入器
		w.gz.Reset(w.resp)                  // 重置写入器
		hdr.Del("content-length")           // 删除内容长度头部
		hdr.Set("content-encoding", "gzip") // 设置 Gzip 编码
	}
}

func (w *gzipResponseWriter) Header() http.Header {
	return w.resp.Header()
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	w.init()                   // 初始化
	w.resp.WriteHeader(status) // 写入状态码
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.init() // 初始化

	if w.gz == nil {
		// Compression is disabled.
		// 压缩已禁用。
		return w.resp.Write(b) // 直接写入
	}

	n, err := w.gz.Write(b) // 写入 Gzip 流
	w.written += uint64(n)  // 更新已写入字节数
	if w.hasLength && w.written >= w.contentLength {
		// The HTTP handler has finished writing the entire uncompressed response. Close
		// the gzip stream to ensure the footer will be seen by the client in case the
		// response is flushed after this call to write.
		// HTTP 处理程序已完成写入整个未压缩响应。关闭 gzip 流以确保在写入后刷新响应时客户端可以看到页脚。
		err = w.gz.Close() // 关闭 Gzip 流
	}
	return n, err
}

func (w *gzipResponseWriter) Flush() {
	if w.gz != nil {
		w.gz.Flush() // 刷新 Gzip 流
	}
	if f, ok := w.resp.(http.Flusher); ok {
		f.Flush() // 刷新响应
	}
}

func (w *gzipResponseWriter) close() {
	if w.gz == nil {
		return
	}
	w.gz.Close()     // 关闭 Gzip 流
	gzPool.Put(w.gz) // 放回池中
	w.gz = nil       // 清空引用
}

func newGzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") { // 检查是否支持 Gzip
			next.ServeHTTP(w, r) // 不支持，直接处理
			return
		}

		wrapper := &gzipResponseWriter{resp: w} // 创建 Gzip 响应写入器
		defer wrapper.close()                   // 延迟关闭

		next.ServeHTTP(wrapper, r) // 处理请求
	})
}

type ipcServer struct {
	log      log.Logger // 日志记录器
	endpoint string     // IPC 端点

	mu       sync.Mutex   // 互斥锁
	listener net.Listener // 监听器
	srv      *rpc.Server  // RPC 服务器
}

func newIPCServer(log log.Logger, endpoint string) *ipcServer {
	return &ipcServer{log: log, endpoint: endpoint}
}

// start starts the httpServer's http.Server
// start 启动 httpServer 的 http.Server
func (is *ipcServer) start(apis []rpc.API) error {
	is.mu.Lock()         // 加锁
	defer is.mu.Unlock() // 解锁

	if is.listener != nil {
		return nil // already running // 已经在运行
	}
	listener, srv, err := rpc.StartIPCEndpoint(is.endpoint, apis) // 启动 IPC 端点
	if err != nil {
		is.log.Warn("IPC opening failed", "url", is.endpoint, "error", err) // 记录失败
		return err
	}
	is.log.Info("IPC endpoint opened", "url", is.endpoint) // 记录成功
	is.listener, is.srv = listener, srv                    // 保存监听器和服务器
	return nil                                             // 返回成功
}

func (is *ipcServer) stop() error {
	is.mu.Lock()         // 加锁
	defer is.mu.Unlock() // 解锁

	if is.listener == nil {
		return nil // not running // 未在运行
	}
	err := is.listener.Close()                             // 关闭监听器
	is.srv.Stop()                                          // 停止服务器
	is.listener, is.srv = nil, nil                         // 清空引用
	is.log.Info("IPC endpoint closed", "url", is.endpoint) // 记录关闭
	return err                                             // 返回错误（如果有）
}

// RegisterApis checks the given modules' availability, generates an allowlist based on the allowed modules,
// and then registers all of the APIs exposed by the services.
// RegisterApis 检查给定模块的可用性，基于允许的模块生成允许列表，
// 然后注册服务暴露的所有 API。
func RegisterApis(apis []rpc.API, modules []string, srv *rpc.Server) error {
	if bad, available := checkModuleAvailability(modules, apis); len(bad) > 0 {
		log.Error("Unavailable modules in HTTP API list", "unavailable", bad, "available", available) // 记录不可用模块
	}
	// Generate the allow list based on the allowed modules
	// 基于允许的模块生成允许列表
	allowList := make(map[string]bool)
	for _, module := range modules {
		allowList[module] = true // 添加到允许列表
	}
	// Register all the APIs exposed by the services
	// 注册服务暴露的所有 API
	for _, api := range apis {
		if allowList[api.Namespace] || len(allowList) == 0 { // 如果模块允许或无限制
			if err := srv.RegisterName(api.Namespace, api.Service); err != nil { // 注册服务
				return err
			}
		}
	}
	return nil // 返回成功
}
