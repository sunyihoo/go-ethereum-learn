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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	defaultBodyLimit = 5 * 1024 * 1024    // 定义默认的 HTTP 请求体大小限制，用于防止过大数据请求。
	contentType      = "application/json" // 指定 JSON-RPC 请求的标准内容类型，作为默认值。
)

// JSON-RPC 协议在 HTTP 上的实现允许多种 Content-Type，以太坊节点（如 Geth）通常支持这些变体以兼容不同的客户端（如 MetaMask、curl）。

// https://www.jsonrpc.org/historical/json-rpc-over-http.html#id13
var acceptedContentTypes = []string{contentType, "application/json-rpc", "application/jsonrequest"}

// httpConn 表示一个 HTTP 客户端连接，用于发送 RPC 请求。
type httpConn struct {
	client    *http.Client     // HTTP 客户端实例，用于发送请求。
	url       string           // 请求的目标 URL。目标服务器的URL（如 "http://localhost:8545"）。
	closeOnce sync.Once        // 确保关闭操作只执行一次。
	closeCh   chan interface{} // 关闭信号通道。
	mu        sync.Mutex       // protects headers 保护 headers 的互斥锁。
	headers   http.Header      // HTTP 请求头部。
	auth      HTTPAuth         // HTTP 认证信息。
}

// httpConn implements ServerCodec, but it is treated specially by Client
// and some methods don't work. The panic() stubs here exist to ensure
// this special treatment is correct.
// httpConn 实现了 ServerCodec 接口，但 Client 对其有特殊处理，
// 某些方法不起作用。此处的 panic() 存根用于确保这种特殊处理的正确性。

// 在 go-ethereum 中，HTTP RPC 的写操作通常由 http.Client 处理，而非直接通过 ServerCodec 的 writeJSON。
// httpConn 作为客户端连接，不需要实现服务器端的写逻辑，因此 panic 防止误用。
func (hc *httpConn) writeJSON(context.Context, interface{}, bool) error {
	panic("writeJSON called on httpConn")
}

// peerInfo 通常由服务器端提供（如 PeerInfoFromContext），表示客户端信息。httpConn 是客户端连接，无法获取服务器的对端信息，因此禁用此方法。
func (hc *httpConn) peerInfo() PeerInfo {
	panic("peerInfo called on httpConn")
}

// 在 HTTP 客户端中，远程地址就是目标 URL，而非底层的 IP 和端口（如服务器端返回的 RemoteAddr）。这与以太坊节点的 RPC 端点（如 Geth 的 HTTP 服务）一致。
func (hc *httpConn) remoteAddr() string {
	return hc.url
}

// HTTP RPC 通常是单次请求-响应模式，不支持服务器端的批量读取（readBatch 更适用于 WebSocket 或 IPC 的流式通信）。httpConn 通过等待关闭模拟无数据的状态，表明其不处理服务器端读取。
func (hc *httpConn) readBatch() ([]*jsonrpcMessage, bool, error) {
	<-hc.closeCh
	return nil, false, io.EOF
}

func (hc *httpConn) close() {
	hc.closeOnce.Do(func() { close(hc.closeCh) })
}

// 返回关闭信号通道。在 go-ethereum 中，closed() 是 ServerCodec 接口的一部分，用于阻塞等待连接关闭。httpConn 通过复用 closeCh 实现此功能。
func (hc *httpConn) closed() <-chan interface{} {
	return hc.closeCh
}

// HTTPTimeouts represents the configuration params for the HTTP RPC server.
// HTTPTimeouts 表示 HTTP RPC 服务器的配置参数。
type HTTPTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	//
	// ReadHeaderTimeout. It is valid to use them both.
	// ReadTimeout 是读取整个请求（包括请求体）的最大持续时间。
	//
	// 因为 ReadTimeout 不允许处理程序针对每个请求体的可接受截止时间或上传速率做出逐请求的决定，
	// 大多数用户会更倾向于使用 ReadHeaderTimeout。可以同时使用这两者。
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If ReadHeaderTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, there is no timeout.
	//
	// ReadHeaderTimeout 是允许读取请求头部的时间量。在读取头部后，连接的读取截止时间会被重置，
	// 处理程序可以决定请求体什么情况下算太慢。如果 ReadHeaderTimeout 为零，则使用 ReadTimeout 的值。
	// 如果两者均为零，则没有超时。
	ReadHeaderTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	//
	// WriteTimeout 是响应写入超时前的最大持续时间。每当读取一个新请求的头部时，它都会被重置。
	// 与 ReadTimeout 类似，它不允许处理程序基于每个请求做出决定。
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, ReadHeaderTimeout is used.
	//
	// IdleTimeout 是启用 keep-alive 时等待下一个请求的最大时间量。如果 IdleTimeout 为零，
	// 则使用 ReadTimeout 的值。如果两者均为零，则使用 ReadHeaderTimeout。
	IdleTimeout time.Duration
}

// DefaultHTTPTimeouts represents the default timeout values used if further
// configuration is not provided.
// DefaultHTTPTimeouts 表示如果未提供进一步配置时使用的默认超时值。
var DefaultHTTPTimeouts = HTTPTimeouts{
	ReadTimeout:       30 * time.Second,
	ReadHeaderTimeout: 30 * time.Second,
	WriteTimeout:      30 * time.Second,
	IdleTimeout:       120 * time.Second,
}

// 在 go-ethereum 中，DialHTTP 是客户端库（如 rpc 包）提供的便捷函数，用于连接以太坊节点的 HTTP RPC 端点（如 Geth 的 --http 服务）。

// DialHTTP creates a new RPC client that connects to an RPC server over HTTP.
// DialHTTP 创建一个新的 RPC 客户端，通过 HTTP 连接到 RPC 服务器。
// endpoint string（RPC 服务器的 URL，如 "http://localhost:8545"）。
func DialHTTP(endpoint string) (*Client, error) {
	return DialHTTPWithClient(endpoint, new(http.Client))
}

// DialHTTPWithClient creates a new RPC client that connects to an RPC server over HTTP
// using the provided HTTP Client.
//
// Deprecated: use DialOptions and the WithHTTPClient option.
//
// DialHTTPWithClient 创建一个新的 RPC 客户端，通过 HTTP 连接到 RPC 服务器，
// 使用提供的 HTTP 客户端。
//
// 已废弃：请使用 DialOptions 和 WithHTTPClient 选项。
func DialHTTPWithClient(endpoint string, client *http.Client) (*Client, error) {
	// Sanity check URL so we don't end up with a client that will fail every request.
	// 检查 URL 的有效性，以避免创建总是失败的客户端。
	_, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	var cfg clientConfig
	cfg.httpClient = client
	fn := newClientTransportHTTP(endpoint, &cfg)
	return newClient(context.Background(), &cfg, fn)
}

// newClientTransportHTTP 创建一个 HTTP 客户端传输函数，用于连接 RPC 端点。
func newClientTransportHTTP(endpoint string, cfg *clientConfig) reconnectFunc {
	// 初始化 HTTP 头部，预分配空间包括默认的两个头部和自定义头部。
	headers := make(http.Header, 2+len(cfg.httpHeaders))
	// 设置接受的内容类型为 "application/json"。
	headers.Set("accept", contentType)
	// 设置请求的内容类型为 "application/json"。
	headers.Set("content-type", contentType)
	// 合并配置中的自定义头部。
	for key, values := range cfg.httpHeaders {
		headers[key] = values
	}

	// 使用配置中的 HTTP 客户端，若未提供则创建默认客户端。
	client := cfg.httpClient
	if client == nil {
		client = new(http.Client)
	}

	// 初始化 HTTP 连接结构体。
	hc := &httpConn{
		client:  client,
		headers: headers,
		url:     endpoint,
		auth:    cfg.httpAuth,
		closeCh: make(chan interface{}),
	}

	// 返回一个重连函数，返回配置好的 httpConn。
	return func(ctx context.Context) (ServerCodec, error) {
		return hc, nil
	}
}

// sendHTTP 通过 HTTP 发送单个 JSON-RPC 消息，并将响应发送到操作的响应通道。
func (c *Client) sendHTTP(ctx context.Context, op *requestOp, msg interface{}) error {
	hc := c.writeConn.(*httpConn)
	respBody, err := hc.doRequest(ctx, msg)
	if err != nil {
		return err
	}
	defer respBody.Close()

	// 以太坊的 JSON-RPC API 支持单次请求：{"jsonrpc": "2.0", "method": "eth_getBalance", "params": ["0x...", "latest"], "id": 1}
	// 服务器返回单个 JSON 对象，例如：{"jsonrpc": "2.0", "id": 1, "result": "0x123456"}

	var resp jsonrpcMessage
	batch := [1]*jsonrpcMessage{&resp}
	if err := json.NewDecoder(respBody).Decode(&resp); err != nil {
		return err
	}
	op.resp <- batch[:]
	return nil
}

// sendBatchHTTP 通过 HTTP 发送一批 JSON-RPC 消息，并将响应发送到操作的响应通道。
func (c *Client) sendBatchHTTP(ctx context.Context, op *requestOp, msgs []*jsonrpcMessage) error {
	hc := c.writeConn.(*httpConn)
	respBody, err := hc.doRequest(ctx, msgs)
	if err != nil {
		return err
	}
	defer respBody.Close()

	var respmsgs []*jsonrpcMessage
	if err := json.NewDecoder(respBody).Decode(&respmsgs); err != nil {
		return err
	}
	op.resp <- respmsgs
	return nil
}

// doRequest 使用给定的上下文和消息执行 HTTP 请求，并返回响应体或错误。
// 用于通过 HTTP 客户端向指定 URL 发送 POST 请求，通常用于与以太坊节点的 JSON-RPC 端点交互。
// 它的主要目的是将输入消息（msg）编码为 JSON，构造 HTTP 请求，发送请求，并处理响应或错误。
func (hc *httpConn) doRequest(ctx context.Context, msg interface{}) (io.ReadCloser, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	// io.NopCloser(bytes.NewReader(body)) 将字节数组包装为 io.ReadCloser，但不执行关闭操作（因为内存数据无需关闭）。
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hc.url, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	// 定义 req.GetBody 函数，提供请求体的副本（用于重试场景，如 HTTP 重定向）。
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }

	// set headers
	// 设置头部
	hc.mu.Lock()
	req.Header = hc.headers.Clone()
	hc.mu.Unlock()
	setHeaders(req.Header, headersFromContext(ctx))

	if hc.auth != nil {
		if err := hc.auth(req.Header); err != nil {
			return nil, err
		}
	}

	// do request
	// 执行请求
	resp, err := hc.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 { // 如果状态码不在 200-299 范围内（表示成功），读取响应体并构造 HTTPError 返回。
		var buf bytes.Buffer
		var body []byte
		if _, err := buf.ReadFrom(resp.Body); err == nil {
			body = buf.Bytes()
		}
		resp.Body.Close()
		return nil, HTTPError{
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       body,
		}
	}
	return resp.Body, nil
}

// httpServerConn turns a HTTP connection into a Conn.
// httpServerConn 将 HTTP 连接转换为一个 Conn。
type httpServerConn struct {
	io.Reader
	io.Writer
	r *http.Request
}

// 用于将 HTTP 连接封装为一个符合 ServerCodec 接口的对象，以便在以太坊节点中处理 JSON-RPC 请求。
// 它的主要目的是将 HTTP 请求和响应的输入输出流（io.Reader 和 io.Writer）适配为一个可以在 RPC 服务中使用的连接对象。
func (s *Server) newHTTPServerConn(r *http.Request, w http.ResponseWriter) ServerCodec {
	// 使用 io.LimitReader 限制请求体的读取长度（s.httpBodyLimit），防止恶意客户端发送超大数据。
	body := io.LimitReader(r.Body, int64(s.httpBodyLimit))
	conn := &httpServerConn{Reader: body, Writer: w, r: r}

	// 定义 encoder 函数，用于将响应数据编码为 JSON 并写入 w。
	encoder := func(v any, isErrorResponse bool) error {
		// 如果不是错误响应，直接使用 json.NewEncoder 编码并写入。
		if !isErrorResponse {
			return json.NewEncoder(conn).Encode(v)
		}

		// It's an error response and requires special treatment.
		//
		// In case of a timeout error, the response must be written before the HTTP
		// server's write timeout occurs. So we need to flush the response. The
		// Content-Length header also needs to be set to ensure the client knows
		// when it has the full response.
		//
		// 这是一个错误响应，需要特殊处理。
		//
		// 在超时错误的情况下，必须在 HTTP 服务器的写入超时发生之前写入响应。因此我们需要刷新响应。
		// 还需要设置 Content-Length 头部，以确保客户端知道何时接收到完整响应。
		encdata, err := json.Marshal(v)
		if err != nil {
			return err
		}
		w.Header().Set("content-length", strconv.Itoa(len(encdata)))

		// If this request is wrapped in a handler that might remove Content-Length (such
		// as the automatic gzip we do in package node), we need to ensure the HTTP server
		// doesn't perform chunked encoding. In case WriteTimeout is reached, the chunked
		// encoding might not be finished correctly, and some clients do not like it when
		// the final chunk is missing.
		//
		// 如果此请求被包装在一个可能会移除 Content-Length 的处理器中（例如我们在 node 包中自动进行的 gzip），
		// 我们需要确保 HTTP 服务器不会执行分块编码。如果达到 WriteTimeout，分块编码可能无法正确完成，
		// 一些客户端不喜欢缺少最后一个分块的情况。
		// 设置 Transfer-Encoding: identity，禁用分块编码（chunked encoding），避免超时导致的不完整响应。
		w.Header().Set("transfer-encoding", "identity")

		_, err = w.Write(encdata)
		// 这种处理方式是为了应对 HTTP 服务器的写入超时（WriteTimeout）问题，确保即使在异常情况下，客户端也能接收到完整响应。
		// 写入数据后调用 Flush，立即发送响应
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return err
	}

	// 定义 decoder（基于 json.NewDecoder），用于解析请求体的 JSON 数据。
	dec := json.NewDecoder(conn)
	dec.UseNumber()

	return NewFuncCodec(conn, encoder, dec.Decode)
}

// Close does nothing and always returns nil.
// Close 什么也不做，总是返回 nil。
func (t *httpServerConn) Close() error { return nil }

// RemoteAddr returns the peer address of the underlying connection.
// RemoteAddr 返回底层连接的对端地址。
func (t *httpServerConn) RemoteAddr() string {
	return t.r.RemoteAddr
}

// SetWriteDeadline does nothing and always returns nil.
// SetWriteDeadline 什么也不做，总是返回 nil。
func (t *httpServerConn) SetWriteDeadline(time.Time) error { return nil }

// ServeHTTP serves JSON-RPC requests over HTTP.
// ServeHTTP 通过 HTTP 服务 JSON-RPC 请求。
// 处理 HTTP 请求，提供 JSON-RPC 服务，支持以太坊节点的 RPC 接口。
//
// ServeHTTP 是 rpc 包中 HTTP 服务器的核心方法，与客户端的 DialHTTP 形成完整通信链路。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Permit dumb empty requests for remote health-checks (AWS)
	// 允许远程健康检查（AWS）的简单空请求。
	// 检查是否为简单的 GET 请求，无内容且无查询参数。
	if r.Method == http.MethodGet && r.ContentLength == 0 && r.URL.RawQuery == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if code, err := s.validateRequest(r); err != nil {
		http.Error(w, err.Error(), code)
		return
	}

	// Create request-scoped context.
	// 创建请求范围的上下文。
	connInfo := PeerInfo{Transport: "http", RemoteAddr: r.RemoteAddr}
	connInfo.HTTP.Version = r.Proto
	connInfo.HTTP.Host = r.Host
	connInfo.HTTP.Origin = r.Header.Get("Origin")
	connInfo.HTTP.UserAgent = r.Header.Get("User-Agent")
	ctx := r.Context()
	ctx = context.WithValue(ctx, peerInfoContextKey{}, connInfo)

	// All checks passed, create a codec that reads directly from the request body
	// until EOF, writes the response to w, and orders the server to process a
	// single request.
	// 所有检查通过后，创建一个直接从请求体读取直到 EOF 的编解码器，
	// 将响应写入 w，并命令服务器处理单个请求。
	w.Header().Set("content-type", contentType)
	codec := s.newHTTPServerConn(r, w)
	defer codec.close()
	s.serveSingleRequest(ctx, codec)
}

// validateRequest returns a non-zero response code and error message if the
// request is invalid.
// validateRequest 如果请求无效，则返回一个非零的响应代码和错误消息。
func (s *Server) validateRequest(r *http.Request) (int, error) {
	if r.Method == http.MethodPut || r.Method == http.MethodDelete {
		return http.StatusMethodNotAllowed, errors.New("method not allowed") // 只允许 POST 方法
	}
	if r.ContentLength > int64(s.httpBodyLimit) {
		err := fmt.Errorf("content length too large (%d>%d)", r.ContentLength, s.httpBodyLimit)
		return http.StatusRequestEntityTooLarge, err
	}
	// Allow OPTIONS (regardless of content-type)
	// 允许 OPTIONS 方法（不考虑 content-type）
	if r.Method == http.MethodOptions {
		return 0, nil
	}
	// Check content-type
	// 检查 content-type
	if mt, _, err := mime.ParseMediaType(r.Header.Get("content-type")); err == nil {
		for _, accepted := range acceptedContentTypes {
			if accepted == mt {
				return 0, nil
			}
		}
	}
	// Invalid content-type
	// 无效的 content-type
	err := fmt.Errorf("invalid content type, only %s is supported", contentType)
	return http.StatusUnsupportedMediaType, err
}

// ContextRequestTimeout returns the request timeout derived from the given context.
// ContextRequestTimeout 返回从给定上下文中派生的请求超时时间。
func ContextRequestTimeout(ctx context.Context) (time.Duration, bool) {
	timeout := time.Duration(math.MaxInt64) // 将超时时间初始化为最大可能时长
	hasTimeout := false
	setTimeout := func(d time.Duration) {
		if d < timeout {
			timeout = d
			hasTimeout = true
		}
	}

	if deadline, ok := ctx.Deadline(); ok { // 检查上下文是否设置了截止时间
		setTimeout(time.Until(deadline)) // 计算到截止时间的剩余时间，并将其设置为超时时间（如果更小）
	}

	// If the context is an HTTP request context, use the server's WriteTimeout.
	// 如果上下文是 HTTP 请求上下文，则使用服务器的 WriteTimeout。
	// http.ServerContextKey 是 net/http 包中定义的用于存储服务器实例的 context key。如果当前请求是通过 HTTP 处理的，那么这个值可能会存在。
	httpSrv, ok := ctx.Value(http.ServerContextKey).(*http.Server) // 尝试从上下文中获取 HTTP 服务器
	if ok && httpSrv.WriteTimeout > 0 {
		wt := httpSrv.WriteTimeout
		// When a write timeout is configured, we need to send the response message before
		// the HTTP server cuts connection. So our internal timeout must be earlier than
		// the server's true timeout.
		//
		// Note: Timeouts are sanitized to be a minimum of 1 second.
		// Also see issue: https://github.com/golang/go/issues/47229
		//
		// 当配置了写入超时时，我们需要在 HTTP 服务器断开连接之前发送响应消息。
		// 因此，我们的内部超时时间必须早于服务器的真实超时时间。
		//
		// 注意：超时时间被清理为至少 1 秒。
		// 另请参阅问题：https://github.com/golang/go/issues/47229
		wt -= 100 * time.Millisecond // 减去一个小的缓冲时间，以确保在我们完成之前服务器不会超时
		setTimeout(wt)               // 将超时时间设置为（调整后的）写入超时时间（如果更小）
	}

	return timeout, hasTimeout
}
