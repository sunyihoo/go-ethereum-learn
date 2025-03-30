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

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrBadResult                 = errors.New("bad result in JSON-RPC response")                        // JSON-RPC 响应中的结果错误。表示在 JSON-RPC 响应的 "result" 字段中发现了格式不正确或内容不符合预期的结果。这可能是由于服务端返回了错误的数据结构。
	ErrClientQuit                = errors.New("client is closed")                                       // 客户端已关闭。表明 RPC 客户端已被显式地关闭。当客户端不再需要与服务器通信时，可能会调用关闭方法，此时如果再尝试进行操作可能会返回此错误。
	ErrNoResult                  = errors.New("JSON-RPC response has no result")                        // JSON-RPC 响应没有结果。指示 JSON-RPC 响应中缺少预期的 "result" 字段。这可能是服务端错误或者请求的方法不应该返回结果
	ErrMissingBatchResponse      = errors.New("response batch did not contain a response to this call") // 响应批处理不包含对此调用的响应。当发送一个批量的 JSON-RPC 请求时，服务器会返回一个批量的响应。如果收到的响应数组中没有包含与某个请求对应的响应，则会返回此错误。这可能是因为服务器处理请求时发生了错误。
	ErrSubscriptionQueueOverflow = errors.New("subscription queue overflow")                            // 订阅队列溢出。通常在使用 WebSocket 进行订阅时，服务器会推送事件到客户端。客户端需要维护一个队列来处理这些事件。如果服务器推送事件的速度超过了客户端处理的速度，导致队列满了，就会发生队列溢出，并返回此错误。
	errClientReconnected         = errors.New("client reconnected")                                     // 客户端已重新连接。 表示 RPC 客户端在连接断开后已成功重新连接到服务器。这通常用于通知上层应用连接状态的变化。
	errDead                      = errors.New("connection lost")                                        // 连接丢失。指示底层的网络连接已丢失。这可能是由于网络故障、服务器关闭等原因导致。
)

// Timeouts
// 超时时间
const (
	defaultDialTimeout = 10 * time.Second // used if context has no deadline // 如果上下文没有截止时间则使用此超时。设置建立与 RPC 服务器连接的默认超时时间，为 10 秒。如果发起连接的上下文中没有设置截止时间，则会使用这个默认的超时时间。
	subscribeTimeout   = 10 * time.Second // overall timeout eth_subscribe, rpc_modules calls  // eth_subscribe, rpc_modules 调用的总超时时间。设置与订阅相关的 RPC 方法（例如 eth_subscribe）以及获取 RPC 模块列表的方法（例如 rpc_modules）的总超时时间，为 10 秒。
	unsubscribeTimeout = 10 * time.Second // timeout for *_unsubscribe calls // *_unsubscribe 调用的超时时间。 设置取消订阅相关的 RPC 方法（例如 eth_unsubscribe）的超时时间，为 10 秒。
)

// 订阅移除： 当订阅者（客户端处理订阅事件的部分）无法及时处理服务器推送的事件，导致缓冲区满时，该订阅会被移除（断开）。
// 使用缓冲通道的替代方案： 注释提到了使用带有足够大小缓冲区的通道来解决这个问题，但指出这种方法存在一些缺点：
// 不方便且难以解释： 用户可能难以确定合适的缓冲区大小。
// 静态缓冲区： 即使大部分时间缓冲区可能不需要那么大，但其大小是固定的，可能会浪费内存。
// 当前采用的方法： 当前的实现采用每个订阅维护一个链表缓冲区，这个缓冲区可以根据实际需求动态缩小。
// 缓冲区大小限制： 如果这个缓冲区的大小达到了 maxClientSubscriptionBuffer 定义的值（20000），则认为订阅者无法跟上事件的推送速度，为了防止内存无限增长和保证客户端的稳定性，该订阅会被断开。

const (
	// Subscriptions are removed when the subscriber cannot keep up.
	//
	// This can be worked around by supplying a channel with sufficiently sized buffer,
	// but this can be inconvenient and hard to explain in the docs. Another issue with
	// buffered channels is that the buffer is static even though it might not be needed
	// most of the time.
	//
	// The approach taken here is to maintain a per-subscription linked list buffer
	// shrinks on demand. If the buffer reaches the size below, the subscription is
	// dropped.
	//
	// 当订阅者无法跟上时，订阅会被移除。
	//
	// 这可以通过提供一个具有足够大小缓冲区的通道来解决，
	// 但这可能很不方便，并且在文档中难以解释。缓冲通道的另一个问题是，
	// 即使在大部分时间可能不需要，缓冲区也是静态的。
	//
	// 这里采取的方法是维护一个每个订阅的链表缓冲区，该缓冲区可以根据需要缩小。
	// 如果缓冲区达到以下大小，则该订阅将被删除。
	maxClientSubscriptionBuffer = 20000
)

// BatchElem is an element in a batch request.
// BatchElem 是批量请求中的一个元素。
type BatchElem struct {
	Method string        // 要调用的方法名
	Args   []interface{} // 调用方法所需的参数列表
	// The result is unmarshaled into this field. Result must be set to a
	// non-nil pointer value of the desired type, otherwise the response will be
	// discarded.
	// 结果将被解组到此字段中。Result 必须设置为所需类型的非 nil 指针值，这是因为在接收到服务器的响应后，RPC 客户端会将响应结果反序列化（unmarshal）到这个指针指向的内存地址。如果 Result 不是指针或者为 nil，那么反序列化将无法进行或者会失败，导致响应被丢弃。
	// 否则响应将被丢弃。
	Result interface{}
	// Error is set if the server returns an error for this request, or if
	// unmarshalling into Result fails. It is not set for I/O errors.
	// 如果服务器为此请求返回错误，或者解组到 Result 失败，则设置 Error。
	// 它不会为 I/O 错误设置。
	Error error
}

// Client represents a connection to an RPC server.
// Client 表示与 RPC 服务器的连接。
type Client struct {
	idgen    func() ID // for subscriptions 用于订阅的 ID 生成器，主要用于标识订阅请求。
	isHTTP   bool      // connection type: http, ws or ipc  连接类型：http、ws 或 ipc
	services *serviceRegistry

	idCounter atomic.Uint32 // 原子计数器，用于生成请求 ID。 每个 JSON-RPC 请求都需要一个唯一的 ID，以便将响应与请求对应起来。这个计数器用于记录 ID。

	// This function, if non-nil, is called when the connection is lost.
	// 如果此函数非 nil，则在连接丢失时调用。
	reconnectFunc reconnectFunc //  对于 WebSocket 或 IPC 连接，如果连接中断，客户端通常需要自动或手动尝试重新连接到以太坊节点。

	// config fields
	// 配置字段
	batchItemLimit       int // 批量请求中允许的最大条目数。为了防止客户端发送过大的批量请求导致服务器压力过大，通常会设置一个限制。
	batchResponseMaxSize int // 批量响应的最大大小（字节数或其他单位）。限制批量响应的大小可以防止服务器返回过大的数据，影响客户端性能或网络带宽。

	// writeConn is used for writing to the connection on the caller's goroutine. It should
	// only be accessed outside of dispatch, with the write lock held. The write lock is
	// taken by sending on reqInit and released by sending on reqSent.
	//
	// writeConn 用于在调用者的 goroutine 上写入连接。只能在 dispatch 之外访问，
	// 并且持有写锁。写锁通过在 reqInit 上发送来获取，通过在 reqSent 上发送来释放。
	writeConn jsonWriter // 客户端需要将构造好的 JSON-RPC 请求发送给以太坊节点。writeConn 负责底层的写入操作。

	// for dispatch
	// 用于分发
	close       chan struct{}    // 用于通知客户端开始关闭，用于通知客户端的内部 goroutine 开始关闭。
	closing     chan struct{}    // closed when client is quitting 在客户端退出时关闭，可以用于通知其他部分客户端正在进行关闭操作。
	didClose    chan struct{}    // closed when client quits  在客户端退出后关闭，可以用于等待客户端完成清理工作。
	reconnected chan ServerCodec // where write/reconnect sends the new connection write/reconnect 将新的连接发送到这里。 在重新连接成功后，负责写入和重连的 goroutine 会将新的 ServerCodec（用于编码和解码 RPC 消息）发送到这个通道。
	readOp      chan readOp      // read messages  读取消息， 用于将从连接中读取到的消息（封装在 readOp 结构体中）发送给处理消息的 goroutine。
	readErr     chan error       // errors from read 来自读取操作的错误，用于将读取过程中发生的错误发送给错误处理的 goroutine。
	reqInit     chan *requestOp  // register response IDs, takes write lock        注册响应 ID，获取写锁， 在发送 RPC 请求前，需要记录请求的 ID，以便在收到响应时进行匹配。写锁用于保证在写入连接时的并发安全。
	reqSent     chan error       // signals write completion, releases write lock  信号写入完成，释放写锁
	reqTimeout  chan *requestOp  // removes response IDs when call timeout expires 当调用超时过期时移除响应 ID
}

// 在与以太坊节点建立连接（例如通过 WebSocket）时，如果连接中断，客户端可能需要尝试重新连接。
// 用于表示重新连接到 RPC 服务器的函数。它接收一个上下文对象，可能用于控制重连的超时或取消。成功重连后，它会返回一个 ServerCodec 接口的实现（用于编码和解码 RPC 消息）以及一个可能发生的错误。
type reconnectFunc func(context.Context) (ServerCodec, error)

// clientContextKey 是用于在上下文中存储客户端的键。
type clientContextKey struct{}

// clientConn 表示客户端连接，包含编解码器和处理程序。
// 在 go-ethereum 的 RPC 实现中，每个客户端连接（如 HTTP、WebSocket）需要独立的处理单元。
type clientConn struct {
	codec   ServerCodec // 编解码器实例，用于读写请求和响应。
	handler *handler    // 请求处理程序
}

// newClientConn 为给定的编解码器创建一个新的客户端连接。
func (c *Client) newClientConn(conn ServerCodec) *clientConn {
	ctx := context.Background()
	ctx = context.WithValue(ctx, clientContextKey{}, c)                                             // 将当前 *Client 实例存入上下文。
	ctx = context.WithValue(ctx, peerInfoContextKey{}, conn.peerInfo())                             // 将连接的对端信息（PeerInfo）存入上下文。
	handler := newHandler(ctx, conn, c.idgen, c.services, c.batchItemLimit, c.batchResponseMaxSize) // 创建处理程序，传入上下文、编解码器、ID 生成器、服务集合及批量限制参数。
	return &clientConn{conn, handler}
}

// close 关闭客户端连接，清理处理程序和编解码器。
func (cc *clientConn) close(err error, inflightReq *requestOp) {
	cc.handler.close(err, inflightReq) // 关闭处理程序，传递错误和未完成请求。
	cc.codec.close()                   // 关闭编解码器，终止底层连接。
}

type readOp struct {
	msgs  []*jsonrpcMessage // 读取到的 JSON-RPC 消息列表
	batch bool              // 指示读取到的是否为批量消息
}

// 当以太坊 RPC 客户端发送一个请求后，它需要等待服务器的响应。
// requestOp 结构体用于在等待期间存储请求的相关信息，包括请求的 ID、可能发生的错误、用于接收响应的通道以及与订阅相关的对象。
// 这使得客户端能够正确地将服务器的响应与发送的请求关联起来，并处理不同类型的请求（普通请求和订阅请求）。

// requestOp represents a pending request. This is used for both batch and non-batch
// requests.
// requestOp 表示一个待处理的请求。这用于批量和非批量请求。
type requestOp struct {
	ids         []json.RawMessage      // 请求的 ID 列表（批量请求可能包含多个 ID）
	err         error                  // 请求过程中发生的错误
	resp        chan []*jsonrpcMessage // the response goes here  响应将发送到这个通道
	sub         *ClientSubscription    // set for Subscribe requests.  如果是订阅请求，则设置此字段
	hadResponse bool                   // true when the request was responded to 指示请求是否已收到响应
}

// wait 等待请求操作的响应或上下文超时，返回响应消息或错误。
func (op *requestOp) wait(ctx context.Context, c *Client) ([]*jsonrpcMessage, error) {
	select {
	case <-ctx.Done():
		// 主要针对 WebSocket 或 IPC 等持久连接，HTTP 请求通常是同步的，不需要额外的超时通知机制。

		// Send the timeout to dispatch so it can remove the request IDs.
		// 如果不是 HTTP 请求，将超时发送到 dispatch 以便移除请求 ID。
		if !c.isHTTP { // 检查是否为非 HTTP 请求。
			select {
			case c.reqTimeout <- op: // 将超时请求发送到 reqTimeout 通道
			case <-c.closing: // 若客户端正在关闭，则退出。
			}
		}
		return nil, ctx.Err()
	case resp := <-op.resp:
		return resp, op.err
	}
}

// Dial creates a new client for the given URL.
//
// The currently supported URL schemes are "http", "https", "ws" and "wss". If rawurl is a
// file name with no URL scheme, a local socket connection is established using UNIX
// domain sockets on supported platforms and named pipes on Windows.
//
// If you want to further configure the transport, use DialOptions instead of this
// function.
//
// For websocket connections, the origin is set to the local host name.
//
// The client reconnects automatically when the connection is lost.
//
// Dial 为给定的 URL 创建一个新客户端。
// 当前支持的 URL 方案包括 "http"、"https"、"ws" 和 "wss"。如果 rawurl 是一个没有 URL 方案的文件名，则在支持的平台上使用 UNIX 域套接字，在 Windows 上使用命名管道建立本地套接字连接。
// 如果你想进一步配置传输，请使用 DialOptions 而不是此函数。
// 对于 WebSocket 连接，来源被设置为本地主机名。
// 客户端在连接丢失时会自动重连。
func Dial(rawurl string) (*Client, error) {
	return DialOptions(context.Background(), rawurl)
}

// DialContext creates a new RPC client, just like Dial.
//
// The context is used to cancel or time out the initial connection establishment. It does
// not affect subsequent interactions with the client.
//
// DialContext 创建一个新的 RPC 客户端，与 Dial 类似。
// 上下文用于取消或超时初始连接建立。它不会影响与客户端的后续交互。
func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	return DialOptions(ctx, rawurl)
}

// 在 go-ethereum 中，DialOptions 是连接以太坊节点的通用入口。以太坊节点通常暴露 JSON-RPC 接口（EIP-1474），支持多种传输协议：
//
// HTTP/HTTPS：用于简单的请求-响应调用，如 eth_getBalance。URL 示例：http://localhost:8545。
// WebSocket (ws/wss)：支持订阅功能（如 eth_subscribe），用于实时推送区块或事件数据。URL 示例：ws://localhost:8546。
// IPC：进程间通信，通常用于本地节点连接（如 Geth 的默认 IPC 文件路径 ./geth.ipc）。
// stdio：通过标准输入输出通信，可能用于测试或特殊场景。

// DialOptions creates a new RPC client for the given URL. You can supply any of the
// pre-defined client options to configure the underlying transport.
//
// The context is used to cancel or time out the initial connection establishment. It does
// not affect subsequent interactions with the client.
//
// The client reconnects automatically when the connection is lost.
//
// DialOptions 为给定的 URL 创建一个新的 RPC 客户端。你可以提供任何预定义的客户端选项来配置底层传输。
// 上下文用于取消或超时初始连接建立。它不会影响与客户端的后续交互。
// 客户端在连接丢失时会自动重连。
func DialOptions(ctx context.Context, rawurl string, options ...ClientOption) (*Client, error) {
	// 解析传入的 URL
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// 创建新的客户端配置
	cfg := new(clientConfig)
	// 应用所有传入的选项到配置中
	for _, opt := range options {
		opt.applyOption(cfg)
	}

	var reconnect reconnectFunc
	// 根据 URL 方案选择不同的传输方式
	switch u.Scheme {
	case "http", "https":
		reconnect = newClientTransportHTTP(rawurl, cfg)
	case "ws", "wss":
		rc, err := newClientTransportWS(rawurl, cfg)
		if err != nil {
			return nil, err
		}
		reconnect = rc
	case "stdio":
		reconnect = newClientTransportIO(os.Stdin, os.Stdout)
	case "":
		reconnect = newClientTransportIPC(rawurl)
	default:
		return nil, fmt.Errorf("no known transport for URL scheme %q", u.Scheme)
	}

	// 使用配置和重连函数创建客户端
	return newClient(ctx, cfg, reconnect)
}

// ClientFromContext retrieves the client from the context, if any. This can be used to perform
// 'reverse calls' in a handler method.
//
// ClientFromContext 从上下文中检索客户端（如果存在）。这可以用于在处理方法中执行“反向调用”。
func ClientFromContext(ctx context.Context) (*Client, bool) {
	client, ok := ctx.Value(clientContextKey{}).(*Client)
	return client, ok
}

// newClient 使用给定的配置和连接函数创建一个新客户端。
func newClient(initctx context.Context, cfg *clientConfig, connect reconnectFunc) (*Client, error) {
	// 调用连接函数建立连接
	conn, err := connect(initctx)
	if err != nil {
		return nil, err
	}
	// 初始化客户端实例
	c := initClient(conn, new(serviceRegistry), cfg)
	// 设置重连函数
	c.reconnectFunc = connect
	return c, nil
}

// initClient 使用给定的连接、服务注册表和配置初始化一个新的 Client 实例。
func initClient(conn ServerCodec, services *serviceRegistry, cfg *clientConfig) *Client {
	// 判断连接是否为 HTTP 连接
	_, isHTTP := conn.(*httpConn)
	c := &Client{
		isHTTP:               isHTTP,                 // 是否为 HTTP 客户端
		services:             services,               // 服务注册表
		idgen:                cfg.idgen,              // ID 生成器
		batchItemLimit:       cfg.batchItemLimit,     // 批处理请求项限制
		batchResponseMaxSize: cfg.batchResponseLimit, // 批处理响应最大大小
		writeConn:            conn,                   // 写入连接
		close:                make(chan struct{}),    // 关闭信号通道
		closing:              make(chan struct{}),    // 正在关闭信号通道
		didClose:             make(chan struct{}),    // 已关闭信号通道
		reconnected:          make(chan ServerCodec), // 重连信号通道
		readOp:               make(chan readOp),      // 读取操作通道
		readErr:              make(chan error),       // 读取错误通道
		reqInit:              make(chan *requestOp),  // 请求初始化通道
		reqSent:              make(chan error, 1),    // 请求发送结果通道（带缓冲）
		reqTimeout:           make(chan *requestOp),  // 请求超时通道
	}

	// Set defaults.
	// 设置默认值
	if c.idgen == nil {
		c.idgen = randomIDGenerator()
	}

	// Launch the main loop.
	// 启动主循环
	if !isHTTP {
		go c.dispatch(conn)
	}
	return c
}

// RegisterName creates a service for the given receiver type under the given name. When no
// methods on the given receiver match the criteria to be either a RPC method or a
// subscription an error is returned. Otherwise a new service is created and added to the
// service collection this client provides to the server.
//
// RegisterName 在给定名称下为给定的接收者类型创建服务。如果接收者上的方法不符合作为 RPC 方法或订阅的条件，则返回错误。
// 否则，将创建一个新服务并添加到此客户端提供给服务器的服务集合中。
func (c *Client) RegisterName(name string, receiver interface{}) error {
	return c.services.registerName(name, receiver)
}

func (c *Client) nextID() json.RawMessage {
	// 使用 idCounter 生成递增的 ID，并转换为 JSON 原始消息
	id := c.idCounter.Add(1)
	return strconv.AppendUint(nil, uint64(id), 10)
}

// SupportedModules calls the rpc_modules method, retrieving the list of
// APIs that are available on the server.
//
// SupportedModules 调用 rpc_modules 方法，检索服务器上可用的 API 列表。
func (c *Client) SupportedModules() (map[string]string, error) {
	var result map[string]string
	ctx, cancel := context.WithTimeout(context.Background(), subscribeTimeout)
	defer cancel()
	err := c.CallContext(ctx, &result, "rpc_modules")
	return result, err
}

// Close closes the client, aborting any in-flight requests.
// Close 关闭客户端，中止任何正在进行的请求。
func (c *Client) Close() {
	if c.isHTTP {
		return
	}
	select {
	case c.close <- struct{}{}: // 向 c.close 通道发送一个空结构体信号，表示开始关闭。
		<-c.didClose // 等待 c.didClose 通道返回信号，表示关闭完成。
	case <-c.didClose:
	}
}

// SetHeader adds a custom HTTP header to the client's requests.
// This method only works for clients using HTTP, it doesn't have
// any effect for clients using another transport.
//
// SetHeader 为客户端的请求添加自定义 HTTP 头。
// 此方法仅适用于使用 HTTP 的客户端，对于使用其他传输方式的客户端没有任何效果。
func (c *Client) SetHeader(key, value string) {
	if !c.isHTTP {
		return
	}
	conn := c.writeConn.(*httpConn)
	conn.mu.Lock()
	conn.headers.Set(key, value)
	conn.mu.Unlock()
}

// Call performs a JSON-RPC call with the given arguments and unmarshals into
// result if no error occurred.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
//
// Call 使用给定的参数执行 JSON-RPC 调用，并在没有错误发生时将结果反序列化到 result 中。
// result 必须是一个指针，以便 json 包可以将其反序列化。你也可以传递 nil，此时结果将被忽略。
func (c *Client) Call(result interface{}, method string, args ...interface{}) error {
	ctx := context.Background()
	return c.CallContext(ctx, result, method, args...)
}

// CallContext performs a JSON-RPC call with the given arguments. If the context is
// canceled before the call has successfully returned, CallContext returns immediately.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
//
// CallContext 使用给定的参数执行 JSON-RPC 调用。如果在调用成功返回之前上下文被取消，CallContext 会立即返回。
//
// 结果必须是一个指针，以便 json 包可以解码到其中。你也可以传递 nil，此时结果将被忽略。
func (c *Client) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	if result != nil && reflect.TypeOf(result).Kind() != reflect.Ptr {
		return fmt.Errorf("call result parameter must be pointer or nil interface: %v", result)
	}
	msg, err := c.newMessage(method, args...)
	if err != nil {
		return err
	}
	op := &requestOp{
		ids:  []json.RawMessage{msg.ID},
		resp: make(chan []*jsonrpcMessage, 1),
	}

	if c.isHTTP {
		err = c.sendHTTP(ctx, op, msg)
	} else {
		err = c.send(ctx, op, msg)
	}
	if err != nil {
		return err
	}

	// dispatch has accepted the request and will close the channel when it quits.
	// 分发器已接受请求，并将在退出时关闭通道。
	batchresp, err := op.wait(ctx, c)
	if err != nil {
		return err
	}
	resp := batchresp[0]
	switch {
	case resp.Error != nil:
		return resp.Error
	case len(resp.Result) == 0:
		return ErrNoResult
	default:
		if result == nil {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	}
}

// BatchCall sends all given requests as a single batch and waits for the server
// to return a response for all of them.
//
// In contrast to Call, BatchCall only returns I/O errors. Any error specific to
// a request is reported through the Error field of the corresponding BatchElem.
//
// Note that batch calls may not be executed atomically on the server side.
//
// BatchCall 将所有给定的请求作为一个批次发送，并等待服务器返回所有请求的响应。
//
// 与 Call 不同，BatchCall 仅返回 I/O 错误。任何特定于某个请求的错误通过对应 BatchElem 的 Error 字段报告。
//
// 注意，批量调用在服务器端可能不是原子执行的。
func (c *Client) BatchCall(b []BatchElem) error {
	ctx := context.Background()
	return c.BatchCallContext(ctx, b)
}

// BatchCallContext sends all given requests as a single batch and waits for the server
// to return a response for all of them. The wait duration is bounded by the
// context's deadline.
//
// In contrast to CallContext, BatchCallContext only returns errors that have occurred
// while sending the request. Any error specific to a request is reported through the
// Error field of the corresponding BatchElem.
//
// Note that batch calls may not be executed atomically on the server side.
//
// BatchCallContext 将所有给定的请求作为一个批次发送，并等待服务器返回所有请求的响应。
// 等待时长受上下文截止时间的限制。
//
// 与 CallContext 不同，BatchCallContext 仅返回发送请求时发生的错误。
// 任何特定于某个请求的错误通过对应 BatchElem 的 Error 字段报告。
//
// 注意，批处理调用在服务器端可能不是原子执行的。
//
// 用于将多个 JSON-RPC 请求作为一个批次发送，并等待服务器返回所有响应。
func (c *Client) BatchCallContext(ctx context.Context, b []BatchElem) error {
	var (
		msgs = make([]*jsonrpcMessage, len(b))
		byID = make(map[string]int, len(b)) // byID（ID 到索引的映射）
	)
	op := &requestOp{
		ids:  make([]json.RawMessage, len(b)),
		resp: make(chan []*jsonrpcMessage, 1),
	}
	for i, elem := range b {
		msg, err := c.newMessage(elem.Method, elem.Args...)
		if err != nil {
			return err
		}
		msgs[i] = msg
		op.ids[i] = msg.ID
		byID[string(msg.ID)] = i
	}

	var err error
	if c.isHTTP {
		err = c.sendBatchHTTP(ctx, op, msgs)
	} else {
		err = c.send(ctx, op, msgs)
	}
	if err != nil {
		return err
	}

	batchresp, err := op.wait(ctx, c)
	if err != nil {
		return err
	}

	// Wait for all responses to come back.
	// 等待所有响应返回。
	for n := 0; n < len(batchresp); n++ {
		resp := batchresp[n]
		if resp == nil {
			// Ignore null responses. These can happen for batches sent via HTTP.
			// 忽略空响应。这些可能在通过 HTTP 发送的批处理中发生。
			continue
		}

		// Find the element corresponding to this response.
		// 找到与此响应对应的元素。
		index, ok := byID[string(resp.ID)]
		if !ok {
			continue
		}
		delete(byID, string(resp.ID))

		// Assign result and error.
		// 分配结果和错误。
		elem := &b[index]
		switch {
		case resp.Error != nil:
			elem.Error = resp.Error
		case resp.Result == nil:
			elem.Error = ErrNoResult
		default:
			elem.Error = json.Unmarshal(resp.Result, elem.Result)
		}
	}

	// Check that all expected responses have been received.
	// 检查是否所有预期的响应都已接收。
	for _, index := range byID {
		elem := &b[index]
		elem.Error = ErrMissingBatchResponse
	}

	return err
}

// Notify sends a notification, i.e. a method call that doesn't expect a response.
// Notify 发送一个通知，即一个不期望响应的方法调用。
// 用于发送不需要响应的 JSON-RPC 通知。它是 go-ethereum RPC 客户端中实现单向通信的便捷接口，适用于不需要服务器确认的场景。
func (c *Client) Notify(ctx context.Context, method string, args ...interface{}) error {
	op := new(requestOp) // 用于注册到分发循环。
	msg, err := c.newMessage(method, args...)
	if err != nil {
		return err
	}
	msg.ID = nil // JSON-RPC 规范中，通知是没有 id 字段的请求，服务器不会返回响应。

	if c.isHTTP {
		return c.sendHTTP(ctx, op, msg)
	}
	return c.send(ctx, op, msg)
}

// EthSubscribe registers a subscription under the "eth" namespace.
// EthSubscribe 在 "eth" 命名空间下注册一个订阅。
func (c *Client) EthSubscribe(ctx context.Context, channel interface{}, args ...interface{}) (*ClientSubscription, error) {
	return c.Subscribe(ctx, "eth", channel, args...)
}

// ShhSubscribe registers a subscription under the "shh" namespace.
// Deprecated: use Subscribe(ctx, "shh", ...).
// ShhSubscribe 在 "shh" 命名空间下注册一个订阅。
// 已弃用：请使用 Subscribe(ctx, "shh", ...)。
// "shh" 是 Whisper 协议的命名空间，Whisper 是以太坊早期的去中心化消息协议。
func (c *Client) ShhSubscribe(ctx context.Context, channel interface{}, args ...interface{}) (*ClientSubscription, error) {
	return c.Subscribe(ctx, "shh", channel, args...)
}

// Subscribe calls the "<namespace>_subscribe" method with the given arguments,
// registering a subscription. Server notifications for the subscription are
// sent to the given channel. The element type of the channel must match the
// expected type of content returned by the subscription.
//
// The context argument cancels the RPC request that sets up the subscription but has no
// effect on the subscription after Subscribe has returned.
//
// Slow subscribers will be dropped eventually. Client buffers up to 20000 notifications
// before considering the subscriber dead. The subscription Err channel will receive
// ErrSubscriptionQueueOverflow. Use a sufficiently large buffer on the channel or ensure
// that the channel usually has at least one reader to prevent this issue.
//
// Subscribe 调用带有给定参数的 "<namespace>_subscribe" 方法，注册一个订阅。
// 服务器对该订阅的通知将被发送到给定的通道。通道的元素类型必须与订阅返回的预期内容类型匹配。
//
// 上下文参数会取消设置订阅的 RPC 请求，但对 Subscribe 返回后的订阅没有影响。
//
// 慢速订阅者最终会被丢弃。客户端最多缓冲 20000 个通知，之后会认为订阅者已死。订阅的 Err 通道将接收到 ErrSubscriptionQueueOverflow。
// 使用足够大的通道缓冲区或确保通道通常至少有一个读取器，以防止此问题。
// 用于向以太坊节点注册一个订阅（如监听新区块或事件），并将服务器通知发送到指定的通道。
func (c *Client) Subscribe(ctx context.Context, namespace string, channel interface{}, args ...interface{}) (*ClientSubscription, error) {
	// Check type of channel first.
	// 首先检查通道的类型。
	chanVal := reflect.ValueOf(channel)
	// 确保是通道类型 || 确保通道可写（支持发送方向）
	if chanVal.Kind() != reflect.Chan || chanVal.Type().ChanDir()&reflect.SendDir == 0 {
		panic(fmt.Sprintf("channel argument of Subscribe has type %T, need writable channel", channel))
	}
	if chanVal.IsNil() {
		panic("channel given to Subscribe must not be nil")
	}
	if c.isHTTP { // HTTP 不支持订阅。
		return nil, ErrNotificationsUnsupported
	}

	// 构造订阅消息
	// 方法名：namespace + subscribeMethodSuffix（如 eth_subscribe）
	msg, err := c.newMessage(namespace+subscribeMethodSuffix, args...)
	if err != nil {
		return nil, err
	}
	// 创建请求操作
	op := &requestOp{
		ids:  []json.RawMessage{msg.ID},                    // 包含订阅消息的 ID。
		resp: make(chan []*jsonrpcMessage, 1),              // 容量为 1 的通道，用于接收订阅确认响应。
		sub:  newClientSubscription(c, namespace, chanVal), // 通过 newClientSubscription 创建订阅对象。
	}

	// Send the subscription request.
	// The arrival and validity of the response is signaled on sub.quit.
	// 发送订阅请求。
	// 响应的到达和有效性通过 sub.quit 信号通知。
	if err := c.send(ctx, op, msg); err != nil {
		return nil, err
	}
	// 等待服务器确认
	if _, err := op.wait(ctx, c); err != nil {
		return nil, err
	}
	return op.sub, nil
}

// SupportsSubscriptions reports whether subscriptions are supported by the client
// transport. When this returns false, Subscribe and related methods will return
// ErrNotificationsUnsupported.
//
// SupportsSubscriptions 报告客户端传输是否支持订阅。
// 当返回 false 时，Subscribe 及相关方法将返回 ErrNotificationsUnsupported。
// 用于检查客户端的传输协议是否支持订阅功能。
func (c *Client) SupportsSubscriptions() bool {
	return !c.isHTTP
}

func (c *Client) newMessage(method string, paramsIn ...interface{}) (*jsonrpcMessage, error) {
	msg := &jsonrpcMessage{Version: vsn, ID: c.nextID(), Method: method}
	if paramsIn != nil { // prevent sending "params":null 防止发送 "params":null
		var err error
		if msg.Params, err = json.Marshal(paramsIn); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// send registers op with the dispatch loop, then sends msg on the connection.
// if sending fails, op is deregistered.
//
// send 将 op 注册到分发循环中，然后在连接上发送 msg。
// 如果发送失败，op 会被取消注册。
// 用于将 JSON-RPC 请求注册到分发循环并发送消息。
func (c *Client) send(ctx context.Context, op *requestOp, msg interface{}) error {
	select {
	case c.reqInit <- op: // 将 op 发送到分发循环的初始化通道。
		err := c.write(ctx, msg, false)
		c.reqSent <- err // 将写入结果（err）发送到 c.reqSent 通道，通知分发循环。
		return err
	case <-ctx.Done(): // 上下文取消或超时的信号。
		// This can happen if the client is overloaded or unable to keep up with
		// subscription notifications.
		// 如果客户端过载或无法跟上订阅通知，可能会发生这种情况。
		return ctx.Err()
	case <-c.closing: // 客户端关闭的信号。
		return ErrClientQuit
	}
}

// 用于向服务器写入 JSON-RPC 消息。支持重连和重试机制，确保消息可靠传输。
func (c *Client) write(ctx context.Context, msg interface{}, retry bool) error {
	if c.writeConn == nil {
		// The previous write failed. Try to establish a new connection.
		// 上一次写入失败。尝试建立新连接。
		if err := c.reconnect(ctx); err != nil {
			return err
		}
	}
	err := c.writeConn.writeJSON(ctx, msg, false)
	if err != nil {
		c.writeConn = nil
		if !retry {
			return c.write(ctx, msg, true)
		}
	}
	return err
}

// 用于在连接断开后尝试重新建立与服务器的连接。它是 go-ethereum RPC 客户端中处理连接恢复的关键逻辑，通常在检测到连接错误后调用。
func (c *Client) reconnect(ctx context.Context) error {
	if c.reconnectFunc == nil {
		return errDead
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, defaultDialTimeout)
		defer cancel()
	}
	// 尝试建立新连接
	newconn, err := c.reconnectFunc(ctx)
	if err != nil {
		log.Trace("RPC client reconnect failed", "err", err)
		return err
	}
	select {
	case c.reconnected <- newconn: // 将 newconn 发送到 c.reconnected 通道，更新 c.writeConn 为新连接，返回 nil
		c.writeConn = newconn
		return nil
	case <-c.didClose: // 如果 c.didClose 通道收到信号（表示客户端已关闭），关闭新连接并返回 ErrClientQuit。
		newconn.close()
		return ErrClientQuit
	}
}

// dispatch is the main loop of the client.
// It sends read messages to waiting calls to Call and BatchCall
// and subscription notifications to registered subscriptions.
//
// dispatch 是客户端的主循环。
// 它将读取的消息发送给等待的 Call 和 BatchCall 调用，
// 以及将订阅通知发送给已注册的订阅。
//
// 负责协调客户端的读取、发送和重连逻辑。
// 它是 go-ethereum RPC 客户端的核心，处理 JSON-RPC 请求和响应的分发，包括普通调用（Call）、批量调用（BatchCall）和订阅通知。
func (c *Client) dispatch(codec ServerCodec) {
	var (
		lastOp      *requestOp  // tracks last send operation 跟踪上一次发送操作
		reqInitLock = c.reqInit // nil while the send lock is held 在持有发送锁时为 nil
		conn        = c.newClientConn(codec)
		reading     = true // 标记是否在读取状态。
	)
	defer func() {
		close(c.closing)
		if reading {
			conn.close(ErrClientQuit, nil)
			c.drainRead()
		}
		close(c.didClose)
	}()

	// Spawn the initial read loop.
	// 启动初始读取循环。
	go c.read(codec) // 异步读取服务器消息。

	for {
		select {
		case <-c.close: // 关闭信号，退出循环。
			return

		// Read path:
		// 读取路径：
		case op := <-c.readOp: // 读取消息 (c.readOp)：分发单消息或批量消息。接收的消息来自 read 方法，支持单请求和批量请求
			if op.batch {
				conn.handler.handleBatch(op.msgs)
			} else {
				conn.handler.handleMsg(op.msgs[0])
			}

		case err := <-c.readErr: // 读取错误 (c.readErr)：关闭连接并标记读取结束。
			conn.handler.log.Debug("RPC connection read error", "err", err)
			conn.close(err, lastOp)
			reading = false

		// Reconnect:
		// 重连：
		case newcodec := <-c.reconnected: // 重连 (c.reconnected)：切换到新连接并重新注册请求。
			log.Debug("RPC client reconnected", "reading", reading, "conn", newcodec.remoteAddr())
			if reading {
				// Wait for the previous read loop to exit. This is a rare case which
				// happens if this loop isn't notified in time after the connection breaks.
				// In those cases the caller will notice first and reconnect. Closing the
				// handler terminates all waiting requests (closing op.resp) except for
				// lastOp, which will be transferred to the new handler.
				//
				// 等待之前的读取循环退出。这是一个罕见的情况，发生在连接断开后此循环未及时收到通知时。
				// 在这些情况下，调用者会首先注意到并重连。关闭处理程序会终止所有等待的请求（关闭 op.resp），
				// 除了 lastOp，它将被转移到新的处理程序。
				conn.close(errClientReconnected, lastOp)
				c.drainRead()
			}
			go c.read(newcodec)
			reading = true
			conn = c.newClientConn(newcodec)
			// Re-register the in-flight request on the new handler
			// because that's where it will be sent.
			//
			// 在新处理程序上重新注册飞行中的请求，
			// 因为那将是发送请求的地方。
			conn.handler.addRequestOp(lastOp)

		// Send path:
		// 发送路径：
		case op := <-reqInitLock: // 发送请求 (reqInitLock)：添加新请求并锁定。
			// Stop listening for further requests until the current one has been sent.
			// 在当前请求发送完成之前，停止监听其他请求。
			reqInitLock = nil
			lastOp = op
			conn.handler.addRequestOp(op)

		case err := <-c.reqSent: // 请求发送完成 (c.reqSent)：处理发送结果并解锁。
			if err != nil {
				// Remove response handlers for the last send. When the read loop
				// goes down, it will signal all other current operations.
				// 移除上一次发送的响应处理程序。当读取循环停止时，它会通知所有其他当前操作。
				conn.handler.removeRequestOp(lastOp)
			}
			// Let the next request in.
			// 允许下一个请求进入。
			reqInitLock = c.reqInit
			lastOp = nil

		case op := <-c.reqTimeout: // 请求超时 (c.reqTimeout)：移除超时的请求。
			conn.handler.removeRequestOp(op)
		}
	}
}

// drainRead drops read messages until an error occurs.
// drainRead 丢弃读取的消息，直到发生错误为止。
//
// 用于清空读取通道中的消息，直到遇到错误。它通常在客户端关闭或重置连接时使用，以避免遗留消息干扰后续操作。
// 当连接断开或重置时，通道中可能残留未处理的消息或错误，drainRead 确保这些数据被清空，避免影响新的连接。
func (c *Client) drainRead() {
	for {
		select {
		case <-c.readOp:
		case <-c.readErr:
			return
		}
	}
}

// read decodes RPC messages from a codec, feeding them into dispatch.
// read 从编解码器中解码 RPC 消息，并将它们送入分发处理。
// 用于从 ServerCodec 中持续读取 JSON-RPC 消息，并将结果发送到客户端的通道。
// 它是 go-ethereum 中客户端处理服务器响应的关键部分，通常在独立的 goroutine 中运行。
func (c *Client) read(codec ServerCodec) {
	for {
		msgs, batch, err := codec.readBatch() // 读取消息。
		// 如果错误是 *json.SyntaxError（JSON 语法错误），构造一个错误消息（msg）并通过 codec.writeJSON 发送回服务器，标记为错误响应（true）。
		if _, ok := err.(*json.SyntaxError); ok {
			msg := errorMessage(&parseError{err.Error()})
			codec.writeJSON(context.Background(), msg, true)
		}
		// 如果发生任何错误（包括语法错误或其他），将错误发送到 c.readErr 通道并退出函数。
		if err != nil {
			c.readErr <- err
			return
		}
		// 将读取到的消息和批量标志封装为 readOp 结构体，发送到 c.readOp 通道。
		c.readOp <- readOp{msgs, batch}
	}
}
