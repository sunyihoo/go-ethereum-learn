// Copyright 2019 The go-ethereum Authors
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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// handler 作用：
// 客户端： 在客户端中，handler 主要负责发送 RPC 请求到以太坊节点，并将接收到的响应与发送的请求进行匹配（通过 respWait）。它也管理着客户端发起的订阅 (clientSubs)。
// 服务器端（例如，在以太坊节点中）： 在服务器端，handler 接收来自客户端的 RPC 请求，通过 reg 找到对应的处理函数并执行，然后将结果通过 conn 发送回客户端。它也负责管理服务器端维护的订阅 (serverSubs)。

// handler handles JSON-RPC messages. There is one handler per connection. Note that
// handler is not safe for concurrent use. Message handling never blocks indefinitely
// because RPCs are processed on background goroutines launched by handler.
//
// The entry points for incoming messages are:
//
//	h.handleMsg(message)
//	h.handleBatch(message)
//
// Outgoing calls use the requestOp struct. Register the request before sending it
// on the connection:
//
//	op := &requestOp{ids: ...}
//	h.addRequestOp(op)
//
// Now send the request, then wait for the reply to be delivered through handleMsg:
//
//	if err := op.wait(...); err != nil {
//		h.removeRequestOp(op) // timeout, etc.
//	}
//
// handler 处理 JSON-RPC 消息。每个连接都有一个 handler 实例。注意，
// handler 不是并发安全的。消息处理永远不会无限期地阻塞，因为 RPC 调用
// 在 handler 启动的后台 goroutine 中处理。
//
// 传入消息的入口点是：
//
//	h.handleMsg(message)
//	h.handleBatch(message)
//
// 发出调用使用 requestOp 结构体。在连接上发送之前注册请求：
//
//	op := &requestOp{ids: ...}
//	h.addRequestOp(op)
//
// 现在发送请求，然后等待通过 handleMsg 传递回复：
//
//	if err := op.wait(...); err != nil {
//	   h.removeRequestOp(op) // 超时等
//	}
type handler struct {
	reg                  *serviceRegistry               // 指向 serviceRegistry 的指针，用于查找和调用与接收到的 RPC 方法名对应的处理函数。这通常在 RPC 服务器端使用。
	unsubscribeCb        *callback                      // 指向 callback 结构体的指针，可能用于在取消订阅时执行特定的回调函数。
	idgen                func() ID                      // subscription ID generator    订阅 ID 生成器
	respWait             map[string]*requestOp          // active client requests       活跃的客户端请求，用于将服务器的响应与客户端发起的请求进行匹配。
	clientSubs           map[string]*ClientSubscription // active client subscriptions  活跃的客户端订阅，用于管理订阅的生命周期和接收事件。
	callWG               sync.WaitGroup                 // pending call goroutines      待处理的调用 goroutine，用于等待所有正在处理的 RPC 调用 goroutine 完成。这通常在关闭连接时使用，以确保所有未完成的请求都得到处理或清理。
	rootCtx              context.Context                // canceled by close()          通过 close() 取消，用于控制所有与此连接相关的操作的生命周期。
	cancelRoot           func()                         // cancel function for rootCtx  用于 rootCtx 的取消函数，用于取消 rootCtx 的函数。
	conn                 jsonWriter                     // where responses will be sent 响应将发送到这里，用于将 JSON 响应写入到连接中。
	log                  log.Logger
	allowSubscribe       bool // 指示此 handler 是否允许处理订阅请求。
	batchRequestLimit    int  // 允许在单个批量请求中包含的最大请求数。
	batchResponseMaxSize int  //  允许为单个批量响应生成的最大大小。

	subLock    sync.Mutex           // 用于保护对 serverSubs map 的并发访问。
	serverSubs map[ID]*Subscription // 存储了服务器端已建立的订阅。
}

type callProc struct {
	ctx       context.Context // 用于控制 RPC 调用生命周期的上下文
	notifiers []*Notifier     // 用于存储与此调用相关的通知器（例如，用于订阅）的切片。在 JSON-RPC 中，客户端可以订阅某些事件（例如，新的区块头）。当服务器端发生这些事件时，需要通过某种机制通知所有订阅的客户端。
}

func newHandler(connCtx context.Context, conn jsonWriter, idgen func() ID, reg *serviceRegistry, batchRequestLimit, batchResponseMaxSize int) *handler {
	rootCtx, cancelRoot := context.WithCancel(connCtx) // 基于连接上下文创建一个可取消的根上下文
	h := &handler{
		reg:                  reg,   // 设置服务注册表
		idgen:                idgen, // 设置 ID 生成器
		conn:                 conn,  // 设置连接写入器
		respWait:             make(map[string]*requestOp),
		clientSubs:           make(map[string]*ClientSubscription),
		rootCtx:              rootCtx,    // 设置根上下文
		cancelRoot:           cancelRoot, // 设置根上下文的取消函数
		allowSubscribe:       true,       // 默认允许订阅
		serverSubs:           make(map[ID]*Subscription),
		log:                  log.Root(),           // 获取根日志记录器
		batchRequestLimit:    batchRequestLimit,    // 设置批量请求限制
		batchResponseMaxSize: batchResponseMaxSize, // 设置批量响应最大大小
	}
	if conn.remoteAddr() != "" { // 如果连接有远程地址
		h.log = h.log.New("conn", conn.remoteAddr()) // 创建一个新的日志记录器，包含连接的远程地址
	}
	h.unsubscribeCb = newCallback(reflect.Value{}, reflect.ValueOf(h.unsubscribe)) // 创建取消订阅的回调函数
	return h
}

// batchCallBuffer manages in progress call messages and their responses during a batch
// call. Calls need to be synchronized between the processing and timeout-triggering
// goroutines.
//
// batchCallBuffer 管理批量调用期间正在处理的调用消息及其响应。
// 调用需要在处理 goroutine 和超时触发 goroutine 之间同步。
type batchCallBuffer struct {
	mutex sync.Mutex
	calls []*jsonrpcMessage // 批量调用中的消息列表
	resp  []*jsonrpcMessage // 批量调用的响应列表
	wrote bool              // 指示响应是否已写入
}

// nextCall returns the next unprocessed message.
// nextCall 返回下一个未处理的消息。
func (b *batchCallBuffer) nextCall() *jsonrpcMessage {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if len(b.calls) == 0 {
		return nil
	}
	// The popping happens in `pushAnswer`. The in progress call is kept
	// so we can return an error for it in case of timeout.
	// 弹出操作发生在 `pushResponse` 中。正在处理的调用被保留，
	// 这样在超时的情况下我们可以为其返回错误。
	msg := b.calls[0] // 表示下一个待处理的消息
	return msg
}

// pushResponse adds the response to last call returned by nextCall.
// pushResponse 将响应添加到 nextCall 返回的最后一个调用。
// 将一个调用的响应添加到 b.resp 列表中，并将对应的调用从 b.calls 列表中移除。
func (b *batchCallBuffer) pushResponse(answer *jsonrpcMessage) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if answer != nil {
		b.resp = append(b.resp, answer)
	}
	b.calls = b.calls[1:]
}

// write sends the responses.
// write 发送响应。
//
// 将 b.resp 中累积的所有响应写入到连接中。
func (b *batchCallBuffer) write(ctx context.Context, conn jsonWriter) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.doWrite(ctx, conn, false)
}

// respondWithError sends the responses added so far. For the remaining unanswered call
// messages, it responds with the given error.
// respondWithError 发送到目前为止添加的响应。对于剩余的未响应的调用消息，它使用给定的错误进行响应。
//
// 处理批量调用中发生错误的情况。它会发送已经得到的响应，并为所有尚未得到响应的非通知类型的调用生成错误响应并发送。
func (b *batchCallBuffer) respondWithError(ctx context.Context, conn jsonWriter, err error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	for _, msg := range b.calls {
		if !msg.isNotification() { // 如果消息不是通知（notification，即没有 ID 的请求），则调用 msg.errorResponse(err) 为其创建一个包含错误的响应，并添加到 b.resp 列表中。
			b.resp = append(b.resp, msg.errorResponse(err))
		}
	}
	b.doWrite(ctx, conn, true)
}

// doWrite actually writes the response.
// This assumes b.mutex is held.
// doWrite 实际写入响应。
// 这假定 b.mutex 已被持有
func (b *batchCallBuffer) doWrite(ctx context.Context, conn jsonWriter, isErrorResponse bool) {
	if b.wrote {
		return
	}
	b.wrote = true // can only write once  只能写入一次
	if len(b.resp) > 0 {
		conn.writeJSON(ctx, b.resp, isErrorResponse)
	}
}

// handleBatch executes all messages in a batch and returns the responses.
// handleBatch 执行批处理中的所有消息并返回响应。
func (h *handler) handleBatch(msgs []*jsonrpcMessage) {
	// Emit error response for empty batches:
	// 为空批处理发送错误响应：
	if len(msgs) == 0 {
		h.startCallProc(func(cp *callProc) {
			resp := errorMessage(&invalidRequestError{"empty batch"})
			h.conn.writeJSON(cp.ctx, resp, true)
		})
		return
	}
	// Apply limit on total number of requests.
	// 应用对请求总数的限制。
	if h.batchRequestLimit != 0 && len(msgs) > h.batchRequestLimit {
		h.startCallProc(func(cp *callProc) {
			h.respondWithBatchTooLarge(cp, msgs)
		})
		return
	}

	// Handle non-call messages first.
	// Here we need to find the requestOp that sent the request batch.
	// 首先处理非调用消息。
	// 这里我们需要找到发送请求批处理的 requestOp。
	calls := make([]*jsonrpcMessage, 0, len(msgs))
	h.handleResponses(msgs, func(msg *jsonrpcMessage) {
		calls = append(calls, msg)
	})
	if len(calls) == 0 {
		return
	}

	// Process calls on a goroutine because they may block indefinitely:
	// 在一个 goroutine 中处理调用，因为它们可能会无限期地阻塞：
	h.startCallProc(func(cp *callProc) {
		var (
			timer      *time.Timer
			cancel     context.CancelFunc
			callBuffer = &batchCallBuffer{calls: calls, resp: make([]*jsonrpcMessage, 0, len(calls))}
		)

		cp.ctx, cancel = context.WithCancel(cp.ctx)
		defer cancel()

		// Cancel the request context after timeout and send an error response. Since the
		// currently-running method might not return immediately on timeout, we must wait
		// for the timeout concurrently with processing the request.
		// 超时后取消请求上下文并发送错误响应。由于当前运行的方法可能不会立即在超时时返回，
		// 我们必须与处理请求并发地等待超时。
		if timeout, ok := ContextRequestTimeout(cp.ctx); ok {
			timer = time.AfterFunc(timeout, func() {
				cancel()
				err := &internalServerError{errcodeTimeout, errMsgTimeout}
				callBuffer.respondWithError(cp.ctx, h.conn, err)
			})
		}

		responseBytes := 0
		for {
			// No need to handle rest of calls if timed out.
			// 如果超时，则无需处理其余调用。
			if cp.ctx.Err() != nil {
				break
			}
			msg := callBuffer.nextCall()
			if msg == nil {
				break
			}
			resp := h.handleCallMsg(cp, msg)
			callBuffer.pushResponse(resp)
			if resp != nil && h.batchResponseMaxSize != 0 {
				responseBytes += len(resp.Result)
				if responseBytes > h.batchResponseMaxSize {
					err := &internalServerError{errcodeResponseTooLarge, errMsgResponseTooLarge}
					callBuffer.respondWithError(cp.ctx, h.conn, err)
					break
				}
			}
		}
		if timer != nil {
			timer.Stop()
		}

		h.addSubscriptions(cp.notifiers)
		callBuffer.write(cp.ctx, h.conn)
		for _, n := range cp.notifiers {
			n.activate()
		}
	})
}

func (h *handler) respondWithBatchTooLarge(cp *callProc, batch []*jsonrpcMessage) {
	resp := errorMessage(&invalidRequestError{errMsgBatchTooLarge})
	// Find the first call and add its "id" field to the error.
	// This is the best we can do, given that the protocol doesn't have a way
	// of reporting an error for the entire batch.
	// 找到第一个调用并在错误中添加其 "id" 字段。
	// 鉴于协议没有报告整个批处理错误的方法，这是我们能做的最好的。
	//
	// 由于 JSON-RPC 协议本身没有针对整个批处理请求的错误报告机制，该函数会遍历批处理中的消息，找到第一个类型为调用 (msg.isCall()) 的消息，
	// 并将其 ID (msg.ID) 设置为错误响应的 ID (resp.ID). 这是一个尽力而为的做法，旨在为客户端提供一些关于哪个批处理（至少是其中的第一个请求）导致了错误的信息。
	for _, msg := range batch {
		if msg.isCall() {
			resp.ID = msg.ID
			break
		}
	}
	h.conn.writeJSON(cp.ctx, []*jsonrpcMessage{resp}, true)
}

// handleMsg handles a single non-batch message.
// handleMsg 处理单个非批量消息。
func (h *handler) handleMsg(msg *jsonrpcMessage) {
	msgs := []*jsonrpcMessage{msg}
	h.handleResponses(msgs, func(msg *jsonrpcMessage) {
		h.startCallProc(func(cp *callProc) {
			h.handleNonBatchCall(cp, msg)
		})
	})
}

func (h *handler) handleNonBatchCall(cp *callProc, msg *jsonrpcMessage) {
	var (
		responded sync.Once
		timer     *time.Timer
		cancel    context.CancelFunc
	)
	cp.ctx, cancel = context.WithCancel(cp.ctx)
	defer cancel()

	// Cancel the request context after timeout and send an error response. Since the
	// running method might not return immediately on timeout, we must wait for the
	// timeout concurrently with processing the request.
	// 如果请求上下文有超时设置，则在超时后取消请求上下文并发送错误响应。由于运行的方法可能不会立即在超时时返回，因此我们必须在处理请求的同时等待超时。
	if timeout, ok := ContextRequestTimeout(cp.ctx); ok {
		timer = time.AfterFunc(timeout, func() {
			cancel()
			responded.Do(func() {
				resp := msg.errorResponse(&internalServerError{errcodeTimeout, errMsgTimeout})
				h.conn.writeJSON(cp.ctx, resp, true)
			})
		})
	}

	answer := h.handleCallMsg(cp, msg)
	if timer != nil {
		timer.Stop()
	}
	h.addSubscriptions(cp.notifiers)
	if answer != nil {
		responded.Do(func() {
			h.conn.writeJSON(cp.ctx, answer, false)
		})
	}
	for _, n := range cp.notifiers {
		n.activate()
	}
}

// close cancels all requests except for inflightReq and waits for
// call goroutines to shut down.
//
// close 取消除了 inflightReq 之外的所有请求，并等待调用 goroutine 关闭。
func (h *handler) close(err error, inflightReq *requestOp) {
	h.cancelAllRequests(err, inflightReq)
	h.callWG.Wait()
	h.cancelRoot()
	h.cancelServerSubscriptions(err)
}

// addRequestOp registers a request operation.
// addRequestOp 注册一个请求操作。
func (h *handler) addRequestOp(op *requestOp) {
	for _, id := range op.ids { // 遍历请求操作中的所有 ID
		h.respWait[string(id)] = op // 将请求操作以 ID 的字符串形式为键存储到 respWait map 中
	}
}

// removeRequestOp stops waiting for the given request IDs.
// removeRequestOp 停止等待给定的请求 ID。
func (h *handler) removeRequestOp(op *requestOp) {
	for _, id := range op.ids { // 遍历请求操作中的所有 ID
		delete(h.respWait, string(id)) // 从 respWait map 中删除以 ID 的字符串形式为键的条目
	}
}

// 在以太坊的 JSON-RPC API 中，客户端可能会发起多个并发请求，或者建立长时间的订阅连接。
// 当连接断开、服务器关闭或者发生错误时，服务器需要妥善地清理这些未完成的请求和活跃的订阅，以避免资源泄露或者客户端一直处于等待状态。

// cancelAllRequests unblocks and removes pending requests and active subscriptions.
// cancelAllRequests 解除阻塞并移除待处理的请求和活跃的订阅。
//
// 清理所有正在等待响应的请求和所有活跃的客户端订阅。这通常在处理程序需要关闭或者遇到错误需要中断所有正在进行的操作时被调用。
func (h *handler) cancelAllRequests(err error, inflightReq *requestOp) {
	didClose := make(map[*requestOp]bool) // 创建一个 map 来记录已经关闭响应通道的请求操作
	if inflightReq != nil {               // 如果有正在处理中的请求
		didClose[inflightReq] = true // 将其标记为已关闭
	}

	for id, op := range h.respWait { // 遍历等待响应的请求 map
		// Remove the op so that later calls will not close op.resp again.
		// 移除该操作，这样后续的调用就不会再次关闭 op.resp 了。
		delete(h.respWait, id)

		if !didClose[op] { // 如果该请求操作的响应通道尚未关闭
			op.err = err        // 设置请求操作的错误
			close(op.resp)      // 关闭请求操作的响应通道，解除等待该响应的 goroutine 的阻塞
			didClose[op] = true // 将该请求操作标记为已关闭
		}
	}
	for id, sub := range h.clientSubs { // 遍历活跃的客户端订阅 map
		delete(h.clientSubs, id) // 从 map 中删除该订阅
		sub.close(err)           // 调用订阅的 close 方法，并传递错误信息
	}
}

func (h *handler) addSubscriptions(nn []*Notifier) {
	h.subLock.Lock()
	defer h.subLock.Unlock()

	for _, n := range nn {
		if sub := n.takeSubscription(); sub != nil {
			h.serverSubs[sub.ID] = sub
		}
	}
}

// cancelServerSubscriptions removes all subscriptions and closes their error channels.
// cancelServerSubscriptions 移除所有服务器端订阅并关闭它们的错误通道。
// 用于清理所有由服务器端维护的订阅。这通常在服务关闭或者需要清理资源时被调用。
func (h *handler) cancelServerSubscriptions(err error) {
	h.subLock.Lock()
	defer h.subLock.Unlock()

	for id, s := range h.serverSubs { // 遍历服务器端订阅 map
		s.err <- err             // 向订阅的错误通道发送错误信息，通知订阅相关的 goroutine 停止
		close(s.err)             // 关闭订阅的错误通道，防止资源泄露
		delete(h.serverSubs, id) // 从服务器端订阅 map 中删除该订阅
	}
}

// startCallProc runs fn in a new goroutine and starts tracking it in the h.calls wait group.
// startCallProc 在一个新的 goroutine 中运行 fn，并开始在 h.calls wait group 中跟踪它。
func (h *handler) startCallProc(fn func(*callProc)) {
	h.callWG.Add(1) // 增加等待组的计数器，表示启动了一个新的 goroutine
	go func() {
		ctx, cancel := context.WithCancel(h.rootCtx) // 基于根上下文创建一个可取消的子上下文
		defer h.callWG.Done()                        // 在 goroutine 结束时，减少等待组的计数器
		defer cancel()                               // 在 goroutine 结束时，取消子上下文
		fn(&callProc{ctx: ctx})                      // 创建一个新的 callProc 实例，并将子上下文传递给 fn 函数
	}()
}

// 在以太坊的 JSON-RPC API 中，客户端可以发送单个请求，也可以发送批量的请求。服务器在处理完这些请求后，会返回一个包含所有响应的数组。handleResponses 函数负责处理服务器返回的这批响应。
//
// h.respWait: 用于存储等待响应的请求操作，通常以请求的 ID 为键。
// 订阅处理: 特别关注了订阅请求的响应。当客户端调用 eth_subscribe 并收到成功响应时，响应中会包含一个订阅 ID。服务器需要记录这个订阅 ID，并在后续有新的事件发生时，向该客户端发送订阅通知。handleResponses 函数在解析到订阅 ID 后，会启动订阅的运行，并将订阅信息存储到 h.clientSubs 中。
// 订阅通知: 服务器主动向客户端发送的订阅事件通知，其方法名通常会带有特定的后缀（notificationMethodSuffix），以便与普通的 RPC 调用区分开。handleSubscriptionResult 函数专门用于处理这类通知。
// 意外响应: 如果收到的响应消息的 ID 在 h.respWait 中找不到对应的请求操作，则认为这是一个意外的响应，会记录一条调试日志。

// handleResponses processes method call responses.
// handleResponses 处理方法调用的响应。
func (h *handler) handleResponses(batch []*jsonrpcMessage, handleCall func(*jsonrpcMessage)) {
	var resolvedops []*requestOp // 存储已处理响应的请求操作
	handleResp := func(msg *jsonrpcMessage) {
		op := h.respWait[string(msg.ID)] // 根据消息 ID 从等待响应的 map 中查找对应的请求操作
		if op == nil {
			h.log.Debug("Unsolicited RPC response", "reqid", idForLog{msg.ID})
			return
		}
		resolvedops = append(resolvedops, op) // 将已处理响应的请求操作添加到 resolvedops 切片
		delete(h.respWait, string(msg.ID))    // 从等待响应的 map 中删除该请求操作

		// For subscription responses, start the subscription if the server
		// indicates success. EthSubscribe gets unblocked in either case through
		// the op.resp channel.
		// 对于订阅响应，如果服务器指示成功，则启动订阅。EthSubscribe 在任何情况下都会通过 op.resp 通道解除阻塞。
		if op.sub != nil {
			if msg.Error != nil { // 如果响应包含错误
				op.err = msg.Error // 将错误信息设置到请求操作中
			} else { // 如果响应成功
				op.err = json.Unmarshal(msg.Result, &op.sub.subid) // 将订阅 ID 从响应结果中解析出来
				if op.err == nil {                                 // 如果解析成功
					go op.sub.run()                     // 启动订阅的运行
					h.clientSubs[op.sub.subid] = op.sub // 将订阅添加到客户端订阅 map 中
				}
			}
		}

		if !op.hadResponse { // 如果请求操作还没有收到响应
			op.hadResponse = true // 标记为已收到响应
			op.resp <- batch      // 将整个批处理消息发送到请求操作的响应通道
		}
	}

	for _, msg := range batch { // 遍历批处理中的每个消息
		start := time.Now() // 记录处理开始时间
		switch {
		case msg.isResponse(): // 如果消息是响应
			handleResp(msg) // 处理响应
			h.log.Trace("Handled RPC response", "reqid", idForLog{msg.ID}, "duration", time.Since(start))

		case msg.isNotification(): // 如果消息是通知
			if strings.HasSuffix(msg.Method, notificationMethodSuffix) { // 如果方法名以 notificationMethodSuffix 结尾（很可能是订阅通知）
				h.handleSubscriptionResult(msg) // 处理订阅通知
				continue
			}
			handleCall(msg) // 处理其他通知

		default: // 如果既不是响应也不是通知，则认为是调用
			handleCall(msg) // 处理调用
		}
	}

	for _, op := range resolvedops { // 遍历已处理响应的请求操作
		h.removeRequestOp(op) // 从跟踪中移除这些请求操作
	}
}

// handleSubscriptionResult processes subscription notifications.
// handleSubscriptionResult 处理订阅通知。
// 用于处理服务器向客户端推送的订阅通知的核心逻辑。
func (h *handler) handleSubscriptionResult(msg *jsonrpcMessage) {
	var result subscriptionResult // 声明一个 subscriptionResult 类型的变量用于存储解析结果
	if err := json.Unmarshal(msg.Params, &result); err != nil {
		h.log.Debug("Dropping invalid subscription message")
		return
	}
	if h.clientSubs[result.ID] != nil { // 根据解析出的订阅 ID 查找对应的客户端订阅
		h.clientSubs[result.ID].deliver(result.Result) // 如果找到了对应的客户端订阅，则将解析出的结果数据传递给该订阅的 deliver 方法
	}
}

// 在以太坊的 JSON-RPC API 中，客户端可以发送两种类型的请求：
// 调用（有 id 字段，需要服务器返回响应）和通知（没有 id 字段，服务器不需要返回响应）。
// handleCallMsg 函数正确地处理了这两种类型的消息。
// 对于调用消息，它会记录成功或失败的情况，并包含详细的错误信息（如果发生错误）。
// 对于格式不正确的请求，它会返回标准的 JSON-RPC 错误响应。

// handleCallMsg executes a call message and returns the answer.
// handleCallMsg 执行一个调用消息并返回答案。
func (h *handler) handleCallMsg(ctx *callProc, msg *jsonrpcMessage) *jsonrpcMessage {
	start := time.Now() // 记录处理开始时间
	switch {
	case msg.isNotification(): // 如果是通知消息（没有 ID）
		h.handleCall(ctx, msg)                                           // 处理调用（但不返回响应）
		h.log.Debug("Served "+msg.Method, "duration", time.Since(start)) // 记录调试日志，包含方法名和处理时长
		return nil                                                       // 通知消息没有响应

	case msg.isCall(): // 如果是调用消息（有 ID）
		resp := h.handleCall(ctx, msg)                                                    // 处理调用并获取响应
		var logctx []any                                                                  // 创建一个用于日志上下文的切片
		logctx = append(logctx, "reqid", idForLog{msg.ID}, "duration", time.Since(start)) // 添加请求 ID 和处理时长到日志上下文
		if resp.Error != nil {                                                            // 如果响应包含错误
			logctx = append(logctx, "err", resp.Error.Message) // 添加错误消息到日志上下文
			if resp.Error.Data != nil {                        // 如果错误包含数据
				logctx = append(logctx, "errdata", formatErrorData(resp.Error.Data)) // 格式化错误数据并添加到日志上下文
			}
			h.log.Warn("Served "+msg.Method, logctx...) // 记录警告日志，包含方法名和日志上下文
		} else { // 如果响应成功
			h.log.Debug("Served "+msg.Method, logctx...) // 记录调试日志，包含方法名和日志上下文
		}
		return resp

	case msg.hasValidID(): // 如果消息有合法的 ID，但不是调用或通知（格式错误）
		return msg.errorResponse(&invalidRequestError{"invalid request"}) // 返回无效请求的错误消息

	default: // 如果消息没有合法的 ID，也不是调用或通知（格式错误）
		return errorMessage(&invalidRequestError{"invalid request"}) // 返回无效请求的错误消息
	}
}

// handleCall processes method calls.
// handleCall 处理方法调用。
func (h *handler) handleCall(cp *callProc, msg *jsonrpcMessage) *jsonrpcMessage {
	if msg.isSubscribe() { // 如果是订阅请求
		return h.handleSubscribe(cp, msg) // 调用 handleSubscribe 处理
	}
	var callb *callback
	if msg.isUnsubscribe() { // 如果是取消订阅请求
		callb = h.unsubscribeCb // 使用预设的取消订阅回调函数
	} else { // 否则是普通的方法调用
		callb = h.reg.callback(msg.Method) // 从服务注册表中查找对应方法的回调函数
	}
	if callb == nil { // 如果找不到回调函数
		return msg.errorResponse(&methodNotFoundError{method: msg.Method}) // 返回方法未找到的错误响应
	}

	args, err := parsePositionalArguments(msg.Params, callb.argTypes)
	if err != nil {
		return msg.errorResponse(&invalidParamsError{err.Error()})
	}
	start := time.Now()                             // 记录方法调用的开始时间
	answer := h.runMethod(cp.ctx, msg, callb, args) // 执行方法

	// Collect the statistics for RPC calls if metrics is enabled.
	// We only care about pure rpc call. Filter out subscription.
	// 如果启用了指标，则收集 RPC 调用的统计信息。
	// 我们只关心纯粹的 RPC 调用，过滤掉订阅相关的调用。
	if callb != h.unsubscribeCb { // 排除取消订阅的回调
		rpcRequestGauge.Inc(1)   // 增加 RPC 请求计数器
		if answer.Error != nil { // 如果响应包含错误
			failedRequestGauge.Inc(1) // 增加失败请求计数器
		} else { // 如果响应成功
			successfulRequestGauge.Inc(1) // 增加成功请求计数器
		}
		rpcServingTimer.UpdateSince(start)                                           // 更新 RPC 服务时间计时器
		updateServeTimeHistogram(msg.Method, answer.Error == nil, time.Since(start)) // 更新 RPC 服务时间直方图
	}

	return answer
}

// 在以太坊的 JSON-RPC API 中，eth_subscribe 方法用于让客户端订阅特定的事件。例如，订阅 newHeads 可以接收关于新区块头的通知，订阅 logs 可以接收符合特定过滤条件的日志事件。
//
// handleSubscribe 函数在以太坊节点或客户端实现中扮演着关键角色，它负责：
//
// 验证是否允许订阅。
// 识别客户端想要订阅的事件类型。
// 查找处理该订阅类型的服务器端逻辑。
// 解析客户端提供的任何过滤参数。
// 创建一个 Notifier，该 Notifier 是服务器向订阅的客户端发送事件的机制。
// 将 Notifier 传递给订阅处理函数，使其能够在事件发生时通知客户端。
// 最终执行订阅处理函数，并返回一个包含订阅 ID 的响应给客户端。
// 这个过程确保了客户端能够成功地发起订阅，并且服务器端能够正确地处理这些订阅请求，并在相关事件发生时通知客户端。

// handleSubscribe processes *_subscribe method calls.
// handleSubscribe 处理 *_subscribe 方法调用。
func (h *handler) handleSubscribe(cp *callProc, msg *jsonrpcMessage) *jsonrpcMessage {
	if !h.allowSubscribe { // 如果不允许订阅
		return msg.errorResponse(ErrNotificationsUnsupported) // 返回不支持通知的错误响应
	}

	// Subscription method name is first argument.
	// 订阅方法名是第一个参数。
	name, err := parseSubscriptionName(msg.Params) // 从消息参数中解析订阅名称
	if err != nil {                                // 如果解析订阅名称出错
		return msg.errorResponse(&invalidParamsError{err.Error()}) // 返回参数无效的错误响应
	}
	namespace := msg.namespace()                 // 获取消息的命名空间
	callb := h.reg.subscription(namespace, name) // 从服务注册表中查找订阅的回调函数
	if callb == nil {                            // 如果找不到订阅的回调函数
		return msg.errorResponse(&subscriptionNotFoundError{namespace, name}) // 返回订阅未找到的错误响应
	}

	// Parse subscription name arg too, but remove it before calling the callback.
	// 也解析订阅名称参数，但在调用回调函数之前将其移除。
	argTypes := append([]reflect.Type{stringType}, callb.argTypes...) // 构建参数类型列表，第一个是字符串类型（订阅名称）
	args, err := parsePositionalArguments(msg.Params, argTypes)       // 根据参数类型解析参数
	if err != nil {
		return msg.errorResponse(&invalidParamsError{err.Error()})
	}
	args = args[1:] // 移除第一个参数（订阅名称），因为回调函数不需要再次接收

	// Install notifier in context so the subscription handler can find it.
	// 在上下文中安装通知器，以便订阅处理程序可以找到它。
	n := &Notifier{h: h, namespace: namespace}         // 创建一个新的通知器
	cp.notifiers = append(cp.notifiers, n)             // 将通知器添加到调用处理器的通知器列表中
	ctx := context.WithValue(cp.ctx, notifierKey{}, n) // 将通知器添加到上下文中

	return h.runMethod(ctx, msg, callb, args) // 运行订阅方法的回调函数
}

// 当以太坊节点接收到客户端发送的 RPC 请求时，会根据请求的方法名找到对应的处理函数（即这里的回调函数），
// 然后通过 runMethod 来执行这个处理函数，并将处理结果或错误封装成 JSON-RPC 响应返回给客户端。

// runMethod runs the Go callback for an RPC method.
// runMethod 运行 RPC 方法的 Go 回调函数。
func (h *handler) runMethod(ctx context.Context, msg *jsonrpcMessage, callb *callback, args []reflect.Value) *jsonrpcMessage {
	result, err := callb.call(ctx, msg.Method, args) // 调用回调函数
	if err != nil {
		return msg.errorResponse(err) // 返回包含错误的 JSON-RPC 响应
	}
	return msg.response(result) // 返回包含结果的 JSON-RPC 响应
}

// 以太坊的 JSON-RPC API 提供了订阅功能，允许客户端订阅例如新的区块头、日志等事件。
// 当客户端不再需要接收这些事件时，会调用相应的 *_unsubscribe 方法来取消订阅。
// 服务器端的 unsubscribe 函数就是用来处理这类请求，停止向客户端发送相关的事件通知，并清理服务器端维护的订阅状态。
// ErrSubscriptionNotFound 表明客户端尝试取消一个不存在的订阅。

// unsubscribe is the callback function for all *_unsubscribe calls.
// unsubscribe 是所有 *_unsubscribe 调用的回调函数。
//
// 处理所有以 *_unsubscribe 结尾的 RPC 方法的回调函数，用于取消客户端先前订阅的事件。
func (h *handler) unsubscribe(ctx context.Context, id ID) (bool, error) {
	h.subLock.Lock() // 获取订阅锁
	defer h.subLock.Unlock()

	s := h.serverSubs[id] // 从服务器订阅 map 中查找指定 ID 的订阅
	if s == nil {
		return false, ErrSubscriptionNotFound // 返回 false 和订阅未找到的错误
	}
	close(s.err)             // 关闭订阅的错误通道，通知相关的发送 goroutine 停止发送事件
	delete(h.serverSubs, id) // 从服务器订阅 map 中删除该 ID 的订阅
	return true, nil
}

// 在 JSON-RPC 协议中，请求和响应通常包含一个 id 字段，用于标识请求和匹配响应。这个 id 可以是字符串、数字或者 null。
// 使用 json.RawMessage 可以灵活地存储这个 id，而无需立即知道其具体类型。

type idForLog struct{ json.RawMessage }

func (id idForLog) String() string {
	// 尝试将原始 JSON 消息解析为带引号的字符串并去除引号
	if s, err := strconv.Unquote(string(id.RawMessage)); err == nil {
		return s // 如果没有错误，说明原始的 JSON 消息是一个带引号的字符串，并且成功去除了引号。
	}
	// 说明原始的 JSON 消息不是一个带引号的字符串，或者解析失败。在这种情况下，直接将原始的 json.RawMessage 转换为 string 并返回。
	return string(id.RawMessage)
}

// 用于表示输出被截断的情况。
var errTruncatedOutput = errors.New("truncated output")

// 在以太坊的 JSON-RPC API 中，错误响应有时会包含一个 data 字段，用于提供更详细的错误信息。这个 data 字段可以是任意的 JSON 值。
// formatErrorData 函数可以用于将这个 data 字段格式化为字符串，以便在日志记录或返回给客户端时使用，同时限制其大小，防止过大的错误信息。
type limitedBuffer struct {
	output []byte // 存储输出的字节切片
	limit  int    // 输出的限制大小
}

func (buf *limitedBuffer) Write(data []byte) (int, error) {
	avail := max(buf.limit, len(buf.output)) // 可用空间为限制大小和当前输出长度中的较大值
	if len(data) < avail {                   // 如果要写入的数据小于可用空间
		buf.output = append(buf.output, data...) // 将数据追加到输出
		return len(data), nil
	}
	buf.output = append(buf.output, data[:avail]...) // 将数据的前 avail 个字节追加到输出
	return avail, errTruncatedOutput                 // 返回写入的长度（即 avail）和截断错误
}

func formatErrorData(v any) string {
	buf := limitedBuffer{limit: 1024}      // 创建一个限制为 1024 字节的 limitedBuffer
	err := json.NewEncoder(&buf).Encode(v) // 创建一个 JSON 编码器并将 v 编码到 buf 中
	switch {
	case err == nil:
		return string(bytes.TrimRight(buf.output, "\n")) // 返回去除尾部换行符后的输出字符串
	case errors.Is(err, errTruncatedOutput): // 如果错误是截断错误
		return fmt.Sprintf("%s... (truncated)", buf.output) // 返回截断后的输出字符串并附加 "(truncated)"
	default:
		return fmt.Sprintf("bad error data (err=%v)", err) // 返回包含错误信息的字符串
	}
}
