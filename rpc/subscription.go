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
	"container/list"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"
)

// 当客户端成功订阅一个事件后，服务器通常会返回一个唯一的订阅 ID。客户端可以使用这个 ID 来管理（例如，取消订阅）该订阅。
// 如果客户端提供的订阅 ID 无效（例如，拼写错误、已过期或从未存在），服务器可能会返回一个错误，表明找不到该订阅。ErrSubscriptionNotFound 就代表了这种错误情况。

var (
	// ErrNotificationsUnsupported is returned by the client when the connection doesn't
	// support notifications. You can use this error value to check for subscription
	// support like this:
	//
	//	sub, err := client.EthSubscribe(ctx, channel, "newHeads", true)
	//	if errors.Is(err, rpc.ErrNotificationsUnsupported) {
	//		// Server does not support subscriptions, fall back to polling.
	//	}
	//
	//
	// ErrNotificationsUnsupported 在连接不支持通知时由客户端返回。你可以使用这个错误值来检查订阅支持，如下所示：
	//
	// sub, err := client.EthSubscribe(ctx, channel, "newHeads", true)
	// if errors.Is(err, rpc.ErrNotificationsUnsupported) {
	//    // 服务器不支持订阅，回退到轮询。
	// }
	//
	ErrNotificationsUnsupported = notificationsUnsupportedError{}

	// ErrSubscriptionNotFound is returned when the notification for the given id is not found
	// ErrSubscriptionNotFound 在找不到给定 ID 的通知时返回
	ErrSubscriptionNotFound = errors.New("subscription not found")
)

var globalGen = randomIDGenerator()

// ID defines a pseudo random number that is used to identify RPC subscriptions.
// ID 定义了一个用于标识 RPC 订阅的伪随机数。
type ID string

// NewID returns a new, random ID.
// NewID 返回一个新的随机 ID。
func NewID() ID {
	return globalGen()
}

// randomIDGenerator returns a function generates a random IDs.
// randomIDGenerator 返回一个生成随机 ID 的函数。
func randomIDGenerator() func() ID {
	var buf = make([]byte, 8)
	var seed int64
	if _, err := crand.Read(buf); err == nil { // 尝试从密码学安全的随机数生成器读取 8 个字节
		seed = int64(binary.BigEndian.Uint64(buf)) // 如果成功，将字节转换为大端序的 uint64 并用作种子
	} else {
		seed = int64(time.Now().Nanosecond()) // 如果失败，则使用当前时间的纳秒作为种子
	}

	var (
		mu  sync.Mutex                       // 用于保护随机数生成器的互斥锁
		rng = rand.New(rand.NewSource(seed)) // 使用获取的种子创建一个新的随机数生成器
	)
	return func() ID { // 返回一个闭包函数，该函数在每次调用时生成一个新的随机 ID
		mu.Lock()
		defer mu.Unlock()
		id := make([]byte, 16)
		rng.Read(id)
		return encodeID(id)
	}
}

func encodeID(b []byte) ID {
	id := hex.EncodeToString(b)
	id = strings.TrimLeft(id, "0") // 移除字符串左侧的零
	if id == "" {
		id = "0" // ID's are RPC quantities, no leading zero's and 0 is 0x0. ID 是 RPC 数值，没有前导零，且 0 是 0x0。
	}
	return ID("0x" + id) //  在字符串前添加 "0x" 前缀并转换为 ID 类型
}

type notifierKey struct{}

// NotifierFromContext returns the Notifier value stored in ctx, if any.
// NotifierFromContext 返回存储在 ctx 中的 Notifier 值（如果存在）。
func NotifierFromContext(ctx context.Context) (*Notifier, bool) {
	n, ok := ctx.Value(notifierKey{}).(*Notifier)
	return n, ok
}

// Notifier 结构体用于管理通过支持订阅的 RPC 连接发送的通知。它通常在服务器端使用，当有事件发生需要通知已订阅的客户端时，服务器会使用 Notifier 来发送这些通知。

// Notifier is tied to an RPC connection that supports subscriptions.
// Server callbacks use the notifier to send notifications.
// Notifier 绑定到一个支持订阅的 RPC 连接。
// 服务器回调使用 notifier 发送通知。
type Notifier struct {
	h         *handler // 处理程序，用于与连接或服务器交互 在以太坊节点中，当有新的区块产生、交易状态改变或者符合特定日志过滤器的事件发生时，服务器需要通知那些已经订阅了这些事件的客户端。handler 代表了处理这些底层连接和消息发送的组件。
	namespace string   // 此 notifier 所属的命名空间 以太坊 JSON-RPC API 按照功能划分为不同的命名空间。例如，与以太坊区块链交互的方法在 "eth" 命名空间下，与网络相关的方法在 "net" 命名空间下。通知也可能按照这些命名空间进行组织。

	mu           sync.Mutex    // 用于保护 notifier 内部状态的互斥锁
	sub          *Subscription // 与此 notifier 关联的订阅   当客户端通过 RPC 接口（例如 eth_subscribe）订阅某个事件时，服务器会创建一个与该订阅关联的 Notifier 实例，并保存相关的订阅信息。
	buffer       []any         // 用于存储待发送的通知的缓冲区
	callReturned bool          // 指示建立订阅的初始 RPC 调用是否已返回
	activated    bool          // 指示此 notifier 是否已激活并准备发送通知
}

// 当一个客户端向以太坊节点发送一个订阅请求（例如 eth_subscribe("newHeads")）时，服务器端的处理逻辑会创建一个与该请求对应的 Notifier 实例。

// CreateSubscription returns a new subscription that is coupled to the
// RPC connection. By default subscriptions are inactive and notifications
// are dropped until the subscription is marked as active. This is done
// by the RPC server after the subscription ID is send to the client.
//
// CreateSubscription 返回一个与 RPC 连接耦合的新订阅。
// 默认情况下，订阅处于非活动状态，并且在订阅标记为活动状态之前，
// 通知将被丢弃。这由 RPC 服务器在将订阅 ID 发送给客户端后完成。
func (n *Notifier) CreateSubscription() *Subscription {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.sub != nil { // 一个 Notifier 只能创建一个订阅 无法使用 Notifier 创建多个订阅
		panic("can't create multiple subscriptions with Notifier")
	} else if n.callReturned { // 订阅调用返回后不能创建订阅
		panic("can't create subscription after subscribe call has returned")
	}
	n.sub = &Subscription{ID: n.h.idgen(), namespace: n.namespace, err: make(chan error, 1)}
	return n.sub
}

// Notify sends a notification to the client with the given data as payload.
// If an error occurs the RPC connection is closed and the error is returned.
//
// Notify 向客户端发送一个带有给定数据作为有效负载的通知。
// 如果发生错误，RPC 连接将被关闭并返回错误。
//
// 用于向与给定 ID 关联的订阅发送通知数据。
//
// 当以太坊节点监听到需要通知客户端的事件时，会调用 Notify 方法。根据订阅是否已经激活，通知可能会立即发送，或者先被缓冲起来。
func (n *Notifier) Notify(id ID, data any) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.sub == nil { // 在创建订阅之前不能发送通知
		panic("can't Notify before subscription is created")
	} else if n.sub.ID != id { // 使用错误的 ID 发送通知
		panic("Notify with wrong ID")
	}
	if n.activated { // 如果已激活，则立即发送通知 如果订阅已经被激活（意味着订阅 ID 已经发送给客户端），则立即调用 n.send() 方法发送通知。
		return n.send(n.sub, data)
	}
	n.buffer = append(n.buffer, data) // 如果未激活，则将通知数据添加到缓冲区
	return nil
}

// 在处理客户端的订阅请求时，服务器可能需要在某个阶段获取已经创建的 Subscription 对象，例如在发送订阅 ID 给客户端之后。、
// takeSubscription 方法提供了这个功能，并确保在获取订阅后不会再创建新的订阅。

// takeSubscription returns the subscription (if one has been created). No subscription can
// be created after this call.
// takeSubscription 返回订阅（如果已创建）。在此调用之后不能创建任何订阅。
// 用于获取已经创建的订阅对象，并且标记订阅调用已经返回，从而阻止之后再创建新的订阅。
func (n *Notifier) takeSubscription() *Subscription {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.callReturned = true // 标记订阅调用已返回，之后不能再创建订阅 表明与订阅相关的初始 RPC 调用已经完成。
	return n.sub
}

// 在处理订阅请求时，服务器通常需要先将订阅 ID 发送给客户端，然后才能开始发送实际的通知。
// activate 方法确保了这一点。在 activate 被调用之前，所有通过 Notify 收到的通知都会被缓冲起来。
// 一旦 activate 被调用，这些缓冲的通知会被发送给客户端，并且后续的通知也会立即发送，从而保证了通知的发送顺序。

// activate is called after the subscription ID was sent to client. Notifications are
// buffered before activation. This prevents notifications being sent to the client before
// the subscription ID is sent to the client.
//
// activate 在订阅 ID 发送给客户端后调用。通知在激活之前被缓冲。
// 这可以防止在订阅 ID 发送给客户端之前将通知发送给客户端。
//
// activate 用于激活订阅。在激活之前，所有通过 Notify 发送的通知都会被缓冲起来。激活操作会将所有缓冲的通知发送出去，并将 activated 标志设置为 true，之后通过 Notify 发送的通知会立即发送。
func (n *Notifier) activate() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, data := range n.buffer {
		if err := n.send(n.sub, data); err != nil {
			return err
		}
	}
	n.activated = true // 标记订阅为已激活
	return nil
}

// send 将传入的订阅信息和数据封装成符合 JSON-RPC 规范的订阅通知消息，并通过底层的 RPC 连接将消息发送出去。
func (n *Notifier) send(sub *Subscription, data any) error {
	// 通知消息遵循 JSON-RPC 规范，并且对于订阅通知，通常会包含一个 method 字段来标识这是一个订阅通知，以及一个 params 字段，其中包含了订阅的 ID 和实际的通知数据。
	msg := jsonrpcSubscriptionNotification{
		Version: vsn,
		Method:  n.namespace + notificationMethodSuffix,
		Params: subscriptionResultEnc{
			ID:     string(sub.ID),
			Result: data,
		},
	}
	return n.h.conn.writeJSON(context.Background(), &msg, false)
}

// A Subscription is created by a notifier and tied to that notifier. The client can use
// this subscription to wait for an unsubscribe request for the client, see Err().
//
// Subscription 由 notifier 创建并绑定到该 notifier。客户端可以使用
// 此订阅来等待客户端的取消订阅请求，请参见 Err()。
type Subscription struct {
	ID        ID         // 订阅的唯一标识符 当客户端成功订阅某个事件（例如，新的区块头）时，服务器会返回一个唯一的订阅 ID。客户端在后续取消订阅时需要提供这个 ID。
	namespace string     // 订阅所属的命名空间 namespace 字段表示该订阅属于哪个 RPC 命名空间（例如 "eth"、"net" 等）。这有助于组织和管理不同类型的订阅。以太坊 JSON-RPC API 按照功能划分为不同的命名空间。订阅也可能与特定的命名空间相关联。
	err       chan error // closed on unsubscribe 在取消订阅时关闭的通道 当客户端发送取消订阅的请求时，服务器会关闭这个通道。这允许服务器端的代码（例如，创建此订阅的 Notifier）能够监听到取消订阅的事件，并进行相应的清理工作（例如，停止发送通知）。当客户端调用 eth_unsubscribe 方法并提供订阅 ID 时，服务器端会找到对应的 Subscription 实例，并关闭其 err 通道。
}

// Err returns a channel that is closed when the client send an unsubscribe request.
// Err 返回一个通道，该通道在客户端发送取消订阅请求时关闭。
// 返回只读通道可以防止外部代码意外地向该通道发送数据或关闭该通道，从而保证了取消订阅信号的正确性。服务器端的代码可以监听这个通道来知道订阅何时被取消。
func (s *Subscription) Err() <-chan error {
	return s.err
}

// MarshalJSON marshals a subscription as its ID.
// MarshalJSON 将订阅序列化为它的 ID。
func (s *Subscription) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ID)
}

// 客户端订阅管理： 在与以太坊节点进行交互时，客户端通常需要订阅某些事件以获取实时的区块链数据。
// 异步通知： 以太坊的订阅机制是异步的，服务器会在事件发生时主动向客户端推送通知。客户端通过 Go 的通道机制来接收这些通知。
// 取消订阅流程：客户端需要能够取消不再需要的订阅，这通常通过向服务器发送一个取消订阅的请求来实现。ClientSubscription 结构体中的 quit 通道和相关的 forwardDone 和 unsubDone 通道就是为了管理这个取消订阅的流程。

// ClientSubscription is a subscription established through the Client's Subscribe or
// EthSubscribe methods.
//
// ClientSubscription 是通过 Client 的 Subscribe 或 EthSubscribe 方法建立的订阅。
// 代表了客户端通过 RPC 接口（如 eth_subscribe）建立的订阅。它负责接收来自服务器的通知，并将这些通知转发到客户端提供的 Go 通道。
type ClientSubscription struct {
	client    *Client       // 创建此订阅的客户端实例
	etype     reflect.Type  // 订阅通道中元素的类型
	channel   reflect.Value // 客户端用于接收通知的 Go 通道
	namespace string        // 订阅的命名空间（例如 "eth"）
	subid     string        // 从服务器接收到的订阅 ID

	// The in channel receives notification values from client dispatcher.
	// in 通道从客户端分发器接收通知值。
	in chan json.RawMessage

	// The error channel receives the error from the forwarding loop.
	// It is closed by Unsubscribe.
	// err 通道接收来自转发循环的错误。
	// 它在 Unsubscribe 时关闭。
	err     chan error
	errOnce sync.Once //  确保错误通道只关闭一次

	// Closing of the subscription is requested by sending on 'quit'. This is handled by
	// the forwarding loop, which closes 'forwardDone' when it has stopped sending to
	// sub.channel. Finally, 'unsubDone' is closed after unsubscribing on the server side.
	//
	// 通过在 'quit' 上发送信号来请求关闭订阅。这由转发循环处理，
	// 当它停止向 sub.channel 发送数据时关闭 'forwardDone'。
	// 最后，在服务器端取消订阅后关闭 'unsubDone'。
	quit        chan error
	forwardDone chan struct{}
	unsubDone   chan struct{}
}

// This is the sentinel value sent on sub.quit when Unsubscribe is called.
// 这是在调用 Unsubscribe 时发送到 sub.quit 的哨兵值。
var errUnsubscribed = errors.New("unsubscribed")

func newClientSubscription(c *Client, namespace string, channel reflect.Value) *ClientSubscription {
	sub := &ClientSubscription{
		client:      c,
		namespace:   namespace,
		etype:       channel.Type().Elem(),
		channel:     channel,
		in:          make(chan json.RawMessage),
		quit:        make(chan error),
		forwardDone: make(chan struct{}),
		unsubDone:   make(chan struct{}),
		err:         make(chan error, 1),
	}
	return sub
}

// Err returns the subscription error channel. The intended use of Err is to schedule
// resubscription when the client connection is closed unexpectedly.
//
// The error channel receives a value when the subscription has ended due to an error. The
// received error is nil if Close has been called on the underlying client and no other
// error has occurred.
//
// The error channel is closed when Unsubscribe is called on the subscription.
//
// Err 返回订阅的错误通道。Err 的预期用途是在客户端连接意外关闭时安排重新订阅。
//
// 当订阅由于错误而结束时，错误通道会接收到一个值。
// 如果在底层客户端上调用了 Close 并且没有发生其他错误，则接收到的错误为 nil。
//
// 当在订阅上调用 Unsubscribe 时，错误通道将被关闭。
func (sub *ClientSubscription) Err() <-chan error {
	return sub.err
}

// Unsubscribe unsubscribes the notification and closes the error channel.
// It can safely be called more than once.
//
// Unsubscribe 取消订阅通知并关闭错误通道。
// 可以安全地多次调用。
func (sub *ClientSubscription) Unsubscribe() {
	sub.errOnce.Do(func() {
		select {
		case sub.quit <- errUnsubscribed: // 这个信号会通知转发循环停止转发通知。
			<-sub.unsubDone // sub.unsubDone 通道应该在服务器端成功取消订阅后被关闭。
		case <-sub.unsubDone: // 如果发送到 sub.quit 通道被阻塞（可能因为转发循环已经退出），则尝试从 sub.unsubDone 通道接收信号。这可能是因为取消订阅已经完成或者正在进行中。
		}
		close(sub.err) // 关闭 sub.err 通道，通知所有监听该通道的 Goroutine 订阅已经结束。
	})
}

// 当以太坊节点通过 RPC 连接发送一个订阅通知时，客户端的底层框架会接收到这个消息，并根据订阅 ID 将消息路由到对应的 ClientSubscription 实例。deliver 方法就是接收这个原始通知数据的入口。

// deliver is called by the client's message dispatcher to send a notification value.
// deliver 由客户端的消息分发器调用以发送通知值。
func (sub *ClientSubscription) deliver(result json.RawMessage) (ok bool) {
	select {
	case sub.in <- result: // 尝试将结果发送到输入通道
		return true
	case <-sub.forwardDone: // 如果转发已完成，则返回 false。sub.forwardDone 通道在转发循环停止工作时关闭（例如，由于取消订阅）。如果该通道已关闭，说明订阅已经结束，无法再传递新的通知，方法返回 false。
		return false
	}
}

// close is called by the client's message dispatcher when the connection is closed.
// close 由客户端的消息分发器在连接关闭时调用。
func (sub *ClientSubscription) close(err error) {
	select {
	case sub.quit <- err: // 尝试将错误发送到退出通道。sub.quit 通道通常被转发循环监听，接收到这个信号后，转发循环会停止工作。
	case <-sub.forwardDone: // 如果转发已完成，则不执行任何操作。如果发送到 sub.quit 通道被阻塞，则会检查 sub.forwardDone 通道是否已关闭。如果该通道已关闭，说明转发循环已经结束，可能由于客户端主动取消订阅，此时无需再次发送连接关闭的信号。
	}
}

// 当客户端通过 eth_subscribe 等方法订阅以太坊事件后，客户端的底层库会启动一个 Goroutine 来执行 run() 方法，从而开始接收和处理来自以太坊节点的实时通知。
// sub.forward() 方法负责实际接收和转发这些通知。
// 当客户端想要取消订阅（调用 Unsubscribe()）时，sub.forward() 会检测到这个请求，并设置 unsubscribe 为 true。然后，run() 方法会调用 requestUnsubscribe() 向以太坊节点发送 eth_unsubscribe 请求。
// 如果与以太坊节点的连接断开或者发生其他错误，sub.forward() 会返回相应的错误，run() 方法会将这些错误通过 sub.err 通道通知给客户端。
// 特别地，当客户端主动关闭连接时，会产生 ErrClientQuit 错误，run() 方法会将这个错误视为正常的结束，并将其报告为 nil。

// run is the forwarding loop of the subscription. It runs in its own goroutine and
// is launched by the client's handler after the subscription has been created.
// run 是订阅的转发循环。它在其自身的 Goroutine 中运行，并且
// 在创建订阅后由客户端的处理程序启动。
// 它在一个独立的 Goroutine 中运行，负责接收、处理和转发来自服务器的订阅通知，并处理订阅的结束。
func (sub *ClientSubscription) run() {
	// sub.unsubDone 通道用于通知 Unsubscribe 方法服务器端的取消订阅操作（或本地清理）已完成。
	defer close(sub.unsubDone) // 在函数退出时关闭 unsubDone 通道

	unsubscribe, err := sub.forward() // 启动转发循环并获取是否需要取消服务器端订阅的标志和错误

	// The client's dispatch loop won't be able to execute the unsubscribe call if it is
	// blocked in sub.deliver() or sub.close(). Closing forwardDone unblocks them.
	// 如果客户端的分发循环阻塞在 sub.deliver() 或 sub.close() 中，则无法执行取消订阅调用。
	// 关闭 forwardDone 会解除它们的阻塞。
	close(sub.forwardDone)

	// Call the unsubscribe method on the server.
	// 调用服务器端的取消订阅方法。
	if unsubscribe {
		sub.requestUnsubscribe()
	}

	// Send the error.
	// 发送错误。
	if err != nil {
		if err == ErrClientQuit {
			// ErrClientQuit gets here when Client.Close is called. This is reported as a
			// nil error because it's not an error, but we can't close sub.err here.
			// 当调用 Client.Close 时，ErrClientQuit 会到达这里。这被报告为 nil 错误，
			// 因为这不是一个错误，但我们不能在这里关闭 sub.err。
			err = nil
		}
		sub.err <- err
	}
}

// forward is the forwarding loop. It takes in RPC notifications and sends them
// on the subscription channel.
//
// forward 是转发循环。它接收 RPC 通知并将它们发送到订阅通道上。
//
// 在一个无限循环中运行，负责从 sub.in 通道接收服务器发送的原始 JSON 通知，将它们反序列化为 Go 类型，并将反序列化后的值发送到客户端提供的 sub.channel 上。
// TODO: re learn
func (sub *ClientSubscription) forward() (unsubscribeServer bool, err error) {
	// 方法使用 reflect.Select 来同时监听多个通道：sub.quit（取消订阅信号）、sub.in（来自消息分发器的通知）和 sub.channel（客户端的接收通道）。这使得循环能够响应不同类型的事件。
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sub.quit)}, // 监听退出信号
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sub.in)},   // 监听来自分发器的通知
		{Dir: reflect.SelectSend, Chan: sub.channel},               // 向客户端提供的通道发送通知
	}
	// 使用 container/list.List 实现了一个缓冲区 buffer，用于存储待发送到 sub.channel 的通知。
	// 当 sub.channel 暂时无法接收数据时，通知会被缓冲起来。
	buffer := list.New() // 用于缓冲待发送的通知

	for {
		var chosen int
		var recv reflect.Value
		if buffer.Len() == 0 {
			// Idle, omit send case.
			// 空闲状态，省略发送 case。
			chosen, recv, _ = reflect.Select(cases[:2])
		} else {
			// Non-empty buffer, send the first queued item.
			// 非空缓冲区，发送队列中的第一个元素。
			cases[2].Send = reflect.ValueOf(buffer.Front().Value)
			chosen, recv, _ = reflect.Select(cases)
		}

		switch chosen {
		case 0: // <-sub.quit
			if !recv.IsNil() {
				err = recv.Interface().(error)
			}
			if err == errUnsubscribed {
				// Exiting because Unsubscribe was called, unsubscribe on server.
				// 因为调用了 Unsubscribe 而退出，需要在服务器端取消订阅。
				return true, nil
			}
			return false, err

		case 1: // <-sub.in
			val, err := sub.unmarshal(recv.Interface().(json.RawMessage))
			if err != nil {
				return true, err
			}
			if buffer.Len() == maxClientSubscriptionBuffer {
				return true, ErrSubscriptionQueueOverflow
			}
			buffer.PushBack(val)

		case 2: // sub.channel<-
			cases[2].Send = reflect.Value{} // Don't hold onto the value. 不再持有发送的值。
			buffer.Remove(buffer.Front())
		}
	}
}

func (sub *ClientSubscription) unmarshal(result json.RawMessage) (interface{}, error) {
	val := reflect.New(sub.etype)
	err := json.Unmarshal(result, val.Interface())
	return val.Elem().Interface(), err
}

// requestUnsubscribe 用于向服务器发送取消订阅的 RPC 请求。
//
// 当客户端想要停止接收来自以太坊节点的某个订阅的通知时，它需要向节点发送一个 eth_unsubscribe 的 RPC 请求，并将要取消订阅的订阅 ID 作为参数传递给该请求。
// requestUnsubscribe() 方法正是实现了这个过程。它构造了 eth_unsubscribe 方法名（通过拼接命名空间和后缀），并使用订阅的 ID 作为参数发起 RPC 调用。
// 使用 context.WithTimeout 可以防止取消订阅操作因为网络问题或其他原因而无限期地阻塞。如果在指定的时间内没有收到服务器的响应，上下文会超时，CallContext 方法会返回一个错误。
func (sub *ClientSubscription) requestUnsubscribe() error {
	var result interface{}
	ctx, cancel := context.WithTimeout(context.Background(), unsubscribeTimeout)
	defer cancel()
	err := sub.client.CallContext(ctx, &result, sub.namespace+unsubscribeMethodSuffix, sub.subid)
	return err
}
