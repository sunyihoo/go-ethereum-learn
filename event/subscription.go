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

package event

import (
	"context"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
)

// 事件订阅的可靠性: 在以太坊开发中，订阅智能合约事件或区块链事件是非常常见的需求。由于网络不稳定或其他原因，订阅可能会中断。Resubscribe 和 ResubscribeErr 提供的自动重连机制对于构建可靠的以太坊应用至关重要。
// 资源管理: 以太坊应用通常需要管理许多并发的连接和订阅。SubscriptionScope 提供了一种方便的方式来跟踪和清理这些资源，防止资源泄露。例如，在一个监听多个合约事件的服务中，可以使用 SubscriptionScope 来管理所有事件订阅，并在服务关闭时统一取消这些订阅。
// 错误处理: Subscription 接口定义的错误 channel 提供了一种机制来报告订阅过程中发生的错误，这对于监控和调试以太坊应用非常重要。

// Subscription represents a stream of events. The carrier of the events is typically a
// channel, but isn't part of the interface.
//
// Subscriptions can fail while established. Failures are reported through an error
// channel. It receives a value if there is an issue with the subscription (e.g. the
// network connection delivering the events has been closed). Only one value will ever be
// sent.
//
// The error channel is closed when the subscription ends successfully (i.e. when the
// source of events is closed). It is also closed when Unsubscribe is called.
//
// The Unsubscribe method cancels the sending of events. You must call Unsubscribe in all
// cases to ensure that resources related to the subscription are released. It can be
// called any number of times.
// Subscription 表示一个事件流。事件的载体通常是一个 channel，但这不是接口的一部分。
//
// 订阅在建立后可能会失败。失败通过一个错误 channel 报告。如果订阅出现问题（例如，传递事件的网络连接已关闭），该 channel 会接收到一个值。只会发送一个值。
//
// 当订阅成功结束（即事件源关闭）时，错误 channel 会被关闭。当调用 Unsubscribe 时，它也会被关闭。
//
// Unsubscribe 方法取消事件的发送。在所有情况下都必须调用 Unsubscribe，以确保释放与订阅相关的资源。它可以被调用任意次数。
type Subscription interface {
	Err() <-chan error // returns the error channel
	// Err() 返回错误 channel
	Unsubscribe() // cancels sending of events, closing the error channel
	// Unsubscribe() 取消事件的发送，关闭错误 channel
}

// NewSubscription runs a producer function as a subscription in a new goroutine. The
// channel given to the producer is closed when Unsubscribe is called. If fn returns an
// error, it is sent on the subscription's error channel.
// NewSubscription 在一个新的 goroutine 中运行一个生产者函数作为订阅。当调用 Unsubscribe 时，传递给生产者的 channel 会被关闭。如果 fn 返回一个错误，它会被发送到订阅的错误 channel 中。
func NewSubscription(producer func(<-chan struct{}) error) Subscription {
	s := &funcSub{unsub: make(chan struct{}), err: make(chan error, 1)}
	go func() {
		defer close(s.err)
		err := producer(s.unsub)
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.unsubscribed {
			if err != nil {
				s.err <- err
			}
			s.unsubscribed = true
		}
	}()
	return s
}

type funcSub struct {
	unsub        chan struct{}
	err          chan error
	mu           sync.Mutex
	unsubscribed bool
}

func (s *funcSub) Unsubscribe() {
	s.mu.Lock()
	if s.unsubscribed {
		s.mu.Unlock()
		return
	}
	s.unsubscribed = true
	close(s.unsub)
	s.mu.Unlock()
	// Wait for producer shutdown.
	// 等待生产者关闭。
	<-s.err
}

func (s *funcSub) Err() <-chan error {
	return s.err
}

// Resubscribe calls fn repeatedly to keep a subscription established. When the
// subscription is established, Resubscribe waits for it to fail and calls fn again. This
// process repeats until Unsubscribe is called or the active subscription ends
// successfully.
//
// Resubscribe applies backoff between calls to fn. The time between calls is adapted
// based on the error rate, but will never exceed backoffMax.
// Resubscribe 会重复调用 fn 以保持订阅的建立。当订阅建立后，Resubscribe 会等待它失败，然后再次调用 fn。这个过程会一直重复，直到调用 Unsubscribe 或活动订阅成功结束。
//
// Resubscribe 在调用 fn 之间应用退避策略。调用之间的时间会根据错误率进行调整，但永远不会超过 backoffMax。
func Resubscribe(backoffMax time.Duration, fn ResubscribeFunc) Subscription {
	return ResubscribeErr(backoffMax, func(ctx context.Context, _ error) (Subscription, error) {
		return fn(ctx)
	})
}

// A ResubscribeFunc attempts to establish a subscription.
// ResubscribeFunc 尝试建立一个订阅。
type ResubscribeFunc func(context.Context) (Subscription, error)

// ResubscribeErr calls fn repeatedly to keep a subscription established. When the
// subscription is established, ResubscribeErr waits for it to fail and calls fn again. This
// process repeats until Unsubscribe is called or the active subscription ends
// successfully.
//
// The difference between Resubscribe and ResubscribeErr is that with ResubscribeErr,
// the error of the failing subscription is available to the callback for logging
// purposes.
//
// ResubscribeErr applies backoff between calls to fn. The time between calls is adapted
// based on the error rate, but will never exceed backoffMax.
// ResubscribeErr 会重复调用 fn 以保持订阅的建立。当订阅建立后，ResubscribeErr 会等待它失败，然后再次调用 fn。这个过程会一直重复，直到调用 Unsubscribe 或活动订阅成功结束。
//
// Resubscribe 和 ResubscribeErr 的区别在于，对于 ResubscribeErr，失败订阅的错误可以传递给回调函数以用于日志记录。
//
// ResubscribeErr 在调用 fn 之间应用退避策略。调用之间的时间会根据错误率进行调整，但永远不会超过 backoffMax。
func ResubscribeErr(backoffMax time.Duration, fn ResubscribeErrFunc) Subscription {
	s := &resubscribeSub{
		waitTime:   backoffMax / 10,
		backoffMax: backoffMax,
		fn:         fn,
		err:        make(chan error),
		unsub:      make(chan struct{}, 1),
	}
	go s.loop()
	return s
}

// A ResubscribeErrFunc attempts to establish a subscription.
// For every call but the first, the second argument to this function is
// the error that occurred with the previous subscription.
// ResubscribeErrFunc 尝试建立一个订阅。
// 除了第一次调用外，此函数的第二个参数是上一个订阅发生的错误。
type ResubscribeErrFunc func(context.Context, error) (Subscription, error)

type resubscribeSub struct {
	fn                   ResubscribeErrFunc
	err                  chan error
	unsub                chan struct{}
	unsubOnce            sync.Once
	lastTry              mclock.AbsTime
	lastSubErr           error
	waitTime, backoffMax time.Duration
}

func (s *resubscribeSub) Unsubscribe() {
	s.unsubOnce.Do(func() {
		s.unsub <- struct{}{}
		<-s.err
	})
}

func (s *resubscribeSub) Err() <-chan error {
	return s.err
}

func (s *resubscribeSub) loop() {
	defer close(s.err)
	var done bool
	for !done {
		sub := s.subscribe()
		if sub == nil {
			break
		}
		done = s.waitForError(sub)
		sub.Unsubscribe()
	}
}

func (s *resubscribeSub) subscribe() Subscription {
	subscribed := make(chan error)
	var sub Subscription
	for {
		s.lastTry = mclock.Now()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			rsub, err := s.fn(ctx, s.lastSubErr)
			sub = rsub
			subscribed <- err
		}()
		select {
		case err := <-subscribed:
			cancel()
			if err == nil {
				if sub == nil {
					panic("event: ResubscribeFunc returned nil subscription and no error")
				}
				return sub
			}
			// Subscribing failed, wait before launching the next try.
			// 订阅失败，等待一段时间再进行下一次尝试。
			if s.backoffWait() {
				return nil // unsubscribed during wait
				// 在等待期间取消订阅
			}
		case <-s.unsub:
			cancel()
			<-subscribed // avoid leaking the s.fn goroutine.
			// 避免泄漏 s.fn goroutine。
			return nil
		}
	}
}

func (s *resubscribeSub) waitForError(sub Subscription) bool {
	defer sub.Unsubscribe()
	select {
	case err := <-sub.Err():
		s.lastSubErr = err
		return err == nil
	case <-s.unsub:
		return true
	}
}

func (s *resubscribeSub) backoffWait() bool {
	if time.Duration(mclock.Now()-s.lastTry) > s.backoffMax {
		s.waitTime = s.backoffMax / 10
	} else {
		s.waitTime *= 2
		if s.waitTime > s.backoffMax {
			s.waitTime = s.backoffMax
		}
	}

	t := time.NewTimer(s.waitTime)
	defer t.Stop()
	select {
	case <-t.C:
		return false
	case <-s.unsub:
		return true
	}
}

// SubscriptionScope provides a facility to unsubscribe multiple subscriptions at once.
//
// For code that handle more than one subscription, a scope can be used to conveniently
// unsubscribe all of them with a single call. The example demonstrates a typical use in a
// larger program.
//
// The zero value is ready to use.
// SubscriptionScope 提供了一种一次性取消多个订阅的机制。
//
// 对于处理多个订阅的代码，可以使用 scope 来方便地通过一次调用取消所有订阅。示例展示了在大型程序中的典型用法。
//
// 零值即可直接使用。
type SubscriptionScope struct {
	mu     sync.Mutex
	subs   map[*scopeSub]struct{}
	closed bool
}

type scopeSub struct {
	sc *SubscriptionScope
	s  Subscription
}

// Track starts tracking a subscription. If the scope is closed, Track returns nil. The
// returned subscription is a wrapper. Unsubscribing the wrapper removes it from the
// scope.
// Track 开始跟踪一个订阅。如果 scope 已经关闭，Track 返回 nil。返回的订阅是一个包装器。取消包装器的订阅会将其从 scope 中移除。
func (sc *SubscriptionScope) Track(s Subscription) Subscription {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	if sc.subs == nil {
		sc.subs = make(map[*scopeSub]struct{})
	}
	ss := &scopeSub{sc, s}
	sc.subs[ss] = struct{}{}
	return ss
}

// Close calls Unsubscribe on all tracked subscriptions and prevents further additions to
// the tracked set. Calls to Track after Close return nil.
// Close 对所有被跟踪的订阅调用 Unsubscribe，并阻止进一步向跟踪集合中添加订阅。在 Close 之后调用 Track 将返回 nil。
func (sc *SubscriptionScope) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return
	}
	sc.closed = true
	for s := range sc.subs {
		s.s.Unsubscribe()
	}
	sc.subs = nil
}

// Count returns the number of tracked subscriptions.
// It is meant to be used for debugging.
// Count 返回被跟踪的订阅数量。
// 它用于调试。
func (sc *SubscriptionScope) Count() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return len(sc.subs)
}

func (s *scopeSub) Unsubscribe() {
	s.s.Unsubscribe()
	s.sc.mu.Lock()
	defer s.sc.mu.Unlock()
	delete(s.sc.subs, s)
}

func (s *scopeSub) Err() <-chan error {
	return s.s.Err()
}
