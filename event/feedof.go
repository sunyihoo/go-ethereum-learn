// Copyright 2022 The go-ethereum Authors
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
	"reflect"
	"sync"
)

// 事件监听: 以太坊智能合约可以发出事件（logs）。以太坊客户端（如 Go-ethereum）通常会提供机制允许外部应用订阅这些事件。FeedOf 这种模式可以用于在 Go-ethereum 内部或暴露给外部应用时，高效地将接收到的事件广播给多个监听器。
// 状态同步: 在以太坊网络中，节点需要同步区块链的状态。某些内部组件可能使用发布订阅模式来通知其他组件关于新的区块、交易或其他状态更新。
// P2P 网络: 以太坊节点之间需要进行点对点通信。虽然更底层的网络协议负责消息的传递，但在应用层，可能存在需要将某些类型的消息广播给多个连接的对等节点的场景。

// FeedOf implements one-to-many subscriptions where the carrier of events is a channel.
// Values sent to a Feed are delivered to all subscribed channels simultaneously.
//
// The zero value is ready to use.
// FeedOf 实现了一对多的订阅，事件的载体是 channel。
// 发送到 Feed 的值会同时传递给所有订阅的 channel。
//
// 零值即可直接使用。
type FeedOf[T any] struct {
	once sync.Once // ensures that init only runs once
	// once 确保 init 方法只运行一次
	sendLock chan struct{} // sendLock has a one-element buffer and is empty when held.It protects sendCases.
	// sendLock 是一个带有一个元素的缓冲 channel，当持有锁时为空。它用于保护 sendCases。
	removeSub chan chan<- T // interrupts Send
	// removeSub 用于中断 Send 操作，通知其移除订阅者。
	sendCases caseList // the active set of select cases used by Send
	// sendCases 是 Send 方法使用的活跃的 select case 集合。

	// The inbox holds newly subscribed channels until they are added to sendCases.
	// inbox 保存新订阅的 channel，直到它们被添加到 sendCases 中。
	mu    sync.Mutex
	inbox caseList
}

func (f *FeedOf[T]) init() {
	f.removeSub = make(chan chan<- T)
	f.sendLock = make(chan struct{}, 1)
	f.sendLock <- struct{}{}
	f.sendCases = caseList{{Chan: reflect.ValueOf(f.removeSub), Dir: reflect.SelectRecv}}
}

// Subscribe adds a channel to the feed. Future sends will be delivered on the channel
// until the subscription is canceled.
//
// The channel should have ample buffer space to avoid blocking other subscribers. Slow
// subscribers are not dropped.
// Subscribe 方法向 feed 添加一个 channel。未来的发送操作会将值传递给该 channel，直到订阅被取消。
//
// 该 channel 应该具有足够的缓冲区空间，以避免阻塞其他订阅者。慢速的订阅者不会被丢弃。
func (f *FeedOf[T]) Subscribe(channel chan<- T) Subscription {
	f.once.Do(f.init)

	chanval := reflect.ValueOf(channel)
	sub := &feedOfSub[T]{feed: f, channel: channel, err: make(chan error, 1)}

	// Add the select case to the inbox.
	// The next Send will add it to f.sendCases.
	// 将 select case 添加到 inbox 中。
	// 下一次 Send 操作会将其添加到 f.sendCases 中。
	f.mu.Lock()
	defer f.mu.Unlock()
	cas := reflect.SelectCase{Dir: reflect.SelectSend, Chan: chanval}
	f.inbox = append(f.inbox, cas)
	return sub
}

func (f *FeedOf[T]) remove(sub *feedOfSub[T]) {
	// Delete from inbox first, which covers channels
	// that have not been added to f.sendCases yet.
	// 首先从 inbox 中删除，这涵盖了尚未添加到 f.sendCases 的 channel。
	f.mu.Lock()
	index := f.inbox.find(sub.channel)
	if index != -1 {
		f.inbox = f.inbox.delete(index)
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	select {
	case f.removeSub <- sub.channel:
		// Send will remove the channel from f.sendCases.
		// Send 操作会从 f.sendCases 中移除该 channel。
	case <-f.sendLock:
		// No Send is in progress, delete the channel now that we have the send lock.
		// 没有正在进行的 Send 操作，现在我们持有 sendLock，可以直接删除该 channel。
		f.sendCases = f.sendCases.delete(f.sendCases.find(sub.channel))
		f.sendLock <- struct{}{}
	}
}

// Send delivers to all subscribed channels simultaneously.
// It returns the number of subscribers that the value was sent to.
// Send 方法同时将值传递给所有订阅的 channel。
// 它返回成功发送到的订阅者数量。
func (f *FeedOf[T]) Send(value T) (nsent int) {
	rvalue := reflect.ValueOf(value)

	f.once.Do(f.init)
	<-f.sendLock // Acquire the send lock. // 获取发送锁。

	// Add new cases from the inbox after taking the send lock.
	// 在获取发送锁后，从 inbox 中添加新的 case。
	f.mu.Lock()
	f.sendCases = append(f.sendCases, f.inbox...)
	f.inbox = nil
	f.mu.Unlock()

	// Set the sent value on all channels.
	// 在所有 channel 上设置要发送的值。
	for i := firstSubSendCase; i < len(f.sendCases); i++ {
		f.sendCases[i].Send = rvalue
	}

	// Send until all channels except removeSub have been chosen. 'cases' tracks a prefix
	// of sendCases. When a send succeeds, the corresponding case moves to the end of
	// 'cases' and it shrinks by one element.
	// 发送直到除了 removeSub 之外的所有 channel 都被选中。'cases' 跟踪 sendCases 的一个前缀。
	// 当发送成功时，相应的 case 会移动到 'cases' 的末尾，并且 'cases' 的长度会减小。
	cases := f.sendCases
	for {
		// Fast path: try sending without blocking before adding to the select set.
		// This should usually succeed if subscribers are fast enough and have free
		// buffer space.
		// 快速路径：在添加到 select 集合之前，尝试非阻塞地发送。
		// 如果订阅者足够快并且有足够的缓冲区空间，这通常会成功。
		for i := firstSubSendCase; i < len(cases); i++ {
			if cases[i].Chan.TrySend(rvalue) {
				nsent++
				cases = cases.deactivate(i)
				i--
			}
		}
		if len(cases) == firstSubSendCase {
			break
		}
		// Select on all the receivers, waiting for them to unblock.
		// 对所有接收者进行 select 操作，等待它们解除阻塞。
		chosen, recv, _ := reflect.Select(cases)
		if chosen == 0 /* <-f.removeSub */ {
			index := f.sendCases.find(recv.Interface())
			f.sendCases = f.sendCases.delete(index)
			if index >= 0 && index < len(cases) {
				// Shrink 'cases' too because the removed case was still active.
				// 因为被移除的 case 仍然处于活跃状态，所以也要缩小 'cases' 的长度。
				cases = f.sendCases[:len(cases)-1]
			}
		} else {
			cases = cases.deactivate(chosen)
			nsent++
		}
	}

	// Forget about the sent value and hand off the send lock.
	// 清除发送的值并释放发送锁。
	for i := firstSubSendCase; i < len(f.sendCases); i++ {
		f.sendCases[i].Send = reflect.Value{}
	}
	f.sendLock <- struct{}{} // Release the send lock. // 释放发送锁。
	return nsent
}

type feedOfSub[T any] struct {
	feed    *FeedOf[T]
	channel chan<- T
	errOnce sync.Once
	err     chan error
}

func (sub *feedOfSub[T]) Unsubscribe() {
	sub.errOnce.Do(func() {
		sub.feed.remove(sub)
		close(sub.err)
	})
}

func (sub *feedOfSub[T]) Err() <-chan error {
	return sub.err
}
