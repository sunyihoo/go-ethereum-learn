// Copyright 2014 The go-ethereum Authors
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

// Package event deals with subscriptions to real-time events.
package event

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// TypeMuxEvent is a time-tagged notification pushed to subscribers.
// TypeMuxEvent 是推送给订阅者、带有时间戳的通知。
type TypeMuxEvent struct {
	Time time.Time   // The time when the event was Post'ed. 事件被 Post 的时间。
	Data interface{} // The actual event data. 实际的事件数据。
}

// A TypeMux dispatches events to registered receivers. Receivers can be
// registered to handle events of certain type. Any operation
// called after mux is stopped will return ErrMuxClosed.
// TypeMux 将事件分发给已注册的接收者。可以注册接收者
// 来处理特定类型的事件。在 mux 停止后调用的任何操作
// 都将返回 ErrMuxClosed。
//
// The zero value is ready to use.
// 零值可以直接使用。
//
// Deprecated: use Feed
// 已弃用：请使用 Feed
type TypeMux struct {
	// mutex protects the subm map and stopped field. RWMutex allows concurrent Posts.
	// mutex 保护 subm 映射和 stopped 字段。RWMutex 允许并发的 Post 操作。
	mutex sync.RWMutex

	// subm maps event types to slices of subscriptions interested in that type.
	// subm 将事件类型映射到对此类型感兴趣的订阅切片。
	subm map[reflect.Type][]*TypeMuxSubscription

	// stopped indicates whether the mux has been stopped.
	// stopped 指示 mux 是否已停止。
	stopped bool
}

// ErrMuxClosed is returned when Posting on a closed TypeMux.
// ErrMuxClosed 在对已关闭的 TypeMux 进行 Post 操作时返回。
var ErrMuxClosed = errors.New("event: mux closed") // event: mux 已关闭

// Subscribe creates a subscription for events of the given types. The
// subscription's channel is closed when it is unsubscribed
// or the mux is closed.
// Subscribe 为给定类型的事件创建一个订阅。当取消订阅
// 或 mux 关闭时，订阅的通道将被关闭。
func (mux *TypeMux) Subscribe(types ...interface{}) *TypeMuxSubscription {
	// 1. Create a new subscription object.
	// 1. 创建一个新的订阅对象。
	sub := newsub(mux)

	// 2. Acquire write lock to modify the subscription map.
	// 2. 获取写锁以修改订阅映射。
	mux.mutex.Lock()
	defer mux.mutex.Unlock()

	// 3. Check if mux is already stopped.
	// 3. 检查 mux 是否已经停止。
	if mux.stopped {
		// set the status to closed so that calling Unsubscribe after this
		// call will short circuit.
		// 将状态设置为 closed，以便在此调用之后调用 Unsubscribe 将短路。
		sub.closed = true // Mark subscription as closed 标记订阅为已关闭
		close(sub.postC)  // Close the internal post channel 关闭内部 post 通道
	} else {
		// 4. Initialize the map if it's the first subscription.
		// 4. 如果是第一个订阅，则初始化映射。
		if mux.subm == nil {
			mux.subm = make(map[reflect.Type][]*TypeMuxSubscription, len(types))
		}
		// 5. Register the subscription for each requested type.
		// 5. 为每个请求的类型注册订阅。
		for _, t := range types {
			rtyp := reflect.TypeOf(t) // Get the type 获取类型
			oldsubs := mux.subm[rtyp] // Get existing subscriptions for this type 获取此类型的现有订阅
			// Check for duplicate registration within this single Subscribe call.
			// 检查在此次 Subscribe 调用中是否重复注册。
			if find(oldsubs, sub) != -1 { // find is a helper function 查找是辅助函数
				// Note: This panic might not be ideal behavior for library users.
				// 注意：对于库用户来说，此 panic 可能不是理想的行为。
				panic(fmt.Sprintf("event: duplicate type %s in Subscribe", rtyp)) // event: Subscribe 中存在重复类型 rtyp
			}
			// Create a new slice with room for the new subscription.
			// 创建一个新切片，为新订阅留出空间。
			subs := make([]*TypeMuxSubscription, len(oldsubs)+1)
			copy(subs, oldsubs)      // Copy existing subscriptions 复制现有订阅
			subs[len(oldsubs)] = sub // Add the new subscription 添加新订阅
			mux.subm[rtyp] = subs    // Update the map 更新映射
		}
	}
	// 6. Return the subscription object.
	// 6. 返回订阅对象。
	return sub
}

// Post sends an event to all receivers registered for the given type.
// Post 将事件发送给所有注册了给定类型的接收者。
// It returns ErrMuxClosed if the mux has been stopped.
// 如果 mux 已停止，则返回 ErrMuxClosed。
func (mux *TypeMux) Post(ev interface{}) error {
	// 1. Wrap the event data with a timestamp.
	// 1. 用时间戳包装事件数据。
	event := &TypeMuxEvent{
		Time: time.Now(), // Record current time 记录当前时间
		Data: ev,         // Store the original event data 存储原始事件数据
	}
	rtyp := reflect.TypeOf(ev) // Get the type of the event data 获取事件数据的类型

	// 2. Acquire read lock to access the subscription map safely.
	// 2. 获取读锁以安全访问订阅映射。
	mux.mutex.RLock()
	// 3. Check if mux is stopped while holding the lock.
	// 3. 在持有锁的同时检查 mux 是否已停止。
	if mux.stopped {
		mux.mutex.RUnlock() // Release lock before returning 释放锁再返回
		return ErrMuxClosed
	}
	// 4. Get the list of subscribers for this event type.
	// 4. 获取此事件类型的订阅者列表。
	subs := mux.subm[rtyp]
	// 5. Release read lock. Delivery happens outside the lock.
	// 5. 释放读锁。传递发生在锁之外。
	mux.mutex.RUnlock()

	// 6. Deliver the event to each subscriber in the list.
	// 6. 将事件传递给列表中的每个订阅者。
	for _, sub := range subs {
		sub.deliver(event) // Call deliver method on the subscription object 在订阅对象上调用 deliver 方法
	}
	return nil // Success 成功
}

// Stop closes a mux. The mux can no longer be used.
// Stop 关闭一个 mux。该 mux 不能再被使用。
// Future Post calls will fail with ErrMuxClosed.
// 未来的 Post 调用将失败并返回 ErrMuxClosed。
// Stop blocks until all current deliveries have finished.
// Stop 会阻塞，直到所有当前的传递完成。 (Note: deliveries happen outside lock, so this blocking is implicit in closing subs) (注意：传递发生在锁之外，因此这种阻塞隐含在关闭订阅中)
func (mux *TypeMux) Stop() {
	// 1. Acquire write lock for exclusive access.
	// 1. 获取写锁以进行独占访问。
	mux.mutex.Lock()
	defer mux.mutex.Unlock()
	// 2. Iterate through all subscriptions and close them.
	// 2. 遍历所有订阅并关闭它们。
	for _, subs := range mux.subm {
		for _, sub := range subs {
			sub.closewait() // Close each subscription 关闭每个订阅
		}
	}
	// 3. Clear the subscription map and mark as stopped.
	// 3. 清空订阅映射并标记为已停止。
	mux.subm = nil
	mux.stopped = true
}

// del removes a subscription 's' from the mux's internal map.
// del 从 mux 的内部映射中移除订阅 's'。
// Called by TypeMuxSubscription.Unsubscribe.
// 由 TypeMuxSubscription.Unsubscribe 调用。
func (mux *TypeMux) del(s *TypeMuxSubscription) {
	// 1. Acquire write lock.
	// 1. 获取写锁。
	mux.mutex.Lock()
	defer mux.mutex.Unlock()
	// 2. Iterate through all types in the map.
	// 2. 遍历映射中的所有类型。
	for typ, subs := range mux.subm {
		// 3. Find the subscription in the slice for this type.
		// 3. 在此类型的切片中查找订阅。
		if pos := find(subs, s); pos >= 0 { // find is a helper function 查找是辅助函数
			// 4. Remove the subscription from the slice.
			// 4. 从切片中移除订阅。
			if len(subs) == 1 { // If it was the last one for this type 如果是此类型的最后一个
				delete(mux.subm, typ) // Delete the type entry from map 从映射中删除该类型条目
			} else { // Otherwise, remove element from slice 否则，从切片中移除元素
				mux.subm[typ] = posdelete(subs, pos) // posdelete is a helper function posdelete 是辅助函数
			}
			// Note: A subscription might be listed under multiple types,
			// but Unsubscribe only needs to remove it once effectively.
			// The loop continues but `find` won't find it again.
			// 注意：一个订阅可能列在多个类型下，
			// 但 Unsubscribe 实际上只需要移除它一次。
			// 循环会继续，但 `find` 不会再次找到它。
		}
	}
}

// find is a helper to find a subscription pointer in a slice.
// find 是在切片中查找订阅指针的辅助函数。
func find(slice []*TypeMuxSubscription, item *TypeMuxSubscription) int {
	for i, v := range slice {
		if v == item { // Pointer comparison 指针比较
			return i // Return index 返回索引
		}
	}
	return -1 // Not found 未找到
}

// posdelete removes the element at index 'pos' from the slice by creating a new slice.
// posdelete 通过创建一个新切片来移除切片中索引 'pos' 处的元素。
// Note: This allocates memory for a new slice.
// 注意：这会为新切片分配内存。
func posdelete(slice []*TypeMuxSubscription, pos int) []*TypeMuxSubscription {
	news := make([]*TypeMuxSubscription, len(slice)-1) // Allocate new slice 分配新切片
	copy(news[:pos], slice[:pos])                      // Copy elements before pos 复制 pos 之前的元素
	copy(news[pos:], slice[pos+1:])                    // Copy elements after pos 复制 pos 之后的元素
	return news                                        // Return the new slice 返回新切片
}

// TypeMuxSubscription is a subscription established through TypeMux.
// TypeMuxSubscription 是通过 TypeMux 建立的订阅。
type TypeMuxSubscription struct {
	mux     *TypeMux      // Reference back to the parent mux 对父 mux 的引用
	created time.Time     // Timestamp when the subscription was created 订阅创建时的时间戳
	closeMu sync.Mutex    // Protects access to 'closed' flag and channel closing logic 保护对 'closed' 标志和通道关闭逻辑的访问
	closing chan struct{} // Internal channel closed to signal termination 内部通道，关闭以表示终止
	closed  bool          // Flag indicating the subscription is closed 标志，指示订阅已关闭

	// these two are the same channel. they are stored separately so
	// postC can be set to nil without affecting the return value of
	// Chan.
	// 这两个是同一个通道。它们分开存储，以便
	// postC 可以设置为 nil 而不影响
	// Chan 的返回值。
	postMu sync.RWMutex         // Protects postC during delivery and closing 在传递和关闭期间保护 postC
	readC  <-chan *TypeMuxEvent // The channel returned to the user (read-only view) 返回给用户的通道（只读视图）
	postC  chan<- *TypeMuxEvent // The channel used for posting internally (write-only view) 内部用于发送的通道（只写视图）
}

// newsub creates a new subscription object.
// newsub 创建一个新的订阅对象。
func newsub(mux *TypeMux) *TypeMuxSubscription {
	c := make(chan *TypeMuxEvent) // Create the underlying channel 创建底层通道
	return &TypeMuxSubscription{
		mux:     mux,                 // Set parent mux 设置父 mux
		created: time.Now(),          // Record creation time 记录创建时间
		readC:   c,                   // Set read-only view 设置只读视图
		postC:   c,                   // Set write-only view 设置只写视图
		closing: make(chan struct{}), // Create closing signal channel 创建关闭信号通道
	}
}

// Chan returns the channel that receives events for this subscription.
// Chan 返回接收此订阅事件的通道。
func (s *TypeMuxSubscription) Chan() <-chan *TypeMuxEvent {
	return s.readC // Return the read-only channel 返回只读通道
}

// Unsubscribe removes the subscription from the mux and closes its channel.
// Unsubscribe 从 mux 中移除订阅并关闭其通道。
func (s *TypeMuxSubscription) Unsubscribe() {
	s.mux.del(s)  // Tell the mux to remove this subscription 告诉 mux 移除此订阅
	s.closewait() // Close the subscription's channels and mark as closed 关闭订阅的通道并标记为已关闭
}

// Closed returns whether the subscription has been closed.
// Closed 返回订阅是否已关闭。
func (s *TypeMuxSubscription) Closed() bool {
	s.closeMu.Lock()         // Lock to access 'closed' flag 安全访问 'closed' 标志
	defer s.closeMu.Unlock() // Ensure unlock 确保解锁
	return s.closed
}

// closewait closes the subscription channels and marks it as closed. Idempotent.
// closewait 关闭订阅通道并将其标记为已关闭。幂等操作。
func (s *TypeMuxSubscription) closewait() {
	s.closeMu.Lock()         // Lock for exclusive access 锁定以进行独占访问
	defer s.closeMu.Unlock() // Ensure unlock 确保解锁
	if s.closed {            // Check if already closed 检查是否已关闭
		return // Do nothing if already closed 如果已关闭则不执行任何操作
	}
	close(s.closing) // Close the internal 'closing' signal channel 关闭内部 'closing' 信号通道
	s.closed = true  // Mark as closed 标记为已关闭

	// Lock the post channel access
	// 锁定 post 通道访问
	s.postMu.Lock()
	defer s.postMu.Unlock() // Ensure unlock 确保解锁
	// Close the actual event channel (safe due to lock)
	// 关闭实际的事件通道（由于锁的存在是安全的）
	close(s.postC)
	// Set postC to nil to prevent further writes (although close should suffice)
	// 将 postC 设置为 nil 以防止进一步写入（尽管 close 应该足够了）
	s.postC = nil
}

// deliver attempts to send an event to the subscription's channel.
// deliver 尝试将事件发送到订阅的通道。
// It handles potential concurrent closure and drops stale events.
// 它处理潜在的并发关闭并丢弃过时的事件。
func (s *TypeMuxSubscription) deliver(event *TypeMuxEvent) {
	// Short circuit delivery if stale event (event posted before subscription)
	// 如果是过时事件（事件在订阅之前发布），则短路传递
	if s.created.After(event.Time) {
		return
	}

	// Acquire read lock for post channel access. Allows concurrent deliveries
	// if the channel isn't blocked, while still coordinating with closewait.
	// 获取 post 通道访问的读锁。如果通道未阻塞，则允许并发传递，
	// 同时仍与 closewait 协调。
	s.postMu.RLock()
	defer s.postMu.RUnlock() // Ensure unlock 确保解锁

	// Use select to attempt send or detect closure.
	// 使用 select 尝试发送或检测关闭。
	select {
	case s.postC <- event: // Try sending the event 尝试发送事件
	case <-s.closing: // Abort if the 'closing' channel is closed 如果 'closing' 通道已关闭则中止
		// This prevents a panic if Unsubscribe/Stop runs concurrently.
		// 这可以防止在 Unsubscribe/Stop 并发运行时发生 panic。
	}
}
