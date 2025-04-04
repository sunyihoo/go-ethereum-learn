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
	"errors"
	"reflect"
	"sync"
)

// errBadChannel indicates that a value passed to Subscribe is not a channel or not sendable.
// errBadChannel 表示传递给 Subscribe 的值不是通道或不可发送。
var errBadChannel = errors.New("event: Subscribe argument does not have sendable channel type") // event: Subscribe 参数没有可发送的通道类型

// Feed implements one-to-many subscriptions where the carrier of events is a channel.
// Feed 实现了一对多的订阅，其中事件的载体是通道。
// Values sent to a Feed are delivered to all subscribed channels simultaneously.
// 发送到 Feed 的值会同时传递给所有订阅的通道。
//
// Feeds can only be used with a single type. The type is determined by the first Send or
// Subscribe operation. Subsequent calls to these methods panic if the type does not
// match.
// Feed 只能用于单一类型。该类型由第一次 Send 或 Subscribe 操作确定。
// 如果后续调用这些方法时的类型不匹配，则会引发 panic。
//
// The zero value is ready to use.
// 零值可以直接使用。
type Feed struct {
	// once ensures that init only runs once for lazy initialization.
	// once 确保 init 方法只运行一次，用于惰性初始化。
	once sync.Once // ensures that init only runs once 确保 init 只运行一次

	// sendLock has a one-element buffer and is empty when held.It protects sendCases.
	// sendLock 有一个大小为 1 的缓冲区，在被持有时为空。它用于保护 sendCases。
	// This acts as a mutex for the Send operation.
	// 这充当 Send 操作的互斥锁。
	sendLock chan struct{}

	// removeSub chan interface{} // interrupts Send when a subscription is removed during a Send operation.
	// removeSub chan interface{} // 当在 Send 操作期间移除订阅时，用于中断 Send 操作。
	removeSub chan interface{}

	// sendCases is the active set of select cases used by Send. sendCases[0] is always the removeSub case.
	// sendCases 是 Send 使用的活动 select case 集合。sendCases[0] 始终是 removeSub case。
	sendCases caseList

	// --- Fields protected by mu ---
	// --- 由 mu 保护的字段 ---

	// mu protects inbox and etype.
	// mu 保护 inbox 和 etype。
	mu sync.Mutex

	// inbox holds newly subscribed channels until they are added to sendCases at the start of the next Send.
	// inbox 持有新订阅的通道，直到它们在下一次 Send 开始时被添加到 sendCases。
	inbox caseList

	// etype stores the required event type for this feed.
	// etype 存储此 feed 所需的事件类型。
	etype reflect.Type
}

// This is the index of the first actual subscription channel in sendCases.
// 这是 sendCases 中第一个实际订阅通道的索引。
// sendCases[0] is a SelectRecv case for the removeSub channel.
// sendCases[0] 是用于 removeSub 通道的 SelectRecv case。
const firstSubSendCase = 1

// feedTypeError represents a type mismatch error during Send or Subscribe.
// feedTypeError 表示在 Send 或 Subscribe 期间发生的类型不匹配错误。
type feedTypeError struct {
	got, want reflect.Type // The type received and the type expected. 接收到的类型和期望的类型。
	op        string       // The operation where the error occurred ("Send" or "Subscribe"). 发生错误的操作（"Send" 或 "Subscribe"）。
}

// Error implements the error interface.
func (e feedTypeError) Error() string {
	return "event: wrong type in " + e.op + " got " + e.got.String() + ", want " + e.want.String() // event: 在 op 操作中类型错误，得到 got，期望 want
}

// init initializes the feed structure. It is called lazily and exactly once by sync.Once.
// init 初始化 feed 结构。它通过 sync.Once 被惰性地、且仅调用一次。
func (f *Feed) init(etype reflect.Type) {
	f.etype = etype                                                                       // Store the event type 存储事件类型
	f.removeSub = make(chan interface{})                                                  // Create remove signal channel 创建移除信号通道
	f.sendLock = make(chan struct{}, 1)                                                   // Create send lock channel (buffered, size 1) 创建发送锁通道（缓冲，大小为 1）
	f.sendLock <- struct{}{}                                                              // Put the initial token into the lock channel 将初始令牌放入锁通道 (使其可用)
	f.sendCases = caseList{{Chan: reflect.ValueOf(f.removeSub), Dir: reflect.SelectRecv}} // Initialize sendCases with the removeSub listener case 用 removeSub 监听 case 初始化 sendCases
}

// Subscribe adds a channel to the feed. Future sends will be delivered on the channel
// until the subscription is canceled. All channels added must have the same element type.
// Subscribe 将一个通道添加到 feed。未来的发送操作将传递到该通道上，
// 直到订阅被取消。所有添加的通道必须具有相同的元素类型。
//
// The channel should have ample buffer space to avoid blocking other subscribers.
// Slow subscribers are not dropped.
// 通道应具有足够的缓冲空间以避免阻塞其他订阅者。
// 慢速订阅者不会被丢弃。
func (f *Feed) Subscribe(channel interface{}) Subscription {
	// 1. Validate input channel using reflection.
	// 1. 使用反射验证输入通道。
	chanval := reflect.ValueOf(channel)
	chantyp := chanval.Type()
	// Must be a channel, must be sendable (SendDir)
	// 必须是通道，必须是可发送的 (SendDir)
	if chantyp.Kind() != reflect.Chan || chantyp.ChanDir()&reflect.SendDir == 0 {
		panic(errBadChannel) // Panic if validation fails 如果验证失败则 panic
	}

	// 2. Create the subscription object.
	// 2. 创建订阅对象。
	sub := &feedSub{feed: f, channel: chanval, err: make(chan error, 1)} // err chan signals Unsubscribe 完成

	// 3. Initialize the feed lazily on the first Subscribe/Send.
	// 3. 在第一次 Subscribe/Send 时惰性初始化 feed。
	// The element type of the first channel determines the feed's type.
	// 第一个通道的元素类型决定了 feed 的类型。
	f.once.Do(func() { f.init(chantyp.Elem()) })

	// 4. Check if the new channel's element type matches the feed's established type.
	// 4. 检查新通道的元素类型是否与 feed 已建立的类型匹配。
	if f.etype != chantyp.Elem() {
		panic(feedTypeError{op: "Subscribe", got: chantyp, want: reflect.ChanOf(reflect.SendDir, f.etype)})
	}

	// 5. Add the channel to the inbox (protected by mutex).
	// 5. 将通道添加到收件箱（受互斥锁保护）。
	f.mu.Lock()
	defer f.mu.Unlock()
	// Add the select case to the inbox.
	// 将 select case 添加到收件箱。
	// The next Send will add it to f.sendCases.
	// 下一次 Send 会将其添加到 f.sendCases。
	cas := reflect.SelectCase{Dir: reflect.SelectSend, Chan: chanval} // Create SelectSend case 创建 SelectSend case
	f.inbox = append(f.inbox, cas)                                    // Append to inbox 追加到收件箱
	return sub                                                        // Return the subscription handle 返回订阅句柄
}

// remove handles the removal of a subscription. It needs to delete the corresponding
// SelectCase from either the inbox or the active sendCases list.
// remove 处理订阅的移除。它需要从 inbox 或活动的 sendCases 列表中删除相应的
// SelectCase。
func (f *Feed) remove(sub *feedSub) {
	// Delete from inbox first, which covers channels
	// that have not been added to f.sendCases yet.
	// 首先从收件箱删除，这涵盖了尚未添加到 f.sendCases 的通道。
	ch := sub.channel.Interface() // Get the raw channel interface 获取原始通道接口
	f.mu.Lock()                   // Lock to access inbox 安全访问 inbox
	index := f.inbox.find(ch)     // Try to find channel in inbox 尝试在 inbox 中查找通道
	if index != -1 {              // Found in inbox? 在 inbox 中找到了？
		f.inbox = f.inbox.delete(index) // Remove from inbox 从 inbox 中移除
		f.mu.Unlock()                   // Unlock and return 解锁并返回
		return
	}
	f.mu.Unlock() // Not in inbox, unlock mu 未在 inbox 中，解锁 mu

	// Not in inbox, so it must be in sendCases (or was).
	// We need to interrupt Send if it's running, or acquire the sendLock
	// if it's not, to safely modify sendCases.
	// 不在 inbox 中，因此它必须在 sendCases 中（或曾经在）。
	// 如果 Send 正在运行，我们需要中断它，或者如果它没有运行，
	// 则获取 sendLock，以安全地修改 sendCases。
	select {
	case f.removeSub <- ch: // Try to signal the running Send operation 尝试向正在运行的 Send 操作发送信号
		// Send will remove the channel from f.sendCases.
		// Send 操作将从 f.sendCases 中移除该通道。
	case <-f.sendLock: // Acquire the send lock (if Send is not running) 获取发送锁（如果 Send 未运行）
		// No Send is in progress, delete the channel now that we have the send lock.
		// 没有 Send 正在进行中，既然我们已持有发送锁，现在删除该通道。
		f.sendCases = f.sendCases.delete(f.sendCases.find(ch)) // Find and delete from sendCases 从 sendCases 中查找并删除
		f.sendLock <- struct{}{}                               // Release the send lock 释放发送锁
	}
}

// Send delivers to all subscribed channels simultaneously.
// Send 同时向所有订阅的通道传递值。
// It returns the number of subscribers that the value was sent to.
// 它返回成功发送值的订阅者数量。
func (f *Feed) Send(value interface{}) (nsent int) {
	// 1. Get reflection value of the input.
	// 1. 获取输入的反射值。
	rvalue := reflect.ValueOf(value)

	// 2. Initialize feed lazily and check type consistency.
	// 2. 惰性初始化 feed 并检查类型一致性。
	f.once.Do(func() { f.init(rvalue.Type()) }) // Lazy init 惰性初始化
	if f.etype != rvalue.Type() {               // Check type 检查类型
		panic(feedTypeError{op: "Send", got: rvalue.Type(), want: f.etype})
	}

	// 3. Acquire the send lock to ensure exclusive access to sendCases.
	// 3. 获取发送锁以确保障对 sendCases 的独占访问。
	<-f.sendLock

	// ---- Send Lock Held ---- // ---- 持有发送锁 ----

	// 4. Move new subscribers from inbox to sendCases.
	// 4. 将新订阅者从 inbox 移动到 sendCases。
	// Add new cases from the inbox after taking the send lock.
	// 获取发送锁后，从收件箱添加新的 case。
	f.mu.Lock()                                   // Lock to access inbox 安全访问 inbox
	f.sendCases = append(f.sendCases, f.inbox...) // Append inbox cases 添加 inbox 中的 case
	f.inbox = nil                                 // Clear inbox 清空 inbox
	f.mu.Unlock()                                 // Unlock mu 解锁 mu

	// 5. Prepare all send cases with the value to be sent.
	// 5. 为所有发送 case 准备要发送的值。
	// Set the sent value on all channels.
	// 在所有通道上设置要发送的值。
	for i := firstSubSendCase; i < len(f.sendCases); i++ {
		f.sendCases[i].Send = rvalue // Set the value field in SelectCase 设置 SelectCase 中的 Send 字段
	}

	// 6. The core sending loop using reflect.Select.
	// 6. 使用 reflect.Select 的核心发送循环。
	// Send until all channels except removeSub have been chosen. 'cases' tracks a prefix
	// of sendCases. When a send succeeds, the corresponding case moves to the end of
	// 'cases' and it shrinks by one element.
	// 发送直到除 removeSub 之外的所有通道都被选中。'cases' 跟踪 sendCases 的一个前缀。
	// 当发送成功时，相应的 case 会移动到 'cases' 的末尾，并且其长度减一。
	cases := f.sendCases // 'cases' is the shrinking slice of active cases 'cases' 是活动 case 的收缩切片
	for {
		// Fast path: try sending without blocking before adding to the select set.
		// This should usually succeed if subscribers are fast enough and have free
		// buffer space.
		// 快速路径：在添加到 select 集合之前尝试非阻塞发送。
		// 如果订阅者速度足够快且有空闲的缓冲空间，这通常会成功。
		for i := firstSubSendCase; i < len(cases); i++ {
			if cases[i].Chan.TrySend(rvalue) { // Attempt non-blocking send 尝试非阻塞发送
				nsent++                     // Increment count 增加计数
				cases = cases.deactivate(i) // Deactivate successful case 停用成功的 case
				i--                         // Adjust index after deactivation 停用后调整索引
			}
		}
		// If all sends completed in fast path, or only removeSub remains.
		// 如果所有发送都在快速路径中完成，或者只剩下 removeSub。
		if len(cases) == firstSubSendCase {
			break // Exit loop 退出循环
		}

		// Blocking path: Wait for at least one case to become ready.
		// 阻塞路径：等待至少一个 case 准备就绪。
		// Select on all the receivers, waiting for them to unblock.
		// 在所有接收器上执行 select，等待它们解除阻塞。
		chosen, recv, _ := reflect.Select(cases) // Block until a case is selected 阻塞直到一个 case 被选中

		if chosen == 0 /* <-f.removeSub */ { // Case 0 is always removeSub Case 0 始终是 removeSub
			// An unsubscribe request arrived during send.
			// 在发送期间收到了取消订阅请求。
			index := f.sendCases.find(recv.Interface()) // Find the channel in the original list 在原始列表中找到该通道
			f.sendCases = f.sendCases.delete(index)     // Delete from original list 从原始列表中删除
			if index >= 0 && index < len(cases) {       // Was it part of the active 'cases'? 它是活动的 'cases' 的一部分吗？
				// Shrink 'cases' too because the removed case was still active.
				// 同时收缩 'cases'，因为被移除的 case 仍然是活动的。
				// Note: This re-slices f.sendCases which was just modified.
				// 注意：这将重新切片刚刚被修改的 f.sendCases。
				cases = f.sendCases[:len(cases)-1]
			}
		} else { // A send to a subscriber channel succeeded 一个对订阅者通道的发送成功了
			cases = cases.deactivate(chosen) // Deactivate the chosen case 停用选中的 case
			nsent++                          // Increment count 增加计数
		}
	} // End of sending loop 发送循环结束

	// 7. Clean up: Remove references to the sent value from sendCases.
	// 7. 清理：从 sendCases 中移除对已发送值的引用。
	// Forget about the sent value and hand off the send lock.
	// 忘记已发送的值并交出发送锁。
	for i := firstSubSendCase; i < len(f.sendCases); i++ {
		f.sendCases[i].Send = reflect.Value{} // Zero out the Send field 将 Send 字段置零
	}

	// 8. Release the send lock.
	// 8. 释放发送锁。
	f.sendLock <- struct{}{}
	// ---- Send Lock Released ---- // ---- 发送锁已释放 ----
	return nsent // Return number of successful sends 返回成功发送的数量
}

// feedSub represents a single subscription managed by a Feed.
// feedSub 表示由 Feed 管理的单个订阅。
type feedSub struct {
	feed    *Feed         // Reference to the parent feed 对父 feed 的引用
	channel reflect.Value // The subscriber's channel value 订阅者的通道值
	errOnce sync.Once     // Ensures Unsubscribe logic runs only once 确保 Unsubscribe 逻辑只运行一次
	err     chan error    // Closed when Unsubscribe is called 当调用 Unsubscribe 时关闭
}

// Unsubscribe removes the subscription from the feed.
// Unsubscribe 从 feed 中移除订阅。
func (sub *feedSub) Unsubscribe() {
	// Use sync.Once to make Unsubscribe idempotent.
	// 使用 sync.Once 使 Unsubscribe 成为幂等的。
	sub.errOnce.Do(func() {
		sub.feed.remove(sub) // Tell the feed to remove this subscription 告诉 feed 移除此订阅
		close(sub.err)       // Close the error channel to signal completion 关闭错误通道以表示完成
	})
}

// Err returns a channel that is closed when the subscription is unsubscribed.
// Err 返回一个通道，该通道在取消订阅时关闭。
// This is useful for select statements waiting on the subscription lifecycle.
// 这对于等待订阅生命周期的 select 语句很有用。
func (sub *feedSub) Err() <-chan error {
	return sub.err
}

// caseList is a helper type for managing a slice of reflect.SelectCase.
// caseList 是用于管理 reflect.SelectCase 切片的辅助类型。
type caseList []reflect.SelectCase

// find returns the index of a case containing the given channel interface.
// find 返回包含给定通道接口的 case 的索引。
func (cs caseList) find(channel interface{}) int {
	for i, cas := range cs {
		// Check Chan field, which should be valid for Send and Recv cases we use.
		// 检查 Chan 字段，这对于我们使用的 Send 和 Recv case 应该是有效的。
		if cas.Chan.IsValid() && cas.Chan.Interface() == channel {
			return i // Return index if found 如果找到则返回索引
		}
	}
	return -1 // Not found 未找到
}

// delete removes the case at the given index from cs.
// delete 从 cs 中移除给定索引处的 case。
// Note: This allocates a new slice.
// 注意：这会分配一个新的切片。
func (cs caseList) delete(index int) caseList {
	if index < 0 || index >= len(cs) {
		return cs // Index out of bounds, return original slice 索引越界，返回原始切片
	}
	return append(cs[:index], cs[index+1:]...) // Standard slice deletion 标准切片删除
}

// deactivate moves the case at index into the non-accessible portion of the cs slice
// by swapping it with the last element and returning a shorter slice view.
// deactivate 通过将索引处的 case 与最后一个元素交换，并返回一个较短的切片视图，
// 将其移动到 cs 切片的不可访问部分。
// This avoids allocation during the Send loop.
// 这避免了在 Send 循环期间的分配。
func (cs caseList) deactivate(index int) caseList {
	last := len(cs) - 1                       // Index of the last element 最后一个元素的索引
	cs[index], cs[last] = cs[last], cs[index] // Swap chosen case with the last one 将选中的 case 与最后一个交换
	return cs[:last]                          // Return slice excluding the last element 返回不包括最后一个元素的切片
}

/* // String method for debugging caseList (commented out in original) 用于调试 caseList 的 String 方法（在原始代码中注释掉了）
func (cs caseList) String() string {
	s := "["
	for i, cas := range cs {
			if i != 0 {
					s += ", "
			}
			switch cas.Dir {
			case reflect.SelectSend:
					s += fmt.Sprintf("%v<-", cas.Chan.Interface())
			case reflect.SelectRecv:
					s += fmt.Sprintf("<-%v", cas.Chan.Interface())
			}
	}
	return s + "]"
}
*/
