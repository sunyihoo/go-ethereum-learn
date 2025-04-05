// Copyright 2021 The go-ethereum Authors
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

// Package syncx contains exotic synchronization primitives.
// syncx 包包含一些特殊的同步原语。
package syncx

// ClosableMutex is a mutex that can also be closed.
// Once closed, it can never be taken again.
// ClosableMutex 是一个可以被关闭的互斥锁。一旦被关闭，就不能再被获取。
type ClosableMutex struct {
	ch chan struct{}
}

// NewClosableMutex creates a new ClosableMutex.
// NewClosableMutex 创建一个新的 ClosableMutex。
func NewClosableMutex() *ClosableMutex {
	ch := make(chan struct{}, 1) // Create a buffered channel with a capacity of 1. This channel is used to represent the lock.
	// 创建一个容量为 1 的缓冲通道。这个通道用于表示锁。
	ch <- struct{}{} // Send an empty struct into the channel, representing that the mutex is initially unlocked.
	// 向通道发送一个空结构体，表示互斥锁最初是未锁定的。
	return &ClosableMutex{ch}
}

// TryLock attempts to lock cm.
// If the mutex is closed, TryLock returns false.
// TryLock 尝试锁定 cm。如果互斥锁已关闭，TryLock 返回 false。
func (cm *ClosableMutex) TryLock() bool {
	_, ok := <-cm.ch // Try to receive a value from the channel. If successful (channel is not empty and not closed), it means the lock was acquired.
	// 尝试从通道接收一个值。如果成功（通道非空且未关闭），则表示锁已获取。
	return ok // 'ok' will be true if the channel was open and a value was received, false otherwise (channel closed).
	// 如果通道是打开的并且接收到了一个值，则 'ok' 为 true，否则（通道已关闭）为 false。
}

// MustLock locks cm.
// If the mutex is closed, MustLock panics.
// MustLock 锁定 cm。如果互斥锁已关闭，MustLock 会 panic。
func (cm *ClosableMutex) MustLock() {
	_, ok := <-cm.ch // Try to receive a value from the channel.
	// 尝试从通道接收一个值。
	if !ok {
		panic("mutex closed") // If the channel is closed, it means the mutex cannot be locked anymore, so panic.
		// 如果通道已关闭，表示互斥锁不能再被锁定，因此 panic。
	}
}

// Unlock unlocks cm.
// Unlock 解锁 cm。
func (cm *ClosableMutex) Unlock() {
	select {
	case cm.ch <- struct{}{}: // Try to send an empty struct back into the channel, representing that the lock is released.
		// 尝试向通道发送一个空结构体，表示锁已释放。
	default:
		panic("Unlock of already-unlocked ClosableMutex") // If the channel is already full (a value is present), it means the mutex was already unlocked.
		// 如果通道已满（已存在一个值），表示互斥锁已经被解锁了。
	}
}

// Close locks the mutex, then closes it.
// Close 锁定互斥锁，然后将其关闭。
func (cm *ClosableMutex) Close() {
	_, ok := <-cm.ch // Try to receive a value from the channel, effectively acquiring the lock.
	// 尝试从通道接收一个值，相当于获取锁。
	if !ok {
		panic("Close of already-closed ClosableMutex") // If the channel is already closed, it means the mutex was already closed.
		// 如果通道已经关闭，表示互斥锁已经被关闭了。
	}
	close(cm.ch) // Close the channel. After this, no more values can be received from or sent to the channel.
	// 关闭通道。在此之后，不能再从该通道接收或发送任何值。
}
