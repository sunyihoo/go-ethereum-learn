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

// Package mclock is a wrapper for a monotonic clock source
package mclock

import (
	"time"

	_ "unsafe" // for go:linkname
)

// go:noescape这是一个编译器指令，告知编译器该函数不会逃逸到堆（heap）
// 逃逸分析（escape analysis）是 Go 编译器优化的一部分，用于确定变量是分配在栈上还是堆上。noescape 指令告诉编译器，该函数的参数或返回值不会逃逸到堆，从而允许编译器进行优化。
// noescape 的作用是确保 nanotime 函数的调用不会导致额外的内存分配
//
// go:linkname这是一个链接指令，将当前包中的 nanotime 函数与 Go 运行时（runtime）中的 runtime.nanotime 函数进行链接
// runtime.nanotime 是 Go 运行时内部的一个函数，用于获取高精度的纳秒级时间戳
// 通过 linkname，可以直接调用运行时内部的 nanotime 函数，而无需通过标准的 time 包。

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64 // 用于获取当前时间的纳秒级时间戳，返回一个 int64 类型的值。

// AbsTime represents absolute monotonic time.
type AbsTime int64

// Now returns the current absolute monotonic time.
func Now() AbsTime {
	return AbsTime(nanotime())
}

// Add returns t + d as absolute time.
func (t AbsTime) Add(d time.Duration) AbsTime {
	return t + AbsTime(d)
}

// Sub returns t - t2 as a duration.
func (t AbsTime) Sub(t2 AbsTime) time.Duration {
	return time.Duration(t - t2)
}

// 模拟时钟（Simulated Clock）：
// 模拟时钟是一种虚拟时钟，通常用于测试或模拟场景。
// 它可以手动控制时间的流逝，例如在测试中快速推进时间，或在特定时间触发事件。
// 通过实现 Clock 接口，可以创建一个模拟时钟来替代系统时钟。

// 单调时钟（Monotonic Clock）：
// 单调时钟是一种不会回退的时钟，通常用于测量时间间隔（如程序运行时间）。
// 与墙钟（Wall Clock）不同，单调时钟不受系统时间调整（如手动修改时间或 NTP 同步）的影响。
// Go 中的 time.Now() 可以返回单调时钟的时间戳。

// The Clock interface makes it possible to replace the monotonic system clock with
// a simulated clock.
// Clock 接口使得可以用模拟时钟替换单调系统时钟。
type Clock interface {
	Now() AbsTime
	Sleep(time.Duration)
	NewTimer(time.Duration) ChanTimer
	After(time.Duration) <-chan AbsTime
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a cancellable event created by AfterFunc.
type Timer interface {
	// Stop cancels the timer. It returns false if the timer has already
	// expired or been stopped.
	Stop() bool
}

// ChanTimer is a cancellable event created by NewTimer.
type ChanTimer interface {
	Timer

	// The channel returned by C receives a value when the timer expires.
	C() <-chan AbsTime
	// Reset reschedules the timer with a new timeout.
	// It should be invoked only on stopped or expired timers with drained channels.
	Reset(time.Duration)
}

// System implements Clock using the system clock.
type System struct{}

// Now returns the current monotonic time.
func (c System) Now() AbsTime {
	return Now()
}

// Sleep blocks for the given duration.
func (c System) Sleep(d time.Duration) {
	time.Sleep(d)
}

// NewTimer creates a timer which can be rescheduled.
// NewTimer 创建一个可以重新计划的计时器
func (c System) NewTimer(d time.Duration) ChanTimer {
	ch := make(chan AbsTime, 1)
	t := time.AfterFunc(d, func() {
		// This send is non-blocking because that's how time.Timer
		// behaves. It doesn't matter in the happy case, but does
		// when Reset is misused.
		// 这个发送操作是非阻塞的，因为 time.Timer 的行为就是如此。
		// 在正常情况下这没有影响，但当 Reset 被误用时，这很重要。
		select {
		case ch <- c.Now():
		default:
		}
	})
	return &systemTimer{t, ch}
}

// After returns a channel which receives the current time after d has elapsed.
func (c System) After(d time.Duration) <-chan AbsTime {
	ch := make(chan AbsTime, 1)
	time.AfterFunc(d, func() { ch <- c.Now() })
	return ch
}

// AfterFunc runs f on a new goroutine after the duration has elapsed.
func (c System) AfterFunc(d time.Duration, f func()) Timer {
	return time.AfterFunc(d, f)
}

type systemTimer struct {
	*time.Timer
	ch <-chan AbsTime
}

func (st *systemTimer) Reset(d time.Duration) {
	st.Timer.Reset(d)
}

func (st *systemTimer) C() <-chan AbsTime {
	return st.ch
}
