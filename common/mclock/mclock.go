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

//go:noescape
//go:linkname nanotime runtime.nanotime
func nanotime() int64

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
