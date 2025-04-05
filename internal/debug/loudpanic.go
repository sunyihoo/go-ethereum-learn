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

package debug

import "runtime/debug"

// LoudPanic panics in a way that gets all goroutine stacks printed on stderr.
// LoudPanic 以一种方式触发 panic，同时将所有 goroutine 的堆栈信息打印到标准错误输出 (stderr)。
func LoudPanic(x interface{}) {
	debug.SetTraceback("all") // 设置调试回溯级别为 "all"，确保在 panic 时打印所有 goroutine 的堆栈信息。
	panic(x)                  // 触发 panic，传入的参数 x 将作为 panic 的值。
}
