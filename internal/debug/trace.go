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

import (
	"errors"
	"os"
	"runtime/trace"

	"github.com/ethereum/go-ethereum/log"
)

// StartGoTrace turns on tracing, writing to the given file.
// StartGoTrace 开启跟踪，将跟踪数据写入指定的文件。
func (h *HandlerT) StartGoTrace(file string) error {
	h.mu.Lock() // 加锁以确保对共享资源的安全访问。
	defer h.mu.Unlock()
	if h.traceW != nil { // 如果 traceW 不为 nil，说明已经有正在进行的跟踪。
		return errors.New("trace already in progress") // 返回错误，提示跟踪已经在进行中。
	}
	f, err := os.Create(expandHome(file)) // 创建文件，expandHome 用于处理路径中的 ~ 符号。
	if err != nil {
		return err // 如果文件创建失败，返回错误。
	}
	if err := trace.Start(f); err != nil { // 调用 trace.Start 开始跟踪，f 是目标文件。
		f.Close()  // 如果跟踪启动失败，关闭文件以释放资源。
		return err // 返回错误。
	}
	h.traceW = f                                        // 将文件句柄赋值给 traceW，表示跟踪正在进行。
	h.traceFile = file                                  // 记录当前跟踪文件的路径。
	log.Info("Go tracing started", "dump", h.traceFile) // 记录日志，指示跟踪已开始。
	return nil
}

// StopGoTrace stops an ongoing trace.
// StopGoTrace 停止正在进行的跟踪。
func (h *HandlerT) StopGoTrace() error {
	h.mu.Lock() // 加锁以确保对共享资源的安全访问。
	defer h.mu.Unlock()
	trace.Stop()         // 调用 trace.Stop 停止跟踪。
	if h.traceW == nil { // 如果 traceW 为 nil，说明没有正在进行的跟踪。
		return errors.New("trace not in progress") // 返回错误，提示没有跟踪在进行中。
	}
	log.Info("Done writing Go trace", "dump", h.traceFile) // 记录日志，指示跟踪已完成。
	h.traceW.Close()                                       // 关闭文件句柄以释放资源。
	h.traceW = nil                                         // 将 traceW 置为 nil，表示跟踪已停止。
	h.traceFile = ""                                       // 清空跟踪文件路径。
	return nil
}
