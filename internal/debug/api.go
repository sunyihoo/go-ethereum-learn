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

// Package debug interfaces Go runtime debugging facilities.
// This package is mostly glue code making these facilities available
// through the CLI and RPC subsystem. If you want to use them from Go code,
// use package runtime instead.
package debug

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/go-bexpr"
)

// Handler is the global debugging handler.
// Handler 是全局调试处理程序。
var Handler = new(HandlerT)

// HandlerT implements the debugging API.
// Do not create values of this type, use the one
// in the Handler variable instead.
// HandlerT 实现调试 API。不要创建此类型的值，请改用 Handler 变量中的值。
type HandlerT struct {
	mu        sync.Mutex     // 互斥锁，保护以下字段。
	cpuW      io.WriteCloser // 用于写入 CPU 性能分析数据的文件句柄。
	cpuFile   string         // 当前 CPU 性能分析文件的路径。
	traceW    io.WriteCloser // 用于写入跟踪数据的文件句柄。
	traceFile string         // 当前跟踪文件的路径。
}

// Verbosity sets the log verbosity ceiling. The verbosity of individual packages
// and source files can be raised using Vmodule.
// Verbosity 设置日志详细程度上限。可以使用 Vmodule 提高单个包和源文件的详细程度。
func (*HandlerT) Verbosity(level int) {
	glogger.Verbosity(log.FromLegacyLevel(level)) // 设置全局日志记录器的详细程度。
}

// Vmodule sets the log verbosity pattern. See package log for details on the
// pattern syntax.
// Vmodule 设置日志详细模式。有关 pattern 语法的详细信息，请参阅 package log。
func (*HandlerT) Vmodule(pattern string) error {
	return glogger.Vmodule(pattern) // 设置模块级别的日志详细程度模式。
}

// MemStats returns detailed runtime memory statistics.
// MemStats 返回详细的运行时内存统计信息。
func (*HandlerT) MemStats() *runtime.MemStats {
	s := new(runtime.MemStats)
	runtime.ReadMemStats(s) // 读取当前运行时的内存统计信息。
	return s
}

// GcStats returns GC statistics.
// GcStats 返回垃圾回收（GC）统计信息。
func (*HandlerT) GcStats() *debug.GCStats {
	s := new(debug.GCStats)
	debug.ReadGCStats(s) // 读取垃圾回收的统计信息。
	return s
}

// CpuProfile turns on CPU profiling for nsec seconds and writes
// profile data to file.
// CpuProfile 启动 CPU 性能分析，持续 nsec 秒，并将性能分析数据写入文件。
func (h *HandlerT) CpuProfile(file string, nsec uint) error {
	if err := h.StartCPUProfile(file); err != nil { // 启动 CPU 性能分析。
		return err
	}
	time.Sleep(time.Duration(nsec) * time.Second) // 等待指定的时间。
	h.StopCPUProfile()                            // 停止 CPU 性能分析。
	return nil
}

// StartCPUProfile turns on CPU profiling, writing to the given file.
// StartCPUProfile 启动 CPU 性能分析，将数据写入指定的文件。
func (h *HandlerT) StartCPUProfile(file string) error {
	h.mu.Lock() // 加锁以确保对共享资源的安全访问。
	defer h.mu.Unlock()
	if h.cpuW != nil { // 如果 cpuW 不为 nil，说明已有性能分析正在进行。
		return errors.New("CPU profiling already in progress") // 返回错误，提示性能分析已经在进行中。
	}
	f, err := os.Create(expandHome(file)) // 创建文件，expandHome 用于处理路径中的 ~ 符号。
	if err != nil {
		return err // 如果文件创建失败，返回错误。
	}
	if err := pprof.StartCPUProfile(f); err != nil { // 调用 pprof.StartCPUProfile 开始性能分析。
		f.Close()  // 如果性能分析启动失败，关闭文件以释放资源。
		return err // 返回错误。
	}
	h.cpuW = f                                           // 将文件句柄赋值给 cpuW，表示性能分析正在进行。
	h.cpuFile = file                                     // 记录当前性能分析文件的路径。
	log.Info("CPU profiling started", "dump", h.cpuFile) // 记录日志，指示性能分析已开始。
	return nil
}

// StopCPUProfile stops an ongoing CPU profile.
// StopCPUProfile 停止正在进行的 CPU 性能分析。
func (h *HandlerT) StopCPUProfile() error {
	h.mu.Lock() // 加锁以确保对共享资源的安全访问。
	defer h.mu.Unlock()
	pprof.StopCPUProfile() // 调用 pprof.StopCPUProfile 停止性能分析。
	if h.cpuW == nil {     // 如果 cpuW 为 nil，说明没有性能分析正在进行。
		return errors.New("CPU profiling not in progress") // 返回错误，提示没有性能分析在进行中。
	}
	log.Info("Done writing CPU profile", "dump", h.cpuFile) // 记录日志，指示性能分析已完成。
	h.cpuW.Close()                                          // 关闭文件句柄以释放资源。
	h.cpuW = nil                                            // 将 cpuW 置为 nil，表示性能分析已停止。
	h.cpuFile = ""                                          // 清空性能分析文件路径。
	return nil
}

// GoTrace turns on tracing for nsec seconds and writes
// trace data to file.
// GoTrace 启动跟踪，持续 nsec 秒，并将跟踪数据写入文件。
func (h *HandlerT) GoTrace(file string, nsec uint) error {
	if err := h.StartGoTrace(file); err != nil { // 启动跟踪。
		return err
	}
	time.Sleep(time.Duration(nsec) * time.Second) // 等待指定的时间。
	h.StopGoTrace()                               // 停止跟踪。
	return nil
}

// BlockProfile turns on goroutine profiling for nsec seconds and writes profile data to
// file. It uses a profile rate of 1 for most accurate information. If a different rate is
// desired, set the rate and write the profile manually.
// BlockProfile 启动 Goroutine 阻塞性能分析，持续 nsec 秒，并将性能分析数据写入文件。
func (*HandlerT) BlockProfile(file string, nsec uint) error {
	runtime.SetBlockProfileRate(1)                // 设置阻塞性能分析的采样率为 1，以获取最精确的信息。
	time.Sleep(time.Duration(nsec) * time.Second) // 等待指定的时间。
	defer runtime.SetBlockProfileRate(0)          // 恢复默认的阻塞性能分析采样率。
	return writeProfile("block", file)            // 写入阻塞性能分析数据。
}

// SetBlockProfileRate sets the rate of goroutine block profile data collection.
// rate 0 disables block profiling.
// SetBlockProfileRate 设置 Goroutine 阻塞性能分析数据收集的采样率。rate 为 0 时禁用阻塞性能分析。
func (*HandlerT) SetBlockProfileRate(rate int) {
	runtime.SetBlockProfileRate(rate) // 设置阻塞性能分析的采样率。
}

// WriteBlockProfile writes a goroutine blocking profile to the given file.
// WriteBlockProfile 将 Goroutine 阻塞性能分析数据写入指定的文件。
func (*HandlerT) WriteBlockProfile(file string) error {
	return writeProfile("block", file) // 写入阻塞性能分析数据。
}

// MutexProfile turns on mutex profiling for nsec seconds and writes profile data to file.
// It uses a profile rate of 1 for most accurate information. If a different rate is
// desired, set the rate and write the profile manually.
// MutexProfile 启动互斥锁性能分析，持续 nsec 秒，并将性能分析数据写入文件。
func (*HandlerT) MutexProfile(file string, nsec uint) error {
	runtime.SetMutexProfileFraction(1)            // 设置互斥锁性能分析的采样率为 1，以获取最精确的信息。
	time.Sleep(time.Duration(nsec) * time.Second) // 等待指定的时间。
	defer runtime.SetMutexProfileFraction(0)      // 恢复默认的互斥锁性能分析采样率。
	return writeProfile("mutex", file)            // 写入互斥锁性能分析数据。
}

// SetMutexProfileFraction sets the rate of mutex profiling.
// SetMutexProfileFraction 设置互斥锁性能分析的采样率。
func (*HandlerT) SetMutexProfileFraction(rate int) {
	runtime.SetMutexProfileFraction(rate) // 设置互斥锁性能分析的采样率。
}

// WriteMutexProfile writes a goroutine blocking profile to the given file.
// WriteMutexProfile 将 Goroutine 阻塞性能分析数据写入指定的文件。
func (*HandlerT) WriteMutexProfile(file string) error {
	return writeProfile("mutex", file) // 写入互斥锁性能分析数据。
}

// WriteMemProfile writes an allocation profile to the given file.
// Note that the profiling rate cannot be set through the API,
// it must be set on the command line.
// WriteMemProfile 将内存分配性能分析数据写入指定的文件。
func (*HandlerT) WriteMemProfile(file string) error {
	return writeProfile("heap", file) // 写入堆内存性能分析数据。
}

// Stacks returns a printed representation of the stacks of all goroutines. It
// also permits the following optional filters to be used:
//   - filter: boolean expression of packages to filter for
//
// Stacks 返回所有 Goroutine 的栈信息的打印表示形式。支持以下可选过滤器：
//   - filter: 包名的布尔表达式，用于过滤栈信息。
func (*HandlerT) Stacks(filter *string) string {
	buf := new(bytes.Buffer)
	pprof.Lookup("goroutine").WriteTo(buf, 2) // 获取所有 Goroutine 的栈信息。

	// 如果需要过滤，则执行过滤逻辑。
	if filter != nil && len(*filter) > 0 {
		expanded := *filter

		// The input filter is a logical expression of package names. Transform
		// it into a proper boolean expression that can be fed into a parser and
		// interpreter:
		//
		// E.g. (eth || snap) && !p2p -> (eth in Value || snap in Value) && p2p not in Value
		expanded = regexp.MustCompile(`[:/\.A-Za-z0-9_-]+`).ReplaceAllString(expanded, "`$0` in Value")
		expanded = regexp.MustCompile("!(`[:/\\.A-Za-z0-9_-]+`)").ReplaceAllString(expanded, "$1 not")
		expanded = strings.ReplaceAll(expanded, "||", "or")
		expanded = strings.ReplaceAll(expanded, "&&", "and")
		log.Info("Expanded filter expression", "filter", *filter, "expanded", expanded)

		expr, err := bexpr.CreateEvaluator(expanded) // 创建布尔表达式解析器。
		if err != nil {
			log.Error("Failed to parse filter expression", "expanded", expanded, "err", err)
			return ""
		}
		// Split the goroutine dump into segments and filter each 将 Goroutine 栈信息分割并逐段过滤。
		dump := buf.String()
		buf.Reset()

		for _, trace := range strings.Split(dump, "\n\n") {
			if ok, _ := expr.Evaluate(map[string]string{"Value": trace}); ok {
				buf.WriteString(trace)
				buf.WriteString("\n\n")
			}
		}
	}
	return buf.String()
}

// FreeOSMemory forces a garbage collection.
// FreeOSMemory 强制执行垃圾回收。
func (*HandlerT) FreeOSMemory() {
	debug.FreeOSMemory() // 调用 debug.FreeOSMemory 强制释放内存。
}

// SetGCPercent sets the garbage collection target percentage. It returns the previous
// setting. A negative value disables GC.
// SetGCPercent 设置垃圾回收的目标百分比。返回之前的设置。负值禁用垃圾回收。
func (*HandlerT) SetGCPercent(v int) int {
	return debug.SetGCPercent(v) // 设置垃圾回收的目标百分比。
}

// writeProfile writes a profile to the given file.
// writeProfile 将性能分析数据写入指定的文件。
func writeProfile(name, file string) error {
	p := pprof.Lookup(name) // 查找指定类型的性能分析数据。
	log.Info("Writing profile records", "count", p.Count(), "type", name, "dump", file)
	f, err := os.Create(expandHome(file)) // 创建文件，expandHome 用于处理路径中的 ~ 符号。
	if err != nil {
		return err // 如果文件创建失败，返回错误。
	}
	defer f.Close()
	return p.WriteTo(f, 0) // 将性能分析数据写入文件。
}

// expands home directory in file paths.
// ~someuser/tmp will not be expanded.
// expandHome 展开文件路径中的主目录符号 ~。
func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") { // 检查路径是否以 ~/ 或 ~\ 开头。
		home := os.Getenv("HOME") // 获取 HOME 环境变量。
		if home == "" {
			if usr, err := user.Current(); err == nil {
				home = usr.HomeDir // 如果 HOME 为空，尝试从用户信息中获取主目录。
			}
		}
		if home != "" {
			p = home + p[1:] // 替换路径中的 ~ 符号为主目录路径。
		}
	}
	return filepath.Clean(p) // 清理路径，去除多余的斜杠等。
}
