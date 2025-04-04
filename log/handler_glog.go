// Copyright 2017 The go-ethereum Authors
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

package log

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// errVmoduleSyntax is returned when a user vmodule pattern is invalid.
// errVmoduleSyntax 是一个错误变量，当用户输入的 vmodule 格式不正确时返回。
var errVmoduleSyntax = errors.New("expect comma-separated list of filename=N")

// Handle 实现 slog.Handler 接口，过滤日志记录并通过全局、局部或回溯过滤器决定是否输出。
// 该方法的核心逻辑是：
// 1. 首先检查全局日志级别是否允许输出。
// 2. 如果未命中全局规则，则尝试从调用点缓存中查找匹配的日志级别。
// 3. 如果缓存未命中，则通过正则表达式匹配调用点文件名，动态计算日志级别。
// 4. 最终决定是否输出日志记录。

// GlogHandler is a log handler that mimics the filtering features of Google's
// glog logger: setting global log levels; overriding with callsite pattern
// matches; and requesting backtraces at certain positions.
type GlogHandler struct {
	origin slog.Handler // The origin handler this wraps
	// origin 是被包装的基础日志处理器，负责最终的日志输出。

	level atomic.Int32 // Current log level, atomically accessible
	// level 当前的日志级别，使用原子操作访问，确保线程安全。

	override atomic.Bool // Flag whether overrides are used, atomically accessible
	// override 标记是否启用了覆盖规则（vmodule 规则），使用原子操作访问。

	patterns []pattern // Current list of patterns to override with
	// patterns 当前的覆盖规则列表，用于根据文件名匹配动态调整日志级别。

	siteCache map[uintptr]slog.Level // Cache of callsite pattern evaluations
	// siteCache 调用点模式评估缓存，避免重复计算匹配结果。

	location string // file:line location where to do a stackdump at
	// location 文件名和行号位置，用于触发堆栈转储。

	lock sync.RWMutex // Lock protecting the override pattern list
	// lock 保护覆盖规则列表的读写锁，确保并发安全。
}

// NewGlogHandler creates a new log handler with filtering functionality similar
// to Google's glog logger. The returned handler implements Handler.
// NewGlogHandler 创建一个新的日志处理器，功能类似于 Google 的 glog 日志库。
// 该函数返回一个实现了 slog.Handler 接口的 GlogHandler 实例。
func NewGlogHandler(h slog.Handler) *GlogHandler {
	return &GlogHandler{
		origin: h,
	}
}

// pattern contains a filter for the Vmodule option, holding a verbosity level
// and a file pattern to match.
type pattern struct {
	pattern *regexp.Regexp // 正则表达式模式，用于匹配文件路径。
	// pattern 存储正则表达式，用于匹配文件名或路径。

	level slog.Level // 对应的日志级别。
	// level 表示匹配成功时应用的日志级别。
}

// Verbosity sets the glog verbosity ceiling. The verbosity of individual packages
// and source files can be raised using Vmodule.
// Verbosity 设置全局日志级别的上限。
// 通过该方法可以动态调整全局日志级别，影响所有未被覆盖规则匹配的日志记录。
func (h *GlogHandler) Verbosity(level slog.Level) {
	h.level.Store(int32(level))
}

// Vmodule sets the glog verbosity pattern.
//
// The syntax of the argument is a comma-separated list of pattern=N, where the
// pattern is a literal file name or "glob" pattern matching and N is a V level.
//
// For instance:
//
//	pattern="gopher.go=3"
//	 sets the V level to 3 in all Go files named "gopher.go"
//
//	pattern="foo=3"
//	 sets V to 3 in all files of any packages whose import path ends in "foo"
//
//	pattern="foo/*=3"
//	 sets V to 3 in all files of any packages whose import path contains "foo"
func (h *GlogHandler) Vmodule(ruleset string) error {
	var filter []pattern
	for _, rule := range strings.Split(ruleset, ",") {
		// Empty strings such as from a trailing comma can be ignored
		if len(rule) == 0 {
			continue
		}
		// Ensure we have a pattern = level filter rule
		parts := strings.Split(rule, "=")
		if len(parts) != 2 {
			return errVmoduleSyntax
		}
		parts[0] = strings.TrimSpace(parts[0])
		parts[1] = strings.TrimSpace(parts[1])
		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			return errVmoduleSyntax
		}
		// Parse the level and if correct, assemble the filter rule
		l, err := strconv.Atoi(parts[1])
		if err != nil {
			return errVmoduleSyntax
		}
		level := FromLegacyLevel(l)

		if level == LevelCrit {
			continue // Ignore. It's harmless but no point in paying the overhead.
		}
		// Compile the rule pattern into a regular expression
		matcher := ".*"
		for _, comp := range strings.Split(parts[0], "/") {
			if comp == "*" {
				matcher += "(/.*)?"
			} else if comp != "" {
				matcher += "/" + regexp.QuoteMeta(comp)
			}
		}
		if !strings.HasSuffix(parts[0], ".go") {
			matcher += "/[^/]+\\.go"
		}
		matcher = matcher + "$"

		re, _ := regexp.Compile(matcher)
		filter = append(filter, pattern{re, level})
	}
	// Swap out the vmodule pattern for the new filter system
	h.lock.Lock()
	defer h.lock.Unlock()

	h.patterns = filter
	h.siteCache = make(map[uintptr]slog.Level)
	h.override.Store(len(filter) != 0)

	return nil
}

// Vmodule 设置基于文件名的动态日志级别规则。
// 该方法解析用户提供的规则字符串（如 "file.go=3"），并将其转换为正则表达式和日志级别的映射。
// 重要解释：
// 1. 规则格式为 "pattern=N"，其中 pattern 是文件名或路径模式，N 是日志级别。
// 2. 使用正则表达式将 pattern 转换为可匹配的规则。
// 3. 将解析后的规则存储在 `patterns` 列表中，并清空调用点缓存 `siteCache`。

// Enabled implements slog.Handler, reporting whether the handler handles records
// at the given level.
// Enabled 实现 slog.Handler 接口，判断是否处理指定级别的日志记录。
// 如果未启用覆盖规则且日志级别高于配置值，则直接跳过日志。
func (h *GlogHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	// fast-track skipping logging if override not enabled and the provided verbosity is above configured
	return h.override.Load() || slog.Level(h.level.Load()) <= lvl
}

// WithAttrs implements slog.Handler, returning a new Handler whose attributes
// consist of both the receiver's attributes and the arguments.
// WithAttrs 实现 slog.Handler 接口，返回一个新的处理器实例，包含当前属性和新增属性。
// 该方法用于扩展日志处理器的上下文信息。
func (h *GlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.lock.RLock()
	siteCache := maps.Clone(h.siteCache)
	h.lock.RUnlock()

	patterns := []pattern{}
	patterns = append(patterns, h.patterns...)

	res := GlogHandler{
		origin:    h.origin.WithAttrs(attrs),
		patterns:  patterns,
		siteCache: siteCache,
		location:  h.location,
	}

	res.level.Store(h.level.Load())
	res.override.Store(h.override.Load())
	return &res
}

// WithGroup implements slog.Handler, returning a new Handler with the given
// group appended to the receiver's existing groups.
//
// Note, this function is not implemented.
//
// WithGroup 实现 slog.Handler 接口，但未实现。
// 该方法用于分组日志记录，目前抛出异常。
func (h *GlogHandler) WithGroup(name string) slog.Handler {
	panic("not implemented")
}

// Handle implements slog.Handler, filtering a log record through the global,
// local and backtrace filters, finally emitting it if either allow it through.
func (h *GlogHandler) Handle(_ context.Context, r slog.Record) error {
	// If the global log level allows, fast track logging
	if slog.Level(h.level.Load()) <= r.Level {
		return h.origin.Handle(context.Background(), r)
	}

	// Check callsite cache for previously calculated log levels
	h.lock.RLock()
	lvl, ok := h.siteCache[r.PC]
	h.lock.RUnlock()

	// If we didn't cache the callsite yet, calculate it
	if !ok {
		h.lock.Lock()

		fs := runtime.CallersFrames([]uintptr{r.PC})
		frame, _ := fs.Next()

		for _, rule := range h.patterns {
			if rule.pattern.MatchString(fmt.Sprintf("+%s", frame.File)) {
				h.siteCache[r.PC], lvl, ok = rule.level, rule.level, true
			}
		}
		// If no rule matched, remember to drop log the next time
		if !ok {
			h.siteCache[r.PC] = 0
		}
		h.lock.Unlock()
	}
	if lvl <= r.Level {
		return h.origin.Handle(context.Background(), r)
	}
	return nil
}
