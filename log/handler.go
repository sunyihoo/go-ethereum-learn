package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/holiman/uint256"
)

type discardHandler struct{}

// DiscardHandler returns a no-op handler
// DiscardHandler 返回一个无操作的处理器。
func DiscardHandler() slog.Handler {
	return &discardHandler{}
}

func (h *discardHandler) Handle(_ context.Context, r slog.Record) error {
	return nil // 无操作，直接返回 nil。
}

func (h *discardHandler) Enabled(_ context.Context, level slog.Level) bool {
	return false // 始终返回 false，表示该处理器不会处理任何日志记录。
}

func (h *discardHandler) WithGroup(name string) slog.Handler {
	panic("not implemented") // 尚未实现。
}

func (h *discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &discardHandler{} // 返回一个新的无操作处理器。
}

type TerminalHandler struct {
	mu       sync.Mutex
	wr       io.Writer
	lvl      slog.Level
	useColor bool
	attrs    []slog.Attr
	// fieldPadding is a map with maximum field value lengths seen until now
	// to allow padding log contexts in a bit smarter way.
	// fieldPadding 是一个映射，记录到目前为止看到的最大字段值长度，
	// 以便以更智能的方式填充日志上下文。
	fieldPadding map[string]int

	buf []byte
}

// NewTerminalHandler returns a handler which formats log records at all levels optimized for human readability on
// a terminal with color-coded level output and terser human friendly timestamp.
// This format should only be used for interactive programs or while developing.
//
// [LEVEL] [TIME] MESSAGE key=value key=value ...
//
// Example:
//
// [DBUG] [May 16 20:58:45] remove route ns=haproxy addr=127.0.0.1:50002
//
// NewTerminalHandler 返回一个处理器，用于格式化所有级别的日志记录，优化为在终端上的人类可读性，
// 支持颜色编码的级别输出和更简洁的时间戳。此格式仅适用于交互式程序或开发期间使用。
func NewTerminalHandler(wr io.Writer, useColor bool) *TerminalHandler {
	return NewTerminalHandlerWithLevel(wr, levelMaxVerbosity, useColor)
}

// NewTerminalHandlerWithLevel returns the same handler as NewTerminalHandler but only outputs
// records which are less than or equal to the specified verbosity level.
// NewTerminalHandlerWithLevel 返回与 NewTerminalHandler 相同的处理器，
// 但仅输出小于或等于指定详细级别的记录。
func NewTerminalHandlerWithLevel(wr io.Writer, lvl slog.Level, useColor bool) *TerminalHandler {
	return &TerminalHandler{
		wr:           wr,
		lvl:          lvl,
		useColor:     useColor,
		fieldPadding: make(map[string]int),
	}
}

func (h *TerminalHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf := h.format(h.buf, r, h.useColor) // 格式化日志记录。
	h.wr.Write(buf)                       // 写入日志输出。
	h.buf = buf[:0]                       // 清空缓冲区。
	return nil
}

// Source returns a Source for the log event.
// If the Record was created without the necessary information,
// or if the location is unavailable, it returns a non-nil *Source
// with zero fields.
// Source 返回日志事件的源信息。如果记录创建时缺少必要信息，
// 或者位置不可用，则返回一个非 nil 的 *Source，但字段为空。
func (h *TerminalHandler) Source(r slog.Record) slog.Value {
	fs := runtime.CallersFrames([]uintptr{r.PC})
	f, _ := fs.Next()
	src := &slog.Source{
		Function: f.Function,
		File:     f.File,
		Line:     f.Line,
	}
	return slog.StringValue(fmt.Sprintf("%s:%d", src.File, src.Line))
}

func (h *TerminalHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.lvl // 仅处理大于或等于当前级别的日志记录。
}

func (h *TerminalHandler) WithGroup(name string) slog.Handler {
	panic("not implemented") // 尚未实现。
}

func (h *TerminalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TerminalHandler{
		wr:           h.wr,
		lvl:          h.lvl,
		useColor:     h.useColor,
		attrs:        append(h.attrs, attrs...), // 添加新的属性。
		fieldPadding: make(map[string]int),
	}
}

// ResetFieldPadding zeroes the field-padding for all attribute pairs.
// ResetFieldPadding 将所有属性对的字段填充重置为零。
func (h *TerminalHandler) ResetFieldPadding() {
	h.mu.Lock()
	h.fieldPadding = make(map[string]int)
	h.mu.Unlock()
}

type leveler struct{ minLevel slog.Level }

func (l *leveler) Level() slog.Level {
	return l.minLevel // 返回最小日志级别。
}

// JSONHandler returns a handler which prints records in JSON format.
// JSONHandler 返回一个以 JSON 格式打印记录的处理器。
func JSONHandler(wr io.Writer) slog.Handler {
	return JSONHandlerWithLevel(wr, levelMaxVerbosity)
}

// JSONHandlerWithLevel returns a handler which prints records in JSON format that are less than or equal to
// the specified verbosity level.
// JSONHandlerWithLevel 返回一个以 JSON 格式打印记录的处理器，但仅输出小于或等于指定详细级别的记录。
func JSONHandlerWithLevel(wr io.Writer, level slog.Level) slog.Handler {
	return slog.NewJSONHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceJSON,
		Level:       &leveler{level},
	})
}

// LogfmtHandler returns a handler which prints records in logfmt format, an easy machine-parseable but human-readable
// format for key/value pairs.
//
// For more details see: http://godoc.org/github.com/kr/logfmt
// LogfmtHandler 返回一个以 logfmt 格式打印记录的处理器，这是一种易于机器解析但同时人类可读的键值对格式。
func LogfmtHandler(wr io.Writer) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
	})
}

// LogfmtHandlerWithLevel returns the same handler as LogfmtHandler but it only outputs
// records which are less than or equal to the specified verbosity level.
// LogfmtHandlerWithLevel 返回与 LogfmtHandler 相同的处理器，但仅输出小于或等于指定详细级别的记录。
func LogfmtHandlerWithLevel(wr io.Writer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(wr, &slog.HandlerOptions{
		ReplaceAttr: builtinReplaceLogfmt,
		Level:       &leveler{level},
	})
}

func builtinReplaceLogfmt(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, true)
}

func builtinReplaceJSON(_ []string, attr slog.Attr) slog.Attr {
	return builtinReplace(nil, attr, false)
}

func builtinReplace(_ []string, attr slog.Attr, logfmt bool) slog.Attr {
	switch attr.Key {
	case slog.TimeKey:
		if attr.Value.Kind() == slog.KindTime {
			if logfmt {
				return slog.String("t", attr.Value.Time().Format(timeFormat)) // logfmt 格式化时间。
			} else {
				return slog.Attr{Key: "t", Value: attr.Value} // JSON 格式保留原始时间值。
			}
		}
	case slog.LevelKey:
		if l, ok := attr.Value.Any().(slog.Level); ok {
			attr = slog.Any("lvl", LevelString(l)) // 自定义级别字符串。
			return attr
		}
	}

	switch v := attr.Value.Any().(type) {
	case time.Time:
		if logfmt {
			attr = slog.String(attr.Key, v.Format(timeFormat)) // logfmt 格式化时间。
		}
	case *big.Int:
		if v == nil {
			attr.Value = slog.StringValue("<nil>") // 处理 nil 的大整数。
		} else {
			attr.Value = slog.StringValue(v.String()) // 转换为字符串。
		}
	case *uint256.Int:
		if v == nil {
			attr.Value = slog.StringValue("<nil>") // 处理 nil 的 uint256 整数。
		} else {
			attr.Value = slog.StringValue(v.Dec()) // 转换为十进制字符串。
		}
	case fmt.Stringer:
		if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
			attr.Value = slog.StringValue("<nil>") // 处理 nil 的 Stringer 接口。
		} else {
			attr.Value = slog.StringValue(v.String()) // 调用 String 方法。
		}
	}
	return attr
}
