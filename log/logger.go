package log

import (
	"context"
	"log/slog"
	"math"
	"os"
	"runtime"
	"time"
)

const errorKey = "LOG_ERROR" // 错误键的常量定义

const (
	legacyLevelCrit  = iota // 旧版 Geth 的日志级别：严重
	legacyLevelError        // 错误
	legacyLevelWarn         // 警告
	legacyLevelInfo         // 信息
	legacyLevelDebug        // 调试
	legacyLevelTrace        // 跟踪
)

const (
	levelMaxVerbosity slog.Level = math.MinInt     // 最大详细级别
	LevelTrace        slog.Level = -8              // 跟踪级别
	LevelDebug                   = slog.LevelDebug // 调试级别
	LevelInfo                    = slog.LevelInfo  // 信息级别
	LevelWarn                    = slog.LevelWarn  // 警告级别
	LevelError                   = slog.LevelError // 错误级别
	LevelCrit         slog.Level = 12              // 严重级别

	// 用于向后兼容
	LvlTrace = LevelTrace
	LvlInfo  = LevelInfo
	LvlDebug = LevelDebug
)

// FromLegacyLevel converts from old Geth verbosity level constants
// to levels defined by slog.
// FromLegacyLevel 将旧版 Geth 的详细级别常量转换为 slog 定义的日志级别。
func FromLegacyLevel(lvl int) slog.Level {
	switch lvl {
	case legacyLevelCrit:
		return LevelCrit
	case legacyLevelError:
		return slog.LevelError
	case legacyLevelWarn:
		return slog.LevelWarn
	case legacyLevelInfo:
		return slog.LevelInfo
	case legacyLevelDebug:
		return slog.LevelDebug
	case legacyLevelTrace:
		return LevelTrace
	default:
		break
	}

	// TODO: 是否允许使用自定义级别？还是强制匹配现有最大/最小值？
	if lvl > legacyLevelTrace {
		return LevelTrace
	}
	return LevelCrit
}

// LevelAlignedString returns a 5-character string containing the name of a Lvl.
// LevelAlignedString 返回一个包含日志级别名称的 5 字符字符串。
func LevelAlignedString(l slog.Level) string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO "
	case LevelWarn:
		return "WARN "
	case LevelError:
		return "ERROR"
	case LevelCrit:
		return "CRIT "
	default:
		return "unknown level"
	}
}

// LevelString returns a string containing the name of a Lvl.
// LevelString 返回一个包含日志级别名称的字符串。
func LevelString(l slog.Level) string {
	switch l {
	case LevelTrace:
		return "trace"
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelCrit:
		return "crit"
	default:
		return "unknown"
	}
}

// A Logger writes key/value pairs to a Handler
// Logger 接口定义了日志记录器的行为，支持将键值对写入处理器。
type Logger interface {
	// With returns a new Logger that has this logger's attributes plus the given attributes
	// With 返回一个新的 Logger，包含当前 Logger 的属性以及给定的属性。
	With(ctx ...interface{}) Logger

	// New returns a new Logger that has this logger's attributes plus the given attributes. Identical to 'With'.
	// New 返回一个新的 Logger，功能与 With 相同。
	New(ctx ...interface{}) Logger

	// Log logs a message at the specified level with context key/value pairs
	// Log 在指定级别记录一条消息，并附带上下文键值对。
	Log(level slog.Level, msg string, ctx ...interface{})

	// Trace log a message at the trace level with context key/value pairs
	// Trace 在跟踪级别记录一条消息，并附带上下文键值对。
	Trace(msg string, ctx ...interface{})

	// Debug logs a message at the debug level with context key/value pairs
	// Debug 在调试级别记录一条消息，并附带上下文键值对。
	Debug(msg string, ctx ...interface{})

	// Info logs a message at the info level with context key/value pairs
	// Info 在信息级别记录一条消息，并附带上下文键值对。
	Info(msg string, ctx ...interface{})

	// Warn logs a message at the warn level with context key/value pairs
	// Warn 在警告级别记录一条消息，并附带上下文键值对。
	Warn(msg string, ctx ...interface{})

	// Error logs a message at the error level with context key/value pairs
	// Error 在错误级别记录一条消息，并附带上下文键值对。
	Error(msg string, ctx ...interface{})

	// Crit logs a message at the crit level with context key/value pairs, and exits
	// Crit 在严重级别记录一条消息，并退出程序。
	Crit(msg string, ctx ...interface{})

	// Write logs a message at the specified level
	// Write 在指定级别记录一条消息。
	Write(level slog.Level, msg string, attrs ...any)

	// Enabled reports whether l emits log records at the given context and level.
	// Enabled 报告是否在给定上下文和级别下发出日志记录。
	Enabled(ctx context.Context, level slog.Level) bool

	// Handler returns the underlying handler of the inner logger.
	// Handler 返回内部日志记录器的基础处理器。
	Handler() slog.Handler
}

// logger 是 Logger 接口的具体实现。
type logger struct {
	inner *slog.Logger // 内部使用的 slog.Logger 实例
}

// NewLogger returns a logger with the specified handler set
// NewLogger 返回一个设置了指定处理器的日志记录器。
func NewLogger(h slog.Handler) Logger {
	return &logger{
		slog.New(h),
	}
}

func (l *logger) Handler() slog.Handler {
	return l.inner.Handler()
}

// Write logs a message at the specified level.
// Write 在指定级别记录一条消息。
func (l *logger) Write(level slog.Level, msg string, attrs ...any) {
	if !l.inner.Enabled(context.Background(), level) {
		return // 如果该级别未启用，则直接返回。
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // 获取调用栈信息。

	if len(attrs)%2 != 0 {
		attrs = append(attrs, nil, errorKey, "Normalized odd number of arguments by adding nil")
		// 如果属性数量为奇数，则添加一个 nil 和错误信息以归一化。
	}
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(attrs...) // 添加属性。
	l.inner.Handler().Handle(context.Background(), r)
}

func (l *logger) Log(level slog.Level, msg string, attrs ...any) {
	l.Write(level, msg, attrs...)
}

func (l *logger) With(ctx ...interface{}) Logger {
	return &logger{l.inner.With(ctx...)}
}

func (l *logger) New(ctx ...interface{}) Logger {
	return l.With(ctx...)
}

// Enabled reports whether l emits log records at the given context and level.
// Enabled 报告是否在给定上下文和级别下发出日志记录。
func (l *logger) Enabled(ctx context.Context, level slog.Level) bool {
	return l.inner.Enabled(ctx, level)
}

func (l *logger) Trace(msg string, ctx ...interface{}) {
	l.Write(LevelTrace, msg, ctx...)
}

func (l *logger) Debug(msg string, ctx ...interface{}) {
	l.Write(LevelDebug, msg, ctx...)
}

func (l *logger) Info(msg string, ctx ...interface{}) {
	l.Write(LevelInfo, msg, ctx...)
}

func (l *logger) Warn(msg string, ctx ...any) {
	l.Write(LevelWarn, msg, ctx...)
}

func (l *logger) Error(msg string, ctx ...interface{}) {
	l.Write(LevelError, msg, ctx...)
}

func (l *logger) Crit(msg string, ctx ...interface{}) {
	l.Write(LevelCrit, msg, ctx...)
	os.Exit(1) // 在严重级别记录后退出程序。
}
