package log

import (
	"log/slog"
	"os"
	"sync/atomic"
)

var root atomic.Value

// 初始化时设置默认的全局日志记录器
// Initialization sets the default global logger.
func init() {
	root.Store(&logger{slog.New(DiscardHandler())})
}

// SetDefault sets the default global logger
// SetDefault 设置默认的全局日志记录器
func SetDefault(l Logger) {
	root.Store(l)
	if lg, ok := l.(*logger); ok {
		slog.SetDefault(lg.inner)
	}
}

// Root returns the root logger
// Root 返回根日志记录器
func Root() Logger {
	return root.Load().(Logger)
}

// The following functions bypass the exported logger methods (logger.Debug,
// etc.) to keep the call depth the same for all paths to logger.Write so
// runtime.Caller(2) always refers to the call site in client code.
// 以下函数绕过导出的日志方法（如 logger.Debug 等），以保持调用深度一致，
// 从而使 runtime.Caller(2) 始终指向客户端代码中的调用点。

// Trace is a convenient alias for Root().Trace
//
// Log a message at the trace level with context key/value pairs
// 在跟踪级别记录一条带有上下文键值对的消息
//
// # Usage
// 使用示例
//
//	log.Trace("msg")
//	log.Trace("msg", "key1", val1)
//	log.Trace("msg", "key1", val1, "key2", val2)
func Trace(msg string, ctx ...interface{}) {
	Root().Write(LevelTrace, msg, ctx...)
}

// Debug is a convenient alias for Root().Debug
//
// Log a message at the debug level with context key/value pairs
// 在调试级别记录一条带有上下文键值对的消息
//
// # Usage Examples
// 使用示例
//
//	log.Debug("msg")
//	log.Debug("msg", "key1", val1)
//	log.Debug("msg", "key1", val1, "key2", val2)
func Debug(msg string, ctx ...interface{}) {
	Root().Write(LevelDebug, msg, ctx...)
}

// Info is a convenient alias for Root().Info
//
// Log a message at the info level with context key/value pairs
// 在信息级别记录一条带有上下文键值对的消息
//
// # Usage Examples
// 使用示例
//
//	log.Info("msg")
//	log.Info("msg", "key1", val1)
//	log.Info("msg", "key1", val1, "key2", val2)
func Info(msg string, ctx ...interface{}) {
	Root().Write(LevelInfo, msg, ctx...)
}

// Warn is a convenient alias for Root().Warn
//
// Log a message at the warn level with context key/value pairs
// 在警告级别记录一条带有上下文键值对的消息
//
// # Usage Examples
// 使用示例
//
//	log.Warn("msg")
//	log.Warn("msg", "key1", val1)
//	log.Warn("msg", "key1", val1, "key2", val2)
func Warn(msg string, ctx ...interface{}) {
	Root().Write(LevelWarn, msg, ctx...)
}

// Error is a convenient alias for Root().Error
//
// Log a message at the error level with context key/value pairs
// 在错误级别记录一条带有上下文键值对的消息
//
// # Usage Examples
// 使用示例
//
//	log.Error("msg")
//	log.Error("msg", "key1", val1)
//	log.Error("msg", "key1", val1, "key2", val2)
func Error(msg string, ctx ...interface{}) {
	Root().Write(LevelError, msg, ctx...)
}

// Crit is a convenient alias for Root().Crit
//
// Log a message at the crit level with context key/value pairs, and then exit.
// 在严重级别记录一条带有上下文键值对的消息，并退出程序
//
// # Usage Examples
// 使用示例
//
//	log.Crit("msg")
//	log.Crit("msg", "key1", val1)
//	log.Crit("msg", "key1", val1, "key2", val2)
func Crit(msg string, ctx ...interface{}) {
	Root().Write(LevelCrit, msg, ctx...)
	os.Exit(1)
}

// New returns a new logger with the given context.
// New is a convenient alias for Root().New
// New 返回一个带有给定上下文的新日志记录器。
// New 是 Root().New 的便捷别名。
func New(ctx ...interface{}) Logger {
	return Root().With(ctx...)
}
