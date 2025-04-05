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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/metrics/exp"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v2"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	verbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail",
		// 日志详细级别：0=静默，1=错误，2=警告，3=信息，4=调试，5=详细。
		Value:    3, // 默认日志级别为 3（信息）。
		Category: flags.LoggingCategory,
	}
	logVmoduleFlag = &cli.StringFlag{
		Name:  "log.vmodule",
		Usage: "Per-module verbosity: comma-separated list of <pattern>=<level> (e.g. eth/*=5,p2p=4)",
		// 模块级别的日志详细程度：逗号分隔的 <模式>=<级别> 列表（例如 eth/*=5,p2p=4）。
		Value:    "",
		Category: flags.LoggingCategory,
	}
	vmoduleFlag = &cli.StringFlag{
		Name:  "vmodule",
		Usage: "Per-module verbosity: comma-separated list of <pattern>=<level> (e.g. eth/*=5,p2p=4)",
		// 模块级别的日志详细程度：逗号分隔的 <模式>=<级别> 列表（例如 eth/*=5,p2p=4）。
		Value:    "",
		Hidden:   true,
		Category: flags.LoggingCategory,
	}
	logjsonFlag = &cli.BoolFlag{
		Name:  "log.json",
		Usage: "Format logs with JSON",
		// 使用 JSON 格式化日志。
		Hidden:   true,
		Category: flags.LoggingCategory,
	}
	logFormatFlag = &cli.StringFlag{
		Name:  "log.format",
		Usage: "Log format to use (json|logfmt|terminal)",
		// 要使用的日志格式（json|logfmt|终端）。
		Category: flags.LoggingCategory,
	}
	logFileFlag = &cli.StringFlag{
		Name:  "log.file",
		Usage: "Write logs to a file",
		// 将日志写入文件。
		Category: flags.LoggingCategory,
	}
	logRotateFlag = &cli.BoolFlag{
		Name:  "log.rotate",
		Usage: "Enables log file rotation",
		// 启用日志文件轮转。
		Category: flags.LoggingCategory,
	}
	logMaxSizeMBsFlag = &cli.IntFlag{
		Name:  "log.maxsize",
		Usage: "Maximum size in MBs of a single log file",
		// 单个日志文件的最大大小（以 MB 为单位）。
		Value:    100,
		Category: flags.LoggingCategory,
	}
	logMaxBackupsFlag = &cli.IntFlag{
		Name:  "log.maxbackups",
		Usage: "Maximum number of log files to retain",
		// 保留的日志文件的最大数量。
		Value:    10,
		Category: flags.LoggingCategory,
	}
	logMaxAgeFlag = &cli.IntFlag{
		Name:  "log.maxage",
		Usage: "Maximum number of days to retain a log file",
		// 保留单个日志文件的最大天数。
		Value:    30,
		Category: flags.LoggingCategory,
	}
	logCompressFlag = &cli.BoolFlag{
		Name:  "log.compress",
		Usage: "Compress the log files",
		// 压缩日志文件。
		Value:    false,
		Category: flags.LoggingCategory,
	}
	pprofFlag = &cli.BoolFlag{
		Name:  "pprof",
		Usage: "Enable the pprof HTTP server",
		// 启用 pprof HTTP 服务器。
		Category: flags.LoggingCategory,
	}
	pprofPortFlag = &cli.IntFlag{
		Name:  "pprof.port",
		Usage: "pprof HTTP server listening port",
		// pprof HTTP 服务器监听的端口。
		Value:    6060,
		Category: flags.LoggingCategory,
	}
	pprofAddrFlag = &cli.StringFlag{
		Name:  "pprof.addr",
		Usage: "pprof HTTP server listening interface",
		// pprof HTTP 服务器监听的接口。
		Value:    "127.0.0.1",
		Category: flags.LoggingCategory,
	}
	memprofilerateFlag = &cli.IntFlag{
		Name:  "pprof.memprofilerate",
		Usage: "Turn on memory profiling with the given rate",
		// 以给定的速率启用内存分析。
		Value:    runtime.MemProfileRate,
		Category: flags.LoggingCategory,
	}
	blockprofilerateFlag = &cli.IntFlag{
		Name:  "pprof.blockprofilerate",
		Usage: "Turn on block profiling with the given rate",
		// 以给定的速率启用阻塞分析。
		Category: flags.LoggingCategory,
	}
	cpuprofileFlag = &cli.StringFlag{
		Name:  "pprof.cpuprofile",
		Usage: "Write CPU profile to the given file",
		// 将 CPU 分析数据写入指定文件。
		Category: flags.LoggingCategory,
	}
	traceFlag = &cli.StringFlag{
		Name:  "go-execution-trace",
		Usage: "Write Go execution trace to the given file",
		// 将 Go 执行跟踪数据写入指定文件。
		Category: flags.LoggingCategory,
	}
)

// Flags holds all command-line flags required for debugging.
// Flags 包含所有用于调试的命令行标志。
var Flags = []cli.Flag{
	verbosityFlag,
	logVmoduleFlag,
	vmoduleFlag,
	logjsonFlag,
	logFormatFlag,
	logFileFlag,
	logRotateFlag,
	logMaxSizeMBsFlag,
	logMaxBackupsFlag,
	logMaxAgeFlag,
	logCompressFlag,
	pprofFlag,
	pprofAddrFlag,
	pprofPortFlag,
	memprofilerateFlag,
	blockprofilerateFlag,
	cpuprofileFlag,
	traceFlag,
}

var (
	glogger       *log.GlogHandler
	logOutputFile io.WriteCloser
)

func init() {
	glogger = log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, false))
}

// Setup initializes profiling and logging based on the CLI flags.
// It should be called as early as possible in the program.
// Setup 根据 CLI 标志初始化性能分析和日志记录。应尽可能早地在程序中调用。
func Setup(ctx *cli.Context) error {
	var (
		handler        slog.Handler
		terminalOutput = io.Writer(os.Stderr)
		output         io.Writer
		logFmtFlag     = ctx.String(logFormatFlag.Name)
	)
	var (
		logFile  = ctx.String(logFileFlag.Name)
		rotation = ctx.Bool(logRotateFlag.Name)
	)
	if len(logFile) > 0 {
		if err := validateLogLocation(filepath.Dir(logFile)); err != nil {
			return fmt.Errorf("failed to initialize file logger: %v", err)
		}
	}
	context := []interface{}{"rotate", rotation}
	if len(logFmtFlag) > 0 {
		context = append(context, "format", logFmtFlag)
	} else {
		context = append(context, "format", "terminal")
	}
	if rotation {
		// Lumberjack uses <processname>-lumberjack.log in os.TempDir() if empty.
		// 如果为空，则 Lumberjack 使用 os.TempDir() 中的 <进程名>-lumberjack.log 文件。
		// 因此通常在 Linux 上是 /tmp/geth-lumberjack.log。
		if len(logFile) > 0 {
			context = append(context, "location", logFile)
		} else {
			context = append(context, "location", filepath.Join(os.TempDir(), "geth-lumberjack.log"))
		}
		logOutputFile = &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    ctx.Int(logMaxSizeMBsFlag.Name),
			MaxBackups: ctx.Int(logMaxBackupsFlag.Name),
			MaxAge:     ctx.Int(logMaxAgeFlag.Name),
			Compress:   ctx.Bool(logCompressFlag.Name),
		}
		output = io.MultiWriter(terminalOutput, logOutputFile)
	} else if logFile != "" {
		var err error
		if logOutputFile, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err != nil {
			return err
		}
		output = io.MultiWriter(logOutputFile, terminalOutput)
		context = append(context, "location", logFile)
	} else {
		output = terminalOutput
	}

	switch {
	case ctx.Bool(logjsonFlag.Name):
		// Retain backwards compatibility with `--log.json` flag if `--log.format` not set
		// 如果未设置 `--log.format`，则保留与 `--log.json` 标志的向后兼容性。
		defer log.Warn("The flag '--log.json' is deprecated, please use '--log.format=json' instead")
		handler = log.JSONHandler(output)
	case logFmtFlag == "json":
		handler = log.JSONHandler(output)
	case logFmtFlag == "logfmt":
		handler = log.LogfmtHandler(output)
	case logFmtFlag == "", logFmtFlag == "terminal":
		useColor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
		if useColor {
			terminalOutput = colorable.NewColorableStderr()
			if logOutputFile != nil {
				output = io.MultiWriter(logOutputFile, terminalOutput)
			} else {
				output = terminalOutput
			}
		}
		handler = log.NewTerminalHandler(output, useColor)
	default:
		// Unknown log format specified
		// 指定了未知的日志格式。
		return fmt.Errorf("unknown log format: %v", ctx.String(logFormatFlag.Name))
	}

	glogger = log.NewGlogHandler(handler)

	// logging
	verbosity := log.FromLegacyLevel(ctx.Int(verbosityFlag.Name))
	glogger.Verbosity(verbosity)
	vmodule := ctx.String(logVmoduleFlag.Name)
	if vmodule == "" {
		// Retain backwards compatibility with `--vmodule` flag if `--log.vmodule` not set
		// 如果未设置 `--log.vmodule`，则保留与 `--vmodule` 标志的向后兼容性。
		vmodule = ctx.String(vmoduleFlag.Name)
		if vmodule != "" {
			defer log.Warn("The flag '--vmodule' is deprecated, please use '--log.vmodule' instead")
		}
	}
	glogger.Vmodule(vmodule)

	log.SetDefault(log.NewLogger(glogger))

	// profiling, tracing
	runtime.MemProfileRate = memprofilerateFlag.Value
	if ctx.IsSet(memprofilerateFlag.Name) {
		runtime.MemProfileRate = ctx.Int(memprofilerateFlag.Name)
	}

	blockProfileRate := ctx.Int(blockprofilerateFlag.Name)
	Handler.SetBlockProfileRate(blockProfileRate)

	if traceFile := ctx.String(traceFlag.Name); traceFile != "" {
		if err := Handler.StartGoTrace(traceFile); err != nil {
			return err
		}
	}

	if cpuFile := ctx.String(cpuprofileFlag.Name); cpuFile != "" {
		if err := Handler.StartCPUProfile(cpuFile); err != nil {
			return err
		}
	}

	// pprof server
	if ctx.Bool(pprofFlag.Name) {
		listenHost := ctx.String(pprofAddrFlag.Name)

		port := ctx.Int(pprofPortFlag.Name)

		address := net.JoinHostPort(listenHost, fmt.Sprintf("%d", port))
		// This context value ("metrics.addr") represents the utils.MetricsHTTPFlag.Name.
		// It cannot be imported because it will cause a cyclical dependency.
		StartPProf(address, !ctx.IsSet("metrics.addr"))
	}
	if len(logFile) > 0 || rotation {
		log.Info("Logging configured", context...)
	}
	return nil
}

// StartPProf starts the pprof HTTP server for profiling and metrics.
// StartPProf 启动用于性能分析和指标的 pprof HTTP 服务器。
func StartPProf(address string, withMetrics bool) {
	// Hook go-metrics into expvar on any /debug/metrics request, load all vars
	// from the registry into expvar, and execute regular expvar handler.
	// 在任何 /debug/metrics 请求时，将 go-metrics 钩入 expvar，从注册表加载所有变量到 expvar，并执行常规的 expvar 处理程序。
	if withMetrics {
		exp.Exp(metrics.DefaultRegistry)
	}
	log.Info("Starting pprof server", "addr", fmt.Sprintf("http://%s/debug/pprof", address))
	go func() {
		if err := http.ListenAndServe(address, nil); err != nil {
			log.Error("Failure in running pprof server", "err", err)
		}
	}()
}

// Exit stops all running profiles, flushing their output to the respective file.
// Exit 停止所有正在运行的性能分析，并将其输出刷新到各自的文件。
func Exit() {
	Handler.StopCPUProfile()
	Handler.StopGoTrace()
	if logOutputFile != nil {
		logOutputFile.Close()
	}
}

// validateLogLocation checks if the log directory is valid and writable.
// validateLogLocation 检查日志目录是否有效且可写。
func validateLogLocation(path string) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		return fmt.Errorf("error creating the directory: %w", err)
	}
	// Check if the path is writable by trying to create a temporary file
	// 通过尝试创建临时文件来检查路径是否可写。
	tmp := filepath.Join(path, "tmp")
	if f, err := os.Create(tmp); err != nil {
		return err
	} else {
		f.Close()
	}
	return os.Remove(tmp)
}
