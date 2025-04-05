// Copyright 2015 The go-ethereum Authors
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

// Package jsre provides execution environment for JavaScript.
package jsre

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/dop251/goja"
	"github.com/ethereum/go-ethereum/common"
)

// JSRE is a JS runtime environment embedding the goja interpreter.
// It provides helper functions to load code from files, run code snippets
// and bind native go objects to JS.
//
// The runtime runs all code on a dedicated event loop and does not expose the underlying
// goja runtime directly. To use the runtime, call JSRE.Do. When binding a Go function,
// use the Call type to gain access to the runtime.
// JSRE 是一个嵌入了 goja 解释器的 JS 运行时环境。
// 它提供了从文件加载代码、运行代码片段以及将原生 Go 对象绑定到 JS 的辅助函数。
//
// 运行时在一个专用的事件循环中运行所有代码，并且不直接暴露底层的 goja 运行时。
// 要使用运行时，请调用 JSRE.Do。绑定 Go 函数时，请使用 Call 类型来访问运行时。
type JSRE struct {
	assetPath     string        // Path to the directory containing script assets. 包含脚本资源的目录路径。
	output        io.Writer     // Writer for runtime output (e.g., stdout). 运行时输出的写入器（例如，stdout）。
	evalQueue     chan *evalReq // Queue for serialized VM execution requests. 用于序列化 VM 执行请求的队列。
	stopEventLoop chan bool     // Channel to signal the event loop to stop. 用于向事件循环发送停止信号的通道。
	closed        chan struct{} // Channel that is closed when the event loop finishes. 事件循环结束时关闭的通道。
	vm            *goja.Runtime // The underlying goja JavaScript runtime. 底层的 goja JavaScript 运行时。
}

// Call is the argument type of Go functions which are callable from JS.
// Call 是可从 JS 调用的 Go 函数的参数类型。
type Call struct {
	goja.FunctionCall               // Embedded goja.FunctionCall for accessing arguments and the 'this' value. 嵌入的 goja.FunctionCall 用于访问参数和 'this' 值。
	VM                *goja.Runtime // The goja JavaScript runtime instance. goja JavaScript 运行时实例。
}

// jsTimer is a single timer instance with a callback function
// jsTimer 是一个带有回调函数的单个定时器实例。
type jsTimer struct {
	timer    *time.Timer       // The Go timer instance. Go 定时器实例。
	duration time.Duration     // The duration of the timer. 定时器的持续时间。
	interval bool              // Whether the timer is an interval (repeating) or a timeout (single execution). 定时器是否为间隔（重复执行）或超时（单次执行）。
	call     goja.FunctionCall // The JavaScript function to call when the timer expires. 定时器到期时要调用的 JavaScript 函数。
}

// evalReq is a serialized vm execution request processed by runEventLoop.
// evalReq 是由 runEventLoop 处理的序列化 VM 执行请求。
type evalReq struct {
	fn   func(vm *goja.Runtime) // The function to execute on the goja runtime. 要在 goja 运行时上执行的函数。
	done chan bool              // Channel to signal completion of the function execution. 用于通知函数执行完成的通道。
}

// New creates and initializes a new JavaScript runtime environment (JSRE).
// The runtime is configured with the provided assetPath for loading scripts and
// an output writer for logging or printing results.
//
// The returned JSRE must be stopped by calling Stop() after use to release resources.
// Attempting to use the JSRE after stopping it will result in undefined behavior.
//
// Parameters:
//   - assetPath: The path to the directory containing script assets.
//   - output: The writer used for logging or printing runtime output.
//
// Returns:
//   - A pointer to the newly created JSRE instance.
func New(assetPath string, output io.Writer) *JSRE {
	re := &JSRE{
		assetPath:     assetPath,
		output:        output,
		closed:        make(chan struct{}),
		evalQueue:     make(chan *evalReq),
		stopEventLoop: make(chan bool),
		vm:            goja.New(), // Create a new goja JavaScript runtime instance. 创建一个新的 goja JavaScript 运行时实例。
	}
	go re.runEventLoop()                                     // Start the event loop in a separate goroutine. 在单独的 goroutine 中启动事件循环。
	re.Set("loadScript", MakeCallback(re.vm, re.loadScript)) // Bind the Go function loadScript to the JS environment. 将 Go 函数 loadScript 绑定到 JS 环境。
	re.Set("inspect", re.prettyPrintJS)                      // Bind the Go function prettyPrintJS to the JS environment (definition not shown here). 将 Go 函数 prettyPrintJS 绑定到 JS 环境（此处未显示定义）。
	return re
}

// randomSource returns a pseudo random value generator.
// randomSource 返回一个伪随机值生成器。
func randomSource() *rand.Rand {
	bytes := make([]byte, 8)
	seed := time.Now().UnixNano()
	if _, err := crand.Read(bytes); err == nil {
		seed = int64(binary.LittleEndian.Uint64(bytes))
	}

	src := rand.NewSource(seed)
	return rand.New(src)
}

// This function runs the main event loop from a goroutine that is started
// when JSRE is created. Use Stop() before exiting to properly stop it.
// The event loop processes vm access requests from the evalQueue in a
// serialized way and calls timer callback functions at the appropriate time.
//
// Exported functions always access the vm through the event queue. You can
// call the functions of the goja vm directly to circumvent the queue. These
// functions should be used if and only if running a routine that was already
// called from JS through an RPC call.
// 此函数从 JSRE 创建时启动的 goroutine 运行主事件循环。在退出之前使用 Stop() 正确停止它。
// 事件循环以序列化的方式处理来自 evalQueue 的 vm 访问请求，并在适当的时间调用定时器回调函数。
//
// 导出的函数总是通过事件队列访问 vm。您可以直接调用 goja vm 的函数来绕过队列。
// 这些函数应仅在运行已通过 RPC 调用从 JS 调用的例程时使用。
func (re *JSRE) runEventLoop() {
	defer close(re.closed) // Close the 'closed' channel when the event loop exits. 在事件循环退出时关闭 'closed' 通道。

	r := randomSource()            // Create a random source. 创建一个随机源。
	re.vm.SetRandSource(r.Float64) // Set the random source for the goja runtime. 为 goja 运行时设置随机源。

	registry := map[*jsTimer]*jsTimer{} // Registry to keep track of active timers. 用于跟踪活动定时器的注册表。
	ready := make(chan *jsTimer)        // Channel to signal when a timer is ready to fire. 用于通知定时器何时准备触发的通道。

	// Helper function to create a new timer.
	// 创建新定时器的辅助函数。
	newTimer := func(call goja.FunctionCall, interval bool) (*jsTimer, goja.Value) {
		delay := call.Argument(1).ToInteger() // Get the delay from the arguments. 从参数中获取延迟。
		if 0 >= delay {
			delay = 1 // Ensure delay is at least 1ms. 确保延迟至少为 1 毫秒。
		}
		timer := &jsTimer{
			duration: time.Duration(delay) * time.Millisecond,
			call:     call,
			interval: interval,
		}
		registry[timer] = timer // Register the new timer. 注册新定时器。

		// Create a new Go timer that sends to the 'ready' channel when it expires.
		// 创建一个新的 Go 定时器，该定时器在到期时发送到 'ready' 通道。
		timer.timer = time.AfterFunc(timer.duration, func() {
			ready <- timer
		})

		return timer, re.vm.ToValue(timer) // Return the timer object as a goja.Value. 将定时器对象作为 goja.Value 返回。
	}

	// Implementation of JavaScript's setTimeout.
	// JavaScript 的 setTimeout 的实现。
	setTimeout := func(call goja.FunctionCall) goja.Value {
		_, value := newTimer(call, false) // Create a non-repeating timer. 创建一个非重复定时器。
		return value
	}

	// Implementation of JavaScript's setInterval.
	// JavaScript 的 setInterval 的实现。
	setInterval := func(call goja.FunctionCall) goja.Value {
		_, value := newTimer(call, true) // Create a repeating timer. 创建一个重复定时器。
		return value
	}

	// Implementation of JavaScript's clearTimeout and clearInterval.
	// JavaScript 的 clearTimeout 和 clearInterval 的实现。
	clearTimeout := func(call goja.FunctionCall) goja.Value {
		timer := call.Argument(0).Export() // Get the timer object from the arguments. 从参数中获取定时器对象。
		if timer, ok := timer.(*jsTimer); ok {
			timer.timer.Stop()      // Stop the Go timer. 停止 Go 定时器。
			delete(registry, timer) // Remove the timer from the registry. 从注册表中删除定时器。
		}
		return goja.Undefined()
	}
	re.vm.Set("_setTimeout", setTimeout)   // Bind the Go setTimeout implementation to a private name in the VM. 将 Go 的 setTimeout 实现绑定到 VM 中的私有名称。
	re.vm.Set("_setInterval", setInterval) // Bind the Go setInterval implementation to a private name in the VM. 将 Go 的 setInterval 实现绑定到 VM 中的私有名称。
	// Define the global setTimeout function in JavaScript.
	// 在 JavaScript 中定义全局 setTimeout 函数。
	re.vm.RunString(`var setTimeout = function(args) {
		if (arguments.length < 1) {
			throw TypeError("Failed to execute 'setTimeout': 1 argument required, but only 0 present.");
		}
		return _setTimeout.apply(this, arguments);
	}`)
	// Define the global setInterval function in JavaScript.
	// 在 JavaScript 中定义全局 setInterval 函数。
	re.vm.RunString(`var setInterval = function(args) {
		if (arguments.length < 1) {
			throw TypeError("Failed to execute 'setInterval': 1 argument required, but only 0 present.");
		}
		return _setInterval.apply(this, arguments);
	}`)
	re.vm.Set("clearTimeout", clearTimeout)  // Bind the Go clearTimeout implementation to the global name. 将 Go 的 clearTimeout 实现绑定到全局名称。
	re.vm.Set("clearInterval", clearTimeout) // Bind the Go clearInterval implementation to the global name. 将 Go 的 clearInterval 实现绑定到全局名称。

	var waitForCallbacks bool // Flag to indicate if the event loop should wait for all timers to finish before stopping. 指示事件循环是否应在停止之前等待所有定时器完成的标志。

loop:
	for {
		select {
		case timer := <-ready: // A timer has expired. 定时器已到期。
			// execute callback, remove/reschedule the timer
			var arguments []interface{}
			if len(timer.call.Arguments) > 2 {
				tmp := timer.call.Arguments[2:]
				arguments = make([]interface{}, 2+len(tmp))
				for i, value := range tmp {
					arguments[i+2] = value
				}
			} else {
				arguments = make([]interface{}, 1)
			}
			arguments[0] = timer.call.Arguments[0] // The first argument is the callback function. 第一个参数是回调函数。
			call, isFunc := goja.AssertFunction(timer.call.Arguments[0])
			if !isFunc {
				panic(re.vm.ToValue("js error: timer/timeout callback is not a function"))
			}
			call(goja.Null(), timer.call.Arguments...) // Call the JavaScript callback function. 调用 JavaScript 回调函数。

			_, inreg := registry[timer] // when clearInterval is called from within the callback don't reset it
			if timer.interval && inreg {
				timer.timer.Reset(timer.duration) // If it's an interval timer and still registered, reset it. 如果是间隔定时器且仍在注册，则重置它。
			} else {
				delete(registry, timer) // If it's a timeout or the interval was cleared, remove it from the registry. 如果是超时或间隔已清除，则从注册表中删除它。
				if waitForCallbacks && (len(registry) == 0) {
					break loop // If waiting for callbacks and no more timers, exit the loop. 如果等待回调且没有更多定时器，则退出循环。
				}
			}
		case req := <-re.evalQueue: // A request to execute code on the VM. 执行 VM 上代码的请求。
			// run the code, send the result back
			req.fn(re.vm)   // Execute the function on the goja runtime. 在 goja 运行时上执行函数。
			close(req.done) // Signal that the execution is complete. 通知执行已完成。
			if waitForCallbacks && (len(registry) == 0) {
				break loop // If waiting for callbacks and no more timers, exit the loop. 如果等待回调且没有更多定时器，则退出循环。
			}
		case waitForCallbacks = <-re.stopEventLoop: // A signal to stop the event loop. 停止事件循环的信号。
			if !waitForCallbacks || (len(registry) == 0) {
				break loop // If not waiting for callbacks or no active timers, exit the loop. 如果不等待回调或没有活动定时器，则退出循环。
			}
		}
	}

	// Stop any remaining timers.
	// 停止任何剩余的定时器。
	for _, timer := range registry {
		timer.timer.Stop()
		delete(registry, timer)
	}
}

// Do executes the given function on the JS event loop.
// When the runtime is stopped, fn will not execute.
// Do 在 JS 事件循环上执行给定的函数。当运行时停止时，fn 将不会执行。
func (re *JSRE) Do(fn func(*goja.Runtime)) {
	done := make(chan bool)
	req := &evalReq{fn, done}
	select {
	case re.evalQueue <- req: // Send the execution request to the queue. 将执行请求发送到队列。
		<-done // Wait for the function to complete execution. 等待函数执行完成。
	case <-re.closed: // If the runtime is closed, do nothing. 如果运行时已关闭，则不执行任何操作。
	}
}

// Stop terminates the event loop, optionally waiting for all timers to expire.
// Stop 终止事件循环，可以选择等待所有定时器到期。
func (re *JSRE) Stop(waitForCallbacks bool) {
	timeout := time.NewTimer(10 * time.Millisecond) // Create a timeout to prevent indefinite blocking. 创建一个超时以防止无限阻塞。
	defer timeout.Stop()

	for {
		select {
		case <-re.closed: // If the event loop has already stopped, return. 如果事件循环已停止，则返回。
			return
		case re.stopEventLoop <- waitForCallbacks: // Signal the event loop to stop. 向事件循环发送停止信号。
			<-re.closed // Wait for the event loop to finish. 等待事件循环完成。
			return
		case <-timeout.C: // If the stop operation takes too long, interrupt the JS runtime. 如果停止操作花费的时间过长，则中断 JS 运行时。
			// JS is blocked, interrupt and try again.
			re.vm.Interrupt(errors.New("JS runtime stopped"))
		}
	}
}

// Exec loads and executes the contents of a JavaScript file.
// If a relative path is provided, the file is resolved relative to the JSRE's assetPath.
// The file is read, compiled, and executed in the JSRE's runtime environment.
//
// Parameters:
//   - file: The path to the JavaScript file to execute. Can be an absolute path or relative to assetPath.
//
// Returns:
//   - error: An error if the file cannot be read, compiled, or executed.
func (re *JSRE) Exec(file string) error {
	code, err := os.ReadFile(common.AbsolutePath(re.assetPath, file)) // Read the content of the JavaScript file. 读取 JavaScript 文件的内容。
	if err != nil {
		return err
	}
	return re.Compile(file, string(code)) // Compile and execute the JavaScript code. 编译并执行 JavaScript 代码。
}

// Run runs a piece of JS code.
// Run 运行一段 JS 代码。
func (re *JSRE) Run(code string) (v goja.Value, err error) {
	re.Do(func(vm *goja.Runtime) { v, err = vm.RunString(code) }) // Execute the JavaScript code string on the VM. 在 VM 上执行 JavaScript 代码字符串。
	return v, err
}

// Set assigns value v to a variable in the JS environment.
// Set 将值 v 赋给 JS 环境中的一个变量。
func (re *JSRE) Set(ns string, v interface{}) (err error) {
	re.Do(func(vm *goja.Runtime) { vm.Set(ns, v) }) // Set the Go value 'v' to the JavaScript variable named 'ns'. 将 Go 值 'v' 设置为名为 'ns' 的 JavaScript 变量。
	return err
}

// MakeCallback turns the given function into a function that's callable by JS.
// MakeCallback 将给定的函数转换为可由 JS 调用的函数。
func MakeCallback(vm *goja.Runtime, fn func(Call) (goja.Value, error)) goja.Value {
	// Return a goja.Value representing a JavaScript function that, when called,
	// executes the provided Go function 'fn'.
	// 返回一个 goja.Value，它表示一个 JavaScript 函数，当被调用时，会执行提供的 Go 函数 'fn'。
	return vm.ToValue(func(call goja.FunctionCall) goja.Value {
		result, err := fn(Call{call, vm}) // Call the Go function 'fn' with the arguments from JavaScript. 使用来自 JavaScript 的参数调用 Go 函数 'fn'。
		if err != nil {
			panic(vm.NewGoError(err)) // If the Go function returns an error, panic in the JavaScript runtime. 如果 Go 函数返回错误，则在 JavaScript 运行时中 panic。
		}
		return result // Return the result of the Go function to JavaScript. 将 Go 函数的结果返回给 JavaScript。
	})
}

// Evaluate executes code and pretty prints the result to the specified output stream.
// Evaluate 执行代码并将结果格式化打印到指定的输出流。
func (re *JSRE) Evaluate(code string, w io.Writer) {
	re.Do(func(vm *goja.Runtime) {
		val, err := vm.RunString(code) // Run the JavaScript code string. 运行 JavaScript 代码字符串。
		if err != nil {
			prettyError(vm, err, w) // If there's an error, pretty print it. 如果有错误，则格式化打印错误。
		} else {
			prettyPrint(vm, val, w) // If successful, pretty print the result. 如果成功，则格式化打印结果。
		}
		fmt.Fprintln(w)
	})
}

// Interrupt stops the current JS evaluation.
// Interrupt 停止当前 JS 的执行。
func (re *JSRE) Interrupt(v interface{}) {
	done := make(chan bool)
	noop := func(*goja.Runtime) {} // A no-operation function. 一个空操作函数。

	select {
	case re.evalQueue <- &evalReq{noop, done}:
		// event loop is not blocked.
	default:
		re.vm.Interrupt(v) // Directly interrupt the goja runtime if the event queue is full. 如果事件队列已满，则直接中断 goja 运行时。
	}
}

// Compile compiles and then runs a piece of JS code.
// Compile 编译然后运行一段 JS 代码。
func (re *JSRE) Compile(filename string, src string) (err error) {
	re.Do(func(vm *goja.Runtime) { _, err = compileAndRun(vm, filename, src) }) // Compile and run the JavaScript source code. 编译并运行 JavaScript 源代码。
	return err
}

// loadScript loads and executes a JS file.
// loadScript 加载并执行一个 JS 文件。
func (re *JSRE) loadScript(call Call) (goja.Value, error) {
	file := call.Argument(0).ToString().String()   // Get the file path from the arguments. 从参数中获取文件路径。
	file = common.AbsolutePath(re.assetPath, file) // Resolve the absolute path of the script file. 解析脚本文件的绝对路径。
	source, err := os.ReadFile(file)               // Read the content of the script file. 读取脚本文件的内容。
	if err != nil {
		return nil, fmt.Errorf("could not read file %s: %v", file, err)
	}
	value, err := compileAndRun(re.vm, file, string(source)) // Compile and run the script. 编译并运行脚本。
	if err != nil {
		return nil, fmt.Errorf("error while compiling or running script: %v", err)
	}
	return value, nil
}

func compileAndRun(vm *goja.Runtime, filename string, src string) (goja.Value, error) {
	script, err := goja.Compile(filename, src, false) // Compile the JavaScript source code. 编译 JavaScript 源代码。
	if err != nil {
		return goja.Null(), err
	}
	return vm.RunProgram(script) // Run the compiled JavaScript program. 运行已编译的 JavaScript 程序。
}
