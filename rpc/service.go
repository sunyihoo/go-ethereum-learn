// Copyright 2019 The go-ethereum Authors
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

package rpc

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"unicode"

	"github.com/ethereum/go-ethereum/log"
)

var (
	contextType      = reflect.TypeOf((*context.Context)(nil)).Elem() // 获取 context.Context 接口的反射类型
	errorType        = reflect.TypeOf((*error)(nil)).Elem()           // 获取 error 接口的反射类型
	subscriptionType = reflect.TypeOf(Subscription{})                 // 获取 Subscription 结构体的反射类型
	stringType       = reflect.TypeOf("")                             // 获取 string 类型的反射类型
)

// 服务注册中心： serviceRegistry 可以看作是一个服务注册中心，它集中管理了 RPC 服务器提供的所有服务。当服务器启动时，不同的服务会被注册到这个注册中心。
// 用于管理已注册的服务。
//
// 服务发现： 当服务器接收到一个 RPC 请求时，它会根据请求中指定的服务名称，在这个 services map 中查找对应的 service 结构体，
// 然后根据请求的方法名在 service 结构体中的 callbacks 或 subscriptions map 中找到要调用的处理函数。
type serviceRegistry struct {
	mu       sync.Mutex         // 用于保护 services 字段的互斥锁
	services map[string]service // 存储已注册服务的 map，键是服务名称，值是 service 结构体
}

// service represents a registered object.
// service 代表一个已注册的对象。
type service struct {
	name          string               // name for service  服务的名称。这个名称通常在 RPC 请求中用于指定要调用的方法属于哪个服务。例如，以太坊的 RPC API 中有 "eth"、"web3" 等服务。
	callbacks     map[string]*callback // registered handlers 注册的处理函数。其键是服务中可调用的方法的名称（字符串），值是指向对应 callback 结构体的指针。
	subscriptions map[string]*callback // available subscriptions/notifications 可用的订阅/通知。用于存储服务中可用的订阅和通知方法及其回调信息。
}

// callback is a method callback which was registered in the server
// callback 是一个在服务器中注册的方法回调。
type callback struct {
	fn          reflect.Value  // the function  函数的反射值
	rcvr        reflect.Value  // receiver object of method, set if fn is method 方法的接收者对象，如果 fn 是方法则设置。如果 fn 是一个方法（即它有一个接收者），那么 rcvr 字段会存储该接收者对象的反射值。如果 fn 是一个普通的函数，则这个字段可能为空。
	argTypes    []reflect.Type // input argument types  输入参数的类型。存储了函数或方法 fn 所需的输入参数的类型列表，使用 reflect.Type 表示。
	hasCtx      bool           // method's first argument is a context (not included in argTypes) 方法的第一个参数是 context (不包含在 argTypes 中)
	errPos      int            // err return idx, of -1 when method cannot return error 错误返回值的索引，如果方法不能返回错误则为 -1
	isSubscribe bool           // true if this is a subscription callback  如果这是一个订阅回调则为 true。指示这个回调是否是用于处理订阅请求的。在以太坊的 RPC 接口中，有一些方法用于订阅特定的事件（例如新的区块头、交易日志）。
}

// 在以太坊节点的 JSON-RPC 服务器启动时，会调用 registerName 方法来注册各种 API 服务，例如 EthAPI、NetAPI、Web3API 等。每个 API 服务都包含了一组用于处理特定类型 RPC 请求的方法。
// 接收者对象： rcvr 参数是实现了这些 API 服务的 Go 对象实例。例如，可能会有一个名为 EthAPI 的结构体，其包含了 GetBlockByNumber、SendTransaction 等方法。
// 自动发现和注册： registerName 方法利用反射机制自动发现 rcvr 对象中符合 RPC 回调标准的方法，并将它们注册到 serviceRegistry 中，使得这些方法可以通过 JSON-RPC 接口被客户端调用。
// 区分普通方法和订阅方法： 通过 callback 对象的 isSubscribe 字段，registerName 方法能够区分普通 RPC 方法和用于创建订阅的方法，并将它们分别存储在 service 结构体的 callbacks 和 subscriptions 字段中。
func (r *serviceRegistry) registerName(name string, rcvr interface{}) error {
	rcvrVal := reflect.ValueOf(rcvr) // 获取接收者对象的反射值
	if name == "" {
		return fmt.Errorf("no service name for type %s", rcvrVal.Type().String())
	}
	callbacks := suitableCallbacks(rcvrVal) // 获取接收者对象中所有合适的回调函数
	if len(callbacks) == 0 {
		return fmt.Errorf("service %T doesn't have any suitable methods/subscriptions to expose", rcvr)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.services == nil {
		r.services = make(map[string]service) // 如果 services map 为空，则初始化它
	}
	svc, ok := r.services[name] // 尝试获取已注册的同名服务
	if !ok {
		svc = service{ // 如果不存在同名服务，则创建一个新的 service 对象
			name:          name,
			callbacks:     make(map[string]*callback),
			subscriptions: make(map[string]*callback),
		}
		r.services[name] = svc // 将新的 service 对象添加到 services map 中
	}
	for name, cb := range callbacks { // 遍历所有找到的合适的回调函数
		if cb.isSubscribe { // 如果回调函数是订阅类型
			svc.subscriptions[name] = cb // 将其添加到服务的 subscriptions map 中
		} else { // 否则（是普通的回调函数）
			svc.callbacks[name] = cb // 将其添加到服务的 callbacks map 中
		}
	}
	return nil
}

// 服务和方法分离： 在以太坊的 JSON-RPC API 中，方法通常会按照服务进行分组，
// 例如 eth_getBlockByNumber 属于 eth 服务。serviceMethodSeparator 的作用就是将请求的方法名（例如 "eth_getBlockByNumber") 分割成服务名 ("eth") 和方法名 ("getBlockByNumber")。
// 回调函数查找： 当以太坊节点接收到 JSON-RPC 请求时，会首先解析出请求的方法名，然后使用 callback 方法在 serviceRegistry 中查找对应的处理函数（callback 对象）。
// 订阅管理： 以太坊的 RPC 接口支持订阅功能（例如 eth_subscribe）。subscription 方法专门用于查找处理订阅请求的回调函数。
// 订阅通常也与特定的服务相关联，并且有唯一的名称（例如 "newHeads" 订阅属于 eth 服务）。
// 并发安全： 由于以太坊节点需要处理大量的并发 RPC 请求，因此对存储服务和回调函数的 serviceRegistry 的访问必须是线程安全的。
// 通过使用互斥锁 (sync.Mutex)，可以确保在多个 Goroutine 同时查询 serviceRegistry 时不会发生数据竞争。

// callback returns the callback corresponding to the given RPC method name.
// callback 返回与给定 RPC 方法名对应的回调函数。
func (r *serviceRegistry) callback(method string) *callback {
	before, after, found := strings.Cut(method, serviceMethodSeparator) // 使用分隔符分割方法名
	if !found {                                                         // 如果找不到分隔符，则返回 nil
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.services[before].callbacks[after] // 返回指定服务下指定方法名的回调函数
}

// subscription returns a subscription callback in the given service.
// subscription 返回给定服务中的订阅回调函数。
func (r *serviceRegistry) subscription(service, name string) *callback {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.services[service].subscriptions[name] // 返回指定服务下指定订阅名称的回调函数
}

// 以太坊知识点：
//
// 在以太坊节点的 JSON-RPC 服务器实现中，suitableCallbacks 函数会被用来扫描一个包含 RPC 方法实现的对象（例如，一个实现了 eth、net 等服务的结构体）。
// 导出方法： 只有导出的方法（首字母大写）才会被认为是潜在的 RPC 方法。
// newCallback 的标准： newCallback 函数中定义的标准（例如，返回值数量和类型）决定了哪些 Go 方法可以作为有效的 JSON-RPC 方法。例如，一个 RPC 方法可能需要返回一个结果和一个 error。
// 方法名格式化： Go 语言的方法名通常以大写字母开头，而 JSON-RPC 的方法名通常以小写字母开头，并使用下划线分隔服务名称和方法名称（例如 eth_getBlockByNumber）。这里的 formatName 函数实现了将 Go 方法名的首字母转换为小写的功能，可能还有其他逻辑（未在给出的代码中显示）来进一步格式化方法名。
// 服务注册： suitableCallbacks 返回的 callbacks map 会被服务器用来注册服务中可用的 RPC 方法，当接收到客户端的请求时，服务器会根据请求的方法名在这个 map 中查找对应的 callback 并执行。

// suitableCallbacks iterates over the methods of the given type. It determines if a method
// satisfies the criteria for an RPC callback or a subscription callback and adds it to the
// collection of callbacks. See server documentation for a summary of these criteria.
//
// suitableCallbacks 遍历给定类型的方法。它确定一个方法是否满足 RPC 回调或订阅回调的标准，
// 并将其添加到回调集合中。有关这些标准的摘要，请参阅服务器文档。
func suitableCallbacks(receiver reflect.Value) map[string]*callback {
	typ := receiver.Type()                  // 获取接收者对象的反射类型
	callbacks := make(map[string]*callback) // 创建一个 map 来存储合适的回调函数
	for m := 0; m < typ.NumMethod(); m++ {  // 遍历接收者类型的所有方法
		method := typ.Method(m) // 获取当前索引的方法
		if method.PkgPath != "" {
			continue // method not exported   方法未导出（非公共）  如果方法的 PkgPath 不为空，则表示该方法没有被导出（即不是公共方法），因此跳过该方法。RPC 方法通常需要是导出的才能被外部调用。
		}
		cb := newCallback(receiver, method.Func) // 尝试将该方法转换为一个 callback 对象
		if cb == nil {
			continue // function invalid 函数无效（不符合 RPC 回调的标准）
		}
		name := formatName(method.Name) // 格式化方法名称（首字母小写）
		callbacks[name] = cb            // 将格式化后的方法名和对应的 callback 对象添加到 map 中
	}
	return callbacks // 返回包含所有合适回调函数的 map
}

// 在以太坊的 JSON-RPC 服务器实现中，当开发者注册一个 Go 函数来处理某个 RPC 方法时，newCallback 函数会对其进行验证，确保其签名符合 RPC 调用的约定。
// 返回值约定： 以太坊的 RPC 方法通常会返回一个结果值（例如请求的信息）和一个错误值（如果操作失败）。newCallback 强制执行了最多一个结果值和一个错误值的约定，并且如果存在错误，它应该是最后一个返回值（或者唯一的返回值）。
// 发布/订阅： 通过 isPubSub 函数的判断，newCallback 能够识别出用于创建订阅的方法，并设置 isSubscribe 标志。这对于处理像 eth_subscribe 这样的方法非常重要。
// 不合适的函数： 如果注册的函数返回了过多或不符合约定的返回值类型，newCallback 会返回 nil，表明该函数不能作为 RPC 回调使用，这有助于防止服务器端注册不正确的处理函数。

// newCallback turns fn (a function) into a callback object. It returns nil if the function
// is unsuitable as an RPC callback.
// newCallback 将 fn（一个函数）转换为一个 callback 对象。如果该函数不适合作为 RPC 回调，则返回 nil。
func newCallback(receiver, fn reflect.Value) *callback {
	fntype := fn.Type()
	c := &callback{fn: fn, rcvr: receiver, errPos: -1, isSubscribe: isPubSub(fntype)}
	// Determine parameter types. They must all be exported or builtin types.
	// 确定参数类型。它们都必须是导出的或内置的类型。
	c.makeArgTypes() // 调用 makeArgTypes 方法来填充参数类型列表

	// Verify return types. The function must return at most one error
	// and/or one other non-error value.
	// 验证返回类型。函数必须最多返回一个错误值和/或一个其他的非错误值。
	outs := make([]reflect.Type, fntype.NumOut()) // 创建存储返回类型的切片
	for i := 0; i < fntype.NumOut(); i++ {
		outs[i] = fntype.Out(i) // 将返回类型添加到切片中
	}
	if len(outs) > 2 { // 如果返回值数量大于 2，则不适合作为 RPC 回调
		return nil
	}
	// If an error is returned, it must be the last returned value.
	// 如果返回了错误，它必须是最后一个返回值。
	switch {
	case len(outs) == 1 && isErrorType(outs[0]): // 如果只有一个返回值且是 error 类型
		c.errPos = 0 // 错误位置是 0
	case len(outs) == 2: // 如果有两个返回值
		if isErrorType(outs[0]) || !isErrorType(outs[1]) { // 如果第一个是 error 或者第二个不是 error
			return nil // 则不适合作为 RPC 回调
		}
		c.errPos = 1 // 错误位置是 1（第二个返回值）
	}
	return c // 返回创建的 callback 对象
}

// makeArgTypes composes the argTypes list.
// makeArgTypes 组装 argTypes 列表。
//
// 分析注册到 callback 中的函数或方法 (c.fn) 的参数类型，并将这些类型存储到 c.argTypes 字段中。它还会检测是否存在接收者和 context.Context 参数。
func (c *callback) makeArgTypes() {
	fntype := c.fn.Type() // 获取回调函数的反射类型。 获取了 callback 中存储的函数或方法的反射类型。
	// Skip receiver and context.Context parameter (if present).
	// 跳过接收者和 context.Context 参数（如果存在）。
	firstArg := 0
	if c.rcvr.IsValid() { // 如果接收者有效（说明是方法）
		firstArg++ // 跳过接收者
	}
	if fntype.NumIn() > firstArg && fntype.In(firstArg) == contextType { // 如果存在 context.Context 参数
		c.hasCtx = true // 标记存在 context
		firstArg++      // 跳过 context.Context 参数
	}
	// Add all remaining parameters.
	// 添加所有剩余的参数。
	c.argTypes = make([]reflect.Type, fntype.NumIn()-firstArg) // 创建存储参数类型的切片
	for i := firstArg; i < fntype.NumIn(); i++ {
		c.argTypes[i-firstArg] = fntype.In(i) // 将剩余参数的类型添加到切片中
	}
}

// call invokes the callback.
// call 调用回调函数。
//
// 它的作用是实际调用在 callback 中注册的 Go 函数或方法 (c.fn)。
// 它处理了参数的准备、panic 的捕获、函数的调用以及结果和错误的解析。
func (c *callback) call(ctx context.Context, method string, args []reflect.Value) (res interface{}, errRes error) {
	// Create the argument slice.
	// 创建参数切片。
	fullargs := make([]reflect.Value, 0, 2+len(args)) // 初始容量被预留为至少能容纳接收者（如果存在）、上下文（如果需要）以及传入的参数。
	if c.rcvr.IsValid() {                             // 如果 c.rcvr 是有效的（即 c.fn 是一个方法并且有一个接收者），则将接收者的 reflect.Value 添加到 fullargs 的开头。
		fullargs = append(fullargs, c.rcvr)
	}
	if c.hasCtx { // 如果 c.hasCtx 为 true（表示 c.fn 的第一个参数是 context.Context），则将传入的 ctx 转换为 reflect.Value 并添加到 fullargs 中。
		fullargs = append(fullargs, reflect.ValueOf(ctx))
	}
	fullargs = append(fullargs, args...) // 将从 RPC 请求中获取的参数 args 添加到 fullargs 的末尾。

	// Catch panic while running the callback.
	// 捕获运行回调时发生的 panic。
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10 // 获取 panic 的值和堆栈信息，并使用日志记录器记录错误信息，包括方法名、panic 信息和堆栈跟踪。
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Error("RPC method " + method + " crashed: " + fmt.Sprintf("%v\n%s", err, buf))
			errRes = &internalServerError{errcodePanic, "method handler crashed"} // 将 errRes 设置为一个 internalServerError 类型的错误，其中包含了表示 panic 的错误代码 (errcodePanic) 和错误消息。
		}
	}()
	// Run the callback.
	// 运行回调函数。
	results := c.fn.Call(fullargs)
	if len(results) == 0 { // 如果 results 的长度为 0，表示被调用的函数没有返回值，此时返回 nil 和 nil。
		return nil, nil
	}
	// 检查 c.errPos 是否大于等于 0（表示该函数可以返回错误）并且返回值切片中索引为 c.errPos 的值是否不是 nil。如果满足这两个条件，则表示函数返回了一个错误。
	if c.errPos >= 0 && !results[c.errPos].IsNil() {
		// Method has returned non-nil error value.
		// 方法返回了非 nil 的错误值。
		err := results[c.errPos].Interface().(error)
		return reflect.Value{}, err
	}
	return results[0].Interface(), nil
}

// Does t satisfy the error interface?
// t 是否满足 error 接口？
func isErrorType(t reflect.Type) bool {
	return t.Implements(errorType) // 检查类型 t 是否实现了 errorType 接口
}

// 以太坊的 RPC 接口支持订阅功能，例如 eth_subscribe 方法会返回一个订阅对象。这个函数用于在反射分析方法签名时判断某个返回值是否是订阅类型。

// Is t Subscription or *Subscription?
// t 是否是 Subscription 或 *Subscription 类型？
func isSubscriptionType(t reflect.Type) bool {
	for t.Kind() == reflect.Ptr { // 如果 t 是指针类型
		t = t.Elem() // 获取指针指向的元素类型
	}
	return t == subscriptionType // 检查最终类型是否与 subscriptionType 相等
}

// 在以太坊的 RPC 接口中，像 eth_subscribe 这样的方法用于创建订阅。
// 这些方法通常遵循特定的签名约定：接收一个 context.Context 参数，并返回一个订阅对象和一个错误。
// isPubSub 函数就是用于在反射分析时识别出符合这种约定的方法。

// isPubSub tests whether the given method's first argument is a context.Context and
// returns the pair (Subscription, error).
// isPubSub 测试给定的方法的第一个参数是否是 context.Context 并且
// 返回值是否为 (Subscription, error) 类型对。
func isPubSub(methodType reflect.Type) bool {
	// 这是因为 RPC 方法通常会有一个接收者（索引 0），并且对于 PubSub 方法，约定第一个参数是 context.Context（索引 1）。
	// numIn(0) is the receiver type
	// numIn(0) 是接收者类型
	if methodType.NumIn() < 2 || methodType.NumOut() != 2 {
		return false // 如果输入参数少于 2 个（接收者 + context）或输出参数不是 2 个，则返回 false
	}
	return methodType.In(1) == contextType && // 检查第二个输入参数（索引为 1）是否是 contextType
		isSubscriptionType(methodType.Out(0)) && // 检查第一个输出参数（索引为 0）是否是 Subscription 或 *Subscription 类型
		isErrorType(methodType.Out(1)) // 检查第二个输出参数（索引为 1）是否是 error 类型
}

// 在以太坊的 JSON-RPC API 中，方法名通常采用驼峰命名法，并且第一个字母是小写（例如 eth_getBlockByNumber）。
// formatName sssss于将 Go 语言中方法名（通常首字母大写）转换为符合 JSON-RPC 规范的格式。

// formatName converts to first character of name to lowercase.
// formatName 将名称的第一个字符转换为小写。
func formatName(name string) string {
	ret := []rune(name) // 将字符串转换为 rune 切片
	if len(ret) > 0 {
		ret[0] = unicode.ToLower(ret[0]) // 将第一个 rune 转换为小写
	}
	return string(ret) // 将 rune 切片转换回字符串
}
