// Copyright 2023 The go-ethereum Authors
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

package request

import (
	"math"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
)

var (
	// request events
	// 请求事件
	EvResponse = &EventType{Name: "response", requestEvent: true} // data: RequestResponse; sent by requestServer
	// 数据：RequestResponse；由 requestServer 发送
	EvFail = &EventType{Name: "fail", requestEvent: true} // data: RequestResponse; sent by requestServer
	// 数据：RequestResponse；由 requestServer 发送
	EvTimeout = &EventType{Name: "timeout", requestEvent: true} // data: RequestResponse; sent by serverWithTimeout
	// 数据：RequestResponse；由 serverWithTimeout 发送
	// server events
	// 服务器事件
	EvRegistered = &EventType{Name: "registered"} // data: nil; sent by Scheduler
	// 数据：nil；由 Scheduler 发送
	EvUnregistered = &EventType{Name: "unregistered"} // data: nil; sent by Scheduler
	// 数据：nil；由 Scheduler 发送
	EvCanRequestAgain = &EventType{Name: "canRequestAgain"} // data: nil; sent by serverWithLimits
	// 数据：nil；由 serverWithLimits 发送
)

const (
	softRequestTimeout = time.Second // allow resending request to a different server but do not cancel yet
	// 软请求超时：允许将请求重新发送到不同服务器，但尚未取消
	hardRequestTimeout = time.Second * 10 // cancel request
	// 硬请求超时：取消请求
)

const (
	// serverWithLimits parameters
	// serverWithLimits 参数
	parallelAdjustUp = 0.1 // adjust parallelLimit up in case of success under full load
	// 在满载成功的情况下将 parallelLimit 上调
	parallelAdjustDown = 1 // adjust parallelLimit down in case of timeout/failure
	// 在超时/失败的情况下将 parallelLimit 下调
	minParallelLimit = 1 // parallelLimit lower bound
	// parallelLimit 下限
	defaultParallelLimit = 3 // parallelLimit initial value
	// parallelLimit 初始值
	minFailureDelay = time.Millisecond * 100 // minimum disable time in case of request failure
	// 请求失败时的最小禁用时间
	maxFailureDelay = time.Minute // maximum disable time in case of request failure
	// 请求失败时的最大禁用时间
	maxServerEventBuffer = 5 // server event allowance buffer limit
	// 服务器事件允许缓冲限制
	maxServerEventRate = time.Second // server event allowance buffer recharge rate
	// 服务器事件允许缓冲充值速率
)

// requestServer can send requests in a non-blocking way and feed back events
// through the event callback. After each request it should send back either
// EvResponse or EvFail. Additionally, it may also send application-defined
// events that the Modules can interpret.
// requestServer 可以以非阻塞方式发送请求，并通过事件回调反馈事件。
// 在每个请求后，它应返回 EvResponse 或 EvFail。此外，它还可以发送模块可以解释的应用程序定义的事件。
type requestServer interface {
	Name() string
	Subscribe(eventCallback func(Event))
	SendRequest(ID, Request)
	Unsubscribe()
}

// server is implemented by a requestServer wrapped into serverWithTimeout and
// serverWithLimits and is used by Scheduler.
// In addition to requestServer functionality, server can also handle timeouts,
// limit the number of parallel in-flight requests and temporarily disable
// new requests based on timeouts and response failures.
// server 由包裹在 serverWithTimeout 和 serverWithLimits 中的 requestServer 实现，并由 Scheduler 使用。
// 除了 requestServer 功能外，server 还可以处理超时、限制并行进行中的请求数量，并根据超时和响应失败暂时禁用新请求。
type server interface {
	Server
	subscribe(eventCallback func(Event))
	canRequestNow() bool
	sendRequest(Request) ID
	fail(string)
	unsubscribe()
}

// NewServer wraps a requestServer and returns a server
// NewServer 封装一个 requestServer 并返回一个 server
func NewServer(rs requestServer, clock mclock.Clock) server {
	s := &serverWithLimits{}
	s.parent = rs
	s.serverWithTimeout.init(clock)
	s.init()
	return s
}

// EventType identifies an event type, either related to a request or the server
// in general. Server events can also be externally defined.
// EventType 标识事件类型，可以与请求或服务器一般相关。服务器事件也可以由外部定义。
type EventType struct {
	Name         string
	requestEvent bool // all request events are pre-defined in request package
	// 所有请求事件都在 request 包中预定义
}

// Event describes an event where the type of Data depends on Type.
// Server field is not required when sent through the event callback; it is filled
// out when processed by the Scheduler. Note that the Scheduler can also create
// and send events (EvRegistered, EvUnregistered) directly.
// Event 描述一个事件，其中 Data 的类型取决于 Type。
// 通过事件回调发送时不需要 Server 字段；在 Scheduler 处理时会填充该字段。
// 注意，Scheduler 也可以直接创建和发送事件（EvRegistered、EvUnregistered）。
type Event struct {
	Type   *EventType
	Server Server // filled by Scheduler
	// 由 Scheduler 填充
	Data any
}

// IsRequestEvent returns true if the event is a request event
// IsRequestEvent 如果事件是请求事件，则返回 true
func (e *Event) IsRequestEvent() bool {
	return e.Type.requestEvent
}

// RequestInfo assumes that the event is a request event and returns its contents
// in a convenient form.
// RequestInfo 假设事件是请求事件，并以方便的形式返回其内容。
func (e *Event) RequestInfo() (ServerAndID, Request, Response) {
	data := e.Data.(RequestResponse)
	return ServerAndID{Server: e.Server, ID: data.ID}, data.Request, data.Response
}

// RequestResponse is the Data type of request events.
// RequestResponse 是请求事件的数据类型。
type RequestResponse struct {
	ID       ID
	Request  Request
	Response Response
}

// serverWithTimeout wraps a requestServer and introduces timeouts.
// The request's lifecycle is concluded if EvResponse or EvFail emitted by the
// parent requestServer. If this does not happen until softRequestTimeout then
// EvTimeout is emitted, after which the final EvResponse or EvFail is still
// guaranteed to follow.
// If the parent fails to send this final event for hardRequestTimeout then
// serverWithTimeout emits EvFail and discards any further events from the
// parent related to the given request.
// serverWithTimeout 封装 requestServer 并引入超时。
// 如果父 requestServer 发出 EvResponse 或 EvFail，则请求的生命周期结束。
// 如果在 softRequestTimeout 之前未发生这种情况，则发出 EvTimeout，此后仍保证会跟随最终的 EvResponse 或 EvFail。
// 如果父级在 hardRequestTimeout 内未能发送此最终事件，则 serverWithTimeout 发出 EvFail 并丢弃父级与该请求相关的任何进一步事件。
type serverWithTimeout struct {
	parent       requestServer
	lock         sync.Mutex
	clock        mclock.Clock
	childEventCb func(event Event)
	timeouts     map[ID]mclock.Timer
	lastID       ID
}

// Name implements request.Server
// Name 实现 request.Server
func (s *serverWithTimeout) Name() string {
	return s.parent.Name()
}

// init initializes serverWithTimeout
// init 初始化 serverWithTimeout
func (s *serverWithTimeout) init(clock mclock.Clock) {
	s.clock = clock
	s.timeouts = make(map[ID]mclock.Timer)
}

// subscribe subscribes to events which include parent (requestServer) events
// plus EvTimeout.
// subscribe 订阅事件，包括父级（requestServer）事件加上 EvTimeout。
func (s *serverWithTimeout) subscribe(eventCallback func(event Event)) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.childEventCb = eventCallback
	s.parent.Subscribe(s.eventCallback)
}

// sendRequest generated a new request ID, emits EvRequest, sets up the timeout
// timer, then sends the request through the parent (requestServer).
// sendRequest 生成一个新的请求 ID，发出 EvRequest，设置超时计时器，然后通过父级（requestServer）发送请求。
func (s *serverWithTimeout) sendRequest(request Request) (reqId ID) {
	s.lock.Lock()
	s.lastID++
	id := s.lastID
	s.startTimeout(RequestResponse{ID: id, Request: request})
	s.lock.Unlock()
	s.parent.SendRequest(id, request)
	return id
}

// eventCallback is called by parent (requestServer) event subscription.
// eventCallback 由父级（requestServer）事件订阅调用。
func (s *serverWithTimeout) eventCallback(event Event) {
	s.lock.Lock()
	defer s.lock.Unlock()

	switch event.Type {
	case EvResponse, EvFail:
		id := event.Data.(RequestResponse).ID
		if timer, ok := s.timeouts[id]; ok {
			// Note: if stopping the timer is unsuccessful then the resulting AfterFunc
			// call will just do nothing
			// 注意：如果停止计时器不成功，则生成的 AfterFunc 调用将什么也不做
			timer.Stop()
			delete(s.timeouts, id)
			if s.childEventCb != nil {
				s.childEventCb(event)
			}
		}
	default:
		if s.childEventCb != nil {
			s.childEventCb(event)
		}
	}
}

// startTimeout starts a timeout timer for the given request.
// startTimeout 为给定请求启动超时计时器。
func (s *serverWithTimeout) startTimeout(reqData RequestResponse) {
	id := reqData.ID
	s.timeouts[id] = s.clock.AfterFunc(softRequestTimeout, func() {
		s.lock.Lock()
		if _, ok := s.timeouts[id]; !ok {
			s.lock.Unlock()
			return
		}
		s.timeouts[id] = s.clock.AfterFunc(hardRequestTimeout-softRequestTimeout, func() {
			s.lock.Lock()
			if _, ok := s.timeouts[id]; !ok {
				s.lock.Unlock()
				return
			}
			delete(s.timeouts, id)
			childEventCb := s.childEventCb
			s.lock.Unlock()
			if childEventCb != nil {
				childEventCb(Event{Type: EvFail, Data: reqData})
			}
		})
		childEventCb := s.childEventCb
		s.lock.Unlock()
		if childEventCb != nil {
			childEventCb(Event{Type: EvTimeout, Data: reqData})
		}
	})
}

// unsubscribe stops all goroutines associated with the server.
// unsubscribe 停止与服务器相关的所有 goroutine。
func (s *serverWithTimeout) unsubscribe() {
	s.lock.Lock()
	for _, timer := range s.timeouts {
		if timer != nil {
			timer.Stop()
		}
	}
	s.lock.Unlock()
	s.parent.Unsubscribe()
}

// serverWithLimits wraps serverWithTimeout and implements server. It limits the
// number of parallel in-flight requests and prevents sending new requests when a
// pending one has already timed out. Server events are also rate limited.
// It also implements a failure delay mechanism that adds an exponentially growing
// delay each time a request fails (wrong answer or hard timeout). This makes the
// syncing mechanism less brittle as temporary failures of the server might happen
// sometimes, but still avoids hammering a non-functional server with requests.
// serverWithLimits 封装 serverWithTimeout 并实现 server。它限制并行进行中的请求数量，并在待处理请求已超时时阻止发送新请求。
// 服务器事件也受到速率限制。
// 它还实现了一个失败延迟机制，每次请求失败（错误答案或硬超时）时增加指数增长的延迟。
// 这使得同步机制不那么脆弱，因为服务器的临时故障有时可能会发生，但仍避免用请求轰炸无法工作的服务器。
type serverWithLimits struct {
	serverWithTimeout
	lock                       sync.Mutex
	childEventCb               func(event Event)
	softTimeouts               map[ID]struct{}
	pendingCount, timeoutCount int
	parallelLimit              float32
	sendEvent                  bool
	delayTimer                 mclock.Timer
	delayCounter               int
	failureDelayEnd            mclock.AbsTime
	failureDelay               float64
	serverEventBuffer          int
	eventBufferUpdated         mclock.AbsTime
}

// init initializes serverWithLimits
// init 初始化 serverWithLimits
func (s *serverWithLimits) init() {
	s.softTimeouts = make(map[ID]struct{})
	s.parallelLimit = defaultParallelLimit
	s.serverEventBuffer = maxServerEventBuffer
}

// subscribe subscribes to events which include parent (serverWithTimeout) events
// plus EvCanRequestAgain.
// subscribe 订阅事件，包括父级（serverWithTimeout）事件加上 EvCanRequestAgain。
func (s *serverWithLimits) subscribe(eventCallback func(event Event)) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.childEventCb = eventCallback
	s.serverWithTimeout.subscribe(s.eventCallback)
}

// eventCallback is called by parent (serverWithTimeout) event subscription.
// eventCallback 由父级（serverWithTimeout）事件订阅调用。
func (s *serverWithLimits) eventCallback(event Event) {
	s.lock.Lock()
	var sendCanRequestAgain bool
	passEvent := true
	switch event.Type {
	case EvTimeout:
		id := event.Data.(RequestResponse).ID
		s.softTimeouts[id] = struct{}{}
		s.timeoutCount++
		s.parallelLimit -= parallelAdjustDown
		if s.parallelLimit < minParallelLimit {
			s.parallelLimit = minParallelLimit
		}
		log.Debug("Server timeout", "count", s.timeoutCount, "parallelLimit", s.parallelLimit)
	case EvResponse, EvFail:
		id := event.Data.(RequestResponse).ID
		if _, ok := s.softTimeouts[id]; ok {
			delete(s.softTimeouts, id)
			s.timeoutCount--
			log.Debug("Server timeout finalized", "count", s.timeoutCount, "parallelLimit", s.parallelLimit)
		}
		if event.Type == EvResponse && s.pendingCount >= int(s.parallelLimit) {
			s.parallelLimit += parallelAdjustUp
		}
		s.pendingCount--
		if s.canRequest() {
			sendCanRequestAgain = s.sendEvent
			s.sendEvent = false
		}
		if event.Type == EvFail {
			s.failLocked("failed request")
		}
	default:
		// server event; check rate limit
		// 服务器事件；检查速率限制
		if s.serverEventBuffer < maxServerEventBuffer {
			now := s.clock.Now()
			sinceUpdate := time.Duration(now - s.eventBufferUpdated)
			if sinceUpdate >= maxServerEventRate*time.Duration(maxServerEventBuffer-s.serverEventBuffer) {
				s.serverEventBuffer = maxServerEventBuffer
				s.eventBufferUpdated = now
			} else {
				addBuffer := int(sinceUpdate / maxServerEventRate)
				s.serverEventBuffer += addBuffer
				s.eventBufferUpdated += mclock.AbsTime(maxServerEventRate * time.Duration(addBuffer))
			}
		}
		if s.serverEventBuffer > 0 {
			s.serverEventBuffer--
		} else {
			passEvent = false
		}
	}
	childEventCb := s.childEventCb
	s.lock.Unlock()
	if passEvent && childEventCb != nil {
		childEventCb(event)
	}
	if sendCanRequestAgain && childEventCb != nil {
		childEventCb(Event{Type: EvCanRequestAgain})
	}
}

// sendRequest sends a request through the parent (serverWithTimeout).
// sendRequest 通过父级（serverWithTimeout）发送请求。
func (s *serverWithLimits) sendRequest(request Request) (reqId ID) {
	s.lock.Lock()
	s.pendingCount++
	s.lock.Unlock()
	return s.serverWithTimeout.sendRequest(request)
}

// unsubscribe stops all goroutines associated with the server.
// unsubscribe 停止与服务器相关的所有 goroutine。
func (s *serverWithLimits) unsubscribe() {
	s.lock.Lock()
	if s.delayTimer != nil {
		s.delayTimer.Stop()
		s.delayTimer = nil
	}
	s.childEventCb = nil
	s.lock.Unlock()
	s.serverWithTimeout.unsubscribe()
}

// canRequest checks whether a new request can be started.
// canRequest 检查是否可以启动新请求。
func (s *serverWithLimits) canRequest() bool {
	if s.delayTimer != nil || s.pendingCount >= int(s.parallelLimit) || s.timeoutCount > 0 {
		return false
	}
	if s.parallelLimit < minParallelLimit {
		s.parallelLimit = minParallelLimit
	}
	return true
}

// canRequestNow checks whether a new request can be started, according to the
// current in-flight request count and parallelLimit, and also the failure delay
// timer.
// If it returns false then it is guaranteed that an EvCanRequestAgain will be
// sent whenever the server becomes available for requesting again.
// canRequestNow 检查是否可以根据当前的进行中请求计数和 parallelLimit 以及失败延迟计时器启动新请求。
// 如果返回 false，则保证在服务器再次可用于请求时将发送 EvCanRequestAgain。
func (s *serverWithLimits) canRequestNow() bool {
	var sendCanRequestAgain bool
	s.lock.Lock()
	canRequest := s.canRequest()
	if canRequest {
		sendCanRequestAgain = s.sendEvent
		s.sendEvent = false
	}
	childEventCb := s.childEventCb
	s.lock.Unlock()
	if sendCanRequestAgain && childEventCb != nil {
		childEventCb(Event{Type: EvCanRequestAgain})
	}
	return canRequest
}

// delay sets the delay timer to the given duration, disabling new requests for
// the given period.
// delay 将延迟计时器设置为给定持续时间，在此期间禁用新请求。
func (s *serverWithLimits) delay(delay time.Duration) {
	if s.delayTimer != nil {
		// Note: if stopping the timer is unsuccessful then the resulting AfterFunc
		// call will just do nothing
		// 注意：如果停止计时器不成功，则生成的 AfterFunc 调用将什么也不做
		s.delayTimer.Stop()
		s.delayTimer = nil
	}

	s.delayCounter++
	delayCounter := s.delayCounter
	log.Debug("Server delay started", "length", delay)
	s.delayTimer = s.clock.AfterFunc(delay, func() {
		log.Debug("Server delay ended", "length", delay)
		var sendCanRequestAgain bool
		s.lock.Lock()
		if s.delayTimer != nil && s.delayCounter == delayCounter { // do nothing if there is a new timer now
			// 如果现在有新计时器，则什么也不做
			s.delayTimer = nil
			if s.canRequest() {
				sendCanRequestAgain = s.sendEvent
				s.sendEvent = false
			}
		}
		childEventCb := s.childEventCb
		s.lock.Unlock()
		if sendCanRequestAgain && childEventCb != nil {
			childEventCb(Event{Type: EvCanRequestAgain})
		}
	})
}

// fail reports that a response from the server was found invalid by the processing
// Module, disabling new requests for a dynamically adjusted time period.
// fail 报告处理模块发现服务器的响应无效，禁用新请求一段时间，时间动态调整。
func (s *serverWithLimits) fail(desc string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.failLocked(desc)
}

// failLocked calculates the dynamic failure delay and applies it.
// failLocked 计算动态失败延迟并应用它。
func (s *serverWithLimits) failLocked(desc string) {
	log.Debug("Server error", "description", desc)
	s.failureDelay *= 2
	now := s.clock.Now()
	if now > s.failureDelayEnd {
		s.failureDelay *= math.Pow(2, -float64(now-s.failureDelayEnd)/float64(maxFailureDelay))
	}
	if s.failureDelay < float64(minFailureDelay) {
		s.failureDelay = float64(minFailureDelay)
	}
	s.failureDelayEnd = now + mclock.AbsTime(s.failureDelay)
	s.delay(time.Duration(s.failureDelay))
}
