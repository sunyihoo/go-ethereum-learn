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
	"sync"

	"github.com/ethereum/go-ethereum/log"
)

// Module represents a mechanism which is typically responsible for downloading
// and updating a passive data structure. It does not directly interact with the
// servers. It can start requests using the Requester interface, maintain its
// internal state by receiving and processing Events and update its target data
// structure based on the obtained data.
// It is the Scheduler's responsibility to feed events to the modules, call
// Process as long as there might be something to process and then generate request
// candidates using MakeRequest and start the best possible requests.
// Modules are called by Scheduler whenever a global trigger is fired. All events
// fire the trigger. Changing a target data structure also triggers a next
// processing round as it could make further actions possible either by the same
// or another Module.
// Module 表示一种机制，通常负责下载和更新被动数据结构。它不直接与服务器交互。
// 它可以使用 Requester 接口发起请求，通过接收和处理 Events 维护其内部状态，并根据获取的数据更新其目标数据结构。
// Scheduler 负责向模块提供事件，只要可能有需要处理的内容就调用 Process，然后使用 MakeRequest 生成请求候选并启动最佳请求。
// 每当全局触发器被触发时，Scheduler 都会调用模块。所有事件都会触发该触发器。更改目标数据结构也会触发下一轮处理，因为这可能使同一模块或其他模块的进一步操作成为可能。
type Module interface {
	// Process is a non-blocking function responsible for starting requests,
	// processing events and updating the target data structures(s) and the
	// internal state of the module. Module state typically consists of information
	// about pending requests and registered servers.
	// Process is always called after an event is received or after a target data
	// structure has been changed.
	//
	// Note: Process functions of different modules are never called concurrently;
	// they are called by Scheduler in the same order of priority as they were
	// registered in.
	// Process 是一个非阻塞函数，负责发起请求、处理事件并更新目标数据结构和模块的内部状态。
	// 模块状态通常包括有关待处理请求和已注册服务器的信息。
	// Process 总是在接收到事件或目标数据结构更改后被调用。
	//
	// 注意：不同模块的 Process 函数不会并发调用；它们由 Scheduler 按照注册时的优先级顺序调用。
	Process(Requester, []Event)
}

// Requester allows Modules to obtain the list of momentarily available servers,
// start new requests and report server failure when a response has been proven
// to be invalid in the processing phase.
// Note that all Requester functions should be safe to call from Module.Process.
// Requester 允许模块获取当前可用服务器的列表、发起新请求，并在处理阶段证明响应无效时报告服务器故障。
// 注意，所有 Requester 函数都应在 Module.Process 中安全调用。
type Requester interface {
	CanSendTo() []Server
	Send(Server, Request) ID
	Fail(Server, string)
}

// Scheduler is a modular network data retrieval framework that coordinates multiple
// servers and retrieval mechanisms (modules). It implements a trigger mechanism
// that calls the Process function of registered modules whenever either the state
// of existing data structures or events coming from registered servers could
// allow new operations.
// Scheduler 是一个模块化的网络数据检索框架，协调多个服务器和检索机制（模块）。
// 它实现了一个触发机制，每当现有数据结构的状态或来自注册服务器的事件可能允许新操作时，调用已注册模块的 Process 函数。
type Scheduler struct {
	lock    sync.Mutex            // 主锁，保护核心数据结构。
	modules []Module              // first has the highest priority 模块列表，第一个具有最高优先级。
	names   map[Module]string     // 模块名称映射。
	servers map[server]struct{}   // 已注册服务器集合。
	targets map[targetData]uint64 // 目标数据结构及其变更计数器。

	requesterLock sync.RWMutex                   // 请求锁，保护服务器顺序和待处理请求。
	serverOrder   []server                       // 服务器顺序列表。
	pending       map[ServerAndID]pendingRequest // 待处理请求映射。

	// eventLock guards access to the events list. Note that eventLock can be
	// locked either while lock is locked or unlocked but lock cannot be locked
	// while eventLock is locked.
	// eventLock 保护事件列表的访问。注意，eventLock 可以在 lock 被锁定或解锁时锁定，但 lock 不能在 eventLock 被锁定时锁定。
	eventLock sync.Mutex         // 事件锁。
	events    []Event            // 事件列表。
	stopCh    chan chan struct{} // 停止信号通道。

	triggerCh chan struct{} // restarts waiting sync loop 重启等待同步循环的触发通道。
	// if trigger has already been fired then send to testWaitCh blocks until
	// the triggered processing round is finished
	// 如果触发器已被触发，则向 testWaitCh 发送会阻塞，直到触发的处理轮次完成。
	testWaitCh chan struct{} // 测试等待通道。
}

type (
	// Server identifies a server without allowing any direct interaction.
	// Note: server interface is used by Scheduler and Tracker but not used by
	// the modules that do not interact with them directly.
	// In order to make module testing easier, Server interface is used in
	// events and modules.
	// Server 标识一个服务器，但不允许直接交互。
	// 注意：server 接口由 Scheduler 和 Tracker 使用，但不被直接与之交互的模块使用。
	// 为了便于模块测试，Server 接口在事件和模块中使用。
	Server interface {
		Name() string
	}
	Request     any      // 请求类型。
	Response    any      // 响应类型。
	ID          uint64   // 请求 ID。
	ServerAndID struct { // 服务器和 ID 的组合。
		Server Server
		ID     ID
	}
)

// targetData represents a registered target data structure that increases its
// ChangeCounter whenever it has been changed.
// targetData 表示一个注册的目标数据结构，每当它被更改时，其 ChangeCounter 会增加。
type targetData interface {
	ChangeCounter() uint64
}

// pendingRequest keeps track of sent and not yet finalized requests and their
// sender modules.
// pendingRequest 跟踪已发送但尚未完成请求及其发送模块。
type pendingRequest struct {
	request Request
	module  Module
}

// NewScheduler creates a new Scheduler.
// NewScheduler 创建一个新的 Scheduler。
func NewScheduler() *Scheduler {
	s := &Scheduler{
		servers: make(map[server]struct{}),
		names:   make(map[Module]string),
		pending: make(map[ServerAndID]pendingRequest),
		targets: make(map[targetData]uint64),
		stopCh:  make(chan chan struct{}),
		// Note: testWaitCh should not have capacity in order to ensure
		// that after a trigger happens testWaitCh will block until the resulting
		// processing round has been finished
		// 注意：testWaitCh 不应有容量，以确保触发发生后 testWaitCh 会阻塞，直到相应的处理轮次完成。
		triggerCh:  make(chan struct{}, 1),
		testWaitCh: make(chan struct{}),
	}
	return s
}

// RegisterTarget registers a target data structure, ensuring that any changes
// made to it trigger a new round of Module.Process calls, giving a chance to
// modules to react to the changes.
// RegisterTarget 注册一个目标数据结构，确保对其的任何更改都会触发新一轮 Module.Process 调用，使模块有机会对更改做出反应。
func (s *Scheduler) RegisterTarget(t targetData) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.targets[t] = 0
}

// RegisterModule registers a module. Should be called before starting the scheduler.
// In each processing round the order of module processing depends on the order of
// registration.
// RegisterModule 注册一个模块。应在启动调度器之前调用。
// 在每个处理轮次中，模块处理的顺序取决于注册顺序。
func (s *Scheduler) RegisterModule(m Module, name string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.modules = append(s.modules, m)
	s.names[m] = name
}

// RegisterServer registers a new server.
// RegisterServer 注册一个新服务器。
func (s *Scheduler) RegisterServer(server server) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.addEvent(Event{Type: EvRegistered, Server: server})
	server.subscribe(func(event Event) {
		event.Server = server
		s.addEvent(event)
	})
}

// UnregisterServer removes a registered server.
// UnregisterServer 移除一个已注册的服务器。
func (s *Scheduler) UnregisterServer(server server) {
	s.lock.Lock()
	defer s.lock.Unlock()

	server.unsubscribe()
	s.addEvent(Event{Type: EvUnregistered, Server: server})
}

// Start starts the scheduler. It should be called after registering all modules
// and before registering any servers.
// Start 启动调度器。应在注册所有模块之后且注册任何服务器之前调用。
func (s *Scheduler) Start() {
	go s.syncLoop()
}

// Stop stops the scheduler.
// Stop 停止调度器。
func (s *Scheduler) Stop() {
	stop := make(chan struct{})
	s.stopCh <- stop
	<-stop
	s.lock.Lock()
	for server := range s.servers {
		server.unsubscribe()
	}
	s.servers = nil
	s.lock.Unlock()
}

// syncLoop is the main event loop responsible for event/data processing and
// sending new requests.
// A round of processing starts whenever the global trigger is fired. Triggers
// fired during a processing round ensure that there is going to be a next round.
// syncLoop 是主事件循环，负责事件/数据处理和发送新请求。
// 每当全局触发器被触发时，就会开始一轮处理。在处理轮次期间触发的触发器确保将会有下一轮处理。
func (s *Scheduler) syncLoop() {
	for {
		s.lock.Lock()
		s.processRound()
		s.lock.Unlock()
	loop:
		for {
			select {
			case stop := <-s.stopCh:
				close(stop)
				return
			case <-s.triggerCh:
				break loop
			case <-s.testWaitCh:
			}
		}
	}
}

// targetChanged returns true if a registered target data structure has been
// changed since the last call to this function.
// targetChanged 如果自上次调用此函数以来注册的目标数据结构已更改，则返回 true。
func (s *Scheduler) targetChanged() (changed bool) {
	for target, counter := range s.targets {
		if newCounter := target.ChangeCounter(); newCounter != counter {
			s.targets[target] = newCounter
			changed = true
		}
	}
	return
}

// processRound runs an entire processing round. It calls the Process functions
// of all modules, passing all relevant events and repeating Process calls as
// long as any changes have been made to the registered target data structures.
// Once all events have been processed and a stable state has been achieved,
// requests are generated and sent if necessary and possible.
// processRound 运行整个处理轮次。它调用所有模块的 Process 函数，传递所有相关事件，并在注册的目标数据结构发生任何更改时重复调用 Process。
// 一旦所有事件处理完毕并达到稳定状态，将根据需要和可能生成并发送请求。
func (s *Scheduler) processRound() {
	for {
		log.Trace("Processing modules")
		filteredEvents := s.filterEvents()
		for _, module := range s.modules {
			log.Trace("Processing module", "name", s.names[module], "events", len(filteredEvents[module]))
			module.Process(requester{s, module}, filteredEvents[module])
		}
		if !s.targetChanged() {
			break
		}
	}
}

// Trigger starts a new processing round. If fired during processing, it ensures
// another full round of processing all modules.
// Trigger 启动新一轮处理。如果在处理期间触发，它确保所有模块的另一轮完整处理。
func (s *Scheduler) Trigger() {
	select {
	case s.triggerCh <- struct{}{}:
	default:
	}
}

// addEvent adds an event to be processed in the next round. Note that it can be
// called regardless of the state of the lock mutex, making it safe for use in
// the server event callback.
// addEvent 添加一个事件以在下一轮中处理。注意，无论 lock 互斥锁的状态如何都可以调用它，使其在服务器事件回调中使用是安全的。
func (s *Scheduler) addEvent(event Event) {
	s.eventLock.Lock()
	s.events = append(s.events, event)
	s.eventLock.Unlock()
	s.Trigger()
}

// filterEvent sorts each Event either as a request event or a server event,
// depending on its type. Request events are also sorted in a map based on the
// module that originally initiated the request. It also ensures that no events
// related to a server are returned before EvRegistered or after EvUnregistered.
// In case of an EvUnregistered server event it also closes all pending requests
// to the given server by adding a failed request event (EvFail), ensuring that
// all requests get finalized and thereby allowing the module logic to be safe
// and simple.
// filterEvent 根据事件类型将每个 Event 分类为请求事件或服务器事件。
// 请求事件还根据最初发起请求的模块在映射中排序。它还确保在 EvRegistered 之前或 EvUnregistered 之后不会返回与服务器相关的事件。
// 如果发生 EvUnregistered 服务器事件，它还会通过添加失败请求事件 (EvFail) 关闭给定服务器的所有待处理请求，确保所有请求都得到最终处理，从而使模块逻辑安全且简单。
func (s *Scheduler) filterEvents() map[Module][]Event {
	s.eventLock.Lock()
	events := s.events
	s.events = nil
	s.eventLock.Unlock()

	s.requesterLock.Lock()
	defer s.requesterLock.Unlock()

	filteredEvents := make(map[Module][]Event)
	for _, event := range events {
		server := event.Server.(server)
		if _, ok := s.servers[server]; !ok && event.Type != EvRegistered {
			continue // before EvRegister or after EvUnregister, discard
			// 在 EvRegister 之前或 EvUnregister 之后，丢弃。
		}

		if event.IsRequestEvent() {
			sid, _, _ := event.RequestInfo()
			pending, ok := s.pending[sid]
			if !ok {
				continue // request already closed, ignore further events
				// 请求已关闭，忽略后续事件。
			}
			if event.Type == EvResponse || event.Type == EvFail {
				delete(s.pending, sid) // final event, close pending request
				// 最终事件，关闭待处理请求。
			}
			filteredEvents[pending.module] = append(filteredEvents[pending.module], event)
		} else {
			switch event.Type {
			case EvRegistered:
				s.servers[server] = struct{}{}
				s.serverOrder = append(s.serverOrder, nil)
				copy(s.serverOrder[1:], s.serverOrder[:len(s.serverOrder)-1])
				s.serverOrder[0] = server
			case EvUnregistered:
				s.closePending(event.Server, filteredEvents)
				delete(s.servers, server)
				for i, srv := range s.serverOrder {
					if srv == server {
						copy(s.serverOrder[i:len(s.serverOrder)-1], s.serverOrder[i+1:])
						s.serverOrder = s.serverOrder[:len(s.serverOrder)-1]
						break
					}
				}
			}
			for _, module := range s.modules {
				filteredEvents[module] = append(filteredEvents[module], event)
			}
		}
	}
	return filteredEvents
}

// closePending closes all pending requests to the given server and adds an EvFail
// event to properly finalize them
// closePending 关闭给定服务器的所有待处理请求，并添加一个 EvFail 事件以正确完成它们。
func (s *Scheduler) closePending(server Server, filteredEvents map[Module][]Event) {
	for sid, pending := range s.pending {
		if sid.Server == server {
			filteredEvents[pending.module] = append(filteredEvents[pending.module], Event{
				Type:   EvFail,
				Server: server,
				Data: RequestResponse{
					ID:      sid.ID,
					Request: pending.request,
				},
			})
			delete(s.pending, sid)
		}
	}
}

// requester implements Requester. Note that while requester basically wraps
// Scheduler (with the added information of the currently processed Module), all
// functions are safe to call from Module.Process which is running while
// the Scheduler.lock mutex is held.
// requester 实现了 Requester。注意，虽然 requester 基本上封装了 Scheduler（附加了当前处理的 Module 信息），
// 但所有函数在 Module.Process 运行时（此时 Scheduler.lock 互斥锁被持有）调用都是安全的。
type requester struct {
	*Scheduler
	module Module
}

// CanSendTo returns the list of currently available servers. It also returns
// them in an order of least to most recently used, ensuring a round-robin usage
// of suitable servers if the module always chooses the first suitable one.
// CanSendTo 返回当前可用服务器的列表。它还按照从最少用到最近使用的顺序返回它们，
// 如果模块始终选择第一个合适的服务器，则确保合适的服务器的轮询使用。
func (s requester) CanSendTo() []Server {
	s.requesterLock.RLock()
	defer s.requesterLock.RUnlock()

	list := make([]Server, 0, len(s.serverOrder))
	for _, server := range s.serverOrder {
		if server.canRequestNow() {
			list = append(list, server)
		}
	}
	return list
}

// Send sends a request and adds an entry to Scheduler.pending map, ensuring that
// related request events will be delivered to the sender Module.
// Send 发送一个请求并向 Scheduler.pending 映射中添加一个条目，确保相关请求事件将传递给发送模块。
func (s requester) Send(srv Server, req Request) ID {
	s.requesterLock.Lock()
	defer s.requesterLock.Unlock()

	server := srv.(server)
	id := server.sendRequest(req)
	sid := ServerAndID{Server: srv, ID: id}
	s.pending[sid] = pendingRequest{request: req, module: s.module}
	for i, ss := range s.serverOrder {
		if ss == server {
			copy(s.serverOrder[i:len(s.serverOrder)-1], s.serverOrder[i+1:])
			s.serverOrder[len(s.serverOrder)-1] = server
			return id
		}
	}
	log.Error("Target server not found in ordered list of registered servers")
	return id
}

// Fail should be called when a server delivers invalid or useless information.
// Calling Fail disables the given server for a period that is initially short
// but is exponentially growing if it happens frequently. This results in a
// somewhat fault tolerant operation that avoids hammering servers with requests
// that they cannot serve but still gives them a chance periodically.
// Fail 应在服务器提供无效或无用信息时调用。
// 调用 Fail 会禁用给定服务器一段时间，该时间最初较短，但如果频繁发生则呈指数增长。
// 这导致某种程度上容错的操作，避免用无法服务的请求轰炸服务器，但仍定期给予它们机会。
func (s requester) Fail(srv Server, desc string) {
	srv.(server).fail(desc)
}
