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

// Package ethstats implements the network stats reporting service.
package ethstats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	ethproto "github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
)

const (
	// historyUpdateRange is the number of blocks a node should report upon login or
	// history request.
	// historyUpdateRange 定义了节点在登录或历史请求时应报告的区块数量。
	historyUpdateRange = 50

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	// txChanSize 定义了监听 NewTxsEvent 事件的通道大小。这个数值参考了交易池的大小。
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	// chainHeadChanSize 定义了监听 ChainHeadEvent 事件的通道大小。
	chainHeadChanSize = 10

	messageSizeLimit = 15 * 1024 * 1024 // 消息大小限制，设置为 15MB。
)

// backend encompasses the bare-minimum functionality needed for ethstats reporting
// backend 接口定义了 ethstats 报告所需的最基本功能
// backend 接口定义了 ethstats 报告服务所需的最基本功能，包括订阅事件、获取区块链头和统计信息等。
type backend interface {
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription          // 订阅链头事件
	SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription                // 订阅新交易事件
	CurrentHeader() *types.Header                                                      // 获取当前区块头
	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) // 根据区块号获取区块头
	GetTd(ctx context.Context, hash common.Hash) *big.Int                              // 获取指定区块的总难度
	Stats() (pending int, queued int)                                                  // 获取交易池统计信息（待处理和队列中的交易数量）
	SyncProgress() ethereum.SyncProgress                                               // 获取同步进度
}

// fullNodeBackend encompasses the functionality necessary for a full node
// reporting to ethstats
// fullNodeBackend 接口定义了全节点向 ethstats 报告所需的功能
// fullNodeBackend 接口扩展了 backend，为全节点提供了额外的功能，如获取完整区块和建议 Gas 小费。
type fullNodeBackend interface {
	backend
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) // 根据区块号获取完整区块
	CurrentBlock() *types.Header                                                     // 获取当前完整区块头
	SuggestGasTipCap(ctx context.Context) (*big.Int, error)                          // 建议的 Gas 小费上限（EIP-1559）
}

// Service implements an Ethereum netstats reporting daemon that pushes local
// chain statistics up to a monitoring server.
// Service 结构体实现了一个以太坊 netstats 报告守护进程，它将本地链的统计数据推送到监控服务器。
// Service 结构体实现了一个以太坊网络统计报告守护进程，通过 WebSocket 将本地节点的链统计数据推送至监控服务器。
type Service struct {
	server *p2p.Server // Peer-to-peer server to retrieve networking infos
	// server 字段用于获取网络信息
	// P2P 服务器，用于获取网络相关信息，如对等节点数量。
	backend backend
	// backend 字段提供了区块链数据的访问接口
	// backend 接口，提供对区块链数据的访问，如区块头、交易等。
	engine consensus.Engine // Consensus engine to retrieve variadic block fields
	// engine 字段是共识引擎，用于获取区块的变量字段
	// 共识引擎，用于获取区块的可变字段，例如矿工地址。

	node string // Name of the node to display on the monitoring page
	// node 字段是节点在监控页面上显示的名称
	// 节点名称，在监控页面上显示的标识。
	pass string // Password to authorize access to the monitoring page
	// pass 字段是授权访问监控页面的密码
	// 密码，用于授权访问监控服务器。
	host string // Remote address of the monitoring service
	// host 字段是监控服务的远程地址
	// 监控服务的远程地址，例如 WebSocket 服务器地址。

	pongCh chan struct{} // Pong notifications are fed into this channel
	// pongCh 通道用于接收 pong 通知
	// pong 通知通道，用于接收服务器的 pong 响应，以测量延迟。
	histCh chan []uint64 // History request block numbers are fed into this channel
	// histCh 通道用于接收历史请求的区块号
	// 历史请求通道，用于接收需要报告的区块号列表。

	headSub event.Subscription
	// headSub 是对 ChainHeadEvent 事件的订阅
	// 链头事件订阅，用于监听区块链头的更新。
	txSub event.Subscription
	// txSub 是对 NewTxsEvent 事件的订阅
	// 新交易事件订阅，用于监听交易池中的新交易。
}

// connWrapper is a wrapper to prevent concurrent-write or concurrent-read on the
// websocket.
//
// From Gorilla websocket docs:
//
// Connections support one concurrent reader and one concurrent writer. Applications are
// responsible for ensuring that
//   - no more than one goroutine calls the write methods
//     NextWriter, SetWriteDeadline, WriteMessage, WriteJSON, EnableWriteCompression,
//     SetCompressionLevel concurrently; and
//   - that no more than one goroutine calls the
//     read methods NextReader, SetReadDeadline, ReadMessage, ReadJSON, SetPongHandler,
//     SetPingHandler concurrently.
//
// The Close and WriteControl methods can be called concurrently with all other methods.
// connWrapper 结构体是对 websocket 连接的包装，防止并发写入或并发读取。
// connWrapper 结构体封装了 WebSocket 连接，通过互斥锁防止并发读写，确保线程安全。
type connWrapper struct {
	conn *websocket.Conn

	rlock sync.Mutex // 读锁
	wlock sync.Mutex // 写锁
}

func newConnectionWrapper(conn *websocket.Conn) *connWrapper {
	conn.SetReadLimit(messageSizeLimit) // 设置读取限制
	return &connWrapper{conn: conn}
}

// WriteJSON wraps corresponding method on the websocket but is safe for concurrent calling
// WriteJSON 方法包装了 websocket 的 WriteJSON 方法，确保并发调用安全。
// WriteJSON 方法封装了 WebSocket 的 JSON 写入方法，通过写锁确保并发安全。
func (w *connWrapper) WriteJSON(v interface{}) error {
	w.wlock.Lock()
	defer w.wlock.Unlock()

	return w.conn.WriteJSON(v)
}

// ReadJSON wraps corresponding method on the websocket but is safe for concurrent calling
// ReadJSON 方法包装了 websocket 的 ReadJSON 方法，确保并发调用安全。
// ReadJSON 方法封装了 WebSocket 的 JSON 读取方法，通过读锁确保并发安全。
func (w *connWrapper) ReadJSON(v interface{}) error {
	w.rlock.Lock()
	defer w.rlock.Unlock()

	return w.conn.ReadJSON(v)
}

// Close wraps corresponding method on the websocket but is safe for concurrent calling
// Close 方法包装了 websocket 的 Close 方法，确保并发调用安全。
// Close 方法封装了 WebSocket 的关闭方法，无需锁保护，因为它允许与其他方法并发调用。
func (w *connWrapper) Close() error {
	// The Close and WriteControl methods can be called concurrently with all other methods,
	// so the mutex is not used here
	// Close 和 WriteControl 方法可以与其他方法并发调用，因此此处不使用互斥锁。
	return w.conn.Close()
}

// parseEthstatsURL parses the netstats connection url.
// URL argument should be of the form <nodename:secret@host:port>
// If non-erroring, the returned slice contains 3 elements: [nodename, pass, host]
// parseEthstatsURL 函数解析 netstats 连接 URL。URL 参数应为 <nodename:secret@host:port> 形式。如果解析成功，返回的切片包含 3 个元素：[nodename, pass, host]
// parseEthstatsURL 函数解析 ethstats 的连接 URL，格式为 <nodename:secret@host:port>，成功时返回节点名、密码和主机地址。
func parseEthstatsURL(url string) (parts []string, err error) {
	err = fmt.Errorf("invalid netstats url: \"%s\", should be nodename:secret@host:port", url)

	hostIndex := strings.LastIndex(url, "@")
	if hostIndex == -1 || hostIndex == len(url)-1 {
		return nil, err
	}
	preHost, host := url[:hostIndex], url[hostIndex+1:]

	passIndex := strings.LastIndex(preHost, ":")
	if passIndex == -1 {
		return []string{preHost, "", host}, nil
	}
	nodename, pass := preHost[:passIndex], ""
	if passIndex != len(preHost)-1 {
		pass = preHost[passIndex+1:]
	}

	return []string{nodename, pass, host}, nil
}

// New returns a monitoring service ready for stats reporting.
// New 函数返回一个准备好进行统计报告的监控服务。
// New 函数创建一个准备好进行统计报告的监控服务实例，并注册到节点生命周期。
func New(node *node.Node, backend backend, engine consensus.Engine, url string) error {
	parts, err := parseEthstatsURL(url)
	if err != nil {
		return err
	}
	ethstats := &Service{
		backend: backend,
		engine:  engine,
		server:  node.Server(),
		node:    parts[0],
		pass:    parts[1],
		host:    parts[2],
		pongCh:  make(chan struct{}),
		histCh:  make(chan []uint64, 1),
	}

	node.RegisterLifecycle(ethstats)
	return nil
}

// Start implements node.Lifecycle, starting up the monitoring and reporting daemon.
// Start 方法实现 node.Lifecycle 接口，启动监控和报告守护进程。
// Start 方法实现 node.Lifecycle 接口，启动监控和报告守护进程，订阅链头和新交易事件。
func (s *Service) Start() error {
	// Subscribe to chain events to execute updates on
	chainHeadCh := make(chan core.ChainHeadEvent, chainHeadChanSize)
	s.headSub = s.backend.SubscribeChainHeadEvent(chainHeadCh)
	txEventCh := make(chan core.NewTxsEvent, txChanSize)
	s.txSub = s.backend.SubscribeNewTxsEvent(txEventCh)
	go s.loop(chainHeadCh, txEventCh)

	log.Info("Stats daemon started")
	return nil
}

// Stop implements node.Lifecycle, terminating the monitoring and reporting daemon.
// Stop 方法实现 node.Lifecycle 接口，终止监控和报告守护进程。
// Stop 方法实现 node.Lifecycle 接口，终止监控和报告守护进程，取消事件订阅。
func (s *Service) Stop() error {
	s.headSub.Unsubscribe()
	s.txSub.Unsubscribe()
	log.Info("Stats daemon stopped")
	return nil
}

// loop keeps trying to connect to the netstats server, reporting chain events
// until termination.
// loop 函数不断尝试连接到 netstats 服务器，报告链事件，直到终止。
// loop 函数持续尝试连接 netstats 服务器，报告链事件，直到服务终止。
// **详细解释**：
// 1. 创建一个 goroutine 处理订阅事件，避免事件堆积。
// 2. 解析主机地址，支持 wss 和 ws 协议。
// 3. 使用 WebSocket 建立连接，进行登录认证。
// 4. 发送初始统计数据，并每 15 秒报告一次完整状态。
// 5. 根据链头、新交易和历史请求触发相应的报告。
// 6. 连接断开时自动重试，确保服务高可用。
func (s *Service) loop(chainHeadCh chan core.ChainHeadEvent, txEventCh chan core.NewTxsEvent) {
	// Start a goroutine that exhausts the subscriptions to avoid events piling up
	var (
		quitCh = make(chan struct{})
		headCh = make(chan *types.Header, 1)
		txCh   = make(chan struct{}, 1)
	)
	go func() {
		var lastTx mclock.AbsTime

	HandleLoop:
		for {
			select {
			// Notify of chain head events, but drop if too frequent
			case head := <-chainHeadCh:
				select {
				case headCh <- head.Header:
				default:
				}

			// Notify of new transaction events, but drop if too frequent
			case <-txEventCh:
				if time.Duration(mclock.Now()-lastTx) < time.Second {
					continue
				}
				lastTx = mclock.Now()

				select {
				case txCh <- struct{}{}:
				default:
				}

			// node stopped
			case <-s.txSub.Err():
				break HandleLoop
			case <-s.headSub.Err():
				break HandleLoop
			}
		}
		close(quitCh)
	}()

	// Resolve the URL, defaulting to TLS, but falling back to none too
	path := fmt.Sprintf("%s/api", s.host)
	urls := []string{path}

	// url.Parse and url.IsAbs is unsuitable (https://github.com/golang/go/issues/19779)
	if !strings.Contains(path, "://") {
		urls = []string{"wss://" + path, "ws://" + path}
	}

	errTimer := time.NewTimer(0)
	defer errTimer.Stop()
	// Loop reporting until termination
	for {
		select {
		case <-quitCh:
			return
		case <-errTimer.C:
			// Establish a websocket connection to the server on any supported URL
			var (
				conn *connWrapper
				err  error
			)
			dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
			header := make(http.Header)
			header.Set("origin", "http://localhost")
			for _, url := range urls {
				c, _, e := dialer.Dial(url, header)
				err = e
				if err == nil {
					conn = newConnectionWrapper(c)
					break
				}
			}
			if err != nil {
				log.Warn("Stats server unreachable", "err", err)
				errTimer.Reset(10 * time.Second)
				continue
			}
			// Authenticate the client with the server
			if err = s.login(conn); err != nil {
				log.Warn("Stats login failed", "err", err)
				conn.Close()
				errTimer.Reset(10 * time.Second)
				continue
			}
			go s.readLoop(conn)

			// Send the initial stats so our node looks decent from the get go
			if err = s.report(conn); err != nil {
				log.Warn("Initial stats report failed", "err", err)
				conn.Close()
				errTimer.Reset(0)
				continue
			}
			// Keep sending status updates until the connection breaks
			fullReport := time.NewTicker(15 * time.Second)

			for err == nil {
				select {
				case <-quitCh:
					fullReport.Stop()
					// Make sure the connection is closed
					conn.Close()
					return

				case <-fullReport.C:
					if err = s.report(conn); err != nil {
						log.Warn("Full stats report failed", "err", err)
					}
				case list := <-s.histCh:
					if err = s.reportHistory(conn, list); err != nil {
						log.Warn("Requested history report failed", "err", err)
					}
				case head := <-headCh:
					if err = s.reportBlock(conn, head); err != nil {
						log.Warn("Block stats report failed", "err", err)
					}
					if err = s.reportPending(conn); err != nil {
						log.Warn("Post-block transaction stats report failed", "err", err)
					}
				case <-txCh:
					if err = s.reportPending(conn); err != nil {
						log.Warn("Transaction stats report failed", "err", err)
					}
				}
			}
			fullReport.Stop()

			// Close the current connection and establish a new one
			conn.Close()
			errTimer.Reset(0)
		}
	}
}

// readLoop loops as long as the connection is alive and retrieves data packets
// from the network socket. If any of them match an active request, it forwards
// it, if they themselves are requests it initiates a reply, and lastly it drops
// unknown packets.
// readLoop 函数在连接存活期间循环，从网络套接字检索数据包。如果数据包与活动请求匹配，则转发；如果数据包本身是请求，则发起回复；最后，丢弃未知数据包。
// readLoop 函数在 WebSocket 连接存活时循环读取数据包，处理 ping 请求、历史请求等，并丢弃未知数据包。
func (s *Service) readLoop(conn *connWrapper) {
	// If the read loop exits, close the connection
	defer conn.Close()

	for {
		// Retrieve the next generic network packet and bail out on error
		var blob json.RawMessage
		if err := conn.ReadJSON(&blob); err != nil {
			log.Warn("Failed to retrieve stats server message", "err", err)
			return
		}
		// If the network packet is a system ping, respond to it directly
		var ping string
		if err := json.Unmarshal(blob, &ping); err == nil && strings.HasPrefix(ping, "primus::ping::") {
			if err := conn.WriteJSON(strings.ReplaceAll(ping, "ping", "pong")); err != nil {
				log.Warn("Failed to respond to system ping message", "err", err)
				return
			}
			continue
		}
		// Not a system ping, try to decode an actual state message
		var msg map[string][]interface{}
		if err := json.Unmarshal(blob, &msg); err != nil {
			log.Warn("Failed to decode stats server message", "err", err)
			return
		}
		log.Trace("Received message from stats server", "msg", msg)
		if len(msg["emit"]) == 0 {
			log.Warn("Stats server sent non-broadcast", "msg", msg)
			return
		}
		command, ok := msg["emit"][0].(string)
		if !ok {
			log.Warn("Invalid stats server message type", "type", msg["emit"][0])
			return
		}
		// If the message is a ping reply, deliver (someone must be listening!)
		if len(msg["emit"]) == 2 && command == "node-pong" {
			select {
			case s.pongCh <- struct{}{}:
				// Pong delivered, continue listening
				continue
			default:
				// Ping routine dead, abort
				log.Warn("Stats server pinger seems to have died")
				return
			}
		}
		// If the message is a history request, forward to the event processor
		if len(msg["emit"]) == 2 && command == "history" {
			// Make sure the request is valid and doesn't crash us
			request, ok := msg["emit"][1].(map[string]interface{})
			if !ok {
				log.Warn("Invalid stats history request", "msg", msg["emit"][1])
				select {
				case s.histCh <- nil: // Treat it as an no indexes request
				default:
				}
				continue
			}
			list, ok := request["list"].([]interface{})
			if !ok {
				log.Warn("Invalid stats history block list", "list", request["list"])
				return
			}
			// Convert the block number list to an integer list
			numbers := make([]uint64, len(list))
			for i, num := range list {
				n, ok := num.(float64)
				if !ok {
					log.Warn("Invalid stats history block number", "number", num)
					return
				}
				numbers[i] = uint64(n)
			}
			select {
			case s.histCh <- numbers:
				continue
			default:
			}
		}
		// Report anything else and continue
		log.Info("Unknown stats message", "msg", msg)
	}
}

// nodeInfo is the collection of meta information about a node that is displayed
// on the monitoring page.
// nodeInfo 结构体包含在监控页面上显示的节点元信息。
// nodeInfo 结构体定义了在监控页面上显示的节点元信息，如名称、端口、网络 ID 等。
type nodeInfo struct {
	Name     string `json:"name"`             // 节点名称
	Node     string `json:"node"`             // 节点标识
	Port     int    `json:"port"`             // 监听端口
	Network  string `json:"net"`              // 网络 ID
	Protocol string `json:"protocol"`         // 协议版本
	API      string `json:"api"`              // API 支持情况
	Os       string `json:"os"`               // 操作系统
	OsVer    string `json:"os_v"`             // 操作系统版本
	Client   string `json:"client"`           // 客户端版本
	History  bool   `json:"canUpdateHistory"` // 是否支持历史更新
}

// authMsg is the authentication infos needed to login to a monitoring server.
// authMsg 结构体包含登录到监控服务器所需的认证信息。
// authMsg 结构体定义了登录监控服务器所需的认证信息，包括节点 ID、节点信息和密码。
type authMsg struct {
	ID     string   `json:"id"`     // 节点 ID
	Info   nodeInfo `json:"info"`   // 节点信息
	Secret string   `json:"secret"` // 认证密码
}

// login tries to authorize the client at the remote server.
// login 函数尝试在远程服务器上授权客户端。
// login 函数通过发送节点信息和密码尝试在远程服务器上进行认证。
func (s *Service) login(conn *connWrapper) error {
	// Construct and send the login authentication
	infos := s.server.NodeInfo()

	var protocols []string
	for _, proto := range s.server.Protocols {
		protocols = append(protocols, fmt.Sprintf("%s/%d", proto.Name, proto.Version))
	}
	var network string
	if info := infos.Protocols["eth"]; info != nil {
		network = fmt.Sprintf("%d", info.(*ethproto.NodeInfo).Network)
	} else {
		return errors.New("no eth protocol available")
	}
	auth := &authMsg{
		ID: s.node,
		Info: nodeInfo{
			Name:     s.node,
			Node:     infos.Name,
			Port:     infos.Ports.Listener,
			Network:  network,
			Protocol: strings.Join(protocols, ", "),
			API:      "No",
			Os:       runtime.GOOS,
			OsVer:    runtime.GOARCH,
			Client:   "0.1.1",
			History:  true,
		},
		Secret: s.pass,
	}
	login := map[string][]interface{}{
		"emit": {"hello", auth},
	}
	if err := conn.WriteJSON(login); err != nil {
		return err
	}
	// Retrieve the remote ack or connection termination
	var ack map[string][]string
	if err := conn.ReadJSON(&ack); err != nil || len(ack["emit"]) != 1 || ack["emit"][0] != "ready" {
		return errors.New("unauthorized")
	}
	return nil
}

// report collects all possible data to report and send it to the stats server.
// This should only be used on reconnects or rarely to avoid overloading the
// server. Use the individual methods for reporting subscribed events.
// report 函数收集所有可能的数据并发送到统计服务器。这应该只在重新连接或很少使用时调用，以避免服务器过载。使用单独的方法报告订阅的事件。
// report 函数收集所有可报告的数据并发送到统计服务器，通常在重连时调用，避免频繁使用以减轻服务器负担。
func (s *Service) report(conn *connWrapper) error {
	if err := s.reportLatency(conn); err != nil {
		return err
	}
	if err := s.reportBlock(conn, nil); err != nil {
		return err
	}
	if err := s.reportPending(conn); err != nil {
		return err
	}
	if err := s.reportStats(conn); err != nil {
		return err
	}
	return nil
}

// reportLatency sends a ping request to the server, measures the RTT time and
// finally sends a latency update.
// reportLatency 函数向服务器发送 ping 请求，测量 RTT 时间，最后发送延迟更新。
// reportLatency 函数通过 ping-pong 机制测量与服务器的往返时间（RTT），并发送延迟更新。
func (s *Service) reportLatency(conn *connWrapper) error {
	// Send the current time to the ethstats server
	start := time.Now()

	ping := map[string][]interface{}{
		"emit": {"node-ping", map[string]string{
			"id":         s.node,
			"clientTime": start.String(),
		}},
	}
	if err := conn.WriteJSON(ping); err != nil {
		return err
	}
	// Wait for the pong request to arrive back
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-s.pongCh:
		// Pong delivered, report the latency
	case <-timer.C:
		// Ping timeout, abort
		return errors.New("ping timed out")
	}
	latency := strconv.Itoa(int((time.Since(start) / time.Duration(2)).Nanoseconds() / 1000000))

	// Send back the measured latency
	log.Trace("Sending measured latency to ethstats", "latency", latency)

	stats := map[string][]interface{}{
		"emit": {"latency", map[string]string{
			"id":      s.node,
			"latency": latency,
		}},
	}
	return conn.WriteJSON(stats)
}

// blockStats is the information to report about individual blocks.
// blockStats 结构体包含关于单个区块的报告信息。
// blockStats 结构体定义了单个区块的统计信息，如区块号、哈希、矿工地址等。
type blockStats struct {
	Number     *big.Int       `json:"number"`           // 区块号
	Hash       common.Hash    `json:"hash"`             // 区块哈希
	ParentHash common.Hash    `json:"parentHash"`       // 父区块哈希
	Timestamp  *big.Int       `json:"timestamp"`        // 时间戳
	Miner      common.Address `json:"miner"`            // 矿工地址
	GasUsed    uint64         `json:"gasUsed"`          // 已用 Gas
	GasLimit   uint64         `json:"gasLimit"`         // Gas 上限
	Diff       string         `json:"difficulty"`       // 难度
	TotalDiff  string         `json:"totalDifficulty"`  // 总难度
	Txs        []txStats      `json:"transactions"`     // 交易列表
	TxHash     common.Hash    `json:"transactionsRoot"` // 交易根哈希
	Root       common.Hash    `json:"stateRoot"`        // 状态根哈希
	Uncles     uncleStats     `json:"uncles"`           // 叔块列表
}

// txStats is the information to report about individual transactions.
// txStats 结构体包含关于单个交易的报告信息。
// txStats 结构体定义了单个交易的统计信息，目前仅包含交易哈希。
type txStats struct {
	Hash common.Hash `json:"hash"` // 交易哈希
}

// uncleStats is a custom wrapper around an uncle array to force serializing
// empty arrays instead of returning null for them.
// uncleStats 是一个自定义的 uncle 数组包装器，强制序列化空数组而不是返回 null。
// uncleStats 是一个叔块数组的包装器，确保序列化时返回空数组而不是 null。
type uncleStats []*types.Header

func (s uncleStats) MarshalJSON() ([]byte, error) {
	if uncles := ([]*types.Header)(s); len(uncles) > 0 {
		return json.Marshal(uncles)
	}
	return []byte("[]"), nil
}

// reportBlock retrieves the current chain head and reports it to the stats server.
// reportBlock 函数检索当前链头并报告给统计服务器。
// reportBlock 函数检索当前链头并将区块统计信息报告给服务器。
func (s *Service) reportBlock(conn *connWrapper, header *types.Header) error {
	// Gather the block details from the header or block chain
	details := s.assembleBlockStats(header)

	// Short circuit if the block detail is not available.
	if details == nil {
		return nil
	}
	// Assemble the block report and send it to the server
	log.Trace("Sending new block to ethstats", "number", details.Number, "hash", details.Hash)

	stats := map[string]interface{}{
		"id":    s.node,
		"block": details,
	}
	report := map[string][]interface{}{
		"emit": {"block", stats},
	}
	return conn.WriteJSON(report)
}

// assembleBlockStats retrieves any required metadata to report a single block
// and assembles the block stats. If block is nil, the current head is processed.
// assembleBlockStats 函数检索报告单个区块所需的任何元数据，并组装区块统计信息。如果 block 为 nil，则处理当前链头。
// assembleBlockStats 函数收集单个区块的元数据并组装统计信息，若未提供区块则使用当前链头。
func (s *Service) assembleBlockStats(header *types.Header) *blockStats {
	// Gather the block infos from the local blockchain
	var (
		td     *big.Int
		txs    []txStats
		uncles []*types.Header
	)

	// check if backend is a full node
	fullBackend, ok := s.backend.(fullNodeBackend)
	if ok {
		// Retrieve current chain head if no block is given.
		if header == nil {
			header = fullBackend.CurrentBlock()
		}
		block, _ := fullBackend.BlockByNumber(context.Background(), rpc.BlockNumber(header.Number.Uint64()))
		if block == nil {
			return nil
		}
		td = fullBackend.GetTd(context.Background(), header.Hash())

		txs = make([]txStats, len(block.Transactions()))
		for i, tx := range block.Transactions() {
			txs[i].Hash = tx.Hash()
		}
		uncles = block.Uncles()
	} else {
		// Light nodes would need on-demand lookups for transactions/uncles, skip
		if header == nil {
			header = s.backend.CurrentHeader()
		}
		td = s.backend.GetTd(context.Background(), header.Hash())
		txs = []txStats{}
	}
	// Assemble and return the block stats
	author, _ := s.engine.Author(header)

	return &blockStats{
		Number:     header.Number,
		Hash:       header.Hash(),
		ParentHash: header.ParentHash,
		Timestamp:  new(big.Int).SetUint64(header.Time),
		Miner:      author,
		GasUsed:    header.GasUsed,
		GasLimit:   header.GasLimit,
		Diff:       header.Difficulty.String(),
		TotalDiff:  td.String(),
		Txs:        txs,
		TxHash:     header.TxHash,
		Root:       header.Root,
		Uncles:     uncles,
	}
}

// reportHistory retrieves the most recent batch of blocks and reports it to the
// stats server.
// reportHistory 函数检索最近一批区块并报告给统计服务器。
// reportHistory 函数检索最近的区块批次并报告给统计服务器，默认范围由 historyUpdateRange 定义。
func (s *Service) reportHistory(conn *connWrapper, list []uint64) error {
	// Figure out the indexes that need reporting
	indexes := make([]uint64, 0, historyUpdateRange)
	if len(list) > 0 {
		// Specific indexes requested, send them back in particular
		indexes = append(indexes, list...)
	} else {
		// No indexes requested, send back the top ones
		head := s.backend.CurrentHeader().Number.Int64()
		start := head - historyUpdateRange + 1
		if start < 0 {
			start = 0
		}
		for i := uint64(start); i <= uint64(head); i++ {
			indexes = append(indexes, i)
		}
	}
	// Gather the batch of blocks to report
	history := make([]*blockStats, len(indexes))
	for i, number := range indexes {
		// Retrieve the next block if it's known to us
		header, _ := s.backend.HeaderByNumber(context.Background(), rpc.BlockNumber(number))
		if header != nil {
			history[len(history)-1-i] = s.assembleBlockStats(header)
			continue
		}
		// Ran out of blocks, cut the report short and send
		history = history[len(history)-i:]
		break
	}
	// Assemble the history report and send it to the server
	if len(history) > 0 {
		log.Trace("Sending historical blocks to ethstats", "first", history[0].Number, "last", history[len(history)-1].Number)
	} else {
		log.Trace("No history to send to stats server")
	}
	stats := map[string]interface{}{
		"id":      s.node,
		"history": history,
	}
	report := map[string][]interface{}{
		"emit": {"history", stats},
	}
	return conn.WriteJSON(report)
}

// pendStats is the information to report about pending transactions.
// pendStats 结构体包含关于待处理交易的报告信息。
// pendStats 结构体定义了待处理交易的统计信息，仅包括待处理交易数量。
type pendStats struct {
	Pending int `json:"pending"` // 待处理交易数量
}

// reportPending retrieves the current number of pending transactions and reports
// it to the stats server.
// reportPending 函数检索当前待处理交易的数量并报告给统计服务器。
// reportPending 函数获取当前交易池中的待处理交易数量并报告给统计服务器。
func (s *Service) reportPending(conn *connWrapper) error {
	// Retrieve the pending count from the local blockchain
	pending, _ := s.backend.Stats()
	// Assemble the transaction stats and send it to the server
	log.Trace("Sending pending transactions to ethstats", "count", pending)

	stats := map[string]interface{}{
		"id": s.node,
		"stats": &pendStats{
			Pending: pending,
		},
	}
	report := map[string][]interface{}{
		"emit": {"pending", stats},
	}
	return conn.WriteJSON(report)
}

// nodeStats is the information to report about the local node.
// nodeStats 结构体包含关于本地节点的报告信息。
// nodeStats 结构体定义了本地节点的统计信息，如活跃状态、同伴数量、Gas 价格等。
type nodeStats struct {
	Active   bool `json:"active"`   // 是否活跃
	Syncing  bool `json:"syncing"`  // 是否在同步
	Peers    int  `json:"peers"`    // 对等节点数量
	GasPrice int  `json:"gasPrice"` // Gas 价格
	Uptime   int  `json:"uptime"`   // 在线时间百分比
}

// reportStats retrieves various stats about the node at the networking layer
// and reports it to the stats server.
// reportStats 函数检索网络层中关于节点的各种统计信息，并报告给统计服务器。
// reportStats 函数收集网络层的节点统计信息（如同步状态、Gas 价格等）并报告给统计服务器。
func (s *Service) reportStats(conn *connWrapper) error {
	// Gather the syncing infos from the local miner instance
	var (
		syncing  bool
		gasprice int
	)
	// check if backend is a full node
	if fullBackend, ok := s.backend.(fullNodeBackend); ok {
		sync := fullBackend.SyncProgress()
		syncing = !sync.Done()

		price, _ := fullBackend.SuggestGasTipCap(context.Background())
		gasprice = int(price.Uint64())
		if basefee := fullBackend.CurrentHeader().BaseFee; basefee != nil {
			gasprice += int(basefee.Uint64())
		}
	} else {
		sync := s.backend.SyncProgress()
		syncing = !sync.Done()
	}
	// Assemble the node stats and send it to the server
	log.Trace("Sending node details to ethstats")

	stats := map[string]interface{}{
		"id": s.node,
		"stats": &nodeStats{
			Active:   true,
			Peers:    s.server.PeerCount(),
			GasPrice: gasprice,
			Syncing:  syncing,
			Uptime:   100,
		},
	}
	report := map[string][]interface{}{
		"emit": {"stats", stats},
	}
	return conn.WriteJSON(report)
}
