// Copyright 2014 The go-ethereum Authors
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

package p2p

import (
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// P2P 网络：以太坊的核心通信机制，支持区块同步和交易广播。
// EIP 标准：如 EIP-778（ENR）和 EIP-1459（Discovery v5），定义了节点记录和发现协议。
// RLPx 握手：使用 secp256k1 密钥对进行加密，确保通信安全。
// 协议握手：协商支持的子协议（如 eth），确保双方兼容。
// P2P 网络：以太坊的去中心化网络，节点通过 RLPx 协议通信，用于区块和交易的传播。
// 握手机制：包括加密握手（doEncHandshake）和协议握手（doProtoHandshake），确保安全性和协议兼容性。
//RLPx 协议：以太坊使用的 P2P 通信协议，基于加密（secp256k1）和多路复用，支持多种子协议（如 eth）。
//Discovery v4/v5：以太坊的节点发现协议，v4 基于 Kademlia DHT（分布式哈希表），v5 引入基于主题的发现机制（EIP-1459）。
//ENR（Ethereum Node Record）：遵循 EIP-778，用于存储节点的身份和网络信息（如 IP、端口、公钥等）。

var (
	// Error when the peer is shutting down
	// 节点正在关闭时的错误
	ErrShuttingDown = errors.New("shutting down")
)

const (
	// Base protocol version
	// 基础协议版本
	baseProtocolVersion = 5
	// Base protocol message count
	// 基础协议消息数量
	baseProtocolLength = uint64(16)
	// Maximum message size for base protocol
	// 基础协议的最大消息大小
	baseProtocolMaxMsgSize = 2 * 1024

	// Snappy protocol version
	// Snappy 协议版本
	snappyProtocolVersion = 5

	// Interval between ping messages
	// Ping 消息的发送间隔
	pingInterval = 15 * time.Second
)

const (
	// devp2p message codes
	// 握手消息代码
	handshakeMsg = 0x00
	// 断开连接消息代码
	discMsg = 0x01
	// Ping 消息代码
	pingMsg = 0x02
	// Pong 消息代码
	pongMsg = 0x03
)

// protoHandshake is the RLP structure of the protocol handshake.
// protoHandshake 是协议握手的 RLP 结构。
type protoHandshake struct {
	// Protocol version
	// 协议版本
	Version uint64
	// Node name
	// 节点名称
	Name string
	// Supported capabilities
	// 支持的功能
	Caps []Cap
	// Listening port
	// 监听端口
	ListenPort uint64
	// Node ID (secp256k1 public key)
	// 节点 ID（secp256k1 公钥）
	ID []byte

	// Ignore additional fields (for forward compatibility).
	// 忽略额外字段（为了向前兼容）。
	Rest []rlp.RawValue `rlp:"tail"`
}

// PeerEventType is the type of peer events emitted by a p2p.Server
// PeerEventType 是 p2p.Server 发出的对等事件类型
type PeerEventType string

const (
	// PeerEventTypeAdd is the type of event emitted when a peer is added to a p2p.Server
	// PeerEventTypeAdd 是在 p2p.Server 中添加对等方时发出的事件类型
	PeerEventTypeAdd PeerEventType = "add"

	// PeerEventTypeDrop is the type of event emitted when a peer is dropped from a p2p.Server
	// PeerEventTypeDrop 是在 p2p.Server 中删除对等方时发出的事件类型
	PeerEventTypeDrop PeerEventType = "drop"

	// PeerEventTypeMsgSend is the type of event emitted when a message is successfully sent to a peer
	// PeerEventTypeMsgSend 是在成功向对等方发送消息时发出的事件类型
	PeerEventTypeMsgSend PeerEventType = "msgsend"

	// PeerEventTypeMsgRecv is the type of event emitted when a message is received from a peer
	// PeerEventTypeMsgRecv 是在从对等方接收到消息时发出的事件类型
	PeerEventTypeMsgRecv PeerEventType = "msgrecv"
)

// PeerEvent is an event emitted when peers are either added or dropped from a p2p.Server
// or when a message is sent or received on a peer connection
// PeerEvent 是在对等方被添加或删除时，或者在对等方连接上发送或接收消息时发出的事件
type PeerEvent struct {
	// Event type
	// 事件类型
	Type PeerEventType `json:"type"`
	// Peer ID
	// 对等方 ID
	Peer enode.ID `json:"peer"`
	// Error message (if any)
	// 错误消息（如果有）
	Error string `json:"error,omitempty"`
	// Protocol name
	// 协议名称
	Protocol string `json:"protocol,omitempty"`
	// Message code
	// 消息代码
	MsgCode *uint64 `json:"msg_code,omitempty"`
	// Message size
	// 消息大小
	MsgSize *uint32 `json:"msg_size,omitempty"`
	// Local address
	// 本地地址
	LocalAddress string `json:"local,omitempty"`
	// Remote address
	// 远程地址
	RemoteAddress string `json:"remote,omitempty"`
}

// Peer represents a connected remote node.
// Peer 表示一个连接的远程节点。
type Peer struct {
	// Connection wrapper
	// 连接包装器
	rw *conn
	// Running protocols
	// 正在运行的协议
	running map[string]*protoRW
	// Logger
	// 日志记录器
	log log.Logger
	// Creation time
	// 创建时间
	created mclock.AbsTime

	// Wait group for goroutines
	// goroutine 等待组
	wg sync.WaitGroup
	// Channel for protocol errors
	// 协议错误通道
	protoErr chan error
	// Channel for shutdown
	// 关闭通道
	closed chan struct{}
	// Channel for ping reception
	// Ping 接收通道
	pingRecv chan struct{}
	// Channel for disconnect reasons
	// 断开连接原因通道
	disc chan DiscReason

	// events receives message send / receive events if set
	// events 如果设置，则接收消息发送/接收事件
	events *event.Feed
	// for testing
	// 用于测试
	testPipe *MsgPipeRW
}

// NewPeer returns a peer for testing purposes.
// NewPeer 返回一个用于测试的对等方。
func NewPeer(id enode.ID, name string, caps []Cap) *Peer {
	// Generate a fake set of local protocols to match as running caps. Almost
	// no fields needs to be meaningful here as we're only using it to cross-
	// check with the "remote" caps array.
	// 生成一组伪本地协议以匹配运行的功能。几乎不需要有意义的字段，因为我们只是用它来与“远程”功能数组进行交叉检查。
	protos := make([]Protocol, len(caps))
	for i, cap := range caps {
		protos[i].Name = cap.Name
		protos[i].Version = cap.Version
	}
	pipe, _ := net.Pipe()
	node := enode.SignNull(new(enr.Record), id)
	conn := &conn{fd: pipe, transport: nil, node: node, caps: caps, name: name}
	peer := newPeer(log.Root(), conn, protos)
	close(peer.closed) // ensures Disconnect doesn't block
	// 确保 Disconnect 不会阻塞
	return peer
}

// NewPeerPipe creates a peer for testing purposes.
// The message pipe given as the last parameter is closed when Disconnect is called on the peer.
// NewPeerPipe 创建一个用于测试的对等方。
// 当在对等方上调用 Disconnect 时，关闭作为最后一个参数的消息管道。
func NewPeerPipe(id enode.ID, name string, caps []Cap, pipe *MsgPipeRW) *Peer {
	p := NewPeer(id, name, caps)
	p.testPipe = pipe
	return p
}

// ID returns the node's public key.
// ID 返回节点的公钥。
func (p *Peer) ID() enode.ID {
	return p.rw.node.ID()
}

// Node returns the peer's node descriptor.
// Node 返回对等方的节点描述符。
func (p *Peer) Node() *enode.Node {
	return p.rw.node
}

// Name returns an abbreviated form of the name
// Name 返回名称的缩写形式
func (p *Peer) Name() string {
	s := p.rw.name
	if len(s) > 20 {
		return s[:20] + "..." // Truncate if too long / 如果太长则截断
	}
	return s
}

// Fullname returns the node name that the remote node advertised.
// Fullname 返回远程节点通告的节点名称。
func (p *Peer) Fullname() string {
	return p.rw.name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
// Caps 返回远程对等方支持的功能（子协议）。
func (p *Peer) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RunningCap returns true if the peer is actively connected using any of the
// enumerated versions of a specific protocol, meaning that at least one of the
// versions is supported by both this node and the peer p.
// RunningCap 如果对等方正在使用特定协议的任何枚举版本积极连接，则返回 true，
// 这意味着该版本中至少有一个版本同时被本节点和对等方 p 支持。
func (p *Peer) RunningCap(protocol string, versions []uint) bool {
	if proto, ok := p.running[protocol]; ok {
		for _, ver := range versions {
			if proto.Version == ver {
				return true
			}
		}
	}
	return false
}

// RemoteAddr returns the remote address of the network connection.
// RemoteAddr 返回网络连接的远程地址。
func (p *Peer) RemoteAddr() net.Addr {
	return p.rw.fd.RemoteAddr()
}

// LocalAddr returns the local address of the network connection.
// LocalAddr 返回网络连接的本地地址。
func (p *Peer) LocalAddr() net.Addr {
	return p.rw.fd.LocalAddr()
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
// Disconnect 使用给定的原因终止对等方连接。
// 它立即返回，并且不等待连接关闭。
func (p *Peer) Disconnect(reason DiscReason) {
	if p.testPipe != nil {
		p.testPipe.Close() // Close test pipe if set / 如果设置了测试管道则关闭
	}

	select {
	case p.disc <- reason: // Send disconnect reason / 发送断开连接原因
	case <-p.closed: // If already closed / 如果已经关闭
	}
}

// String implements fmt.Stringer.
// String 实现 fmt.Stringer。
func (p *Peer) String() string {
	id := p.ID()
	return fmt.Sprintf("Peer %x %v", id[:8], p.RemoteAddr()) // Format peer string / 格式化对等方字符串
}

// Inbound returns true if the peer is an inbound connection
// Inbound 如果对等方是入站连接，则返回 true
func (p *Peer) Inbound() bool {
	return p.rw.is(inboundConn) // Check if inbound / 检查是否为入站
}

func newPeer(log log.Logger, conn *conn, protocols []Protocol) *Peer {
	protomap := matchProtocols(protocols, conn.caps, conn)
	p := &Peer{
		rw:       conn,
		running:  protomap,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, len(protomap)+1), // protocols + pingLoop / 协议 + pingLoop
		closed:   make(chan struct{}),
		pingRecv: make(chan struct{}, 16),
		log:      log.New("id", conn.node.ID(), "conn", conn.flags),
	}
	return p
}

func (p *Peer) Log() log.Logger {
	return p.log // Return logger / 返回日志记录器
}

func (p *Peer) run() (remoteRequested bool, err error) {
	var (
		writeStart = make(chan struct{}, 1) // Channel to start write / 启动写入的通道
		writeErr   = make(chan error, 1)    // Channel for write errors / 写入错误的通道
		readErr    = make(chan error, 1)    // Channel for read errors / 读取错误的通道
		reason     DiscReason               // sent to the peer / 发送给对等方的原因
	)
	p.wg.Add(2)
	go p.readLoop(readErr) // Start read loop / 启动读取循环
	go p.pingLoop()        // Start ping loop / 启动 ping 循环

	// Start all protocol handlers.
	// 启动所有协议处理程序。
	writeStart <- struct{}{}               // Allow first write / 允许第一次写入
	p.startProtocols(writeStart, writeErr) // Start protocols / 启动协议

	// Wait for an error or disconnect.
	// 等待错误或断开连接。
loop:
	for {
		select {
		case err = <-writeErr: // Handle write error / 处理写入错误
			// A write finished. Allow the next write to start if there was no error.
			// 写入完成。如果没有错误，允许下一次写入开始。
			if err != nil {
				reason = DiscNetworkError
				break loop
			}
			writeStart <- struct{}{} // Allow next write / 允许下一次写入
		case err = <-readErr: // Handle read error / 处理读取错误
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				reason = r
			} else {
				reason = DiscNetworkError
			}
			break loop
		case err = <-p.protoErr: // Handle protocol error / 处理协议错误
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc: // Handle disconnect request / 处理断开连接请求
			reason = discReasonForError(err)
			break loop
		}
	}

	close(p.closed)    // Close peer / 关闭对等方
	p.rw.close(reason) // Close connection / 关闭连接
	p.wg.Wait()        // Wait for goroutines / 等待 goroutine
	return remoteRequested, err
}

func (p *Peer) pingLoop() {
	defer p.wg.Done()

	ping := time.NewTimer(pingInterval) // Create ping timer / 创建 ping 定时器
	defer ping.Stop()

	for {
		select {
		case <-ping.C: // On ping interval / 在 ping 间隔时
			if err := SendItems(p.rw, pingMsg); err != nil { // Send ping / 发送 ping
				p.protoErr <- err
				return
			}
			ping.Reset(pingInterval) // Reset timer / 重置定时器
		case <-p.pingRecv: // On ping received / 在收到 ping 时
			SendItems(p.rw, pongMsg) // Send pong / 发送 pong
		case <-p.closed: // On shutdown / 在关闭时
			return
		}
	}
}

func (p *Peer) readLoop(errc chan<- error) {
	defer p.wg.Done()
	for {
		msg, err := p.rw.ReadMsg() // Read message / 读取消息
		if err != nil {
			errc <- err // Send error / 发送错误
			return
		}
		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil { // Handle message / 处理消息
			errc <- err
			return
		}
	}
}

func (p *Peer) handle(msg Msg) error {
	switch {
	case msg.Code == pingMsg: // Handle ping / 处理 ping
		msg.Discard()
		select {
		case p.pingRecv <- struct{}{}: // Signal ping received / 信号 ping 已接收
		case <-p.closed:
		}
	case msg.Code == discMsg: // Handle disconnect / 处理断开连接
		// This is the last message. We don't need to discard or check errors because,
		// the connection will be closed after it.
		// 这是最后的消息。我们不需要丢弃或检查错误，因为连接将在之后关闭。
		return decodeDisconnectMessage(msg.Payload)
	case msg.Code < baseProtocolLength: // Ignore other base protocol messages / 忽略其他基础协议消息
		return msg.Discard()
	default: // Subprotocol message / 子协议消息
		// it's a subprotocol message
		proto, err := p.getProto(msg.Code) // Get protocol / 获取协议
		if err != nil {
			return fmt.Errorf("msg code out of range: %v", msg.Code) // Return error if out of range / 如果超出范围则返回错误
		}
		if metrics.Enabled() { // If metrics enabled / 如果启用了指标
			m := fmt.Sprintf("%s/%s/%d/%#02x", ingressMeterName, proto.Name, proto.Version, msg.Code-proto.offset)
			metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize))
			metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)
		}
		select {
		case proto.in <- msg: // Send to protocol / 发送到协议
			return nil
		case <-p.closed: // If closed / 如果关闭
			return io.EOF
		}
	}
	return nil
}

// decodeDisconnectMessage decodes the payload of discMsg.
// decodeDisconnectMessage 解码 discMsg 的有效载荷。
func decodeDisconnectMessage(r io.Reader) (reason DiscReason) {
	s := rlp.NewStream(r, 100)
	k, _, err := s.Kind()
	if err != nil {
		return DiscInvalid
	}
	if k == rlp.List {
		s.List()
		err = s.Decode(&reason)
	} else {
		// Legacy path: some implementations, including geth, used to send the disconnect
		// reason as a byte array by accident.
		// 遗留路径：一些实现，包括 geth，曾经意外地将断开连接原因作为字节数组发送。
		err = s.Decode(&reason)
	}
	if err != nil {
		reason = DiscInvalid
	}
	return reason
}

func countMatchingProtocols(protocols []Protocol, caps []Cap) int {
	n := 0
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				n++
			}
		}
	}
	return n
}

// matchProtocols creates structures for matching named subprotocols.
// matchProtocols 创建用于匹配命名子协议的结构。
func matchProtocols(protocols []Protocol, caps []Cap, rw MsgReadWriter) map[string]*protoRW {
	slices.SortFunc(caps, Cap.Cmp) // Sort capabilities / 排序功能
	offset := baseProtocolLength
	result := make(map[string]*protoRW)

outer:
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				// If an old protocol version matched, revert it
				// 如果旧协议版本匹配，则恢复它
				if old := result[cap.Name]; old != nil {
					offset -= old.Length
				}
				// Assign the new match
				// 分配新的匹配
				result[cap.Name] = &protoRW{Protocol: proto, offset: offset, in: make(chan Msg), w: rw}
				offset += proto.Length
				continue outer
			}
		}
	}
	return result
}

func (p *Peer) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {
	p.wg.Add(len(p.running))
	for _, proto := range p.running {
		proto.closed = p.closed
		proto.wstart = writeStart
		proto.werr = writeErr
		var rw MsgReadWriter = proto
		if p.events != nil {
			rw = newMsgEventer(rw, p.events, p.ID(), proto.Name, p.Info().Network.RemoteAddress, p.Info().Network.LocalAddress)
		}
		p.log.Trace(fmt.Sprintf("Starting protocol %s/%d", proto.Name, proto.Version))
		go func() {
			defer p.wg.Done()
			err := proto.Run(p, rw)
			if err == nil {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d returned", proto.Name, proto.Version))
				err = errProtocolReturned
			} else if !errors.Is(err, io.EOF) {
				p.log.Trace(fmt.Sprintf("Protocol %s/%d failed", proto.Name, proto.Version), "err", err)
			}
			p.protoErr <- err
		}()
	}
}

// getProto finds the protocol responsible for handling the given message code.
// getProto 查找负责处理给定消息代码的协议。
func (p *Peer) getProto(code uint64) (*protoRW, error) {
	for _, proto := range p.running {
		if code >= proto.offset && code < proto.offset+proto.Length {
			return proto, nil
		}
	}
	return nil, newPeerError(errInvalidMsgCode, "%d", code)
}

type protoRW struct {
	Protocol
	// receives read messages
	// 接收读取的消息
	in chan Msg
	// receives when peer is shutting down
	// 在对等方关闭时接收
	closed <-chan struct{}
	// receives when write may start
	// 在写入可以开始时接收
	wstart <-chan struct{}
	// for write results
	// 用于写入结果
	werr   chan<- error
	offset uint64
	w      MsgWriter
}

func (rw *protoRW) WriteMsg(msg Msg) (err error) {
	if msg.Code >= rw.Length {
		return newPeerError(errInvalidMsgCode, "not handled")
	}
	msg.meterCap = rw.cap()
	msg.meterCode = msg.Code

	msg.Code += rw.offset

	select {
	case <-rw.wstart: // Wait for write start / 等待写入开始
		err = rw.w.WriteMsg(msg) // Write message / 写入消息
		// Report write status back to Peer.run. It will initiate shutdown if the error
		// is non-nil and unblock the next write otherwise. The calling protocol code
		// should exit for errors as well but we don't want to rely on that.
		// 将写入状态报告回 Peer.run。如果错误非 nil，它将启动关闭，否则解除对下一次写入的阻塞。
		// 调用的协议代码也应为错误退出，但我们不想依赖于此。
		rw.werr <- err
	case <-rw.closed: // If closed / 如果关闭
		err = ErrShuttingDown
	}
	return err
}

func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg := <-rw.in: // Read from channel / 从通道读取
		msg.Code -= rw.offset // Adjust code / 调整代码
		return msg, nil
	case <-rw.closed: // If closed / 如果关闭
		return Msg{}, io.EOF
	}
}

// PeerInfo represents a short summary of the information known about a connected peer.
// Sub-protocol independent fields are contained and initialized here, with protocol
// specifics delegated to all connected sub-protocols.
// PeerInfo 表示关于已连接对等方的已知信息的简短摘要。
// 与子协议无关的字段包含并在此处初始化，协议细节委托给所有连接的子协议。
type PeerInfo struct {
	// Ethereum Node Record
	// 以太坊节点记录
	ENR string `json:"enr,omitempty"`
	// Node URL
	// 节点 URL
	Enode string `json:"enode"`
	// Unique node identifier
	// 唯一节点标识符
	ID string `json:"id"`
	// Name of the node, including client type, version, OS, custom data
	// 节点名称，包括客户端类型、版本、OS、自定义数据
	Name string `json:"name"`
	// Protocols advertised by this peer
	// 此对等方通告的协议
	Caps    []string `json:"caps"`
	Network struct {
		// Local endpoint of the TCP data connection
		// TCP 数据连接的本地端点
		LocalAddress string `json:"localAddress"`
		// Remote endpoint of the TCP data connection
		// TCP 数据连接的远程端点
		RemoteAddress string `json:"remoteAddress"`
		Inbound       bool   `json:"inbound"`
		Trusted       bool   `json:"trusted"`
		Static        bool   `json:"static"`
	} `json:"network"`
	// Sub-protocol specific metadata fields
	// 子协议特定的元数据字段
	Protocols map[string]interface{} `json:"protocols"`
}

// Info gathers and returns a collection of metadata known about a peer.
// Info 收集并返回关于对等方的已知元数据集合。
func (p *Peer) Info() *PeerInfo {
	// Gather the protocol capabilities
	// 收集协议功能
	var caps []string
	for _, cap := range p.Caps() {
		caps = append(caps, cap.String()) // Add capability strings / 添加功能字符串
	}
	// Assemble the generic peer metadata
	// 组装通用对等方元数据
	info := &PeerInfo{
		Enode:     p.Node().URLv4(),                             // Get node URL / 获取节点 URL
		ID:        p.ID().String(),                              // Get ID string / 获取 ID 字符串
		Name:      p.Fullname(),                                 // Get full name / 获取全名
		Caps:      caps,                                         // Set capabilities / 设置功能
		Protocols: make(map[string]interface{}, len(p.running)), // Initialize protocols / 初始化协议
	}
	if p.Node().Seq() > 0 {
		info.ENR = p.Node().String() // Set ENR if available / 如果可用则设置 ENR
	}
	info.Network.LocalAddress = p.LocalAddr().String()   // Set local address / 设置本地地址
	info.Network.RemoteAddress = p.RemoteAddr().String() // Set remote address / 设置远程地址
	info.Network.Inbound = p.rw.is(inboundConn)          // Set inbound flag / 设置入站标志
	info.Network.Trusted = p.rw.is(trustedConn)          // Set trusted flag / 设置受信任标志
	info.Network.Static = p.rw.is(staticDialedConn)      // Set static flag / 设置静态标志

	// Gather all the running protocol infos
	// 收集所有正在运行的协议信息
	for _, proto := range p.running {
		protoInfo := interface{}("unknown") // Default to "unknown" / 默认为“未知”
		if query := proto.Protocol.PeerInfo; query != nil {
			if metadata := query(p.ID()); metadata != nil {
				protoInfo = metadata // Set protocol metadata / 设置协议元数据
			} else {
				protoInfo = "handshake" // Set to "handshake" if no metadata / 如果没有元数据则设置为“握手”
			}
		}
		info.Protocols[proto.Name] = protoInfo // Add to protocols / 添加到协议
	}
	return info
}
