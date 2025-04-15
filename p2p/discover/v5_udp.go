// Copyright 2020 The go-ethereum Authors
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

package discover

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// Discovery v5 是以太坊 P2P 网络的节点发现协议，基于 Kademlia 算法，用于在去中心化网络中高效发现和连接节点（EIP-868）。
// enode.LocalNode 表示本地节点，包含节点的 ENR（Ethereum Node Record），ENR 是 EIP-778 定义的节点信息记录格式，用于存储节点的身份、IP 地址、端口等信息。

const (
	// 查找过程中对单个节点的最大请求数
	lookupRequestLimit = 3 // max requests against a single node during lookup
	// 应用于 FINDNODE 处理程序
	findnodeResultLimit = 16 // applies in FINDNODE handler
	// 应用于 waitForNodes
	totalNodesResponseLimit = 5 // applies in waitForNodes

	respTimeoutV5 = 700 * time.Millisecond // 响应超时时间
)

// codecV5 is implemented by v5wire.Codec (and testCodec).
//
// The UDPv5 transport is split into two objects: the codec object deals with
// encoding/decoding and with the handshake; the UDPv5 object handles higher-level concerns.
//
// codecV5 由 v5wire.Codec（和 testCodec）实现。
// UDPv5 传输被分为两个对象：codec 对象处理编码/解码和握手；UDPv5 对象处理更高级别的关注点。
type codecV5 interface {
	// Encode encodes a packet.
	// Encode 对数据包进行编码。
	Encode(enode.ID, string, v5wire.Packet, *v5wire.Whoareyou) ([]byte, v5wire.Nonce, error)

	// Decode decodes a packet. It returns a *v5wire.Unknown packet if decryption fails.
	// The *enode.Node return value is non-nil when the input contains a handshake response.
	// Decode 解码数据包。如果解密失败，返回 *v5wire.Unknown 数据包。
	// 当输入包含握手响应时，*enode.Node 返回值不为 nil。
	Decode([]byte, string) (enode.ID, *enode.Node, v5wire.Packet, error)
}

// UDPv5 is the implementation of protocol version 5.
// UDPv5 是协议版本 5 的实现。
type UDPv5 struct {
	// static fields
	// 静态字段
	conn         UDPConn
	tab          *Table
	netrestrict  *netutil.Netlist
	priv         *ecdsa.PrivateKey
	localNode    *enode.LocalNode
	db           *enode.DB
	log          log.Logger
	clock        mclock.Clock
	validSchemes enr.IdentityScheme

	// misc buffers used during message handling
	// 消息处理期间使用的杂项缓冲区
	logcontext []interface{}

	// talkreq handler registry
	// talkreq 处理程序注册表
	talk *talkSystem

	// channels into dispatch
	// 进入 dispatch 的通道
	packetInCh    chan ReadPacket
	readNextCh    chan struct{}
	callCh        chan *callV5
	callDoneCh    chan *callV5
	respTimeoutCh chan *callTimeout
	sendCh        chan sendRequest
	unhandled     chan<- ReadPacket

	// state of dispatch
	// dispatch 的状态
	codec            codecV5
	activeCallByNode map[enode.ID]*callV5
	activeCallByAuth map[v5wire.Nonce]*callV5
	callQueue        map[enode.ID][]*callV5

	// shutdown stuff
	// 关闭相关
	closeOnce      sync.Once
	closeCtx       context.Context
	cancelCloseCtx context.CancelFunc
	wg             sync.WaitGroup
}

type sendRequest struct {
	destID   enode.ID
	destAddr netip.AddrPort
	msg      v5wire.Packet
}

// callV5 represents a remote procedure call against another node.
// callV5 表示对另一个节点的远程过程调用。
type callV5 struct {
	id   enode.ID
	addr netip.AddrPort
	// 这是执行握手所必需的。
	node *enode.Node // This is required to perform handshakes.

	packet v5wire.Packet
	// 预期的响应数据包类型
	responseType byte // expected packet type of response
	reqid        []byte
	// 响应发送到这里
	ch chan v5wire.Packet // responses sent here
	// 错误发送到这里
	err chan error // errors sent here

	// Valid for active calls only:
	// 仅对活动调用有效：
	// 请求数据包的 nonce
	nonce v5wire.Nonce // nonce of request packet
	// 为此调用尝试握手的次数
	handshakeCount int // # times we attempted handshake for this call
	// 最后发送的握手挑战
	challenge *v5wire.Whoareyou // last sent handshake challenge
	timeout   mclock.Timer
}

// callTimeout is the response timeout event of a call.
// callTimeout 是调用的响应超时事件。
type callTimeout struct {
	c     *callV5
	timer mclock.Timer
}

// ListenV5 listens on the given connection.
// ListenV5 在给定的连接上监听。
func ListenV5(conn UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv5, error) {
	t, err := newUDPv5(conn, ln, cfg)
	if err != nil {
		return nil, err
	}
	go t.tab.loop()
	t.wg.Add(2)
	go t.readLoop()
	go t.dispatch()
	return t, nil
}

// newUDPv5 creates a UDPv5 transport, but doesn't start any goroutines.
// newUDPv5 创建一个 UDPv5 传输，但不启动任何 goroutine。
func newUDPv5(conn UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv5, error) {
	closeCtx, cancelCloseCtx := context.WithCancel(context.Background())
	cfg = cfg.withDefaults()
	t := &UDPv5{
		// static fields
		conn:         newMeteredConn(conn),
		localNode:    ln,
		db:           ln.Database(),
		netrestrict:  cfg.NetRestrict,
		priv:         cfg.PrivateKey,
		log:          cfg.Log,
		validSchemes: cfg.ValidSchemes,
		clock:        cfg.Clock,
		// channels into dispatch
		packetInCh:    make(chan ReadPacket, 1),
		readNextCh:    make(chan struct{}, 1),
		callCh:        make(chan *callV5),
		callDoneCh:    make(chan *callV5),
		sendCh:        make(chan sendRequest),
		respTimeoutCh: make(chan *callTimeout),
		unhandled:     cfg.Unhandled,
		// state of dispatch
		codec:            v5wire.NewCodec(ln, cfg.PrivateKey, cfg.Clock, cfg.V5ProtocolID),
		activeCallByNode: make(map[enode.ID]*callV5),
		activeCallByAuth: make(map[v5wire.Nonce]*callV5),
		callQueue:        make(map[enode.ID][]*callV5),
		// shutdown
		closeCtx:       closeCtx,
		cancelCloseCtx: cancelCloseCtx,
	}
	t.talk = newTalkSystem(t)
	tab, err := newTable(t, t.db, cfg)
	if err != nil {
		return nil, err
	}
	t.tab = tab
	return t, nil
}

// Self returns the local node record.
// Self 返回本地节点记录。
func (t *UDPv5) Self() *enode.Node {
	return t.localNode.Node()
}

// Close shuts down packet processing.
// Close 关闭数据包处理。
func (t *UDPv5) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.talk.wait()
		t.wg.Wait()
		t.tab.close()
	})
}

// Ping sends a ping message to the given node.
// Ping 向给定节点发送 ping 消息。
func (t *UDPv5) Ping(n *enode.Node) error {
	_, err := t.ping(n)
	return err
}

// Resolve searches for a specific node with the given ID and tries to get the most recent
// version of the node record for it. It returns n if the node could not be resolved.
// Resolve 搜索具有给定 ID 的特定节点，并尝试获取其最新版本的节点记录。如果无法解析节点，则返回 n。
func (t *UDPv5) Resolve(n *enode.Node) *enode.Node {
	if intable := t.tab.getNode(n.ID()); intable != nil && intable.Seq() > n.Seq() {
		n = intable
	}
	// Try asking directly. This works if the node is still responding on the endpoint we have.
	// 尝试直接询问。如果节点仍在我们拥有的端点上响应，这将起作用。
	if resp, err := t.RequestENR(n); err == nil {
		return resp
	}
	// Otherwise do a network lookup.
	// 否则执行网络查找。
	result := t.Lookup(n.ID())
	for _, rn := range result {
		if rn.ID() == n.ID() && rn.Seq() > n.Seq() {
			return rn
		}
	}
	return n
}

// AllNodes returns all the nodes stored in the local table.
// AllNodes 返回存储在本地表中的所有节点。
func (t *UDPv5) AllNodes() []*enode.Node {
	t.tab.mutex.Lock()
	defer t.tab.mutex.Unlock()
	nodes := make([]*enode.Node, 0)

	for _, b := range &t.tab.buckets {
		for _, n := range b.entries {
			nodes = append(nodes, n.Node)
		}
	}
	return nodes
}

// LocalNode returns the current local node running the protocol.
// LocalNode 返回当前运行协议的本地节点。
func (t *UDPv5) LocalNode() *enode.LocalNode {
	return t.localNode
}

// RegisterTalkHandler adds a handler for 'talk requests'. The handler function is called
// whenever a request for the given protocol is received and should return the response
// data or nil.
//
// RegisterTalkHandler 为“talk 请求”添加处理程序。
// 每当收到给定协议的请求时，都会调用处理程序函数，并应返回响应数据或 nil。
func (t *UDPv5) RegisterTalkHandler(protocol string, handler TalkRequestHandler) {
	t.talk.register(protocol, handler)
}

// TalkRequest sends a talk request to a node and waits for a response.
// TalkRequest 向节点发送 talk 请求并等待响应。
func (t *UDPv5) TalkRequest(n *enode.Node, protocol string, request []byte) ([]byte, error) {
	req := &v5wire.TalkRequest{Protocol: protocol, Message: request}
	resp := t.callToNode(n, v5wire.TalkResponseMsg, req)
	defer t.callDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*v5wire.TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// TalkRequestToID sends a talk request to a node and waits for a response.
// TalkRequestToID 向节点发送 talk 请求并等待响应。
func (t *UDPv5) TalkRequestToID(id enode.ID, addr netip.AddrPort, protocol string, request []byte) ([]byte, error) {
	req := &v5wire.TalkRequest{Protocol: protocol, Message: request}
	resp := t.callToID(id, addr, v5wire.TalkResponseMsg, req)
	defer t.callDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*v5wire.TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// RandomNodes returns an iterator that finds random nodes in the DHT.
// RandomNodes 返回一个在 DHT 中查找随机节点的迭代器。
func (t *UDPv5) RandomNodes() enode.Iterator {
	if t.tab.len() == 0 {
		// All nodes were dropped, refresh. The very first query will hit this
		// case and run the bootstrapping logic.
		// 所有节点都被丢弃，刷新。第一个查询将命中此情况并运行引导逻辑。
		<-t.tab.refresh()
	}

	return newLookupIterator(t.closeCtx, t.newRandomLookup)
}

// Lookup performs a recursive lookup for the given target.
// It returns the closest nodes to target.
//
// Lookup 对给定目标执行递归查找。
// 它返回最接近目标的节点。
func (t *UDPv5) Lookup(target enode.ID) []*enode.Node {
	return t.newLookup(t.closeCtx, target).run()
}

// lookupRandom looks up a random target.
// This is needed to satisfy the transport interface.
//
// lookupRandom 查找随机目标。
// 这是满足传输接口所必需的。
func (t *UDPv5) lookupRandom() []*enode.Node {
	return t.newRandomLookup(t.closeCtx).run()
}

// lookupSelf looks up our own node ID.
// This is needed to satisfy the transport interface.
//
// lookupSelf 查找我们自己的节点 ID。
// 这是满足传输接口所必需的。
func (t *UDPv5) lookupSelf() []*enode.Node {
	return t.newLookup(t.closeCtx, t.Self().ID()).run()
}

func (t *UDPv5) newRandomLookup(ctx context.Context) *lookup {
	var target enode.ID
	crand.Read(target[:])
	return t.newLookup(ctx, target)
}

func (t *UDPv5) newLookup(ctx context.Context, target enode.ID) *lookup {
	return newLookup(ctx, t.tab, target, func(n *enode.Node) ([]*enode.Node, error) {
		return t.lookupWorker(n, target)
	})
}

// lookupWorker performs FINDNODE calls against a single node during lookup.
//
// lookupWorker 在查找期间对单个节点执行 FINDNODE 调用。
func (t *UDPv5) lookupWorker(destNode *enode.Node, target enode.ID) ([]*enode.Node, error) {
	var (
		dists = lookupDistances(target, destNode.ID())
		nodes = nodesByDistance{target: target}
		err   error
	)
	var r []*enode.Node
	r, err = t.findnode(destNode, dists)
	if errors.Is(err, errClosed) {
		return nil, err
	}
	for _, n := range r {
		if n.ID() != t.Self().ID() {
			nodes.push(n, findnodeResultLimit)
		}
	}
	return nodes.entries, err
}

// lookupDistances computes the distance parameter for FINDNODE calls to dest.
// It chooses distances adjacent to logdist(target, dest), e.g. for a target
// with logdist(target, dest) = 255 the result is [255, 256, 254].
//
// lookupDistances 计算对 dest 的 FINDNODE 调用的距离参数。
// 它选择与 logdist(target, dest) 相邻的距离，
// 例如，对于 logdist(target, dest) = 255 的目标，结果为 [255, 256, 254]。
func lookupDistances(target, dest enode.ID) (dists []uint) {
	td := enode.LogDist(target, dest)
	dists = append(dists, uint(td))
	for i := 1; len(dists) < lookupRequestLimit; i++ {
		if td+i <= 256 {
			dists = append(dists, uint(td+i))
		}
		if td-i > 0 {
			dists = append(dists, uint(td-i))
		}
	}
	return dists
}

// ping calls PING on a node and waits for a PONG response.
// ping 在节点上调用 PING 并等待 PONG 响应。
func (t *UDPv5) ping(n *enode.Node) (uint64, error) {
	req := &v5wire.Ping{ENRSeq: t.localNode.Node().Seq()}
	resp := t.callToNode(n, v5wire.PongMsg, req)
	defer t.callDone(resp)

	select {
	case pong := <-resp.ch:
		return pong.(*v5wire.Pong).ENRSeq, nil
	case err := <-resp.err:
		return 0, err
	}
}

// RequestENR requests n's record.
// RequestENR 请求 n 的记录。
func (t *UDPv5) RequestENR(n *enode.Node) (*enode.Node, error) {
	nodes, err := t.findnode(n, []uint{0})
	if err != nil {
		return nil, err
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("%d nodes in response for distance zero", len(nodes))
	}
	return nodes[0], nil
}

// findnode calls FINDNODE on a node and waits for responses.
// findnode 在节点上调用 FINDNODE 并等待响应。
func (t *UDPv5) findnode(n *enode.Node, distances []uint) ([]*enode.Node, error) {
	resp := t.callToNode(n, v5wire.NodesMsg, &v5wire.Findnode{Distances: distances})
	return t.waitForNodes(resp, distances)
}

// waitForNodes waits for NODES responses to the given call.
// waitForNodes 等待对给定调用的 NODES 响应。
func (t *UDPv5) waitForNodes(c *callV5, distances []uint) ([]*enode.Node, error) {
	defer t.callDone(c)

	var (
		nodes           []*enode.Node
		seen            = make(map[enode.ID]struct{})
		received, total = 0, -1
	)
	for {
		select {
		case responseP := <-c.ch:
			response := responseP.(*v5wire.Nodes)
			for _, record := range response.Nodes {
				node, err := t.verifyResponseNode(c, record, distances, seen)
				if err != nil {
					t.log.Debug("Invalid record in "+response.Name(), "id", c.node.ID(), "err", err)
					continue
				}
				nodes = append(nodes, node)
			}
			if total == -1 {
				total = min(int(response.RespCount), totalNodesResponseLimit)
			}
			if received++; received == total {
				return nodes, nil
			}
		case err := <-c.err:
			return nodes, err
		}
	}
}

// verifyResponseNode checks validity of a record in a NODES response.
// verifyResponseNode 检查 NODES 响应中记录的有效性。
func (t *UDPv5) verifyResponseNode(c *callV5, r *enr.Record, distances []uint, seen map[enode.ID]struct{}) (*enode.Node, error) {
	node, err := enode.New(t.validSchemes, r)
	if err != nil {
		return nil, err
	}
	if err := netutil.CheckRelayAddr(c.addr.Addr(), node.IPAddr()); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.ContainsAddr(node.IPAddr()) {
		return nil, errors.New("not contained in netrestrict list")
	}
	if node.UDP() <= 1024 {
		return nil, errLowPort
	}
	if distances != nil {
		nd := enode.LogDist(c.id, node.ID())
		if !slices.Contains(distances, uint(nd)) {
			return nil, errors.New("does not match any requested distance")
		}
	}
	if _, ok := seen[node.ID()]; ok {
		return nil, errors.New("duplicate record")
	}
	seen[node.ID()] = struct{}{}
	return node, nil
}

// callToNode sends the given call and sets up a handler for response packets (of message
// type responseType). Responses are dispatched to the call's response channel.
//
// callToNode 发送给定调用并为响应数据包（消息类型 responseType）设置处理程序。
// 响应被分派到调用的响应通道。
func (t *UDPv5) callToNode(n *enode.Node, responseType byte, req v5wire.Packet) *callV5 {
	addr, _ := n.UDPEndpoint()
	c := &callV5{id: n.ID(), addr: addr, node: n}
	t.initCall(c, responseType, req)
	return c
}

// callToID is like callToNode, but for cases where the node record is not available.
// callToID 类似于 callToNode，但用于节点记录不可用的情况。
func (t *UDPv5) callToID(id enode.ID, addr netip.AddrPort, responseType byte, req v5wire.Packet) *callV5 {
	c := &callV5{id: id, addr: addr}
	t.initCall(c, responseType, req)
	return c
}

func (t *UDPv5) initCall(c *callV5, responseType byte, packet v5wire.Packet) {
	c.packet = packet
	c.responseType = responseType
	c.reqid = make([]byte, 8)
	c.ch = make(chan v5wire.Packet, 1)
	c.err = make(chan error, 1)
	// Assign request ID.
	// 分配请求 ID。
	crand.Read(c.reqid)
	packet.SetRequestID(c.reqid)
	// Send call to dispatch.
	// 将调用发送到 dispatch。
	select {
	case t.callCh <- c:
	case <-t.closeCtx.Done():
		c.err <- errClosed
	}
}

// callDone tells dispatch that the active call is done.
// callDone 告诉 dispatch 活动调用已完成。
func (t *UDPv5) callDone(c *callV5) {
	// This needs a loop because further responses may be incoming until the
	// send to callDoneCh has completed. Such responses need to be discarded
	// in order to avoid blocking the dispatch loop.
	// 这里需要一个循环，因为在 callDoneCh 发送完成之前，可能会有更多的响应到达。这些响应需要被丢弃，以避免阻塞 dispatch 循环。
	for {
		select {
		case <-c.ch:
			// late response, discard.
			// 迟到的响应，丢弃。
		case <-c.err:
			// late error, discard.
			// 迟到的错误，丢弃。
		case t.callDoneCh <- c:
			return
		case <-t.closeCtx.Done():
			return
		}
	}
}

// Discovery v5 使用请求-响应模型，dispatch 函数协调请求的发送和响应的处理。
// I WHOAREYOU` 握手机制用于验证节点身份，防止未授权访问，是 Discovery v5 的安全特性之一（EIP-868）。

// dispatch runs in its own goroutine, handles incoming packets and deals with calls.
//
// For any destination node there is at most one 'active call', stored in the t.activeCall*
// maps. A call is made active when it is sent. The active call can be answered by a
// matching response, in which case c.ch receives the response; or by timing out, in which case
// c.err receives the error. When the function that created the call signals the active
// call is done through callDone, the next call from the call queue is started.
//
// Calls may also be answered by a WHOAREYOU packet referencing the call packet's authTag.
// When that happens the call is simply re-sent to complete the handshake. We allow one
// handshake attempt per call.
//
// dispatch 在自己的 goroutine 中运行，处理传入的数据包和调用。
//
// 对于任何目标节点，最多只有一个“活动调用”，存储在 t.activeCall*map 中。
// 调用在发送时变为活动状态。活动调用可以通过匹配的响应来回答，此时 c.ch 接收响应；
// 或者通过超时，此时 c.err 接收错误。当创建调用的函数通过 callDone 信号表示活动调用完成时，从调用队列中启动下一个调用。
//
// 调用也可能被引用调用数据包 authTag 的 WHOAREYOU 数据包回答。
// 当这种情况发生时，调用会被重新发送以完成握手。我们允许每个调用进行一次握手尝试。
func (t *UDPv5) dispatch() {
	defer t.wg.Done()

	// Arm first read.
	// 准备第一次读取。
	t.readNextCh <- struct{}{}

	for {
		select {
		case c := <-t.callCh:
			t.callQueue[c.id] = append(t.callQueue[c.id], c)
			t.sendNextCall(c.id)

		case ct := <-t.respTimeoutCh:
			active := t.activeCallByNode[ct.c.id]
			if ct.c == active && ct.timer == active.timeout {
				ct.c.err <- errTimeout
			}

		case c := <-t.callDoneCh:
			active := t.activeCallByNode[c.id]
			if active != c {
				panic("BUG: callDone for inactive call")
			}
			c.timeout.Stop()
			delete(t.activeCallByAuth, c.nonce)
			delete(t.activeCallByNode, c.id)
			t.sendNextCall(c.id)

		case r := <-t.sendCh:
			t.send(r.destID, r.destAddr, r.msg, nil)

		case p := <-t.packetInCh:
			t.handlePacket(p.Data, p.Addr)
			// Arm next read.
			// 准备下一次读取。
			t.readNextCh <- struct{}{}

		case <-t.closeCtx.Done():
			close(t.readNextCh)
			for id, queue := range t.callQueue {
				for _, c := range queue {
					c.err <- errClosed
				}
				delete(t.callQueue, id)
			}
			for id, c := range t.activeCallByNode {
				c.err <- errClosed
				delete(t.activeCallByNode, id)
				delete(t.activeCallByAuth, c.nonce)
			}
			return
		}
	}
}

// startResponseTimeout sets the response timer for a call.
// startResponseTimeout 为调用设置响应定时器。
func (t *UDPv5) startResponseTimeout(c *callV5) {
	if c.timeout != nil {
		c.timeout.Stop()
	}
	var (
		timer mclock.Timer
		done  = make(chan struct{})
	)
	timer = t.clock.AfterFunc(respTimeoutV5, func() {
		<-done
		select {
		case t.respTimeoutCh <- &callTimeout{c, timer}:
		case <-t.closeCtx.Done():
		}
	})
	c.timeout = timer
	close(done)
}

// sendNextCall sends the next call in the call queue if there is no active call.
// sendNextCall 如果没有活动调用，则发送调用队列中的下一个调用。
func (t *UDPv5) sendNextCall(id enode.ID) {
	queue := t.callQueue[id]
	if len(queue) == 0 || t.activeCallByNode[id] != nil {
		return
	}
	t.activeCallByNode[id] = queue[0]
	t.sendCall(t.activeCallByNode[id])
	if len(queue) == 1 {
		delete(t.callQueue, id)
	} else {
		copy(queue, queue[1:])
		t.callQueue[id] = queue[:len(queue)-1]
	}
}

// sendCall encodes and sends a request packet to the call's recipient node.
// This performs a handshake if needed.
//
// sendCall 对请求数据包进行编码并发送到调用的接收者节点。
// 如果需要，执行握手。
func (t *UDPv5) sendCall(c *callV5) {
	// The call might have a nonce from a previous handshake attempt. Remove the entry for
	// the old nonce because we're about to generate a new nonce for this call.
	// 调用可能有来自先前握手尝试的 nonce。删除旧 nonce 的条目，因为我们将为此次调用生成一个新的 nonce。
	if c.nonce != (v5wire.Nonce{}) {
		delete(t.activeCallByAuth, c.nonce)
	}

	newNonce, _ := t.send(c.id, c.addr, c.packet, c.challenge)
	c.nonce = newNonce
	t.activeCallByAuth[newNonce] = c
	t.startResponseTimeout(c)
}

// sendResponse sends a response packet to the given node.
// This doesn't trigger a handshake even if no keys are available.
//
// sendResponse 向给定节点发送响应数据包。
// 即使没有可用的密钥，也不会触发握手。
func (t *UDPv5) sendResponse(toID enode.ID, toAddr netip.AddrPort, packet v5wire.Packet) error {
	_, err := t.send(toID, toAddr, packet, nil)
	return err
}

func (t *UDPv5) sendFromAnotherThread(toID enode.ID, toAddr netip.AddrPort, packet v5wire.Packet) {
	select {
	case t.sendCh <- sendRequest{toID, toAddr, packet}:
	case <-t.closeCtx.Done():
	}
}

// send sends a packet to the given node.
// send 向给定节点发送数据包。
func (t *UDPv5) send(toID enode.ID, toAddr netip.AddrPort, packet v5wire.Packet, c *v5wire.Whoareyou) (v5wire.Nonce, error) {
	addr := toAddr.String()
	t.logcontext = append(t.logcontext[:0], "id", toID, "addr", addr)
	t.logcontext = packet.AppendLogInfo(t.logcontext)

	enc, nonce, err := t.codec.Encode(toID, addr, packet, c)
	if err != nil {
		t.logcontext = append(t.logcontext, "err", err)
		t.log.Warn(">> "+packet.Name(), t.logcontext...)
		return nonce, err
	}

	_, err = t.conn.WriteToUDPAddrPort(enc, toAddr)
	t.log.Trace(">> "+packet.Name(), t.logcontext...)
	return nonce, err
}

// readLoop runs in its own goroutine and reads packets from the network.
// readLoop 在自己的 goroutine 中运行并从网络读取数据包。
func (t *UDPv5) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, maxPacketSize)
	for range t.readNextCh {
		nbytes, from, err := t.conn.ReadFromUDPAddrPort(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			// 忽略临时读取错误。
			t.log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permanent errors.
			// 对于永久性错误，关闭循环。
			if !errors.Is(err, io.EOF) {
				t.log.Debug("UDP read error", "err", err)
			}
			return
		}
		t.dispatchReadPacket(from, buf[:nbytes])
	}
}

// dispatchReadPacket sends a packet into the dispatch loop.
// dispatchReadPacket 将数据包发送到 dispatch 循环。
func (t *UDPv5) dispatchReadPacket(from netip.AddrPort, content []byte) bool {
	// Unwrap IPv4-in-6 source address.
	// 解包 IPv4-in-6 源地址。
	if from.Addr().Is4In6() {
		from = netip.AddrPortFrom(netip.AddrFrom4(from.Addr().As4()), from.Port())
	}
	select {
	case t.packetInCh <- ReadPacket{content, from}:
		return true
	case <-t.closeCtx.Done():
		return false
	}
}

// handlePacket decodes and processes an incoming packet from the network.
// handlePacket 解码并处理来自网络的传入数据包。
func (t *UDPv5) handlePacket(rawpacket []byte, fromAddr netip.AddrPort) error {
	addr := fromAddr.String()
	fromID, fromNode, packet, err := t.codec.Decode(rawpacket, addr)
	if err != nil {
		if t.unhandled != nil && v5wire.IsInvalidHeader(err) {
			// The packet seems unrelated to discv5, send it to the next protocol.
			// 数据包似乎与 discv5 无关，将其发送到下一个协议。
			// t.log.Trace("Unhandled discv5 packet", "id", fromID, "addr", addr, "err", err)
			up := ReadPacket{Data: make([]byte, len(rawpacket)), Addr: fromAddr}
			copy(up.Data, rawpacket)
			t.unhandled <- up
			return nil
		}
		t.log.Debug("Bad discv5 packet", "id", fromID, "addr", addr, "err", err)
		return err
	}
	if fromNode != nil {
		// Handshake succeeded, add to table.
		// 握手成功，添加到表中。
		t.tab.addInboundNode(fromNode)
	}
	if packet.Kind() != v5wire.WhoareyouPacket {
		// WHOAREYOU logged separately to report errors.
		// WHOAREYOU 单独记录以报告错误。
		t.logcontext = append(t.logcontext[:0], "id", fromID, "addr", addr)
		t.logcontext = packet.AppendLogInfo(t.logcontext)
		t.log.Trace("<< "+packet.Name(), t.logcontext...)
	}
	t.handle(packet, fromID, fromAddr)
	return nil
}

// handleCallResponse dispatches a response packet to the call waiting for it.
// handleCallResponse 将响应数据包分派到等待它的调用。
func (t *UDPv5) handleCallResponse(fromID enode.ID, fromAddr netip.AddrPort, p v5wire.Packet) bool {
	ac := t.activeCallByNode[fromID]
	if ac == nil || !bytes.Equal(p.RequestID(), ac.reqid) {
		t.log.Debug(fmt.Sprintf("Unsolicited/late %s response", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if fromAddr != ac.addr {
		t.log.Debug(fmt.Sprintf("%s from wrong endpoint", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if p.Kind() != ac.responseType {
		t.log.Debug(fmt.Sprintf("Wrong discv5 response type %s", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	t.startResponseTimeout(ac)
	ac.ch <- p
	return true
}

// getNode looks for a node record in table and database.
// getNode 在表和数据库中查找节点记录。
func (t *UDPv5) getNode(id enode.ID) *enode.Node {
	if n := t.tab.getNode(id); n != nil {
		return n
	}
	if n := t.localNode.Database().Node(id); n != nil {
		return n
	}
	return nil
}

// handle processes incoming packets according to their message type.
// handle 根据消息类型处理传入的数据包。
func (t *UDPv5) handle(p v5wire.Packet, fromID enode.ID, fromAddr netip.AddrPort) {
	switch p := p.(type) {
	case *v5wire.Unknown:
		t.handleUnknown(p, fromID, fromAddr)
	case *v5wire.Whoareyou:
		t.handleWhoareyou(p, fromID, fromAddr)
	case *v5wire.Ping:
		t.handlePing(p, fromID, fromAddr)
	case *v5wire.Pong:
		if t.handleCallResponse(fromID, fromAddr, p) {
			toAddr := netip.AddrPortFrom(netutil.IPToAddr(p.ToIP), p.ToPort)
			t.localNode.UDPEndpointStatement(fromAddr, toAddr)
		}
	case *v5wire.Findnode:
		t.handleFindnode(p, fromID, fromAddr)
	case *v5wire.Nodes:
		t.handleCallResponse(fromID, fromAddr, p)
	case *v5wire.TalkRequest:
		t.talk.handleRequest(fromID, fromAddr, p)
	case *v5wire.TalkResponse:
		t.handleCallResponse(fromID, fromAddr, p)
	}
}

// handleUnknown initiates a handshake by responding with WHOAREYOU.
// handleUnknown 通过响应 WHOAREYOU 来启动握手。
func (t *UDPv5) handleUnknown(p *v5wire.Unknown, fromID enode.ID, fromAddr netip.AddrPort) {
	challenge := &v5wire.Whoareyou{Nonce: p.Nonce}
	crand.Read(challenge.IDNonce[:])
	if n := t.getNode(fromID); n != nil {
		challenge.Node = n
		challenge.RecordSeq = n.Seq()
	}
	t.sendResponse(fromID, fromAddr, challenge)
}

var (
	errChallengeNoCall = errors.New("no matching call") // 没有匹配的调用
	errChallengeTwice  = errors.New("second handshake") // 第二次握手
)

// handleWhoareyou resends the active call as a handshake packet.
// handleWhoareyou 将活动调用作为握手数据包重新发送。
func (t *UDPv5) handleWhoareyou(p *v5wire.Whoareyou, fromID enode.ID, fromAddr netip.AddrPort) {
	c, err := t.matchWithCall(fromID, p.Nonce)
	if err != nil {
		t.log.Debug("Invalid "+p.Name(), "addr", fromAddr, "err", err)
		return
	}

	if c.node == nil {
		// Can't perform handshake because we don't have the ENR.
		// 无法执行握手，因为我们没有 ENR。
		t.log.Debug("Can't handle "+p.Name(), "addr", fromAddr, "err", "call has no ENR")
		c.err <- errors.New("remote wants handshake, but call has no ENR")
		return
	}
	// Resend the call that was answered by WHOAREYOU.
	// 重新发送被 WHOAREYOU 回答的调用。
	t.log.Trace("<< "+p.Name(), "id", c.node.ID(), "addr", fromAddr)
	c.handshakeCount++
	c.challenge = p
	p.Node = c.node
	t.sendCall(c)
}

// matchWithCall checks whether a handshake attempt matches the active call.
// matchWithCall 检查握手尝试是否与活动调用匹配。
func (t *UDPv5) matchWithCall(fromID enode.ID, nonce v5wire.Nonce) (*callV5, error) {
	c := t.activeCallByAuth[nonce]
	if c == nil {
		return nil, errChallengeNoCall
	}
	if c.handshakeCount > 0 {
		return nil, errChallengeTwice
	}
	return c, nil
}

// handlePing sends a PONG response.
// handlePing 发送 PONG 响应。
func (t *UDPv5) handlePing(p *v5wire.Ping, fromID enode.ID, fromAddr netip.AddrPort) {
	var remoteIP net.IP
	// Handle IPv4 mapped IPv6 addresses in the event the local node is binded
	// to an ipv6 interface.
	// 处理 IPv4 映射的 IPv6 地址，以防本地节点绑定到 ipv6 接口。
	if fromAddr.Addr().Is4() || fromAddr.Addr().Is4In6() {
		ip4 := fromAddr.Addr().As4()
		remoteIP = ip4[:]
	} else {
		remoteIP = fromAddr.Addr().AsSlice()
	}
	t.sendResponse(fromID, fromAddr, &v5wire.Pong{
		ReqID:  p.ReqID,
		ToIP:   remoteIP,
		ToPort: fromAddr.Port(),
		ENRSeq: t.localNode.Node().Seq(),
	})
}

// handleFindnode returns nodes to the requester.
// handleFindnode 向请求者返回节点。
func (t *UDPv5) handleFindnode(p *v5wire.Findnode, fromID enode.ID, fromAddr netip.AddrPort) {
	nodes := t.collectTableNodes(fromAddr.Addr(), p.Distances, findnodeResultLimit)
	for _, resp := range packNodes(p.ReqID, nodes) {
		t.sendResponse(fromID, fromAddr, resp)
	}
}

// collectTableNodes creates a FINDNODE result set for the given distances.
// collectTableNodes 为给定距离创建 FINDNODE 结果集。
func (t *UDPv5) collectTableNodes(rip netip.Addr, distances []uint, limit int) []*enode.Node {
	var bn []*enode.Node
	var nodes []*enode.Node
	var processed = make(map[uint]struct{})
	for _, dist := range distances {
		// Reject duplicate / invalid distances.
		// 拒绝重复/无效的距离。
		_, seen := processed[dist]
		if seen || dist > 256 {
			continue
		}
		processed[dist] = struct{}{}

		checkLive := !t.tab.cfg.NoFindnodeLivenessCheck
		for _, n := range t.tab.appendBucketNodes(dist, bn[:0], checkLive) {
			// Apply some pre-checks to avoid sending invalid nodes.
			// Note liveness is checked by appendLiveNodes.
			//
			// 应用一些预检查以避免发送无效节点。
			// 注意 appendLiveNodes 检查存活状态。
			if netutil.CheckRelayAddr(rip, n.IPAddr()) != nil {
				continue
			}
			nodes = append(nodes, n)
			if len(nodes) >= limit {
				return nodes
			}
		}
	}
	return nodes
}

// packNodes creates NODES response packets for the given node list.
// packNodes 为给定的节点列表创建 NODES 响应数据包。
func packNodes(reqid []byte, nodes []*enode.Node) []*v5wire.Nodes {
	if len(nodes) == 0 {
		return []*v5wire.Nodes{{ReqID: reqid, RespCount: 1}}
	}

	// This limit represents the available space for nodes in output packets. Maximum
	// packet size is 1280, and out of this ~80 bytes will be taken up by the packet
	// frame. So limiting to 1000 bytes here leaves 200 bytes for other fields of the
	// NODES message, which is a lot.
	//
	// 此限制表示输出数据包中可用于节点的可用空间。
	// 最大数据包大小为 1280 字节，其中约 80 字节将由数据包帧占用。
	// 因此，此处限制为 1000 字节，为 NODES 消息的其他字段留下了 200 字节，这已经很多了。
	const sizeLimit = 1000

	var resp []*v5wire.Nodes
	for len(nodes) > 0 {
		p := &v5wire.Nodes{ReqID: reqid}
		size := uint64(0)
		for len(nodes) > 0 {
			r := nodes[0].Record()
			if size += r.Size(); size > sizeLimit {
				break
			}
			p.Nodes = append(p.Nodes, r)
			nodes = nodes[1:]
		}
		resp = append(resp, p)
	}
	for _, msg := range resp {
		msg.RespCount = uint8(len(resp))
	}
	return resp
}
