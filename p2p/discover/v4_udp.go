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

package discover

import (
	"bytes"
	"container/list"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v4wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// Discovery v4：这是以太坊 P2P 网络的节点发现协议，基于 Kademlia 分布式哈希表（DHT），用于在去中心化网络中发现其他节点。
// ENR（Ethereum Node Record）：enode.LocalNode 包含本地节点的 ENR，遵循 EIP-778 标准，记录节点的公钥、IP 地址和端口等信息。

// Errors
// 错误
var (
	errExpired          = errors.New("expired")                              // 已过期
	errUnsolicitedReply = errors.New("unsolicited reply")                    // 未请求的回复
	errUnknownNode      = errors.New("unknown node")                         // 未知节点
	errTimeout          = errors.New("RPC timeout")                          // RPC 超时
	errClockWarp        = errors.New("reply deadline too far in the future") // 回复截止日期太远
	errClosed           = errors.New("socket closed")                        // 套接字已关闭
	errLowPort          = errors.New("low port")                             // 低端口
	errNoUDPEndpoint    = errors.New("node has no UDP endpoint")             // 节点没有 UDP 端点
)

const (
	respTimeout    = 500 * time.Millisecond // 响应超时时间
	expiration     = 20 * time.Second       // 数据包过期时间
	bondExpiration = 24 * time.Hour         // 绑定过期时间

	maxFindnodeFailures = 5                // 节点失败次数超过此限制将被丢弃 // nodes exceeding this limit are dropped
	ntpFailureThreshold = 32               // 连续超时时触发 NTP 检查 // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // NTP 警告的冷却时间 // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // 允许的时钟漂移 // Allowed clock drift before warning user

	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	// 发现数据包定义为不超过 1280 字节。
	// 超过此大小的数据包将被截断并视为无效，因为其哈希将不匹配。
	maxPacketSize = 1280
)

// UDPv4 implements the v4 wire protocol.
// UDPv4 实现了 v4 线协议。
type UDPv4 struct {
	conn        UDPConn
	log         log.Logger
	netrestrict *netutil.Netlist
	priv        *ecdsa.PrivateKey
	localNode   *enode.LocalNode
	db          *enode.DB
	tab         *Table
	closeOnce   sync.Once
	wg          sync.WaitGroup

	addReplyMatcher chan *replyMatcher
	gotreply        chan reply
	closeCtx        context.Context
	cancelCloseCtx  context.CancelFunc
}

// replyMatcher represents a pending reply.
// replyMatcher 表示待处理的回复。
//
// Some implementations of the protocol wish to send more than one
// reply packet to findnode. In general, any neighbors packet cannot
// be matched up with a specific findnode packet.
// 协议的某些实现希望向 findnode 发送多个回复数据包。一般来说，任何 neighbors 数据包都不能与特定的 findnode 数据包匹配。
//
// Our implementation handles this by storing a callback function for
// each pending reply. Incoming packets from a node are dispatched
// to all callback functions for that node.
// 我们的实现通过为每个待处理的回复存储一个回调函数来处理这一点。来自节点的传入数据包被分派到该节点的所有回调函数。
type replyMatcher struct {
	// these fields must match in the reply.
	// 这些字段必须在回复中匹配。
	from  enode.ID
	ip    netip.Addr
	ptype byte

	// time when the request must complete
	// 请求必须完成的时间
	deadline time.Time

	// callback is called when a matching reply arrives. If it returns matched == true, the
	// reply was acceptable. The second return value indicates whether the callback should
	// be removed from the pending reply queue. If it returns false, the reply is considered
	// incomplete and the callback will be invoked again for the next matching reply.
	// 当匹配的回复到达时调用 callback。如果返回 matched == true，则回复可接受。第二个返回值指示是否应从待处理回复队列中删除回调。如果返回 false，则回复被视为不完整，回调将为下一个匹配的回复再次调用。
	callback replyMatchFunc

	// errc receives nil when the callback indicates completion or an
	// error if no further reply is received within the timeout.
	// 当回调指示完成时，errc 接收 nil；如果在超时内未收到进一步的回复，则接收错误。
	errc chan error

	// reply contains the most recent reply. This field is safe for reading after errc has
	// received a value.
	// reply 包含最近的回复。在 errc 接收到值后，此字段可安全读取。
	reply v4wire.Packet
}

type replyMatchFunc func(v4wire.Packet) (matched bool, requestDone bool)

// reply is a reply packet from a certain node.
// reply 是来自某个节点的回复数据包。
type reply struct {
	from enode.ID
	ip   netip.Addr
	data v4wire.Packet
	// loop indicates whether there was
	// a matching request by sending on this channel.
	// loop 通过在此通道上发送来指示是否有匹配的请求。
	matched chan<- bool
}

func ListenV4(c UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	cfg = cfg.withDefaults()
	closeCtx, cancel := context.WithCancel(context.Background())
	t := &UDPv4{
		conn:            newMeteredConn(c),
		priv:            cfg.PrivateKey,
		netrestrict:     cfg.NetRestrict,
		localNode:       ln,
		db:              ln.Database(),
		gotreply:        make(chan reply),
		addReplyMatcher: make(chan *replyMatcher),
		closeCtx:        closeCtx,
		cancelCloseCtx:  cancel,
		log:             cfg.Log,
	}

	tab, err := newTable(t, ln.Database(), cfg)
	if err != nil {
		return nil, err
	}
	t.tab = tab
	go tab.loop()

	t.wg.Add(2)
	go t.loop()
	go t.readLoop(cfg.Unhandled)
	return t, nil
}

// Self returns the local node.
// Self 返回本地节点。
func (t *UDPv4) Self() *enode.Node {
	return t.localNode.Node()
}

// Close shuts down the socket and aborts any running queries.
// Close 关闭套接字并中止任何正在运行的查询。
func (t *UDPv4) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.wg.Wait()
		t.tab.close()
	})
}

// ENR 序列号：Seq 表示 ENR 的版本号，较高的序列号意味着更新的记录。
// Kademlia 查找：LookupPubkey 使用 Kademlia 算法递归查找接近目标公钥的节点。

// Resolve searches for a specific node with the given ID and tries to get the most recent
// version of the node record for it. It returns n if the node could not be resolved.
// Resolve 搜索具有给定 ID 的特定节点，并尝试获取其最新版本的节点记录。如果无法解析节点，则返回 n。
func (t *UDPv4) Resolve(n *enode.Node) *enode.Node {
	// Try asking directly. This works if the node is still responding on the endpoint we have.
	// 尝试直接询问。如果节点仍在我们拥有的端点上响应，这将起作用。
	if rn, err := t.RequestENR(n); err == nil {
		return rn
	}
	// Check table for the ID, we might have a newer version there.
	// 检查表中是否有 ID，我们可能在那里有更新的版本。
	if intable := t.tab.getNode(n.ID()); intable != nil && intable.Seq() > n.Seq() {
		n = intable
		if rn, err := t.RequestENR(n); err == nil {
			return rn
		}
	}
	// Otherwise perform a network lookup.
	// 否则执行网络查找。
	var key enode.Secp256k1
	if n.Load(&key) != nil {
		return n // no secp256k1 key // 无 secp256k1 密钥
	}
	result := t.LookupPubkey((*ecdsa.PublicKey)(&key))
	for _, rn := range result {
		if rn.ID() == n.ID() {
			if rn, err := t.RequestENR(rn); err == nil {
				return rn
			}
		}
	}
	return n
}

func (t *UDPv4) ourEndpoint() v4wire.Endpoint {
	node := t.Self()
	addr, ok := node.UDPEndpoint()
	if !ok {
		return v4wire.Endpoint{}
	}
	return v4wire.NewEndpoint(addr, uint16(node.TCP()))
}

// Ping sends a ping message to the given node.
// Ping 向给定节点发送 ping 消息。
func (t *UDPv4) Ping(n *enode.Node) error {
	_, err := t.ping(n)
	return err
}

// ping sends a ping message to the given node and waits for a reply.
// ping 向给定节点发送 ping 消息并等待回复。
func (t *UDPv4) ping(n *enode.Node) (seq uint64, err error) {
	addr, ok := n.UDPEndpoint()
	if !ok {
		return 0, errNoUDPEndpoint
	}
	rm := t.sendPing(n.ID(), addr, nil)
	if err = <-rm.errc; err == nil {
		seq = rm.reply.(*v4wire.Pong).ENRSeq
	}
	return seq, err
}

// sendPing sends a ping message to the given node and invokes the callback
// when the reply arrives.
// sendPing 向给定节点发送 ping 消息，并在回复到达时调用回调。
func (t *UDPv4) sendPing(toid enode.ID, toaddr netip.AddrPort, callback func()) *replyMatcher {
	req := t.makePing(toaddr)
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		errc := make(chan error, 1)
		errc <- err
		return &replyMatcher{errc: errc}
	}
	// Add a matcher for the reply to the pending reply queue. Pongs are matched if they
	// reference the ping we're about to send.
	// 将回复的匹配器添加到待处理回复队列中。如果 pong 引用了我们即将发送的 ping，则匹配。
	rm := t.pending(toid, toaddr.Addr(), v4wire.PongPacket, func(p v4wire.Packet) (matched bool, requestDone bool) {
		matched = bytes.Equal(p.(*v4wire.Pong).ReplyTok, hash)
		if matched && callback != nil {
			callback()
		}
		return matched, matched
	})
	// Send the packet.
	// 发送数据包。
	t.localNode.UDPContact(toaddr)
	t.write(toaddr, toid, req.Name(), packet)
	return rm
}

func (t *UDPv4) makePing(toaddr netip.AddrPort) *v4wire.Ping {
	return &v4wire.Ping{
		Version:    4,
		From:       t.ourEndpoint(),
		To:         v4wire.NewEndpoint(toaddr, 0),
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	}
}

// LookupPubkey finds the closest nodes to the given public key.
// LookupPubkey 查找最接近给定公钥的节点。
func (t *UDPv4) LookupPubkey(key *ecdsa.PublicKey) []*enode.Node {
	if t.tab.len() == 0 {
		// All nodes were dropped, refresh. The very first query will hit this
		// case and run the bootstrapping logic.
		// 所有节点都被丢弃，刷新。第一个查询将命中此情况并运行引导逻辑。
		<-t.tab.refresh()
	}
	return t.newLookup(t.closeCtx, v4wire.EncodePubkey(key)).run()
}

// RandomNodes is an iterator yielding nodes from a random walk of the DHT.
// RandomNodes 是一个迭代器，从 DHT 的随机游走中生成节点。
func (t *UDPv4) RandomNodes() enode.Iterator {
	return newLookupIterator(t.closeCtx, t.newRandomLookup)
}

// lookupRandom implements transport.
// lookupRandom 实现了 transport。
func (t *UDPv4) lookupRandom() []*enode.Node {
	return t.newRandomLookup(t.closeCtx).run()
}

// lookupSelf implements transport.
// lookupSelf 实现了 transport。
func (t *UDPv4) lookupSelf() []*enode.Node {
	pubkey := v4wire.EncodePubkey(&t.priv.PublicKey)
	return t.newLookup(t.closeCtx, pubkey).run()
}

func (t *UDPv4) newRandomLookup(ctx context.Context) *lookup {
	var target v4wire.Pubkey
	crand.Read(target[:])
	return t.newLookup(ctx, target)
}

func (t *UDPv4) newLookup(ctx context.Context, targetKey v4wire.Pubkey) *lookup {
	target := enode.ID(crypto.Keccak256Hash(targetKey[:]))
	it := newLookup(ctx, t.tab, target, func(n *enode.Node) ([]*enode.Node, error) {
		addr, ok := n.UDPEndpoint()
		if !ok {
			return nil, errNoUDPEndpoint
		}
		return t.findnode(n.ID(), addr, targetKey)
	})
	return it
}

// findnode sends a findnode request to the given node and waits until
// the node has sent up to k neighbors.
// findnode 向给定节点发送 findnode 请求，并等待节点发送最多 k 个邻居。
func (t *UDPv4) findnode(toid enode.ID, toAddrPort netip.AddrPort, target v4wire.Pubkey) ([]*enode.Node, error) {
	t.ensureBond(toid, toAddrPort)

	// Add a matcher for 'neighbours' replies to the pending reply queue. The matcher is
	// active until enough nodes have been received.
	// 将 'neighbours' 回复的匹配器添加到待处理回复队列中。匹配器在接收到足够节点之前保持活动。
	nodes := make([]*enode.Node, 0, bucketSize)
	nreceived := 0
	rm := t.pending(toid, toAddrPort.Addr(), v4wire.NeighborsPacket, func(r v4wire.Packet) (matched bool, requestDone bool) {
		reply := r.(*v4wire.Neighbors)
		for _, rn := range reply.Nodes {
			nreceived++
			n, err := t.nodeFromRPC(toAddrPort, rn)
			if err != nil {
				t.log.Trace("Invalid neighbor node received", "ip", rn.IP, "addr", toAddrPort, "err", err)
				continue
			}
			nodes = append(nodes, n)
		}
		return true, nreceived >= bucketSize
	})
	t.send(toAddrPort, toid, &v4wire.Findnode{
		Target:     target,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	})
	// Ensure that callers don't see a timeout if the node actually responded. Since
	// findnode can receive more than one neighbors response, the reply matcher will be
	// active until the remote node sends enough nodes. If the remote end doesn't have
	// enough nodes the reply matcher will time out waiting for the second reply, but
	// there's no need for an error in that case.
	// 确保如果节点实际响应了，调用者不会看到超时。由于 findnode 可以接收多个 neighbors 响应，回复匹配器将保持活动状态，直到远程节点发送足够数量的节点。如果远程节点没有足够的节点，回复匹配器将等待第二个回复时超时，但在这种情况下不需要错误。
	err := <-rm.errc
	if errors.Is(err, errTimeout) && rm.reply != nil {
		err = nil
	}
	return nodes, err
}

// RequestENR sends ENRRequest to the given node and waits for a response.
// RequestENR 向给定节点发送 ENRRequest 并等待响应。
func (t *UDPv4) RequestENR(n *enode.Node) (*enode.Node, error) {
	addr, _ := n.UDPEndpoint()
	t.ensureBond(n.ID(), addr)

	req := &v4wire.ENRRequest{
		Expiration: uint64(time.Now().Add(expiration).Unix()),
	}
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		return nil, err
	}

	// Add a matcher for the reply to the pending reply queue. Responses are matched if
	// they reference the request we're about to send.
	// 将回复的匹配器添加到待处理回复队列中。如果响应引用了我们即将发送的请求，则匹配。
	rm := t.pending(n.ID(), addr.Addr(), v4wire.ENRResponsePacket, func(r v4wire.Packet) (matched bool, requestDone bool) {
		matched = bytes.Equal(r.(*v4wire.ENRResponse).ReplyTok, hash)
		return matched, matched
	})
	// Send the packet and wait for the reply.
	// 发送数据包并等待回复。
	t.write(addr, n.ID(), req.Name(), packet)
	if err := <-rm.errc; err != nil {
		return nil, err
	}
	// Verify the response record.
	// 验证响应记录。
	respN, err := enode.New(enode.ValidSchemes, &rm.reply.(*v4wire.ENRResponse).Record)
	if err != nil {
		return nil, err
	}
	if respN.ID() != n.ID() {
		return nil, errors.New("invalid ID in response record")
	}
	if respN.Seq() < n.Seq() {
		return n, nil // response record is older // 响应记录较旧
	}
	if err := netutil.CheckRelayAddr(addr.Addr(), respN.IPAddr()); err != nil {
		return nil, fmt.Errorf("invalid IP in response record: %v", err)
	}
	return respN, nil
}

func (t *UDPv4) TableBuckets() [][]BucketNode {
	return t.tab.Nodes()
}

// pending adds a reply matcher to the pending reply queue.
// pending 将回复匹配器添加到待处理回复队列。
// see the documentation of type replyMatcher for a detailed explanation.
// 有关详细说明，请参阅 replyMatcher 类型的文档。
func (t *UDPv4) pending(id enode.ID, ip netip.Addr, ptype byte, callback replyMatchFunc) *replyMatcher {
	ch := make(chan error, 1)
	p := &replyMatcher{from: id, ip: ip, ptype: ptype, callback: callback, errc: ch}
	select {
	case t.addReplyMatcher <- p:
		// loop will handle it
		// loop 将处理它
	case <-t.closeCtx.Done():
		ch <- errClosed
	}
	return p
}

// handleReply dispatches a reply packet, invoking reply matchers. It returns
// whether any matcher considered the packet acceptable.
// handleReply 分派回复数据包，调用回复匹配器。它返回是否有任何匹配器认为数据包可接受。
func (t *UDPv4) handleReply(from enode.ID, fromIP netip.Addr, req v4wire.Packet) bool {
	matched := make(chan bool, 1)
	select {
	case t.gotreply <- reply{from, fromIP, req, matched}:
		// loop will handle it
		// loop 将处理它
		return <-matched
	case <-t.closeCtx.Done():
		return false
	}
}

// 请求-响应模型：Discovery v4 使用 PING/PONG 等消息验证节点活性，loop 协调这些请求和响应的处理。
// NTP 同步：确保节点间时间一致性，避免因时钟漂移导致的协议失败。

// loop runs in its own goroutine. it keeps track of
// the refresh timer and the pending reply queue.
// loop 在自己的 goroutine 中运行。它跟踪刷新定时器和待处理回复队列。
func (t *UDPv4) loop() {
	defer t.wg.Done()

	var (
		plist        = list.New()
		timeout      = time.NewTimer(0)
		nextTimeout  *replyMatcher // head of plist when timeout was last reset // plist 的头部，当超时最后一次重置时
		contTimeouts = 0           // number of continuous timeouts to do NTP checks // 连续超时的次数，用于触发 NTP 检查
		ntpWarnTime  = time.Unix(0, 0)
	)
	<-timeout.C // ignore first timeout // 忽略第一次超时
	defer timeout.Stop()

	resetTimeout := func() {
		if plist.Front() == nil || nextTimeout == plist.Front().Value {
			return
		}
		// Start the timer so it fires when the next pending reply has expired.
		// 启动定时器，以便在下一个待处理回复过期时触发。
		now := time.Now()
		for el := plist.Front(); el != nil; el = el.Next() {
			nextTimeout = el.Value.(*replyMatcher)
			if dist := nextTimeout.deadline.Sub(now); dist < 2*respTimeout {
				timeout.Reset(dist)
				return
			}
			// Remove pending replies whose deadline is too far in the
			// future. These can occur if the system clock jumped
			// backwards after the deadline was assigned.
			// 删除截止日期太远的待处理回复。这些情况可能在分配截止日期后系统时钟向后跳跃时发生。
			nextTimeout.errc <- errClockWarp
			plist.Remove(el)
		}
		nextTimeout = nil
		timeout.Stop()
	}

	for {
		resetTimeout()

		select {
		case <-t.closeCtx.Done():
			for el := plist.Front(); el != nil; el = el.Next() {
				el.Value.(*replyMatcher).errc <- errClosed
			}
			return

		case p := <-t.addReplyMatcher:
			p.deadline = time.Now().Add(respTimeout)
			plist.PushBack(p)

		case r := <-t.gotreply:
			var matched bool // whether any replyMatcher considered the reply acceptable. // 是否有任何 replyMatcher 认为回复可接受
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if p.from == r.from && p.ptype == r.data.Kind() && p.ip == r.ip {
					ok, requestDone := p.callback(r.data)
					matched = matched || ok
					p.reply = r.data
					// Remove the matcher if callback indicates that all replies have been received.
					// 如果回调指示所有回复已收到，则删除匹配器。
					if requestDone {
						p.errc <- nil
						plist.Remove(el)
					}
					// Reset the continuous timeout counter (time drift detection)
					// 重置连续超时计数器（时间漂移检测）
					contTimeouts = 0
				}
			}
			r.matched <- matched

		case now := <-timeout.C:
			nextTimeout = nil

			// Notify and remove callbacks whose deadline is in the past.
			// 通知并删除截止日期已过的回调。
			for el := plist.Front(); el != nil; el = el.Next() {
				p := el.Value.(*replyMatcher)
				if now.After(p.deadline) || now.Equal(p.deadline) {
					p.errc <- errTimeout
					plist.Remove(el)
					contTimeouts++
				}
			}
			// If we've accumulated too many timeouts, do an NTP time sync check
			// 如果累积了太多超时，则进行 NTP 时间同步检查
			if contTimeouts > ntpFailureThreshold {
				if time.Since(ntpWarnTime) >= ntpWarningCooldown {
					ntpWarnTime = time.Now()
					go checkClockDrift()
				}
				contTimeouts = 0
			}
		}
	}
}

func (t *UDPv4) send(toaddr netip.AddrPort, toid enode.ID, req v4wire.Packet) ([]byte, error) {
	packet, hash, err := v4wire.Encode(t.priv, req)
	if err != nil {
		return hash, err
	}
	return hash, t.write(toaddr, toid, req.Name(), packet)
}

func (t *UDPv4) write(toaddr netip.AddrPort, toid enode.ID, what string, packet []byte) error {
	_, err := t.conn.WriteToUDPAddrPort(packet, toaddr)
	t.log.Trace(">> "+what, "id", toid, "addr", toaddr, "err", err)
	return err
}

// readLoop runs in its own goroutine. it handles incoming UDP packets.
// readLoop 在自己的 goroutine 中运行。它处理传入的 UDP 数据包。
func (t *UDPv4) readLoop(unhandled chan<- ReadPacket) {
	defer t.wg.Done()
	if unhandled != nil {
		defer close(unhandled)
	}

	buf := make([]byte, maxPacketSize)
	for {
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
		if err := t.handlePacket(from, buf[:nbytes]); err != nil && unhandled == nil {
			t.log.Debug("Bad discv4 packet", "addr", from, "err", err)
		} else if err != nil && unhandled != nil {
			select {
			case unhandled <- ReadPacket{buf[:nbytes], from}:
			default:
			}
		}
	}
}

func (t *UDPv4) handlePacket(from netip.AddrPort, buf []byte) error {
	// Unwrap IPv4-in-6 source address.
	// 解包 IPv4-in-6 源地址。
	if from.Addr().Is4In6() {
		from = netip.AddrPortFrom(netip.AddrFrom4(from.Addr().As4()), from.Port())
	}

	rawpacket, fromKey, hash, err := v4wire.Decode(buf)
	if err != nil {
		return err
	}
	packet := t.wrapPacket(rawpacket)
	fromID := fromKey.ID()
	if packet.preverify != nil {
		err = packet.preverify(packet, from, fromID, fromKey)
	}
	t.log.Trace("<< "+packet.Name(), "id", fromID, "addr", from, "err", err)
	if err == nil && packet.handle != nil {
		packet.handle(packet, from, fromID, hash)
	}
	return err
}

// checkBond checks if the given node has a recent enough endpoint proof.
// checkBond 检查给定节点是否具有足够近期的端点证明。
func (t *UDPv4) checkBond(id enode.ID, ip netip.AddrPort) bool {
	return time.Since(t.db.LastPongReceived(id, ip.Addr())) < bondExpiration
}

// ensureBond solicits a ping from a node if we haven't seen a ping from it for a while.
// This ensures there is a valid endpoint proof on the remote end.
// ensureBond 如果我们有一段时间没有收到来自节点的 ping，则向节点请求 ping。
// 这确保在远程端存在有效的端点证明。
func (t *UDPv4) ensureBond(toid enode.ID, toaddr netip.AddrPort) {
	tooOld := time.Since(t.db.LastPingReceived(toid, toaddr.Addr())) > bondExpiration
	if tooOld || t.db.FindFails(toid, toaddr.Addr()) > maxFindnodeFailures {
		rm := t.sendPing(toid, toaddr, nil)
		<-rm.errc
		// Wait for them to ping back and process our pong.
		// 等待他们 ping 回来并处理我们的 pong。
		time.Sleep(respTimeout)
	}
}

func (t *UDPv4) nodeFromRPC(sender netip.AddrPort, rn v4wire.Node) (*enode.Node, error) {
	if rn.UDP <= 1024 {
		return nil, errLowPort
	}
	if err := netutil.CheckRelayIP(sender.Addr().AsSlice(), rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict list") // 未包含在网络限制列表中
	}
	key, err := v4wire.DecodePubkey(crypto.S256(), rn.ID)
	if err != nil {
		return nil, err
	}
	n := enode.NewV4(key, rn.IP, int(rn.TCP), int(rn.UDP))
	err = n.ValidateComplete()
	return n, err
}

func nodeToRPC(n *enode.Node) v4wire.Node {
	var key ecdsa.PublicKey
	var ekey v4wire.Pubkey
	if err := n.Load((*enode.Secp256k1)(&key)); err == nil {
		ekey = v4wire.EncodePubkey(&key)
	}
	return v4wire.Node{ID: ekey, IP: n.IP(), UDP: uint16(n.UDP()), TCP: uint16(n.TCP())}
}

// wrapPacket returns the handler functions applicable to a packet.
// wrapPacket 返回适用于数据包的处理程序函数。
func (t *UDPv4) wrapPacket(p v4wire.Packet) *packetHandlerV4 {
	var h packetHandlerV4
	h.Packet = p
	switch p.(type) {
	case *v4wire.Ping:
		h.preverify = t.verifyPing
		h.handle = t.handlePing
	case *v4wire.Pong:
		h.preverify = t.verifyPong
	case *v4wire.Findnode:
		h.preverify = t.verifyFindnode
		h.handle = t.handleFindnode
	case *v4wire.Neighbors:
		h.preverify = t.verifyNeighbors
	case *v4wire.ENRRequest:
		h.preverify = t.verifyENRRequest
		h.handle = t.handleENRRequest
	case *v4wire.ENRResponse:
		h.preverify = t.verifyENRResponse
	}
	return &h
}

// packetHandlerV4 wraps a packet with handler functions.
// packetHandlerV4 用处理程序函数包装数据包。
type packetHandlerV4 struct {
	v4wire.Packet
	senderKey *ecdsa.PublicKey // used for ping // 用于 ping

	// preverify checks whether the packet is valid and should be handled at all.
	// preverify 检查数据包是否有效以及是否应该处理。
	preverify func(p *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error
	// handle handles the packet.
	// handle 处理数据包。
	handle func(req *packetHandlerV4, from netip.AddrPort, fromID enode.ID, mac []byte)
}

// PING/v4

func (t *UDPv4) verifyPing(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Ping)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	senderKey, err := v4wire.DecodePubkey(crypto.S256(), fromKey)
	if err != nil {
		return err
	}
	h.senderKey = senderKey
	return nil
}

func (t *UDPv4) handlePing(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Ping)

	// Reply.
	// 回复。
	t.send(from, fromID, &v4wire.Pong{
		To:         v4wire.NewEndpoint(from, req.From.TCP),
		ReplyTok:   mac,
		Expiration: uint64(time.Now().Add(expiration).Unix()),
		ENRSeq:     t.localNode.Node().Seq(),
	})

	// Ping back if our last pong on file is too far in the past.
	// 如果我们记录的最后一个 pong 太久远，则 ping 回来。
	fromIP := from.Addr().AsSlice()
	n := enode.NewV4(h.senderKey, fromIP, int(req.From.TCP), int(from.Port()))
	if time.Since(t.db.LastPongReceived(n.ID(), from.Addr())) > bondExpiration {
		t.sendPing(fromID, from, func() {
			t.tab.addInboundNode(n)
		})
	} else {
		t.tab.addInboundNode(n)
	}

	// Update node database and endpoint predictor.
	// 更新节点数据库和端点预测器。
	t.db.UpdateLastPingReceived(n.ID(), from.Addr(), time.Now())
	toaddr := netip.AddrPortFrom(netutil.IPToAddr(req.To.IP), req.To.UDP)
	t.localNode.UDPEndpointStatement(from, toaddr)
}

// PONG/v4

func (t *UDPv4) verifyPong(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Pong)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.Addr(), req) {
		return errUnsolicitedReply
	}
	toaddr := netip.AddrPortFrom(netutil.IPToAddr(req.To.IP), req.To.UDP)
	t.localNode.UDPEndpointStatement(from, toaddr)
	t.db.UpdateLastPongReceived(fromID, from.Addr(), time.Now())
	return nil
}

// FINDNODE/v4

func (t *UDPv4) verifyFindnode(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Findnode)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.checkBond(fromID, from) {
		// No endpoint proof pong exists, we don't process the packet. This prevents an
		// attack vector where the discovery protocol could be used to amplify traffic in a
		// DDOS attack. A malicious actor would send a findnode request with the IP address
		// and UDP port of the target as the source address. The recipient of the findnode
		// packet would then send a neighbors packet (which is a much bigger packet than
		// findnode) to the victim.
		// 如果没有端点证明 pong 存在，我们不处理数据包。这可以防止攻击向量，其中发现协议可用于在 DDOS 攻击中放大流量。恶意行为者将发送 findnode 请求，使用目标的 IP 地址和 UDP 端口作为源地址。findnode 数据包的接收者然后会向受害者发送 neighbors 数据包（比 findnode 更大的数据包）。
		return errUnknownNode
	}
	return nil
}

func (t *UDPv4) handleFindnode(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, mac []byte) {
	req := h.Packet.(*v4wire.Findnode)

	// Determine closest nodes.
	// 确定最近的节点。
	target := enode.ID(crypto.Keccak256Hash(req.Target[:]))
	preferLive := !t.tab.cfg.NoFindnodeLivenessCheck
	closest := t.tab.findnodeByID(target, bucketSize, preferLive).entries

	// Send neighbors in chunks with at most maxNeighbors per packet
	// to stay below the packet size limit.
	// 以每个数据包最多 maxNeighbors 的块发送 neighbors，以保持在数据包大小限制以下。
	p := v4wire.Neighbors{Expiration: uint64(time.Now().Add(expiration).Unix())}
	var sent bool
	for _, n := range closest {
		if netutil.CheckRelayAddr(from.Addr(), n.IPAddr()) == nil {
			p.Nodes = append(p.Nodes, nodeToRPC(n))
		}
		if len(p.Nodes) == v4wire.MaxNeighbors {
			t.send(from, fromID, &p)
			p.Nodes = p.Nodes[:0]
			sent = true
		}
	}
	if len(p.Nodes) > 0 || !sent {
		t.send(from, fromID, &p)
	}
}

// NEIGHBORS/v4

func (t *UDPv4) verifyNeighbors(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.Neighbors)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.handleReply(fromID, from.Addr(), h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}

// ENRREQUEST/v4

func (t *UDPv4) verifyENRRequest(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	req := h.Packet.(*v4wire.ENRRequest)

	if v4wire.Expired(req.Expiration) {
		return errExpired
	}
	if !t.checkBond(fromID, from) {
		return errUnknownNode
	}
	return nil
}

func (t *UDPv4) handleENRRequest(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, mac []byte) {
	t.send(from, fromID, &v4wire.ENRResponse{
		ReplyTok: mac,
		Record:   *t.localNode.Node().Record(),
	})
}

// ENRRESPONSE/v4

func (t *UDPv4) verifyENRResponse(h *packetHandlerV4, from netip.AddrPort, fromID enode.ID, fromKey v4wire.Pubkey) error {
	if !t.handleReply(fromID, from.Addr(), h.Packet) {
		return errUnsolicitedReply
	}
	return nil
}
