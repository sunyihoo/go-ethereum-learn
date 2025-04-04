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

package p2p

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// P2P 网络与 Kademlia DHT
// 以太坊使用 Kademlia 分布式哈希表（DHT）进行节点发现。dialScheduler 通过动态拨号从 DHT 获取候选节点，并尝试建立连接。
// 静态节点
// 静态节点是预配置的连接目标，通常用于私有网络或测试网络。dialScheduler 优先保持这些节点的连接，确保网络稳定性。
// 拨号历史（dialHistoryExpiration）
// 定义了重拨等待时间（默认 inboundThrottleTime + 5秒），防止短时间内重复拨号，减轻网络负担。
// 网络限制（netRestrict）
// 允许用户指定可连接的 IP 范围，提升安全性，防止连接到不受信任的节点。
// ENR（Ethereum Node Records）
// dnsResolveHostname 中更新节点 IP 时使用 ENR，虽然签名会失效，但作为拨号目标无影响。

const (
	// This is the amount of time spent waiting in between redialing a certain node. The
	// limit is a bit higher than inboundThrottleTime to prevent failing dials in small
	// private networks.
	// 这是重新拨号某个节点之间等待的时间。
	// 限制略高于 inboundThrottleTime，以防止在小型私有网络中拨号失败。
	dialHistoryExpiration = inboundThrottleTime + 5*time.Second

	// Config for the "Looking for peers" message.
	// "Looking for peers" 消息的配置。
	dialStatsLogInterval = 10 * time.Second // printed at most this often // 最多每隔这个时间打印一次
	dialStatsPeerLimit   = 3                // but not if more than this many dialed peers // 但如果拨号的 peer 数量超过此值，则不打印

	// Endpoint resolution is throttled with bounded backoff.
	// 端点解析受到限制，使用有界退避。
	initialResolveDelay = 60 * time.Second
	maxResolveDelay     = time.Hour
)

// NodeDialer is used to connect to nodes in the network, typically by using
// an underlying net.Dialer but also using net.Pipe in tests.
// NodeDialer 用于连接网络中的节点，通常使用底层的 net.Dialer，但在测试中也使用 net.Pipe。
type NodeDialer interface {
	Dial(context.Context, *enode.Node) (net.Conn, error)
}

type nodeResolver interface {
	Resolve(*enode.Node) *enode.Node
}

// tcpDialer implements NodeDialer using real TCP connections.
// tcpDialer 使用真实的 TCP 连接实现 NodeDialer。
type tcpDialer struct {
	d *net.Dialer
}

func (t tcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	addr, _ := dest.TCPEndpoint()
	return t.d.DialContext(ctx, "tcp", addr.String())
}

// checkDial errors:
// checkDial 错误：
var (
	errSelf             = errors.New("is self")
	errAlreadyDialing   = errors.New("already dialing")
	errAlreadyConnected = errors.New("already connected")
	errRecentlyDialed   = errors.New("recently dialed")
	errNetRestrict      = errors.New("not contained in netrestrict list")
	errNoPort           = errors.New("node does not provide TCP port")
	errNoResolvedIP     = errors.New("node does not provide a resolved IP")
)

// dialer creates outbound connections and submits them into Server.
// Two types of peer connections can be created:
//   - static dials are pre-configured connections. The dialer attempts
//     keep these nodes connected at all times.
//   - dynamic dials are created from node discovery results. The dialer
//     continuously reads candidate nodes from its input iterator and attempts
//     to create peer connections to nodes arriving through the iterator.
//
// dialer 创建出站连接并将它们提交到 Server。
// 可以创建两种类型的 peer 连接：
//   - 静态拨号是预配置的连接。dialer 尝试始终保持这些节点连接。
//   - 动态拨号是从节点发现结果创建的。dialer 持续从其输入迭代器读取候选节点，并尝试创建到通过迭代器到达的节点的 peer 连接。
type dialScheduler struct {
	dialConfig
	setupFunc     dialSetupFunc
	dnsLookupFunc func(ctx context.Context, network string, name string) ([]netip.Addr, error)
	wg            sync.WaitGroup
	cancel        context.CancelFunc
	ctx           context.Context
	nodesIn       chan *enode.Node
	doneCh        chan *dialTask
	addStaticCh   chan *enode.Node
	remStaticCh   chan *enode.Node
	addPeerCh     chan *conn
	remPeerCh     chan *conn

	// Everything below here belongs to loop and
	// should only be accessed by code on the loop goroutine.
	// 以下所有内容都属于 loop，并且只能由 loop goroutine 上的代码访问。
	dialing   map[enode.ID]*dialTask // active tasks // 活动任务
	peers     map[enode.ID]struct{}  // all connected peers // 所有已连接的 peer
	dialPeers int                    // current number of dialed peers // 当前拨号的 peer 数量

	// The static map tracks all static dial tasks. The subset of usable static dial tasks
	// (i.e. those passing checkDial) is kept in staticPool. The scheduler prefers
	// launching random static tasks from the pool over launching dynamic dials from the
	// iterator.
	// static 映射跟踪所有静态拨号任务。可用的静态拨号任务子集（即通过 checkDial 的任务）保存在 staticPool 中。
	// 调度器优先从池中启动随机静态任务，而不是从迭代器启动动态拨号。
	static     map[enode.ID]*dialTask
	staticPool []*dialTask

	// The dial history keeps recently dialed nodes. Members of history are not dialed.
	// dial history 保留最近拨号的节点。history 中的成员不会被拨号。
	history      expHeap
	historyTimer *mclock.Alarm

	// for logStats
	// 用于 logStats
	lastStatsLog     mclock.AbsTime
	doneSinceLastLog int
}

type dialSetupFunc func(net.Conn, connFlag, *enode.Node) error

type dialConfig struct {
	self           enode.ID         // our own ID // 我们自己的 ID
	maxDialPeers   int              // maximum number of dialed peers // 拨号 peer 的最大数量
	maxActiveDials int              // maximum number of active dials // 活动拨号的最大数量
	netRestrict    *netutil.Netlist // IP netrestrict list, disabled if nil // IP netrestrict 列表，如果为 nil 则禁用
	resolver       nodeResolver
	dialer         NodeDialer
	log            log.Logger
	clock          mclock.Clock
	rand           *mrand.Rand
}

func (cfg dialConfig) withDefaults() dialConfig {
	if cfg.maxActiveDials == 0 {
		cfg.maxActiveDials = defaultMaxPendingPeers
	}
	if cfg.log == nil {
		cfg.log = log.Root()
	}
	if cfg.clock == nil {
		cfg.clock = mclock.System{}
	}
	if cfg.rand == nil {
		seedb := make([]byte, 8)
		crand.Read(seedb)
		seed := int64(binary.BigEndian.Uint64(seedb))
		cfg.rand = mrand.New(mrand.NewSource(seed))
	}
	return cfg
}

func newDialScheduler(config dialConfig, it enode.Iterator, setupFunc dialSetupFunc) *dialScheduler {
	cfg := config.withDefaults()
	d := &dialScheduler{
		dialConfig:    cfg,
		historyTimer:  mclock.NewAlarm(cfg.clock),
		setupFunc:     setupFunc,
		dnsLookupFunc: net.DefaultResolver.LookupNetIP,
		dialing:       make(map[enode.ID]*dialTask),
		static:        make(map[enode.ID]*dialTask),
		peers:         make(map[enode.ID]struct{}),
		doneCh:        make(chan *dialTask),
		nodesIn:       make(chan *enode.Node),
		addStaticCh:   make(chan *enode.Node),
		remStaticCh:   make(chan *enode.Node),
		addPeerCh:     make(chan *conn),
		remPeerCh:     make(chan *conn),
	}
	d.lastStatsLog = d.clock.Now()
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.wg.Add(2)
	go d.readNodes(it)
	go d.loop(it)
	return d
}

// stop shuts down the dialer, canceling all current dial tasks.
// stop 关闭 dialer，取消所有当前的拨号任务。
func (d *dialScheduler) stop() {
	d.cancel()
	d.wg.Wait()
}

// addStatic adds a static dial candidate.
// addStatic 添加一个静态拨号候选。
func (d *dialScheduler) addStatic(n *enode.Node) {
	select {
	case d.addStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// removeStatic removes a static dial candidate.
// removeStatic 移除一个静态拨号候选。
func (d *dialScheduler) removeStatic(n *enode.Node) {
	select {
	case d.remStaticCh <- n:
	case <-d.ctx.Done():
	}
}

// peerAdded updates the peer set.
// peerAdded 更新 peer 集合。
func (d *dialScheduler) peerAdded(c *conn) {
	select {
	case d.addPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// peerRemoved updates the peer set.
// peerRemoved 更新 peer 集合。
func (d *dialScheduler) peerRemoved(c *conn) {
	select {
	case d.remPeerCh <- c:
	case <-d.ctx.Done():
	}
}

// loop is the main loop of the dialer.
// loop 是 dialer 的主循环。
func (d *dialScheduler) loop(it enode.Iterator) {
	var (
		nodesCh chan *enode.Node
	)

loop:
	for {
		// Launch new dials if slots are available.
		// 如果有可用的槽位，启动新的拨号。
		slots := d.freeDialSlots()
		slots -= d.startStaticDials(slots)
		if slots > 0 {
			nodesCh = d.nodesIn
		} else {
			nodesCh = nil
		}
		d.rearmHistoryTimer()
		d.logStats()

		select {
		case node := <-nodesCh:
			if err := d.checkDial(node); err != nil {
				d.log.Trace("Discarding dial candidate", "id", node.ID(), "ip", node.IPAddr(), "reason", err)
			} else {
				d.startDial(newDialTask(node, dynDialedConn))
			}

		case task := <-d.doneCh:
			id := task.dest().ID()
			delete(d.dialing, id)
			d.updateStaticPool(id)
			d.doneSinceLastLog++

		case c := <-d.addPeerCh:
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers++
			}
			id := c.node.ID()
			d.peers[id] = struct{}{}
			// Remove from static pool because the node is now connected.
			// 从 staticPool 中移除，因为节点现在已连接。
			task := d.static[id]
			if task != nil && task.staticPoolIndex >= 0 {
				d.removeFromStaticPool(task.staticPoolIndex)
			}
			// TODO: cancel dials to connected peers
			// TODO: 取消对已连接 peer 的拨号

		case c := <-d.remPeerCh:
			if c.is(dynDialedConn) || c.is(staticDialedConn) {
				d.dialPeers--
			}
			delete(d.peers, c.node.ID())
			d.updateStaticPool(c.node.ID())

		case node := <-d.addStaticCh:
			id := node.ID()
			_, exists := d.static[id]
			d.log.Trace("Adding static node", "id", id, "endpoint", nodeEndpointForLog(node), "added", !exists)
			if exists {
				continue loop
			}
			task := newDialTask(node, staticDialedConn)
			d.static[id] = task
			if d.checkDial(node) == nil {
				d.addToStaticPool(task)
			}

		case node := <-d.remStaticCh:
			id := node.ID()
			task := d.static[id]
			d.log.Trace("Removing static node", "id", id, "ok", task != nil)
			if task != nil {
				delete(d.static, id)
				if task.staticPoolIndex >= 0 {
					d.removeFromStaticPool(task.staticPoolIndex)
				}
			}

		case <-d.historyTimer.C():
			d.expireHistory()

		case <-d.ctx.Done():
			it.Close()
			break loop
		}
	}

	d.historyTimer.Stop()
	for range d.dialing {
		<-d.doneCh
	}
	d.wg.Done()
}

// readNodes runs in its own goroutine and delivers nodes from
// the input iterator to the nodesIn channel.
// readNodes 在自己的 goroutine 中运行，并将节点从输入迭代器传递到 nodesIn 通道。
func (d *dialScheduler) readNodes(it enode.Iterator) {
	defer d.wg.Done()

	for it.Next() {
		select {
		case d.nodesIn <- it.Node():
		case <-d.ctx.Done():
		}
	}
}

// logStats prints dialer statistics to the log. The message is suppressed when enough
// peers are connected because users should only see it while their client is starting up
// or comes back online.
// logStats 将 dialer 统计信息打印到日志中。当连接了足够的 peer 时，消息会被抑制，
// 因为用户应该只在客户端启动或重新上线时看到它。
func (d *dialScheduler) logStats() {
	now := d.clock.Now()
	if d.lastStatsLog.Add(dialStatsLogInterval) > now {
		return
	}
	if d.dialPeers < dialStatsPeerLimit && d.dialPeers < d.maxDialPeers {
		d.log.Info("Looking for peers", "peercount", len(d.peers), "tried", d.doneSinceLastLog, "static", len(d.static))
	}
	d.doneSinceLastLog = 0
	d.lastStatsLog = now
}

// rearmHistoryTimer configures d.historyTimer to fire when the
// next item in d.history expires.
// rearmHistoryTimer 配置 d.historyTimer 以在 d.history 中的下一个项目过期时触发。
func (d *dialScheduler) rearmHistoryTimer() {
	if len(d.history) == 0 {
		return
	}
	d.historyTimer.Schedule(d.history.nextExpiry())
}

// expireHistory removes expired items from d.history.
// expireHistory 从 d.history 中移除过期的项目。
func (d *dialScheduler) expireHistory() {
	d.history.expire(d.clock.Now(), func(hkey string) {
		var id enode.ID
		copy(id[:], hkey)
		d.updateStaticPool(id)
	})
}

// freeDialSlots returns the number of free dial slots. The result can be negative
// when peers are connected while their task is still running.
// freeDialSlots 返回可用拨号槽位的数量。当 peer 连接时但其任务仍在运行时，结果可能为负。
func (d *dialScheduler) freeDialSlots() int {
	slots := (d.maxDialPeers - d.dialPeers) * 2
	if slots > d.maxActiveDials {
		slots = d.maxActiveDials
	}
	free := slots - len(d.dialing)
	return free
}

// checkDial returns an error if node n should not be dialed.
// checkDial 如果节点 n 不应该被拨号，则返回错误。
func (d *dialScheduler) checkDial(n *enode.Node) error {
	if n.ID() == d.self {
		return errSelf
	}
	if n.IPAddr().IsValid() && n.TCP() == 0 {
		// This check can trigger if a non-TCP node is found
		// by discovery. If there is no IP, the node is a static
		// node and the actual endpoint will be resolved later in dialTask.
		// 如果通过发现找到一个非 TCP 节点，则此检查可能会触发。
		// 如果没有 IP，则该节点是静态节点，实际端点将在 dialTask 中稍后解析。
		return errNoPort
	}
	if _, ok := d.dialing[n.ID()]; ok {
		return errAlreadyDialing
	}
	if _, ok := d.peers[n.ID()]; ok {
		return errAlreadyConnected
	}
	if d.netRestrict != nil && !d.netRestrict.ContainsAddr(n.IPAddr()) {
		return errNetRestrict
	}
	if d.history.contains(string(n.ID().Bytes())) {
		return errRecentlyDialed
	}
	return nil
}

// startStaticDials starts n static dial tasks.
// startStaticDials 启动 n 个静态拨号任务。
func (d *dialScheduler) startStaticDials(n int) (started int) {
	for started = 0; started < n && len(d.staticPool) > 0; started++ {
		idx := d.rand.Intn(len(d.staticPool))
		task := d.staticPool[idx]
		d.startDial(task)
		d.removeFromStaticPool(idx)
	}
	return started
}

// updateStaticPool attempts to move the given static dial back into staticPool.
// updateStaticPool 尝试将给定的静态拨号移回 staticPool。
func (d *dialScheduler) updateStaticPool(id enode.ID) {
	task, ok := d.static[id]
	if ok && task.staticPoolIndex < 0 && d.checkDial(task.dest()) == nil {
		d.addToStaticPool(task)
	}
}

func (d *dialScheduler) addToStaticPool(task *dialTask) {
	if task.staticPoolIndex >= 0 {
		panic("attempt to add task to staticPool twice")
	}
	d.staticPool = append(d.staticPool, task)
	task.staticPoolIndex = len(d.staticPool) - 1
}

// removeFromStaticPool removes the task at idx from staticPool. It does that by moving the
// current last element of the pool to idx and then shortening the pool by one.
// removeFromStaticPool 从 staticPool 中移除 idx 处的任务。
// 它通过将池中的当前最后一个元素移动到 idx 处，然后将池缩短一个来实现。
func (d *dialScheduler) removeFromStaticPool(idx int) {
	task := d.staticPool[idx]
	end := len(d.staticPool) - 1
	d.staticPool[idx] = d.staticPool[end]
	d.staticPool[idx].staticPoolIndex = idx
	d.staticPool[end] = nil
	d.staticPool = d.staticPool[:end]
	task.staticPoolIndex = -1
}

// dnsResolveHostname updates the given node from its DNS hostname.
// This is used to resolve static dial targets.
// dnsResolveHostname 从其 DNS 主机名更新给定节点。这用于解析静态拨号目标。
func (d *dialScheduler) dnsResolveHostname(n *enode.Node) (*enode.Node, error) {
	if n.Hostname() == "" {
		return n, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	foundIPs, err := d.dnsLookupFunc(ctx, "ip", n.Hostname())
	if err != nil {
		return n, err
	}

	// Check for IP updates.
	// 检查 IP 更新。
	var (
		nodeIP4, nodeIP6   netip.Addr
		foundIP4, foundIP6 netip.Addr
	)
	n.Load((*enr.IPv4Addr)(&nodeIP4))
	n.Load((*enr.IPv6Addr)(&nodeIP6))
	for _, ip := range foundIPs {
		if ip.Is4() && !foundIP4.IsValid() {
			foundIP4 = ip
		}
		if ip.Is6() && !foundIP6.IsValid() {
			foundIP6 = ip
		}
	}

	if !foundIP4.IsValid() && !foundIP6.IsValid() {
		// Lookup failed.
		// 查找失败。
		return n, errNoResolvedIP
	}
	if foundIP4 == nodeIP4 && foundIP6 == nodeIP6 {
		// No updates necessary.
		// 不需要更新。
		d.log.Trace("Node DNS lookup had no update", "id", n.ID(), "name", n.Hostname(), "ip", foundIP4, "ip6", foundIP6)
		return n, nil
	}

	// Update the node. Note this invalidates the ENR signature, because we use SignNull
	// to create a modified copy. But this should be OK, since we just use the node as a
	// dial target. And nodes will usually only have a DNS hostname if they came from a
	// enode:// URL, which has no signature anyway. If it ever becomes a problem, the
	// resolved IP could also be stored into dialTask instead of the node.
	// 更新节点。注意，这会使 ENR 签名无效，因为我们使用 SignNull 创建修改后的副本。
	// 但这应该没问题，因为我们只是将节点用作拨号目标。
	// 而且节点通常只有在来自 enode:// URL 时才会有 DNS 主机名，而 enode:// URL 本身就没有签名。
	// 如果这成为问题，解析的 IP 也可以存储到 dialTask 中而不是节点中。
	rec := n.Record()
	if foundIP4.IsValid() {
		rec.Set(enr.IPv4Addr(foundIP4))
	}
	if foundIP6.IsValid() {
		rec.Set(enr.IPv6Addr(foundIP6))
	}
	rec.SetSeq(n.Seq()) // ensure seq not bumped by update // 确保 seq 不会因更新而增加
	newNode := enode.SignNull(rec, n.ID()).WithHostname(n.Hostname())
	d.log.Debug("Node updated from DNS lookup", "id", n.ID(), "name", n.Hostname(), "ip", newNode.IP())
	return newNode, nil
}

// startDial runs the given dial task in a separate goroutine.
// startDial 在单独的 goroutine 中运行给定的拨号任务。
func (d *dialScheduler) startDial(task *dialTask) {
	node := task.dest()
	d.log.Trace("Starting p2p dial", "id", node.ID(), "endpoint", nodeEndpointForLog(node), "flag", task.flags)
	hkey := string(node.ID().Bytes())
	d.history.add(hkey, d.clock.Now().Add(dialHistoryExpiration))
	d.dialing[node.ID()] = task
	go func() {
		task.run(d)
		d.doneCh <- task
	}()
}

// A dialTask generated for each node that is dialed.
// 为每个拨号的节点生成一个 dialTask。
type dialTask struct {
	staticPoolIndex int
	flags           connFlag

	// These fields are private to the task and should not be
	// accessed by dialScheduler while the task is running.
	// 这些字段是任务私有的，在任务运行时不应被 dialScheduler 访问。
	destPtr      atomic.Pointer[enode.Node]
	lastResolved mclock.AbsTime
	resolveDelay time.Duration
}

func newDialTask(dest *enode.Node, flags connFlag) *dialTask {
	t := &dialTask{flags: flags, staticPoolIndex: -1}
	t.destPtr.Store(dest)
	return t
}

type dialError struct {
	error
}

func (t *dialTask) dest() *enode.Node {
	return t.destPtr.Load()
}

func (t *dialTask) run(d *dialScheduler) {
	if t.isStatic() {
		// Resolve DNS.
		// 解析 DNS。
		if n := t.dest(); n.Hostname() != "" {
			resolved, err := d.dnsResolveHostname(n)
			if err != nil {
				d.log.Warn("DNS lookup of static node failed", "id", n.ID(), "name", n.Hostname(), "err", err)
			} else {
				t.destPtr.Store(resolved)
			}
		}
		// Try resolving node ID through the DHT if there is no IP address.
		// 如果没有 IP 地址，尝试通过 DHT 解析节点 ID。
		if !t.dest().IPAddr().IsValid() {
			if !t.resolve(d) {
				return // DHT resolve failed, skip dial. // DHT 解析失败，跳过拨号。
			}
		}
	}

	err := t.dial(d, t.dest())
	if err != nil {
		// For static nodes, resolve one more time if dialing fails.
		// 对于静态节点，如果拨号失败，再解析一次。
		var dialErr *dialError
		if errors.As(err, &dialErr) && t.isStatic() {
			if t.resolve(d) {
				t.dial(d, t.dest())
			}
		}
	}
}

func (t *dialTask) isStatic() bool {
	return t.flags&staticDialedConn != 0
}

// resolve attempts to find the current endpoint for the destination
// using discovery.
// Resolve operations are throttled with backoff to avoid flooding the
// discovery network with useless queries for nodes that don't exist.
// The backoff delay resets when the node is found.
// resolve 尝试使用发现来查找目标的当前端点。
// 解析操作会通过退避进行节流，以避免用无用的查询淹没发现网络。
// 当节点被找到时，退避延迟重置。
func (t *dialTask) resolve(d *dialScheduler) bool {
	if d.resolver == nil {
		return false
	}
	if t.resolveDelay == 0 {
		t.resolveDelay = initialResolveDelay
	}
	if t.lastResolved > 0 && time.Duration(d.clock.Now()-t.lastResolved) < t.resolveDelay {
		return false
	}

	node := t.dest()
	resolved := d.resolver.Resolve(node)
	t.lastResolved = d.clock.Now()
	if resolved == nil {
		t.resolveDelay *= 2
		if t.resolveDelay > maxResolveDelay {
			t.resolveDelay = maxResolveDelay
		}
		d.log.Debug("Resolving node failed", "id", node.ID(), "newdelay", t.resolveDelay)
		return false
	}
	// The node was found.
	// 节点被找到。
	t.resolveDelay = initialResolveDelay
	t.destPtr.Store(resolved)
	resAddr, _ := resolved.TCPEndpoint()
	d.log.Debug("Resolved node", "id", resolved.ID(), "addr", resAddr)
	return true
}

// dial performs the actual connection attempt.
// dial 执行实际的连接尝试。
func (t *dialTask) dial(d *dialScheduler, dest *enode.Node) error {
	dialMeter.Mark(1)
	fd, err := d.dialer.Dial(d.ctx, dest)
	if err != nil {
		addr, _ := dest.TCPEndpoint()
		d.log.Trace("Dial error", "id", dest.ID(), "addr", addr, "conn", t.flags, "err", cleanupDialErr(err))
		dialConnectionError.Mark(1)
		return &dialError{err}
	}
	return d.setupFunc(newMeteredConn(fd), t.flags, dest)
}

func (t *dialTask) String() string {
	node := t.dest()
	id := node.ID()
	return fmt.Sprintf("%v %x %v:%d", t.flags, id[:8], node.IPAddr(), node.TCP())
}

func cleanupDialErr(err error) error {
	if netErr, ok := err.(*net.OpError); ok && netErr.Op == "dial" {
		return netErr.Err
	}
	return err
}

func nodeEndpointForLog(n *enode.Node) string {
	if n.Hostname() != "" {
		return n.Hostname()
	}
	return n.IPAddr().String()
}
