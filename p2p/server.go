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

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	defaultDialTimeout = 15 * time.Second // 默认拨号超时时间

	// This is the fairness knob for the discovery mixer. When looking for peers, we'll
	// wait this long for a single source of candidates before moving on and trying other
	// sources.
	// 这是发现混合器的公平旋钮。在寻找对等方时，我们会等待单一候选源这么长时间，然后再尝试其他源。
	discmixTimeout = 5 * time.Second

	// Connectivity defaults.
	// 连接性默认值。
	defaultMaxPendingPeers = 50 // 默认最大挂起对等方数量
	defaultDialRatio       = 3  // 默认拨号比例

	// This time limits inbound connection attempts per source IP.
	// 此时间限制每个源 IP 的入站连接尝试。
	inboundThrottleTime = 30 * time.Second

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	// 读取完整消息允许的最长时间。
	// 这实际上是连接可以空闲的时间。
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	// 写入完整消息允许的最长时间。
	frameWriteTimeout = 20 * time.Second
)

var (
	errServerStopped       = errors.New("server stopped")   // 服务器已停止
	errEncHandshakeError   = errors.New("rlpx enc error")   // RLPx 加密错误
	errProtoHandshakeError = errors.New("rlpx proto error") // RLPx 协议错误
)

// Config holds Server options.
// Config 包含服务器选项。
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	// 此字段必须设置为有效的 secp256k1 私钥。
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	// MaxPeers 是可以连接的最大对等方数量。必须大于零。
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	// MaxPendingPeers 是在握手阶段可以挂起的最大对等方数量，入站和出站连接分别计数。
	// 零默认使用预设值。
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	// DialRatio 控制入站连接与拨号连接的比例。
	// 例如：DialRatio 为 2 允许 1/2 的连接被拨号。
	// 将 DialRatio 设置为零默认使用 3。
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	// NoDiscovery 可用于禁用对等方发现机制。
	// 禁用对于协议调试（手动拓扑）很有用。
	NoDiscovery bool

	// DiscoveryV4 specifies whether V4 discovery should be started.
	// DiscoveryV4 指定是否应启动 V4 发现。
	DiscoveryV4 bool `toml:",omitempty"`

	// DiscoveryV5 specifies whether the new topic-discovery based V5 discovery
	// protocol should be started or not.
	// DiscoveryV5 指定是否应启动新的基于主题发现的 V5 发现协议。
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Name 设置此服务器的节点名称。
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	// BootstrapNodes 用于与网络的其余部分建立连接。
	BootstrapNodes []*enode.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	// BootstrapNodesV5 用于使用 V5 发现协议与网络的其余部分建立连接。
	BootstrapNodesV5 []*enode.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	// 静态节点用作预配置的连接，始终保持并在断开连接时重新连接。
	StaticNodes []*enode.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	// 受信任节点用作预配置的连接，始终允许连接，即使超过对等方限制。
	TrustedNodes []*enode.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	// 连接性可以限制到某些 IP 网络。
	// 如果此选项设置为非 nil 值，则仅考虑与列表中包含的 IP 网络之一匹配的主机。
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	// NodeDatabase 是包含网络中先前看到的活动节点的数据库的路径。
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	// Protocols 应包含服务器支持的协议。
	// 为每个对等方启动匹配的协议。
	Protocols []Protocol `toml:"-" json:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	// 如果 ListenAddr 设置为非 nil 地址，服务器将监听传入连接。
	//
	// 如果端口为零，操作系统将选择一个端口。
	// 服务器启动时，ListenAddr 字段将更新为实际地址。
	ListenAddr string

	// If DiscAddr is set to a non-nil value, the server will use ListenAddr
	// for TCP and DiscAddr for the UDP discovery protocol.
	// 如果 DiscAddr 设置为非 nil 值，服务器将为 TCP 使用 ListenAddr，为 UDP 发现协议使用 DiscAddr。
	DiscAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	// 如果设置为非 nil 值，则使用给定的 NAT 端口映射器使监听端口可用于 Internet。
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	// 如果 Dialer 设置为非 nil 值，则使用给定的 Dialer 拨号出站对等方连接。
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	// 如果 NoDial 为 true，服务器将不拨号任何对等方。
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	// 如果 EnableMsgEvents 设置，则服务器将在向对等方发送或从对等方接收消息时发出 PeerEvents
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	// Logger 是与 p2p.Server 一起使用的自定义记录器。
	Logger log.Logger `toml:",omitempty"`

	clock mclock.Clock
}

// Server manages all peer connections.
// Server 管理所有对等方连接。
type Server struct {
	// Config fields may not be modified while the server is running.
	// 在服务器运行时，Config 字段不可修改。
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	// 测试钩子。这些很有用，因为我们可以禁止整个协议栈。
	newTransport func(net.Conn, *ecdsa.PublicKey) transport
	newPeerHook  func(*Peer)
	listenFunc   func(network, addr string) (net.Listener, error)

	lock    sync.Mutex // protects running // 保护 running
	running bool

	listener     net.Listener
	ourHandshake *protoHandshake
	loopWG       sync.WaitGroup // loop, listenLoop // 主循环和监听循环
	peerFeed     event.Feed
	log          log.Logger

	nodedb    *enode.DB
	localnode *enode.LocalNode
	discv4    *discover.UDPv4
	discv5    *discover.UDPv5
	discmix   *enode.FairMix
	dialsched *dialScheduler

	// This is read by the NAT port mapping loop.
	// NAT 端口映射循环读取此通道。
	portMappingRegister chan *portMapping

	// Channels into the run loop.
	// 进入 run 循环的通道。
	quit                    chan struct{}
	addtrusted              chan *enode.Node
	removetrusted           chan *enode.Node
	peerOp                  chan peerOpFunc
	peerOpDone              chan struct{}
	delpeer                 chan peerDrop
	checkpointPostHandshake chan *conn
	checkpointAddPeer       chan *conn

	// State of run loop and listenLoop.
	// run 循环和 listenLoop 的状态。
	inboundHistory expHeap
}

type peerOpFunc func(map[enode.ID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer // 如果由对等方发出信号，则为 true
}

type connFlag int32

const (
	dynDialedConn    connFlag = 1 << iota // 动态拨号连接
	staticDialedConn                      // 静态拨号连接
	inboundConn                           // 入站连接
	trustedConn                           // 受信任连接
)

// conn wraps a network connection with information gathered
// during the two handshakes.
// conn 用两次握手期间收集的信息包装网络连接。
type conn struct {
	fd net.Conn
	transport
	node  *enode.Node
	flags connFlag
	cont  chan error // The run loop uses cont to signal errors to SetupConn. // run 循环使用 cont 向 SetupConn 发出错误信号。
	caps  []Cap      // valid after the protocol handshake // 协议握手后有效
	name  string     // valid after the protocol handshake // 协议握手后有效
}

type transport interface {
	// The two handshakes.
	// 两次握手。
	doEncHandshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	// 加密握手完成后才能使用 MsgReadWriter。代码通过在加密握手后将 conn.id 设置为非 nil 值来跟踪这一点。
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because MsgPipe doesn't use it.
	// transports 必须提供 Close，因为我们在一些测试中使用 MsgPipe。关闭实际的网络连接在这些测试中不起作用，因为 MsgPipe 不使用它。
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.node.ID() != enode.ID{}) {
		s += " " + c.node.ID().String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}

func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}

// LocalNode returns the local node record.
// LocalNode 返回本地节点记录。
func (srv *Server) LocalNode() *enode.LocalNode {
	return srv.localnode
}

// Peers returns all connected peers.
// Peers 返回所有连接的对等方。
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	})
	return ps
}

// PeerCount returns the number of connected peers.
// PeerCount 返回连接的对等方数量。
func (srv *Server) PeerCount() int {
	var count int
	srv.doPeerOp(func(ps map[enode.ID]*Peer) {
		count = len(ps)
	})
	return count
}

// AddPeer adds the given node to the static node set. When there is room in the peer set,
// the server will connect to the node. If the connection fails for any reason, the server
// will attempt to reconnect the peer.
// AddPeer 将给定节点添加到静态节点集。当对等方集中有空间时，
// 服务器将连接到该节点。如果连接因任何原因失败，服务器将尝试重新连接对等方。
func (srv *Server) AddPeer(node *enode.Node) {
	srv.dialsched.addStatic(node)
}

// RemovePeer removes a node from the static node set. It also disconnects from the given
// node if it is currently connected as a peer.
//
// This method blocks until all protocols have exited and the peer is removed. Do not use
// RemovePeer in protocol implementations, call Disconnect on the Peer instead.
// RemovePeer 从静态节点集中移除节点。如果该节点当前作为对等方连接，也会断开连接。
//
// 此方法会阻塞，直到所有协议退出且对等方被移除。不要在协议实现中使用 RemovePeer，而是调用 Peer 上的 Disconnect。
func (srv *Server) RemovePeer(node *enode.Node) {
	var (
		ch  chan *PeerEvent
		sub event.Subscription
	)
	// Disconnect the peer on the main loop.
	// 在主循环上断开对等方连接。
	srv.doPeerOp(func(peers map[enode.ID]*Peer) {
		srv.dialsched.removeStatic(node)
		if peer := peers[node.ID()]; peer != nil {
			ch = make(chan *PeerEvent, 1)
			sub = srv.peerFeed.Subscribe(ch)
			peer.Disconnect(DiscRequested)
		}
	})
	// Wait for the peer connection to end.
	// 等待对等方连接结束。
	if ch != nil {
		defer sub.Unsubscribe()
		for ev := range ch {
			if ev.Peer == node.ID() && ev.Type == PeerEventTypeDrop {
				return
			}
		}
	}
}

// AddTrustedPeer adds the given node to a reserved trusted list which allows the
// node to always connect, even if the slot are full.
// AddTrustedPeer 将给定节点添加到保留的受信任列表中，允许节点始终连接，即使插槽已满。
func (srv *Server) AddTrustedPeer(node *enode.Node) {
	select {
	case srv.addtrusted <- node:
	case <-srv.quit:
	}
}

// RemoveTrustedPeer removes the given node from the trusted peer set.
// RemoveTrustedPeer 从受信任对等方集中移除给定节点。
func (srv *Server) RemoveTrustedPeer(node *enode.Node) {
	select {
	case srv.removetrusted <- node:
	case <-srv.quit:
	}
}

// SubscribeEvents subscribes the given channel to peer events
// SubscribeEvents 将给定通道订阅到对等方事件
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
// Self 返回本地节点的端点信息。
func (srv *Server) Self() *enode.Node {
	srv.lock.Lock()
	ln := srv.localnode
	srv.lock.Unlock()

	if ln == nil {
		return enode.NewV4(&srv.PrivateKey.PublicKey, net.ParseIP("0.0.0.0"), 0, 0)
	}
	return ln.Node()
}

// DiscoveryV4 returns the discovery v4 instance, if configured.
// DiscoveryV4 返回配置的 discovery v4 实例。
func (srv *Server) DiscoveryV4() *discover.UDPv4 {
	return srv.discv4
}

// DiscoveryV5 returns the discovery v5 instance, if configured.
// DiscoveryV5 返回配置的 discovery v5 实例。
func (srv *Server) DiscoveryV5() *discover.UDPv5 {
	return srv.discv5
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
// Stop 终止服务器和所有活动对等方连接。
// 它会阻塞，直到所有活动连接都已关闭。
func (srv *Server) Stop() {
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		// 这解除 listener Accept 的阻塞
		srv.listener.Close()
	}
	close(srv.quit)
	srv.lock.Unlock()
	srv.loopWG.Wait()
}

// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
// sharedUDPConn 实现共享连接。Write 将消息发送到底层连接，而 read 返回被发现无法处理并由主监听器发送到 unhandled 通道的消息。
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDPAddrPort implements discover.UDPConn
// ReadFromUDPAddrPort 实现 discover.UDPConn
func (s *sharedUDPConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, netip.AddrPort{}, errors.New("connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discover.UDPConn
// Close 实现 discover.UDPConn
func (s *sharedUDPConn) Close() error {
	return nil
}

// Start starts running the server.
// Servers can not be re-used after stopping.
// Start 开始运行服务器。
// 服务器在停止后不能重复使用。
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Logger
	if srv.log == nil {
		srv.log = log.Root()
	}
	if srv.clock == nil {
		srv.clock = mclock.System{}
	}
	if srv.NoDial && srv.ListenAddr == "" {
		srv.log.Warn("P2P server will be useless, neither dialing nor listening")
	}

	// static fields
	if srv.PrivateKey == nil {
		return errors.New("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.listenFunc == nil {
		srv.listenFunc = net.Listen
	}
	srv.quit = make(chan struct{})
	srv.delpeer = make(chan peerDrop)
	srv.checkpointPostHandshake = make(chan *conn)
	srv.checkpointAddPeer = make(chan *conn)
	srv.addtrusted = make(chan *enode.Node)
	srv.removetrusted = make(chan *enode.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})

	if err := srv.setupLocalNode(); err != nil {
		return err
	}
	srv.setupPortMapping()

	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			return err
		}
	}
	if err := srv.setupDiscovery(); err != nil {
		return err
	}
	srv.setupDialScheduler()

	srv.loopWG.Add(1)
	go srv.run()
	return nil
}

func (srv *Server) setupLocalNode() error {
	// Create the devp2p handshake.
	// 创建 devp2p 握手。
	pubkey := crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: pubkey[1:]}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}
	slices.SortFunc(srv.ourHandshake.Caps, Cap.Cmp)

	// Create the local node.
	// 创建本地节点。
	db, err := enode.OpenDB(srv.NodeDatabase)
	if err != nil {
		return err
	}
	srv.nodedb = db
	srv.localnode = enode.NewLocalNode(db, srv.PrivateKey)
	srv.localnode.SetFallbackIP(net.IP{127, 0, 0, 1})
	// TODO: check conflicts
	for _, p := range srv.Protocols {
		for _, e := range p.Attributes {
			srv.localnode.Set(e)
		}
	}
	return nil
}

func (srv *Server) setupDiscovery() error {
	srv.discmix = enode.NewFairMix(discmixTimeout)

	// Don't listen on UDP endpoint if DHT is disabled.
	// 如果 DHT 被禁用，则不在 UDP 端点上监听。
	if srv.NoDiscovery {
		return nil
	}
	conn, err := srv.setupUDPListening()
	if err != nil {
		return err
	}

	var (
		sconn     discover.UDPConn = conn
		unhandled chan discover.ReadPacket
	)
	// If both versions of discovery are running, setup a shared
	// connection, so v5 can read unhandled messages from v4.
	// 如果两个版本的发现都在运行，设置共享连接，以便 v5 可以从 v4 读取未处理的消息。
	if srv.Config.DiscoveryV4 && srv.Config.DiscoveryV5 {
		unhandled = make(chan discover.ReadPacket, 100)
		sconn = &sharedUDPConn{conn, unhandled}
	}

	// Start discovery services.
	// 启动发现服务。
	if srv.Config.DiscoveryV4 {
		cfg := discover.Config{
			PrivateKey:  srv.PrivateKey,
			NetRestrict: srv.NetRestrict,
			Bootnodes:   srv.BootstrapNodes,
			Unhandled:   unhandled,
			Log:         srv.log,
		}
		ntab, err := discover.ListenV4(conn, srv.localnode, cfg)
		if err != nil {
			return err
		}
		srv.discv4 = ntab
		srv.discmix.AddSource(ntab.RandomNodes())
	}
	if srv.Config.DiscoveryV5 {
		cfg := discover.Config{
			PrivateKey:  srv.PrivateKey,
			NetRestrict: srv.NetRestrict,
			Bootnodes:   srv.BootstrapNodesV5,
			Log:         srv.log,
		}
		srv.discv5, err = discover.ListenV5(sconn, srv.localnode, cfg)
		if err != nil {
			return err
		}
	}

	// Add protocol-specific discovery sources.
	// 添加协议特定的发现源。
	added := make(map[string]bool)
	for _, proto := range srv.Protocols {
		if proto.DialCandidates != nil && !added[proto.Name] {
			srv.discmix.AddSource(proto.DialCandidates)
			added[proto.Name] = true
		}
	}
	return nil
}

func (srv *Server) setupDialScheduler() {
	config := dialConfig{
		self:           srv.localnode.ID(),
		maxDialPeers:   srv.maxDialedConns(),
		maxActiveDials: srv.MaxPendingPeers,
		log:            srv.Logger,
		netRestrict:    srv.NetRestrict,
		dialer:         srv.Dialer,
		clock:          srv.clock,
	}
	if srv.discv4 != nil {
		config.resolver = srv.discv4
	}
	if config.dialer == nil {
		config.dialer = tcpDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	srv.dialsched = newDialScheduler(config, srv.discmix, srv.SetupConn)
	for _, n := range srv.StaticNodes {
		srv.dialsched.addStatic(n)
	}
}

func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}

func (srv *Server) maxDialedConns() (limit int) {
	if srv.NoDial || srv.MaxPeers == 0 {
		return 0
	}
	if srv.DialRatio == 0 {
		limit = srv.MaxPeers / defaultDialRatio
	} else {
		limit = srv.MaxPeers / srv.DialRatio
	}
	if limit == 0 {
		limit = 1
	}
	return limit
}

func (srv *Server) setupListening() error {
	// Launch the listener.
	// 启动监听器。
	listener, err := srv.listenFunc("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	srv.listener = listener
	srv.ListenAddr = listener.Addr().String()

	// Update the local node record and map the TCP listening port if NAT is configured.
	// 更新本地节点记录，如果配置了 NAT，则映射 TCP 监听端口。
	tcp, isTCP := listener.Addr().(*net.TCPAddr)
	if isTCP {
		srv.localnode.Set(enr.TCP(tcp.Port))
		if !tcp.IP.IsLoopback() && !tcp.IP.IsPrivate() {
			srv.portMappingRegister <- &portMapping{
				protocol: "TCP",
				name:     "ethereum p2p",
				port:     tcp.Port,
			}
		}
	}

	srv.loopWG.Add(1)
	go srv.listenLoop()
	return nil
}

func (srv *Server) setupUDPListening() (*net.UDPConn, error) {
	listenAddr := srv.ListenAddr

	// Use an alternate listening address for UDP if
	// a custom discovery address is configured.
	// 如果配置了自定义发现地址，则为 UDP 使用备用监听地址。
	if srv.DiscAddr != "" {
		listenAddr = srv.DiscAddr
	}
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	laddr := conn.LocalAddr().(*net.UDPAddr)
	srv.localnode.SetFallbackUDP(laddr.Port)
	srv.log.Debug("UDP listener up", "addr", laddr)
	if !laddr.IP.IsLoopback() && !laddr.IP.IsPrivate() {
		srv.portMappingRegister <- &portMapping{
			protocol: "UDP",
			name:     "ethereum peer discovery",
			port:     laddr.Port,
		}
	}

	return conn, nil
}

// doPeerOp runs fn on the main loop.
// doPeerOp 在主循环上运行 fn。
func (srv *Server) doPeerOp(fn peerOpFunc) {
	select {
	case srv.peerOp <- fn:
		<-srv.peerOpDone
	case <-srv.quit:
	}
}

// run is the main loop of the server.
// run 是服务器的主循环。
func (srv *Server) run() {
	srv.log.Info("Started P2P networking", "self", srv.localnode.Node().URLv4())
	defer srv.loopWG.Done()
	defer srv.nodedb.Close()
	defer srv.discmix.Close()
	defer srv.dialsched.stop()

	var (
		peers        = make(map[enode.ID]*Peer)
		inboundCount = 0
		trusted      = make(map[enode.ID]bool, len(srv.TrustedNodes))
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	// 将受信任节点放入地图以加速检查。
	// 受信任对等方在启动时加载或通过 AddTrustedPeer RPC 添加。
	for _, n := range srv.TrustedNodes {
		trusted[n.ID()] = true
	}

running:
	for {
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			// 服务器已停止。运行清理逻辑。
			break running

		case n := <-srv.addtrusted:
			// This channel is used by AddTrustedPeer to add a node
			// to the trusted node set.
			// 此通道由 AddTrustedPeer 使用，以将节点添加到受信任节点集。
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID()] = true
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, true)
			}

		case n := <-srv.removetrusted:
			// This channel is used by RemoveTrustedPeer to remove a node
			// from the trusted node set.
			// 此通道由 RemoveTrustedPeer 使用，以从受信任节点集中移除节点。
			srv.log.Trace("Removing trusted node", "node", n)
			delete(trusted, n.ID())
			if p, ok := peers[n.ID()]; ok {
				p.rw.set(trustedConn, false)
			}

		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			// 此通道由 Peers 和 PeerCount 使用。
			op(peers)
			srv.peerOpDone <- struct{}{}

		case c := <-srv.checkpointPostHandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			// 连接已通过加密握手，因此远程身份已知（但尚未验证）。
			if trusted[c.node.ID()] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				// 在检查 MaxPeers 之前确保设置了受信任标志。
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			// TODO: 跟踪进行中的入站节点 ID（pre-Peer）以避免拨号它们。
			c.cont <- srv.postHandshakeChecks(peers, inboundCount, c)

		case c := <-srv.checkpointAddPeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			// 此时连接已通过协议握手。
			// 其功能已知且远程身份已验证。
			err := srv.addPeerChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				// 握手完成且通过所有检查。
				p := srv.launchPeer(c)
				peers[c.node.ID()] = p
				srv.log.Debug("Adding p2p peer", "peercount", len(peers), "id", p.ID(), "conn", c.flags, "addr", p.RemoteAddr(), "name", p.Name())
				srv.dialsched.peerAdded(c)
				if p.Inbound() {
					inboundCount++
					serveSuccessMeter.Mark(1)
					activeInboundPeerGauge.Inc(1)
				} else {
					dialSuccessMeter.Mark(1)
					activeOutboundPeerGauge.Inc(1)
				}
				activePeerGauge.Inc(1)
			}
			c.cont <- err

		case pd := <-srv.delpeer:
			// A peer disconnected.
			// 对等方断开连接。
			d := common.PrettyDuration(mclock.Now() - pd.created)
			delete(peers, pd.ID())
			srv.log.Debug("Removing p2p peer", "peercount", len(peers), "id", pd.ID(), "duration", d, "req", pd.requested, "err", pd.err)
			srv.dialsched.peerRemoved(pd.rw)
			if pd.Inbound() {
				inboundCount--
				activeInboundPeerGauge.Dec(1)
			} else {
				activeOutboundPeerGauge.Dec(1)
			}
			activePeerGauge.Dec(1)
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	// 终止发现。如果有正在运行的查找，它将很快终止。
	if srv.discv4 != nil {
		srv.discv4.Close()
	}
	if srv.discv5 != nil {
		srv.discv5.Close()
	}
	// Disconnect all peers.
	// 断开所有对等方。
	for _, p := range peers {
		p.Disconnect(DiscQuitting)
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	// 等待对等方关闭。挂起的连接和任务在此处不处理，并将很快终止，因为 srv.quit 已关闭。
	for len(peers) > 0 {
		p := <-srv.delpeer
		p.log.Trace("<-delpeer (spindown)")
		delete(peers, p.ID())
	}
}

func (srv *Server) postHandshakeChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	switch {
	case !c.is(trustedConn) && len(peers) >= srv.MaxPeers:
		return DiscTooManyPeers
	case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
		return DiscTooManyPeers
	case peers[c.node.ID()] != nil:
		return DiscAlreadyConnected
	case c.node.ID() == srv.localnode.ID():
		return DiscSelf
	default:
		return nil
	}
}

func (srv *Server) addPeerChecks(peers map[enode.ID]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	// 丢弃没有匹配协议的连接。
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the post-handshake checks because the
	// peer set might have changed since those checks were performed.
	// 重复握手后检查，因为自执行这些检查以来，对等方集可能已更改。
	return srv.postHandshakeChecks(peers, inboundCount, c)
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
// listenLoop 在自己的 goroutine 中运行并接受入站连接。
func (srv *Server) listenLoop() {
	srv.log.Debug("TCP listener up", "addr", srv.listener.Addr())

	// The slots channel limits accepts of new connections.
	// slots 通道限制新连接的接受。
	tokens := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	// Wait for slots to be returned on exit. This ensures all connection goroutines
	// are down before listenLoop returns.
	// 等待退出时返回 slots。这确保在 listenLoop 返回之前所有连接 goroutine 都已关闭。
	defer srv.loopWG.Done()
	defer func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	}()

	for {
		// Wait for a free slot before accepting.
		// 在接受之前等待空闲槽。
		<-slots

		var (
			fd      net.Conn
			err     error
			lastLog time.Time
		)
		for {
			fd, err = srv.listener.Accept()
			if netutil.IsTemporaryError(err) {
				if time.Since(lastLog) > 1*time.Second {
					srv.log.Debug("Temporary read error", "err", err)
					lastLog = time.Now()
				}
				time.Sleep(time.Millisecond * 200)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				slots <- struct{}{}
				return
			}
			break
		}

		remoteIP := netutil.AddrAddr(fd.RemoteAddr())
		if err := srv.checkInboundConn(remoteIP); err != nil {
			srv.log.Debug("Rejected inbound connection", "addr", fd.RemoteAddr(), "err", err)
			fd.Close()
			slots <- struct{}{}
			continue
		}
		if remoteIP.IsValid() {
			fd = newMeteredConn(fd)
			serveMeter.Mark(1)
			srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		}
		go func() {
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}

func (srv *Server) checkInboundConn(remoteIP netip.Addr) error {
	if !remoteIP.IsValid() {
		// This case happens for internal test connections without remote address.
		// 这种情况发生在没有远程地址的内部测试连接。
		return nil
	}
	// Reject connections that do not match NetRestrict.
	// 拒绝不匹配 NetRestrict 的连接。
	if srv.NetRestrict != nil && !srv.NetRestrict.ContainsAddr(remoteIP) {
		return errors.New("not in netrestrict list")
	}
	// Reject Internet peers that try too often.
	// 拒绝尝试过于频繁的 Internet 对等方。
	now := srv.clock.Now()
	srv.inboundHistory.expire(now, nil)
	if !netutil.AddrIsLAN(remoteIP) && srv.inboundHistory.contains(remoteIP.String()) {
		return errors.New("too many attempts")
	}
	srv.inboundHistory.add(remoteIP.String(), now.Add(inboundThrottleTime))
	return nil
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
// SetupConn 运行握手并尝试将连接添加为对等方。
// 当连接已添加为对等方或握手失败时返回。
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *enode.Node) error {
	c := &conn{fd: fd, flags: flags, cont: make(chan error)}
	if dialDest == nil {
		c.transport = srv.newTransport(fd, nil)
	} else {
		c.transport = srv.newTransport(fd, dialDest.Pubkey())
	}

	err := srv.setupConn(c, dialDest)
	if err != nil {
		if !c.is(inboundConn) {
			markDialError(err)
		}
		c.close(err)
	}
	return err
}

func (srv *Server) setupConn(c *conn, dialDest *enode.Node) error {
	// Prevent leftover pending conns from entering the handshake.
	// 防止剩余的挂起连接进入握手。
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}

	// If dialing, figure out the remote public key.
	// 如果正在拨号，找出远程公钥。
	if dialDest != nil {
		dialPubkey := new(ecdsa.PublicKey)
		if err := dialDest.Load((*enode.Secp256k1)(dialPubkey)); err != nil {
			err = fmt.Errorf("%w: dial destination doesn't have a secp256k1 public key", errEncHandshakeError)
			srv.log.Trace("Setting up connection failed", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
			return err
		}
	}

	// Run the RLPx handshake.
	// 运行 RLPx 握手。
	remotePubkey, err := c.doEncHandshake(srv.PrivateKey)
	if err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return fmt.Errorf("%w: %v", errEncHandshakeError, err)
	}
	if dialDest != nil {
		c.node = dialDest
	} else {
		c.node = nodeFromConn(remotePubkey, c.fd)
	}
	clog := srv.log.New("id", c.node.ID(), "addr", c.fd.RemoteAddr(), "conn", c.flags)
	err = srv.checkpoint(c, srv.checkpointPostHandshake)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	// Run the capability negotiation handshake.
	// 运行能力协商握手。
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed p2p handshake", "err", err)
		return fmt.Errorf("%w: %v", errProtoHandshakeError, err)
	}
	if id := c.node.ID(); !bytes.Equal(crypto.Keccak256(phs.ID), id[:]) {
		clog.Trace("Wrong devp2p handshake identity", "phsid", hex.EncodeToString(phs.ID))
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.checkpointAddPeer)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}

	return nil
}

func nodeFromConn(pubkey *ecdsa.PublicKey, conn net.Conn) *enode.Node {
	var ip net.IP
	var port int
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = tcp.IP
		port = tcp.Port
	}
	return enode.NewV4(pubkey, ip, port, port)
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
// checkpoint 将 conn 发送到 run，run 执行阶段（posthandshake, addpeer）的握手后检查。
func (srv *Server) checkpoint(c *conn, stage chan<- *conn) error {
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	}
	return <-c.cont
}

func (srv *Server) launchPeer(c *conn) *Peer {
	p := newPeer(srv.log, c, srv.Protocols)
	if srv.EnableMsgEvents {
		// If message events are enabled, pass the peerFeed
		// to the peer.
		// 如果启用了消息事件，将 peerFeed 传递给对等方。
		p.events = &srv.peerFeed
	}
	go srv.runPeer(p)
	return p
}

// runPeer runs in its own goroutine for each peer.
// runPeer 为每个对等方在自己的 goroutine 中运行。
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeAdd,
		Peer:          p.ID(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})

	// Run the per-peer main loop.
	// 运行每个对等方的主循环。
	remoteRequested, err := p.run()

	// Announce disconnect on the main loop to update the peer set.
	// The main loop waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	// 在主循环上宣布断开连接以更新对等方集。
	// 主循环等待现有对等方在 srv.delpeer 上发送后才返回，因此此发送不应在 srv.quit 上选择。
	srv.delpeer <- peerDrop{p, err, remoteRequested}

	// Broadcast peer drop to external subscribers. This needs to be
	// after the send to delpeer so subscribers have a consistent view of
	// the peer set (i.e. Server.Peers() doesn't include the peer when the
	// event is received).
	// 向外部订阅者广播对等方丢弃。这需要在发送到 delpeer 之后，以便订阅者对对等方集有一致的视图（即 Server.Peers() 在接收到事件时不包括该对等方）。
	srv.peerFeed.Send(&PeerEvent{
		Type:          PeerEventTypeDrop,
		Peer:          p.ID(),
		Error:         err.Error(),
		RemoteAddress: p.RemoteAddr().String(),
		LocalAddress:  p.LocalAddr().String(),
	})
}

// NodeInfo represents a short summary of the information known about the host.
// NodeInfo 表示有关主机的已知信息的简短摘要。
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key) // 唯一节点标识符（也是加密密钥）
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data // 节点名称，包括客户端类型、版本、操作系统、自定义数据
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers // Enode URL，用于从远程对等方添加此对等方
	ENR   string `json:"enr"`   // Ethereum Node Record // 以太坊节点记录
	IP    string `json:"ip"`    // IP address of the node // 节点的 IP 地址
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol // 发现协议的 UDP 监听端口
		Listener  int `json:"listener"`  // TCP listening port for RLPx // RLPx 的 TCP 监听端口
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
// NodeInfo 收集并返回有关主机的已知元数据集合。
func (srv *Server) NodeInfo() *NodeInfo {
	// Gather and assemble the generic node infos
	// 收集和组装通用节点信息
	node := srv.Self()
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.URLv4(),
		ID:         node.ID().String(),
		IP:         node.IPAddr().String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = node.UDP()
	info.Ports.Listener = node.TCP()
	info.ENR = node.String()

	// Gather all the running protocol infos (only once per protocol type)
	// 收集所有正在运行的协议信息（每种协议类型仅一次）
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
// PeersInfo 返回描述连接对等方的元数据对象数组。
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	// 收集所有通用和子协议特定信息
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	// 按节点标识符字母顺序对结果数组进行排序
	slices.SortFunc(infos, func(a, b *PeerInfo) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return infos
}
