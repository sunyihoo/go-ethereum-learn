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
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// Discovery 协议：基于 Kademlia DHT，v4 和 v5 版本分别用于不同的以太坊客户端实现（如 Geth）。v5 引入了更强的加密和握手机制。
// ECDSA 私钥：PrivateKey 是节点的身份标识，用于签名和验证消息。
// ENR（Ethereum Node Records）：enode 包和 ValidSchemes 涉及 ENR，用于存储节点元数据。

// UDPConn is a network connection on which discovery can operate.
// UDPConn 是发现协议可以操作的网络连接。
type UDPConn interface {
	ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) // Read packet from UDP / 从 UDP 读取数据包
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error)  // Write packet to UDP / 向 UDP 写入数据包
	Close() error                                                         // Close the connection / 关闭连接
	LocalAddr() net.Addr                                                  // Get local address / 获取本地地址
}

// Config holds settings for the discovery listener.
// Config 保存发现监听器的设置。
type Config struct {
	// These settings are required and configure the UDP listener:
	// 这些设置是必需的，用于配置 UDP 监听器：
	PrivateKey *ecdsa.PrivateKey // Private key for node identity / 节点身份的私钥

	// All remaining settings are optional.
	// 其余设置均为可选。

	// Packet handling configuration:
	// 数据包处理配置：
	NetRestrict *netutil.Netlist  // list of allowed IP networks / 允许的 IP 网络列表
	Unhandled   chan<- ReadPacket // unhandled packets are sent on this channel / 未处理的数据包发送到此通道

	// Node table configuration:
	// 节点表配置：
	Bootnodes               []*enode.Node // list of bootstrap nodes / 引导节点列表
	PingInterval            time.Duration // speed of node liveness check / 节点存活检查的频率
	RefreshInterval         time.Duration // used in bucket refresh / 用于桶刷新的间隔
	NoFindnodeLivenessCheck bool          // turns off validation of table nodes in FINDNODE handler / 关闭 FINDNODE 处理程序中的表节点验证

	// The options below are useful in very specific cases, like in unit tests.
	// 以下选项在特定情况下（如单元测试）有用。
	V5ProtocolID *[6]byte           // Protocol ID for Discovery v5 / Discovery v5 的协议 ID
	Log          log.Logger         // if set, log messages go here / 如果设置，日志消息发送到此处
	ValidSchemes enr.IdentityScheme // allowed identity schemes / 允许的身份方案
	Clock        mclock.Clock       // Clock for time operations / 用于时间操作的时钟
}

func (cfg Config) withDefaults() Config {
	// Node table configuration:
	// 节点表配置：
	if cfg.PingInterval == 0 {
		cfg.PingInterval = 3 * time.Second // Default ping interval: 3 seconds / 默认 ping 间隔：3秒
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 30 * time.Minute // Default refresh interval: 30 minutes / 默认刷新间隔：30分钟
	}

	// Debug/test settings:
	// 调试/测试设置：
	if cfg.Log == nil {
		cfg.Log = log.Root() // Default to root logger / 默认使用根日志记录器
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes // Default identity schemes / 默认身份方案
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{} // Default to system clock / 默认使用系统时钟
	}
	return cfg
}

// ListenUDP starts listening for discovery packets on the given UDP socket.
// ListenUDP 开始在给定的 UDP 套接字上监听发现数据包。
func ListenUDP(c UDPConn, ln *enode.LocalNode, cfg Config) (*UDPv4, error) {
	return ListenV4(c, ln, cfg) // Delegate to v4-specific listener / 委托给 v4 特定的监听器
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
// ReadPacket 是无法处理的数据包。如果配置了未处理通道，这些数据包会发送到该通道。
type ReadPacket struct {
	Data []byte         // Packet data / 数据包内容
	Addr netip.AddrPort // Source address / 来源地址
}

type randomSource interface {
	Intn(int) int                // Generate random int in [0, n) / 生成 [0, n) 范围内的随机整数
	Int63n(int64) int64          // Generate random int64 in [0, n) / 生成 [0, n) 范围内的随机 int64
	Shuffle(int, func(int, int)) // Shuffle elements / 打乱元素顺序
}

// reseedingRandom is a random number generator that tracks when it was last re-seeded.
// reseedingRandom 是一个随机数生成器，跟踪其最后一次重新播种的时间。
type reseedingRandom struct {
	mu  sync.Mutex // Mutex for thread safety / 用于线程安全的互斥锁
	cur *rand.Rand // Current random generator / 当前随机生成器
}

func (r *reseedingRandom) seed() {
	var b [8]byte
	crand.Read(b[:])                             // Read 8 random bytes / 读取 8 个随机字节
	seed := binary.BigEndian.Uint64(b[:])        // Convert to uint64 seed / 转换为 uint64 种子
	new := rand.New(rand.NewSource(int64(seed))) // Create new RNG / 创建新的随机数生成器

	r.mu.Lock()
	r.cur = new // Update current RNG / 更新当前随机生成器
	r.mu.Unlock()
}

func (r *reseedingRandom) Intn(n int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur.Intn(n) // Generate random int / 生成随机整数
}

func (r *reseedingRandom) Int63n(n int64) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur.Int63n(n) // Generate random int64 / 生成随机 int64
}

func (r *reseedingRandom) Shuffle(n int, swap func(i, j int)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur.Shuffle(n, swap) // Shuffle elements / 打乱元素顺序
}
