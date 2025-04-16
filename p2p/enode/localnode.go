// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	// IP tracker configuration
	// IP 跟踪器配置
	iptrackMinStatements = 10               // Minimum number of statements for IP prediction // IP 预测所需的最小声明数
	iptrackWindow        = 5 * time.Minute  // Window for tracking statements // 跟踪声明的时间窗口
	iptrackContactWindow = 10 * time.Minute // Window for tracking contacts // 跟踪联系的时间窗口

	// time needed to wait between two updates to the local ENR
	// 本地 ENR 两次更新之间所需的等待时间
	recordUpdateThrottle = time.Millisecond // Throttle updates to 1ms intervals // 将更新限制为 1 毫秒间隔
)

// LocalNode produces the signed node record of a local node, i.e. a node run in the
// current process. Setting ENR entries via the Set method updates the record. A new version
// of the record is signed on demand when the Node method is called.
//
// LocalNode 生成当前进程中运行的本地节点的签名记录。通过 Set 方法设置 ENR 条目会更新记录。
// 当调用 Node 方法时，会按需签名生成记录的新版本。
type LocalNode struct {
	// 在记录保持最新时，保存非 nil 的节点指针
	cur atomic.Value // holds a non-nil node pointer while the record is up-to-date

	id  ID                // 节点 ID
	key *ecdsa.PrivateKey // 用于签名的私钥
	db  *DB               // 节点数据库

	// everything below is protected by a lock
	// 以下所有内容受锁保护
	mu        sync.RWMutex         // 读写锁
	seq       uint64               // 记录序列号
	update    time.Time            // timestamp when the record was last updated // 上次更新时间戳
	entries   map[string]enr.Entry // ENR 条目映射
	endpoint4 lnEndpoint           // IPv4 端点
	endpoint6 lnEndpoint           // IPv6 端点
}

type lnEndpoint struct {
	track       *netutil.IPTracker // IP 预测跟踪器
	staticIP    net.IP             // 静态 IP
	fallbackIP  net.IP             // 备用 IP
	fallbackUDP uint16             // port 备用 UDP 端口
}

// NewLocalNode creates a local node.
// NewLocalNode 创建一个本地节点。
func NewLocalNode(db *DB, key *ecdsa.PrivateKey) *LocalNode {
	ln := &LocalNode{
		id:      PubkeyToIDV4(&key.PublicKey), // 从公钥派生节点 ID
		db:      db,                           // 设置数据库
		key:     key,                          // 设置私钥
		entries: make(map[string]enr.Entry),   // 初始化 ENR 条目映射
		endpoint4: lnEndpoint{
			track: netutil.NewIPTracker(iptrackWindow, iptrackContactWindow, iptrackMinStatements), // 初始化 IPv4 跟踪器
		},
		endpoint6: lnEndpoint{
			track: netutil.NewIPTracker(iptrackWindow, iptrackContactWindow, iptrackMinStatements), // 初始化 IPv6 跟踪器
		},
	}
	ln.seq = db.localSeq(ln.id) // 从数据库加载序列号
	ln.update = time.Now()      // 设置初始更新时间
	ln.cur.Store((*Node)(nil))  // 初始化当前记录为空
	return ln
}

// Database returns the node database associated with the local node.
// Database 返回与本地节点关联的节点数据库。
func (ln *LocalNode) Database() *DB {
	return ln.db // 返回数据库
}

// Node returns the current version of the local node record.
// Node 返回本地节点记录的当前版本。
func (ln *LocalNode) Node() *Node {
	// If we have a valid record, return that
	// 如果有有效记录，直接返回
	n := ln.cur.Load().(*Node)
	if n != nil {
		return n
	}

	// Record was invalidated, sign a new copy.
	// 记录已失效，签名生成新副本。
	ln.mu.Lock()
	defer ln.mu.Unlock()

	// Double check the current record, since multiple goroutines might be waiting
	// on the write mutex.
	// 再次检查当前记录，因为多个 goroutine 可能在等待写锁。
	if n = ln.cur.Load().(*Node); n != nil {
		return n
	}

	// The initial sequence number is the current timestamp in milliseconds. To ensure
	// that the initial sequence number will always be higher than any previous sequence
	// number (assuming the clock is correct), we want to avoid updating the record faster
	// than once per ms. So we need to sleep here until the next possible update time has
	// arrived.
	//
	// 初始序列号是当前时间的毫秒时间戳。为确保初始序列号始终高于之前的序列号（假设时钟正确），
	// 我们希望避免每毫秒更新记录超过一次。因此需要在这里休眠，直到下一次可能的更新时间到达。
	lastChange := time.Since(ln.update)
	if lastChange < recordUpdateThrottle {
		time.Sleep(recordUpdateThrottle - lastChange)
	}

	ln.sign()                    // 签名生成新记录
	ln.update = time.Now()       // 更新时间戳
	return ln.cur.Load().(*Node) // 返回新记录
}

// Seq returns the current sequence number of the local node record.
// Seq 返回本地节点记录的当前序列号。
func (ln *LocalNode) Seq() uint64 {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	return ln.seq // 返回序列号
}

// ID returns the local node ID.
// ID 返回本地节点 ID。
func (ln *LocalNode) ID() ID {
	return ln.id // 返回节点 ID
}

// Set puts the given entry into the local record, overwriting any existing value.
// Use Set*IP and SetFallbackUDP to set IP addresses and UDP port, otherwise they'll
// be overwritten by the endpoint predictor.
//
// Since node record updates are throttled to one per second, Set is asynchronous.
// Any update will be queued up and published when at least one second passes from
// the last change.
//
// Set 将给定条目放入本地记录，覆盖任何现有值。
// 使用 Set*IP 和 SetFallbackUDP 设置 IP 地址和 UDP 端口，否则它们将被端点预测器覆盖。
//
// 由于节点记录更新被限制为每秒一次，Set 是异步的。
// 任何更新都将被排队，并在距上次更改至少一秒后发布。
func (ln *LocalNode) Set(e enr.Entry) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.set(e) // 设置条目
}

func (ln *LocalNode) set(e enr.Entry) {
	val, exists := ln.entries[e.ENRKey()]      // 检查条目是否存在
	if !exists || !reflect.DeepEqual(val, e) { // 如果不存在或值不同
		ln.entries[e.ENRKey()] = e // 更新条目
		ln.invalidate()            // 使记录失效
	}
}

// Delete removes the given entry from the local record.
// Delete 从本地记录中移除给定条目。
func (ln *LocalNode) Delete(e enr.Entry) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.delete(e) // 删除条目
}

func (ln *LocalNode) delete(e enr.Entry) {
	_, exists := ln.entries[e.ENRKey()] // 检查条目是否存在
	if exists {
		delete(ln.entries, e.ENRKey()) // 删除条目
		ln.invalidate()                // 使记录失效
	}
}

func (ln *LocalNode) endpointForIP(ip netip.Addr) *lnEndpoint {
	if ip.Is4() { // 如果是 IPv4
		return &ln.endpoint4 // 返回 IPv4 端点
	}
	return &ln.endpoint6 // 返回 IPv6 端点
}

// SetStaticIP sets the local IP to the given one unconditionally.
// This disables endpoint prediction.
//
// SetStaticIP 无条件设置本地 IP 为给定值。
// 这会禁用端点预测。
func (ln *LocalNode) SetStaticIP(ip net.IP) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.endpointForIP(netutil.IPToAddr(ip)).staticIP = ip // 设置静态 IP
	ln.updateEndpoints()                                 // 更新端点
}

// SetFallbackIP sets the last-resort IP address. This address is used
// if no endpoint prediction can be made and no static IP is set.
//
// SetFallbackIP 设置最后手段的 IP 地址。如果无法进行端点预测且未设置静态 IP，则使用此地址。
func (ln *LocalNode) SetFallbackIP(ip net.IP) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.endpointForIP(netutil.IPToAddr(ip)).fallbackIP = ip // 设置备用 IP
	ln.updateEndpoints()                                   // 更新端点
}

// SetFallbackUDP sets叶子-resort UDP-on-IPv4 port. This port is used
// if no endpoint prediction can be made.
// SetFallbackUDP 设置最后手段的 IPv4 UDP 端口。如果无法进行端点预测，则使用此端口。
func (ln *LocalNode) SetFallbackUDP(port int) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.endpoint4.fallbackUDP = uint16(port) // 设置 IPv4 备用端口
	ln.endpoint6.fallbackUDP = uint16(port) // 设置 IPv6 备用端口
	ln.updateEndpoints()                    // 更新端点
}

// UDPEndpointStatement should be called whenever a statement about the local node's
// UDP endpoint is received. It feeds the local endpoint predictor.
//
// UDPEndpointStatement 应在收到关于本地节点 UDP 端点的声明时调用。它为本地端点预测器提供数据。
func (ln *LocalNode) UDPEndpointStatement(fromaddr, endpoint netip.AddrPort) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.endpointForIP(endpoint.Addr()).track.AddStatement(fromaddr.Addr(), endpoint) // 添加端点声明
	ln.updateEndpoints()                                                            // 更新端点
}

// UDPContact should be called whenever the local node has announced itself to another node
// via UDP. It feeds the local endpoint predictor.
//
// UDPContact 应在本地节点通过 UDP 向另一节点宣布自身时调用。它为本地端点预测器提供数据。
func (ln *LocalNode) UDPContact(toaddr netip.AddrPort) {
	ln.mu.Lock()         // 加锁
	defer ln.mu.Unlock() // 延迟解锁

	ln.endpointForIP(toaddr.Addr()).track.AddContact(toaddr.Addr()) // 添加联系记录
	ln.updateEndpoints()                                            // 更新端点
}

// updateEndpoints updates the record with predicted endpoints.
// updateEndpoints 使用预测的端点更新记录。
func (ln *LocalNode) updateEndpoints() {
	ip4, udp4 := ln.endpoint4.get() // 获取 IPv4 端点
	ip6, udp6 := ln.endpoint6.get() // 获取 IPv6 端点

	if ip4 != nil && !ip4.IsUnspecified() { // 如果 IPv4 有效
		ln.set(enr.IPv4(ip4)) // 设置 IPv4
	} else {
		ln.delete(enr.IPv4{}) // 删除 IPv4
	}
	if ip6 != nil && !ip6.IsUnspecified() { // 如果 IPv6 有效
		ln.set(enr.IPv6(ip6)) // 设置 IPv6
	} else {
		ln.delete(enr.IPv6{}) // 删除 IPv6
	}
	if udp4 != 0 { // 如果 UDP4 端口有效
		ln.set(enr.UDP(udp4)) // 设置 UDP4
	} else {
		ln.delete(enr.UDP(0)) // 删除 UDP4
	}
	if udp6 != 0 && udp6 != udp4 { // 如果 UDP6 端口有效且不同于 UDP4
		ln.set(enr.UDP6(udp6)) // 设置 UDP6
	} else {
		ln.delete(enr.UDP6(0)) // 删除 UDP6
	}
}

// get returns the endpoint with highest precedence.
// get 返回优先级最高的端点。
func (e *lnEndpoint) get() (newIP net.IP, newPort uint16) {
	newPort = e.fallbackUDP  // 默认使用备用端口
	if e.fallbackIP != nil { // 如果有备用 IP
		newIP = e.fallbackIP // 使用备用 IP
	}
	if e.staticIP != nil { // 如果有静态 IP
		newIP = e.staticIP // 使用静态 IP（最高优先级）
	} else if ap := e.track.PredictEndpoint(); ap.IsValid() { // 如果预测有效
		newIP = ap.Addr().AsSlice() // 使用预测 IP
		newPort = ap.Port()         // 使用预测端口
	}
	return newIP, newPort // 返回 IP 和端口
}

func (ln *LocalNode) invalidate() {
	ln.cur.Store((*Node)(nil)) // 将当前记录置为 nil，使其失效
}

func (ln *LocalNode) sign() {
	if n := ln.cur.Load().(*Node); n != nil { // 如果记录已有效，返回
		return
	}

	var r enr.Record               // 创建新记录
	for _, e := range ln.entries { // 设置所有条目
		r.Set(e)
	}
	ln.bumpSeq()                               // 增加序列号
	r.SetSeq(ln.seq)                           // 设置序列号
	if err := SignV4(&r, ln.key); err != nil { // 签名记录
		panic(fmt.Errorf("enode: can't sign record: %v", err))
	}
	n, err := New(ValidSchemes, &r) // 创建新节点
	if err != nil {
		panic(fmt.Errorf("enode: can't verify local record: %v", err))
	}
	ln.cur.Store(n)                                                                                                  // 存储新记录
	log.Info("New local node record", "seq", ln.seq, "id", n.ID(), "ip", n.IPAddr(), "udp", n.UDP(), "tcp", n.TCP()) // 记录日志
}

func (ln *LocalNode) bumpSeq() {
	ln.seq++                           // 增加序列号
	ln.db.storeLocalSeq(ln.id, ln.seq) // 在数据库中存储序列号
}

// nowMilliseconds gives the current timestamp at millisecond precision.
// nowMilliseconds 以毫秒精度返回当前时间戳。
func nowMilliseconds() uint64 {
	ns := time.Now().UnixNano() // 获取纳秒时间戳
	if ns < 0 {                 // 如果时间戳负值，返回 0
		return 0
	}
	return uint64(ns / 1000 / 1000) // 转换为毫秒
}
