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

package netutil

import (
	"net/netip"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
)

// P2P 网络中的 NAT 穿越：
// 以太坊节点常位于 NAT 后，外部端点的准确预测对建立连接至关重要。
//
// 全锥形 NAT 的检测帮助客户端决定是否需要额外的 NAT 穿越技术（如 UPnP 或 STUN）。
//
// go-ethereum 中的应用：
// IPTracker 类似 go-ethereum 中 p2p/nat 包的功能，用于动态发现外部地址。
//
// 在节点启动时，客户端通过与其他节点的交互确定自己的 enode URL。
//
// EIP 相关背景：
// 虽然未直接涉及具体 EIP，但此功能支持 Discovery v4/v5 协议（EIP-778），确保节点在复杂网络环境下的可达性。

// 全锥形 NAT（Full Cone NAT）：一种网络地址转换类型，允许外部主机主动发起连接到 NAT 后的本地主机。在以太坊 P2P 网络中，检测 NAT 类型对节点的可达性至关重要。
//
// 以太坊的节点发现协议（Discovery v4/v5）依赖 UDP，若本地主机在全锥形 NAT 后，外部节点可直接发送数据包，这影响节点是否能作为“可达节点”参与网络。

// IPTracker predicts the external endpoint, i.e. IP address and port, of the local host
// based on statements made by other hosts.
//
// IPTracker 根据其他主机的声明预测本地主机的外部端点，即 IP 地址和端口。
type IPTracker struct {
	window          time.Duration                 // 时间窗口，用于保留过去的网络事件
	contactWindow   time.Duration                 // 联系时间窗口，用于保留联系记录
	minStatements   int                           // 最小声明数量，在预测前必须记录的声明数
	clock           mclock.Clock                  // 时钟，用于获取当前时间
	statements      map[netip.Addr]ipStatement    // 存储其他主机对我们外部端点的声明
	contact         map[netip.Addr]mclock.AbsTime // 存储我们联系过的主机的时间
	lastStatementGC mclock.AbsTime                // 上次声明垃圾回收的时间
	lastContactGC   mclock.AbsTime                // 上次联系垃圾回收的时间
}

type ipStatement struct {
	endpoint netip.AddrPort // 外部端点（IP 地址和端口）
	time     mclock.AbsTime // 声明的时间
}

// NewIPTracker creates an IP tracker.
//
// The window parameters configure the amount of past network events which are kept. The
// minStatements parameter enforces a minimum number of statements which must be recorded
// before any prediction is made. Higher values for these parameters decrease 'flapping' of
// predictions as network conditions change. Window duration values should typically be in
// the range of minutes.
//
// NewIPTracker 创建一个 IP 跟踪器。
//
// 窗口参数配置保留的过去网络事件的数量。minStatements 参数强制要求在进行任何预测前必须记录的最小声明数量。
// 这些参数的较高值可以减少网络条件变化时预测的“抖动”。窗口持续时间值通常应在分钟范围内。
func NewIPTracker(window, contactWindow time.Duration, minStatements int) *IPTracker {
	return &IPTracker{
		window:        window,
		contactWindow: contactWindow,
		statements:    make(map[netip.Addr]ipStatement),
		minStatements: minStatements,
		contact:       make(map[netip.Addr]mclock.AbsTime),
		clock:         mclock.System{},
	}
}

// PredictFullConeNAT checks whether the local host is behind full cone NAT. It predicts by
// checking whether any statement has been received from a node we didn't contact before
// the statement was made.
//
// PredictFullConeNAT 检查本地主机是否位于全锥形 NAT 后面。它通过检查是否从我们未在声明前联系过的节点接收到声明来进行预测。
func (it *IPTracker) PredictFullConeNAT() bool {
	now := it.clock.Now()
	it.gcContact(now)
	it.gcStatements(now)
	for host, st := range it.statements {
		if c, ok := it.contact[host]; !ok || c > st.time {
			return true
		}
	}
	return false
}

// 在以太坊 P2P 网络中，外部端点（IP 和端口）的预测用于构建 enode URL（如之前代码所示），这是节点间通信的基础。
//
// 通过多主机声明投票机制预测端点，能有效应对 NAT 穿越或动态 IP 的场景。

// PredictEndpoint returns the current prediction of the external endpoint.
// PredictEndpoint 返回当前对外部端点的预测。
func (it *IPTracker) PredictEndpoint() netip.AddrPort {
	it.gcStatements(it.clock.Now())

	// The current strategy is simple: find the endpoint with most statements.
	// 当前策略很简单：找到声明最多的端点。
	var (
		counts   = make(map[netip.AddrPort]int, len(it.statements))
		maxcount int
		max      netip.AddrPort
	)
	for _, s := range it.statements {
		c := counts[s.endpoint] + 1
		counts[s.endpoint] = c
		if c > maxcount && c >= it.minStatements {
			maxcount, max = c, s.endpoint
		}
	}
	return max
}

// AddStatement records that a certain host thinks our external endpoint is the one given.
// AddStatement 记录某个主机认为我们的外部端点是给定的端点。
func (it *IPTracker) AddStatement(host netip.Addr, endpoint netip.AddrPort) {
	now := it.clock.Now()
	it.statements[host] = ipStatement{endpoint, now}
	if time.Duration(now-it.lastStatementGC) >= it.window {
		it.gcStatements(now)
	}
}

// AddContact records that a packet containing our endpoint information has been sent to a
// certain host.
//
// AddContact 记录已将包含我们端点信息的数据包发送到某个主机。
func (it *IPTracker) AddContact(host netip.Addr) {
	now := it.clock.Now()
	it.contact[host] = now
	if time.Duration(now-it.lastContactGC) >= it.contactWindow {
		it.gcContact(now)
	}
}

// gcStatements 从 IPTracker 的 statements 映射中移除过期的语句。
// 超过指定窗口时间的语句将被删除，以保持映射大小可控。
func (it *IPTracker) gcStatements(now mclock.AbsTime) {
	it.lastStatementGC = now      // 表示最近一次语句垃圾回收的时间。
	cutoff := now.Add(-it.window) // 计算过期时间点 cutoff，将当前时间减去窗口时间，得到过期时间点。任何早于 cutoff 的语句将被视为过期。
	for host, s := range it.statements {
		if s.time < cutoff {
			delete(it.statements, host)
		}
	}
}

// gcContact 从 IPTracker 的 contact 映射中移除过期的联系记录。
// 超过指定联系窗口时间的联系记录将被删除，以保持映射大小可控。
func (it *IPTracker) gcContact(now mclock.AbsTime) {
	it.lastContactGC = now               // 表示最近一次联系记录垃圾回收的时间。
	cutoff := now.Add(-it.contactWindow) // 将当前时间减去窗口时间，得到过期时间点。
	for host, ct := range it.contact {
		if ct < cutoff {
			delete(it.contact, host)
		}
	}
}
