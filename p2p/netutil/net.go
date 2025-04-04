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

// Package netutil contains extensions to the net package.
package netutil

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/exp/maps"
)

// P2P 网络地址管理：
// 以太坊节点需要区分特殊地址、局域网地址和公共地址，以确保连接目标有效。
//
// CheckRelayAddr 的规则与以太坊客户端（如 go-ethereum）的地址验证逻辑一致。
//
// 节点发现与分布：
// DistinctNetSet 可用于优化节点选择，避免过多节点来自同一子网，提升网络健壮性。

// 特殊地址（如 192.0.2.0/24 TEST-NET-1 或 2001:db8::/32 文档地址）在以太坊网络中应避免使用，以防止测试地址混入生产环境。
//
// 192.88.99.0/24（6to4 中继）与以太坊的 IPv6 支持相关，可能用于混合网络环境。

var special4, special6 Netlist

func init() {
	// Lists from RFC 5735, RFC 5156,
	// https://www.iana.org/assignments/iana-ipv4-special-registry/
	// 来自 RFC 5735、RFC 5156 和 IANA IPv4 特殊注册表的列表
	special4.Add("0.0.0.0/8")          // "This" network. "本网络"
	special4.Add("192.0.0.0/29")       // IPv4 Service Continuity IPv4 服务连续性
	special4.Add("192.0.0.9/32")       // PCP Anycast PCP 任意广播
	special4.Add("192.0.0.170/32")     // NAT64/DNS64 Discovery NAT64/DNS64 发现
	special4.Add("192.0.0.171/32")     // NAT64/DNS64 Discovery NAT64/DNS64 发现
	special4.Add("192.0.2.0/24")       // TEST-NET-1 测试网络-1
	special4.Add("192.31.196.0/24")    // AS112
	special4.Add("192.52.193.0/24")    // AMT
	special4.Add("192.88.99.0/24")     // 6to4 Relay Anycast 6to4 中继任意广播
	special4.Add("192.175.48.0/24")    // AS112
	special4.Add("198.18.0.0/15")      // Device Benchmark Testing 设备基准测试
	special4.Add("198.51.100.0/24")    // TEST-NET-2 测试网络-2
	special4.Add("203.0.113.0/24")     // TEST-NET-3 测试网络-3
	special4.Add("255.255.255.255/32") // Limited Broadcast 有限广播

	// http://www.iana.org/assignments/iana-ipv6-special-registry/
	// 来自 IANA IPv6 特殊注册表的列表
	special6.Add("100::/64")
	special6.Add("2001::/32")
	special6.Add("2001:1::1/128")
	special6.Add("2001:2::/48")
	special6.Add("2001:3::/32")
	special6.Add("2001:4:112::/48")
	special6.Add("2001:5::/32")
	special6.Add("2001:10::/28")
	special6.Add("2001:20::/28")
	special6.Add("2001:db8::/32")
	special6.Add("2002::/16")
}

// Netlist is a list of IP networks.
// Netlist 是 IP 网络的列表。
type Netlist []netip.Prefix

// ParseNetlist parses a comma-separated list of CIDR masks.
// Whitespace and extra commas are ignored.
// ParseNetlist 解析以逗号分隔的 CIDR 掩码列表。
// 忽略空格和多余的逗号。
func ParseNetlist(s string) (*Netlist, error) {
	ws := strings.NewReplacer(" ", "", "\n", "", "\t", "")
	masks := strings.Split(ws.Replace(s), ",")
	l := make(Netlist, 0)
	for _, mask := range masks {
		if mask == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(mask)
		if err != nil {
			return nil, err
		}
		l = append(l, prefix)
	}
	return &l, nil
}

// MarshalTOML implements toml.MarshalerRec.
// MarshalTOML 实现 toml.MarshalerRec。
func (l Netlist) MarshalTOML() interface{} {
	list := make([]string, 0, len(l))
	for _, net := range l {
		list = append(list, net.String())
	}
	return list
}

// UnmarshalTOML implements toml.UnmarshalerRec.
// UnmarshalTOML 实现 toml.UnmarshalerRec。
func (l *Netlist) UnmarshalTOML(fn func(interface{}) error) error {
	var masks []string
	if err := fn(&masks); err != nil {
		return err
	}
	for _, mask := range masks {
		prefix, err := netip.ParsePrefix(mask)
		if err != nil {
			return err
		}
		*l = append(*l, prefix)
	}
	return nil
}

// Add parses a CIDR mask and appends it to the list. It panics for invalid masks and is
// intended to be used for setting up static lists.
// Add 解析 CIDR 掩码并将其追加到列表中。对于无效掩码会引发 panic，旨在用于设置静态列表。
func (l *Netlist) Add(cidr string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}
	*l = append(*l, prefix)
}

// Contains reports whether the given IP is contained in the list.
// Contains 报告给定的 IP 是否包含在列表中。
func (l *Netlist) Contains(ip net.IP) bool {
	return l.ContainsAddr(IPToAddr(ip))
}

// ContainsAddr reports whether the given IP is contained in the list.
// ContainsAddr 报告给定的 IP 是否包含在列表中。
func (l *Netlist) ContainsAddr(ip netip.Addr) bool {
	if l == nil {
		return false
	}
	for _, net := range *l {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

// IsLAN reports whether an IP is a local network address.
// IsLAN 报告 IP 是否为本地网络地址。
func IsLAN(ip net.IP) bool {
	return AddrIsLAN(IPToAddr(ip))
}

// AddrIsLAN reports whether an IP is a local network address.
// AddrIsLAN 报告 IP 是否为本地网络地址。
func AddrIsLAN(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = netip.AddrFrom4(ip.As4())
	}
	if ip.IsLoopback() {
		return true
	}
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// IsSpecialNetwork reports whether an IP is located in a special-use network range
// This includes broadcast, multicast and documentation addresses.
// IsSpecialNetwork 报告 IP 是否位于特殊用途网络范围内，包括广播、多播和文档地址。
func IsSpecialNetwork(ip net.IP) bool {
	return AddrIsSpecialNetwork(IPToAddr(ip))
}

// AddrIsSpecialNetwork reports whether an IP is located in a special-use network range
// This includes broadcast, multicast and documentation addresses.
// AddrIsSpecialNetwork 报告 IP 是否位于特殊用途网络范围内，包括广播、多播和文档地址。
func AddrIsSpecialNetwork(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = netip.AddrFrom4(ip.As4())
	}
	if ip.IsMulticast() {
		return true
	}
	if ip.Is4() {
		return special4.ContainsAddr(ip)
	}
	return special6.ContainsAddr(ip)
}

var (
	errInvalid     = errors.New("invalid IP")                              // 无效 IP
	errUnspecified = errors.New("zero address")                            // 零地址
	errSpecial     = errors.New("special network")                         // 特殊网络
	errLoopback    = errors.New("loopback address from non-loopback host") // 非回环主机发出的回环地址
	errLAN         = errors.New("LAN address from WAN host")               // 广域网主机发出的局域网地址
)

// CheckRelayIP reports whether an IP relayed from the given sender IP
// is a valid connection target.
//
// There are four rules:
//   - Special network addresses are never valid.
//   - Loopback addresses are OK if relayed by a loopback host.
//   - LAN addresses are OK if relayed by a LAN host.
//   - All other addresses are always acceptable.
//
// CheckRelayIP 报告从给定发送者 IP 中继的 IP 是否为有效的连接目标。
//
// 有四条规则：
//   - 特殊网络地址永远无效。
//   - 如果由回环主机中继，回环地址是允许的。
//   - 如果由局域网主机中继，局域网地址是允许的。
//   - 所有其他地址始终是可接受的。
func CheckRelayIP(sender, addr net.IP) error {
	return CheckRelayAddr(IPToAddr(sender), IPToAddr(addr))
}

// CheckRelayAddr reports whether an IP relayed from the given sender IP
// is a valid connection target.
//
// There are four rules:
//   - Special network addresses are never valid.
//   - Loopback addresses are OK if relayed by a loopback host.
//   - LAN addresses are OK if relayed by a LAN host.
//   - All other addresses are always acceptable.
//
// CheckRelayAddr 报告从给定发送者 IP 中继的 IP 是否为有效的连接目标。
//
// 有四条规则：
//   - 特殊网络地址永远无效。
//   - 如果由回环主机中继，回环地址是允许的。
//   - 如果由局域网主机中继，局域网地址是允许的。
//   - 所有其他地址始终是可接受的。
func CheckRelayAddr(sender, addr netip.Addr) error {
	if !addr.IsValid() {
		return errInvalid
	}
	if addr.IsUnspecified() {
		return errUnspecified
	}
	if AddrIsSpecialNetwork(addr) {
		return errSpecial
	}
	if addr.IsLoopback() && !sender.IsLoopback() {
		return errLoopback
	}
	if AddrIsLAN(addr) && !AddrIsLAN(sender) {
		return errLAN
	}
	return nil
}

// SameNet reports whether two IP addresses have an equal prefix of the given bit length.
// SameNet 报告两个 IP 地址是否具有给定位长度的相同前缀。
func SameNet(bits uint, ip, other net.IP) bool {
	ip4, other4 := ip.To4(), other.To4()
	switch {
	case (ip4 == nil) != (other4 == nil):
		return false
	case ip4 != nil:
		return sameNet(bits, ip4, other4)
	default:
		return sameNet(bits, ip.To16(), other.To16())
	}
}

func sameNet(bits uint, ip, other net.IP) bool {
	nb := int(bits / 8)
	mask := ^byte(0xFF >> (bits % 8))
	if mask != 0 && nb < len(ip) && ip[nb]&mask != other[nb]&mask {
		return false
	}
	return nb <= len(ip) && ip[:nb].Equal(other[:nb])
}

// 在以太坊的节点发现（Discovery v4/v5）中，限制同一子网的节点数量可防止网络过于集中，提升去中心化程度。

// DistinctNetSet tracks IPs, ensuring that at most N of them
// fall into the same network range.
// DistinctNetSet 跟踪 IP，确保同一网络范围内最多有 N 个 IP。
type DistinctNetSet struct {
	Subnet  uint                  // 公共前缀位数
	Limit   uint                  // 每个子网中的最大 IP 数量
	members map[netip.Prefix]uint // 存储子网和其 IP 数量
}

// Add adds an IP address to the set. It returns false (and doesn't add the IP) if the
// number of existing IPs in the defined range exceeds the limit.
// Add 将 IP 地址添加到集合中。如果定义范围内的现有 IP 数量超过限制，则返回 false（且不添加 IP）。
func (s *DistinctNetSet) Add(ip net.IP) bool {
	return s.AddAddr(IPToAddr(ip))
}

// AddAddr adds an IP address to the set. It returns false (and doesn't add the IP) if the
// number of existing IPs in the defined range exceeds the limit.
// AddAddr 将 IP 地址添加到集合中。如果定义范围内的现有 IP 数量超过限制，则返回 false（且不添加 IP）。
func (s *DistinctNetSet) AddAddr(ip netip.Addr) bool {
	key := s.key(ip)
	n := s.members[key]
	if n < s.Limit {
		s.members[key] = n + 1
		return true
	}
	return false
}

// Remove removes an IP from the set.
// Remove 从集合中移除 IP。
func (s *DistinctNetSet) Remove(ip net.IP) {
	s.RemoveAddr(IPToAddr(ip))
}

// RemoveAddr removes an IP from the set.
// RemoveAddr 从集合中移除 IP。
func (s *DistinctNetSet) RemoveAddr(ip netip.Addr) {
	key := s.key(ip)
	if n, ok := s.members[key]; ok {
		if n == 1 {
			delete(s.members, key)
		} else {
			s.members[key] = n - 1
		}
	}
}

// Contains reports whether the given IP is contained in the set.
// Contains 报告给定的 IP 是否包含在集合中。
func (s DistinctNetSet) Contains(ip net.IP) bool {
	return s.ContainsAddr(IPToAddr(ip))
}

// ContainsAddr reports whether the given IP is contained in the set.
// ContainsAddr 报告给定的 IP 是否包含在集合中。
func (s DistinctNetSet) ContainsAddr(ip netip.Addr) bool {
	key := s.key(ip)
	_, ok := s.members[key]
	return ok
}

// Len returns the number of tracked IPs.
// Len 返回跟踪的 IP 数量。
func (s DistinctNetSet) Len() int {
	n := uint(0)
	for _, i := range s.members {
		n += i
	}
	return int(n)
}

// key returns the map key for ip.
// key 返回 IP 的映射键。
func (s *DistinctNetSet) key(ip netip.Addr) netip.Prefix {
	// Lazily initialize storage.
	// 延迟初始化存储。
	if s.members == nil {
		s.members = make(map[netip.Prefix]uint)
	}
	p, err := ip.Prefix(int(s.Subnet))
	if err != nil {
		panic(err)
	}
	return p
}

// String implements fmt.Stringer
// String 实现 fmt.Stringer
func (s DistinctNetSet) String() string {
	keys := maps.Keys(s.members)
	slices.SortFunc(keys, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})

	var buf bytes.Buffer
	buf.WriteString("{")
	for i, k := range keys {
		fmt.Fprintf(&buf, "%v×%d", k, s.members[k])
		if i != len(keys)-1 {
			buf.WriteString(" ")
		}
	}
	buf.WriteString("}")
	return buf.String()
}
