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

package netutil

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
)

// 在以太坊的 P2P 网络中，节点通信依赖于 TCP 和 UDP 协议，net.TCPAddr 和 net.UDPAddr 是常见的地址类型。
//
// netip.Addr 是 Go 1.18 引入的新类型，比 net.IP 更高效且支持现代网络协议（如 IPv6），在以太坊客户端（如 go-ethereum）中常用于优化网络层处理。

// AddrAddr gets the IP address contained in addr. The result will be invalid if the
// address type is unsupported.
//
// AddrAddr 获取 addr 中包含的 IP 地址。如果地址类型不受支持，结果将无效。
func AddrAddr(addr net.Addr) netip.Addr {
	switch a := addr.(type) {
	case *net.IPAddr:
		return IPToAddr(a.IP)
	case *net.TCPAddr:
		return IPToAddr(a.IP)
	case *net.UDPAddr:
		return IPToAddr(a.IP)
	default:
		return netip.Addr{}
	}
}

// 以太坊网络目前主要使用 IPv4 地址，但随着 IPv6 的普及，客户端需要支持两种格式。
//
// netip.Addr 的引入减少了字符串解析的开销，这在处理大量节点地址时（如节点发现协议）尤为重要。

// IPToAddr converts net.IP to netip.Addr. Note that unlike netip.AddrFromSlice, this
// function will always ensure that the resulting Addr is IPv4 when the input is.
//
// IPToAddr 将 net.IP 转换为 netip.Addr。请注意，与 netip.AddrFromSlice 不同，
// 此函数将始终确保当输入为 IPv4 时，结果 Addr 也是 IPv4。
func IPToAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		addr, _ := netip.AddrFromSlice(ip4)
		return addr
	} else if ip6 := ip.To16(); ip6 != nil {
		addr, _ := netip.AddrFromSlice(ip6)
		return addr
	}
	return netip.Addr{}
}

// 随机 IP 地址生成在测试以太坊网络客户端（如 go-ethereum）时非常有用，例如模拟节点分布或测试网络层功能。
//
// 在以太坊的 Kademlia DHT 节点发现协议中，随机地址可用于生成测试节点 ID 或模拟网络拓扑。

// RandomAddr creates a random IP address.
// RandomAddr 创建一个随机 IP 地址。
func RandomAddr(rng *rand.Rand, ipv4 bool) netip.Addr {
	var bytes []byte
	if ipv4 || rng.Intn(2) == 0 {
		bytes = make([]byte, 4)
	} else {
		bytes = make([]byte, 16)
	}
	rng.Read(bytes)
	addr, ok := netip.AddrFromSlice(bytes)
	if !ok {
		panic(fmt.Errorf("BUG! invalid IP %v", bytes))
	}
	return addr
}
