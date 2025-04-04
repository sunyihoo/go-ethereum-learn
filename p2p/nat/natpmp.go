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

package nat

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	natpmp "github.com/jackpal/go-nat-pmp"
)

// 代码背景：以太坊 P2P 网络中的 NAT-PMP
// 这段代码是 Go-Ethereum 中 p2p/nat 包的一部分，专注于 NAT-PMP 协议的实现。NAT-PMP 是由 Apple 开发的轻量级 NAT 穿越协议，广泛用于家庭路由器。以太坊节点需要穿越 NAT 以确保外部可达性，尤其是在节点发现和数据传输中。
//
// 以太坊相关知识点：
// DevP2P：以太坊的 P2P 协议依赖 UDP（节点发现）和 TCP（数据传输），NAT-PMP 提供端口映射支持。
// Kademlia 协议：以太坊节点发现使用 UDP 协议，NAT 穿越确保节点可被其他节点找到。
// EIP-778（ENR）：节点记录中包含外部 IP 和端口，NAT-PMP 帮助获取和映射这些信息。

// 端口映射：以太坊节点默认使用 UDP 30303（发现）和 TCP 30303（通信），NAT-PMP 确保这些端口对外可见。
// 外部 IP：节点需要知道自己的公网 IP 以在 ENR 中广播，ExternalIP 满足此需求。
// 快速发现：1 秒超时设计与 Kademlia 协议的快速节点发现需求一致。

// todo learn
// pmp adapts the NAT-PMP protocol implementation so it conforms to
// the common interface.
// pmp 适配 NAT-PMP 协议实现，使其符合通用接口。
type pmp struct {
	gw net.IP         // 网关 IP 地址 / Gateway IP address
	c  *natpmp.Client // NAT-PMP 客户端 / NAT-PMP client
}

func (n *pmp) String() string {
	return fmt.Sprintf("NAT-PMP(%v)", n.gw) // 返回 NAT-PMP 的字符串表示，包括网关 IP / Return string representation of NAT-PMP with gateway IP
}

func (n *pmp) ExternalIP() (net.IP, error) {
	response, err := n.c.GetExternalAddress() // 获取外部地址 / Get external address
	if err != nil {
		return nil, err // 如果出错则返回错误 / Return error if failed
	}
	return response.ExternalIPAddress[:], nil // 返回外部 IP 地址 / Return external IP address
}

func (n *pmp) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	if lifetime <= 0 {
		return 0, errors.New("lifetime must not be <= 0") // 如果生命周期小于等于 0 则返回错误 / Return error if lifetime <= 0
	}
	// Note order of port arguments is switched between our
	// AddMapping and the client's AddPortMapping.
	// 注意，我们的 AddMapping 和客户端的 AddPortMapping 的端口参数顺序是相反的。
	res, err := n.c.AddPortMapping(strings.ToLower(protocol), intport, extport, int(lifetime/time.Second)) // 添加端口映射 / Add port mapping
	if err != nil {
		return 0, err // 如果出错则返回错误 / Return error if failed
	}

	// NAT-PMP maps an alternative available port number if the requested port
	// is already mapped to another address and returns success. Handling of
	// alternate port numbers is done by the caller.
	// 如果请求的端口已被映射到另一个地址，NAT-PMP 会映射一个可用的替代端口号并返回成功。
	// 替代端口号的处理由调用者完成。
	return res.MappedExternalPort, nil // 返回映射的外部端口 / Return mapped external port
}

func (n *pmp) DeleteMapping(protocol string, extport, intport int) (err error) {
	// To destroy a mapping, send an add-port with an internalPort of
	// the internal port to destroy, an external port of zero and a
	// time of zero.
	// 要销毁一个映射，发送一个添加端口请求，内部端口为要销毁的端口，外部端口为 0，时间为 0。
	_, err = n.c.AddPortMapping(strings.ToLower(protocol), intport, 0, 0) // 删除端口映射 / Delete port mapping
	return err                                                            // 返回错误（如果有） / Return error (if any)
}

func discoverPMP() Interface {
	// run external address lookups on all potential gateways
	// 在所有潜在网关上运行外部地址查找
	gws := potentialGateways()         // 获取潜在网关列表 / Get list of potential gateways
	found := make(chan *pmp, len(gws)) // 创建发现通道 / Create discovery channel
	for i := range gws {
		gw := gws[i]
		go func() {
			c := natpmp.NewClient(gw)                         // 创建 NAT-PMP 客户端 / Create NAT-PMP client
			if _, err := c.GetExternalAddress(); err != nil { // 尝试获取外部地址 / Try to get external address
				found <- nil // 如果失败则发送 nil / Send nil if failed
			} else {
				found <- &pmp{gw, c} // 如果成功则发送 pmp 实例 / Send pmp instance if successful
			}
		}()
	}
	// return the one that responds first.
	// discovery needs to be quick, so we stop caring about
	// any responses after a very short timeout.
	// 返回第一个响应的网关。
	// 发现过程需要快速，因此在非常短的超时后停止关心任何响应。
	timeout := time.NewTimer(1 * time.Second) // 设置 1 秒超时 / Set 1-second timeout
	defer timeout.Stop()                      // 延迟停止定时器 / Defer stop timer
	for range gws {
		select {
		case c := <-found: // 从发现通道接收结果 / Receive result from discovery channel
			if c != nil {
				return c // 如果成功则返回 / Return if successful
			}
		case <-timeout.C: // 超时 / Timeout
			return nil // 返回 nil / Return nil
		}
	}
	return nil // 如果没有网关响应则返回 nil / Return nil if no gateway responds
}

// TODO: improve this. We currently assume that (on most networks)
// the router is X.X.X.1 in a local LAN range.
// TODO：改进此方法。我们当前假设（在大多数网络中）路由器是本地 LAN 范围内的 X.X.X.1。
func potentialGateways() (gws []net.IP) {
	ifaces, err := net.Interfaces() // 获取网络接口列表 / Get list of network interfaces
	if err != nil {
		return nil // 如果出错则返回空列表 / Return empty list if error
	}
	for _, iface := range ifaces {
		ifaddrs, err := iface.Addrs() // 获取接口的地址 / Get addresses of interface
		if err != nil {
			return gws // 如果出错则返回当前列表 / Return current list if error
		}
		for _, addr := range ifaddrs {
			if x, ok := addr.(*net.IPNet); ok { // 检查是否为 IPNet 类型 / Check if address is IPNet type
				if x.IP.IsPrivate() { // 检查是否为私有 IP / Check if IP is private
					ip := x.IP.Mask(x.Mask).To4() // 获取子网掩码后的 IP（IPv4） / Get IP after subnet mask (IPv4)
					if ip != nil {
						ip[3] = ip[3] | 0x01  // 将最后一个八位字节设置为 1（假设网关） / Set last octet to 1 (assume gateway)
						gws = append(gws, ip) // 添加到网关列表 / Add to gateway list
					}
				}
			}
		}
	}
	return gws // 返回潜在网关列表 / Return list of potential gateways
}
