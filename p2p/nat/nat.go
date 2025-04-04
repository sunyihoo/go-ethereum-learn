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

// Package nat provides access to common network port mapping protocols.
package nat

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// 代码背景：以太坊 P2P 网络中的 NAT 穿越
// 这段代码是 Go-Ethereum 中 p2p/nat 包的核心，用于解决 NAT（Network Address Translation）环境下的端口映射问题。以太坊节点通常运行在私有网络中，NAT 穿越是确保节点可被外部访问的关键技术。
//
// 以太坊相关知识点：
// DevP2P：以太坊的 P2P 协议依赖 UDP（用于节点发现）和 TCP（用于数据传输），需要外部端口映射。
// UPnP 和 NAT-PMP：常见的 NAT 穿越协议，UPnP（Universal Plug and Play）适用于家庭路由器，NAT-PMP（NAT Port Mapping Protocol）由 Apple 推广。
// EIP-778（ENR）：节点记录中包含 IP 和端口信息，NAT 映射确保这些信息对外可见。

// 端口映射需求：以太坊节点需要映射 UDP 端口（如 30303）用于节点发现（基于 Kademlia 协议），映射 TCP 端口用于数据传输。
// 自动发现：Any 函数并发尝试 UPnP 和 NAT-PMP，适应不同网络环境。
// 外部 IP：ExternalIP 方法提供节点在 ENR 中的外部地址。

// Interface An implementation of nat.Interface can map local ports to ports
// accessible from the Internet.
// 接口 nat.Interface 的实现可以将本地端口映射到互联网可访问的端口。
type Interface interface {
	// These methods manage a mapping between a port on the local
	// machine to a port that can be connected to from the internet.
	//
	// protocol is "UDP" or "TCP". Some implementations allow setting
	// a display name for the mapping. The mapping may be removed by
	// the gateway when its lifetime ends.
	// 这些方法管理本地机器上的端口与互联网可连接端口之间的映射。
	//
	// protocol 是 "UDP" 或 "TCP"。一些实现允许设置映射的显示名称。映射在生命周期结束后可能会被网关移除。
	AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error)
	DeleteMapping(protocol string, extport, intport int) error

	// ExternalIP should return the external (Internet-facing)
	// address of the gateway device.
	// ExternalIP 应返回网关设备的外部（面向互联网的）地址。
	ExternalIP() (net.IP, error)

	// String should return name of the method. This is used for logging.
	// String 应返回方法的名称，用于日志记录。
	String() string
}

// Parse parses a NAT interface description.
// The following formats are currently accepted.
// Note that mechanism names are not case-sensitive.
//
//	"" or "none"         return nil
//	"extip:77.12.33.4"   will assume the local machine is reachable on the given IP
//	"any"                uses the first auto-detected mechanism
//	"upnp"               uses the Universal Plug and Play protocol
//	"pmp"                uses NAT-PMP with an auto-detected gateway address
//	"pmp:192.168.0.1"    uses NAT-PMP with the given gateway address
//
// Parse 解析 NAT 接口描述。
// 当前接受以下格式。
// 注意机制名称对大小写不敏感。
//
//	"" 或 "none"         返回 nil
//	"extip:77.12.33.4"   假设本地机器在给定的 IP 上可达
//	"any"                使用第一个自动检测的机制
//	"upnp"               使用通用即插即用协议
//	"pmp"                使用 NAT-PMP 并自动检测网关地址
//	"pmp:192.168.0.1"    使用 NAT-PMP 并使用给定的网关地址
func Parse(spec string) (Interface, error) {
	var (
		before, after, found = strings.Cut(spec, ":")  // 分割字符串为前缀和后缀 / Split string into prefix and suffix
		mech                 = strings.ToLower(before) // 将机制转换为小写 / Convert mechanism to lowercase
		ip                   net.IP                    // IP 地址 / IP address
	)
	if found {
		ip = net.ParseIP(after) // 解析 IP 地址 / Parse IP address
		if ip == nil {
			return nil, errors.New("invalid IP address") // 如果 IP 无效则返回错误 / Return error if IP is invalid
		}
	}
	switch mech {
	case "", "none", "off":
		return nil, nil // 返回空接口 / Return nil interface
	case "any", "auto", "on":
		return Any(), nil // 返回自动检测的接口 / Return auto-detected interface
	case "extip", "ip":
		if ip == nil {
			return nil, errors.New("missing IP address") // 如果缺少 IP 则返回错误 / Return error if IP is missing
		}
		return ExtIP(ip), nil // 返回外部 IP 接口 / Return ExtIP interface
	case "upnp":
		return UPnP(), nil // 返回 UPnP 接口 / Return UPnP interface
	case "pmp", "natpmp", "nat-pmp":
		return PMP(ip), nil // 返回 NAT-PMP 接口 / Return NAT-PMP interface
	default:
		return nil, fmt.Errorf("unknown mechanism %q", before) // 返回未知机制错误 / Return unknown mechanism error
	}
}

const (
	// Default port mapping timeout
	// 默认端口映射超时时间
	DefaultMapTimeout = 10 * time.Minute
)

// Map adds a port mapping on m and keeps it alive until c is closed.
// This function is typically invoked in its own goroutine.
//
// Note that Map does not handle the situation where the NAT interface assigns a different
// external port than the requested one.
// Map 在 m 上添加端口映射并保持其活动，直到 c 关闭。
// 此函数通常在其自己的 goroutine 中调用。
//
// 注意，Map 不处理 NAT 接口分配与请求不同的外部端口的情况。
func Map(m Interface, c <-chan struct{}, protocol string, extport, intport int, name string) {
	log := log.New("proto", protocol, "extport", extport, "intport", intport, "interface", m) // 创建日志记录器 / Create logger
	refresh := time.NewTimer(DefaultMapTimeout)                                               // 创建刷新定时器 / Create refresh timer
	defer func() {
		refresh.Stop()                              // 停止定时器 / Stop timer
		log.Debug("Deleting port mapping")          // 记录删除映射 / Log deleting mapping
		m.DeleteMapping(protocol, extport, intport) // 删除端口映射 / Delete port mapping
	}()
	if _, err := m.AddMapping(protocol, extport, intport, name, DefaultMapTimeout); err != nil { // 添加初始映射 / Add initial mapping
		log.Debug("Couldn't add port mapping", "err", err) // 如果失败则记录错误 / Log error if failed
	} else {
		log.Info("Mapped network port") // 记录成功映射 / Log successful mapping
	}
	for {
		select {
		case _, ok := <-c: // 监听关闭信号 / Listen for close signal
			if !ok {
				return // 如果通道关闭则返回 / Return if channel closed
			}
		case <-refresh.C: // 定时刷新 / Periodic refresh
			log.Trace("Refreshing port mapping")                                                         // 记录刷新 / Log refresh
			if _, err := m.AddMapping(protocol, extport, intport, name, DefaultMapTimeout); err != nil { // 刷新映射 / Refresh mapping
				log.Debug("Couldn't add port mapping", "err", err) // 如果失败则记录错误 / Log error if failed
			}
			refresh.Reset(DefaultMapTimeout) // 重置定时器 / Reset timer
		}
	}
}

// ExtIP assumes that the local machine is reachable on the given
// external IP address, and that any required ports were mapped manually.
// Mapping operations will not return an error but won't actually do anything.
// ExtIP 假设本地机器在给定的外部 IP 地址上可达，并且任何所需的端口已手动映射。
// 映射操作不会返回错误，但实际上不会执行任何操作。
type ExtIP net.IP

func (n ExtIP) ExternalIP() (net.IP, error) { return net.IP(n), nil }                      // 返回外部 IP / Return external IP
func (n ExtIP) String() string              { return fmt.Sprintf("ExtIP(%v)", net.IP(n)) } // 返回字符串表示 / Return string representation

// These do nothing.
// 这些方法不执行任何操作。
func (ExtIP) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	return uint16(extport), nil // 返回外部端口，不执行映射 / Return extport, no mapping
}
func (ExtIP) DeleteMapping(string, int, int) error { return nil } // 不执行删除 / No deletion

// Any returns a port mapper that tries to discover any supported
// mechanism on the local network.
// Any 返回一个端口映射器，尝试发现本地网络上支持的任何机制。
func Any() Interface {
	// TODO: attempt to discover whether the local machine has an
	// Internet-class address. Return ExtIP in this case.
	// TODO：尝试发现本地机器是否具有互联网级地址，在此情况下返回 ExtIP。
	return startautodisc("UPnP or NAT-PMP", func() Interface { // 启动自动发现 / Start autodiscovery
		found := make(chan Interface, 2)        // 创建发现通道 / Create discovery channel
		go func() { found <- discoverUPnP() }() // 并发发现 UPnP / Discover UPnP concurrently
		go func() { found <- discoverPMP() }()  // 并发发现 NAT-PMP / Discover NAT-PMP concurrently
		for i := 0; i < cap(found); i++ {       // 检查所有结果 / Check all results
			if c := <-found; c != nil {
				return c // 返回第一个成功的机制 / Return first successful mechanism
			}
		}
		return nil // 如果都失败则返回 nil / Return nil if all fail
	})
}

// UPnP returns a port mapper that uses UPnP. It will attempt to
// discover the address of your router using UDP broadcasts.
// UPnP 返回一个使用 UPnP 的端口映射器。它将尝试使用 UDP 广播发现路由器的地址。
func UPnP() Interface {
	return startautodisc("UPnP", discoverUPnP) // 启动 UPnP 自动发现 / Start UPnP autodiscovery
}

// PMP returns a port mapper that uses NAT-PMP. The provided gateway
// address should be the IP of your router. If the given gateway
// address is nil, PMP will attempt to auto-discover the router.
// PMP 返回一个使用 NAT-PMP 的端口映射器。提供的网关地址应为路由器的 IP。
// 如果给定的网关地址为 nil，PMP 将尝试自动发现路由器。
func PMP(gateway net.IP) Interface {
	if gateway != nil {
		return &pmp{gw: gateway, c: natpmp.NewClient(gateway)} // 使用指定网关创建 NAT-PMP / Create NAT-PMP with specified gateway
	}
	return startautodisc("NAT-PMP", discoverPMP) // 启动 NAT-PMP 自动发现 / Start NAT-PMP autodiscovery
}

// autodisc represents a port mapping mechanism that is still being
// auto-discovered. Calls to the Interface methods on this type will
// wait until the discovery is done and then call the method on the
// discovered mechanism.
//
// This type is useful because discovery can take a while but we
// want return an Interface value from UPnP, PMP and Auto immediately.
// autodisc 表示仍在自动发现的端口映射机制。对此类型的 Interface 方法的调用将等待发现完成，
// 然后在发现的机制上调用该方法。
//
// 此类型很有用，因为发现可能需要一段时间，但我们希望从 UPnP、PMP 和 Auto 立即返回 Interface 值。
type autodisc struct {
	what string           // type of interface being autodiscovered / 正在自动发现的接口类型
	once sync.Once        // ensures discovery happens once / 确保发现只发生一次
	doit func() Interface // discovery function / 发现函数

	mu    sync.Mutex // protects found / 保护 found
	found Interface  // discovered mechanism / 已发现的机制
}

func startautodisc(what string, doit func() Interface) Interface {
	// TODO: monitor network configuration and rerun doit when it changes.
	// TODO：监控网络配置并在发生变化时重新运行 doit。
	return &autodisc{what: what, doit: doit} // 返回自动发现对象 / Return autodiscovery object
}

func (n *autodisc) AddMapping(protocol string, extport, intport int, name string, lifetime time.Duration) (uint16, error) {
	if err := n.wait(); err != nil { // 等待发现完成 / Wait for discovery
		return 0, err
	}
	return n.found.AddMapping(protocol, extport, intport, name, lifetime) // 调用已发现机制的 AddMapping / Call AddMapping on discovered mechanism
}

func (n *autodisc) DeleteMapping(protocol string, extport, intport int) error {
	if err := n.wait(); err != nil { // 等待发现完成 / Wait for discovery
		return err
	}
	return n.found.DeleteMapping(protocol, extport, intport) // 调用已发现机制的 DeleteMapping / Call DeleteMapping on discovered mechanism
}

func (n *autodisc) ExternalIP() (net.IP, error) {
	if err := n.wait(); err != nil { // 等待发现完成 / Wait for discovery
		return nil, err
	}
	return n.found.ExternalIP() // 调用已发现机制的 ExternalIP / Call ExternalIP on discovered mechanism
}

func (n *autodisc) String() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.found == nil {
		return n.what // 返回正在发现的类型 / Return type being discovered
	}
	return n.found.String() // 返回已发现机制的名称 / Return discovered mechanism's name
}

// wait blocks until auto-discovery has been performed.
// wait 阻塞直到自动发现完成。
func (n *autodisc) wait() error {
	n.once.Do(func() { // 只执行一次发现 / Perform discovery once
		n.mu.Lock()
		n.found = n.doit() // 执行发现函数 / Execute discovery function
		n.mu.Unlock()
	})
	if n.found == nil {
		return fmt.Errorf("no %s router discovered", n.what) // 如果未发现则返回错误 / Return error if not discovered
	}
	return nil
}
