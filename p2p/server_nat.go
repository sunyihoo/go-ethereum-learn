// Copyright 2023 The go-ethereum Authors
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
	"net"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/nat"
)

// 节点发现：以太坊使用 UDP 协议（基于 discv4 或 discv5，EIP-868）发现对等节点，需映射 UDP 端口。
//
// P2P 通信：TCP 端口用于区块同步和交易传播，映射确保节点可接受外部连接。
//
// ENR（EIP-778）：端口和 IP 信息存储在 ENR 中，供其他节点查询。

const (
	portMapDuration        = 10 * time.Minute // 端口映射持续时间
	portMapRefreshInterval = 8 * time.Minute  // 端口映射刷新间隔
	portMapRetryInterval   = 5 * time.Minute  // 端口映射重试间隔
	extipRetryInterval     = 2 * time.Minute  // 外部 IP 重试间隔
)

type portMapping struct {
	protocol string // 协议类型（TCP/UDP）
	name     string // 映射名称
	port     int    // 内部端口

	// for use by the portMappingLoop goroutine:
	// 供 portMappingLoop goroutine 使用：
	extPort  int            //  the mapped port returned by the NAT interface / NAT 接口返回的映射端口
	nextTime mclock.AbsTime // 下次刷新或重试的计划时间
}

// setupPortMapping starts the port mapping loop if necessary.
// Note: this needs to be called after the LocalNode instance has been set on the server.
//
// setupPortMapping 在必要时启动端口映射循环。
// 注意：这需要在服务器上设置 LocalNode 实例后调用。
func (srv *Server) setupPortMapping() {
	// portMappingRegister will receive up to two values: one for the TCP port if
	// listening is enabled, and one more for enabling UDP port mapping if discovery is
	// enabled. We make it buffered to avoid blocking setup while a mapping request is in
	// progress.
	//
	// portMappingRegister 将接收最多两个值：如果启用了侦听，则一个用于 TCP 端口，如果启用了发现，则另一个用于启用 UDP 端口映射。
	// 我们将其设置为缓冲，以避免在映射请求正在进行时阻止设置。
	srv.portMappingRegister = make(chan *portMapping, 2)

	switch srv.NAT.(type) {
	case nil:
		// No NAT interface configured.
		// 未配置 NAT 接口。
		srv.loopWG.Add(1)
		go srv.consumePortMappingRequests()

	case nat.ExtIP:
		// ExtIP doesn't block, set the IP right away.
		// ExtIP 不会阻塞，立即设置 IP。
		ip, _ := srv.NAT.ExternalIP()
		srv.localnode.SetStaticIP(ip)
		srv.loopWG.Add(1)
		go srv.consumePortMappingRequests()

	default:
		srv.loopWG.Add(1)
		go srv.portMappingLoop()
	}
}

func (srv *Server) consumePortMappingRequests() {
	defer srv.loopWG.Done()
	for {
		select {
		case <-srv.quit:
			return
		case <-srv.portMappingRegister:
		}
	}
}

// portMappingLoop manages port mappings for UDP and TCP.
// portMappingLoop 管理 UDP 和 TCP 的端口映射。
func (srv *Server) portMappingLoop() {
	defer srv.loopWG.Done()

	newLogger := func(p string, e int, i int) log.Logger {
		// Create a new logger with protocol, external port, and internal port
		// 创建一个带有协议、外部端口和内部端口的新日志记录器
		return log.New("proto", p, "extport", e, "intport", i, "interface", srv.NAT)
	}

	var (
		mappings  = make(map[string]*portMapping, 2) // 存储 TCP 和 UDP 的映射
		refresh   = mclock.NewAlarm(srv.clock)       // 用于刷新映射的闹钟
		extip     = mclock.NewAlarm(srv.clock)       // 用于检查外部 IP 的闹钟
		lastExtIP net.IP                             // 上次已知的外部 IP
	)
	extip.Schedule(srv.clock.Now())
	defer func() {
		refresh.Stop()
		extip.Stop()
		for _, m := range mappings {
			if m.extPort != 0 {
				log := newLogger(m.protocol, m.extPort, m.port)
				log.Debug("Deleting port mapping") // 删除端口映射
				srv.NAT.DeleteMapping(m.protocol, m.extPort, m.port)
			}
		}
	}()

	for {
		// Schedule refresh of existing mappings.
		// 安排现有映射的刷新。
		for _, m := range mappings {
			refresh.Schedule(m.nextTime)
		}

		select {
		case <-srv.quit:
			return

		case <-extip.C():
			// Check and update external IP periodically
			// 定期检查并更新外部 IP
			extip.Schedule(srv.clock.Now().Add(extipRetryInterval))
			ip, err := srv.NAT.ExternalIP()
			if err != nil {
				log.Debug("Couldn't get external IP", "err", err, "interface", srv.NAT) // 无法获取外部 IP
			} else if !ip.Equal(lastExtIP) {
				log.Debug("External IP changed", "ip", ip, "interface", srv.NAT) // 外部 IP 已更改
			} else {
				continue
			}
			// Here, we either failed to get the external IP, or it has changed.
			// 这里，要么无法获取外部 IP，要么它已更改。
			lastExtIP = ip
			srv.localnode.SetStaticIP(ip)
			// Ensure port mappings are refreshed in case we have moved to a new network.
			// 确保端口映射在网络更改时刷新。
			for _, m := range mappings {
				m.nextTime = srv.clock.Now()
			}

		case m := <-srv.portMappingRegister:
			if m.protocol != "TCP" && m.protocol != "UDP" {
				panic("unknown NAT protocol name: " + m.protocol) // 未知的 NAT 协议名称
			}
			mappings[m.protocol] = m
			m.nextTime = srv.clock.Now()

		case <-refresh.C():
			for _, m := range mappings {
				if srv.clock.Now() < m.nextTime {
					continue
				}

				external := m.port
				if m.extPort != 0 {
					external = m.extPort
				}
				log := newLogger(m.protocol, external, m.port)

				log.Trace("Attempting port mapping") // 尝试端口映射
				p, err := srv.NAT.AddMapping(m.protocol, external, m.port, m.name, portMapDuration)
				if err != nil {
					log.Debug("Couldn't add port mapping", "err", err) // 无法添加端口映射
					m.extPort = 0
					m.nextTime = srv.clock.Now().Add(portMapRetryInterval)
					continue
				}
				// It was mapped!
				// 映射成功！
				m.extPort = int(p)
				m.nextTime = srv.clock.Now().Add(portMapRefreshInterval)
				if external != m.extPort {
					log = newLogger(m.protocol, m.extPort, m.port)
					log.Info("NAT mapped alternative port") // NAT 映射了替代端口
				} else {
					log.Info("NAT mapped port") // NAT 映射了端口
				}

				// Update port in local ENR.
				// 更新本地 ENR 中的端口。
				switch m.protocol {
				case "TCP":
					srv.localnode.Set(enr.TCP(m.extPort))
				case "UDP":
					srv.localnode.SetFallbackUDP(m.extPort)
				}
			}
		}
	}
}
