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

package discover

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/ethereum/go-ethereum/metrics"
)

const (
	moduleName = "discover" // Module name for metrics / 模块名称用于指标
	// ingressMeterName is the prefix of the per-packet inbound metrics.
	// ingressMeterName 是每个数据包入站指标的前缀。
	ingressMeterName = moduleName + "/ingress"

	// egressMeterName is the prefix of the per-packet outbound metrics.
	// egressMeterName 是每个数据包出站指标的前缀。
	egressMeterName = moduleName + "/egress"
)

var (
	bucketsCounter      []*metrics.Counter                                  // Counters for each bucket / 每个桶的计数器
	ingressTrafficMeter = metrics.NewRegisteredMeter(ingressMeterName, nil) // Meter for inbound traffic / 入站流量的计量器
	egressTrafficMeter  = metrics.NewRegisteredMeter(egressMeterName, nil)  // Meter for outbound traffic / 出站流量的计量器
)

func init() {
	for i := 0; i < nBuckets; i++ {
		// Initialize counters for each bucket / 为每个桶初始化计数器
		bucketsCounter = append(bucketsCounter, metrics.NewRegisteredCounter(fmt.Sprintf("%s/bucket/%d/count", moduleName, i), nil))
	}
}

// meteredUdpConn is a wrapper around a net.UDPConn that meters both the
// inbound and outbound network traffic.
//
// meteredUdpConn 是对 net.UDPConn 的包装，用于计量入站和出站网络流量。
type meteredUdpConn struct {
	udpConn UDPConn // Underlying UDP connection / 底层的 UDP 连接
}

func newMeteredConn(conn UDPConn) UDPConn {
	// Short circuit if metrics are disabled
	// 如果指标被禁用，则直接返回原始连接
	if !metrics.Enabled() {
		return conn
	}
	return &meteredUdpConn{udpConn: conn} // Wrap connection with metering / 用计量包装连接
}

func (c *meteredUdpConn) Close() error {
	return c.udpConn.Close() // Delegate to underlying connection / 委托给底层连接
}

func (c *meteredUdpConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr() // Delegate to underlying connection / 委托给底层连接
}

// ReadFromUDPAddrPort delegates a network read to the underlying connection, bumping the udp ingress traffic meter along the way.
// ReadFromUDPAddrPort 将网络读取委托给底层连接，同时增加 UDP 入站流量计量。
func (c *meteredUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	n, addr, err = c.udpConn.ReadFromUDPAddrPort(b) // Read from underlying connection / 从底层连接读取
	ingressTrafficMeter.Mark(int64(n))              // Increment ingress meter by bytes read / 按读取的字节数增加入站计量器
	return n, addr, err
}

// WriteToUDPAddrPort delegates a network write to the underlying connection, bumping the udp egress traffic meter along the way.
// WriteToUDPAddrPort 将网络写入委托给底层连接，同时增加 UDP 出站流量计量。
func (c *meteredUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	n, err = c.udpConn.WriteToUDPAddrPort(b, addr) // Write to underlying connection / 写入底层连接
	egressTrafficMeter.Mark(int64(n))              // Increment egress meter by bytes written / 按写入的字节数增加出站计量器
	return n, err
}
