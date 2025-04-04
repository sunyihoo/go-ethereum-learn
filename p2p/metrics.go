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

// Contains the meters and timers used by the networking layer.

package p2p

import (
	"errors"
	"net"

	"github.com/ethereum/go-ethereum/metrics"
)

// P2P 网络在以太坊中的作用
// 以太坊使用 P2P 网络实现节点间的数据同步和通信（如区块、交易传播）。监控 peer 数量和流量对于确保网络健康至关重要。
// RLPx 协议
// 以太坊的 P2P 通信基于 RLPx 协议，它包括加密握手（dialEncHandshakeError）和协议握手（dialProtoHandshakeError）。
// 加密握手使用 ECIES（椭圆曲线集成加密方案）确保通信安全。
// 协议握手协商具体的子协议（如 ETH 协议）。

const (
	// HandleHistName is the prefix of the per-packet serving time histograms.
	// HandleHistName 是每个数据包服务时间直方图的前缀。
	HandleHistName = "p2p/handle"

	// ingressMeterName is the prefix of the per-packet inbound metrics.
	// ingressMeterName 是每个数据包入站度量的前缀。
	ingressMeterName = "p2p/ingress"

	// egressMeterName is the prefix of the per-packet outbound metrics.
	// egressMeterName 是每个数据包出站度量的前缀。
	egressMeterName = "p2p/egress"
)

var (
	activePeerGauge         = metrics.NewRegisteredGauge("p2p/peers", nil)
	activeInboundPeerGauge  = metrics.NewRegisteredGauge("p2p/peers/inbound", nil)
	activeOutboundPeerGauge = metrics.NewRegisteredGauge("p2p/peers/outbound", nil)

	ingressTrafficMeter = metrics.NewRegisteredMeter("p2p/ingress", nil)
	egressTrafficMeter  = metrics.NewRegisteredMeter("p2p/egress", nil)

	// general ingress/egress connection meters
	// 通用入站/出站连接度量
	serveMeter          = metrics.NewRegisteredMeter("p2p/serves", nil)
	serveSuccessMeter   = metrics.NewRegisteredMeter("p2p/serves/success", nil)
	dialMeter           = metrics.NewRegisteredMeter("p2p/dials", nil)
	dialSuccessMeter    = metrics.NewRegisteredMeter("p2p/dials/success", nil)
	dialConnectionError = metrics.NewRegisteredMeter("p2p/dials/error/connection", nil)

	// handshake error meters
	// 握手错误度量
	dialTooManyPeers        = metrics.NewRegisteredMeter("p2p/dials/error/saturated", nil)
	dialAlreadyConnected    = metrics.NewRegisteredMeter("p2p/dials/error/known", nil)
	dialSelf                = metrics.NewRegisteredMeter("p2p/dials/error/self", nil)
	dialUselessPeer         = metrics.NewRegisteredMeter("p2p/dials/error/useless", nil)
	dialUnexpectedIdentity  = metrics.NewRegisteredMeter("p2p/dials/error/id/unexpected", nil)
	dialEncHandshakeError   = metrics.NewRegisteredMeter("p2p/dials/error/rlpx/enc", nil)
	dialProtoHandshakeError = metrics.NewRegisteredMeter("p2p/dials/error/rlpx/proto", nil)
)

// markDialError matches errors that occur while setting up a dial connection
// to the corresponding meter.
// markDialError 将在设置拨号连接时发生的错误与相应的度量器匹配。
func markDialError(err error) {
	if !metrics.Enabled() {
		return
	}
	if err2 := errors.Unwrap(err); err2 != nil {
		err = err2
	}
	switch err {
	case DiscTooManyPeers:
		dialTooManyPeers.Mark(1)
	case DiscAlreadyConnected:
		dialAlreadyConnected.Mark(1)
	case DiscSelf:
		dialSelf.Mark(1)
	case DiscUselessPeer:
		dialUselessPeer.Mark(1)
	case DiscUnexpectedIdentity:
		dialUnexpectedIdentity.Mark(1)
	case errEncHandshakeError:
		dialEncHandshakeError.Mark(1)
	case errProtoHandshakeError:
		dialProtoHandshakeError.Mark(1)
	}
}

// meteredConn is a wrapper around a net.Conn that meters both the
// inbound and outbound network traffic.
// meteredConn 是 net.Conn 的包装器，用于度量入站和出站网络流量。
type meteredConn struct {
	net.Conn
}

// newMeteredConn creates a new metered connection, bumps the ingress or egress
// connection meter and also increases the metered peer count. If the metrics
// system is disabled, function returns the original connection.
// newMeteredConn 创建一个新的 metered 连接，增加入站或出站连接度量，并增加 metered peer 计数。
// 如果度量系统被禁用，函数返回原始连接。
func newMeteredConn(conn net.Conn) net.Conn {
	if !metrics.Enabled() {
		return conn
	}
	return &meteredConn{Conn: conn}
}

// Read delegates a network read to the underlying connection, bumping the common
// and the peer ingress traffic meters along the way.
// Read 将网络读取委托给底层连接，并在过程中增加通用和 peer 入站流量度量。
func (c *meteredConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	ingressTrafficMeter.Mark(int64(n))
	return n, err
}

// Write delegates a network write to the underlying connection, bumping the common
// and the peer egress traffic meters along the way.
// Write 将网络写入委托给底层连接，并在过程中增加通用和 peer 出站流量度量。
func (c *meteredConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	egressTrafficMeter.Mark(int64(n))
	return n, err
}
