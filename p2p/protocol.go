// Copyright 2014 The go-ethereum Authors
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
	"cmp"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

// devp2p 协议：以太坊的 P2P 网络基于 devp2p（EIP-8），支持多种子协议。Protocol 结构是实现这些子协议的基础。
//
// 协议协商：在连接对等节点时，双方交换能力列表（如 "eth/66"），通过比较版本号选择兼容的协议。
//
// ENR（EIP-778）：Attributes 字段支持 Ethereum Node Records，用于在发现协议中携带协议特定的键值对，例如支持的子协议或网络 ID。

// Protocol represents a P2P subprotocol implementation.
// Protocol 表示一个 P2P 子协议的实现。
type Protocol struct {
	// Name should contain the official protocol name,
	// often a three-letter word.
	// Name 应包含官方协议名称，通常是三个字母的单词。
	Name string

	// Version should contain the version number of the protocol.
	// Version 应包含协议的版本号。
	Version uint

	// Length should contain the number of message codes used
	// by the protocol.
	// Length 应包含协议使用的消息代码数量。
	Length uint64

	// Run is called in a new goroutine when the protocol has been
	// negotiated with a peer. It should read and write messages from
	// rw. The Payload for each message must be fully consumed.
	//
	// The peer connection is closed when Start returns. It should return
	// any protocol-level error (such as an I/O error) that is
	// encountered.
	//
	// Run 在与对等节点协商协议后在一个新的 goroutine 中被调用。
	// 它应从 rw 读取和写入消息。每条消息的 Payload 必须被完全消费。
	//
	// 当 Start 返回时，对等连接关闭。它应返回遇到的任何协议级错误（例如 I/O 错误）。
	Run func(peer *Peer, rw MsgReadWriter) error

	// NodeInfo is an optional helper method to retrieve protocol specific metadata
	// about the host node.
	// NodeInfo 是一个可选的辅助方法，用于检索关于主机节点的协议特定元数据。
	NodeInfo func() interface{}

	// PeerInfo is an optional helper method to retrieve protocol specific metadata
	// about a certain peer in the network. If an info retrieval function is set,
	// but returns nil, it is assumed that the protocol handshake is still running.
	//
	// PeerInfo 是一个可选的辅助方法，用于检索网络中某个对等节点的协议特定元数据。
	// 如果设置了信息检索函数但返回 nil，则假定协议握手仍在进行。
	PeerInfo func(id enode.ID) interface{}

	// DialCandidates, if non-nil, is a way to tell Server about protocol-specific nodes
	// that should be dialed. The server continuously reads nodes from the iterator and
	// attempts to create connections to them.
	//
	// DialCandidates 如果非 nil，是告诉服务器关于应拨号的协议特定节点的一种方式。
	// 服务器会持续从迭代器中读取节点并尝试与它们建立连接。
	DialCandidates enode.Iterator

	// Attributes contains protocol specific information for the node record.
	// Attributes 包含节点记录的协议特定信息。
	Attributes []enr.Entry
}

// 返回协议的能力
func (p Protocol) cap() Cap {
	return Cap{p.Name, p.Version}
}

// Cap is the structure of a peer capability.
// Cap 是对等节点能力的结构体。
type Cap struct {
	Name    string // 协议名称
	Version uint   // 协议版本
}

func (cap Cap) String() string {
	// 返回能力的字符串表示
	return fmt.Sprintf("%s/%d", cap.Name, cap.Version)
}

// Cmp defines the canonical sorting order of capabilities.
// Cmp 定义了能力的规范排序顺序。
func (cap Cap) Cmp(other Cap) int {
	// 如果名称相同，则比较版本
	if cap.Name == other.Name {
		return cmp.Compare(cap.Version, other.Version)
	}
	// 否则比较名称
	return strings.Compare(cap.Name, other.Name)
}
