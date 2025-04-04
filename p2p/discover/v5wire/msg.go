// Copyright 2020 The go-ethereum Authors
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

package v5wire

import (
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// Discovery v5：EIP-1459 定义的协议，改进自 v4，增加了加密会话和隐私保护。
// Kademlia DHT：Findnode/Nodes 基于 Kademlia 算法，通过距离查询构建节点路由表。
// ENR：EIP-778 定义的节点记录，携带节点元数据，ENRSeq 用于版本控制。

// Discovery v5 协议使用这些方法统一处理不同类型的消息，确保协议的扩展性和一致性。
// 请求 ID 是 P2P 协议中的常见设计，用于异步通信中跟踪请求-响应对。

// Packet is implemented by all message types.
// Packet 由所有消息类型实现。
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	// Name 返回与消息类型对应的字符串。
	Kind() byte // Kind returns the message type.
	// Kind 返回消息类型。
	RequestID() []byte // Returns the request ID.
	// RequestID 返回请求 ID。
	SetRequestID([]byte) // Sets the request ID.
	// SetRequestID 设置请求 ID。

	// AppendLogInfo returns its argument 'ctx' with additional fields
	// appended for logging purposes.
	// AppendLogInfo 返回其参数 'ctx'，并附加用于日志记录的额外字段。
	AppendLogInfo(ctx []interface{}) []interface{}
}

// 这些消息类型对应 Discovery v5 协议（EIP-1459）定义的通信原语，用于节点发现和应用层交互。
// Ping/Pong 用于存活检测，Findnode/Nodes 用于 Kademlia 风格的节点查询。

// Message types.
// 消息类型。
const (
	PingMsg          byte = iota + 1 // PING 消息，从 1 开始计数
	PongMsg                          // PONG 消息
	FindnodeMsg                      // FINDNODE 消息
	NodesMsg                         // NODES 消息
	TalkRequestMsg                   // TALKREQ 消息
	TalkResponseMsg                  // TALKRESP 消息
	RequestTicketMsg                 // REQUESTTICKET 消息
	TicketMsg                        // TICKET 消息

	UnknownPacket   = byte(255) // any non-decryptable packet // 任何无法解密的数据包
	WhoareyouPacket = byte(254) // the WHOAREYOU packet // WHOAREYOU 数据包
)

// Protocol messages.
// 协议消息。
type (
	// Unknown represents any packet that can't be decrypted.
	// Unknown 表示任何无法解密的数据包。
	Unknown struct {
		Nonce Nonce // 请求的随机数
	}

	// Whoareyou 是 Discovery v5 握手过程的核心，用于在建立加密会话前验证对方身份。
	// IDNonce 和签名机制基于 Secp256k1 曲线，符合以太坊的加密标准。

	// WHOAREYOU contains the handshake challenge.
	// WHOAREYOU 包含握手挑战。
	Whoareyou struct {
		ChallengeData []byte   // Encoded challenge // 编码的挑战数据 编码后的挑战数据，用于验证握手响应。
		Nonce         Nonce    // Nonce of request packet // 请求数据包的随机数 请求数据包的随机数，用于防止重放攻击。
		IDNonce       [16]byte // Identity proof data // 身份证明数据 身份证明数据，要求对方签名以验证身份。
		RecordSeq     uint64   // ENR sequence number of recipient // 接收者的 ENR 序列号 接收者的 ENR 序列号，用于检查是否需要更新节点记录。

		// Node is the locally known node record of recipient.
		// This must be set by the caller of Encode.
		// Node 是接收者的本地已知节点记录。
		// 这必须由 Encode 的调用者设置。
		Node *enode.Node

		sent mclock.AbsTime // for handshake GC. // 用于握手垃圾回收的时间戳 发送时间，用于握手超时清理。
	}

	// PING is sent during liveness checks.
	// PING 在存活检查期间发送。
	Ping struct {
		ReqID  []byte // 请求 ID
		ENRSeq uint64 // ENR 序列号
	}

	// PONG is the reply to PING.
	// PONG 是对 PING 的回复。
	Pong struct {
		ReqID  []byte // 请求 ID
		ENRSeq uint64 // ENR 序列号
		ToIP   net.IP // These fields should mirror the UDP envelope address of the ping
		// 这些字段应反映 PING 数据包的 UDP 信封地址
		ToPort uint16 // packet, which provides a way to discover the external address (after NAT).
		// 数据包，提供了一种发现外部地址（经过 NAT 后）的方法。
	}

	// FINDNODE is a query for nodes in the given bucket.
	// FINDNODE 是对给定桶中节点的查询。
	Findnode struct {
		ReqID     []byte // 请求 ID
		Distances []uint // 距离列表

		// OpID is for debugging purposes and is not part of the packet encoding.
		// It identifies the 'operation' on behalf of which the request was sent.
		// OpID 用于调试目的，不包含在数据包编码中。
		// 它标识发送请求所代表的操作。
		OpID uint64 `rlp:"-"` // RLP 编码时忽略
	}

	// NODES is a response to FINDNODE.
	// NODES 是对 FINDNODE 的响应。
	Nodes struct {
		ReqID     []byte        // 请求 ID
		RespCount uint8         // 响应的总数
		Nodes     []*enr.Record // 节点记录列表
	}

	// TALKREQ is an application-level request.
	// TALKREQ 是应用级请求。
	TalkRequest struct {
		ReqID    []byte // 请求 ID
		Protocol string // 协议名称
		Message  []byte // 消息内容
	}

	// TALKRESP is the reply to TALKREQ.
	// TALKRESP 是对 TALKREQ 的回复。
	TalkResponse struct {
		ReqID   []byte // 请求 ID
		Message []byte // 消息内容
	}
)

// RLP 是以太坊的标准序列化格式，广泛用于协议消息和区块链数据。
// 8 字节的 RequestID 限制是协议设计的一部分，确保消息头部的紧凑性。

// DecodeMessage decodes the message body of a packet.
// DecodeMessage 解码数据包的消息体。
func DecodeMessage(ptype byte, body []byte) (Packet, error) {
	var dec Packet
	switch ptype {
	case PingMsg:
		dec = new(Ping)
	case PongMsg:
		dec = new(Pong)
	case FindnodeMsg:
		dec = new(Findnode)
	case NodesMsg:
		dec = new(Nodes)
	case TalkRequestMsg:
		dec = new(TalkRequest)
	case TalkResponseMsg:
		dec = new(TalkResponse)
	default:
		return nil, fmt.Errorf("unknown packet type %d", ptype)
	}
	if err := rlp.DecodeBytes(body, dec); err != nil {
		return nil, err
	}
	if dec.RequestID() != nil && len(dec.RequestID()) > 8 {
		return nil, ErrInvalidReqID
	}
	return dec, nil
}

func (*Whoareyou) Name() string        { return "WHOAREYOU/v5" }
func (*Whoareyou) Kind() byte          { return WhoareyouPacket }
func (*Whoareyou) RequestID() []byte   { return nil }
func (*Whoareyou) SetRequestID([]byte) {}

func (*Whoareyou) AppendLogInfo(ctx []interface{}) []interface{} {
	return ctx
}

func (*Unknown) Name() string        { return "UNKNOWN/v5" }
func (*Unknown) Kind() byte          { return UnknownPacket }
func (*Unknown) RequestID() []byte   { return nil }
func (*Unknown) SetRequestID([]byte) {}

func (*Unknown) AppendLogInfo(ctx []interface{}) []interface{} {
	return ctx
}

func (*Ping) Name() string             { return "PING/v5" }
func (*Ping) Kind() byte               { return PingMsg }
func (p *Ping) RequestID() []byte      { return p.ReqID }
func (p *Ping) SetRequestID(id []byte) { p.ReqID = id }

func (p *Ping) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(p.ReqID), "enrseq", p.ENRSeq)
}

func (*Pong) Name() string             { return "PONG/v5" }
func (*Pong) Kind() byte               { return PongMsg }
func (p *Pong) RequestID() []byte      { return p.ReqID }
func (p *Pong) SetRequestID(id []byte) { p.ReqID = id }

func (p *Pong) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(p.ReqID), "enrseq", p.ENRSeq)
}

func (p *Findnode) Name() string           { return "FINDNODE/v5" }
func (p *Findnode) Kind() byte             { return FindnodeMsg }
func (p *Findnode) RequestID() []byte      { return p.ReqID }
func (p *Findnode) SetRequestID(id []byte) { p.ReqID = id }

func (p *Findnode) AppendLogInfo(ctx []interface{}) []interface{} {
	ctx = append(ctx, "req", hexutil.Bytes(p.ReqID))
	if p.OpID != 0 {
		ctx = append(ctx, "opid", p.OpID)
	}
	return ctx
}

func (*Nodes) Name() string             { return "NODES/v5" }
func (*Nodes) Kind() byte               { return NodesMsg }
func (p *Nodes) RequestID() []byte      { return p.ReqID }
func (p *Nodes) SetRequestID(id []byte) { p.ReqID = id }

func (p *Nodes) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx,
		"req", hexutil.Bytes(p.ReqID),
		"tot", p.RespCount,
		"n", len(p.Nodes),
	)
}

func (*TalkRequest) Name() string             { return "TALKREQ/v5" }
func (*TalkRequest) Kind() byte               { return TalkRequestMsg }
func (p *TalkRequest) RequestID() []byte      { return p.ReqID }
func (p *TalkRequest) SetRequestID(id []byte) { p.ReqID = id }

func (p *TalkRequest) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "proto", p.Protocol, "req", hexutil.Bytes(p.ReqID), "len", len(p.Message))
}

func (*TalkResponse) Name() string             { return "TALKRESP/v5" }
func (*TalkResponse) Kind() byte               { return TalkResponseMsg }
func (p *TalkResponse) RequestID() []byte      { return p.ReqID }
func (p *TalkResponse) SetRequestID(id []byte) { p.ReqID = id }

func (p *TalkResponse) AppendLogInfo(ctx []interface{}) []interface{} {
	return append(ctx, "req", hexutil.Bytes(p.ReqID), "len", len(p.Message))
}
