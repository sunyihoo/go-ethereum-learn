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

// Package v4wire implements the Discovery v4 Wire Protocol.
package v4wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// RPC packet types
// RPC 数据包类型
const (
	PingPacket = iota + 1 // zero is 'reserved' 0 被保留
	PongPacket
	FindnodePacket
	NeighborsPacket
	ENRRequestPacket
	ENRResponsePacket
)

// RPC request structures
// RPC 请求结构
type (
	Ping struct {
		Version    uint     // 协议版本
		From, To   Endpoint // 发送方和接收方的端点
		Expiration uint64   // 数据包过期时间戳
		ENRSeq     uint64   `rlp:"optional"` // Sequence number of local record, added by EIP-868. 本地记录的序列号，由 EIP-868 添加

		// Ignore additional fields (for forward compatibility). 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Pong is the reply to ping.
	// Pong 是对 ping 的回复
	Pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// external address (after NAT).
		// 该字段应反映 ping 数据包的 UDP 信封地址，提供一种发现外部地址的方法（经过 NAT）
		To         Endpoint // 接收方的端点
		ReplyTok   []byte   // This contains the hash of the ping packet. 包含 ping 数据包的哈希
		Expiration uint64   // Absolute timestamp at which the packet becomes invalid. 数据包失效的绝对时间戳
		ENRSeq     uint64   `rlp:"optional"` // Sequence number of local record, added by EIP-868. 本地记录的序列号，由 EIP-868 添加

		// Ignore additional fields (for forward compatibility).
		// 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Findnode is a query for nodes close to the given target.
	// Findnode 是查询靠近给定目标的节点
	Findnode struct {
		Target     Pubkey // 目标公钥
		Expiration uint64 // 数据包过期时间戳
		// Ignore additional fields (for forward compatibility).
		// 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// Neighbors is the reply to findnode.
	// Neighbors 是对 findnode 的回复
	Neighbors struct {
		Nodes      []Node // 邻居节点列表
		Expiration uint64 // 数据包过期时间戳
		// Ignore additional fields (for forward compatibility).
		// 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// ENRRequest queries for the remote node's record.
	// ENRRequest 查询远程节点的记录
	ENRRequest struct {
		Expiration uint64 // 数据包过期时间戳
		// Ignore additional fields (for forward compatibility).
		// 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// ENRResponse is the reply to ENRRequest.
	// ENRResponse 是对 ENRRequest 的回复
	ENRResponse struct {
		ReplyTok []byte     // Hash of the ENRRequest packet. // ENRRequest 数据包的哈希
		Record   enr.Record // 节点的 ENR 记录
		// Ignore additional fields (for forward compatibility).
		// 忽略额外字段（为了向前兼容性）
		Rest []rlp.RawValue `rlp:"tail"`
	}
)

// MaxNeighbors is the maximum number of neighbor nodes in a Neighbors packet.
// MaxNeighbors 是 Neighbors 数据包中邻居节点的最大数量
const MaxNeighbors = 12

// This code computes the MaxNeighbors constant value.
// 这段代码计算 MaxNeighbors 常量的值

// func init() {
// 	var maxNeighbors int
// 	p := Neighbors{Expiration: ^uint64(0)}
// 	maxSizeNode := Node{IP: make(net.IP, 16), UDP: ^uint16(0), TCP: ^uint16(0)}
// 	for n := 0; ; n++ {
// 		p.Nodes = append(p.Nodes, maxSizeNode)
// 		size, _, err := rlp.EncodeToReader(p)
// 		if err != nil {
// 			// If this ever happens, it will be caught by the unit tests.
// 			// 如果发生这种情况，将由单元测试捕获
// 			panic("cannot encode: " + err.Error())
// 		}
// 		if headSize+size+1 >= 1280 {
// 			maxNeighbors = n
// 			break
// 		}
// 	}
// 	fmt.Println("maxNeighbors", maxNeighbors)
// }

// Pubkey represents an encoded 64-byte secp256k1 public key.
// Pubkey 表示编码后的 64 字节 secp256k1 公钥
type Pubkey [64]byte

// ID returns the node ID corresponding to the public key.
// ID 返回对应公钥的节点 ID
func (e Pubkey) ID() enode.ID {
	return enode.ID(crypto.Keccak256Hash(e[:]))
}

// Node represents information about a node.
// Node 表示节点的信息
type Node struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6 IPv4 为 4 字节，IPv6 为 16 字节
	UDP uint16 // for discovery protocol 用于发现协议
	TCP uint16 // for RLPx protocol 节点的公钥
	ID  Pubkey
}

// Endpoint represents a network endpoint.
// Endpoint 表示网络端点
type Endpoint struct {
	IP  net.IP // len 4 for IPv4 or 16 for IPv6 IPv4 为 4 字节，IPv6 为 16 字节
	UDP uint16 // for discovery protocol 用于发现协议
	TCP uint16 // for RLPx protocol 用于 RLPx 协议
}

// NewEndpoint creates an endpoint.
// NewEndpoint 创建一个端点
func NewEndpoint(addr netip.AddrPort, tcpPort uint16) Endpoint {
	var ip net.IP
	if addr.Addr().Is4() || addr.Addr().Is4In6() {
		ip4 := addr.Addr().As4()
		ip = ip4[:]
	} else {
		ip = addr.Addr().AsSlice()
	}
	return Endpoint{IP: ip, UDP: addr.Port(), TCP: tcpPort}
}

type Packet interface {
	// Name is the name of the package, for logging purposes.
	// Name 是数据包的名称，用于日志记录
	Name() string
	// Kind is the packet type, for logging purposes.
	// Kind 是数据包类型，用于日志记录
	Kind() byte
}

func (req *Ping) Name() string { return "PING/v4" }
func (req *Ping) Kind() byte   { return PingPacket }

func (req *Pong) Name() string { return "PONG/v4" }
func (req *Pong) Kind() byte   { return PongPacket }

func (req *Findnode) Name() string { return "FINDNODE/v4" }
func (req *Findnode) Kind() byte   { return FindnodePacket }

func (req *Neighbors) Name() string { return "NEIGHBORS/v4" }
func (req *Neighbors) Kind() byte   { return NeighborsPacket }

func (req *ENRRequest) Name() string { return "ENRREQUEST/v4" }
func (req *ENRRequest) Kind() byte   { return ENRRequestPacket }

func (req *ENRResponse) Name() string { return "ENRRESPONSE/v4" }
func (req *ENRResponse) Kind() byte   { return ENRResponsePacket }

// Expired checks whether the given UNIX time stamp is in the past.
// Expired 检查给定的 UNIX 时间戳是否已过期
func Expired(ts uint64) bool {
	return time.Unix(int64(ts), 0).Before(time.Now())
}

// Encoder/decoder.
// 编码器/解码器

const (
	macSize  = 32
	sigSize  = crypto.SignatureLength
	headSize = macSize + sigSize // space of packet frame data 数据包框架数据的空间大小
)

var (
	// ErrPacketTooSmall 表示数据包太小
	ErrPacketTooSmall = errors.New("too small")
	// ErrBadHash 表示哈希错误
	ErrBadHash = errors.New("bad hash")
	// ErrBadPoint 表示无效的曲线点
	ErrBadPoint = errors.New("invalid curve point")
)

var headSpace = make([]byte, headSize)

// Decode reads a discovery v4 packet.
// Decode 读取一个发现 v4 数据包
func Decode(input []byte) (Packet, Pubkey, []byte, error) {
	if len(input) < headSize+1 {
		return nil, Pubkey{}, nil, ErrPacketTooSmall
	}
	hash, sig, sigdata := input[:macSize], input[macSize:headSize], input[headSize:]
	shouldhash := crypto.Keccak256(input[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, Pubkey{}, nil, ErrBadHash
	}
	fromKey, err := recoverNodeKey(crypto.Keccak256(input[headSize:]), sig)
	if err != nil {
		return nil, fromKey, hash, err
	}

	var req Packet
	switch ptype := sigdata[0]; ptype {
	case PingPacket:
		req = new(Ping)
	case PongPacket:
		req = new(Pong)
	case FindnodePacket:
		req = new(Findnode)
	case NeighborsPacket:
		req = new(Neighbors)
	case ENRRequestPacket:
		req = new(ENRRequest)
	case ENRResponsePacket:
		req = new(ENRResponse)
	default:
		return nil, fromKey, hash, fmt.Errorf("unknown type: %d", ptype)
	}
	// Here we use NewStream to allow for additional data after the first
	// RLP object (forward-compatibility).
	// 这里我们使用 NewStream 以允许在第一个 RLP 对象后有额外数据（向前兼容性）
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(req)
	return req, fromKey, hash, err
}

// Encode encodes a discovery packet.
// Encode 编码一个发现数据包
func Encode(priv *ecdsa.PrivateKey, req Packet) (packet, hash []byte, err error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(req.Kind())
	if err := rlp.Encode(b, req); err != nil {
		return nil, nil, err
	}
	packet = b.Bytes()
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		return nil, nil, err
	}
	copy(packet[macSize:], sig)
	// Add the hash to the front. Note: this doesn't protect the packet in any way.
	// 将哈希添加到前面。注意：这并不能以任何方式保护数据包
	hash = crypto.Keccak256(packet[macSize:])
	copy(packet, hash)
	return packet, hash, nil
}

// recoverNodeKey computes the public key used to sign the given hash from the signature.
// recoverNodeKey 从签名中计算用于签署给定哈希的公钥
func recoverNodeKey(hash, sig []byte) (key Pubkey, err error) {
	pubkey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return key, err
	}
	copy(key[:], pubkey[1:])
	return key, nil
}

// EncodePubkey encodes a secp256k1 public key.
// EncodePubkey 编码一个 secp256k1 公钥
func EncodePubkey(key *ecdsa.PublicKey) Pubkey {
	var e Pubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

// DecodePubkey reads an encoded secp256k1 public key.
// DecodePubkey 读取一个编码的 secp256k1 公钥
func DecodePubkey(curve elliptic.Curve, e Pubkey) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: curve, X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, ErrBadPoint
	}
	return p, nil
}
