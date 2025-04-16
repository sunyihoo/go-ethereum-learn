// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enr"
)

// ENR（Ethereum Node Records） 是以太坊节点发现协议（Discovery v4/v5）的一部分，基于 EIP-778 定义，用于存储节点的元数据（如 IP、端口、公钥等）。
//
// TCP 端口用于以太坊的 P2P 通信（如交易和区块同步），UDP 端口用于节点发现协议。
//
// 签名机制确保节点信息的可信性，防止伪造。

var (
	// incompleteNodeURL is a regular expression to match incomplete node URLs
	// incompleteNodeURL 是一个正则表达式，用于匹配不完整的节点 URL
	incompleteNodeURL = regexp.MustCompile("(?i)^(?:enode://)?([0-9a-f]+)$")
)

// MustParseV4 parses a node URL. It panics if the URL is not valid.
// MustParseV4 解析一个节点 URL。如果 URL 无效，它会引发 panic。
func MustParseV4(rawurl string) *Node {
	n, err := ParseV4(rawurl)
	if err != nil {
		panic("invalid node URL: " + err.Error())
	}
	return n
}

// ParseV4 parses a node URL.
//
// There are two basic forms of node URLs:
//
//   - incomplete nodes, which only have the public key (node ID)
//   - complete nodes, which contain the public key and IP/Port information
//
// For incomplete nodes, the designator must look like one of these
//
//	enode://<hex node id>
//	<hex node id>
//
// For complete nodes, the node ID is encoded in the username portion
// of the URL, separated from the host by an @ sign. The hostname can
// only be given as an IP address or using DNS domain name.
// The port in the host name section is the TCP listening port. If the
// TCP and UDP (discovery) ports differ, the UDP port is specified as
// query parameter "discport".
//
// In the following example, the node URL describes
// a node with IP address 10.3.58.6, TCP listening port 30303
// and UDP discovery port 30301.
//
//	enode://<hex node id>@10.3.58.6:30303?discport=30301
//
// ParseV4 解析一个节点 URL。
//
// 节点 URL 有两种基本形式：
//   - 不完整节点，仅包含公钥（节点 ID）
//   - 完整节点，包含公钥和 IP/端口信息
//
// 对于不完整节点，其标识符必须如下所示：
//
//	enode://<十六进制节点 ID>
//	<十六进制节点 ID>
//
// 对于完整节点，节点 ID 编码在 URL 的用户名部分，与主机通过 @ 符号分隔。
// 主机名只能以 IP 地址或 DNS 域名形式给出。
// 主机名部分的端口是 TCP 监听端口。如果 TCP 和 UDP（发现）端口不同，
// UDP 端口通过查询参数 "discport" 指定。
//
// 在以下示例中，节点 URL 描述了一个节点，其 IP 地址为 10.3.58.6，
// TCP 监听端口为 30303，UDP 发现端口为 30301。
//
//	enode://<十六进制节点 ID>@10.3.58.6:30303?discport=30301
func ParseV4(rawurl string) (*Node, error) {
	if m := incompleteNodeURL.FindStringSubmatch(rawurl); m != nil {
		id, err := parsePubkey(m[1])
		if err != nil {
			return nil, fmt.Errorf("invalid public key (%v)", err)
		}
		return NewV4(id, nil, 0, 0), nil
	}
	return parseComplete(rawurl)
}

// NewV4 creates a node from discovery v4 node information. The record
// contained in the node has a zero-length signature.
//
// NewV4 从 discovery v4 节点信息创建一个节点。节点中包含的记录具有零长度签名。
func NewV4(pubkey *ecdsa.PublicKey, ip net.IP, tcp, udp int) *Node {
	var r enr.Record
	if len(ip) > 0 {
		r.Set(enr.IP(ip))
	}
	if udp != 0 {
		r.Set(enr.UDP(udp))
	}
	if tcp != 0 {
		r.Set(enr.TCP(tcp))
	}
	signV4Compat(&r, pubkey)
	n, err := New(v4CompatID{}, &r)
	if err != nil {
		panic(err)
	}
	return n
}

// Discovery v4 协议：
// 以太坊使用基于 UDP 的节点发现协议（EIP-868 和 EIP-778），通过 Kademlia DHT 算法定位网络中的节点。
//
// enode URL 是节点发现的入口，包含足够信息以建立连接。
//
// secp256k1 公钥：
// 以太坊的地址和节点 ID 都依赖于 secp256k1 椭圆曲线，PubkeyToIDV4 使用 Keccak256 哈希从公钥派生节点 ID。
//
// ENR（Ethereum Node Records）：
// ENR 是以太坊对传统节点记录的扩展，支持动态元数据和签名验证。

// isNewV4 returns true for nodes created by NewV4.
// isNewV4 对于由 NewV4 创建的节点返回 true。
func isNewV4(n *Node) bool {
	var k s256raw
	return n.r.IdentityScheme() == "" && n.r.Load(&k) == nil && len(n.r.Signature()) == 0
}

func parseComplete(rawurl string) (*Node, error) {
	var (
		id               *ecdsa.PublicKey
		tcpPort, udpPort uint64
	)
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "enode" {
		return nil, errors.New("invalid URL scheme, want \"enode\"")
	}
	// Parse the Node ID from the user portion.
	// 从用户部分解析节点 ID。
	if u.User == nil {
		return nil, errors.New("does not contain node ID")
	}
	if id, err = parsePubkey(u.User.String()); err != nil {
		return nil, fmt.Errorf("invalid public key (%v)", err)
	}

	// Parse the IP and ports.
	// 解析 IP 和端口。
	ip := net.ParseIP(u.Hostname())
	if tcpPort, err = strconv.ParseUint(u.Port(), 10, 16); err != nil {
		return nil, errors.New("invalid port")
	}
	udpPort = tcpPort
	qv := u.Query()
	if qv.Get("discport") != "" {
		udpPort, err = strconv.ParseUint(qv.Get("discport"), 10, 16)
		if err != nil {
			return nil, errors.New("invalid discport in query")
		}
	}

	// Create the node.
	// 创建节点。
	node := NewV4(id, ip, int(tcpPort), int(udpPort))
	if ip == nil && u.Hostname() != "" {
		node = node.WithHostname(u.Hostname())
	}
	return node, nil
}

// parsePubkey parses a hex-encoded secp256k1 public key.
// parsePubkey 解析一个十六进制编码的 secp256k1 公钥。
func parsePubkey(in string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	} else if len(b) != 64 {
		return nil, fmt.Errorf("wrong length, want %d hex chars", 128)
	}
	b = append([]byte{0x4}, b...)
	return crypto.UnmarshalPubkey(b)
}

func (n *Node) URLv4() string {
	var (
		scheme enr.ID
		nodeid string
		key    ecdsa.PublicKey
	)
	n.Load(&scheme)
	n.Load((*Secp256k1)(&key))
	switch {
	case scheme == "v4" || key != ecdsa.PublicKey{}:
		nodeid = fmt.Sprintf("%x", crypto.FromECDSAPub(&key)[1:])
	default:
		nodeid = fmt.Sprintf("%s.%x", scheme, n.id[:])
	}
	u := url.URL{Scheme: "enode"}
	if n.Hostname() != "" {
		// For nodes with a DNS name: include DNS name, TCP port, and optional UDP port
		// 对于具有 DNS 名称的节点：包括 DNS 名称、TCP 端口和可选的 UDP 端口
		u.User = url.User(nodeid)
		u.Host = fmt.Sprintf("%s:%d", n.Hostname(), n.TCP())
		if n.UDP() != n.TCP() {
			u.RawQuery = "discport=" + strconv.Itoa(n.UDP())
		}
	} else if n.ip.IsValid() {
		// For IP-based nodes: include IP address, TCP port, and optional UDP port
		// 对于基于 IP 的节点：包括 IP 地址、TCP 端口和可选的 UDP 端口
		addr := net.TCPAddr{IP: n.IP(), Port: n.TCP()}
		u.User = url.User(nodeid)
		u.Host = addr.String()
		if n.UDP() != n.TCP() {
			u.RawQuery = "discport=" + strconv.Itoa(n.UDP())
		}
	} else {
		u.Host = nodeid
	}
	return u.String()
}

// PubkeyToIDV4 derives the v4 node address from the given public key.
// PubkeyToIDV4 从给定的公钥派生 v4 节点地址。
func PubkeyToIDV4(key *ecdsa.PublicKey) ID {
	e := make([]byte, 64)
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return ID(crypto.Keccak256Hash(e))
}
