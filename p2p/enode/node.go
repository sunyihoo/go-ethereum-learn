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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

// EIP-778（ENR）：定义了以太坊节点记录的格式，允许节点动态更新其元数据（如 IP、端口），并通过签名确保安全性。
//
// Kademlia 算法：以太坊的节点发现协议基于 Kademlia，通过异或距离构建分布式网络，支持高效的节点查找。
//
// secp256k1：以太坊使用的椭圆曲线算法，节点公钥基于此生成，用于身份验证和加密通信。

// ENR（EIP-778）：ENR 是以太坊节点发现协议的一部分，用于存储节点的元数据（如 IP、端口、公钥等），并通过签名确保数据的完整性。enr.IdentityScheme 定义了签名和地址生成的方式，通常基于 secp256k1 椭圆曲线。
//
// 节点 ID：在以太坊的 P2P 网络中，节点 ID 通常是公钥的哈希（如 Keccak-256），长度为 32 字节。

var errMissingPrefix = errors.New("missing 'enr:' prefix for base64-encoded record")

// 定义一个错误，表示 base64 编码的记录缺少 'enr:' 前缀

// Node represents a host on the network.
type Node struct {
	// 节点的以太坊节点记录（ENR）格式记录
	r enr.Record // Record of the node in Ethereum Node Records (ENR) format
	// 节点的唯一标识符
	id ID // Unique identifier of the node

	// hostname tracks the DNS name of the node.
	// 跟踪节点的 DNS 名称
	hostname string

	// endpoint information
	// 节点的 IP 地址
	ip netip.Addr // IP address of the node
	// 节点的 UDP 端口
	udp uint16 // UDP port of the node
	// 节点的 TCP 端口
	tcp uint16 // TCP port of the node
}

// New wraps a node record. The record must be valid according to the given
// identity scheme.
//
// New 包装节点记录。根据给定的身份方案，记录必须有效。
func New(validSchemes enr.IdentityScheme, r *enr.Record) (*Node, error) {
	// Verify the signature of the ENR record using the provided identity scheme
	// 使用提供的身份方案验证 ENR 记录的签名
	if err := r.VerifySignature(validSchemes); err != nil {
		return nil, err
	}
	var id ID
	// Copy the node address into the ID, ensuring correct length
	// 将节点地址复制到 ID 中，确保长度正确
	if n := copy(id[:], validSchemes.NodeAddr(r)); n != len(id) {
		return nil, fmt.Errorf("invalid node ID length %d, need %d", n, len(id))
	}
	return newNodeWithID(r, id), nil
}

// 节点端点：在以太坊的 P2P 网络（如 devp2p）中，节点需要公布其 IP 和端口以便其他节点连接。ENR 支持 IPv4 和 IPv6，代码中通过优先级选择更适合的地址。
//
// localityScore：这是一个自定义算法，用于判断 IP 的“全局性”，与以太坊的 Kademlia 分布式哈希表（DHT）无关，但反映了网络设计的实用性。

func newNodeWithID(r *enr.Record, id ID) *Node {
	n := &Node{r: *r, id: id}
	// Set the preferred endpoint.
	// Here we decide between IPv4 and IPv6, choosing the 'most global' address.
	// 设置首选端点。在此处决定使用 IPv4 或 IPv6，选择“最全局”的地址
	var ip4 netip.Addr
	var ip6 netip.Addr
	n.Load((*enr.IPv4Addr)(&ip4)) // Load IPv4 address from ENR  从 ENR 中加载 IPv4 地址
	n.Load((*enr.IPv6Addr)(&ip6)) // Load IPv6 address from ENR  从 ENR 中加载 IPv6 地址
	valid4 := validIP(ip4)
	valid6 := validIP(ip6)
	switch {
	case valid4 && valid6: // If both IPv4 and IPv6 are valid 如果 IPv4 和 IPv6 都有效
		if localityScore(ip4) >= localityScore(ip6) {
			n.setIP4(ip4) // Prefer IPv4 if it has higher locality score 如果 IPv4 的本地性得分更高，则优先使用 IPv4
		} else {
			n.setIP6(ip6) // Otherwise prefer IPv6  否则优先使用 IPv6
		}
	case valid4:
		n.setIP4(ip4) // Use IPv4 if only it is valid 如果只有 IPv4 有效，则使用 IPv4
	case valid6:
		n.setIP6(ip6) // Use IPv6 if only it is valid 如果只有 IPv6 有效，则使用 IPv6
	default:
		n.setIPv4Ports() // Fallback to default ports if no valid IP 如果没有有效的 IP，则回退到默认端口
	}
	return n
}

// validIP reports whether 'ip' is a valid node endpoint IP address.
// 报告“ip”是否为有效的节点端点 IP 地址
func validIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsMulticast()
}

func localityScore(ip netip.Addr) int {
	// 计算 IP 地址的本地性得分
	switch {
	case ip.IsUnspecified():
		return 0 // Unspecified IP (e.g., 0.0.0.0) // 未指定的 IP（例如 0.0.0.0）
	case ip.IsLoopback():
		return 1 // Loopback IP (e.g., 127.0.0.1) // 回环 IP（例如 127.0.0.1）
	case ip.IsLinkLocalUnicast():
		return 2 // Link-local unicast IP // 链路本地单播 IP
	case ip.IsPrivate():
		return 3 // Private IP (e.g., 192.168.x.x) // 私有 IP（例如 192.168.x.x）
	default:
		return 4 // Public IP // 公共 IP
	}
}

func (n *Node) setIP4(ip netip.Addr) {
	n.ip = ip
	n.setIPv4Ports() // Load UDP and TCP ports for IPv4 // 加载 IPv4 的 UDP 和 TCP 端口
}

func (n *Node) setIPv4Ports() {
	n.Load((*enr.UDP)(&n.udp)) // Load UDP port 加载 UDP 端口
	n.Load((*enr.TCP)(&n.tcp)) // Load TCP port 加载 TCP 端口
}

func (n *Node) setIP6(ip netip.Addr) {
	if ip.Is4In6() { // Handle IPv4-mapped IPv6 addresses 处理映射为 IPv6 的 IPv4 地址
		n.setIP4(ip)
		return
	}
	n.ip = ip
	if err := n.Load((*enr.UDP6)(&n.udp)); err != nil {
		n.Load((*enr.UDP)(&n.udp)) // Fallback to UDP if UDP6 fails 如果 UDP6 失败，则回退到 UDP
	}
	if err := n.Load((*enr.TCP6)(&n.tcp)); err != nil {
		n.Load((*enr.TCP)(&n.tcp)) // Fallback to TCP if TCP6 fails 如果 TCP6 失败，则回退到 TCP
	}
}

// MustParse parses a node record or enode:// URL. It panics if the input is invalid.
// 解析节点记录或 enode:// URL。如果输入无效，则引发 panic
func MustParse(rawurl string) *Node {
	n, err := Parse(ValidSchemes, rawurl)
	if err != nil {
		panic("invalid node: " + err.Error())
	}
	return n
}

// RLP（Recursive Length Prefix）：以太坊使用的序列化格式，ENR 数据以 RLP 编码存储，便于在网络中传输。
//
// ENR vs enode://：enode:// 是以太坊早期的节点表示格式，包含 ID、IP 和端口，而 ENR 是更现代的扩展格式（EIP-778），支持更多元数据。

// Parse decodes and verifies a base64-encoded node record.
func Parse(validSchemes enr.IdentityScheme, input string) (*Node, error) {
	// 解码并验证 base64 编码的节点记录
	if strings.HasPrefix(input, "enode://") {
		return ParseV4(input) // Handle legacy enode:// URLs 处理旧版 enode:// URLs
	}
	if !strings.HasPrefix(input, "enr:") {
		return nil, errMissingPrefix // Check for 'enr:' prefix 检查是否有 'enr:' 前缀
	}
	bin, err := base64.RawURLEncoding.DecodeString(input[4:]) // Decode base64 string 解码 base64 字符串
	if err != nil {
		return nil, err
	}
	var r enr.Record
	if err := rlp.DecodeBytes(bin, &r); err != nil { // Decode RLP-encoded ENR 解码 RLP 编码的 ENR
		return nil, err
	}
	return New(validSchemes, &r) // Create new Node instance 创建新的 Node 实例
}

// ID returns the node identifier.
// 返回节点标识符
func (n *Node) ID() ID {
	return n.id
}

// Seq returns the sequence number of the underlying record.
// 返回底层记录的序列号
func (n *Node) Seq() uint64 {
	return n.r.Seq()
}

// Load retrieves an entry from the underlying record.
// 从底层记录中检索条目
func (n *Node) Load(k enr.Entry) error {
	return n.r.Load(k)
}

// IP returns the IP address of the node.
// 返回节点的 IP 地址
func (n *Node) IP() net.IP {
	return net.IP(n.ip.AsSlice())
}

// IPAddr returns the IP address of the node.
// 返回节点的 IP 地址
func (n *Node) IPAddr() netip.Addr {
	return n.ip
}

// UDP returns the UDP port of the node.
// 返回节点的 UDP 端口
func (n *Node) UDP() int {
	return int(n.udp)
}

// TCP returns the TCP port of the node.
// 返回节点的 TCP 端口
func (n *Node) TCP() int {
	return int(n.tcp)
}

// WithHostname adds a DNS hostname to the node.
// 为节点添加 DNS 主机名
func (n *Node) WithHostname(hostname string) *Node {
	cpy := *n
	cpy.hostname = hostname
	return &cpy
}

// Hostname returns the DNS name assigned by WithHostname.
// 返回通过 WithHostname 分配的 DNS 名称
func (n *Node) Hostname() string {
	return n.hostname
}

// UDPEndpoint returns the announced UDP endpoint.
// 返回公布的 UDP 端点
func (n *Node) UDPEndpoint() (netip.AddrPort, bool) {
	if !n.ip.IsValid() || n.ip.IsUnspecified() || n.udp == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(n.ip, n.udp), true
}

// TCPEndpoint returns the announced TCP endpoint.
// 返回公布的 TCP 端点
func (n *Node) TCPEndpoint() (netip.AddrPort, bool) {
	if !n.ip.IsValid() || n.ip.IsUnspecified() || n.tcp == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(n.ip, n.tcp), true
}

// QUICEndpoint returns the announced QUIC endpoint.
// 返回公布的 QUIC 端点
func (n *Node) QUICEndpoint() (netip.AddrPort, bool) {
	var quic uint16
	if n.ip.Is4() || n.ip.Is4In6() {
		n.Load((*enr.QUIC)(&quic)) // Load QUIC port for IPv4 加载 IPv4 的 QUIC 端口
	} else if n.ip.Is6() {
		n.Load((*enr.QUIC6)(&quic)) // Load QUIC port for IPv6 加载 IPv6 的 QUIC 端口
	}
	if !n.ip.IsValid() || n.ip.IsUnspecified() || quic == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(n.ip, quic), true
}

// Pubkey returns the secp256k1 public key of the node, if present.
// 返回节点的 secp256k1 公钥（如果存在）
func (n *Node) Pubkey() *ecdsa.PublicKey {
	var key ecdsa.PublicKey
	if n.Load((*Secp256k1)(&key)) != nil {
		return nil
	}
	return &key
}

// Record returns the node's record. The return value is a copy and may
// be modified by the caller.
//
// 返回节点的记录。返回值是副本，可由调用者修改
func (n *Node) Record() *enr.Record {
	cpy := n.r
	return &cpy
}

// ValidateComplete checks whether n has a valid IP and UDP port.
// Deprecated: don't use this method.
//
// 检查节点是否具有有效的 IP 和 UDP 端口
// 已弃用：请勿使用此方法
func (n *Node) ValidateComplete() error {
	if !n.ip.IsValid() {
		return errors.New("missing IP address")
	}
	if n.ip.IsMulticast() || n.ip.IsUnspecified() {
		return errors.New("invalid IP (multicast/unspecified)")
	}
	if n.udp == 0 {
		return errors.New("missing UDP port")
	}
	// Validate the node key (on curve, etc.).
	var key Secp256k1
	return n.Load(&key)
}

// String returns the text representation of the record.
// 返回记录的文本表示形式
func (n *Node) String() string {
	if isNewV4(n) {
		return n.URLv4() // backwards-compatibility glue for NewV4 nodes 为 NewV4 节点提供向后兼容性支持
	}
	enc, _ := rlp.EncodeToBytes(&n.r)                // always succeeds because record is valid 将记录编码为 RLP 字节（始终成功，因为记录有效）
	b64 := base64.RawURLEncoding.EncodeToString(enc) // 将 RLP 字节编码为 base64 字符串
	return "enr:" + b64
}

// MarshalText implements encoding.TextMarshaler.
// 实现 encoding.TextMarshaler 接口
func (n *Node) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// 实现 encoding.TextUnmarshaler 接口
func (n *Node) UnmarshalText(text []byte) error {
	dec, err := Parse(ValidSchemes, string(text))
	if err == nil {
		*n = *dec
	}
	return err
}

// ID is a unique identifier for each node.
// ID 是每个节点的唯一标识符
type ID [32]byte

// Bytes returns a byte slice representation of the ID
// 返回 ID 的字节切片表示形式
func (n ID) Bytes() []byte {
	return n[:]
}

// ID prints as a long hexadecimal number.
// 将 ID 打印为长十六进制数
func (n ID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// GoString returns the Go syntax representation of a ID is a call to HexID.
// 返回 ID 的 Go 语法表示形式，调用 HexID
func (n ID) GoString() string {
	return fmt.Sprintf("enode.HexID(\"%x\")", n[:])
}

// TerminalString returns a shortened hex string for terminal logging.
// 返回用于终端日志记录的缩短十六进制字符串
func (n ID) TerminalString() string {
	return hex.EncodeToString(n[:8])
}

// MarshalText implements the encoding.TextMarshaler interface.
// 实现 encoding.TextMarshaler 接口
func (n ID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// 实现 encoding.TextUnmarshaler 接口
func (n *ID) UnmarshalText(text []byte) error {
	id, err := ParseID(string(text))
	if err != nil {
		return err
	}
	*n = id
	return nil
}

// HexID converts a hex string to an ID.
// The string may be prefixed with 0x.
// It panics if the string is not a valid ID.
//
// HexID 将十六进制字符串转换为 ID。
// 字符串可以带有 0x 前缀。
// 如果字符串不是有效的 ID，则引发 panic
func HexID(in string) ID {
	id, err := ParseID(in)
	if err != nil {
		panic(err)
	}
	return id
}

// ParseID 解析十六进制字符串为 ID
func ParseID(in string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(strings.TrimPrefix(in, "0x"))
	if err != nil {
		return id, err
	} else if len(b) != len(id) {
		return id, fmt.Errorf("wrong length, want %d hex chars", len(id)*2)
	}
	copy(id[:], b)
	return id, nil
}

// Kademlia DHT：这两个函数是以太坊节点发现协议（基于 Kademlia）的核心部分。Kademlia 使用异或距离（XOR distance）来衡量节点之间的“距离”，以构建分布式哈希表。

// 用途：DistCmp 用于比较两个节点与目标的接近程度，LogDist 用于计算距离的对数形式，常用于路由表的分桶。

// DistCmp compares the distances a->target and b->target.
// Returns -1 if a is closer to target, 1 if b is closer to target
// and 0 if they are equal.
//
// 比较 a->target 和 b->target 的距离。如果 a 更接近 target 返回 -1，如果 b 更接近 target 返回 1，相等返回 0
func DistCmp(target, a, b ID) int {
	for i := range target {
		da := a[i] ^ target[i]
		db := b[i] ^ target[i]
		if da > db {
			return 1
		} else if da < db {
			return -1
		}
	}
	return 0
}

// LogDist returns the logarithmic distance between a and b, log2(a ^ b).
// 返回 a 和 b 之间的对数距离，log2(a ^ b)
func LogDist(a, b ID) int {
	lz := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			lz += 8
		} else {
			lz += bits.LeadingZeros8(x)
			break
		}
	}
	return len(a)*8 - lz
}
