// Copyright 2017 The go-ethereum Authors
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

package enr

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/ethereum/go-ethereum/rlp"
)

// Entry is implemented by known node record entry types.
//
// To define a new entry that is to be included in a node record,
// create a Go type that satisfies this interface. The type should
// also implement rlp.Decoder if additional checks are needed on the value.
// Entry 由已知的节点记录条目类型实现。
//
// 要定义一个要包含在节点记录中的新条目，创建一个满足此接口的 Go 类型。
// 如果需要对值进行额外检查，该类型还应实现 rlp.Decoder。
type Entry interface {
	ENRKey() string // 返回 ENR 键名 / Return ENR key name
}

type generic struct {
	key   string      // 键名 / Key name
	value interface{} // 值 / Value
}

func (g generic) ENRKey() string { return g.key } // 返回键名 / Return key name

func (g generic) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, g.value) // 编码值 / Encode value
}

func (g *generic) DecodeRLP(s *rlp.Stream) error {
	return s.Decode(g.value) // 解码值 / Decode value
}

// WithEntry wraps any value with a key name. It can be used to set and load arbitrary values
// in a record. The value v must be supported by rlp. To use WithEntry with Load, the value
// must be a pointer.
// WithEntry 用键名包装任何值。可用于在记录中设置和加载任意值。
// 值 v 必须受 rlp 支持。要与 Load 一起使用 WithEntry，值必须是指针。
func WithEntry(k string, v interface{}) Entry {
	return &generic{key: k, value: v} // 返回通用条目 / Return generic entry
}

// TCP is the "tcp" key, which holds the TCP port of the node.
// TCP 是 "tcp" 键，保存节点的 TCP 端口。
type TCP uint16

func (v TCP) ENRKey() string { return "tcp" } // 返回 "tcp" / Return "tcp"

// TCP6 is the "tcp6" key, which holds the IPv6-specific tcp6 port of the node.
// TCP6 是 "tcp6" 键，保存节点的 IPv6 专用 TCP 端口。
type TCP6 uint16

func (v TCP6) ENRKey() string { return "tcp6" } // 返回 "tcp6" / Return "tcp6"

// UDP is the "udp" key, which holds the UDP port of the node.
// UDP 是 "udp" 键，保存节点的 UDP 端口。
type UDP uint16

func (v UDP) ENRKey() string { return "udp" } // 返回 "udp" / Return "udp"

// UDP6 is the "udp6" key, which holds the IPv6-specific UDP port of the node.
// UDP6 是 "udp6" 键，保存节点的 IPv6 专用 UDP 端口。
type UDP6 uint16

func (v UDP6) ENRKey() string { return "udp6" } // 返回 "udp6" / Return "udp6"

// QUIC is the "quic" key, which holds the QUIC port of the node.
// QUIC 是 "quic" 键，保存节点的 QUIC 端口。
type QUIC uint16

func (v QUIC) ENRKey() string { return "quic" } // 返回 "quic" / Return "quic"

// QUIC6 is the "quic6" key, which holds the IPv6-specific quic6 port of the node.
// QUIC6 是 "quic6" 键，保存节点的 IPv6 专用 QUIC 端口。
type QUIC6 uint16

func (v QUIC6) ENRKey() string { return "quic6" } // 返回 "quic6" / Return "quic6"

// ID is the "id" key, which holds the name of the identity scheme.
// ID 是 "id" 键，保存身份方案的名称。
type ID string

const IDv4 = ID("v4") // the default identity scheme / 默认身份方案

func (v ID) ENRKey() string { return "id" } // 返回 "id" / Return "id"

// IP is either the "ip" or "ip6" key, depending on the value.
// Use this value to encode IP addresses that can be either v4 or v6.
// To load an address from a record use the IPv4 or IPv6 types.
// IP 是 "ip" 或 "ip6" 键，取决于值。
// 使用此值编码可能是 IPv4 或 IPv6 的 IP 地址。
// 要从记录中加载地址，请使用 IPv4 或 IPv6 类型。
type IP net.IP

func (v IP) ENRKey() string {
	if net.IP(v).To4() == nil {
		return "ip6" // 如果是 IPv6 则返回 "ip6" / Return "ip6" if IPv6
	}
	return "ip" // 如果是 IPv4 则返回 "ip" / Return "ip" if IPv4
}

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder。
func (v IP) EncodeRLP(w io.Writer) error {
	if ip4 := net.IP(v).To4(); ip4 != nil {
		return rlp.Encode(w, ip4) // 编码 IPv4 / Encode IPv4
	}
	if ip6 := net.IP(v).To16(); ip6 != nil {
		return rlp.Encode(w, ip6) // 编码 IPv6 / Encode IPv6
	}
	return fmt.Errorf("invalid IP address: %v", net.IP(v)) // 无效 IP 地址则返回错误 / Return error if invalid IP
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder。
func (v *IP) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err // 解码失败则返回错误 / Return error if decode fails
	}
	if len(*v) != 4 && len(*v) != 16 {
		return fmt.Errorf("invalid IP address, want 4 or 16 bytes: %v", *v) // 长度无效则返回错误 / Return error if length invalid
	}
	return nil // 成功则返回 nil / Return nil on success
}

// IPv4 is the "ip" key, which holds the IP address of the node.
// IPv4 是 "ip" 键，保存节点的 IP 地址。
type IPv4 net.IP

func (v IPv4) ENRKey() string { return "ip" } // 返回 "ip" / Return "ip"

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder。
func (v IPv4) EncodeRLP(w io.Writer) error {
	ip4 := net.IP(v).To4()
	if ip4 == nil {
		return fmt.Errorf("invalid IPv4 address: %v", net.IP(v)) // 无效 IPv4 地址则返回错误 / Return error if invalid IPv4
	}
	return rlp.Encode(w, ip4) // 编码 IPv4 / Encode IPv4
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder。
func (v *IPv4) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err // 解码失败则返回错误 / Return error if decode fails
	}
	if len(*v) != 4 {
		return fmt.Errorf("invalid IPv4 address, want 4 bytes: %v", *v) // 长度不为 4 则返回错误 / Return error if not 4 bytes
	}
	return nil // 成功则返回 nil / Return nil on success
}

// IPv6 is the "ip6" key, which holds the IP address of the node.
// IPv6 是 "ip6" 键，保存节点的 IP 地址。
type IPv6 net.IP

func (v IPv6) ENRKey() string { return "ip6" } // 返回 "ip6" / Return "ip6"

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder。
func (v IPv6) EncodeRLP(w io.Writer) error {
	ip6 := net.IP(v).To16()
	if ip6 == nil {
		return fmt.Errorf("invalid IPv6 address: %v", net.IP(v)) // 无效 IPv6 地址则返回错误 / Return error if invalid IPv6
	}
	return rlp.Encode(w, ip6) // 编码 IPv6 / Encode IPv6
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder。
func (v *IPv6) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err // 解码失败则返回错误 / Return error if decode fails
	}
	if len(*v) != 16 {
		return fmt.Errorf("invalid IPv6 address, want 16 bytes: %v", *v) // 长度不为 16 则返回错误 / Return error if not 16 bytes
	}
	return nil // 成功则返回 nil / Return nil on success
}

// IPv4Addr is the "ip" key, which holds the IP address of the node.
// IPv4Addr 是 "ip" 键，保存节点的 IP 地址。
type IPv4Addr netip.Addr

func (v IPv4Addr) ENRKey() string { return "ip" } // 返回 "ip" / Return "ip"

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder。
func (v IPv4Addr) EncodeRLP(w io.Writer) error {
	addr := netip.Addr(v)
	if !addr.Is4() {
		return errors.New("address is not IPv4") // 非 IPv4 地址则返回错误 / Return error if not IPv4
	}
	enc := rlp.NewEncoderBuffer(w)
	bytes := addr.As4()
	enc.WriteBytes(bytes[:])
	return enc.Flush() // 编码并写入 IPv4 / Encode and write IPv4
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder。
func (v *IPv4Addr) DecodeRLP(s *rlp.Stream) error {
	var bytes [4]byte
	if err := s.ReadBytes(bytes[:]); err != nil {
		return err // 读取失败则返回错误 / Return error if read fails
	}
	*v = IPv4Addr(netip.AddrFrom4(bytes)) // 解码为 IPv4 地址 / Decode to IPv4 address
	return nil                            // 成功则返回 nil / Return nil on success
}

// IPv6Addr is the "ip6" key, which holds the IP address of the node.
// IPv6Addr 是 "ip6" 键，保存节点的 IP 地址。
type IPv6Addr netip.Addr

func (v IPv6Addr) ENRKey() string { return "ip6" } // 返回 "ip6" / Return "ip6"

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder。
func (v IPv6Addr) EncodeRLP(w io.Writer) error {
	addr := netip.Addr(v)
	if !addr.Is6() {
		return errors.New("address is not IPv6") // 非 IPv6 地址则返回错误 / Return error if not IPv6
	}
	enc := rlp.NewEncoderBuffer(w)
	bytes := addr.As16()
	enc.WriteBytes(bytes[:])
	return enc.Flush() // 编码并写入 IPv6 / Encode and write IPv6
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder。
func (v *IPv6Addr) DecodeRLP(s *rlp.Stream) error {
	var bytes [16]byte
	if err := s.ReadBytes(bytes[:]); err != nil {
		return err // 读取失败则返回错误 / Return error if read fails
	}
	*v = IPv6Addr(netip.AddrFrom16(bytes)) // 解码为 IPv6 地址 / Decode to IPv6 address
	return nil                             // 成功则返回 nil / Return nil on success
}

// KeyError is an error related to a key.
// KeyError 是与键相关的错误。
type KeyError struct {
	Key string // 键名 / Key name
	Err error  // 错误 / Error
}

// Error implements error.
// Error 实现 error 接口。
func (err *KeyError) Error() string {
	if err.Err == errNotFound {
		return fmt.Sprintf("missing ENR key %q", err.Key) // 键缺失的错误信息 / Error message for missing key
	}
	return fmt.Sprintf("ENR key %q: %v", err.Key, err.Err) // 其他键相关的错误信息 / Other key-related error message
}

func (err *KeyError) Unwrap() error {
	return err.Err // 返回底层错误 / Return underlying error
}

// IsNotFound reports whether the given error means that a key/value pair is
// missing from a record.
// IsNotFound 报告给定错误是否表示记录中缺少键值对。
func IsNotFound(err error) bool {
	var ke *KeyError
	if errors.As(err, &ke) { // 检查是否为 KeyError / Check if error is KeyError
		return ke.Err == errNotFound // 如果是未找到错误则返回 true / Return true if not found error
	}
	return false // 否则返回 false / Otherwise return false
}
