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
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

var errMissingPrefix = errors.New("missing 'enr:' prefix for base64-encoded record")

// Node represents a host on the network.
type Node struct {
	r  enr.Record
	id ID

	// hostname tracks the DNS name of the node
	hostname string

	// endpoint information
	ip  netip.Addr
	udp uint16
	tcp uint16
}

// New wraps a node record. The record must be valid according to the given
// identity scheme.
func New(validSchemes enr.IdentityScheme, r *enr.Record) (*Node, error) {
	if err := r.VerifySignature(validSchemes); err != nil {
		return nil, err
	}
	var id ID
	if n := copy(id[:], validSchemes.NodeAddr(r)); n != len(id) {
		return nil, fmt.Errorf("invalid node ID length %d, need %d", n, len(id))
	}
	return newNodeWithID(r, id), nil
}

func newNodeWithID(r *enr.Record, id ID) *Node {
	n := &Node{r: *r, id: id}
	// Set the preferred endpoint.
	// Here we decide between IPv4 and IPv6, choosing the 'most global' address.
	var ip4 netip.Addr
	var ip6 netip.Addr
	n.Load((*enr.IPv4Addr)(&ip4))
	n.Load((*enr.IPv6Addr)(&ip6))
	valid4 := validIP(ip4)
	valid6 := validIP(ip6)
	switch {
	case valid4 && valid6:
		if localityScore(ip4) >= localityScore(ip6) {
			n.setIP4(ip4)
		} else {
			n.setIP6(ip6)
		}
	case valid4:
		n.setIP4(ip4)
	case valid6:
		n.setIP6(ip6)
	default:
		n.setIPv4Ports()
	}
	return n
}

// validIP reports whether 'ip' is a valid node endpoint IP address.
func validIP(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsMulticast()
}

func localityScore(ip netip.Addr) int {
	switch {
	case ip.IsUnspecified():
		return 0
	case ip.IsLoopback():
		return 1
	case ip.IsLinkLocalUnicast():
		return 2
	case ip.IsPrivate():
		return 3
	default:
		return 4
	}
}

func (n *Node) setIP4(ip netip.Addr) {
	n.ip = ip
	n.setIPv4Ports()
}

func (n *Node) setIPv4Ports() {
	n.Load((*enr.UDP)(&n.udp))
	n.Load((*enr.TCP)(&n.tcp))
}

func (n *Node) setIP6(ip netip.Addr) {
	if ip.Is4In6() {
		n.setIP4(ip)
		return
	}
	n.ip = ip
	if err := n.Load((*enr.UDP6)(&n.udp)); err != nil {
		n.Load((*enr.UDP)(&n.udp))
	}
	if err := n.Load((*enr.TCP6)(&n.tcp)); err != nil {
		n.Load((*enr.TCP)(&n.tcp))
	}
}

// MustParse parses a node record or enode:// URL. It panics if the input is invalid.
func MustParse(rawurl string) *Node {
	n, err := Parse(ValidSchemes, rawurl)
	if err != nil {
		panic("invalid node: " + err.Error())
	}
	return n
}

// Parse decodes and verifies a base64-encoded node record.
func Parse(validSchemes enr.IdentityScheme, input string) (*Node, error) {
	if strings.HasPrefix(input, "enode://") {
		return ParseV4(input)
	}
	if !strings.HasPrefix(input, "enr:") {
		return nil, errMissingPrefix
	}
	bin, err := base64.RawURLEncoding.DecodeString(input[4:])
	if err != nil {
		return nil, err
	}
	var r enr.Record
	if err := rlp.DecodeBytes(bin, &r); err != nil {
		return nil, err
	}
	return New(validSchemes, &r)
}

// ID returns the node identifier.
func (n *Node) ID() ID {
	return n.id
}

// Seq returns the sequence number of the underlying record.
func (n *Node) Seq() uint64 {
	return n.r.Seq()
}

// Load retrieves an entry from the underlying record.
func (n *Node) Load(k enr.Entry) error {
	return n.r.Load(k)
}

// WithHostname adds a DNS hostname to the node.
func (n *Node) WithHostname(hostname string) *Node {
	cpy := *n
	cpy.hostname = hostname
	return &cpy
}

// ID is a unique identifier for each node.
type ID [32]byte

// Bytes returns a byte slice representation of the ID
func (n ID) Bytes() []byte {
	return n[:]
}

// ID prints as a long hexadecimal number.
func (n ID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// GoString returns the Go syntax representation of a ID is a call to HexID.
func (n ID) GoString() string {
	return fmt.Sprintf("encode.HexID(\"%x\")", n[:])
}

// TerminalString returns a shortened hex string for terminal logging.
func (n ID) TerminalString() string {
	return hex.EncodeToString(n[:8])
}

// MarshalText implements the encoding.TextMarshaler interface.
func (n ID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
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
func HexID(in string) ID {
	id, err := ParseID(in)
	if err != nil {
		panic(err)
	}
	return id
}

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
