// Copyright 2016 The go-ethereum Authors
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

// Package netutil contains extensions to the net package.
package netutil

import (
	"bytes"
	"fmt"
	"golang.org/x/exp/maps"
	"net"
	"net/netip"
	"slices"
	"strings"
)

var special4, special6 Netlist

func init() {
	// Lists from RFC 5735, RFC 5156,
	// https://www.iana.org/assignments/iana-ipv4-special-registry/
	special4.Add("0.0.0.0/8")          // "This" network.
	special4.Add("192.0.0.0/29")       // IPv4 Service Continuity
	special4.Add("192.0.0.9/32")       // PCP Anycast
	special4.Add("192.0.0.170/32")     // NAT64/DNS64 Discovery
	special4.Add("192.0.0.171/32")     // NAT64/DNS64 Discovery
	special4.Add("192.0.2.0/24")       // TEST-NET-1
	special4.Add("192.31.196.0/24")    // AS112
	special4.Add("192.52.193.0/24")    // AMT
	special4.Add("192.88.99.0/24")     // 6to4 Relay Anycast
	special4.Add("192.175.48.0/24")    // AS112
	special4.Add("198.18.0.0/15")      // Device Benchmark Testing
	special4.Add("198.51.100.0/24")    // TEST-NET-2
	special4.Add("203.0.113.0/24")     // TEST-NET-3
	special4.Add("255.255.255.255/32") // Limited Broadcast

	// http://www.iana.org/assignments/iana-ipv6-special-registry/
	special6.Add("100::/64")
	special6.Add("2001::/32")
	special6.Add("2001:1::1/128")
	special6.Add("2001:2::/48")
	special6.Add("2001:3::/32")
	special6.Add("2001:4:112::/48")
	special6.Add("2001:5::/32")
	special6.Add("2001:10::/28")
	special6.Add("2001:20::/28")
	special6.Add("2001:db8::/32")
	special6.Add("2002::/16")
}

// Netlist is a list of IP networks.
type Netlist []netip.Prefix

// ParseNetlist parses a comma-separated list of CIDR masks.
// Whitespace and extra commas are ignored.
func ParseNetlist(s string) (*Netlist, error) {
	ws := strings.NewReplacer(" ", "", "\n", "", "\t", "")
	masks := strings.Split(ws.Replace(s), ",")
	l := make(Netlist, 0)
	for _, mask := range masks {
		if mask == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(mask)
		if err != nil {
			return nil, err
		}
		l = append(l, prefix)
	}
	return &l, nil
}

// Add parses a CIDR mask and appends it to the list. It panics for invalid masks and is
// intended to be used for setting up static lists.
func (l *Netlist) Add(cidr string) {
	perfix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(err)
	}
	*l = append(*l, perfix)
}

// DistinctNetSet tracks IPs, ensuring that at most N of them
// fall into the same network range.
type DistinctNetSet struct {
	Subnet uint // number of common prefix bits
	Limit  uint // maximum number of IPs in each subnet

	members map[netip.Prefix]uint
}

// Add adds an IP address to the set. It returns false (and doesn't add the IP) if the
// number of existing IPs in the defined range exceeds the limit.
func (s *DistinctNetSet) Add(ip net.IP) bool {
	return s.AddAddr(IPToAddr(ip))
}

// AddAddr adds an IP address to the set. It returns false (and doesn't add the IP) if the
// number of existing IPs in the defined range exceeds the limit.
func (s *DistinctNetSet) AddAddr(ip netip.Addr) bool {
	key := s.key(ip)
	n := s.members[key]
	if n < s.Limit {
		s.members[key] = n + 1
		return true
	}
	return false
}

// Remove removes an IP from the set.
func (s *DistinctNetSet) Remove(ip net.IP) {
	s.RemoveAddr(IPToAddr(ip))
}

// RemoveAddr removes an IP from the set.
func (s *DistinctNetSet) RemoveAddr(ip netip.Addr) {
	key := s.key(ip)
	if n, ok := s.members[key]; ok {
		if n == 1 {
			delete(s.members, key)
		} else {
			s.members[key] = n - 1
		}
	}
}

// Contains reports whether the given IP is contained in the set.
func (s DistinctNetSet) Contains(ip net.IP) bool {
	return s.ContainsAddr(IPToAddr(ip))
}

// ContainsAddr reports whether the given IP is contained in the set.
func (s DistinctNetSet) ContainsAddr(ip netip.Addr) bool {
	key := s.key(ip)
	_, ok := s.members[key]
	return ok
}

// Len returns the number of tracked IPs.
func (s DistinctNetSet) Len() int {
	n := uint(0)
	for _, i := range s.members {
		n += i
	}
	return int(n)
}

// key returns the map key for ip.
func (s *DistinctNetSet) key(ip netip.Addr) netip.Prefix {
	// Lazily initialize storage.
	if s.members == nil {
		s.members = make(map[netip.Prefix]uint)
	}
	p, err := ip.Prefix(int(s.Subnet))
	if err != nil {
		panic(err)
	}
	return p
}

// String implements fmt.Stringer
func (s DistinctNetSet) String() string {
	keys := maps.Keys(s.members)
	slices.SortFunc(keys, func(a, b netip.Prefix) int {
		return strings.Compare(a.String(), b.String())
	})

	var buf bytes.Buffer
	buf.WriteString("{")
	for i, k := range keys {
		fmt.Fprintf(&buf, "%v×%d", k, s.members[k])
		if i != len(keys)-1 {
			buf.WriteString(" ")
		}
	}
	buf.WriteString("}")
	return buf.String()
}
