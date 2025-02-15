// Copyright 2019 The go-ethereum Authors
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

package netutil

import (
	"net"
	"net/netip"
)

// IPToAddr converts net.IP to netip.Addr. Note that unlike netip.AddrFromSlice, this
// function will always ensure that the resulting Addr is IPv4 when the input is.
func IPToAddr(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		addr, _ := netip.AddrFromSlice(ip4)
		return addr
	} else if ip6 := ip.To16(); ip6 != nil {
		addr, _ := netip.AddrFromSlice(ip6)
		return addr
	}
	return netip.Addr{}
}
