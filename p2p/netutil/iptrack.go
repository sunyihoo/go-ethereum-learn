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

package netutil

import (
	"net/netip"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
)

// IPTracker predicts the external endpoint, i.e. IP address and port, of the local host
// based on statements made by other hosts.
type IPTracker struct {
	window          time.Duration
	contactWindow   time.Duration
	minStatements   int
	clock           mclock.Clock
	statements      map[netip.Addr]ipStatement
	contact         map[netip.Addr]mclock.AbsTime
	lastStatementGC mclock.AbsTime
	lastContactGC   mclock.AbsTime
}

type ipStatement struct {
	endpoint netip.AddrPort
	time     mclock.AbsTime
}
