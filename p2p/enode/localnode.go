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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// LocalNode produces the signed node record of a local node, i.e. a node run in the
// current process. Setting ENR entries via the Set method updates the record. A new version
// of the record is signed on demand when the Node method is called.
type LocalNode struct {
	cur atomic.Value // holds a non-nil node pointer while the record is up-to-date

	id  ID
	key *ecdsa.PrivateKey
	db  *DB

	// everything below is protected by a lock
	mu        sync.RWMutex
	seq       uint64
	update    time.Time // timestamp when the record was last updated
	entries   map[string]enr.Entry
	endpoint4 lnEndpoint
	endpoint6 lnEndpoint
}

type lnEndpoint struct {
	track                *netutil.IPTracker
	staticIP, fallbackIP net.IP
	fallbackUDP          uint16 // port
}
