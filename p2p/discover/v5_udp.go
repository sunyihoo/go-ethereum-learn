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

package discover

import (
	"context"
	"crypto/ecdsa"
	"net/netip"
	"sync"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover/v5wire"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

// codecV5 is implemented by v5wire.Codec (and testCodec).
//
// The UDPv5 transport is split into two objects: the codec object deals with
// encoding/decoding and with the handshake; the UDPv5 object handles higher-level concerns.
type codecV5 interface {
	// Encode encodes a packet.
	Encode(enode.ID, string, v5wire.Packet, *v5wire.Whoareyou) ([]byte, v5wire.Nonce, error)

	// Decode decodes a packet. It returns a *v5wire.Unknown packet if decryption fails.
	// The *enode.Node return value is non-nil when the input contains a handshake response.
	Decode([]byte, string) (enode.ID, *enode.Node, v5wire.Packet, error)
}

// UDPv5 is the implementation of protocol version 5.
type UDPv5 struct {
	// static fields
	conn         UDPConn
	tab          *Table
	netrestrict  *netutil.Netlist
	priv         *ecdsa.PrivateKey
	localNode    *enode.LocalNode
	db           *enode.DB
	log          log.Logger
	clock        mclock.Clock
	validSchemes enr.IdentityScheme

	// misc buffers used during message handling
	logcontext []interface{}

	// talkreq handler registry
	talk *talkSystem

	// channels into dispatch
	packetInCh    chan ReadPacket
	readNextCh    chan struct{}
	callCh        chan *callV5
	callDoneCh    chan *callV5
	respTimeoutCh chan *callTimeout
	sendCh        chan sendRequest
	unhandled     chan<- ReadPacket

	// state of dispatch
	codec            codecV5
	activeCallByNode map[enode.ID]*callV5
	activeCallByAuth map[v5wire.Nonce]*callV5
	callQueue        map[enode.ID][]*callV5

	// shutdown stuff
	closeOnce      sync.Once
	closeCtx       context.Context
	cancelCloseCtx context.CancelFunc
	wg             sync.WaitGroup
}

type sendRequest struct {
	destID   enode.ID
	destAddr netip.AddrPort
	msg      v5wire.Packet
}

// callV5 represents a remote procedure call against another node.
type callV5 struct {
	id   enode.ID
	addr netip.AddrPort
	node *enode.Node // This is required to perform handshakes.

	packet       v5wire.Packet
	responseType byte // expected packet type of response
	reqid        []byte
	ch           chan v5wire.Packet // responses sent here
	err          chan error         // errors sent here

	// Valid for active calls only:
	nonce          v5wire.Nonce      // nonce of request packet
	handshakeCount int               // # times we attempted handshake for this call
	challenge      *v5wire.Whoareyou // last sent handshake challenge
	timeout        mclock.Timer
}

// callTimeout is the response timeout event of a call.
type callTimeout struct {
	c     *callV5
	timer mclock.Timer
}
