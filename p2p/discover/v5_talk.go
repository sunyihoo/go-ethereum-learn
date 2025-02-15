// Copyright 2023 The go-ethereum Authors
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
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// TalkRequestHandler callback processes a talk request and returns a response.
//
// Note that talk handlers are expected to come up with a response very quickly, within at
// most 200ms or so. If the handler takes longer than that, the remote end may time out
// and wont receive the response.
type TalkRequestHandler func(enode.ID, *net.UDPAddr, []byte) []byte

type talkSystem struct {
	transport *UDPv5

	mutex     sync.Mutex
	handlers  map[string]TalkRequestHandler
	slots     chan struct{}
	lastLog   time.Time
	dropCount int
}
