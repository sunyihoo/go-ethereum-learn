// Copyright 2015 The go-ethereum Authors
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

package node

import (
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/rpc"
)

// apis returns the collection of built-in RPC APIs.
func (n *Node) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Service:   &adminAPI{n},
		}, {
			Namespace: "debug",
			Service:   debug.Handler,
		}, {
			Namespace: "debug",
			Service:   &p2pDebugAPI{n},
		}, {
			Namespace: "web3",
			Service:   &web3API{n},
		},
	}
}

// adminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
type adminAPI struct {
	node *Node // Node interfaced by this API
}

// web3API offers helper utils
type web3API struct {
	stack *Node
}

// p2pDebugAPI provides access to p2p internals for debugging.
type p2pDebugAPI struct {
	stack *Node
}
