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

package enode

import (
	"sync"
	"time"
)

// Iterator represents a sequence of nodes. The Next method moves to the next node in the
// sequence. It returns false when the sequence has ended or the iterator is closed. Close
// may be called concurrently with Next and Node, and interrupts Next if it is blocked.
type Iterator interface {
	Next() bool  // moves to next node
	Node() *Node // returns current node
	Close()      // ends the iterator
}

// FairMix aggregates multiple node iterators. The mixer itself is an iterator which ends
// only when Close is called. Source iterators added via AddSource are removed from the
// mix when they end.
//
// The distribution of nodes returned by Next is approximately fair, i.e. FairMix
// attempts to draw from all sources equally often. However, if a certain source is slow
// and doesn't return a node within the configured timeout, a node from any other source
// will be returned.
//
// It's safe to call AddSource and Close concurrently with Next.
type FairMix struct {
	wg      sync.WaitGroup
	fromAny chan *Node
	timeout time.Duration
	cur     *Node

	mu      sync.Mutex
	closed  chan struct{}
	sources []*mixSource
	last    int
}

type mixSource struct {
	it      Iterator
	next    chan *Node
	timeout time.Duration
}
