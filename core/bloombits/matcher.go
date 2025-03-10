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

package bloombits

import (
	"context"
	"sync"
	"sync/atomic"
)

// bloomIndexes represents the bit indexes inside the bloom filter that belong
// to some key.
type bloomIndexes [3]uint

// Retrieval represents a request for retrieval task assignments for a given
// bit with the given number of fetch elements, or a response for such a request.
// It can also have the actual results set to be used as a delivery data struct.
//
// The context and error fields are used by the light client to terminate matching
// early if an error is encountered on some path of the pipeline.
type Retrieval struct {
	Bit      uint
	Sections []uint64
	Bitsets  [][]byte

	Context context.Context
	Error   error
}

// Matcher is a pipelined system of schedulers and logic matchers which perform
// binary AND/OR operations on the bit-streams, creating a stream of potential
// blocks to inspect for data content.
type Matcher struct {
	sectionSize uint64 // Size of the data batches to filter on

	filters    [][]bloomIndexes    // Filter the system is matching for
	schedulers map[uint]*scheduler // Retrieval schedulers for loading bloom bits

	retrievers chan chan uint       // Retriever processes waiting for bit allocations
	counters   chan chan uint       // Retriever processes waiting for task count reports
	retrievals chan chan *Retrieval // Retriever processes waiting for task allocations
	deliveries chan *Retrieval      // Retriever processes waiting for task response deliveries

	running atomic.Bool // Atomic flag whether a session is live or not
}

// MatcherSession is returned by a started matcher to be used as a terminator
// for the actively running matching operation.
type MatcherSession struct {
	matcher *Matcher

	closer sync.Once     // Sync object to ensure we only ever close once
	quit   chan struct{} // Quit channel to request pipeline termination

	ctx     context.Context // Context used by the light client to abort filtering
	err     error           // Global error to track retrieval failures deep in the chain
	errLock sync.Mutex

	pend sync.WaitGroup
}
