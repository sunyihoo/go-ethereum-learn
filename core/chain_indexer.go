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

package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// ChainIndexerBackend defines the methods needed to process chain segments in
// the background and write the segment results into the database. These can be
// used to create filter blooms or CHTs.
type ChainIndexerBackend interface {
	// Reset initiates the processing of a new chain segment, potentially terminating
	// any partially completed operations (in case of a reorg).
	Reset(ctx context.Context, section uint64, prevHead common.Hash) error

	// Process crunches through the next header in the chain segment. The caller
	// will ensure a sequential order of headers.
	Process(ctx context.Context, header *types.Header) error

	// Commit finalizes the section metadata and stores it into the database.
	Commit() error

	// Prune deletes the chain index older than the given threshold.
	Prune(threshold uint64) error
}

// ChainIndexer does a post-processing job for equally sized sections of the
// canonical chain (like BlooomBits and CHT structures). A ChainIndexer is
// connected to the blockchain through the event system by starting a
// ChainHeadEventLoop in a goroutine.
//
// Further child ChainIndexers can be added which use the output of the parent
// section indexer. These child indexers receive new head notifications only
// after an entire section has been finished or in case of rollbacks that might
// affect already finished sections.
type ChainIndexer struct {
	chainDb  ethdb.Database      // Chain database to index the data from
	indexDb  ethdb.Database      // Prefixed table-view of the db to write index metadata into
	backend  ChainIndexerBackend // Background processor generating the index data content
	children []*ChainIndexer     // Child indexers to cascade chain updates to

	active    atomic.Bool     // Flag whether the event loop was started
	update    chan struct{}   // Notification channel that headers should be processed
	quit      chan chan error // Quit channel to tear down running goroutines
	ctx       context.Context
	ctxCancel func()

	sectionSize uint64 // Number of blocks in a single chain segment to process
	confirmsReq uint64 // Number of confirmations before processing a completed segment

	storedSections uint64 // Number of sections successfully indexed into the database
	knownSections  uint64 // Number of sections known to be complete (block wise)
	cascadedHead   uint64 // Block number of the last completed section cascaded to subindexers

	checkpointSections uint64      // Number of sections covered by the checkpoint
	checkpointHead     common.Hash // Section head belonging to the checkpoint

	throttling time.Duration // Disk throttling to prevent a heavy upgrade from hogging resources

	log  log.Logger
	lock sync.Mutex
}
