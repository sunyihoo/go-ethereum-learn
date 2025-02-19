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

// Contains the block download scheduler to collect download tasks and schedule
// them in an ordered, and throttled way.

package downloader

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/prque"
	"github.com/ethereum/go-ethereum/core/types"
)

// fetchRequest is a currently running data retrieval operation.
type fetchRequest struct {
	Peer    *peerConnection // Peer to which the request was sent
	From    uint64          // Requested chain element index (used for skeleton fills only)
	Headers []*types.Header // Requested headers, sorted by request order
	Time    time.Time       // Time when the request was made
}

// fetchResult is a struct collecting partial results from data fetchers until
// all outstanding pieces complete and the result as a whole can be processed.
type fetchResult struct {
	pending atomic.Int32 // Flag telling what deliveries are outstanding

	Header       *types.Header
	Uncles       []*types.Header
	Transactions types.Transactions
	Receipts     types.Receipts
	Withdrawals  types.Withdrawals
}

// queue represents hashes that are either need fetching or are being fetched
type queue struct {
	mode SyncMode // Synchronisation mode to decide on the block parts to schedule for fetching

	// Headers are "special", they download in batches, supported by a skeleton chain
	headerHead      common.Hash                    // Hash of the last queued header to verify order
	headerTaskPool  map[uint64]*types.Header       // Pending header retrieval tasks, mapping starting indexes to skeleton headers
	headerTaskQueue *prque.Prque[int64, uint64]    // Priority queue of the skeleton indexes to fetch the filling headers for
	headerPeerMiss  map[string]map[uint64]struct{} // Set of per-peer header batches known to be unavailable
	headerPendPool  map[string]*fetchRequest       // Currently pending header retrieval operations
	headerResults   []*types.Header                // Result cache accumulating the completed headers
	headerHashes    []common.Hash                  // Result cache accumulating the completed header hashes
	headerProced    int                            // Number of headers already processed from the results
	headerOffset    uint64                         // Number of the first header in the result cache
	headerContCh    chan bool                      // Channel to notify when header download finishes

	// All data retrievals below are based on an already assembles header chain
	blockTaskPool  map[common.Hash]*types.Header      // Pending block (body) retrieval tasks, mapping hashes to headers
	blockTaskQueue *prque.Prque[int64, *types.Header] // Priority queue of the headers to fetch the blocks (bodies) for
	blockPendPool  map[string]*fetchRequest           // Currently pending block (body) retrieval operations
	blockWakeCh    chan bool                          // Channel to notify the block fetcher of new tasks

	receiptTaskPool  map[common.Hash]*types.Header      // Pending receipt retrieval tasks, mapping hashes to headers
	receiptTaskQueue *prque.Prque[int64, *types.Header] // Priority queue of the headers to fetch the receipts for
	receiptPendPool  map[string]*fetchRequest           // Currently pending receipt retrieval operations
	receiptWakeCh    chan bool                          // Channel to notify when receipt fetcher of new tasks

	resultCache *resultStore       // Downloaded but not yet delivered fetch results
	resultSize  common.StorageSize // Approximate size of a block (exponential moving average)

	lock   *sync.RWMutex
	active *sync.Cond
	closed bool

	logTime time.Time // Time instance when status was last reported
}
