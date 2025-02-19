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

package fetcher

import (
	mrand "math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/core/types"
)

// txAnnounce is the notification of the availability of a batch
// of new transactions in the network.
type txAnnounce struct {
	origin string        // Identifier of the peer originating the notification
	hashes []common.Hash // Batch of transaction hashes being announced
	metas  []txMetadata  // Batch of metadata associated with the hashes
}

// txMetadata provides the extra data transmitted along with the announcement
// for better fetch scheduling.
type txMetadata struct {
	kind byte   // Transaction consensus type
	size uint32 // Transaction size in bytes
}

// txMetadataWithSeq is a wrapper of transaction metadata with an extra field
// tracking the transaction sequence number.
type txMetadataWithSeq struct {
	txMetadata
	seq uint64
}

// txRequest represents an in-flight transaction retrieval request destined to
// a specific peers.
type txRequest struct {
	hashes []common.Hash            // Transactions having been requested
	stolen map[common.Hash]struct{} // Deliveries by someone else (don't re-request)
	time   mclock.AbsTime           // Timestamp of the request
}

// txDelivery is the notification that a batch of transactions have been added
// to the pool and should be untracked.
type txDelivery struct {
	origin string        // Identifier of the peer originating the notification
	hashes []common.Hash // Batch of transaction hashes having been delivered
	metas  []txMetadata  // Batch of metadata associated with the delivered hashes
	direct bool          // Whether this is a direct reply or a broadcast
}

// txDrop is the notification that a peer has disconnected.
type txDrop struct {
	peer string
}

// TxFetcher is responsible for retrieving new transaction based on announcements.
//
// The fetcher operates in 3 stages:
//   - Transactions that are newly discovered are moved into a wait list.
//   - After ~500ms passes, transactions from the wait list that have not been
//     broadcast to us in whole are moved into a queueing area.
//   - When a connected peer doesn't have in-flight retrieval requests, any
//     transaction queued up (and announced by the peer) are allocated to the
//     peer and moved into a fetching status until it's fulfilled or fails.
//
// The invariants of the fetcher are:
//   - Each tracked transaction (hash) must only be present in one of the
//     three stages. This ensures that the fetcher operates akin to a finite
//     state automata and there's no data leak.
//   - Each peer that announced transactions may be scheduled retrievals, but
//     only ever one concurrently. This ensures we can immediately know what is
//     missing from a reply and reschedule it.
type TxFetcher struct {
	notify  chan *txAnnounce
	cleanup chan *txDelivery
	drop    chan *txDrop
	quit    chan struct{}

	txSeq       uint64                             // Unique transaction sequence number
	underpriced *lru.Cache[common.Hash, time.Time] // Transactions discarded as too cheap (don't re-fetch)

	// Stage 1: Waiting lists for newly discovered transactions that might be
	// broadcast without needing explicit request/reply round trips.
	waitlist  map[common.Hash]map[string]struct{}           // Transactions waiting for an potential broadcast
	waittime  map[common.Hash]mclock.AbsTime                // Timestamps when transactions were added to the waitlist
	waitslots map[string]map[common.Hash]*txMetadataWithSeq // Waiting announcements grouped by peer (DoS protection)

	// Stage 2: Queue of transactions that waiting to be allocated to some peer
	// to be retrieved directly.
	announces map[string]map[common.Hash]*txMetadataWithSeq // Set of announced transactions, grouped by origin peer
	announced map[common.Hash]map[string]struct{}           // Set of download locations, grouped by transaction hash

	// Stage 3: Set of transactions currently being retrieved, some which may be
	// fulfilled and some rescheduled. Note, this step shares 'announces' from the
	// previous stage to avoid having to duplicate (need it for DoS checks).
	fetching   map[common.Hash]string              // Transaction set currently being retrieved
	requests   map[string]*txRequest               // In-flight transaction retrievals
	alternates map[common.Hash]map[string]struct{} // In-flight transaction alternate origins if retrieval fails

	// Callbacks
	hasTx    func(common.Hash) bool             // Retrieves a tx from the local txpool
	addTxs   func([]*types.Transaction) []error // Insert a batch of transactions into local txpool
	fetchTxs func(string, []common.Hash) error  // Retrieves a set of txs from a remote peer
	dropPeer func(string)                       // Drops a peer in case of announcement violation

	step  chan struct{} // Notification channel when the fetcher loop iterates
	clock mclock.Clock  // Time wrapper to simulate in tests
	rand  *mrand.Rand   // Randomizer to use in tests instead of map range loops (soft-random)
}
