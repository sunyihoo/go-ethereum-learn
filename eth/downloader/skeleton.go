// Copyright 2022 The go-ethereum Authors
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

package downloader

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// scratchHeaders is the number of headers to store in a scratch space to allow
// concurrent downloads. A header is about 0.5KB in size, so there is no worry
// about using too much memory. The only catch is that we can only validate gaps
// after they're linked to the head, so the bigger the scratch space, the larger
// potential for invalid headers.
//
// The current scratch space of 131072 headers is expected to use 64MB RAM.
const scratchHeaders = 131072

// requestHeaders is the number of header to request from a remote peer in a single
// network packet. Although the skeleton downloader takes into consideration peer
// capacities when picking idlers, the packet size was decided to remain constant
// since headers are relatively small and it's easier to work with fixed batches
// vs. dynamic interval fillings.
const requestHeaders = 512

func init() {
	// Tuning parameters is nice, but the scratch space must be assignable in
	// full to peers. It's a useless cornercase to support a dangling half-group.
	if scratchHeaders%requestHeaders != 0 {
		panic("Please make scratchHeaders divisible by requestHeaders")
	}
}

// subchain is a contiguous header chain segment that is backed by the database,
// but may not be linked to the live chain. The skeleton downloader may produce
// a new one of these every time it is restarted until the subchain grows large
// enough to connect with a previous subchain.
//
// The subchains use the exact same database namespace and are not disjoint from
// each other. As such, extending one to overlap the other entails reducing the
// second one first. This combined buffer model is used to avoid having to move
// data on disk when two subchains are joined together.
type subchain struct {
	Head uint64      // Block number of the newest header in the subchain
	Tail uint64      // Block number of the oldest header in the subchain
	Next common.Hash // Block hash of the next oldest header in the subchain
}

// skeletonProgress is a database entry to allow suspending and resuming a chain
// sync. As the skeleton header chain is downloaded backwards, restarts can and
// will produce temporarily disjoint subchains. There is no way to restart a
// suspended skeleton sync without prior knowledge of all prior suspension points.
type skeletonProgress struct {
	Subchains []*subchain // Disjoint subchains downloaded until now
	Finalized *uint64     // Last known finalized block number
}

// headUpdate is a notification that the beacon sync should switch to a new target.
// The update might request whether to forcefully change the target, or only try to
// extend it and fail if it's not possible.
type headUpdate struct {
	header *types.Header // Header to update the sync target to
	final  *types.Header // Finalized header to use as thresholds
	force  bool          // Whether to force the update or only extend if possible
	errc   chan error    // Channel to signal acceptance of the new head
}

// headerRequest tracks a pending header request to ensure responses are to
// actual requests and to validate any security constraints.
//
// Concurrency note: header requests and responses are handled concurrently from
// the main runloop to allow Keccak256 hash verifications on the peer's thread and
// to drop on invalid response. The request struct must contain all the data to
// construct the response without accessing runloop internals (i.e. subchains).
// That is only included to allow the runloop to match a response to the task being
// synced without having yet another set of maps.
type headerRequest struct {
	peer string // Peer to which this request is assigned
	id   uint64 // Request ID of this request

	deliver chan *headerResponse // Channel to deliver successful response on
	revert  chan *headerRequest  // Channel to deliver request failure on
	cancel  chan struct{}        // Channel to track sync cancellation
	stale   chan struct{}        // Channel to signal the request was dropped

	head uint64 // Head number of the requested batch of headers
}

// headerResponse is an already verified remote response to a header request.
type headerResponse struct {
	peer    *peerConnection // Peer from which this response originates
	reqid   uint64          // Request ID that this response fulfils
	headers []*types.Header // Chain of headers
}

// backfiller is a callback interface through which the skeleton sync can tell
// the downloader that it should suspend or resume backfilling on specific head
// events (e.g. suspend on forks or gaps, resume on successful linkups).
type backfiller interface {
	// suspend requests the backfiller to abort any running full or snap sync
	// based on the skeleton chain as it might be invalid. The backfiller should
	// gracefully handle multiple consecutive suspends without a resume, even
	// on initial startup.
	//
	// The method should return the last block header that has been successfully
	// backfilled (in the current or a previous run), falling back to the genesis.
	suspend() *types.Header

	// resume requests the backfiller to start running fill or snap sync based on
	// the skeleton chain as it has successfully been linked. Appending new heads
	// to the end of the chain will not result in suspend/resume cycles.
	// leaking too much sync logic out to the filler.
	resume()
}

// skeleton represents a header chain synchronized after the merge where blocks
// aren't validated any more via PoW in a forward fashion, rather are dictated
// and extended at the head via the beacon chain and backfilled on the original
// Ethereum block sync protocol.
//
// Since the skeleton is grown backwards from head to genesis, it is handled as
// a separate entity, not mixed in with the logical sequential transition of the
// blocks. Once the skeleton is connected to an existing, validated chain, the
// headers will be moved into the main downloader for filling and execution.
//
// Opposed to the original Ethereum block synchronization which is trustless (and
// uses a master peer to minimize the attack surface), post-merge block sync starts
// from a trusted head. As such, there is no need for a master peer any more and
// headers can be requested fully concurrently (though some batches might be
// discarded if they don't link up correctly).
//
// Although a skeleton is part of a sync cycle, it is not recreated, rather stays
// alive throughout the lifetime of the downloader. This allows it to be extended
// concurrently with the sync cycle, since extensions arrive from an API surface,
// not from within (vs. legacy Ethereum sync).
//
// Since the skeleton tracks the entire header chain until it is consumed by the
// forward block filling, it needs 0.5KB/block storage. At current mainnet sizes
// this is only possible with a disk backend. Since the skeleton is separate from
// the node's header chain, storing the headers ephemerally until sync finishes
// is wasted disk IO, but it's a price we're going to pay to keep things simple
// for now.
type skeleton struct {
	db     ethdb.Database // Database backing the skeleton
	filler backfiller     // Chain syncer suspended/resumed by head events

	peers *peerSet                   // Set of peers we can sync from
	idles map[string]*peerConnection // Set of idle peers in the current sync cycle
	drop  peerDropFn                 // Drops a peer for misbehaving

	progress *skeletonProgress // Sync progress tracker for resumption and metrics
	started  time.Time         // Timestamp when the skeleton syncer was created
	logged   time.Time         // Timestamp when progress was last logged to the user
	pulled   uint64            // Number of headers downloaded in this run

	scratchSpace  []*types.Header // Scratch space to accumulate headers in (first = recent)
	scratchOwners []string        // Peer IDs owning chunks of the scratch space (pend or delivered)
	scratchHead   uint64          // Block number of the first item in the scratch space

	requests map[uint64]*headerRequest // Header requests currently running

	headEvents chan *headUpdate // Notification channel for new heads
	terminate  chan chan error  // Termination channel to abort sync
	terminated chan struct{}    // Channel to signal that the syncer is dead

	// Callback hooks used during testing
	syncStarting func() // callback triggered after a sync cycle is inited but before started
}
