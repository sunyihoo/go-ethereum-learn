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

package state

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/metrics"
)

// triePrefetcher is an active prefetcher, which receives accounts or storage
// items and does trie-loading of them. The goal is to get as much useful content
// into the caches as possible.
//
// Note, the prefetcher's API is not thread safe.

type triePrefetcher struct {
	verkle   bool                   // Flag whether the prefetcher is in verkle mode
	db       Database               // Database to fetch trie nodes through
	root     common.Hash            // Root hash of the account trie for metrics
	fetchers map[string]*subfetcher // Subfetchers for each trie
	term     chan struct{}          // Channel to signal interruption
	noreads  bool                   // Whether to ignore state-read-only prefetch requests

	deliveryMissMeter *metrics.Meter

	accountLoadReadMeter  *metrics.Meter
	accountLoadWriteMeter *metrics.Meter
	accountDupReadMeter   *metrics.Meter
	accountDupWriteMeter  *metrics.Meter
	accountDupCrossMeter  *metrics.Meter
	accountWasteMeter     *metrics.Meter

	storageLoadReadMeter  *metrics.Meter
	storageLoadWriteMeter *metrics.Meter
	storageDupReadMeter   *metrics.Meter
	storageDupWriteMeter  *metrics.Meter
	storageDupCrossMeter  *metrics.Meter
	storageWasteMeter     *metrics.Meter
}

// subfetcher is a trie fetcher goroutine responsible for pulling entries for a
// single trie. It is spawned when a new root is encountered and lives until the
// main prefetcher is paused and either all requested items are processed or if
// the trie being worked on is retrieved from the prefetcher.
type subfetcher struct {
	db    Database       // Database to load trie nodes through
	state common.Hash    // Root hash of the state to prefetch
	owner common.Hash    // Owner of the trie, usually account hash
	root  common.Hash    // Root hash of the trie to prefetch
	addr  common.Address // Address of the account that the trie belongs to
	trie  Trie           // Trie being populated with nodes

	tasks []*subfetcherTask // Items queued up for retrieval
	lock  sync.Mutex        // Lock protecting the task queue

	wake chan struct{} // Wake channel if a new task is scheduled
	stop chan struct{} // Channel to interrupt processing
	term chan struct{} // Channel to signal interruption

	seenReadAddr  map[common.Address]struct{} // Tracks the accounts already loaded via read operations
	seenWriteAddr map[common.Address]struct{} // Tracks the accounts already loaded via write operations
	seenReadSlot  map[common.Hash]struct{}    // Tracks the storage already loaded via read operations
	seenWriteSlot map[common.Hash]struct{}    // Tracks the storage already loaded via write operations

	dupsRead  int // Number of duplicate preload tasks via reads only
	dupsWrite int // Number of duplicate preload tasks via writes only
	dupsCross int // Number of duplicate preload tasks via read-write-crosses

	usedAddr []common.Address // Tracks the accounts used in the end
	usedSlot []common.Hash    // Tracks the storage used in the end
}

// subfetcherTask is a trie path to prefetch, tagged with whether it originates
// from a read or a write request.
type subfetcherTask struct {
	read bool
	addr *common.Address
	slot *common.Hash
}
