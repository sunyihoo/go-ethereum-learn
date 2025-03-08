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

package eth

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// txMaxBroadcastSize is the max size of a transaction that will be broadcasted.
	// All transactions with a higher size will be announced and need to be fetched
	// by the peer.
	txMaxBroadcastSize = 4096
)

var syncChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the sync progress challenge

// txPool defines the methods needed from a transaction pool implementation to
// support all the operations needed by the Ethereum chain protocols.
type txPool interface {
	// Has returns an indicator whether txpool has a transaction
	// cached with the given hash.
	Has(hash common.Hash) bool

	// Get retrieves the transaction from local txpool with given
	// tx hash.
	Get(hash common.Hash) *types.Transaction

	// Add should add the given transactions to the pool.
	Add(txs []*types.Transaction, local bool, sync bool) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction

	// SubscribeTransactions subscribes to new transaction events. The subscriber
	// can decide whether to receive notifications only for newly seen transactions
	// or also for reorged out ones.
	SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription
}

// handlerConfig is the collection of initialization parameters to create a full
// node network handler.
type handlerConfig struct {
	NodeID         enode.ID               // P2P node ID used for tx propagation topology
	Database       ethdb.Database         // Database for direct sync insertions
	Chain          *core.BlockChain       // Blockchain to serve data from
	TxPool         txPool                 // Transaction pool to propagate from
	Network        uint64                 // Network identifier to advertise
	Sync           ethconfig.SyncMode     // Whether to snap or full sync
	BloomCache     uint64                 // Megabytes to alloc for snap sync bloom
	EventMux       *event.TypeMux         // Legacy event mux, deprecate for `feed`
	RequiredBlocks map[uint64]common.Hash // Hard coded map of required block hashes for sync challenges
}

type handler struct {
	nodeID     enode.ID
	networkID  uint64
	forkFilter forkid.Filter // Fork ID filter, constant across the lifetime of the node

	snapSync atomic.Bool // Flag whether snap sync is enabled (gets disabled if we already have blocks)
	synced   atomic.Bool // Flag whether we're considered synchronised (enables transaction processing)

	database ethdb.Database
	txpool   txPool
	chain    *core.BlockChain

	maxPeers   int
	downloader *downloader.Downloader
	txFetcher  *fetcher.TxFetcher
	peers      *peerSet

	eventMux *event.TypeMux
	txsCh    chan core.NewTxsEvent
	txsSub   event.Subscription

	requiredBlocks map[uint64]common.Hash

	// channels for fetcher, syncer, txsyncLoop
	quitSync chan struct{}

	wg sync.WaitGroup

	handlerStartCh chan struct{}
	handlerDoneCh  chan struct{}
}

// newHandler returns a handler for all Ethereum chain management protocol.
func newHandler(config *handlerConfig) (*handler, error) {
	// Create the protocol manager with the base fields
	if config.EventMux == nil {
		config.EventMux = new(event.TypeMux) // Nicety initialization for tests
	}
	h := &handler{
		nodeID:         config.NodeID,
		networkID:      config.Network,
		forkFilter:     forkid.NewFilter(config.Chain),
		eventMux:       config.EventMux,
		database:       config.Database,
		txpool:         config.TxPool,
		chain:          config.Chain,
		peers:          newPeerSet(),
		requiredBlocks: config.RequiredBlocks,
		quitSync:       make(chan struct{}),
		handlerDoneCh:  make(chan struct{}),
		handlerStartCh: make(chan struct{}),
	}
	if config.Sync == ethconfig.FullSync {
		// The database seems empty as the current block is the genesis. Yet the snap
		// block is ahead, so snap sync was enabled for this node at a certain point.
		// The scenarios where this can happen is
		// * if the user manually (or via a bad block) rolled back a snap sync node
		//   below the sync point.
		// * the last snap sync is not finished while user specifies a full sync this
		//   time. But we don't have any recent state for full sync.
		// In these cases however it's safe to reenable snap sync.
		fullBlock, snapBlock := h.chain.CurrentBlock(), h.chain.CurrentSnapBlock()
		if fullBlock.Number.Uint64() == 0 && snapBlock.Number.Uint64() > 0 {
			h.snapSync.Store(true)
			log.Warn("Switch sync mode from full sync to snap sync", "reason", "snap sync incomplete")
		} else if !h.chain.HasState(fullBlock.Root) {
			h.snapSync.Store(true)
			log.Warn("Switch sync mode from full sync to snap sync", "reason", "head state missing")
		}
	} else {
		head := h.chain.CurrentBlock()
		if head.Number.Uint64() > 0 && h.chain.HasState(head.Root) {
			// Print warning log if database is not empty to run snap sync.
			log.Warn("Switch sync mode from snap sync to full sync", "reason", "snap sync complete")
		} else {
			// If snap sync was requested and our database is empty, grant it
			h.snapSync.Store(true)
			log.Info("Enabled snap sync", "head", head.Number, "hash", head.Hash())
		}
	}
	// If snap sync is requested but snapshots are disabled, fail loudly
	if h.snapSync.Load() && config.Chain.Snapshots() == nil {
		return nil, errors.New("snap sync not supported with snapshots disabled")
	}
	// Construct the downloader (long sync)
	h.downloader = downloader.New(config.Database, h.eventMux, h.chain, h.removePeer, h.enableSyncedFeatures)

	fetchTx := func(peer string, hashes []common.Hash) error {
		p := h.peers.peer(peer)
		if p == nil {
			return errors.New("unknown peer")
		}
		return p.RequestTxs(hashes)
	}
	addTxs := func(txs []*types.Transaction) []error {
		return h.txpool.Add(txs, false, false)
	}
	h.txFetcher = fetcher.NewTxFetcher(h.txpool.Has, addTxs, fetchTx, h.removePeer)
	return h, nil
}
