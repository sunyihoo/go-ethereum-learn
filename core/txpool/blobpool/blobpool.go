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

// Package blobpool implements the EIP-4844 blob transaction pool.
package blobpool

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/billy"
	"github.com/holiman/uint256"
)

const (
	// blobSize is the protocol constrained byte size of a single blob in a
	// transaction. There can be multiple of these embedded into a single tx.
	blobSize = params.BlobTxFieldElementsPerBlob * params.BlobTxBytesPerFieldElement

	// maxBlobsPerTransaction is the maximum number of blobs a single transaction
	// is allowed to contain. Whilst the spec states it's unlimited, the block
	// data slots are protocol bound, which implicitly also limit this.
	maxBlobsPerTransaction = params.MaxBlobGasPerBlock / params.BlobTxBlobGasPerBlob

	// txAvgSize is an approximate byte size of a transaction metadata to avoid
	// tiny overflows causing all txs to move a shelf higher, wasting disk space.
	txAvgSize = 4 * 1024

	// txMaxSize is the maximum size a single transaction can have, outside
	// the included blobs. Since blob transactions are pulled instead of pushed,
	// and only a small metadata is kept in ram, the rest is on disk, there is
	// no critical limit that should be enforced. Still, capping it to some sane
	// limit can never hurt.
	txMaxSize = 1024 * 1024

	// maxTxsPerAccount is the maximum number of blob transactions admitted from
	// a single account. The limit is enforced to minimize the DoS potential of
	// a private tx cancelling publicly propagated blobs.
	//
	// Note, transactions resurrected by a reorg are also subject to this limit,
	// so pushing it down too aggressively might make resurrections non-functional.
	maxTxsPerAccount = 16

	// pendingTransactionStore is the subfolder containing the currently queued
	// blob transactions.
	pendingTransactionStore = "queue"

	// limboedTransactionStore is the subfolder containing the currently included
	// but not yet finalized transaction blobs.
	limboedTransactionStore = "limbo"
)

// blobTxMeta is the minimal subset of types.BlobTx necessary to validate and
// schedule the blob transactions into the following blocks. Only ever add the
// bare minimum needed fields to keep the size down (and thus number of entries
// larger with the same memory consumption).
type blobTxMeta struct {
	hash    common.Hash   // Transaction hash to maintain the lookup table
	vhashes []common.Hash // Blob versioned hashes to maintain the lookup table

	id   uint64 // Storage ID in the pool's persistent store
	size uint32 // Byte size in the pool's persistent store

	nonce      uint64       // Needed to prioritize inclusion order within an account
	costCap    *uint256.Int // Needed to validate cumulative balance sufficiency
	execTipCap *uint256.Int // Needed to prioritize inclusion order across accounts and validate replacement price bump
	execFeeCap *uint256.Int // Needed to validate replacement price bump
	blobFeeCap *uint256.Int // Needed to validate replacement price bump
	execGas    uint64       // Needed to check inclusion validity before reading the blob
	blobGas    uint64       // Needed to check inclusion validity before reading the blob

	basefeeJumps float64 // Absolute number of 1559 fee adjustments needed to reach the tx's fee cap
	blobfeeJumps float64 // Absolute number of 4844 fee adjustments needed to reach the tx's blob fee cap

	evictionExecTip      *uint256.Int // Worst gas tip across all previous nonces
	evictionExecFeeJumps float64      // Worst base fee (converted to fee jumps) across all previous nonces
	evictionBlobFeeJumps float64      // Worse blob fee (converted to fee jumps) across all previous nonces
}

// newBlobTxMeta retrieves the indexed metadata fields from a blob transaction
// and assembles a helper struct to track in memory.
func newBlobTxMeta(id uint64, size uint32, tx *types.Transaction) *blobTxMeta {
	meta := &blobTxMeta{
		hash:       tx.Hash(),
		vhashes:    tx.BlobHashes(),
		id:         id,
		size:       size,
		nonce:      tx.Nonce(),
		costCap:    uint256.MustFromBig(tx.Cost()),
		execTipCap: uint256.MustFromBig(tx.GasTipCap()),
		execFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
		blobFeeCap: uint256.MustFromBig(tx.BlobGasFeeCap()),
		execGas:    tx.Gas(),
		blobGas:    tx.BlobGas(),
	}
	meta.basefeeJumps = dynamicFeeJumps(meta.execFeeCap)
	meta.blobfeeJumps = dynamicFeeJumps(meta.blobFeeCap)

	return meta
}

// BlobPool is the transaction pool dedicated to EIP-4844 blob transactions.
//
// Blob transactions are special snowflakes that are designed for a very specific
// purpose (rollups) and are expected to adhere to that specific use case. These
// behavioural expectations allow us to design a transaction pool that is more robust
// (i.e. resending issues) and more resilient to DoS attacks (e.g. replace-flush
// attacks) than the generic tx pool. These improvements will also mean, however,
// that we enforce a significantly more aggressive strategy on entering and exiting
// the pool:
//
//   - Blob transactions are large. With the initial design aiming for 128KB blobs,
//     we must ensure that these only traverse the network the absolute minimum
//     number of times. Broadcasting to sqrt(peers) is out of the question, rather
//     these should only ever be announced and the remote side should request it if
//     it wants to.
//
//   - Block blob-space is limited. With blocks being capped to a few blob txs, we
//     can make use of the very low expected churn rate within the pool. Notably,
//     we should be able to use a persistent disk backend for the pool, solving
//     the tx resend issue that plagues the generic tx pool, as long as there's no
//     artificial churn (i.e. pool wars).
//
//   - Purpose of blobs are layer-2s. Layer-2s are meant to use blob transactions to
//     commit to their own current state, which is independent of Ethereum mainnet
//     (state, txs). This means that there's no reason for blob tx cancellation or
//     replacement, apart from a potential basefee / miner tip adjustment.
//
//   - Replacements are expensive. Given their size, propagating a replacement
//     blob transaction to an existing one should be aggressively discouraged.
//     Whilst generic transactions can start at 1 Wei gas cost and require a 10%
//     fee bump to replace, we suggest requiring a higher min cost (e.g. 1 gwei)
//     and a more aggressive bump (100%).
//
//   - Cancellation is prohibitive. Evicting an already propagated blob tx is a huge
//     DoS vector. As such, a) replacement (higher-fee) blob txs mustn't invalidate
//     already propagated (future) blob txs (cumulative fee); b) nonce-gapped blob
//     txs are disallowed; c) the presence of blob transactions exclude non-blob
//     transactions.
//
//   - Malicious cancellations are possible. Although the pool might prevent txs
//     that cancel blobs, blocks might contain such transaction (malicious miner
//     or flashbotter). The pool should cap the total number of blob transactions
//     per account as to prevent propagating too much data before cancelling it
//     via a normal transaction. It should nonetheless be high enough to support
//     resurrecting reorged transactions. Perhaps 4-16.
//
//   - Local txs are meaningless. Mining pools historically used local transactions
//     for payouts or for backdoor deals. With 1559 in place, the basefee usually
//     dominates the final price, so 0 or non-0 tip doesn't change much. Blob txs
//     retain the 1559 2D gas pricing (and introduce on top a dynamic blob gas fee),
//     so locality is moot. With a disk backed blob pool avoiding the resend issue,
//     there's also no need to save own transactions for later.
//
//   - No-blob blob-txs are bad. Theoretically there's no strong reason to disallow
//     blob txs containing 0 blobs. In practice, admitting such txs into the pool
//     breaks the low-churn invariant as blob constraints don't apply anymore. Even
//     though we could accept blocks containing such txs, a reorg would require moving
//     them back into the blob pool, which can break invariants.
//
//   - Dropping blobs needs delay. When normal transactions are included, they
//     are immediately evicted from the pool since they are contained in the
//     including block. Blobs however are not included in the execution chain,
//     so a mini reorg cannot re-pool "lost" blob transactions. To support reorgs,
//     blobs are retained on disk until they are finalised.
//
//   - Blobs can arrive via flashbots. Blocks might contain blob transactions we
//     have never seen on the network. Since we cannot recover them from blocks
//     either, the engine_newPayload needs to give them to us, and we cache them
//     until finality to support reorgs without tx losses.
//
// Whilst some constraints above might sound overly aggressive, the general idea is
// that the blob pool should work robustly for its intended use case and whilst
// anyone is free to use blob transactions for arbitrary non-rollup use cases,
// they should not be allowed to run amok the network.
//
// Implementation wise there are a few interesting design choices:
//
//   - Adding a transaction to the pool blocks until persisted to disk. This is
//     viable because TPS is low (2-4 blobs per block initially, maybe 8-16 at
//     peak), so natural churn is a couple MB per block. Replacements doing O(n)
//     updates are forbidden and transaction propagation is pull based (i.e. no
//     pileup of pending data).
//
//   - When transactions are chosen for inclusion, the primary criteria is the
//     signer tip (and having a basefee/data fee high enough of course). However,
//     same-tip transactions will be split by their basefee/datafee, preferring
//     those that are closer to the current network limits. The idea being that
//     very relaxed ones can be included even if the fees go up, when the closer
//     ones could already be invalid.
//
// When the pool eventually reaches saturation, some old transactions - that may
// never execute - will need to be evicted in favor of newer ones. The eviction
// strategy is quite complex:
//
//   - Exceeding capacity evicts the highest-nonce of the account with the lowest
//     paying blob transaction anywhere in the pooled nonce-sequence, as that tx
//     would be executed the furthest in the future and is thus blocking anything
//     after it. The smallest is deliberately not evicted to avoid a nonce-gap.
//
//   - Analogously, if the pool is full, the consideration price of a new tx for
//     evicting an old one is the smallest price in the entire nonce-sequence of
//     the account. This avoids malicious users DoSing the pool with seemingly
//     high paying transactions hidden behind a low-paying blocked one.
//
//   - Since blob transactions have 3 price parameters: execution tip, execution
//     fee cap and data fee cap, there's no singular parameter to create a total
//     price ordering on. What's more, since the base fee and blob fee can move
//     independently of one another, there's no pre-defined way to combine them
//     into a stable order either. This leads to a multi-dimensional problem to
//     solve after every block.
//
//   - The first observation is that comparing 1559 base fees or 4844 blob fees
//     needs to happen in the context of their dynamism. Since these fees jump
//     up or down in ~1.125 multipliers (at max) across blocks, comparing fees
//     in two transactions should be based on log1.125(fee) to eliminate noise.
//
//   - The second observation is that the basefee and blobfee move independently,
//     so there's no way to split mixed txs on their own (A has higher base fee,
//     B has higher blob fee). Rather than look at the absolute fees, the useful
//     metric is the max time it can take to exceed the transaction's fee caps.
//     Specifically, we're interested in the number of jumps needed to go from
//     the current fee to the transaction's cap:
//
//     jumps = log1.125(txfee) - log1.125(basefee)
//
//   - The third observation is that the base fee tends to hover around rather
//     than swing wildly. The number of jumps needed from the current fee starts
//     to get less relevant the higher it is. To remove the noise here too, the
//     pool will use log(jumps) as the delta for comparing transactions.
//
//     delta = sign(jumps) * log(abs(jumps))
//
//   - To establish a total order, we need to reduce the dimensionality of the
//     two base fees (log jumps) to a single value. The interesting aspect from
//     the pool's perspective is how fast will a tx get executable (fees going
//     down, crossing the smaller negative jump counter) or non-executable (fees
//     going up, crossing the smaller positive jump counter). As such, the pool
//     cares only about the min of the two delta values for eviction priority.
//
//     priority = min(deltaBasefee, deltaBlobfee)
//
//   - The above very aggressive dimensionality and noise reduction should result
//     in transaction being grouped into a small number of buckets, the further
//     the fees the larger the buckets. This is good because it allows us to use
//     the miner tip meaningfully as a splitter.
//
//   - For the scenario where the pool does not contain non-executable blob txs
//     anymore, it does not make sense to grant a later eviction priority to txs
//     with high fee caps since it could enable pool wars. As such, any positive
//     priority will be grouped together.
//
//     priority = min(deltaBasefee, deltaBlobfee, 0)
//
// Optimisation tradeoffs:
//
//   - Eviction relies on 3 fee minimums per account (exec tip, exec cap and blob
//     cap). Maintaining these values across all transactions from the account is
//     problematic as each transaction replacement or inclusion would require a
//     rescan of all other transactions to recalculate the minimum. Instead, the
//     pool maintains a rolling minimum across the nonce range. Updating all the
//     minimums will need to be done only starting at the swapped in/out nonce
//     and leading up to the first no-change.
type BlobPool struct {
	config  Config                 // Pool configuration
	reserve txpool.AddressReserver // Address reserver to ensure exclusivity across subpools

	store  billy.Database // Persistent data store for the tx metadata and blobs
	stored uint64         // Useful data size of all transactions on disk
	limbo  *limbo         // Persistent data store for the non-finalized blobs

	signer types.Signer // Transaction signer to use for sender recovery
	chain  BlockChain   // Chain object to access the state through

	head   *types.Header  // Current head of the chain
	state  *state.StateDB // Current state at the head of the chain
	gasTip *uint256.Int   // Currently accepted minimum gas tip

	lookup *lookup                          // Lookup table mapping blobs to txs and txs to billy entries
	index  map[common.Address][]*blobTxMeta // Blob transactions grouped by accounts, sorted by nonce
	spent  map[common.Address]*uint256.Int  // Expenditure tracking for individual accounts
	evict  *evictHeap                       // Heap of cheapest accounts for eviction when full

	discoverFeed event.Feed // Event feed to send out new tx events on pool discovery (reorg excluded)
	insertFeed   event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)

	// txValidationFn defaults to txpool.ValidateTransaction, but can be
	// overridden for testing purposes.
	txValidationFn txpool.ValidationFunction

	lock sync.RWMutex // Mutex protecting the pool during reorg handling
}
