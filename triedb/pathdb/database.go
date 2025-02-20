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

package pathdb

import (
	"io"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-verkle"
)

const (
	// defaultCleanSize is the default memory allowance of clean cache.
	defaultCleanSize = 16 * 1024 * 1024

	// maxBufferSize is the maximum memory allowance of node buffer.
	// Too large buffer will cause the system to pause for a long
	// time when write happens. Also, the largest batch that pebble can
	// support is 4GB, node will panic if batch size exceeds this limit.
	maxBufferSize = 256 * 1024 * 1024

	// defaultBufferSize is the default memory allowance of node buffer
	// that aggregates the writes from above until it's flushed into the
	// disk. It's meant to be used once the initial sync is finished.
	// Do not increase the buffer size arbitrarily, otherwise the system
	// pause time will increase when the database writes happen.
	defaultBufferSize = 64 * 1024 * 1024
)

var (
	// maxDiffLayers is the maximum diff layers allowed in the layer tree.
	maxDiffLayers = 128
)

// layer is the interface implemented by all state layers which includes some
// public methods and some additional methods for internal usage.
type layer interface {
	// node retrieves the trie node with the node info. An error will be returned
	// if the read operation exits abnormally. Specifically, if the layer is
	// already stale.
	//
	// Note:
	// - the returned node is not a copy, please don't modify it.
	// - no error will be returned if the requested node is not found in database.
	node(owner common.Hash, path []byte, depth int) ([]byte, common.Hash, *nodeLoc, error)

	// account directly retrieves the account RLP associated with a particular
	// hash in the slim data format. An error will be returned if the read
	// operation exits abnormally. Specifically, if the layer is already stale.
	//
	// Note:
	// - the returned account is not a copy, please don't modify it.
	// - no error will be returned if the requested account is not found in database.
	account(hash common.Hash, depth int) ([]byte, error)

	// storage directly retrieves the storage data associated with a particular hash,
	// within a particular account. An error will be returned if the read operation
	// exits abnormally. Specifically, if the layer is already stale.
	//
	// Note:
	// - the returned storage data is not a copy, please don't modify it.
	// - no error will be returned if the requested slot is not found in database.
	storage(accountHash, storageHash common.Hash, depth int) ([]byte, error)

	// rootHash returns the root hash for which this layer was made.
	rootHash() common.Hash

	// stateID returns the associated state id of layer.
	stateID() uint64

	// parentLayer returns the subsequent layer of it, or nil if the disk was reached.
	parentLayer() layer

	// update creates a new layer on top of the existing layer diff tree with
	// the provided dirty trie nodes along with the state change set.
	//
	// Note, the maps are retained by the method to avoid copying everything.
	update(root common.Hash, id uint64, block uint64, nodes *nodeSet, states *StateSetWithOrigin) *diffLayer

	// journal commits an entire diff hierarchy to disk into a single journal entry.
	// This is meant to be used during shutdown to persist the layer without
	// flattening everything down (bad for reorgs).
	journal(w io.Writer) error
}

// Config contains the settings for database.
type Config struct {
	StateHistory    uint64 // Number of recent blocks to maintain state history for
	CleanCacheSize  int    // Maximum memory allowance (in bytes) for caching clean nodes
	WriteBufferSize int    // Maximum memory allowance (in bytes) for write buffer
	ReadOnly        bool   // Flag whether the database is opened in read only mode.
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (c *Config) sanitize() *Config {
	conf := *c
	if conf.WriteBufferSize > maxBufferSize {
		log.Warn("Sanitizing invalid node buffer size", "provided", common.StorageSize(conf.WriteBufferSize), "updated", common.StorageSize(maxBufferSize))
		conf.WriteBufferSize = maxBufferSize
	}
	return &conf
}

// Defaults contains default settings for Ethereum mainnet.
var Defaults = &Config{
	StateHistory:    params.FullImmutabilityThreshold,
	CleanCacheSize:  defaultCleanSize,
	WriteBufferSize: defaultBufferSize,
}

// nodeHasher is the function to compute the hash of supplied node blob.
type nodeHasher func([]byte) (common.Hash, error)

// merkleNodeHasher computes the hash of the given merkle node.
func merkleNodeHasher(blob []byte) (common.Hash, error) {
	if len(blob) == 0 {
		return types.EmptyRootHash, nil
	}
	return crypto.Keccak256Hash(blob), nil
}

// verkleNodeHasher computes the hash of the given verkle node.
func verkleNodeHasher(blob []byte) (common.Hash, error) {
	if len(blob) == 0 {
		return types.EmptyVerkleHash, nil
	}
	n, err := verkle.ParseNode(blob, 0)
	if err != nil {
		return common.Hash{}, err
	}
	return n.Commit().Bytes(), nil
}

// Database is a multiple-layered structure for maintaining in-memory states
// along with its dirty trie nodes. It consists of one persistent base layer
// backed by a key-value store, on top of which arbitrarily many in-memory diff
// layers are stacked. The memory diffs can form a tree with branching, but the
// disk layer is singleton and common to all. If a reorg goes deeper than the
// disk layer, a batch of reverse diffs can be applied to rollback. The deepest
// reorg that can be handled depends on the amount of state histories tracked
// in the disk.
//
// At most one readable and writable database can be opened at the same time in
// the whole system which ensures that only one database writer can operate the
// persistent state. Unexpected open operations can cause the system to panic.
type Database struct {
	// readOnly is the flag whether the mutation is allowed to be applied.
	// It will be set automatically when the database is journaled during
	// the shutdown to reject all following unexpected mutations.
	readOnly bool       // Flag if database is opened in read only mode
	waitSync bool       // Flag if database is deactivated due to initial state sync
	isVerkle bool       // Flag if database is used for verkle tree
	hasher   nodeHasher // Trie node hasher

	config *Config // Configuration for database

	diskdb  ethdb.Database               // Persistent storage for matured trie nodes
	tree    *layerTree                   // The group for all known layers
	freezer ethdb.ResettableAncientStore // Freezer for storing trie histories, nil possible in tests
	lock    sync.RWMutex                 // Lock to prevent mutations from happening at the same time
}

// New attempts to load an already existing layer from a persistent key-value
// store (with a number of memory layers from a journal). If the journal is not
// matched with the base persistent layer, all the recorded diff layers are discarded.
func New(diskdb ethdb.Database, config *Config, isVerkle bool) *Database {
	if config == nil {
		config = Defaults
	}
	config = config.sanitize()

	db := &Database{
		readOnly: config.ReadOnly,
		isVerkle: isVerkle,
		config:   config,
		diskdb:   diskdb,
		hasher:   merkleNodeHasher,
	}
	// Establish a dedicated database namespace tailored for verkle-specific
	// data, ensuring the isolation of both verkle and merkle tree data. It's
	// important to note that the introduction of a prefix won't lead to
	// substantial storage overhead, as the underlying database will efficiently
	// compress the shared key prefix.
	if isVerkle {
		db.diskdb = rawdb.NewTable(diskdb, string(rawdb.VerklePrefix))
		db.hasher = verkleNodeHasher
	}
	// Construct the layer tree by resolving the in-disk singleton state
	// and in-memory layer journal.
	db.tree = newLayerTree(db.loadLayers())

}
