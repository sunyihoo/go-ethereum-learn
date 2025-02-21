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

package triedb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/triedb/database"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

// Config defines all necessary options for database.
type Config struct {
	Preimages bool           // Flag whether the preimage of node key is recorded
	IsVerkle  bool           // Flag whether the db is holding a verkle tree
	HashDB    *hashdb.Config // Configs for hash-based scheme
	PathDB    *pathdb.Config // Configs for experimental path-based scheme
}

// HashDefaults represents a config for using hash-based scheme with
// default settings.
var HashDefaults = &Config{
	Preimages: false,
	IsVerkle:  false,
	HashDB:    hashdb.Defaults,
}

// backend defines the methods needed to access/update trie nodes in different
// state scheme.
type backend interface {
	// NodeReader returns a reader for accessing trie nodes within the specified state.
	// An error will be returned if the specified state is not available.
	NodeReader(root common.Hash) (database.NodeReader, error)

	// StateReader returns a reader for accessing flat states within the specified
	// state. An error will be returned if the specified state is not available.
	StateReader(root common.Hash) (database.StateReader, error)

	// Size returns the current storage size of the diff layers on top of the
	// disk layer and the storage size of the nodes cached in the disk layer.
	//
	// For hash scheme, there is no differentiation between diff layer nodes
	// and dirty disk layer nodes, so both are merged into the second return.
	Size() (common.StorageSize, common.StorageSize)

	// Commit writes all relevant trie nodes belonging to the specified state
	// to disk. Report specifies whether logs will be displayed in info level.
	Commit(root common.Hash, report bool) error

	// Close closes the trie database backend and releases all held resources.
	Close() error
}

type Database struct {
	disk      ethdb.Database
	config    *Config        // Configuration for trie database
	preimages *preimageStore // The store for caching preimages
	backend   backend        // The backend for managing trie nodes
}

// NewDatabase initializes the trie database with default settings, note
// the legacy hash-based scheme is used by default.
func NewDatabase(diskdb ethdb.Database, config *Config) *Database {
	// Sanitize the config and use the default one if it's not specified.
	if config == nil {
		config = HashDefaults
	}
	var preimages *preimageStore
	if config.Preimages {
		preimages = newPreimageStore(diskdb)
	}
	db := &Database{
		disk:      diskdb,
		config:    config,
		preimages: preimages,
	}
	if config.HashDB != nil && config.PathDB != nil {
		log.Crit("Both 'hash' and 'path' mode are configured")
	}
	if config.PathDB != nil {
		db.backend = pathdb.New(diskdb, config.PathDB, config.IsVerkle)
	} else {
		db.backend = hashdb.New(diskdb, config.HashDB)
	}
	return db
}

// NodeReader returns a reader for accessing trie nodes within the specified state.
// An error will be returned if the specified state is not available.
func (db *Database) NodeReader(blockRoot common.Hash) (database.NodeReader, error) {
	return db.backend.NodeReader(blockRoot)
}
