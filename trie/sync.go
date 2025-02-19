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

package trie

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/prque"
	"github.com/ethereum/go-ethereum/ethdb"
)

// LeafCallback is a callback type invoked when a trie operation reaches a leaf
// node.
//
// The keys is a path tuple identifying a particular trie node either in a single
// trie (account) or a layered trie (account -> storage). Each key in the tuple
// is in the raw format(32 bytes).
//
// The path is a composite hexary path identifying the trie node. All the key
// bytes are converted to the hexary nibbles and composited with the parent path
// if the trie node is in a layered trie.
//
// It's used by state sync and commit to allow handling external references
// between account and storage tries. And also it's used in the state healing
// for extracting the raw states(leaf nodes) with corresponding paths.
type LeafCallback func(keys [][]byte, path []byte, leaf []byte, parent common.Hash, parentPath []byte) error

// nodeRequest represents a scheduled or already in-flight trie node retrieval request.
type nodeRequest struct {
	hash common.Hash // Hash of the trie node to retrieve
	path []byte      // Merkle path leading to this node for prioritization
	data []byte      // Data content of the node, cached until all subtrees complete

	parent   *nodeRequest // Parent state node referencing this entry
	deps     int          // Number of dependencies before allowed to commit this node
	callback LeafCallback // Callback to invoke if a leaf node it reached on this branch
}

// codeRequest represents a scheduled or already in-flight bytecode retrieval request.
type codeRequest struct {
	hash    common.Hash    // Hash of the contract bytecode to retrieve
	path    []byte         // Merkle path leading to this node for prioritization
	data    []byte         // Data content of the node, cached until all subtrees complete
	parents []*nodeRequest // Parent state nodes referencing this entry (notify all upon completion)
}

// nodeOp represents an operation upon the trie node. It can either represent a
// deletion to the specific node or a node write for persisting retrieved node.
type nodeOp struct {
	del   bool        // flag if op stands for a delete operation
	owner common.Hash // identifier of the trie (empty for account trie)
	path  []byte      // path from the root to the specified node.
	blob  []byte      // the content of the node (nil for deletion)
	hash  common.Hash // hash of the node content (empty for node deletion)
}

// syncMemBatch is an in-memory buffer of successfully downloaded but not yet
// persisted data items.
type syncMemBatch struct {
	scheme string                 // State scheme identifier
	codes  map[common.Hash][]byte // In-memory batch of recently completed codes
	nodes  []nodeOp               // In-memory batch of recently completed/deleted nodes
	size   uint64                 // Estimated batch-size of in-memory data.
}

// Sync is the main state trie synchronisation scheduler, which provides yet
// unknown trie hashes to retrieve, accepts node data associated with said hashes
// and reconstructs the trie step by step until all is done.
type Sync struct {
	scheme   string                       // Node scheme descriptor used in database.
	database ethdb.KeyValueReader         // Persistent database to check for existing entries
	membatch *syncMemBatch                // Memory buffer to avoid frequent database writes
	nodeReqs map[string]*nodeRequest      // Pending requests pertaining to a trie node path
	codeReqs map[common.Hash]*codeRequest // Pending requests pertaining to a code hash
	queue    *prque.Prque[int64, any]     // Priority queue with the pending requests
	fetches  map[int]int                  // Number of active fetches per trie node depth
}
