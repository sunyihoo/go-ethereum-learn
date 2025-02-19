// Copyright 2024 The go-ethereum Authors
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

package stateless

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// HeaderReader is an interface to pull in headers in place of block hashes for
// the witness.
type HeaderReader interface {
	// GetHeader retrieves a block header from the database by hash and number,
	GetHeader(hash common.Hash, number uint64) *types.Header
}

// Witness encompasses the state required to apply a set of transactions and
// derive a post state/receipt root.
type Witness struct {
	context *types.Header // Header to which this witness belongs to, with rootHash and receiptHash zeroed out

	Headers []*types.Header     // Past headers in reverse order (0=parent, 1=parent's-parent, etc). First *must* be set.
	Codes   map[string]struct{} // Set of bytecodes ran or accessed
	State   map[string]struct{} // Set of MPT state trie nodes (account and storage together)

	chain HeaderReader // Chain reader to convert block hash ops to header proofs
	lock  sync.Mutex   // Lock to allow concurrent state insertions
}
