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

package snap

import "github.com/ethereum/go-ethereum/common"

// genTrie interface is used by the snap syncer to generate merkle tree nodes
// based on a received batch of states.
type genTrie interface {
	// update inserts the state item into generator trie.
	update(key, value []byte) error

	// delete removes the state item from the generator trie.
	delete(key []byte) error

	// commit flushes the right boundary nodes if complete flag is true. This
	// function must be called before flushing the associated database batch.
	commit(complete bool) common.Hash
}
