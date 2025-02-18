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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package rawdb

// HashScheme is the legacy hash-based state scheme with which trie nodes are
// stored in the disk with node hash as the database key. The advantage of this
// scheme is that different versions of trie nodes can be stored in disk, which
// is very beneficial for constructing archive nodes. The drawback is it will
// store different trie nodes on the same path to different locations on the disk
// with no data locality, and it's unfriendly for designing state pruning.
//
// Now this scheme is still kept for backward compatibility, and it will be used
// for archive node and some other tries(e.g. light trie).
const HashScheme = "hash"
