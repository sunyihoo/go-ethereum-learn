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

package snap

// TrieNodePathSet is a list of trie node paths to retrieve. A naive way to
// represent trie nodes would be a simple list of `account || storage` path
// segments concatenated, but that would be very wasteful on the network.
//
// Instead, this array special cases the first element as the path in the
// account trie and the remaining elements as paths in the storage trie. To
// address an account node, the slice should have a length of 1 consisting
// of only the account path. There's no need to be able to address both an
// account node and a storage node in the same request as it cannot happen
// that a slot is accessed before the account path is fully expanded.
type TrieNodePathSet [][]byte
