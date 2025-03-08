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

import "errors"

// Constants to match up protocol versions and messages
const (
	SNAP1 = 1
)

// ProtocolName is the official short name of the `snap` protocol used during
// devp2p capability negotiation.
const ProtocolName = "snap"

// ProtocolVersions are the supported versions of the `snap` protocol (first
// is primary).
var ProtocolVersions = []uint{SNAP1}

// protocolLengths are the number of implemented message corresponding to
// different protocol versions.
var protocolLengths = map[uint]uint64{SNAP1: 8}

// maxMessageSize is the maximum cap on the size of a protocol message.
const maxMessageSize = 10 * 1024 * 1024

const (
	GetAccountRangeMsg  = 0x00
	AccountRangeMsg     = 0x01
	GetStorageRangesMsg = 0x02
	StorageRangesMsg    = 0x03
	GetByteCodesMsg     = 0x04
	ByteCodesMsg        = 0x05
	GetTrieNodesMsg     = 0x06
	TrieNodesMsg        = 0x07
)

var (
	errMsgTooLarge    = errors.New("message too long")
	errDecode         = errors.New("invalid message")
	errInvalidMsgCode = errors.New("invalid message code")
	errBadRequest     = errors.New("bad request")
)

// Packet represents a p2p message in the `snap` protocol.
type Packet interface {
	Name() string // Name returns a string corresponding to the message type.
	Kind() byte   // Kind returns the message type.
}

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
