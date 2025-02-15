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

package v5wire

import (
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Packet is implemented by all message types.
type Packet interface {
	Name() string        // Name returns a string corresponding to the message type.
	Kind() byte          // Kind returns the message type.
	RequestID() []byte   // Returns the request ID.
	SetRequestID([]byte) // Sets the request ID.

	// AppendLogInfo returns its argument 'ctx' with additional fields
	// appended for logging purposes.
	AppendLogInfo(ctx []interface{}) []interface{}
}

type (
	// Unknown represents any packet that can't be decrypted.
	Unknown struct {
		Nonce Nonce
	}
	
	// WHOAREYOU contains the handshake challenge.
	Whoareyou struct {
		ChallengeData []byte   // Encoded challenge
		Nonce         Nonce    // Nonce of request packet
		IDNonce       [16]byte // Identity proof data
		RecordSeq     uint64   // ENR sequence number of recipient

		// Node is the locally known node record of recipient.
		// This must be set by the caller of Encode.
		Node *enode.Node

		sent mclock.AbsTime // for handshake GC.
	}
)
