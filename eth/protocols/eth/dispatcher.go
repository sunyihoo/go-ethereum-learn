// Copyright 2021 The go-ethereum Authors
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

package eth

import "time"

// Request is a pending request to allow tracking it and delivering a response
// back to the requester on their chosen channel.
type Request struct {
	peer *Peer  // Peer to which this request belongs for untracking
	id   uint64 // Request ID to match up replies to

	sink   chan *Response // Channel to deliver the response on
	cancel chan struct{}  // Channel to cancel requests ahead of time

	code uint64      // Message code of the request packet
	want uint64      // Message code of the response packet
	data interface{} // Data content of the request packet

	Peer string    // Demultiplexer if cross-peer requests are batched together
	Sent time.Time // Timestamp when the request was sent
}

// request is a wrapper around a client Request that has an error channel to
// signal on if sending the request already failed on a network level.
type request struct {
	req  *Request
	fail chan error
}

// cancel is a maintenance type on the dispatcher to stop tracking a pending
// request.
type cancel struct {
	id   uint64 // Request ID to stop tracking
	fail chan error
}

// Response is a reply packet to a previously created request. It is delivered
// on the channel assigned by the requester subsystem and contains the original
// request embedded to allow uniquely matching it caller side.

type Response struct {
	id   uint64    // Request ID to match up this reply to
	recv time.Time // Timestamp when the request was received
	code uint64    // Response packet type to cross validate with request

	Req  *Request      // Original request to cross-reference with
	Res  interface{}   // Remote response for the request query
	Meta interface{}   // Metadata generated locally on the receiver thread
	Time time.Duration // Time it took for the request to be served
	Done chan error    // Channel to signal message handling to the reader
}

// response is a wrapper around a remote Response that has an error channel to
// signal on if processing the response failed.
type response struct {
	res  *Response
	fail chan error
}
