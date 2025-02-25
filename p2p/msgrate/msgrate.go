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

// Package msgrate allows estimating the throughput of peers for more balanced syncs.
package msgrate

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// Tracker estimates the throughput capacity of a peer with regard to each data
// type it can deliver. The goal is to dynamically adjust request sizes to max
// out network throughput without overloading either the peer or the local node.
//
// By tracking in real time the latencies and bandwidths peers exhibit for each
// packet type, it's possible to prevent overloading by detecting a slowdown on
// one type when another type is pushed too hard.
//
// Similarly, real time measurements also help avoid overloading the local net
// connection if our peers would otherwise be capable to deliver more, but the
// local link is saturated. In that case, the live measurements will force us
// to reduce request sizes until the throughput gets stable.
//
// Lastly, message rate measurements allows us to detect if a peer is unusually
// slow compared to other peers, in which case we can decide to keep it around
// or free up the slot so someone closer.
//
// Since throughput tracking and estimation adapts dynamically to live network
// conditions, it's fine to have multiple trackers locally track the same peer
// in different subsystem. The throughput will simply be distributed across the
// two trackers if both are highly active.
// TODO to learn what this?
type Tracker struct {
	// capacity is the number of items retrievable per second of a given type.
	// It is analogous to bandwidth, but we deliberately avoided using bytes
	// as the unit, since serving nodes also spend a lot of time loading data
	// from disk, which is linear in the number of items, but mostly constant
	// in their sizes.
	//
	// Callers of course are free to use the item counter as a byte counter if
	// or when their protocol of choice if capped by bytes instead of items.
	// (eg. eth.getHeaders vs snap.getAccountRange).
	capacity map[uint64]float64

	// roundtrip is the latency a peer in general responds to data requests.
	// This number is not used inside the tracker, but is exposed to compare
	// peers to each other and filter out slow ones. Note however, it only
	// makes sense to compare RTTs if the caller caters request sizes for
	// each peer to target the same RTT. There's no need to make this number
	// the real networking RTT, we just need a number to compare peers with.
	roundtrip time.Duration

	lock sync.RWMutex
}

// Trackers is a set of message rate trackers across a number of peers with the
// goal of aggregating certain measurements across the entire set for outlier
// filtering and newly joining initialization.
type Trackers struct {
	trackers map[string]*Tracker

	// roundtrip is the current best guess as to what is a stable round trip time
	// across the entire collection of connected peers. This is derived from the
	// various trackers added, but is used as a cache to avoid recomputing on each
	// network request. The value is updated once every RTT to avoid fluctuations
	// caused by hiccups or peer events.
	roundtrip time.Duration

	// confidence represents the probability that the estimated roundtrip value
	// is the real one across all our peers. The confidence value is used as an
	// impact factor of new measurements on old estimates. As our connectivity
	// stabilizes, this value gravitates towards 1, new measurements having
	// almost no impact. If there's a large peer churn and few peers, then new
	// measurements will impact it more. The confidence is increased with every
	// packet and dropped with every new connection.
	confidence float64

	// tuned is the time instance the tracker recalculated its cached roundtrip
	// value and confidence values. A cleaner way would be to have a heartbeat
	// goroutine do it regularly, but that requires a lot of maintenance to just
	// run every now and again.
	tuned time.Time

	// The fields below can be used to override certain default values. Their
	// purpose is to allow quicker tests. Don't use them in production.
	OverrideTTLLimit time.Duration

	log  log.Logger
	lock sync.RWMutex
}
