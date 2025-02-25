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

package downloader

import (
	"sync"
	"sync/atomic"
)

// resultStore implements a structure for maintaining fetchResults, tracking their
// download-progress and delivering (finished) results.
type resultStore struct {
	items        []*fetchResult // Downloaded but not yet delivered fetch results
	resultOffset uint64         // Offset of the first cached fetch result in the block chain

	// Internal index of first non-completed entry, updated atomically when needed.
	// If all items are complete, this will equal length(items), so
	// *important* : is not safe to use for indexing without checking against length
	indexIncomplete atomic.Int32

	// throttleThreshold is the limit up to which we _want_ to fill the
	// results. If blocks are large, we want to limit the results to less
	// than the number of available slots, and maybe only fill 1024 out of
	// 8192 possible places. The queue will, at certain times, recalibrate
	// this index.
	throttleThreshold uint64

	lock sync.RWMutex
}
