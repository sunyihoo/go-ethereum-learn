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

package discover

import (
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// tableNode is an entry in Table.
type tableNode struct {
	*enode.Node
	revalList       *revalidationList
	addedToTable    time.Time // first time node was added to bucket or replacement list
	addedToBucket   time.Time // time it was added in the actual bucket
	livenessChecks  uint      // how often liveness was checked
	isValidatedLive bool      // true if existence of node is considered validated right now
}
