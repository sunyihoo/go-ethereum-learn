// Copyright 2023 The go-ethereum Authors
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

package pathdb

import "errors"

var (
	// errSnapshotStale is returned from data accessors if the underlying layer
	// had been invalidated due to the chain progressing forward far enough
	// to not maintain the layer's original state.
	errSnapshotStale = errors.New("layer stale")

	// errUnexpectedHistory is returned if an unmatched state history is applied
	// to the database for state rollback.
	errUnexpectedHistory = errors.New("unexpected state history")
	
	// errStateUnrecoverable is returned if state is required to be reverted to
	// a destination without associated state history available.
	errStateUnrecoverable = errors.New("state is unrecoverable")
)
