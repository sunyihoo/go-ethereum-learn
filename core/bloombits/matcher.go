// Copyright 2017 The go-ethereum Authors
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

package bloombits

import "context"

// Retrieval represents a request for retrieval task assignments for a given
// bit with the given number of fetch elements, or a response for such a request.
// It can also have the actual results set to be used as a delivery data struct.
//
// The context and error fields are used by the light client to terminate matching
// early if an error is encountered on some path of the pipeline.
type Retrieval struct {
	Bit      uint
	Sections []uint64
	Bitsets  [][]byte

	Context context.Context
	Error   error
}
