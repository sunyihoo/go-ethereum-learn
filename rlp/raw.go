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

package rlp

import "reflect"

// RawValue represents an encoded RLP value and can be used to delay
// RLP decoding or to precompute an encoding. Note that the decoder does
// not verify whether the content of RawValues is valid RLP.
type RawValue []byte

var rawValueType = reflect.TypeOf(RawValue{})

// StringSize returns the encoded size of a string.
func StringSize(s string) uint64 {
	switch n := len(s); n {
	case 0:
		return 1
	case 1:
		if s[0] <= 0x7f {
			return 1
		} else {
			return 2
		}
	default:
		return uint64(headsize(uint64(n)) + n)
	}
}

// BytesSize returns the encoded size of a byte slice.
func BytesSize(b []byte) uint64 {
	switch n := len(b); n {
	case 0:
		return 1
	case 1:
		if b[0] <= 0x7f {
			return 1
		} else {
			return 2
		}
	default:
		return uint64(headsize(uint64(n)) + n)
	}
}

// ListSize returns the encoded size of an RLP list with the given
// content size.
func ListSize(contentSize uint64) uint64 {
	return uint64(headsize(contentSize)) + contentSize
}

// IntSize returns the encoded size of the integer x. Note: The return type of this
// function is 'int' for backwards-compatibility reasons. The result is always positive.
func IntSize(x uint64) int {
	if x < 0x80 {
		return 1
	}
	return 1 + intsize(x)
}
