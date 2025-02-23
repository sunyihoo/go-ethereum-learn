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

package bitutil

// The compression algorithm implemented by CompressBytes and DecompressBytes is
// optimized for sparse input data which contains a lot of zero bytes. Decompression
// requires knowledge of the decompressed data length.
//
// Compression works as follows:
//
//   if data only contains zeroes,
//       CompressBytes(data) == nil
//   otherwise if len(data) <= 1,
//       CompressBytes(data) == data
//   otherwise:
//       CompressBytes(data) == append(CompressBytes(nonZeroBitset(data)), nonZeroBytes(data)...)
//       where
//         nonZeroBitset(data) is a bit vector with len(data) bits (MSB first):
//             nonZeroBitset(data)[i/8] && (1 << (7-i%8)) != 0  if data[i] != 0
//             len(nonZeroBitset(data)) == (len(data)+7)/8
//         nonZeroBytes(data) contains the non-zero bytes of data in the same order

// CompressBytes compresses the input byte slice according to the sparse bitset
// representation algorithm. If the result is bigger than the original input, no
// compression is done.
func CompressBytes(data []byte) []byte {
	if out := bitsetEncodeBytes(data); len(out) < len(data) {
		return out
	}
	cpy := make([]byte, len(data))
	copy(cpy, data)
	return cpy
}

// bitsetEncodeBytes compresses the input byte slice according to the sparse
// bitset representation algorithm.
func bitsetEncodeBytes(data []byte) []byte {
	// Empty slices get compressed to nil
	if len(data) == 0 {
		return nil
	}
	// One byte slices compress to nil or retain the single byte
	if len(data) == 1 {
		if data[0] == 0 {
			return nil
		}
		return data
	}
	// Calculate the bitset of set bytes, and gather the non-zero bytes
	nonZeroBitset := make([]byte, (len(data)+7)/8)
	nonZeroBytes := make([]byte, 0, len(data))

	for i, b := range data {
		if b != 0 {
			nonZeroBytes = append(nonZeroBytes, b)
			nonZeroBitset[i/8] |= 1 << byte(7-i%8)
		}
	}
	if len(nonZeroBytes) == 0 {
		return nil
	}
	return append(bitsetEncodeBytes(nonZeroBitset), nonZeroBytes...)
}
