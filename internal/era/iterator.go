// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package era

import (
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// Iterator wraps RawIterator and returns decoded Era1 entries.
// Iterator 封装了 RawIterator 并返回解码后的 Era1 条目。
type Iterator struct {
	inner *RawIterator
}

// NewIterator returns a new Iterator instance. Next must be immediately
// called on new iterators to load the first item.
// NewIterator 返回一个新的 Iterator 实例。必须立即在新迭代器上调用 Next 以加载第一个条目。
func NewIterator(e *Era) (*Iterator, error) {
	inner, err := NewRawIterator(e)
	if err != nil {
		return nil, err
	}
	return &Iterator{inner}, nil
}

// Next moves the iterator to the next block entry. It returns false when all
// items have been read or an error has halted its progress. Block, Receipts,
// and BlockAndReceipts should no longer be called after false is returned.
// Next 将迭代器移动到下一个区块条目。当所有条目都已读取或发生错误导致其停止时，它返回 false。
// 在返回 false 后，不应再调用 Block、Receipts 和 BlockAndReceipts。
func (it *Iterator) Next() bool {
	return it.inner.Next()
}

// Number returns the current number block the iterator will return.
// Number 返回迭代器将返回的当前区块号。
func (it *Iterator) Number() uint64 {
	return it.inner.next - 1
}

// Error returns the error status of the iterator. It should be called before
// reading from any of the iterator's values.
// Error 返回迭代器的错误状态。在读取迭代器的任何值之前应该调用它。
func (it *Iterator) Error() error {
	return it.inner.Error()
}

// Block returns the block for the iterator's current position.
// Block 返回迭代器当前位置的区块。
func (it *Iterator) Block() (*types.Block, error) {
	if it.inner.Header == nil || it.inner.Body == nil {
		return nil, errors.New("header and body must be non-nil")
	}
	var (
		header types.Header
		body   types.Body
	)
	if err := rlp.Decode(it.inner.Header, &header); err != nil {
		return nil, err
	}
	if err := rlp.Decode(it.inner.Body, &body); err != nil {
		return nil, err
	}
	return types.NewBlockWithHeader(&header).WithBody(body), nil
}

// Receipts returns the receipts for the iterator's current position.
// Receipts 返回迭代器当前位置的交易回执。
func (it *Iterator) Receipts() (types.Receipts, error) {
	if it.inner.Receipts == nil {
		return nil, errors.New("receipts must be non-nil")
	}
	var receipts types.Receipts
	err := rlp.Decode(it.inner.Receipts, &receipts)
	return receipts, err
}

// BlockAndReceipts returns the block and receipts for the iterator's current
// position.
// BlockAndReceipts 返回迭代器当前位置的区块和交易回执。
func (it *Iterator) BlockAndReceipts() (*types.Block, types.Receipts, error) {
	b, err := it.Block()
	if err != nil {
		return nil, nil, err
	}
	r, err := it.Receipts()
	if err != nil {
		return nil, nil, err
	}
	return b, r, nil
}

// TotalDifficulty returns the total difficulty for the iterator's current
// position.
// TotalDifficulty 返回迭代器当前位置的总难度。
func (it *Iterator) TotalDifficulty() (*big.Int, error) {
	td, err := io.ReadAll(it.inner.TotalDifficulty)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(reverseOrder(td)), nil
}

// RawIterator reads an RLP-encode Era1 entries.
// RawIterator 读取 RLP 编码的 Era1 条目。
type RawIterator struct {
	e    *Era   // backing Era1
	next uint64 // next block to read
	err  error  // last error

	Header          io.Reader
	Body            io.Reader
	Receipts        io.Reader
	TotalDifficulty io.Reader
}

// NewRawIterator returns a new RawIterator instance. Next must be immediately
// called on new iterators to load the first item.
// NewRawIterator 返回一个新的 RawIterator 实例。必须立即在新迭代器上调用 Next 以加载第一个条目。
func NewRawIterator(e *Era) (*RawIterator, error) {
	return &RawIterator{
		e:    e,
		next: e.m.start,
	}, nil
}

// Next moves the iterator to the next block entry. It returns false when all
// items have been read or an error has halted its progress. Header, Body,
// Receipts, TotalDifficulty will be set to nil in the case returning false or
// finding an error and should therefore no longer be read from.
// Next 将迭代器移动到下一个区块条目。当所有条目都已读取或发生错误导致其停止时，它返回 false。
// 在返回 false 或发现错误的情况下，Header、Body、Receipts、TotalDifficulty 将被设置为 nil，因此不应再从中读取。
func (it *RawIterator) Next() bool {
	// Clear old errors.
	// 清除旧的错误。
	it.err = nil
	if it.e.m.start+it.e.m.count <= it.next {
		it.clear()
		return false
	}
	off, err := it.e.readOffset(it.next)
	if err != nil {
		// Error here means block index is corrupted, so don't
		// continue.
		// 这里的错误意味着区块索引已损坏，因此不要继续。
		it.clear()
		it.err = err
		return false
	}
	var n int64
	// newSnappyReader creates a reader that decompresses the data on the fly using snappy.
	// It takes the underlying storage (it.e.s), the type of data (e.g., TypeCompressedHeader), and the offset as input.
	// It returns an io.Reader, the number of bytes read from the offset, and an error if any.
	if it.Header, n, it.err = newSnappyReader(it.e.s, TypeCompressedHeader, off); it.err != nil {
		it.clear()
		return true
	}
	off += n
	if it.Body, n, it.err = newSnappyReader(it.e.s, TypeCompressedBody, off); it.err != nil {
		it.clear()
		return true
	}
	off += n
	if it.Receipts, n, it.err = newSnappyReader(it.e.s, TypeCompressedReceipts, off); it.err != nil {
		it.clear()
		return true
	}
	off += n
	// it.e.s.ReaderAt creates a reader that reads directly from the storage at the given type and offset.
	// In this case, it's used for TotalDifficulty, which might not be compressed or handled differently.
	if it.TotalDifficulty, _, it.err = it.e.s.ReaderAt(TypeTotalDifficulty, off); it.err != nil {
		it.clear()
		return true
	}
	it.next += 1
	return true
}

// Number returns the current number block the iterator will return.
// Number 返回迭代器将返回的当前区块号。
func (it *RawIterator) Number() uint64 {
	return it.next - 1
}

// Error returns the error status of the iterator. It should be called before
// reading from any of the iterator's values.
// Error 返回迭代器的错误状态。在读取迭代器的任何值之前应该调用它。
func (it *RawIterator) Error() error {
	if it.err == io.EOF {
		return nil
	}
	return it.err
}

// clear sets all the outputs to nil.
// clear 将所有输出设置为 nil。
func (it *RawIterator) clear() {
	it.Header = nil
	it.Body = nil
	it.Receipts = nil
	it.TotalDifficulty = nil
}
