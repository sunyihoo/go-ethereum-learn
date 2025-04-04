// Copyright 2024 The go-ethereum Authors
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

package pathdb

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// holdableIterator is a wrapper of underlying database iterator. It extends
// the basic iterator interface by adding Hold which can hold the element
// locally where the iterator is currently located and serve it up next time.
// holdableIterator 是底层数据库迭代器的包装器。它通过添加 Hold 方法扩展了基本的迭代器接口，
// 该方法可以将迭代器当前位置的元素本地保存起来，并在下次 Next 调用时返回。
type holdableIterator struct {
	it     ethdb.Iterator // 底层数据库迭代器。
	key    []byte         // 本地保存的键。
	val    []byte         //  本地保存的值。
	atHeld bool           // 标志，指示迭代器当前是否正在返回保存的值。
}

// newHoldableIterator initializes the holdableIterator with the given iterator.
// newHoldableIterator 使用给定的迭代器初始化 holdableIterator。
func newHoldableIterator(it ethdb.Iterator) *holdableIterator {
	return &holdableIterator{it: it}
}

// Hold holds the element locally where the iterator is currently located which
// can be served up next time.
// Hold 方法将迭代器当前位置的元素本地保存起来，以便下次 Next 调用时返回。
func (it *holdableIterator) Hold() {
	// 如果迭代器已经到达末尾，则不执行任何操作。
	if it.it.Key() == nil {
		return // nothing to hold
	}
	// 复制当前的键和值并保存到本地。
	it.key = common.CopyBytes(it.it.Key())
	it.val = common.CopyBytes(it.it.Value())
	// 设置标志，表示下次 Next 调用应该返回保存的值。
	it.atHeld = false
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
// Next 方法将迭代器移动到下一个键/值对。它返回迭代器是否已耗尽。
func (it *holdableIterator) Next() bool {
	// 如果当前没有返回保存的值，并且本地保存了键，则准备返回保存的值。
	if !it.atHeld && it.key != nil {
		it.atHeld = true
	} else if it.atHeld {
		// 如果上次 Next 调用返回的是保存的值，则清空保存的值，并实际移动底层迭代器。
		it.atHeld = false
		it.key = nil
		it.val = nil
	}
	// 如果本地保存了键，则表示下次应该返回保存的值，因此返回 true。
	if it.key != nil {
		return true // shifted to locally held value
	}
	// 如果没有保存的值，则调用底层迭代器的 Next 方法。
	return it.it.Next()
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
// Error 方法返回任何累积的错误。耗尽所有键/值对不被视为错误。
func (it *holdableIterator) Error() error { return it.it.Error() }

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
// Release 方法释放相关的资源。Release 应该总是成功，并且可以多次调用而不会导致错误。
func (it *holdableIterator) Release() {
	// 重置标志和本地保存的值。
	it.atHeld = false
	it.key = nil
	it.val = nil
	// 释放底层迭代器的资源。
	it.it.Release()
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
//
// Key 方法返回当前键/值对的键，如果迭代器已耗尽则返回 nil。调用者不应修改返回的切片的内容，并且其内容可能会在下次调用 Next 时更改。
func (it *holdableIterator) Key() []byte {
	// 如果本地保存了键，则返回保存的键。
	if it.key != nil {
		return it.key
	}
	// 否则，返回底层迭代器的键。
	return it.it.Key()
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
//
// Value 方法返回当前键/值对的值，如果迭代器已耗尽则返回 nil。调用者不应修改返回的切片的内容，并且其内容可能会在下次调用 Next 时更改。
func (it *holdableIterator) Value() []byte {
	if it.val != nil {
		return it.val
	}
	return it.it.Value()
}
