// Copyright 2022 The go-ethereum Authors
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

package snapshot

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// holdableIterator is a wrapper of underlying database iterator. It extends
// the basic iterator interface by adding Hold which can hold the element
// locally where the iterator is currently located and serve it up next time.
// holdableIterator 是底层数据库迭代器的包装器。它通过添加 Hold 方法扩展了基本的迭代器接口，
// Hold 方法可以在迭代器当前所在的位置本地持有元素，并在下次迭代时提供该元素。
type holdableIterator struct {
	it ethdb.Iterator // Underlying database iterator.
	// it 是底层的数据库迭代器。
	key []byte // Locally held key.
	// key 是本地持有的键。
	val []byte // Locally held value.
	// val 是本地持有的值。
	atHeld bool // Flag indicating whether the iterator is currently serving the held element.
	// atHeld 标志表示迭代器当前是否正在提供持有的元素。
}

// newHoldableIterator initializes the holdableIterator with the given iterator.
// newHoldableIterator 使用给定的迭代器初始化 holdableIterator。
func newHoldableIterator(it ethdb.Iterator) *holdableIterator {
	return &holdableIterator{it: it}
}

// Hold holds the element locally where the iterator is currently located which
// can be served up next time.
// Hold 方法在迭代器当前所在的位置本地持有元素，该元素可以在下次迭代时被提供。
func (it *holdableIterator) Hold() {
	if it.it.Key() == nil {
		return // nothing to hold
		// 如果底层迭代器没有当前的键，则没有可持有的元素，直接返回。
	}
	it.key = common.CopyBytes(it.it.Key())   // 复制当前迭代器的键并保存到本地。
	it.val = common.CopyBytes(it.it.Value()) // 复制当前迭代器的值并保存到本地。
	it.atHeld = false                        // 设置标志，表示下次 Next() 调用将返回持有的元素。
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
// Next 方法将迭代器移动到下一个键值对。它返回迭代器是否已耗尽。
func (it *holdableIterator) Next() bool {
	if !it.atHeld && it.key != nil {
		// 如果当前没有提供持有的元素，并且本地持有了一个元素，
		it.atHeld = true // 则设置标志，表示下次调用 Key() 和 Value() 将返回持有的元素。
	} else if it.atHeld {
		// 如果上次 Next() 调用提供了持有的元素，
		it.atHeld = false // 则重置标志。
		it.key = nil      // 清空本地持有的键。
		it.val = nil      // 清空本地持有的值。
	}
	if it.key != nil {
		return true // shifted to locally held value
		// 如果本地持有一个键，则表示下次调用将返回该持有的元素，返回 true。
	}
	return it.it.Next() // 如果没有本地持有的元素，则调用底层迭代器的 Next() 方法。
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
// Error 方法返回任何累积的错误。遍历完所有键值对不被认为是错误。
func (it *holdableIterator) Error() error { return it.it.Error() }

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
// Release 方法释放相关的资源。Release 应该总是成功，并且可以多次调用而不会导致错误。
func (it *holdableIterator) Release() {
	it.atHeld = false // 重置持有标志。
	it.key = nil      // 清空本地持有的键。
	it.val = nil      // 清空本地持有的值。
	it.it.Release()   // 调用底层迭代器的 Release() 方法释放资源。
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
// Key 方法返回当前键值对的键，如果迭代完成则返回 nil。调用者不应修改返回的切片的内容，并且其内容可能会在下次调用 Next() 时更改。
func (it *holdableIterator) Key() []byte {
	if it.key != nil {
		return it.key // 如果本地持有了一个键，则返回该键。
	}
	return it.it.Key() // 否则返回底层迭代器的键。
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
// Value 方法返回当前键值对的值，如果迭代完成则返回 nil。调用者不应修改返回的切片的内容，并且其内容可能会在下次调用 Next() 时更改。
func (it *holdableIterator) Value() []byte {
	if it.val != nil {
		return it.val // 如果本地持有一个值，则返回该值。
	}
	return it.it.Value() // 否则返回底层迭代器的值。
}
