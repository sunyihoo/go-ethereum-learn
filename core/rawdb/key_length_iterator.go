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

package rawdb

import "github.com/ethereum/go-ethereum/ethdb"

// KeyLengthIterator is a wrapper for a database iterator that ensures only key-value pairs
// with a specific key length will be returned.
// KeyLengthIterator 是一个数据库迭代器的包装器，用于确保只返回具有特定键长度的键值对。
type KeyLengthIterator struct {
	requiredKeyLength int // 所需键的长度。
	ethdb.Iterator        // 底层迭代器。
}

// NewKeyLengthIterator returns a wrapped version of the iterator that will only return key-value
// pairs where keys with a specific key length will be returned.
// NewKeyLengthIterator 返回一个包装后的迭代器，该迭代器仅返回键长度符合指定长度的键值对。
func NewKeyLengthIterator(it ethdb.Iterator, keyLen int) ethdb.Iterator {
	return &KeyLengthIterator{
		Iterator:          it,     // 被包装的底层迭代器。
		requiredKeyLength: keyLen, // 指定的键长度。
	}
}

// Next 方法通过底层迭代器的 Next() 方法逐步检查每一个键的长度。
func (it *KeyLengthIterator) Next() bool {
	// Return true as soon as a key with the required key length is discovered
	// 一旦发现符合所需键长度的键，就返回 true。
	for it.Iterator.Next() {
		if len(it.Iterator.Key()) == it.requiredKeyLength {
			return true
		}
	}

	// Return false when we exhaust the keys in the underlying iterator.
	// 如果在底层迭代器中耗尽了键，则返回 false。
	return false
}
