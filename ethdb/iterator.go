// Copyright 2018 The go-ethereum Authors
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

package ethdb

// Iterator iterates over a database's key/value pairs in ascending key order.
//
// When it encounters an error any seek will return false and will yield no key/
// value pairs. The error can be queried by calling the Error method. Calling
// Release is still necessary.
//
// An iterator must be released after use, but it is not necessary to read an
// iterator until exhaustion. An iterator is not safe for concurrent use, but it
// is safe to use multiple iterators concurrently.
//
// Iterator 以升序键顺序迭代数据库的键/值对。
//
// 当遇到错误时，任何 seek 操作将返回 false，并且不会产生键/值对。可以通过调用 Error 方法查询错误。
// 仍然需要调用 Release 方法。
//
// 迭代器使用后必须释放，但不一定需要读取迭代器直到耗尽。迭代器对并发使用不安全，但可以安全地并发使用多个迭代器。
//
//	它是数据库操作中常见的抽象，适用于如 LevelDB、RocksDB 或以太坊的存储层。
//	Iterator 常用于底层存储（如 LevelDB），遍历状态树、交易或日志数据。
//	以太坊的状态数据库（如 MPT）以键/值对形式存储数据，Iterator 提供按键顺序访问的能力。
type Iterator interface {
	// Next moves the iterator to the next key/value pair. It returns whether the
	// iterator is exhausted.
	// Next 将迭代器移动到下一个键/值对。它返回迭代器是否已耗尽。
	Next() bool

	// Error returns any accumulated error. Exhausting all the key/value pairs
	// is not considered to be an error.
	// Error 返回任何累积的错误。耗尽所有键/值对不视为错误。
	Error() error

	// Key returns the key of the current key/value pair, or nil if done. The caller
	// should not modify the contents of the returned slice, and its contents may
	// change on the next call to Next.
	// Key 返回当前键/值对的键，如果完成则返回 nil。调用者不应修改返回切片的内容，
	// 其内容在下一次调用 Next 时可能会改变。
	Key() []byte

	// Value returns the value of the current key/value pair, or nil if done. The
	// caller should not modify the contents of the returned slice, and its contents
	// may change on the next call to Next.
	// Value 返回当前键/值对的值，如果完成则返回 nil。调用者不应修改返回切片的内容，
	// 其内容在下一次调用 Next 时可能会改变。
	Value() []byte

	// Release releases associated resources. Release should always succeed and can
	// be called multiple times without causing error.
	// Release 释放关联的资源。Release 应始终成功，并且可以多次调用而不引发错误。
	Release()
}

// Iteratee wraps the NewIterator methods of a backing data store.
// Iteratee 封装了后端数据存储的 NewIterator 方法。
//
// 前缀（prefix）通常用于隔离不同类型的数据（如账户状态、交易）。
type Iteratee interface {
	// NewIterator creates a binary-alphabetical iterator over a subset
	// of database content with a particular key prefix, starting at a particular
	// initial key (or after, if it does not exist).
	//
	// Note: This method assumes that the prefix is NOT part of the start, so there's
	// no need for the caller to prepend the prefix to the start
	//
	// NewIterator 创建一个二进制字母顺序的迭代器，遍历数据库内容的一个子集，该子集具有特定的键前缀，
	// 从特定的初始键开始（如果该键不存在，则从其后开始）。
	//
	// 注意：此方法假设前缀不是 start 的一部分，因此调用者无需将前缀添加到 start 前。
	NewIterator(prefix []byte, start []byte) Iterator
}
