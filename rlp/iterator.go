// Copyright 2020 The go-ethereum Authors
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

// 提供了一种高效的方式来遍历 RLP 编码的列表，而无需一次性解码整个列表。这对于处理大型列表非常有用，可以节省内存和提高性能。
type listIterator struct {
	data []byte // 存储剩余的尚未被迭代器处理的 RLP 编码数据。
	next []byte // 存储当前迭代到的元素的 RLP 编码数据。
	err  error  // 存储在迭代过程中遇到的任何错误。
}

// NewListIterator creates an iterator for the (list) represented by data
// NewListIterator 为由 data 表示的（列表）创建一个迭代器
func NewListIterator(data RawValue) (*listIterator, error) {
	k, t, c, err := readKind(data)
	if err != nil {
		return nil, err
	}
	if k != List { // 如果解析出错或者解析得到的类型 k 不是 List，
		return nil, ErrExpectedList
	}
	// 如果 data 是一个 RLP 列表，则创建一个新的 listIterator 实例。
	// it.data 被设置为列表的内容部分，即去除列表头部的 data[t : t+c]。
	it := &listIterator{
		data: data[t : t+c],
	}
	return it, nil
}

// Next forwards the iterator one step, returns true if it was not at end yet
// Next 将迭代器向前移动一步，如果尚未到达末尾则返回 true
func (it *listIterator) Next() bool {
	if len(it.data) == 0 { // 检查是否到达末尾：如果 it.data 的长度为 0，表示已经遍历完所有元素，返回 false。
		return false
	}
	_, t, c, err := readKind(it.data) // 解析 it.data 中下一个元素的 RLP 类型、标签长度和内容长度。
	it.next = it.data[:t+c]           // 将当前元素的 RLP 编码数据 it.data[:t+c] 存储到 it.next。
	it.data = it.data[t+c:]           //  将 it.data 更新为指向剩余的尚未处理的数据 it.data[t+c:]。
	it.err = err                      //  将 readKind 返回的错误存储到 it.err。
	return true
}

// Value returns the current value
// Value 返回当前值
func (it *listIterator) Value() []byte {
	return it.next //  当前迭代到的元素的 RLP 编码数据。
}

func (it *listIterator) Err() error {
	return it.err
}
