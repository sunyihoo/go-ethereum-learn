// Copyright 2019 The go-ethereum Authors
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
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

// 以太坊白皮书：白皮书中描述了状态树（State Trie）存储所有账户和存储槽的状态。快照系统通过分层设计（diskLayer 和 diffLayer）管理这些数据，而 binaryIterator 提供了一种可靠但较慢的方式来遍历这些数据，主要用于验证快速迭代器的正确性。
// 黄皮书：黄皮书中定义了状态树的结构和迭代规则。binaryIterator 的设计与状态树的键值对（账户哈希和存储哈希）遍历一致，通过比较哈希值来合并多层数据。
// EIP-2929（Gas Cost Increases for State Access Opcodes）：此 EIP 提高了状态访问的 Gas 成本，促使开发者优化状态查询。快照迭代器（如 binaryIterator）是优化的一部分，确保在验证过程中能够高效访问状态。

// binaryIterator is a simplistic iterator to step over the accounts or storage
// in a snapshot, which may or may not be composed of multiple layers. Performance
// wise this iterator is slow, it's meant for cross validating the fast one,
// binaryIterator 是一个简单的迭代器，用于逐步遍历快照中的账户或存储，快照可能由多层组成，也可能不是。从性能上看，这个迭代器较慢，它旨在交叉验证快速迭代器。
type binaryIterator struct {
	a               Iterator    // 第一个迭代器，通常指向当前层的迭代器
	b               Iterator    // 第二个迭代器，通常指向父层的迭代器
	aDone           bool        // 标记迭代器 a 是否已完成
	bDone           bool        // 标记迭代器 b 是否已完成
	accountIterator bool        // 标记是否为账户迭代器（true 表示账户，false 表示存储）
	k               common.Hash // 当前迭代的哈希键
	account         common.Hash // 当前存储迭代所属的账户哈希（仅用于存储迭代器）
	fail            error       // 迭代过程中发生的错误
}

// initBinaryAccountIterator creates a simplistic iterator to step over all the
// accounts in a slow, but easily verifiable way. Note this function is used for
// initialization, use `newBinaryAccountIterator` as the API.
// initBinaryAccountIterator 创建一个简单的迭代器，以缓慢但易于验证的方式逐步遍历所有账户。注意，此函数用于初始化，请使用 `newBinaryAccountIterator` 作为 API。
func (dl *diffLayer) initBinaryAccountIterator(seek common.Hash) Iterator {
	parent, ok := dl.parent.(*diffLayer) // 检查父层是否为 diffLayer 类型
	if !ok {
		l := &binaryIterator{
			a:               dl.AccountIterator(seek),          // 当前层的账户迭代器
			b:               dl.Parent().AccountIterator(seek), // 父层的账户迭代器
			accountIterator: true,                              // 标记为账户迭代器
		}
		l.aDone = !l.a.Next() // 检查迭代器 a 是否有下一个元素，若无则标记为完成
		l.bDone = !l.b.Next() // 检查迭代器 b 是否有下一个元素，若无则标记为完成
		return l              // 返回初始化好的迭代器
	}
	l := &binaryIterator{
		a:               dl.AccountIterator(seek),               // 当前层的账户迭代器
		b:               parent.initBinaryAccountIterator(seek), // 递归调用父层的初始化
		accountIterator: true,                                   // 标记为账户迭代器
	}
	l.aDone = !l.a.Next() // 检查迭代器 a 是否有下一个元素，若无则标记为完成
	l.bDone = !l.b.Next() // 检查迭代器 b 是否有下一个元素，若无则标记为完成
	return l              // 返回初始化好的迭代器
}

// initBinaryStorageIterator creates a simplistic iterator to step over all the
// storage slots in a slow, but easily verifiable way. Note this function is used
// for initialization, use `newBinaryStorageIterator` as the API.
// initBinaryStorageIterator 创建一个简单的迭代器，以缓慢但易于验证的方式逐步遍历所有存储槽。注意，此函数用于初始化，请使用 `newBinaryStorageIterator` 作为 API。
func (dl *diffLayer) initBinaryStorageIterator(account, seek common.Hash) Iterator {
	parent, ok := dl.parent.(*diffLayer) // 检查父层是否为 diffLayer 类型
	if !ok {
		l := &binaryIterator{
			a:       dl.StorageIterator(account, seek),          // 当前层的存储迭代器
			b:       dl.Parent().StorageIterator(account, seek), // 父层的存储迭代器
			account: account,                                    // 设置当前账户哈希
		}
		l.aDone = !l.a.Next() // 检查迭代器 a 是否有下一个元素，若无则标记为完成
		l.bDone = !l.b.Next() // 检查迭代器 b 是否有下一个元素，若无则标记为完成
		return l              // 返回初始化好的迭代器
	}
	l := &binaryIterator{
		a:       dl.StorageIterator(account, seek),               // 当前层的存储迭代器
		b:       parent.initBinaryStorageIterator(account, seek), // 递归调用父层的初始化
		account: account,                                         // 设置当前账户哈希
	}
	l.aDone = !l.a.Next() // 检查迭代器 a 是否有下一个元素，若无则标记为完成
	l.bDone = !l.b.Next() // 检查迭代器 b 是否有下一个元素，若无则标记为完成
	return l              // 返回初始化好的迭代器
}

// Next steps the iterator forward one element, returning false if exhausted,
// or an error if iteration failed for some reason (e.g. root being iterated
// becomes stale and garbage collected).
// Next 将迭代器向前移动一个元素，如果迭代器耗尽则返回 false，如果因某种原因（如迭代的根变得陈旧并被垃圾回收）失败则返回错误。
func (it *binaryIterator) Next() bool {
	for {
		if !it.next() { // 调用内部 next 方法推进迭代器
			return false // 如果无法推进，返回 false
		}
		if len(it.Account()) != 0 || len(it.Slot()) != 0 { // 检查当前元素是否有效（账户或存储数据不为空）
			return true // 如果有效，返回 true
		}
		// it.fail might be set if error occurs by calling
		// it.Account() or it.Slot(), stop iteration if so.
		// 如果调用 it.Account() 或 it.Slot() 时发生错误，it.fail 可能被设置，若如此则停止迭代。
		if it.fail != nil {
			return false // 如果有错误，返回 false
		}
	}
}

func (it *binaryIterator) next() bool {
	if it.aDone && it.bDone { // 如果两个迭代器都已完成
		return false // 返回 false
	}
	for {
		if it.aDone { // 如果迭代器 a 完成
			it.k = it.b.Hash()      // 使用迭代器 b 的哈希
			it.bDone = !it.b.Next() // 推进迭代器 b 并更新状态
			return true             // 返回 true
		}
		if it.bDone { // 如果迭代器 b 完成
			it.k = it.a.Hash()      // 使用迭代器 a 的哈希
			it.aDone = !it.a.Next() // 推进迭代器 a 并更新状态
			return true             // 返回 true
		}
		nextA, nextB := it.a.Hash(), it.b.Hash()                 // 获取两个迭代器的下一个哈希
		if diff := bytes.Compare(nextA[:], nextB[:]); diff < 0 { // 比较两个哈希
			it.aDone = !it.a.Next() // 如果 a 小于 b，推进 a
			it.k = nextA            // 设置当前哈希为 a 的值
			return true             // 返回 true
		} else if diff == 0 { // 如果相等
			// Now we need to advance one of them
			// 现在需要推进其中一个
			it.aDone = !it.a.Next() // 推进迭代器 a
			continue                // 继续循环以检查下一个元素
		}
		it.bDone = !it.b.Next() // 如果 b 小于 a，推进 b
		it.k = nextB            // 设置当前哈希为 b 的值
		return true             // 返回 true
	}
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 返回迭代过程中发生的任何失败，可能导致迭代提前退出（例如快照堆栈变得陈旧）。
func (it *binaryIterator) Error() error {
	return it.fail // 返回迭代器中的错误
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 返回迭代器当前所在的账户或存储槽的哈希。
func (it *binaryIterator) Hash() common.Hash {
	return it.k // 返回当前哈希
}

// Account returns the RLP encoded slim account the iterator is currently at, or
// nil if the iterated snapshot stack became stale (you can check Error after
// to see if it failed or not).
// Account 返回迭代器当前所在的 RLP 编码的瘦账户数据，如果迭代的快照堆栈变得陈旧则返回 nil（之后可以检查 Error 以查看是否失败）。
//
// Note the returned account is not a copy, please don't modify it.
// 注意，返回的账户不是副本，请勿修改。
func (it *binaryIterator) Account() []byte {
	if !it.accountIterator { // 如果不是账户迭代器
		return nil // 返回 nil
	}
	// The topmost iterator must be `diffAccountIterator`
	// 最顶层的迭代器必须是 `diffAccountIterator`
	blob, err := it.a.(*diffAccountIterator).layer.AccountRLP(it.k) // 从当前层获取账户 RLP 数据
	if err != nil {
		it.fail = err // 如果出错，记录错误
		return nil    // 返回 nil
	}
	return blob // 返回账户数据
}

// Slot returns the raw storage slot data the iterator is currently at, or
// nil if the iterated snapshot stack became stale (you can check Error after
// to see if it failed or not).
// Slot 返回迭代器当前所在的原始存储槽数据，如果迭代的快照堆栈变得陈旧则返回 nil（之后可以检查 Error 以查看是否失败）。
//
// Note the returned slot is not a copy, please don't modify it.
// 注意，返回的槽不是副本，请勿修改。
func (it *binaryIterator) Slot() []byte {
	if it.accountIterator { // 如果是账户迭代器
		return nil // 返回 nil
	}
	blob, err := it.a.(*diffStorageIterator).layer.Storage(it.account, it.k) // 从当前层获取存储槽数据
	if err != nil {
		it.fail = err // 如果出错，记录错误
		return nil    // 返回 nil
	}
	return blob // 返回存储槽数据
}

// Release recursively releases all the iterators in the stack.
// Release 递归释放堆栈中的所有迭代器。
func (it *binaryIterator) Release() {
	it.a.Release()   // 释放迭代器 a
	if it.b != nil { // 如果迭代器 b 不为空
		it.b.Release() // 释放迭代器 b
	}
}

// newBinaryAccountIterator creates a simplistic account iterator to step over
// all the accounts in a slow, but easily verifiable way.
// newBinaryAccountIterator 创建一个简单的账户迭代器，以缓慢但易于验证的方式逐步遍历所有账户。
func (dl *diffLayer) newBinaryAccountIterator(seek common.Hash) AccountIterator {
	iter := dl.initBinaryAccountIterator(seek) // 调用初始化函数创建迭代器
	return iter.(AccountIterator)              // 转换为 AccountIterator 类型并返回
}

// newBinaryStorageIterator creates a simplistic account iterator to step over
// all the storage slots in a slow, but easily verifiable way.
// newBinaryStorageIterator 创建一个简单的存储迭代器，以缓慢但易于验证的方式逐步遍历所有存储槽。
func (dl *diffLayer) newBinaryStorageIterator(account, seek common.Hash) StorageIterator {
	iter := dl.initBinaryStorageIterator(account, seek) // 调用初始化函数创建迭代器
	return iter.(StorageIterator)                       // 转换为 StorageIterator 类型并返回
}
