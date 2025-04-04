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
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

// 态层 (State Layers): go-ethereum 使用分层结构来管理以太坊的状态，包括磁盘层 (diskLayer) 和内存中的差异层 (diffLayer)。
// 这些“binary”迭代器能够将来自不同层的数据进行合并遍历。
// 账户和存储: 这些迭代器分别用于遍历以太坊的账户和每个账户的存储槽，这是以太坊状态管理的基本操作。
// 迭代器模式: 代码中使用了迭代器设计模式，提供了一种统一的方式来遍历不同数据源中的元素。

// binaryIterator is a simplistic iterator to step over the accounts or storage
// in a snapshot, which may or may not be composed of multiple layers. Performance
// wise this iterator is slow, it's meant for cross validating the fast one.
//
// This iterator cannot be used on its own; it should be wrapped with an outer
// iterator, such as accountBinaryIterator or storageBinaryIterator.
//
// This iterator can only traverse the keys of the entries stored in the layers,
// but cannot obtain the corresponding values. Besides, the deleted entry will
// also be traversed, the outer iterator must check the emptiness before returning.
//
// binaryIterator 是一个简单的迭代器，用于遍历快照中的账户或存储，该快照可能由多个层组成。从性能上看，这个迭代器很慢，它用于交叉验证快速迭代器。
// 这个迭代器不能单独使用；它应该被包装在一个外部迭代器中，例如 accountBinaryIterator 或 storageBinaryIterator。
// 这个迭代器只能遍历存储在层中的条目的键，但无法获取相应的值。此外，已删除的条目也会被遍历，外部迭代器必须在返回之前检查是否为空。
type binaryIterator struct {
	a     Iterator    // 要合并的第一个迭代器。
	b     Iterator    // 要合并的第二个迭代器。
	aDone bool        // 标志，指示第一个迭代器是否已耗尽。
	bDone bool        // 标志，指示第二个迭代器是否已耗尽。
	k     common.Hash // 迭代器当前指向的键（哈希）。
	fail  error       // 迭代过程中遇到的任何错误。
}

// initBinaryAccountIterator creates a simplistic iterator to step over all the
// accounts in a slow, but easily verifiable way. Note this function is used
// for initialization, use `newBinaryAccountIterator` as the API.
//
// initBinaryAccountIterator 创建一个简单的迭代器，以缓慢但易于验证的方式遍历所有账户。
// 注意：此函数用于初始化，请使用 `newBinaryAccountIterator` 作为 API。
func (dl *diskLayer) initBinaryAccountIterator(seek common.Hash) *binaryIterator {
	// Create two iterators for state buffer and the persistent state in disk
	// respectively and combine them as a binary iterator.
	//
	// 分别为状态缓冲区和磁盘上的持久状态创建两个迭代器，并将它们组合成一个 binaryIterator。
	l := &binaryIterator{
		// The account loader function is unnecessary; the account key list
		// produced by the supplied buffer alone is sufficient for iteration.
		//
		// The account key list for iteration is deterministic once the iterator
		// is constructed, no matter the referenced disk layer is stale or not
		// later.
		//
		// 账户加载函数是不必要的；仅由提供的缓冲区生成的账户键列表就足以进行迭代。
		//
		// 一旦构造了迭代器，账户键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
		a: newDiffAccountIterator(seek, dl.buffer.states, nil),
		b: newDiskAccountIterator(dl.db.diskdb, seek),
	}
	l.aDone = !l.a.Next()
	l.bDone = !l.b.Next()
	return l
}

// initBinaryAccountIterator creates a simplistic iterator to step over all the
// accounts in a slow, but easily verifiable way. Note this function is used
// for initialization, use `newBinaryAccountIterator` as the API.
//
// initBinaryAccountIterator 创建一个简单的迭代器，以缓慢但易于验证的方式遍历所有账户。
// 注意：此函数用于初始化，请使用 `newBinaryAccountIterator` 作为 API。
func (dl *diffLayer) initBinaryAccountIterator(seek common.Hash) *binaryIterator {
	parent, ok := dl.parent.(*diffLayer)
	if !ok {
		l := &binaryIterator{
			// The account loader function is unnecessary; the account key list
			// produced by the supplied state set alone is sufficient for iteration.
			//
			// The account key list for iteration is deterministic once the iterator
			// is constructed, no matter the referenced disk layer is stale or not
			// later.
			//
			// 账户加载函数是不必要的；仅由提供的状态集生成的账户键列表就足以进行迭代。
			//
			// 一旦构造了迭代器，账户键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
			a: newDiffAccountIterator(seek, dl.states.stateSet, nil),
			b: dl.parent.(*diskLayer).initBinaryAccountIterator(seek),
		}
		l.aDone = !l.a.Next()
		l.bDone = !l.b.Next()
		return l
	}
	l := &binaryIterator{
		// The account loader function is unnecessary; the account key list
		// produced by the supplied state set alone is sufficient for iteration.
		//
		// The account key list for iteration is deterministic once the iterator
		// is constructed, no matter the referenced disk layer is stale or not
		// later.
		//
		// 账户加载函数是不必要的；仅由提供的状态集生成的账户键列表就足以进行迭代。
		//
		// 一旦构造了迭代器，账户键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
		a: newDiffAccountIterator(seek, dl.states.stateSet, nil),
		b: parent.initBinaryAccountIterator(seek),
	}
	l.aDone = !l.a.Next()
	l.bDone = !l.b.Next()
	return l
}

// initBinaryStorageIterator creates a simplistic iterator to step over all the
// storage slots in a slow, but easily verifiable way. Note this function is used
// for initialization, use `newBinaryStorageIterator` as the API.
//
// initBinaryStorageIterator 创建一个简单的迭代器，以缓慢但易于验证的方式遍历所有存储槽。注意：此函数用于初始化，请使用 `newBinaryStorageIterator` 作为 API。
func (dl *diskLayer) initBinaryStorageIterator(account common.Hash, seek common.Hash) *binaryIterator {
	// Create two iterators for state buffer and the persistent state in disk
	// respectively and combine them as a binary iterator.
	// 分别为状态缓冲区和磁盘上的持久状态创建两个迭代器，并将它们组合成一个 binaryIterator。
	l := &binaryIterator{
		// The storage loader function is unnecessary; the storage key list
		// produced by the supplied buffer alone is sufficient for iteration.
		//
		// The storage key list for iteration is deterministic once the iterator
		// is constructed, no matter the referenced disk layer is stale or not
		// later.
		//
		// 存储加载函数是不必要的；仅由提供的缓冲区生成的存储键列表就足以进行迭代。
		//
		// 一旦构造了迭代器，存储键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
		a: newDiffStorageIterator(account, seek, dl.buffer.states, nil),
		b: newDiskStorageIterator(dl.db.diskdb, account, seek),
	}
	l.aDone = !l.a.Next()
	l.bDone = !l.b.Next()
	return l
}

// initBinaryStorageIterator creates a simplistic iterator to step over all the
// storage slots in a slow, but easily verifiable way. Note this function is used
// for initialization, use `newBinaryStorageIterator` as the API.
//
// initBinaryStorageIterator 创建一个简单的迭代器，以缓慢但易于验证的方式遍历所有存储槽。注意：此函数用于初始化，请使用 `newBinaryStorageIterator` 作为 API。
func (dl *diffLayer) initBinaryStorageIterator(account common.Hash, seek common.Hash) *binaryIterator {
	parent, ok := dl.parent.(*diffLayer)
	if !ok {
		l := &binaryIterator{
			// The storage loader function is unnecessary; the storage key list
			// produced by the supplied state set alone is sufficient for iteration.
			//
			// The storage key list for iteration is deterministic once the iterator
			// is constructed, no matter the referenced disk layer is stale or not
			// later.
			//
			// 存储加载函数是不必要的；仅由提供的状态集生成的存储键列表就足以进行迭代。
			//
			// 一旦构造了迭代器，存储键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
			a: newDiffStorageIterator(account, seek, dl.states.stateSet, nil),
			b: dl.parent.(*diskLayer).initBinaryStorageIterator(account, seek),
		}
		l.aDone = !l.a.Next()
		l.bDone = !l.b.Next()
		return l
	}
	l := &binaryIterator{
		// The storage loader function is unnecessary; the storage key list
		// produced by the supplied state set alone is sufficient for iteration.
		//
		// The storage key list for iteration is deterministic once the iterator
		// is constructed, no matter the referenced disk layer is stale or not
		// later.
		//
		// 存储加载函数是不必要的；仅由提供的状态集生成的存储键列表就足以进行迭代。
		//
		// 一旦构造了迭代器，存储键列表的迭代顺序就是确定的，无论之后引用的磁盘层是否过期。
		a: newDiffStorageIterator(account, seek, dl.states.stateSet, nil),
		b: parent.initBinaryStorageIterator(account, seek),
	}
	l.aDone = !l.a.Next()
	l.bDone = !l.b.Next()
	return l
}

// Next advances the iterator by one element, returning false if both iterators
// are exhausted. Note that the entry pointed to by the iterator may be null
// (e.g., when an account is deleted but still accessible for iteration).
// The outer iterator must verify emptiness before terminating the iteration.
//
// There’s no need to check for errors in the two iterators, as we only iterate
// through the entries without retrieving their values.
//
// Next 将迭代器向前移动一个元素，如果两个迭代器都已耗尽，则返回 false。请注意，迭代器指向的条目可能为空（例如，当账户被删除但仍然可以用于迭代时）。外部迭代器必须在终止迭代之前验证是否为空。
//
// 无需检查两个迭代器中的错误，因为我们只遍历条目而不检索它们的值。
func (it *binaryIterator) Next() bool {
	// 如果两个迭代器都已耗尽，则返回 false。
	if it.aDone && it.bDone {
		return false
	}
	// 无限循环，直到找到下一个键或两个迭代器都耗尽。
	for {
		// 如果第一个迭代器已耗尽，则返回第二个迭代器的当前哈希，并移动第二个迭代器到下一个位置。
		if it.aDone {
			it.k = it.b.Hash()
			it.bDone = !it.b.Next()
			return true
		}
		// 如果第二个迭代器已耗尽，则返回第一个迭代器的当前哈希，并移动第一个迭代器到下一个位置。
		if it.bDone {
			it.k = it.a.Hash()
			it.aDone = !it.a.Next()
			return true
		}
		// 获取两个迭代器当前的哈希。
		nextA, nextB := it.a.Hash(), it.b.Hash()
		// 比较两个哈希。
		if diff := bytes.Compare(nextA[:], nextB[:]); diff < 0 {
			// 如果第一个迭代器的哈希较小，则返回第一个迭代器的哈希，并移动第一个迭代器到下一个位置。
			it.aDone = !it.a.Next()
			it.k = nextA
			return true
		} else if diff == 0 {
			// Now we need to advance one of them
			// 如果两个哈希相等，则移动第一个迭代器到下一个位置，并继续循环（因为我们只需要唯一的键）。
			it.aDone = !it.a.Next()
			continue
		}
		// 如果第二个迭代器的哈希较小，则返回第二个迭代器的哈希，并移动第二个迭代器到下一个位置。
		it.bDone = !it.b.Next()
		it.k = nextB
		return true
	}
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
func (it *binaryIterator) Error() error {
	return it.fail
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 返回迭代器当前指向的账户的哈希。
func (it *binaryIterator) Hash() common.Hash {
	return it.k
}

// Release recursively releases all the iterators in the stack.
// Release 递归地释放堆栈中的所有迭代器。
func (it *binaryIterator) Release() {
	it.a.Release()
	it.b.Release()
}

// accountBinaryIterator is a wrapper around a binary iterator that adds functionality
// to retrieve account data from the associated layer at the current position.
// accountBinaryIterator 是 binaryIterator 的包装器，它添加了从当前位置的关联层检索账户数据的功能。
type accountBinaryIterator struct {
	*binaryIterator       // 嵌入 binaryIterator。
	layer           layer //  与此迭代器关联的层。
}

// newBinaryAccountIterator creates a simplistic account iterator to step over
// all the accounts in a slow, but easily verifiable way.
//
// newBinaryAccountIterator 创建一个简单的账户迭代器，以缓慢但易于验证的方式遍历所有账户。
//
// nolint:all
func (dl *diskLayer) newBinaryAccountIterator(seek common.Hash) AccountIterator {
	return &accountBinaryIterator{
		binaryIterator: dl.initBinaryAccountIterator(seek),
		layer:          dl,
	}
}

// newBinaryAccountIterator creates a simplistic account iterator to step over
// all the accounts in a slow, but easily verifiable way.
//
// newBinaryAccountIterator 创建一个简单的账户迭代器，以缓慢但易于验证的方式遍历所有账户。
func (dl *diffLayer) newBinaryAccountIterator(seek common.Hash) AccountIterator {
	return &accountBinaryIterator{
		binaryIterator: dl.initBinaryAccountIterator(seek),
		layer:          dl,
	}
}

// Next steps the iterator forward one element, returning false if exhausted,
// or an error if iteration failed for some reason (e.g. the linked layer is
// stale during the iteration).
//
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false，如果由于某种原因（例如，链接的层在迭代期间变得陈旧）迭代失败则返回错误。
func (it *accountBinaryIterator) Next() bool {
	for {
		// 调用底层的 binaryIterator 的 Next 方法来获取下一个键（哈希）。
		if !it.binaryIterator.Next() {
			return false
		}
		// Retrieve the account data referenced by the current iterator, the
		// associated layers might be outdated due to chain progressing,
		// the relative error will be set to it.fail just in case.
		//
		// Skip the null account which was deleted before and move to the
		// next account.
		//
		// 检索当前迭代器引用的账户数据，由于链的进展，关联的层可能已过时，
		// 万一发生这种情况，相关的错误将设置到 it.fail 中。
		//
		// 跳过之前已删除的空账户，并移动到下一个账户。
		if len(it.Account()) != 0 {
			return true
		}
		// it.fail might be set if error occurs by calling it.Account().
		// Stop iteration if so.
		// 如果调用 it.Account() 发生错误，则可能会设置 it.fail。
		// 如果是这样，则停止迭代。
		if it.fail != nil {
			return false
		}
	}
}

// Account returns the RLP encoded slim account the iterator is currently at, or
// nil if the iterated snapshot stack became stale (you can check Error after
// to see if it failed or not).
//
// Note the returned account is not a copy, please don't modify it.
//
// Account 返回迭代器当前指向的 RLP 编码的精简账户，如果迭代的快照堆栈变得陈旧则返回 nil（之后可以检查 Error 以查看是否失败）。
//
// 注意：返回的账户不是副本，请不要修改它。
func (it *accountBinaryIterator) Account() []byte {
	// 从关联的层获取指定哈希的账户数据。
	blob, err := it.layer.account(it.k, 0)
	if err != nil {
		it.fail = err
		return nil
	}
	return blob
}

// storageBinaryIterator is a wrapper around a binary iterator that adds functionality
// to retrieve storage slot data from the associated layer at the current position.
//
// storageBinaryIterator 是 binaryIterator 的包装器，它添加了从当前位置的关联层检索存储槽数据的功能。
type storageBinaryIterator struct {
	*binaryIterator             // 嵌入 binaryIterator。
	account         common.Hash // 正在迭代其存储的账户。
	layer           layer       // 与此迭代器关联的层。
}

// newBinaryStorageIterator creates a simplistic account iterator to step over
// all the storage slots in a slow, but easily verifiable way.
//
// newBinaryStorageIterator 创建一个简单的账户迭代器，以缓慢但易于验证的方式遍历所有存储槽。
//
// nolint:all
func (dl *diskLayer) newBinaryStorageIterator(account common.Hash, seek common.Hash) StorageIterator {
	return &storageBinaryIterator{
		binaryIterator: dl.initBinaryStorageIterator(account, seek),
		account:        account,
		layer:          dl,
	}
}

// newBinaryStorageIterator creates a simplistic account iterator to step over
// all the storage slots in a slow, but easily verifiable way.
//
// newBinaryStorageIterator 创建一个简单的账户迭代器，以缓慢但易于验证的方式遍历所有存储槽。
func (dl *diffLayer) newBinaryStorageIterator(account common.Hash, seek common.Hash) StorageIterator {
	return &storageBinaryIterator{
		binaryIterator: dl.initBinaryStorageIterator(account, seek),
		account:        account,
		layer:          dl,
	}
}

// Next steps the iterator forward one element, returning false if exhausted,
// or an error if iteration failed for some reason (e.g. the linked layer is
// stale during the iteration).
//
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false，如果由于某种原因（例如，链接的层在迭代期间变得陈旧）迭代失败则返回错误。
func (it *storageBinaryIterator) Next() bool {
	for {
		// 调用底层的 binaryIterator 的 Next 方法来获取下一个键（哈希）。
		if !it.binaryIterator.Next() {
			return false
		}
		// Retrieve the storage data referenced by the current iterator, the
		// associated layers might be outdated due to chain progressing,
		// the relative error will be set to it.fail just in case.
		//
		// Skip the null storage which was deleted before and move to the
		// next account.
		// 检索当前迭代器引用的存储数据，由于链的进展，关联的层可能已过时，
		// 万一发生这种情况，相关的错误将设置到 it.fail 中。
		//
		// 跳过之前已删除的空存储，并移动到下一个账户。
		if len(it.Slot()) != 0 {
			return true
		}
		// it.fail might be set if error occurs by calling it.Slot().
		// Stop iteration if so.
		// 如果调用 it.Slot() 发生错误，则可能会设置 it.fail。
		// 如果是这样，则停止迭代。
		if it.fail != nil {
			return false
		}
	}
}

// Slot returns the raw storage slot data the iterator is currently at, or
// nil if the iterated snapshot stack became stale (you can check Error after
// to see if it failed or not).
//
// Note the returned slot is not a copy, please don't modify it.
//
// Slot 返回迭代器当前指向的原始存储槽数据，如果迭代的快照堆栈变得陈旧则返回 nil（之后可以检查 Error 以查看是否失败）。
//
// 注意：返回的槽不是副本，请不要修改它。
func (it *storageBinaryIterator) Slot() []byte {
	blob, err := it.layer.storage(it.account, it.k, 0)
	if err != nil {
		it.fail = err
		return nil
	}
	return blob
}
