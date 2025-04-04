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
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// Iterator is an iterator to step over all the accounts or the specific
// storage in a snapshot which may or may not be composed of multiple layers.
// Iterator 是一个迭代器，用于遍历快照中的所有账户或特定的存储，该快照可能由多个层组成。
type Iterator interface {
	// Next steps the iterator forward one element, returning false if exhausted,
	// or an error if iteration failed for some reason (e.g. root being iterated
	// becomes stale and garbage collected).
	// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false，或者如果由于某种原因（例如，正在迭代的根变得陈旧并被垃圾回收）迭代失败则返回错误。
	Next() bool

	// Error returns any failure that occurred during iteration, which might have
	// caused a premature iteration exit (e.g. layer stack becoming stale).
	// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，层堆栈变得陈旧）。
	Error() error

	// Hash returns the hash of the account or storage slot the iterator is
	// currently at.
	// Hash 返回迭代器当前指向的账户或存储槽的哈希。
	Hash() common.Hash

	// Release releases associated resources. Release should always succeed and
	// can be called multiple times without causing error.
	// Release 释放相关的资源。Release 应该总是成功，并且可以多次调用而不会导致错误。
	Release()
}

// AccountIterator is an iterator to step over all the accounts in a snapshot,
// which may or may not be composed of multiple layers.
// AccountIterator 是一个迭代器，用于遍历快照中的所有账户，该快照可能由多个层组成。
type AccountIterator interface {
	Iterator

	// Account returns the RLP encoded slim account the iterator is currently at.
	// An error will be returned if the iterator becomes invalid
	// Account 返回迭代器当前指向的 RLP 编码的精简账户。如果迭代器变得无效，将返回错误。
	Account() []byte
}

// StorageIterator is an iterator to step over the specific storage in a snapshot,
// which may or may not be composed of multiple layers.
// StorageIterator 是一个迭代器，用于遍历快照中的特定存储，该快照可能由多个层组成。
type StorageIterator interface {
	Iterator

	// Slot returns the storage slot the iterator is currently at. An error will
	// be returned if the iterator becomes invalid
	// Slot 返回迭代器当前指向的存储槽。如果迭代器变得无效，将返回错误。
	Slot() []byte
}

type (
	// loadAccount is the function to retrieve the account from the associated
	// layer. An error will be returned if the associated layer is stale.
	// loadAccount 是一个函数类型，用于从关联的层检索账户。如果关联的层变得陈旧，将返回错误。
	loadAccount func(hash common.Hash) ([]byte, error)

	// loadStorage is the function to retrieve the storage slot from the associated
	// layer. An error will be returned if the associated layer is stale.
	// loadStorage 是一个函数类型，用于从关联的层检索存储槽。如果关联的层变得陈旧，将返回错误。
	loadStorage func(addrHash common.Hash, slotHash common.Hash) ([]byte, error)
)

// diffAccountIterator is an account iterator that steps over the accounts (both
// live and deleted) contained within a state set. Higher order iterators will
// use the deleted accounts to skip deeper iterators.
// diffAccountIterator 是一个账户迭代器，用于遍历状态集中包含的账户（包括活动的和已删除的）。更高阶的迭代器将使用已删除的账户来跳过更深层的迭代器。
//
// This iterator could be created from the diff layer or the disk layer (the
// aggregated state buffer).
// 此迭代器可以从差异层或磁盘层（聚合状态缓冲区）创建。
type diffAccountIterator struct {
	curHash common.Hash // The current hash the iterator is positioned on
	// 迭代器当前指向的哈希。
	keys []common.Hash // Keys left in the layer to iterate
	// 层中剩余要迭代的键列表。
	fail error // Any failures encountered (stale)
	// 遇到的任何失败（例如，层变得陈旧）。
	loadFn loadAccount // Function to retrieve the account from with supplied hash
	// 使用提供的哈希检索账户的函数。
}

// newDiffAccountIterator creates an account iterator over the given state set.
// newDiffAccountIterator 在给定的状态集上创建一个账户迭代器。
func newDiffAccountIterator(seek common.Hash, states *stateSet, fn loadAccount) AccountIterator {
	// Seek out the requested starting account
	// 查找请求的起始账户。
	hashes := states.accountList()
	index := sort.Search(len(hashes), func(i int) bool {
		return bytes.Compare(seek[:], hashes[i][:]) <= 0
	})
	// Assemble and returned the already seeked iterator
	// 组装并返回已查找的迭代器。
	return &diffAccountIterator{
		keys:   hashes[index:],
		loadFn: fn,
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diffAccountIterator) Next() bool {
	// If the iterator was already stale, consider it a programmer error. Although
	// we could just return false here, triggering this path would probably mean
	// somebody forgot to check for Error, so lets blow up instead of undefined
	// behavior that's hard to debug.
	// 如果迭代器已经变得陈旧，则认为这是一个程序员错误。虽然我们可以在这里直接返回 false，
	// 但触发此路径可能意味着有人忘记检查 Error，所以我们直接 panic，而不是产生难以调试的未定义行为。
	if it.fail != nil {
		panic(fmt.Sprintf("called Next of failed iterator: %v", it.fail))
	}
	// Stop iterating if all keys were exhausted
	// 如果所有键都已耗尽，则停止迭代。
	if len(it.keys) == 0 {
		return false
	}
	// Iterator seems to be still alive, retrieve and cache the live hash
	// 迭代器似乎仍然有效，检索并缓存活动的哈希。
	it.curHash = it.keys[0]

	// key cached, shift the iterator and notify the user of success
	// 键已缓存，移动迭代器并通知用户成功。
	it.keys = it.keys[1:]
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. the linked state set becoming stale).
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，链接的状态集变得陈旧）。
func (it *diffAccountIterator) Error() error {
	return it.fail
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 返回迭代器当前指向的账户的哈希。
func (it *diffAccountIterator) Hash() common.Hash {
	return it.curHash
}

// Account returns the RLP encoded slim account the iterator is currently at.
// This method may fail if the associated state goes stale. An error will
// be set to it.fail just in case.
// Account 返回迭代器当前指向的 RLP 编码的精简账户。如果关联的状态变得陈旧，此方法可能会失败。
// 万一发生这种情况，错误将设置到 it.fail 中。
//
// Note the returned account is not a copy, please don't modify it.
// 注意：返回的账户不是副本，请不要修改它。
func (it *diffAccountIterator) Account() []byte {
	blob, err := it.loadFn(it.curHash)
	if err != nil {
		it.fail = err
		return nil
	}
	return blob
}

// Release is a noop for diff account iterators as there are no held resources.
// 对于差异账户迭代器，Release 是一个空操作，因为没有持有任何资源。
func (it *diffAccountIterator) Release() {}

// diskAccountIterator is an account iterator that steps over the persistent
// accounts within the database.
// diskAccountIterator 是一个账户迭代器，用于遍历数据库中的持久账户。
//
// To simplify, the staleness of the persistent state is not tracked. The disk
// iterator is not intended to be used alone. It should always be wrapped with
// a diff iterator, as the bottom-most disk layer uses both the in-memory
// aggregated buffer and the persistent disk layer as the data sources. The
// staleness of the diff iterator is sufficient to invalidate the iterator pair.
// 为了简化，不跟踪持久状态的陈旧性。磁盘迭代器不打算单独使用。它应该总是用一个差异迭代器包装起来，
// 因为最底层的磁盘层同时使用内存中的聚合缓冲区和持久磁盘层作为数据源。差异迭代器的陈旧性足以使迭代器对无效。
type diskAccountIterator struct {
	it ethdb.Iterator
}

// newDiskAccountIterator creates an account iterator over the persistent state.
// newDiskAccountIterator 在持久状态上创建一个账户迭代器。
func newDiskAccountIterator(db ethdb.KeyValueStore, seek common.Hash) AccountIterator {
	pos := common.TrimRightZeroes(seek[:])
	return &diskAccountIterator{
		it: db.NewIterator(rawdb.SnapshotAccountPrefix, pos),
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diskAccountIterator) Next() bool {
	// If the iterator was already exhausted, don't bother
	// 如果迭代器已经耗尽，则不再尝试。
	if it.it == nil {
		return false
	}
	// Try to advance the iterator and release it if we reached the end
	// 尝试前进迭代器，如果到达末尾则释放它。
	for {
		if !it.it.Next() {
			it.it.Release()
			it.it = nil
			return false
		}
		if len(it.it.Key()) == len(rawdb.SnapshotAccountPrefix)+common.HashLength {
			break
		}
	}
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit. (e.g, any error occurred in the database)
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，数据库中发生任何错误）。
func (it *diskAccountIterator) Error() error {
	if it.it == nil {
		return nil // Iterator is exhausted and released
	}
	return it.it.Error()
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 返回迭代器当前指向的账户的哈希。
func (it *diskAccountIterator) Hash() common.Hash {
	return common.BytesToHash(it.it.Key()) // The prefix will be truncated
}

// Account returns the RLP encoded slim account the iterator is currently at.
// Account 返回迭代器当前指向的 RLP 编码的精简账户。
func (it *diskAccountIterator) Account() []byte {
	return it.it.Value()
}

// Release releases the database snapshot held during iteration.
// Release 释放迭代期间持有的数据库快照。
func (it *diskAccountIterator) Release() {
	// The iterator is auto-released on exhaustion, so make sure it's still alive
	// 迭代器在耗尽时会自动释放，所以要确保它仍然有效。
	if it.it != nil {
		it.it.Release()
		it.it = nil
	}
}

// diffStorageIterator is a storage iterator that steps over the specific storage
// (both live and deleted) contained within a state set. Higher order iterators
// will use the deleted slot to skip deeper iterators.
// diffStorageIterator 是一个存储迭代器，用于遍历状态集中包含的特定存储（包括活动的和已删除的）。更高阶的迭代器将使用已删除的槽位来跳过更深层的迭代器。
//
// This iterator could be created from the diff layer or the disk layer (the
// aggregated state buffer).
// 此迭代器可以从差异层或磁盘层（聚合状态缓冲区）创建。
type diffStorageIterator struct {
	curHash common.Hash // The current slot hash the iterator is positioned on
	// 迭代器当前指向的槽位哈希。
	account common.Hash // The account hash the storage slots belonging to
	// 存储槽所属的账户哈希。
	keys []common.Hash // Keys left in the layer to iterate
	// 层中剩余要迭代的键列表。
	fail error // Any failures encountered (stale)
	// 遇到的任何失败（例如，层变得陈旧）。
	loadFn loadStorage // Function to retrieve the storage slot from with supplied hash
	// 使用提供的哈希检索存储槽的函数。
}

// newDiffStorageIterator creates a storage iterator over a single diff layer.
// newDiffStorageIterator 在单个差异层上创建一个存储迭代器。
func newDiffStorageIterator(account common.Hash, seek common.Hash, states *stateSet, fn loadStorage) StorageIterator {
	hashes := states.storageList(account)
	index := sort.Search(len(hashes), func(i int) bool {
		return bytes.Compare(seek[:], hashes[i][:]) <= 0
	})
	// Assemble and returned the already seeked iterator
	// 组装并返回已查找的迭代器。
	return &diffStorageIterator{
		account: account,
		keys:    hashes[index:],
		loadFn:  fn,
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diffStorageIterator) Next() bool {
	// If the iterator was already stale, consider it a programmer error. Although
	// we could just return false here, triggering this path would probably mean
	// somebody forgot to check for Error, so lets blow up instead of undefined
	// behavior that's hard to debug.
	// 如果迭代器已经变得陈旧，则认为这是一个程序员错误。虽然我们可以在这里直接返回 false，
	// 但触发此路径可能意味着有人忘记检查 Error，所以我们直接 panic，而不是产生难以调试的未定义行为。
	if it.fail != nil {
		panic(fmt.Sprintf("called Next of failed iterator: %v", it.fail))
	}
	// Stop iterating if all keys were exhausted
	// 如果所有键都已耗尽，则停止迭代。
	if len(it.keys) == 0 {
		return false
	}
	// Iterator seems to be still alive, retrieve and cache the live hash
	// 迭代器似乎仍然有效，检索并缓存活动的哈希。
	it.curHash = it.keys[0]

	// key cached, shift the iterator and notify the user of success
	// 键已缓存，移动迭代器并通知用户成功。
	it.keys = it.keys[1:]
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. the state set becoming stale).
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，状态集变得陈旧）。
func (it *diffStorageIterator) Error() error {
	return it.fail
}

// Hash returns the hash of the storage slot the iterator is currently at.
// Hash 返回迭代器当前指向的存储槽的哈希。
func (it *diffStorageIterator) Hash() common.Hash {
	return it.curHash
}

// Slot returns the raw storage slot value the iterator is currently at.
// This method may fail if the associated state goes stale. An error will
// be set to it.fail just in case.
// Slot 返回迭代器当前指向的原始存储槽值。如果关联的状态变得陈旧，此方法可能会失败。
// 万一发生这种情况，错误将设置到 it.fail 中。
//
// Note the returned slot is not a copy, please don't modify it.
// 注意：返回的槽位不是副本，请不要修改它。
func (it *diffStorageIterator) Slot() []byte {
	storage, err := it.loadFn(it.account, it.curHash)
	if err != nil {
		it.fail = err
		return nil
	}
	return storage
}

// Release is a noop for diff account iterators as there are no held resources.
// 对于差异账户迭代器，Release 是一个空操作，因为没有持有任何资源。
func (it *diffStorageIterator) Release() {}

// diskStorageIterator is a storage iterator that steps over the persistent
// storage slots contained within the database.
// diskStorageIterator 是一个存储迭代器，用于遍历数据库中持久存储槽。
//
// To simplify, the staleness of the persistent state is not tracked. The disk
// iterator is not intended to be used alone. It should always be wrapped with
// a diff iterator, as the bottom-most disk layer uses both the in-memory
// aggregated buffer and the persistent disk layer as the data sources. The
// staleness of the diff iterator is sufficient to invalidate the iterator pair.
// 为了简化，不跟踪持久状态的陈旧性。磁盘迭代器不打算单独使用。它应该总是用一个差异迭代器包装起来，
// 因为最底层的磁盘层同时使用内存中的聚合缓冲区和持久磁盘层作为数据源。差异迭代器的陈旧性足以使迭代器对无效。
type diskStorageIterator struct {
	account common.Hash
	it      ethdb.Iterator
}

// StorageIterator creates a storage iterator over the persistent state.
// StorageIterator 在持久状态上创建一个存储迭代器。
func newDiskStorageIterator(db ethdb.KeyValueStore, account common.Hash, seek common.Hash) StorageIterator {
	pos := common.TrimRightZeroes(seek[:])
	return &diskStorageIterator{
		account: account,
		it:      db.NewIterator(append(rawdb.SnapshotStoragePrefix, account.Bytes()...), pos),
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diskStorageIterator) Next() bool {
	// If the iterator was already exhausted, don't bother
	// 如果迭代器已经耗尽，则不再尝试。
	if it.it == nil {
		return false
	}
	// Try to advance the iterator and release it if we reached the end
	// 尝试前进迭代器，如果到达末尾则释放它。
	for {
		if !it.it.Next() {
			it.it.Release()
			it.it = nil
			return false
		}
		if len(it.it.Key()) == len(rawdb.SnapshotStoragePrefix)+common.HashLength+common.HashLength {
			break
		}
	}
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. the error occurred in the database).
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，数据库中发生错误）。
func (it *diskStorageIterator) Error() error {
	if it.it == nil {
		return nil // Iterator is exhausted and released
	}
	return it.it.Error()
}

// Hash returns the hash of the storage slot the iterator is currently at.
// Hash 返回迭代器当前指向的存储槽的哈希。
func (it *diskStorageIterator) Hash() common.Hash {
	return common.BytesToHash(it.it.Key()) // The prefix will be truncated
}

// Slot returns the raw storage slot content the iterator is currently at.
// Slot 返回迭代器当前指向的原始存储槽内容。
func (it *diskStorageIterator) Slot() []byte {
	return it.it.Value()
}

// Release releases the database snapshot held during iteration.
// Release 释放迭代期间持有的数据库快照。
func (it *diskStorageIterator) Release() {
	// The iterator is auto-released on exhaustion, so make sure it's still alive
	// 迭代器在耗尽时会自动释放，所以要确保它仍然有效。
	if it.it != nil {
		it.it.Release()
		it.it = nil
	}
}
