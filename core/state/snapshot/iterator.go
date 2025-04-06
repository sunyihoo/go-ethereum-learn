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
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
)

// 磁盘层 (Disk Layer): 这是最底层的存储，直接将状态数据存储在磁盘上的数据库中（通常是 LevelDB）。
// 差异层 (Diff Layer): 当区块链发生状态变化时（例如执行交易），这些变化不会直接写入磁盘层，而是记录在内存中的差异层。一个差异层代表了一段时间内的状态变化。可以有多个差异层叠加在一起，形成一个“快照堆栈”。
// 状态表示 (State Representation): 以太坊的状态在黄皮书中被定义为一个从地址到账户状态的映射。账户状态包括余额、nonce、代码哈希和存储根哈希。快照机制旨在高效地存储和访问这个状态。分层存储和迭代器的使用是实现这一目标的关键。
// Merkle-Patricia Tree: 虽然这段代码本身没有直接涉及到 Merkle-Patricia 树的构建或验证，但这些迭代器是遍历状态数据的基础，而状态数据最终会组织成 Merkle-Patricia 树，其根哈希用于确保状态的一致性。
// 状态同步 (State Sync): 高效的状态迭代对于快速的节点同步至关重要。新的节点可以使用快照和迭代器来快速获取最新的状态数据，而无需从头开始处理所有交易。
// EIP (Ethereum Improvement Proposals): 许多 EIP 都关注于改进以太坊的状态管理和存储，例如通过引入新的状态存储格式或优化状态访问方式。这些迭代器的设计和实现是 go-ethereum 实现这些改进的基础。

// Iterator is an iterator to step over all the accounts or the specific
// storage in a snapshot which may or may not be composed of multiple layers.
// Iterator 是一个迭代器，用于遍历快照中的所有账户或特定存储，该快照可能由多个层组成。
type Iterator interface {
	// Next steps the iterator forward one element, returning false if exhausted,
	// or an error if iteration failed for some reason (e.g. root being iterated
	// becomes stale and garbage collected).
	// Next 方法将迭代器向前移动一个元素。如果迭代器已耗尽则返回 false，如果由于某种原因（例如，正在迭代的根变得陈旧并被垃圾回收）迭代失败则返回错误。
	Next() bool

	// Error returns any failure that occurred during iteration, which might have
	// caused a premature iteration exit (e.g. snapshot stack becoming stale).
	// Error 方法返回迭代过程中发生的任何错误，这些错误可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
	Error() error

	// Hash returns the hash of the account or storage slot the iterator is
	// currently at.
	// Hash 方法返回迭代器当前指向的账户或存储槽的哈希值。
	Hash() common.Hash

	// Release releases associated resources. Release should always succeed and
	// can be called multiple times without causing error.
	// Release 方法释放相关的资源。Release 应该总是成功，并且可以多次调用而不会导致错误。
	Release()
}

// AccountIterator is an iterator to step over all the accounts in a snapshot,
// which may or may not be composed of multiple layers.
// AccountIterator 是一个迭代器，用于遍历快照中的所有账户，该快照可能由多个层组成。
type AccountIterator interface {
	Iterator

	// Account returns the RLP encoded slim account the iterator is currently at.
	// An error will be returned if the iterator becomes invalid
	// Account 方法返回迭代器当前指向的经过 RLP 编码的精简账户数据。如果迭代器变得无效，则会返回错误。
	Account() []byte
}

// StorageIterator is an iterator to step over the specific storage in a snapshot,
// which may or may not be composed of multiple layers.
// StorageIterator 是一个迭代器，用于遍历快照中的特定存储，该快照可能由多个层组成。
type StorageIterator interface {
	Iterator

	// Slot returns the storage slot the iterator is currently at. An error will
	// be returned if the iterator becomes invalid
	// Slot 方法返回迭代器当前指向的存储槽数据。如果迭代器变得无效，则会返回错误。
	Slot() []byte
}

// diffAccountIterator is an account iterator that steps over the accounts (both
// live and deleted) contained within a single diff layer. Higher order iterators
// will use the deleted accounts to skip deeper iterators.
// diffAccountIterator 是一个账户迭代器，用于遍历单个差异层中包含的账户（包括活跃的和已删除的）。
// 更高阶的迭代器将使用已删除的账户来跳过更深层的迭代器。
type diffAccountIterator struct {
	// curHash is the current hash the iterator is positioned on. The field is
	// explicitly tracked since the referenced diff layer might go stale after
	// the iterator was positioned and we don't want to fail accessing the old
	// hash as long as the iterator is not touched any more.
	// curHash 是迭代器当前所处的哈希值。显式跟踪该字段是因为在迭代器定位后，引用的差异层可能会变得陈旧，
	// 只要不再访问迭代器，我们就不希望访问旧哈希失败。
	curHash common.Hash

	layer *diffLayer // Live layer to retrieve values from
	// layer 是用于检索值的活跃层。
	keys []common.Hash // Keys left in the layer to iterate
	// keys 是层中剩余要迭代的键。
	fail error // Any failures encountered (stale)
	// fail 是遇到的任何失败（例如，陈旧）。
}

// AccountIterator creates an account iterator over a single diff layer.
// AccountIterator 在单个差异层上创建一个账户迭代器。
func (dl *diffLayer) AccountIterator(seek common.Hash) AccountIterator {
	// Seek out the requested starting account
	// 查找请求的起始账户。
	hashes := dl.AccountList()
	index := sort.Search(len(hashes), func(i int) bool {
		return bytes.Compare(seek[:], hashes[i][:]) <= 0
	})
	// Assemble and returned the already seeked iterator
	// 组装并返回已查找的迭代器。
	return &diffAccountIterator{
		layer: dl,
		keys:  hashes[index:],
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 方法将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diffAccountIterator) Next() bool {
	// If the iterator was already stale, consider it a programmer error. Although
	// we could just return false here, triggering this path would probably mean
	// somebody forgot to check for Error, so lets blow up instead of undefined
	// behavior that's hard to debug.
	// 如果迭代器已经陈旧，则将其视为程序员错误。虽然我们可以在这里直接返回 false，
	// 但触发此路径可能意味着有人忘记检查 Error，因此我们抛出 panic 而不是难以调试的未定义行为。
	if it.fail != nil {
		panic(fmt.Sprintf("called Next of failed iterator: %v", it.fail))
	}
	// Stop iterating if all keys were exhausted
	// 如果所有键都已耗尽，则停止迭代。
	if len(it.keys) == 0 {
		return false
	}
	if it.layer.Stale() {
		// 如果底层层变得陈旧，则记录错误并停止迭代。
		it.fail, it.keys = ErrSnapshotStale, nil
		return false
	}
	// Iterator seems to be still alive, retrieve and cache the live hash
	// 迭代器似乎仍然存活，检索并缓存活跃的哈希值。
	it.curHash = it.keys[0]

	// key cached, shift the iterator and notify the user of success
	// 键已缓存，移动迭代器并通知用户成功。
	it.keys = it.keys[1:]
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 方法返回迭代过程中发生的任何错误，这些错误可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
func (it *diffAccountIterator) Error() error {
	return it.fail
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 方法返回迭代器当前指向的账户的哈希值。
func (it *diffAccountIterator) Hash() common.Hash {
	return it.curHash
}

// Account returns the RLP encoded slim account the iterator is currently at.
// This method may _fail_, if the underlying layer has been flattened between
// the call to Next and Account. That type of error will set it.Err.
// This method assumes that flattening does not delete elements from
// the accountData mapping (writing nil into it is fine though), and will panic
// if elements have been deleted.
//
// Note the returned account is not a copy, please don't modify it.
// Account 方法返回迭代器当前指向的经过 RLP 编码的精简账户数据。
// 如果在调用 Next 和 Account 之间底层层被展平，则此方法可能会失败，并将错误设置到 it.Err。
// 此方法假定展平操作不会从 accountData 映射中删除元素（写入 nil 是允许的），如果删除了元素，则会触发 panic。
// 注意：返回的账户数据不是副本，请不要修改它。
func (it *diffAccountIterator) Account() []byte {
	it.layer.lock.RLock()
	blob, ok := it.layer.accountData[it.curHash]
	if !ok {
		panic(fmt.Sprintf("iterator referenced non-existent account: %x", it.curHash))
	}
	it.layer.lock.RUnlock()
	if it.layer.Stale() {
		it.fail, it.keys = ErrSnapshotStale, nil
	}
	return blob
}

// Release is a noop for diff account iterators as there are no held resources.
// Release 方法对于差异账户迭代器来说是一个空操作，因为没有需要释放的资源。
func (it *diffAccountIterator) Release() {}

// diskAccountIterator is an account iterator that steps over the live accounts
// contained within a disk layer.
// diskAccountIterator 是一个账户迭代器，用于遍历磁盘层中包含的活跃账户。
type diskAccountIterator struct {
	layer *diskLayer
	it    ethdb.Iterator
}

// AccountIterator creates an account iterator over a disk layer.
// AccountIterator 在磁盘层上创建一个账户迭代器。
func (dl *diskLayer) AccountIterator(seek common.Hash) AccountIterator {
	pos := common.TrimRightZeroes(seek[:])
	return &diskAccountIterator{
		layer: dl,
		it:    dl.diskdb.NewIterator(rawdb.SnapshotAccountPrefix, pos),
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 方法将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diskAccountIterator) Next() bool {
	// If the iterator was already exhausted, don't bother
	// 如果迭代器已经耗尽，则无需再操作。
	if it.it == nil {
		return false
	}
	// Try to advance the iterator and release it if we reached the end
	// 尝试移动迭代器，如果到达末尾则释放它。
	for {
		if !it.it.Next() {
			it.it.Release()
			it.it = nil
			return false
		}
		if len(it.it.Key()) == len(rawdb.SnapshotAccountPrefix)+common.HashLength {
			// 确保键的长度是账户快照前缀加上哈希长度，以过滤掉其他类型的数据。
			break
		}
	}
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
//
// A diff layer is immutable after creation content wise and can always be fully
// iterated without error, so this method always returns nil.
// Error 方法返回迭代过程中发生的任何错误，这些错误可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
// 从内容上看，差异层在创建后是不可变的，并且总是可以完整地迭代而不会出错，因此此方法始终返回 nil。
func (it *diskAccountIterator) Error() error {
	if it.it == nil {
		return nil // Iterator is exhausted and released
		// 迭代器已耗尽并释放。
	}
	return it.it.Error()
}

// Hash returns the hash of the account the iterator is currently at.
// Hash 方法返回迭代器当前指向的账户的哈希值。
func (it *diskAccountIterator) Hash() common.Hash {
	return common.BytesToHash(it.it.Key()) // The prefix will be truncated
	// 前缀将被截断。
}

// Account returns the RLP encoded slim account the iterator is currently at.
// Account 方法返回迭代器当前指向的经过 RLP 编码的精简账户数据。
func (it *diskAccountIterator) Account() []byte {
	return it.it.Value()
}

// Release releases the database snapshot held during iteration.
// Release 方法释放迭代期间持有的数据库快照。
func (it *diskAccountIterator) Release() {
	// The iterator is auto-released on exhaustion, so make sure it's still alive
	// 迭代器在耗尽时会自动释放，因此请确保它仍然存活。
	if it.it != nil {
		it.it.Release()
		it.it = nil
	}
}

// diffStorageIterator is a storage iterator that steps over the specific storage
// (both live and deleted) contained within a single diff layer. Higher order
// iterators will use the deleted slot to skip deeper iterators.
// diffStorageIterator 是一个存储迭代器，用于遍历单个差异层中包含的特定存储（包括活跃的和已删除的）。
// 更高阶的迭代器将使用已删除的存储槽来跳过更深层的迭代器。
type diffStorageIterator struct {
	// curHash is the current hash the iterator is positioned on. The field is
	// explicitly tracked since the referenced diff layer might go stale after
	// the iterator was positioned and we don't want to fail accessing the old
	// hash as long as the iterator is not touched any more.
	// curHash 是迭代器当前所处的哈希值。显式跟踪该字段是因为在迭代器定位后，引用的差异层可能会变得陈旧，
	// 只要不再访问迭代器，我们就不希望访问旧哈希失败。
	curHash common.Hash
	account common.Hash

	layer *diffLayer // Live layer to retrieve values from
	// layer 是用于检索值的活跃层。
	keys []common.Hash // Keys left in the layer to iterate
	// keys 是层中剩余要迭代的键。
	fail error // Any failures encountered (stale)
	// fail 是遇到的任何失败（例如，陈旧）。
}

// StorageIterator creates a storage iterator over a single diff layer.
// Except the storage iterator is returned, there is an additional flag
// "destructed" returned. If it's true then it means the whole storage is
// destructed in this layer(maybe recreated too), don't bother deeper layer
// for storage retrieval.
// StorageIterator 在单个差异层上创建一个存储迭代器。
// 除了返回存储迭代器之外，还会返回一个额外的标志 "destructed"。如果为 true，则表示整个存储在此层中被销毁（也可能被重新创建），
// 无需再深入下一层检索存储。
func (dl *diffLayer) StorageIterator(account common.Hash, seek common.Hash) StorageIterator {
	// Create the storage for this account even it's marked
	// as destructed. The iterator is for the new one which
	// just has the same address as the deleted one.
	// 即使标记为已销毁，也为该账户创建存储。迭代器用于新的存储，该存储只是与已删除的存储具有相同的地址。
	hashes := dl.StorageList(account)
	index := sort.Search(len(hashes), func(i int) bool {
		return bytes.Compare(seek[:], hashes[i][:]) <= 0
	})
	// Assemble and returned the already seeked iterator
	// 组装并返回已查找的迭代器。
	return &diffStorageIterator{
		layer:   dl,
		account: account,
		keys:    hashes[index:],
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 方法将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diffStorageIterator) Next() bool {
	// If the iterator was already stale, consider it a programmer error. Although
	// we could just return false here, triggering this path would probably mean
	// somebody forgot to check for Error, so lets blow up instead of undefined
	// behavior that's hard to debug.
	// 如果迭代器已经陈旧，则将其视为程序员错误。虽然我们可以在这里直接返回 false，
	// 但触发此路径可能意味着有人忘记检查 Error，因此我们抛出 panic 而不是难以调试的未定义行为。
	if it.fail != nil {
		panic(fmt.Sprintf("called Next of failed iterator: %v", it.fail))
	}
	// Stop iterating if all keys were exhausted
	// 如果所有键都已耗尽，则停止迭代。
	if len(it.keys) == 0 {
		return false
	}
	if it.layer.Stale() {
		// 如果底层层变得陈旧，则记录错误并停止迭代。
		it.fail, it.keys = ErrSnapshotStale, nil
		return false
	}
	// Iterator seems to be still alive, retrieve and cache the live hash
	// 迭代器似乎仍然存活，检索并缓存活跃的哈希值。
	it.curHash = it.keys[0]
	// key cached, shift the iterator and notify the user of success
	// 键已缓存，移动迭代器并通知用户成功。
	it.keys = it.keys[1:]
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 方法返回迭代过程中发生的任何错误，这些错误可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
func (it *diffStorageIterator) Error() error {
	return it.fail
}

// Hash returns the hash of the storage slot the iterator is currently at.
// Hash 方法返回迭代器当前指向的存储槽的哈希值。
func (it *diffStorageIterator) Hash() common.Hash {
	return it.curHash
}

// Slot returns the raw storage slot value the iterator is currently at.
// This method may _fail_, if the underlying layer has been flattened between
// the call to Next and Value. That type of error will set it.Err.
// This method assumes that flattening does not delete elements from
// the storage mapping (writing nil into it is fine though), and will panic
// if elements have been deleted.
//
// Note the returned slot is not a copy, please don't modify it.
// Slot 方法返回迭代器当前指向的原始存储槽值。
// 如果在调用 Next 和 Value 之间底层层被展平，则此方法可能会失败，并将错误设置到 it.Err。
// 此方法假定展平操作不会从 storage 映射中删除元素（写入 nil 是允许的），如果删除了元素，则会触发 panic。
// 注意：返回的存储槽数据不是副本，请不要修改它。
func (it *diffStorageIterator) Slot() []byte {
	it.layer.lock.RLock()
	storage, ok := it.layer.storageData[it.account]
	if !ok {
		panic(fmt.Sprintf("iterator referenced non-existent account storage: %x", it.account))
	}
	// Storage slot might be nil(deleted), but it must exist
	// 存储槽可能为 nil（已删除），但必须存在。
	blob, ok := storage[it.curHash]
	if !ok {
		panic(fmt.Sprintf("iterator referenced non-existent storage slot: %x", it.curHash))
	}
	it.layer.lock.RUnlock()
	if it.layer.Stale() {
		it.fail, it.keys = ErrSnapshotStale, nil
	}
	return blob
}

// Release is a noop for diff account iterators as there are no held resources.
// Release 方法对于差异账户迭代器来说是一个空操作，因为没有需要释放的资源。
func (it *diffStorageIterator) Release() {}

// diskStorageIterator is a storage iterator that steps over the live storage
// contained within a disk layer.
// diskStorageIterator 是一个存储迭代器，用于遍历磁盘层中包含的活跃存储。
type diskStorageIterator struct {
	layer   *diskLayer
	account common.Hash
	it      ethdb.Iterator
}

// StorageIterator creates a storage iterator over a disk layer.
// If the whole storage is destructed, then all entries in the disk
// layer are deleted already. So the "destructed" flag returned here
// is always false.
// StorageIterator 在磁盘层上创建一个存储迭代器。
// 如果整个存储被销毁，那么磁盘层中的所有条目都已被删除。因此，此处返回的 "destructed" 标志始终为 false。
func (dl *diskLayer) StorageIterator(account common.Hash, seek common.Hash) StorageIterator {
	pos := common.TrimRightZeroes(seek[:])
	return &diskStorageIterator{
		layer:   dl,
		account: account,
		it:      dl.diskdb.NewIterator(append(rawdb.SnapshotStoragePrefix, account.Bytes()...), pos),
	}
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 方法将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (it *diskStorageIterator) Next() bool {
	// If the iterator was already exhausted, don't bother
	// 如果迭代器已经耗尽，则无需再操作。
	if it.it == nil {
		return false
	}
	// Try to advance the iterator and release it if we reached the end
	// 尝试移动迭代器，如果到达末尾则释放它。
	for {
		if !it.it.Next() {
			it.it.Release()
			it.it = nil
			return false
		}
		if len(it.it.Key()) == len(rawdb.SnapshotStoragePrefix)+common.HashLength+common.HashLength {
			// 确保键的长度是存储快照前缀加上账户哈希长度再加上存储槽哈希长度。
			break
		}
	}
	return true
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
//
// A diff layer is immutable after creation content wise and can always be fully
// iterated without error, so this method always returns nil.
// Error 方法返回迭代过程中发生的任何错误，这些错误可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
// 从内容上看，差异层在创建后是不可变的，并且总是可以完整地迭代而不会出错，因此此方法始终返回 nil。
func (it *diskStorageIterator) Error() error {
	if it.it == nil {
		return nil // Iterator is exhausted and released
		// 迭代器已耗尽并释放。
	}
	return it.it.Error()
}

// Hash returns the hash of the storage slot the iterator is currently at.
// Hash 方法返回迭代器当前指向的存储槽的哈希值。
func (it *diskStorageIterator) Hash() common.Hash {
	return common.BytesToHash(it.it.Key()) // The prefix will be truncated
	// 前缀将被截断。
}

// Slot returns the raw storage slot content the iterator is currently at.
// Slot 方法返回迭代器当前指向的原始存储槽内容。
func (it *diskStorageIterator) Slot() []byte {
	return it.it.Value()
}

// Release releases the database snapshot held during iteration.
// Release 方法释放迭代期间持有的数据库快照。
func (it *diskStorageIterator) Release() {
	// The iterator is auto-released on exhaustion, so make sure it's still alive
	// 迭代器在耗尽时会自动释放，因此请确保它仍然存活。
	if it.it != nil {
		it.it.Release()
		it.it = nil
	}
}
