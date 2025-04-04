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
	"cmp"
	"fmt"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

// weightedIterator is an iterator with an assigned weight. It is used to prioritise
// which account or storage slot is the correct one if multiple iterators find the
// same one (modified in multiple consecutive blocks).
// weightedIterator 是一个带有权重的迭代器。当多个迭代器找到同一个账户或存储槽（在多个连续的区块中被修改）时，它用于确定哪个是正确的。
type weightedIterator struct {
	it       Iterator
	priority int
	// 优先级，通常与层在层叠中的深度相关，越深的层优先级越低。
}

// Cmp compares two weighted iterators.
// Cmp 比较两个 weightedIterator。
func (it *weightedIterator) Cmp(other *weightedIterator) int {
	// Order the iterators primarily by the account hashes
	// 主要按账户哈希对迭代器进行排序。
	hashI := it.it.Hash()
	hashJ := other.it.Hash()

	switch bytes.Compare(hashI[:], hashJ[:]) {
	case -1:
		return -1
	case 1:
		return 1
	}
	// Same account/storage-slot in multiple layers, split by priority
	// 多个层中存在相同的账户/存储槽，按优先级进行区分。
	return cmp.Compare(it.priority, other.priority)
}

// fastIterator is a more optimized multi-layer iterator which maintains a
// direct mapping of all iterators leading down to the bottom layer.
// fastIterator 是一个更优化的多层迭代器，它维护着通向底层的所有迭代器的直接映射。
type fastIterator struct {
	curAccount []byte
	curSlot    []byte

	iterators []*weightedIterator
	initiated bool
	// 标记迭代器是否已完成首次初始化（首次 Next 调用后为 true）。
	account bool
	// 标记迭代器是用于账户还是存储槽。
	fail error
	// 迭代过程中遇到的任何错误。
}

// newFastIterator creates a new hierarchical account or storage iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire layer stack simultaneously.
// newFastIterator 创建一个新的分层账户或存储迭代器，每个差异层对应一个元素。
// 返回的组合迭代器可以用于同时遍历整个层堆栈。
func newFastIterator(db *Database, root common.Hash, account common.Hash, seek common.Hash, accountIterator bool) (*fastIterator, error) {
	current := db.tree.get(root)
	if current == nil {
		return nil, fmt.Errorf("unknown layer: %x", root)
	}
	fi := &fastIterator{
		account: accountIterator,
	}
	for depth := 0; current != nil; depth++ {
		if accountIterator {
			switch dl := current.(type) {
			case *diskLayer:
				fi.iterators = append(fi.iterators, &weightedIterator{
					// The state set in the disk layer is mutable, and the entire state becomes stale
					// if a diff layer above is merged into it. Therefore, staleness must be checked,
					// and the storage slot should be retrieved with read lock protection.
					// 磁盘层中的状态集是可变的，如果上面的差异层合并到其中，则整个状态都会变得陈旧。
					// 因此，必须检查陈旧性，并且应该使用读锁保护来检索存储槽。
					it: newDiffAccountIterator(seek, dl.buffer.states, func(hash common.Hash) ([]byte, error) {
						dl.lock.RLock()
						defer dl.lock.RUnlock()

						if dl.stale {
							return nil, errSnapshotStale
						}
						return dl.buffer.states.mustAccount(hash)
					}),
					priority: depth,
				})
				fi.iterators = append(fi.iterators, &weightedIterator{
					it:       newDiskAccountIterator(dl.db.diskdb, seek),
					priority: depth + 1,
				})
			case *diffLayer:
				// The state set in diff layer is immutable and will never be stale,
				// so the read lock protection is unnecessary.
				// 差异层中的状态集是不可变的，永远不会变得陈旧，因此不需要读锁保护。
				fi.iterators = append(fi.iterators, &weightedIterator{
					it:       newDiffAccountIterator(seek, dl.states.stateSet, dl.states.mustAccount),
					priority: depth,
				})
			}
		} else {
			switch dl := current.(type) {
			case *diskLayer:
				fi.iterators = append(fi.iterators, &weightedIterator{
					// The state set in the disk layer is mutable, and the entire state becomes stale
					// if a diff layer above is merged into it. Therefore, staleness must be checked,
					// and the storage slot should be retrieved with read lock protection.
					// 磁盘层中的状态集是可变的，如果上面的差异层合并到其中，则整个状态都会变得陈旧。
					// 因此，必须检查陈旧性，并且应该使用读锁保护来检索存储槽。
					it: newDiffStorageIterator(account, seek, dl.buffer.states, func(addrHash common.Hash, slotHash common.Hash) ([]byte, error) {
						dl.lock.RLock()
						defer dl.lock.RUnlock()

						if dl.stale {
							return nil, errSnapshotStale
						}
						return dl.buffer.states.mustStorage(addrHash, slotHash)
					}),
					priority: depth,
				})
				fi.iterators = append(fi.iterators, &weightedIterator{
					it:       newDiskStorageIterator(dl.db.diskdb, account, seek),
					priority: depth + 1,
				})
			case *diffLayer:
				// The state set in diff layer is immutable and will never be stale,
				// so the read lock protection is unnecessary.
				// 差异层中的状态集是不可变的，永远不会变得陈旧，因此不需要读锁保护。
				fi.iterators = append(fi.iterators, &weightedIterator{
					it:       newDiffStorageIterator(account, seek, dl.states.stateSet, dl.states.mustStorage),
					priority: depth,
				})
			}
		}
		current = current.parentLayer()
	}
	fi.init()
	return fi, nil
}

// init walks over all the iterators and resolves any clashes between them, after
// which it prepares the stack for step-by-step iteration.
// init 遍历所有迭代器并解决它们之间的任何冲突，然后准备堆栈以进行逐步迭代。
func (fi *fastIterator) init() {
	// Track which account hashes are iterators positioned on
	// 跟踪迭代器定位在哪些账户哈希上。
	var positioned = make(map[common.Hash]int)

	// Position all iterators and track how many remain live
	// 定位所有迭代器并跟踪有多少仍然处于活动状态。
	for i := 0; i < len(fi.iterators); i++ {
		// Retrieve the first element and if it clashes with a previous iterator,
		// advance either the current one or the old one. Repeat until nothing is
		// clashing anymore.
		// 检索第一个元素，如果它与之前的迭代器冲突，则前进当前迭代器或旧迭代器。重复此过程直到不再发生冲突。
		it := fi.iterators[i]
		for {
			// If the iterator is exhausted, drop it off the end
			// 如果迭代器已耗尽，则将其从末尾删除。
			if !it.it.Next() {
				it.it.Release()
				last := len(fi.iterators) - 1

				fi.iterators[i] = fi.iterators[last]
				fi.iterators[last] = nil
				fi.iterators = fi.iterators[:last]

				i--
				break
			}
			// The iterator is still alive, check for collisions with previous ones
			// 迭代器仍然处于活动状态，检查与之前的迭代器是否存在冲突。
			hash := it.it.Hash()
			if other, exist := positioned[hash]; !exist {
				positioned[hash] = i
				break
			} else {
				// Iterators collide, one needs to be progressed, use priority to
				// determine which.
				// 迭代器冲突，需要前进一个，使用优先级来确定前进哪个。
				//
				// This whole else-block can be avoided, if we instead
				// do an initial priority-sort of the iterators. If we do that,
				// then we'll only wind up here if a lower-priority (preferred) iterator
				// has the same value, and then we will always just continue.
				// However, it costs an extra sort, so it's probably not better
				// 如果我们首先对迭代器进行优先级排序，则可以避免整个 else 块。
				// 如果这样做，那么只有当较低优先级（首选）的迭代器具有相同的值时，我们才会进入这里，
				// 然后我们将始终继续。然而，这会增加额外的排序成本，所以可能不是更好。
				if fi.iterators[other].priority < it.priority {
					// The 'it' should be progressed
					// 应该前进 'it'。
					continue
				} else {
					// The 'other' should be progressed, swap them
					// 应该前进 'other'，交换它们。
					it = fi.iterators[other]
					fi.iterators[other], fi.iterators[i] = fi.iterators[i], fi.iterators[other]
					continue
				}
			}
		}
	}
	// Re-sort the entire list
	// 重新排序整个列表。
	slices.SortFunc(fi.iterators, func(a, b *weightedIterator) int { return a.Cmp(b) })
	fi.initiated = false
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果已耗尽则返回 false。
func (fi *fastIterator) Next() bool {
	if len(fi.iterators) == 0 {
		return false
	}
	if !fi.initiated {
		// Don't forward first time -- we had to 'Next' once in order to
		// do the sorting already
		// 首次不前进 -- 我们已经需要调用一次 'Next' 来完成排序。
		fi.initiated = true
		if fi.account {
			fi.curAccount = fi.iterators[0].it.(AccountIterator).Account()
		} else {
			fi.curSlot = fi.iterators[0].it.(StorageIterator).Slot()
		}
		if innerErr := fi.iterators[0].it.Error(); innerErr != nil {
			fi.fail = innerErr
			return false
		}
		if fi.curAccount != nil || fi.curSlot != nil {
			return true
		}
		// Implicit else: we've hit a nil-account or nil-slot, and need to
		// fall through to the loop below to land on something non-nil
		// 隐式 else：我们遇到了一个 nil 账户或 nil 槽位，需要继续执行下面的循环以找到非 nil 的值。
	}
	// If an account or a slot is deleted in one of the layers, the key will
	// still be there, but the actual value will be nil. However, the iterator
	// should not export nil-values (but instead simply omit the key), so we
	// need to loop here until we either
	//  - get a non-nil value,
	//  - hit an error,
	//  - or exhaust the iterator
	// 如果账户或槽位在某个层中被删除，键仍然存在，但实际值将为 nil。
	// 然而，迭代器不应该导出 nil 值（而是简单地省略该键），
	// 因此我们需要在此循环，直到我们得到一个非 nil 值、遇到错误或耗尽迭代器。
	for {
		if !fi.next(0) {
			return false // exhausted
		}
		if fi.account {
			fi.curAccount = fi.iterators[0].it.(AccountIterator).Account()
		} else {
			fi.curSlot = fi.iterators[0].it.(StorageIterator).Slot()
		}
		if innerErr := fi.iterators[0].it.Error(); innerErr != nil {
			fi.fail = innerErr
			return false // error
		}
		if fi.curAccount != nil || fi.curSlot != nil {
			break // non-nil value found
		}
	}
	return true
}

// next handles the next operation internally and should be invoked when we know
// that two elements in the list may have the same value.
// next 在内部处理下一个操作，当知道列表中可能存在两个相同的值时应该调用它。
//
// For example, if the iterated hashes become [2,3,5,5,8,9,10], then we should
// invoke next(3), which will call Next on elem 3 (the second '5') and will
// cascade along the list, applying the same operation if needed.
// 例如，如果迭代的哈希值变为 [2,3,5,5,8,9,10]，那么我们应该调用 next(3)，
// 这将对元素 3（第二个 '5'）调用 Next，并沿着列表级联，根据需要应用相同的操作。
func (fi *fastIterator) next(idx int) bool {
	// If this particular iterator got exhausted, remove it and return true (the
	// next one is surely not exhausted yet, otherwise it would have been removed
	// already).
	// 如果这个特定的迭代器耗尽了，则移除它并返回 true（下一个肯定还没有耗尽，否则它已经被移除了）。
	if it := fi.iterators[idx].it; !it.Next() {
		it.Release()

		fi.iterators = append(fi.iterators[:idx], fi.iterators[idx+1:]...)
		return len(fi.iterators) > 0
	}
	// If there's no one left to cascade into, return
	// 如果没有剩余的可以级联的迭代器，则返回。
	if idx == len(fi.iterators)-1 {
		return true
	}
	// We next-ed the iterator at 'idx', now we may have to re-sort that element
	// 我们对索引为 'idx' 的迭代器调用了 Next，现在可能需要重新排序该元素。
	var (
		cur, next         = fi.iterators[idx], fi.iterators[idx+1]
		curHash, nextHash = cur.it.Hash(), next.it.Hash()
	)
	if diff := bytes.Compare(curHash[:], nextHash[:]); diff < 0 {
		// It is still in correct place
		// 它仍然在正确的位置。
		return true
	} else if diff == 0 && cur.priority < next.priority {
		// So still in correct place, but we need to iterate on the next
		// 所以仍然在正确的位置，但是我们需要迭代下一个。
		fi.next(idx + 1)
		return true
	}
	// At this point, the iterator is in the wrong location, but the remaining
	// list is sorted. Find out where to move the item.
	// 此时，迭代器位于错误的位置，但剩余的列表已排序。找出将该项移动到哪里。
	clash := -1
	index := sort.Search(len(fi.iterators), func(n int) bool {
		// The iterator always advances forward, so anything before the old slot
		// is known to be behind us, so just skip them altogether. This actually
		// is an important clause since the sort order got invalidated.
		// 迭代器总是向前移动，所以旧位置之前的任何内容都已知在我们之后，所以完全跳过它们。
		// 这实际上是一个重要的子句，因为排序顺序已经失效。
		if n < idx {
			return false
		}
		if n == len(fi.iterators)-1 {
			// Can always place an elem last
			// 总是可以将元素放在最后。
			return true
		}
		nextHash := fi.iterators[n+1].it.Hash()
		if diff := bytes.Compare(curHash[:], nextHash[:]); diff < 0 {
			return true
		} else if diff > 0 {
			return false
		}
		// The elem we're placing it next to has the same value,
		// so whichever winds up on n+1 will need further iteration
		// 我们要放置在其旁边的元素具有相同的值，因此无论哪个最终位于 n+1，都需要进一步迭代。
		clash = n + 1

		return cur.priority < fi.iterators[n+1].priority
	})
	fi.move(idx, index)
	if clash != -1 {
		fi.next(clash)
	}
	return true
}

// move advances an iterator to another position in the list.
// move 将迭代器移动到列表中的另一个位置。
func (fi *fastIterator) move(index, newpos int) {
	elem := fi.iterators[index]
	copy(fi.iterators[index:], fi.iterators[index+1:newpos+1])
	fi.iterators[newpos] = elem
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 返回迭代过程中发生的任何失败，这可能导致迭代提前退出（例如，快照堆栈变得陈旧）。
func (fi *fastIterator) Error() error {
	return fi.fail
}

// Hash returns the current key
// Hash 返回当前的键。
func (fi *fastIterator) Hash() common.Hash {
	return fi.iterators[0].it.Hash()
}

// Account returns the current account blob.
// Note the returned account is not a copy, please don't modify it.
// Account 返回当前的账户 blob。
// 注意：返回的账户不是副本，请不要修改它。
func (fi *fastIterator) Account() []byte {
	return fi.curAccount
}

// Slot returns the current storage slot.
// Note the returned slot is not a copy, please don't modify it.
// Slot 返回当前的存储槽。
// 注意：返回的槽位不是副本，请不要修改它。
func (fi *fastIterator) Slot() []byte {
	return fi.curSlot
}

// Release iterates over all the remaining live layer iterators and releases each
// of them individually.
// Release 遍历所有剩余的活动层迭代器并分别释放它们。
func (fi *fastIterator) Release() {
	for _, it := range fi.iterators {
		it.it.Release()
	}
	fi.iterators = nil
}

// Debug is a convenience helper during testing
// Debug 是测试期间的便捷助手。
func (fi *fastIterator) Debug() {
	for _, it := range fi.iterators {
		fmt.Printf("[p=%v v=%v] ", it.priority, it.it.Hash()[0])
	}
	fmt.Println()
}

// newFastAccountIterator creates a new hierarchical account iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire snapshot diff stack simultaneously.
// newFastAccountIterator 创建一个新的分层账户迭代器，每个差异层对应一个元素。
// 返回的组合迭代器可以用于同时遍历整个快照差异堆栈。
func newFastAccountIterator(db *Database, root common.Hash, seek common.Hash) (AccountIterator, error) {
	return newFastIterator(db, root, common.Hash{}, seek, true)
}

// newFastStorageIterator creates a new hierarchical storage iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire snapshot diff stack simultaneously.
// newFastStorageIterator 创建一个新的分层存储迭代器，每个差异层对应一个元素。
// 返回的组合迭代器可以用于同时遍历整个快照差异堆栈。
func newFastStorageIterator(db *Database, root common.Hash, account common.Hash, seek common.Hash) (StorageIterator, error) {
	return newFastIterator(db, root, account, seek, false)
}
