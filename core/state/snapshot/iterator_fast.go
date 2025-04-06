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
	"cmp"
	"fmt"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
)

// 状态树 (State Tree): fastIterator 的工作是基于一个分层的状态快照树。每个层级代表了以太坊状态在不同区块高度的快照。
// 差异层 (Diff Layers): 在基础的 diskLayer 之上，可能存在多个 diffLayer，每个 diffLayer 记录了在一个或多个区块执行后状态的变更。fastIterator 需要能够有效地遍历这些层级。
// 优先级 (Priority): 通过为每个层级的迭代器分配优先级，fastIterator 能够确定在多个层级都修改了同一个账户或存储槽时，应该以哪个版本为准。通常，更靠近当前状态的层级具有更高的优先级。
// 迭代器模式 (Iterator Pattern): 这段代码实现了迭代器设计模式，提供了一种 последовательный (sequential) 访问集合对象元素的方法，而无需暴露其底层表示。
// 高效遍历: fastIterator 的设计目标是高效地遍历整个状态快照堆栈，避免重复的数据，并能够快速定位到指定哈希的账户或存储槽。

// weightedIterator is an iterator with an assigned weight. It is used to prioritise
// which account or storage slot is the correct one if multiple iterators find the
// same one (modified in multiple consecutive blocks).
// weightedIterator 是一个带有指定权重的迭代器。如果多个迭代器找到同一个账户或存储槽（在多个连续区块中被修改），它用于确定哪个是正确的。
type weightedIterator struct {
	it Iterator // The underlying iterator
	// it 底层迭代器
	priority int // Priority of this iterator (lower is better)
	// priority 此迭代器的优先级（越低越好）
}

// Cmp compares two weighted iterators.
// Cmp 比较两个加权迭代器。
func (it *weightedIterator) Cmp(other *weightedIterator) int {
	// Order the iterators primarily by the account hashes
	// 主要按账户哈希对迭代器排序
	hashI := it.it.Hash()
	hashJ := other.it.Hash()

	switch bytes.Compare(hashI[:], hashJ[:]) {
	case -1:
		return -1
	case 1:
		return 1
	}
	// Same account/storage-slot in multiple layers, split by priority
	// 多个层中存在相同的账户/存储槽，按优先级进行区分
	return cmp.Compare(it.priority, other.priority)
}

// fastIterator is a more optimized multi-layer iterator which maintains a
// direct mapping of all iterators leading down to the bottom layer.
// fastIterator 是一个更优化的多层迭代器，它维护着通向底层的所有迭代器的直接映射。
type fastIterator struct {
	tree *Tree // Snapshot tree to reinitialize stale sub-iterators with
	// tree 用于重新初始化过时子迭代器的快照树
	root common.Hash // Root hash to reinitialize stale sub-iterators through
	// root 用于重新初始化过时子迭代器的根哈希

	curAccount []byte // Current account data
	// curAccount 当前账户数据
	curSlot []byte // Current storage slot data
	// curSlot 当前存储槽数据

	iterators []*weightedIterator // Stack of iterators, one per layer
	// iterators 迭代器堆栈，每层一个
	initiated bool // Flag to indicate if the first Next() has been called
	// initiated 标志指示是否已调用第一个 Next()
	account bool // Flag to indicate if this is an account iterator (vs storage)
	// account 标志指示这是否是账户迭代器（相对于存储迭代器）
	fail error // Any error encountered during iteration
	// fail 迭代过程中遇到的任何错误
}

// newFastIterator creates a new hierarchical account or storage iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire snapshot diff stack simultaneously.
// newFastIterator 创建一个新的分层账户或存储迭代器，每层一个元素。返回的组合迭代器可用于同时遍历整个快照差异堆栈。
func newFastIterator(tree *Tree, root common.Hash, account common.Hash, seek common.Hash, accountIterator bool) (*fastIterator, error) {
	// newFastIterator 函数创建一个新的 fastIterator。
	snap := tree.Snapshot(root)
	if snap == nil {
		return nil, fmt.Errorf("unknown snapshot: %x", root)
	}
	fi := &fastIterator{
		tree:    tree,
		root:    root,
		account: accountIterator,
	}
	current := snap.(snapshot)
	for depth := 0; current != nil; depth++ {
		// 遍历快照树的每一层，为每一层创建一个加权迭代器。
		if accountIterator {
			// 如果是账户迭代器，则创建 AccountIterator。
			fi.iterators = append(fi.iterators, &weightedIterator{
				it:       current.AccountIterator(seek),
				priority: depth,
			})
		} else {
			// 如果是存储迭代器，则创建 StorageIterator。
			fi.iterators = append(fi.iterators, &weightedIterator{
				it:       current.StorageIterator(account, seek),
				priority: depth,
			})
		}
		current = current.Parent()
	}
	fi.init()
	return fi, nil
}

// init walks over all the iterators and resolves any clashes between them, after
// which it prepares the stack for step-by-step iteration.
// init 遍历所有迭代器并解决它们之间的任何冲突，之后准备堆栈以进行逐步迭代。
func (fi *fastIterator) init() {
	// init 方法初始化 fastIterator。
	// Track which account hashes are iterators positioned on
	// 跟踪迭代器定位在哪个账户哈希上
	var positioned = make(map[common.Hash]int)

	// Position all iterators and track how many remain live
	// 定位所有迭代器并跟踪有多少仍然有效
	for i := 0; i < len(fi.iterators); i++ {
		// Retrieve the first element and if it clashes with a previous iterator,
		// advance either the current one or the old one. Repeat until nothing is
		// clashing any more.
		// 检索第一个元素，如果它与先前的迭代器冲突，则前进当前迭代器或旧迭代器。重复直到不再有任何冲突。
		it := fi.iterators[i]
		for {
			// If the iterator is exhausted, drop it off the end
			// 如果迭代器已耗尽，则将其从末尾删除
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
			// 迭代器仍然有效，检查与先前迭代器的冲突
			hash := it.it.Hash()
			if other, exist := positioned[hash]; !exist {
				// 如果当前哈希没有在 positioned map 中，则记录其位置。
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
				// 如果我们改为对迭代器进行初始优先级排序，则可以避免整个 else 块。如果我们这样做，那么只有当较低优先级（首选）的迭代器具有相同的值时，我们才会最终到达这里，然后我们将始终继续。但是，这会增加额外的排序成本，因此可能不是更好。
				if fi.iterators[other].priority < it.priority {
					// The 'it' should be progressed
					// 应该前进 'it'
					continue
				} else {
					// The 'other' should be progressed, swap them
					// 应该前进 'other'，交换它们
					it = fi.iterators[other]
					fi.iterators[other], fi.iterators[i] = fi.iterators[i], fi.iterators[other]
					continue
				}
			}
		}
	}
	// Re-sort the entire list
	// 重新排序整个列表
	slices.SortFunc(fi.iterators, func(a, b *weightedIterator) int { return a.Cmp(b) })
	fi.initiated = false
}

// Next steps the iterator forward one element, returning false if exhausted.
// Next 将迭代器向前移动一个元素，如果耗尽则返回 false。
func (fi *fastIterator) Next() bool {
	// Next 方法使迭代器前进到下一个元素。
	if len(fi.iterators) == 0 {
		// 如果没有更多的迭代器，则返回 false。
		return false
	}
	if !fi.initiated {
		// Don't forward first time -- we had to 'Next' once in order to
		// do the sorting already
		// 第一次不前进 -- 我们已经需要 'Next' 一次才能进行排序
		fi.initiated = true
		if fi.account {
			// 如果是账户迭代器，则获取当前账户。
			fi.curAccount = fi.iterators[0].it.(AccountIterator).Account()
		} else {
			// 如果是存储迭代器，则获取当前存储槽。
			fi.curSlot = fi.iterators[0].it.(StorageIterator).Slot()
		}
		if innerErr := fi.iterators[0].it.Error(); innerErr != nil {
			// 检查底层迭代器是否发生错误。
			fi.fail = innerErr
			return false
		}
		if fi.curAccount != nil || fi.curSlot != nil {
			// 如果当前账户或存储槽不为空，则返回 true。
			return true
		}
		// Implicit else: we've hit a nil-account or nil-slot, and need to
		// fall through to the loop below to land on something non-nil
		// 隐式 else：我们遇到了一个 nil 账户或 nil 槽，需要继续执行下面的循环以找到非 nil 的内容
	}
	// If an account or a slot is deleted in one of the layers, the key will
	// still be there, but the actual value will be nil. However, the iterator
	// should not export nil-values (but instead simply omit the key), so we
	// need to loop here until we either
	//  - get a non-nil value,
	//  - hit an error,
	//  - or exhaust the iterator
	// 如果在其中一个层中删除了账户或槽位，则该键仍然存在，但实际值将为 nil。但是，迭代器不应导出 nil 值（而应简单地省略该键），因此我们需要在此循环，直到我们
	//  - 获得一个非 nil 值，
	//  - 遇到错误，
	//  - 或耗尽迭代器
	for {
		if !fi.next(0) {
			// 如果下一个元素不存在，则返回 false。
			return false // exhausted
		}
		if fi.account {
			// 如果是账户迭代器，则获取当前账户。
			fi.curAccount = fi.iterators[0].it.(AccountIterator).Account()
		} else {
			// 如果是存储迭代器，则获取当前存储槽。
			fi.curSlot = fi.iterators[0].it.(StorageIterator).Slot()
		}
		if innerErr := fi.iterators[0].it.Error(); innerErr != nil {
			// 检查底层迭代器是否发生错误。
			fi.fail = innerErr
			return false // error
		}
		if fi.curAccount != nil || fi.curSlot != nil {
			// 如果当前账户或存储槽不为空，则跳出循环。
			break // non-nil value found
		}
	}
	return true
}

// next handles the next operation internally and should be invoked when we know
// that two elements in the list may have the same value.
// next 在内部处理下一个操作，当我们知道列表中可能有两个元素具有相同的值时，应该调用它。
//
// For example, if the iterated hashes become [2,3,5,5,8,9,10], then we should
// invoke next(3), which will call Next on elem 3 (the second '5') and will
// cascade along the list, applying the same operation if needed.
// 例如，如果迭代的哈希变成 [2,3,5,5,8,9,10]，那么我们应该调用 next(3)，它将对元素 3（第二个 '5'）调用 Next，并沿着列表级联，并在需要时应用相同的操作。
func (fi *fastIterator) next(idx int) bool {
	// next 方法在内部处理迭代器的前进操作，用于处理具有相同哈希值的不同层级迭代器。
	// If this particular iterator got exhausted, remove it and return true (the
	// next one is surely not exhausted yet, otherwise it would have been removed
	// already).
	// 如果这个特定的迭代器耗尽了，移除它并返回 true（下一个肯定还没有耗尽，否则它已经被移除了）。
	if it := fi.iterators[idx].it; !it.Next() {
		it.Release()

		fi.iterators = append(fi.iterators[:idx], fi.iterators[idx+1:]...)
		return len(fi.iterators) > 0
	}
	// If there's no one left to cascade into, return
	// 如果没有剩下的可以级联的，则返回
	if idx == len(fi.iterators)-1 {
		return true
	}
	// We next-ed the iterator at 'idx', now we may have to re-sort that element
	// 我们对索引为 'idx' 的迭代器执行了 Next 操作，现在我们可能需要重新排序该元素
	var (
		cur, next         = fi.iterators[idx], fi.iterators[idx+1]
		curHash, nextHash = cur.it.Hash(), next.it.Hash()
	)
	if diff := bytes.Compare(curHash[:], nextHash[:]); diff < 0 {
		// It is still in correct place
		// 它仍然在正确的位置
		return true
	} else if diff == 0 && cur.priority < next.priority {
		// So still in correct place, but we need to iterate on the next
		// 所以仍然在正确的位置，但是我们需要迭代下一个
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
		// 迭代器总是向前移动，所以旧位置之前的任何内容都知道在我们后面，所以完全跳过它们。这实际上是一个重要的子句，因为排序顺序已失效。
		if n < idx {
			return false
		}
		if n == len(fi.iterators)-1 {
			// Can always place an elem last
			// 总是可以将元素放在最后
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
		// 我们要放置在其旁边的元素具有相同的值，所以无论哪个最终位于 n+1，都需要进一步迭代
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
	// move 方法将指定索引处的迭代器移动到新的位置。
	elem := fi.iterators[index]
	copy(fi.iterators[index:], fi.iterators[index+1:newpos+1])
	fi.iterators[newpos] = elem
}

// Error returns any failure that occurred during iteration, which might have
// caused a premature iteration exit (e.g. snapshot stack becoming stale).
// Error 返回迭代过程中发生的任何失败，这可能导致过早的迭代退出（例如，快照堆栈变得过时）。
func (fi *fastIterator) Error() error {
	// Error 方法返回迭代过程中发生的任何错误。
	return fi.fail
}

// Hash returns the current key
// Hash 返回当前键
func (fi *fastIterator) Hash() common.Hash {
	// Hash 方法返回当前迭代到的哈希值。
	return fi.iterators[0].it.Hash()
}

// Account returns the current account blob.
// Note the returned account is not a copy, please don't modify it.
// Account 返回当前的账户 blob。
// 注意：返回的账户不是副本，请不要修改它。
func (fi *fastIterator) Account() []byte {
	// Account 方法返回当前迭代到的账户数据。
	return fi.curAccount
}

// Slot returns the current storage slot.
// Note the returned slot is not a copy, please don't modify it.
// Slot 返回当前的存储槽。
// 注意：返回的槽位不是副本，请不要修改它。
func (fi *fastIterator) Slot() []byte {
	// Slot 方法返回当前迭代到的存储槽数据。
	return fi.curSlot
}

// Release iterates over all the remaining live layer iterators and releases each
// of them individually.
// Release 遍历所有剩余的活动层迭代器并分别释放它们。
func (fi *fastIterator) Release() {
	// Release 方法释放所有底层迭代器占用的资源。
	for _, it := range fi.iterators {
		it.it.Release()
	}
	fi.iterators = nil
}

// Debug is a convenience helper during testing
// Debug 是测试期间的便捷助手
func (fi *fastIterator) Debug() {
	// Debug 方法用于调试，打印当前迭代器的状态。
	for _, it := range fi.iterators {
		fmt.Printf("[p=%v v=%v] ", it.priority, it.it.Hash()[0])
	}
	fmt.Println()
}

// newFastAccountIterator creates a new hierarchical account iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire snapshot diff stack simultaneously.
// newFastAccountIterator 创建一个新的分层账户迭代器，每层一个元素。返回的组合迭代器可用于同时遍历整个快照差异堆栈。
func newFastAccountIterator(tree *Tree, root common.Hash, seek common.Hash) (AccountIterator, error) {
	// newFastAccountIterator 函数创建一个新的快速账户迭代器。
	return newFastIterator(tree, root, common.Hash{}, seek, true)
}

// newFastStorageIterator creates a new hierarchical storage iterator with one
// element per diff layer. The returned combo iterator can be used to walk over
// the entire snapshot diff stack simultaneously.
// newFastStorageIterator 创建一个新的分层存储迭代器，每层一个元素。返回的组合迭代器可用于同时遍历整个快照差异堆栈。
func newFastStorageIterator(tree *Tree, root common.Hash, account common.Hash, seek common.Hash) (StorageIterator, error) {
	// newFastStorageIterator 函数创建一个新的快速存储迭代器。
	return newFastIterator(tree, root, account, seek, false)
}
