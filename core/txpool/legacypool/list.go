// Copyright 2016 The go-ethereum Authors
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

package legacypool

import (
	"container/heap"
	"math"
	"math/big"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// 交易池管理: 这些数据结构是以太坊节点中交易池 (txpool) 实现的关键组成部分。交易池负责接收、验证和存储等待被矿工打包到区块中的交易。
// Nonce 排序: nonceHeap 和 sortedMap 用于按 nonce 对属于同一账户的交易进行排序，确保交易按照正确的顺序执行。这对于维护账户状态的正确性至关重要。
// 价格排序: priceHeap 和 pricedList 用于根据交易的 Gas 价格对交易进行排序。这使得矿工可以优先打包 Gas 价格较高的交易，从而实现一个基于市场的交易优先级系统。在交易池满时，价格较低的交易可能会被丢弃。
// 交易驱逐: 当交易池达到其容量限制时，需要一种机制来决定哪些交易应该被移除。pricedList 的 Discard 方法就是用于这个目的，它会选择价格最低的交易进行驱逐。
// Base Fee 和小费: 在引入 EIP-1559 后，交易的 Gas 费用包括基础费用和小费。priceHeap 考虑了基础费用，以便更准确地评估交易的优先级。
// 远程与本地交易: pricedList 主要关注远程交易，因为本地节点产生的交易通常具有更高的优先级。

// nonceHeap is a heap.Interface implementation over 64bit unsigned integers for
// retrieving sorted transactions from the possibly gapped future queue.
// nonceHeap 是一个在 64 位无符号整数上实现 heap.Interface 的结构，用于从可能存在间隙的未来队列中检索排序后的交易。
type nonceHeap []uint64

func (h nonceHeap) Len() int           { return len(h) }
func (h nonceHeap) Less(i, j int) bool { return h[i] < h[j] }
func (h nonceHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *nonceHeap) Push(x interface{}) {
	*h = append(*h, x.(uint64))
}

func (h *nonceHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = 0
	*h = old[0 : n-1]
	return x
}

// sortedMap is a nonce->transaction hash map with a heap based index to allow
// iterating over the contents in a nonce-incrementing way.
// sortedMap 是一个 nonce 到交易的哈希映射，带有一个基于堆的索引，允许以 nonce 递增的方式迭代内容。
type sortedMap struct {
	items map[uint64]*types.Transaction // Hash map storing the transaction data
	// items 哈希映射，存储交易数据。
	index *nonceHeap // Heap of nonces of all the stored transactions (non-strict mode)
	// index 存储的所有交易的 nonce 的堆（非严格模式）。
	cache types.Transactions // Cache of the transactions already sorted
	// cache 已经排序的交易缓存。
	cacheMu sync.Mutex // Mutex covering the cache
	// cacheMu 覆盖缓存的互斥锁。
}

// newSortedMap creates a new nonce-sorted transaction map.
// newSortedMap 创建一个新的按 nonce 排序的交易映射。
func newSortedMap() *sortedMap {
	return &sortedMap{
		items: make(map[uint64]*types.Transaction),
		index: new(nonceHeap),
	}
}

// Get retrieves the current transactions associated with the given nonce.
// Get 检索与给定 nonce 关联的当前交易。
func (m *sortedMap) Get(nonce uint64) *types.Transaction {
	return m.items[nonce]
}

// Put inserts a new transaction into the map, also updating the map's nonce
// index. If a transaction already exists with the same nonce, it's overwritten.
// Put 将一个新交易插入到映射中，同时更新映射的 nonce 索引。如果已存在具有相同 nonce 的交易，则将其覆盖。
func (m *sortedMap) Put(tx *types.Transaction) {
	nonce := tx.Nonce()
	if m.items[nonce] == nil {
		heap.Push(m.index, nonce)
	}
	m.cacheMu.Lock()
	m.items[nonce], m.cache = tx, nil
	m.cacheMu.Unlock()
}

// Forward removes all transactions from the map with a nonce lower than the
// provided threshold. Every removed transaction is returned for any post-removal
// maintenance.
// Forward 从映射中删除所有 nonce 低于给定阈值的交易。每个被删除的交易都会被返回以进行任何删除后的维护。
func (m *sortedMap) Forward(threshold uint64) types.Transactions {
	var removed types.Transactions

	// Pop off heap items until the threshold is reached
	// 弹出堆中的元素，直到达到阈值。
	for m.index.Len() > 0 && (*m.index)[0] < threshold {
		nonce := heap.Pop(m.index).(uint64)
		removed = append(removed, m.items[nonce])
		delete(m.items, nonce)
	}
	// If we had a cached order, shift the front
	// 如果我们有一个缓存的顺序，则移动到前面。
	m.cacheMu.Lock()
	if m.cache != nil {
		m.cache = m.cache[len(removed):]
	}
	m.cacheMu.Unlock()
	return removed
}

// Filter iterates over the list of transactions and removes all of them for which
// the specified function evaluates to true.
// Filter 遍历交易列表，并删除所有指定函数评估为 true 的交易。
// Filter, as opposed to 'filter', re-initialises the heap after the operation is done.
// 与 'filter' 不同，'Filter' 在操作完成后重新初始化堆。
// If you want to do several consecutive filterings, it's therefore better to first
// do a .filter(func1) followed by .Filter(func2) or reheap()
// 如果你想执行多个连续的过滤操作，最好先执行 .filter(func1)，然后执行 .Filter(func2) 或 reheap()。
func (m *sortedMap) Filter(filter func(*types.Transaction) bool) types.Transactions {
	removed := m.filter(filter)
	// If transactions were removed, the heap and cache are ruined
	// 如果交易被删除，堆和缓存都会失效。
	if len(removed) > 0 {
		m.reheap()
	}
	return removed
}

func (m *sortedMap) reheap() {
	*m.index = make([]uint64, 0, len(m.items))
	for nonce := range m.items {
		*m.index = append(*m.index, nonce)
	}
	heap.Init(m.index)
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()
}

// filter is identical to Filter, but **does not** regenerate the heap. This method
// should only be used if followed immediately by a call to Filter or reheap()
// filter 与 Filter 相同，但 **不会** 重新生成堆。此方法应仅在紧随其后调用 Filter 或 reheap() 时使用。
func (m *sortedMap) filter(filter func(*types.Transaction) bool) types.Transactions {
	var removed types.Transactions

	// Collect all the transactions to filter out
	// 收集所有要过滤掉的交易。
	for nonce, tx := range m.items {
		if filter(tx) {
			removed = append(removed, tx)
			delete(m.items, nonce)
		}
	}
	if len(removed) > 0 {
		m.cacheMu.Lock()
		m.cache = nil
		m.cacheMu.Unlock()
	}
	return removed
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
// Cap 对项目数量设置硬性限制，并返回所有超出该限制的交易。
func (m *sortedMap) Cap(threshold int) types.Transactions {
	// Short circuit if the number of items is under the limit
	// 如果项目数量低于限制，则直接返回。
	if len(m.items) <= threshold {
		return nil
	}
	// Otherwise gather and drop the highest nonce'd transactions
	// 否则，收集并删除 nonce 最高的交易。
	var drops types.Transactions
	slices.Sort(*m.index)
	for size := len(m.items); size > threshold; size-- {
		drops = append(drops, m.items[(*m.index)[size-1]])
		delete(m.items, (*m.index)[size-1])
	}
	*m.index = (*m.index)[:threshold]
	// The sorted m.index slice is still a valid heap, so there is no need to
	// reheap after deleting tail items.
	// 排序后的 m.index 切片仍然是一个有效的堆，因此在删除尾部项目后无需重新堆化。

	// If we had a cache, shift the back
	// 如果我们有一个缓存，则移动到后面。
	m.cacheMu.Lock()
	if m.cache != nil {
		m.cache = m.cache[:len(m.cache)-len(drops)]
	}
	m.cacheMu.Unlock()
	return drops
}

// Remove deletes a transaction from the maintained map, returning whether the
// transaction was found.
// Remove 从维护的映射中删除一个交易，并返回是否找到该交易。
func (m *sortedMap) Remove(nonce uint64) bool {
	// Short circuit if no transaction is present
	// 如果不存在该交易，则直接返回。
	_, ok := m.items[nonce]
	if !ok {
		return false
	}
	// Otherwise delete the transaction and fix the heap index
	// 否则，删除交易并修复堆索引。
	for i := 0; i < m.index.Len(); i++ {
		if (*m.index)[i] == nonce {
			heap.Remove(m.index, i)
			break
		}
	}
	delete(m.items, nonce)
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()

	return true
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
// Ready 检索从提供的 nonce 开始的按顺序递增的准备处理的交易列表。返回的交易将从列表中删除。
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into an invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
// 注意，所有 nonce 低于 start 的交易也会被返回，以防止进入无效状态。这不应该发生，但最好自我纠正而不是失败！
func (m *sortedMap) Ready(start uint64) types.Transactions {
	// Short circuit if no transactions are available
	// 如果没有可用的交易，则直接返回。
	if m.index.Len() == 0 || (*m.index)[0] > start {
		return nil
	}
	// Otherwise start accumulating incremental transactions
	// 否则，开始累积增量交易。
	var ready types.Transactions
	// todo start为什么没用呢？
	for next := (*m.index)[0]; m.index.Len() > 0 && (*m.index)[0] == next; next++ {
		ready = append(ready, m.items[next])
		delete(m.items, next)
		heap.Pop(m.index)
	}
	m.cacheMu.Lock()
	m.cache = nil
	m.cacheMu.Unlock()

	return ready
}

// Len returns the length of the transaction map.
// Len 返回交易映射的长度。
func (m *sortedMap) Len() int {
	return len(m.items)
}

func (m *sortedMap) flatten() types.Transactions {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	// If the sorting was not cached yet, create and cache it
	// 如果排序尚未缓存，则创建并缓存它。
	if m.cache == nil {
		m.cache = make(types.Transactions, 0, len(m.items))
		for _, tx := range m.items {
			m.cache = append(m.cache, tx)
		}
		sort.Sort(types.TxByNonce(m.cache))
	}
	return m.cache
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
// Flatten 基于松散排序的内部表示创建一个按 nonce 排序的交易切片。
// 如果在对内容进行任何修改之前再次请求，则缓存排序结果。
func (m *sortedMap) Flatten() types.Transactions {
	cache := m.flatten()
	// Copy the cache to prevent accidental modification
	// 复制缓存以防止意外修改。
	txs := make(types.Transactions, len(cache))
	copy(txs, cache)
	return txs
}

// LastElement returns the last element of a flattened list, thus, the
// transaction with the highest nonce
// LastElement 返回扁平化列表的最后一个元素，即 nonce 最高的交易。
func (m *sortedMap) LastElement() *types.Transaction {
	cache := m.flatten()
	return cache[len(cache)-1]
}

// list is a "list" of transactions belonging to an account, sorted by account
// nonce. The same type can be used both for storing contiguous transactions for
// the executable/pending queue; and for storing gapped transactions for the non-
// executable/future queue, with minor behavioral changes.
// list 是属于一个账户的交易“列表”，按账户 nonce 排序。
// 同一种类型可以用于存储可执行/待处理队列的连续交易；也可以用于存储不可执行/未来队列的带有间隙的交易，行为略有不同。
type list struct {
	strict bool // Whether nonces are strictly continuous or not
	// strict 指示 nonce 是否严格连续。
	txs *sortedMap // Heap indexed sorted hash map of the transactions
	// txs 带有堆索引的按 nonce 排序的交易哈希映射。

	costcap *uint256.Int // Price of the highest costing transaction (reset only if exceeds balance)
	// costcap 最高成本交易的价格（仅在超过余额时重置）。
	gascap uint64 // Gas limit of the highest spending transaction (reset only if exceeds block limit)
	// gascap 最高花费交易的 Gas 限制（仅在超过区块限制时重置）。
	totalcost *uint256.Int // Total cost of all transactions in the list
	// totalcost 列表中所有交易的总成本。
}

// newList creates a new transaction list for maintaining nonce-indexable fast,
// gapped, sortable transaction lists.
// newList 创建一个新的交易列表，用于维护按 nonce 索引的快速、带间隙、可排序的交易列表。
func newList(strict bool) *list {
	return &list{
		strict:    strict,
		txs:       newSortedMap(),
		costcap:   new(uint256.Int),
		totalcost: new(uint256.Int),
	}
}

// Contains returns whether the  list contains a transaction
// with the provided nonce.
// Contains 返回列表是否包含具有提供的 nonce 的交易。
func (l *list) Contains(nonce uint64) bool {
	return l.txs.Get(nonce) != nil
}

// Add tries to insert a new transaction into the list, returning whether the
// transaction was accepted, and if yes, any previous transaction it replaced.
// Add 尝试将一个新交易插入到列表中，返回该交易是否被接受，如果接受，则返回它替换的任何先前交易。
//
// If the new transaction is accepted into the list, the lists' cost and gas
// thresholds are also potentially updated.
// 如果新交易被接受到列表中，列表的成本和 gas 阈值也可能会被更新。
func (l *list) Add(tx *types.Transaction, priceBump uint64) (bool, *types.Transaction) {
	// If there's an older better transaction, abort
	// 如果存在一个更旧更好的交易，则中止。
	old := l.txs.Get(tx.Nonce())
	if old != nil {
		if old.GasFeeCapCmp(tx) >= 0 || old.GasTipCapCmp(tx) >= 0 {
			return false, nil
		}
		// thresholdFeeCap = oldFC  * (100 + priceBump) / 100
		a := big.NewInt(100 + int64(priceBump))
		aFeeCap := new(big.Int).Mul(a, old.GasFeeCap())
		aTip := a.Mul(a, old.GasTipCap())

		// thresholdTip    = oldTip * (100 + priceBump) / 100
		b := big.NewInt(100)
		thresholdFeeCap := aFeeCap.Div(aFeeCap, b)
		thresholdTip := aTip.Div(aTip, b)

		// We have to ensure that both the new fee cap and tip are higher than the
		// old ones as well as checking the percentage threshold to ensure that
		// this is accurate for low (Wei-level) gas price replacements.
		// 我们必须确保新的费用上限和小费都高于旧的，并检查百分比阈值，以确保这对于低（Wei 级别）gas 价格替换是准确的。
		if tx.GasFeeCapIntCmp(thresholdFeeCap) < 0 || tx.GasTipCapIntCmp(thresholdTip) < 0 {
			return false, nil
		}
		// Old is being replaced, subtract old cost
		// 旧交易被替换，减去旧交易的成本。
		l.subTotalCost([]*types.Transaction{old})
	}
	// Add new tx cost to totalcost
	// 将新交易的成本添加到 totalcost。
	cost, overflow := uint256.FromBig(tx.Cost())
	if overflow {
		return false, nil
	}
	l.totalcost.Add(l.totalcost, cost)

	// Otherwise overwrite the old transaction with the current one
	// 否则，用当前交易覆盖旧交易。
	l.txs.Put(tx)
	if l.costcap.Cmp(cost) < 0 {
		l.costcap = cost
	}
	if gas := tx.Gas(); l.gascap < gas {
		l.gascap = gas
	}
	return true, old
}

// Forward removes all transactions from the list with a nonce lower than the
// provided threshold. Every removed transaction is returned for any post-removal
// maintenance.
// Forward 从列表中删除所有 nonce 低于给定阈值的交易。每个被删除的交易都会被返回以进行任何删除后的维护。
func (l *list) Forward(threshold uint64) types.Transactions {
	txs := l.txs.Forward(threshold)
	l.subTotalCost(txs)
	return txs
}

// Filter removes all transactions from the list with a cost or gas limit higher
// than the provided thresholds. Every removed transaction is returned for any
// post-removal maintenance. Strict-mode invalidated transactions are also
// returned.
// Filter 从列表中删除所有成本或 gas 限制高于给定阈值的交易。每个被删除的交易都会被返回以进行任何删除后的维护。
// 严格模式下无效的交易也会被返回。
//
// This method uses the cached costcap and gascap to quickly decide if there's even
// a point in calculating all the costs or if the balance covers all. If the threshold
// is lower than the costgas cap, the caps will be reset to a new high after removing
// the newly invalidated transactions.
// 此方法使用缓存的 costcap 和 gascap 来快速决定是否有必要计算所有成本，或者余额是否足够。
// 如果阈值低于 costgas cap，则在删除新失效的交易后，上限将被重置为新的较高值。
func (l *list) Filter(costLimit *uint256.Int, gasLimit uint64) (types.Transactions, types.Transactions) {
	// If all transactions are below the threshold, short circuit
	// 如果所有交易都低于阈值，则直接返回。
	if l.costcap.Cmp(costLimit) <= 0 && l.gascap <= gasLimit {
		return nil, nil
	}
	l.costcap = new(uint256.Int).Set(costLimit) // Lower the caps to the thresholds
	l.gascap = gasLimit

	// Filter out all the transactions above the account's funds
	// 过滤掉所有高于账户资金的交易。
	removed := l.txs.Filter(func(tx *types.Transaction) bool {
		return tx.Gas() > gasLimit || tx.Cost().Cmp(costLimit.ToBig()) > 0
	})

	if len(removed) == 0 {
		return nil, nil
	}
	var invalids types.Transactions
	// If the list was strict, filter anything above the lowest nonce
	// 如果列表是严格模式，则过滤掉所有高于最低 nonce 的交易。
	if l.strict {
		lowest := uint64(math.MaxUint64)
		for _, tx := range removed {
			if nonce := tx.Nonce(); lowest > nonce {
				lowest = nonce
			}
		}
		invalids = l.txs.filter(func(tx *types.Transaction) bool { return tx.Nonce() > lowest })
	}
	// Reset total cost
	// 重置总成本。
	l.subTotalCost(removed)
	l.subTotalCost(invalids)
	l.txs.reheap()
	return removed, invalids
}

// Cap places a hard limit on the number of items, returning all transactions
// exceeding that limit.
// Cap 对项目数量设置硬性限制，并返回所有超出该限制的交易。
func (l *list) Cap(threshold int) types.Transactions {
	txs := l.txs.Cap(threshold)
	l.subTotalCost(txs)
	return txs
}

// Remove deletes a transaction from the maintained list, returning whether the
// transaction was found, and also returning any transaction invalidated due to
// the deletion (strict mode only).
// Remove 从维护的列表中删除一个交易，返回是否找到该交易，并返回由于删除而失效的任何交易（仅限严格模式）。
func (l *list) Remove(tx *types.Transaction) (bool, types.Transactions) {
	// Remove the transaction from the set
	// 从集合中删除交易。
	nonce := tx.Nonce()
	if removed := l.txs.Remove(nonce); !removed {
		return false, nil
	}
	l.subTotalCost([]*types.Transaction{tx})
	// In strict mode, filter out non-executable transactions
	// 在严格模式下，过滤掉不可执行的交易。
	if l.strict {
		txs := l.txs.Filter(func(tx *types.Transaction) bool { return tx.Nonce() > nonce })
		l.subTotalCost(txs)
		return true, txs
	}
	return true, nil
}

// Ready retrieves a sequentially increasing list of transactions starting at the
// provided nonce that is ready for processing. The returned transactions will be
// removed from the list.
// Ready 检索从提供的 nonce 开始的按顺序递增的准备处理的交易列表。返回的交易将从列表中删除。
//
// Note, all transactions with nonces lower than start will also be returned to
// prevent getting into an invalid state. This is not something that should ever
// happen but better to be self correcting than failing!
// 注意，所有 nonce 低于 start 的交易也会被返回，以防止进入无效状态。这不应该发生，但最好自我纠正而不是失败！
func (l *list) Ready(start uint64) types.Transactions {
	txs := l.txs.Ready(start)
	l.subTotalCost(txs)
	return txs
}

// Len returns the length of the transaction list.
// Len 返回交易列表的长度。
func (l *list) Len() int {
	return l.txs.Len()
}

// Empty returns whether the list of transactions is empty or not.
// Empty 返回交易列表是否为空。
func (l *list) Empty() bool {
	return l.Len() == 0
}

// Flatten creates a nonce-sorted slice of transactions based on the loosely
// sorted internal representation. The result of the sorting is cached in case
// it's requested again before any modifications are made to the contents.
// Flatten 基于松散排序的内部表示创建一个按 nonce 排序的交易切片。
// 如果在对内容进行任何修改之前再次请求，则缓存排序结果。
func (l *list) Flatten() types.Transactions {
	return l.txs.Flatten()
}

// LastElement returns the last element of a flattened list, thus, the
// transaction with the highest nonce
// LastElement 返回扁平化列表的最后一个元素，即 nonce 最高的交易。
func (l *list) LastElement() *types.Transaction {
	return l.txs.LastElement()
}

// subTotalCost subtracts the cost of the given transactions from the
// total cost of all transactions.
// subTotalCost 从所有交易的总成本中减去给定交易的成本。
func (l *list) subTotalCost(txs []*types.Transaction) {
	for _, tx := range txs {
		_, underflow := l.totalcost.SubOverflow(l.totalcost, uint256.MustFromBig(tx.Cost()))
		if underflow {
			panic("totalcost underflow")
		}
	}
}

// priceHeap is a heap.Interface implementation over transactions for retrieving
// price-sorted transactions to discard when the pool fills up. If baseFee is set
// then the heap is sorted based on the effective tip based on the given base fee.
// If baseFee is nil then the sorting is based on gasFeeCap.
// priceHeap 是一个在交易上实现 heap.Interface 的结构，用于在池满时检索按价格排序的交易以丢弃。
// 如果设置了 baseFee，则堆根据给定 baseFee 的有效小费进行排序。如果 baseFee 为 nil，则根据 gasFeeCap 进行排序。
type priceHeap struct {
	baseFee *big.Int // heap should always be re-sorted after baseFee is changed
	// baseFee 基础费用，更改后应始终重新排序堆。
	list []*types.Transaction
	// list 存储交易的切片。
}

func (h *priceHeap) Len() int      { return len(h.list) }
func (h *priceHeap) Swap(i, j int) { h.list[i], h.list[j] = h.list[j], h.list[i] }

func (h *priceHeap) Less(i, j int) bool {
	switch h.cmp(h.list[i], h.list[j]) {
	case -1:
		return true
	case 1:
		return false
	default:
		return h.list[i].Nonce() > h.list[j].Nonce()
	}
}

func (h *priceHeap) cmp(a, b *types.Transaction) int {
	if h.baseFee != nil {
		// Compare effective tips if baseFee is specified
		// 如果指定了 baseFee，则比较有效小费。
		if c := a.EffectiveGasTipCmp(b, h.baseFee); c != 0 {
			return c
		}
	}
	// Compare fee caps if baseFee is not specified or effective tips are equal
	// 如果未指定 baseFee 或有效小费相等，则比较费用上限。
	if c := a.GasFeeCapCmp(b); c != 0 {
		return c
	}
	// Compare tips if effective tips and fee caps are equal
	// 如果有效小费和费用上限相等，则比较小费。
	return a.GasTipCapCmp(b)
}

func (h *priceHeap) Push(x interface{}) {
	tx := x.(*types.Transaction)
	h.list = append(h.list, tx)
}

func (h *priceHeap) Pop() interface{} {
	old := h.list
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	h.list = old[0 : n-1]
	return x
}

// pricedList is a price-sorted heap to allow operating on transactions pool
// contents in a price-incrementing way. It's built upon the all transactions
// in txpool but only interested in the remote part. It means only remote transactions
// will be considered for tracking, sorting, eviction, etc.
// pricedList 是一个按价格排序的堆，允许以价格递增的方式操作交易池内容。
// 它基于交易池中的所有交易构建，但只关注远程部分。这意味着只有远程交易才会被考虑用于跟踪、排序、驱逐等。
//
// Two heaps are used for sorting: the urgent heap (based on effective tip in the next
// block) and the floating heap (based on gasFeeCap). Always the bigger heap is chosen for
// eviction. Transactions evicted from the urgent heap are first demoted into the floating heap.
// In some cases (during a congestion, when blocks are full) the urgent heap can provide
// better candidates for inclusion while in other cases (at the top of the baseFee peak)
// the floating heap is better. When baseFee is decreasing they behave similarly.
// 使用两个堆进行排序：紧急堆（基于下一个区块的有效小费）和浮动堆（基于 gasFeeCap）。
// 总是选择较大的堆进行驱逐。从紧急堆驱逐的交易首先降级到浮动堆。
// 在某些情况下（拥塞期间，当区块已满时），紧急堆可以提供更好的包含候选者，而在其他情况下（在 baseFee 峰值的顶部），浮动堆更好。
// 当 baseFee 减少时，它们的行为类似。
type pricedList struct {
	// Number of stale price points to (re-heap trigger).
	stales atomic.Int64

	all *lookup // Pointer to the map of all transactions
	// all 指向所有交易映射的指针。
	urgent, floating priceHeap // Heaps of prices of all the stored **remote** transactions
	// urgent, floating 存储所有 **远程** 交易价格的堆。
	reheapMu sync.Mutex // Mutex asserts that only one routine is reheaping the list
	// reheapMu 互斥锁，确保只有一个例程在重新堆化列表。
}

const (
	// urgentRatio : floatingRatio is the capacity ratio of the two queues
	urgentRatio   = 4
	floatingRatio = 1
)

// newPricedList creates a new price-sorted transaction heap.
// newPricedList 创建一个新的按价格排序的交易堆。
func newPricedList(all *lookup) *pricedList {
	return &pricedList{
		all: all,
	}
}

// Put inserts a new transaction into the heap.
// Put 将一个新交易插入到堆中。
func (l *pricedList) Put(tx *types.Transaction, local bool) {
	if local {
		return
	}
	// Insert every new transaction to the urgent heap first; Discard will balance the heaps
	// 首先将每个新交易插入到紧急堆中；Discard 方法将平衡两个堆。
	heap.Push(&l.urgent, tx)
}

// Removed notifies the prices transaction list that an old transaction dropped
// from the pool. The list will just keep a counter of stale objects and update
// the heap if a large enough ratio of transactions go stale.
// Removed 通知价格交易列表，一个旧交易已从池中删除。列表将只保留一个过时对象计数器，并在足够比例的交易过时时更新堆。
func (l *pricedList) Removed(count int) {
	// Bump the stale counter, but exit if still too low (< 25%)
	// 增加过时计数器，但如果仍然太低（< 25%），则退出。
	stales := l.stales.Add(int64(count))
	if int(stales) <= (len(l.urgent.list)+len(l.floating.list))/4 {
		return
	}
	// Seems we've reached a critical number of stale transactions, reheap
	// 似乎我们已经达到了临界数量的过时交易，重新堆化。
	l.Reheap()
}

// Underpriced checks whether a transaction is cheaper than (or as cheap as) the
// lowest priced (remote) transaction currently being tracked.
// Underpriced 检查一个交易是否比当前跟踪的最低价格（远程）交易更便宜（或一样便宜）。
func (l *pricedList) Underpriced(tx *types.Transaction) bool {
	// Note: with two queues, being underpriced is defined as being worse than the worst item
	// in all non-empty queues if there is any. If both queues are empty then nothing is underpriced.
	// 注意：对于两个队列，价格过低定义为比所有非空队列中最差的项更差（如果存在的话）。如果两个队列都为空，则没有什么是价格过低的。
	return (l.underpricedFor(&l.urgent, tx) || len(l.urgent.list) == 0) &&
		(l.underpricedFor(&l.floating, tx) || len(l.floating.list) == 0) &&
		(len(l.urgent.list) != 0 || len(l.floating.list) != 0)
}

// underpricedFor checks whether a transaction is cheaper than (or as cheap as) the
// lowest priced (remote) transaction in the given heap.
// underpricedFor 检查一个交易是否比给定堆中最低价格（远程）的交易更便宜（或一样便宜）。
func (l *pricedList) underpricedFor(h *priceHeap, tx *types.Transaction) bool {
	// Discard stale price points if found at the heap start
	// 如果在堆的开头找到过时的价格点，则丢弃它们。
	for len(h.list) > 0 {
		head := h.list[0]
		if l.all.GetRemote(head.Hash()) == nil { // Removed or migrated
			l.stales.Add(-1)
			heap.Pop(h)
			continue
		}
		break
	}
	// Check if the transaction is underpriced or not
	// 检查交易是否价格过低。
	if len(h.list) == 0 {
		return false // There is no remote transaction at all.
	}
	// If the remote transaction is even cheaper than the
	// cheapest one tracked locally, reject it.
	// 如果远程交易甚至比本地跟踪的最便宜的交易还要便宜，则拒绝它。
	return h.cmp(h.list[0], tx) >= 0
}

// Discard finds a number of most underpriced transactions, removes them from the
// priced list and returns them for further removal from the entire pool.
// If noPending is set to true, we will only consider the floating list
//
// Note local transaction won't be considered for eviction.
// Discard 找到一些价格最低的交易，将它们从价格列表中删除，并返回它们以便进一步从整个池中删除。
// 如果 noPending 设置为 true，我们将只考虑浮动列表。
//
// 注意，本地交易不会被考虑驱逐。
func (l *pricedList) Discard(slots int, force bool) (types.Transactions, bool) {
	drop := make(types.Transactions, 0, slots) // Remote underpriced transactions to drop
	// 要删除的远程价格过低的交易。
	for slots > 0 {
		if len(l.urgent.list)*floatingRatio > len(l.floating.list)*urgentRatio {
			// Discard stale transactions if found during cleanup
			// 如果在清理过程中发现过时交易，则丢弃它们。
			tx := heap.Pop(&l.urgent).(*types.Transaction)
			if l.all.GetRemote(tx.Hash()) == nil { // Removed or migrated
				l.stales.Add(-1)
				continue
			}
			// Non stale transaction found, move to floating heap
			// 找到非过时交易，移动到浮动堆。
			heap.Push(&l.floating, tx)
		} else {
			if len(l.floating.list) == 0 {
				// Stop if both heaps are empty
				// 如果两个堆都为空，则停止。
				break
			}
			// Discard stale transactions if found during cleanup
			// 如果在清理过程中发现过时交易，则丢弃它们。
			tx := heap.Pop(&l.floating).(*types.Transaction)
			if l.all.GetRemote(tx.Hash()) == nil { // Removed or migrated
				l.stales.Add(-1)
				continue
			}
			// Non stale transaction found, discard it
			// 找到非过时交易，丢弃它。
			drop = append(drop, tx)
			slots -= numSlots(tx)
		}
	}
	// If we still can't make enough room for the new transaction
	// 如果我们仍然无法为新交易腾出足够的空间。
	if slots > 0 && !force {
		for _, tx := range drop {
			heap.Push(&l.urgent, tx)
		}
		return nil, false
	}
	return drop, true
}

// Reheap forcibly rebuilds the heap based on the current remote transaction set.
// Reheap 根据当前的远程交易集合强制重建堆。
func (l *pricedList) Reheap() {
	l.reheapMu.Lock()
	defer l.reheapMu.Unlock()
	start := time.Now()
	l.stales.Store(0)
	l.urgent.list = make([]*types.Transaction, 0, l.all.RemoteCount())
	l.all.Range(func(hash common.Hash, tx *types.Transaction, local bool) bool {
		l.urgent.list = append(l.urgent.list, tx)
		return true
	}, false, true) // Only iterate remotes
	heap.Init(&l.urgent)

	// balance out the two heaps by moving the worse half of transactions into the
	// floating heap
	// 通过将较差的一半交易移动到浮动堆来平衡两个堆。
	// Note: Discard would also do this before the first eviction but Reheap can do
	// is more efficiently. Also, Underpriced would work suboptimally the first time
	// if the floating queue was empty.
	// 注意：Discard 方法在第一次驱逐之前也会这样做，但 Reheap 方法效率更高。
	// 此外，如果浮动队列为空，Underpriced 方法第一次执行时效果不佳。
	floatingCount := len(l.urgent.list) * floatingRatio / (urgentRatio + floatingRatio)
	l.floating.list = make([]*types.Transaction, floatingCount)
	for i := 0; i < floatingCount; i++ {
		l.floating.list[i] = heap.Pop(&l.urgent).(*types.Transaction)
	}
	heap.Init(&l.floating)
	reheapTimer.Update(time.Since(start))
}

// SetBaseFee updates the base fee and triggers a re-heap. Note that Removed is not
// necessary to call right before SetBaseFee when processing a new block.
// SetBaseFee 更新基础费用并触发重新堆化。请注意，在处理新区块时，不必在 SetBaseFee 之前调用 Removed。
func (l *pricedList) SetBaseFee(baseFee *big.Int) {
	l.urgent.baseFee = baseFee
	l.Reheap()
}
