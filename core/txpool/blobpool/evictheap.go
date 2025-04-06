// Copyright 2023 The go-ethereum Authors
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

package blobpool

import (
	"container/heap"
	"math"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"golang.org/x/exp/maps"
)

// 交易池、Blob 交易和驱逐
//
// 在以太坊节点中，交易在被打包到区块之前会先进入一个交易池 (Transaction Pool 或 Mempool)。对于引入了 Blob 交易的 EIP-4844 来说，存在一个专门的 Blob 池用于存储包含 Blob 的交易。当 Blob 池达到容量限制时，节点需要一种策略来决定哪些交易应该被驱逐 (evicted) 以腾出空间给新的交易。
//
// evictHeap 的目的是帮助交易池管理器决定应该从哪个账户驱逐 Blob 交易。它通过跟踪每个账户最便宜的“瓶颈”交易来实现这一点。这里的“瓶颈”指的是那些因为费用不够高而难以被打包到区块中的交易。
//
// evictHeap 结构体的作用
//
// evictHeap 是一个基于堆数据结构的实现，用于维护一个按驱逐优先级排序的账户列表。优先级高的账户（即具有更便宜的瓶颈交易）会更早地被考虑驱逐其交易。

// EIP-4844 (Blob 交易): evictHeap 的出现与 EIP-4844 引入的 Blob 交易密切相关。Blob 交易包含大量额外数据，需要专门的池来管理。
// 交易池管理: evictHeap 是交易池管理策略的一部分，用于在资源紧张时决定如何清理池中的交易。
// 费用市场: 以太坊的费用市场机制（包括基础费和 Blob 费）直接影响交易的优先级。evictHeap 通过考虑这些费用来确定哪些交易应该被驱逐。
// 驱逐策略: 当 Blob 池过饱和时，驱逐策略的目标通常是移除那些费用较低、不太可能被矿工打包的交易，从而为更高费用的交易腾出空间。evictHeap 通过跟踪每个账户最便宜的交易来实现这个目标。
// 瓶颈交易: “瓶颈交易”指的是一个账户中费用最低的交易，它可能会阻止该账户中其他费用较高的交易被打包。通过关注这些瓶颈交易，evictHeap 可以更有效地选择要驱逐的账户。

// evictHeap is a helper data structure to keep track of the cheapest bottleneck
// transaction from each account to determine which account to evict from.
// evictHeap 是一个辅助数据结构，用于跟踪每个账户最便宜的瓶颈交易，以确定要从哪个账户驱逐交易。
//
// The heap internally tracks a slice of cheapest transactions from each account
// and a mapping from addresses to indices for direct removals/updates.
// 堆内部跟踪每个账户最便宜的交易切片以及从地址到索引的映射，以便直接删除/更新。
//
// The goal of the heap is to decide which account has the worst bottleneck to
// evict transactions from.
// 堆的目标是决定哪个账户的瓶颈最严重，从而驱逐该账户的交易。
type evictHeap struct {
	metas map[common.Address][]*blobTxMeta // Pointer to the blob pool's index for price retrievals
	// metas 指向 blob 池索引的指针，用于价格检索。

	basefeeJumps float64 // Pre-calculated absolute dynamic fee jumps for the base fee
	// basefeeJumps 预先计算的基础费用绝对动态费用跳跃值。
	blobfeeJumps float64 // Pre-calculated absolute dynamic fee jumps for the blob fee
	// blobfeeJumps 预先计算的 blob 费用绝对动态费用跳跃值。

	addrs []common.Address // Heap of addresses to retrieve the cheapest out of
	// addrs 用于检索最便宜交易的地址堆。
	index map[common.Address]int // Indices into the heap for replacements
	// index 用于替换的堆中地址的索引。
}

// newPriceHeap creates a new heap of cheapest accounts in the blob pool to evict
// from in case of over saturation.
// newPriceHeap 在 blob 池中创建一个新的最便宜账户堆，以便在过饱和的情况下驱逐交易。
func newPriceHeap(basefee *uint256.Int, blobfee *uint256.Int, index map[common.Address][]*blobTxMeta) *evictHeap {
	// newPriceHeap 函数创建一个新的 evictHeap 实例。
	heap := &evictHeap{
		metas: index,
		index: make(map[common.Address]int, len(index)),
	}
	// Populate the heap in account sort order. Not really needed in practice,
	// but it makes the heap initialization deterministic and less annoying to
	// test in unit tests.
	// 以账户排序顺序填充堆。实际上并不需要，但它使堆初始化具有确定性，并且在单元测试中更容易测试。
	heap.addrs = maps.Keys(index)
	slices.SortFunc(heap.addrs, common.Address.Cmp)
	for i, addr := range heap.addrs {
		heap.index[addr] = i
	}
	heap.reinit(basefee, blobfee, true)
	return heap
}

// reinit updates the pre-calculated dynamic fee jumps in the price heap and runs
// the sorting algorithm from scratch on the entire heap.
// reinit 更新价格堆中预先计算的动态费用跳跃值，并对整个堆从头开始运行排序算法。
func (h *evictHeap) reinit(basefee *uint256.Int, blobfee *uint256.Int, force bool) {
	// reinit 方法重新初始化价格堆，更新动态费用跳跃值并重新排序。
	// If the update is mostly the same as the old, don't sort pointlessly
	// 如果更新与旧的几乎相同，则不要进行无谓的排序。
	basefeeJumps := dynamicFeeJumps(basefee)
	blobfeeJumps := dynamicFeeJumps(blobfee)

	if !force && math.Abs(h.basefeeJumps-basefeeJumps) < 0.01 && math.Abs(h.blobfeeJumps-blobfeeJumps) < 0.01 { // TODO(karalabe): 0.01 enough, maybe should be smaller? Maybe this optimization is moot?
		return
	}
	// One or both of the dynamic fees jumped, resort the pool
	// 一个或两个动态费用发生跳跃，重新排序池。
	h.basefeeJumps = basefeeJumps
	h.blobfeeJumps = blobfeeJumps

	heap.Init(h)
}

// Len implements sort.Interface as part of heap.Interface, returning the number
// of accounts in the pool which can be considered for eviction.
// Len 实现了 sort.Interface 作为 heap.Interface 的一部分，返回池中可以考虑驱逐的账户数量。
func (h *evictHeap) Len() int {
	// Len 方法返回堆中地址的数量。
	return len(h.addrs)
}

// Less implements sort.Interface as part of heap.Interface, returning which of
// the two requested accounts has a cheaper bottleneck.
// Less 实现了 sort.Interface 作为 heap.Interface 的一部分，返回两个请求的账户中哪个的瓶颈更便宜。
func (h *evictHeap) Less(i, j int) bool {
	// Less 方法比较堆中两个地址对应的最便宜交易的驱逐优先级。
	txsI := h.metas[h.addrs[i]]
	txsJ := h.metas[h.addrs[j]]

	lastI := txsI[len(txsI)-1]
	lastJ := txsJ[len(txsJ)-1]

	prioI := evictionPriority(h.basefeeJumps, lastI.evictionExecFeeJumps, h.blobfeeJumps, lastI.evictionBlobFeeJumps)
	if prioI > 0 {
		prioI = 0
	}
	prioJ := evictionPriority(h.basefeeJumps, lastJ.evictionExecFeeJumps, h.blobfeeJumps, lastJ.evictionBlobFeeJumps)
	if prioJ > 0 {
		prioJ = 0
	}
	if prioI == prioJ {
		return lastI.evictionExecTip.Lt(lastJ.evictionExecTip)
	}
	return prioI < prioJ
}

// Swap implements sort.Interface as part of heap.Interface, maintaining both the
// order of the accounts according to the heap, and the account->item slot mapping
// for replacements.
// Swap 实现了 sort.Interface 作为 heap.Interface 的一部分，维护堆中账户的顺序以及用于替换的账户->项目槽位映射。
func (h *evictHeap) Swap(i, j int) {
	// Swap 方法交换堆中两个地址的位置，并更新索引映射。
	h.index[h.addrs[i]], h.index[h.addrs[j]] = h.index[h.addrs[j]], h.index[h.addrs[i]]
	h.addrs[i], h.addrs[j] = h.addrs[j], h.addrs[i]
}

// Push implements heap.Interface, appending an item to the end of the account
// ordering as well as the address to item slot mapping.
// Push 实现了 heap.Interface，将一个项目追加到账户排序的末尾以及地址到项目槽位映射。
func (h *evictHeap) Push(x any) {
	h.index[x.(common.Address)] = len(h.addrs)
	h.addrs = append(h.addrs, x.(common.Address))
}

// Pop implements heap.Interface, removing and returning the last element of the
// heap.
// Pop 实现了 heap.Interface，移除并返回堆的最后一个元素。
//
// Note, use `heap.Pop`, not `evictHeap.Pop`. This method is used by Go's heap,
// to provide the functionality, it does not embed it.
// 注意，使用 `heap.Pop`，而不是 `evictHeap.Pop`。此方法由 Go 的 heap 包使用，以提供功能，它不嵌入该功能。
func (h *evictHeap) Pop() any {
	// Pop 方法从堆中移除并返回优先级最高的地址（最便宜的瓶颈）。
	// Remove the last element from the heap
	size := len(h.addrs)
	addr := h.addrs[size-1]
	h.addrs = h.addrs[:size-1]

	// Unindex the removed element and return
	delete(h.index, addr)
	return addr
}
