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

package p2p

import (
	"container/heap"

	"github.com/ethereum/go-ethereum/common/mclock"
)

// 拨号历史管理
//  在以太坊的 P2P 网络中，节点通过 dialScheduler 管理出站连接。为避免频繁重拨同一节点（如连接失败后立即重试），使用类似 expHeap 的结构记录最近拨号的节点 ID 及其过期时间（通常为几秒到几分钟）。
// Kademlia DHT 与节点发现
//  以太坊使用 Kademlia 分布式哈希表（DHT）进行节点发现。expHeap 可用于限制对同一节点的重复查询或拨号，减轻网络负载。
// 时间管理（mclock.AbsTime）
//  mclock.AbsTime 是以太坊 go-ethereum 中使用的绝对时间类型，通常与 mclock.Clock 接口结合，提供可测试的时间管理（支持模拟时间）。

// expHeap tracks strings and their expiry time.
// expHeap 跟踪字符串及其过期时间。
type expHeap []expItem

// expItem is an entry in addrHistory.
// expItem 是 addrHistory 中的一个条目。
type expItem struct {
	item string
	exp  mclock.AbsTime
}

// nextExpiry returns the next expiry time.
// nextExpiry 返回下一个过期时间。
func (h *expHeap) nextExpiry() mclock.AbsTime {
	return (*h)[0].exp
}

// add adds an item and sets its expiry time.
// add 添加一个项目并设置其过期时间。
func (h *expHeap) add(item string, exp mclock.AbsTime) {
	heap.Push(h, expItem{item, exp})
}

// contains checks whether an item is present.
// contains 检查某个项目是否存在。
func (h expHeap) contains(item string) bool {
	for _, v := range h {
		if v.item == item {
			return true
		}
	}
	return false
}

// expire removes items with expiry time before 'now'.
// expire 移除过期时间早于 'now' 的项目。
func (h *expHeap) expire(now mclock.AbsTime, onExp func(string)) {
	for h.Len() > 0 && h.nextExpiry() < now {
		item := heap.Pop(h)
		if onExp != nil {
			onExp(item.(expItem).item)
		}
	}
}

// heap.Interface boilerplate
// heap.Interface 的样板代码
func (h expHeap) Len() int            { return len(h) }
func (h expHeap) Less(i, j int) bool  { return h[i].exp < h[j].exp }
func (h expHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *expHeap) Push(x interface{}) { *h = append(*h, x.(expItem)) }
func (h *expHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = expItem{}
	*h = old[0 : n-1]
	return x
}
