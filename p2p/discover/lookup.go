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

package discover

import (
	"context"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// lookup performs a network search for nodes close to the given target. It approaches the
// target by querying nodes that are closer to it on each iteration. The given target does
// not need to be an actual node identifier.
// lookup 执行网络搜索，查找接近给定目标的节点。它通过在每次迭代中查询更接近目标的节点来接近目标。
// 给定的目标不需要是实际的节点标识符。
type lookup struct {
	tab         *Table             // 节点表
	queryfunc   queryFunc          // 查询函数
	replyCh     chan []*enode.Node // 回复通道
	cancelCh    <-chan struct{}    // 取消通道
	asked, seen map[enode.ID]bool  // 已询问和已看到的节点
	result      nodesByDistance    // 按距离排序的结果
	replyBuffer []*enode.Node      // 回复缓冲区
	queries     int                // 当前查询数量
}

type queryFunc func(*enode.Node) ([]*enode.Node, error) // 查询函数类型定义

func newLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	it := &lookup{
		tab:       tab,                             // 设置节点表
		queryfunc: q,                               // 设置查询函数
		asked:     make(map[enode.ID]bool),         // 初始化已询问节点集合
		seen:      make(map[enode.ID]bool),         // 初始化已看到节点集合
		result:    nodesByDistance{target: target}, // 初始化按距离排序的结果
		replyCh:   make(chan []*enode.Node, alpha), // 创建回复通道，容量为 alpha
		cancelCh:  ctx.Done(),                      // 设置取消通道
		queries:   -1,                              // 初始化查询计数为 -1
	}
	// Don't query further if we hit ourself.
	// Unlikely to happen often in practice.
	// 如果遇到自身，则不再进一步查询。
	// 在实践中不太可能经常发生。
	it.asked[tab.self().ID()] = true
	return it
}

// run runs the lookup to completion and returns the closest nodes found.
// run 运行查找直到完成，并返回找到的最接近的节点。
func (it *lookup) run() []*enode.Node {
	for it.advance() { // 持续推进查找
	}
	return it.result.entries // 返回结果中的节点列表
}

// advance advances the lookup until any new nodes have been found.
// It returns false when the lookup has ended.
// advance 推进查找直到找到任何新节点。
// 当查找结束时返回 false。
func (it *lookup) advance() bool {
	for it.startQueries() { // 启动查询
		select {
		case nodes := <-it.replyCh: // 从回复通道接收节点
			it.replyBuffer = it.replyBuffer[:0] // 清空回复缓冲区
			for _, n := range nodes {           // 处理每个返回的节点
				if n != nil && !it.seen[n.ID()] { // 如果节点非空且未见过
					it.seen[n.ID()] = true                     // 标记为已见过
					it.result.push(n, bucketSize)              // 按距离添加到结果
					it.replyBuffer = append(it.replyBuffer, n) // 添加到缓冲区
				}
			}
			it.queries--                 // 减少查询计数
			if len(it.replyBuffer) > 0 { // 如果缓冲区有新节点
				return true // 表示查找有进展
			}
		case <-it.cancelCh: // 如果收到取消信号
			it.shutdown() // 关闭查找
		}
	}
	return false // 查找结束
}

func (it *lookup) shutdown() {
	for it.queries > 0 { // 等待所有查询完成
		<-it.replyCh
		it.queries--
	}
	it.queryfunc = nil   // 清空查询函数
	it.replyBuffer = nil // 清空缓冲区
}

func (it *lookup) startQueries() bool {
	if it.queryfunc == nil { // 如果查询函数为空
		return false // 停止查询
	}

	// The first query returns nodes from the local table.
	// 第一次查询返回本地表中的节点。
	if it.queries == -1 {
		closest := it.tab.findnodeByID(it.result.target, bucketSize, false) // 从本地表查找接近目标的节点
		// Avoid finishing the lookup too quickly if table is empty. It'd be better to wait
		// for the table to fill in this case, but there is no good mechanism for that
		// yet.
		// 如果表为空，避免过快结束查找。在这种情况下最好等待表填充，但目前还没有好的机制。
		if len(closest.entries) == 0 {
			it.slowdown() // 减慢查找速度
		}
		it.queries = 1                // 设置查询计数
		it.replyCh <- closest.entries // 发送本地节点到回复通道
		return true                   // 表示查询已启动
	}

	// Ask the closest nodes that we haven't asked yet.
	// 询问我们尚未询问的最接近的节点。
	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i] // 获取结果中的节点
		if !it.asked[n.ID()] {    // 如果未询问过
			it.asked[n.ID()] = true    // 标记为已询问
			it.queries++               // 增加查询计数
			go it.query(n, it.replyCh) // 异步执行查询
		}
	}
	// The lookup ends when no more nodes can be asked.
	// 当没有更多节点可询问时，查找结束。
	return it.queries > 0
}

func (it *lookup) slowdown() {
	sleep := time.NewTimer(1 * time.Second) // 创建 1 秒定时器
	defer sleep.Stop()
	select {
	case <-sleep.C: // 等待 1 秒
	case <-it.tab.closeReq: // 如果表关闭
	}
}

func (it *lookup) query(n *enode.Node, reply chan<- []*enode.Node) {
	r, err := it.queryfunc(n)       // 执行查询函数
	if !errors.Is(err, errClosed) { // avoid recording failures on shutdown // 避免在关闭时记录失败
		success := len(r) > 0              // 查询是否成功
		it.tab.trackRequest(n, success, r) // 跟踪请求结果
		if err != nil {
			it.tab.log.Trace("FINDNODE failed", "id", n.ID(), "err", err) // 记录失败日志
		}
	}
	reply <- r // 将结果发送到回复通道
}

// lookupIterator performs lookup operations and iterates over all seen nodes.
// When a lookup finishes, a new one is created through nextLookup.
// lookupIterator 执行查找操作并迭代所有看到的节点。
// 当一个查找完成时，通过 nextLookup 创建一个新的查找。
type lookupIterator struct {
	buffer     []*enode.Node   // 节点缓冲区
	nextLookup lookupFunc      // 下一次查找函数
	ctx        context.Context // 上下文
	cancel     func()          // 取消函数
	lookup     *lookup         // 当前查找实例
}

type lookupFunc func(ctx context.Context) *lookup // 查找函数类型定义

func newLookupIterator(ctx context.Context, next lookupFunc) *lookupIterator {
	ctx, cancel := context.WithCancel(ctx) // 创建可取消的上下文
	return &lookupIterator{ctx: ctx, cancel: cancel, nextLookup: next}
}

// Node returns the current node.
// Node 返回当前节点。
func (it *lookupIterator) Node() *enode.Node {
	if len(it.buffer) == 0 { // 如果缓冲区为空
		return nil
	}
	return it.buffer[0] // 返回缓冲区第一个节点
}

// Next moves to the next node.
// Next 移动到下一个节点。
func (it *lookupIterator) Next() bool {
	// Consume next node in buffer.
	// 消费缓冲区中的下一个节点。
	if len(it.buffer) > 0 {
		it.buffer = it.buffer[1:] // 移除第一个节点
	}
	// Advance the lookup to refill the buffer.
	// 推进查找以重新填充缓冲区。
	for len(it.buffer) == 0 {
		if it.ctx.Err() != nil { // 如果上下文已取消
			it.lookup = nil
			it.buffer = nil
			return false
		}
		if it.lookup == nil { // 如果当前没有查找
			it.lookup = it.nextLookup(it.ctx) // 创建新查找
			continue
		}
		if !it.lookup.advance() { // 如果当前查找无进展
			it.lookup = nil // 清空当前查找
			continue
		}
		it.buffer = it.lookup.replyBuffer // 更新缓冲区
	}
	return true // 表示还有节点可迭代
}

// Close ends the iterator.
// Close 结束迭代器。
func (it *lookupIterator) Close() {
	it.cancel() // 取消上下文
}
