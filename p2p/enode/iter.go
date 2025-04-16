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

package enode

import (
	"sync"
	"time"
)

// 节点发现协议 (EIP-8): 以太坊使用 UDP 发现协议（如 Discv4）查找对等节点，迭代器在此过程中管理节点列表。
//
// Kademlia DHT: FairMix 的公平分发与 Kademlia 的节点查找逻辑相辅相成，确保查询覆盖多个桶（buckets）。
//
// ENR (EIP-778): 节点序列号用于更新判断，与 ReadNodes 的去重逻辑相关。

// Iterator represents a sequence of nodes. The Next method moves to the next node in the
// sequence. It returns false when the sequence has ended or the iterator is closed. Close
// may be called concurrently with Next and Node, and interrupts Next if it is blocked.
//
// Iterator 表示节点序列。Next 方法移动到序列中的下一个节点，
// 当序列结束或迭代器关闭时返回 false。Close 可与 Next 和 Node 并发调用，
// 并在 Next 阻塞时中断它。
type Iterator interface {
	Next() bool  // moves to next node // 移动到下一个节点
	Node() *Node // returns current node // 返回当前节点
	Close()      // ends the iterator // 结束迭代器
}

// ReadNodes reads at most n nodes from the given iterator. The return value contains no
// duplicates and no nil values. To prevent looping indefinitely for small repeating node
// sequences, this function calls Next at most n times.
//
// ReadNodes 从给定迭代器中读取最多 n 个节点。返回值不包含重复项和 nil 值。
// 为防止在小型重复节点序列上无限循环，此函数最多调用 Next n 次。
func ReadNodes(it Iterator, n int) []*Node {
	seen := make(map[ID]*Node, n)         // 用于跟踪已见节点，防止重复
	for i := 0; i < n && it.Next(); i++ { // 最多读取 n 个节点
		// Remove duplicates, keeping the node with higher seq.
		// 移除重复项，保留序列号较高的节点。
		node := it.Node()
		prevNode, ok := seen[node.ID()]
		if ok && prevNode.Seq() > node.Seq() { // 如果已有节点且序列号更高，则跳过
			continue
		}
		seen[node.ID()] = node // 更新或添加节点
	}
	result := make([]*Node, 0, len(seen)) // 创建结果切片
	for _, node := range seen {           // 将所有节点添加到结果中
		result = append(result, node)
	}
	return result
}

// IterNodes makes an iterator which runs through the given nodes once.
// IterNodes 创建一个迭代器，单次遍历给定节点。
func IterNodes(nodes []*Node) Iterator {
	return &sliceIter{nodes: nodes, index: -1} // 返回基于切片的迭代器
}

// CycleNodes makes an iterator which cycles through the given nodes indefinitely.
// CycleNodes 创建一个迭代器，无限循环遍历给定节点。
func CycleNodes(nodes []*Node) Iterator {
	return &sliceIter{nodes: nodes, index: -1, cycle: true} // 返回循环迭代器
}

type sliceIter struct {
	mu    sync.Mutex // 互斥锁，确保线程安全
	nodes []*Node    // 节点列表
	index int        // 当前索引
	cycle bool       // 是否循环
}

func (it *sliceIter) Next() bool {
	it.mu.Lock()         // 加锁
	defer it.mu.Unlock() // 延迟解锁

	if len(it.nodes) == 0 { // 如果节点列表为空，返回 false
		return false
	}
	it.index++                     // 索引递增
	if it.index == len(it.nodes) { // 如果到达末尾
		if it.cycle { // 如果是循环模式，重置索引
			it.index = 0
		} else { // 否则清空节点列表并结束
			it.nodes = nil
			return false
		}
	}
	return true
}

func (it *sliceIter) Node() *Node {
	it.mu.Lock()            // 加锁
	defer it.mu.Unlock()    // 延迟解锁
	if len(it.nodes) == 0 { // 如果节点列表为空，返回 nil
		return nil
	}
	return it.nodes[it.index] // 返回当前节点
}

func (it *sliceIter) Close() {
	it.mu.Lock()         // 加锁
	defer it.mu.Unlock() // 延迟解锁

	it.nodes = nil // 清空节点列表，结束迭代
}

// Filter wraps an iterator such that Next only returns nodes for which
// the 'check' function returns true.
//
// Filter 包装一个迭代器，使 Next 只返回 'check' 函数返回 true 的节点。
func Filter(it Iterator, check func(*Node) bool) Iterator {
	return &filterIter{it, check} // 返回过滤迭代器
}

type filterIter struct {
	Iterator                  // 嵌入基础迭代器
	check    func(*Node) bool // 过滤条件函数
}

func (f *filterIter) Next() bool {
	for f.Iterator.Next() { // 遍历基础迭代器
		if f.check(f.Node()) { // 如果节点满足条件，返回 true
			return true
		}
	}
	return false // 没有更多满足条件的节点
}

// FairMix aggregates multiple node iterators. The mixer itself is an iterator which ends
// only when Close is called. Source iterators added via AddSource are removed from the
// mix when they end.
//
// The distribution of nodes returned by Next is approximately fair, i.e. FairMix
// attempts to draw from all sources equally often. However, if a certain source is slow
// and doesn't return a node within the configured timeout, a node from any other source
// will be returned.
//
// It's safe to call AddSource and Close concurrently with Next.
//
// FairMix 聚合多个节点迭代器。混合器本身是一个迭代器，仅在调用 Close 时结束。
// 通过 AddSource 添加的源迭代器在结束时从混合中移除。
//
// Next 返回的节点分布近似公平，即 FairMix 尝试从所有源中均匀抽取。
// 但如果某个源较慢，未能在配置的超时时间内返回节点，则从其他源返回节点。
//
// AddSource 和 Close 可与 Next 并发调用。
type FairMix struct {
	wg      sync.WaitGroup // 等待组，同步源 goroutine
	fromAny chan *Node     // 从任意源获取节点的通道
	timeout time.Duration  // 超时时间
	cur     *Node          // 当前节点

	mu      sync.Mutex    // 互斥锁，保护 sources
	closed  chan struct{} // 关闭信号通道
	sources []*mixSource  // 源列表
	last    int           // 上次选择的源索引
}

type mixSource struct {
	it      Iterator      // 源迭代器
	next    chan *Node    // 源的下一个节点通道
	timeout time.Duration // 源的超时时间
}

// NewFairMix creates a mixer.
//
// The timeout specifies how long the mixer will wait for the next fairly-chosen source
// before giving up and taking a node from any other source. A good way to set the timeout
// is deciding how long you'd want to wait for a node on average. Passing a negative
// timeout makes the mixer completely fair.
//
// NewFairMix 创建一个混合器。
//
// timeout 指定混合器在放弃公平选择的下一个源并从任意源获取节点前等待的时间。
// 设置 timeout 的一种好方法是决定你平均愿意等待节点多久。传入负值 timeout 使混合器完全公平。
func NewFairMix(timeout time.Duration) *FairMix {
	m := &FairMix{
		fromAny: make(chan *Node),    // 初始化任意源通道
		closed:  make(chan struct{}), // 初始化关闭通道
		timeout: timeout,             // 设置超时时间
	}
	return m
}

// AddSource adds a source of nodes.
// AddSource 添加一个节点源。
func (m *FairMix) AddSource(it Iterator) {
	m.mu.Lock()         // 加锁
	defer m.mu.Unlock() // 延迟解锁

	if m.closed == nil { // 如果已关闭，返回
		return
	}
	m.wg.Add(1)                                           // 增加等待计数
	source := &mixSource{it, make(chan *Node), m.timeout} // 创建新源
	m.sources = append(m.sources, source)                 // 添加到源列表
	go m.runSource(m.closed, source)                      // 启动源处理 goroutine
}

// Close shuts down the mixer and all current sources.
// Calling this is required to release resources associated with the mixer.
//
// Close 关闭混合器及其所有当前源。
// 调用此方法是释放混合器相关资源的必要步骤。
func (m *FairMix) Close() {
	m.mu.Lock()         // 加锁
	defer m.mu.Unlock() // 延迟解锁

	if m.closed == nil { // 如果已关闭，返回
		return
	}
	for _, s := range m.sources { // 关闭所有源迭代器
		s.it.Close()
	}
	close(m.closed)  // 发送关闭信号
	m.wg.Wait()      // 等待所有源 goroutine 结束
	close(m.fromAny) // 关闭任意源通道
	m.sources = nil  // 清空源列表
	m.closed = nil   // 标记已关闭
}

// Next returns a node from a random source.
// Next 从随机源返回一个节点。
func (m *FairMix) Next() bool {
	m.cur = nil // 重置当前节点

	for { // 无限循环直到成功获取节点或结束
		source := m.pickSource() // 选择下一个源
		if source == nil {       // 如果没有源，从任意通道获取
			return m.nextFromAny()
		}

		var timeout <-chan time.Time // 超时通道
		if source.timeout >= 0 {     // 如果超时非负，设置定时器
			timer := time.NewTimer(source.timeout)
			timeout = timer.C
			defer timer.Stop()
		}

		select { // 选择操作
		case n, ok := <-source.next: // 从源获取节点
			if ok {
				// Here, the timeout is reset to the configured value
				// because the source delivered a node.
				// 这里将超时重置为配置值，因为源成功提供了节点。
				source.timeout = m.timeout
				m.cur = n // 设置当前节点
				return true
			}
			// This source has ended.
			// 此源已结束。
			m.deleteSource(source) // 删除结束的源
		case <-timeout: // 超时触发
			// The selected source did not deliver a node within the timeout, so the
			// timeout duration is halved for next time. This is supposed to improve
			// latency with stuck sources.
			// 选择的源未能在超时时间内提供节点，因此下次超时时间减半，以改善卡住源的延迟。
			source.timeout /= 2
			return m.nextFromAny() // 从任意源获取
		}
	}
}

// Node returns the current node.
// Node 返回当前节点。
func (m *FairMix) Node() *Node {
	return m.cur // 返回当前节点
}

// nextFromAny is used when there are no sources or when the 'fair' choice
// doesn't turn up a node quickly enough.
//
// nextFromAny 在没有源或公平选择未及时返回节点时使用。
func (m *FairMix) nextFromAny() bool {
	n, ok := <-m.fromAny // 从任意通道获取节点
	if ok {
		m.cur = n // 设置当前节点
	}
	return ok
}

// pickSource chooses the next source to read from, cycling through them in order.
// pickSource 按顺序选择下一个要读取的源。
func (m *FairMix) pickSource() *mixSource {
	m.mu.Lock()         // 加锁
	defer m.mu.Unlock() // 延迟解锁

	if len(m.sources) == 0 { // 如果没有源，返回 nil
		return nil
	}
	m.last = (m.last + 1) % len(m.sources) // 循环选择下一个索引
	return m.sources[m.last]               // 返回选择的源
}

// deleteSource deletes a source.
// deleteSource 删除一个源。
func (m *FairMix) deleteSource(s *mixSource) {
	m.mu.Lock()         // 加锁
	defer m.mu.Unlock() // 延迟解锁

	for i := range m.sources { // 查找并删除指定源
		if m.sources[i] == s {
			copy(m.sources[i:], m.sources[i+1:])
			m.sources[len(m.sources)-1] = nil
			m.sources = m.sources[:len(m.sources)-1]
			break
		}
	}
}

// runSource reads a single source in a loop.
// runSource 在循环中读取单个源。
func (m *FairMix) runSource(closed chan struct{}, s *mixSource) {
	defer m.wg.Done()   // 减少等待计数
	defer close(s.next) // 关闭源通道
	for s.it.Next() {   // 遍历源迭代器
		n := s.it.Node() // 获取节点
		select {         // 选择操作
		case s.next <- n: // 发送到源通道
		case m.fromAny <- n: // 发送到任意通道
		case <-closed: // 如果关闭信号触发，退出
			return
		}
	}
}
