// Copyright 2021 The go-ethereum Authors
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

package tracker

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// 这段代码是 Go-Ethereum p2p 包中的请求跟踪器，用于监控 DevP2P 协议中节点间请求的性能和可靠性。以太坊的 P2P 网络依赖于高效的请求-响应机制（如获取区块头、交易等），而 Tracker 提供了一种测量和调试工具。
//
// 以太坊相关知识点：
// DevP2P：以太坊的点对点网络协议，包含子协议如 eth（以太坊协议）和 les（轻客户端协议）。
// Metrics：Geth 使用 expvar 和 metrics 包收集运行时指标，便于性能分析和故障排查。
// 请求-响应模型：以太坊节点通过 RLPx 传输层发送请求（如 GetBlockHeaders），期待特定响应。

const (
	// trackedGaugeName is the prefix of the per-packet request tracking.
	// trackedGaugeName 是每个数据包请求跟踪的前缀。
	trackedGaugeName = "p2p/tracked"

	// lostMeterName is the prefix of the per-packet request expirations.
	// lostMeterName 是每个数据包请求过期的前缀。
	lostMeterName = "p2p/lost"

	// staleMeterName is the prefix of the per-packet stale responses.
	// staleMeterName 是每个数据包过时响应的前缀。
	staleMeterName = "p2p/stale"

	// waitHistName is the prefix of the per-packet (req only) waiting time histograms.
	// waitHistName 是每个数据包（仅请求）等待时间直方图的前缀。
	waitHistName = "p2p/wait"

	// maxTrackedPackets is a huge number to act as a failsafe on the number of
	// pending requests the node will track. It should never be hit unless an
	// attacker figures out a way to spin requests.
	// maxTrackedPackets 是一个巨大的数字，作为节点跟踪的待处理请求数量的故障保护。
	// 除非攻击者找到一种方法来制造大量请求，否则不应达到此限制。
	maxTrackedPackets = 100000
)

// request tracks sent network requests which have not yet received a response.
// request 跟踪已发送但尚未收到响应的网络请求。
type request struct {
	peer    string // 对等节点标识 / Peer identifier
	version uint   // 协议版本 / Protocol version

	reqCode uint64 // 请求的协议消息代码 / Protocol message code of the request
	resCode uint64 // 预期的响应协议消息代码 / Protocol message code of the expected response

	time   time.Time     // 请求发送时的时间戳 / Timestamp when the request was made
	expire *list.Element // 到期标记，用于取消跟踪 / Expiration marker to untrack it
}

// Tracker is a pending network request tracker to measure how much time it takes
// a remote peer to respond.
// Tracker 是一个待处理的网络请求跟踪器，用于测量远程对等节点响应的时间。
type Tracker struct {
	protocol string        // 协议能力标识，用于指标 / Protocol capability identifier for the metrics
	timeout  time.Duration // 全局超时时间，超过此时间将丢弃跟踪的数据包 / Global timeout after which to drop a tracked packet

	pending map[uint64]*request // 当前待处理的请求 / Currently pending requests
	expire  *list.List          // 跟踪到期顺序的链表 / Linked list tracking the expiration order
	wake    *time.Timer         // 跟踪下一项到期时间的计时器 / Timer tracking the expiration of the next item

	lock sync.Mutex // 保护并发更新的锁 / Lock protecting from concurrent updates
}

// New creates a new network request tracker to monitor how much time it takes to
// fill certain requests and how individual peers perform.
// New 创建一个新的网络请求跟踪器，以监控填充某些请求所需的时间以及各个对等节点的性能。
func New(protocol string, timeout time.Duration) *Tracker {
	return &Tracker{
		protocol: protocol,                  // 设置协议 / Set protocol
		timeout:  timeout,                   // 设置超时时间 / Set timeout
		pending:  make(map[uint64]*request), // 初始化待处理请求映射 / Initialize pending requests map
		expire:   list.New(),                // 初始化到期链表 / Initialize expiration list
	}
}

// Track adds a network request to the tracker to wait for a response to arrive
// or until the request it cancelled or times out.
// Track 将网络请求添加到跟踪器，以等待响应到达，或者直到请求被取消或超时。
func (t *Tracker) Track(peer string, version uint, reqCode uint64, resCode uint64, id uint64) {
	if !metrics.Enabled() { // 如果指标未启用，则返回 / Return if metrics are not enabled
		return
	}
	t.lock.Lock()         // 加锁 / Lock
	defer t.lock.Unlock() // 延迟解锁 / Defer unlock

	// If there's a duplicate request, we've just random-collided (or more probably,
	// we have a bug), report it. We could also add a metric, but we're not really
	// expecting ourselves to be buggy, so a noisy warning should be enough.
	// 如果存在重复请求，可能是随机冲突（或者更可能是代码有 bug），报告它。
	// 我们也可以添加一个指标，但我们不期望自己有 bug，所以一个 noisy 警告就足够了。
	if _, ok := t.pending[id]; ok {
		log.Error("Network request id collision", "protocol", t.protocol, "version", version, "code", reqCode, "id", id)
		// 网络请求 ID 冲突 / Network request ID collision
		return
	}
	// If we have too many pending requests, bail out instead of leaking memory
	// 如果待处理请求过多，则退出以避免内存泄漏
	if pending := len(t.pending); pending >= maxTrackedPackets {
		log.Error("Request tracker exceeded allowance", "pending", pending, "peer", peer, "protocol", t.protocol, "version", version, "code", reqCode)
		// 请求跟踪器超出限额 / Request tracker exceeded allowance
		return
	}
	// Id doesn't exist yet, start tracking it
	// ID 尚不存在，开始跟踪它
	t.pending[id] = &request{
		peer:    peer,                  // 设置对等节点 / Set peer
		version: version,               // 设置版本 / Set version
		reqCode: reqCode,               // 设置请求代码 / Set request code
		resCode: resCode,               // 设置响应代码 / Set response code
		time:    time.Now(),            // 设置当前时间 / Set current time
		expire:  t.expire.PushBack(id), // 将 ID 添加到到期链表 / Add ID to expiration list
	}
	g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, version, reqCode)
	metrics.GetOrRegisterGauge(g, nil).Inc(1) // 增加跟踪指标 / Increment tracking gauge

	// If we've just inserted the first item, start the expiration timer
	// 如果刚插入第一个项，则启动到期计时器
	if t.wake == nil {
		t.wake = time.AfterFunc(t.timeout, t.clean) // 设置超时清理 / Set timeout cleanup
	}
}

// clean is called automatically when a preset time passes without a response
// being delivered for the first network request.
// clean 在预设时间过去而第一个网络请求未收到响应时自动调用。
func (t *Tracker) clean() {
	t.lock.Lock()         // 加锁 / Lock
	defer t.lock.Unlock() // 延迟解锁 / Defer unlock

	// Expire anything within a certain threshold (might be no items at all if
	// we raced with the delivery)
	// 使一定阈值内的任何内容到期（如果与交付竞争，可能根本没有项）
	for t.expire.Len() > 0 {
		// Stop iterating if the next pending request is still alive
		// 如果下一个待处理请求仍然有效，则停止迭代
		var (
			head = t.expire.Front()    // 获取链表头部 / Get list head
			id   = head.Value.(uint64) // 获取 ID / Get ID
			req  = t.pending[id]       // 获取请求 / Get request
		)
		if time.Since(req.time) < t.timeout+5*time.Millisecond {
			break // 如果未超时，则退出 / Break if not timed out
		}
		// Nope, dead, drop it
		// 不，已超时，丢弃它
		t.expire.Remove(head) // 从到期链表移除 / Remove from expiration list
		delete(t.pending, id) // 从待处理映射移除 / Remove from pending map

		g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
		metrics.GetOrRegisterGauge(g, nil).Dec(1) // 减少跟踪指标 / Decrement tracking gauge

		m := fmt.Sprintf("%s/%s/%d/%#02x", lostMeterName, t.protocol, req.version, req.reqCode)
		metrics.GetOrRegisterMeter(m, nil).Mark(1) // 标记丢失指标 / Mark lost meter
	}
	t.schedule() // 重新调度 / Reschedule
}

// schedule starts a timer to trigger on the expiration of the first network
// packet.
// schedule 启动一个计时器，在第一个网络数据包到期时触发。
func (t *Tracker) schedule() {
	if t.expire.Len() == 0 {
		t.wake = nil // 如果没有待处理项，则清空计时器 / Clear timer if no pending items
		return
	}
	t.wake = time.AfterFunc(time.Until(t.pending[t.expire.Front().Value.(uint64)].time.Add(t.timeout)), t.clean)
	// 设置计时器到第一个请求的到期时间 / Set timer to the expiration time of the first request
}

// Fulfil fills a pending request, if any is available, reporting on various metrics.
// Fulfil 填充一个待处理的请求（如果有的话），并报告各种指标。
func (t *Tracker) Fulfil(peer string, version uint, code uint64, id uint64) {
	if !metrics.Enabled() { // 如果指标未启用，则返回 / Return if metrics are not enabled
		return
	}
	t.lock.Lock()         // 加锁 / Lock
	defer t.lock.Unlock() // 延迟解锁 / Defer unlock

	// If it's a non existing request, track as stale response
	// 如果请求不存在，跟踪为过时响应
	req, ok := t.pending[id]
	if !ok {
		m := fmt.Sprintf("%s/%s/%d/%#02x", staleMeterName, t.protocol, version, code)
		metrics.GetOrRegisterMeter(m, nil).Mark(1) // 标记过时指标 / Mark stale meter
		return
	}
	// If the response is funky, it might be some active attack
	// 如果响应异常，可能是某种主动攻击
	if req.peer != peer || req.version != version || req.resCode != code {
		log.Warn("Network response id collision",
			"have", fmt.Sprintf("%s:%s/%d:%d", peer, t.protocol, version, code),
			"want", fmt.Sprintf("%s:%s/%d:%d", peer, t.protocol, req.version, req.resCode),
		)
		// 网络响应 ID 冲突 / Network response ID collision
		return
	}
	// Everything matches, mark the request serviced and meter it
	// 一切匹配，标记请求已服务并计量
	t.expire.Remove(req.expire)   // 从到期链表移除 / Remove from expiration list
	delete(t.pending, id)         // 从待处理映射移除 / Remove from pending map
	if req.expire.Prev() == nil { // 如果这是第一个请求 / If this is the first request
		if t.wake.Stop() { // 停止计时器 / Stop timer
			t.schedule() // 重新调度 / Reschedule
		}
	}
	g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
	metrics.GetOrRegisterGauge(g, nil).Dec(1) // 减少跟踪指标 / Decrement tracking gauge

	h := fmt.Sprintf("%s/%s/%d/%#02x", waitHistName, t.protocol, req.version, req.reqCode)
	sampler := func() metrics.Sample {
		return metrics.ResettingSample(
			metrics.NewExpDecaySample(1028, 0.015), // 创建指数衰减样本 / Create exponential decay sample
		)
	}
	metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(time.Since(req.time).Microseconds())
	// 更新等待时间直方图 / Update wait time histogram
}
