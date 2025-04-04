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

package discover

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

const never = mclock.AbsTime(math.MaxInt64) // Represents a time that never occurs / 表示永不发生的时间

const slowRevalidationFactor = 3 // Factor to slow down revalidation for stable nodes / 用于减慢稳定节点重新验证的因子

// tableRevalidation implements the node revalidation process.
// It tracks all nodes contained in Table, and schedules sending PING to them.
// tableRevalidation 实现了节点重新验证过程。
// 它跟踪 Table 中包含的所有节点，并调度向它们发送 PING。
type tableRevalidation struct {
	fast      revalidationList      // Fast revalidation list for new/unstable nodes / 快速重新验证列表，用于新节点或不稳定节点
	slow      revalidationList      // Slow revalidation list for stable nodes / 慢速重新验证列表，用于稳定节点
	activeReq map[enode.ID]struct{} // Tracks nodes with active revalidation requests / 跟踪具有活跃重新验证请求的节点
}

type revalidationResponse struct {
	n          *tableNode  // Node being revalidated / 被重新验证的节点
	newRecord  *enode.Node // Updated ENR if available / 如果可用，则为更新的 ENR
	didRespond bool        // Whether the node responded to ping / 节点是否响应了 ping
}

func (tr *tableRevalidation) init(cfg *Config) {
	tr.activeReq = make(map[enode.ID]struct{})                   // Initialize active request map / 初始化活跃请求映射
	tr.fast.nextTime = never                                     // Set fast list next time to never / 将快速列表的下次时间设置为永不
	tr.fast.interval = cfg.PingInterval                          // Set fast list interval / 设置快速列表间隔
	tr.fast.name = "fast"                                        // Name the fast list / 命名快速列表
	tr.slow.nextTime = never                                     // Set slow list next time to never / 将慢速列表的下次时间设置为永不
	tr.slow.interval = cfg.PingInterval * slowRevalidationFactor // Set slow list interval / 设置慢速列表间隔
	tr.slow.name = "slow"                                        // Name the slow list / 命名慢速列表
}

// nodeAdded is called when the table receives a new node.
// nodeAdded 在表接收到新节点时被调用。
func (tr *tableRevalidation) nodeAdded(tab *Table, n *tableNode) {
	tr.fast.push(n, tab.cfg.Clock.Now(), &tab.rand) // Add new node to fast list / 将新节点添加到快速列表
}

// nodeRemoved is called when a node was removed from the table.
// nodeRemoved 在节点从表中移除时被调用。
func (tr *tableRevalidation) nodeRemoved(n *tableNode) {
	if n.revalList == nil {
		panic(fmt.Errorf("removed node %v has nil revalList", n.ID())) // Panic if list is nil / 如果列表为空则抛出异常
	}
	n.revalList.remove(n) // Remove node from its list / 从其列表中移除节点
}

// nodeEndpointChanged is called when a change in IP or port is detected.
// nodeEndpointChanged 在检测到 IP 或端口更改时被调用。
func (tr *tableRevalidation) nodeEndpointChanged(tab *Table, n *tableNode) {
	n.isValidatedLive = false                                  // Mark as unvalidated / 标记为未验证
	tr.moveToList(&tr.fast, n, tab.cfg.Clock.Now(), &tab.rand) // Move to fast list / 移动到快速列表
}

// run performs node revalidation.
// It returns the next time it should be invoked, which is used in the Table main loop
// to schedule a timer. However, run can be called at any time.
// run 执行节点重新验证。
// 它返回下次应调用的时间，用于 Table 主循环中调度定时器。但 run 可随时调用。
func (tr *tableRevalidation) run(tab *Table, now mclock.AbsTime) (nextTime mclock.AbsTime) {
	reval := func(list *revalidationList) {
		if list.nextTime <= now { // If it's time to revalidate / 如果到了重新验证的时间
			if n := list.get(now, &tab.rand, tr.activeReq); n != nil { // Get a node to revalidate / 获取一个要重新验证的节点
				tr.startRequest(tab, n) // Start revalidation / 开始重新验证
			}
			// Update nextTime regardless if any requests were started because
			// current value has passed.
			// 无论是否启动了请求，都更新 nextTime，因为当前值已过去。
			list.schedule(now, &tab.rand) // Schedule next revalidation / 调度下次重新验证
		}
	}
	reval(&tr.fast) // Revalidate fast list / 重新验证快速列表
	reval(&tr.slow) // Revalidate slow list / 重新验证慢速列表

	return min(tr.fast.nextTime, tr.slow.nextTime) // Return earliest next time / 返回最早的下次时间
}

// startRequest spawns a revalidation request for node n.
// startRequest 为节点 n 启动重新验证请求。
func (tr *tableRevalidation) startRequest(tab *Table, n *tableNode) {
	if _, ok := tr.activeReq[n.ID()]; ok {
		panic(fmt.Errorf("duplicate startRequest (node %v)", n.ID())) // Panic on duplicate / 如果重复则抛出异常
	}
	tr.activeReq[n.ID()] = struct{}{}  // Mark as active / 标记为活跃
	resp := revalidationResponse{n: n} // Prepare response / 准备响应

	// Fetch the node while holding lock.
	// 在持有锁时获取节点。
	tab.mutex.Lock()
	node := n.Node
	tab.mutex.Unlock()

	go tab.doRevalidate(resp, node) // Start revalidation in goroutine / 在 goroutine 中启动重新验证
}

func (tab *Table) doRevalidate(resp revalidationResponse, node *enode.Node) {
	// Ping the selected node and wait for a pong response.
	// Ping 选定的节点并等待 pong 响应。
	remoteSeq, err := tab.net.ping(node)
	resp.didRespond = err == nil // Set response status / 设置响应状态

	// Also fetch record if the node replied and returned a higher sequence number.
	// 如果节点回复并返回更高的序列号，则还获取记录。
	if remoteSeq > node.Seq() {
		newrec, err := tab.net.RequestENR(node) // Request updated ENR / 请求更新的 ENR
		if err != nil {
			tab.log.Debug("ENR request failed", "id", node.ID(), "err", err) // Log failure / 记录失败
		} else {
			resp.newRecord = newrec // Store new record / 存储新记录
		}
	}

	select {
	case tab.revalResponseCh <- resp: // Send response to channel / 将响应发送到通道
	case <-tab.closed: // Exit if table closed / 如果表关闭则退出
	}
}

// handleResponse processes the result of a revalidation request.
// handleResponse 处理重新验证请求的结果。
func (tr *tableRevalidation) handleResponse(tab *Table, resp revalidationResponse) {
	var (
		now = tab.cfg.Clock.Now() // Current time / 当前时间
		n   = resp.n              // Node being processed / 被处理的节点
		b   = tab.bucket(n.ID())  // Bucket containing node / 包含节点的桶
	)
	delete(tr.activeReq, n.ID()) // Remove from active requests / 从活跃请求中移除

	// If the node was removed from the table while getting checked, we need to stop
	// processing here to avoid re-adding it.
	// 如果节点在检查时已从表中移除，则需停止处理以避免重新添加。
	if n.revalList == nil {
		return
	}

	// Store potential seeds in database.
	// This is done via defer to avoid holding Table lock while writing to DB.
	// 将潜在种子存储到数据库中。
	// 通过 defer 执行，以避免在写入数据库时持有 Table 锁。
	defer func() {
		if n.isValidatedLive && n.livenessChecks > 5 { // If node is live and stable / 如果节点存活且稳定
			tab.db.UpdateNode(resp.n.Node) // Update in database / 更新到数据库
		}
	}()

	// Remaining logic needs access to Table internals.
	// 剩余逻辑需要访问 Table 内部。
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	if !resp.didRespond { // If node didn't respond / 如果节点未响应
		n.livenessChecks /= 3      // Reduce liveness score / 减少存活分数
		if n.livenessChecks <= 0 { // If score drops to zero / 如果分数降至零
			tab.deleteInBucket(b, n.ID()) // Remove from table / 从表中移除
		} else {
			tab.log.Debug("Node revalidation failed", "b", b.index, "id", n.ID(), "checks", n.livenessChecks, "q", n.revalList.name) // Log failure / 记录失败
			tr.moveToList(&tr.fast, n, now, &tab.rand)                                                                               // Move to fast list / 移动到快速列表
		}
		return
	}

	// The node responded.
	// 节点已响应。
	n.livenessChecks++                                                                                               // Increment liveness score / 增加存活分数
	n.isValidatedLive = true                                                                                         // Mark as validated / 标记为已验证
	tab.log.Debug("Node revalidated", "b", b.index, "id", n.ID(), "checks", n.livenessChecks, "q", n.revalList.name) // Log success / 记录成功
	var endpointChanged bool
	if resp.newRecord != nil { // If new ENR received / 如果收到新 ENR
		_, endpointChanged = tab.bumpInBucket(b, resp.newRecord, false) // Update bucket / 更新桶
	}

	// Node moves to slow list if it passed and hasn't changed.
	// 如果节点通过且未更改，则移动到慢速列表。
	if !endpointChanged {
		tr.moveToList(&tr.slow, n, now, &tab.rand) // Move to slow list / 移动到慢速列表
	}
}

// moveToList ensures n is in the 'dest' list.
// moveToList 确保 n 在目标列表中。
func (tr *tableRevalidation) moveToList(dest *revalidationList, n *tableNode, now mclock.AbsTime, rand randomSource) {
	if n.revalList == dest { // If already in destination / 如果已在目标列表
		return
	}
	if n.revalList != nil { // If in another list / 如果在另一个列表中
		n.revalList.remove(n) // Remove from current list / 从当前列表移除
	}
	dest.push(n, now, rand) // Add to destination list / 添加到目标列表
}

// revalidationList holds a list nodes and the next revalidation time.
// revalidationList 保存节点列表和下次重新验证时间。
type revalidationList struct {
	nodes    []*tableNode   // List of nodes / 节点列表
	nextTime mclock.AbsTime // Next revalidation time / 下次重新验证时间
	interval time.Duration  // Revalidation interval / 重新验证间隔
	name     string         // List name (fast/slow) / 列表名称（快速/慢速）
}

// get returns a random node from the queue. Nodes in the 'exclude' map are not returned.
// get 从队列中返回一个随机节点，不返回在 'exclude' 映射中的节点。
func (list *revalidationList) get(now mclock.AbsTime, rand randomSource, exclude map[enode.ID]struct{}) *tableNode {
	if len(list.nodes) == 0 { // If list is empty / 如果列表为空
		return nil
	}
	for i := 0; i < len(list.nodes)*3; i++ { // Try up to 3x list length / 尝试最多 3 倍列表长度
		n := list.nodes[rand.Intn(len(list.nodes))] // Pick random node / 随机选择节点
		_, excluded := exclude[n.ID()]              // Check if excluded / 检查是否被排除
		if !excluded {
			return n // Return if not excluded / 如果未被排除则返回
		}
	}
	return nil // Return nil if no valid node found / 如果未找到有效节点则返回 nil
}

func (list *revalidationList) schedule(now mclock.AbsTime, rand randomSource) {
	list.nextTime = now.Add(time.Duration(rand.Int63n(int64(list.interval)))) // Schedule next time with random offset / 使用随机偏移调度下次时间
}

func (list *revalidationList) push(n *tableNode, now mclock.AbsTime, rand randomSource) {
	list.nodes = append(list.nodes, n) // Add node to list / 将节点添加到列表
	if list.nextTime == never {        // If no schedule yet / 如果尚未调度
		list.schedule(now, rand) // Schedule revalidation / 调度重新验证
	}
	n.revalList = list // Mark node's list / 标记节点的列表
}

func (list *revalidationList) remove(n *tableNode) {
	i := slices.Index(list.nodes, n) // Find node index / 查找节点索引
	if i == -1 {
		panic(fmt.Errorf("node %v not found in list", n.ID())) // Panic if not found / 如果未找到则抛出异常
	}
	list.nodes = slices.Delete(list.nodes, i, i+1) // Remove node / 移除节点
	if len(list.nodes) == 0 {                      // If list is empty / 如果列表为空
		list.nextTime = never // Reset next time / 重置下次时间
	}
	n.revalList = nil // Clear node's list / 清除节点的列表
}

func (list *revalidationList) contains(id enode.ID) bool {
	return slices.ContainsFunc(list.nodes, func(n *tableNode) bool { // Check if ID exists / 检查 ID 是否存在
		return n.ID() == id
	})
}
