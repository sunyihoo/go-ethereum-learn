// Copyright 2015 The go-ethereum Authors
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

// Package discover implements the Node Discovery Protocol.
//
// The Node Discovery protocol provides a way to find RLPx nodes that
// can be connected to. It uses a Kademlia-like protocol to maintain a
// distributed database of the IDs and endpoints of all listening
// nodes.
package discover

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const (
	alpha = 3 // Kademlia concurrency factor
	// Kademlia并发因子
	bucketSize = 16 // Kademlia bucket size
	// Kademlia桶大小
	maxReplacements = 10 // Size of per-bucket replacement list
	// 每个桶的替换列表大小

	// We keep buckets for the upper 1/15 of distances because
	// it's very unlikely we'll ever encounter a node that's closer.
	// 我们保留距离上限的1/15的桶，因为我们不太可能遇到更近的节点。
	hashBits = len(common.Hash{}) * 8 // 256 bits for SHA3 hash
	// SHA3哈希的256位
	nBuckets = hashBits / 15 // Number of buckets
	// 桶的数量
	bucketMinDistance = hashBits - nBuckets // Log distance of closest bucket
	// 最近桶的日志距离

	// IP address limits.
	// IP地址限制。
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	// 每个/24子网最多2个地址
	tableIPLimit, tableSubnet = 10, 24 // overall table limit
	// 整体表限制

	seedMinTableTime = 5 * time.Minute // Minimum time to keep seed nodes
	// 保留种子节点的最短时间
	seedCount = 30 // Number of seed nodes to query
	// 查询的种子节点数量
	seedMaxAge = 5 * 24 * time.Hour // Maximum age of seed nodes
	// 种子节点的最大年龄
)

// Table is the 'node table', a Kademlia-like index of neighbor nodes. The table keeps
// itself up-to-date by verifying the liveness of neighbors and requesting their node
// records when announcements of a new record version are received.
// Table是“节点表”，一个类似Kademlia的邻居节点索引。表通过验证邻居的存活性和在收到新记录版本公告时请求其节点记录来保持自身更新。
type Table struct {
	mutex sync.Mutex // protects buckets, bucket content, nursery, rand
	// 保护桶、桶内容、苗圃、随机数
	buckets [nBuckets]*bucket // index of known nodes by distance
	// 按距离索引的已知节点
	nursery []*enode.Node // bootstrap nodes
	// 引导节点
	rand reseedingRandom // source of randomness, periodically reseeded
	// 随机源，定期重新种子
	ips netutil.DistinctNetSet // IP address limits
	// IP地址限制
	revalidation tableRevalidation // revalidation process
	// 重新验证过程

	db *enode.DB // database of known nodes
	// 已知节点的数据库
	net transport // network transport
	// 网络传输
	cfg Config // configuration
	// 配置
	log log.Logger // logger
	// 日志记录器

	// loop channels
	// 循环通道
	refreshReq chan chan struct{} // refresh request channel
	// 刷新请求通道
	revalResponseCh chan revalidationResponse // revalidation response channel
	// 重新验证响应通道
	addNodeCh chan addNodeOp // add node operation channel
	// 添加节点操作通道
	addNodeHandled chan bool // add node handled channel
	// 添加节点处理通道
	trackRequestCh chan trackRequestOp // track request operation channel
	// 跟踪请求操作通道
	initDone chan struct{} // initialization done channel
	// 初始化完成通道
	closeReq chan struct{} // close request channel
	// 关闭请求通道
	closed chan struct{} // closed channel
	// 关闭通道

	nodeAddedHook func(*bucket, *tableNode) // hook for node added
	// 节点添加钩子
	nodeRemovedHook func(*bucket, *tableNode) // hook for node removed
	// 节点移除钩子
}

// transport is implemented by the UDP transports.
// transport由UDP传输实现。
type transport interface {
	Self() *enode.Node // returns the local node
	// 返回本地节点
	RequestENR(*enode.Node) (*enode.Node, error) // requests ENR from a node
	// 从节点请求ENR
	lookupRandom() []*enode.Node // performs a random lookup
	// 执行随机查找
	lookupSelf() []*enode.Node // performs a self lookup
	// 执行自我查找
	ping(*enode.Node) (seq uint64, err error) // pings a node
	// ping一个节点
}

// bucket contains nodes, ordered by their last activity. the entry
// that was most recently active is the first element in entries.
// bucket包含节点，按其最后活动时间排序。最近活动的条目是entries中的第一个元素。
type bucket struct {
	entries []*tableNode // live entries, sorted by time of last contact
	// 活动条目，按最后联系时间排序
	replacements []*tableNode // recently seen nodes to be used if revalidation fails
	// 最近看到的节点，用于重新验证失败时
	ips netutil.DistinctNetSet // IP address limits
	// IP地址限制
	index int // bucket index
	// 桶索引
}

type addNodeOp struct {
	node *enode.Node // node to add
	// 要添加的节点
	isInbound bool // whether the node is from inbound contact
	// 节点是否来自入站联系
	forceSetLive bool // for tests
	// 用于测试
}

type trackRequestOp struct {
	node *enode.Node // node that was requested
	// 请求的节点
	foundNodes []*enode.Node // nodes found in response
	// 响应中找到的节点
	success bool // whether the request was successful
	// 请求是否成功
}

func newTable(t transport, db *enode.DB, cfg Config) (*Table, error) {
	// cfg = cfg.withDefaults() applies default configuration
	// cfg = cfg.withDefaults() 应用默认配置
	cfg = cfg.withDefaults()
	tab := &Table{
		net:             t,
		db:              db,
		cfg:             cfg,
		log:             cfg.Log,
		refreshReq:      make(chan chan struct{}),
		revalResponseCh: make(chan revalidationResponse),
		addNodeCh:       make(chan addNodeOp),
		addNodeHandled:  make(chan bool),
		trackRequestCh:  make(chan trackRequestOp),
		initDone:        make(chan struct{}),
		closeReq:        make(chan struct{}),
		closed:          make(chan struct{}),
		ips:             netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
	}
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			index: i,
			ips:   netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: bucketIPLimit},
		}
	}
	tab.rand.seed() // seed the random number generator
	// 种子随机数生成器
	tab.revalidation.init(&cfg) // initialize revalidation
	// 初始化重新验证

	// initial table content
	// 初始表内容
	if err := tab.setFallbackNodes(cfg.Bootnodes); err != nil {
		return nil, err
	}
	tab.loadSeedNodes() // load seed nodes from database
	// 从数据库加载种子节点

	return tab, nil
}

// Nodes returns all nodes contained in the table.
// Nodes返回表中包含的所有节点。
func (tab *Table) Nodes() [][]BucketNode {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	nodes := make([][]BucketNode, len(tab.buckets))
	for i, b := range &tab.buckets {
		nodes[i] = make([]BucketNode, len(b.entries))
		for j, n := range b.entries {
			nodes[i][j] = BucketNode{
				Node:          n.Node,
				Checks:        int(n.livenessChecks),
				Live:          n.isValidatedLive,
				AddedToTable:  n.addedToTable,
				AddedToBucket: n.addedToBucket,
			}
		}
	}
	return nodes
}

func (tab *Table) self() *enode.Node {
	return tab.net.Self()
}

// getNode returns the node with the given ID or nil if it isn't in the table.
// getNode返回具有给定ID的节点，如果表中没有则返回nil。
func (tab *Table) getNode(id enode.ID) *enode.Node {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bucket(id) // find the bucket for the node ID
	// 找到节点ID的桶
	for _, e := range b.entries {
		if e.ID() == id {
			return e.Node
		}
	}
	return nil
}

// close terminates the network listener and flushes the node database.
// close终止网络监听器并刷新节点数据库。
func (tab *Table) close() {
	close(tab.closeReq)
	<-tab.closed
}

// setFallbackNodes sets the initial points of contact. These nodes
// are used to connect to the network if the table is empty and there
// are no known nodes in the database.
// setFallbackNodes设置初始联系点。如果表为空且数据库中没有已知节点，则使用这些节点连接到网络。
func (tab *Table) setFallbackNodes(nodes []*enode.Node) error {
	nursery := make([]*enode.Node, 0, len(nodes))
	for _, n := range nodes {
		if err := n.ValidateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap node %q: %v", n, err)
		}
		if tab.cfg.NetRestrict != nil && !tab.cfg.NetRestrict.ContainsAddr(n.IPAddr()) {
			tab.log.Error("Bootstrap node filtered by netrestrict", "id", n.ID(), "ip", n.IPAddr())
			continue
		}
		nursery = append(nursery, n)
	}
	tab.nursery = nursery
	return nil
}

// isInitDone returns whether the table's initial seeding procedure has completed.
// isInitDone返回表的初始种子过程是否已完成。
func (tab *Table) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

func (tab *Table) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case tab.refreshReq <- done:
	case <-tab.closeReq:
		close(done)
	}
	return done
}

// findnodeByID returns the n nodes in the table that are closest to the given id.
// This is used by the FINDNODE/v4 handler.
//
// The preferLive parameter says whether the caller wants liveness-checked results. If
// preferLive is true and the table contains any verified nodes, the result will not
// contain unverified nodes. However, if there are no verified nodes at all, the result
// will contain unverified nodes.
// findnodeByID返回表中与给定ID最接近的n个节点。用于FINDNODE/v4处理程序。
func (tab *Table) findnodeByID(target enode.ID, nresults int, preferLive bool) *nodesByDistance {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// Scan all buckets. There might be a better way to do this, but there aren't that many
	// buckets, so this solution should be fine. The worst-case complexity of this loop
	// is O(tab.len() * nresults).
	// 扫描所有桶。可能有更好的方法，但桶数量不多，所以这种方法可以接受。此循环的最坏情况复杂度为O(tab.len() * nresults)。
	nodes := &nodesByDistance{target: target}
	liveNodes := &nodesByDistance{target: target}
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			nodes.push(n.Node, nresults)
			if preferLive && n.isValidatedLive {
				liveNodes.push(n.Node, nresults)
			}
		}
	}

	if preferLive && len(liveNodes.entries) > 0 {
		return liveNodes
	}
	return nodes
}

// appendBucketNodes adds nodes at the given distance to the result slice.
// This is used by the FINDNODE/v5 handler.
// appendBucketNodes将给定距离的节点添加到结果切片中。用于FINDNODE/v5处理程序。
func (tab *Table) appendBucketNodes(dist uint, result []*enode.Node, checkLive bool) []*enode.Node {
	if dist > 256 {
		return result
	}
	if dist == 0 {
		return append(result, tab.self())
	}

	tab.mutex.Lock()
	for _, n := range tab.bucketAtDistance(int(dist)).entries {
		if !checkLive || n.isValidatedLive {
			result = append(result, n.Node)
		}
	}
	tab.mutex.Unlock()

	// Shuffle result to avoid always returning same nodes in FINDNODE/v5.
	// 打乱结果以避免在FINDNODE/v5中始终返回相同的节点。
	tab.rand.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})
	return result
}

// len returns the number of nodes in the table.
// len返回表中的节点数量。
func (tab *Table) len() (n int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// addFoundNode adds a node which may not be live. If the bucket has space available,
// adding the node succeeds immediately. Otherwise, the node is added to the replacements
// list.
//
// The caller must not hold tab.mutex.
// addFoundNode添加一个可能不存活的节点。如果桶有可用空间，则立即添加成功。否则，将节点添加到替换列表。
func (tab *Table) addFoundNode(n *enode.Node, forceSetLive bool) bool {
	op := addNodeOp{node: n, isInbound: false, forceSetLive: forceSetLive}
	select {
	case tab.addNodeCh <- op:
		return <-tab.addNodeHandled
	case <-tab.closeReq:
		return false
	}
}

// addInboundNode adds a node from an inbound contact. If the bucket has no space, the
// node is added to the replacements list.
//
// There is an additional safety measure: if the table is still initializing the node is
// not added. This prevents an attack where the table could be filled by just sending ping
// repeatedly.
//
// The caller must not hold tab.mutex.
// addInboundNode添加来自入站联系的节点。如果桶没有空间，则将节点添加到替换列表。
func (tab *Table) addInboundNode(n *enode.Node) bool {
	op := addNodeOp{node: n, isInbound: true}
	select {
	case tab.addNodeCh <- op:
		return <-tab.addNodeHandled
	case <-tab.closeReq:
		return false
	}
}

func (tab *Table) trackRequest(n *enode.Node, success bool, foundNodes []*enode.Node) {
	op := trackRequestOp{n, foundNodes, success}
	select {
	case tab.trackRequestCh <- op:
	case <-tab.closeReq:
	}
}

// loop is the main loop of Table.
// loop是Table的主循环。
func (tab *Table) loop() {
	var (
		refresh = time.NewTimer(tab.nextRefreshTime()) // timer for refresh
		// 刷新定时器
		refreshDone = make(chan struct{}) // where doRefresh reports Eritrepletion
		// doRefresh报告完成
		waiting = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
		// 在doRefresh运行时持有等待的调用者
		revalTimer = mclock.NewAlarm(tab.cfg.Clock) // alarm for revalidation
		// 重新验证的闹钟
		reseedRandTimer = time.NewTicker(10 * time.Minute) // timer for reseeding random
		// 重新种子随机的定时器
	)
	defer refresh.Stop()
	defer revalTimer.Stop()
	defer reseedRandTimer.Stop()

	// Start initial refresh.
	// 启动初始刷新。
	go tab.doRefresh(refreshDone)

loop:
	for {
		nextTime := tab.revalidation.run(tab, tab.cfg.Clock.Now()) // run revalidation
		// 运行重新验证
		revalTimer.Schedule(nextTime) // schedule next revalidation
		// 安排下一次重新验证

		select {
		case <-reseedRandTimer.C:
			tab.rand.seed() // reseed random number generator
			// 重新种子随机数生成器

		case <-revalTimer.C():
			// revalidation timer triggered
			// 重新验证定时器触发

		case r := <-tab.revalResponseCh:
			tab.revalidation.handleResponse(tab, r) // handle revalidation response
			// 处理重新验证响应

		case op := <-tab.addNodeCh:
			tab.mutex.Lock()
			ok := tab.handleAddNode(op) // handle add node operation
			// 处理添加节点操作
			tab.mutex.Unlock()
			tab.addNodeHandled <- ok // send result back
			// 发送结果

		case op := <-tab.trackRequestCh:
			tab.handleTrackRequest(op) // handle track request operation
			// 处理跟踪请求操作

		case <-refresh.C:
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone) // start refresh
				// 启动刷新
			}

		case req := <-tab.refreshReq:
			waiting = append(waiting, req)
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone) // start refresh
				// 启动刷新
			}

		case <-refreshDone:
			for _, ch := range waiting {
				close(ch) // notify waiting callers
				// 通知等待的调用者
			}
			waiting, refreshDone = nil, nil
			refresh.Reset(tab.nextRefreshTime()) // reset refresh timer
			// 重置刷新定时器

		case <-tab.closeReq:
			break loop // exit loop on close request
			// 在关闭请求时退出循环
		}
	}

	if refreshDone != nil {
		<-refreshDone // wait for ongoing refresh to complete
		// 等待正在进行的刷新完成
	}
	for _, ch := range waiting {
		close(ch) // close waiting channels
		// 关闭等待通道
	}
	close(tab.closed) // signal that the loop has closed
	// 信号循环已关闭
}

// doRefresh performs a lookup for a random target to keep buckets full. seed nodes are
// inserted if the table is empty (initial bootstrap or discarded faulty peers).
// doRefresh执行随机目标的查找以保持桶满。如果表为空（初始引导或丢弃故障对等体），则插入种子节点。
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// Load nodes from the database and insert
	// them. This should yield a few previously seen nodes that are
	// (hopefully) still alive.
	// 从数据库加载节点并插入。这应该会产生一些之前看到的（希望）仍然存活的节点。
	tab.loadSeedNodes()

	// Run self lookup to discover new neighbor nodes.
	// 运行自我查找以发现新的邻居节点。
	tab.net.lookupSelf()

	// The Kademlia paper specifies that the bucket refresh should
	// perform a lookup in the least recently used bucket. We cannot
	// adhere to this because the findnode target is a 512bit value
	// (not hash-sized) and it is not easily possible to generate a
	// sha3 preimage that falls into a chosen bucket.
	// Kademlia论文指定桶刷新应在最近最少使用的桶中执行查找。我们不能遵守这一点，因为findnode目标是512位值（不是哈希大小），并且不容易生成落入所选桶的sha3原像。
	// We perform a few lookups with a random target instead.
	// 我们改为执行几次随机目标的查找。
	for i := 0; i < 3; i++ {
		tab.net.lookupRandom()
	}
}

func (tab *Table) loadSeedNodes() {
	seeds := tab.db.QuerySeeds(seedCount, seedMaxAge)
	seeds = append(seeds, tab.nursery...)
	for i := range seeds {
		seed := seeds[i]
		if tab.log.Enabled(context.Background(), log.LevelTrace) {
			age := time.Since(tab.db.LastPongReceived(seed.ID(), seed.IPAddr()))
			addr, _ := seed.UDPEndpoint()
			tab.log.Trace("Found seed node in database", "id", seed.ID(), "addr", addr, "age", age)
		}
		tab.mutex.Lock()
		tab.handleAddNode(addNodeOp{node: seed, isInbound: false})
		tab.mutex.Unlock()
	}
}

func (tab *Table) nextRefreshTime() time.Duration {
	half := tab.cfg.RefreshInterval / 2
	return half + time.Duration(tab.rand.Int63n(int64(half)))
}

// bucket returns the bucket for the given node ID hash.
// bucket返回给定节点ID哈希的桶。
func (tab *Table) bucket(id enode.ID) *bucket {
	d := enode.LogDist(tab.self().ID(), id)
	return tab.bucketAtDistance(d)
}

func (tab *Table) bucketAtDistance(d int) *bucket {
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	return tab.buckets[d-bucketMinDistance-1]
}

func (tab *Table) addIP(b *bucket, ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() {
		return false // Nodes without IP cannot be added.
		// 没有IP的节点不能添加。
	}
	if netutil.AddrIsLAN(ip) {
		return true
	}
	if !tab.ips.AddAddr(ip) {
		tab.log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	if !b.ips.AddAddr(ip) {
		tab.log.Debug("IP exceeds bucket limit", "ip", ip)
		tab.ips.RemoveAddr(ip)
		return false
	}
	return true
}

func (tab *Table) removeIP(b *bucket, ip netip.Addr) {
	if netutil.AddrIsLAN(ip) {
		return
	}
	tab.ips.RemoveAddr(ip)
	b.ips.RemoveAddr(ip)
}

// handleAddNode adds the node in the request to the table, if there is space.
// The caller must hold tab.mutex.
// handleAddNode将请求中的节点添加到表中，如果有空间。调用者必须持有tab.mutex。
func (tab *Table) handleAddNode(req addNodeOp) bool {
	if req.node.ID() == tab.self().ID() {
		return false // don't add self
		// 不添加自己
	}
	// For nodes from inbound contact, there is an additional safety measure: if the table
	// is still initializing the node is not added.
	// 对于来自入站联系的节点，有一个额外的安全措施：如果表仍在初始化，则不添加节点。
	if req.isInbound && !tab.isInitDone() {
		return false
	}

	b := tab.bucket(req.node.ID()) // find the bucket for the node
	// 找到节点的桶
	n, _ := tab.bumpInBucket(b, req.node, req.isInbound) // check if node already exists
	// 检查节点是否已存在
	if n != nil {
		// Already in bucket.
		return false
	}
	if len(b.entries) >= bucketSize {
		// Bucket full, maybe add as replacement.
		// 桶已满，可能作为替换添加。
		tab.addReplacement(b, req.node)
		return false
	}
	if !tab.addIP(b, req.node.IPAddr()) {
		// Can't add: IP limit reached.
		// 无法添加：达到IP限制。
		return false
	}

	// Add to bucket.
	// 添加到桶中。
	wn := &tableNode{Node: req.node}
	if req.forceSetLive {
		wn.livenessChecks = 1
		wn.isValidatedLive = true
	}
	b.entries = append(b.entries, wn)
	b.replacements = deleteNode(b.replacements, wn.ID()) // remove from replacements if exists
	// 如果存在，从替换列表中移除
	tab.nodeAdded(b, wn) // trigger node added hook
	// 触发节点添加钩子
	return true
}

// addReplacement adds n to the replacement cache of bucket b.
// addReplacement将n添加到桶b的替换缓存中。
func (tab *Table) addReplacement(b *bucket, n *enode.Node) {
	if containsID(b.replacements, n.ID()) {
		// TODO: update ENR
		return
	}
	if !tab.addIP(b, n.IPAddr()) {
		return
	}

	wn := &tableNode{Node: n, addedToTable: time.Now()}
	var removed *tableNode
	b.replacements, removed = pushNode(b.replacements, wn, maxReplacements)
	if removed != nil {
		tab.removeIP(b, removed.IPAddr())
	}
}

func (tab *Table) nodeAdded(b *bucket, n *tableNode) {
	if n.addedToTable == (time.Time{}) {
		n.addedToTable = time.Now()
	}
	n.addedToBucket = time.Now()
	tab.revalidation.nodeAdded(tab, n)
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(b, n)
	}
	if metrics.Enabled() {
		bucketsCounter[b.index].Inc(1)
	}
}

func (tab *Table) nodeRemoved(b *bucket, n *tableNode) {
	tab.revalidation.nodeRemoved(n)
	if tab.nodeRemovedHook != nil {
		tab.nodeRemovedHook(b, n)
	}
	if metrics.Enabled() {
		bucketsCounter[b.index].Dec(1)
	}
}

// deleteInBucket removes node n from the table.
// If there are replacement nodes in the bucket, the node is replaced.
// deleteInBucket从表中移除节点n。如果桶中有替换节点，则替换该节点。
func (tab *Table) deleteInBucket(b *bucket, id enode.ID) *tableNode {
	index := slices.IndexFunc(b.entries, func(e *tableNode) bool { return e.ID() == id })
	if index == -1 {
		// Entry has been removed already.
		// 条目已被移除。
		return nil
	}

	// Remove the node.
	// 移除节点。
	n := b.entries[index]
	b.entries = slices.Delete(b.entries, index, index+1)
	tab.removeIP(b, n.IPAddr())
	tab.nodeRemoved(b, n)

	// Add replacement.
	// 添加替换。
	if len(b.replacements) == 0 {
		tab.log.Debug("Removed dead node", "b", b.index, "id", n.ID(), "ip", n.IPAddr())
		return nil
	}
	rindex := tab.rand.Intn(len(b.replacements))
	rep := b.replacements[rindex]
	b.replacements = slices.Delete(b.replacements, rindex, rindex+1)
	b.entries = append(b.entries, rep)
	tab.nodeAdded(b, rep)
	tab.log.Debug("Replaced dead node", "b", b.index, "id", n.ID(), "ip", n.IPAddr(), "r", rep.ID(), "rip", rep.IPAddr())
	return rep
}

// bumpInBucket updates a node record if it exists in the bucket.
// The second return value reports whether the node's endpoint (IP/port) was updated.
// bumpInBucket更新桶中存在的节点记录。第二个返回值报告节点的端点（IP/端口）是否已更新。
func (tab *Table) bumpInBucket(b *bucket, newRecord *enode.Node, isInbound bool) (n *tableNode, endpointChanged bool) {
	i := slices.IndexFunc(b.entries, func(elem *tableNode) bool {
		return elem.ID() == newRecord.ID()
	})
	if i == -1 {
		return nil, false // not in bucket
		// 不在桶中
	}
	n = b.entries[i]

	// For inbound updates (from the node itself) we accept any change, even if it sets
	// back the sequence number. For found nodes (!isInbound), seq has to advance. Note
	// this check also ensures found discv4 nodes (which always have seq=0) can't be
	// updated.
	// 对于来自节点本身的入站更新，我们接受任何更改，即使它回退了序列号。对于发现的节点（!isInbound），序列号必须前进。此检查还确保发现的discv4节点（始终seq=0）无法更新。
	if newRecord.Seq() <= n.Seq() && !isInbound {
		return n, false
	}

	// Check endpoint update against IP limits.
	// 检查端点更新是否符合IP限制。
	ipchanged := newRecord.IPAddr() != n.IPAddr()
	portchanged := newRecord.UDP() != n.UDP()
	if ipchanged {
		tab.removeIP(b, n.IPAddr())
		if !tab.addIP(b, newRecord.IPAddr()) {
			// It doesn't fit with the limit, put the previous record back.
			// 它不符合限制，放回之前的记录。
			tab.addIP(b, n.IPAddr())
			return n, false
		}
	}

	// Apply update.
	// 应用更新。
	n.Node = newRecord
	if ipchanged || portchanged {
		// Ensure node is revalidated quickly for endpoint changes.
		// 确保节点在端点更改时快速重新验证。
		tab.revalidation.nodeEndpointChanged(tab, n)
		return n, true
	}
	return n, false
}

func (tab *Table) handleTrackRequest(op trackRequestOp) {
	var fails int
	if op.success {
		// Reset failure counter because it counts _consecutive_ failures.
		// 重置失败计数器，因为它计算_连续_失败。
		tab.db.UpdateFindFails(op.node.ID(), op.node.IPAddr(), 0)
	} else {
		fails = tab.db.FindFails(op.node.ID(), op.node.IPAddr())
		fails++
		tab.db.UpdateFindFails(op.node.ID(), op.node.IPAddr(), fails)
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	b := tab.bucket(op.node.ID())
	// Remove the node from the local table if it fails to return anything useful too
	// many times, but only if there are enough other nodes in the bucket. This latter
	// condition specifically exists to make bootstrapping in smaller test networks more
	// reliable.
	// 如果节点多次未能返回有用的信息，则从本地表中移除该节点，但前提是桶中有足够多的其他节点。后一个条件特别存在于使小型测试网络中的引导更可靠。
	if fails >= maxFindnodeFailures && len(b.entries) >= bucketSize/4 {
		tab.deleteInBucket(b, op.node.ID())
	}

	// Add found nodes.
	// 添加找到的节点。
	for _, n := range op.foundNodes {
		tab.handleAddNode(addNodeOp{n, false, false})
	}
}

// pushNode adds n to the front of list, keeping at most max items.
// pushNode将n添加到列表前端，最多保留max项。
func pushNode(list []*tableNode, n *tableNode, max int) ([]*tableNode, *tableNode) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}
