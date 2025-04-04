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

package dnsdisc

import (
	"context"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// This is the number of consecutive leaf requests that may fail before
// we consider re-resolving the tree root.
// 在我们考虑重新解析树根之前，连续叶子请求可能失败的次数。
const rootRecheckFailCount = 5

// clientTree is a full tree being synced.
// clientTree 是一个正在同步的完整树。
type clientTree struct {
	c   *Client    // Client instance / 客户端实例
	loc *linkEntry // link to this tree / 到此树的链接

	lastRootCheck mclock.AbsTime // last revalidation of root / 上次根验证时间
	leafFailCount int            // Number of failed leaf requests / 叶子请求失败次数
	rootFailCount int            // Number of failed root requests / 根请求失败次数

	root  *rootEntry   // Root of the tree / 树的根
	enrs  *subtreeSync // ENR subtree sync / ENR 子树同步
	links *subtreeSync // Link subtree sync / 链接子树同步

	lc         *linkCache          // tracks all links between all trees / 跟踪所有树之间的链接
	curLinks   map[string]struct{} // links contained in this tree / 此树中包含的链接
	linkGCRoot string              // root on which last link GC has run / 上次链接垃圾回收运行的根
}

func newClientTree(c *Client, lc *linkCache, loc *linkEntry) *clientTree {
	return &clientTree{c: c, lc: lc, loc: loc} // Initialize clientTree / 初始化 clientTree
}

// syncAll retrieves all entries of the tree.
// syncAll 检索树的所有条目。
func (ct *clientTree) syncAll(dest map[string]entry) error {
	if err := ct.updateRoot(context.Background()); err != nil { // Update tree root / 更新树根
		return err
	}
	if err := ct.links.resolveAll(dest); err != nil { // Sync all links / 同步所有链接
		return err
	}
	if err := ct.enrs.resolveAll(dest); err != nil { // Sync all ENRs / 同步所有 ENR
		return err
	}
	return nil
}

// syncRandom retrieves a single entry of the tree. The Node return value
// is non-nil if the entry was a node.
// syncRandom 检索树的单个条目。如果条目是节点，则返回的 Node 不为 nil。
func (ct *clientTree) syncRandom(ctx context.Context) (n *enode.Node, err error) {
	if ct.rootUpdateDue() { // Check if root update is needed / 检查是否需要更新根
		if err := ct.updateRoot(ctx); err != nil {
			return nil, err
		}
	}

	// Update fail counter for leaf request errors.
	// 更新叶子请求错误的失败计数器。
	defer func() {
		if err != nil {
			ct.leafFailCount++ // Increment on error / 出错时增加
		}
	}()

	// Link tree sync has priority, run it to completion before syncing ENRs.
	// 链接树同步优先，在同步 ENR 之前完成。
	if !ct.links.done() {
		err := ct.syncNextLink(ctx) // Sync next link / 同步下一个链接
		return nil, err
	}
	ct.gcLinks() // Garbage collect links / 垃圾回收链接

	// Sync next random entry in ENR tree. Once every node has been visited, we simply
	// start over. This is fine because entries are cached internally by the client LRU
	// also by DNS resolvers.
	// 同步 ENR 树中的下一个随机条目。所有节点访问一遍后，重新开始。
	// 这是可以的，因为条目会在客户端 LRU 和 DNS 解析器中缓存。
	if ct.enrs.done() {
		ct.enrs = newSubtreeSync(ct.c, ct.loc, ct.root.eroot, false) // Restart ENR sync / 重启 ENR 同步
	}
	return ct.syncNextRandomENR(ctx) // Sync random ENR / 同步随机 ENR
}

// canSyncRandom checks if any meaningful action can be performed by syncRandom.
// canSyncRandom 检查 syncRandom 是否可以执行任何有意义的动作。
func (ct *clientTree) canSyncRandom() bool {
	// Note: the check for non-zero leaf count is very important here.
	// If we're done syncing all nodes, and no leaves were found, the tree
	// is empty and we can't use it for sync.
	// 注意：这里检查非零叶子计数非常重要。
	// 如果我们完成了所有节点的同步，但没有找到叶子，则树为空，无法用于同步。
	return ct.rootUpdateDue() || !ct.links.done() || !ct.enrs.done() || ct.enrs.leaves != 0
}

// gcLinks removes outdated links from the global link cache. GC runs once
// when the link sync finishes.
// gcLinks 从全局链接缓存中移除过时的链接。垃圾回收在链接同步完成后运行一次。
func (ct *clientTree) gcLinks() {
	if !ct.links.done() || ct.root.lroot == ct.linkGCRoot { // Skip if not done or already GC'd / 如果未完成或已回收则跳过
		return
	}
	ct.lc.resetLinks(ct.loc.str, ct.curLinks) // Reset outdated links / 重置过时链接
	ct.linkGCRoot = ct.root.lroot             // Update GC root / 更新垃圾回收根
}

func (ct *clientTree) syncNextLink(ctx context.Context) error {
	hash := ct.links.missing[0]               // Get next missing link hash / 获取下一个缺失的链接哈希
	e, err := ct.links.resolveNext(ctx, hash) // Resolve link / 解析链接
	if err != nil {
		return err
	}
	ct.links.missing = ct.links.missing[1:] // Remove resolved hash / 移除已解析的哈希

	if dest, ok := e.(*linkEntry); ok { // If entry is a link / 如果条目是链接
		ct.lc.addLink(ct.loc.str, dest.str) // Add to link cache / 添加到链接缓存
		ct.curLinks[dest.str] = struct{}{}  // Track in current links / 在当前链接中跟踪
	}
	return nil
}

func (ct *clientTree) syncNextRandomENR(ctx context.Context) (*enode.Node, error) {
	index := rand.Intn(len(ct.enrs.missing)) // Pick random index / 随机选择索引
	hash := ct.enrs.missing[index]           // Get hash / 获取哈希
	e, err := ct.enrs.resolveNext(ctx, hash) // Resolve ENR / 解析 ENR
	if err != nil {
		return nil, err
	}
	ct.enrs.missing = removeHash(ct.enrs.missing, index) // Remove resolved hash / 移除已解析的哈希
	if ee, ok := e.(*enrEntry); ok {                     // If entry is ENR / 如果条目是 ENR
		return ee.node, nil // Return node / 返回节点
	}
	return nil, nil // Return nil if not ENR / 如果不是 ENR 则返回 nil
}

func (ct *clientTree) String() string {
	return ct.loc.String() // String representation / 字符串表示
}

// removeHash removes the element at index from h.
// removeHash 从 h 中移除索引处的元素。
func removeHash(h []string, index int) []string {
	if len(h) == 1 {
		return nil // Return nil if last element / 如果是最后一个元素则返回 nil
	}
	last := len(h) - 1
	if index < last {
		h[index] = h[last] // Move last to index / 将最后一个移动到索引处
		h[last] = ""       // Clear last / 清除最后一个
	}
	return h[:last] // Return shortened slice / 返回缩短的切片
}

// updateRoot ensures that the given tree has an up-to-date root.
// updateRoot 确保给定树具有最新的根。
func (ct *clientTree) updateRoot(ctx context.Context) error {
	if !ct.slowdownRootUpdate(ctx) { // Apply delay if needed / 如果需要则应用延迟
		return ctx.Err()
	}

	ct.lastRootCheck = ct.c.clock.Now()                       // Update last check time / 更新上次检查时间
	ctx, cancel := context.WithTimeout(ctx, ct.c.cfg.Timeout) // Set timeout / 设置超时
	defer cancel()
	root, err := ct.c.resolveRoot(ctx, ct.loc) // Resolve root / 解析根
	if err != nil {
		ct.rootFailCount++ // Increment fail count / 增加失败计数
		return err
	}
	ct.root = &root      // Update root / 更新根
	ct.rootFailCount = 0 // Reset fail counts / 重置失败计数
	ct.leafFailCount = 0

	// Invalidate subtrees if changed.
	// 如果更改，则使子树无效。
	if ct.links == nil || root.lroot != ct.links.root { // If links root changed / 如果链接根更改
		ct.links = newSubtreeSync(ct.c, ct.loc, root.lroot, true) // Restart link sync / 重启链接同步
		ct.curLinks = make(map[string]struct{})                   // Reset current links / 重置当前链接
	}
	if ct.enrs == nil || root.eroot != ct.enrs.root { // If ENR root changed / 如果 ENR 根更改
		ct.enrs = newSubtreeSync(ct.c, ct.loc, root.eroot, false) // Restart ENR sync / 重启 ENR 同步
	}
	return nil
}

// rootUpdateDue returns true when a root update is needed.
// rootUpdateDue 当需要更新根时返回 true。
func (ct *clientTree) rootUpdateDue() bool {
	tooManyFailures := ct.leafFailCount > rootRecheckFailCount        // Too many leaf failures / 叶子失败过多
	scheduledCheck := ct.c.clock.Now() >= ct.nextScheduledRootCheck() // Time for scheduled check / 到计划检查时间
	return ct.root == nil || tooManyFailures || scheduledCheck        // Root update needed / 需要更新根
}

func (ct *clientTree) nextScheduledRootCheck() mclock.AbsTime {
	return ct.lastRootCheck.Add(ct.c.cfg.RecheckInterval) // Next scheduled check time / 下次计划检查时间
}

// slowdownRootUpdate applies a delay to root resolution if is tried
// too frequently. This avoids busy polling when the client is offline.
// Returns true if the timeout passed, false if sync was canceled.
// slowdownRootUpdate 如果尝试过于频繁，则对根解析应用延迟。
// 这避免了客户端离线时的忙碌轮询。
// 如果超时通过则返回 true，如果同步取消则返回 false。
func (ct *clientTree) slowdownRootUpdate(ctx context.Context) bool {
	var delay time.Duration
	switch {
	case ct.rootFailCount > 20:
		delay = 10 * time.Second // 10s delay after 20 failures / 20 次失败后延迟 10 秒
	case ct.rootFailCount > 5:
		delay = 5 * time.Second // 5s delay after 5 failures / 5 次失败后延迟 5 秒
	default:
		return true // No delay if few failures / 如果失败少则无延迟
	}
	timeout := ct.c.clock.NewTimer(delay) // Create timer / 创建定时器
	defer timeout.Stop()
	select {
	case <-timeout.C(): // Wait for timeout / 等待超时
		return true
	case <-ctx.Done(): // Check for cancellation / 检查取消
		return false
	}
}

// subtreeSync is the sync of an ENR or link subtree.
// subtreeSync 是 ENR 或链接子树的同步。
type subtreeSync struct {
	c       *Client    // Client instance / 客户端实例
	loc     *linkEntry // Tree location / 树位置
	root    string     // Subtree root hash / 子树根哈希
	missing []string   // missing tree node hashes / 缺失的树节点哈希
	link    bool       // true if this sync is for the link tree / 如果此同步用于链接树则为 true
	leaves  int        // counter of synced leaves / 已同步叶子的计数器
}

func newSubtreeSync(c *Client, loc *linkEntry, root string, link bool) *subtreeSync {
	return &subtreeSync{c, loc, root, []string{root}, link, 0} // Initialize subtree sync / 初始化子树同步
}

func (ts *subtreeSync) done() bool {
	return len(ts.missing) == 0 // Check if sync is complete / 检查同步是否完成
}

func (ts *subtreeSync) resolveAll(dest map[string]entry) error {
	for !ts.done() {
		hash := ts.missing[0]                                                      // Get next hash / 获取下一个哈希
		ctx, cancel := context.WithTimeout(context.Background(), ts.c.cfg.Timeout) // Set timeout / 设置超时
		e, err := ts.resolveNext(ctx, hash)                                        // Resolve next entry / 解析下一个条目
		cancel()
		if err != nil {
			return err
		}
		dest[hash] = e              // Store entry / 存储条目
		ts.missing = ts.missing[1:] // Remove resolved hash / 移除已解析的哈希
	}
	return nil
}

func (ts *subtreeSync) resolveNext(ctx context.Context, hash string) (entry, error) {
	e, err := ts.c.resolveEntry(ctx, ts.loc.domain, hash) // Resolve entry / 解析条目
	if err != nil {
		return nil, err
	}
	switch e := e.(type) {
	case *enrEntry: // If ENR entry / 如果是 ENR 条目
		if ts.link {
			return nil, errENRInLinkTree // Error if in link tree / 如果在链接树中则报错
		}
		ts.leaves++ // Increment leaf count / 增加叶子计数
	case *linkEntry: // If link entry / 如果是链接条目
		if !ts.link {
			return nil, errLinkInENRTree // Error if in ENR tree / 如果在 ENR 树中则报错
		}
		ts.leaves++ // Increment leaf count / 增加叶子计数
	case *branchEntry: // If branch entry / 如果是分支条目
		ts.missing = append(ts.missing, e.children...) // Add child hashes / 添加子哈希
	}
	return e, nil
}

// linkCache tracks links between trees.
// linkCache 跟踪树之间的链接。
type linkCache struct {
	backrefs map[string]map[string]struct{} // Back references for links / 链接的反向引用
	changed  bool                           // Indicates if cache changed / 指示缓存是否更改
}

func (lc *linkCache) isReferenced(r string) bool {
	return len(lc.backrefs[r]) != 0 // Check if link is referenced / 检查链接是否被引用
}

func (lc *linkCache) addLink(from, to string) {
	if _, ok := lc.backrefs[to][from]; ok { // Skip if already exists / 如果已存在则跳过
		return
	}

	if lc.backrefs == nil {
		lc.backrefs = make(map[string]map[string]struct{}) // Initialize if nil / 如果为空则初始化
	}
	if _, ok := lc.backrefs[to]; !ok {
		lc.backrefs[to] = make(map[string]struct{}) // Initialize inner map / 初始化内部映射
	}
	lc.backrefs[to][from] = struct{}{} // Add link / 添加链接
	lc.changed = true                  // Mark as changed / 标记为已更改
}

// resetLinks clears all links of the given tree.
// resetLinks 清除给定树的所有链接。
func (lc *linkCache) resetLinks(from string, keep map[string]struct{}) {
	stk := []string{from} // Stack for traversal / 遍历栈
	for len(stk) > 0 {
		item := stk[len(stk)-1] // Get top item / 获取顶部项
		stk = stk[:len(stk)-1]  // Pop item / 弹出项

		for r, refs := range lc.backrefs {
			if _, ok := keep[r]; ok { // Skip if in keep set / 如果在保留集中则跳过
				continue
			}
			if _, ok := refs[item]; !ok { // Skip if no reference / 如果无引用则跳过
				continue
			}
			lc.changed = true   // Mark as changed / 标记为已更改
			delete(refs, item)  // Remove reference / 移除引用
			if len(refs) == 0 { // If no refs left / 如果没有引用剩余
				delete(lc.backrefs, r) // Remove entry / 移除条目
				stk = append(stk, r)   // Add to stack / 添加到栈
			}
		}
	}
}
