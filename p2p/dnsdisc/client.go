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
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// ENR Tree：EIP-1459 定义的 DNS 树结构，使用 TXT 记录存储节点信息。
// ENR：EIP-778 定义的节点记录格式。
// DNS 发现：以太坊客户端（如 Geth）用于快速加入网络。

// Client discovers nodes by querying DNS servers.
// Client 通过查询 DNS 服务器发现节点。
type Client struct {
	cfg          Config
	clock        mclock.Clock
	entries      *lru.Cache[string, entry] // 缓存解析的条目
	ratelimit    *rate.Limiter             // 速率限制器
	singleflight singleflight.Group        // 单次飞行组，用于避免重复查询
}

// Config holds configuration options for the client.
// Config 保存客户端的配置选项。
type Config struct {
	Timeout         time.Duration      // DNS 查询超时（默认 5 秒）
	RecheckInterval time.Duration      // 树根更新检查间隔（默认 30 分钟）
	CacheLimit      int                // 缓存的最大记录数（默认 1000）
	RateLimit       float64            // 每秒最大 DNS 请求数（默认 3）
	ValidSchemes    enr.IdentityScheme // 可接受的 ENR 身份方案（默认 enode.ValidSchemes）
	Resolver        Resolver           // DNS 解析器（默认使用系统 DNS）
	Logger          log.Logger         // 日志记录器（默认使用根日志器）
}

// Resolver is a DNS resolver that can query TXT records.
// Resolver 是一个可以查询 TXT 记录的 DNS 解析器。
type Resolver interface {
	LookupTXT(ctx context.Context, domain string) ([]string, error)
}

func (cfg Config) withDefaults() Config {
	const (
		defaultTimeout   = 5 * time.Second
		defaultRecheck   = 30 * time.Minute
		defaultRateLimit = 3
		defaultCache     = 1000
	)
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.RecheckInterval == 0 {
		cfg.RecheckInterval = defaultRecheck
	}
	if cfg.CacheLimit == 0 {
		cfg.CacheLimit = defaultCache
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = defaultRateLimit
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = enode.ValidSchemes
	}
	if cfg.Resolver == nil {
		cfg.Resolver = new(net.Resolver)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Root()
	}
	return cfg
}

// NewClient creates a client.
// NewClient 创建一个客户端。
func NewClient(cfg Config) *Client {
	cfg = cfg.withDefaults()
	rlimit := rate.NewLimiter(rate.Limit(cfg.RateLimit), 10) // 创建速率限制器
	return &Client{
		cfg:       cfg,
		entries:   lru.NewCache[string, entry](cfg.CacheLimit), // 初始化 LRU 缓存
		clock:     mclock.System{},
		ratelimit: rlimit,
	}
}

// SyncTree downloads the entire node tree at the given URL.
// SyncTree 下载给定 URL 的整个节点树。
func (c *Client) SyncTree(url string) (*Tree, error) {
	le, err := parseLink(url)
	if err != nil {
		return nil, fmt.Errorf("invalid enrtree URL: %v", err)
	}
	ct := newClientTree(c, new(linkCache), le)
	t := &Tree{entries: make(map[string]entry)}
	if err := ct.syncAll(t.entries); err != nil {
		return nil, err
	}
	t.root = ct.root
	return t, nil
}

// NewIterator creates an iterator that visits all nodes at the
// given tree URLs.
// NewIterator 创建一个迭代器，访问给定树 URL 中的所有节点。
func (c *Client) NewIterator(urls ...string) (enode.Iterator, error) {
	it := c.newRandomIterator()
	for _, url := range urls {
		if err := it.addTree(url); err != nil {
			return nil, err
		}
	}
	return it, nil
}

// resolveRoot retrieves a root entry via DNS.
// resolveRoot 通过 DNS 检索根条目。
func (c *Client) resolveRoot(ctx context.Context, loc *linkEntry) (rootEntry, error) {
	e, err, _ := c.singleflight.Do(loc.str, func() (interface{}, error) {
		txts, err := c.cfg.Resolver.LookupTXT(ctx, loc.domain)
		c.cfg.Logger.Trace("Updating DNS discovery root", "tree", loc.domain, "err", err)
		if err != nil {
			return rootEntry{}, err
		}
		for _, txt := range txts {
			if strings.HasPrefix(txt, rootPrefix) {
				return parseAndVerifyRoot(txt, loc)
			}
		}
		return rootEntry{}, nameError{loc.domain, errNoRoot}
	})
	return e.(rootEntry), err
}

func parseAndVerifyRoot(txt string, loc *linkEntry) (rootEntry, error) {
	e, err := parseRoot(txt)
	if err != nil {
		return e, err
	}
	if !e.verifySignature(loc.pubkey) {
		return e, entryError{typ: "root", err: errInvalidSig}
	}
	return e, nil
}

// resolveEntry retrieves an entry from the cache or fetches it from the network
// if it isn't cached.
// resolveEntry 从缓存中检索条目，如果未缓存则从网络获取。
func (c *Client) resolveEntry(ctx context.Context, domain, hash string) (entry, error) {
	if err := c.ratelimit.Wait(ctx); err != nil {
		return nil, err
	}
	cacheKey := truncateHash(hash)
	if e, ok := c.entries.Get(cacheKey); ok {
		return e, nil
	}

	ei, err, _ := c.singleflight.Do(cacheKey, func() (interface{}, error) {
		e, err := c.doResolveEntry(ctx, domain, hash)
		if err != nil {
			return nil, err
		}
		c.entries.Add(cacheKey, e)
		return e, nil
	})
	e, _ := ei.(entry)
	return e, err
}

// doResolveEntry fetches an entry via DNS.
// doResolveEntry 通过 DNS 获取条目。
func (c *Client) doResolveEntry(ctx context.Context, domain, hash string) (entry, error) {
	wantHash, err := b32format.DecodeString(hash)
	if err != nil {
		return nil, errors.New("invalid base32 hash")
	}
	name := hash + "." + domain
	txts, err := c.cfg.Resolver.LookupTXT(ctx, hash+"."+domain)
	c.cfg.Logger.Trace("DNS discovery lookup", "name", name, "err", err)
	if err != nil {
		return nil, err
	}
	for _, txt := range txts {
		e, err := parseEntry(txt, c.cfg.ValidSchemes)
		if errors.Is(err, errUnknownEntry) {
			continue
		}
		if !bytes.HasPrefix(crypto.Keccak256([]byte(txt)), wantHash) {
			err = nameError{name, errHashMismatch}
		} else if err != nil {
			err = nameError{name, err}
		}
		return e, err
	}
	return nil, nameError{name, errNoEntry}
}

// randomIterator traverses a set of trees and returns nodes found in them.
// randomIterator 遍历一组树并返回其中发现的节点。
type randomIterator struct {
	cur      *enode.Node
	ctx      context.Context
	cancelFn context.CancelFunc
	c        *Client

	mu    sync.Mutex
	lc    linkCache              // 跟踪树依赖关系
	trees map[string]*clientTree // 所有树
	// buffers for syncableTrees
	syncableList []*clientTree
	disabledList []*clientTree
}

func (c *Client) newRandomIterator() *randomIterator {
	ctx, cancel := context.WithCancel(context.Background())
	return &randomIterator{
		c:        c,
		ctx:      ctx,
		cancelFn: cancel,
		trees:    make(map[string]*clientTree),
	}
}

// Node returns the current node.
// Node 返回当前节点。
func (it *randomIterator) Node() *enode.Node {
	return it.cur
}

// Close closes the iterator.
// Close 关闭迭代器。
func (it *randomIterator) Close() {
	it.cancelFn()

	it.mu.Lock()
	defer it.mu.Unlock()
	it.trees = nil
}

// Next moves the iterator to the next node.
// Next 将迭代器移动到下一个节点。
func (it *randomIterator) Next() bool {
	it.cur = it.nextNode()
	return it.cur != nil
}

// addTree adds an enrtree:// URL to the iterator.
// addTree 将 enrtree:// URL 添加到迭代器。
func (it *randomIterator) addTree(url string) error {
	le, err := parseLink(url)
	if err != nil {
		return fmt.Errorf("invalid enrtree URL: %v", err)
	}
	it.lc.addLink("", le.str)
	return nil
}

// nextNode syncs random tree entries until it finds a node.
// nextNode 同步随机树条目直到找到一个节点。
func (it *randomIterator) nextNode() *enode.Node {
	for {
		ct := it.pickTree()
		if ct == nil {
			return nil
		}
		n, err := ct.syncRandom(it.ctx)
		if err != nil {
			if errors.Is(err, it.ctx.Err()) {
				return nil // 上下文已取消
			}
			it.c.cfg.Logger.Debug("Error in DNS random node sync", "tree", ct.loc.domain, "err", err)
			continue
		}
		if n != nil {
			return n
		}
	}
}

// pickTree returns a random tree to sync from.
// pickTree 返回一个随机树进行同步。
func (it *randomIterator) pickTree() *clientTree {
	it.mu.Lock()
	defer it.mu.Unlock()

	if it.trees == nil {
		return nil
	}

	if it.lc.changed {
		it.rebuildTrees()
		it.lc.changed = false
	}

	for {
		canSync, trees := it.syncableTrees()
		switch {
		case canSync:
			return trees[rand.Intn(len(trees))]
		case len(trees) > 0:
			if !it.waitForRootUpdates(trees) {
				return nil
			}
		default:
			return nil
		}
	}
}

// syncableTrees finds trees on which any meaningful sync action can be performed.
// syncableTrees 找到可以执行有意义同步操作的树。
func (it *randomIterator) syncableTrees() (canSync bool, trees []*clientTree) {
	it.syncableList = it.syncableList[:0]
	it.disabledList = it.disabledList[:0]

	for _, ct := range it.trees {
		if ct.canSyncRandom() {
			it.syncableList = append(it.syncableList, ct)
		} else {
			it.disabledList = append(it.disabledList, ct)
		}
	}
	if len(it.syncableList) > 0 {
		return true, it.syncableList
	}
	return false, it.disabledList
}

// waitForRootUpdates waits for the closest scheduled root check time on the given trees.
// waitForRootUpdates 等待给定树上最近的计划根检查时间。
func (it *randomIterator) waitForRootUpdates(trees []*clientTree) bool {
	var minTree *clientTree
	var nextCheck mclock.AbsTime
	for _, ct := range trees {
		check := ct.nextScheduledRootCheck()
		if minTree == nil || check < nextCheck {
			minTree = ct
			nextCheck = check
		}
	}

	sleep := nextCheck.Sub(it.c.clock.Now())
	it.c.cfg.Logger.Debug("DNS iterator waiting for root updates", "sleep", sleep, "tree", minTree.loc.domain)
	timeout := it.c.clock.NewTimer(sleep)
	defer timeout.Stop()
	select {
	case <-timeout.C():
		return true
	case <-it.ctx.Done():
		return false
	}
}

// rebuildTrees rebuilds the 'trees' map.
// rebuildTrees 重建 'trees' 映射。
func (it *randomIterator) rebuildTrees() {
	for loc := range it.trees {
		if !it.lc.isReferenced(loc) {
			delete(it.trees, loc)
		}
	}
	for loc := range it.lc.backrefs {
		if it.trees[loc] == nil {
			link, _ := parseLink(linkPrefix + loc)
			it.trees[loc] = newClientTree(it.c, &it.lc, link)
		}
	}
}
