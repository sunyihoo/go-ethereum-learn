// Copyright 2014 The go-ethereum Authors
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

// Package core implements the Ethereum consensus protocol.
package core

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/common/prque"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/internal/syncx"
	"github.com/ethereum/go-ethereum/internal/version"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
)

var (
	// headBlockGauge 用于监控链的当前区块高度
	headBlockGauge = metrics.NewRegisteredGauge("chain/head/block", nil)
	// headBlockGauge 用于监控链的当前区块高度

	// headHeaderGauge 用于监控链的当前头部高度
	headHeaderGauge = metrics.NewRegisteredGauge("chain/head/header", nil)
	// headHeaderGauge 用于监控链的当前头部高度

	// headFastBlockGauge 用于监控链的当前快照同步区块高度
	headFastBlockGauge = metrics.NewRegisteredGauge("chain/head/receipt", nil)
	// headFastBlockGauge 用于监控链的当前快照同步区块高度

	// headFinalizedBlockGauge 用于监控链的当前最终化区块高度
	headFinalizedBlockGauge = metrics.NewRegisteredGauge("chain/head/finalized", nil)
	// headFinalizedBlockGauge 用于监控链的当前最终化区块高度

	// headSafeBlockGauge 用于监控链的当前安全区块高度
	headSafeBlockGauge = metrics.NewRegisteredGauge("chain/head/safe", nil)
	// headSafeBlockGauge 用于监控链的当前安全区块高度

	// chainInfoGauge 用于记录链的基本信息
	chainInfoGauge = metrics.NewRegisteredGaugeInfo("chain/info", nil)
	// chainInfoGauge 用于记录链的基本信息

	// accountReadTimer 用于统计账户读取的时间
	accountReadTimer = metrics.NewRegisteredResettingTimer("chain/account/reads", nil)
	// accountReadTimer 用于统计账户读取的时间

	// accountHashTimer 用于统计账户哈希计算的时间
	accountHashTimer = metrics.NewRegisteredResettingTimer("chain/account/hashes", nil)
	// accountHashTimer 用于统计账户哈希计算的时间

	// accountUpdateTimer 用于统计账户更新的时间
	accountUpdateTimer = metrics.NewRegisteredResettingTimer("chain/account/updates", nil)
	// accountUpdateTimer 用于统计账户更新的时间

	// accountCommitTimer 用于统计账户提交的时间
	accountCommitTimer = metrics.NewRegisteredResettingTimer("chain/account/commits", nil)
	// accountCommitTimer 用于统计账户提交的时间

	// storageReadTimer 用于统计存储读取的时间
	storageReadTimer = metrics.NewRegisteredResettingTimer("chain/storage/reads", nil)
	// storageReadTimer 用于统计存储读取的时间

	// storageUpdateTimer 用于统计存储更新的时间
	storageUpdateTimer = metrics.NewRegisteredResettingTimer("chain/storage/updates", nil)
	// storageUpdateTimer 用于统计存储更新的时间

	// storageCommitTimer 用于统计存储提交的时间
	storageCommitTimer = metrics.NewRegisteredResettingTimer("chain/storage/commits", nil)
	// storageCommitTimer 用于统计存储提交的时间

	// accountReadSingleTimer 用于统计单次账户读取的时间
	accountReadSingleTimer = metrics.NewRegisteredResettingTimer("chain/account/single/reads", nil)
	// accountReadSingleTimer 用于统计单次账户读取的时间

	// storageReadSingleTimer 用于统计单次存储读取的时间
	storageReadSingleTimer = metrics.NewRegisteredResettingTimer("chain/storage/single/reads", nil)
	// storageReadSingleTimer 用于统计单次存储读取的时间

	// snapshotCommitTimer 用于统计快照提交的时间
	snapshotCommitTimer = metrics.NewRegisteredResettingTimer("chain/snapshot/commits", nil)
	// snapshotCommitTimer 用于统计快照提交的时间

	// triedbCommitTimer 用于统计 trie 数据库提交的时间
	triedbCommitTimer = metrics.NewRegisteredResettingTimer("chain/triedb/commits", nil)
	// triedbCommitTimer 用于统计 trie 数据库提交的时间

	// blockInsertTimer 用于统计区块插入的时间
	blockInsertTimer = metrics.NewRegisteredResettingTimer("chain/inserts", nil)
	// blockInsertTimer 用于统计区块插入的时间

	// blockValidationTimer 用于统计区块验证的时间
	blockValidationTimer = metrics.NewRegisteredResettingTimer("chain/validation", nil)
	// blockValidationTimer 用于统计区块验证的时间

	// blockCrossValidationTimer 用于统计区块交叉验证的时间
	blockCrossValidationTimer = metrics.NewRegisteredResettingTimer("chain/crossvalidation", nil)
	// blockCrossValidationTimer 用于统计区块交叉验证的时间

	// blockExecutionTimer 用于统计区块执行的时间
	blockExecutionTimer = metrics.NewRegisteredResettingTimer("chain/execution", nil)
	// blockExecutionTimer 用于统计区块执行的时间

	// blockWriteTimer 用于统计区块写入的时间
	blockWriteTimer = metrics.NewRegisteredResettingTimer("chain/write", nil)
	// blockWriteTimer 用于统计区块写入的时间

	// blockReorgMeter 用于统计区块重组的执行次数
	blockReorgMeter = metrics.NewRegisteredMeter("chain/reorg/executes", nil)
	// blockReorgMeter 用于统计区块重组的执行次数

	// blockReorgAddMeter 用于统计区块重组中添加的次数
	blockReorgAddMeter = metrics.NewRegisteredMeter("chain/reorg/add", nil)
	// blockReorgAddMeter 用于统计区块重组中添加的次数

	// blockReorgDropMeter 用于统计区块重组中丢弃的次数
	blockReorgDropMeter = metrics.NewRegisteredMeter("chain/reorg/drop", nil)
	// blockReorgDropMeter 用于统计区块重组中丢弃的次数

	// blockPrefetchExecuteTimer 用于统计区块预取执行的时间
	blockPrefetchExecuteTimer = metrics.NewRegisteredTimer("chain/prefetch/executes", nil)
	// blockPrefetchExecuteTimer 用于统计区块预取执行的时间

	// blockPrefetchInterruptMeter 用于统计区块预取中断的次数
	blockPrefetchInterruptMeter = metrics.NewRegisteredMeter("chain/prefetch/interrupts", nil)
	// blockPrefetchInterruptMeter 用于统计区块预取中断的次数

	// errInsertionInterrupted 表示插入被中断的错误
	errInsertionInterrupted = errors.New("insertion is interrupted")
	// errInsertionInterrupted 表示插入被中断的错误

	// errChainStopped 表示区块链已停止的错误
	errChainStopped = errors.New("blockchain is stopped")
	// errChainStopped 表示区块链已停止的错误

	// errInvalidOldChain 表示旧链无效的错误
	errInvalidOldChain = errors.New("invalid old chain")
	// errInvalidOldChain 表示旧链无效的错误

	// errInvalidNewChain 表示新链无效的错误
	errInvalidNewChain = errors.New("invalid new chain")
	// errInvalidNewChain 表示新链无效的错误
)

const (
	// bodyCacheLimit 表示区块体的缓存限制
	bodyCacheLimit = 256
	// bodyCacheLimit 表示区块体的缓存限制

	// blockCacheLimit 表示区块的缓存限制
	blockCacheLimit = 256
	// blockCacheLimit 表示区块的缓存限制

	// receiptsCacheLimit 表示收据的缓存限制
	receiptsCacheLimit = 32
	// receiptsCacheLimit 表示收据的缓存限制

	// txLookupCacheLimit 表示交易查找的缓存限制
	txLookupCacheLimit = 1024
	// txLookupCacheLimit 表示交易查找的缓存限制

	// BlockChainVersion ensures that an incompatible database forces a resync from scratch.
	// BlockChainVersion 确保不兼容的数据库强制从头开始重新同步。
	//
	// Changelog:
	//
	// - Version 4
	//   The following incompatible database changes were added:
	//   * the `BlockNumber`, `TxHash`, `TxIndex`, `BlockHash` and `Index` fields of log are deleted
	//   * the `Bloom` field of receipt is deleted
	//   * the `BlockIndex` and `TxIndex` fields of txlookup are deleted
	// - Version 5
	//  The following incompatible database changes were added:
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are no longer stored for a receipt
	//    * the `TxHash`, `GasCost`, and `ContractAddress` fields are computed by looking up the
	//      receipts' corresponding block
	// - Version 6
	//  The following incompatible database changes were added:
	//    * Transaction lookup information stores the corresponding block number instead of block hash
	// - Version 7
	//  The following incompatible database changes were added:
	//    * Use freezer as the ancient database to maintain all ancient data
	// - Version 8
	//  The following incompatible database changes were added:
	//    * New scheme for contract code in order to separate the codes and trie nodes
	//
	// 更新日志：
	//
	// - 版本 4
	//   添加了以下不兼容的数据库更改：
	//   * 日志的 `BlockNumber`、`TxHash`、`TxIndex`、`BlockHash` 和 `Index` 字段被删除
	//   * 收据的 `Bloom` 字段被删除
	//   * 交易查找的 `BlockIndex` 和 `TxIndex` 字段被删除
	// - 版本 5
	//   添加了以下不兼容的数据库更改：
	//     * 收据不再存储 `TxHash`、`GasCost` 和 `ContractAddress` 字段
	//     * `TxHash`、`GasCost` 和 `ContractAddress` 字段通过查找收据对应的区块计算得出
	// - 版本 6
	//   添加了以下不兼容的数据库更改：
	//     * 交易查找信息存储对应的区块号而不是区块哈希
	// - 版本 7
	//   添加了以下不兼容的数据库更改：
	//     * 使用 freezer 作为古老数据库来维护所有古老数据
	// - 版本 8
	//   添加了以下不兼容的数据库更改：
	//     * 新的合约代码方案，以便将代码和 trie 节点分开
	BlockChainVersion uint64 = 8
)

// CacheConfig contains the configuration values for the trie database
// and state snapshot these are resident in a blockchain.
// CacheConfig 包含区块链中 trie 数据库和状态快照的配置值。
type CacheConfig struct {
	TrieCleanLimit int // Memory allowance (MB) to use for caching trie nodes in memory
	// TrieCleanLimit 用于在内存中缓存 trie 节点的内存分配（MB）
	TrieCleanNoPrefetch bool // Whether to disable heuristic state prefetching for followup blocks
	// TrieCleanNoPrefetch 是否禁用后续区块的启发式状态预取
	TrieDirtyLimit int // Memory limit (MB) at which to start flushing dirty trie nodes to disk
	// TrieDirtyLimit 开始将脏 trie 节点刷新到磁盘的内存限制（MB）
	TrieDirtyDisabled bool // Whether to disable trie write caching and GC altogether (archive node)
	// TrieDirtyDisabled 是否完全禁用 trie 写入缓存和垃圾回收（归档节点）
	TrieTimeLimit time.Duration // Time limit after which to flush the current in-memory trie to disk
	// TrieTimeLimit 将当前内存中的 trie 刷新到磁盘的时间限制
	SnapshotLimit int // Memory allowance (MB) to use for caching snapshot entries in memory
	// SnapshotLimit 用于在内存中缓存快照条目的内存分配（MB）
	Preimages bool // Whether to store preimage of trie key to the disk
	// Preimages 是否将 trie 键的预映像存储到磁盘
	StateHistory uint64 // Number of blocks from head whose state histories are reserved.
	// StateHistory 从头部开始保留状态历史的区块数
	StateScheme string // Scheme used to store ethereum states and merkle tree nodes on top
	// StateScheme 用于存储以太坊状态和 merkle 树节点的方案

	SnapshotNoBuild bool // Whether the background generation is allowed
	// SnapshotNoBuild 是否允许后台生成
	SnapshotWait bool // Wait for snapshot construction on startup. TODO(karalabe): This is a dirty hack for testing, nuke it
	// SnapshotWait 在启动时等待快照构建。TODO(karalabe)：这是一个用于测试的临时解决方案，应删除
}

// triedbConfig derives the configures for trie database.
// triedbConfig 推导出 trie 数据库的配置。
func (c *CacheConfig) triedbConfig(isVerkle bool) *triedb.Config {
	config := &triedb.Config{
		Preimages: c.Preimages, // 设置预映像存储选项
		IsVerkle:  isVerkle,    // 是否启用 Verkle 树
	}
	if c.StateScheme == rawdb.HashScheme {
		config.HashDB = &hashdb.Config{
			CleanCacheSize: c.TrieCleanLimit * 1024 * 1024, // 设置哈希数据库的干净缓存大小
		}
	}
	if c.StateScheme == rawdb.PathScheme {
		config.PathDB = &pathdb.Config{
			StateHistory:    c.StateHistory,                 // 设置状态历史保留的区块数
			CleanCacheSize:  c.TrieCleanLimit * 1024 * 1024, // 设置路径数据库的干净缓存大小
			WriteBufferSize: c.TrieDirtyLimit * 1024 * 1024, // 设置写缓冲区大小
		}
	}
	return config
	// 关键逻辑注解：
	// 1. 根据 CacheConfig 创建 trie 数据库配置。
	// 2. 如果使用 HashScheme，则配置 HashDB 的缓存大小。
	// 3. 如果使用 PathScheme，则配置 PathDB 的状态历史和缓存大小。
}

// defaultCacheConfig are the default caching values if none are specified by the
// user (also used during testing).
// defaultCacheConfig 是用户未指定时的默认缓存值（也用于测试）。
var defaultCacheConfig = &CacheConfig{
	TrieCleanLimit: 256,              // 默认干净 trie 缓存限制为 256MB
	TrieDirtyLimit: 256,              // 默认脏 trie 缓存限制为 256MB
	TrieTimeLimit:  5 * time.Minute,  // 默认 trie 刷新时间限制为 5 分钟
	SnapshotLimit:  256,              // 默认快照缓存限制为 256MB
	SnapshotWait:   true,             // 默认启动时等待快照构建
	StateScheme:    rawdb.HashScheme, // 默认状态方案为 HashScheme
}

// DefaultCacheConfigWithScheme returns a deep copied default cache config with
// a provided trie node scheme.
// DefaultCacheConfigWithScheme 返回带有提供的 trie 节点方案的深度复制默认缓存配置。
func DefaultCacheConfigWithScheme(scheme string) *CacheConfig {
	config := *defaultCacheConfig // 深度复制默认配置
	config.StateScheme = scheme   // 设置指定的状态方案
	return &config
	// 关键逻辑注解：
	// 1. 创建 defaultCacheConfig 的副本。
	// 2. 根据传入的 scheme 更新 StateScheme。
}

// txLookup is wrapper over transaction lookup along with the corresponding
// transaction object.
// txLookup 是交易查找的包装器，包含对应的交易对象。
type txLookup struct {
	lookup      *rawdb.LegacyTxLookupEntry // 交易查找条目
	transaction *types.Transaction         // 交易对象
}

// BlockChain represents the canonical chain given a database with a genesis
// block. The Blockchain manages chain imports, reverts, chain reorganisations.
//
// Importing blocks in to the block chain happens according to the set of rules
// defined by the two stage Validator. Processing of blocks is done using the
// Processor which processes the included transaction. The validation of the state
// is done in the second part of the Validator. Failing results in aborting of
// the import.
//
// The BlockChain also helps in returning blocks from **any** chain included
// in the database as well as blocks that represents the canonical chain. It's
// important to note that GetBlock can return any block and does not need to be
// included in the canonical one where as GetBlockByNumber always represents the
// canonical chain.
// BlockChain 表示给定具有创世区块的数据库的规范链。BlockChain 管理链的导入、回退和重组。
//
// 将区块导入区块链按照由两阶段验证器定义的规则进行。区块的处理使用 Processor 处理包含的交易。状态的验证在验证器的第二部分进行。如果失败，将中止导入。
//
// BlockChain 还帮助返回数据库中包含的任何链的区块以及表示规范链的区块。重要的是要注意，GetBlock 可以返回任何区块，不需要包含在规范链中，而 GetBlockByNumber 始终表示规范链。
type BlockChain struct {
	chainConfig *params.ChainConfig // Chain & network configuration
	// chainConfig 链和网络配置
	cacheConfig *CacheConfig // Cache configuration for pruning
	// cacheConfig 用于修剪的缓存配置

	db ethdb.Database // Low level persistent database to store final content in
	// db 低级持久数据库，用于存储最终内容
	snaps *snapshot.Tree // Snapshot tree for fast trie leaf access
	// snaps 快照树，用于快速访问 trie 叶节点
	triegc *prque.Prque[int64, common.Hash] // Priority queue mapping block numbers to tries to gc
	// triegc 优先级队列，将区块号映射到需要垃圾回收的 trie
	gcproc time.Duration // Accumulates canonical block processing for trie dumping
	// gcproc 累积规范区块处理时间，用于 trie 转储
	lastWrite uint64 // Last block when the state was flushed
	// lastWrite 状态最后一次刷新的区块
	flushInterval atomic.Int64 // Time interval (processing time) after which to flush a state
	// flushInterval 刷新状态的时间间隔（处理时间）
	triedb *triedb.Database // The database handler for maintaining trie nodes.
	// triedb 用于维护 trie 节点的数据库处理器
	statedb *state.CachingDB // State database to reuse between imports (contains state cache)
	// statedb 在导入之间重用的状态数据库（包含状态缓存）
	txIndexer *txIndexer // Transaction indexer, might be nil if not enabled
	// txIndexer 交易索引器，如果未启用可能为 nil

	hc            *HeaderChain            // 头部链
	rmLogsFeed    event.Feed              // 删除日志的事件订阅
	chainFeed     event.Feed              // 链事件订阅
	chainHeadFeed event.Feed              // 链头部事件订阅
	logsFeed      event.Feed              // 日志事件订阅
	blockProcFeed event.Feed              // 区块处理事件订阅
	scope         event.SubscriptionScope // 事件订阅范围
	genesisBlock  *types.Block            // 创世区块

	// This mutex synchronizes chain write operations.
	// Readers don't need to take it, they can just read the database.
	// 此互斥锁同步链的写操作。
	// 读者无需获取它，他们可以直接读取数据库。
	chainmu *syncx.ClosableMutex

	currentBlock atomic.Pointer[types.Header] // Current head of the chain
	// currentBlock 链的当前头部
	currentSnapBlock atomic.Pointer[types.Header] // Current head of snap-sync
	// currentSnapBlock 快照同步的当前头部
	currentFinalBlock atomic.Pointer[types.Header] // Latest (consensus) finalized block
	// currentFinalBlock 最新的（共识）最终化区块
	currentSafeBlock atomic.Pointer[types.Header] // Latest (consensus) safe block
	// currentSafeBlock 最新的（共识）安全区块

	bodyCache     *lru.Cache[common.Hash, *types.Body]      // 区块体缓存
	bodyRLPCache  *lru.Cache[common.Hash, rlp.RawValue]     // 区块体 RLP 缓存
	receiptsCache *lru.Cache[common.Hash, []*types.Receipt] // 收据缓存
	blockCache    *lru.Cache[common.Hash, *types.Block]     // 区块缓存

	txLookupLock  sync.RWMutex                      // 交易查找锁
	txLookupCache *lru.Cache[common.Hash, txLookup] // 交易查找缓存

	wg   sync.WaitGroup // 等待组
	quit chan struct{}  // shutdown signal, closed in Stop.
	// quit 关闭信号，在 Stop 中关闭
	stopping atomic.Bool // false if chain is running, true when stopped
	// stopping 如果链运行则为 false，停止时为 true
	procInterrupt atomic.Bool // interrupt signaler for block processing
	// procInterrupt 区块处理的中断信号器

	engine    consensus.Engine // 共识引擎
	validator Validator        // Block and state validator interface
	// validator 区块和状态验证器接口
	prefetcher Prefetcher // 预取器
	processor  Processor  // Block transaction processor interface
	// processor 区块交易处理器接口
	vmConfig vm.Config      // EVM 配置
	logger   *tracing.Hooks // 日志钩子
}

// NewBlockChain returns a fully initialised block chain using information
// available in the database. It initialises the default Ethereum Validator
// and Processor.
// NewBlockChain 返回一个使用数据库中可用信息完全初始化的区块链。它初始化默认的以太坊验证器和处理器。
func NewBlockChain(db ethdb.Database, cacheConfig *CacheConfig, genesis *Genesis, overrides *ChainOverrides, engine consensus.Engine, vmConfig vm.Config, txLookupLimit *uint64) (*BlockChain, error) {
	if cacheConfig == nil {
		cacheConfig = defaultCacheConfig // 如果未提供缓存配置，使用默认配置
	}
	// Open trie database with provided config
	// 使用提供的配置打开 trie 数据库
	enableVerkle, err := EnableVerkleAtGenesis(db, genesis)
	if err != nil {
		return nil, err // 如果检查 Verkle 启用失败，返回错误
	}
	triedb := triedb.NewDatabase(db, cacheConfig.triedbConfig(enableVerkle)) // 创建 trie 数据库

	// Write the supplied genesis to the database if it has not been initialized
	// yet. The corresponding chain config will be returned, either from the
	// provided genesis or from the locally stored configuration if the genesis
	// has already been initialized.
	// 如果数据库尚未初始化创世区块，则将提供的创世区块写入数据库。将返回对应的链配置，可以来自提供的创世区块或本地存储的配置（如果创世区块已初始化）。
	chainConfig, genesisHash, compatErr, err := SetupGenesisBlockWithOverride(db, triedb, genesis, overrides)
	if err != nil {
		return nil, err // 如果设置创世区块失败，返回错误
	}
	log.Info("")
	log.Info(strings.Repeat("-", 153))
	for _, line := range strings.Split(chainConfig.Description(), "\n") {
		log.Info(line) // 打印链配置描述
	}
	log.Info(strings.Repeat("-", 153))
	log.Info("")

	bc := &BlockChain{
		chainConfig:   chainConfig,
		cacheConfig:   cacheConfig,
		db:            db,
		triedb:        triedb,
		triegc:        prque.New[int64, common.Hash](nil),                              // 初始化 trie 垃圾回收队列
		quit:          make(chan struct{}),                                             // 初始化关闭通道
		chainmu:       syncx.NewClosableMutex(),                                        // 初始化链写互斥锁
		bodyCache:     lru.NewCache[common.Hash, *types.Body](bodyCacheLimit),          // 初始化区块体缓存
		bodyRLPCache:  lru.NewCache[common.Hash, rlp.RawValue](bodyCacheLimit),         // 初始化区块体 RLP 缓存
		receiptsCache: lru.NewCache[common.Hash, []*types.Receipt](receiptsCacheLimit), // 初始化收据缓存
		blockCache:    lru.NewCache[common.Hash, *types.Block](blockCacheLimit),        // 初始化区块缓存
		txLookupCache: lru.NewCache[common.Hash, txLookup](txLookupCacheLimit),         // 初始化交易查找缓存
		engine:        engine,
		vmConfig:      vmConfig,
		logger:        vmConfig.Tracer, // 设置日志钩子
	}
	bc.hc, err = NewHeaderChain(db, chainConfig, engine, bc.insertStopped) // 初始化头部链
	if err != nil {
		return nil, err
	}
	bc.flushInterval.Store(int64(cacheConfig.TrieTimeLimit)) // 设置状态刷新间隔
	bc.statedb = state.NewDatabase(bc.triedb, nil)           // 初始化状态数据库
	bc.validator = NewBlockValidator(chainConfig, bc)        // 初始化区块验证器
	bc.prefetcher = newStatePrefetcher(chainConfig, bc.hc)   // 初始化状态预取器
	bc.processor = NewStateProcessor(chainConfig, bc.hc)     // 初始化状态处理器

	bc.genesisBlock = bc.GetBlockByNumber(0) // 获取创世区块
	if bc.genesisBlock == nil {
		return nil, ErrNoGenesis // 如果创世区块不存在，返回错误
	}

	bc.currentBlock.Store(nil)      // 初始化当前区块
	bc.currentSnapBlock.Store(nil)  // 初始化当前快照同步区块
	bc.currentFinalBlock.Store(nil) // 初始化当前最终化区块
	bc.currentSafeBlock.Store(nil)  // 初始化当前安全区块

	// Update chain info data metrics
	// 更新链信息数据指标
	chainInfoGauge.Update(metrics.GaugeInfoValue{"chain_id": bc.chainConfig.ChainID.String()})

	// If Geth is initialized with an external ancient store, re-initialize the
	// missing chain indexes and chain flags. This procedure can survive crash
	// and can be resumed in next restart since chain flags are updated in last step.
	// 如果 Geth 使用外部古老存储初始化，重新初始化缺失的链索引和链标志。此过程可以在崩溃后继续，并在下次重启时恢复，因为链标志在最后一步更新。
	if bc.empty() {
		rawdb.InitDatabaseFromFreezer(bc.db) // 从 freezer 初始化数据库
	}
	// Load blockchain states from disk
	// 从磁盘加载区块链状态
	if err := bc.loadLastState(); err != nil {
		return nil, err
	}
	// Make sure the state associated with the block is available, or log out
	// if there is no available state, waiting for state sync.
	// 确保与区块关联的状态可用，如果没有可用状态，则记录日志并等待状态同步。
	head := bc.CurrentBlock()
	if !bc.HasState(head.Root) {
		if head.Number.Uint64() == 0 {
			// The genesis state is missing, which is only possible in the path-based
			// scheme. This situation occurs when the initial state sync is not finished
			// yet, or the chain head is rewound below the pivot point. In both scenarios,
			// there is no possible recovery approach except for rerunning a snap sync.
			// Do nothing here until the state syncer picks it up.
			// 创世状态缺失，这只可能在基于路径的方案中发生。这种情况发生在初始状态同步尚未完成，或链头部被回退到 pivot 点以下。在这两种情况下，除了重新运行快照同步外，没有可能的恢复方法。
			// 在这里什么也不做，直到状态同步器接手。
			log.Info("Genesis state is missing, wait state sync")
		} else {
			// Head state is missing, before the state recovery, find out the
			// disk layer point of snapshot(if it's enabled). Make sure the
			// rewound point is lower than disk layer.
			// 头部状态缺失，在状态恢复之前，找出快照的磁盘层点（如果启用）。确保回退点低于磁盘层。
			var diskRoot common.Hash
			if bc.cacheConfig.SnapshotLimit > 0 {
				diskRoot = rawdb.ReadSnapshotRoot(bc.db) // 读取快照根
			}
			if diskRoot != (common.Hash{}) {
				log.Warn("Head state missing, repairing", "number", head.Number, "hash", head.Hash(), "snaproot", diskRoot)
				snapDisk, err := bc.setHeadBeyondRoot(head.Number.Uint64(), 0, diskRoot, true) // 修复头部状态
				if err != nil {
					return nil, err
				}
				// Chain rewound, persist old snapshot number to indicate recovery procedure
				// 链已回退，持久化旧快照编号以指示恢复过程
				if snapDisk != 0 {
					rawdb.WriteSnapshotRecoveryNumber(bc.db, snapDisk)
				}
			} else {
				log.Warn("Head state missing, repairing", "number", head.Number, "hash", head.Hash())
				if _, err := bc.setHeadBeyondRoot(head.Number.Uint64(), 0, common.Hash{}, true); err != nil {
					return nil, err
				}
			}
		}
	}
	// Ensure that a previous crash in SetHead doesn't leave extra ancients
	// 确保之前在 SetHead 中的崩溃不会留下多余的古老数据
	if frozen, err := bc.db.Ancients(); err == nil && frozen > 0 {
		var (
			needRewind bool
			low        uint64
		)
		// The head full block may be rolled back to a very low height due to
		// blockchain repair. If the head full block is even lower than the ancient
		// chain, truncate the ancient store.
		// 由于区块链修复，头部完整区块可能被回退到非常低的高度。如果头部完整区块甚至低于古老链，则截断古老存储。
		fullBlock := bc.CurrentBlock()
		if fullBlock != nil && fullBlock.Hash() != bc.genesisBlock.Hash() && fullBlock.Number.Uint64() < frozen-1 {
			needRewind = true
			low = fullBlock.Number.Uint64()
		}
		// In snap sync, it may happen that ancient data has been written to the
		// ancient store, but the LastFastBlock has not been updated, truncate the
		// extra data here.
		// 在快照同步中，可能发生古老数据已写入古老存储，但 LastFastBlock 未更新的情况，在此截断多余数据。
		snapBlock := bc.CurrentSnapBlock()
		if snapBlock != nil && snapBlock.Number.Uint64() < frozen-1 {
			needRewind = true
			if snapBlock.Number.Uint64() < low || low == 0 {
				low = snapBlock.Number.Uint64()
			}
		}
		if needRewind {
			log.Error("Truncating ancient chain", "from", bc.CurrentHeader().Number.Uint64(), "to", low)
			if err := bc.SetHead(low); err != nil {
				return nil, err
			}
		}
	}
	// The first thing the node will do is reconstruct the verification data for
	// the head block (ethash cache or clique voting snapshot). Might as well do
	// it in advance.
	// 节点将做的第一件事是为头部区块重建验证数据（ethash 缓存或 clique 投票快照）。不妨提前做。
	bc.engine.VerifyHeader(bc, bc.CurrentHeader()) // 验证头部

	if bc.logger != nil && bc.logger.OnBlockchainInit != nil {
		bc.logger.OnBlockchainInit(chainConfig) // 调用区块链初始化钩子
	}
	if bc.logger != nil && bc.logger.OnGenesisBlock != nil {
		if block := bc.CurrentBlock(); block.Number.Uint64() == 0 {
			alloc, err := getGenesisState(bc.db, block.Hash()) // 获取创世状态
			if err != nil {
				return nil, fmt.Errorf("failed to get genesis state: %w", err)
			}
			if alloc == nil {
				return nil, errors.New("live blockchain tracer requires genesis alloc to be set")
			}
			bc.logger.OnGenesisBlock(bc.genesisBlock, alloc) // 调用创世区块钩子
		}
	}

	// Load any existing snapshot, regenerating it if loading failed
	// 加载任何现有快照，如果加载失败则重新生成
	if bc.cacheConfig.SnapshotLimit > 0 {
		// If the chain was rewound past the snapshot persistent layer (causing
		// a recovery block number to be persisted to disk), check if we're still
		// in recovery mode and in that case, don't invalidate the snapshot on a
		// head mismatch.
		// 如果链被回退超过快照持久层（导致恢复区块号被持久化到磁盘），检查我们是否仍处于恢复模式，在这种情况下，不要因头部不匹配而使快照无效。
		var recover bool

		head := bc.CurrentBlock()
		if layer := rawdb.ReadSnapshotRecoveryNumber(bc.db); layer != nil && *layer >= head.Number.Uint64() {
			log.Warn("Enabling snapshot recovery", "chainhead", head.Number, "diskbase", *layer)
			recover = true
		}
		snapconfig := snapshot.Config{
			CacheSize:  bc.cacheConfig.SnapshotLimit,   // 设置快照缓存大小
			Recovery:   recover,                        // 是否启用恢复模式
			NoBuild:    bc.cacheConfig.SnapshotNoBuild, // 是否禁止后台构建
			AsyncBuild: !bc.cacheConfig.SnapshotWait,   // 是否异步构建
		}
		bc.snaps, _ = snapshot.New(snapconfig, bc.db, bc.triedb, head.Root) // 创建快照

		// Re-initialize the state database with snapshot
		// 使用快照重新初始化状态数据库
		bc.statedb = state.NewDatabase(bc.triedb, bc.snaps)
	}

	// Rewind the chain in case of an incompatible config upgrade.
	// 如果配置升级不兼容，回退链。
	if compatErr != nil {
		log.Warn("Rewinding chain to upgrade configuration", "err", compatErr)
		if compatErr.RewindToTime > 0 {
			bc.SetHeadWithTimestamp(compatErr.RewindToTime) // 按时间戳回退
		} else {
			bc.SetHead(compatErr.RewindToBlock) // 按区块号回退
		}
		rawdb.WriteChainConfig(db, genesisHash, chainConfig) // 更新链配置
	}
	// Start tx indexer if it's enabled.
	// 如果启用交易索引器，则启动它。
	if txLookupLimit != nil {
		bc.txIndexer = newTxIndexer(*txLookupLimit, bc) // 初始化交易索引器
	}
	return bc, nil
	// 关键逻辑注解：
	// 1. 检查并设置默认缓存配置。
	// 2. 初始化 trie 数据库并处理创世区块。
	// 3. 创建 BlockChain 实例并初始化缓存和组件。
	// 4. 加载最后状态并修复缺失状态。
	// 5. 处理古老数据和快照，启动交易索引器。
}

// empty returns an indicator whether the blockchain is empty.
// Note, it's a special case that we connect a non-empty ancient
// database with an empty node, so that we can plugin the ancient
// into node seamlessly.
// empty 返回区块链是否为空的指示器。
// 注意，这是一个特殊情况，我们将一个非空的古老数据库与一个空节点连接，以便将古老数据无缝插入节点。
func (bc *BlockChain) empty() bool {
	genesis := bc.genesisBlock.Hash()
	for _, hash := range []common.Hash{rawdb.ReadHeadBlockHash(bc.db), rawdb.ReadHeadHeaderHash(bc.db), rawdb.ReadHeadFastBlockHash(bc.db)} {
		if hash != genesis {
			return false // 如果任一头部哈希不是创世哈希，则不为空
		}
	}
	return true
	// 关键逻辑注解：
	// 1. 获取创世区块哈希。
	// 2. 检查所有头部哈希是否等于创世哈希。
}

// loadLastState loads the last known chain state from the database. This method
// assumes that the chain manager mutex is held.
// loadLastState 从数据库加载最后已知的链状态。此方法假定链管理器互斥锁已被持有。
func (bc *BlockChain) loadLastState() error {
	// Restore the last known head block
	// 恢复最后已知的头部区块
	head := rawdb.ReadHeadBlockHash(bc.db)
	if head == (common.Hash{}) {
		// Corrupt or empty database, init from scratch
		// 数据库损坏或为空，从头开始初始化
		log.Warn("Empty database, resetting chain")
		return bc.Reset()
	}
	// Make sure the entire head block is available
	// 确保整个头部区块可用
	headBlock := bc.GetBlockByHash(head)
	if headBlock == nil {
		// Corrupt or empty database, init from scratch
		// 数据库损坏或为空，从头开始初始化
		log.Warn("Head block missing, resetting chain", "hash", head)
		return bc.Reset()
	}
	// Everything seems to be fine, set as the head block
	// 一切正常，设置为头部区块
	bc.currentBlock.Store(headBlock.Header())
	headBlockGauge.Update(int64(headBlock.NumberU64()))

	// Restore the last known head header
	// 恢复最后已知的头部
	headHeader := headBlock.Header()
	if head := rawdb.ReadHeadHeaderHash(bc.db); head != (common.Hash{}) {
		if header := bc.GetHeaderByHash(head); header != nil {
			headHeader = header
		}
	}
	bc.hc.SetCurrentHeader(headHeader)

	// Restore the last known head snap block
	// 恢复最后已知的快照同步区块
	bc.currentSnapBlock.Store(headBlock.Header())
	headFastBlockGauge.Update(int64(headBlock.NumberU64()))

	if head := rawdb.ReadHeadFastBlockHash(bc.db); head != (common.Hash{}) {
		if block := bc.GetBlockByHash(head); block != nil {
			bc.currentSnapBlock.Store(block.Header())
			headFastBlockGauge.Update(int64(block.NumberU64()))
		}
	}

	// Restore the last known finalized block and safe block
	// Note: the safe block is not stored on disk and it is set to the last
	// known finalized block on startup
	// 恢复最后已知的最终化区块和安全区块
	// 注意：安全区块未存储在磁盘上，启动时设置为最后已知的最终化区块
	if head := rawdb.ReadFinalizedBlockHash(bc.db); head != (common.Hash{}) {
		if block := bc.GetBlockByHash(head); block != nil {
			bc.currentFinalBlock.Store(block.Header())
			headFinalizedBlockGauge.Update(int64(block.NumberU64()))
			bc.currentSafeBlock.Store(block.Header())
			headSafeBlockGauge.Update(int64(block.NumberU64()))
		}
	}
	// Issue a status log for the user
	// 为用户发出状态日志
	var (
		currentSnapBlock  = bc.CurrentSnapBlock()
		currentFinalBlock = bc.CurrentFinalBlock()

		headerTd = bc.GetTd(headHeader.Hash(), headHeader.Number.Uint64()) // 获取头部总难度
		blockTd  = bc.GetTd(headBlock.Hash(), headBlock.NumberU64())       // 获取区块总难度
	)
	if headHeader.Hash() != headBlock.Hash() {
		log.Info("Loaded most recent local header", "number", headHeader.Number, "hash", headHeader.Hash(), "td", headerTd, "age", common.PrettyAge(time.Unix(int64(headHeader.Time), 0)))
	}
	log.Info("Loaded most recent local block", "number", headBlock.Number(), "hash", headBlock.Hash(), "td", blockTd, "age", common.PrettyAge(time.Unix(int64(headBlock.Time()), 0)))
	if headBlock.Hash() != currentSnapBlock.Hash() {
		snapTd := bc.GetTd(currentSnapBlock.Hash(), currentSnapBlock.Number.Uint64())
		log.Info("Loaded most recent local snap block", "number", currentSnapBlock.Number, "hash", currentSnapBlock.Hash(), "td", snapTd, "age", common.PrettyAge(time.Unix(int64(currentSnapBlock.Time), 0)))
	}
	if currentFinalBlock != nil {
		finalTd := bc.GetTd(currentFinalBlock.Hash(), currentFinalBlock.Number.Uint64())
		log.Info("Loaded most recent local finalized block", "number", currentFinalBlock.Number, "hash", currentFinalBlock.Hash(), "td", finalTd, "age", common.PrettyAge(time.Unix(int64(currentFinalBlock.Time), 0)))
	}
	if pivot := rawdb.ReadLastPivotNumber(bc.db); pivot != nil {
		log.Info("Loaded last snap-sync pivot marker", "number", *pivot)
	}
	return nil
	// 关键逻辑注解：
	// 1. 从数据库读取头部区块哈希并验证其存在性。
	// 2. 设置当前区块、头部、快照同步区块和最终化区块。
	// 3. 更新相关指标并记录状态日志。
}

// SetHead rewinds the local chain to a new head. Depending on whether the node
// was snap synced or full synced and in which state, the method will try to
// delete minimal data from disk whilst retaining chain consistency.
// SetHead 将本地链回退到一个新的头部。根据节点是快照同步还是完全同步以及处于何种状态，该方法将尝试从磁盘删除最少的数据，同时保持链的一致性。
func (bc *BlockChain) SetHead(head uint64) error {
	if _, err := bc.setHeadBeyondRoot(head, 0, common.Hash{}, false); err != nil {
		return err // 如果回退失败，返回错误
	}
	// Send chain head event to update the transaction pool
	// 发送链头部事件以更新交易池
	header := bc.CurrentBlock()
	if block := bc.GetBlock(header.Hash(), header.Number.Uint64()); block == nil {
		// This should never happen. In practice, previously currentBlock
		// contained the entire block whereas now only a "marker", so there
		// is an ever so slight chance for a race we should handle.
		// 这不应该发生。在实践中，以前的 currentBlock 包含整个区块，而现在只是一个“标记”，因此存在轻微的竞争可能性，我们应该处理。
		log.Error("Current block not found in database", "block", header.Number, "hash", header.Hash())
		return fmt.Errorf("current block missing: #%d [%x..]", header.Number, header.Hash().Bytes()[:4])
	}
	bc.chainHeadFeed.Send(ChainHeadEvent{Header: header}) // 发送链头部事件
	return nil
	// 关键逻辑注解：
	// 1. 调用 setHeadBeyondRoot 执行回退。
	// 2. 获取当前区块并发送链头部事件。
}

// SetHeadWithTimestamp rewinds the local chain to a new head that has at max
// the given timestamp. Depending on whether the node was snap synced or full
// synced and in which state, the method will try to delete minimal data from
// disk whilst retaining chain consistency.
// SetHeadWithTimestamp 将本地链回退到一个新的头部，其最大时间戳为给定的时间戳。根据节点是快照同步还是完全同步以及处于何种状态，该方法将尝试从磁盘删除最少的数据，同时保持链的一致性。
func (bc *BlockChain) SetHeadWithTimestamp(timestamp uint64) error {
	if _, err := bc.setHeadBeyondRoot(0, timestamp, common.Hash{}, false); err != nil {
		return err // 如果回退失败，返回错误
	}
	// Send chain head event to update the transaction pool
	// 发送链头部事件以更新交易池
	header := bc.CurrentBlock()
	if block := bc.GetBlock(header.Hash(), header.Number.Uint64()); block == nil {
		// This should never happen. In practice, previously currentBlock
		// contained the entire block whereas now only a "marker", so there
		// is an ever so slight chance for a race we should handle.
		// 这不应该发生。在实践中，以前的 currentBlock 包含整个区块，而现在只是一个“标记”，因此存在轻微的竞争可能性，我们应该处理。
		log.Error("Current block not found in database", "block", header.Number, "hash", header.Hash())
		return fmt.Errorf("current block missing: #%d [%x..]", header.Number, header.Hash().Bytes()[:4])
	}
	bc.chainHeadFeed.Send(ChainHeadEvent{Header: header}) // 发送链头部事件
	return nil
	// 关键逻辑注解：
	// 1. 调用 setHeadBeyondRoot 按时间戳回退。
	// 2. 获取当前区块并发送链头部事件。
}

// SetFinalized sets the finalized block.
// SetFinalized 设置最终化区块。
func (bc *BlockChain) SetFinalized(header *types.Header) {
	bc.currentFinalBlock.Store(header) // 存储最终化区块头部
	if header != nil {
		rawdb.WriteFinalizedBlockHash(bc.db, header.Hash())           // 写入最终化区块哈希
		headFinalizedBlockGauge.Update(int64(header.Number.Uint64())) // 更新指标
	} else {
		rawdb.WriteFinalizedBlockHash(bc.db, common.Hash{}) // 写入空哈希
		headFinalizedBlockGauge.Update(0)                   // 重置指标
	}
	// 关键逻辑注解：
	// 1. 更新当前最终化区块。
	// 2. 根据 header 是否为 nil，写入哈希并更新指标。
}

// SetSafe sets the safe block.
// SetSafe 设置安全区块。
func (bc *BlockChain) SetSafe(header *types.Header) {
	bc.currentSafeBlock.Store(header) // 存储安全区块头部
	if header != nil {
		headSafeBlockGauge.Update(int64(header.Number.Uint64())) // 更新指标
	} else {
		headSafeBlockGauge.Update(0) // 重置指标
	}
	// 关键逻辑注解：
	// 1. 更新当前安全区块。
	// 2. 根据 header 是否为 nil，更新指标。
}

// rewindHashHead implements the logic of rewindHead in the context of hash scheme.
// rewindHashHead 在哈希方案上下文中实现 rewindHead 的逻辑。
func (bc *BlockChain) rewindHashHead(head *types.Header, root common.Hash) (*types.Header, uint64) {
	var (
		limit uint64 // The oldest block that will be searched for this rewinding
		// limit 将为此回退搜索的最旧区块
		beyondRoot = root == common.Hash{} // Flag whether we're beyond the requested root (no root, always true)
		// beyondRoot 我们是否已超过请求的根（无根时始终为 true）
		pivot = rawdb.ReadLastPivotNumber(bc.db) // Associated block number of pivot point state
		// pivot pivot 点状态的关联区块号
		rootNumber uint64 // Associated block number of requested root
		// rootNumber 请求根的关联区块号

		start = time.Now() // Timestamp the rewinding is restarted
		// start 回退重新开始的时间戳
		logged = time.Now() // Timestamp last progress log was printed
		// logged 上次打印进度日志的时间戳
	)
	// The oldest block to be searched is determined by the pivot block or a constant
	// searching threshold. The rationale behind this is as follows:
	//
	// - Snap sync is selected if the pivot block is available. The earliest available
	//   state is the pivot block itself, so there is no sense in going further back.
	//
	// - Full sync is selected if the pivot block does not exist. The hash database
	//   periodically flushes the state to disk, and the used searching threshold is
	//   considered sufficient to find a persistent state, even for the testnet. It
	//   might be not enough for a chain that is nearly empty. In the worst case,
	//   the entire chain is reset to genesis, and snap sync is re-enabled on top,
	//   which is still acceptable.
	// 将要搜索的最旧区块由 pivot 区块或常量搜索阈值确定。其背后的理由如下：
	//
	// - 如果 pivot 区块可用，则选择快照同步。最早可用状态是 pivot 区块本身，因此没有理由再往回走。
	//
	// - 如果 pivot 区块不存在，则选择完全同步。哈希数据库定期将状态刷新到磁盘，使用的搜索阈值被认为足以找到持久状态，即使对于测试网也是如此。对于几乎为空的链可能不够。在最坏情况下，整个链重置为创世区块，并在顶部重新启用快照同步，这仍然是可以接受的。
	if pivot != nil {
		limit = *pivot // 设置限制为 pivot 区块号
	} else if head.Number.Uint64() > params.FullImmutabilityThreshold {
		limit = head.Number.Uint64() - params.FullImmutabilityThreshold // 设置限制为头部减去阈值
	}
	for {
		logger := log.Trace
		if time.Since(logged) > time.Second*8 {
			logged = time.Now()
			logger = log.Info // 每 8 秒升级日志级别
		}
		logger("Block state missing, rewinding further", "number", head.Number, "hash", head.Hash(), "elapsed", common.PrettyDuration(time.Since(start)))

		// If a root threshold was requested but not yet crossed, check
		// 如果请求了根阈值但尚未跨越，检查
		if !beyondRoot && head.Root == root {
			beyondRoot, rootNumber = true, head.Number.Uint64() // 标记已跨越根并记录区块号
		}
		// If search limit is reached, return the genesis block as the
		// new chain head.
		// 如果达到搜索限制，返回创世区块作为新的链头部。
		if head.Number.Uint64() < limit {
			log.Info("Rewinding limit reached, resetting to genesis", "number", head.Number, "hash", head.Hash(), "limit", limit)
			return bc.genesisBlock.Header(), rootNumber
		}
		// If the associated state is not reachable, continue searching
		// backwards until an available state is found.
		// 如果关联状态不可达，继续向后搜索直到找到可用状态。
		if !bc.HasState(head.Root) {
			// If the chain is gapped in the middle, return the genesis
			// block as the new chain head.
			// 如果链中间有间隙，返回创世区块作为新的链头部。
			parent := bc.GetHeader(head.ParentHash, head.Number.Uint64()-1)
			if parent == nil {
				log.Error("Missing block in the middle, resetting to genesis", "number", head.Number.Uint64()-1, "hash", head.ParentHash)
				return bc.genesisBlock.Header(), rootNumber
			}
			head = parent

			// If the genesis block is reached, stop searching.
			// 如果达到创世区块，停止搜索。
			if head.Number.Uint64() == 0 {
				log.Info("Genesis block reached", "number", head.Number, "hash", head.Hash())
				return head, rootNumber
			}
			continue // keep rewinding
		}
		// Once the available state is found, ensure that the requested root
		// has already been crossed. If not, continue rewinding.
		// 一旦找到可用状态，确保请求的根已被跨越。如果没有，继续回退。
		if beyondRoot || head.Number.Uint64() == 0 {
			log.Info("Rewound to block with state", "number", head.Number, "hash", head.Hash())
			return head, rootNumber
		}
		log.Debug("Skipping block with threshold state", "number", head.Number, "hash", head.Hash(), "root", head.Root)
		head = bc.GetHeader(head.ParentHash, head.Number.Uint64()-1) // Keep rewinding
	}
	// 关键逻辑注解：
	// 1. 根据 pivot 或阈值确定搜索限制。
	// 2. 循环检查状态是否可用，若不可用则回退至父区块。
	// 3. 处理根跨越和限制到达的情况，返回适当的头部。
}

// rewindPathHead implements the logic of rewindHead in the context of path scheme.
// rewindPathHead 在路径方案上下文中实现 rewindHead 的逻辑。
func (bc *BlockChain) rewindPathHead(head *types.Header, root common.Hash) (*types.Header, uint64) {
	var (
		pivot = rawdb.ReadLastPivotNumber(bc.db) // Associated block number of pivot block
		// pivot pivot 区块的关联区块号
		rootNumber uint64 // Associated block number of requested root
		// rootNumber 请求根的关联区块号

		// BeyondRoot represents whether the requested root is already
		// crossed. The flag value is set to true if the root is empty.
		// BeyondRoot 表示请求的根是否已被跨越。如果根为空，则标志值为 true。
		beyondRoot = root == common.Hash{}

		// noState represents if the target state requested for search
		// is unavailable and impossible to be recovered.
		// noState 表示请求搜索的目标状态是否不可用且无法恢复。
		noState = !bc.HasState(root) && !bc.stateRecoverable(root)

		start = time.Now() // Timestamp the rewinding is restarted
		// start 回退重新开始的时间戳
		logged = time.Now() // Timestamp last progress log was printed
		// logged 上次打印进度日志的时间戳
	)
	// Rewind the head block tag until an available state is found.
	// 回退头部区块标签直到找到可用状态。
	for {
		logger := log.Trace
		if time.Since(logged) > time.Second*8 {
			logged = time.Now()
			logger = log.Info // 每 8 秒升级日志级别
		}
		logger("Block state missing, rewinding further", "number", head.Number, "hash", head.Hash(), "elapsed", common.PrettyDuration(time.Since(start)))

		// If a root threshold was requested but not yet crossed, check
		// 如果请求了根阈值但尚未跨越，检查
		if !beyondRoot && head.Root == root {
			beyondRoot, rootNumber = true, head.Number.Uint64() // 标记已跨越根并记录区块号
		}
		// If the root threshold hasn't been crossed but the available
		// state is reached, quickly determine if the target state is
		// possible to be reached or not.
		// 如果根阈值尚未跨越但已达到可用状态，快速确定目标状态是否可能到达。
		if !beyondRoot && noState && bc.HasState(head.Root) {
			beyondRoot = true
			log.Info("Disable the search for unattainable state", "root", root)
		}
		// Check if the associated state is available or recoverable if
		// the requested root has already been crossed.
		// 如果请求的根已被跨越，检查关联状态是否可用或可恢复。
		if beyondRoot && (bc.HasState(head.Root) || bc.stateRecoverable(head.Root)) {
			break // 找到可用或可恢复状态，退出循环
		}
		// If pivot block is reached, return the genesis block as the
		// new chain head. Theoretically there must be a persistent
		// state before or at the pivot block, prevent endless rewinding
		// towards the genesis just in case.
		// 如果达到 pivot 区块，返回创世区块作为新的链头部。理论上在 pivot 区块之前或处必须有持久状态，以防无休止地回退到创世区块。
		if pivot != nil && *pivot >= head.Number.Uint64() {
			log.Info("Pivot block reached, resetting to genesis", "number", head.Number, "hash", head.Hash())
			return bc.genesisBlock.Header(), rootNumber
		}
		// If the chain is gapped in the middle, return the genesis
		// block as the new chain head
		// 如果链中间有间隙，返回创世区块作为新的链头部
		parent := bc.GetHeader(head.ParentHash, head.Number.Uint64()-1) // Keep rewinding
		if parent == nil {
			log.Error("Missing block in the middle, resetting to genesis", "number", head.Number.Uint64()-1, "hash", head.ParentHash)
			return bc.genesisBlock.Header(), rootNumber
		}
		head = parent

		// If the genesis block is reached, stop searching.
		// 如果达到创世区块，停止搜索。
		if head.Number.Uint64() == 0 {
			log.Info("Genesis block reached", "number", head.Number, "hash", head.Hash())
			return head, rootNumber
		}
	}
	// Recover if the target state if it's not available yet.
	// 如果目标状态尚不可用，则恢复。
	if !bc.HasState(head.Root) {
		if err := bc.triedb.Recover(head.Root); err != nil {
			log.Crit("Failed to rollback state", "err", err)
		}
	}
	log.Info("Rewound to block with state", "number", head.Number, "hash", head.Hash())
	return head, rootNumber
	// 关键逻辑注解：
	// 1. 检查根是否跨越并确定是否可恢复。
	// 2. 循环回退直到找到可用或可恢复状态，或达到 pivot/genesis。
	// 3. 若状态不可用，尝试恢复并返回最终头部。
}

// rewindHead searches the available states in the database and returns the associated
// block as the new head block.
//
// If the given root is not empty, then the rewind should attempt to pass the specified
// state root and return the associated block number as well. If the root, typically
// representing the state corresponding to snapshot disk layer, is deemed impassable,
// then block number zero is returned, indicating that snapshot recovery is disabled
// and the whole snapshot should be auto-generated in case of head mismatch.
// rewindHead 在数据库中搜索可用状态并返回关联的区块作为新的头部区块。
//
// 如果给定的根不为空，则回退应尝试通过指定的状态根并返回关联的区块号。如果根（通常表示快照磁盘层的状态）被认为不可通过，则返回区块号零，表示快照恢复被禁用，并且在头部不匹配的情况下应自动生成整个快照。
func (bc *BlockChain) rewindHead(head *types.Header, root common.Hash) (*types.Header, uint64) {
	if bc.triedb.Scheme() == rawdb.PathScheme {
		return bc.rewindPathHead(head, root) // 使用路径方案回退
	}
	return bc.rewindHashHead(head, root) // 使用哈希方案回退
	// 关键逻辑注解：
	// 1. 根据 trie 数据库方案选择回退方法。
	// 2. 返回回退后的头部和根区块号。
}

// setHeadBeyondRoot rewinds the local chain to a new head with the extra condition
// that the rewind must pass the specified state root. This method is meant to be
// used when rewinding with snapshots enabled to ensure that we go back further than
// persistent disk layer. Depending on whether the node was snap synced or full, and
// in which state, the method will try to delete minimal data from disk whilst
// retaining chain consistency.
//
// The method also works in timestamp mode if `head == 0` but `time != 0`. In that
// case blocks are rolled back until the new head becomes older or equal to the
// requested time. If both `head` and `time` is 0, the chain is rewound to genesis.
//
// The method returns the block number where the requested root cap was found.
// setHeadBeyondRoot 将本地链回退到一个新的头部，并附加条件，即回退必须通过指定的状态根。此方法旨在启用快照时使用，以确保回退超过持久化磁盘层。根据节点是快照同步还是全同步，以及处于何种状态，该方法将尝试从磁盘删除最少的数据，同时保持链一致性。
//
// 如果 `head == 0` 但 `time != 0`，该方法将以时间戳模式工作。在这种情况下，区块将被回滚，直到新头部的时间早于或等于请求的时间。如果 `head` 和 `time` 均为 0，则链将回退到创世块。
//
// 该方法返回找到请求根上限的区块编号。
func (bc *BlockChain) setHeadBeyondRoot(head uint64, time uint64, root common.Hash, repair bool) (uint64, error) {
	if !bc.chainmu.TryLock() {
		return 0, errChainStopped // 中文翻译：如果无法获取锁，返回链已停止错误
	}
	defer bc.chainmu.Unlock() // 中文翻译：延迟释放锁

	var (
		// Track the block number of the requested root hash
		// 跟踪请求的根哈希的区块编号
		rootNumber uint64 // (no root == always 0)
		// 中文翻译：（无根时始终为 0）

		// Retrieve the last pivot block to short circuit rollbacks beyond it
		// and the current freezer limit to start nuking it's underflown.
		// 检索最后一个 pivot 块以短路超过它的回滚，并获取当前 freezer 限制以开始清除其溢出部分。
		pivot = rawdb.ReadLastPivotNumber(bc.db) // 中文注解：读取最后一个 pivot 块编号
	)
	updateFn := func(db ethdb.KeyValueWriter, header *types.Header) (*types.Header, bool) {
		// Rewind the blockchain, ensuring we don't end up with a stateless head
		// block. Note, depth equality is permitted to allow using SetHead as a
		// chain reparation mechanism without deleting any data!
		// 回退区块链，确保不会以无状态头部块结束。注意，允许深度相等以便将 SetHead 用作链修复机制，而不删除任何数据！
		if currentBlock := bc.CurrentBlock(); currentBlock != nil && header.Number.Uint64() <= currentBlock.Number.Uint64() {
			var newHeadBlock *types.Header // 中文注解：新的头部区块
			newHeadBlock, rootNumber = bc.rewindHead(header, root)
			rawdb.WriteHeadBlockHash(db, newHeadBlock.Hash())

			// Degrade the chain markers if they are explicitly reverted.
			// In theory we should update all in-memory markers in the
			// last step, however the direction of SetHead is from high
			// to low, so it's safe to update in-memory markers directly.
			// 如果链标记被明确回退，则降低它们。
			// 理论上我们应该在最后一步更新所有内存中的标记，然而 SetHead 的方向是从高到低，因此直接更新内存中的标记是安全的。
			bc.currentBlock.Store(newHeadBlock)
			headBlockGauge.Update(int64(newHeadBlock.Number.Uint64()))

			// The head state is missing, which is only possible in the path-based
			// scheme. This situation occurs when the chain head is rewound below
			// the pivot point. In this scenario, there is no possible recovery
			// approach except for rerunning a snap sync. Do nothing here until the
			// state syncer picks it up.
			// 头部状态缺失，这仅在基于路径的方案中可能发生。这种情况发生在链头部回退到 pivot 点以下时。在此场景中，除了重新运行快照同步外，没有可能的恢复方法。在此处不做任何操作，直到状态同步器处理它。
			if !bc.HasState(newHeadBlock.Root) {
				if newHeadBlock.Number.Uint64() != 0 {
					log.Crit("Chain is stateless at a non-genesis block")
					// 中文翻译：链在非创世块处无状态
				}
				log.Info("Chain is stateless, wait state sync", "number", newHeadBlock.Number, "hash", newHeadBlock.Hash())
				// 中文翻译：链无状态，等待状态同步
			}
		}
		// Rewind the snap block in a simpleton way to the target head
		// 以简单的方式将快照块回退到目标头部
		if currentSnapBlock := bc.CurrentSnapBlock(); currentSnapBlock != nil && header.Number.Uint64() < currentSnapBlock.Number.Uint64() {
			newHeadSnapBlock := bc.GetBlock(header.Hash(), header.Number.Uint64())
			// If either blocks reached nil, reset to the genesis state
			// 如果任一块达到 nil，重置为创世状态
			if newHeadSnapBlock == nil {
				newHeadSnapBlock = bc.genesisBlock
			}
			rawdb.WriteHeadFastBlockHash(db, newHeadSnapBlock.Hash())

			// Degrade the chain markers if they are explicitly reverted.
			// In theory we should update all in-memory markers in the
			// last step, however the direction of SetHead is from high
			// to low, so it's safe the update in-memory markers directly.
			// 如果链标记被明确回退，则降低它们。
			// 理论上我们应该在最后一步更新所有内存中的标记，然而 SetHead 的方向是从高到低，因此直接更新内存中的标记是安全的。
			bc.currentSnapBlock.Store(newHeadSnapBlock.Header())
			headFastBlockGauge.Update(int64(newHeadSnapBlock.NumberU64()))
		}
		var (
			headHeader = bc.CurrentBlock()          // 中文注解：当前头部区块
			headNumber = headHeader.Number.Uint64() // 中文注解：当前头部区块编号
		)
		// If setHead underflown the freezer threshold and the block processing
		// intent afterwards is full block importing, delete the chain segment
		// between the stateful-block and the sethead target.
		// 如果 setHead 溢出 freezer 阈值并且之后的区块处理意图是全块导入，则删除有状态块和 sethead 目标之间的链段。
		var wipe bool                 // 中文注解：是否需要擦除数据
		frozen, _ := bc.db.Ancients() // 中文注解：获取冻结块数量
		if headNumber+1 < frozen {
			wipe = pivot == nil || headNumber >= *pivot
		}
		return headHeader, wipe // Only force wipe if full synced
		// 中文翻译：仅在完全同步时强制擦除
	}
	// Rewind the header chain, deleting all block bodies until then
	// 回退头部链，删除直到那时为止的所有块体
	delFn := func(db ethdb.KeyValueWriter, hash common.Hash, num uint64) {
		// Ignore the error here since light client won't hit this path
		// 在此忽略错误，因为轻客户端不会进入此路径
		frozen, _ := bc.db.Ancients()
		if num+1 <= frozen {
			// Truncate all relative data(header, total difficulty, body, receipt
			// and canonical hash) from ancient store.
			// 从古老存储中截断所有相关数据（头部、总难度、主体、收据和规范哈希）。
			if _, err := bc.db.TruncateHead(num); err != nil {
				log.Crit("Failed to truncate ancient data", "number", num, "err", err)
				// 中文翻译：无法截断古老数据
			}
			// Remove the hash <-> number mapping from the active store.
			// 从活动存储中移除哈希 <-> 编号映射。
			rawdb.DeleteHeaderNumber(db, hash)
		} else {
			// Remove relative body and receipts from the active store.
			// The header, total difficulty and canonical hash will be
			// removed in the hc.SetHead function.
			// 从活动存储中移除相关主体和收据。
			// 头部、总难度和规范哈希将在 hc.SetHead 函数中移除。
			rawdb.DeleteBody(db, hash, num)
			rawdb.DeleteReceipts(db, hash, num)
		}
		// Todo(rjl493456442) txlookup, bloombits, etc
		// Todo(rjl493456442) 交易查找、bloom位 等
	}
	// If SetHead was only called as a chain reparation method, try to skip
	// touching the header chain altogether, unless the freezer is broken
	// 如果 SetHead 仅作为链修复方法被调用，尝试完全跳过触及头部链，除非 freezer 损坏
	if repair {
		if target, force := updateFn(bc.db, bc.CurrentBlock()); force {
			bc.hc.SetHead(target.Number.Uint64(), nil, delFn)
		}
	} else {
		// Rewind the chain to the requested head and keep going backwards until a
		// block with a state is found or snap sync pivot is passed
		// 将链回退到请求的头部，并继续向后回退，直到找到带有状态的块或通过快照同步 pivot
		if time > 0 {
			log.Warn("Rewinding blockchain to timestamp", "target", time)
			// 中文翻译：将区块链回退到时间戳
			bc.hc.SetHeadWithTimestamp(time, updateFn, delFn)
		} else {
			log.Warn("Rewinding blockchain to block", "target", head)
			// 中文翻译：将区块链回退到区块
			bc.hc.SetHead(head, updateFn, delFn)
		}
	}
	// Clear out any stale content from the caches
	// 清除缓存中的任何过期内容
	bc.bodyCache.Purge()
	bc.bodyRLPCache.Purge()
	bc.receiptsCache.Purge()
	bc.blockCache.Purge()
	bc.txLookupCache.Purge()

	// Clear safe block, finalized block if needed
	// 如果需要，清除安全块和最终化块
	if safe := bc.CurrentSafeBlock(); safe != nil && head < safe.Number.Uint64() {
		log.Warn("SetHead invalidated safe block")
		// 中文翻译：SetHead 使安全块无效
		bc.SetSafe(nil)
	}
	if finalized := bc.CurrentFinalBlock(); finalized != nil && head < finalized.Number.Uint64() {
		log.Error("SetHead invalidated finalized block")
		// 中文翻译：SetHead 使最终化块无效
		bc.SetFinalized(nil)
	}
	return rootNumber, bc.loadLastState()
	// 关键逻辑注解：
	// 1. 获取链锁并初始化 pivot 点。
	// 2. 定义 updateFn 更新头部并检查状态可用性。
	// 3. 定义 delFn 删除超出目标的数据。
	// 4. 根据 repair 参数或时间戳/高度回退链。
	// 5. 清理缓存和安全/最终化标记，返回根编号。
}

// SnapSyncCommitHead sets the current head block to the one defined by the hash
// irrelevant what the chain contents were prior.
// SnapSyncCommitHead 将当前头部块设置为由哈希定义的块，与之前的链内容无关。
func (bc *BlockChain) SnapSyncCommitHead(hash common.Hash) error {
	// Make sure that both the block as well at its state trie exists
	// 确保块及其状态 trie 都存在
	block := bc.GetBlockByHash(hash)
	if block == nil {
		return fmt.Errorf("non existent block [%x..]", hash[:4])
		// 中文翻译：不存在的块 [%x..]
	}
	// Reset the trie database with the fresh snap synced state.
	// 使用新鲜的快照同步状态重置 trie 数据库。
	root := block.Root()
	if bc.triedb.Scheme() == rawdb.PathScheme {
		if err := bc.triedb.Enable(root); err != nil {
			return err
		}
	}
	if !bc.HasState(root) {
		return fmt.Errorf("non existent state [%x..]", root[:4])
		// 中文翻译：不存在的状态 [%x..]
	}
	// If all checks out, manually set the head block.
	// 如果所有检查通过，手动设置头部块。
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	bc.currentBlock.Store(block.Header())
	headBlockGauge.Update(int64(block.NumberU64()))
	bc.chainmu.Unlock()

	// Destroy any existing state snapshot and regenerate it in the background,
	// also resuming the normal maintenance of any previously paused snapshot.
	// 销毁任何现有的状态快照并在后台重新生成，同时恢复任何先前暂停的快照的正常维护。
	if bc.snaps != nil {
		bc.snaps.Rebuild(root)
	}
	log.Info("Committed new head block", "number", block.Number(), "hash", hash)
	// 中文翻译：提交了新的头部块
	return nil
	// 关键逻辑注解：
	// 1. 验证块和状态存在。
	// 2. 更新 trie 数据库并设置新头部。
	// 3. 重建快照并记录日志。
}

// Reset purges the entire blockchain, restoring it to its genesis state.
// Reset 清空整个区块链，将其恢复到创世状态。
func (bc *BlockChain) Reset() error {
	return bc.ResetWithGenesisBlock(bc.genesisBlock)
	// 关键逻辑注解：
	// 1. 调用 ResetWithGenesisBlock 重置到创世块。
}

// ResetWithGenesisBlock purges the entire blockchain, restoring it to the
// specified genesis state.
// ResetWithGenesisBlock 清空整个区块链，将其恢复到指定的创世状态。
func (bc *BlockChain) ResetWithGenesisBlock(genesis *types.Block) error {
	// Dump the entire block chain and purge the caches
	// 丢弃整个区块链并清除缓存
	if err := bc.SetHead(0); err != nil {
		return err
	}
	if !bc.chainmu.TryLock() {
		return errChainStopped
	}
	defer bc.chainmu.Unlock()

	// Prepare the genesis block and reinitialise the chain
	// 准备创世块并重新初始化链
	batch := bc.db.NewBatch()
	rawdb.WriteTd(batch, genesis.Hash(), genesis.NumberU64(), genesis.Difficulty())
	rawdb.WriteBlock(batch, genesis)
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write genesis block", "err", err)
		// 中文翻译：无法写入创世块
	}
	bc.writeHeadBlock(genesis)

	// Last update all in-memory chain markers
	// 最后更新所有内存中的链标记
	bc.genesisBlock = genesis
	bc.currentBlock.Store(bc.genesisBlock.Header())
	headBlockGauge.Update(int64(bc.genesisBlock.NumberU64()))
	bc.hc.SetGenesis(bc.genesisBlock.Header())
	bc.hc.SetCurrentHeader(bc.genesisBlock.Header())
	bc.currentSnapBlock.Store(bc.genesisBlock.Header())
	headFastBlockGauge.Update(int64(bc.genesisBlock.NumberU64()))
	return nil
	// 关键逻辑注解：
	// 1. 调用 SetHead(0) 清空链。
	// 2. 写入创世块并更新所有链标记。
}

// Export writes the active chain to the given writer.
// Export 将活动链写入给定的写入器。
func (bc *BlockChain) Export(w io.Writer) error {
	return bc.ExportN(w, uint64(0), bc.CurrentBlock().Number.Uint64())
	// 关键逻辑注解：
	// 1. 调用 ExportN 导出从 0 到当前块的链。
}

// ExportN writes a subset of the active chain to the given writer.
// ExportN 将活动链的子集写入给定的写入器。
func (bc *BlockChain) ExportN(w io.Writer, first uint64, last uint64) error {
	if first > last {
		return fmt.Errorf("export failed: first (%d) is greater than last (%d)", first, last)
		// 中文翻译：导出失败：第一个 (%d) 大于最后一个 (%d)
	}
	log.Info("Exporting batch of blocks", "count", last-first+1)
	// 中文翻译：正在导出批量区块

	var (
		parentHash common.Hash  // 中文注解：父区块哈希
		start      = time.Now() // 中文注解：开始时间
		reported   = time.Now() // 中文注解：报告时间
	)
	for nr := first; nr <= last; nr++ {
		block := bc.GetBlockByNumber(nr)
		if block == nil {
			return fmt.Errorf("export failed on #%d: not found", nr)
			// 中文翻译：导出在 #%d 上失败：未找到
		}
		if nr > first && block.ParentHash() != parentHash {
			return errors.New("export failed: chain reorg during export")
			// 中文翻译：导出失败：导出期间链重组
		}
		parentHash = block.Hash()
		if err := block.EncodeRLP(w); err != nil {
			return err
		}
		if time.Since(reported) >= statsReportLimit {
			log.Info("Exporting blocks", "exported", block.NumberU64()-first, "elapsed", common.PrettyDuration(time.Since(start)))
			// 中文翻译：正在导出区块
			reported = time.Now()
		}
	}
	return nil
	// 关键逻辑注解：
	// 1. 验证起止范围。
	// 2. 逐块导出并检查连续性。
	// 3. 使用 RLP 编码写入。
}

// writeHeadBlock injects a new head block into the current block chain. This method
// assumes that the block is indeed a true head. It will also reset the head
// header and the head snap sync block to this very same block if they are older
// or if they are on a different side chain.
//
// Note, this function assumes that the `mu` mutex is held!
// writeHeadBlock 将一个新的头部块注入当前区块链。此方法假定该块确实是一个真正的头部。它还将头部和快照同步块重置为同一个块，如果它们较旧或在不同的侧链上。
//
// 注意，此函数假定 `mu` 互斥锁已被持有！
func (bc *BlockChain) writeHeadBlock(block *types.Block) {
	// Add the block to the canonical chain number scheme and mark as the head
	// 将块添加到规范链编号方案并标记为头部
	batch := bc.db.NewBatch()
	rawdb.WriteHeadHeaderHash(batch, block.Hash())
	rawdb.WriteHeadFastBlockHash(batch, block.Hash())
	rawdb.WriteCanonicalHash(batch, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(batch, block)
	rawdb.WriteHeadBlockHash(batch, block.Hash())

	// Flush the whole batch into the disk, exit the node if failed
	// 将整个批次刷新到磁盘，如果失败则退出节点
	if err := batch.Write(); err != nil {
		log.Crit("Failed to update chain indexes and markers", "err", err)
		// 中文翻译：无法更新链索引和标记
	}
	// Update all in-memory chain markers in the last step
	// 在最后一步更新所有内存中的链标记
	bc.hc.SetCurrentHeader(block.Header())

	bc.currentSnapBlock.Store(block.Header())
	headFastBlockGauge.Update(int64(block.NumberU64()))

	bc.currentBlock.Store(block.Header())
	headBlockGauge.Update(int64(block.NumberU64()))
	// 关键逻辑注解：
	// 1. 写入头部相关的所有数据库条目。
	// 2. 更新内存中的链标记。
}

// stopWithoutSaving stops the blockchain service. If any imports are currently in progress
// it will abort them using the procInterrupt. This method stops all running
// goroutines, but does not do all the post-stop work of persisting data.
// OBS! It is generally recommended to use the Stop method!
// This method has been exposed to allow tests to stop the blockchain while simulating
// a crash.
// stopWithoutSaving 停止区块链服务。如果当前有任何导入正在进行，它将使用 procInterrupt 中止它们。此方法停止所有运行的 goroutine，但不执行所有停止后持久化数据的工作。
// 注意！一般建议使用 Stop 方法！
// 此方法已被暴露，以允许测试在模拟崩溃时停止区块链。
func (bc *BlockChain) stopWithoutSaving() {
	if !bc.stopping.CompareAndSwap(false, true) {
		return
	}
	// Signal shutdown tx indexer.
	// 信号关闭交易索引器。
	if bc.txIndexer != nil {
		bc.txIndexer.close()
	}
	// Unsubscribe all subscriptions registered from blockchain.
	// 取消订阅所有从区块链注册的订阅。
	bc.scope.Close()

	// Signal shutdown to all goroutines.
	// 向所有 goroutine 发送关闭信号。
	close(bc.quit)
	bc.StopInsert()

	// Now wait for all chain modifications to end and persistent goroutines to exit.
	//
	// Note: Close waits for the mutex to become available, i.e. any running chain
	// modification will have exited when Close returns. Since we also called StopInsert,
	// the mutex should become available quickly. It cannot be taken again after Close has
	// returned.
	// 现在等待所有链修改结束和持久化 goroutine 退出。
	//
	// 注意：Close 等待互斥锁变得可用，即当 Close 返回时，任何运行的链修改都已退出。由于我们还调用了 StopInsert，互斥锁应该很快变得可用。在 Close 返回后无法再次获取。
	bc.chainmu.Close()
	bc.wg.Wait()
	// 关键逻辑注解：
	// 1. 使用原子操作标记停止状态。
	// 2. 关闭索引器、订阅和 goroutine。
	// 3. 等待所有操作完成。
}

// Stop stops the blockchain service. If any imports are currently in progress
// it will abort them using the procInterrupt.
// Stop 停止区块链服务。如果当前有任何导入正在进行，它将使用 procInterrupt 中止它们。
func (bc *BlockChain) Stop() {
	bc.stopWithoutSaving()

	// Ensure that the entirety of the state snapshot is journaled to disk.
	// 确保状态快照的全部内容都被记录到磁盘。
	var snapBase common.Hash // 中文注解：快照基础哈希
	if bc.snaps != nil {
		var err error
		if snapBase, err = bc.snaps.Journal(bc.CurrentBlock().Root); err != nil {
			log.Error("Failed to journal state snapshot", "err", err)
			// 中文翻译：无法记录状态快照
		}
		bc.snaps.Release()
	}
	if bc.triedb.Scheme() == rawdb.PathScheme {
		// Ensure that the in-memory trie nodes are journaled to disk properly.
		// 确保内存中的 trie 节点被正确记录到磁盘。
		if err := bc.triedb.Journal(bc.CurrentBlock().Root); err != nil {
			log.Info("Failed to journal in-memory trie nodes", "err", err)
			// 中文翻译：无法记录内存中的 trie 节点
		}
	} else {
		// Ensure the state of a recent block is also stored to disk before exiting.
		// We're writing three different states to catch different restart scenarios:
		//  - HEAD:     So we don't need to reprocess any blocks in the general case
		//  - HEAD-1:   So we don't do large reorgs if our HEAD becomes an uncle
		//  - HEAD-127: So we have a hard limit on the number of blocks reexecuted
		// 确保在退出前将最近块的状态也存储到磁盘。
		// 我们写入三种不同的状态以捕捉不同的重启场景：
		//  - HEAD:     因此在一般情况下我们无需重新处理任何块
		//  - HEAD-1:   因此如果我们的 HEAD 成为叔块，我们不会进行大型重组
		//  - HEAD-127: 因此我们对重新执行的块数有一个硬性限制
		if !bc.cacheConfig.TrieDirtyDisabled {
			triedb := bc.triedb

			for _, offset := range []uint64{0, 1, state.TriesInMemory - 1} {
				if number := bc.CurrentBlock().Number.Uint64(); number > offset {
					recent := bc.GetBlockByNumber(number - offset)

					log.Info("Writing cached state to disk", "block", recent.Number(), "hash", recent.Hash(), "root", recent.Root())
					// 中文翻译：将缓存状态写入磁盘
					if err := triedb.Commit(recent.Root(), true); err != nil {
						log.Error("Failed to commit recent state trie", "err", err)
						// 中文翻译：无法提交最近的状态 trie
					}
				}
			}
			if snapBase != (common.Hash{}) {
				log.Info("Writing snapshot state to disk", "root", snapBase)
				// 中文翻译：将快照状态写入磁盘
				if err := triedb.Commit(snapBase, true); err != nil {
					log.Error("Failed to commit recent state trie", "err", err)
					// 中文翻译：无法提交最近的状态 trie
				}
			}
			for !bc.triegc.Empty() {
				triedb.Dereference(bc.triegc.PopItem())
			}
			if _, nodes, _ := triedb.Size(); nodes != 0 { // all memory is contained within the nodes return for hashdb
				log.Error("Dangling trie nodes after full cleanup")
				// 中文翻译：完全清理后仍存在悬空 trie 节点
			}
		}
	}
	// Allow tracers to clean-up and release resources.
	// 允许跟踪器清理并释放资源。
	if bc.logger != nil && bc.logger.OnClose != nil {
		bc.logger.OnClose()
	}
	// Close the trie database, release all the held resources as the last step.
	// 关闭 trie 数据库，作为最后一步释放所有持有的资源。
	if err := bc.triedb.Close(); err != nil {
		log.Error("Failed to close trie database", "err", err)
		// 中文翻译：无法关闭 trie 数据库
	}
	log.Info("Blockchain stopped")
	// 中文翻译：区块链已停止
	// 关键逻辑注解：
	// 1. 调用 stopWithoutSaving 停止服务。
	// 2. 将快照和 trie 状态持久化到磁盘。
	// 3. 清理资源并关闭数据库。
}

// StopInsert interrupts all insertion methods, causing them to return
// errInsertionInterrupted as soon as possible. Insertion is permanently disabled after
// calling this method.
// StopInsert 中断所有插入方法，使其尽快返回 errInsertionInterrupted。调用此方法后，插入将被永久禁用。
func (bc *BlockChain) StopInsert() {
	bc.procInterrupt.Store(true) // 中文注解：设置中断标志
	// 关键逻辑注解：
	// 1. 使用原子操作设置插入中断标志。
}

// insertStopped returns true after StopInsert has been called.
// insertStopped 在 StopInsert 被调用后返回 true。
func (bc *BlockChain) insertStopped() bool {
	return bc.procInterrupt.Load() // 中文注解：检查中断标志
	// 关键逻辑注解：
	// 1. 使用原子操作读取插入中断状态。
}

// WriteStatus status of write
// WriteStatus 写入状态
type WriteStatus byte // 中文注解：写入状态的枚举类型

const (
	NonStatTy   WriteStatus = iota // 中文注解：非状态类型
	CanonStatTy                    // 中文注解：规范状态类型
	SideStatTy                     // 中文注解：侧链状态类型
)

// InsertReceiptChain attempts to complete an already existing header chain with
// transaction and receipt data.
// InsertReceiptChain 尝试用交易和收据数据完成已有的头部链。
func (bc *BlockChain) InsertReceiptChain(blockChain types.Blocks, receiptChain []types.Receipts, ancientLimit uint64) (int, error) {
	// We don't require the chainMu here since we want to maximize the
	// concurrency of header insertion and receipt insertion.
	// 我们在这里不需要 chainMu，因为我们希望最大化头部插入和收据插入的并发性。
	bc.wg.Add(1)
	defer bc.wg.Done()

	var (
		ancientBlocks, liveBlocks     types.Blocks     // 中文注解：古老块和活动块列表
		ancientReceipts, liveReceipts []types.Receipts // 中文注解：古老收据和活动收据列表
	)
	// Do a sanity check that the provided chain is actually ordered and linked
	// 对提供的链进行完整性检查，确保其有序且链接正确
	for i, block := range blockChain {
		if i != 0 {
			prev := blockChain[i-1]
			if block.NumberU64() != prev.NumberU64()+1 || block.ParentHash() != prev.Hash() {
				log.Error("Non contiguous receipt insert",
					"number", block.Number(), "hash", block.Hash(), "parent", block.ParentHash(),
					"prevnumber", prev.Number(), "prevhash", prev.Hash())
				// 中文翻译：非连续收据插入
				return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x..], item %d is #%d [%x..] (parent [%x..])",
					i-1, prev.NumberU64(), prev.Hash().Bytes()[:4],
					i, block.NumberU64(), block.Hash().Bytes()[:4], block.ParentHash().Bytes()[:4])
				// 中文翻译：非连续插入：第 %d 项是 #%d [%x..]，第 %d 项是 #%d [%x..]（父区块 [%x..]）
			}
		}
		if block.NumberU64() <= ancientLimit {
			ancientBlocks, ancientReceipts = append(ancientBlocks, block), append(ancientReceipts, receiptChain[i])
		} else {
			liveBlocks, liveReceipts = append(liveBlocks, block), append(liveReceipts, receiptChain[i])
		}

		// Here we also validate that blob transactions in the block do not contain a sidecar.
		// While the sidecar does not affect the block hash / tx hash, sending blobs within a block is not allowed.
		// 在此我们还验证块中的 blob 交易不包含 sidecar。
		// 虽然 sidecar 不影响块哈希/交易哈希，但在块内发送 blobs 是不允许的。
		for txIndex, tx := range block.Transactions() {
			if tx.Type() == types.BlobTxType && tx.BlobTxSidecar() != nil {
				return 0, fmt.Errorf("block #%d contains unexpected blob sidecar in tx at index %d", block.NumberU64(), txIndex)
				// 中文翻译：块 #%d 在交易索引 %d 处包含意外的 blob sidecar
			}
		}
	}

	var (
		stats = struct{ processed, ignored int32 }{} // 中文注解：统计信息结构体
		start = time.Now()                           // 中文注解：开始时间
		size  = int64(0)                             // 中文注解：写入数据大小
	)

	// updateHead updates the head snap sync block if the inserted blocks are better
	// and returns an indicator whether the inserted blocks are canonical.
	// updateHead 如果插入的块更好，则更新头部快照同步块，并返回指示插入的块是否为规范的标志。
	updateHead := func(head *types.Block) bool {
		if !bc.chainmu.TryLock() {
			return false
		}
		defer bc.chainmu.Unlock()

		// Rewind may have occurred, skip in that case.
		// 如果发生了回退，则跳过。
		if bc.CurrentHeader().Number.Cmp(head.Number()) >= 0 {
			rawdb.WriteHeadFastBlockHash(bc.db, head.Hash())
			bc.currentSnapBlock.Store(head.Header())
			headFastBlockGauge.Update(int64(head.NumberU64()))
			return true
		}
		return false
	}
	// writeAncient writes blockchain and corresponding receipt chain into ancient store.
	//
	// this function only accepts canonical chain data. All side chain will be reverted
	// eventually.
	// writeAncient 将区块链和对应的收据链写入古老存储。
	//
	// 此函数仅接受规范链数据。所有侧链最终将被回退。
	writeAncient := func(blockChain types.Blocks, receiptChain []types.Receipts) (int, error) {
		first := blockChain[0]
		last := blockChain[len(blockChain)-1]

		// Ensure genesis is in ancients.
		// 确保创世块在古老存储中。
		if first.NumberU64() == 1 {
			if frozen, _ := bc.db.Ancients(); frozen == 0 {
				td := bc.genesisBlock.Difficulty()
				writeSize, err := rawdb.WriteAncientBlocks(bc.db, []*types.Block{bc.genesisBlock}, []types.Receipts{nil}, td)
				if err != nil {
					log.Error("Error writing genesis to ancients", "err", err)
					// 中文翻译：写入创世块到古老存储时出错
					return 0, err
				}
				size += writeSize
				log.Info("Wrote genesis to ancients")
				// 中文翻译：已将创世块写入古老存储
			}
		}
		// Before writing the blocks to the ancients, we need to ensure that
		// they correspond to what the headerchain 'expects'.
		// We only check the last block/header, since it's a contiguous chain.
		// 在将块写入古老存储之前，我们需要确保它们与头部链“预期”的内容相对应。
		// 我们只检查最后一个块/头部，因为这是一个连续的链。
		if !bc.HasHeader(last.Hash(), last.NumberU64()) {
			return 0, fmt.Errorf("containing header #%d [%x..] unknown", last.Number(), last.Hash().Bytes()[:4])
			// 中文翻译：包含的头部 #%d [%x..] 未知
		}

		// Write all chain data to ancients.
		// 将所有链数据写入古老存储。
		td := bc.GetTd(first.Hash(), first.NumberU64())
		writeSize, err := rawdb.WriteAncientBlocks(bc.db, blockChain, receiptChain, td)
		if err != nil {
			log.Error("Error importing chain data to ancients", "err", err)
			// 中文翻译：导入链数据到古老存储时出错
			return 0, err
		}
		size += writeSize

		// Sync the ancient store explicitly to ensure all data has been flushed to disk.
		// 明确同步古老存储，以确保所有数据都已刷新到磁盘。
		if err := bc.db.Sync(); err != nil {
			return 0, err
		}
		// Update the current snap block because all block data is now present in DB.
		// 更新当前快照块，因为所有块数据现在都存在于数据库中。
		previousSnapBlock := bc.CurrentSnapBlock().Number.Uint64()
		if !updateHead(blockChain[len(blockChain)-1]) {
			// We end up here if the header chain has reorg'ed, and the blocks/receipts
			// don't match the canonical chain.
			// 如果头部链已重组，并且块/收据与规范链不匹配，我们会到达这里。
			if _, err := bc.db.TruncateHead(previousSnapBlock + 1); err != nil {
				log.Error("Can't truncate ancient store after failed insert", "err", err)
				// 中文翻译：插入失败后无法截断古老存储
			}
			return 0, errSideChainReceipts
		}

		// Delete block data from the main database.
		// 从主数据库中删除块数据。
		var (
			batch       = bc.db.NewBatch()                                // 中文注解：数据库批处理对象
			canonHashes = make(map[common.Hash]struct{}, len(blockChain)) // 中文注解：规范哈希集合
		)
		for _, block := range blockChain {
			canonHashes[block.Hash()] = struct{}{}
			if block.NumberU64() == 0 {
				continue
			}
			rawdb.DeleteCanonicalHash(batch, block.NumberU64())
			rawdb.DeleteBlockWithoutNumber(batch, block.Hash(), block.NumberU64())
		}
		// Delete side chain hash-to-number mappings.
		// 删除侧链哈希到编号的映射。
		for _, nh := range rawdb.ReadAllHashesInRange(bc.db, first.NumberU64(), last.NumberU64()) {
			if _, canon := canonHashes[nh.Hash]; !canon {
				rawdb.DeleteHeader(batch, nh.Hash, nh.Number)
			}
		}
		if err := batch.Write(); err != nil {
			return 0, err
		}
		stats.processed += int32(len(blockChain))
		return 0, nil
	}

	// writeLive writes blockchain and corresponding receipt chain into active store.
	// writeLive 将区块链和对应的收据链写入活动存储。
	writeLive := func(blockChain types.Blocks, receiptChain []types.Receipts) (int, error) {
		var (
			skipPresenceCheck = false            // 中文注解：是否跳过存在检查
			batch             = bc.db.NewBatch() // 中文注解：数据库批处理对象
		)
		for i, block := range blockChain {
			// Short circuit insertion if shutting down or processing failed
			// 如果关闭或处理失败，短路插入
			if bc.insertStopped() {
				return 0, errInsertionInterrupted
			}
			// Short circuit if the owner header is unknown
			// 如果拥有者头部未知，短路
			if !bc.HasHeader(block.Hash(), block.NumberU64()) {
				return i, fmt.Errorf("containing header #%d [%x..] unknown", block.Number(), block.Hash().Bytes()[:4])
				// 中文翻译：包含的头部 #%d [%x..] 未知
			}
			if !skipPresenceCheck {
				// Ignore if the entire data is already known
				// 如果整个数据已知，则忽略
				if bc.HasBlock(block.Hash(), block.NumberU64()) {
					stats.ignored++
					continue
				} else {
					// If block N is not present, neither are the later blocks.
					// This should be true, but if we are mistaken, the shortcut
					// here will only cause overwriting of some existing data
					// 如果块 N 不存在，后面的块也不存在。
					// 这应该是正确的，但如果我们错了，这里的捷径只会导致覆盖一些现有数据
					skipPresenceCheck = true
				}
			}
			// Write all the data out into the database
			// 将所有数据写入数据库
			rawdb.WriteBody(batch, block.Hash(), block.NumberU64(), block.Body())
			rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), receiptChain[i])

			// Write everything belongs to the blocks into the database. So that
			// we can ensure all components of body is completed(body, receipts)
			// except transaction indexes(will be created once sync is finished).
			// 将属于块的所有内容写入数据库。以便我们确保主体的所有组件（主体、收据）都已完成，
			// 除了交易索引（将在同步完成后创建）。
			if batch.ValueSize() >= ethdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					return 0, err
				}
				size += int64(batch.ValueSize())
				batch.Reset()
			}
			stats.processed++
		}
		// Write everything belongs to the blocks into the database. So that
		// we can ensure all components of body is completed(body, receipts,
		// tx indexes)
		// 将属于块的所有内容写入数据库。以便我们确保主体的所有组件（主体、收据、交易索引）都已完成
		if batch.ValueSize() > 0 {
			size += int64(batch.ValueSize())
			if err := batch.Write(); err != nil {
				return 0, err
			}
		}
		updateHead(blockChain[len(blockChain)-1])
		return 0, nil
	}

	// Write downloaded chain data and corresponding receipt chain data
	// 写入下载的链数据和对应的收据链数据
	if len(ancientBlocks) > 0 {
		if n, err := writeAncient(ancientBlocks, ancientReceipts); err != nil {
			if err == errInsertionInterrupted {
				return 0, nil
			}
			return n, err
		}
	}
	if len(liveBlocks) > 0 {
		if n, err := writeLive(liveBlocks, liveReceipts); err != nil {
			if err == errInsertionInterrupted {
				return 0, nil
			}
			return n, err
		}
	}
	var (
		head    = blockChain[len(blockChain)-1] // 中文注解：链的最后一个块
		context = []interface{}{
			"count", stats.processed, "elapsed", common.PrettyDuration(time.Since(start)),
			"number", head.Number(), "hash", head.Hash(), "age", common.PrettyAge(time.Unix(int64(head.Time()), 0)),
			"size", common.StorageSize(size),
		}
	)
	if stats.ignored > 0 {
		context = append(context, []interface{}{"ignored", stats.ignored}...)
	}
	log.Debug("Imported new block receipts", context...)
	// 中文翻译：导入了新的块收据

	return 0, nil
	// 关键逻辑注解：
	// 1. 检查链连续性并分割古老和活动块。
	// 2. 验证 Blob 交易无 sidecar。
	// 3. 分别写入古老和活动存储。
	// 4. 更新快照头部并记录统计信息。
}

// writeBlockWithoutState writes only the block and its metadata to the database,
// but does not write any state. This is used to construct competing side forks
// up to the point where they exceed the canonical total difficulty.
// writeBlockWithoutState 仅将块及其元数据写入数据库，但不写入任何状态。这用于构建竞争的侧分叉，直到它们超过规范总难度。
func (bc *BlockChain) writeBlockWithoutState(block *types.Block, td *big.Int) (err error) {
	if bc.insertStopped() {
		return errInsertionInterrupted
	}
	batch := bc.db.NewBatch()
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), td)
	rawdb.WriteBlock(batch, block)
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write block into disk", "err", err)
		// 中文翻译：无法将块写入磁盘
	}
	return nil
	// 关键逻辑注解：
	// 1. 检查是否中断插入。
	// 2. 写入块和总难度到数据库。
}

// writeKnownBlock updates the head block flag with a known block
// and introduces chain reorg if necessary.
// writeKnownBlock 使用已知块更新头部块标志，并在必要时引入链重组。
func (bc *BlockChain) writeKnownBlock(block *types.Block) error {
	current := bc.CurrentBlock()
	if block.ParentHash() != current.Hash() {
		if err := bc.reorg(current, block.Header()); err != nil {
			return err
		}
	}
	bc.writeHeadBlock(block)
	return nil
	// 关键逻辑注解：
	// 1. 检查父哈希是否匹配当前头部。
	// 2. 如果不匹配，执行重组。
	// 3. 更新头部块。
}

// writeBlockWithState writes block, metadata and corresponding state data to the
// database.
// writeBlockWithState 将块、元数据和对应的状态数据写入数据库。
func (bc *BlockChain) writeBlockWithState(block *types.Block, receipts []*types.Receipt, statedb *state.StateDB) error {
	// Calculate the total difficulty of the block
	// 计算块的总难度
	ptd := bc.GetTd(block.ParentHash(), block.NumberU64()-1)
	if ptd == nil {
		return consensus.ErrUnknownAncestor
	}
	// Make sure no inconsistent state is leaked during insertion
	// 确保插入期间没有不一致的状态泄漏
	externTd := new(big.Int).Add(block.Difficulty(), ptd)

	// Irrelevant of the canonical status, write the block itself to the database.
	//
	// Note all the components of block(td, hash->number map, header, body, receipts)
	// should be written atomically. BlockBatch is used for containing all components.
	// 无论规范状态如何，将块本身写入数据库。
	//
	// 注意块的所有组件（总难度、哈希到编号映射、头部、主体、收据）应原子性写入。BlockBatch 用于包含所有组件。
	blockBatch := bc.db.NewBatch()
	rawdb.WriteTd(blockBatch, block.Hash(), block.NumberU64(), externTd)
	rawdb.WriteBlock(blockBatch, block)
	rawdb.WriteReceipts(blockBatch, block.Hash(), block.NumberU64(), receipts)
	rawdb.WritePreimages(blockBatch, statedb.Preimages())
	if err := blockBatch.Write(); err != nil {
		log.Crit("Failed to write block into disk", "err", err)
		// 中文翻译：无法将块写入磁盘
	}
	// Commit all cached state changes into underlying memory database.
	// 将所有缓存的状态更改提交到底层内存数据库。
	root, err := statedb.Commit(block.NumberU64(), bc.chainConfig.IsEIP158(block.Number()))
	if err != nil {
		return err
	}
	// If node is running in path mode, skip explicit gc operation
	// which is unnecessary in this mode.
	// 如果节点以路径模式运行，跳过显式垃圾回收操作，此模式下这是不必要的。
	if bc.triedb.Scheme() == rawdb.PathScheme {
		return nil
	}
	// If we're running an archive node, always flush
	// 如果我们运行的是归档节点，始终刷新
	if bc.cacheConfig.TrieDirtyDisabled {
		return bc.triedb.Commit(root, false)
	}
	// Full but not archive node, do proper garbage collection
	// 完整但非归档节点，执行适当的垃圾回收
	bc.triedb.Reference(root, common.Hash{}) // metadata reference to keep trie alive
	// 中文翻译：元数据引用以保持 trie 存活
	bc.triegc.Push(root, -int64(block.NumberU64()))

	// Flush limits are not considered for the first TriesInMemory blocks.
	// 前 TriesInMemory 个块不考虑刷新限制。
	current := block.NumberU64()
	if current <= state.TriesInMemory {
		return nil
	}
	// If we exceeded our memory allowance, flush matured singleton nodes to disk
	// 如果我们超过了内存允许量，将成熟的单一节点刷新到磁盘
	var (
		_, nodes, imgs = bc.triedb.Size() // all memory is contained within the nodes return for hashdb
		// 中文翻译：所有内存都包含在 hashdb 返回的节点中
		limit = common.StorageSize(bc.cacheConfig.TrieDirtyLimit) * 1024 * 1024 // 中文注解：内存限制
	)
	if nodes > limit || imgs > 4*1024*1024 {
		bc.triedb.Cap(limit - ethdb.IdealBatchSize)
	}
	// Find the next state trie we need to commit
	// 找到我们需要提交的下一个状态 trie
	chosen := current - state.TriesInMemory
	flushInterval := time.Duration(bc.flushInterval.Load())
	// If we exceeded time allowance, flush an entire trie to disk
	// 如果我们超过了时间允许量，将整个 trie 刷新到磁盘
	if bc.gcproc > flushInterval {
		// If the header is missing (canonical chain behind), we're reorging a low
		// diff sidechain. Suspend committing until this operation is completed.
		// 如果头部缺失（规范链落后），我们正在重组一个低难度的侧链。暂停提交直到此操作完成。
		header := bc.GetHeaderByNumber(chosen)
		if header == nil {
			log.Warn("Reorg in progress, trie commit postponed", "number", chosen)
			// 中文翻译：重组进行中，trie 提交推迟
		} else {
			// If we're exceeding limits but haven't reached a large enough memory gap,
			// warn the user that the system is becoming unstable.
			// 如果我们超出了限制但尚未达到足够大的内存差距，警告用户系统变得不稳定。
			if chosen < bc.lastWrite+state.TriesInMemory && bc.gcproc >= 2*flushInterval {
				log.Info("State in memory for too long, committing", "time", bc.gcproc, "allowance", flushInterval, "optimum", float64(chosen-bc.lastWrite)/state.TriesInMemory)
				// 中文翻译：状态在内存中太久，正在提交
			}
			// Flush an entire trie and restart the counters
			// 刷新整个 trie 并重启计数器
			bc.triedb.Commit(header.Root, true)
			bc.lastWrite = chosen
			bc.gcproc = 0
		}
	}
	// Garbage collect anything below our required write retention
	// 垃圾回收任何低于我们所需写入保留的内容
	for !bc.triegc.Empty() {
		root, number := bc.triegc.Pop()
		if uint64(-number) > chosen {
			bc.triegc.Push(root, number)
			break
		}
		bc.triedb.Dereference(root)
	}
	return nil
	// 关键逻辑注解：
	// 1. 计算总难度并验证父块。
	// 2. 原子性写入块数据和状态。
	// 3. 根据模式管理 trie 提交和垃圾回收。
}

// writeBlockAndSetHead is the internal implementation of WriteBlockAndSetHead.
// This function expects the chain mutex to be held.
// writeBlockAndSetHead 是 WriteBlockAndSetHead 的内部实现。
// 此函数期望链互斥锁已被持有。
func (bc *BlockChain) writeBlockAndSetHead(block *types.Block, receipts []*types.Receipt, logs []*types.Log, state *state.StateDB, emitHeadEvent bool) (status WriteStatus, err error) {
	if err := bc.writeBlockWithState(block, receipts, state); err != nil {
		return NonStatTy, err
	}
	currentBlock := bc.CurrentBlock()

	// Reorganise the chain if the parent is not the head block
	// 如果父块不是头部块，则重组链
	if block.ParentHash() != currentBlock.Hash() {
		if err := bc.reorg(currentBlock, block.Header()); err != nil {
			return NonStatTy, err
		}
	}

	// Set new head.
	// 设置新头部。
	bc.writeHeadBlock(block)

	bc.chainFeed.Send(ChainEvent{Header: block.Header()})
	if len(logs) > 0 {
		bc.logsFeed.Send(logs)
	}
	// In theory, we should fire a ChainHeadEvent when we inject
	// a canonical block, but sometimes we can insert a batch of
	// canonical blocks. Avoid firing too many ChainHeadEvents,
	// we will fire an accumulated ChainHeadEvent and disable fire
	// event here.
	// 理论上，当我们注入规范块时应触发 ChainHeadEvent，但有时我们可以插入一批规范块。
	// 避免触发太多的 ChainHeadEvent，我们将触发一个累积的 ChainHeadEvent 并在此禁用触发事件。
	if emitHeadEvent {
		bc.chainHeadFeed.Send(ChainHeadEvent{Header: block.Header()})
	}
	return CanonStatTy, nil
	// 关键逻辑注解：
	// 1. 写入块和状态。
	// 2. 如果需要，执行重组。
	// 3. 设置新头部并发射事件。
}

// InsertChain attempts to insert the given batch of blocks in to the canonical
// chain or, otherwise, create a fork. If an error is returned it will return
// the index number of the failing block as well an error describing what went
// wrong. After insertion is done, all accumulated events will be fired.
// InsertChain 尝试将给定的批量区块插入到规范链中，否则创建一个分叉。如果返回错误，它将返回失败区块的索引号以及描述出错原因的错误。插入完成后，所有累积的事件将被触发。
func (bc *BlockChain) InsertChain(chain types.Blocks) (int, error) {
	// Sanity check that we have something meaningful to import
	// 检查我们是否有有意义的导入内容
	if len(chain) == 0 {
		return 0, nil // 如果链为空，直接返回
	}
	bc.blockProcFeed.Send(true)        // 发送区块处理开始事件
	defer bc.blockProcFeed.Send(false) // 延迟发送区块处理结束事件

	// Do a sanity check that the provided chain is actually ordered and linked.
	// 对提供的链进行完整性检查，确保其有序且链接正确。
	for i := 1; i < len(chain); i++ {
		block, prev := chain[i], chain[i-1]
		if block.NumberU64() != prev.NumberU64()+1 || block.ParentHash() != prev.Hash() {
			log.Error("Non contiguous block insert",
				"number", block.Number(),
				"hash", block.Hash(),
				"parent", block.ParentHash(),
				"prevnumber", prev.Number(),
				"prevhash", prev.Hash(),
			)
			// 非连续区块插入
			return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x..], item %d is #%d [%x..] (parent [%x..])", i-1, prev.NumberU64(),
				prev.Hash().Bytes()[:4], i, block.NumberU64(), block.Hash().Bytes()[:4], block.ParentHash().Bytes()[:4])
			// 非连续插入：第 %d 项是 #%d [%x..]，第 %d 项是 #%d [%x..]（父区块 [%x..]）
		}
	}
	// Pre-checks passed, start the full block imports
	// 预检查通过，开始完整的区块导入
	if !bc.chainmu.TryLock() {
		return 0, errChainStopped // 如果无法获取锁，返回链已停止的错误
	}
	defer bc.chainmu.Unlock() // 延迟释放锁

	_, n, err := bc.insertChain(chain, true, false) // No witness collection for mass inserts (would get super large)
	// 不收集大规模插入的见证数据（会变得非常大）
	return n, err
	// 关键逻辑注解：
	// 1. 检查输入链是否为空。
	// 2. 验证链的连续性和链接性。
	// 3. 获取链写锁并调用内部插入函数。
	// 4. 返回插入结果和可能的错误。
}

// insertChain is the internal implementation of InsertChain, which assumes that
// 1) chains are contiguous, and 2) The chain mutex is held.
//
// This method is split out so that import batches that require re-injecting
// historical blocks can do so without releasing the lock, which could lead to
// racey behaviour. If a sidechain import is in progress, and the historic state
// is imported, but then new canon-head is added before the actual sidechain
// completes, then the historic state could be pruned again
// insertChain 是 InsertChain 的内部实现，假定：
// 1) 链是连续的，2) 链互斥锁已被持有。
//
// 此方法被分离出来，以便需要重新注入历史区块的导入批次可以在不释放锁的情况下进行，否则可能导致竞争行为。如果侧链导入正在进行，并且导入了历史状态，但在实际侧链完成之前添加了新的规范头部，那么历史状态可能会再次被修剪。
func (bc *BlockChain) insertChain(chain types.Blocks, setHead bool, makeWitness bool) (*stateless.Witness, int, error) {
	// If the chain is terminating, don't even bother starting up.
	// 如果链正在终止，甚至不开始处理。
	if bc.insertStopped() {
		return nil, 0, nil // 如果插入已停止，直接返回
	}
	// Start a parallel signature recovery (signer will fluke on fork transition, minimal perf loss)
	// 启动并行签名恢复（签名者在分叉转换时可能会出错，性能损失最小）
	SenderCacher.RecoverFromBlocks(types.MakeSigner(bc.chainConfig, chain[0].Number(), chain[0].Time()), chain)

	var (
		stats     = insertStats{startTime: mclock.Now()} // 插入统计信息
		lastCanon *types.Block                           // 最后的规范区块
	)
	// Fire a single chain head event if we've progressed the chain
	// 如果链有进展，触发单个链头部事件
	defer func() {
		if lastCanon != nil && bc.CurrentBlock().Hash() == lastCanon.Hash() {
			bc.chainHeadFeed.Send(ChainHeadEvent{Header: lastCanon.Header()})
		}
	}()
	// Start the parallel header verifier
	// 启动并行头部验证器
	headers := make([]*types.Header, len(chain))
	for i, block := range chain {
		headers[i] = block.Header()
	}
	abort, results := bc.engine.VerifyHeaders(bc, headers) // 并行验证头部
	defer close(abort)                                     // 延迟关闭中止通道

	// Peek the error for the first block to decide the directing import logic
	// 查看第一个区块的错误以决定导入逻辑的方向
	it := newInsertIterator(chain, results, bc.validator) // 创建插入迭代器
	block, err := it.next()                               // 获取下一个区块和错误

	// Left-trim all the known blocks that don't need to build snapshot
	// 左修剪所有不需要构建快照的已知区块
	if bc.skipBlock(err, it) {
		// First block (and state) is known
		//   1. We did a roll-back, and should now do a re-import
		//   2. The block is stored as a sidechain, and is lying about it's stateroot, and passes a stateroot
		//      from the canonical chain, which has not been verified.
		// 第一个区块（及其状态）是已知的
		//   1. 我们进行了回滚，现在应该重新导入
		//   2. 该区块作为侧链存储，并且关于其状态根撒谎，传递了一个未经验证的规范链的状态根。
		// Skip all known blocks that are behind us.
		// 跳过所有在我们之前的已知区块。
		current := bc.CurrentBlock()
		for block != nil && bc.skipBlock(err, it) {
			if block.NumberU64() > current.Number.Uint64() || bc.GetCanonicalHash(block.NumberU64()) != block.Hash() {
				break // 如果区块号大于当前或不是规范区块，退出循环
			}
			log.Debug("Ignoring already known block", "number", block.Number(), "hash", block.Hash())
			// 忽略已知区块
			stats.ignored++

			block, err = it.next()
		}
		// The remaining blocks are still known blocks, the only scenario here is:
		// During the snap sync, the pivot point is already submitted but rollback
		// happens. Then node resets the head full block to a lower height via `rollback`
		// and leaves a few known blocks in the database.
		//
		// When node runs a snap sync again, it can re-import a batch of known blocks via
		// `insertChain` while a part of them have higher total difficulty than current
		// head full block(new pivot point).
		// 剩余的区块仍是已知区块，这里唯一的情况是：
		// 在快照同步期间，pivot 点已提交但发生了回滚。然后节点通过 `rollback` 将头部完整区块重置为较低高度，并在数据库中留下一些已知区块。
		//
		// 当节点再次运行快照同步时，它可以通过 `insertChain` 重新导入一批已知区块，其中部分区块的总难度高于当前头部完整区块（新的 pivot 点）。
		for block != nil && bc.skipBlock(err, it) {
			log.Debug("Writing previously known block", "number", block.Number(), "hash", block.Hash())
			// 写入之前已知的区块
			if err := bc.writeKnownBlock(block); err != nil {
				return nil, it.index, err // 写入失败返回错误
			}
			lastCanon = block

			block, err = it.next()
		}
		// Falls through to the block import
		// 进入区块导入流程
	}
	switch {
	// First block is pruned
	// 第一个区块被修剪
	case errors.Is(err, consensus.ErrPrunedAncestor):
		if setHead {
			// First block is pruned, insert as sidechain and reorg only if TD grows enough
			// 第一个区块被修剪，作为侧链插入，仅当总难度足够大时才进行重组
			log.Debug("Pruned ancestor, inserting as sidechain", "number", block.Number(), "hash", block.Hash())
			// 修剪的祖先，作为侧链插入
			return bc.insertSideChain(block, it, makeWitness)
		} else {
			// We're post-merge and the parent is pruned, try to recover the parent state
			// 我们处于合并后且父区块被修剪，尝试恢复父状态
			log.Debug("Pruned ancestor", "number", block.Number(), "hash", block.Hash())
			// 修剪的祖先
			_, err := bc.recoverAncestors(block, makeWitness)
			return nil, it.index, err
		}
	// Some other error(except ErrKnownBlock) occurred, abort.
	// ErrKnownBlock is allowed here since some known blocks
	// still need re-execution to generate snapshots that are missing
	// 发生了其他错误（除了 ErrKnownBlock），中止。
	// 这里允许 ErrKnownBlock，因为一些已知区块仍需重新执行以生成缺失的快照
	case err != nil && !errors.Is(err, ErrKnownBlock):
		stats.ignored += len(it.chain)
		bc.reportBlock(block, nil, err)
		return nil, it.index, err
	}
	// No validation errors for the first block (or chain prefix skipped)
	// 第一个区块没有验证错误（或链前缀被跳过）
	var activeState *state.StateDB
	defer func() {
		// The chain importer is starting and stopping trie prefetchers. If a bad
		// block or other error is hit however, an early return may not properly
		// terminate the background threads. This defer ensures that we clean up
		// and dangling prefetcher, without deferring each and holding on live refs.
		// 链导入器正在启动和停止 trie 预取器。然而，如果遇到坏块或其他错误，提前返回可能无法正确终止后台线程。此延迟确保我们清理悬挂的预取器，而不延迟每个并持有活动引用。
		if activeState != nil {
			activeState.StopPrefetcher() // 停止预取器
		}
	}()

	// Track the singleton witness from this chain insertion (if any)
	// 跟踪此次链插入的单一见证（如果有）
	var witness *stateless.Witness

	for ; block != nil && err == nil || errors.Is(err, ErrKnownBlock); block, err = it.next() {
		// If the chain is terminating, stop processing blocks
		// 如果链正在终止，停止处理区块
		if bc.insertStopped() {
			log.Debug("Abort during block processing")
			// 区块处理期间中止
			break
		}
		// If the block is known (in the middle of the chain), it's a special case for
		// Clique blocks where they can share state among each other, so importing an
		// older block might complete the state of the subsequent one. In this case,
		// just skip the block (we already validated it once fully (and crashed), since
		// its header and body was already in the database). But if the corresponding
		// snapshot layer is missing, forcibly rerun the execution to build it.
		// 如果区块是已知的（在链中间），对于 Clique 区块这是一个特殊情况，它们可以共享状态，因此导入较旧的区块可能完成后续区块的状态。在这种情况下，跳过该区块（我们已经完全验证过一次并崩溃，因为其头部和主体已在数据库中）。但如果对应的快照层缺失，强制重新运行执行以构建它。
		if bc.skipBlock(err, it) {
			logger := log.Debug
			if bc.chainConfig.Clique == nil {
				logger = log.Warn // 如果不是 Clique 链，升级日志级别
			}
			logger("Inserted known block", "number", block.Number(), "hash", block.Hash(),
				"uncles", len(block.Uncles()), "txs", len(block.Transactions()), "gas", block.GasUsed(),
				"root", block.Root())
			// 插入已知区块

			// Special case. Commit the empty receipt slice if we meet the known
			// block in the middle. It can only happen in the clique chain. Whenever
			// we insert blocks via `insertSideChain`, we only commit `td`, `header`
			// and `body` if it's non-existent. Since we don't have receipts without
			// reexecution, so nothing to commit. But if the sidechain will be adopted
			// as the canonical chain eventually, it needs to be reexecuted for missing
			// state, but if it's this special case here(skip reexecution) we will lose
			// the empty receipt entry.
			// 特殊情况。如果我们在中间遇到已知区块，提交空收据切片。这只能在 Clique 链中发生。每当我们通过 `insertSideChain` 插入区块时，仅在不存在时提交 `td`、`header` 和 `body`。由于没有重新执行我们没有收据，所以没有什么可提交的。但如果侧链最终被采纳为规范链，它需要为缺失的状态重新执行，但如果是这里的特殊情况（跳过重新执行），我们将丢失空收据条目。
			if len(block.Transactions()) == 0 {
				rawdb.WriteReceipts(bc.db, block.Hash(), block.NumberU64(), nil) // 写入空收据
			} else {
				log.Error("Please file an issue, skip known block execution without receipt",
					"hash", block.Hash(), "number", block.NumberU64())
				// 请提交问题，跳过已知区块执行但没有收据
			}
			if err := bc.writeKnownBlock(block); err != nil {
				return nil, it.index, err // 写入失败返回错误
			}
			stats.processed++
			if bc.logger != nil && bc.logger.OnSkippedBlock != nil {
				bc.logger.OnSkippedBlock(tracing.BlockEvent{
					Block:     block,
					TD:        bc.GetTd(block.ParentHash(), block.NumberU64()-1),
					Finalized: bc.CurrentFinalBlock(),
					Safe:      bc.CurrentSafeBlock(),
				}) // 调用跳过区块钩子
			}
			// We can assume that logs are empty here, since the only way for consecutive
			// Clique blocks to have the same state is if there are no transactions.
			// 我们可以假设这里的日志为空，因为连续的 Clique 区块具有相同状态的唯一方式是没有交易。
			lastCanon = block
			continue
		}
		// Retrieve the parent block and it's state to execute on top
		// 获取父区块及其状态以在其上执行
		start := time.Now()
		parent := it.previous()
		if parent == nil {
			parent = bc.GetHeader(block.ParentHash(), block.NumberU64()-1) // 如果迭代器没有父区块，从数据库获取
		}
		statedb, err := state.New(parent.Root, bc.statedb) // 创建基于父状态的状态数据库
		if err != nil {
			return nil, it.index, err
		}

		// If we are past Byzantium, enable prefetching to pull in trie node paths
		// while processing transactions. Before Byzantium the prefetcher is mostly
		// useless due to the intermediate root hashing after each transaction.
		// 如果我们超过了 Byzantium 阶段，启用预取以在处理交易时拉取 trie 节点路径。在 Byzantium 之前，由于每次交易后的中间根哈希，预取器大多无用。
		if bc.chainConfig.IsByzantium(block.Number()) {
			// Generate witnesses either if we're self-testing, or if it's the
			// only block being inserted. A bit crude, but witnesses are huge,
			// so we refuse to make an entire chain of them.
			// 如果我们在自我测试，或者这是唯一插入的区块，则生成见证。有点粗糙，但见证数据很大，所以我们拒绝为整个链生成它们。
			if bc.vmConfig.StatelessSelfValidation || (makeWitness && len(chain) == 1) {
				witness, err = stateless.NewWitness(block.Header(), bc)
				if err != nil {
					return nil, it.index, err
				}
			}
			statedb.StartPrefetcher("chain", witness) // 启动预取器
		}
		activeState = statedb

		// If we have a followup block, run that against the current state to pre-cache
		// transactions and probabilistically some of the account/storage trie nodes.
		// 如果有后续区块，对当前状态运行它以预缓存交易和概率性地缓存一些账户/存储 trie 节点。
		var followupInterrupt atomic.Bool
		if !bc.cacheConfig.TrieCleanNoPrefetch {
			if followup, err := it.peek(); followup != nil && err == nil {
				throwaway, _ := state.New(parent.Root, bc.statedb) // 创建丢弃状态用于预取

				go func(start time.Time, followup *types.Block, throwaway *state.StateDB) {
					// Disable tracing for prefetcher executions.
					// 为预取器执行禁用跟踪。
					vmCfg := bc.vmConfig
					vmCfg.Tracer = nil
					bc.prefetcher.Prefetch(followup, throwaway, vmCfg, &followupInterrupt) // 执行预取

					blockPrefetchExecuteTimer.Update(time.Since(start))
					if followupInterrupt.Load() {
						blockPrefetchInterruptMeter.Mark(1)
					}
				}(time.Now(), followup, throwaway)
			}
		}

		// The traced section of block import.
		// 区块导入的跟踪部分。
		res, err := bc.processBlock(block, statedb, start, setHead) // 处理区块
		followupInterrupt.Store(true)                               // 中断后续预取
		if err != nil {
			return nil, it.index, err
		}
		// Report the import stats before returning the various results
		// 在返回各种结果之前报告导入统计信息
		stats.processed++
		stats.usedGas += res.usedGas

		var snapDiffItems, snapBufItems common.StorageSize
		if bc.snaps != nil {
			snapDiffItems, snapBufItems = bc.snaps.Size() // 获取快照大小
		}
		trieDiffNodes, trieBufNodes, _ := bc.triedb.Size() // 获取 trie 大小
		stats.report(chain, it.index, snapDiffItems, snapBufItems, trieDiffNodes, trieBufNodes, setHead)

		if !setHead {
			// After merge we expect few side chains. Simply count
			// all blocks the CL gives us for GC processing time
			// 合并后我们预期很少有侧链。简单地统计 CL 给我们的所有区块用于 GC 处理时间
			bc.gcproc += res.procTime
			return witness, it.index, nil // Direct block insertion of a single block
			// 直接插入单个区块
		}
		switch res.status {
		case CanonStatTy:
			log.Debug("Inserted new block", "number", block.Number(), "hash", block.Hash(),
				"uncles", len(block.Uncles()), "txs", len(block.Transactions()), "gas", block.GasUsed(),
				"elapsed", common.PrettyDuration(time.Since(start)),
				"root", block.Root())
			// 插入新区块

			lastCanon = block

			// Only count canonical blocks for GC processing time
			// 仅计算规范区块的 GC 处理时间
			bc.gcproc += res.procTime

		case SideStatTy:
			log.Debug("Inserted forked block", "number", block.Number(), "hash", block.Hash(),
				"diff", block.Difficulty(), "elapsed", common.PrettyDuration(time.Since(start)),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()),
				"root", block.Root())
			// 插入分叉区块

		default:
			// This in theory is impossible, but lets be nice to our future selves and leave
			// a log, instead of trying to track down blocks imports that don't emit logs.
			// 这在理论上是不可能的，但让我们对未来的自己友好，留下日志，而不是试图追踪不发出日志的区块导入。
			log.Warn("Inserted block with unknown status", "number", block.Number(), "hash", block.Hash(),
				"diff", block.Difficulty(), "elapsed", common.PrettyDuration(time.Since(start)),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()),
				"root", block.Root())
			// 插入状态未知的区块
		}
	}
	stats.ignored += it.remaining() // 统计剩余忽略的区块
	return witness, it.index, err
}

// blockProcessingResult is a summary of block processing
// used for updating the stats.
// blockProcessingResult 是区块处理的摘要，用于更新统计信息。
type blockProcessingResult struct {
	usedGas  uint64        // 已使用的 Gas
	procTime time.Duration // 处理时间
	status   WriteStatus   // 写入状态
}

// processBlock executes and validates the given block. If there was no error
// it writes the block and associated state to database.
// processBlock 执行并验证给定的区块。如果没有错误，它将区块和关联状态写入数据库。
func (bc *BlockChain) processBlock(block *types.Block, statedb *state.StateDB, start time.Time, setHead bool) (_ *blockProcessingResult, blockEndErr error) {
	if bc.logger != nil && bc.logger.OnBlockStart != nil {
		td := bc.GetTd(block.ParentHash(), block.NumberU64()-1)
		bc.logger.OnBlockStart(tracing.BlockEvent{
			Block:     block,
			TD:        td,
			Finalized: bc.CurrentFinalBlock(),
			Safe:      bc.CurrentSafeBlock(),
		}) // 调用区块开始钩子
	}
	if bc.logger != nil && bc.logger.OnBlockEnd != nil {
		defer func() {
			bc.logger.OnBlockEnd(blockEndErr) // 延迟调用区块结束钩子
		}()
	}

	// Process block using the parent state as reference point
	// 使用父状态作为参考点处理区块
	pstart := time.Now()
	res, err := bc.processor.Process(block, statedb, bc.vmConfig) // 执行区块
	if err != nil {
		bc.reportBlock(block, res, err)
		return nil, err
	}
	ptime := time.Since(pstart)

	vstart := time.Now()
	if err := bc.validator.ValidateState(block, statedb, res, false); err != nil {
		bc.reportBlock(block, res, err)
		return nil, err // 验证状态失败返回错误
	}
	vtime := time.Since(vstart)

	// If witnesses was generated and stateless self-validation requested, do
	// that now. Self validation should *never* run in production, it's more of
	// a tight integration to enable running *all* consensus tests through the
	// witness builder/runner, which would otherwise be impossible due to the
	// various invalid chain states/behaviors being contained in those tests.
	// 如果生成了见证且请求了无状态自我验证，现在执行。自我验证绝不应用于生产环境，它更多是为了紧密集成，以通过见证构建器/运行器运行所有共识测试，否则由于测试中包含的各种无效链状态/行为，这将是不可能的。
	xvstart := time.Now()
	if witness := statedb.Witness(); witness != nil && bc.vmConfig.StatelessSelfValidation {
		log.Warn("Running stateless self-validation", "block", block.Number(), "hash", block.Hash())
		// 运行无状态自我验证

		// Remove critical computed fields from the block to force true recalculation
		// 从区块中移除关键计算字段以强制重新计算
		context := block.Header()
		context.Root = common.Hash{}
		context.ReceiptHash = common.Hash{}

		task := types.NewBlockWithHeader(context).WithBody(*block.Body())

		// Run the stateless self-cross-validation
		// 运行无状态自我交叉验证
		crossStateRoot, crossReceiptRoot, err := ExecuteStateless(bc.chainConfig, bc.vmConfig, task, witness)
		if err != nil {
			return nil, fmt.Errorf("stateless self-validation failed: %v", err)
			// 无状态自我验证失败：%v
		}
		if crossStateRoot != block.Root() {
			return nil, fmt.Errorf("stateless self-validation root mismatch (cross: %x local: %x)", crossStateRoot, block.Root())
			// 无状态自我验证根不匹配（交叉：%x 本地：%x）
		}
		if crossReceiptRoot != block.ReceiptHash() {
			return nil, fmt.Errorf("stateless self-validation receipt root mismatch (cross: %x local: %x)", crossReceiptRoot, block.ReceiptHash())
			// 无状态自我验证收据根不匹配（交叉：%x 本地：%x）
		}
	}
	xvtime := time.Since(xvstart)
	proctime := time.Since(start) // processing + validation + cross validation
	// 处理 + 验证 + 交叉验证

	// Update the metrics touched during block processing and validation
	// 更新区块处理和验证期间接触的指标
	accountReadTimer.Update(statedb.AccountReads) // Account reads are complete(in processing)
	// 账户读取已完成（在处理中）
	storageReadTimer.Update(statedb.StorageReads) // Storage reads are complete(in processing)
	// 存储读取已完成（在处理中）
	if statedb.AccountLoaded != 0 {
		accountReadSingleTimer.Update(statedb.AccountReads / time.Duration(statedb.AccountLoaded))
	}
	if statedb.StorageLoaded != 0 {
		storageReadSingleTimer.Update(statedb.StorageReads / time.Duration(statedb.StorageLoaded))
	}
	accountUpdateTimer.Update(statedb.AccountUpdates) // Account updates are complete(in validation)
	// 账户更新已完成（在验证中）
	storageUpdateTimer.Update(statedb.StorageUpdates) // Storage updates are complete(in validation)
	// 存储更新已完成（在验证中）
	accountHashTimer.Update(statedb.AccountHashes) // Account hashes are complete(in validation)
	// 账户哈希已完成（在验证中）
	triehash := statedb.AccountHashes // The time spent on tries hashing
	// trie 哈希所花费的时间
	trieUpdate := statedb.AccountUpdates + statedb.StorageUpdates // The time spent on tries update
	// trie 更新所花费的时间
	blockExecutionTimer.Update(ptime - (statedb.AccountReads + statedb.StorageReads)) // The time spent on EVM processing
	// EVM 处理所花费的时间
	blockValidationTimer.Update(vtime - (triehash + trieUpdate)) // The time spent on block validation
	// 区块验证所花费的时间
	blockCrossValidationTimer.Update(xvtime) // The time spent on stateless cross validation
	// 无状态交叉验证所花费的时间

	// Write the block to the chain and get the status.
	// 将区块写入链并获取状态。
	var (
		wstart = time.Now()
		status WriteStatus
	)
	if !setHead {
		// Don't set the head, only insert the block
		// 不设置头部，仅插入区块
		err = bc.writeBlockWithState(block, res.Receipts, statedb)
	} else {
		status, err = bc.writeBlockAndSetHead(block, res.Receipts, res.Logs, statedb, false)
	}
	if err != nil {
		return nil, err
	}
	// Update the metrics touched during block commit
	// 更新区块提交期间接触的指标
	accountCommitTimer.Update(statedb.AccountCommits) // Account commits are complete, we can mark them
	// 账户提交已完成，我们可以标记它们
	storageCommitTimer.Update(statedb.StorageCommits) // Storage commits are complete, we can mark them
	// 存储提交已完成，我们可以标记它们
	snapshotCommitTimer.Update(statedb.SnapshotCommits) // Snapshot commits are complete, we can mark them
	// 快照提交已完成，我们可以标记它们
	triedbCommitTimer.Update(statedb.TrieDBCommits) // Trie database commits are complete, we can mark them
	// Trie 数据库提交已完成，我们可以标记它们

	blockWriteTimer.Update(time.Since(wstart) - max(statedb.AccountCommits, statedb.StorageCommits) /* concurrent */ - statedb.SnapshotCommits - statedb.TrieDBCommits)
	blockInsertTimer.UpdateSince(start)

	return &blockProcessingResult{usedGas: res.GasUsed, procTime: proctime, status: status}, nil
	// 关键逻辑注解：
	// 1. 执行区块并验证状态。
	// 2. 如果需要，执行无状态自我验证。
	// 3. 更新处理和验证的指标。
	// 4. 根据 setHead 参数写入区块并设置头部。
	// 5. 返回处理结果。
}

// insertSideChain is called when an import batch hits upon a pruned ancestor
// error, which happens when a sidechain with a sufficiently old fork-block is
// found.
//
// The method writes all (header-and-body-valid) blocks to disk, then tries to
// switch over to the new chain if the TD exceeded the current chain.
// insertSideChain is only used pre-merge.
// insertSideChain 在导入批次遇到修剪的祖先错误时被调用，这种情况发生在发现具有足够旧的分叉区块的侧链时。
//
// 该方法将所有（头部和主体有效的）区块写入磁盘，然后如果总难度超过当前链，尝试切换到新链。
// insertSideChain 仅在合并前使用。
func (bc *BlockChain) insertSideChain(block *types.Block, it *insertIterator, makeWitness bool) (*stateless.Witness, int, error) {
	var (
		externTd *big.Int            // 外部总难度
		current  = bc.CurrentBlock() // 当前区块
	)
	// The first sidechain block error is already verified to be ErrPrunedAncestor.
	// Since we don't import them here, we expect ErrUnknownAncestor for the remaining
	// ones. Any other errors means that the block is invalid, and should not be written
	// to disk.
	// 第一个侧链区块错误已被验证为 ErrPrunedAncestor。
	// 由于我们在这里不导入它们，我们预期其余的为 ErrUnknownAncestor。任何其他错误意味着区块无效，不应写入磁盘。
	err := consensus.ErrPrunedAncestor
	for ; block != nil && errors.Is(err, consensus.ErrPrunedAncestor); block, err = it.next() {
		// Check the canonical state root for that number
		// 检查该编号的规范状态根
		if number := block.NumberU64(); current.Number.Uint64() >= number {
			canonical := bc.GetBlockByNumber(number)
			if canonical != nil && canonical.Hash() == block.Hash() {
				// Not a sidechain block, this is a re-import of a canon block which has it's state pruned
				// 不是侧链区块，这是状态被修剪的规范区块的重新导入

				// Collect the TD of the block. Since we know it's a canon one,
				// we can get it directly, and not (like further below) use
				// the parent and then add the block on top
				// 收集区块的总难度。由于我们知道它是规范区块，我们可以直接获取，而不是（像下面那样）使用父区块然后加上该区块。
				externTd = bc.GetTd(block.Hash(), block.NumberU64())
				continue
			}
			if canonical != nil && canonical.Root() == block.Root() {
				// This is most likely a shadow-state attack. When a fork is imported into the
				// database, and it eventually reaches a block height which is not pruned, we
				// just found that the state already exist! This means that the sidechain block
				// refers to a state which already exists in our canon chain.
				//
				// If left unchecked, we would now proceed importing the blocks, without actually
				// having verified the state of the previous blocks.
				// 这很可能是影子状态攻击。当一个分叉被导入数据库，并且最终达到一个未修剪的区块高度时，我们发现状态已经存在！这意味着侧链区块引用了我们规范链中已存在的状态。
				//
				// 如果不加检查，我们现在将继续导入区块，而实际上并未验证前面的区块状态。
				log.Warn("Sidechain ghost-state attack detected", "number", block.NumberU64(), "sideroot", block.Root(), "canonroot", canonical.Root())
				// 检测到侧链影子状态攻击

				// If someone legitimately side-mines blocks, they would still be imported as usual. However,
				// we cannot risk writing unverified blocks to disk when they obviously target the pruning
				// mechanism.
				// 如果有人合法地侧挖区块，它们仍将照常导入。然而，当它们明显针对修剪机制时，我们不能冒险将未验证的区块写入磁盘。
				return nil, it.index, errors.New("sidechain ghost-state attack")
				// 侧链影子状态攻击
			}
		}
		if externTd == nil {
			externTd = bc.GetTd(block.ParentHash(), block.NumberU64()-1) // 获取父区块总难度
		}
		externTd = new(big.Int).Add(externTd, block.Difficulty()) // 累加当前区块难度

		if !bc.HasBlock(block.Hash(), block.NumberU64()) {
			start := time.Now()
			if err := bc.writeBlockWithoutState(block, externTd); err != nil {
				return nil, it.index, err // 写入失败返回错误
			}
			log.Debug("Injected sidechain block", "number", block.Number(), "hash", block.Hash(),
				"diff", block.Difficulty(), "elapsed", common.PrettyDuration(time.Since(start)),
				"txs", len(block.Transactions()), "gas", block.GasUsed(), "uncles", len(block.Uncles()),
				"root", block.Root())
			// 注入侧链区块
		}
	}
	// Gather all the sidechain hashes (full blocks may be memory heavy)
	// 收集所有侧链哈希（完整区块可能占用大量内存）
	var (
		hashes  []common.Hash
		numbers []uint64
	)
	parent := it.previous()
	for parent != nil && !bc.HasState(parent.Root) {
		if bc.stateRecoverable(parent.Root) {
			if err := bc.triedb.Recover(parent.Root); err != nil {
				return nil, 0, err // 恢复状态失败返回错误
			}
			break
		}
		hashes = append(hashes, parent.Hash())
		numbers = append(numbers, parent.Number.Uint64())

		parent = bc.GetHeader(parent.ParentHash, parent.Number.Uint64()-1)
	}
	if parent == nil {
		return nil, it.index, errors.New("missing parent")
		// 缺少父区块
	}
	// Import all the pruned blocks to make the state available
	// 导入所有修剪的区块以使状态可用
	var (
		blocks []*types.Block
		memory uint64
	)
	for i := len(hashes) - 1; i >= 0; i-- {
		// Append the next block to our batch
		// 将下一个区块追加到我们的批次中
		block := bc.GetBlock(hashes[i], numbers[i])

		blocks = append(blocks, block)
		memory += block.Size()

		// If memory use grew too large, import and continue. Sadly we need to discard
		// all raised events and logs from notifications since we're too heavy on the
		// memory here.
		// 如果内存使用增长过大，导入并继续。可悲的是我们需要丢弃所有通知引发的事件和日志，因为这里的内存负担太重。
		if len(blocks) >= 2048 || memory > 64*1024*1024 {
			log.Info("Importing heavy sidechain segment", "blocks", len(blocks), "start", blocks[0].NumberU64(), "end", block.NumberU64())
			// 导入大型侧链段
			if _, _, err := bc.insertChain(blocks, true, false); err != nil {
				return nil, 0, err
			}
			blocks, memory = blocks[:0], 0

			// If the chain is terminating, stop processing blocks
			// 如果链正在终止，停止处理区块
			if bc.insertStopped() {
				log.Debug("Abort during blocks processing")
				// 区块处理期间中止
				return nil, 0, nil
			}
		}
	}
	if len(blocks) > 0 {
		log.Info("Importing sidechain segment", "start", blocks[0].NumberU64(), "end", blocks[len(blocks)-1].NumberU64())
		// 导入侧链段
		return bc.insertChain(blocks, true, makeWitness)
	}
	return nil, 0, nil
	// 关键逻辑注解：
	// 1. 处理修剪祖先错误，写入侧链区块并计算总难度。
	// 2. 检测影子状态攻击并中止。
	// 3. 收集缺失状态的父区块并分批导入。
	// 4. 返回插入结果。
}

// recoverAncestors finds the closest ancestor with available state and re-execute
// all the ancestor blocks since that.
// recoverAncestors is only used post-merge.
// We return the hash of the latest block that we could correctly validate.
// recoverAncestors 找到最近的具有可用状态的祖先，并从该祖先开始重新执行所有祖先区块。
// recoverAncestors 仅在合并后使用。
// 我们返回我们能够正确验证的最新区块的哈希。
func (bc *BlockChain) recoverAncestors(block *types.Block, makeWitness bool) (common.Hash, error) {
	// Gather all the sidechain hashes (full blocks may be memory heavy)
	// 收集所有侧链哈希（完整区块可能占用大量内存）
	var (
		hashes  []common.Hash // 存储侧链区块的哈希列表
		numbers []uint64      // 存储侧链区块的编号列表
		parent  = block       // 当前处理的父区块，初始化为输入的区块
	)
	for parent != nil && !bc.HasState(parent.Root()) {
		if bc.stateRecoverable(parent.Root()) {
			if err := bc.triedb.Recover(parent.Root()); err != nil {
				return common.Hash{}, err // 如果恢复状态失败，返回空哈希和错误
			}
			break
		}
		hashes = append(hashes, parent.Hash())
		numbers = append(numbers, parent.NumberU64())
		parent = bc.GetBlock(parent.ParentHash(), parent.NumberU64()-1)

		// If the chain is terminating, stop iteration
		// 如果链正在终止，停止迭代
		if bc.insertStopped() {
			log.Debug("Abort during blocks iteration")
			// 区块迭代期间中止
			return common.Hash{}, errInsertionInterrupted
		}
	}
	if parent == nil {
		return common.Hash{}, errors.New("missing parent")
		// 缺少父区块
	}
	// Import all the pruned blocks to make the state available
	// 导入所有修剪的区块以使状态可用
	for i := len(hashes) - 1; i >= 0; i-- {
		// If the chain is terminating, stop processing blocks
		// 如果链正在终止，停止处理区块
		if bc.insertStopped() {
			log.Debug("Abort during blocks processing")
			// 区块处理期间中止
			return common.Hash{}, errInsertionInterrupted
		}
		var b *types.Block
		if i == 0 {
			b = block // 如果是第一个区块，使用输入的区块
		} else {
			b = bc.GetBlock(hashes[i], numbers[i]) // 否则从数据库获取
		}
		if _, _, err := bc.insertChain(types.Blocks{b}, false, makeWitness && i == 0); err != nil {
			return b.ParentHash(), err // 如果插入失败，返回父哈希和错误
		}
	}
	return block.Hash(), nil // 返回成功验证的区块哈希
	// 关键逻辑注解：
	// 1. 从输入区块开始，向上追溯父区块，直到找到具有可用状态的祖先。
	// 2. 如果状态可恢复，尝试恢复 trie 数据。
	// 3. 收集所有缺少状态的区块哈希和编号。
	// 4. 从最旧的区块开始，逐一重新插入，直到输入区块。
	// 5. 返回最新验证成功的区块哈希。
}

// collectLogs collects the logs that were generated or removed during the
// processing of a block. These logs are later announced as deleted or reborn.
// collectLogs 收集在区块处理期间生成或移除的日志。这些日志随后将被宣布为已删除或重生。
func (bc *BlockChain) collectLogs(b *types.Block, removed bool) []*types.Log {
	var blobGasPrice *big.Int          // Blob Gas 价格
	excessBlobGas := b.ExcessBlobGas() // 获取超额 Blob Gas
	if excessBlobGas != nil {
		blobGasPrice = eip4844.CalcBlobFee(*excessBlobGas) // 计算 Blob Gas 费用
	}
	receipts := rawdb.ReadRawReceipts(bc.db, b.Hash(), b.NumberU64()) // 从数据库读取原始收据
	if err := receipts.DeriveFields(bc.chainConfig, b.Hash(), b.NumberU64(), b.Time(), b.BaseFee(), blobGasPrice, b.Transactions()); err != nil {
		log.Error("Failed to derive block receipts fields", "hash", b.Hash(), "number", b.NumberU64(), "err", err)
		// 无法派生区块收据字段
	}
	var logs []*types.Log // 存储收集的日志
	for _, receipt := range receipts {
		for _, log := range receipt.Logs {
			if removed {
				log.Removed = true // 如果是移除状态，标记日志
			}
			logs = append(logs, log)
		}
	}
	return logs
	// 关键逻辑注解：
	// 1. 计算 Blob Gas 价格（如果适用）。
	// 2. 从数据库读取收据并派生字段。
	// 3. 遍历收据，收集所有日志并根据 removed 参数标记。
	// 4. 返回日志列表。
}

// reorg takes two blocks, an old chain and a new chain and will reconstruct the
// blocks and inserts them to be part of the new canonical chain and accumulates
// potential missing transactions and post an event about them.
//
// Note the new head block won't be processed here, callers need to handle it
// externally.
// reorg 接受两个区块，一个旧链和一个新链，将重建区块并插入它们使其成为新的规范链的一部分，并累积可能缺失的交易并发布相关事件。
//
// 注意，新头部区块不会在这里处理，调用者需要外部处理。
func (bc *BlockChain) reorg(oldHead *types.Header, newHead *types.Header) error {
	var (
		newChain    []*types.Header // 新链的头部列表
		oldChain    []*types.Header // 旧链的头部列表
		commonBlock *types.Header   // 公共祖先区块
	)
	// Reduce the longer chain to the same number as the shorter one
	// 将较长的链减少到与较短的链相同的数量
	if oldHead.Number.Uint64() > newHead.Number.Uint64() {
		// Old chain is longer, gather all transactions and logs as deleted ones
		// 旧链较长，收集所有交易和日志作为已删除的
		for ; oldHead != nil && oldHead.Number.Uint64() != newHead.Number.Uint64(); oldHead = bc.GetHeader(oldHead.ParentHash, oldHead.Number.Uint64()-1) {
			oldChain = append(oldChain, oldHead)
		}
	} else {
		// New chain is longer, stash all blocks away for subsequent insertion
		// 新链较长，存储所有区块以供后续插入
		for ; newHead != nil && newHead.Number.Uint64() != oldHead.Number.Uint64(); newHead = bc.GetHeader(newHead.ParentHash, newHead.Number.Uint64()-1) {
			newChain = append(newChain, newHead)
		}
	}
	if oldHead == nil {
		return errInvalidOldChain // 无效的旧链
	}
	if newHead == nil {
		return errInvalidNewChain // 无效的新链
	}
	// Both sides of the reorg are at the same number, reduce both until the common
	// ancestor is found
	// 重组的两侧高度相同，减少两者直到找到公共祖先
	for {
		// If the common ancestor was found, bail out
		// 如果找到公共祖先，退出循环
		if oldHead.Hash() == newHead.Hash() {
			commonBlock = oldHead
			break
		}
		// Remove an old block as well as stash away a new block
		// 移除一个旧区块并存储一个新区块
		oldChain = append(oldChain, oldHead)
		newChain = append(newChain, newHead)

		// Step back with both chains
		// 两链同时回退一步
		oldHead = bc.GetHeader(oldHead.ParentHash, oldHead.Number.Uint64()-1)
		if oldHead == nil {
			return errInvalidOldChain // 无效的旧链
		}
		newHead = bc.GetHeader(newHead.ParentHash, newHead.Number.Uint64()-1)
		if newHead == nil {
			return errInvalidNewChain // 无效的新链
		}
	}
	// Ensure the user sees large reorgs
	// 确保用户看到大型重组
	if len(oldChain) > 0 && len(newChain) > 0 {
		logFn := log.Info
		msg := "Chain reorg detected"
		// 检测到链重组
		if len(oldChain) > 63 {
			msg = "Large chain reorg detected"
			// 检测到大型链重组
			logFn = log.Warn
		}
		logFn(msg, "number", commonBlock.Number, "hash", commonBlock.Hash(),
			"drop", len(oldChain), "dropfrom", oldChain[0].Hash(), "add", len(newChain), "addfrom", newChain[0].Hash())
		blockReorgAddMeter.Mark(int64(len(newChain)))
		blockReorgDropMeter.Mark(int64(len(oldChain)))
		blockReorgMeter.Mark(1)
	} else if len(newChain) > 0 {
		// Special case happens in the post merge stage that current head is
		// the ancestor of new head while these two blocks are not consecutive
		// 特殊情况发生在合并后阶段，当前头部是新头部的祖先，而这两个区块并非连续的
		log.Info("Extend chain", "add", len(newChain), "number", newChain[0].Number, "hash", newChain[0].Hash())
		// 扩展链
		blockReorgAddMeter.Mark(int64(len(newChain)))
	} else {
		// len(newChain) == 0 && len(oldChain) > 0
		// rewind the canonical chain to a lower point.
		// len(newChain) == 0 && len(oldChain) > 0
		// 将规范链回退到较低点。
		log.Error("Impossible reorg, please file an issue", "oldnum", oldHead.Number, "oldhash", oldHead.Hash(), "oldblocks", len(oldChain), "newnum", newHead.Number, "newhash", newHead.Hash(), "newblocks", len(newChain))
		// 不可能的重组，请提交问题
	}
	// Acquire the tx-lookup lock before mutation. This step is essential
	// as the txlookups should be changed atomically, and all subsequent
	// reads should be blocked until the mutation is complete.
	// 在变更前获取交易查找锁。这一步至关重要，因为交易查找应原子性更改，并且在变更完成前所有后续读取应被阻止。
	bc.txLookupLock.Lock()

	// Reorg can be executed, start reducing the chain's old blocks and appending
	// the new blocks
	// 可以执行重组，开始减少链的旧区块并追加新区块
	var (
		deletedTxs  []common.Hash // 已删除的交易哈希列表
		rebirthTxs  []common.Hash // 重生的交易哈希列表
		deletedLogs []*types.Log  // 已删除的日志列表
		rebirthLogs []*types.Log  // 重生的日志列表
	)
	// Deleted log emission on the API uses forward order, which is borked, but
	// we'll leave it in for legacy reasons.
	//
	// TODO(karalabe): This should be nuked out, no idea how, deprecate some APIs?
	// API 上的已删除日志发射使用正序，这是有问题的，但出于遗留原因我们保留它。
	//
	// TODO(karalabe)：这应该被移除，不知道怎么做，废弃一些 API？
	{
		for i := len(oldChain) - 1; i >= 0; i-- {
			block := bc.GetBlock(oldChain[i].Hash(), oldChain[i].Number.Uint64())
			if block == nil {
				return errInvalidOldChain // Corrupt database, mostly here to avoid weird panics
				// 无效的旧链 // 数据库损坏，主要用于避免奇怪的恐慌
			}
			if logs := bc.collectLogs(block, true); len(logs) > 0 {
				deletedLogs = append(deletedLogs, logs...)
			}
			if len(deletedLogs) > 512 {
				bc.rmLogsFeed.Send(RemovedLogsEvent{deletedLogs})
				deletedLogs = nil
			}
		}
		if len(deletedLogs) > 0 {
			bc.rmLogsFeed.Send(RemovedLogsEvent{deletedLogs})
		}
	}
	// Undo old blocks in reverse order
	// 以相反顺序撤销旧区块
	for i := 0; i < len(oldChain); i++ {
		// Collect all the deleted transactions
		// 收集所有已删除的交易
		block := bc.GetBlock(oldChain[i].Hash(), oldChain[i].Number.Uint64())
		if block == nil {
			return errInvalidOldChain // Corrupt database, mostly here to avoid weird panics
			// 无效的旧链 // 数据库损坏，主要用于避免奇怪的恐慌
		}
		for _, tx := range block.Transactions() {
			deletedTxs = append(deletedTxs, tx.Hash())
		}
		// Collect deleted logs and emit them for new integrations
		// 收集已删除的日志并为新集成发射它们
		if logs := bc.collectLogs(block, true); len(logs) > 0 {
			// Emit revertals latest first, older then
			// 发射撤销日志，最新优先，然后较旧的
			slices.Reverse(logs)

			// TODO(karalabe): Hook into the reverse emission part
			// TODO(karalabe)：接入反向发射部分
		}
	}
	// Apply new blocks in forward order
	// 以正序应用新区块
	for i := len(newChain) - 1; i >= 1; i-- {
		// Collect all the included transactions
		// 收集所有包含的交易
		block := bc.GetBlock(newChain[i].Hash(), newChain[i].Number.Uint64())
		if block == nil {
			return errInvalidNewChain // Corrupt database, mostly here to avoid weird panics
			// 无效的新链 // 数据库损坏，主要用于避免奇怪的恐慌
		}
		for _, tx := range block.Transactions() {
			rebirthTxs = append(rebirthTxs, tx.Hash())
		}
		// Collect inserted logs and emit them
		// 收集插入的日志并发射它们
		if logs := bc.collectLogs(block, false); len(logs) > 0 {
			rebirthLogs = append(rebirthLogs, logs...)
		}
		if len(rebirthLogs) > 512 {
			bc.logsFeed.Send(rebirthLogs)
			rebirthLogs = nil
		}
		// Update the head block
		// 更新头部区块
		bc.writeHeadBlock(block)
	}
	if len(rebirthLogs) > 0 {
		bc.logsFeed.Send(rebirthLogs)
	}
	// Delete useless indexes right now which includes the non-canonical
	// transaction indexes, canonical chain indexes which above the head.
	// 立即删除无用的索引，包括非规范交易索引、超过头部的规范链索引。
	batch := bc.db.NewBatch()
	for _, tx := range types.HashDifference(deletedTxs, rebirthTxs) {
		rawdb.DeleteTxLookupEntry(batch, tx) // 删除非规范交易索引
	}
	// Delete all hash markers that are not part of the new canonical chain.
	// Because the reorg function does not handle new chain head, all hash
	// markers greater than or equal to new chain head should be deleted.
	// 删除所有不属于新规范链的哈希标记。
	// 因为重组函数不处理新链头部，所有大于或等于新链头部的哈希标记都应删除。
	number := commonBlock.Number
	if len(newChain) > 1 {
		number = newChain[1].Number
	}
	for i := number.Uint64() + 1; ; i++ {
		hash := rawdb.ReadCanonicalHash(bc.db, i)
		if hash == (common.Hash{}) {
			break
		}
		rawdb.DeleteCanonicalHash(batch, i)
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to delete useless indexes", "err", err)
		// 无法删除无用索引
	}
	// Reset the tx lookup cache to clear stale txlookup cache.
	// 重置交易查找缓存以清除过期的交易查找缓存。
	bc.txLookupCache.Purge()

	// Release the tx-lookup lock after mutation.
	// 在变更后释放交易查找锁。
	bc.txLookupLock.Unlock()

	return nil
	// 关键逻辑注解：
	// 1. 找到旧链和新链的公共祖先。
	// 2. 收集旧链的删除交易和日志，收集新链的重生交易和日志。
	// 3. 以相反顺序撤销旧链区块，以正序应用新链区块。
	// 4. 更新头部区块并清理无用索引。
	// 5. 发射相关事件并释放锁。
}

// InsertBlockWithoutSetHead executes the block, runs the necessary verification
// upon it and then persist the block and the associate state into the database.
// The key difference between the InsertChain is it won't do the canonical chain
// updating. It relies on the additional SetCanonical call to finalize the entire
// procedure.
// InsertBlockWithoutSetHead 执行区块，对其运行必要的验证，然后将区块和关联状态持久化到数据库中。
// 与 InsertChain 的关键区别在于它不会更新规范链。它依赖额外的 SetCanonical 调用来完成整个过程。
func (bc *BlockChain) InsertBlockWithoutSetHead(block *types.Block, makeWitness bool) (*stateless.Witness, error) {
	if !bc.chainmu.TryLock() {
		return nil, errChainStopped // 如果无法获取锁，返回链停止错误
	}
	defer bc.chainmu.Unlock() // 延迟释放锁

	witness, _, err := bc.insertChain(types.Blocks{block}, false, makeWitness) // 执行插入
	return witness, err
	// 关键逻辑注解：
	// 1. 获取链锁以确保线程安全。
	// 2. 调用 insertChain 执行区块插入但不设置头部。
	// 3. 返回见证数据和可能的错误。
}

// SetCanonical rewinds the chain to set the new head block as the specified
// block. It's possible that the state of the new head is missing, and it will
// be recovered in this function as well.
// SetCanonical 回退链以将新头部区块设置为指定的区块。新头部状态可能缺失，也会在此函数中恢复。
func (bc *BlockChain) SetCanonical(head *types.Block) (common.Hash, error) {
	if !bc.chainmu.TryLock() {
		return common.Hash{}, errChainStopped // 如果无法获取锁，返回链停止错误
	}
	defer bc.chainmu.Unlock() // 延迟释放锁

	// Re-execute the reorged chain in case the head state is missing.
	// 如果头部状态缺失，重新执行重组链。
	if !bc.HasState(head.Root()) {
		if latestValidHash, err := bc.recoverAncestors(head, false); err != nil {
			return latestValidHash, err // 如果恢复失败，返回最新有效哈希和错误
		}
		log.Info("Recovered head state", "number", head.Number(), "hash", head.Hash())
		// 已恢复头部状态
	}
	// Run the reorg if necessary and set the given block as new head.
	// 如果需要，运行重组并将给定区块设置为新头部。
	start := time.Now()
	if head.ParentHash() != bc.CurrentBlock().Hash() {
		if err := bc.reorg(bc.CurrentBlock(), head.Header()); err != nil {
			return common.Hash{}, err // 如果重组失败，返回错误
		}
	}
	bc.writeHeadBlock(head) // 写入头部区块

	// Emit events
	// 发射事件
	logs := bc.collectLogs(head, false)
	bc.chainFeed.Send(ChainEvent{Header: head.Header()})
	if len(logs) > 0 {
		bc.logsFeed.Send(logs)
	}
	bc.chainHeadFeed.Send(ChainHeadEvent{Header: head.Header()})

	context := []interface{}{
		"number", head.Number(),
		"hash", head.Hash(),
		"root", head.Root(),
		"elapsed", time.Since(start),
	}
	if timestamp := time.Unix(int64(head.Time()), 0); time.Since(timestamp) > time.Minute {
		context = append(context, []interface{}{"age", common.PrettyAge(timestamp)}...)
	}
	log.Info("Chain head was updated", context...)
	// 链头部已更新
	return head.Hash(), nil
	// 关键逻辑注解：
	// 1. 检查并恢复新头部状态（如果缺失）。
	// 2. 如果需要，与当前头部执行重组。
	// 3. 写入新头部并发射相关事件。
	// 4. 返回新头部哈希。
}

// skipBlock returns 'true', if the block being imported can be skipped over, meaning
// that the block does not need to be processed but can be considered already fully 'done'.
// skipBlock 返回 'true'，如果正在导入的区块可以跳过，意味着该区块无需处理，可以认为已经完全“完成”。
func (bc *BlockChain) skipBlock(err error, it *insertIterator) bool {
	// We can only ever bypass processing if the only error returned by the validator
	// is ErrKnownBlock, which means all checks passed, but we already have the block
	// and state.
	// 我们只能在验证器返回的唯一错误是 ErrKnownBlock 时绕过处理，这意味着所有检查都通过，但我们已经拥有该区块和状态。
	if !errors.Is(err, ErrKnownBlock) {
		return false
	}
	// If we're not using snapshots, we can skip this, since we have both block
	// and (trie-) state
	// 如果我们不使用快照，可以跳过，因为我们同时拥有区块和（trie-）状态
	if bc.snaps == nil {
		return true
	}
	var (
		header = it.current() // header can't be nil
		// 头部不能为空
		parentRoot common.Hash // 父区块的状态根
	)
	// If we also have the snapshot-state, we can skip the processing.
	// 如果我们也有快照状态，可以跳过处理。
	if bc.snaps.Snapshot(header.Root) != nil {
		return true
	}
	// In this case, we have the trie-state but not snapshot-state. If the parent
	// snapshot-state exists, we need to process this in order to not get a gap
	// in the snapshot layers.
	// 在这种情况下，我们有 trie 状态但没有快照状态。如果父快照状态存在，我们需要处理这个以避免快照层出现间隙。
	// Resolve parent block
	// 解析父区块
	if parent := it.previous(); parent != nil {
		parentRoot = parent.Root
	} else if parent = bc.GetHeaderByHash(header.ParentHash); parent != nil {
		parentRoot = parent.Root
	}
	if parentRoot == (common.Hash{}) {
		return false // Theoretically impossible case
		// 理论上不可能的情况
	}
	// Parent is also missing snapshot: we can skip this. Otherwise process.
	// 父区块也缺少快照：我们可以跳过。否则处理。
	if bc.snaps.Snapshot(parentRoot) == nil {
		return true
	}
	return false
	// 关键逻辑注解：
	// 1. 检查错误是否为 ErrKnownBlock。
	// 2. 如果不使用快照且有状态，直接跳过。
	// 3. 如果有快照，检查当前和父区块的快照状态。
	// 4. 根据快照连续性决定是否跳过。
}

// reportBlock logs a bad block error.
// reportBlock 记录一个坏块错误。
func (bc *BlockChain) reportBlock(block *types.Block, res *ProcessResult, err error) {
	var receipts types.Receipts // 收据列表
	if res != nil {
		receipts = res.Receipts
	}
	rawdb.WriteBadBlock(bc.db, block) // 写入坏块到数据库
	log.Error(summarizeBadBlock(block, receipts, bc.Config(), err))
}

// summarizeBadBlock returns a string summarizing the bad block and other
// relevant information.
// summarizeBadBlock 返回一个字符串，总结坏块和其他相关信息。
func summarizeBadBlock(block *types.Block, receipts []*types.Receipt, config *params.ChainConfig, err error) string {
	var receiptString string // 收据信息字符串
	for i, receipt := range receipts {
		receiptString += fmt.Sprintf("\n  %d: cumulative: %v gas: %v contract: %v status: %v tx: %v logs: %v bloom: %x state: %x",
			i, receipt.CumulativeGasUsed, receipt.GasUsed, receipt.ContractAddress.Hex(),
			receipt.Status, receipt.TxHash.Hex(), receipt.Logs, receipt.Bloom, receipt.PostState)
	}
	version, vcs := version.Info()
	platform := fmt.Sprintf("%s %s %s %s", version, runtime.Version(), runtime.GOARCH, runtime.GOOS)
	if vcs != "" {
		vcs = fmt.Sprintf("\nVCS: %s", vcs)
	}
	return fmt.Sprintf(`
########## BAD BLOCK #########
Block: %v (%#x)
Error: %v
Platform: %v%v
Chain config: %#v
Receipts: %v
##############################
`, block.Number(), block.Hash(), err, platform, vcs, config, receiptString)
	// 关键逻辑注解：
	// 1. 格式化收据信息。
	// 2. 收集版本和平台信息。
	// 3. 返回包含坏块详情的字符串。
}

// InsertHeaderChain attempts to insert the given header chain in to the local
// chain, possibly creating a reorg. If an error is returned, it will return the
// index number of the failing header as well an error describing what went wrong.
// InsertHeaderChain 尝试将给定的头部链插入到本地链中，可能会创建重组。如果返回错误，将返回失败头部的索引号以及描述出错原因的错误。
func (bc *BlockChain) InsertHeaderChain(chain []*types.Header) (int, error) {
	if len(chain) == 0 {
		return 0, nil // 如果链为空，直接返回
	}
	start := time.Now()
	if i, err := bc.hc.ValidateHeaderChain(chain); err != nil {
		return i, err // 验证失败，返回失败索引和错误
	}

	if !bc.chainmu.TryLock() {
		return 0, errChainStopped // 如果无法获取锁，返回链停止错误
	}
	defer bc.chainmu.Unlock()                       // 延迟释放锁
	_, err := bc.hc.InsertHeaderChain(chain, start) // 执行头部插入
	return 0, err
	// 关键逻辑注解：
	// 1. 检查输入链是否为空。
	// 2. 验证头部链的有效性。
	// 3. 获取锁并插入头部链。
	// 4. 返回插入结果。
}

// SetBlockValidatorAndProcessorForTesting sets the current validator and processor.
// This method can be used to force an invalid blockchain to be verified for tests.
// This method is unsafe and should only be used before block import starts.
// SetBlockValidatorAndProcessorForTesting 设置当前的验证器和处理器。
// 此方法可用于强制验证无效的区块链以进行测试。
// 此方法不安全，仅应在区块导入开始前使用。
func (bc *BlockChain) SetBlockValidatorAndProcessorForTesting(v Validator, p Processor) {
	bc.validator = v // 设置验证器
	bc.processor = p // 设置处理器
	// 关键逻辑注解：
	// 1. 直接更新区块链对象的验证器和处理器。
	// 2. 用于测试目的，允许自定义验证逻辑。
}

// SetTrieFlushInterval configures how often in-memory tries are persisted to disk.
// The interval is in terms of block processing time, not wall clock.
// It is thread-safe and can be called repeatedly without side effects.
// SetTrieFlushInterval 配置内存中的 trie 多长时间持久化到磁盘一次。
// 间隔是按区块处理时间计算的，而不是挂钟时间。
// 它是线程安全的，可以反复调用而没有副作用。
func (bc *BlockChain) SetTrieFlushInterval(interval time.Duration) {
	bc.flushInterval.Store(int64(interval)) // 存储刷新间隔
	// 关键逻辑注解：
	// 1. 使用原子操作设置 trie 刷新间隔。
	// 2. 确保线程安全。
}

// GetTrieFlushInterval gets the in-memory tries flushAlloc interval
// GetTrieFlushInterval 获取内存中 trie 的刷新分配间隔
func (bc *BlockChain) GetTrieFlushInterval() time.Duration {
	return time.Duration(bc.flushInterval.Load()) // 加载并返回刷新间隔
	// 关键逻辑注解：
	// 1. 使用原子操作读取 trie 刷新间隔。
	// 2. 返回时间间隔值。
}
