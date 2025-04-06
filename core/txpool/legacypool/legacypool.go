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

// Package legacypool implements the normal EVM execution transaction pool.
package legacypool

import (
	"errors"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/prque"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/exp/maps"
)

const (
	// txSlotSize is used to calculate how many data slots a single transaction
	// takes up based on its size. The slots are used as DoS protection, ensuring
	// that validating a new transaction remains a constant operation (in reality
	// O(maxslots), where max slots are 4 currently).
	// txSlotSize 用于根据交易的大小计算单个交易占用多少数据槽。这些槽用作 DoS 保护，确保验证新交易保持恒定操作（实际上是 O(maxslots)，当前最大槽数为 4）。
	txSlotSize = 32 * 1024

	// txMaxSize is the maximum size a single transaction can have. This field has
	// non-trivial consequences: larger transactions are significantly harder and
	// more expensive to propagate; larger transactions also take more resources
	// to validate whether they fit into the pool or not.
	// txMaxSize 是单个交易的最大大小。此字段有非 trivial 的后果：较大的交易传播起来明显更困难且成本更高；较大的交易还需要更多资源来验证是否适合放入交易池。
	txMaxSize = 4 * txSlotSize // 128KB
)

var (
	// ErrTxPoolOverflow is returned if the transaction pool is full and can't accept
	// another remote transaction.
	// ErrTxPoolOverflow 在交易池已满且无法接受另一个远程交易时返回。
	ErrTxPoolOverflow = errors.New("txpool is full") // 交易池已满
)

var (
	evictionInterval = time.Minute // Time interval to check for evictable transactions
	// evictionInterval 检查可驱逐交易的时间间隔
	statsReportInterval = 8 * time.Second // Time interval to report transaction pool stats
	// statsReportInterval 报告交易池统计数据的时间间隔
)

var (
	// Metrics for the pending pool
	// 待处理池的指标
	pendingDiscardMeter   = metrics.NewRegisteredMeter("txpool/pending/discard", nil)   // 记录被丢弃的待处理交易
	pendingReplaceMeter   = metrics.NewRegisteredMeter("txpool/pending/replace", nil)   // 记录被替换的待处理交易
	pendingRateLimitMeter = metrics.NewRegisteredMeter("txpool/pending/ratelimit", nil) // Dropped due to rate limiting
	// pendingRateLimitMeter 记录因速率限制而丢弃的交易
	pendingNofundsMeter = metrics.NewRegisteredMeter("txpool/pending/nofunds", nil) // Dropped due to out-of-funds
	// pendingNofundsMeter 记录因资金不足而丢弃的交易

	// Metrics for the queued pool
	// 队列池的指标
	queuedDiscardMeter   = metrics.NewRegisteredMeter("txpool/queued/discard", nil)   // 记录被丢弃的队列交易
	queuedReplaceMeter   = metrics.NewRegisteredMeter("txpool/queued/replace", nil)   // 记录被替换的队列交易
	queuedRateLimitMeter = metrics.NewRegisteredMeter("txpool/queued/ratelimit", nil) // Dropped due to rate limiting
	// queuedRateLimitMeter 记录因速率限制而丢弃的交易
	queuedNofundsMeter = metrics.NewRegisteredMeter("txpool/queued/nofunds", nil) // Dropped due to out-of-funds
	// queuedNofundsMeter 记录因资金不足而丢弃的交易
	queuedEvictionMeter = metrics.NewRegisteredMeter("txpool/queued/eviction", nil) // Dropped due to lifetime
	// queuedEvictionMeter 记录因生存时间到期而丢弃的交易

	// General tx metrics
	// 通用交易指标
	knownTxMeter       = metrics.NewRegisteredMeter("txpool/known", nil)       // 记录已知交易数量
	validTxMeter       = metrics.NewRegisteredMeter("txpool/valid", nil)       // 记录有效交易数量
	invalidTxMeter     = metrics.NewRegisteredMeter("txpool/invalid", nil)     // 记录无效交易数量
	underpricedTxMeter = metrics.NewRegisteredMeter("txpool/underpriced", nil) // 记录因价格过低而丢弃的交易
	overflowedTxMeter  = metrics.NewRegisteredMeter("txpool/overflowed", nil)  // 记录因池溢出而丢弃的交易

	// throttleTxMeter counts how many transactions are rejected due to too-many-changes between
	// txpool reorgs.
	// throttleTxMeter 统计因交易池重组之间变化过多而被拒绝的交易数量。
	throttleTxMeter = metrics.NewRegisteredMeter("txpool/throttle", nil)
	// reorgDurationTimer measures how long time a txpool reorg takes.
	// reorgDurationTimer 测量交易池重组所需的时间。
	reorgDurationTimer = metrics.NewRegisteredTimer("txpool/reorgtime", nil)
	// dropBetweenReorgHistogram counts how many drops we experience between two reorg runs. It is expected
	// that this number is pretty low, since txpool reorgs happen very frequently.
	// dropBetweenReorgHistogram 统计两次重组运行之间丢弃的交易数量。预计这个数字很低，因为交易池重组非常频繁。
	dropBetweenReorgHistogram = metrics.NewRegisteredHistogram("txpool/dropbetweenreorg", nil, metrics.NewExpDecaySample(1028, 0.015))

	pendingGauge = metrics.NewRegisteredGauge("txpool/pending", nil) // 待处理交易的总数
	queuedGauge  = metrics.NewRegisteredGauge("txpool/queued", nil)  // 队列中交易的总数
	localGauge   = metrics.NewRegisteredGauge("txpool/local", nil)   // 本地交易的总数
	slotsGauge   = metrics.NewRegisteredGauge("txpool/slots", nil)   // 当前占用的槽总数

	reheapTimer = metrics.NewRegisteredTimer("txpool/reheap", nil) // 记录重新堆化的时间
)

// BlockChain defines the minimal set of methods needed to back a tx pool with
// a chain. Exists to allow mocking the live chain out of tests.
// BlockChain 定义了支持交易池所需的最小区块链方法集。存在此接口是为了在测试中模拟实时链。
type BlockChain interface {
	// Config retrieves the chain's fork configuration.
	// Config 获取链的分叉配置。
	Config() *params.ChainConfig

	// CurrentBlock returns the current head of the chain.
	// CurrentBlock 返回链的当前头部。
	CurrentBlock() *types.Header

	// GetBlock retrieves a specific block, used during pool resets.
	// GetBlock 获取特定区块，用于池重置期间。
	GetBlock(hash common.Hash, number uint64) *types.Block

	// StateAt returns a state database for a given root hash (generally the head).
	// StateAt 返回给定根哈希（通常是头部）的状态数据库。
	StateAt(root common.Hash) (*state.StateDB, error)
}

// Config are the configuration parameters of the transaction pool.
// Config 是交易池的配置参数。
type Config struct {
	Locals []common.Address // Addresses that should be treated by default as local
	// Locals 默认应视为本地的地址列表
	NoLocals bool // Whether local transaction handling should be disabled
	// NoLocals 是否禁用本地交易处理
	Journal string // Journal of local transactions to survive node restarts
	// Journal 本地交易日志，用于节点重启后恢复
	Rejournal time.Duration // Time interval to regenerate the local transaction journal
	// Rejournal 重新生成本地交易日志的时间间隔

	PriceLimit uint64 // Minimum gas price to enforce for acceptance into the pool
	// PriceLimit 接受进入交易池的最低 gas 价格
	PriceBump uint64 // Minimum price bump percentage to replace an already existing transaction (nonce)
	// PriceBump 替换已有交易（相同 nonce）所需的最小价格提升百分比

	AccountSlots uint64 // Number of executable transaction slots guaranteed per account
	// AccountSlots 每个账户保证的可执行交易槽数量
	GlobalSlots uint64 // Maximum number of executable transaction slots for all accounts
	// GlobalSlots 所有账户的最大可执行交易槽数量
	AccountQueue uint64 // Maximum number of non-executable transaction slots permitted per account
	// AccountQueue 每个账户允许的最大非可执行交易槽数量
	GlobalQueue uint64 // Maximum number of non-executable transaction slots for all accounts
	// GlobalQueue 所有账户的最大非可执行交易槽数量

	Lifetime time.Duration // Maximum amount of time non-executable transaction are queued
	// Lifetime 非可执行交易在队列中的最大存活时间
}

// DefaultConfig contains the default configurations for the transaction pool.
// DefaultConfig 包含交易池的默认配置。
var DefaultConfig = Config{
	Journal:   "transactions.rlp", // 默认日志文件名为 "transactions.rlp"
	Rejournal: time.Hour,          // 默认重新生成日志的间隔为 1 小时

	PriceLimit: 1,  // 默认最低 gas 价格为 1
	PriceBump:  10, // 默认替换交易的最小价格提升百分比为 10%

	AccountSlots: 16,          // 默认每个账户的可执行槽数为 16
	GlobalSlots:  4096 + 1024, // urgent + floating queue capacity with 4:1 ratio 默认全局可执行槽数为 4096 + 1024（紧急 + 浮动队列容量，4:1 比例）
	AccountQueue: 64,          // 默认每个账户的非可执行槽数为 64
	GlobalQueue:  1024,        // 默认全局非可执行槽数为 1024

	Lifetime: 3 * time.Hour, // 默认非可执行交易存活时间为 3 小时
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
// sanitize 检查用户提供的配置，并更改任何不合理或不可行的设置。
func (config *Config) sanitize() Config {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		// 如果 Rejournal 小于 1 秒，记录警告并更新为 1 秒
		conf.Rejournal = time.Second
	}
	if conf.PriceLimit < 1 {
		log.Warn("Sanitizing invalid txpool price limit", "provided", conf.PriceLimit, "updated", DefaultConfig.PriceLimit)
		// 如果 PriceLimit 小于 1，记录警告并更新为默认值
		conf.PriceLimit = DefaultConfig.PriceLimit
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultConfig.PriceBump)
		// 如果 PriceBump 小于 1，记录警告并更新为默认值
		conf.PriceBump = DefaultConfig.PriceBump
	}
	if conf.AccountSlots < 1 {
		log.Warn("Sanitizing invalid txpool account slots", "provided", conf.AccountSlots, "updated", DefaultConfig.AccountSlots)
		// 如果 AccountSlots 小于 1，记录警告并更新为默认值
		conf.AccountSlots = DefaultConfig.AccountSlots
	}
	if conf.GlobalSlots < 1 {
		log.Warn("Sanitizing invalid txpool global slots", "provided", conf.GlobalSlots, "updated", DefaultConfig.GlobalSlots)
		// 如果 GlobalSlots 小于 1，记录警告并更新为默认值
		conf.GlobalSlots = DefaultConfig.GlobalSlots
	}
	if conf.AccountQueue < 1 {
		log.Warn("Sanitizing invalid txpool account queue", "provided", conf.AccountQueue, "updated", DefaultConfig.AccountQueue)
		// 如果 AccountQueue 小于 1，记录警告并更新为默认值
		conf.AccountQueue = DefaultConfig.AccountQueue
	}
	if conf.GlobalQueue < 1 {
		log.Warn("Sanitizing invalid txpool global queue", "provided", conf.GlobalQueue, "updated", DefaultConfig.GlobalQueue)
		// 如果 GlobalQueue 小于 1，记录警告并更新为默认值
		conf.GlobalQueue = DefaultConfig.GlobalQueue
	}
	if conf.Lifetime < 1 {
		log.Warn("Sanitizing invalid txpool lifetime", "provided", conf.Lifetime, "updated", DefaultConfig.Lifetime)
		// 如果 Lifetime 小于 1，记录警告并更新为默认值
		conf.Lifetime = DefaultConfig.Lifetime
	}
	return conf
	// 逻辑注解：此函数对 Config 进行合理性检查，确保所有参数都在合理范围内。如果参数低于最小阈值，则将其设置为默认值并记录警告日志。
}

// LegacyPool contains all currently known transactions. Transactions
// enter the pool when they are received from the network or submitted
// locally. They exit the pool when they are included in the blockchain.
//
// The pool separates processable transactions (which can be applied to the
// current state) and future transactions. Transactions move between those
// two states over time as they are received and processed.
// LegacyPool 包含所有当前已知的交易。交易从网络接收或本地提交时进入池，当它们被包含在区块链中时退出池。
// 交易池将可处理交易（可应用于当前状态）和未来交易分开。交易随着接收和处理在这两个状态之间移动。
type LegacyPool struct {
	config      Config                      // 交易池配置
	chainconfig *params.ChainConfig         // 区块链配置
	chain       BlockChain                  // 区块链接口实例
	gasTip      atomic.Pointer[uint256.Int] // 当前最低 gas tip（原子操作）
	txFeed      event.Feed                  // 交易事件订阅
	signer      types.Signer                // 交易签名器
	mu          sync.RWMutex                // 读写锁，用于保护池状态

	currentHead atomic.Pointer[types.Header] // Current head of the blockchain
	// currentHead 区块链当前头部（原子操作）
	currentState *state.StateDB // Current state in the blockchain head
	// currentState 区块链头部当前状态
	pendingNonces *noncer // Pending state tracking virtual nonces
	// pendingNonces 跟踪待处理状态的虚拟 nonce

	locals *accountSet // Set of local transaction to exempt from eviction rules
	// locals 本地交易账户集合，免于驱逐规则
	journal *journal // Journal of local transaction to back up to disk
	// journal 本地交易日志，用于备份到磁盘

	reserve txpool.AddressReserver // Address reserver to ensure exclusivity across subpools
	// reserve 地址预留器，确保子池之间的独占性
	pending map[common.Address]*list // All currently processable transactions
	// pending 所有当前可处理交易，按地址映射
	queue map[common.Address]*list // Queued but non-processable transactions
	// queue 队列中的非可处理交易，按地址映射
	beats map[common.Address]time.Time // Last heartbeat from each known account
	// beats 每个已知账户的最后心跳时间
	all *lookup // All transactions to allow lookups
	// all 所有交易的查找表
	priced *pricedList // All transactions sorted by price
	// priced 按价格排序的所有交易

	reqResetCh      chan *txpoolResetRequest // 重置请求通道
	reqPromoteCh    chan *accountSet         // 提升请求通道
	queueTxEventCh  chan *types.Transaction  // 队列交易事件通道
	reorgDoneCh     chan chan struct{}       // 重组完成通道
	reorgShutdownCh chan struct{}            // requests shutdown of scheduleReorgLoop
	// reorgShutdownCh 请求关闭 scheduleReorgLoop
	wg sync.WaitGroup // tracks loop, scheduleReorgLoop
	// wg 跟踪循环和 scheduleReorgLoop
	initDoneCh chan struct{} // is closed once the pool is initialized (for tests)
	// initDoneCh 在池初始化完成后关闭（用于测试）

	changesSinceReorg int // A counter for how many drops we've performed in-between reorg.
	// changesSinceReorg 统计两次重组之间执行的丢弃次数
}

type txpoolResetRequest struct {
	oldHead, newHead *types.Header // 旧头部和新头部，用于重置请求
}

// New creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
// New 创建一个新的交易池，用于收集、排序和过滤网络传入的交易。
func New(config Config, chain BlockChain) *LegacyPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	// 对输入进行清理，确保没有设置易受攻击的 gas 价格
	config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	// 使用初始设置创建交易池
	pool := &LegacyPool{
		config:          config,                             // 设置交易池配置
		chain:           chain,                              // 设置区块链实例
		chainconfig:     chain.Config(),                     // 设置区块链配置
		signer:          types.LatestSigner(chain.Config()), // 设置最新签名器
		pending:         make(map[common.Address]*list),     // 初始化待处理交易映射
		queue:           make(map[common.Address]*list),     // 初始化队列交易映射
		beats:           make(map[common.Address]time.Time), // 初始化心跳映射
		all:             newLookup(),                        // 初始化所有交易查找表
		reqResetCh:      make(chan *txpoolResetRequest),     // 初始化重置请求通道
		reqPromoteCh:    make(chan *accountSet),             // 初始化提升请求通道
		queueTxEventCh:  make(chan *types.Transaction),      // 初始化队列交易事件通道
		reorgDoneCh:     make(chan chan struct{}),           // 初始化重组完成通道
		reorgShutdownCh: make(chan struct{}),                // 初始化重组关闭通道
		initDoneCh:      make(chan struct{}),                // 初始化完成通道
	}
	pool.locals = newAccountSet(pool.signer) // 创建本地账户集合
	for _, addr := range config.Locals {
		log.Info("Setting new local account", "address", addr)
		// 设置新的本地账户
		pool.locals.add(addr)
	}
	pool.priced = newPricedList(pool.all) // 创建按价格排序的交易列表

	if !config.NoLocals && config.Journal != "" {
		pool.journal = newTxJournal(config.Journal) // 如果启用本地交易和日志，创建交易日志
	}
	return pool
	// 逻辑注解：此函数初始化一个 LegacyPool 实例，设置基本参数并根据配置决定是否启用本地交易日志。关键逻辑包括清理配置、初始化映射和通道、设置本地账户。
}

// Filter returns whether the given transaction can be consumed by the legacy
// pool, specifically, whether it is a Legacy, AccessList or Dynamic transaction.
// Filter 返回给定交易是否可以被遗留池消费，具体来说，是否是 Legacy、AccessList 或 Dynamic 交易。
func (pool *LegacyPool) Filter(tx *types.Transaction) bool {
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType:
		return true // 如果交易类型是支持的类型，返回 true
	default:
		return false // 否则返回 false
	}
	// 逻辑注解：此函数检查交易类型，只接受 Legacy、AccessList 和 DynamicFee 三种类型。这是为了确保遗留池只处理兼容的交易类型。
}

// Init sets the gas price needed to keep a transaction in the pool and the chain
// head to allow balance / nonce checks. The transaction journal will be loaded
// from disk and filtered based on the provided starting settings. The internal
// goroutines will be spun up and the pool deemed operational afterwards.
// Init 设置保持交易在池中所需的 gas 价格和链头部，以允许余额和 nonce 检查。交易日志将从磁盘加载并根据提供的起始设置进行过滤。之后启动内部 goroutine，池将被视为可操作。
func (pool *LegacyPool) Init(gasTip uint64, head *types.Header, reserve txpool.AddressReserver) error {
	// Set the address reserver to request exclusive access to pooled accounts
	// 设置地址预留器以请求对池中账户的独占访问
	pool.reserve = reserve

	// Set the basic pool parameters
	// 设置基本池参数
	pool.gasTip.Store(uint256.NewInt(gasTip)) // 设置最低 gas tip

	// Initialize the state with head block, or fallback to empty one in
	// case the head state is not available (might occur when node is not
	// fully synced).
	// 使用头部区块初始化状态，如果头部状态不可用（可能在节点未完全同步时发生），则回退到空状态。
	statedb, err := pool.chain.StateAt(head.Root)
	if err != nil {
		statedb, err = pool.chain.StateAt(types.EmptyRootHash) // 尝试使用空根哈希获取状态
	}
	if err != nil {
		return err // 如果仍然失败，返回错误
	}
	pool.currentHead.Store(head)            // 设置当前头部
	pool.currentState = statedb             // 设置当前状态
	pool.pendingNonces = newNoncer(statedb) // 初始化待处理 nonce 跟踪器

	// Start the reorg loop early, so it can handle requests generated during
	// journal loading.
	// 提前启动重组循环，以便在日志加载期间处理请求。
	pool.wg.Add(1)
	go pool.scheduleReorgLoop()

	// If local transactions and journaling is enabled, load from disk
	// 如果启用了本地交易和日志记录，则从磁盘加载
	if pool.journal != nil {
		if err := pool.journal.load(pool.addLocals); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
			// 如果加载交易日志失败，记录警告
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
			// 如果旋转交易日志失败，记录警告
		}
	}
	pool.wg.Add(1)
	go pool.loop() // 启动主事件循环
	return nil
	// 逻辑注解：此函数初始化交易池，设置 gas tip、当前状态和头部，启动重组循环和主循环。如果启用了日志，则加载并旋转本地交易。关键逻辑是确保池在链状态可用后正常运行。
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
// loop 是交易池的主事件循环，等待并响应外部区块链事件以及各种报告和交易驱逐事件。
func (pool *LegacyPool) loop() {
	defer pool.wg.Done()

	var (
		prevPending, prevQueued, prevStales int // 前一次的待处理、队列和过期交易数量

		// Start the stats reporting and transaction eviction tickers
		// 启动统计报告和交易驱逐定时器
		report  = time.NewTicker(statsReportInterval)   // 统计报告定时器
		evict   = time.NewTicker(evictionInterval)      // 驱逐定时器
		journal = time.NewTicker(pool.config.Rejournal) // 日志旋转定时器
	)
	defer report.Stop()
	defer evict.Stop()
	defer journal.Stop()

	// Notify tests that the init phase is done
	// 通知测试初始化阶段已完成
	close(pool.initDoneCh)
	for {
		select {
		// Handle pool shutdown
		// 处理池关闭
		case <-pool.reorgShutdownCh:
			return // 收到关闭信号，退出循环

		// Handle stats reporting ticks
		// 处理统计报告定时器触发
		case <-report.C:
			pool.mu.RLock()
			pending, queued := pool.stats() // 获取当前待处理和队列交易数量
			pool.mu.RUnlock()
			stales := int(pool.priced.stales.Load()) // 获取过期交易数量

			if pending != prevPending || queued != prevQueued || stales != prevStales {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued, "stales", stales)
				// 如果数量有变化，记录调试日志
				prevPending, prevQueued, prevStales = pending, queued, stales // 更新前一次数量
			}

		// Handle inactive account transaction eviction
		// 处理不活跃账户的交易驱逐
		case <-evict.C:
			pool.mu.Lock()
			for addr := range pool.queue {
				// Skip local transactions from the eviction mechanism
				// 跳过本地交易的驱逐机制
				if pool.locals.contains(addr) {
					continue
				}
				// Any non-locals old enough should be removed
				// 任何足够老的非本地交易都应被移除
				if time.Since(pool.beats[addr]) > pool.config.Lifetime {
					list := pool.queue[addr].Flatten()
					for _, tx := range list {
						pool.removeTx(tx.Hash(), true, true) // 移除交易
					}
					queuedEvictionMeter.Mark(int64(len(list))) // 记录驱逐数量
				}
			}
			pool.mu.Unlock()

		// Handle local transaction journal rotation
		// 处理本地交易日志旋转
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local tx journal", "err", err)
					// 如果旋转失败，记录警告
				}
				pool.mu.Unlock()
			}
		}
	}
	// 逻辑注解：此函数是交易池的主循环，处理关闭、统计报告、交易驱逐和日志旋转。关键逻辑包括定期检查队列中交易的存活时间并驱逐超时的非本地交易，以及定期更新本地交易日志。
}

// Close terminates the transaction pool.
// Close 终止交易池。
func (pool *LegacyPool) Close() error {
	// Terminate the pool reorger and return
	// 终止池重组器并返回
	close(pool.reorgShutdownCh)
	pool.wg.Wait() // 等待所有 goroutine 完成

	if pool.journal != nil {
		pool.journal.close() // 关闭交易日志
	}
	log.Info("Transaction pool stopped")
	return nil
	// 逻辑注解：此函数关闭交易池，停止重组循环并等待所有任务完成。如果有日志，则关闭日志文件。关键逻辑是确保池安全关闭。
}

// Reset implements txpool.SubPool, allowing the legacy pool's internal state to be
// kept in sync with the main transaction pool's internal state.
// Reset 实现 txpool.SubPool 接口，允许遗留池的内部状态与主交易池的内部状态保持同步。
func (pool *LegacyPool) Reset(oldHead, newHead *types.Header) {
	wait := pool.requestReset(oldHead, newHead) // 请求重置
	<-wait                                      // 等待重置完成
	// 逻辑注解：此函数通过通道请求重置池状态，传入旧头部和新头部，等待重组完成。关键逻辑是确保池状态与区块链头部同步。
}

// SubscribeTransactions registers a subscription for new transaction events,
// supporting feeding only newly seen or also resurrected transactions.
// SubscribeTransactions 注册新交易事件的订阅，支持仅提供新看到的交易或包括复活的交易。
func (pool *LegacyPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	// The legacy pool has a very messed up internal shuffling, so it's kind of
	// hard to separate newly discovered transaction from resurrected ones. This
	// is because the new txs are added to the queue, resurrected ones too and
	// reorgs run lazily, so separating the two would need a marker.
	// 遗留池的内部洗牌非常混乱，因此很难将新发现的交易与复活的交易分开。这是因为新交易被添加到队列中，复活的交易也是如此，而重组是懒惰运行的，因此分开两者需要一个标记。
	return pool.txFeed.Subscribe(ch) // 返回订阅对象
	// 逻辑注解：此函数通过事件订阅机制提供新交易通知。由于遗留池的复杂性，无法区分新交易和复活交易，直接使用 txFeed 订阅。
}

// SetGasTip updates the minimum gas tip required by the transaction pool for a
// new transaction, and drops all transactions below this threshold.
// SetGasTip 更新交易池对新交易所需的最低 gas tip，并丢弃低于此阈值的所有交易。
func (pool *LegacyPool) SetGasTip(tip *big.Int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	var (
		newTip = uint256.MustFromBig(tip) // 将 big.Int 转换为 uint256.Int
		old    = pool.gasTip.Load()       // 获取当前 gas tip
	)
	pool.gasTip.Store(newTip) // 更新 gas tip
	// If the min miner fee increased, remove transactions below the new threshold
	// 如果最低矿工费用增加，移除低于新阈值的交易
	if newTip.Cmp(old) > 0 {
		// pool.priced is sorted by GasFeeCap, so we have to iterate through pool.all instead
		// pool.priced 按 GasFeeCap 排序，因此我们必须遍历 pool.all
		drop := pool.all.RemotesBelowTip(tip) // 获取低于新 tip 的远程交易
		for _, tx := range drop {
			pool.removeTx(tx.Hash(), false, true) // 移除交易
		}
		pool.priced.Removed(len(drop)) // 更新价格列表
	}
	log.Info("Legacy pool tip threshold updated", "tip", newTip)
	// 逻辑注解：此函数更新最低 gas tip，并移除低于新阈值的交易。关键逻辑是确保池中的交易满足新的 gas 价格要求。
}

// Nonce returns the next nonce of an account, with all transactions executable
// by the pool already applied on top.
// Nonce 返回账户的下一个 nonce，池中所有可执行交易已应用其上。
func (pool *LegacyPool) Nonce(addr common.Address) uint64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.pendingNonces.get(addr) // 获取账户的下一个 nonce
	// 逻辑注解：此函数返回账户的下一个 nonce，基于待处理交易的状态。关键逻辑是提供准确的 nonce 值以避免冲突。
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
// Stats 获取当前池统计数据，即待处理和队列（非可执行）交易的数量。
func (pool *LegacyPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.stats() // 调用内部 stats 方法
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
// stats 获取当前池统计数据，即待处理和队列（非可执行）交易的数量。
func (pool *LegacyPool) stats() (int, int) {
	pending := 0
	for _, list := range pool.pending {
		pending += list.Len() // 统计待处理交易总数
	}
	queued := 0
	for _, list := range pool.queue {
		queued += list.Len() // 统计队列交易总数
	}
	return pending, queued
	// 逻辑注解：此函数计算待处理和队列中的交易数量。关键逻辑是提供池的当前状态统计。
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
// Content 获取交易池的数据内容，返回所有待处理和队列交易，按账户分组并按 nonce 排序。
func (pool *LegacyPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address][]*types.Transaction, len(pool.pending))
	for addr, list := range pool.pending {
		pending[addr] = list.Flatten() // 将待处理交易展平
	}
	queued := make(map[common.Address][]*types.Transaction, len(pool.queue))
	for addr, list := range pool.queue {
		queued[addr] = list.Flatten() // 将队列交易展平
	}
	return pending, queued
	// 逻辑注解：此函数返回池中所有交易的内容，按账户分组并展平列表。关键逻辑是提供完整的交易视图。
}

// ContentFrom retrieves the data content of the transaction pool, returning the
// pending as well as queued transactions of this address, grouped by nonce.
// ContentFrom 获取交易池的数据内容，返回指定地址的待处理和队列交易，按 nonce 分组。
func (pool *LegacyPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	var pending []*types.Transaction
	if list, ok := pool.pending[addr]; ok {
		pending = list.Flatten() // 展平待处理交易
	}
	var queued []*types.Transaction
	if list, ok := pool.queue[addr]; ok {
		queued = list.Flatten() // 展平队列交易
	}
	return pending, queued
	// 逻辑注解：此函数返回指定地址的交易内容。关键逻辑是提供特定账户的交易视图。
}

// Pending retrieves all currently processable transactions, grouped by origin
// account and sorted by nonce.
//
// The transactions can also be pre-filtered by the dynamic fee components to
// reduce allocations and load on downstream subsystems.
// Pending 获取所有当前可处理交易，按原始账户分组并按 nonce 排序。
// 交易还可以根据动态费用组件进行预过滤，以减少分配和下游子系统的负载。
func (pool *LegacyPool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	// If only blob transactions are requested, this pool is unsuitable as it
	// contains none, don't even bother.
	// 如果只请求 blob 交易，此池不适用，因为它不包含任何 blob 交易，直接返回 nil。
	if filter.OnlyBlobTxs {
		return nil
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// Convert the new uint256.Int types to the old big.Int ones used by the legacy pool
	// 将新的 uint256.Int 类型转换为遗留池使用的旧 big.Int 类型
	var (
		minTipBig  *big.Int
		baseFeeBig *big.Int
	)
	if filter.MinTip != nil {
		minTipBig = filter.MinTip.ToBig() // 转换最低 tip
	}
	if filter.BaseFee != nil {
		baseFeeBig = filter.BaseFee.ToBig() // 转换基础费用
	}
	pending := make(map[common.Address][]*txpool.LazyTransaction, len(pool.pending))
	for addr, list := range pool.pending {
		txs := list.Flatten() // 展平交易列表

		// If the miner requests tip enforcement, cap the lists now
		// 如果矿工请求强制执行 tip，现在限制列表
		if minTipBig != nil && !pool.locals.contains(addr) {
			for i, tx := range txs {
				if tx.EffectiveGasTipIntCmp(minTipBig, baseFeeBig) < 0 {
					txs = txs[:i] // 截断低于最低 tip 的交易
					break
				}
			}
		}
		if len(txs) > 0 {
			lazies := make([]*txpool.LazyTransaction, len(txs))
			for i := 0; i < len(txs); i++ {
				lazies[i] = &txpool.LazyTransaction{
					Pool:      pool,
					Hash:      txs[i].Hash(),
					Tx:        txs[i],
					Time:      txs[i].Time(),
					GasFeeCap: uint256.MustFromBig(txs[i].GasFeeCap()),
					GasTipCap: uint256.MustFromBig(txs[i].GasTipCap()),
					Gas:       txs[i].Gas(),
					BlobGas:   txs[i].BlobGas(),
				} // 转换为 LazyTransaction 对象
			}
			pending[addr] = lazies
		}
	}
	return pending
	// 逻辑注解：此函数返回待处理交易，支持根据 tip 和基础费用过滤。关键逻辑是提供可执行交易的懒加载视图，并根据过滤条件裁剪列表。
}

// Locals retrieves the accounts currently considered local by the pool.
// Locals 获取池当前视为本地的账户。
func (pool *LegacyPool) Locals() []common.Address {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.locals.flatten() // 返回展平的本地账户列表
	// 逻辑注解：此函数返回本地账户列表。关键逻辑是提供当前标记为本地的账户。
}

// local retrieves all currently known local transactions, grouped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
// local 获取所有当前已知的本地交易，按原始账户分组并按 nonce 排序。返回的交易集是副本，调用代码可自由修改。
func (pool *LegacyPool) local() map[common.Address]types.Transactions {
	txs := make(map[common.Address]types.Transactions)
	for addr := range pool.locals.accounts {
		if pending := pool.pending[addr]; pending != nil {
			txs[addr] = append(txs[addr], pending.Flatten()...) // 添加待处理交易
		}
		if queued := pool.queue[addr]; queued != nil {
			txs[addr] = append(txs[addr], queued.Flatten()...) // 添加队列交易
		}
	}
	return txs
	// 逻辑注解：此函数返回所有本地交易，按账户分组。关键逻辑是提供本地交易的完整副本。
}

// validateTxBasics checks whether a transaction is valid according to the consensus
// rules, but does not check state-dependent validation such as sufficient balance.
// This check is meant as an early check which only needs to be performed once,
// and does not require the pool mutex to be held.
// validateTxBasics 根据共识规则检查交易是否有效，但不检查状态相关的验证，如余额是否充足。
// 此检查旨在作为早期检查，仅需执行一次，且不需要持有池互斥锁。
func (pool *LegacyPool) validateTxBasics(tx *types.Transaction, local bool) error {
	opts := &txpool.ValidationOptions{
		Config: pool.chainconfig,
		Accept: 0 |
			1<<types.LegacyTxType |
			1<<types.AccessListTxType |
			1<<types.DynamicFeeTxType, // 设置接受的交易类型
		MaxSize: txMaxSize,                  // 设置最大交易大小
		MinTip:  pool.gasTip.Load().ToBig(), // 设置最低 tip
	}
	if local {
		opts.MinTip = new(big.Int) // 本地交易不强制最低 tip
	}
	if err := txpool.ValidateTransaction(tx, pool.currentHead.Load(), pool.signer, opts); err != nil {
		return err // 如果验证失败，返回错误
	}
	return nil
	// 逻辑注解：此函数执行交易的基本验证（如类型、大小、tip），不涉及状态检查。关键逻辑是快速筛选无效交易。
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
// validateTx 根据共识规则检查交易是否有效，并遵守本地节点的一些启发式限制（价格和大小）。
func (pool *LegacyPool) validateTx(tx *types.Transaction) error {
	opts := &txpool.ValidationOptionsWithState{
		State: pool.currentState, // 设置当前状态

		FirstNonceGap: nil, // Pool allows arbitrary arrival order, don't invalidate nonce gaps
		// FirstNonceGap 为 nil，池允许任意到达顺序，不验证 nonce 间隙
		UsedAndLeftSlots: func(addr common.Address) (int, int) {
			var have int
			if list := pool.pending[addr]; list != nil {
				have += list.Len() // 计算待处理交易数量
			}
			if list := pool.queue[addr]; list != nil {
				have += list.Len() // 计算队列交易数量
			}
			return have, math.MaxInt // 返回已用槽数和剩余槽数（无限制）
		},
		ExistingExpenditure: func(addr common.Address) *big.Int {
			if list := pool.pending[addr]; list != nil {
				return list.totalcost.ToBig() // 返回待处理交易的总成本
			}
			return new(big.Int) // 如果没有待处理交易，返回 0
		},
		ExistingCost: func(addr common.Address, nonce uint64) *big.Int {
			if list := pool.pending[addr]; list != nil {
				if tx := list.txs.Get(nonce); tx != nil {
					return tx.Cost() // 返回指定 nonce 交易的成本
				}
			}
			return nil // 如果没有对应交易，返回 nil
		},
	}
	if err := txpool.ValidateTransactionWithState(tx, pool.signer, opts); err != nil {
		return err // 如果验证失败，返回错误
	}
	return nil
	// 逻辑注解：此函数执行完整的交易验证，包括状态检查（如余额、nonce）。关键逻辑是确保交易符合共识规则和本地限制。
}

// add validates a transaction and inserts it into the non-executable queue for later
// pending promotion and execution. If the transaction is a replacement for an already
// pending or queued one, it overwrites the previous transaction if its price is higher.
//
// If a newly added transaction is marked as local, its sending account will be
// added to the allowlist, preventing any associated transaction from being dropped
// out of the pool due to pricing constraints.
// add 验证交易并将其插入非可执行队列，以便稍后提升为待处理和执行。如果交易是替换已有的待处理或队列交易，且价格更高，则覆盖之前的交易。
// 如果新添加的交易标记为本地，其发送账户将被添加到白名单，防止因价格限制而被丢弃。
func (pool *LegacyPool) add(tx *types.Transaction, local bool) (replaced bool, err error) {
	// If the transaction is already known, discard it
	// 如果交易已知，则丢弃
	hash := tx.Hash()
	if pool.all.Get(hash) != nil {
		log.Trace("Discarding already known transaction", "hash", hash)
		knownTxMeter.Mark(1)
		return false, txpool.ErrAlreadyKnown
	}
	// Make the local flag. If it's from local source or it's from the network but
	// the sender is marked as local previously, treat it as the local transaction.
	// 设置本地标志。如果交易来自本地源或网络但发送者之前标记为本地，则视为本地交易。
	isLocal := local || pool.locals.containsTx(tx)

	// If the transaction fails basic validation, discard it
	// 如果交易未通过基本验证，则丢弃
	if err := pool.validateTx(tx); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err)
		invalidTxMeter.Mark(1)
		return false, err
	}
	// already validated by this point
	// 到此点交易已通过验证
	from, _ := types.Sender(pool.signer, tx) // 获取交易发送者

	// If the address is not yet known, request exclusivity to track the account
	// only by this subpool until all transactions are evicted
	// 如果地址未知，请求独占性以仅由此子池跟踪账户，直到所有交易被驱逐
	var (
		_, hasPending = pool.pending[from]
		_, hasQueued  = pool.queue[from]
	)
	if !hasPending && !hasQueued {
		if err := pool.reserve(from, true); err != nil {
			return false, err // 如果预留失败，返回错误
		}
		defer func() {
			// If the transaction is rejected by some post-validation check, remove
			// the lock on the reservation set.
			// 如果交易因某些后续验证检查被拒绝，移除预留集上的锁。
			//
			// Note, `err` here is the named error return, which will be initialized
			// by a return statement before running deferred methods. Take care with
			// removing or subscoping err as it will break this clause.
			// 注意，这里的 `err` 是命名错误返回值，将在运行延迟方法前由 return 语句初始化。小心移除或缩小 err 的作用域，否则会破坏此条款。
			if err != nil {
				pool.reserve(from, false) // 释放预留
			}
		}()
	}
	// If the transaction pool is full, discard underpriced transactions
	// 如果交易池已满，丢弃价格过低的交易
	if uint64(pool.all.Slots()+numSlots(tx)) > pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new transaction is underpriced, don't accept it
		// 如果新交易价格过低，不接受
		if !isLocal && pool.priced.Underpriced(tx) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "gasTipCap", tx.GasTipCap(), "gasFeeCap", tx.GasFeeCap())
			underpricedTxMeter.Mark(1)
			return false, txpool.ErrUnderpriced
		}

		// We're about to replace a transaction. The reorg does a more thorough
		// analysis of what to remove and how, but it runs async. We don't want to
		// do too many replacements between reorg-runs, so we cap the number of
		// replacements to 25% of the slots
		// 我们将要替换交易。重组会更彻底地分析要移除什么以及如何移除，但它是异步运行的。我们不希望在重组运行之间进行太多替换，因此将替换数量限制为槽数的 25%。
		if pool.changesSinceReorg > int(pool.config.GlobalSlots/4) {
			throttleTxMeter.Mark(1)
			return false, ErrTxPoolOverflow // 如果替换次数过多，返回溢出错误
		}

		// New transaction is better than our worse ones, make room for it.
		// If it's a local transaction, forcibly discard all available transactions.
		// Otherwise if we can't make enough room for new one, abort the operation.
		// 新交易比我们最差的交易更好，为其腾出空间。
		// 如果是本地交易，强制丢弃所有可用交易。
		// 否则，如果无法为新交易腾出足够空间，则中止操作。
		drop, success := pool.priced.Discard(pool.all.Slots()-int(pool.config.GlobalSlots+pool.config.GlobalQueue)+numSlots(tx), isLocal)

		// Special case, we still can't make the room for the new remote one.
		// 特殊情况，我们仍然无法为新的远程交易腾出空间。
		if !isLocal && !success {
			log.Trace("Discarding overflown transaction", "hash", hash)
			overflowedTxMeter.Mark(1)
			return false, ErrTxPoolOverflow
		}

		// If the new transaction is a future transaction it should never churn pending transactions
		// 如果新交易是未来交易，它不应该扰动待处理交易
		if !isLocal && pool.isGapped(from, tx) {
			var replacesPending bool
			for _, dropTx := range drop {
				dropSender, _ := types.Sender(pool.signer, dropTx)
				if list := pool.pending[dropSender]; list != nil && list.Contains(dropTx.Nonce()) {
					replacesPending = true // 如果丢弃的交易在待处理列表中，标记为 true
					break
				}
			}
			// Add all transactions back to the priced queue
			// 将所有交易添加回价格队列
			if replacesPending {
				for _, dropTx := range drop {
					pool.priced.Put(dropTx, false)
				}
				log.Trace("Discarding future transaction replacing pending tx", "hash", hash)
				return false, txpool.ErrFutureReplacePending // 如果替换了待处理交易，返回错误
			}
		}

		// Kick out the underpriced remote transactions.
		// 踢出价格过低的远程交易。
		for _, tx := range drop {
			log.Trace("Discarding freshly underpriced transaction", "hash", tx.Hash(), "gasTipCap", tx.GasTipCap(), "gasFeeCap", tx.GasFeeCap())
			underpricedTxMeter.Mark(1)

			sender, _ := types.Sender(pool.signer, tx)
			dropped := pool.removeTx(tx.Hash(), false, sender != from) // 如果不是新交易的发送者，不释放预留
			pool.changesSinceReorg += dropped                          // 更新重组间变化计数
		}
	}

	// Try to replace an existing transaction in the pending pool
	// 尝试替换待处理池中的现有交易
	if list := pool.pending[from]; list != nil && list.Contains(tx.Nonce()) {
		// Nonce already pending, check if required price bump is met
		// nonce 已待处理，检查是否满足所需的价格提升
		inserted, old := list.Add(tx, pool.config.PriceBump)
		if !inserted {
			pendingDiscardMeter.Mark(1)
			return false, txpool.ErrReplaceUnderpriced // 如果价格不足，返回错误
		}
		// New transaction is better, replace old one
		// 新交易更好，替换旧交易
		if old != nil {
			pool.all.Remove(old.Hash()) // 移除旧交易
			pool.priced.Removed(1)      // 更新价格列表
			pendingReplaceMeter.Mark(1) // 记录替换
		}
		pool.all.Add(tx, isLocal)    // 添加新交易
		pool.priced.Put(tx, isLocal) // 更新价格列表
		pool.journalTx(from, tx)     // 记录到日志
		pool.queueTxEvent(tx)        // 触发交易事件
		log.Trace("Pooled new executable transaction", "hash", hash, "from", from, "to", tx.To())

		// Successful promotion, bump the heartbeat
		// 成功提升，更新心跳
		pool.beats[from] = time.Now()
		return old != nil, nil // 返回是否替换了旧交易
	}
	// New transaction isn't replacing a pending one, push into queue
	// 新交易未替换待处理交易，推入队列
	replaced, err = pool.enqueueTx(hash, tx, isLocal, true)
	if err != nil {
		return false, err // 如果入队失败，返回错误
	}
	// Mark local addresses and journal local transactions
	// 标记本地地址并记录本地交易日志
	if local && !pool.locals.contains(from) {
		log.Info("Setting new local account", "address", from)
		pool.locals.add(from)                                     // 添加到本地账户
		pool.priced.Removed(pool.all.RemoteToLocals(pool.locals)) // Migrate the remotes if it's marked as local first time. 将远程交易迁移为本地
	}
	if isLocal {
		localGauge.Inc(1) // 增加本地交易计数
	}
	pool.journalTx(from, tx) // 记录交易到日志

	log.Trace("Pooled new future transaction", "hash", hash, "from", from, "to", tx.To())
	return replaced, nil
	// 逻辑注解：此函数验证并添加交易到池中。如果池满，丢弃低价交易；如果有相同 nonce，尝试替换；否则入队。关键逻辑包括交易验证、池容量管理、本地交易处理。
}

// isGapped reports whether the given transaction is immediately executable.
// isGapped 报告给定交易是否立即可执行。
func (pool *LegacyPool) isGapped(from common.Address, tx *types.Transaction) bool {
	// Short circuit if transaction falls within the scope of the pending list
	// or matches the next pending nonce which can be promoted as an executable
	// transaction afterwards. Note, the tx staleness is already checked in
	// 'validateTx' function previously.
	// 如果交易在待处理列表范围内或匹配下一个待处理 nonce，则短路返回 false。
	// 注意，交易的过期性已在之前的 'validateTx' 函数中检查。
	next := pool.pendingNonces.get(from) // 获取账户的下一个待处理 nonce
	if tx.Nonce() <= next {
		return false // 如果交易的 nonce 小于等于下一个待处理 nonce，则立即可执行，返回 false
	}
	// The transaction has a nonce gap with pending list, it's only considered
	// as executable if transactions in queue can fill up the nonce gap.
	// 交易与待处理列表有 nonce 间隙，仅当队列中的交易能填补 nonce 间隙时才视为可执行。
	queue, ok := pool.queue[from] // 获取该账户的队列交易列表
	if !ok {
		return true // 如果队列中没有该账户的交易，存在间隙，返回 true
	}
	for nonce := next; nonce < tx.Nonce(); nonce++ {
		if !queue.Contains(nonce) {
			return true // txs in queue can't fill up the nonce gap
			// 如果队列中缺少某个 nonce，说明无法填补间隙，返回 true
		}
	}
	return false // 如果队列填补了所有间隙，则可执行，返回 false
	// 逻辑注解：此函数检查交易是否因 nonce 间隙而不可立即执行。关键逻辑是判断队列中的交易是否能连续填补从 next 到 tx.Nonce() 的所有 nonce。
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
// enqueueTx 将新交易插入非可执行交易队列。
// 注意，此方法假设已持有池锁！
func (pool *LegacyPool) enqueueTx(hash common.Hash, tx *types.Transaction, local bool, addAll bool) (bool, error) {
	// Try to insert the transaction into the future queue
	// 尝试将交易插入未来队列
	from, _ := types.Sender(pool.signer, tx) // already validated // 获取交易发送者，已验证
	if pool.queue[from] == nil {
		pool.queue[from] = newList(false) // 如果该账户的队列不存在，创建新列表（非待处理）
	}
	inserted, old := pool.queue[from].Add(tx, pool.config.PriceBump) // 尝试添加交易
	if !inserted {
		// An older transaction was better, discard this
		// 如果旧交易更好，丢弃此交易
		queuedDiscardMeter.Mark(1)                 // 记录丢弃的队列交易
		return false, txpool.ErrReplaceUnderpriced // 返回替换价格不足错误
	}
	// Discard any previous transaction and mark this
	// 丢弃任何之前的交易并标记此交易
	if old != nil {
		pool.all.Remove(old.Hash()) // 从全局查找表中移除旧交易
		pool.priced.Removed(1)      // 从价格列表中移除一个交易
		queuedReplaceMeter.Mark(1)  // 记录替换的队列交易
	} else {
		// Nothing was replaced, bump the queued counter
		// 没有替换，增加队列计数器
		queuedGauge.Inc(1) // 增加队列交易总数
	}
	// If the transaction isn't in lookup set but it's expected to be there,
	// show the error log.
	// 如果交易不在查找集中但预期应该在其中，显示错误日志。
	if pool.all.Get(hash) == nil && !addAll {
		log.Error("Missing transaction in lookup set, please report the issue", "hash", hash)
	}
	if addAll {
		pool.all.Add(tx, local)    // 将交易添加到全局查找表
		pool.priced.Put(tx, local) // 将交易添加到价格列表
	}
	// If we never record the heartbeat, do it right now.
	// 如果从未记录心跳，现在记录。
	if _, exist := pool.beats[from]; !exist {
		pool.beats[from] = time.Now() // 设置账户的首次心跳时间
	}
	return old != nil, nil // 返回是否替换了旧交易
	// 逻辑注解：此函数将交易插入队列，若有相同 nonce 的旧交易，则根据价格提升规则替换。关键逻辑包括队列管理、交易替换和心跳更新。
}

// journalTx adds the specified transaction to the local disk journal if it is
// deemed to have been sent from a local account.
// journalTx 如果交易被认为来自本地账户，则将其添加到本地磁盘日志。
func (pool *LegacyPool) journalTx(from common.Address, tx *types.Transaction) {
	// Only journal if it's enabled and the transaction is local
	// 仅在启用日志且交易为本地时记录
	if pool.journal == nil || !pool.locals.contains(from) {
		return // 如果日志未启用或账户不是本地，直接返回
	}
	if err := pool.journal.insert(tx); err != nil {
		log.Warn("Failed to journal local transaction", "err", err)
		// 如果插入日志失败，记录警告
	}
	// 逻辑注解：此函数将本地交易记录到磁盘日志，确保节点重启后可恢复。关键逻辑是检查本地性并处理日志写入。
}

// promoteTx adds a transaction to the pending (processable) list of transactions
// and returns whether it was inserted or an older was better.
//
// Note, this method assumes the pool lock is held!
// promoteTx 将交易添加到待处理（可处理）交易列表，并返回是否插入成功或旧交易更好。
// 注意，此方法假设已持有池锁！
func (pool *LegacyPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool {
	// Try to insert the transaction into the pending queue
	// 尝试将交易插入待处理队列
	if pool.pending[addr] == nil {
		pool.pending[addr] = newList(true) // 如果该账户的待处理列表不存在，创建新列表（待处理）
	}
	list := pool.pending[addr]

	inserted, old := list.Add(tx, pool.config.PriceBump) // 尝试添加交易
	if !inserted {
		// An older transaction was better, discard this
		// 如果旧交易更好，丢弃此交易
		pool.all.Remove(hash)       // 从全局查找表中移除
		pool.priced.Removed(1)      // 从价格列表中移除
		pendingDiscardMeter.Mark(1) // 记录丢弃的待处理交易
		return false
	}
	// Otherwise discard any previous transaction and mark this
	// 否则丢弃任何之前的交易并标记此交易
	if old != nil {
		pool.all.Remove(old.Hash()) // 从全局查找表中移除旧交易
		pool.priced.Removed(1)      // 从价格列表中移除一个交易
		pendingReplaceMeter.Mark(1) // 记录替换的待处理交易
	} else {
		// Nothing was replaced, bump the pending counter
		// 没有替换，增加待处理计数器
		pendingGauge.Inc(1) // 增加待处理交易总数
	}
	// Set the potentially new pending nonce and notify any subsystems of the new tx
	// 设置可能的新的待处理 nonce 并通知子系统新交易
	pool.pendingNonces.set(addr, tx.Nonce()+1) // 更新账户的待处理 nonce

	// Successful promotion, bump the heartbeat
	// 成功提升，更新心跳
	pool.beats[addr] = time.Now()
	return true
	// 逻辑注解：此函数将交易提升到待处理列表，若有相同 nonce 的旧交易，则根据价格提升规则替换。关键逻辑包括待处理列表管理、nonce 更新和心跳刷新。
}

// addLocals enqueues a batch of transactions into the pool if they are valid, marking the
// senders as local ones, ensuring they go around the local pricing constraints.
//
// This method is used to add transactions from the RPC API and performs synchronous pool
// reorganization and event propagation.
// addLocals 将一批交易入队到池中如果它们有效，将发送者标记为本地，确保绕过本地价格限制。
// 此方法用于从 RPC API 添加交易，并执行同步池重组和事件传播。
func (pool *LegacyPool) addLocals(txs []*types.Transaction) []error {
	return pool.Add(txs, !pool.config.NoLocals, true) // 调用 Add 方法，标记为本地并同步
	// 逻辑注解：此函数是 addLocal 的批量版本，处理本地交易并同步重组。关键逻辑是调用通用 Add 方法并设置本地标志。
}

// addLocal enqueues a single local transaction into the pool if it is valid. This is
// a convenience wrapper around addLocals.
// addLocal 将单个本地交易入队到池中如果它有效。这是 addLocals 的便捷包装。
func (pool *LegacyPool) addLocal(tx *types.Transaction) error {
	return pool.addLocals([]*types.Transaction{tx})[0] // 调用 addLocals 并返回第一个错误
	// 逻辑注解：此函数是 addLocals 的单交易版本，简化本地交易添加。关键逻辑是复用批量方法。
}

// addRemotes enqueues a batch of transactions into the pool if they are valid. If the
// senders are not among the locally tracked ones, full pricing constraints will apply.
//
// This method is used to add transactions from the p2p network and does not wait for pool
// reorganization and internal event propagation.
// addRemotes 将一批交易入队到池中如果它们有效。如果发送者不在本地跟踪列表中，将应用完整的价格限制。
// 此方法用于从 P2P 网络添加交易，不等待池重组和内部事件传播。
func (pool *LegacyPool) addRemotes(txs []*types.Transaction) []error {
	return pool.Add(txs, false, false) // 调用 Add 方法，非本地且不同步
	// 逻辑注解：此函数处理远程交易，不同步重组。关键逻辑是调用通用 Add 方法并设置远程标志。
}

// addRemote enqueues a single transaction into the pool if it is valid. This is a convenience
// wrapper around addRemotes.
// addRemote 将单个交易入队到池中如果它有效。这是 addRemotes 的便捷包装。
func (pool *LegacyPool) addRemote(tx *types.Transaction) error {
	return pool.addRemotes([]*types.Transaction{tx})[0] // 调用 addRemotes 并返回第一个错误
	// 逻辑注解：此函数是 addRemotes 的单交易版本，简化远程交易添加。关键逻辑是复用批量方法。
}

// addRemotesSync is like addRemotes, but waits for pool reorganization. Tests use this method.
// addRemotesSync 类似于 addRemotes，但等待池重组。测试使用此方法。
func (pool *LegacyPool) addRemotesSync(txs []*types.Transaction) []error {
	return pool.Add(txs, false, true) // 调用 Add 方法，非本地且同步
	// 逻辑注解：此函数是 addRemotes 的同步版本，用于测试。关键逻辑是设置同步标志。
}

// This is like addRemotes with a single transaction, but waits for pool reorganization. Tests use this method.
// 类似于 addRemotes 的单交易版本，但等待池重组。测试使用此方法。
func (pool *LegacyPool) addRemoteSync(tx *types.Transaction) error {
	return pool.Add([]*types.Transaction{tx}, false, true)[0] // 调用 Add 方法，非本地且同步，返回第一个错误
	// 逻辑注解：此函数是 addRemotesSync 的单交易版本，用于测试。关键逻辑是复用批量方法。
}

// Add enqueues a batch of transactions into the pool if they are valid. Depending
// on the local flag, full pricing constraints will or will not be applied.
//
// If sync is set, the method will block until all internal maintenance related
// to the add is finished. Only use this during tests for determinism!
// Add 将一批交易入队到池中如果它们有效。根据本地标志，将或不将应用完整的价格限制。
// 如果设置了 sync，此方法将阻塞直到与添加相关的所有内部维护完成。仅在测试中使用以确保确定性！
func (pool *LegacyPool) Add(txs []*types.Transaction, local, sync bool) []error {
	// Do not treat as local if local transactions have been disabled
	// 如果本地交易被禁用，不视为本地
	local = local && !pool.config.NoLocals

	// Filter out known ones without obtaining the pool lock or recovering signatures
	// 在不获取池锁或恢复签名的情况下过滤已知交易
	var (
		errs = make([]error, len(txs))                 // 错误数组
		news = make([]*types.Transaction, 0, len(txs)) // 新交易数组
	)
	for i, tx := range txs {
		// If the transaction is known, pre-set the error slot
		// 如果交易已知，预设错误槽
		if pool.all.Get(tx.Hash()) != nil {
			errs[i] = txpool.ErrAlreadyKnown // 设置已知错误
			knownTxMeter.Mark(1)             // 记录已知交易
			continue
		}
		// Exclude transactions with basic errors, e.g invalid signatures and
		// insufficient intrinsic gas as soon as possible and cache senders
		// in transactions before obtaining lock
		// 尽早排除基本错误的交易，例如无效签名和不足的内在 gas，并在获取锁前缓存发送者
		if err := pool.validateTxBasics(tx, local); err != nil {
			errs[i] = err // 设置错误
			log.Trace("Discarding invalid transaction", "hash", tx.Hash(), "err", err)
			invalidTxMeter.Mark(1) // 记录无效交易
			continue
		}
		// Accumulate all unknown transactions for deeper processing
		// 累积所有未知交易以进行深入处理
		news = append(news, tx)
	}
	if len(news) == 0 {
		return errs // 如果没有新交易，直接返回错误数组
	}

	// Process all the new transaction and merge any errors into the original slice
	// 处理所有新交易并将任何错误合并到原始切片中
	pool.mu.Lock()
	newErrs, dirtyAddrs := pool.addTxsLocked(news, local) // 添加新交易
	pool.mu.Unlock()

	var nilSlot = 0
	for _, err := range newErrs {
		for errs[nilSlot] != nil {
			nilSlot++ // 找到下一个空槽
		}
		errs[nilSlot] = err // 填充错误
		nilSlot++
	}
	// Reorg the pool internals if needed and return
	// 如果需要，重组池内部并返回
	done := pool.requestPromoteExecutables(dirtyAddrs) // 请求提升可执行交易
	if sync {
		<-done // 如果同步，等待重组完成
	}
	return errs
	// 逻辑注解：此函数是交易添加的核心入口，过滤已知和无效交易，添加新交易并根据 sync 参数决定是否等待重组。关键逻辑包括初步验证、批量添加和重组触发。
}

// addTxsLocked attempts to queue a batch of transactions if they are valid.
// The transaction pool lock must be held.
// addTxsLocked 尝试将一批有效交易入队。
// 必须持有交易池锁。
func (pool *LegacyPool) addTxsLocked(txs []*types.Transaction, local bool) ([]error, *accountSet) {
	dirty := newAccountSet(pool.signer) // 创建脏账户集合
	errs := make([]error, len(txs))     // 错误数组
	for i, tx := range txs {
		replaced, err := pool.add(tx, local) // 添加单个交易
		errs[i] = err
		if err == nil && !replaced {
			dirty.addTx(tx) // 如果成功添加且未替换，标记账户为脏
		}
	}
	validTxMeter.Mark(int64(len(dirty.accounts))) // 记录有效交易的账户数
	return errs, dirty
	// 逻辑注解：此函数在锁保护下批量添加交易，跟踪成功添加的账户。关键逻辑是调用 add 方法并收集脏账户用于后续提升。
}

// Status returns the status (unknown/pending/queued) of a batch of transactions
// identified by their hashes.
// Status 返回由哈希标识的一批交易的状态（未知/待处理/队列）。
func (pool *LegacyPool) Status(hash common.Hash) txpool.TxStatus {
	tx := pool.get(hash) // 获取交易
	if tx == nil {
		return txpool.TxStatusUnknown // 如果交易不存在，返回未知状态
	}
	from, _ := types.Sender(pool.signer, tx) // already validated // 获取发送者，已验证

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if txList := pool.pending[from]; txList != nil && txList.txs.items[tx.Nonce()] != nil {
		return txpool.TxStatusPending // 如果在待处理列表中，返回待处理状态
	} else if txList := pool.queue[from]; txList != nil && txList.txs.items[tx.Nonce()] != nil {
		return txpool.TxStatusQueued // 如果在队列中，返回队列状态
	}
	return txpool.TxStatusUnknown // 否则返回未知状态
	// 逻辑注解：此函数检查交易状态，优先检查待处理列表，再检查队列。关键逻辑是根据交易位置返回准确状态。
}

// Get returns a transaction if it is contained in the pool and nil otherwise.
// Get 返回池中包含的交易，如果不存在则返回 nil。
func (pool *LegacyPool) Get(hash common.Hash) *types.Transaction {
	tx := pool.get(hash) // 调用内部 get 方法
	if tx == nil {
		return nil // 如果不存在，返回 nil
	}
	return tx
	// 逻辑注解：此函数是 get 的公开包装，提供外部访问接口。关键逻辑是复用内部方法。
}

// get returns a transaction if it is contained in the pool and nil otherwise.
// get 返回池中包含的交易，如果不存在则返回 nil。
func (pool *LegacyPool) get(hash common.Hash) *types.Transaction {
	return pool.all.Get(hash) // 从全局查找表中获取交易
	// 逻辑注解：此函数直接查询全局查找表。关键逻辑是提供快速访问交易的方法。
}

// GetBlobs is not supported by the legacy transaction pool, it is just here to
// implement the txpool.SubPool interface.
// GetBlobs 不被遗留交易池支持，仅用于实现 txpool.SubPool 接口。
func (pool *LegacyPool) GetBlobs(vhashes []common.Hash) ([]*kzg4844.Blob, []*kzg4844.Proof) {
	return nil, nil // 返回 nil，因为遗留池不支持 blob 交易
	// 逻辑注解：此函数为接口占位符，遗留池不支持 blob 交易（EIP-4844）。关键逻辑是明确不支持此功能。
}

// Has returns an indicator whether txpool has a transaction cached with the
// given hash.
// Has 返回交易池是否缓存了具有给定哈希的交易的指示器。
func (pool *LegacyPool) Has(hash common.Hash) bool {
	return pool.all.Get(hash) != nil // 检查全局查找表中是否存在交易
	// 逻辑注解：此函数快速检查交易存在性。关键逻辑是利用查找表的高效性。
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
//
// In unreserve is false, the account will not be relinquished to the main txpool
// even if there are no more references to it. This is used to handle a race when
// a tx being added, and it evicts a previously scheduled tx from the same account,
// which could lead to a premature release of the lock.
//
// Returns the number of transactions removed from the pending queue.
// removeTx 从队列中移除单个交易，将所有后续交易移回未来队列。
// 如果 unreserve 为 false，即使没有更多引用，账户也不会释放给主交易池。这是为了处理添加交易时驱逐同一账户先前计划交易的竞争情况，防止过早释放锁。
// 返回从待处理队列中移除的交易数量。
func (pool *LegacyPool) removeTx(hash common.Hash, outofbound bool, unreserve bool) int {
	// Fetch the transaction we wish to delete
	// 获取要删除的交易
	tx := pool.all.Get(hash)
	if tx == nil {
		return 0 // 如果交易不存在，返回 0
	}
	addr, _ := types.Sender(pool.signer, tx) // already validated during insertion // 获取发送者，已验证

	// If after deletion there are no more transactions belonging to this account,
	// relinquish the address reservation. It's a bit convoluted do this, via a
	// defer, but it's safer vs. the many return pathways.
	// 如果删除后该账户没有更多交易，释放地址预留。通过 defer 执行此操作有些复杂，但对于多种返回路径更安全。
	if unreserve {
		defer func() {
			var (
				_, hasPending = pool.pending[addr]
				_, hasQueued  = pool.queue[addr]
			)
			if !hasPending && !hasQueued {
				pool.reserve(addr, false) // 如果没有待处理和队列交易，释放预留
			}
		}()
	}
	// Remove it from the list of known transactions
	// 从已知交易列表中移除
	pool.all.Remove(hash)
	if outofbound {
		pool.priced.Removed(1) // 如果超出范围，从价格列表中移除
	}
	if pool.locals.contains(addr) {
		localGauge.Dec(1) // 如果是本地账户，减少本地交易计数
	}
	// Remove the transaction from the pending lists and reset the account nonce
	// 从待处理列表中移除交易并重置账户 nonce
	if pending := pool.pending[addr]; pending != nil {
		if removed, invalids := pending.Remove(tx); removed {
			// If no more pending transactions are left, remove the list
			// 如果没有更多待处理交易，移除列表
			if pending.Empty() {
				delete(pool.pending, addr)
			}
			// Postpone any invalidated transactions
			// 将任何无效交易推迟
			for _, tx := range invalids {
				// Internal shuffle shouldn't touch the lookup set.
				// 内部洗牌不应触及查找集。
				pool.enqueueTx(tx.Hash(), tx, false, false) // 将无效交易重新入队
			}
			// Update the account nonce if needed
			// 如果需要，更新账户 nonce
			pool.pendingNonces.setIfLower(addr, tx.Nonce())
			// Reduce the pending counter
			// 减少待处理计数器
			pendingGauge.Dec(int64(1 + len(invalids)))
			return 1 + len(invalids) // 返回移除的交易数量
		}
	}
	// Transaction is in the future queue
	// 交易在未来队列中
	if future := pool.queue[addr]; future != nil {
		if removed, _ := future.Remove(tx); removed {
			// Reduce the queued counter
			// 减少队列计数器
			queuedGauge.Dec(1)
		}
		if future.Empty() {
			delete(pool.queue, addr) // 如果队列为空，删除队列
			delete(pool.beats, addr) // 删除心跳记录
		}
	}
	return 0
	// 逻辑注解：此函数移除交易并处理后续影响，如将无效交易移回队列或释放账户预留。关键逻辑包括交易移除、计数器更新和状态清理。
}

// requestReset requests a pool reset to the new head block.
// The returned channel is closed when the reset has occurred.
// requestReset 请求将池重置到新的头部区块。
// 返回的通道在重置发生时关闭。
func (pool *LegacyPool) requestReset(oldHead *types.Header, newHead *types.Header) chan struct{} {
	select {
	case pool.reqResetCh <- &txpoolResetRequest{oldHead, newHead}: // 发送重置请求
		return <-pool.reorgDoneCh // 等待重组完成
	case <-pool.reorgShutdownCh: // 如果池关闭，返回关闭通道
		return pool.reorgShutdownCh
	}
	// 逻辑注解：此函数通过通道请求池重置，等待重组完成。关键逻辑是异步触发重置并同步等待结果。
}

// requestPromoteExecutables requests transaction promotion checks for the given addresses.
// The returned channel is closed when the promotion checks have occurred.
// requestPromoteExecutables 请求对给定地址进行交易提升检查。
// 返回的通道在提升检查发生时关闭。
func (pool *LegacyPool) requestPromoteExecutables(set *accountSet) chan struct{} {
	select {
	case pool.reqPromoteCh <- set: // 发送提升请求
		return <-pool.reorgDoneCh // 等待重组完成
	case <-pool.reorgShutdownCh: // 如果池关闭，返回关闭通道
		return pool.reorgShutdownCh
	}
	// 逻辑注解：此函数通过通道请求交易提升，等待检查完成。关键逻辑是异步触发提升并同步等待结果。
}

// queueTxEvent enqueues a transaction event to be sent in the next reorg run.
// queueTxEvent 将交易事件入队，以便在下一次重组运行中发送。
func (pool *LegacyPool) queueTxEvent(tx *types.Transaction) {
	select {
	case pool.queueTxEventCh <- tx: // 发送交易事件
	case <-pool.reorgShutdownCh: // 如果池关闭，忽略事件
	}
	// 逻辑注解：此函数将交易事件加入队列，等待下次重组处理。关键逻辑是异步收集事件。
}

// scheduleReorgLoop schedules runs of reset and promoteExecutables. Code above should not
// call those methods directly, but request them being run using requestReset and
// requestPromoteExecutables instead.
// scheduleReorgLoop 调度 reset 和 promoteExecutables 的运行。上面的代码不应直接调用这些方法，而应使用 requestReset 和 requestPromoteExecutables 请求运行。
func (pool *LegacyPool) scheduleReorgLoop() {
	defer pool.wg.Done()

	var (
		curDone       chan struct{}                         // non-nil while runReorg is active // 当前重组完成通道，在 runReorg 活动时非 nil
		nextDone      = make(chan struct{})                 // 下一个重组完成通道
		launchNextRun bool                                  // 是否启动下一次运行
		reset         *txpoolResetRequest                   // 重置请求
		dirtyAccounts *accountSet                           // 脏账户集合
		queuedEvents  = make(map[common.Address]*sortedMap) // 排队的事件
	)
	for {
		// Launch next background reorg if needed
		// 如果需要，启动下一次后台重组
		if curDone == nil && launchNextRun {
			// Run the background reorg and announcements
			// 运行后台重组和公告
			go pool.runReorg(nextDone, reset, dirtyAccounts, queuedEvents)

			// Prepare everything for the next round of reorg
			// 为下一轮重组准备一切
			curDone, nextDone = nextDone, make(chan struct{})
			launchNextRun = false

			reset, dirtyAccounts = nil, nil
			queuedEvents = make(map[common.Address]*sortedMap)
		}

		select {
		case req := <-pool.reqResetCh:
			// Reset request: update head if request is already pending.
			// 重置请求：如果请求已待处理，更新头部。
			if reset == nil {
				reset = req
			} else {
				reset.newHead = req.newHead // 更新新头部
			}
			launchNextRun = true
			pool.reorgDoneCh <- nextDone // 发送完成通道

		case req := <-pool.reqPromoteCh:
			// Promote request: update address set if request is already pending.
			// 提升请求：如果请求已待处理，更新地址集。
			if dirtyAccounts == nil {
				dirtyAccounts = req
			} else {
				dirtyAccounts.merge(req) // 合并脏账户
			}
			launchNextRun = true
			pool.reorgDoneCh <- nextDone // 发送完成通道

		case tx := <-pool.queueTxEventCh:
			// Queue up the event, but don't schedule a reorg. It's up to the caller to
			// request one later if they want the events sent.
			// 将事件入队，但不调度重组。由调用者决定是否稍后请求发送事件。
			addr, _ := types.Sender(pool.signer, tx)
			if _, ok := queuedEvents[addr]; !ok {
				queuedEvents[addr] = newSortedMap() // 创建新的事件映射
			}
			queuedEvents[addr].Put(tx) // 添加交易事件

		case <-curDone:
			curDone = nil // 当前重组完成

		case <-pool.reorgShutdownCh:
			// Wait for current run to finish.
			// 等待当前运行完成。
			if curDone != nil {
				<-curDone
			}
			close(nextDone) // 关闭下一次完成通道
			return
		}
	}
	// 逻辑注解：此函数是重组循环的调度器，处理重置、提升和事件队列。关键逻辑是异步运行重组并协调多个请求。
}

// runReorg runs reset and promoteExecutables on behalf of scheduleReorgLoop.
// runReorg 代表 scheduleReorgLoop 运行 reset 和 promoteExecutables。
func (pool *LegacyPool) runReorg(done chan struct{}, reset *txpoolResetRequest, dirtyAccounts *accountSet, events map[common.Address]*sortedMap) {
	defer func(t0 time.Time) {
		reorgDurationTimer.Update(time.Since(t0)) // 更新重组持续时间
	}(time.Now())
	defer close(done) // 完成后关闭通道

	var promoteAddrs []common.Address
	if dirtyAccounts != nil && reset == nil {
		// Only dirty accounts need to be promoted, unless we're resetting.
		// For resets, all addresses in the tx queue will be promoted and
		// the flatten operation can be avoided.
		// 仅脏账户需要提升，除非我们在重置。
		// 对于重置，队列中的所有地址都将被提升，可避免展平操作。
		promoteAddrs = dirtyAccounts.flatten() // 展平脏账户列表
	}
	pool.mu.Lock()
	if reset != nil {
		// Reset from the old head to the new, rescheduling any reorged transactions
		// 从旧头部重置到新头部，重新调度任何重组的交易
		pool.reset(reset.oldHead, reset.newHead)

		// Nonces were reset, discard any events that became stale
		// nonce 已重置，丢弃任何过时的事件
		for addr := range events {
			events[addr].Forward(pool.pendingNonces.get(addr)) // 移除低于当前 nonce 的事件
			if events[addr].Len() == 0 {
				delete(events, addr) // 如果事件为空，删除
			}
		}
		// Reset needs promote for all addresses
		// 重置需要为所有地址提升
		promoteAddrs = make([]common.Address, 0, len(pool.queue))
		for addr := range pool.queue {
			promoteAddrs = append(promoteAddrs, addr) // 添加所有队列地址
		}
	}
	// Check for pending transactions for every account that sent new ones
	// 检查每个发送新交易的账户的待处理交易
	promoted := pool.promoteExecutables(promoteAddrs)

	// If a new block appeared, validate the pool of pending transactions. This will
	// remove any transaction that has been included in the block or was invalidated
	// because of another transaction (e.g. higher gas price).
	// 如果出现新区块，验证待处理交易池。这将移除已包含在区块中或因其他交易而无效的交易（例如更高的 gas 价格）。
	if reset != nil {
		pool.demoteUnexecutables() // 降级不可执行交易
		if reset.newHead != nil {
			if pool.chainconfig.IsLondon(new(big.Int).Add(reset.newHead.Number, big.NewInt(1))) {
				pendingBaseFee := eip1559.CalcBaseFee(pool.chainconfig, reset.newHead) // 计算基础费用
				pool.priced.SetBaseFee(pendingBaseFee)                                 // 设置基础费用
			} else {
				pool.priced.Reheap() // 重新堆化价格列表
			}
		}
		// Update all accounts to the latest known pending nonce
		// 更新所有账户到最新的已知待处理 nonce
		nonces := make(map[common.Address]uint64, len(pool.pending))
		for addr, list := range pool.pending {
			highestPending := list.LastElement()
			nonces[addr] = highestPending.Nonce() + 1 // 设置下一个 nonce
		}
		pool.pendingNonces.setAll(nonces)
	}
	// Ensure pool.queue and pool.pending sizes stay within the configured limits.
	// 确保 pool.queue 和 pool.pending 的大小保持在配置限制内。
	pool.truncatePending() // 截断待处理交易
	pool.truncateQueue()   // 截断队列交易

	dropBetweenReorgHistogram.Update(int64(pool.changesSinceReorg)) // 更新重组间丢弃计数
	pool.changesSinceReorg = 0                                      // Reset change counter 重置变化计数器
	pool.mu.Unlock()

	// Notify subsystems for newly added transactions
	// 通知子系统新添加的交易
	for _, tx := range promoted {
		addr, _ := types.Sender(pool.signer, tx)
		if _, ok := events[addr]; !ok {
			events[addr] = newSortedMap() // 创建新的事件映射
		}
		events[addr].Put(tx) // 添加提升的交易事件
	}
	if len(events) > 0 {
		var txs []*types.Transaction
		for _, set := range events {
			txs = append(txs, set.Flatten()...) // 展平所有事件交易
		}
		pool.txFeed.Send(core.NewTxsEvent{Txs: txs}) // 发送新交易事件
	}
	// 逻辑注解：此函数执行重组，处理重置、提升和事件通知。关键逻辑包括状态重置、交易提升、池大小控制和事件广播。
}

// reset retrieves the current state of the blockchain and ensures the content
// of the transaction pool is valid with regard to the chain state.
// reset 获取区块链的当前位置并确保交易池内容相对于链状态有效。
func (pool *LegacyPool) reset(oldHead, newHead *types.Header) {
	// If we're reorging an old state, reinject all dropped transactions
	// 如果我们在重组旧状态，重新注入所有丢弃的交易
	var reinject types.Transactions

	if oldHead != nil && oldHead.Hash() != newHead.ParentHash {
		// If the reorg is too deep, avoid doing it (will happen during fast sync)
		// 如果重组太深，避免执行（在快速同步期间可能发生）
		oldNum := oldHead.Number.Uint64()
		newNum := newHead.Number.Uint64()

		if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
			log.Debug("Skipping deep transaction reorg", "depth", depth)
		} else {
			// Reorg seems shallow enough to pull in all transactions into memory
			// 重组似乎足够浅，可以将所有交易拉入内存
			var (
				rem = pool.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64()) // 获取旧区块
				add = pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64()) // 获取新区块
			)
			if rem == nil {
				// This can happen if a setHead is performed, where we simply discard the old
				// head from the chain.
				// If that is the case, we don't have the lost transactions anymore, and
				// there's nothing to add
				// 如果执行了 setHead，我们只是简单丢弃旧头部。
				// 如果是这样，我们不再有丢失的交易，也没有什么可添加的
				if newNum >= oldNum {
					// If we reorged to a same or higher number, then it's not a case of setHead
					// 如果重组到相同或更高的编号，则不是 setHead 的情况
					log.Warn("Transaction pool reset with missing old head",
						"old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
					return
				}
				// If the reorg ended up on a lower number, it's indicative of setHead being the cause
				// 如果重组结束于较低的编号，表明 setHead 是原因
				log.Debug("Skipping transaction reset caused by setHead",
					"old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
				// We still need to update the current state s.th. the lost transactions can be readded by the user
				// 我们仍需更新当前状态，以便用户可以重新添加丢失的交易
			} else {
				if add == nil {
					// if the new head is nil, it means that something happened between
					// the firing of newhead-event and _now_: most likely a
					// reorg caused by sync-reversion or explicit sethead back to an
					// earlier block.
					// 如果新头部为 nil，意味着在触发 newhead 事件和现在之间发生了某些事情：很可能是同步回滚或显式 sethead 回到早期区块导致的重组。
					log.Warn("Transaction pool reset with missing new head", "number", newHead.Number, "hash", newHead.Hash())
					return
				}
				var discarded, included types.Transactions
				for rem.NumberU64() > add.NumberU64() {
					discarded = append(discarded, rem.Transactions()...) // 添加丢弃的交易
					if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
						log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
						return
					}
				}
				for add.NumberU64() > rem.NumberU64() {
					included = append(included, add.Transactions()...) // 添加包含的交易
					if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
						log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
						return
					}
				}
				for rem.Hash() != add.Hash() {
					discarded = append(discarded, rem.Transactions()...) // 添加丢弃的交易
					if rem = pool.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
						log.Error("Unrooted old chain seen by tx pool", "block", oldHead.Number, "hash", oldHead.Hash())
						return
					}
					included = append(included, add.Transactions()...) // 添加包含的交易
					if add = pool.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
						log.Error("Unrooted new chain seen by tx pool", "block", newHead.Number, "hash", newHead.Hash())
						return
					}
				}
				lost := make([]*types.Transaction, 0, len(discarded))
				for _, tx := range types.TxDifference(discarded, included) {
					if pool.Filter(tx) {
						lost = append(lost, tx) // 筛选出遗留池支持的丢失交易
					}
				}
				reinject = lost // 设置需要重新注入的交易
			}
		}
	}
	// Initialize the internal state to the current head
	// 将内部状态初始化为当前头部
	if newHead == nil {
		newHead = pool.chain.CurrentBlock() // Special case during testing // 测试中的特殊情况
	}
	statedb, err := pool.chain.StateAt(newHead.Root) // 获取新头部的状态
	if err != nil {
		log.Error("Failed to reset txpool state", "err", err)
		return
	}
	pool.currentHead.Store(newHead)         // 更新当前头部
	pool.currentState = statedb             // 更新当前状态
	pool.pendingNonces = newNoncer(statedb) // 更新待处理 nonce 跟踪器

	// Inject any transactions discarded due to reorgs
	// 注入因重组而丢弃的任何交易
	log.Debug("Reinjecting stale transactions", "count", len(reinject))
	core.SenderCacher.Recover(pool.signer, reinject) // 恢复交易发送者缓存
	pool.addTxsLocked(reinject, false)               // 重新添加交易
	// 逻辑注解：此函数处理链重组，重新注入因分叉丢弃的交易并更新池状态。关键逻辑包括分叉检测、交易恢复和状态同步。
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
// promoteExecutables 将已变得可处理的交易从未来队列移动到待处理交易集。在此过程中，所有无效交易（低 nonce、低余额）将被删除。
func (pool *LegacyPool) promoteExecutables(accounts []common.Address) []*types.Transaction {
	// Track the promoted transactions to broadcast them at once
	// 跟踪提升的交易以一次性广播
	var promoted []*types.Transaction

	// Iterate over all accounts and promote any executable transactions
	// 遍历所有账户并提升任何可执行交易
	gasLimit := pool.currentHead.Load().GasLimit // 获取当前区块 gas 限制
	for _, addr := range accounts {
		list := pool.queue[addr]
		if list == nil {
			continue // Just in case someone calls with a non existing account // 如果账户不存在，跳过
		}
		// Drop all transactions that are deemed too old (low nonce)
		// 丢弃所有被认为太旧的交易（低 nonce）
		forwards := list.Forward(pool.currentState.GetNonce(addr))
		for _, tx := range forwards {
			hash := tx.Hash()
			pool.all.Remove(hash) // 从全局查找表中移除
		}
		log.Trace("Removed old queued transactions", "count", len(forwards))
		// Drop all transactions that are too costly (low balance or out of gas)
		// 丢弃所有成本过高的交易（低余额或 gas 不足）
		drops, _ := list.Filter(pool.currentState.GetBalance(addr), gasLimit)
		for _, tx := range drops {
			hash := tx.Hash()
			pool.all.Remove(hash) // 从全局查找表中移除
		}
		log.Trace("Removed unpayable queued transactions", "count", len(drops))
		queuedNofundsMeter.Mark(int64(len(drops))) // 记录因资金不足丢弃的交易

		// Gather all executable transactions and promote them
		// 收集所有可执行交易并提升它们
		readies := list.Ready(pool.pendingNonces.get(addr))
		for _, tx := range readies {
			hash := tx.Hash()
			if pool.promoteTx(addr, hash, tx) {
				promoted = append(promoted, tx) // 如果提升成功，添加到 promoted 列表
			}
		}
		log.Trace("Promoted queued transactions", "count", len(promoted))
		queuedGauge.Dec(int64(len(readies))) // 减少队列计数器

		// Drop all transactions over the allowed limit
		// 丢弃超过允许限制的所有交易
		var caps types.Transactions
		if !pool.locals.contains(addr) {
			caps = list.Cap(int(pool.config.AccountQueue)) // 限制队列大小
			for _, tx := range caps {
				hash := tx.Hash()
				pool.all.Remove(hash) // 从全局查找表中移除
				log.Trace("Removed cap-exceeding queued transaction", "hash", hash)
			}
			queuedRateLimitMeter.Mark(int64(len(caps))) // 记录因限制丢弃的交易
		}
		// Mark all the items dropped as removed
		// 将所有丢弃的项目标记为已移除
		pool.priced.Removed(len(forwards) + len(drops) + len(caps))
		queuedGauge.Dec(int64(len(forwards) + len(drops) + len(caps)))
		if pool.locals.contains(addr) {
			localGauge.Dec(int64(len(forwards) + len(drops) + len(caps))) // 减少本地交易计数
		}
		// Delete a entire queue entry if it became empty.
		// 如果队列变为空，删除整个队列条目。
		if list.Empty() {
			delete(pool.queue, addr)
			delete(pool.beats, addr)
			if _, ok := pool.pending[addr]; !ok {
				pool.reserve(addr, false) // 如果没有待处理交易，释放预留
			}
		}
	}
	return promoted
	// 逻辑注解：此函数从队列提升可执行交易到待处理列表，移除无效交易并限制队列大小。关键逻辑包括交易筛选、提升和清理。
}

// truncatePending removes transactions from the pending queue if the pool is above the
// pending limit. The algorithm tries to reduce transaction counts by an approximately
// equal number for all for accounts with many pending transactions.
// truncatePending 如果池超过待处理限制，从待处理队列中移除交易。算法尝试为所有具有大量待处理交易的账户大约均等地减少交易数量。
func (pool *LegacyPool) truncatePending() {
	pending := uint64(0)
	for _, list := range pool.pending {
		pending += uint64(list.Len()) // 计算待处理交易总数
	}
	if pending <= pool.config.GlobalSlots {
		return // 如果未超过全局槽限制，直接返回
	}

	pendingBeforeCap := pending
	// Assemble a spam order to penalize large transactors first
	// 组装一个垃圾顺序，首先惩罚大交易者
	spammers := prque.New[int64, common.Address](nil)
	for addr, list := range pool.pending {
		// Only evict transactions from high rollers
		// 仅从高交易量账户中驱逐交易
		if !pool.locals.contains(addr) && uint64(list.Len()) > pool.config.AccountSlots {
			spammers.Push(addr, int64(list.Len())) // 按交易数量推送
		}
	}
	// Gradually drop transactions from offenders
	// 逐步从违规者中丢弃交易
	offenders := []common.Address{}
	for pending > pool.config.GlobalSlots && !spammers.Empty() {
		// Retrieve the next offender if not local address
		// 如果不是本地地址，检索下一个违规者
		offender, _ := spammers.Pop()
		offenders = append(offenders, offender)

		// Equalize balances until all the same or below threshold
		// 平衡交易数量直到所有账户相同或低于阈值
		if len(offenders) > 1 {
			// Calculate the equalization threshold for all current offenders
			// 计算所有当前违规者的均衡阈值
			threshold := pool.pending[offender].Len()

			// Iteratively reduce all offenders until below limit or threshold reached
			// 迭代减少所有违规者直到低于限制或达到阈值
			for pending > pool.config.GlobalSlots && pool.pending[offenders[len(offenders)-2]].Len() > threshold {
				for i := 0; i < len(offenders)-1; i++ {
					list := pool.pending[offenders[i]]

					caps := list.Cap(list.Len() - 1) // 移除最后一个交易
					for _, tx := range caps {
						// Drop the transaction from the global pools too
						// 从全局池中也丢弃交易
						hash := tx.Hash()
						pool.all.Remove(hash)

						// Update the account nonce to the dropped transaction
						// 更新账户 nonce 到丢弃的交易
						pool.pendingNonces.setIfLower(offenders[i], tx.Nonce())
						log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
					}
					pool.priced.Removed(len(caps))
					pendingGauge.Dec(int64(len(caps)))
					if pool.locals.contains(offenders[i]) {
						localGauge.Dec(int64(len(caps))) // 减少本地交易计数
					}
					pending--
				}
			}
		}
	}

	// If still above threshold, reduce to limit or min allowance
	// 如果仍高于阈值，减少到限制或最小允许值
	if pending > pool.config.GlobalSlots && len(offenders) > 0 {
		for pending > pool.config.GlobalSlots && uint64(pool.pending[offenders[len(offenders)-1]].Len()) > pool.config.AccountSlots {
			for _, addr := range offenders {
				list := pool.pending[addr]

				caps := list.Cap(list.Len() - 1) // 移除最后一个交易
				for _, tx := range caps {
					// Drop the transaction from the global pools too
					// 从全局池中也丢弃交易
					hash := tx.Hash()
					pool.all.Remove(hash)

					// Update the account nonce to the dropped transaction
					// 更新账户 nonce 到丢弃的交易
					pool.pendingNonces.setIfLower(addr, tx.Nonce())
					log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
				}
				pool.priced.Removed(len(caps))
				pendingGauge.Dec(int64(len(caps)))
				if pool.locals.contains(addr) {
					localGauge.Dec(int64(len(caps))) // 减少本地交易计数
				}
				pending--
			}
		}
	}
	pendingRateLimitMeter.Mark(int64(pendingBeforeCap - pending)) // 记录因限制丢弃的交易数量
	// 逻辑注解：此函数截断待处理交易，优先减少高交易量账户的数量。关键逻辑是公平性控制和池容量管理。
}

// truncateQueue drops the oldest transactions in the queue if the pool is above the global queue limit.
// truncateQueue 如果池超过全局队列限制，丢弃队列中最旧的交易。
func (pool *LegacyPool) truncateQueue() {
	queued := uint64(0)
	for _, list := range pool.queue {
		queued += uint64(list.Len()) // 计算队列交易总数
	}
	if queued <= pool.config.GlobalQueue {
		return // 如果未超过全局队列限制，直接返回
	}

	// Sort all accounts with queued transactions by heartbeat
	// 按心跳时间排序所有具有队列交易的账户
	addresses := make(addressesByHeartbeat, 0, len(pool.queue))
	for addr := range pool.queue {
		if !pool.locals.contains(addr) { // don't drop locals // 不丢弃本地账户
			addresses = append(addresses, addressByHeartbeat{addr, pool.beats[addr]})
		}
	}
	sort.Sort(sort.Reverse(addresses)) // 按心跳时间倒序排序

	// Drop transactions until the total is below the limit or only locals remain
	// 丢弃交易直到总数低于限制或仅剩本地账户
	for drop := queued - pool.config.GlobalQueue; drop > 0 && len(addresses) > 0; {
		addr := addresses[len(addresses)-1]
		list := pool.queue[addr.address]

		addresses = addresses[:len(addresses)-1]

		// Drop all transactions if they are less than the overflow
		// 如果交易少于溢出量，丢弃所有交易
		if size := uint64(list.Len()); size <= drop {
			for _, tx := range list.Flatten() {
				pool.removeTx(tx.Hash(), true, true) // 移除交易
			}
			drop -= size
			queuedRateLimitMeter.Mark(int64(size)) // 记录丢弃数量
			continue
		}
		// Otherwise drop only last few transactions
		// 否则只丢弃最后几个交易
		txs := list.Flatten()
		for i := len(txs) - 1; i >= 0 && drop > 0; i-- {
			pool.removeTx(txs[i].Hash(), true, true) // 移除交易
			drop--
			queuedRateLimitMeter.Mark(1) // 记录丢弃数量
		}
	}
	// 逻辑注解：此函数截断队列交易，按心跳时间丢弃最旧的非本地交易。关键逻辑是按时间顺序清理队列以符合容量限制。
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
//
// Note: transactions are not marked as removed in the priced list because re-heaping
// is always explicitly triggered by SetBaseFee and it would be unnecessary and wasteful
// to trigger a re-heap is this function
// demoteUnexecutables 从池的可执行/待处理队列中移除无效和已处理的交易，任何随后变得不可执行的交易将被移回未来队列。
// 注意：交易在价格列表中未标记为已移除，因为重新堆化始终由 SetBaseFee 显式触发，在此函数中触发重新堆化是不必要且浪费的。
func (pool *LegacyPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	// 遍历所有账户并降级任何不可执行交易
	gasLimit := pool.currentHead.Load().GasLimit // 获取当前区块 gas 限制
	for addr, list := range pool.pending {
		nonce := pool.currentState.GetNonce(addr) // 获取账户当前 nonce

		// Drop all transactions that are deemed too old (low nonce)
		// 丢弃所有被认为太旧的交易（低 nonce）
		olds := list.Forward(nonce)
		for _, tx := range olds {
			hash := tx.Hash()
			pool.all.Remove(hash) // 从全局查找表中移除
			log.Trace("Removed old pending transaction", "hash", hash)
		}
		// Drop all transactions that are too costly (low balance or out of gas), and queue any invalids back for later
		// 丢弃所有成本过高的交易（低余额或 gas 不足），并将任何无效交易重新入队
		drops, invalids := list.Filter(pool.currentState.GetBalance(addr), gasLimit)
		for _, tx := range drops {
			hash := tx.Hash()
			log.Trace("Removed unpayable pending transaction", "hash", hash)
			pool.all.Remove(hash) // 从全局查找表中移除
		}
		pendingNofundsMeter.Mark(int64(len(drops))) // 记录因资金不足丢弃的交易

		for _, tx := range invalids {
			hash := tx.Hash()
			log.Trace("Demoting pending transaction", "hash", hash)

			// Internal shuffle shouldn't touch the lookup set.
			// 内部洗牌不应触及查找集。
			pool.enqueueTx(hash, tx, false, false) // 将无效交易重新入队
		}
		pendingGauge.Dec(int64(len(olds) + len(drops) + len(invalids))) // 减少待处理计数器
		if pool.locals.contains(addr) {
			localGauge.Dec(int64(len(olds) + len(drops) + len(invalids))) // 减少本地交易计数
		}
		// If there's a gap in front, alert (should never happen) and postpone all transactions
		// 如果前面有间隙，发出警报（不应发生）并推迟所有交易
		if list.Len() > 0 && list.txs.Get(nonce) == nil {
			gapped := list.Cap(0)
			for _, tx := range gapped {
				hash := tx.Hash()
				log.Error("Demoting invalidated transaction", "hash", hash)

				// Internal shuffle shouldn't touch the lookup set.
				// 内部洗牌不应触及查找集。
				pool.enqueueTx(hash, tx, false, false) // 将无效交易重新入队
			}
			pendingGauge.Dec(int64(len(gapped))) // 减少待处理计数器
		}
		// Delete the entire pending entry if it became empty.
		// 如果待处理条目变为空，删除整个条目。
		if list.Empty() {
			delete(pool.pending, addr)
			if _, ok := pool.queue[addr]; !ok {
				pool.reserve(addr, false) // 如果没有队列交易，释放预留
			}
		}
	}
	// 逻辑注解：此函数降级待处理队列中的无效交易，移回队列或删除。关键逻辑是根据状态验证交易并调整池结构。
}

// addressByHeartbeat is an account address tagged with its last activity timestamp.
// addressByHeartbeat 是一个标记了最后活动时间戳的账户地址。
type addressByHeartbeat struct {
	address   common.Address // 账户地址
	heartbeat time.Time      // 最后心跳时间
}

type addressesByHeartbeat []addressByHeartbeat

func (a addressesByHeartbeat) Len() int           { return len(a) }
func (a addressesByHeartbeat) Less(i, j int) bool { return a[i].heartbeat.Before(a[j].heartbeat) }
func (a addressesByHeartbeat) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

// 逻辑注解：此类型和方法用于按心跳时间排序账户地址。关键逻辑是实现 Sort 接口以支持队列截断。

// accountSet is simply a set of addresses to check for existence, and a signer
// capable of deriving addresses from transactions.
// accountSet 是一个简单的地址集合，用于检查存在性，并带有一个能够从交易中派生地址的签名器。
type accountSet struct {
	accounts map[common.Address]struct{} // 地址映射
	signer   types.Signer                // 签名器
	cache    []common.Address            // 缓存地址列表
}

// newAccountSet creates a new address set with an associated signer for sender
// derivations.
// newAccountSet 创建一个新的地址集，带有关联的签名器用于发送者派生。
func newAccountSet(signer types.Signer, addrs ...common.Address) *accountSet {
	as := &accountSet{
		accounts: make(map[common.Address]struct{}, len(addrs)),
		signer:   signer,
	}
	for _, addr := range addrs {
		as.add(addr) // 添加初始地址
	}
	return as
	// 逻辑注解：此函数初始化账户集合。关键逻辑是创建映射并填充初始地址。
}

// contains checks if a given address is contained within the set.
// contains 检查给定地址是否包含在集合中。
func (as *accountSet) contains(addr common.Address) bool {
	_, exist := as.accounts[addr]
	return exist // 返回是否存在
	// 逻辑注解：此函数检查地址存在性。关键逻辑是快速查询映射。
}

// containsTx checks if the sender of a given tx is within the set. If the sender
// cannot be derived, this method returns false.
// containsTx 检查给定交易的发送者是否在集合中。如果无法派生发送者，此方法返回 false。
func (as *accountSet) containsTx(tx *types.Transaction) bool {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		return as.contains(addr) // 如果派生成功，检查地址
	}
	return false // 如果派生失败，返回 false
	// 逻辑注解：此函数检查交易发送者是否在集合中。关键逻辑是结合签名器验证发送者。
}

// add inserts a new address into the set to track.
// add 将新地址插入集合中进行跟踪。
func (as *accountSet) add(addr common.Address) {
	as.accounts[addr] = struct{}{} // 添加地址
	as.cache = nil                 // 清除缓存
	// 逻辑注解：此函数添加地址并失效缓存。关键逻辑是更新集合状态。
}

// addTx adds the sender of tx into the set.
// addTx 将交易的发送者添加到集合中。
func (as *accountSet) addTx(tx *types.Transaction) {
	if addr, err := types.Sender(as.signer, tx); err == nil {
		as.add(addr) // 如果派生成功，添加地址
	}
	// 逻辑注解：此函数添加交易发送者。关键逻辑是复用 add 方法。
}

// flatten returns the list of addresses within this set, also caching it for later
// reuse. The returned slice should not be changed!
// flatten 返回集合中的地址列表，并缓存以供稍后重用。返回的切片不应更改！
func (as *accountSet) flatten() []common.Address {
	if as.cache == nil {
		as.cache = maps.Keys(as.accounts) // 从映射生成列表并缓存
	}
	return as.cache
	// 逻辑注解：此函数展平地址集合并缓存结果。关键逻辑是优化重复访问。
}

// merge adds all addresses from the 'other' set into 'as'.
// merge 将 'other' 集合中的所有地址添加到 'as' 中。
func (as *accountSet) merge(other *accountSet) {
	maps.Copy(as.accounts, other.accounts) // 合并映射
	as.cache = nil                         // 清除缓存
	// 逻辑注解：此函数合并两个账户集合。关键逻辑是高效合并并更新状态。
}

// lookup is used internally by LegacyPool to track transactions while allowing
// lookup without mutex contention.
//
// Note, although this type is properly protected against concurrent access, it
// is **not** a type that should ever be mutated or even exposed outside of the
// transaction pool, since its internal state is tightly coupled with the pools
// internal mechanisms. The sole purpose of the type is to permit out-of-bound
// peeking into the pool in LegacyPool.Get without having to acquire the widely scoped
// LegacyPool.mu mutex.
//
// This lookup set combines the notion of "local transactions", which is useful
// to build upper-level structure.
// lookup 被 LegacyPool 内部使用以跟踪交易，同时允许在无互斥锁争用的情况下查找。
// 注意，尽管此类型针对并发访问进行了适当保护，但它**不是**一个应在交易池外部修改甚至暴露的类型，因为其内部状态与池的内部机制紧密耦合。此类型的唯一目的是允许在 LegacyPool.Get 中无需获取广泛作用域的 LegacyPool.mu 互斥锁即可窥视池。
// 此查找集结合了“本地交易”的概念，这对于构建上层结构很有用。
type lookup struct {
	slots   int                                // 使用的槽数
	lock    sync.RWMutex                       // 读写锁
	locals  map[common.Hash]*types.Transaction // 本地交易映射
	remotes map[common.Hash]*types.Transaction // 远程交易映射
}

// newLookup returns a new lookup structure.
// newLookup 返回一个新的查找结构。
func newLookup() *lookup {
	return &lookup{
		locals:  make(map[common.Hash]*types.Transaction), // 初始化本地交易映射
		remotes: make(map[common.Hash]*types.Transaction), // 初始化远程交易映射
	}
	// 逻辑注解：此函数初始化查找结构。关键逻辑是创建空映射以区分本地和远程交易。
}

// Range calls f on each key and value present in the map. The callback passed
// should return the indicator whether the iteration needs to be continued.
// Callers need to specify which set (or both) to be iterated.
// Range 对映射中的每个键和值调用 f。传递的回调应返回是否需要继续迭代的指示器。
// 调用者需要指定要迭代的集合（或两者）。
func (t *lookup) Range(f func(hash common.Hash, tx *types.Transaction, local bool) bool, local bool, remote bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if local {
		for key, value := range t.locals {
			if !f(key, value, true) {
				return // 如果回调返回 false，停止迭代
			}
		}
	}
	if remote {
		for key, value := range t.remotes {
			if !f(key, value, false) {
				return // 如果回调返回 false，停止迭代
			}
		}
	}
	// 逻辑注解：此函数遍历本地和/或远程交易映射，执行回调。关键逻辑是支持灵活的迭代控制。
}

// Get returns a transaction if it exists in the lookup, or nil if not found.
// Get 返回查找中存在的交易，如果未找到则返回 nil。
func (t *lookup) Get(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if tx := t.locals[hash]; tx != nil {
		return tx // 如果在本地交易中找到，返回
	}
	return t.remotes[hash] // 否则返回远程交易或 nil
	// 逻辑注解：此函数快速获取交易，优先检查本地交易。关键逻辑是高效查询。
}

// GetLocal returns a transaction if it exists in the lookup, or nil if not found.
// GetLocal 返回查找中存在的本地交易，如果未找到则返回 nil。
func (t *lookup) GetLocal(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.locals[hash] // 返回本地交易或 nil
	// 逻辑注解：此函数仅查询本地交易。关键逻辑是限制查询范围。
}

// GetRemote returns a transaction if it exists in the lookup, or nil if not found.
// GetRemote 返回查找中存在的远程交易，如果未找到则返回 nil。
func (t *lookup) GetRemote(hash common.Hash) *types.Transaction {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.remotes[hash] // 返回远程交易或 nil
	// 逻辑注解：此函数仅查询远程交易。关键逻辑是限制查询范围。
}

// Count returns the current number of transactions in the lookup.
// Count 返回查找中当前的交易数量。
func (t *lookup) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.locals) + len(t.remotes) // 返回本地和远程交易总数
	// 逻辑注解：此函数统计所有交易数量。关键逻辑是提供总数统计。
}

// LocalCount returns the current number of local transactions in the lookup.
// LocalCount 返回查找中当前本地交易的数量。
func (t *lookup) LocalCount() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.locals) // 返回本地交易数量
	// 逻辑注解：此函数统计本地交易数量。关键逻辑是提供本地统计。
}

// RemoteCount returns the current number of remote transactions in the lookup.
// RemoteCount 返回查找中当前远程交易的数量。
func (t *lookup) RemoteCount() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.remotes) // 返回远程交易数量
	// 逻辑注解：此函数统计远程交易数量。关键逻辑是提供远程统计。
}

// Slots returns the current number of slots used in the lookup.
// Slots 返回查找中当前使用的槽数。
func (t *lookup) Slots() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.slots // 返回槽数
	// 逻辑注解：此函数返回当前槽使用量。关键逻辑是提供资源使用统计。
}

// Add adds a transaction to the lookup.
// Add 将交易添加到查找中。
func (t *lookup) Add(tx *types.Transaction, local bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.slots += numSlots(tx)           // 增加槽数
	slotsGauge.Update(int64(t.slots)) // 更新槽计数器

	if local {
		t.locals[tx.Hash()] = tx // 添加到本地交易
	} else {
		t.remotes[tx.Hash()] = tx // 添加到远程交易
	}
	// 逻辑注解：此函数添加交易并更新槽数。关键逻辑是区分本地和远程交易并记录。
}

// Remove removes a transaction from the lookup.
// Remove 从查找中移除交易。
func (t *lookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()

	tx, ok := t.locals[hash]
	if !ok {
		tx, ok = t.remotes[hash]
	}
	if !ok {
		log.Error("No transaction found to be deleted", "hash", hash)
		return // 如果未找到交易，记录错误并返回
	}
	t.slots -= numSlots(tx)           // 减少槽数
	slotsGauge.Update(int64(t.slots)) // 更新槽计数器

	delete(t.locals, hash)  // 从本地交易中删除
	delete(t.remotes, hash) // 从远程交易中删除
	// 逻辑注解：此函数移除交易并更新槽数。关键逻辑是确保从正确映射中删除并调整资源计数。
}

// RemoteToLocals migrates the transactions belongs to the given locals to locals
// set. The assumption is held the locals set is thread-safe to be used.
// RemoteToLocals 将属于给定本地账户的交易迁移到本地集。假设本地集是线程安全的。
func (t *lookup) RemoteToLocals(locals *accountSet) int {
	t.lock.Lock()
	defer t.lock.Unlock()

	var migrated int
	for hash, tx := range t.remotes {
		if locals.containsTx(tx) {
			t.locals[hash] = tx     // 迁移到本地交易
			delete(t.remotes, hash) // 从远程交易中删除
			migrated++              // 增加迁移计数
		}
	}
	return migrated // 返回迁移的交易数量
	// 逻辑注解：此函数将远程交易迁移到本地集。关键逻辑是根据本地账户检查并移动交易。
}

// RemotesBelowTip finds all remote transactions below the given tip threshold.
// RemotesBelowTip 查找低于给定 tip 阈值的所有远程交易。
func (t *lookup) RemotesBelowTip(threshold *big.Int) types.Transactions {
	found := make(types.Transactions, 0, 128)
	t.Range(func(hash common.Hash, tx *types.Transaction, local bool) bool {
		if tx.GasTipCapIntCmp(threshold) < 0 {
			found = append(found, tx) // 如果 tip 低于阈值，添加到结果
		}
		return true // 继续迭代
	}, false, true) // Only iterate remotes // 仅迭代远程交易
	return found
	// 逻辑注解：此函数筛选低于 tip 阈值的远程交易。关键逻辑是利用 Range 方法高效过滤。
}

// numSlots calculates the number of slots needed for a single transaction.
// numSlots 计算单个交易所需的槽数。
func numSlots(tx *types.Transaction) int {
	return int((tx.Size() + txSlotSize - 1) / txSlotSize) // 计算槽数，向上取整
	// 逻辑注解：此函数根据交易大小计算槽数。关键逻辑是实现 DoS 保护的资源分配。
}

// Clear implements txpool.SubPool, removing all tracked txs from the pool
// and rotating the journal.
// Clear 实现 txpool.SubPool 接口，从池中移除所有跟踪的交易并旋转日志。
func (pool *LegacyPool) Clear() {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// unreserve each tracked account.  Ideally, we could just clear the
	// reservation map in the parent txpool context.  However, if we clear in
	// parent context, to avoid exposing the subpool lock, we have to lock the
	// reservations and then lock each subpool.
	//
	// This creates the potential for a deadlock situation:
	//
	// * TxPool.Clear locks the reservations
	// * a new transaction is received which locks the subpool mutex
	// * TxPool.Clear attempts to lock subpool mutex
	//
	// The transaction addition may attempt to reserve the sender addr which
	// can't happen until Clear releases the reservation lock.  Clear cannot
	// acquire the subpool lock until the transaction addition is completed.
	// 释放每个跟踪账户的预留。理想情况下，我们可以直接在父 txpool 上下文中清除预留映射。
	// 然而，如果在父上下文中清除，为了避免暴露子池锁，我们必须先锁定预留，然后锁定每个子池。
	//
	// 这会造成潜在的死锁情况：
	//
	// * TxPool.Clear 锁定预留
	// * 接收到新交易，锁定子池互斥锁
	// * TxPool.Clear 尝试锁定子池互斥锁
	//
	// 交易添加可能尝试预留发送者地址，但直到 Clear 释放预留锁之前无法进行。Clear 在交易添加完成之前无法获取子池锁。
	for _, tx := range pool.all.remotes {
		senderAddr, _ := types.Sender(pool.signer, tx)
		pool.reserve(senderAddr, false) // 释放远程交易的预留
	}
	for localSender := range pool.locals.accounts {
		pool.reserve(localSender, false) // 释放本地账户的预留
	}

	pool.all = newLookup()                        // 重置全局查找表
	pool.priced = newPricedList(pool.all)         // 重置价格列表
	pool.pending = make(map[common.Address]*list) // 重置待处理映射
	pool.queue = make(map[common.Address]*list)   // 重置队列映射

	if !pool.config.NoLocals && pool.config.Journal != "" {
		pool.journal = newTxJournal(pool.config.Journal) // 创建新日志
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
			// 如果旋转日志失败，记录警告
		}
	}
	// 逻辑注解：此函数清除池中所有交易并重置状态，旋转日志以保留本地交易。关键逻辑是安全释放预留并重建池结构。
}
