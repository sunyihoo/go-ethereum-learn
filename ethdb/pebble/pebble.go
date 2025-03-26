// Copyright 2023 The go-ethereum Authors
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

// Package pebble implements the key-value database layer based on pebble.
// Package pebble 实现了基于 Pebble 的键值数据库层。
package pebble

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// Pebble 简介
// Pebble 是一个高性能的键值存储库，由 CockroachDB 团队开发，用 Go 语言实现。
// 它是 LevelDB 的替代品，设计目标是提供更高的性能、更低的延迟和更好的并发支持。
// Pebble 使用 LSM 树（Log-Structured Merge-Tree）数据结构，与 LevelDB 类似，但优化了写入放大、读取性能和内存管理。
// Pebble 提供更好的并发支持，适合多线程环境下的区块链节点。
// 更低的写入放大减少磁盘使用，优化同步和存储效率。

const (
	// minCache is the minimum amount of memory in megabytes to allocate to pebble
	// read and write caching, split half and half.
	// minCache 是分配给 pebble 读写缓存的最小内存量，以兆字节为单位，读写各占一半。
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	// minHandles 是分配给打开的数据库文件的最小文件句柄数。
	minHandles = 16

	// metricsGatheringInterval specifies the interval to retrieve pebble database
	// compaction, io and pause stats to report to the user.
	// metricsGatheringInterval 指定了获取 pebble 数据库压缩、IO 和暂停统计数据以报告给用户的时间间隔。
	metricsGatheringInterval = 3 * time.Second

	// degradationWarnInterval specifies how often warning should be printed if the
	// leveldb database cannot keep up with requested writes.
	// degradationWarnInterval 指定了当 leveldb 数据库无法跟上请求的写入时，警告打印的频率。
	degradationWarnInterval = time.Minute
)

// Database is a persistent key-value store based on the pebble storage engine.
// Apart from basic data storage functionality it also supports batch writes and
// iterating over the keyspace in binary-alphabetical order.
//
// Database 是一个基于 pebble 存储引擎的持久化键值存储。
// 除了基本的数据存储功能外，它还支持批量写入和按二进制字母顺序遍历键空间。
type Database struct {
	fn string     // filename for reporting
	db *pebble.DB // Underlying pebble storage engine

	compTimeMeter       *metrics.Meter // Meter for measuring the total time spent in database compaction
	compReadMeter       *metrics.Meter // Meter for measuring the data read during compaction
	compWriteMeter      *metrics.Meter // Meter for measuring the data written during compaction
	writeDelayNMeter    *metrics.Meter // Meter for measuring the write delay number due to database compaction
	writeDelayMeter     *metrics.Meter // Meter for measuring the write delay duration due to database compaction
	diskSizeGauge       *metrics.Gauge // Gauge for tracking the size of all the levels in the database
	diskReadMeter       *metrics.Meter // Meter for measuring the effective amount of data read
	diskWriteMeter      *metrics.Meter // Meter for measuring the effective amount of data written
	memCompGauge        *metrics.Gauge // Gauge for tracking the number of memory compaction
	level0CompGauge     *metrics.Gauge // Gauge for tracking the number of table compaction in level0
	nonlevel0CompGauge  *metrics.Gauge // Gauge for tracking the number of table compaction in non0 level
	seekCompGauge       *metrics.Gauge // Gauge for tracking the number of table compaction caused by read opt
	manualMemAllocGauge *metrics.Gauge // Gauge for tracking amount of non-managed memory currently allocated

	levelsGauge []*metrics.Gauge // Gauge for tracking the number of tables in levels // 用于跟踪各层表数量的仪表

	quitLock sync.RWMutex    // Mutex protecting the quit channel and the closed flag
	quitChan chan chan error // Quit channel to stop the metrics collection before closing the database
	closed   bool            // keep track of whether we're Closed

	log log.Logger // Contextual logger tracking the database path

	activeComp    int           // Current number of active compactions 当前活跃压缩的数量
	compStartTime time.Time     // The start time of the earliest currently-active compaction 当前最早活跃压缩的开始时间
	compTime      atomic.Int64  // Total time spent in compaction in ns 压缩所花费的总时间（纳秒）
	level0Comp    atomic.Uint32 // Total number of level-zero compactions 第0层压缩的总次数
	nonLevel0Comp atomic.Uint32 // Total number of non level-zero compactions 非第0层压缩的总次数

	writeStalled        atomic.Bool  // Flag whether the write is stalled 标志写入是否已暂停
	writeDelayStartTime time.Time    // The start time of the latest write stall 最近一次写入暂停的开始时间
	writeDelayCount     atomic.Int64 // Total number of write stall counts 写入暂停的总次数
	writeDelayTime      atomic.Int64 // Total time spent in write stalls 写入暂停所花费的总时间

	writeOptions *pebble.WriteOptions // 写入选项
}

// LSM 树与压缩：
//	pebble 的 LSM 树将数据分层，第0层直接写入，之后通过压缩移到更高层。
//	以太坊的状态更新（如账户余额、合约状态）会导致频繁的第0层压缩。

// onCompactionBegin 是当数据库压缩开始时调用的回调函数。
// 它记录压缩的开始时间，更新第0层或非第0层压缩计数，并增加活跃压缩数量。
// 接收 pebble.CompactionInfo 结构体，包含压缩的详细信息（如输入层、输出层等）。
func (d *Database) onCompactionBegin(info pebble.CompactionInfo) {
	if d.activeComp == 0 { // 当第一次压缩开始时，记录当前时间。
		d.compStartTime = time.Now()
	}
	// pebble 使用 LSM 树，数据分层存储。
	// 第0层（Level 0）直接接收写入，高层通过压缩整理。
	// info.Input[0] 是压缩的输入表，Level 表示其层级。
	// 以太坊状态树更新频繁，第0层压缩通常更频繁且影响写入性能，单独统计有助于优化。
	l0 := info.Input[0] // 根据输入数据的层级，分别更新 level0Comp 或 nonLevel0Comp。
	if l0.Level == 0 {
		d.level0Comp.Add(1)
	} else {
		d.nonLevel0Comp.Add(1)
	}
	d.activeComp++ // 记录当前正在进行的压缩数量。
}

// onCompactionEnd 是当数据库压缩结束时调用的回调函数。
// 它计算并累加压缩总时间，并在活跃压缩数量为0时触发异常，最后减少活跃压缩数量。
func (d *Database) onCompactionEnd(info pebble.CompactionInfo) {
	if d.activeComp == 1 { // 当最后一个活跃压缩结束时，计算从 compStartTime 到现在的总时间并累加到 compTime。仅在 activeComp == 1 时更新，避免多重压缩时重复计时。
		d.compTime.Add(int64(time.Since(d.compStartTime)))
	} else if d.activeComp == 0 {
		panic("should not happen")
	}
	d.activeComp-- // 每次压缩结束时递减活跃压缩数量。
}

// onWriteStallBegin 是当数据库写入暂停开始时调用的回调函数。
// 它记录写入暂停的开始时间，增加暂停计数，并将暂停状态设置为 true。
//
// 写入暂停原因：在 pebble 中，写入暂停通常由 LSM 树的第0层表过多或压缩滞后触发。以太坊的状态更新（如账户余额变化）会增加写入压力。
func (d *Database) onWriteStallBegin(b pebble.WriteStallBeginInfo) {
	d.writeDelayStartTime = time.Now() // 记录写入暂停开始的当前时间。
	d.writeDelayCount.Add(1)           // 累加写入暂停的次数。
	d.writeStalled.Store(true)         // 将写入暂停状态标记为 true。
}

// onWriteStallEnd 是当数据库写入暂停结束时调用的回调函数。
// 它计算并累加写入暂停的总时间，并将暂停状态设置为 false。
//
// 以太坊节点在高负载（如大量交易写入）时可能触发暂停，结束回调用于恢复正常操作并统计影响。
func (d *Database) onWriteStallEnd() {
	d.writeDelayTime.Add(int64(time.Since(d.writeDelayStartTime))) // 计算本次写入暂停的持续时间并累加到 writeDelayTime。
	d.writeStalled.Store(false)                                    // 将写入暂停状态标记为 false，表示暂停已结束。
}

// panicLogger is just a noop logger to disable Pebble's internal logger.
//
// TODO(karalabe): Remove when Pebble sets this as the default.
type panicLogger struct{}

func (l panicLogger) Infof(format string, args ...interface{}) {
}

func (l panicLogger) Errorf(format string, args ...interface{}) {
}

func (l panicLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Errorf("fatal: "+format, args...))
}

// New returns a wrapped pebble DB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
func New(file string, cache int, handles int, namespace string, readonly bool) (*Database, error) {
	// Ensure we have some minimal caching and file guarantees
	if cache < minCache {
		cache = minCache
	}
	if handles < minHandles {
		handles = minHandles
	}
	logger := log.New("database", file)
	logger.Info("Allocated cache and file handles", "cache", common.StorageSize(cache*1024*1024), "handles", handles)

	// The max memtable size is limited by the uint32 offsets stored in
	// internal/arenaskl.node, DeferredBatchOp, and flushableBatchEntry.
	//
	// - MaxUint32 on 64-bit platforms;
	// - MaxInt on 32-bit platforms.
	//
	// It is used when slices are limited to Uint32 on 64-bit platforms (the
	// length limit for slices is naturally MaxInt on 32-bit platforms).
	//
	// Taken from https://github.com/cockroachdb/pebble/blob/master/internal/constants/constants.go
	maxMemTableSize := (1<<31)<<(^uint(0)>>63) - 1

	// Two memory tables is configured which is identical to leveldb,
	// including a frozen memory table and another live one.
	memTableLimit := 2
	memTableSize := cache * 1024 * 1024 / 2 / memTableLimit

	// The memory table size is currently capped at maxMemTableSize-1 due to a
	// known bug in the pebble where maxMemTableSize is not recognized as a
	// valid size.
	//
	// TODO use the maxMemTableSize as the maximum table size once the issue
	// in pebble is fixed.
	if memTableSize >= maxMemTableSize {
		memTableSize = maxMemTableSize - 1
	}
	db := &Database{
		fn:           file,
		log:          logger,
		quitChan:     make(chan chan error),
		writeOptions: &pebble.WriteOptions{Sync: false},
	}
	opt := &pebble.Options{
		// Pebble has a single combined cache area and the write
		// buffers are taken from this too. Assign all available
		// memory allowance for cache.
		Cache:        pebble.NewCache(int64(cache * 1024 * 1024)),
		MaxOpenFiles: handles,

		// The size of memory table(as well as the write buffer).
		// Note, there may have more than two memory tables in the system.
		MemTableSize: uint64(memTableSize),

		// MemTableStopWritesThreshold places a hard limit on the size
		// of the existent MemTables(including the frozen one).
		// Note, this must be the number of tables not the size of all memtables
		// according to https://github.com/cockroachdb/pebble/blob/master/options.go#L738-L742
		// and to https://github.com/cockroachdb/pebble/blob/master/db.go#L1892-L1903.
		MemTableStopWritesThreshold: memTableLimit,

		// The default compaction concurrency(1 thread),
		// Here use all available CPUs for faster compaction.
		MaxConcurrentCompactions: runtime.NumCPU,

		// Per-level options. Options for at least one level must be specified. The
		// options for the last level are used for all subsequent levels.
		Levels: []pebble.LevelOptions{
			{TargetFileSize: 2 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 4 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 8 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 16 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 32 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 64 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
			{TargetFileSize: 128 * 1024 * 1024, FilterPolicy: bloom.FilterPolicy(10)},
		},
		ReadOnly: readonly,
		EventListener: &pebble.EventListener{
			CompactionBegin: db.onCompactionBegin,
			CompactionEnd:   db.onCompactionEnd,
			WriteStallBegin: db.onWriteStallBegin,
			WriteStallEnd:   db.onWriteStallEnd,
		},
		Logger: panicLogger{}, // TODO(karalabe): Delete when this is upstreamed in Pebble
	}
	// Disable seek compaction explicitly. Check https://github.com/ethereum/go-ethereum/pull/20130
	// for more details.
	opt.Experimental.ReadSamplingMultiplier = -1

	// Open the db and recover any potential corruptions
	innerDB, err := pebble.Open(file, opt)
	if err != nil {
		return nil, err
	}
	db.db = innerDB

	db.compTimeMeter = metrics.GetOrRegisterMeter(namespace+"compact/time", nil)
	db.compReadMeter = metrics.GetOrRegisterMeter(namespace+"compact/input", nil)
	db.compWriteMeter = metrics.GetOrRegisterMeter(namespace+"compact/output", nil)
	db.diskSizeGauge = metrics.GetOrRegisterGauge(namespace+"disk/size", nil)
	db.diskReadMeter = metrics.GetOrRegisterMeter(namespace+"disk/read", nil)
	db.diskWriteMeter = metrics.GetOrRegisterMeter(namespace+"disk/write", nil)
	db.writeDelayMeter = metrics.GetOrRegisterMeter(namespace+"compact/writedelay/duration", nil)
	db.writeDelayNMeter = metrics.GetOrRegisterMeter(namespace+"compact/writedelay/counter", nil)
	db.memCompGauge = metrics.GetOrRegisterGauge(namespace+"compact/memory", nil)
	db.level0CompGauge = metrics.GetOrRegisterGauge(namespace+"compact/level0", nil)
	db.nonlevel0CompGauge = metrics.GetOrRegisterGauge(namespace+"compact/nonlevel0", nil)
	db.seekCompGauge = metrics.GetOrRegisterGauge(namespace+"compact/seek", nil)
	db.manualMemAllocGauge = metrics.GetOrRegisterGauge(namespace+"memory/manualalloc", nil)

	// Start up the metrics gathering and return
	go db.meter(metricsGatheringInterval, namespace)
	return db, nil
}

// Close stops the metrics collection, flushes any pending data to disk and closes
// all io accesses to the underlying key-value store.
// Close 停止指标收集，将任何待处理的数据刷新到磁盘，并关闭
// 对底层键值存储的所有 IO 访问。
func (d *Database) Close() error {
	d.quitLock.Lock()
	defer d.quitLock.Unlock()
	// Allow double closing, simplifies things
	// 允许重复关闭，简化操作
	if d.closed {
		return nil
	}
	d.closed = true // 标记为已关闭
	if d.quitChan != nil {
		errc := make(chan error)
		d.quitChan <- errc // 发送退出信号
		if err := <-errc; err != nil {
			d.log.Error("Metrics collection failed", "err", err)
		}
		d.quitChan = nil
	}
	return d.db.Close()
}

// Has retrieves if a key is present in the key-value store.
// Has 检查键值存储中是否存在某个键。
func (d *Database) Has(key []byte) (bool, error) {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return false, pebble.ErrClosed
	}
	_, closer, err := d.db.Get(key) // 获取键对应的值
	if err == pebble.ErrNotFound {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err = closer.Close(); err != nil {
		return false, err
	}
	return true, nil
}

// Get retrieves the given key if it's present in the key-value store.
// Get 如果给定的键存在于键值存储中，则检索该键对应的值。
func (d *Database) Get(key []byte) ([]byte, error) {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return nil, pebble.ErrClosed
	}
	dat, closer, err := d.db.Get(key)
	if err != nil {
		return nil, err
	}
	ret := make([]byte, len(dat)) // 创建返回值切片
	copy(ret, dat)                // 复制数据到新切片
	if err = closer.Close(); err != nil {
		return nil, err
	}
	return ret, nil
}

// Put inserts the given value into the key-value store.
// Put 将给定的值插入键值存储。
func (d *Database) Put(key []byte, value []byte) error {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return pebble.ErrClosed
	}
	return d.db.Set(key, value, d.writeOptions)
}

// Delete removes the key from the key-value store.
// Delete 从键值存储中删除指定的键。
func (d *Database) Delete(key []byte) error {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return pebble.ErrClosed
	}
	return d.db.Delete(key, d.writeOptions)
}

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
// DeleteRange 删除范围 [start, end) 内所有的键（及其值）
// （包含 start，不包含 end）。
func (d *Database) DeleteRange(start, end []byte) error {
	d.quitLock.RLock()
	defer d.quitLock.RUnlock()
	if d.closed {
		return pebble.ErrClosed
	}
	return d.db.DeleteRange(start, end, d.writeOptions)
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
// NewBatch 创建一个只写的键值存储，将更改缓冲到其宿主数据库，
// 直到调用最终的写入操作。
func (d *Database) NewBatch() ethdb.Batch {
	return &batch{
		b:  d.db.NewBatch(),
		db: d,
	}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
// NewBatchWithSize 创建一个带有预分配缓冲区的只写数据库批次。
func (d *Database) NewBatchWithSize(size int) ethdb.Batch {
	return &batch{
		b:  d.db.NewBatchWithSize(size), // 创建具有指定大小的 pebble 批次
		db: d,
	}
}

//键序与 Trie：以太坊状态树按二进制顺序存储键，上界计算需确保不跨前缀。

// upperBound returns the upper bound for the given prefix
// upperBound 返回给定前缀的上界
func upperBound(prefix []byte) (limit []byte) {
	for i := len(prefix) - 1; i >= 0; i-- {
		c := prefix[i]
		if c == 0xff {
			continue
		}
		limit = make([]byte, i+1)
		copy(limit, prefix)
		limit[i] = c + 1
		break
	}
	return limit
}

// Stat returns the internal metrics of Pebble in a text format. It's a developer
// method to read everything there is to read, independent of Pebble version.
func (d *Database) Stat() (string, error) {
	return d.db.Metrics().String(), nil
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
//
// Compact 压缩底层数据存储在给定的键范围内的数据。本质上，
// 被删除和覆盖的版本会被丢弃，数据会被重新排列以降低访问它们所需的操作成本。
//
// 如果 start 为 nil，则视为数据存储中所有键之前的一个键；如果 limit 为 nil，
// 则视为数据存储中所有键之后的一个键。如果两者均为 nil，则会压缩整个数据存储。
//
// 以太坊状态树（Trie）键长通常为 32 字节（如哈希），32 个 0xff 确保覆盖所有键，包括前缀共享的情况。
func (d *Database) Compact(start []byte, limit []byte) error {
	// There is no special flag to represent the end of key range
	// in pebble(nil in leveldb). Use an ugly hack to construct a
	// large key to represent it.
	// Note any prefixed database entry will be smaller than this
	// flag, as for trie nodes we need the 32 byte 0xff because
	// there might be a shared prefix starting with a number of
	// 0xff-s, so 32 ensures than only a hash collision could touch it.
	// https://github.com/cockroachdb/pebble/issues/2359#issuecomment-1443995833
	//
	// 在 pebble 中没有特殊标志来表示键范围的结束
	//（在 leveldb 中为 nil）。使用一个丑陋的 hack 来构造一个
	// 大键来表示它。
	// 注意，任何带有前缀的数据库条目都会比这个标志小，因为对于 trie 节点，
	// 我们需要 32 字节的 0xff，因为可能存在以多个 0xff 开头的共享前缀，
	// 所以 32 字节确保只有哈希冲突才会触及它。
	if limit == nil {
		limit = bytes.Repeat([]byte{0xff}, 32) // 用 32 个 0xff 表示最大键
	}
	return d.db.Compact(start, limit, true) // Parallelization is preferred 优先使用并行化
}

// Path returns the path to the database directory.
func (d *Database) Path() string {
	return d.fn
}

// meter periodically retrieves internal pebble counters and reports them to
// the metrics subsystem.
// meter 定期检索 pebble 内部计数器并将其报告给指标子系统。
func (d *Database) meter(refresh time.Duration, namespace string) {
	var errc chan error
	timer := time.NewTimer(refresh)
	defer timer.Stop()

	// Create storage and warning log tracer for write delay.
	// 创建存储和警告日志跟踪器，用于写入延迟。
	var (
		compTimes  [2]int64 // 压缩时间数组
		compWrites [2]int64 // 压缩写入数据量数组
		compReads  [2]int64 // 压缩读取数据量数组

		nWrites [2]int64 // 总写入数据量数组

		writeDelayTimes      [2]int64  // 写入延迟时间数组
		writeDelayCounts     [2]int64  // 写入延迟次数数组
		lastWriteStallReport time.Time // 上次写入暂停报告时间
	)

	// Iterate ad infinitum and collect the stats
	// 无限循环并收集统计数据
	for i := 1; errc == nil; i++ {
		var (
			compWrite int64 // 本次压缩写入数据量
			compRead  int64 // 本次压缩读取数据量
			nWrite    int64 // 本次总写入数据量

			stats              = d.db.Metrics()                // 获取数据库指标
			compTime           = d.compTime.Load()             // 获取压缩总时间
			writeDelayCount    = d.writeDelayCount.Load()      // 获取写入延迟次数
			writeDelayTime     = d.writeDelayTime.Load()       // 获取写入延迟总时间
			nonLevel0CompCount = int64(d.nonLevel0Comp.Load()) // 获取非第0层压缩次数
			level0CompCount    = int64(d.level0Comp.Load())    // 获取第0层压缩次数
		)
		writeDelayTimes[i%2] = writeDelayTime
		writeDelayCounts[i%2] = writeDelayCount
		compTimes[i%2] = compTime

		for _, levelMetrics := range stats.Levels {
			nWrite += int64(levelMetrics.BytesCompacted)    // 累加压缩写入字节数
			nWrite += int64(levelMetrics.BytesFlushed)      // 累加刷新写入字节数
			compWrite += int64(levelMetrics.BytesCompacted) // 累加压缩写入字节数
			compRead += int64(levelMetrics.BytesRead)       // 累加压缩读取字节数
		}

		nWrite += int64(stats.WAL.BytesWritten) // 累加WAL写入字节数

		compWrites[i%2] = compWrite
		compReads[i%2] = compRead
		nWrites[i%2] = nWrite

		if d.writeDelayNMeter != nil {
			d.writeDelayNMeter.Mark(writeDelayCounts[i%2] - writeDelayCounts[(i-1)%2]) // 报告写入延迟次数增量
		}
		if d.writeDelayMeter != nil {
			d.writeDelayMeter.Mark(writeDelayTimes[i%2] - writeDelayTimes[(i-1)%2]) // 报告写入延迟时间增量
		}
		// Print a warning log if writing has been stalled for a while. The log will
		// be printed per minute to avoid overwhelming users.
		// 如果写入长时间暂停，则打印警告日志。每分钟打印一次，以避免淹没用户。
		if d.writeStalled.Load() && writeDelayCounts[i%2] == writeDelayCounts[(i-1)%2] &&
			time.Now().After(lastWriteStallReport.Add(degradationWarnInterval)) {
			d.log.Warn("Database compacting, degraded performance")
			lastWriteStallReport = time.Now()
		}
		if d.compTimeMeter != nil {
			d.compTimeMeter.Mark(compTimes[i%2] - compTimes[(i-1)%2]) // 报告压缩时间增量
		}
		if d.compReadMeter != nil {
			d.compReadMeter.Mark(compReads[i%2] - compReads[(i-1)%2]) // 报告压缩读取增量
		}
		if d.compWriteMeter != nil {
			d.compWriteMeter.Mark(compWrites[i%2] - compWrites[(i-1)%2]) // 报告压缩写入增量
		}
		if d.diskSizeGauge != nil {
			d.diskSizeGauge.Update(int64(stats.DiskSpaceUsage())) // 更新磁盘使用量
		}
		if d.diskReadMeter != nil {
			d.diskReadMeter.Mark(0) // pebble doesn't track non-compaction reads. pebble 不跟踪非压缩读取
		}
		if d.diskWriteMeter != nil {
			d.diskWriteMeter.Mark(nWrites[i%2] - nWrites[(i-1)%2]) // 报告总写入增量
		}
		// See https://github.com/cockroachdb/pebble/pull/1628#pullrequestreview-1026664054
		manuallyAllocated := stats.BlockCache.Size + int64(stats.MemTable.Size) + int64(stats.MemTable.ZombieSize) // 计算手动分配内存
		d.manualMemAllocGauge.Update(manuallyAllocated)                                                            // 更新手动分配内存量
		d.memCompGauge.Update(stats.Flush.Count)                                                                   // 更新内存压缩次数
		d.nonlevel0CompGauge.Update(nonLevel0CompCount)                                                            // 更新非第0层压缩次数
		d.level0CompGauge.Update(level0CompCount)                                                                  // 更新第0层压缩次数
		d.seekCompGauge.Update(stats.Compact.ReadCount)                                                            // 更新因读取引发的压缩次数

		for i, level := range stats.Levels {
			// Append metrics for additional layers
			// 为额外层追加指标
			if i >= len(d.levelsGauge) {
				d.levelsGauge = append(d.levelsGauge, metrics.GetOrRegisterGauge(namespace+fmt.Sprintf("tables/level%v", i), nil))
			}
			d.levelsGauge[i].Update(level.NumFiles) // 更新各层表数量
		}

		// Sleep a bit, then repeat the stats collection
		// 休眠一段时间，然后重复收集统计数据
		select {
		case errc = <-d.quitChan:
			// Quit requesting, stop hammering the database
			// 退出请求，停止对数据库的频繁操作
		case <-timer.C:
			timer.Reset(refresh)
			// Timeout, gather a new set of stats
			// 超时，收集新一组统计数据
		}
	}
	errc <- nil
}

// batch is a write-only batch that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
//
// batch 是一个只写批次，在调用 Write 时将其更改提交到宿主数据库。
// 批次不能并发使用。
type batch struct {
	b    *pebble.Batch // 底层的 pebble 批次
	db   *Database     // 宿主数据库
	size int           // 批次中排队的数据量
}

// Put inserts the given value into the batch for later committing.
// Put 将给定的值插入批次中，以便稍后提交。
func (b *batch) Put(key, value []byte) error {
	if err := b.b.Set(key, value, nil); err != nil {
		return err
	}
	b.size += len(key) + len(value) // 更新批次大小
	return nil
}

// Delete inserts the key removal into the batch for later committing.
//
// Delete 将键的删除操作插入批次中，以便稍后提交。
func (b *batch) Delete(key []byte) error {
	if err := b.b.Delete(key, nil); err != nil {
		return err
	}
	b.size += len(key)
	return nil
}

// ValueSize retrieves the amount of data queued up for writing.
// ValueSize 检索排队等待写入的数据量。
func (b *batch) ValueSize() int {
	return b.size
}

// Write flushes any accumulated data to disk.
// Write 将任何累积的数据刷新到磁盘。
func (b *batch) Write() error {
	b.db.quitLock.RLock()
	defer b.db.quitLock.RUnlock()
	if b.db.closed {
		return pebble.ErrClosed
	}
	return b.b.Commit(b.db.writeOptions) // 提交批次
}

// Reset resets the batch for reuse.
// Reset 重置批次以便重用。
func (b *batch) Reset() {
	b.b.Reset()
	b.size = 0
}

// Replay replays the batch contents.
// Replay 重放批次内容。
func (b *batch) Replay(w ethdb.KeyValueWriter) error {
	reader := b.b.Reader()
	for {
		kind, k, v, ok, err := reader.Next()
		if !ok || err != nil {
			return err
		}
		// The (k,v) slices might be overwritten if the batch is reset/reused,
		// and the receiver should copy them if they are to be retained long-term.
		// (k,v) 切片可能会在批次重置/重用时被覆盖，
		// 如果需要长期保留，接收者应复制它们。
		if kind == pebble.InternalKeyKindSet {
			if err = w.Put(k, v); err != nil {
				return err
			}
		} else if kind == pebble.InternalKeyKindDelete {
			if err = w.Delete(k); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unhandled operation, keytype: %v", kind)
		}
	}
}

// 状态树遍历：以太坊使用 Merkle Patricia Trie 存储状态，键按二进制顺序排列，迭代器支持前缀查询。
// 如 EIP-2929 调整状态访问成本，迭代器可用于分析受影响的数据。

// pebbleIterator is a wrapper of underlying iterator in storage engine.
// The purpose of this structure is to implement the missing APIs.
//
// The pebble iterator is not thread-safe.
//
// pebbleIterator 是存储引擎底层迭代器的包装器。
// 这个结构体的目的是实现缺失的 API。
//
// pebble 迭代器不是线程安全的。
type pebbleIterator struct {
	iter     *pebble.Iterator // 底层的 pebble 迭代器
	moved    bool             // 标记是否已经移动
	released bool             // 标记是否已释放资源
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
//
// NewIterator 创建一个按二进制字母顺序遍历数据库内容的迭代器，
// 该迭代器针对具有特定键前缀的子集，从特定的初始键开始（如果该键不存在，则从之后开始）。
//
// 以太坊状态树（Trie）按键前缀组织，迭代器可用于扫描特定账户或合约数据。
func (d *Database) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	iter, _ := d.db.NewIter(&pebble.IterOptions{
		LowerBound: append(prefix, start...), // 设置迭代下界
		UpperBound: upperBound(prefix),       // 设置迭代上界
	})
	iter.First() // 移动到第一个键值对
	return &pebbleIterator{iter: iter, moved: true, released: false}
}

// Next moves the iterator to the next key/value pair. It returns whether the
// iterator is exhausted.
// Next 将迭代器移动到下一个键值对。它返回迭代器是否已耗尽。
//
// 遍历状态数据时，需按顺序访问键值对以验证或导出。
func (iter *pebbleIterator) Next() bool {
	if iter.moved { // 若 moved 为 true（初始或刚创建），检查当前是否有效。
		iter.moved = false
		return iter.iter.Valid() // 检查当前键值对是否有效
	}
	return iter.iter.Next() // 移动到下一个键值对并返回是否成功
}

// Error returns any accumulated error. Exhausting all the key/value pairs
// is not considered to be an error.
//
// Error 返回任何累积的错误。耗尽所有键值对不视为错误。
func (iter *pebbleIterator) Error() error {
	return iter.iter.Error()
}

// Key returns the key of the current key/value pair, or nil if done. The caller
// should not modify the contents of the returned slice, and its contents may
// change on the next call to Next.
//
// Key 返回当前键值对的键，如果迭代完成则返回 nil。
// 调用者不应修改返回切片的内容，其内容可能在下一次调用 Next 时改变。
func (iter *pebbleIterator) Key() []byte {
	return iter.iter.Key()
}

// Value returns the value of the current key/value pair, or nil if done. The
// caller should not modify the contents of the returned slice, and its contents
// may change on the next call to Next.
//
// Value 返回当前键值对的值，如果迭代完成则返回 nil。
// 调用者不应修改返回切片的内容，其内容可能在下一次调用 Next 时改变。
func (iter *pebbleIterator) Value() []byte {
	return iter.iter.Value()
}

// Release releases associated resources. Release should always succeed and can
// be called multiple times without causing error.
// Release 释放相关资源。Release 应始终成功，且可多次调用而不引发错误。
func (iter *pebbleIterator) Release() {
	if !iter.released {
		iter.iter.Close()
		iter.released = true
	}
}
