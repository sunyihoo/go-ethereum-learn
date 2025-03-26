// Copyright 2018 The go-ethereum Authors
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

//go:build !js
// +build !js

// Package leveldb implements the key-value database layer based on LevelDB.
// Package leveldb 实现了基于 LevelDB 的键值数据库层。
package leveldb

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDB 是一个由 Google 开发的轻量级、嵌入式键值存储库，以高性能读写和简单 API 著称。
// 它使用 LSM 树（Log-Structured Merge Tree）作为底层数据结构，适合高写吞吐量场景。
// 在以太坊中，LevelDB 被用作默认的底层存储引擎，用于保存区块链数据，包括：
//  - 状态树（State Trie）：存储所有账户的状态（余额、Nonce、代码等）。
//  - 交易数据：记录交易的详细信息。
//  - 区块头和索引：便于快速查询区块信息。

const (
	// degradationWarnInterval specifies how often warning should be printed if the
	// leveldb database cannot keep up with requested writes.
	//
	// degradationWarnInterval 指定当 leveldb 数据库无法跟上请求的写入时，多久打印一次警告。
	//
	// 当 LevelDB 数据库的写入性能下降（即无法及时处理写入请求）时，每隔 1 分钟打印一次警告日志。
	// 以太坊节点需要处理大量交易和状态更新（如账户余额变化），这些操作会频繁写入 LevelDB。如果写入速度跟不上，可能导致同步延迟或节点不可用。这个常量用于定期提醒用户性能问题。
	degradationWarnInterval = time.Minute

	// minCache is the minimum amount of memory in megabytes to allocate to leveldb
	// read and write caching, split half and half.
	//
	// minCache 是分配给 leveldb 读写缓存的最小内存量，以兆字节为单位，读写各占一半。
	//
	// 以太坊的状态树和区块数据查询依赖快速的读取操作，而写缓存则加速了状态更新。16 MB 是最低配置，实际运行全节点可能需要数百 MB 甚至更多，取决于网络负载。
	// LevelDB 使用内存缓存来减少直接访问磁盘的开销，缓存大小直接影响查询和写入效率。
	minCache = 16

	// minHandles is the minimum number of files handles to allocate to the open
	// database files.
	//
	// minHandles 是分配给打开的数据库文件的最小文件句柄数。
	//
	// LevelDB 将数据存储在多个 SSTable 文件中，同时操作多个文件需要足够的句柄。以太坊节点在同步区块或处理交易时会频繁访问这些文件，句柄不足可能导致文件打开失败。
	// 操作系统对文件句柄有限制，默认值（如 16）确保基本功能，但高负载场景可能需要调整。
	minHandles = 16

	// metricsGatheringInterval specifies the interval to retrieve leveldb database
	// compaction, io and pause stats to report to the user.
	//
	// metricsGatheringInterval 指定检索 leveldb 数据库压缩、IO 和暂停统计数据以报告给用户的时间间隔。
	//
	// 以太坊节点运行时需要监控数据库性能，确保同步和交易处理正常。3 秒的间隔平衡了监控频率和性能开销。
	metricsGatheringInterval = 3 * time.Second
)

// Database is a persistent key-value store. Apart from basic data storage
// functionality it also supports batch writes and iterating over the keyspace in
// binary-alphabetical order.
//
// Database 是一个持久化的键值存储。除了基本的数据存储功能外，
// 它还支持批量写入和按二进制字母顺序遍历键空间。
//
// 在以太坊中，db 用于存储状态树、交易和区块数据，fn 帮助跟踪数据文件位置（如 chaindata 目录）。
//
// 状态存储：以太坊的状态树（Merkle Patricia Trie）以键值对形式存储在 LevelDB 中，键是节点哈希，值是序列化数据。
//
// LSM 树与 Compaction：
// LevelDB 的 LSM 树将写入分为内存（MemTable）和磁盘（SSTable），compaction 是将数据从 Level 0 合并到更高层的过程。以太坊的高写入负载使这些指标尤为重要。
type Database struct {
	fn string      // filename for reporting  用于报告的文件名
	db *leveldb.DB // LevelDB instance  LevelDB 实例

	compTimeMeter       *metrics.Meter // Meter for measuring the total time spent in database compaction 用于测量数据库压缩所花费的总时间的仪表
	compReadMeter       *metrics.Meter // Meter for measuring the data read during compaction 用于测量压缩期间读取的数据量的仪表
	compWriteMeter      *metrics.Meter // Meter for measuring the data written during compaction 用于测量压缩期间写入的数据量的仪表
	writeDelayNMeter    *metrics.Meter // Meter for measuring the write delay number due to database compaction 用于测量由于数据库压缩导致的写入延迟次数的仪表
	writeDelayMeter     *metrics.Meter // Meter for measuring the write delay duration due to database compaction 用于测量由于数据库压缩导致的写入延迟持续时间的仪表
	diskSizeGauge       *metrics.Gauge // Gauge for tracking the size of all the levels in the database 用于跟踪数据库中所有级别大小的量规
	diskReadMeter       *metrics.Meter // Meter for measuring the effective amount of data read 用于测量有效读取数据量的仪表
	diskWriteMeter      *metrics.Meter // Meter for measuring the effective amount of data written 用于测量有效写入数据量的仪表
	memCompGauge        *metrics.Gauge // Gauge for tracking the number of memory compaction 用于跟踪内存压缩次数的量规
	level0CompGauge     *metrics.Gauge // Gauge for tracking the number of table compaction in level0 用于跟踪 level0 中表压缩次数的量规
	nonlevel0CompGauge  *metrics.Gauge // Gauge for tracking the number of table compaction in non0 level 用于跟踪非 level0 中表压缩次数的量规
	seekCompGauge       *metrics.Gauge // Gauge for tracking the number of table compaction caused by read opt 用于跟踪由读取操作引起的表压缩次数的量规
	manualMemAllocGauge *metrics.Gauge // Gauge to track the amount of memory that has been manually allocated (not a part of runtime/GC) 用于跟踪手动分配的内存量的量规（不属于 runtime/GC 的一部分）

	levelsGauge []*metrics.Gauge // Gauge for tracking the number of tables in levels 用于跟踪各层级表数量的量规

	quitLock sync.Mutex      // Mutex protecting the quit channel access 保护退出通道访问的互斥锁
	quitChan chan chan error // Quit channel to stop the metrics collection before closing the database 在关闭数据库前停止指标收集的退出通道

	log log.Logger // Contextual logger tracking the database path 跟踪数据库路径的上下文日志记录器
}

// New returns a wrapped LevelDB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
//
// New 返回一个封装的 LevelDB 对象。namespace 是指标报告用于显示内部统计数据的前缀。
func New(file string, cache int, handles int, namespace string, readonly bool) (*Database, error) {
	return NewCustom(file, namespace, func(options *opt.Options) {
		// Ensure we have some minimal caching and file guarantees
		// 确保有一些最小的缓存和文件保证
		// 过小的缓存会导致频繁磁盘 IO，降低性能。
		if cache < minCache {
			cache = minCache
		}
		// 以太坊全节点需同时操作多个 SSTable 文件，句柄不足会限制并发访问。
		if handles < minHandles {
			handles = minHandles
		}
		// Set default options
		// 设置默认选项
		options.OpenFilesCacheCapacity = handles         // 文件句柄缓存减少重复打开文件的开销，提升状态查询效率。
		options.BlockCacheCapacity = cache / 2 * opt.MiB // 块缓存占总缓存一半，转换为字节（opt.MiB 是 1 MB 的常量）。块缓存存储 SSTable 数据块，加速读取。
		// LevelDB 可同时持有两个 memdb，总写缓冲区为 cache / 2，与块缓存平分缓存。
		options.WriteBuffer = cache / 4 * opt.MiB // Two of these are used internally  内部使用其中的两个。写缓冲区占总缓存四分之一，注释说明内部使用两个。
		if readonly {                             // 只读模式适用于存档节点或仅查询的客户端。
			options.ReadOnly = true
		}
	})
}

// NewCustom returns a wrapped LevelDB object. The namespace is the prefix that the
// metrics reporting should use for surfacing internal stats.
// The customize function allows the caller to modify the leveldb options.
//
// NewCustom 返回一个封装的 LevelDB 对象。namespace 是指标报告用于显示内部统计数据的前缀。
// customize 函数允许调用者修改 LevelDB 选项。
func NewCustom(file string, namespace string, customize func(options *opt.Options)) (*Database, error) {
	options := configureOptions(customize)
	logger := log.New("database", file)
	// 计算总缓存（块缓存 + 两个写缓冲区）。
	// LevelDB 可同时持有两个 memdb，故写缓冲区乘以 2。
	usedCache := options.GetBlockCacheCapacity() + options.GetWriteBuffer()*2
	// logCtx 记录缓存大小、文件句柄数和只读状态。
	logCtx := []interface{}{"cache", common.StorageSize(usedCache), "handles", options.GetOpenFilesCacheCapacity()}
	if options.ReadOnly {
		logCtx = append(logCtx, "readonly", "true")
	}
	logger.Info("Allocated cache and file handles", logCtx...)

	// Open the db and recover any potential corruptions
	// 打开数据库并恢复任何潜在的损坏
	// 打开状态数据库，存储区块和状态树。
	db, err := leveldb.OpenFile(file, options)
	// 检查是否损坏，若是则尝试恢复。节点意外关闭可能导致数据损坏，恢复功能确保数据一致性。
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(file, nil) // 恢复损坏的数据库。
	}
	if err != nil {
		return nil, err
	}
	// Assemble the wrapper with all the registered metrics
	// 使用所有注册的指标组装包装器
	ldb := &Database{
		fn:       file,
		db:       db,
		log:      logger,
		quitChan: make(chan chan error),
	}
	ldb.compTimeMeter = metrics.NewRegisteredMeter(namespace+"compact/time", nil)
	ldb.compReadMeter = metrics.NewRegisteredMeter(namespace+"compact/input", nil)
	ldb.compWriteMeter = metrics.NewRegisteredMeter(namespace+"compact/output", nil)
	ldb.diskSizeGauge = metrics.NewRegisteredGauge(namespace+"disk/size", nil)
	ldb.diskReadMeter = metrics.NewRegisteredMeter(namespace+"disk/read", nil)
	ldb.diskWriteMeter = metrics.NewRegisteredMeter(namespace+"disk/write", nil)
	ldb.writeDelayMeter = metrics.NewRegisteredMeter(namespace+"compact/writedelay/duration", nil)
	ldb.writeDelayNMeter = metrics.NewRegisteredMeter(namespace+"compact/writedelay/counter", nil)
	ldb.memCompGauge = metrics.NewRegisteredGauge(namespace+"compact/memory", nil)
	ldb.level0CompGauge = metrics.NewRegisteredGauge(namespace+"compact/level0", nil)
	ldb.nonlevel0CompGauge = metrics.NewRegisteredGauge(namespace+"compact/nonlevel0", nil)
	ldb.seekCompGauge = metrics.NewRegisteredGauge(namespace+"compact/seek", nil)
	ldb.manualMemAllocGauge = metrics.NewRegisteredGauge(namespace+"memory/manualalloc", nil)

	// Start up the metrics gathering and return
	// 启动指标收集并返回
	go ldb.meter(metricsGatheringInterval, namespace)
	return ldb, nil
}

// configureOptions sets some default options, then runs the provided setter.
// configureOptions 设置一些默认选项，然后运行提供的设置函数。
//
// 目的是初始化 LevelDB 的 Options 结构体，设置默认值，并允许通过回调函数进行自定义配置。
func configureOptions(customizeFn func(*opt.Options)) *opt.Options {
	// Set default options
	// 设置默认选项
	options := &opt.Options{
		// 布隆过滤器是一种概率数据结构，用于快速判断键是否存在，减少无效磁盘读取。10 位意味着每个键占用约 1.25 字节，假阳率约为 1%，在性能和空间间取得平衡。
		// 以太坊状态树查询频繁，布隆过滤器可显著减少 SSTable 的读取次数，提升性能。
		Filter: filter.NewBloomFilter(10), // 设置默认过滤器为布隆过滤器，每键 10 位。
		// LevelDB 默认通过查找（seek）频率触发压缩以优化读取，但这可能导致频繁的小规模压缩，增加写入开销。禁用此功能减少压缩频率。
		// 以太坊节点可能优先写入性能（如同步区块），禁用 seek compaction 适合高写入场景。
		DisableSeeksCompaction: true, // 禁用“由查找触发的压缩”。
	}
	// Allow caller to make custom modifications to the options
	// 允许调用者对选项进行自定义修改
	if customizeFn != nil {
		customizeFn(options)
	}
	return options
}

// Close stops the metrics collection, flushes any pending data to disk and closes
// all io accesses to the underlying key-value store.
//
// Close 停止指标收集，将任何待处理数据刷新到磁盘，并关闭对底层键值存储的所有 IO 访问。
func (db *Database) Close() error {
	db.quitLock.Lock() // 使用互斥锁保护 quitChan 的访问。
	defer db.quitLock.Unlock()

	if db.quitChan != nil { // 检查是否已初始化退出通道（即数据库未关闭）。
		errc := make(chan error)       // 创建错误通道，用于接收 meter 的退出结果。
		db.quitChan <- errc            // 发送退出信号给 meter goroutine。
		if err := <-errc; err != nil { // 等待 meter 完成并检查错误，若有则记录日志。
			db.log.Error("Metrics collection failed", "err", err)
		}
		db.quitChan = nil // 标记通道已关闭，避免重复操作
	}
	return db.db.Close()
}

// Has retrieves if a key is present in the key-value store.
// Has 检索键值存储中是否存在某个键。
func (db *Database) Has(key []byte) (bool, error) {
	return db.db.Has(key, nil)
}

// Get retrieves the given key if it's present in the key-value store.
// Get 如果键存在于键值存储中，则检索该键的值。
func (db *Database) Get(key []byte) ([]byte, error) {
	dat, err := db.db.Get(key, nil)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

// Put inserts the given value into the key-value store.
// Put 将给定的值插入键值存储。
func (db *Database) Put(key []byte, value []byte) error {
	return db.db.Put(key, value, nil)
}

// Delete removes the key from the key-value store.
// Delete 从键值存储中移除某个键。
func (db *Database) Delete(key []byte) error {
	return db.db.Delete(key, nil)
}

// ErrTooManyKeys 表示删除范围内的键过多
var ErrTooManyKeys = errors.New("too many keys in deleted range")

// 以太坊修剪：范围删除支持状态优化（如 EIP-2929）。

// DeleteRange deletes all of the keys (and values) in the range [start,end)
// (inclusive on start, exclusive on end).
// Note that this is a fallback implementation as leveldb does not natively
// support range deletion. It can be slow and therefore the number of deleted
// keys is limited in order to avoid blocking for a very long time.
// ErrTooManyKeys is returned if the range has only been partially deleted.
// In this case the caller can repeat the call until it finally succeeds.
//
// DeleteRange 删除范围 [start,end) 内所有的键（和值）（包含 start，不包含 end）。
// 注意，这是一个回退实现，因为 LevelDB 原生不支持范围删除。
// 它可能很慢，因此限制了删除的键数量，以避免长时间阻塞。
// 如果范围仅部分删除，则返回 ErrTooManyKeys。
// 在这种情况下，调用者可以重复调用直到最终成功。
func (db *Database) DeleteRange(start, end []byte) error {
	batch := db.NewBatch()
	it := db.NewIterator(nil, start)
	defer it.Release()

	var count int
	for it.Next() && bytes.Compare(end, it.Key()) > 0 {
		count++
		if count > 10000 { // should not block for more than a second 不应阻塞超过一秒
			if err := batch.Write(); err != nil {
				return err
			}
			return ErrTooManyKeys
		}
		if err := batch.Delete(it.Key()); err != nil {
			return err
		}
	}
	return batch.Write()
}

// NewBatch creates a write-only key-value store that buffers changes to its host
// database until a final write is called.
// NewBatch 创建一个只写的键值存储，将更改缓冲到其宿主数据库，直到调用最终写入。
func (db *Database) NewBatch() ethdb.Batch {
	return &batch{
		db: db.db,
		b:  new(leveldb.Batch),
	}
}

// NewBatchWithSize creates a write-only database batch with pre-allocated buffer.
// NewBatchWithSize 创建一个带有预分配缓冲区的只写数据库批处理。
func (db *Database) NewBatchWithSize(size int) ethdb.Batch {
	return &batch{
		db: db.db,
		b:  leveldb.MakeBatch(size),
	}
}

// NewIterator creates a binary-alphabetical iterator over a subset
// of database content with a particular key prefix, starting at a particular
// initial key (or after, if it does not exist).
// NewIterator 创建一个二进制字母顺序的迭代器，遍历数据库内容的子集，
// 该子集具有特定的键前缀，从特定的初始键开始（或之后，如果该键不存在）。
func (db *Database) NewIterator(prefix []byte, start []byte) ethdb.Iterator {
	return db.db.NewIterator(bytesPrefixRange(prefix, start), nil)
}

// Stat returns the statistic data of the database.
// Stat 返回数据库的统计数据。
func (db *Database) Stat() (string, error) {
	var stats leveldb.DBStats
	if err := db.db.Stats(&stats); err != nil {
		return "", err
	}
	var (
		message       string        // 存储最终输出的统计信息。
		totalRead     int64         // 累积每层的读量。
		totalWrite    int64         // 累积每层的读量。
		totalSize     int64         // 累积每层的大小。
		totalTables   int           // 累积表总数。
		totalDuration time.Duration // 累积压缩时间。
	)
	if len(stats.LevelSizes) > 0 {
		message += " Level |   Tables   |    Size(MB)   |    Time(sec)  |    Read(MB)   |   Write(MB)\n" +
			"-------+------------+---------------+---------------+---------------+---------------\n"
		for level, size := range stats.LevelSizes {
			read := stats.LevelRead[level]
			write := stats.LevelWrite[level]
			duration := stats.LevelDurations[level]
			tables := stats.LevelTablesCounts[level]

			if tables == 0 && duration == 0 {
				continue
			}
			totalTables += tables
			totalSize += size
			totalRead += read
			totalWrite += write
			totalDuration += duration
			message += fmt.Sprintf(" %3d   | %10d | %13.5f | %13.5f | %13.5f | %13.5f\n",
				level, tables, float64(size)/1048576.0, duration.Seconds(),
				float64(read)/1048576.0, float64(write)/1048576.0)
		}
		message += "-------+------------+---------------+---------------+---------------+---------------\n"
		message += fmt.Sprintf(" Total | %10d | %13.5f | %13.5f | %13.5f | %13.5f\n",
			totalTables, float64(totalSize)/1048576.0, totalDuration.Seconds(),
			float64(totalRead)/1048576.0, float64(totalWrite)/1048576.0)
		message += "-------+------------+---------------+---------------+---------------+---------------\n\n"
	}
	message += fmt.Sprintf("Read(MB):%.5f Write(MB):%.5f\n", float64(stats.IORead)/1048576.0, float64(stats.IOWrite)/1048576.0)
	message += fmt.Sprintf("BlockCache(MB):%.5f FileCache:%d\n", float64(stats.BlockCacheSize)/1048576.0, stats.OpenedTablesCount)
	message += fmt.Sprintf("MemoryCompaction:%d Level0Compaction:%d NonLevel0Compaction:%d SeekCompaction:%d\n", stats.MemComp, stats.Level0Comp, stats.NonLevel0Comp, stats.SeekComp)
	message += fmt.Sprintf("WriteDelayCount:%d WriteDelayDuration:%s Paused:%t\n", stats.WriteDelayCount, common.PrettyDuration(stats.WriteDelayDuration), stats.WritePaused)
	message += fmt.Sprintf("Snapshots:%d Iterators:%d\n", stats.AliveSnapshots, stats.AliveIterators)
	return message, nil
}

// Compact flattens the underlying data store for the given key range. In essence,
// deleted and overwritten versions are discarded, and the data is rearranged to
// reduce the cost of operations needed to access them.
//
// A nil start is treated as a key before all keys in the data store; a nil limit
// is treated as a key after all keys in the data store. If both is nil then it
// will compact entire data store.
//
// Compact 压缩指定键范围内的底层数据存储。本质上，删除和覆盖的版本会被丢弃，数据会被重新排列，以降低访问它们所需的操作成本。
// 如果 start 为 nil，则视为数据存储中所有键之前的一个键；如果 limit 为 nil，则视为数据存储中所有键之后的一个键。如果两者均为 nil，则压缩整个数据存储。
// Path 返回数据库目录的路径。
//
// 压缩在以太坊中用于优化状态数据库，减少碎片和历史版本。
// 全范围压缩可清理整个状态数据库。
// 部分范围压缩可针对特定前缀（如账户状态）优化。
// 状态碎片：以太坊状态树随交易更新会产生大量历史版本，压缩可减少存储占用。
// 性能优化：压缩后，读取效率提高，适合长时间运行的节点。
func (db *Database) Compact(start []byte, limit []byte) error {
	return db.db.CompactRange(util.Range{Start: start, Limit: limit})
}

// Path returns the path to the database directory.
// Path 返回数据库目录的路径。
func (db *Database) Path() string {
	return db.fn
}

// meter periodically retrieves internal leveldb counters and reports them to
// the metrics subsystem.
//
// meter 定期检索 LevelDB 内部监控并将其报告给指标子系统。
//
// 用于定期（由 refresh 参数指定）收集 LevelDB 的统计数据并更新指标。它在以太坊节点中用于监控数据库性能。
// 以太坊节点需要实时监控数据库状态，确保同步和交易处理正常。
// TODO learn meter
func (db *Database) meter(refresh time.Duration, namespace string) {
	// Create the counters to store current and previous compaction values
	// 创建计数器以存储当前和之前的压缩值
	compactions := make([][]int64, 2) // 创建二维数组，存储当前和上一次的压缩统计（大小、时间、读写量）。通过对比前后值计算增量，更新指标。
	for i := 0; i < 2; i++ {
		compactions[i] = make([]int64, 4)
	}
	// Create storages for states and warning log tracer.
	// 创建状态和警告日志追踪器的存储
	var (
		errc chan error
		merr error

		stats           leveldb.DBStats // 存储 LevelDB 的统计数据，如层大小、压缩时间等。
		iostats         [2]int64
		delaystats      [2]int64
		lastWritePaused time.Time
	)
	timer := time.NewTimer(refresh) // 定时器控制采集频率。
	defer timer.Stop()

	// Iterate ad infinitum and collect the stats
	// 无限循环并收集统计数据
	for i := 1; errc == nil && merr == nil; i++ {
		// Retrieve the database stats
		// Stats method resets buffers inside therefore it's okay to just pass the struct.
		// 检索数据库统计数据
		// Stats 方法会重置内部缓冲区，因此直接传递结构体是安全的
		err := db.db.Stats(&stats) // 统计数据反映状态树和交易存储的健康状况。
		if err != nil {
			db.log.Error("Failed to read database stats", "err", err)
			merr = err
			continue
		}
		// compactions[i%2][0]：所有层 SSTable 总大小。
		// compactions[i%2][1]：压缩总时间。
		// compactions[i%2][2] 和 [3]：压缩期间的读写量
		// 使用增量（如 compactions[i%2][x] - compactions[(i-1)%2][x]）更新 compTimeMeter、compReadMeter 等

		// Iterate over all the leveldbTable rows, and accumulate the entries
		// 遍历所有 leveldbTable 行，并累加条目
		for j := 0; j < len(compactions[i%2]); j++ {
			compactions[i%2][j] = 0
		}
		compactions[i%2][0] = stats.LevelSizes.Sum()
		for _, t := range stats.LevelDurations {
			compactions[i%2][1] += t.Nanoseconds()
		}
		compactions[i%2][2] = stats.LevelRead.Sum()
		compactions[i%2][3] = stats.LevelWrite.Sum()
		// Update all the requested meters
		// 更新所有请求的仪表
		if db.diskSizeGauge != nil {
			db.diskSizeGauge.Update(compactions[i%2][0])
		}
		if db.compTimeMeter != nil {
			db.compTimeMeter.Mark(compactions[i%2][1] - compactions[(i-1)%2][1])
		}
		if db.compReadMeter != nil {
			db.compReadMeter.Mark(compactions[i%2][2] - compactions[(i-1)%2][2])
		}
		if db.compWriteMeter != nil {
			db.compWriteMeter.Mark(compactions[i%2][3] - compactions[(i-1)%2][3])
		}
		var (
			delayN   = int64(stats.WriteDelayCount) // 记录写入延迟次数。
			duration = stats.WriteDelayDuration     // 记录写入持续时间。
			paused   = stats.WritePaused            // 如果检测到性能下降（paused 为真），每隔 degradationWarnInterval（1 分钟）记录一次警告。
		)
		if db.writeDelayNMeter != nil {
			db.writeDelayNMeter.Mark(delayN - delaystats[0])
		}
		if db.writeDelayMeter != nil {
			db.writeDelayMeter.Mark(duration.Nanoseconds() - delaystats[1])
		}
		// If a warning that db is performing compaction has been displayed, any subsequent
		// warnings will be withheld for one minute not to overwhelm the user.
		// 如果已显示数据库正在执行压缩的警告，后续警告将在1分钟内被抑制，以免使用户不堪重负
		if paused && delayN-delaystats[0] == 0 && duration.Nanoseconds()-delaystats[1] == 0 &&
			time.Now().After(lastWritePaused.Add(degradationWarnInterval)) {
			db.log.Warn("Database compacting, degraded performance")
			lastWritePaused = time.Now()
		}
		delaystats[0], delaystats[1] = delayN, duration.Nanoseconds()

		var (
			nRead  = int64(stats.IORead)
			nWrite = int64(stats.IOWrite)
		)
		if db.diskReadMeter != nil { // 更新实际 IO 量。
			db.diskReadMeter.Mark(nRead - iostats[0])
		}
		if db.diskWriteMeter != nil { // 更新实际 IO 量。
			db.diskWriteMeter.Mark(nWrite - iostats[1])
		}
		iostats[0], iostats[1] = nRead, nWrite

		// 更新各类压缩次数。
		db.memCompGauge.Update(int64(stats.MemComp))
		db.level0CompGauge.Update(int64(stats.Level0Comp))
		db.nonlevel0CompGauge.Update(int64(stats.NonLevel0Comp))
		db.seekCompGauge.Update(int64(stats.SeekComp))

		// levelsGauge：动态扩展数组，记录每层 SSTable 数量。
		for i, tables := range stats.LevelTablesCounts {
			// Append metrics for additional layers
			// 为附加层添加指标
			if i >= len(db.levelsGauge) {
				db.levelsGauge = append(db.levelsGauge, metrics.NewRegisteredGauge(namespace+fmt.Sprintf("tables/level%v", i), nil))
			}
			db.levelsGauge[i].Update(int64(tables))
		}

		// Sleep a bit, then repeat the stats collection
		// 休眠片刻，然后重复统计数据收集
		select {
		case errc = <-db.quitChan:
			// Quit requesting, stop hammering the database
			// 退出请求，停止对数据库的频繁操作
		case <-timer.C:
			timer.Reset(refresh)
			// Timeout, gather a new set of stats
			// 超时，收集新一组统计数据
		}
	}

	if errc == nil {
		errc = <-db.quitChan
	}
	errc <- merr
}

// batch is a write-only leveldb batch that commits changes to its host database
// when Write is called. A batch cannot be used concurrently.
//
// batch 是一个只写的 LevelDB 批处理，在调用 Write 时将其更改提交到宿主数据库。
// 一个批处理不能并发使用。
type batch struct {
	db   *leveldb.DB    // LevelDB 数据库实例
	b    *leveldb.Batch // LevelDB 批处理对象
	size int            // 批处理中数据的总大小
}

// Put inserts the given value into the batch for later committing.
// Put 将给定的值插入批处理中以供稍后提交。
func (b *batch) Put(key, value []byte) error {
	b.b.Put(key, value)
	b.size += len(key) + len(value)
	return nil
}

// Delete inserts the key removal into the batch for later committing.
// Delete 将键的移除操作插入批处理中以供稍后提交。
func (b *batch) Delete(key []byte) error {
	b.b.Delete(key)
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
	return b.db.Write(b.b, nil)
}

// Reset resets the batch for reuse.
// Reset 重置批处理以供重用。
func (b *batch) Reset() {
	b.b.Reset()
	b.size = 0
}

// Replay replays the batch contents.
// Replay 重放批处理内容。
// 将状态从一个存储迁移到另一个（如从 LevelDB 到内存数据库）时使用。
func (b *batch) Replay(w ethdb.KeyValueWriter) error {
	return b.b.Replay(&replayer{writer: w})
}

// 重放机制在以太坊中常用于日志回放（如恢复状态）或测试场景。
// 用于重放状态更新（如交易执行后的账户状态），确保操作顺序一致。
// 日志重放：以太坊节点可能从日志（如 WAL，Write-Ahead Log）中恢复状态，replayer 确保操作按序应用。

// replayer is a small wrapper to implement the correct replay methods.
// replayer 是一个小型包装器，用于实现正确的重放方法。
type replayer struct {
	writer  ethdb.KeyValueWriter // 键值写入器接口
	failure error                // 记录操作失败的错误
}

// Put inserts the given value into the key-value data store.
// Put 将给定的值插入键值数据存储。
func (r *replayer) Put(key, value []byte) {
	// If the replay already failed, stop executing ops
	// 如果重放已失败，停止执行操作
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Put(key, value)
}

// Delete removes the key from the key-value data store.
// Delete 从键值数据存储中移除某个键。
func (r *replayer) Delete(key []byte) {
	// If the replay already failed, stop executing ops
	// 如果重放已失败，停止执行操作
	if r.failure != nil {
		return
	}
	r.failure = r.writer.Delete(key)
}

// 状态树查询：以太坊的状态树（Merkle Patricia Trie）使用键值对存储，键通常带有前缀（如账户地址或存储槽路径）。此函数可用于遍历特定账户的状态。
// 迭代器：生成的 Range 常与 leveldb.Iterator 配合，查询符合条件的键值对。
// 前缀设计：以太坊数据库常按前缀组织数据（如 state: 前缀），此函数支持精确范围定位。

// bytesPrefixRange returns key range that satisfy
// - the given prefix, and
// - the given seek position
//
// bytesPrefixRange 返回满足以下条件的键范围：
// - 给定的前缀，以及
// - 给定的起始位置
//
// 基于给定的前缀和起始位置构造一个键范围，用于 LevelDB 的迭代操作。
// 在以太坊中，键范围常用于查询特定前缀的状态数据（如账户或存储槽）。
func bytesPrefixRange(prefix, start []byte) *util.Range {
	r := util.BytesPrefix(prefix)
	r.Start = append(r.Start, start...)
	return r
}
