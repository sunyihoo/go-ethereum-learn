// Copyright 2020 The go-ethereum Authors
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

package rawdb

import (
	"runtime"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/prque"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// InitDatabaseFromFreezer reinitializes an empty database from a previous batch
// of frozen ancient blocks. The method iterates over all the frozen blocks and
// injects into the database the block hash->number mappings.
//
// InitDatabaseFromFreezer 从先前批次冻结的古老区块重新初始化一个空数据库。
// 该方法遍历所有冻结的区块，并将块哈希和编号的映射写入数据库。
func InitDatabaseFromFreezer(db ethdb.Database) {
	// If we can't access the freezer or it's empty, abort
	// 如果无法访问冷冻存储或其为空，则中止。
	frozen, err := db.Ancients() // 获取已冻结的区块数量
	if err != nil || frozen == 0 {
		return
	}
	var (
		batch  = db.NewBatch()               // 创建一个新的写入批次
		start  = time.Now()                  // 记录开始时间
		logged = start.Add(-7 * time.Second) // Unindex during import is fast, don't double log  为了避免日志重复，记录时间
		hash   common.Hash                   // 用于存储当前块的哈希
	)
	for i := uint64(0); i < frozen; {
		// We read 100K hashes at a time, for a total of 3.2M
		// 每次读取100K个哈希，总共可以读取最多3.2M。
		count := uint64(100_000) // 每批次数量
		if i+count > frozen {    // 确保不超出已冻结数量
			count = frozen - i
		}
		data, err := db.AncientRange(ChainFreezerHashTable, i, count, 32*count) // 读取古老哈希表
		if err != nil {
			log.Crit("Failed to init database from freezer", "err", err)
		}
		for j, h := range data { // 遍历读取的哈希
			number := i + uint64(j)
			hash = common.BytesToHash(h)           // 转换为 Hash 类型
			WriteHeaderNumber(batch, hash, number) // 写入哈希与编号的映射
			// If enough data was accumulated in memory or we're at the last block, dump to disk
			// 如果内存中的数据足够或到了最后一个区块，则写入磁盘
			if batch.ValueSize() > ethdb.IdealBatchSize { // 检查是否超过理想批量大小
				if err := batch.Write(); err != nil {
					log.Crit("Failed to write data to db", "err", err)
				}
				batch.Reset() // 重置写入批次
			}
		}
		i += uint64(len(data)) // 增加已处理块的数量
		// If we've spent too much time already, notify the user of what we're doing
		// 如果花费的时间太久，通知用户发生的操作
		if time.Since(logged) > 8*time.Second {
			log.Info("Initializing database from freezer", "total", frozen, "number", i, "hash", hash, "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now() // 更新最后记录时间
		}
	}
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write data to db", "err", err)
	}
	batch.Reset()

	WriteHeadHeaderHash(db, hash)    // 写入头区块的哈希
	WriteHeadFastBlockHash(db, hash) // 写入快速区块的哈希
	log.Info("Initialized database from freezer", "blocks", frozen, "elapsed", common.PrettyDuration(time.Since(start)))
}

type blockTxHashes struct {
	number uint64        // 该区块的编号
	hashes []common.Hash // 该区块中的事务哈希
}

// iterateTransactions iterates over all transactions in the (canon) block
// number(s) given, and yields the hashes on a channel. If there is a signal
// received from interrupt channel, the iteration will be aborted and result
// channel will be closed.
//
// iterateTransactions 遍历给定区块数字中的所有事务，并在通道中返回哈希。
// 如果从 interrupt 通道接收到信号，迭代将被中止，结果通道将被关闭。
func iterateTransactions(db ethdb.Database, from uint64, to uint64, reverse bool, interrupt chan struct{}) chan *blockTxHashes {
	// One thread sequentially reads data from db
	// 一个线程顺序地从数据库中读取数据
	type numberRlp struct {
		number uint64       // 区块编号
		rlp    rlp.RawValue // RLP 编码的区块值
	}
	if to == from {
		return nil // 如果范围无效，返回 nil
	}
	threads := to - from // 计算线程数量
	if cpus := runtime.NumCPU(); threads > uint64(cpus) {
		threads = uint64(cpus) // 限制线程数量为 CPU 核心数
	}
	var (
		rlpCh    = make(chan *numberRlp, threads*2)     // we send raw rlp over this channel // 用于传递 RLP 编码数据的通道
		hashesCh = make(chan *blockTxHashes, threads*2) // send hashes over hashesCh  // 用于传递事务哈希的通道
	)
	// lookup runs in one instance
	lookup := func() {
		n, end := from, to
		if reverse {
			n, end = to-1, from-1 // 如果是反向迭代，取反向参数
		}
		defer close(rlpCh)
		for n != end {
			data := ReadCanonicalBodyRLP(db, n) // 读取 RLP 编码的区块体
			// Feed the block to the aggregator, or abort on interrupt
			select {
			case rlpCh <- &numberRlp{n, data}: // 将数据传递至 RLP 通道
			case <-interrupt: // 检查中断信号
				return
			}
			if reverse {
				n-- // 如果是反向迭代，递减编号
			} else {
				n++ // 正向迭代，递增编号
			}
		}
	}
	// process runs in parallel
	var nThreadsAlive atomic.Int32 // 初始化活动线程计数
	nThreadsAlive.Store(int32(threads))
	process := func() {
		defer func() {
			// Last processor closes the result channel
			if nThreadsAlive.Add(-1) == 0 {
				close(hashesCh) // 最后一个处理器关闭结果通道
			}
		}()
		for data := range rlpCh { // 从 RLP 通道读取数据
			var body types.Body
			if err := rlp.DecodeBytes(data.rlp, &body); err != nil {
				log.Warn("Failed to decode block body", "block", data.number, "error", err)
				return
			}
			var hashes []common.Hash
			for _, tx := range body.Transactions { // 遍历区块中的每个事务
				hashes = append(hashes, tx.Hash()) // 获取事务哈希并加入数组
			}
			result := &blockTxHashes{
				hashes: hashes,      // 存储事务哈希
				number: data.number, // 存储区块编号
			}
			// Feed the block to the aggregator, or abort on interrupt
			select {
			case hashesCh <- result: // 将结果发送至哈希通道
			case <-interrupt:
				return
			}
		}
	}
	go lookup() // start the sequential db accessor 启动顺序数据读取
	for i := 0; i < int(threads); i++ {
		go process() // 启动并行处理
	}
	return hashesCh // 返回哈希通道
}

// indexTransactions creates txlookup indices of the specified block range.
//
// This function iterates canonical chain in reverse order, it has one main advantage:
// We can write tx index tail flag periodically even without the whole indexing
// procedure is finished. So that we can resume indexing procedure next time quickly.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
//
// indexTransactions 为指定区块范围创建事务查找索引。
//
// 此函数以反向顺序遍历规范链，有一个主要优点：
// 我们可以定期写入事务索引尾标志，即使整个索引过程尚未完成。
// 所以我们可以快速恢复索引过程。
//
// 传递的通道会在接收到信号时中断整个过程。
func indexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool, report bool) {
	// short circuit for invalid range
	// 对于无效范围直接返回
	if from >= to {
		return
	}
	var (
		hashesCh = iterateTransactions(db, from, to, true, interrupt) // 启动迭代事务的通道
		batch    = db.NewBatch()                                      // 创建一个新的写入批次
		start    = time.Now()                                         // 记录开始时间
		logged   = start.Add(-7 * time.Second)                        // 记录上一次日志的时间

		// Since we iterate in reverse, we expect the first number to come
		// in to be [to-1]. Therefore, setting lastNum to means that the
		// queue gap-evaluation will work correctly
		// 因为我们以反向顺序遍历，期望第一个到达的编号是 [to-1]。
		// 因此，将 lastNum 设置为 to 可以确保队列断裂评估正常工作
		lastNum     = to
		queue       = prque.New[int64, *blockTxHashes](nil) // 初始化一个优先级队列
		blocks, txs = 0, 0                                  // for stats reporting 用于统计报告
	)
	for chanDelivery := range hashesCh { // 遍历哈希通道中的数据
		// Push the delivery into the queue and process contiguous ranges.
		// Since we iterate in reverse, so lower numbers have lower prio, and
		// we can use the number directly as prio marker
		// 将数据推入队列并处理连续范围。
		queue.Push(chanDelivery, int64(chanDelivery.number)) // 根据区块编号设置优先级
		for !queue.Empty() {
			// If the next available item is gapped, return
			// 如果下一个可用项目存在间隔，则返回
			if _, priority := queue.Peek(); priority != int64(lastNum-1) {
				break
			}
			// For testing
			if hook != nil && !hook(lastNum-1) {
				break
			}
			// Next block available, pop it off and index it
			// 下一个可用的块，弹出并索引它
			delivery := queue.PopItem()
			lastNum = delivery.number
			WriteTxLookupEntries(batch, delivery.number, delivery.hashes) // 写入事务查找条目
			blocks++
			txs += len(delivery.hashes) // 累加事务数量
			// If enough data was accumulated in memory or we're at the last block, dump to disk
			// 如果内存中积累的数据足够或处于最后一个区块，则写入磁盘
			if batch.ValueSize() > ethdb.IdealBatchSize {
				WriteTxIndexTail(batch, lastNum) // Also write the tail here 同时写入尾标记
				if err := batch.Write(); err != nil {
					log.Crit("Failed writing batch to db", "error", err)
					return
				}
				batch.Reset() // 重置写入批次
			}
			// If we've spent too much time already, notify the user of what we're doing
			// 如果花费的时间太久，通知用户
			if time.Since(logged) > 8*time.Second {
				log.Info("Indexing transactions", "blocks", blocks, "txs", txs, "tail", lastNum, "total", to-from, "elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now() // 更新日志时间
			}
		}
	}
	// Flush the new indexing tail and the last committed data. It can also happen
	// that the last batch is empty because nothing to index, but the tail has to
	// be flushed anyway.
	WriteTxIndexTail(batch, lastNum) // 写入新的索引尾标记
	if err := batch.Write(); err != nil {
		log.Crit("Failed writing batch to db", "error", err)
		return
	}
	logger := log.Debug // 设置日志级别为调试
	if report {
		logger = log.Info // 如果需要报告，则设置为信息级别
	}
	select {
	case <-interrupt:
		logger("Transaction indexing interrupted", "blocks", blocks, "txs", txs, "tail", lastNum, "elapsed", common.PrettyDuration(time.Since(start)))
	default:
		logger("Indexed transactions", "blocks", blocks, "txs", txs, "tail", lastNum, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

// IndexTransactions creates txlookup indices of the specified block range. The from
// is included while to is excluded.
//
// This function iterates canonical chain in reverse order, it has one main advantage:
// We can write tx index tail flag periodically even without the whole indexing
// procedure is finished. So that we can resume indexing procedure next time quickly.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// IndexTransactions 创建指定区块范围的事务查找索引。from 包含，而 to 不包含。
//
// 此函数以反向顺序遍历规范链，有一个主要优点：
// 我们可以定期写入事务索引尾标志，即使整个索引过程尚未完成。
// 所以我们可以快速恢复索引过程。
//
// 传递的通道会在接收到信号时中断整个过程。
func IndexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, report bool) {
	indexTransactions(db, from, to, interrupt, nil, report)
}

// indexTransactionsForTesting is the internal debug version with an additional hook.
func indexTransactionsForTesting(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	indexTransactions(db, from, to, interrupt, hook, false)
}

// unindexTransactions removes txlookup indices of the specified block range.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
// unindexTransactions 移除指定区块范围的事务查找索引。
//
// 传递的通道会在接收到信号时中断整个过程。
func unindexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool, report bool) {
	// short circuit for invalid range
	// 对于无效范围直接返回
	if from >= to {
		return
	}
	var (
		hashesCh = iterateTransactions(db, from, to, false, interrupt) // 启动迭代事务的通道
		batch    = db.NewBatch()                                       // 创建一个新的写入批次
		start    = time.Now()                                          // 记录开始时间
		logged   = start.Add(-7 * time.Second)                         // 记录上一次日志时间

		// we expect the first number to come in to be [from]. Therefore, setting
		// nextNum to from means that the queue gap-evaluation will work correctly
		// 我们期望第一个到达的编号为 [from]。因此，将 nextNum 设置为 [from] 表示队列间隙评估将正确工作
		nextNum     = from
		queue       = prque.New[int64, *blockTxHashes](nil)
		blocks, txs = 0, 0 // for stats reporting
	)
	// Otherwise spin up the concurrent iterator and unindexer
	for delivery := range hashesCh {
		// Push the delivery into the queue and process contiguous ranges.
		queue.Push(delivery, -int64(delivery.number))
		for !queue.Empty() {
			// If the next available item is gapped, return
			if _, priority := queue.Peek(); -priority != int64(nextNum) {
				break
			}
			// For testing
			if hook != nil && !hook(nextNum) {
				break
			}
			delivery := queue.PopItem()
			nextNum = delivery.number + 1
			DeleteTxLookupEntries(batch, delivery.hashes)
			txs += len(delivery.hashes)
			blocks++

			// If enough data was accumulated in memory or we're at the last block, dump to disk
			// A batch counts the size of deletion as '1', so we need to flush more
			// often than that.
			// 如果内存中积累的数据足够或处于最后一个区块，则写入磁盘
			if blocks%1000 == 0 {
				WriteTxIndexTail(batch, nextNum)
				if err := batch.Write(); err != nil {
					log.Crit("Failed writing batch to db", "error", err)
					return
				}
				batch.Reset()
			}
			// If we've spent too much time already, notify the user of what we're doing
			// 如果花费的时间太久，通知用户
			if time.Since(logged) > 8*time.Second {
				log.Info("Unindexing transactions", "blocks", blocks, "txs", txs, "total", to-from, "elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
		}
	}
	// Flush the new indexing tail and the last committed data. It can also happen
	// that the last batch is empty because nothing to unindex, but the tail has to
	// be flushed anyway.
	WriteTxIndexTail(batch, nextNum)
	if err := batch.Write(); err != nil {
		log.Crit("Failed writing batch to db", "error", err)
		return
	}
	logger := log.Debug
	if report {
		logger = log.Info
	}
	select {
	case <-interrupt:
		logger("Transaction unindexing interrupted", "blocks", blocks, "txs", txs, "tail", to, "elapsed", common.PrettyDuration(time.Since(start)))
	default:
		logger("Unindexed transactions", "blocks", blocks, "txs", txs, "tail", to, "elapsed", common.PrettyDuration(time.Since(start)))
	}
}

// UnindexTransactions removes txlookup indices of the specified block range.
// The from is included while to is excluded.
//
// There is a passed channel, the whole procedure will be interrupted if any
// signal received.
//
// 此函数以反向顺序遍历规范链，有一个主要优点：
// 我们可以定期写入事务索引尾标志，即使整个索引过程尚未完成。
// 所以我们可以快速恢复索引过程。
//
// 传递的通道会在接收到信号时中断整个过程。
func UnindexTransactions(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, report bool) {
	unindexTransactions(db, from, to, interrupt, nil, report)
}

// unindexTransactionsForTesting is the internal debug version with an additional hook.
func unindexTransactionsForTesting(db ethdb.Database, from uint64, to uint64, interrupt chan struct{}, hook func(uint64) bool) {
	unindexTransactions(db, from, to, interrupt, hook, false)
}
