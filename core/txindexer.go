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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// TxIndexProgress is the struct describing the progress for transaction indexing.
// TxIndexProgress 是描述交易索引进度的结构体。
type TxIndexProgress struct {
	Indexed uint64 // number of blocks whose transactions are indexed
	// Indexed 已索引交易的区块数量。
	Remaining uint64 // number of blocks whose transactions are not indexed yet
	// Remaining 尚未索引交易的区块数量。
}

// Done returns an indicator if the transaction indexing is finished.
// Done 返回一个指示器，表明交易索引是否已完成。
func (progress TxIndexProgress) Done() bool {
	return progress.Remaining == 0
}

// txIndexer is the module responsible for maintaining transaction indexes
// according to the configured indexing range by users.
// txIndexer 是负责根据用户配置的索引范围维护交易索引的模块。
type txIndexer struct {
	// limit is the maximum number of blocks from head whose tx indexes
	// are reserved:
	//  * 0: means the entire chain should be indexed
	//  * N: means the latest N blocks [HEAD-N+1, HEAD] should be indexed
	//       and all others shouldn't.
	// limit 是从头部开始，保留交易索引的最大区块数：
	//  * 0: 表示应该索引整个链。
	//  * N: 表示应该索引最新的 N 个区块 [HEAD-N+1, HEAD]，
	//       所有其他区块都不应该被索引。
	limit    uint64
	db       ethdb.Database
	progress chan chan TxIndexProgress
	term     chan chan struct{}
	closed   chan struct{}
}

// newTxIndexer initializes the transaction indexer.
// newTxIndexer 初始化交易索引器。
func newTxIndexer(limit uint64, chain *BlockChain) *txIndexer {
	indexer := &txIndexer{
		limit:    limit,
		db:       chain.db,
		progress: make(chan chan TxIndexProgress),
		term:     make(chan chan struct{}),
		closed:   make(chan struct{}),
	}
	go indexer.loop(chain)

	var msg string
	if limit == 0 {
		msg = "entire chain"
	} else {
		msg = fmt.Sprintf("last %d blocks", limit)
	}
	log.Info("Initialized transaction indexer", "range", msg)

	return indexer
}

// run executes the scheduled indexing/unindexing task in a separate thread.
// If the stop channel is closed, the task should be terminated as soon as
// possible, the done channel will be closed once the task is finished.
// run 在单独的线程中执行计划的索引/取消索引任务。
// 如果 stop 通道关闭，则应尽快终止任务，任务完成后 done 通道将关闭。
func (indexer *txIndexer) run(tail *uint64, head uint64, stop chan struct{}, done chan struct{}) {
	defer func() { close(done) }()

	// Short circuit if chain is empty and nothing to index.
	// 如果链为空且没有要索引的内容，则直接返回。
	if head == 0 {
		return
	}
	// The tail flag is not existent, it means the node is just initialized
	// and all blocks in the chain (part of them may from ancient store) are
	// not indexed yet, index the chain according to the configured limit.
	// tail 标志不存在，这意味着节点刚刚初始化，并且链中的所有区块（其中一部分可能来自旧存储）
	// 尚未被索引，根据配置的限制索引链。
	if tail == nil {
		from := uint64(0)
		if indexer.limit != 0 && head >= indexer.limit {
			from = head - indexer.limit + 1
		}
		rawdb.IndexTransactions(indexer.db, from, head+1, stop, true)
		return
	}
	// The tail flag is existent (which means indexes in [tail, head] should be
	// present), while the whole chain are requested for indexing.
	// tail 标志存在（这意味着 [tail, head] 中的索引应该存在），而整个链都请求索引。
	if indexer.limit == 0 || head < indexer.limit {
		if *tail > 0 {
			// It can happen when chain is rewound to a historical point which
			// is even lower than the indexes tail, recap the indexing target
			// to new head to avoid reading non-existent block bodies.
			// 当链回滚到甚至低于索引尾部的历史点时，可能会发生这种情况，
			// 将索引目标重新设置为新的头部以避免读取不存在的区块主体。
			end := *tail
			if end > head+1 {
				end = head + 1
			}
			rawdb.IndexTransactions(indexer.db, 0, end, stop, true)
		}
		return
	}
	// The tail flag is existent, adjust the index range according to configured
	// limit and the latest chain head.
	// tail 标志存在，根据配置的限制和最新的链头部调整索引范围。
	if head-indexer.limit+1 < *tail {
		// Reindex a part of missing indices and rewind index tail to HEAD-limit
		// 重新索引一部分缺失的索引并将索引尾部回溯到 HEAD-limit。
		rawdb.IndexTransactions(indexer.db, head-indexer.limit+1, *tail, stop, true)
	} else {
		// Unindex a part of stale indices and forward index tail to HEAD-limit
		// 取消索引一部分过时的索引并将索引尾部向前移动到 HEAD-limit。
		rawdb.UnindexTransactions(indexer.db, *tail, head-indexer.limit+1, stop, false)
	}
}

// loop is the scheduler of the indexer, assigning indexing/unindexing tasks depending
// on the received chain event.
// loop 是索引器的调度器，根据接收到的链事件分配索引/取消索引任务。
func (indexer *txIndexer) loop(chain *BlockChain) {
	defer close(indexer.closed)

	// Listening to chain events and manipulate the transaction indexes.
	// 监听链事件并操作交易索引。
	var (
		stop chan struct{} // Non-nil if background routine is active.
		// stop 如果后台例程处于活动状态，则为非 nil。
		done chan struct{} // Non-nil if background routine is active.
		// done 如果后台例程处于活动状态，则为非 nil。
		lastHead uint64 // The latest announced chain head (whose tx indexes are assumed created)
		// lastHead 最新宣布的链头部（假定其交易索引已创建）。
		lastTail = rawdb.ReadTxIndexTail(indexer.db) // The oldest indexed block, nil means nothing indexed

		headCh = make(chan ChainHeadEvent)
		sub    = chain.SubscribeChainHeadEvent(headCh)
	)
	defer sub.Unsubscribe()

	// Launch the initial processing if chain is not empty (head != genesis).
	// This step is useful in these scenarios that chain has no progress.
	// 如果链不为空（head != genesis），则启动初始处理。
	// 此步骤在链没有进展的情况下很有用。
	if head := rawdb.ReadHeadBlock(indexer.db); head != nil && head.Number().Uint64() != 0 {
		stop = make(chan struct{})
		done = make(chan struct{})
		lastHead = head.Number().Uint64()
		go indexer.run(rawdb.ReadTxIndexTail(indexer.db), head.NumberU64(), stop, done)
	}
	for {
		select {
		case head := <-headCh:
			if done == nil {
				stop = make(chan struct{})
				done = make(chan struct{})
				go indexer.run(rawdb.ReadTxIndexTail(indexer.db), head.Header.Number.Uint64(), stop, done)
			}
			lastHead = head.Header.Number.Uint64()
		case <-done:
			stop = nil
			done = nil
			lastTail = rawdb.ReadTxIndexTail(indexer.db)
		case ch := <-indexer.progress:
			ch <- indexer.report(lastHead, lastTail)
		case ch := <-indexer.term:
			if stop != nil {
				close(stop)
			}
			if done != nil {
				log.Info("Waiting background transaction indexer to exit")
				<-done
			}
			close(ch)
			return
		}
	}
}

// report returns the tx indexing progress.
// report 返回交易索引的进度。
func (indexer *txIndexer) report(head uint64, tail *uint64) TxIndexProgress {
	total := indexer.limit
	if indexer.limit == 0 || total > head {
		total = head + 1 // genesis included
		// 包含创世区块。
	}
	var indexed uint64
	if tail != nil {
		indexed = head - *tail + 1
	}
	// The value of indexed might be larger than total if some blocks need
	// to be unindexed, avoiding a negative remaining.
	// 如果某些区块需要取消索引，则 indexed 的值可能大于 total，从而避免剩余为负数。
	var remaining uint64
	if indexed < total {
		remaining = total - indexed
	}
	return TxIndexProgress{
		Indexed:   indexed,
		Remaining: remaining,
	}
}

// txIndexProgress retrieves the tx indexing progress, or an error if the
// background tx indexer is already stopped.
// txIndexProgress 检索交易索引的进度，如果后台交易索引器已停止，则返回错误。
func (indexer *txIndexer) txIndexProgress() (TxIndexProgress, error) {
	ch := make(chan TxIndexProgress, 1)
	select {
	case indexer.progress <- ch:
		return <-ch, nil
	case <-indexer.closed:
		return TxIndexProgress{}, errors.New("indexer is closed")
	}
}

// close shutdown the indexer. Safe to be called for multiple times.
// close 关闭索引器。可以安全地多次调用。
func (indexer *txIndexer) close() {
	ch := make(chan struct{})
	select {
	case indexer.term <- ch:
		<-ch
	case <-indexer.closed:
	}
}
