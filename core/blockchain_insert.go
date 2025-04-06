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

package core

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// 区块链同步: 以太坊节点在启动或与网络断开后重新连接时，需要同步最新的区块链数据。这个过程涉及到下载、验证和导入大量的区块。insertStats 和 insertIterator 就是在这个过程中使用的工具。
// 区块验证: 在导入区块时，节点需要对接收到的区块进行验证，以确保其符合共识规则并且是有效的。这包括验证区块头部的 PoW (或 PoS) 证明、交易的签名、以及执行区块中的交易后状态的正确性。insertIterator 负责管理这个验证过程，并处理验证结果。
// 性能监控: insertStats 提供的统计信息对于监控同步过程的性能非常有用。通过查看处理速度、Gas 使用情况等指标，可以帮助开发者和运维人员了解节点的运行状况，并在出现问题时进行诊断。
// 用户反馈: statsReportLimit 确保即使在处理速度较慢的情况下，用户也能定期看到同步的进度信息，从而提高用户体验。

// insertStats tracks and reports on block insertion.
// insertStats 跟踪并报告区块插入的情况。
type insertStats struct {
	queued, processed, ignored int
	usedGas                    uint64
	lastIndex                  int
	startTime                  mclock.AbsTime
}

// statsReportLimit is the time limit during import and export after which we
// always print out progress. This avoids the user wondering what's going on.
// statsReportLimit 是导入和导出期间的时间限制，超过此限制后我们总是会打印进度。
// 这避免了用户疑惑发生了什么。
const statsReportLimit = 8 * time.Second

// report prints statistics if some number of blocks have been processed
// or more than a few seconds have passed since the last message.
// 如果已处理一定数量的区块或自上次消息以来已过去几秒钟以上，则 report 会打印统计信息。
func (st *insertStats) report(chain []*types.Block, index int, snapDiffItems, snapBufItems, trieDiffNodes, triebufNodes common.StorageSize, setHead bool) {
	// Fetch the timings for the batch
	// 获取批处理的时序。
	var (
		now     = mclock.Now()
		elapsed = now.Sub(st.startTime)
	)
	// If we're at the last block of the batch or report period reached, log
	// 如果我们处于批处理的最后一个区块或已达到报告周期，则记录。
	if index == len(chain)-1 || elapsed >= statsReportLimit {
		// Count the number of transactions in this segment
		// 计算此段中的交易数量。
		var txs int
		for _, block := range chain[st.lastIndex : index+1] {
			txs += len(block.Transactions())
		}
		end := chain[index]

		// Assemble the log context and send it to the logger
		// 组装日志上下文并将其发送给记录器。
		context := []interface{}{
			"number", end.Number(), "hash", end.Hash(),
			"blocks", st.processed, "txs", txs, "mgas", float64(st.usedGas) / 1000000,
			"elapsed", common.PrettyDuration(elapsed), "mgasps", float64(st.usedGas) * 1000 / float64(elapsed),
		}
		if timestamp := time.Unix(int64(end.Time()), 0); time.Since(timestamp) > time.Minute {
			context = append(context, []interface{}{"age", common.PrettyAge(timestamp)}...)
		}
		if snapDiffItems != 0 || snapBufItems != 0 { // snapshots enabled
			context = append(context, []interface{}{"snapdiffs", snapDiffItems}...)
			if snapBufItems != 0 { // future snapshot refactor
				context = append(context, []interface{}{"snapdirty", snapBufItems}...)
			}
		}
		if trieDiffNodes != 0 { // pathdb
			context = append(context, []interface{}{"triediffs", trieDiffNodes}...)
		}
		context = append(context, []interface{}{"triedirty", triebufNodes}...)

		if st.queued > 0 {
			context = append(context, []interface{}{"queued", st.queued}...)
		}
		if st.ignored > 0 {
			context = append(context, []interface{}{"ignored", st.ignored}...)
		}
		if setHead {
			log.Info("Imported new chain segment", context...)
		} else {
			log.Info("Imported new potential chain segment", context...)
		}
		// Bump the stats reported to the next section
		// 将报告的统计信息更新到下一节。
		*st = insertStats{startTime: now, lastIndex: index + 1}
	}
}

// insertIterator is a helper to assist during chain import.
// insertIterator 是在链导入期间提供帮助的辅助工具。
type insertIterator struct {
	chain types.Blocks // Chain of blocks being iterated over
	// chain 正在迭代的区块链。

	results <-chan error // Verification result sink from the consensus engine
	// results 来自共识引擎的验证结果接收通道。
	errors []error // Header verification errors for the blocks
	// errors 区块的头部验证错误。

	index int // Current offset of the iterator
	// index 迭代器的当前偏移量。
	validator Validator // Validator to run if verification succeeds
	// validator 如果验证成功则运行的验证器。
}

// newInsertIterator creates a new iterator based on the given blocks, which are
// assumed to be a contiguous chain.
// newInsertIterator 基于给定的区块创建一个新的迭代器，这些区块被假定为连续的链。
func newInsertIterator(chain types.Blocks, results <-chan error, validator Validator) *insertIterator {
	return &insertIterator{
		chain:     chain,
		results:   results,
		errors:    make([]error, 0, len(chain)),
		index:     -1,
		validator: validator,
	}
}

// next returns the next block in the iterator, along with any potential validation
// error for that block. When the end is reached, it will return (nil, nil).
// next 返回迭代器中的下一个区块，以及该区块的任何潜在验证错误。到达末尾时，将返回 (nil, nil)。
func (it *insertIterator) next() (*types.Block, error) {
	// If we reached the end of the chain, abort
	// 如果我们到达链的末尾，则中止。
	if it.index+1 >= len(it.chain) {
		it.index = len(it.chain)
		return nil, nil
	}
	// Advance the iterator and wait for verification result if not yet done
	// 前进迭代器，如果尚未完成，则等待验证结果。
	it.index++
	if len(it.errors) <= it.index {
		it.errors = append(it.errors, <-it.results)
	}
	if it.errors[it.index] != nil {
		return it.chain[it.index], it.errors[it.index]
	}
	// Block header valid, run body validation and return
	// 区块头有效，运行区块体验证并返回。
	return it.chain[it.index], it.validator.ValidateBody(it.chain[it.index])
}

// peek returns the next block in the iterator, along with any potential validation
// error for that block, but does **not** advance the iterator.
// peek 返回迭代器中的下一个区块，以及该区块的任何潜在验证错误，但 **不会** 前进迭代器。
//
// Both header and body validation errors (nil too) is cached into the iterator
// to avoid duplicating work on the following next() call.
// 头部和区块体验证错误（包括 nil）都被缓存到迭代器中，以避免在后续的 next() 调用中重复工作。
func (it *insertIterator) peek() (*types.Block, error) {
	// If we reached the end of the chain, abort
	// 如果我们到达链的末尾，则中止。
	if it.index+1 >= len(it.chain) {
		return nil, nil
	}
	// Wait for verification result if not yet done
	// 如果尚未完成，则等待验证结果。
	if len(it.errors) <= it.index+1 {
		it.errors = append(it.errors, <-it.results)
	}
	if it.errors[it.index+1] != nil {
		return it.chain[it.index+1], it.errors[it.index+1]
	}
	// Block header valid, ignore body validation since we don't have a parent anyway
	// 区块头有效，由于我们无论如何都没有父区块，因此忽略区块体验证。
	return it.chain[it.index+1], nil
}

// previous returns the previous header that was being processed, or nil.
// previous 返回正在处理的上一个头部，如果不存在则返回 nil。
func (it *insertIterator) previous() *types.Header {
	if it.index < 1 {
		return nil
	}
	return it.chain[it.index-1].Header()
}

// current returns the current header that is being processed, or nil.
// current 返回当前正在处理的头部，如果不存在则返回 nil。
func (it *insertIterator) current() *types.Header {
	if it.index == -1 || it.index >= len(it.chain) {
		return nil
	}
	return it.chain[it.index].Header()
}

// remaining returns the number of remaining blocks.
// remaining 返回剩余的区块数量。
func (it *insertIterator) remaining() int {
	return len(it.chain) - it.index
}
