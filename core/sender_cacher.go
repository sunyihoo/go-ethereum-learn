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
	"runtime"

	"github.com/ethereum/go-ethereum/core/types"
)

// SenderCacher is a concurrent transaction sender recoverer and cacher.
// SenderCacher 是一个并发的交易发送者恢复器和缓存器。
var SenderCacher = newTxSenderCacher(runtime.NumCPU())

// txSenderCacherRequest is a request for recovering transaction senders with a
// specific signature scheme and caching it into the transactions themselves.
//
// The inc field defines the number of transactions to skip after each recovery,
// which is used to feed the same underlying input array to different threads but
// ensure they process the early transactions fast.
// txSenderCacherRequest 是一个请求，用于使用特定的签名方案恢复交易发送者，并将其缓存到交易本身中。
//
// inc 字段定义了每次恢复后要跳过的交易数量，用于将相同的底层输入数组提供给不同的线程，
// 但确保它们快速处理早期的交易。
type txSenderCacherRequest struct {
	signer types.Signer
	txs    []*types.Transaction
	inc    int
}

// txSenderCacher is a helper structure to concurrently ecrecover transaction
// senders from digital signatures on background threads.
// txSenderCacher 是一个辅助结构，用于在后台线程上并发地从数字签名中恢复交易发送者。
type txSenderCacher struct {
	threads int
	tasks   chan *txSenderCacherRequest
}

// newTxSenderCacher creates a new transaction sender background cacher and starts
// as many processing goroutines as allowed by the GOMAXPROCS on construction.
// newTxSenderCacher 创建一个新的交易发送者后台缓存器，并在创建时启动与 GOMAXPROCS 允许数量一样多的处理 goroutine。
func newTxSenderCacher(threads int) *txSenderCacher {
	cacher := &txSenderCacher{
		tasks:   make(chan *txSenderCacherRequest, threads),
		threads: threads,
	}
	for i := 0; i < threads; i++ {
		go cacher.cache()
	}
	return cacher
}

// cache is an infinite loop, caching transaction senders from various forms of
// data structures.
// cache 是一个无限循环，用于从各种形式的数据结构中缓存交易发送者。
func (cacher *txSenderCacher) cache() {
	for task := range cacher.tasks {
		for i := 0; i < len(task.txs); i += task.inc {
			types.Sender(task.signer, task.txs[i])
		}
	}
}

// Recover recovers the senders from a batch of transactions and caches them
// back into the same data structures. There is no validation being done, nor
// any reaction to invalid signatures. That is up to calling code later.
// Recover 从一批交易中恢复发送者，并将它们缓存回相同的数据结构中。
// 这里不进行任何验证，也不对无效签名做出任何反应。这些都留给后面的调用代码处理。
func (cacher *txSenderCacher) Recover(signer types.Signer, txs []*types.Transaction) {
	// If there's nothing to recover, abort
	// 如果没有需要恢复的，则中止。
	if len(txs) == 0 {
		return
	}
	// Ensure we have meaningful task sizes and schedule the recoveries
	// 确保我们有合理的任务大小并安排恢复操作。
	tasks := cacher.threads
	if len(txs) < tasks*4 {
		tasks = (len(txs) + 3) / 4
	}
	for i := 0; i < tasks; i++ {
		cacher.tasks <- &txSenderCacherRequest{
			signer: signer,
			txs:    txs[i:],
			inc:    tasks,
		}
	}
}

// RecoverFromBlocks recovers the senders from a batch of blocks and caches them
// back into the same data structures. There is no validation being done, nor
// any reaction to invalid signatures. That is up to calling code later.
// RecoverFromBlocks 从一批区块中恢复发送者，并将它们缓存回相同的数据结构中。
// 这里不进行任何验证，也不对无效签名做出任何反应。这些都留给后面的调用代码处理。
func (cacher *txSenderCacher) RecoverFromBlocks(signer types.Signer, blocks []*types.Block) {
	count := 0
	for _, block := range blocks {
		count += len(block.Transactions())
	}
	txs := make([]*types.Transaction, 0, count)
	for _, block := range blocks {
		txs = append(txs, block.Transactions()...)
	}
	cacher.Recover(signer, txs)
}
