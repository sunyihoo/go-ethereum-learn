// Copyright 2017 The go-ethereum Authors
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

package legacypool

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// 交易日志 (Transaction Journal)
//
// 这段代码定义了一个 journal 结构体，用于在本地磁盘上持久化存储以太坊交易。其主要目的是确保由本地节点创建但尚未被矿工打包到区块中的交易，在节点意外重启后能够被恢复并重新广播到网络中。这对于提高用户体验和确保交易的可靠性非常重要。
//
// 交易日志的重要性
//
// 当用户通过其本地以太坊节点发送一笔交易时，该交易首先会被广播到网络中的其他节点，并加入到这些节点的交易池（Mempool）中，等待被矿工打包到下一个区块。如果用户的本地节点在交易被打包之前意外崩溃或重启，那么这笔交易可能会丢失，用户需要重新发送。为了避免这种情况，以太坊客户端通常会实现交易日志功能，将本地发送的交易记录到磁盘上。当节点重启后，它可以从日志文件中重新加载这些交易，并将它们重新添加到交易池中，确保交易最终能够被处理。

// errNoActiveJournal is returned if a transaction is attempted to be inserted
// into the journal, but no such file is currently open.
// errNoActiveJournal 在尝试将交易插入日志时返回，但当前没有打开这样的文件。
var errNoActiveJournal = errors.New("no active journal")

// devNull is a WriteCloser that just discards anything written into it. Its
// goal is to allow the transaction journal to write into a fake journal when
// loading transactions on startup without printing warnings due to no file
// being read for write.
// devNull 是一个 WriteCloser，它会丢弃写入其中的任何内容。其目的是允许交易日志在启动时加载交易时写入一个假的日志，
// 而不会因为没有文件被读取以进行写入而打印警告。
type devNull struct{}

func (*devNull) Write(p []byte) (n int, err error) { return len(p), nil }
func (*devNull) Close() error                      { return nil }

// journal is a rotating log of transactions with the aim of storing locally
// created transactions to allow non-executed ones to survive node restarts.
// journal 是一个轮转的交易日志，旨在存储本地创建的交易，以便未执行的交易在节点重启后能够保留。
type journal struct {
	path string // Filesystem path to store the transactions at
	// path 存储交易的文件系统路径。
	writer io.WriteCloser // Output stream to write new transactions into
	// writer 用于写入新交易的输出流。
}

// newTxJournal creates a new transaction journal to
// newTxJournal 创建一个新的交易日志。
func newTxJournal(path string) *journal {
	return &journal{
		path: path,
	}
}

// load parses a transaction journal dump from disk, loading its contents into
// the specified pool.
// load 解析磁盘上的交易日志转储，将其内容加载到指定的池中。
func (journal *journal) load(add func([]*types.Transaction) []error) error {
	// Open the journal for loading any past transactions
	// 打开日志以加载任何过去的交易。
	input, err := os.Open(journal.path)
	if errors.Is(err, fs.ErrNotExist) {
		// Skip the parsing if the journal file doesn't exist at all
		// 如果日志文件根本不存在，则跳过解析。
		return nil
	}
	if err != nil {
		return err
	}
	defer input.Close()

	// Temporarily discard any journal additions (don't double add on load)
	// 临时丢弃任何日志添加（加载时不要重复添加）。
	journal.writer = new(devNull)
	defer func() { journal.writer = nil }()

	// Inject all transactions from the journal into the pool
	// 将日志中的所有交易注入到池中。
	stream := rlp.NewStream(input, 0)
	total, dropped := 0, 0

	// Create a method to load a limited batch of transactions and bump the
	// appropriate progress counters. Then use this method to load all the
	// journaled transactions in small-ish batches.
	// 创建一个方法来加载有限批次的交易并增加相应的进度计数器。然后使用此方法以较小的批次加载所有记录在日志中的交易。
	loadBatch := func(txs types.Transactions) {
		for _, err := range add(txs) {
			if err != nil {
				log.Debug("Failed to add journaled transaction", "err", err)
				dropped++
			}
		}
	}
	var (
		failure error
		batch   types.Transactions
	)
	for {
		// Parse the next transaction and terminate on error
		// 解析下一个交易，并在发生错误时终止。
		tx := new(types.Transaction)
		if err = stream.Decode(tx); err != nil {
			if err != io.EOF {
				failure = err
			}
			if batch.Len() > 0 {
				loadBatch(batch)
			}
			break
		}
		// New transaction parsed, queue up for later, import if threshold is reached
		// 解析到新的交易，将其排队等待稍后导入，如果达到阈值则立即导入。
		total++

		if batch = append(batch, tx); batch.Len() > 1024 {
			loadBatch(batch)
			batch = batch[:0]
		}
	}
	log.Info("Loaded local transaction journal", "transactions", total, "dropped", dropped)
	// 记录信息：已加载本地交易日志，显示加载的交易总数和丢弃的交易数量。

	return failure
}

// insert adds the specified transaction to the local disk journal.
// insert 将指定的交易添加到本地磁盘日志。
func (journal *journal) insert(tx *types.Transaction) error {
	if journal.writer == nil {
		return errNoActiveJournal // Return error if no journal file is currently open for writing.
		// 如果当前没有打开任何日志文件进行写入，则返回错误。
	}
	if err := rlp.Encode(journal.writer, tx); err != nil {
		return err // Encode and write the transaction to the journal.
		// 将交易编码并写入日志。
	}
	return nil
}

// rotate regenerates the transaction journal based on the current contents of
// the transaction pool.
// rotate 基于当前交易池的内容重新生成交易日志。
func (journal *journal) rotate(all map[common.Address]types.Transactions) error {
	// Close the current journal (if any is open)
	// 关闭当前的日志（如果已打开）。
	if journal.writer != nil {
		if err := journal.writer.Close(); err != nil {
			return err
		}
		journal.writer = nil
	}
	// Generate a new journal with the contents of the current pool
	// 使用当前池的内容生成一个新的日志。
	replacement, err := os.OpenFile(journal.path+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	journaled := 0
	for _, txs := range all {
		for _, tx := range txs {
			if err = rlp.Encode(replacement, tx); err != nil {
				replacement.Close()
				return err
			}
		}
		journaled += len(txs)
	}
	replacement.Close()

	// Replace the live journal with the newly generated one
	// 将活动的日志替换为新生成的日志。
	if err = os.Rename(journal.path+".new", journal.path); err != nil {
		return err
	}
	sink, err := os.OpenFile(journal.path, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	journal.writer = sink

	logger := log.Info
	if len(all) == 0 {
		logger = log.Debug
	}
	logger("Regenerated local transaction journal", "transactions", journaled, "accounts", len(all))
	// 记录信息：已重新生成本地交易日志，显示记录的交易数量和账户数量。

	return nil
}

// close flushes the transaction journal contents to disk and closes the file.
// close 将交易日志内容刷新到磁盘并关闭文件。
func (journal *journal) close() error {
	var err error

	if journal.writer != nil {
		err = journal.writer.Close()
		journal.writer = nil
	}
	return err
}
