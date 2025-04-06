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

package core

import (
	"sync/atomic"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// 状态数据库 (StateDB): 以太坊的状态是存储在 Merkle Patricia Trie 结构中的。当执行交易时，EVM 需要从状态数据库中读取账户信息、合约代码、存储数据等。这些数据可能存储在磁盘上，读取磁盘的延迟会影响交易执行的性能。
// 预取 (Prefetching): 预取是一种常见的性能优化技术。在预测到未来可能需要某些数据时，提前将其加载到更快的存储介质（如内存）中，可以减少实际使用时的等待时间。
// 交易签名: 在执行交易之前，需要验证交易的签名是否有效。预取过程中的 TransactionToMessage 步骤会涉及到交易签名的验证和发送者地址的恢复，这有助于提前将相关数据加载到缓存中。
// 状态 Trie 节点: 以太坊的状态是存储在 Trie 结构中的。执行交易时，可能需要访问 Trie 中的多个节点。预取过程通过模拟执行，可以触发对这些节点的访问，从而将它们加载到内存中。
// 拜占庭分叉 (Byzantium): 拜占庭是以太坊的一个重要硬分叉。在拜占庭分叉前后，以太坊的状态管理和 Gas 消耗等方面发生了一些变化。statePrefetcher 的行为也根据是否在拜占庭分叉之后而有所不同，这主要是因为状态根的计算方式可能有所改变。

// statePrefetcher is a basic Prefetcher, which blindly executes a block on top
// of an arbitrary state with the goal of prefetching potentially useful state
// data from disk before the main block processor start executing.
// statePrefetcher 是一个基本的预取器，它盲目地在一个任意状态之上执行一个区块，
// 目的是在主区块处理器开始执行之前，从磁盘预取可能需要的状态数据。
type statePrefetcher struct {
	config *params.ChainConfig // Chain configuration options
	// config 链配置选项。
	chain *HeaderChain // Canonical block chain
	// chain 规范区块链。
}

// newStatePrefetcher initialises a new statePrefetcher.
// newStatePrefetcher 初始化一个新的 statePrefetcher。
func newStatePrefetcher(config *params.ChainConfig, chain *HeaderChain) *statePrefetcher {
	return &statePrefetcher{
		config: config,
		chain:  chain,
	}
}

// Prefetch processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb, but any changes are discarded. The
// only goal is to pre-cache transaction signatures and state trie nodes.
// Prefetch 通过使用 statedb 运行交易消息，根据以太坊规则处理状态更改，但任何更改都会被丢弃。
// 唯一的目标是预缓存交易签名和状态 trie 节点。
func (p *statePrefetcher) Prefetch(block *types.Block, statedb *state.StateDB, cfg vm.Config, interrupt *atomic.Bool) {
	var (
		header       = block.Header()
		gaspool      = new(GasPool).AddGas(block.GasLimit())
		blockContext = NewEVMBlockContext(header, p.chain, nil)
		evm          = vm.NewEVM(blockContext, statedb, p.config, cfg)
		signer       = types.MakeSigner(p.config, header.Number, header.Time)
	)
	// Iterate over and process the individual transactions
	// 迭代并处理单个交易。
	byzantium := p.config.IsByzantium(block.Number())
	for i, tx := range block.Transactions() {
		// If block precaching was interrupted, abort
		// 如果区块预缓存被中断，则中止。
		if interrupt != nil && interrupt.Load() {
			return
		}
		// Convert the transaction into an executable message and pre-cache its sender
		// 将交易转换为可执行的消息并预缓存其发送者。
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return // Also invalid block, bail out
			// 也是无效的区块，退出。
		}
		statedb.SetTxContext(tx.Hash(), i)

		// We attempt to apply a transaction. The goal is not to execute
		// the transaction successfully, rather to warm up touched data slots.
		// 我们尝试应用一个交易。目标不是成功执行交易，而是预热访问过的数据槽。
		if _, err := ApplyMessage(evm, msg, gaspool); err != nil {
			return // Ugh, something went horribly wrong, bail out
			// 糟糕，出了严重错误，退出。
		}
		// If we're pre-byzantium, pre-load trie nodes for the intermediate root
		// 如果我们处于拜占庭分叉之前，则预加载中间根的 trie 节点。
		if !byzantium {
			statedb.IntermediateRoot(true)
		}
	}
	// If were post-byzantium, pre-load trie nodes for the final root hash
	// 如果我们处于拜占庭分叉之后，则预加载最终根哈希的 trie 节点。
	if byzantium {
		statedb.IntermediateRoot(true)
	}
}
