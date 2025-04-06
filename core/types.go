// Copyright 2015 The go-ethereum Authors
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
)

// Validator is an interface which defines the standard for block validation. It
// is only responsible for validating block contents, as the header validation is
// done by the specific consensus engines.
// Validator 是一个接口，定义了区块验证的标准。它只负责验证区块内容，
// 而头部验证由特定的共识引擎完成。
type Validator interface {
	// ValidateBody validates the given block's content.
	// ValidateBody 验证给定区块的内容。
	ValidateBody(block *types.Block) error

	// ValidateState validates the given statedb and optionally the process result.
	// ValidateState 验证给定的 statedb 以及可选的处理结果。
	ValidateState(block *types.Block, state *state.StateDB, res *ProcessResult, stateless bool) error
}

// Prefetcher is an interface for pre-caching transaction signatures and state.
// Prefetcher 是一个用于预缓存交易签名和状态的接口。
type Prefetcher interface {
	// Prefetch processes the state changes according to the Ethereum rules by running
	// the transaction messages using the statedb, but any changes are discarded. The
	// only goal is to pre-cache transaction signatures and state trie nodes.
	// Prefetch 通过使用 statedb 运行交易消息，根据以太坊规则处理状态更改，但任何更改都会被丢弃。
	// 唯一的目标是预缓存交易签名和状态 trie 节点。
	Prefetch(block *types.Block, statedb *state.StateDB, cfg vm.Config, interrupt *atomic.Bool)
}

// Processor is an interface for processing blocks using a given initial state.
// Processor 是一个使用给定的初始状态处理区块的接口。
type Processor interface {
	// Process processes the state changes according to the Ethereum rules by running
	// the transaction messages using the statedb and applying any rewards to both
	// the processor (coinbase) and any included uncles.
	// Process 通过使用 statedb 运行交易消息并向处理器（coinbase）和任何包含的叔块应用奖励，
	// 根据以太坊规则处理状态更改。
	Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*ProcessResult, error)
}

// ProcessResult contains the values computed by Process.
// ProcessResult 包含 Process 计算出的值。
type ProcessResult struct {
	Receipts types.Receipts
	Requests [][]byte
	Logs     []*types.Log
	GasUsed  uint64
}
