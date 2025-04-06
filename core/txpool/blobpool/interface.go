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

package blobpool

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// BlockChain defines the minimal set of methods needed to back a blob pool with
// a chain. Exists to allow mocking the live chain out of tests.
// BlockChain 定义了使用链来支持 Blob 池所需的最小方法集合。它的存在是为了允许在测试中模拟真实的链。
type BlockChain interface {
	// Config retrieves the chain's fork configuration.
	// Config 方法检索链的分叉配置。
	Config() *params.ChainConfig

	// CurrentBlock returns the current head of the chain.
	// CurrentBlock 方法返回链的当前头部区块。
	CurrentBlock() *types.Header

	// CurrentFinalBlock returns the current block below which blobs should not
	// be maintained anymore for reorg purposes.
	// CurrentFinalBlock 方法返回当前区块，低于此区块的 Blob 不应再为了应对重组而保留。
	CurrentFinalBlock() *types.Header

	// GetBlock retrieves a specific block, used during pool resets.
	// GetBlock 方法检索一个特定的区块，用于在池重置期间使用。
	GetBlock(hash common.Hash, number uint64) *types.Block

	// StateAt returns a state database for a given root hash (generally the head).
	// StateAt 方法返回给定根哈希（通常是头部区块的根哈希）的状态数据库。
	StateAt(root common.Hash) (*state.StateDB, error)
}
