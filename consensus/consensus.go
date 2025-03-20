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

// Package consensus implements different Ethereum consensus engines.
package consensus

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// ChainHeaderReader defines a small collection of methods needed to access the local
// blockchain during header verification.
// ChainHeaderReader 定义了在 Header 验证期间访问本地区块链所需的一小部分方法。
type ChainHeaderReader interface {
	// Config retrieves the blockchain's chain configuration.
	// Config 获取区块链的链配置。
	Config() *params.ChainConfig

	// CurrentHeader retrieves the current header from the local chain.
	// CurrentHeader 从本地区块链中获取当前区块头。
	CurrentHeader() *types.Header

	// GetHeader retrieves a block header from the database by hash and number.
	// GetHeader 通过哈希和编号从数据库中检索一个区块头。
	GetHeader(hash common.Hash, number uint64) *types.Header

	// GetHeaderByNumber retrieves a block header from the database by number.
	// GetHeaderByNumber 通过编号从数据库中检索一个区块头。
	GetHeaderByNumber(number uint64) *types.Header

	// GetHeaderByHash retrieves a block header from the database by its hash.
	// GetHeaderByHash 通过哈希从数据库中检索一个区块头。
	GetHeaderByHash(hash common.Hash) *types.Header

	// GetTd retrieves the total difficulty from the database by hash and number.
	// GetTd 通过哈希和编号从数据库中检索总难度（Total Difficulty）。
	GetTd(hash common.Hash, number uint64) *big.Int
}

// ChainReader defines a small collection of methods needed to access the local
// blockchain during header and/or uncle verification.
// ChainReader 定义了在区块头（header）和/或叔块（uncle）验证期间访问本地区块链所需的一小部分方法。
type ChainReader interface {
	ChainHeaderReader

	// GetBlock retrieves a block from the database by hash and number.
	// GetBlock 通过哈希和编号从数据库中检索一个区块。
	GetBlock(hash common.Hash, number uint64) *types.Block
}

// Engine is an algorithm agnostic consensus engine.
// Engine 是一个与算法无关的共识引擎。
type Engine interface {
	// Author retrieves the Ethereum address of the account that minted the given
	// block, which may be different from the header's coinbase if a consensus
	// engine is based on signatures.
	// Author 检索挖出给定区块的账户的以太坊地址，如果基于签名的共识引擎可能与区块头的 coinbase 不同。
	Author(header *types.Header) (common.Address, error)

	// VerifyHeader checks whether a header conforms to the consensus rules of a
	// given engine.
	// VerifyHeader 检查一个区块头是否符合给定引擎的共识规则。
	VerifyHeader(chain ChainHeaderReader, header *types.Header) error

	// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
	// concurrently. The method returns a quit channel to abort the operations and
	// a results channel to retrieve the async verifications (the order is that of
	// the input slice).
	// VerifyHeaders 类似于 VerifyHeader，但并发地验证一批区块头。该方法返回一个用于中止操作的退出通道和一个用于获取异步验证结果的结果通道（顺序与输入切片相同）。
	VerifyHeaders(chain ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error)

	// VerifyUncles verifies that the given block's uncles conform to the consensus
	// rules of a given engine.
	// VerifyUncles 验证给定区块的叔块是否符合给定引擎的共识规则。
	VerifyUncles(chain ChainReader, block *types.Block) error

	// Prepare initializes the consensus fields of a block header according to the
	// rules of a particular engine. The changes are executed inline.
	// Prepare 根据特定引擎的规则初始化一个区块头的共识字段。这些修改是内联执行的。
	Prepare(chain ChainHeaderReader, header *types.Header) error

	// Finalize runs any post-transaction state modifications (e.g. block rewards
	// or process withdrawals) but does not assemble the block.
	//
	// Note: The state database might be updated to reflect any consensus rules
	// that happen at finalization (e.g. block rewards).
	// Finalize 运行任何交易后的状态修改（例如区块奖励或处理提款），但不组装区块。
	//
	// 注意：状态数据库可能会更新以反映在最终化过程中发生的任何共识规则（例如区块奖励）。
	Finalize(chain ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body)

	// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
	// rewards or process withdrawals) and assembles the final block.
	//
	// Note: The block header and state database might be updated to reflect any
	// consensus rules that happen at finalization (e.g. block rewards).
	// FinalizeAndAssemble 运行任何交易后的状态修改（例如区块奖励或处理提款）并组装最终区块。
	//
	// 注意：区块头和状态数据库可能会更新以反映在最终化过程中发生的任何共识规则（例如区块奖励）。
	FinalizeAndAssemble(chain ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error)

	// Seal generates a new sealing request for the given input block and pushes
	// the result into the given channel.
	//
	// Note, the method returns immediately and will send the result async. More
	// than one result may also be returned depending on the consensus algorithm.
	// Seal 为给定输入区块生成一个新的密封请求，并将结果推送到给定通道中。
	//
	// 注意，该方法会立即返回，并异步发送结果。根据共识算法，可能会返回多个结果。
	Seal(chain ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error

	// SealHash returns the hash of a block prior to it being sealed.
	// SealHash 返回区块在密封之前的哈希值。
	SealHash(header *types.Header) common.Hash

	// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
	// that a new block should have.
	// CalcDifficulty 是难度调整算法。它返回新区块应具有的难度。
	CalcDifficulty(chain ChainHeaderReader, time uint64, parent *types.Header) *big.Int

	// APIs returns the RPC APIs this consensus engine provides.
	// APIs 返回此共识引擎提供的 RPC API。
	APIs(chain ChainHeaderReader) []rpc.API

	// Close terminates any background threads maintained by the consensus engine.
	// Close 终止共识引擎维护的任何后台线程。
	Close() error
}
