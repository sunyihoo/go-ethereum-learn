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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// 无状态客户端 (Stateless Clients): 传统的以太坊全节点需要存储和维护完整的区块链历史和当前状态。无状态客户端的目标是只存储少量数据（例如，最新的区块头和一些证明），并通过“见证”来验证交易和区块的有效性。ExecuteStateless 函数是实现无状态客户端的关键部分。
// 见证 (Witness): 在无状态执行中，当一个无状态客户端收到一个新的区块时，它还需要接收一个“见证”，这个见证包含了执行该区块中交易所需的最小状态数据片段。stateless.Witness 结构体就是用来存储这些数据的。
// 状态根和收据根: 状态根是当前以太坊状态的 Merkle 根哈希，它代表了所有账户的余额、合约代码和存储等信息。收据根是区块中所有交易收据的 Merkle 根哈希。这两个根哈希是验证区块有效性的重要组成部分。
// 循环依赖问题: 注释中提到了 core/stateless 和 state.New 之间的循环依赖问题，这解释了为什么这个看似属于无状态执行逻辑的函数会出现在 txpool 包中。这通常是代码组织上的一个临时性妥协。
// 共识客户端: 注释中提到的“faulty consensus client”暗示了 ExecuteStateless 函数可能被用于一些新的共识协议或测试场景中，这些场景可能需要对区块的有效性进行额外的检查。

// ExecuteStateless runs a stateless execution based on a witness, verifies
// everything it can locally and returns the state root and receipt root, that
// need the other side to explicitly check.
// ExecuteStateless 基于见证运行无状态执行，本地验证所有可以验证的内容，并返回状态根和收据根，
// 这需要另一方显式检查。
//
// This method is a bit of a sore thumb here, but:
// 这个方法在这里有点格格不入，但是：
//   - It cannot be placed in core/stateless, because state.New prodces a circular dep
//     它不能放在 core/stateless 中，因为 state.New 会产生循环依赖。
//   - It cannot be placed outside of core, because it needs to construct a dud headerchain
//     它不能放在 core 之外，因为它需要构建一个假的头部链。
//
// TODO(karalabe): Would be nice to resolve both issues above somehow and move it.
// TODO(karalabe): 如果能以某种方式解决上述两个问题并移动它会很好。
func ExecuteStateless(config *params.ChainConfig, vmconfig vm.Config, block *types.Block, witness *stateless.Witness) (common.Hash, common.Hash, error) {
	// Sanity check if the supplied block accidentally contains a set root or
	// receipt hash. If so, be very loud, but still continue.
	// 理智检查提供的区块是否意外包含已设置的状态根或收据哈希。如果是，则发出强烈警告，但仍然继续。
	if block.Root() != (common.Hash{}) {
		log.Error("stateless runner received state root it's expected to calculate (faulty consensus client)", "block", block.Number())
	}
	if block.ReceiptHash() != (common.Hash{}) {
		log.Error("stateless runner received receipt root it's expected to calculate (faulty consensus client)", "block", block.Number())
	}
	// Create and populate the state database to serve as the stateless backend
	// 创建并填充状态数据库，用作无状态后端。
	memdb := witness.MakeHashDB()
	db, err := state.New(witness.Root(), state.NewDatabase(triedb.NewDatabase(memdb, triedb.HashDefaults), nil))
	if err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	// Create a blockchain that is idle, but can be used to access headers through
	// 创建一个空闲的区块链，但可以用于通过它访问头部。
	chain := &HeaderChain{
		config:      config,
		chainDb:     memdb,
		headerCache: lru.NewCache[common.Hash, *types.Header](256),
		engine:      beacon.New(ethash.NewFaker()),
	}
	processor := NewStateProcessor(config, chain)
	validator := NewBlockValidator(config, nil) // No chain, we only validate the state, not the block
	// 没有链，我们只验证状态，不验证区块。

	// Run the stateless blocks processing and self-validate certain fields
	// 运行无状态区块处理并自验证某些字段。
	res, err := processor.Process(block, db, vmconfig)
	if err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	if err = validator.ValidateState(block, db, res, true); err != nil {
		return common.Hash{}, common.Hash{}, err
	}
	// Almost everything validated, but receipt and state root needs to be returned
	// 几乎所有内容都已验证，但需要返回收据根和状态根。
	receiptRoot := types.DeriveSha(res.Receipts, trie.NewStackTrie(nil))
	stateRoot := db.IntermediateRoot(config.IsEIP158(block.Number()))
	return stateRoot, receiptRoot, nil
}
