// Copyright 2014 The go-ethereum Authors
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

// Package miner implements Ethereum block creation and mining.
package miner

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

//EIP-1559 ：
// EIP-1559 改变了以太坊的交易费用模型，引入了基础费用和小费机制。矿工只能控制小费部分，基础费用由协议自动计算。
//提款机制 ：
// 上海升级（EIP-4895）引入了提款功能，允许验证者提取其质押的 ETH。这一功能对 PoS 机制下的经济模型具有重要意义。
//信标链与执行层的分离 ：
// 在以太坊合并后，共识层（信标链）与执行层分离。Miner 负责与共识层协作，生成符合要求的区块有效载荷。

// 1. 矿工的核心职责
// 挖矿任务管理 ：
//  Miner 是以太坊节点中负责挖矿的核心组件。它通过与共识引擎（如 Ethash 或 PoS 引擎）交互来生成新区块，并将交易池中的交易打包到区块中。
// 生命周期方法 ：
//  Pending() 方法返回当前待处理的区块及其相关数据（如收据和状态数据库）。这是供其他模块（如 RPC 或同步模块）使用的重要接口。
// 动态配置更新 ：
//  SetExtra、SetGasCeil 和 SetGasTip 方法允许动态调整矿工的配置参数，而无需重启节点。
// 2. EIP-1559 和上海升级的支持
// EIP-1559 ：
//  在 EIP-1559 中引入了动态基础费用机制，矿工需要为目标 Gas 上限（GasCeil）设置一个合理的值，以优化区块的填充率。
// 上海升级 ：
//  上海升级引入了提款功能（Withdrawals），允许验证者提取其质押的 ETH。getPending 方法中检查是否启用了上海升级，并在必要时初始化提款列表。
// 3. 共识层与执行层的协作
//  PoS 机制下的矿工角色 ：
//   在 PoS（权益证明）机制下，矿工的角色从传统的工作量证明（PoW）转变为区块提议者（Block Proposer）。BuildPayload 方法根据共识层提供的参数构建区块有效载荷。
//  重新提交间隔 ：
//   Recommit 参数定义了矿工重新创建挖矿任务的时间间隔。默认值为 2 秒，这是为了适应信标链的 slot 时间（12 秒），确保矿工有足够的时间生成区块。

// Backend wraps all methods required for mining. Only full node is capable
// to offer all the functions here.
// Backend 接口封装了所有与挖矿相关的方法。只有全节点才能提供这些功能。
type Backend interface {
	BlockChain() *core.BlockChain // 返回区块链实例
	TxPool() *txpool.TxPool       // 返回交易池实例
}

// Config is the configuration parameters of mining.
// Config 是挖矿的配置参数。
type Config struct {
	Etherbase           common.Address `toml:"-"`          // 已弃用
	PendingFeeRecipient common.Address `toml:"-"`          // 待处理区块奖励的地址
	ExtraData           hexutil.Bytes  `toml:",omitempty"` // 矿工设置的区块额外数据
	GasCeil             uint64         // 挖矿区块的目标 Gas 上限
	GasPrice            *big.Int       // 挖矿交易的最低 Gas 价格
	Recommit            time.Duration  // 矿工重新创建挖矿任务的时间间隔
}

// DefaultConfig contains default settings for miner.
// DefaultConfig 包含矿工的默认设置。
var DefaultConfig = Config{
	GasCeil:  30_000_000,                     // 默认 Gas 上限为 30M
	GasPrice: big.NewInt(params.GWei / 1000), // 默认最低 Gas 价格为 1 Gwei 的千分之一
	Recommit: 2 * time.Second,                // 默认重新提交间隔为 2 秒
}

// Miner is the main object which takes care of submitting new work to consensus
// engine and gathering the sealing result.
// Miner 是负责向共识引擎提交新工作并收集密封结果的主要对象。
type Miner struct {
	confMu      sync.RWMutex        // 用于保护配置字段（如 GasCeil、GasPrice 和 ExtraData）的锁
	config      *Config             // 挖矿配置
	chainConfig *params.ChainConfig // 区块链配置
	engine      consensus.Engine    // 共识引擎
	txpool      *txpool.TxPool      // 交易池
	chain       *core.BlockChain    // 区块链实例
	pending     *pending            // 待处理区块
	pendingMu   sync.Mutex          // 保护待处理区块的锁
}

// New creates a new miner with provided config.
// New 使用提供的配置创建一个新的矿工实例。
func New(eth Backend, config Config, engine consensus.Engine) *Miner {
	return &Miner{
		config:      &config,
		chainConfig: eth.BlockChain().Config(),
		engine:      engine,
		txpool:      eth.TxPool(),
		chain:       eth.BlockChain(),
		pending:     &pending{},
	}
}

// Pending returns the currently pending block and associated receipts, logs
// and statedb. The returned values can be nil in case the pending block is
// not initialized.
// Pending 返回当前待处理的区块及其相关的收据、日志和状态数据库。
// 如果待处理区块未初始化，则返回值可能为 nil。
func (miner *Miner) Pending() (*types.Block, types.Receipts, *state.StateDB) {
	pending := miner.getPending()
	if pending == nil {
		return nil, nil, nil
	}
	return pending.block, pending.receipts, pending.stateDB.Copy()
}

// SetExtra sets the content used to initialize the block extra field.
// SetExtra 设置用于初始化区块额外数据字段的内容。
func (miner *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	miner.confMu.Lock()
	miner.config.ExtraData = extra
	miner.confMu.Unlock()
	return nil
}

// SetGasCeil sets the gaslimit to strive for when mining blocks post 1559.
// For pre-1559 blocks, it sets the ceiling.
// SetGasCeil 设置 EIP-1559 后挖矿区块的目标 Gas 上限。
// 对于 EIP-1559 前的区块，它设置 Gas 上限。
func (miner *Miner) SetGasCeil(ceil uint64) {
	miner.confMu.Lock()
	miner.config.GasCeil = ceil
	miner.confMu.Unlock()
}

// SetGasTip sets the minimum gas tip for inclusion.
// SetGasTip 设置最低 Gas 小费以包含交易。
func (miner *Miner) SetGasTip(tip *big.Int) error {
	miner.confMu.Lock()
	miner.config.GasPrice = tip
	miner.confMu.Unlock()
	return nil
}

// BuildPayload builds the payload according to the provided parameters.
// BuildPayload 根据提供的参数构建区块有效载荷。
func (miner *Miner) BuildPayload(args *BuildPayloadArgs, witness bool) (*Payload, error) {
	return miner.buildPayload(args, witness)
}

// getPending retrieves the pending block based on the current head block.
// The result might be nil if pending generation is failed.
// getPending 根据当前头部区块检索待处理区块。
// 如果待处理区块生成失败，结果可能为 nil。
func (miner *Miner) getPending() *newPayloadResult {
	header := miner.chain.CurrentHeader()
	miner.pendingMu.Lock()
	defer miner.pendingMu.Unlock()
	if cached := miner.pending.resolve(header.Hash()); cached != nil {
		return cached
	}

	var (
		timestamp  = uint64(time.Now().Unix()) // 当前时间戳
		withdrawal types.Withdrawals           // 提款信息
	)
	if miner.chainConfig.IsShanghai(new(big.Int).Add(header.Number, big.NewInt(1)), timestamp) {
		withdrawal = []*types.Withdrawal{} // 如果启用了上海升级，则初始化提款列表
	}
	ret := miner.generateWork(&generateParams{
		timestamp:   timestamp,
		forceTime:   false,
		parentHash:  header.Hash(),
		coinbase:    miner.config.PendingFeeRecipient,
		random:      common.Hash{},
		withdrawals: withdrawal,
		beaconRoot:  nil,
		noTxs:       false,
	}, false) // we will never make a witness for a pending block 我们永远不会为待处理区块生成见证数据
	if ret.err != nil {
		return nil
	}
	miner.pending.update(header.Hash(), ret)
	return ret
}
