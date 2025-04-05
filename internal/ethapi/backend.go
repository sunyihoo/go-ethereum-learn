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

// Package ethapi implements the general Ethereum API functions.
package ethapi

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// Backend interface provides the common API services (that are provided by
// both full and light clients) with access to necessary functions.
// Backend 接口提供了由完整节点和轻量级客户端共同实现的通用 API 服务，包含必要的功能。
type Backend interface {
	// General Ethereum API
	SyncProgress() ethereum.SyncProgress
	// 返回当前的同步进度，用于监控节点的区块同步状态。

	SuggestGasTipCap(ctx context.Context) (*big.Int, error)
	// 建议用户为交易设置的 gas 小费上限（EIP-1559）。这是动态费用机制的一部分，帮助用户估算合理的 gas 价格。

	FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, []*big.Int, []float64, error)
	// 返回指定范围内的历史 gas 费用数据，包括基础费用、奖励百分位等。用于分析 gas 价格趋势。

	BlobBaseFee(ctx context.Context) *big.Int
	// 返回当前区块的基础费用（Blob Base Fee），用于 EIP-4844 数据 blob 交易。

	ChainDb() ethdb.Database
	// 返回底层链数据库，用于访问区块链数据存储。

	AccountManager() *accounts.Manager
	// 返回账户管理器，用于管理钱包和账户。

	ExtRPCEnabled() bool
	// 检查是否启用了外部 RPC 服务。

	RPCGasCap() uint64 // global gas cap for eth_call over rpc: DoS protection
	// 全局 gas 上限，用于 eth_call 的 RPC 调用，防止 DoS 攻击。通过限制 gas 消耗，避免恶意调用导致节点资源耗尽。

	RPCEVMTimeout() time.Duration // global timeout for eth_call over rpc: DoS protection
	// 全局超时时间，用于 eth_call 的 RPC 调用，防止 DoS 攻击。设置 EVM 执行的最大时间，避免长时间运行的调用占用过多资源。

	RPCTxFeeCap() float64 // global tx fee cap for all transaction related APIs
	// 全局交易费用上限，用于所有与交易相关的 API。限制交易费用可以防止恶意交易消耗过多资源。

	UnprotectedAllowed() bool // allows only for EIP155 transactions.
	// 是否允许未受保护的交易（非 EIP-155 标准）。通常用于兼容性或安全性检查。

	// Blockchain API
	SetHead(number uint64)
	// 设置区块链的头部到指定区块高度（回滚操作）。

	HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error)
	// 根据区块编号获取区块头信息。

	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	// 根据区块哈希获取区块头信息。

	HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error)
	// 根据区块编号或哈希获取区块头信息。

	CurrentHeader() *types.Header
	// 返回当前链的最新区块头。

	CurrentBlock() *types.Header
	// 返回当前链的最新区块。

	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error)
	// 根据区块编号获取完整区块信息。

	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	// 根据区块哈希获取完整区块信息。

	BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error)
	// 根据区块编号或哈希获取完整区块信息。

	StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error)
	// 根据区块编号获取状态数据库和区块头。

	StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error)
	// 根据区块编号或哈希获取状态数据库和区块头。

	Pending() (*types.Block, types.Receipts, *state.StateDB)
	// 返回当前待处理的区块、收据和状态数据库。

	GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error)
	// 根据区块哈希获取交易收据。

	GetEVM(ctx context.Context, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockCtx *vm.BlockContext) *vm.EVM
	// 根据给定的状态和区块上下文创建一个 EVM 实例，用于执行智能合约。

	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
	// 订阅区块链事件（如新区块生成）。

	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
	// 订阅链头更新事件。

	// Transaction pool API
	SendTx(ctx context.Context, signedTx *types.Transaction) error
	// 发送已签名的交易到交易池。

	GetTransaction(ctx context.Context, txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64, error)
	// 根据交易哈希获取交易信息及其所在区块的详细信息。

	GetPoolTransactions() (types.Transactions, error)
	// 获取交易池中的所有交易。

	GetPoolTransaction(txHash common.Hash) *types.Transaction
	// 根据交易哈希从交易池中获取交易。

	GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error)
	// 获取指定地址的交易池 nonce。

	Stats() (pending int, queued int)
	// 返回交易池的统计信息，包括待处理和排队的交易数量。

	TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction)
	// 返回交易池的内容，按地址分类。

	TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction)
	// 返回指定地址的交易池内容。

	SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription
	// 订阅新交易事件。

	ChainConfig() *params.ChainConfig
	// 返回当前链的配置参数。

	Engine() consensus.Engine
	// 返回共识引擎实例。

	// This is copied from filters.Backend
	// eth/filters needs to be initialized from this backend type, so methods needed by
	// it must also be included here.
	GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error)
	// 根据区块哈希和编号获取区块体。

	GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error)
	// 根据区块哈希和编号获取日志。

	SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription
	// 订阅移除日志事件。

	SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription
	// 订阅日志事件。

	BloomStatus() (uint64, uint64)
	// 返回布隆过滤器的状态。

	ServiceFilter(ctx context.Context, session *bloombits.MatcherSession)
	// 为布隆过滤器提供服务。
}

func GetAPIs(apiBackend Backend) []rpc.API {
	nonceLock := new(AddrLocker)
	return []rpc.API{
		{
			Namespace: "eth",
			Service:   NewEthereumAPI(apiBackend),
			// 注册以太坊核心 API 服务。
		}, {
			Namespace: "eth",
			Service:   NewBlockChainAPI(apiBackend),
			// 注册区块链相关 API 服务。
		}, {
			Namespace: "eth",
			Service:   NewTransactionAPI(apiBackend, nonceLock),
			// 注册交易相关 API 服务，并使用 nonceLock 管理地址锁定。
		}, {
			Namespace: "txpool",
			Service:   NewTxPoolAPI(apiBackend),
			// 注册交易池相关 API 服务。
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(apiBackend),
			// 注册调试相关 API 服务。
		}, {
			Namespace: "eth",
			Service:   NewEthereumAccountAPI(apiBackend.AccountManager()),
			// 注册账户管理相关 API 服务。
		},
	}
}
