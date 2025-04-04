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

package simulated

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/catalyst"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// BlockNumberReader: 用于读取最新的区块号。
// ChainReader: 用于读取链数据，如区块、交易等。
// ChainStateReader: 用于读取链的状态，如账户信息、合约存储等。
// ContractCaller: 用于调用智能合约。
// GasEstimator: 用于估计交易所需的 gas。
// GasPricer 和 GasPricer1559: 用于获取 gas 价格信息（包括 EIP-1559 引入的机制）。
// FeeHistoryReader: 用于读取历史的 gas 费用信息。
// LogFilterer: 用于过滤和查询区块链日志（事件）。
// PendingStateReader: 用于读取当前待处理交易池的状态。
// PendingContractCaller: 用于在待处理状态下调用合约。
// TransactionReader: 用于读取交易信息。
// TransactionSender: 用于发送交易到网络。
// ChainIDReader: 用于读取当前网络的链 ID。

// Client exposes the methods provided by the Ethereum RPC client.
// Client 暴露了以太坊 RPC 客户端提供的方法。
type Client interface {
	ethereum.BlockNumberReader
	ethereum.ChainReader
	ethereum.ChainStateReader
	ethereum.ContractCaller
	ethereum.GasEstimator
	ethereum.GasPricer
	ethereum.GasPricer1559
	ethereum.FeeHistoryReader
	ethereum.LogFilterer
	ethereum.PendingStateReader
	ethereum.PendingContractCaller
	ethereum.TransactionReader
	ethereum.TransactionSender
	ethereum.ChainIDReader
}

// simClient wraps ethclient. This exists to prevent extracting ethclient.Client
// from the Client interface returned by Backend.
// simClient 封装了 ethclient。它的存在是为了防止从 Backend 返回的 Client 接口中提取 ethclient.Client。
type simClient struct {
	*ethclient.Client
}

// Backend is a simulated blockchain. You can use it to test your contracts or
// other code that interacts with the Ethereum chain.
// Backend 是一个模拟的区块链。你可以使用它来测试你的合约或其他与以太坊链交互的代码。
type Backend struct {
	node   *node.Node
	beacon *catalyst.SimulatedBeacon
	client simClient
}

// NewBackend creates a new simulated blockchain that can be used as a backend for
// contract bindings in unit tests.
//
// A simulated backend always uses chainID 1337.
// NewBackend 创建一个新的模拟区块链，可以用作单元测试中合约绑定的后端。
//
// 模拟后端总是使用 chainID 1337。
func NewBackend(alloc types.GenesisAlloc, options ...func(nodeConf *node.Config, ethConf *ethconfig.Config)) *Backend {
	// Create the default configurations for the outer node shell and the Ethereum
	// service to mutate with the options afterwards
	// 创建外部节点 shell 和以太坊服务的默认配置，之后可以使用选项进行修改
	nodeConf := node.DefaultConfig
	nodeConf.DataDir = ""
	nodeConf.P2P = p2p.Config{NoDiscovery: true}

	ethConf := ethconfig.Defaults
	ethConf.Genesis = &core.Genesis{
		Config:   params.AllDevChainProtocolChanges,
		GasLimit: ethconfig.Defaults.Miner.GasCeil,
		Alloc:    alloc,
	}
	ethConf.SyncMode = ethconfig.FullSync
	ethConf.TxPool.NoLocals = true

	for _, option := range options {
		option(&nodeConf, &ethConf)
	}
	// Assemble the Ethereum stack to run the chain with
	// 组装以太坊堆栈以运行链
	stack, err := node.New(&nodeConf)
	if err != nil {
		panic(err) // this should never happen
	}
	sim, err := newWithNode(stack, &ethConf, 0)
	if err != nil {
		panic(err) // this should never happen
	}
	return sim
}

// newWithNode sets up a simulated backend on an existing node. The provided node
// must not be started and will be started by this method.
// newWithNode 在现有节点上设置一个模拟后端。提供的节点不能启动，并且将由此方法启动。
func newWithNode(stack *node.Node, conf *eth.Config, blockPeriod uint64) (*Backend, error) {
	backend, err := eth.New(stack, conf)
	if err != nil {
		return nil, err
	}
	// Register the filter system
	// 注册过滤器系统
	filterSystem := filters.NewFilterSystem(backend.APIBackend, filters.Config{})
	stack.RegisterAPIs([]rpc.API{{
		Namespace: "eth",
		Service:   filters.NewFilterAPI(filterSystem),
	}})
	// Start the node
	// 启动节点
	if err := stack.Start(); err != nil {
		return nil, err
	}
	// Set up the simulated beacon
	// 设置模拟信标
	beacon, err := catalyst.NewSimulatedBeacon(blockPeriod, backend)
	if err != nil {
		return nil, err
	}
	// Reorg our chain back to genesis
	// 将我们的链重组回创世区块
	if err := beacon.Fork(backend.BlockChain().GetCanonicalHash(0)); err != nil {
		return nil, err
	}
	return &Backend{
		node:   stack,
		beacon: beacon,
		client: simClient{ethclient.NewClient(stack.Attach())},
	}, nil
}

// Close shuts down the simBackend.
// The simulated backend can't be used afterwards.
// Close 关闭模拟后端。
// 之后无法再使用模拟后端。
func (n *Backend) Close() error {
	if n.client.Client != nil {
		n.client.Close()
		n.client = simClient{}
	}
	var err error
	if n.beacon != nil {
		err = n.beacon.Stop()
		n.beacon = nil
	}
	if n.node != nil {
		err = errors.Join(err, n.node.Close())
		n.node = nil
	}
	return err
}

// Commit seals a block and moves the chain forward to a new empty block.
// Commit 密封一个区块并将链向前移动到新的空区块。
func (n *Backend) Commit() common.Hash {
	return n.beacon.Commit()
}

// Rollback removes all pending transactions, reverting to the last committed state.
// Rollback 移除所有待处理交易，恢复到上次提交的状态。
func (n *Backend) Rollback() {
	n.beacon.Rollback()
}

// Fork creates a side-chain that can be used to simulate reorgs.
//
// This function should be called with the ancestor block where the new side
// chain should be started. Transactions (old and new) can then be applied on
// top and Commit-ed.
//
// Note, the side-chain will only become canonical (and trigger the events) when
// it becomes longer. Until then CallContract will still operate on the current
// canonical chain.
//
// There is a % chance that the side chain becomes canonical at the same length
// to simulate live network behavior.
// Fork 创建一个侧链，可以用于模拟链重组。
//
// 应该使用新侧链应该开始的祖先区块来调用此函数。然后可以在其上应用交易（旧的和新的）并进行 Commit。
//
// 注意，只有当侧链变得更长时，它才会成为规范链（并触发事件）。在此之前，CallContract 仍将在当前的规范链上运行。
//
// 侧链在相同长度时有一定百分比的几率成为规范链，以模拟真实网络的行为。
func (n *Backend) Fork(parentHash common.Hash) error {
	return n.beacon.Fork(parentHash)
}

// AdjustTime changes the block timestamp and creates a new block.
// It can only be called on empty blocks.
// AdjustTime 更改区块时间戳并创建一个新区块。
// 它只能在空区块上调用。
func (n *Backend) AdjustTime(adjustment time.Duration) error {
	return n.beacon.AdjustTime(adjustment)
}

// Client returns a client that accesses the simulated chain.
// Client 返回一个访问模拟链的客户端。
func (n *Backend) Client() Client {
	return n.client
}
