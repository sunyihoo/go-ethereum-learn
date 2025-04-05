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

package bind

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested
	// recipient contract to operate on does not exist in the state db or does not
	// have any code associated with it (i.e. self-destructed).
	// ErrNoCode 在调用或交易操作中返回，当目标合约在状态数据库中不存在或没有关联的代码（例如自毁）时。
	ErrNoCode = errors.New("no contract code at given address")

	// ErrNoPendingState is raised when attempting to perform a pending state action
	// on a backend that doesn't implement PendingContractCaller.
	// ErrNoPendingState 在尝试对不支持 PendingContractCaller 的后端执行待处理状态操作时引发。
	ErrNoPendingState = errors.New("backend does not support pending state")

	// ErrNoBlockHashState is raised when attempting to perform a block hash action
	// on a backend that doesn't implement BlockHashContractCaller.
	// ErrNoBlockHashState 在尝试对不支持 BlockHashContractCaller 的后端执行区块哈希操作时引发。
	ErrNoBlockHashState = errors.New("backend does not support block hash state")

	// ErrNoCodeAfterDeploy is returned by WaitDeployed if contract creation leaves
	// an empty contract behind.
	// ErrNoCodeAfterDeploy 在合约创建后留下空合约时由 WaitDeployed 返回。
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

// ContractCaller defines the methods needed to allow operating with a contract on a read
// only basis.
// ContractCaller 定义了以只读方式与合约交互所需的方法。
type ContractCaller interface {
	// CodeAt returns the code of the given account. This is needed to differentiate
	// between contract internal errors and the local chain being out of sync.
	// CodeAt 返回给定账户的代码。这是为了区分合约内部错误和本地链不同步的情况。
	CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error)

	// CallContract executes an Ethereum contract call with the specified data as the
	// input.
	// CallContract 执行一个以太坊合约调用，指定数据作为输入。
	CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// PendingContractCaller defines methods to perform contract calls on the pending state.
// Call will try to discover this interface when access to the pending state is requested.
// If the backend does not support the pending state, Call returns ErrNoPendingState.
// PendingContractCaller 定义了在待处理状态下执行合约调用的方法。
// 当请求访问待处理状态时，Call 会尝试发现此接口。
// 如果后端不支持待处理状态，Call 返回 ErrNoPendingState。
type PendingContractCaller interface {
	// PendingCodeAt returns the code of the given account in the pending state.
	// PendingCodeAt 返回给定账户在待处理状态下的代码。
	PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error)

	// PendingCallContract executes an Ethereum contract call against the pending state.
	// PendingCallContract 针对待处理状态执行一个以太坊合约调用。
	PendingCallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error)
}

// BlockHashContractCaller defines methods to perform contract calls on a specific block hash.
// Call will try to discover this interface when access to a block by hash is requested.
// If the backend does not support the block hash state, Call returns ErrNoBlockHashState.
// BlockHashContractCaller 定义了在特定区块哈希状态下执行合约调用的方法。
// 当请求通过哈希访问区块时，Call 会尝试发现此接口。
// 如果后端不支持区块哈希状态，Call 返回 ErrNoBlockHashState。
type BlockHashContractCaller interface {
	// CodeAtHash returns the code of the given account in the state at the specified block hash.
	// CodeAtHash 返回给定账户在指定区块哈希状态下的代码。
	CodeAtHash(ctx context.Context, contract common.Address, blockHash common.Hash) ([]byte, error)

	// CallContractAtHash executes an Ethereum contract call against the state at the specified block hash.
	// CallContractAtHash 针对指定区块哈希状态执行一个以太坊合约调用。
	CallContractAtHash(ctx context.Context, call ethereum.CallMsg, blockHash common.Hash) ([]byte, error)
}

// ContractTransactor defines the methods needed to allow operating with a contract
// on a write only basis. Besides the transacting method, the remainder are helpers
// used when the user does not provide some needed values, but rather leaves it up
// to the transactor to decide.
// ContractTransactor 定义了以只写方式与合约交互所需的方法。
// 除了交易方法外，其余方法是辅助方法，用于用户未提供某些所需值时，由交易器自行决定。
type ContractTransactor interface {
	ethereum.GasEstimator      // Gas 估算器
	ethereum.GasPricer         // Gas 价格计算器
	ethereum.GasPricer1559     // EIP-1559 Gas 价格计算器
	ethereum.TransactionSender // 交易发送器

	// HeaderByNumber returns a block header from the current canonical chain. If
	// number is nil, the latest known header is returned.
	// HeaderByNumber 返回当前规范链中的区块头。如果 number 为 nil，则返回最新的已知区块头。
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)

	// PendingCodeAt returns the code of the given account in the pending state.
	// PendingCodeAt 返回给定账户在待处理状态下的代码。
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)

	// PendingNonceAt retrieves the current pending nonce associated with an account.
	// PendingNonceAt 检索与账户关联的当前待处理 nonce。
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

// DeployBackend wraps the operations needed by WaitMined and WaitDeployed.
// DeployBackend 包装了 WaitMined 和 WaitDeployed 所需的操作。
type DeployBackend interface {
	// TransactionReceipt returns the receipt of a mined transaction.
	// TransactionReceipt 返回已挖出交易的收据。
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)

	// CodeAt returns the code of the given account. This is needed to differentiate
	// between contract internal errors and the local chain being out of sync.
	// CodeAt 返回给定账户的代码。这是为了区分合约内部错误和本地链不同步的情况。
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// ContractFilterer defines the methods needed to access log events using one-off
// queries or continuous event subscriptions.
// ContractFilterer 定义了使用一次性查询或连续事件订阅访问日志事件所需的方法。
type ContractFilterer interface {
	ethereum.LogFilterer // 日志过滤器
}

// ContractBackend defines the methods needed to work with contracts on a read-write basis.
// ContractBackend 定义了以读写方式与合约交互所需的方法。
type ContractBackend interface {
	ContractCaller     // 合约调用器
	ContractTransactor // 合约交易器
	ContractFilterer   // 合约过滤器
}
