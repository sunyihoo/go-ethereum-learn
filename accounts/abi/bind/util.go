// Copyright 2016 The go-ethereum Authors
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
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// WaitMined waits for tx to be mined on the blockchain.
// It stops waiting when the context is canceled.
// WaitMined 方法等待指定的交易被挖矿并打包到区块链中。
// 当上下文（context）被取消时停止等待。
func WaitMined(ctx context.Context, b DeployBackend, tx *types.Transaction) (*types.Receipt, error) {
	// 调用 WaitMinedHash 方法，传入交易的哈希值进行等待。
	return WaitMinedHash(ctx, b, tx.Hash())
}

// WaitMinedHash waits for a transaction with the provided hash to be mined on the blockchain.
// It stops waiting when the context is canceled.
// WaitMinedHash 方法等待指定哈希值的交易被挖矿并打包到区块链中。
// 当上下文（context）被取消时停止等待。
func WaitMinedHash(ctx context.Context, b DeployBackend, hash common.Hash) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second) // 创建一个每秒触发一次的定时器，用于定期查询交易状态。
	defer queryTicker.Stop()                   // 确保在函数退出时停止定时器，避免资源泄漏。

	logger := log.New("hash", hash) // 创建日志记录器，包含交易哈希信息。

	for {
		receipt, err := b.TransactionReceipt(ctx, hash) // 查询交易的收据（receipt）。
		if err == nil {
			return receipt, nil // 如果没有错误且收据存在，则返回收据。
		}

		// If the transaction is not found, it means it's not mined yet.
		// 如果交易未找到，表示尚未被挖矿。
		if errors.Is(err, ethereum.NotFound) {
			logger.Trace("Transaction not yet mined") // 记录日志表明交易尚未被挖矿。
		} else {
			// If any other error occurs, log it.
			// 如果发生其他错误，记录错误日志。
			logger.Trace("Receipt retrieval failed", "err", err)
		}

		// Wait for the next round.
		// 等待下一轮查询。
		select {
		case <-ctx.Done(): // 如果上下文被取消，则返回取消错误。
			return nil, ctx.Err()
		case <-queryTicker.C: // 否则等待定时器触发，继续下一轮查询。
		}
	}
}

// WaitDeployed waits for a contract deployment transaction and returns the on-chain
// contract address when it is mined. It stops waiting when ctx is canceled.
// WaitDeployed 方法等待合约部署交易，并在交易被挖矿后返回合约的链上地址。
// 当上下文（context）被取消时停止等待。
func WaitDeployed(ctx context.Context, b DeployBackend, tx *types.Transaction) (common.Address, error) {
	if tx.To() != nil {
		// If the transaction has a 'To' field, it's not a contract creation transaction.
		// 如果交易的目标地址不为空，则表示这不是一个合约创建交易，返回错误。
		return common.Address{}, errors.New("tx is not contract creation")
	}
	// Call WaitDeployedHash with the transaction hash.
	// 调用 WaitDeployedHash 方法，传入交易的哈希值进行等待。
	return WaitDeployedHash(ctx, b, tx.Hash())
}

// WaitDeployedHash waits for a contract deployment transaction with the provided hash and returns the on-chain
// contract address when it is mined. It stops waiting when ctx is canceled.
// WaitDeployedHash 方法等待指定哈希值的合约部署交易，并在交易被挖矿后返回合约的链上地址。
// 当上下文（context）被取消时停止等待。
func WaitDeployedHash(ctx context.Context, b DeployBackend, hash common.Hash) (common.Address, error) {
	// First, wait for the transaction to be mined and get the receipt.
	// 首先，等待交易被挖矿并获取收据。
	receipt, err := WaitMinedHash(ctx, b, hash)
	if err != nil {
		return common.Address{}, err // 如果等待失败，返回错误。
	}
	if receipt.ContractAddress == (common.Address{}) {
		// If the contract address in the receipt is empty, return an error.
		// 如果收据中的合约地址为空，则返回错误。
		return common.Address{}, errors.New("zero address")
	}

	// Check that code has indeed been deployed at the address.
	// This matters on pre-Homestead chains: OOG in the constructor
	// could leave an empty account behind.
	// 检查合约地址上是否确实部署了代码。
	// 这对于 Homestead 之前的链很重要：构造函数中耗尽 gas 可能会留下一个空账户。
	code, err := b.CodeAt(ctx, receipt.ContractAddress, nil) // 获取合约地址上的代码。
	if err == nil && len(code) == 0 {                        // 如果没有错误但代码长度为 0，则表示合约未成功部署。
		err = ErrNoCodeAfterDeploy
	}
	return receipt.ContractAddress, err // 返回合约地址和可能的错误。
}
