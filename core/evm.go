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

package core

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// 1. 区块链上下文（白皮书）
// 以太坊白皮书中提到，交易执行需要访问当前区块链状态和共识参数。ChainContext 接口提供了这种能力：
//
// Engine：返回共识引擎（如 PoW 的 Ethash 或 PoS 的 Beacon），用于确定矿工（Author）。
// GetHeader：根据哈希和高度检索块头，供 EVM 获取历史数据。
// 2. EVM 上下文（黄皮书 Section 9）
// 黄皮书 Section 9 定义了 EVM 的执行环境，分为块上下文（BlockContext）和交易上下文（TxContext）。代码中的 NewEVMBlockContext 和 NewEVMTxContext 实现了这些：
//
// BlockContext：包含块级信息（如 BlockNumber、Time、GasLimit），用于合约调用中的环境变量（如 block.number、block.timestamp）。
// TxContext：包含交易级信息（如 Origin、GasPrice），用于追踪交易发起者和费用。
// 3. EIP 的影响
// 代码支持多个 EIP，反映以太坊的演进：
//
// EIP-1559（伦敦硬分叉）：BaseFee 从块头提取，支持动态费用机制，替代传统的单一 Gas 价格。
// EIP-4399：Random（从 MixDigest 提取）在 PoS 下提供可验证随机数，取代 PoW 的难度（Difficulty == 0 表示 PoS）。
// EIP-4844（Cancun 硬分叉）：BlobBaseFee 和 BlobHashes 支持 Blob 交易，计算 Blob 费用（CalcBlobFee）并传递给 EVM。
// 4. 块哈希获取（黄皮书 Section 4）
// GetHashFn 实现了 EVM 的 blockhash 操作（黄皮书 Section 4.4），提供最近 256 个块的哈希：
//
// 缓存机制：从当前块的 ParentHash 开始，逐步回溯并缓存历史哈希。
// 边界处理：如果请求的高度超出当前块或无法获取，返回零哈希。
// 5. 转账逻辑（白皮书）
// 白皮书中描述的以太坊状态转换包括价值转移。CanTransfer 和 Transfer 实现了这一核心功能：
//
// CanTransfer：检查余额是否足够，不考虑 Gas 成本（由状态转换层处理）。
// Transfer：更新状态数据库（StateDB），记录余额变更，符合白皮书的账户模型。
// 6. 共识引擎与受益人
// NewEVMBlockContext 通过 Engine().Author 或指定 author 确定 Coinbase（受益人）：
//
// PoW：通常是矿工地址，由 Ethash 计算。
// PoS：由 Beacon 共识确定，通常是验证者地址。
// 7. 状态数据库（go-ethereum 实现）
// StateDB（状态数据库）管理账户状态，Transfer 使用 SubBalance 和 AddBalance 更新余额，追踪变更原因（BalanceChangeTransfer），支持调试和回滚。

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
// ChainContext 支持从当前区块链中检索头部和共识参数，以在交易处理期间使用。
type ChainContext interface {
	// Engine retrieves the chain's consensus engine.
	// Engine 检索链的共识引擎。
	Engine() consensus.Engine

	// GetHeader returns the header corresponding to the hash/number argument pair.
	// GetHeader 返回与哈希/高度参数对对应的头部。
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMBlockContext creates a new context for use in the EVM.
// NewEVMBlockContext 创建一个新的上下文供 EVM 使用。
func NewEVMBlockContext(header *types.Header, chain ChainContext, author *common.Address) vm.BlockContext {
	var (
		beneficiary common.Address // 受益人地址
		baseFee     *big.Int       // 基础费用
		blobBaseFee *big.Int       // Blob 基础费用
		random      *common.Hash   // 随机值
	)

	// If we don't have an explicit author (i.e. not mining), extract from the header
	// 如果没有明确指定作者（即不是挖矿），则从头部提取
	if author == nil {
		beneficiary, _ = chain.Engine().Author(header) // Ignore error, we're past header validation
		// 忽略错误，因为我们已通过头部验证
	} else {
		beneficiary = *author // 使用指定的作者地址
	}
	if header.BaseFee != nil {
		baseFee = new(big.Int).Set(header.BaseFee) // 设置基础费用
	}
	if header.ExcessBlobGas != nil {
		blobBaseFee = eip4844.CalcBlobFee(*header.ExcessBlobGas) // 计算 Blob 基础费用（EIP-4844）
	}
	if header.Difficulty.Sign() == 0 {
		random = &header.MixDigest // 如果难度为 0，则使用混合哈希作为随机值
	}
	return vm.BlockContext{
		CanTransfer: CanTransfer,                         // 检查是否可以转账的函数
		Transfer:    Transfer,                            // 执行转账的函数
		GetHash:     GetHashFn(header, chain),            // 获取块哈希的函数
		Coinbase:    beneficiary,                         // 受益人地址（通常是矿工）
		BlockNumber: new(big.Int).Set(header.Number),     // 块高度
		Time:        header.Time,                         // 时间戳
		Difficulty:  new(big.Int).Set(header.Difficulty), // 难度
		BaseFee:     baseFee,                             // 基础费用（EIP-1559）
		BlobBaseFee: blobBaseFee,                         // Blob 基础费用（EIP-4844）
		GasLimit:    header.GasLimit,                     // Gas 限制
		Random:      random,                              // 随机值（EIP-4399）
	}
}

// NewEVMTxContext creates a new transaction context for a single transaction.
// NewEVMTxContext 为单笔交易创建一个新的交易上下文。
func NewEVMTxContext(msg *Message) vm.TxContext {
	ctx := vm.TxContext{
		Origin:     msg.From,                       // 交易发起者
		GasPrice:   new(big.Int).Set(msg.GasPrice), // Gas 价格
		BlobHashes: msg.BlobHashes,                 // Blob 哈希（EIP-4844）
	}
	if msg.BlobGasFeeCap != nil {
		ctx.BlobFeeCap = new(big.Int).Set(msg.BlobGasFeeCap) // 设置 Blob Gas 费用上限
	}
	return ctx
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
// GetHashFn 返回一个 GetHashFunc，通过块高度检索头部哈希
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	// Cache will initially contain [refHash.parent],
	// Then fill up with [refHash.p, refHash.pp, refHash.ppp, ...]
	// 缓存最初包含 [refHash.parent]，
	// 然后填充为 [refHash.p, refHash.pp, refHash.ppp, ...]
	var cache []common.Hash

	return func(n uint64) common.Hash {
		if ref.Number.Uint64() <= n {
			// This situation can happen if we're doing tracing and using
			// block overrides.
			// 如果我们在追踪并使用块覆盖，这种情况可能发生。
			return common.Hash{} // 返回零哈希
		}
		// If there's no hash cache yet, make one
		// 如果还没有哈希缓存，则创建一个
		if len(cache) == 0 {
			cache = append(cache, ref.ParentHash) // 添加父块哈希到缓存
		}
		if idx := ref.Number.Uint64() - n - 1; idx < uint64(len(cache)) {
			return cache[idx] // 如果索引在缓存范围内，返回缓存中的哈希
		}
		// No luck in the cache, but we can start iterating from the last element we already know
		// 缓存中没有找到，但我们可以从已知的最后一个元素开始迭代
		lastKnownHash := cache[len(cache)-1]                        // 已知的最后一个哈希
		lastKnownNumber := ref.Number.Uint64() - uint64(len(cache)) // 已知的最后一个块高度

		for {
			header := chain.GetHeader(lastKnownHash, lastKnownNumber) // 获取头部
			if header == nil {
				break // 如果头部为空，退出循环
			}
			cache = append(cache, header.ParentHash)     // 添加父块哈希到缓存
			lastKnownHash = header.ParentHash            // 更新已知哈希
			lastKnownNumber = header.Number.Uint64() - 1 // 更新已知高度
			if n == lastKnownNumber {
				return lastKnownHash // 如果找到目标高度，返回哈希
			}
		}
		return common.Hash{} // 未找到，返回零哈希
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
// CanTransfer 检查地址账户中是否有足够的资金进行转账。
// 这不考虑使转账有效的必要 Gas。
func CanTransfer(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0 // 如果余额大于等于转账金额，返回 true
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
// Transfer 使用给定的数据库从发送者减去金额并添加到接收者
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int) {
	db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)    // 从发送者减去金额
	db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer) // 给接收者增加金额
}
