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

package core

import (
	"errors"

	"github.com/ethereum/go-ethereum/core/types"
)

var (
	// ErrKnownBlock is returned when a block to import is already known locally.
	ErrKnownBlock = errors.New("block already known")

	// ErrNoGenesis is returned when there is no Genesis Block.
	ErrNoGenesis = errors.New("genesis not found in chain")

	errSideChainReceipts = errors.New("side blocks can't be accepted as ancient chain data")
)

// List of evm-call-message pre-checking errors. All state transition messages will
// be pre-checked before execution. If any invalidation detected, the corresponding
// error should be returned which is defined here.
//
// - If the pre-checking happens in the miner, then the transaction won't be packed.
// - If the pre-checking happens in the block processing procedure, then a "BAD BLOCk"
// error should be emitted.
var (
	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	// ErrNonceTooLow 在交易的 nonce 低于本地链中已存在的 nonce 时返回。
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrNonceTooHigh is returned if the nonce of a transaction is higher than the
	// next one expected based on the local chain.
	// ErrNonceTooHigh 在交易的 nonce 高于本地链中预期的下一个 nonce 时返回。
	ErrNonceTooHigh = errors.New("nonce too high")

	// ErrNonceMax is returned if the nonce of a transaction sender account has
	// maximum allowed value and would become invalid if incremented.
	// ErrNonceMax 在交易发送者账户的 nonce 达到最大允许值，并且如果再增加就会失效时返回。
	ErrNonceMax = errors.New("nonce has max value")

	// ErrGasLimitReached is returned by the gas pool if the amount of gas required
	// by a transaction is higher than what's left in the block.
	// ErrGasLimitReached 在交易所需的 gas 量高于区块中剩余的 gas 量时，由 gas 池返回。
	ErrGasLimitReached = errors.New("gas limit reached")

	// ErrInsufficientFundsForTransfer is returned if the transaction sender doesn't
	// have enough funds for transfer(topmost call only).
	// ErrInsufficientFundsForTransfer 在交易发送者没有足够的资金进行转账（仅限最顶层调用）时返回。
	ErrInsufficientFundsForTransfer = errors.New("insufficient funds for transfer")

	// ErrMaxInitCodeSizeExceeded is returned if creation transaction provides the init code bigger
	// than init code size limit.
	// ErrMaxInitCodeSizeExceeded 在创建合约的交易提供的初始化代码大于允许的最大尺寸时返回。
	ErrMaxInitCodeSizeExceeded = errors.New("max initcode size exceeded")

	// ErrInsufficientBalanceWitness is returned if the transaction sender has enough
	// funds to cover the transfer, but not enough to pay for witness access/modification
	// costs for the transaction
	// ErrInsufficientBalanceWitness 在交易发送者有足够的资金进行转账，但不足以支付交易的见证访问/修改成本时返回。
	ErrInsufficientBalanceWitness = errors.New("insufficient funds to cover witness access costs for transaction")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	// ErrInsufficientFunds 在执行交易的总成本高于用户账户余额时返回。
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")

	// ErrGasUintOverflow is returned when calculating gas usage.
	// ErrGasUintOverflow 在计算 gas 使用量时发生 uint64 溢出时返回。
	ErrGasUintOverflow = errors.New("gas uint64 overflow")

	// ErrIntrinsicGas is returned if the transaction is specified to use less gas
	// than required to start the invocation.
	// ErrIntrinsicGas 在交易指定的 gas 量低于启动执行所需的最低 gas 量时返回。
	ErrIntrinsicGas = errors.New("intrinsic gas too low")

	// ErrTxTypeNotSupported is returned if a transaction is not supported in the
	// current network configuration.
	// ErrTxTypeNotSupported 在当前网络配置不支持交易类型时返回。
	ErrTxTypeNotSupported = types.ErrTxTypeNotSupported

	// ErrTipAboveFeeCap is a sanity error to ensure no one is able to specify a
	// transaction with a tip higher than the total fee cap.
	// ErrTipAboveFeeCap 是一个健全性错误，用于确保没有人能够指定一个小费高于总费用上限的交易。
	ErrTipAboveFeeCap = errors.New("max priority fee per gas higher than max fee per gas")

	// ErrTipVeryHigh is a sanity error to avoid extremely big numbers specified
	// in the tip field.
	// ErrTipVeryHigh 是一个健全性错误，用于避免在小费字段中指定过大的数字。
	ErrTipVeryHigh = errors.New("max priority fee per gas higher than 2^256-1")

	// ErrFeeCapVeryHigh is a sanity error to avoid extremely big numbers specified
	// in the fee cap field.
	// ErrFeeCapVeryHigh 是一个健全性错误，用于避免在费用上限字段中指定过大的数字。
	ErrFeeCapVeryHigh = errors.New("max fee per gas higher than 2^256-1")

	// ErrFeeCapTooLow is returned if the transaction fee cap is less than the
	// base fee of the block.
	// ErrFeeCapTooLow 在交易的费用上限低于区块的基础费用时返回。
	ErrFeeCapTooLow = errors.New("max fee per gas less than block base fee")

	// ErrSenderNoEOA is returned if the sender of a transaction is a contract.
	// ErrSenderNoEOA 在交易的发送者是一个合约账户时返回（预期发送者是外部拥有的账户）。
	ErrSenderNoEOA = errors.New("sender not an eoa")

	// -- EIP-4844 errors --

	// ErrBlobFeeCapTooLow is returned if the transaction fee cap is less than the
	// blob gas fee of the block.
	// ErrBlobFeeCapTooLow 在交易的 blob 费用上限低于区块的 blob gas 费用时返回。
	ErrBlobFeeCapTooLow = errors.New("max fee per blob gas less than block blob gas fee")

	// ErrMissingBlobHashes is returned if a blob transaction has no blob hashes.
	// ErrMissingBlobHashes 在 blob 交易没有包含 blob 哈希时返回。
	ErrMissingBlobHashes = errors.New("blob transaction missing blob hashes")

	// ErrBlobTxCreate is returned if a blob transaction has no explicit to field.
	// ErrBlobTxCreate 在 blob 交易没有明确的接收者字段（通常用于合约创建）时返回。
	ErrBlobTxCreate = errors.New("blob transaction of type create")

	// -- EIP-7702 errors --

	// Message validation errors:
	// 消息验证错误：
	ErrEmptyAuthList = errors.New("EIP-7702 transaction with empty auth list")
	// ErrEmptyAuthList 在 EIP-7702 交易的授权列表为空时返回。
	ErrSetCodeTxCreate = errors.New("EIP-7702 transaction cannot be used to create contract")
	// ErrSetCodeTxCreate 在 EIP-7702 交易尝试创建合约时返回。
)

// EIP-7702 state transition errors.
// Note these are just informational, and do not cause tx execution abort.
// EIP-7702 状态转换错误。
// 注意：这些只是信息性的，不会导致交易执行中止。
var (
	ErrAuthorizationWrongChainID = errors.New("EIP-7702 authorization chain ID mismatch")
	// ErrAuthorizationWrongChainID 在 EIP-7702 授权中的链 ID 与当前链的 ID 不匹配时返回。
	ErrAuthorizationNonceOverflow = errors.New("EIP-7702 authorization nonce > 64 bit")
	// ErrAuthorizationNonceOverflow 在 EIP-7702 授权中的 nonce 大于 64 位时返回。
	ErrAuthorizationInvalidSignature = errors.New("EIP-7702 authorization has invalid signature")
	// ErrAuthorizationInvalidSignature 在 EIP-7702 授权的签名无效时返回。
	ErrAuthorizationDestinationHasCode = errors.New("EIP-7702 authorization destination is a contract")
	// ErrAuthorizationDestinationHasCode 在 EIP-7702 授权的目标地址是一个合约时返回。
	ErrAuthorizationNonceMismatch = errors.New("EIP-7702 authorization nonce does not match current account nonce")
	// ErrAuthorizationNonceMismatch 在 EIP-7702 授权中的 nonce 与当前账户的 nonce 不匹配时返回。
)
