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

package types

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
)

// 执行负载 (Execution Payload): 包含了执行层需要执行的交易以及相关的状态信息。在信标链上，执行负载有其特定的数据结构。
// types.Block 和 types.Header: 这是执行层（例如 Go-Ethereum）中标准的区块和区块头表示方式。
// 分叉 (Forks): 以太坊协议会不断升级，不同的分叉（例如 Capella 和 Deneb）可能会引入新的特性和数据结构，因此代码需要能够处理这些差异。Deneb 分叉引入了与 blob 交易相关的新字段。
// 交易 (Transactions): 用户在以太坊网络上发起的价值转移或状态变更操作。
// 提款 (Withdrawals): 在 Capella 升级后，信标链验证者可以将他们的质押奖励提取到执行层地址。这些提款信息包含在执行负载中。
// Merkle 根哈希 (Merkle Root Hash): 用于验证数据完整性的数据结构。交易根哈希 (TxHash) 和提款根哈希 (WithdrawalsHash) 都是通过对交易列表和提款列表构建 Merkle 树得到的根节点哈希值。
// 完整性检查 (Sanity Check): convertPayload 函数会比较转换后得到的 types.Block 的哈希值与执行负载中预期的哈希值，这是一个重要的步骤，用于确保转换过程的正确性。

type payloadType interface {
	*capella.ExecutionPayload | *deneb.ExecutionPayload
}

// convertPayload converts a beacon chain execution payload to types.Block.
// convertPayload 将信标链的执行负载转换为 types.Block 类型。
func convertPayload[T payloadType](payload T, parentRoot *zrntcommon.Root) (*types.Block, error) {
	var (
		header       types.Header
		transactions []*types.Transaction
		withdrawals  []*types.Withdrawal
		expectedHash [32]byte
		err          error
	)
	switch p := any(payload).(type) {
	case *capella.ExecutionPayload:
		convertCapellaHeader(p, &header)
		transactions, err = convertTransactions(p.Transactions, &header)
		if err != nil {
			return nil, err
		}
		withdrawals = convertWithdrawals(p.Withdrawals, &header)
		expectedHash = p.BlockHash
	case *deneb.ExecutionPayload:
		convertDenebHeader(p, common.Hash(*parentRoot), &header)
		transactions, err = convertTransactions(p.Transactions, &header)
		if err != nil {
			return nil, err
		}
		withdrawals = convertWithdrawals(p.Withdrawals, &header)
		expectedHash = p.BlockHash
	default:
		panic("unsupported block type")
	}

	block := types.NewBlockWithHeader(&header).WithBody(types.Body{Transactions: transactions, Withdrawals: withdrawals})
	if hash := block.Hash(); hash != expectedHash {
		return nil, fmt.Errorf("sanity check failed, payload hash does not match (expected %x, got %x)", expectedHash, hash)
	}
	return block, nil
}

// convertCapellaHeader converts a Capella execution payload header to types.Header.
// convertCapellaHeader 将 Capella 执行负载的头部转换为 types.Header 类型。
func convertCapellaHeader(payload *capella.ExecutionPayload, h *types.Header) {
	// note: h.TxHash is set in convertTransactions
	// 注意: h.TxHash 在 convertTransactions 函数中设置。
	h.ParentHash = common.Hash(payload.ParentHash)
	// ParentHash: 父区块的哈希。
	h.UncleHash = types.EmptyUncleHash
	// UncleHash: 叔块的哈希，在 PoS 中通常为空。
	h.Coinbase = common.Address(payload.FeeRecipient)
	// Coinbase (FeeRecipient): 交易手续费的接收者地址。
	h.Root = common.Hash(payload.StateRoot)
	// Root (StateRoot): 世界状态的 Merkle 根。
	h.ReceiptHash = common.Hash(payload.ReceiptsRoot)
	// ReceiptHash (ReceiptsRoot): 交易回执的 Merkle 根。
	h.Bloom = types.Bloom(payload.LogsBloom)
	// Bloom (LogsBloom): 用于快速过滤日志的 Bloom 过滤器。
	h.Difficulty = common.Big0
	// Difficulty: 在 PoS 中通常为零。
	h.Number = new(big.Int).SetUint64(uint64(payload.BlockNumber))
	// Number (BlockNumber): 区块号。
	h.GasLimit = uint64(payload.GasLimit)
	// GasLimit: 区块允许的最大 Gas 消耗量。
	h.GasUsed = uint64(payload.GasUsed)
	// GasUsed: 区块中所有交易消耗的总 Gas 量。
	h.Time = uint64(payload.Timestamp)
	// Time (Timestamp): 区块的时间戳。
	h.Extra = []byte(payload.ExtraData)
	// Extra: 额外的区块数据。
	h.MixDigest = common.Hash(payload.PrevRandao)
	// MixDigest (PrevRandao): 用于权益证明的随机数。
	h.Nonce = types.BlockNonce{}
	// Nonce: 在 PoS 中通常为空。
	h.BaseFee = (*uint256.Int)(&payload.BaseFeePerGas).ToBig()
	// BaseFee: 每个 Gas 的基础费用，由 EIP-1559 引入。
}

// convertDenebHeader converts a Deneb execution payload header to types.Header.
// convertDenebHeader 将 Deneb 执行负载的头部转换为 types.Header 类型。
func convertDenebHeader(payload *deneb.ExecutionPayload, parentRoot common.Hash, h *types.Header) {
	// note: h.TxHash is set in convertTransactions
	// 注意: h.TxHash 在 convertTransactions 函数中设置。
	h.ParentHash = common.Hash(payload.ParentHash)
	// ParentHash: 父区块的哈希。
	h.UncleHash = types.EmptyUncleHash
	// UncleHash: 叔块的哈希，在 PoS 中通常为空。
	h.Coinbase = common.Address(payload.FeeRecipient)
	// Coinbase (FeeRecipient): 交易手续费的接收者地址。
	h.Root = common.Hash(payload.StateRoot)
	// Root (StateRoot): 世界状态的 Merkle 根。
	h.ReceiptHash = common.Hash(payload.ReceiptsRoot)
	// ReceiptHash (ReceiptsRoot): 交易回执的 Merkle 根。
	h.Bloom = types.Bloom(payload.LogsBloom)
	// Bloom (LogsBloom): 用于快速过滤日志的 Bloom 过滤器。
	h.Difficulty = common.Big0
	// Difficulty: 在 PoS 中通常为零。
	h.Number = new(big.Int).SetUint64(uint64(payload.BlockNumber))
	// Number (BlockNumber): 区块号。
	h.GasLimit = uint64(payload.GasLimit)
	// GasLimit: 区块允许的最大 Gas 消耗量。
	h.GasUsed = uint64(payload.GasUsed)
	// GasUsed: 区块中所有交易消耗的总 Gas 量。
	h.Time = uint64(payload.Timestamp)
	// Time (Timestamp): 区块的时间戳。
	h.Extra = []byte(payload.ExtraData)
	// Extra: 额外的区块数据。
	h.MixDigest = common.Hash(payload.PrevRandao)
	// MixDigest (PrevRandao): 用于权益证明的随机数。
	h.Nonce = types.BlockNonce{}
	// Nonce: 在 PoS 中通常为空。
	h.BaseFee = (*uint256.Int)(&payload.BaseFeePerGas).ToBig()
	// BaseFee: 每个 Gas 的基础费用，由 EIP-1559 引入。
	// new in deneb
	// 在 Deneb 中新增的字段。
	h.BlobGasUsed = (*uint64)(&payload.BlobGasUsed)
	// BlobGasUsed: 此区块中 blob 交易使用的总 gas 量。
	h.ExcessBlobGas = (*uint64)(&payload.ExcessBlobGas)
	// ExcessBlobGas: 此区块中 blob 交易的超额 gas 量。
	h.ParentBeaconRoot = &parentRoot
	// ParentBeaconRoot: 父信标区块的根哈希。
}

// convertTransactions converts a list of opaque transactions to types.Transaction.
// convertTransactions 将一个不透明的交易列表转换为 types.Transaction 类型。
func convertTransactions(list zrntcommon.PayloadTransactions, execHeader *types.Header) ([]*types.Transaction, error) {
	txs := make([]*types.Transaction, len(list))
	for i, opaqueTx := range list {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(opaqueTx); err != nil {
			return nil, fmt.Errorf("failed to parse tx %d: %v", i, err)
		}
		txs[i] = &tx
	}
	execHeader.TxHash = types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil))
	// TxHash: 区块中所有交易的 Merkle 根哈希。
	return txs, nil
}

// convertWithdrawals converts a list of zrnt withdrawals to types.Withdrawal.
// convertWithdrawals 将 zrnt 提款列表转换为 types.Withdrawal 类型。
func convertWithdrawals(list zrntcommon.Withdrawals, execHeader *types.Header) []*types.Withdrawal {
	withdrawals := make([]*types.Withdrawal, len(list))
	for i, w := range list {
		withdrawals[i] = &types.Withdrawal{
			Index: uint64(w.Index),
			// Index: 提款的索引。
			Validator: uint64(w.ValidatorIndex),
			// Validator: 验证者的索引。
			Address: common.Address(w.Address),
			// Address: 提款地址。
			Amount: uint64(w.Amount),
			// Amount: 提款金额 (以 Gwei 为单位)。
		}
	}
	wroot := types.DeriveSha(types.Withdrawals(withdrawals), trie.NewStackTrie(nil))
	execHeader.WithdrawalsHash = &wroot
	// WithdrawalsHash: 区块中所有提款的 Merkle 根哈希。
	return withdrawals
}
