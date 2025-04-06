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

package core

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// 区块验证的重要性
//
// 当一个节点接收到一个新的区块时，它必须验证该区块是否符合以太坊协议的规则。这包括检查区块头、区块体（包含交易和叔块等）以及执行交易后产生的状态变化。只有通过验证的区块才会被节点接受并添加到其本地区块链副本中。区块验证确保了没有恶意或错误的区块被添加到链上，从而保护了整个网络的安全性。

// 根哈希的重要性
//
// 在区块验证过程中，各种根哈希（叔块根、交易根、取款根、收据根、状态根）起着至关重要的作用。它们通过 Merkle 树这种数据结构，能够高效地验证区块中包含的大量数据是否被篡改。任何对区块体中数据的微小改动都会导致根哈希值的巨大变化。因此，通过比较区块头中承诺的根哈希值与根据区块体实际计算出的根哈希值，节点可以快速且可靠地验证区块数据的完整性。
//

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
// BlockValidator 负责验证区块头、叔块和处理后的状态。
//
// BlockValidator 实现了 Validator 接口。
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	// config 链的配置选项。
	bc *BlockChain // Canonical block chain
	// bc 规范的区块链。
}

// NewBlockValidator returns a new block validator which is safe for re-use
// NewBlockValidator 返回一个新的区块验证器，该验证器可以安全地重复使用。
func NewBlockValidator(config *params.ChainConfig, blockchain *BlockChain) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		bc:     blockchain,
	}
	return validator
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
// ValidateBody 验证给定区块的叔块，并验证区块头的交易根和叔块根。此时假定区块头已经过验证。
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whether the block is already imported.
	// 检查区块是否已被导入。
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}

	// Header validity is known at this point. Here we verify that uncles, transactions
	// and withdrawals given in the block body match the header.
	// 此时区块头的有效性是已知的。这里我们验证区块体中给出的叔块、交易和取款是否与区块头匹配。
	header := block.Header()
	if err := v.bc.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch (header value %x, calculated %x)", header.UncleHash, hash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch (header value %x, calculated %x)", header.TxHash, hash)
	}

	// Withdrawals are present after the Shanghai fork.
	// 上海分叉后存在取款。
	if header.WithdrawalsHash != nil {
		// Withdrawals list must be present in body after Shanghai.
		// 上海分叉后，区块体中必须存在取款列表。
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch (header value %x, calculated %x)", *header.WithdrawalsHash, hash)
		}
	} else if block.Withdrawals() != nil {
		// Withdrawals are not allowed prior to Shanghai fork
		// 上海分叉之前不允许取款。
		return errors.New("withdrawals present in block body")
	}

	// Blob transactions may be present after the Cancun fork.
	// Cancun 分叉后可能存在 Blob 交易。
	var blobs int
	for i, tx := range block.Transactions() {
		// Count the number of blobs to validate against the header's blobGasUsed
		// 计算 Blob 的数量，以便对照区块头的 blobGasUsed 进行验证。
		blobs += len(tx.BlobHashes())

		// If the tx is a blob tx, it must NOT have a sidecar attached to be valid in a block.
		// 如果交易是 Blob 交易，为了在区块中有效，它不能附加 sidecar。
		if tx.BlobTxSidecar() != nil {
			return fmt.Errorf("unexpected blob sidecar in transaction at index %d", i)
		}

		// The individual checks for blob validity (version-check + not empty)
		// happens in state transition.
		// Blob 有效性的单独检查（版本检查 + 非空）发生在状态转换中。
	}

	// Check blob gas usage.
	// 检查 Blob Gas 的使用情况。
	if header.BlobGasUsed != nil {
		if want := *header.BlobGasUsed / params.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
			return fmt.Errorf("blob gas used mismatch (header %v, calculated %v)", *header.BlobGasUsed, blobs*params.BlobTxBlobGasPerBlob)
		}
	} else {
		if blobs > 0 {
			return errors.New("data blobs present in block body")
		}
	}

	// Ancestor block must be known.
	// 必须已知祖先区块。
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	return nil
}

// ValidateState validates the various changes that happen after a state transition,
// such as amount of used gas, the receipt roots and the state root itself.
// ValidateState 验证状态转换后发生的各种更改，例如已用 Gas 量、收据根和状态根本身。
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, res *ProcessResult, stateless bool) error {
	if res == nil {
		return errors.New("nil ProcessResult value")
	}
	header := block.Header()
	if block.GasUsed() != res.GasUsed {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), res.GasUsed)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	// 使用从生成的收据派生的 Bloom 过滤器验证接收到的区块的 Bloom 过滤器。对于有效的区块，这应该始终验证为 true。
	rbloom := types.CreateBloom(res.Receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// In stateless mode, return early because the receipt and state root are not
	// provided through the witness, rather the cross validator needs to return it.
	// 在无状态模式下，提前返回，因为收据根和状态根不是通过见证提供的，而是需要交叉验证器返回它。
	if stateless {
		return nil
	}
	// The receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	// 收据 Trie 的根 (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	receiptSha := types.DeriveSha(res.Receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the parsed requests match the expected header value.
	// 验证解析的请求是否与预期的头部值匹配。
	if header.RequestsHash != nil {
		reqhash := types.CalcRequestsHash(res.Requests)
		if reqhash != *header.RequestsHash {
			return fmt.Errorf("invalid requests hash (remote: %x local: %x)", *header.RequestsHash, reqhash)
		}
	} else if res.Requests != nil {
		return errors.New("block has requests before prague fork")
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	// 针对接收到的状态根验证状态根，如果它们不匹配则抛出错误。
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x) dberr: %w", header.Root, root, statedb.Error())
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
// CalcGasLimit 计算父区块之后下一个区块的 Gas 限制。它的目标是使基线 Gas 接近提供的目标，
// 如果基线 Gas 较低，则将其增加到目标值。
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	// 如果我们超出允许的 Gas 范围，我们会尝试向它们靠拢。
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
