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

package txpool

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var (
	// blobTxMinBlobGasPrice is the big.Int version of the configured protocol
	// parameter to avoid constructing a new big integer for every transaction.
	// blobTxMinBlobGasPrice 是已配置协议参数的 big.Int 版本，用于避免为每个交易构造一个新的 big integer。
	blobTxMinBlobGasPrice = big.NewInt(params.BlobTxMinBlobGasprice)
)

// ValidationOptions define certain differences between transaction validation
// across the different pools without having to duplicate those checks.
// ValidationOptions 定义了不同池之间交易验证的某些差异，而无需重复这些检查。
type ValidationOptions struct {
	Config *params.ChainConfig // Chain configuration to selectively validate based on current fork rules
	// Config 链配置，用于根据当前分叉规则有选择地进行验证。

	Accept uint8 // Bitmap of transaction types that should be accepted for the calling pool
	// Accept 位图，指示调用池应接受的交易类型。
	MaxSize uint64 // Maximum size of a transaction that the caller can meaningfully handle
	// MaxSize 调用者可以有效处理的交易的最大大小。
	MinTip *big.Int // Minimum gas tip needed to allow a transaction into the caller pool
	// MinTip 允许交易进入调用池所需的最低 gas 小费。
}

// ValidationFunction is an method type which the pools use to perform the tx-validations which do not
// require state access. Production code typically uses ValidateTransaction, whereas testing-code
// might choose to instead use something else, e.g. to always fail or avoid heavy cpu usage.
// ValidationFunction 是一种方法类型，池使用它来执行不需要状态访问的交易验证。
// 生产代码通常使用 ValidateTransaction，而测试代码可能会选择使用其他方法，例如，总是失败或避免大量的 CPU 使用。
type ValidationFunction func(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error

// ValidateTransaction is a helper method to check whether a transaction is valid
// according to the consensus rules, but does not check state-dependent validation
// (balance, nonce, etc).
// ValidateTransaction 是一个辅助方法，用于根据共识规则检查交易是否有效，但不检查依赖于状态的验证（余额、nonce 等）。
//
// This check is public to allow different transaction pools to check the basic
// rules without duplicating code and running the risk of missed updates.
// 此检查是公开的，允许不同的交易池检查基本规则，而无需重复代码并避免错过更新的风险。
func ValidateTransaction(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error {
	// Ensure transactions not implemented by the calling pool are rejected
	// 确保拒绝调用池未实现的交易。
	if opts.Accept&(1<<tx.Type()) == 0 {
		return fmt.Errorf("%w: tx type %v not supported by this pool", core.ErrTxTypeNotSupported, tx.Type())
	}
	// Before performing any expensive validations, sanity check that the tx is
	// smaller than the maximum limit the pool can meaningfully handle
	// 在执行任何昂贵的验证之前，初步检查交易是否小于池可以有效处理的最大限制。
	if tx.Size() > opts.MaxSize {
		return fmt.Errorf("%w: transaction size %v, limit %v", ErrOversizedData, tx.Size(), opts.MaxSize)
	}
	// Ensure only transactions that have been enabled are accepted
	// 确保只接受已启用的交易。
	if !opts.Config.IsBerlin(head.Number) && tx.Type() != types.LegacyTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Berlin", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !opts.Config.IsLondon(head.Number) && tx.Type() == types.DynamicFeeTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in London", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !opts.Config.IsCancun(head.Number, head.Time) && tx.Type() == types.BlobTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Cancun", core.ErrTxTypeNotSupported, tx.Type())
	}
	// Check whether the init code size has been exceeded
	// 检查是否超过了 init 代码大小限制。
	if opts.Config.IsShanghai(head.Number, head.Time) && tx.To() == nil && len(tx.Data()) > params.MaxInitCodeSize {
		return fmt.Errorf("%w: code size %v, limit %v", core.ErrMaxInitCodeSizeExceeded, len(tx.Data()), params.MaxInitCodeSize)
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur for transactions created using the RPC.
	// 交易不能为负数。使用 RLP 解码的交易永远不会发生这种情况，但对于使用 RPC 创建的交易可能会发生。
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	// Ensure the transaction doesn't exceed the current block limit gas
	// 确保交易不超过当前区块的 gas 限制。
	if head.GasLimit < tx.Gas() {
		return ErrGasLimit
	}
	// Sanity check for extremely large numbers (supported by RLP or RPC)
	// 对极大数字（RLP 或 RPC 支持）进行合理性检查。
	if tx.GasFeeCap().BitLen() > 256 {
		return core.ErrFeeCapVeryHigh
	}
	if tx.GasTipCap().BitLen() > 256 {
		return core.ErrTipVeryHigh
	}
	// Ensure gasFeeCap is greater than or equal to gasTipCap
	// 确保 gasFeeCap 大于或等于 gasTipCap。
	if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
		return core.ErrTipAboveFeeCap
	}
	// Make sure the transaction is signed properly
	// 确保交易已正确签名。
	if _, err := types.Sender(signer, tx); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSender, err)
	}
	// Ensure the transaction has more gas than the bare minimum needed to cover
	// the transaction metadata
	// 确保交易的 gas 大于覆盖交易元数据所需的最低 gas 量。
	intrGas, err := core.IntrinsicGas(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), tx.To() == nil, true, opts.Config.IsIstanbul(head.Number), opts.Config.IsShanghai(head.Number, head.Time))
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return fmt.Errorf("%w: gas %v, minimum needed %v", core.ErrIntrinsicGas, tx.Gas(), intrGas)
	}
	// Ensure the gasprice is high enough to cover the requirement of the calling pool
	// 确保 gasprice 足够高，以满足调用池的要求。
	if tx.GasTipCapIntCmp(opts.MinTip) < 0 {
		return fmt.Errorf("%w: gas tip cap %v, minimum needed %v", ErrUnderpriced, tx.GasTipCap(), opts.MinTip)
	}
	if tx.Type() == types.BlobTxType {
		// Ensure the blob fee cap satisfies the minimum blob gas price
		// 确保 blob 费用上限满足最低 blob gas 价格。
		if tx.BlobGasFeeCapIntCmp(blobTxMinBlobGasPrice) < 0 {
			return fmt.Errorf("%w: blob fee cap %v, minimum needed %v", ErrUnderpriced, tx.BlobGasFeeCap(), blobTxMinBlobGasPrice)
		}
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			return errors.New("missing sidecar in blob transaction")
		}
		// Ensure the number of items in the blob transaction and various side
		// data match up before doing any expensive validations
		// 在进行任何昂贵的验证之前，确保 blob 交易中的项目数量和各种辅助数据匹配。
		hashes := tx.BlobHashes()
		if len(hashes) == 0 {
			return errors.New("blobless blob transaction")
		}
		if len(hashes) > params.MaxBlobGasPerBlock/params.BlobTxBlobGasPerBlob {
			return fmt.Errorf("too many blobs in transaction: have %d, permitted %d", len(hashes), params.MaxBlobGasPerBlock/params.BlobTxBlobGasPerBlob)
		}
		// Ensure commitments, proofs and hashes are valid
		// 确保承诺、证明和哈希有效。
		if err := validateBlobSidecar(hashes, sidecar); err != nil {
			return err
		}
	}
	return nil
}

func validateBlobSidecar(hashes []common.Hash, sidecar *types.BlobTxSidecar) error {
	if len(sidecar.Blobs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blobs compared to %d blob hashes", len(sidecar.Blobs), len(hashes))
	}
	if len(sidecar.Commitments) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob commitments compared to %d blob hashes", len(sidecar.Commitments), len(hashes))
	}
	if len(sidecar.Proofs) != len(hashes) {
		return fmt.Errorf("invalid number of %d blob proofs compared to %d blob hashes", len(sidecar.Proofs), len(hashes))
	}
	// Blob quantities match up, validate that the provers match with the
	// transaction hash before getting to the cryptography
	// Blob 数量匹配，在进行密码学验证之前，验证证明者是否与交易哈希匹配。
	hasher := sha256.New()
	for i, vhash := range hashes {
		computed := kzg4844.CalcBlobHashV1(hasher, &sidecar.Commitments[i])
		if vhash != computed {
			return fmt.Errorf("blob %d: computed hash %#x mismatches transaction one %#x", i, computed, vhash)
		}
	}
	// Blob commitments match with the hashes in the transaction, verify the
	// blobs themselves via KZG
	// Blob 承诺与交易中的哈希匹配，通过 KZG 验证 blob 本身。
	for i := range sidecar.Blobs {
		if err := kzg4844.VerifyBlobProof(&sidecar.Blobs[i], sidecar.Commitments[i], sidecar.Proofs[i]); err != nil {
			return fmt.Errorf("invalid blob %d: %v", i, err)
		}
	}
	return nil
}

// ValidationOptionsWithState define certain differences between stateful transaction
// validation across the different pools without having to duplicate those checks.
// ValidationOptionsWithState 定义了不同池之间有状态交易验证的某些差异，而无需重复这些检查。
type ValidationOptionsWithState struct {
	State *state.StateDB // State database to check nonces and balances against
	// State 状态数据库，用于检查 nonce 和余额。

	// FirstNonceGap is an optional callback to retrieve the first nonce gap in
	// the list of pooled transactions of a specific account. If this method is
	// set, nonce gaps will be checked and forbidden. If this method is not set,
	// nonce gaps will be ignored and permitted.
	// FirstNonceGap 是一个可选的回调函数，用于检索特定账户的池化交易列表中第一个 nonce 间隙。
	// 如果设置了此方法，将检查并禁止 nonce 间隙。如果未设置此方法，将忽略并允许 nonce 间隙。
	FirstNonceGap func(addr common.Address) uint64

	// UsedAndLeftSlots is a mandatory callback to retrieve the number of tx slots
	// used and the number still permitted for an account. New transactions will
	// be rejected once the number of remaining slots reaches zero.
	// UsedAndLeftSlots 是一个强制回调函数，用于检索一个账户已使用的交易槽位数和剩余的允许槽位数。
	// 一旦剩余的槽位数达到零，新的交易将被拒绝。
	UsedAndLeftSlots func(addr common.Address) (int, int)

	// ExistingExpenditure is a mandatory callback to retrieve the cumulative
	// cost of the already pooled transactions to check for overdrafts.
	// ExistingExpenditure 是一个强制回调函数，用于检索已池化交易的累计成本，以检查是否透支。
	ExistingExpenditure func(addr common.Address) *big.Int

	// ExistingCost is a mandatory callback to retrieve an already pooled
	// transaction's cost with the given nonce to check for overdrafts.
	// ExistingCost 是一个强制回调函数，用于检索具有给定 nonce 的已池化交易的成本，以检查是否透支。
	ExistingCost func(addr common.Address, nonce uint64) *big.Int
}

// ValidateTransactionWithState is a helper method to check whether a transaction
// is valid according to the pool's internal state checks (balance, nonce, gaps).
// ValidateTransactionWithState 是一个辅助方法，用于根据池的内部状态检查（余额、nonce、间隙）来检查交易是否有效。
//
// This check is public to allow different transaction pools to check the stateful
// rules without duplicating code and running the risk of missed updates.
// 此检查是公开的，允许不同的交易池检查有状态规则，而无需重复代码并避免错过更新的风险。
func ValidateTransactionWithState(tx *types.Transaction, signer types.Signer, opts *ValidationOptionsWithState) error {
	// Ensure the transaction adheres to nonce ordering
	// 确保交易遵循 nonce 排序。
	from, err := types.Sender(signer, tx) // already validated (and cached), but cleaner to check
	// 已经验证（并缓存），但为了代码更清晰，这里再次检查。
	if err != nil {
		log.Error("Transaction sender recovery failed", "err", err)
		return err
	}
	next := opts.State.GetNonce(from)
	if next > tx.Nonce() {
		return fmt.Errorf("%w: next nonce %v, tx nonce %v", core.ErrNonceTooLow, next, tx.Nonce())
	}
	// Ensure the transaction doesn't produce a nonce gap in pools that do not
	// support arbitrary orderings
	// 确保交易在不支持任意排序的池中不会产生 nonce 间隙。
	if opts.FirstNonceGap != nil {
		if gap := opts.FirstNonceGap(from); gap < tx.Nonce() {
			return fmt.Errorf("%w: tx nonce %v, gapped nonce %v", core.ErrNonceTooHigh, tx.Nonce(), gap)
		}
	}
	// Ensure the transactor has enough funds to cover the transaction costs
	// 确保交易发送者有足够的资金来支付交易成本。
	var (
		balance = opts.State.GetBalance(from).ToBig()
		cost    = tx.Cost()
	)
	if balance.Cmp(cost) < 0 {
		return fmt.Errorf("%w: balance %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, cost, new(big.Int).Sub(cost, balance))
	}
	// Ensure the transactor has enough funds to cover for replacements or nonce
	// expansions without overdrafts
	// 确保交易发送者有足够的资金来支付替换或 nonce 扩展，而不会透支。
	spent := opts.ExistingExpenditure(from)
	if prev := opts.ExistingCost(from, tx.Nonce()); prev != nil {
		bump := new(big.Int).Sub(cost, prev)
		need := new(big.Int).Add(spent, bump)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx bumped %v, overshot %v", core.ErrInsufficientFunds, balance, spent, bump, new(big.Int).Sub(need, balance))
		}
	} else {
		need := new(big.Int).Add(spent, cost)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, spent, cost, new(big.Int).Sub(need, balance))
		}
		// Transaction takes a new nonce value out of the pool. Ensure it doesn't
		// overflow the number of permitted transactions from a single account
		// (i.e. max cancellable via out-of-bound transaction).
		// 交易从池中取出一个新的 nonce 值。确保它不会超过单个账户允许的交易数量限制
		// （即，可以通过越界交易取消的最大数量）。
		if used, left := opts.UsedAndLeftSlots(from); left <= 0 {
			return fmt.Errorf("%w: pooled %d txs", ErrAccountLimitExceeded, used)
		}
	}
	return nil
}
