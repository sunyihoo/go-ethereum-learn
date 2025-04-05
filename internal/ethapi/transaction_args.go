// Copyright 2021 The go-ethereum Authors
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

package ethapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

var (
	maxBlobsPerTransaction = params.MaxBlobGasPerBlock / params.BlobTxBlobGasPerBlob
)

// TransactionArgs represents the arguments to construct a new transaction
// or a message call.
// TransactionArgs 表示构造新交易或消息调用的参数。
type TransactionArgs struct {
	From                 *common.Address `json:"from"`                 // Sender address. Omitted if CreateTx is used. 发送者地址。如果使用 CreateTx，则省略。
	To                   *common.Address `json:"to"`                   // Recipient address. Omitted if contract creation. 接收者地址。如果创建合约，则省略。
	Gas                  *hexutil.Uint64 `json:"gas"`                  // Gas limit. 交易的 Gas 上限。
	GasPrice             *hexutil.Big    `json:"gasPrice"`             // Gas price for legacy transactions. 传统交易的 Gas 价格。
	MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas"`         // Maximum fee per unit of gas willing to pay (EIP-1559). 愿意支付的每单位 Gas 的最高费用 (EIP-1559)。
	MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas"` // Fee per unit of gas to reward the miner (EIP-1559). 奖励矿工的每单位 Gas 的费用 (EIP-1559)。
	Value                *hexutil.Big    `json:"value"`                // Amount of ether to transfer. 要转移的以太币数量。
	Nonce                *hexutil.Uint64 `json:"nonce"`                // Transaction nonce. 交易的 Nonce 值。

	// We accept "data" and "input" for backwards-compatibility reasons.
	// "input" is the newer name and should be preferred by clients.
	// Issue detail: https://github.com/ethereum/go-ethereum/issues/15628
	// 为了向后兼容，我们接受 "data" 和 "input"。
	// "input" 是较新的名称，客户端应优先使用。
	// 问题详情：https://github.com/ethereum/go-ethereum/issues/15628
	Data  *hexutil.Bytes `json:"data"`  // Transaction data (optional). 交易数据（可选）。
	Input *hexutil.Bytes `json:"input"` // Transaction data (optional). 交易数据（可选）。

	// Introduced by AccessListTxType transaction.
	// 由 AccessListTxType 交易引入。
	AccessList *types.AccessList `json:"accessList,omitempty"` // Access list (EIP-2930). 访问列表 (EIP-2930)。
	ChainID    *hexutil.Big      `json:"chainId,omitempty"`    // Chain ID (EIP-155). 链 ID (EIP-155)。

	// For BlobTxType
	// 用于 BlobTxType。这是 EIP-4844 引入的交易类型，用于处理数据 Blob。
	BlobFeeCap *hexutil.Big  `json:"maxFeePerBlobGas"`              // Maximum fee per unit of blob gas willing to pay (EIP-4844). 愿意支付的每单位 Blob Gas 的最高费用 (EIP-4844)。
	BlobHashes []common.Hash `json:"blobVersionedHashes,omitempty"` // List of blob hashes (EIP-4844). Blob 哈希列表 (EIP-4844)。

	// For BlobTxType transactions with blob sidecar
	// 用于带有 Blob Sidecar 的 BlobTxType 交易。Blob Sidecar 包含了交易的 Blob 数据，与主交易分开传输。
	Blobs       []kzg4844.Blob       `json:"blobs"`       // List of blobs (EIP-4844). Blob 列表 (EIP-4844)。
	Commitments []kzg4844.Commitment `json:"commitments"` // List of KZG commitments for the blobs (EIP-4844). Blob 的 KZG 承诺列表 (EIP-4844)。
	Proofs      []kzg4844.Proof      `json:"proofs"`      // List of KZG proofs for the blobs (EIP-4844). Blob 的 KZG 证明列表 (EIP-4844)。

	// For SetCodeTxType
	// 用于 SetCodeTxType。这是一个用于修改合约代码的特殊交易类型。
	AuthorizationList []types.SetCodeAuthorization `json:"authorizationList"` // List of authorized addresses to set code (EIP-3607). 设置代码的授权地址列表 (EIP-3607)。

	// This configures whether blobs are allowed to be passed.
	// 此配置确定是否允许传递 Blob。
	blobSidecarAllowed bool
}

// from retrieves the transaction sender address.
// from 方法检索交易发送者的地址。
func (args *TransactionArgs) from() common.Address {
	if args.From == nil {
		return common.Address{}
	}
	return *args.From
}

// data retrieves the transaction calldata. Input field is preferred.
// data 方法检索交易的 calldata。建议优先使用 Input 字段。
func (args *TransactionArgs) data() []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

// setDefaults fills in default values for unspecified tx fields.
// setDefaults 方法为未指定的交易字段填充默认值。
func (args *TransactionArgs) setDefaults(ctx context.Context, b Backend, skipGasEstimation bool) error {
	// 设置 Blob 交易的 Sidecar。Sidecar 包含 Blob 数据，允许在支持 EIP-4844 的网络中发送大数据。
	if err := args.setBlobTxSidecar(ctx); err != nil {
		return err
	}
	// 设置交易费用的默认值，包括处理 EIP-1559 的费用参数。
	if err := args.setFeeDefaults(ctx, b, b.CurrentHeader()); err != nil {
		return err
	}

	// 如果 Value 为空，则将其初始化为零。Value 代表要转移的以太币数量。
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	// 如果 Nonce 为空，则从 Backend 获取发送者的下一个可用 Nonce。Nonce 用于防止交易重放。
	if args.Nonce == nil {
		nonce, err := b.GetPoolNonce(ctx, args.from())
		if err != nil {
			return err
		}
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}
	// 检查是否同时设置了 Data 和 Input 字段，并且它们的值不相等。如果发生这种情况，建议使用 Input 字段。
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return errors.New(`both "data" and "input" are set and not equal. Please use "input" to pass transaction call data`)
	}

	// BlobTx fields
	// 检查 Blob 交易的 BlobHashes 是否为空。Blob 交易至少需要一个 Blob。
	if args.BlobHashes != nil && len(args.BlobHashes) == 0 {
		return errors.New(`need at least 1 blob for a blob transaction`)
	}
	// 检查 Blob 交易中的 Blob 数量是否超过了每个交易允许的最大 Blob 数量。
	if args.BlobHashes != nil && len(args.BlobHashes) > maxBlobsPerTransaction {
		return fmt.Errorf(`too many blobs in transaction (have=%d, max=%d)`, len(args.BlobHashes), maxBlobsPerTransaction)
	}

	// create check
	// 如果 To 地址为空，则表示这是一笔合约创建交易。
	if args.To == nil {
		// Blob 交易不能是合约创建交易。
		if args.BlobHashes != nil {
			return errors.New(`missing "to" in blob transaction`)
		}
		// 如果是合约创建交易，但没有提供任何数据，则返回错误。
		if len(args.data()) == 0 {
			return errors.New(`contract creation without any data provided`)
		}
	}

	// 如果 Gas 为空，则根据 skipGasEstimation 的值来决定是否跳过 Gas 估计。
	if args.Gas == nil {
		if skipGasEstimation { // Skip gas usage estimation if a precise gas limit is not critical, e.g., in non-transaction calls.
			// 如果不需要精确的 Gas 限制（例如，在非交易调用中），则跳过 Gas 使用量估计。
			gas := hexutil.Uint64(b.RPCGasCap())
			if gas == 0 {
				gas = hexutil.Uint64(math.MaxUint64 / 2)
			}
			args.Gas = &gas
		} else { // Estimate the gas usage otherwise.
			// 否则，估计 Gas 的使用量。
			// These fields are immutable during the estimation, safe to
			// pass the pointer directly.
			// 这些字段在估计期间是不可变的，可以直接传递指针。
			data := args.data()
			callArgs := TransactionArgs{
				From:                 args.From,
				To:                   args.To,
				GasPrice:             args.GasPrice,
				MaxFeePerGas:         args.MaxFeePerGas,
				MaxPriorityFeePerGas: args.MaxPriorityFeePerGas,
				Value:                args.Value,
				Data:                 (*hexutil.Bytes)(&data),
				AccessList:           args.AccessList,
				BlobFeeCap:           args.BlobFeeCap,
				BlobHashes:           args.BlobHashes,
			}
			latestBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
			// 调用 DoEstimateGas 函数来估计执行此交易所需的 Gas 量。
			estimated, err := DoEstimateGas(ctx, b, callArgs, latestBlockNr, nil, nil, b.RPCGasCap())
			if err != nil {
				return err
			}
			args.Gas = &estimated
			log.Trace("Estimate gas usage automatically", "gas", args.Gas)
		}
	}

	// If chain id is provided, ensure it matches the local chain id. Otherwise, set the local
	// chain id as the default.
	// 如果提供了 Chain ID，则确保它与本地 Chain ID 匹配。否则，将本地 Chain ID 设置为默认值。
	want := b.ChainConfig().ChainID
	if args.ChainID != nil {
		if have := (*big.Int)(args.ChainID); have.Cmp(want) != 0 {
			return fmt.Errorf("chainId does not match node's (have=%v, want=%v)", have, want)
		}
	} else {
		args.ChainID = (*hexutil.Big)(want)
	}
	return nil
}

// setFeeDefaults fills in default fee values for unspecified tx fields.
// setFeeDefaults 方法为未指定的交易费用字段填充默认值。
func (args *TransactionArgs) setFeeDefaults(ctx context.Context, b Backend, head *types.Header) error {
	// Sanity check the EIP-4844 fee parameters.
	// 对 EIP-4844 的费用参数进行健全性检查。
	if args.BlobFeeCap != nil && args.BlobFeeCap.ToInt().Sign() == 0 {
		return errors.New("maxFeePerBlobGas, if specified, must be non-zero")
	}
	// 设置 Cancun 升级后的默认费用参数，包括 Blob 相关的费用。
	args.setCancunFeeDefaults(head)
	// If both gasPrice and at least one of the EIP-1559 fee parameters are specified, error.
	// 如果同时指定了 gasPrice 和至少一个 EIP-1559 的费用参数，则返回错误。
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil) {
		return errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	}
	// If the tx has completely specified a fee mechanism, no default is needed.
	// This allows users who are not yet synced past London to get defaults for
	// other tx values. See https://github.com/ethereum/go-ethereum/pull/23274
	// for more information.
	// 如果交易已经完全指定了一种费用机制，则不需要默认值。
	// 这允许尚未同步到伦敦升级的用户获取其他交易值的默认值。
	// 有关更多信息，请参阅 https://github.com/ethereum/go-ethereum/pull/23274。
	eip1559ParamsSet := args.MaxFeePerGas != nil && args.MaxPriorityFeePerGas != nil
	// Sanity check the EIP-1559 fee parameters if present.
	// 如果存在 EIP-1559 的费用参数，则对其进行健全性检查。
	if args.GasPrice == nil && eip1559ParamsSet {
		if args.MaxFeePerGas.ToInt().Sign() == 0 {
			return errors.New("maxFeePerGas must be non-zero")
		}
		if args.MaxFeePerGas.ToInt().Cmp(args.MaxPriorityFeePerGas.ToInt()) < 0 {
			return fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", args.MaxFeePerGas, args.MaxPriorityFeePerGas)
		}
		return nil // No need to set anything, user already set MaxFeePerGas and MaxPriorityFeePerGas
		// 无需设置任何内容，用户已设置 MaxFeePerGas 和 MaxPriorityFeePerGas。
	}

	// Sanity check the non-EIP-1559 fee parameters.
	// 对非 EIP-1559 的费用参数进行健全性检查。
	isLondon := b.ChainConfig().IsLondon(head.Number)
	if args.GasPrice != nil && !eip1559ParamsSet {
		// Zero gas-price is not allowed after London fork
		// 在伦敦升级后不允许零 Gas 价格。伦敦升级引入了 EIP-1559，改变了 Gas 费用的计算方式。
		if args.GasPrice.ToInt().Sign() == 0 && isLondon {
			return errors.New("gasPrice must be non-zero after london fork")
		}
		return nil // No need to set anything, user already set GasPrice
		// 无需设置任何内容，用户已设置 GasPrice。
	}

	// Now attempt to fill in default value depending on whether London is active or not.
	// 现在尝试根据伦敦升级是否激活来填充默认值。
	if isLondon {
		// London is active, set maxPriorityFeePerGas and maxFeePerGas.
		// 伦敦升级已激活，设置 maxPriorityFeePerGas 和 maxFeePerGas。这是 EIP-1559 引入的费用参数。
		if err := args.setLondonFeeDefaults(ctx, head, b); err != nil {
			return err
		}
	} else {
		if args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil {
			return errors.New("maxFeePerGas and maxPriorityFeePerGas are not valid before London is active")
		}
		// London not active, set gas price.
		// 伦敦升级未激活，设置 Gas 价格。这是在伦敦升级之前的传统费用参数。
		price, err := b.SuggestGasTipCap(ctx)
		if err != nil {
			return err
		}
		args.GasPrice = (*hexutil.Big)(price)
	}
	return nil
}

// setCancunFeeDefaults fills in reasonable default fee values for unspecified fields.
// setCancunFeeDefaults 方法为未指定的字段填充合理的默认费用值。
func (args *TransactionArgs) setCancunFeeDefaults(head *types.Header) {
	// Set maxFeePerBlobGas if it is missing.
	// 如果 maxFeePerBlobGas 缺失，则设置它。这是为 EIP-4844 引入的 Blob 交易设置最大费用。
	if args.BlobHashes != nil && args.BlobFeeCap == nil {
		var excessBlobGas uint64
		if head.ExcessBlobGas != nil {
			excessBlobGas = *head.ExcessBlobGas
		}
		// ExcessBlobGas must be set for a Cancun block.
		// 对于 Cancun 块，必须设置 ExcessBlobGas。ExcessBlobGas 跟踪区块中剩余的 Blob Gas。
		blobBaseFee := eip4844.CalcBlobFee(excessBlobGas)
		// Set the max fee to be 2 times larger than the previous block's blob base fee.
		// The additional slack allows the tx to not become invalidated if the base
		// fee is rising.
		// 将最大费用设置为前一个区块的 Blob 基础费用的 2 倍。
		// 额外的余量允许交易在基础费用上涨时不会失效。
		val := new(big.Int).Mul(blobBaseFee, big.NewInt(2))
		args.BlobFeeCap = (*hexutil.Big)(val)
	}
}

// setLondonFeeDefaults fills in reasonable default fee values for unspecified fields.
// setLondonFeeDefaults 方法为未指定的字段填充合理的默认费用值。这是针对伦敦升级 (EIP-1559) 后的费用参数。
func (args *TransactionArgs) setLondonFeeDefaults(ctx context.Context, head *types.Header, b Backend) error {
	// Set maxPriorityFeePerGas if it is missing.
	// 如果 maxPriorityFeePerGas 缺失，则设置它。这是矿工的小费，鼓励矿工打包交易。
	if args.MaxPriorityFeePerGas == nil {
		tip, err := b.SuggestGasTipCap(ctx)
		if err != nil {
			return err
		}
		args.MaxPriorityFeePerGas = (*hexutil.Big)(tip)
	}
	// Set maxFeePerGas if it is missing.
	// 如果 maxFeePerGas 缺失，则设置它。这是用户愿意为每单位 Gas 支付的最高费用，包括基础费用和小费。
	if args.MaxFeePerGas == nil {
		// Set the max fee to be 2 times larger than the previous block's base fee.
		// The additional slack allows the tx to not become invalidated if the base
		// fee is rising.
		// 将最大费用设置为前一个区块的基础费用的 2 倍加上用户设置的小费。
		// 额外的余量允许交易在基础费用上涨时不会失效。
		val := new(big.Int).Add(
			args.MaxPriorityFeePerGas.ToInt(),
			new(big.Int).Mul(head.BaseFee, big.NewInt(2)),
		)
		args.MaxFeePerGas = (*hexutil.Big)(val)
	}
	// Both EIP-1559 fee parameters are now set; sanity check them.
	// 现在已设置所有 EIP-1559 的费用参数；对其进行健全性检查。
	if args.MaxFeePerGas.ToInt().Cmp(args.MaxPriorityFeePerGas.ToInt()) < 0 {
		return fmt.Errorf("maxFeePerGas (%v) < maxPriorityFeePerGas (%v)", args.MaxFeePerGas, args.MaxPriorityFeePerGas)
	}
	return nil
}

// setBlobTxSidecar adds the blob tx
// setBlobTxSidecar 方法添加 Blob 交易的 Sidecar 信息。
func (args *TransactionArgs) setBlobTxSidecar(ctx context.Context) error {
	// No blobs, we're done.
	// 如果没有 Blob，则完成。
	if args.Blobs == nil {
		return nil
	}

	// Passing blobs is not allowed in all contexts, only in specific methods.
	// 并非所有上下文中都允许传递 Blob，仅在特定方法中允许。
	if !args.blobSidecarAllowed {
		return errors.New(`"blobs" is not supported for this RPC method`)
	}

	n := len(args.Blobs)
	// Assume user provides either only blobs (w/o hashes), or
	// blobs together with commitments and proofs.
	// 假设用户仅提供 Blob（没有哈希），或者同时提供 Blob、承诺和证明。
	if args.Commitments == nil && args.Proofs != nil {
		return errors.New(`blob proofs provided while commitments were not`)
	} else if args.Commitments != nil && args.Proofs == nil {
		return errors.New(`blob commitments provided while proofs were not`)
	}

	// len(blobs) == len(commitments) == len(proofs) == len(hashes)
	// Blob、承诺、证明和哈希的数量必须相等。
	if args.Commitments != nil && len(args.Commitments) != n {
		return fmt.Errorf("number of blobs and commitments mismatch (have=%d, want=%d)", len(args.Commitments), n)
	}
	if args.Proofs != nil && len(args.Proofs) != n {
		return fmt.Errorf("number of blobs and proofs mismatch (have=%d, want=%d)", len(args.Proofs), n)
	}
	if args.BlobHashes != nil && len(args.BlobHashes) != n {
		return fmt.Errorf("number of blobs and hashes mismatch (have=%d, want=%d)", len(args.BlobHashes), n)
	}

	if args.Commitments == nil {
		// Generate commitment and proof.
		// 生成承诺和证明。这是使用 KZG 承诺方案来确保 Blob 数据的可用性。
		commitments := make([]kzg4844.Commitment, n)
		proofs := make([]kzg4844.Proof, n)
		for i, b := range args.Blobs {
			c, err := kzg4844.BlobToCommitment(&b)
			if err != nil {
				return fmt.Errorf("blobs[%d]: error computing commitment: %v", i, err)
			}
			commitments[i] = c
			p, err := kzg4844.ComputeBlobProof(&b, c)
			if err != nil {
				return fmt.Errorf("blobs[%d]: error computing proof: %v", i, err)
			}
			proofs[i] = p
		}
		args.Commitments = commitments
		args.Proofs = proofs
	} else {
		// Verify provided commitment and proof.
		// 验证提供的承诺和证明。
		for i, b := range args.Blobs {
			if err := kzg4844.VerifyBlobProof(&b, args.Commitments[i], args.Proofs[i]); err != nil {
				return fmt.Errorf("failed to verify blob proof: %v", err)
			}
		}
	}

	hashes := make([]common.Hash, n)
	hasher := sha256.New()
	for i, c := range args.Commitments {
		// Calculate the blob hash from the commitment.
		// 从承诺计算 Blob 的哈希值。
		hashes[i] = kzg4844.CalcBlobHashV1(hasher, &c)
	}
	if args.BlobHashes != nil {
		// Verify the calculated blob hash against the provided hash.
		// 将计算出的 Blob 哈希值与提供的哈希值进行比较验证。
		for i, h := range hashes {
			if h != args.BlobHashes[i] {
				return fmt.Errorf("blob hash verification failed (have=%s, want=%s)", args.BlobHashes[i], h)
			}
		}
	} else {
		args.BlobHashes = hashes
	}
	return nil
}

// CallDefaults sanitizes the transaction arguments, often filling in zero values,
// for the purpose of eth_call class of RPC methods.
// CallDefaults 方法清理交易参数，通常会填充零值，用于 eth_call 类别的 RPC 方法。
func (args *TransactionArgs) CallDefaults(globalGasCap uint64, baseFee *big.Int, chainID *big.Int) error {
	// Reject invalid combinations of pre- and post-1559 fee styles
	// 拒绝 1559 前后费用样式的无效组合。
	if args.GasPrice != nil && (args.MaxFeePerGas != nil || args.MaxPriorityFeePerGas != nil) {
		return errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
	}
	if args.ChainID == nil {
		args.ChainID = (*hexutil.Big)(chainID)
	} else {
		if have := (*big.Int)(args.ChainID); have.Cmp(chainID) != 0 {
			return fmt.Errorf("chainId does not match node's (have=%v, want=%v)", have, chainID)
		}
	}
	if args.Gas == nil {
		gas := globalGasCap
		if gas == 0 {
			gas = uint64(math.MaxUint64 / 2)
		}
		args.Gas = (*hexutil.Uint64)(&gas)
	} else {
		if globalGasCap > 0 && globalGasCap < uint64(*args.Gas) {
			log.Warn("Caller gas above allowance, capping", "requested", args.Gas, "cap", globalGasCap)
			args.Gas = (*hexutil.Uint64)(&globalGasCap)
		}
	}
	if args.Nonce == nil {
		args.Nonce = new(hexutil.Uint64)
	}
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if baseFee == nil {
		// If there's no basefee, then it must be a non-1559 execution
		// 如果没有基础费用，则必须是非 1559 类型的执行。
		if args.GasPrice == nil {
			args.GasPrice = new(hexutil.Big)
		}
	} else {
		// A basefee is provided, necessitating 1559-type execution
		// 提供了基础费用，需要 1559 类型的执行。
		if args.MaxFeePerGas == nil {
			args.MaxFeePerGas = new(hexutil.Big)
		}
		if args.MaxPriorityFeePerGas == nil {
			args.MaxPriorityFeePerGas = new(hexutil.Big)
		}
	}
	if args.BlobFeeCap == nil && args.BlobHashes != nil {
		args.BlobFeeCap = new(hexutil.Big)
	}

	return nil
}

// ToMessage converts the transaction arguments to the Message type used by the
// core evm. This method is used in calls and traces that do not require a real
// live transaction.
// Assumes that fields are not nil, i.e. setDefaults or CallDefaults has been called.
// ToMessage 方法将交易参数转换为核心 EVM 使用的 Message 类型。此方法用于不需要实际活动交易的调用和跟踪。
// 假设字段不为空，即已调用 setDefaults 或 CallDefaults。
func (args *TransactionArgs) ToMessage(baseFee *big.Int, skipNonceCheck, skipEoACheck bool) *core.Message {
	var (
		gasPrice  *big.Int
		gasFeeCap *big.Int
		gasTipCap *big.Int
	)
	if baseFee == nil {
		// Legacy transaction (pre-EIP-1559)
		// 传统交易（EIP-1559 之前）。Gas 价格直接作为 Gas 限制。
		gasPrice = args.GasPrice.ToInt()
		gasFeeCap, gasTipCap = gasPrice, gasPrice
	} else {
		// EIP-1559 transaction
		// EIP-1559 交易。包含基础费用、最高费用和小费。
		if args.GasPrice != nil {
			// User specified the legacy gas field, convert to 1559 gas typing
			// 用户指定了传统的 Gas 字段，转换为 1559 类型的 Gas。
			gasPrice = args.GasPrice.ToInt()
			gasFeeCap, gasTipCap = gasPrice, gasPrice
		} else {
			// User specified 1559 gas fields (or none), use those
			// 用户指定了 1559 的 Gas 字段（或没有指定），使用这些字段。
			gasFeeCap = args.MaxFeePerGas.ToInt()
			gasTipCap = args.MaxPriorityFeePerGas.ToInt()
			// Backfill the legacy gasPrice for EVM execution, unless we're all zeroes
			// 回填传统的 gasPrice 以供 EVM 执行，除非所有值都为零。
			gasPrice = new(big.Int)
			if gasFeeCap.BitLen() > 0 || gasTipCap.BitLen() > 0 {
				gasPrice = gasPrice.Add(gasTipCap, baseFee)
				if gasPrice.Cmp(gasFeeCap) > 0 {
					gasPrice = gasFeeCap
				}
			}
		}
	}
	var accessList types.AccessList
	if args.AccessList != nil {
		accessList = *args.AccessList
	}
	return &core.Message{
		From:                  args.from(),
		To:                    args.To,
		Value:                 (*big.Int)(args.Value),
		Nonce:                 uint64(*args.Nonce),
		GasLimit:              uint64(*args.Gas),
		GasPrice:              gasPrice,
		GasFeeCap:             gasFeeCap,
		GasTipCap:             gasTipCap,
		Data:                  args.data(),
		AccessList:            accessList,
		BlobGasFeeCap:         (*big.Int)(args.BlobFeeCap),
		BlobHashes:            args.BlobHashes,
		SetCodeAuthorizations: args.AuthorizationList,
		SkipNonceChecks:       skipNonceCheck,
		SkipFromEOACheck:      skipEoACheck,
	}
}

// ToTransaction converts the arguments to a transaction.
// This assumes that setDefaults has been called.
// ToTransaction 方法将参数转换为一个交易。
// 这假定已调用 setDefaults 方法。
func (args *TransactionArgs) ToTransaction(defaultType int) *types.Transaction {
	usedType := types.LegacyTxType
	switch {
	case args.AuthorizationList != nil || defaultType == types.SetCodeTxType:
		usedType = types.SetCodeTxType // EIP-3607: SetCode transaction type
		// EIP-3607：设置代码交易类型。用于修改合约的代码。
	case args.BlobHashes != nil || defaultType == types.BlobTxType:
		usedType = types.BlobTxType // EIP-4844: Blob-carrying transaction type
		// EIP-4844：携带 Blob 的交易类型。用于处理大数据。
	case args.MaxFeePerGas != nil || defaultType == types.DynamicFeeTxType:
		usedType = types.DynamicFeeTxType // EIP-1559: Dynamic fee transaction type
		// EIP-1559：动态费用交易类型。引入了基础费用、最高费用和小费的概念。
	case args.AccessList != nil || defaultType == types.AccessListTxType:
		usedType = types.AccessListTxType // EIP-2930: Access list transaction type
		// EIP-2930：访问列表交易类型。允许指定交易将访问的地址和存储键，以降低 Gas 成本。
	}
	// Make it possible to default to newer tx, but use legacy if gasprice is provided
	// 允许默认使用较新的交易类型，但如果提供了 gasprice，则使用传统类型。
	if args.GasPrice != nil {
		usedType = types.LegacyTxType // Legacy transaction type
		// 传统交易类型。使用 gasPrice 和 gasLimit 来确定交易费用。
	}
	var data types.TxData
	switch usedType {
	case types.SetCodeTxType:
		al := types.AccessList{}
		if args.AccessList != nil {
			al = *args.AccessList
		}
		authList := []types.SetCodeAuthorization{}
		if args.AuthorizationList != nil {
			authList = args.AuthorizationList
		}
		data = &types.SetCodeTx{
			To:         *args.To,
			ChainID:    uint256.MustFromBig(args.ChainID.ToInt()),
			Nonce:      uint64(*args.Nonce),
			Gas:        uint64(*args.Gas),
			GasFeeCap:  uint256.MustFromBig((*big.Int)(args.MaxFeePerGas)),
			GasTipCap:  uint256.MustFromBig((*big.Int)(args.MaxPriorityFeePerGas)),
			Value:      uint256.MustFromBig((*big.Int)(args.Value)),
			Data:       args.data(),
			AccessList: al,
			AuthList:   authList,
		}

	case types.BlobTxType:
		al := types.AccessList{}
		if args.AccessList != nil {
			al = *args.AccessList
		}
		data = &types.BlobTx{
			To:         *args.To,
			ChainID:    uint256.MustFromBig((*big.Int)(args.ChainID)),
			Nonce:      uint64(*args.Nonce),
			Gas:        uint64(*args.Gas),
			GasFeeCap:  uint256.MustFromBig((*big.Int)(args.MaxFeePerGas)),
			GasTipCap:  uint256.MustFromBig((*big.Int)(args.MaxPriorityFeePerGas)),
			Value:      uint256.MustFromBig((*big.Int)(args.Value)),
			Data:       args.data(),
			AccessList: al,
			BlobHashes: args.BlobHashes,
			BlobFeeCap: uint256.MustFromBig((*big.Int)(args.BlobFeeCap)),
		}
		if args.Blobs != nil {
			data.(*types.BlobTx).Sidecar = &types.BlobTxSidecar{
				Blobs:       args.Blobs,
				Commitments: args.Commitments,
				Proofs:      args.Proofs,
			}
		}

	case types.DynamicFeeTxType:
		al := types.AccessList{}
		if args.AccessList != nil {
			al = *args.AccessList
		}
		data = &types.DynamicFeeTx{
			To:         args.To,
			ChainID:    (*big.Int)(args.ChainID),
			Nonce:      uint64(*args.Nonce),
			Gas:        uint64(*args.Gas),
			GasFeeCap:  (*big.Int)(args.MaxFeePerGas),
			GasTipCap:  (*big.Int)(args.MaxPriorityFeePerGas),
			Value:      (*big.Int)(args.Value),
			Data:       args.data(),
			AccessList: al,
		}

	case types.AccessListTxType:
		data = &types.AccessListTx{
			To:         args.To,
			ChainID:    (*big.Int)(args.ChainID),
			Nonce:      uint64(*args.Nonce),
			Gas:        uint64(*args.Gas),
			GasPrice:   (*big.Int)(args.GasPrice),
			Value:      (*big.Int)(args.Value),
			Data:       args.data(),
			AccessList: *args.AccessList,
		}

	default: // types.LegacyTxType
		data = &types.LegacyTx{
			To:       args.To,
			Nonce:    uint64(*args.Nonce),
			Gas:      uint64(*args.Gas),
			GasPrice: (*big.Int)(args.GasPrice),
			Value:    (*big.Int)(args.Value),
			Data:     args.data(),
		}
	}
	return types.NewTx(data)
}

// IsEIP4844 returns an indicator if the args contains EIP4844 fields.
// IsEIP4844 方法返回一个指标，指示参数是否包含 EIP-4844 相关的字段。
func (args *TransactionArgs) IsEIP4844() bool {
	return args.BlobHashes != nil || args.BlobFeeCap != nil
}
