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

package eip4844

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// 1. EIP-4844 的核心机制
// Blob 数据 ：EIP-4844 引入了 Blob 数据的概念，用于支持二层扩展（如 Rollup）和数据可用性（Data Availability）。Blob 数据是一种低成本的数据存储形式，适合短期存储。
// Blob Gas ：
// 每个 Blob 数据消耗固定的 BlobTxBlobGasPerBlob。
// 区块内的总 Blob Gas 不能超过 MaxBlobGasPerBlock。
// 2. VerifyEIP4844Header 的功能
// 字段完整性检查 ：确保区块头部包含 ExcessBlobGas 和 BlobGasUsed 字段。
// Blob Gas 使用限制 ：
// 确保 BlobGasUsed 不超过最大允许值 MaxBlobGasPerBlock。
// 确保 BlobGasUsed 是 BlobTxBlobGasPerBlob 的整数倍。
// 剩余 Blob Gas 验证 ：根据父区块的 ExcessBlobGas 和 BlobGasUsed 计算当前区块的预期值，并与实际值进行比较。
// 3. CalcExcessBlobGas 的实现细节
// 公式 ：剩余 Blob Gas 的计算公式为：
// excessBlobGas=max(0,parentExcessBlobGas+parentBlobGasUsed−targetBlobGasPerBlock)
// 目标值 ：BlobTxTargetBlobGasPerBlock 是目标 Blob Gas 消耗值。如果总 Blob Gas 低于目标值，则剩余 Blob Gas 为 0。

var (
	minBlobGasPrice            = big.NewInt(params.BlobTxMinBlobGasprice)            // 最小 Blob Gas 价格
	blobGaspriceUpdateFraction = big.NewInt(params.BlobTxBlobGaspriceUpdateFraction) // Blob Gas 价格更新分母
)

// VerifyEIP4844Header verifies the presence of the excessBlobGas field and that
// if the current block contains no transactions, the excessBlobGas is updated
// accordingly.
// VerifyEIP4844Header 验证 excessBlobGas 字段的存在性，并确保如果当前区块不包含交易，
// excessBlobGas 被正确更新。
func VerifyEIP4844Header(parent, header *types.Header) error {
	// Verify the header is not malformed
	// 验证头部未被恶意构造
	if header.ExcessBlobGas == nil {
		return errors.New("header is missing excessBlobGas") // 如果缺少 excessBlobGas，返回错误
	}
	if header.BlobGasUsed == nil {
		return errors.New("header is missing blobGasUsed") // 如果缺少 blobGasUsed，返回错误
	}
	// Verify that the blob gas used remains within reasonable limits.
	// 验证使用的 Blob Gas 是否在合理范围内。
	if *header.BlobGasUsed > params.MaxBlobGasPerBlock {
		return fmt.Errorf("blob gas used %d exceeds maximum allowance %d", *header.BlobGasUsed, params.MaxBlobGasPerBlock)
	}
	if *header.BlobGasUsed%params.BlobTxBlobGasPerBlob != 0 {
		return fmt.Errorf("blob gas used %d not a multiple of blob gas per blob %d", header.BlobGasUsed, params.BlobTxBlobGasPerBlob)
	}
	// Verify the excessBlobGas is correct based on the parent header
	// 根据父区块头部验证 excessBlobGas 是否正确。
	var (
		parentExcessBlobGas uint64
		parentBlobGasUsed   uint64
	)
	if parent.ExcessBlobGas != nil {
		parentExcessBlobGas = *parent.ExcessBlobGas
		parentBlobGasUsed = *parent.BlobGasUsed
	}
	expectedExcessBlobGas := CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed)
	if *header.ExcessBlobGas != expectedExcessBlobGas {
		return fmt.Errorf("invalid excessBlobGas: have %d, want %d, parent excessBlobGas %d, parent blobDataUsed %d",
			*header.ExcessBlobGas, expectedExcessBlobGas, parentExcessBlobGas, parentBlobGasUsed)
	}
	return nil
}

// CalcExcessBlobGas calculates the excess blob gas after applying the set of
// blobs on top of the excess blob gas.
// CalcExcessBlobGas 计算在应用一组 Blob 后的剩余 Blob Gas。
func CalcExcessBlobGas(parentExcessBlobGas uint64, parentBlobGasUsed uint64) uint64 {
	excessBlobGas := parentExcessBlobGas + parentBlobGasUsed
	if excessBlobGas < params.BlobTxTargetBlobGasPerBlock {
		return 0 // 如果总 Blob Gas 小于目标值，则返回 0
	}
	return excessBlobGas - params.BlobTxTargetBlobGasPerBlock // 剩余 Blob Gas
}

// CalcBlobFee calculates the blobfee from the header's excess blob gas field.
// CalcBlobFee 根据头部的 excessBlobGas 字段计算 Blob 费用。
func CalcBlobFee(excessBlobGas uint64) *big.Int {
	return fakeExponential(minBlobGasPrice, new(big.Int).SetUint64(excessBlobGas), blobGaspriceUpdateFraction)
}

// fakeExponential approximates factor * e ** (numerator / denominator) using
// Taylor expansion.
// fakeExponential 使用泰勒展开近似计算 factor * e ** (numerator / denominator)。
func fakeExponential(factor, numerator, denominator *big.Int) *big.Int {
	var (
		output = new(big.Int)
		accum  = new(big.Int).Mul(factor, denominator)
	)
	for i := 1; accum.Sign() > 0; i++ {
		output.Add(output, accum)

		accum.Mul(accum, numerator)
		accum.Div(accum, denominator)
		accum.Div(accum, big.NewInt(int64(i)))
	}
	return output.Div(output, denominator)
}
