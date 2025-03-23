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

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// EIP-1559：2021 年伦敦硬分叉，交易类型 0x02，引入基础费用（baseFee）和优先费（tip）。
// 实际 Gas 费用 = min(GasFeeCap, baseFee + GasTipCap) × Gas 使用量。

// DynamicFeeTx 结构体定义了 EIP-1559 动态费用交易的格式，交易类型为 0x02。
// 它是伦敦硬分叉（2021 年）引入的新交易类型，通过引入基础费用和优先费机制取代了传统的单一 GasPrice，旨在优化 Gas 市场并提高用户体验。

// DynamicFeeTx 是 EIP-1559 的核心数据结构，结合了 EIP-2930 的访问列表和显式 ChainID，
// 同时引入了动态费用机制（GasTipCap 和 GasFeeCap）。
// 它通过类型化交易（EIP-2718）支持更灵活的 Gas 定价，提高网络效率。

// DynamicFeeTx represents an EIP-1559 transaction.
// DynamicFeeTx 表示 EIP-1559 交易。
type DynamicFeeTx struct {
	ChainID    *big.Int        // 链 ID
	Nonce      uint64          // 发送者账户的 nonce
	GasTipCap  *big.Int        // a.k.a. maxPriorityFeePerGas 又称 maxPriorityFeePerGas，最大优先费每单位 Gas,表示用户愿意支付给矿工的额外费用，以加速交易确认。单位为 Wei，实际支付的优先费受区块基础费用影响。优先费（tip）是矿工收到的额外奖励。
	GasFeeCap  *big.Int        // a.k.a. maxFeePerGas 又称 maxFeePerGas，最大费用每单位 Gas,表示用户愿意支付的最高 Gas 费用（包括基础费用和优先费）。实际费用计算为：min(GasFeeCap, baseFee + GasTipCap)。
	Gas        uint64          // Gas 限制，限制交易的计算资源，未用尽的 Gas 退回。
	To         *common.Address `rlp:"nil"` // nil means contract creation, nil 表示合约创建
	Value      *big.Int        // Wei 金额
	Data       []byte          // 合约调用的输入数据或字节码。
	AccessList AccessList      // 访问列表 EIP-2930 访问列表。

	// Signature values 签名值
	V *big.Int // V 为恢复标识符（0 或 1），不嵌入 ChainID。
	R *big.Int // R 是签名结果，用于验证发送者。
	S *big.Int // S 是签名结果，用于验证发送者。
}

// copy creates a deep copy of the transaction data and initializes all fields.
// copy 创建交易数据的深拷贝并初始化所有字段。
func (tx *DynamicFeeTx) copy() TxData {
	cpy := &DynamicFeeTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *DynamicFeeTx) txType() byte           { return DynamicFeeTxType }
func (tx *DynamicFeeTx) chainID() *big.Int      { return tx.ChainID }
func (tx *DynamicFeeTx) accessList() AccessList { return tx.AccessList }
func (tx *DynamicFeeTx) data() []byte           { return tx.Data }
func (tx *DynamicFeeTx) gas() uint64            { return tx.Gas }
func (tx *DynamicFeeTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *DynamicFeeTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *DynamicFeeTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *DynamicFeeTx) value() *big.Int        { return tx.Value }
func (tx *DynamicFeeTx) nonce() uint64          { return tx.Nonce }
func (tx *DynamicFeeTx) to() *common.Address    { return tx.To }

// effectiveGasPrice 计算动态费用交易的有效 Gas 价格。
//
// effectiveGasPrice 方法为 DynamicFeeTx（EIP-1559 交易）计算实际支付的每单位 Gas 价格（有效 Gas 价格）。
// 它根据区块的基础费用（baseFee）、最大费用（GasFeeCap）和最大优先费（GasTipCap）确定最终费用，是 EIP-1559 动态费用机制的核心逻辑。
func (tx *DynamicFeeTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		// 如果基础费用为空，直接返回 GasFeeCap
		return dst.Set(tx.GasFeeCap)
	}
	// 计算实际优先费：GasFeeCap - baseFee
	tip := dst.Sub(tx.GasFeeCap, baseFee) // 优先费（tip）是矿工收到的额外奖励。 限制 tip ≤ GasTipCap
	if tip.Cmp(tx.GasTipCap) > 0 {        // 确保实际支付的优先费不超过用户意愿。
		// 如果计算出的优先费超过 GasTipCap，则限制为 GasTipCap。
		tip.Set(tx.GasTipCap)
	}
	// 返回有效 Gas 价格：优先费 + 基础费用
	// 有效 Gas 价格 = baseFee + min(GasTipCap, GasFeeCap - baseFee)。这确保用户支付的 Gas 费用不超过 GasFeeCap，且优先费不超过 GasTipCap。
	return tip.Add(tip, baseFee)
}

func (tx *DynamicFeeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *DynamicFeeTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *DynamicFeeTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *DynamicFeeTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
