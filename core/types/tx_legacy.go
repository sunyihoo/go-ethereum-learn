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
)

// LegacyTx 结构体定义了以太坊最初的交易格式（称为“传统交易”，类型 0x00），用于在以太坊网络上执行转账或合约调用。
// NewTransaction 是一个辅助函数，用于创建未签名的传统交易实例，现已废弃，推荐使用更通用的 NewTx。

// LegacyTx is the transaction data of the original Ethereum transactions.
// LegacyTx 是原始以太坊交易的交易数据。
type LegacyTx struct {
	Nonce    uint64          // nonce of sender account 发送者账户的 nonce 发送者账户的交易计数器。Nonce 用于防止交易重放攻击，确保交易按顺序处理。
	GasPrice *big.Int        // wei per gas 每单位 Gas 的价格（单位 Wei） // GasPrice 决定交易费用（GasPrice * Gas），在 EIP-1559 之前是唯一的 Gas 定价机制。
	Gas      uint64          // gas limit Gas 限制 Gas 限制交易的计算复杂度，未用完的 Gas 会退回。
	To       *common.Address `rlp:"nil"` // nil means contract creation；nil 表示合约创建
	Value    *big.Int        // wei amount Wei 金额 表示发送的 ETH 数量，若为合约调用可为 0。
	Data     []byte          // contract invocation input data 合约调用的输入数据或合约字节码。
	V, R, S  *big.Int        // signature values 签名值 V（恢复标识符） R 和 S 是私钥签名的结果，用于验证交易发起者。
}

// NewTransaction creates an unsigned legacy transaction.
// Deprecated: use NewTx instead.
//
// NewTransaction 创建一个未签名的传统交易。
// 已废弃：请使用 NewTx 替代。
func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	return NewTx(&LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    amount,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}

// NewContractCreation creates an unsigned legacy transaction.
// Deprecated: use NewTx instead.
//
// NewContractCreation 创建一个未签名的传统合约创建交易。
// 已废弃：请使用 NewTx 替代。
func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *Transaction {
	// 创建并返回一个未签名的 LegacyTx 合约创建交易
	// 但通过省略 To 字段（默认 nil）明确表示合约创建。
	// 合约创建交易执行后，新合约地址由发送者地址和 Nonce 派生（keccak256(rlp([sender, nonce])) 的后 20 字节）。
	return NewTx(&LegacyTx{
		Nonce:    nonce,
		Value:    amount,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}

// copy creates a deep copy of the transaction data and initializes all fields.
// copy 创建交易数据的深拷贝并初始化所有字段。
func (tx *LegacyTx) copy() TxData {
	cpy := &LegacyTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are initialized below.
		// 以下字段在下方初始化
		Value:    new(big.Int),
		GasPrice: new(big.Int),
		V:        new(big.Int),
		R:        new(big.Int),
		S:        new(big.Int),
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice.Set(tx.GasPrice)
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
func (tx *LegacyTx) txType() byte           { return LegacyTxType }
func (tx *LegacyTx) chainID() *big.Int      { return deriveChainId(tx.V) }
func (tx *LegacyTx) accessList() AccessList { return nil }
func (tx *LegacyTx) data() []byte           { return tx.Data }
func (tx *LegacyTx) gas() uint64            { return tx.Gas }
func (tx *LegacyTx) gasPrice() *big.Int     { return tx.GasPrice }
func (tx *LegacyTx) gasTipCap() *big.Int    { return tx.GasPrice }
func (tx *LegacyTx) gasFeeCap() *big.Int    { return tx.GasPrice }
func (tx *LegacyTx) value() *big.Int        { return tx.Value }
func (tx *LegacyTx) nonce() uint64          { return tx.Nonce }
func (tx *LegacyTx) to() *common.Address    { return tx.To }

func (tx *LegacyTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	// 将 GasPrice 设置为有效 Gas 价格
	return dst.Set(tx.GasPrice)
}

func (tx *LegacyTx) rawSignatureValues() (v, r, s *big.Int) {
	// 返回原始签名值
	return tx.V, tx.R, tx.S
}

func (tx *LegacyTx) setSignatureValues(chainID, v, r, s *big.Int) {
	// 设置签名值
	tx.V, tx.R, tx.S = v, r, s
}

// 传统交易的 RLP 编码应通过 *Transaction 处理，防止直接操作内部结构。
func (tx *LegacyTx) encode(*bytes.Buffer) error {
	panic("encode called on LegacyTx")
}

// 传统交易的 RLP 解码应通过 *Transaction 处理，防止直接操作内部结构。
func (tx *LegacyTx) decode([]byte) error {
	panic("decode called on LegacyTx)")
}
