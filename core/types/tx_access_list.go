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

//go:generate go run github.com/fjl/gencodec -type AccessTuple -out gen_access_tuple.go

// AccessList 和 AccessTuple 定义了 EIP-2930 访问列表交易中的访问列表结构，用于指定交易中预加载的状态（地址和存储槽）。
// StorageKeys 方法计算访问列表中所有存储键的总数。这些结构和方法是柏林硬分叉（2021 年）中引入的 Gas 优化机制的一部分。

// AccessList is an EIP-2930 access list.
// AccessList 是 EIP-2930 访问列表。
type AccessList []AccessTuple

// AccessTuple is the element type of an access list.
// AccessTuple 是访问列表的元素类型。
type AccessTuple struct {
	Address     common.Address `json:"address"     gencodec:"required"` // 地址
	StorageKeys []common.Hash  `json:"storageKeys" gencodec:"required"` // 存储键列表
}

// StorageKeys returns the total number of storage keys in the access list.
// StorageKeys 返回访问列表中存储键的总数。
func (al AccessList) StorageKeys() int {
	sum := 0
	for _, tuple := range al {
		sum += len(tuple.StorageKeys)
	}
	return sum
}

// EIP-2930：2021 年柏林硬分叉引入，交易类型 0x01，添加访问列表。
// EIP-2929：增加状态访问的 Gas 成本，AccessList 可抵消部分费用。
// V 不再包含 ChainID，简化签名逻辑。

// AccessListTx is the data of EIP-2930 access list transactions.
// AccessListTx 是 EIP-2930 访问列表交易的数据。
type AccessListTx struct {
	ChainID    *big.Int        // destination chain ID 目标链 ID 从 EIP-155 的签名嵌入改为显式字段，增强重放保护。
	Nonce      uint64          // nonce of sender account 发送者账户的 nonce 发送者账户的交易计数器。防止交易重放，确保顺序执行。
	GasPrice   *big.Int        // wei per gas 每单位 Gas 的价格（单位 Wei）决定交易费用（GasPrice * Gas）
	Gas        uint64          // gas limit Gas 限制，限制交易的计算资源，未用尽的 Gas 退回。
	To         *common.Address `rlp:"nil"` // nil means contract creation，nil 表示合约创建
	Value      *big.Int        // wei amount Wei 金额
	Data       []byte          // contract invocation input data 合约调用的输入数据或字节码
	AccessList AccessList      // EIP-2930 access list EIP-2930 访问列表，指定交易预加载的状态，降低 Gas 成本（EIP-2929）
	V, R, S    *big.Int        // signature values 签名值 V 为恢复标识符（0 或 1），不再嵌入 ChainID（与 LegacyTx 的 EIP-155 不同）。 R 和 S 是签名结果，用于验证发送者。
}

// copy creates a deep copy of the transaction data and initializes all fields.
// copy 创建交易数据的深拷贝并初始化所有字段。
func (tx *AccessListTx) copy() TxData {
	cpy := &AccessListTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasPrice:   new(big.Int),
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
// 用于 innerTx 的访问器。
func (tx *AccessListTx) txType() byte           { return AccessListTxType }
func (tx *AccessListTx) chainID() *big.Int      { return tx.ChainID }
func (tx *AccessListTx) accessList() AccessList { return tx.AccessList }
func (tx *AccessListTx) data() []byte           { return tx.Data }
func (tx *AccessListTx) gas() uint64            { return tx.Gas }
func (tx *AccessListTx) gasPrice() *big.Int     { return tx.GasPrice }
func (tx *AccessListTx) gasTipCap() *big.Int    { return tx.GasPrice }
func (tx *AccessListTx) gasFeeCap() *big.Int    { return tx.GasPrice }
func (tx *AccessListTx) value() *big.Int        { return tx.Value }
func (tx *AccessListTx) nonce() uint64          { return tx.Nonce }
func (tx *AccessListTx) to() *common.Address    { return tx.To }

func (tx *AccessListTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.Set(tx.GasPrice)
}

func (tx *AccessListTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *AccessListTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *AccessListTx) encode(b *bytes.Buffer) error {
	// 使用 RLP 编码交易到缓冲区
	// RLP 是以太坊的标准序列化格式，EIP-2930 交易直接编码所有字段。
	return rlp.Encode(b, tx)
}

func (tx *AccessListTx) decode(input []byte) error {
	// 从字节数据解码 RLP 到交易
	return rlp.DecodeBytes(input, tx)
}
