// Copyright 2020 The go-ethereum Authors
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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// GnosisSafeTx is a type to parse the safe-tx returned by the relayer,
// it also conforms to the API required by the Gnosis Safe tx relay service.
// See 'SafeMultisigTransaction' on https://safe-transaction.mainnet.gnosis.io/
//
// GnosisSafeTx 是一个用于解析中继器返回的安全交易的类型，
// 它还符合 Gnosis Safe 交易中继服务所需的 API。
// 请参阅 https://safe-transaction.mainnet.gnosis.io/ 上的 'SafeMultisigTransaction'
//
// 表示 Gnosis Safe 多重签名交易，兼容中继服务 API。
type GnosisSafeTx struct {
	// These fields are only used on output 输出字段
	Signature  hexutil.Bytes           `json:"signature"`               // 签名数据
	SafeTxHash common.Hash             `json:"contractTransactionHash"` // 交易哈希（合约生成的）
	Sender     common.MixedcaseAddress `json:"sender"`                  // 发送者地址
	// These fields are used both on input and output 输入/输出字段
	Safe           common.MixedcaseAddress `json:"safe"`              // Safe 合约地址
	To             common.MixedcaseAddress `json:"to"`                // 目标地址。
	Value          math.Decimal256         `json:"value"`             // 交易金额。
	GasPrice       math.Decimal256         `json:"gasPrice"`          // 燃气价格。
	Data           *hexutil.Bytes          `json:"data"`              // 交易数据（可选）
	Operation      uint8                   `json:"operation"`         // 操作类型（例如，0=调用，1=委托调用）
	GasToken       common.Address          `json:"gasToken"`          // 支付燃气的代币地址
	RefundReceiver common.Address          `json:"refundReceiver"`    // 退款接收者地址
	BaseGas        big.Int                 `json:"baseGas"`           // 基础燃气
	SafeTxGas      big.Int                 `json:"safeTxGas"`         // Safe 交易燃气
	Nonce          big.Int                 `json:"nonce"`             // 交易序号
	InputExpHash   common.Hash             `json:"safeTxHash"`        // 输入的预期哈希
	ChainId        *math.HexOrDecimal256   `json:"chainId,omitempty"` // 链 ID（可选）
}

// ToTypedData converts the tx to a EIP-712 Typed Data structure for signing
// ToTypedData 将交易转换为用于签名的 EIP-712 类型化数据结构
func (tx *GnosisSafeTx) ToTypedData() apitypes.TypedData {
	var data hexutil.Bytes
	if tx.Data != nil {
		data = *tx.Data
	}
	var domainType = []apitypes.Type{{Name: "verifyingContract", Type: "address"}} // 默认包含 verifyingContract。
	if tx.ChainId != nil {
		domainType = append([]apitypes.Type{{Name: "chainId", Type: "uint256"}}, domainType[0])
	}

	gnosisTypedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": domainType,
			"SafeTx": []apitypes.Type{
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "data", Type: "bytes"},
				{Name: "operation", Type: "uint8"},
				{Name: "safeTxGas", Type: "uint256"},
				{Name: "baseGas", Type: "uint256"},
				{Name: "gasPrice", Type: "uint256"},
				{Name: "gasToken", Type: "address"},
				{Name: "refundReceiver", Type: "address"},
				{Name: "nonce", Type: "uint256"},
			},
		},
		Domain: apitypes.TypedDataDomain{
			VerifyingContract: tx.Safe.Address().Hex(),
			ChainId:           tx.ChainId,
		},
		PrimaryType: "SafeTx",
		Message: apitypes.TypedDataMessage{
			"to":             tx.To.Address().Hex(),
			"value":          tx.Value.String(),
			"data":           data,
			"operation":      fmt.Sprintf("%d", tx.Operation),
			"safeTxGas":      fmt.Sprintf("%#d", &tx.SafeTxGas),
			"baseGas":        fmt.Sprintf("%#d", &tx.BaseGas),
			"gasPrice":       tx.GasPrice.String(),
			"gasToken":       tx.GasToken.Hex(),
			"refundReceiver": tx.RefundReceiver.Hex(),
			"nonce":          fmt.Sprintf("%d", tx.Nonce.Uint64()),
		},
	}
	return gnosisTypedData
}

// ArgsForValidation returns a SendTxArgs struct, which can be used for the
// common validations, e.g. look up 4byte destinations
// ArgsForValidation 返回一个 SendTxArgs 结构体，可用于常见验证，例如查找 4byte 目标
func (tx *GnosisSafeTx) ArgsForValidation() *apitypes.SendTxArgs {
	gp := hexutil.Big(tx.GasPrice)
	args := &apitypes.SendTxArgs{
		From:     tx.Safe,
		To:       &tx.To,
		Gas:      hexutil.Uint64(tx.SafeTxGas.Uint64()),
		GasPrice: &gp,
		Value:    hexutil.Big(tx.Value),
		Nonce:    hexutil.Uint64(tx.Nonce.Uint64()),
		Data:     tx.Data,
		Input:    nil,
		ChainID:  (*hexutil.Big)(tx.ChainId),
	}
	return args
}
