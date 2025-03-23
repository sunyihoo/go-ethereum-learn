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
	"bytes"
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// DelegationPrefix is used by code to denote the account is delegating to
// another account.
// DelegationPrefix 被代码用来表示账户正在委托给另一个账户。
var DelegationPrefix = []byte{0xef, 0x01, 0x00} // 定义一个 3 字节的前缀（[0xef, 0x01, 0x00]），用于标识账户委托状态。长度为 3 字节，与以太坊地址（20 字节）组合后总长 23 字节。

// ParseDelegation tries to parse the address from a delegation slice.
// ParseDelegation 尝试从委托字节切片中解析出地址。
//
// 从字节切片中解析委托地址，验证前缀并提取目标地址。
func ParseDelegation(b []byte) (common.Address, bool) {
	// 检查长度和前缀是否匹配。检查字节长度是否为 23（3 字节前缀 + 20 字节地址）。
	if len(b) != 23 || !bytes.HasPrefix(b, DelegationPrefix) {
		return common.Address{}, false
	}
	// 从前缀后的字节解析出地址
	return common.BytesToAddress(b[len(DelegationPrefix):]), true
}

// AddressToDelegation adds the delegation prefix to the specified address.
// AddressToDelegation 将委托前缀添加到指定地址。
//
// 将地址转换为带前缀的委托格式字节切片。
func AddressToDelegation(addr common.Address) []byte {
	return append(DelegationPrefix, addr.Bytes()...)
}

// SetCodeTx 定义了 EIP-7702 交易类型（预计 2025 年布拉格升级引入），允许在签名者地址临时部署代码。它基于 EIP-1559 的动态费用机制，并引入 AuthList 来授权代码安装。

// SetCodeTx implements the EIP-7702 transaction type which temporarily installs
// the code at the signer's address.
// SetCodeTx 实现了 EIP-7702 交易类型，该交易类型在签名者的地址临时安装代码。
type SetCodeTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	GasTipCap  *uint256.Int // a.k.a. maxPriorityFeePerGas 又称 maxPriorityFeePerGas，最大优先费每单位 Gas
	GasFeeCap  *uint256.Int // a.k.a. maxFeePerGas 又称 maxFeePerGas，最大费用每单位 Gas
	Gas        uint64
	To         common.Address
	Value      *uint256.Int
	Data       []byte
	AccessList AccessList
	AuthList   []SetCodeAuthorization // 授权列表 AuthList 引入临时代码部署，支持账户抽象。账户抽象：允许 EOA（外部拥有账户）临时获得合约功能。模糊 EOA 和合约账户界限，提升用户体验。

	// Signature values
	// 签名值
	V *uint256.Int
	R *uint256.Int
	S *uint256.Int
}

//go:generate go run github.com/fjl/gencodec -type SetCodeAuthorization -field-override authorizationMarshaling -out gen_authorization.go

// SetCodeAuthorization is an authorization from an account to deploy code at its address.
// SetCodeAuthorization 是账户授权在其地址部署代码的结构。
//
//	SetCodeAuthorization：定义了授权结构，表示某个账户允许在其地址部署代码，包含签名以验证授权。
type SetCodeAuthorization struct {
	ChainID uint256.Int    `json:"chainId" gencodec:"required"` // 链 ID
	Address common.Address `json:"address" gencodec:"required"` // 地址
	Nonce   uint64         `json:"nonce" gencodec:"required"`   // nonce
	V       uint8          `json:"yParity" gencodec:"required"` // Y 平价（签名恢复标识符）
	R       uint256.Int    `json:"r" gencodec:"required"`       // 签名 R 值
	S       uint256.Int    `json:"s" gencodec:"required"`       // 签名 S 值
}

// field type overrides for gencodec
type authorizationMarshaling struct {
	ChainID hexutil.U256
	Nonce   hexutil.Uint64
	V       hexutil.Uint64
	R       hexutil.U256
	S       hexutil.U256
}

// SignSetCode creates a signed the SetCode authorization.
// SignSetCode 创建一个签名的 SetCode 授权。
func SignSetCode(prv *ecdsa.PrivateKey, auth SetCodeAuthorization) (SetCodeAuthorization, error) {
	sighash := auth.sigHash()
	// 使用私钥对哈希签名
	sig, err := crypto.Sign(sighash[:], prv)
	if err != nil {
		return SetCodeAuthorization{}, err
	}
	// 解码签名，提取 R 和 S
	r, s, _ := decodeSignature(sig)
	return SetCodeAuthorization{
		ChainID: auth.ChainID,
		Address: auth.Address,
		Nonce:   auth.Nonce,
		V:       sig[64],
		R:       *uint256.MustFromBig(r),
		S:       *uint256.MustFromBig(s),
	}, nil
}

func (a *SetCodeAuthorization) sigHash() common.Hash {
	return prefixedRlpHash(0x05, []any{
		a.ChainID,
		a.Address,
		a.Nonce,
	})
}

// Authority recovers the the authorizing account of an authorization.
// Authority 恢复授权账户的地址。
//
// Authority 方法从 SetCodeAuthorization 的签名值（V, R, S）恢复授权账户的地址。它是 EIP-7702 交易中验证授权合法性的核心功能，确保只有授权账户能允许在其地址部署代码。
func (a *SetCodeAuthorization) Authority() (common.Address, error) {
	// 计算签名哈希
	sighash := a.sigHash()
	// 验证签名值的有效性
	if !crypto.ValidateSignatureValues(a.V, a.R.ToBig(), a.S.ToBig(), true) {
		return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	// 将签名编码为未压缩格式
	var sig [crypto.SignatureLength]byte
	a.R.WriteToSlice(sig[:32])
	a.S.WriteToSlice(sig[32:64])
	sig[64] = a.V
	// recover the public key from the signature
	// 从签名恢复公钥
	pub, err := crypto.Ecrecover(sighash[:], sig[:])
	if err != nil {
		return common.Address{}, err
	}
	// 检查公钥的有效性
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	// 从公钥派生地址
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *SetCodeTx) copy() TxData {
	cpy := &SetCodeTx{
		Nonce: tx.Nonce,
		To:    tx.To,
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		AuthList:   make([]SetCodeAuthorization, len(tx.AuthList)),
		Value:      new(uint256.Int),
		ChainID:    tx.ChainID,
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		V:          new(uint256.Int),
		R:          new(uint256.Int),
		S:          new(uint256.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	copy(cpy.AuthList, tx.AuthList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
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
func (tx *SetCodeTx) txType() byte           { return SetCodeTxType }
func (tx *SetCodeTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *SetCodeTx) accessList() AccessList { return tx.AccessList }
func (tx *SetCodeTx) data() []byte           { return tx.Data }
func (tx *SetCodeTx) gas() uint64            { return tx.Gas }
func (tx *SetCodeTx) gasFeeCap() *big.Int    { return tx.GasFeeCap.ToBig() }
func (tx *SetCodeTx) gasTipCap() *big.Int    { return tx.GasTipCap.ToBig() }
func (tx *SetCodeTx) gasPrice() *big.Int     { return tx.GasFeeCap.ToBig() }
func (tx *SetCodeTx) value() *big.Int        { return tx.Value.ToBig() }
func (tx *SetCodeTx) nonce() uint64          { return tx.Nonce }
func (tx *SetCodeTx) to() *common.Address    { tmp := tx.To; return &tmp }

func (tx *SetCodeTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

func (tx *SetCodeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V.ToBig(), tx.R.ToBig(), tx.S.ToBig()
}

func (tx *SetCodeTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = uint256.MustFromBig(chainID)
	tx.V.SetFromBig(v)
	tx.R.SetFromBig(r)
	tx.S.SetFromBig(s)
}

func (tx *SetCodeTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *SetCodeTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
