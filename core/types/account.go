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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
)

//go:generate go run github.com/fjl/gencodec -type Account -field-override accountMarshaling -out gen_account.go

// Account represents an Ethereum account and its attached data.
// This type is used to specify accounts in the genesis block state, and
// is also useful for JSON encoding/decoding of accounts.
// Account 表示一个以太坊账户及其附加数据。
// 此类型用于指定创世区块状态中的账户，同时也适用于账户的 JSON 编码/解码。
type Account struct {
	Code    []byte                      `json:"code,omitempty"`              // 表示账户的智能合约代码。如果这是一个外部账户（EOA），则为空；如果是合约账户，则存储该合约的字节码。
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`           // 表示合约账户的存储状态。键是存储槽的哈希，值是存储在该槽中的数据。这是智能合约状态的一部分。
	Balance *big.Int                    `json:"balance" gencodec:"required"` // 表示账户的余额，以wei为单位（以太坊的最小货币单位）。
	Nonce   uint64                      `json:"nonce,omitempty"`             // 表示账户的交易计数器（nonce）。对于EOA，它记录该账户发出的交易数量；对于合约账户，通常为0。

	// used in tests
	PrivateKey []byte `json:"secretKey,omitempty"` // 表示账户的私钥
}

type accountMarshaling struct {
	Code       hexutil.Bytes
	Balance    *math.HexOrDecimal256
	Nonce      math.HexOrDecimal64
	Storage    map[storageJSON]storageJSON
	PrivateKey hexutil.Bytes
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshalling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// 在以太坊中，创世块（genesis block）是区块链的第一个块，它的初始状态包括账户地址和对应的账户信息（例如余额、存储等）。
// GenesisAlloc 是一个类型，用于定义这种初始分配的状态。

// GenesisAlloc specifies the initial state of a genesis block.
// GenesisAlloc 指定了创世块的初始状态。
type GenesisAlloc map[common.Address]Account

// UnmarshalJSON 这段代码通常用于解析以太坊创世块的 JSON 文件（例如 genesis.json），将文件中定义的账户地址和状态加载到内存中。
func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]Account)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}
