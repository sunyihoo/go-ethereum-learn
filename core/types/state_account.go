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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

//go:generate go run ../../rlp/rlpgen -type StateAccount -out gen_account_rlp.go

// StateAccount is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
//
// StateAccount 是以太坊账户的共识表示。
// 这些对象存储在主账户 Trie 中。
//
// 表示以太坊账户的共识状态，存储在账户 Trie（状态 Trie）中。
type StateAccount struct {
	Nonce    uint64       // 账户的交易计数器（对于外部账户）或合约创建计数器（对于合约账户）
	Balance  *uint256.Int // 账户余额，使用 uint256.Int（256 位整数）表示大额 Ether。
	Root     common.Hash  // merkle root of the storage trie 存储 Trie 的 Merkle 根；存储 Trie 的 Merkle 根哈希（32 字节），指向账户的存储数据。对于空账户，通常是 EmptyRootHash。
	CodeHash []byte       // 合约代码的哈希（通常 32 字节），对于外部账户是空代码哈希。
}

// NewEmptyStateAccount constructs an empty state account.
// NewEmptyStateAccount 构造一个空的账户状态。
func NewEmptyStateAccount() *StateAccount {
	return &StateAccount{
		Balance:  new(uint256.Int),
		Root:     EmptyRootHash,         // 使用预定义的空存储 Trie 根哈希
		CodeHash: EmptyCodeHash.Bytes(), // 使用空代码哈希
	}
}

// Copy returns a deep-copied state account object.
// Copy 返回一个深拷贝的账户状态对象。
func (acct *StateAccount) Copy() *StateAccount {
	var balance *uint256.Int
	if acct.Balance != nil {
		balance = new(uint256.Int).Set(acct.Balance)
	}
	return &StateAccount{
		Nonce:    acct.Nonce,
		Balance:  balance,
		Root:     acct.Root,
		CodeHash: common.CopyBytes(acct.CodeHash),
	}
}

// SlimAccount is a modified version of an Account, where the root is replaced
// with a byte slice. This format can be used to represent full-consensus format
// or slim format which replaces the empty root and code hash as nil byte slice.
//
// SlimAccount 是 Account 的修改版本，其中根被替换为字节切片。
// 这种格式可用于表示完整的共识格式或slim格式，后者将空根和代码哈希替换为 nil 字节切片。
type SlimAccount struct {
	Nonce    uint64
	Balance  *uint256.Int
	Root     []byte // Nil if root equals to types.EmptyRootHash 如果根等于 types.EmptyRootHash，则为 nil
	CodeHash []byte // Nil if hash equals to types.EmptyCodeHash 如果哈希等于 types.EmptyCodeHash，则为 nil
}

// SlimAccountRLP encodes the state account in 'slim RLP' format.
//
// SlimAccountRLP 以“slim RLP”格式编码状态账户。
func SlimAccountRLP(account StateAccount) []byte {
	slim := SlimAccount{
		Nonce:   account.Nonce,
		Balance: account.Balance,
	}
	if account.Root != EmptyRootHash {
		slim.Root = account.Root[:]
	}
	if !bytes.Equal(account.CodeHash, EmptyCodeHash[:]) {
		slim.CodeHash = account.CodeHash
	}
	data, err := rlp.EncodeToBytes(slim)
	if err != nil {
		panic(err)
	}
	return data
}

// FullAccount decodes the data on the 'slim RLP' format and returns
// the consensus format account.
//
// FullAccount 解码“slim RLP”格式的数据并返回共识格式的账户。
func FullAccount(data []byte) (*StateAccount, error) {
	var slim SlimAccount
	if err := rlp.DecodeBytes(data, &slim); err != nil {
		return nil, err
	}
	var account StateAccount
	account.Nonce, account.Balance = slim.Nonce, slim.Balance

	// Interpret the storage root and code hash in slim format.
	// 解释slim格式中的存储根和代码哈希。
	if len(slim.Root) == 0 {
		account.Root = EmptyRootHash
	} else {
		account.Root = common.BytesToHash(slim.Root)
	}
	if len(slim.CodeHash) == 0 {
		account.CodeHash = EmptyCodeHash[:]
	} else {
		account.CodeHash = slim.CodeHash
	}
	return &account, nil
}

// FullAccountRLP converts data on the 'slim RLP' format into the full RLP-format.
//
// FullAccountRLP 将“slim RLP”格式的数据转换为完整的 RLP 格式。
func FullAccountRLP(data []byte) ([]byte, error) {
	account, err := FullAccount(data)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(account)
}
