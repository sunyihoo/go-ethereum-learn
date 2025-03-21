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

package types

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// EmptyRootHash is the known root hash of an empty merkle trie.
	// EmptyRootHash 是已知的空 Merkle 树的根哈希。
	// 这是空 Merkle Patricia Trie 的 RLP 编码后经过 Keccak256 计算的固定值。
	EmptyRootHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// EmptyUncleHash is the known hash of the empty uncle set.
	// EmptyUncleHash 是已知的空叔块集的哈希。
	// 对一个空的 *Header 切片（nil）进行 RLP 编码并计算 Keccak256 哈希。
	EmptyUncleHash = rlpHash([]*Header(nil)) // 1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347

	// EmptyCodeHash is the known hash of the empty EVM bytecode.
	// 对空字节切片（nil）直接计算 Keccak256 哈希。
	EmptyCodeHash = crypto.Keccak256Hash(nil) // c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

	// EmptyTxsHash is the known hash of the empty transaction set.
	// EmptyTxsHash 是已知的空交易集的哈希。
	// 空交易树的根哈希，与空 Merkle 树相同。
	EmptyTxsHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// EmptyReceiptsHash is the known hash of the empty receipt set.
	// EmptyReceiptsHash 是已知的空收据集的哈希。
	// 空收据树的根哈希，与空 Merkle 树相同。
	EmptyReceiptsHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// EmptyWithdrawalsHash is the known hash of the empty withdrawal set.
	// EmptyWithdrawalsHash 是已知的空提款集的哈希。
	// 空提款树的根哈希（EIP-4895 引入），与空 Merkle 树相同。
	EmptyWithdrawalsHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// EmptyRequestsHash is the known hash of an empty request set, sha256("").
	// 对空字符串 "" 计算 SHA-256 哈希
	EmptyRequestsHash = common.HexToHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	// EmptyVerkleHash is the known hash of an empty verkle trie.
	// EmptyVerkleHash 是已知的空 Verkle 树的哈希。
	EmptyVerkleHash = common.Hash{}
)
