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

package stateless

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
)

// 以太坊的 Witness 和轻客户端
//
// 在以太坊中，一个“见证 (Witness)”通常指的是为了验证某些状态或交易的有效性而提供的一小部分数据。这在轻客户端 (Light Client) 的场景中尤其重要。轻客户端不存储完整的区块链状态，而是依赖于全节点提供的证明来验证它们感兴趣的数据。
//
// Witness 结构体（虽然其具体定义未在此代码中给出）很可能包含了验证特定状态或交易所需的部分区块头、合约代码片段和状态 Trie 节点。
//
// # MakeHashDB 函数的作用
//
// MakeHashDB 函数的作用是将一个 Witness 对象中包含的数据（区块头、合约代码和状态 Trie 节点）导入到一个新的内存数据库中。这个数据库的关键特性是它使用数据的哈希值作为键来存储数据。

// 基于哈希的存储: 以太坊中许多数据的存储都依赖于其内容的哈希值。例如，区块头通过其哈希值相互链接，交易和收据也都有自己的哈希值。状态 Trie 的节点也是通过哈希值来引用的。
// 自验证性: 函数注释中提到的“自验证性”是指，由于数据是通过其内容的哈希值来索引的，当尝试检索数据时（例如，通过区块哈希查找区块头，通过代码哈希查找合约代码，或者在 Trie 扩展时查找子节点），如果提供了一个不正确的哈希值，数据库中将找不到对应的数据，从而可以检测到数据的不一致或损坏。
// 轻客户端: 轻客户端通常会收到来自全节点的关于特定数据的“见证”，例如一个账户余额的 Merkle 证明。为了验证这个证明，轻客户端需要能够访问相关的区块头和 Trie 节点。MakeHashDB 函数可能就是用于在轻客户端中创建一个临时的、基于哈希的数据库，用于存储接收到的见证数据，从而进行本地验证。
// 加速结构: 注释中提到，如果构建任何加速结构（例如，为了更快地验证见证），这些结构需要显式地验证见证的完整性。这可能是因为虽然基于哈希的存储提供了一定的自验证能力，但更高层次的逻辑可能需要额外的验证步骤来确保见证的可靠性。

// MakeHashDB imports tries, codes and block hashes from a witness into a new
// hash-based memory db. We could eventually rewrite this into a pathdb, but
// simple is better for now.
// MakeHashDB 将来自见证的 tries、codes 和区块哈希导入到一个新的基于哈希的内存数据库中。
// 我们最终可以将其重写为 pathdb，但目前简单起见更好。
//
// Note, this hashdb approach is quite strictly self-validating:
// 注意，这种 hashdb 方法具有非常严格的自验证性：
//   - Headers are persisted keyed by hash, so blockhash will error on junk
//     区块头通过哈希作为键持久化，因此 blockhash 在遇到垃圾数据时会报错。
//   - Codes are persisted keyed by hash, so bytecode lookup will error on junk
//     代码通过哈希作为键持久化，因此字节码查找在遇到垃圾数据时会报错。
//   - Trie nodes are persisted keyed by hash, so trie expansion will error on junk
//     Trie 节点通过哈希作为键持久化，因此 Trie 扩展在遇到垃圾数据时会报错。
//
// Acceleration structures built would need to explicitly validate the witness.
// 构建的加速结构需要显式地验证见证。
func (w *Witness) MakeHashDB() ethdb.Database {
	// MakeHashDB 方法创建一个新的基于哈希的内存数据库，并将见证数据导入其中。
	var (
		memdb  = rawdb.NewMemoryDatabase() // 创建一个新的内存数据库。
		hasher = crypto.NewKeccakState()   // 创建一个新的 Keccak 哈希状态。
		hash   = make([]byte, 32)          // 创建一个用于存储哈希值的字节切片。
	)
	// Inject all the "block hashes" (i.e. headers) into the ephemeral database
	// 将所有“区块哈希”（即区块头）注入到临时数据库中。
	for _, header := range w.Headers {
		rawdb.WriteHeader(memdb, header)
	}
	// Inject all the bytecodes into the ephemeral database
	// 将所有字节码注入到临时数据库中。
	for code := range w.Codes {
		blob := []byte(code)

		hasher.Reset()     // 重置哈希器状态。
		hasher.Write(blob) // 将字节码写入哈希器。
		hasher.Read(hash)  // 从哈希器读取哈希值。

		rawdb.WriteCode(memdb, common.BytesToHash(hash), blob) // 使用哈希值作为键写入字节码。
	}
	// Inject all the MPT trie nodes into the ephemeral database
	// 将所有 MPT Trie 节点注入到临时数据库中。
	for node := range w.State {
		blob := []byte(node)

		hasher.Reset()     // 重置哈希器状态。
		hasher.Write(blob) // 将节点数据写入哈希器。
		hasher.Read(hash)  // 从哈希器读取哈希值。

		rawdb.WriteLegacyTrieNode(memdb, common.BytesToHash(hash), blob) // 使用哈希值作为键写入 Trie 节点。
	}
	return memdb // 返回创建的内存数据库。
}
