// Copyright 2015 The go-ethereum Authors
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

package state

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// 状态同步的重要性
//
// 当一个新的以太坊节点加入网络时，它需要下载并验证当前的区块链状态，才能参与到交易处理和区块验证中。由于以太坊的状态非常庞大，直接下载所有数据是不切实际的。状态同步的目标是高效地获取到最新的、经过验证的状态数据。
//
// # Merkle-Patricia Trie 在状态同步中的作用
//
// 以太坊使用 Merkle-Patricia Trie 来存储状态数据。这种数据结构具有以下优点，使其非常适合状态同步：
//
// 高效的验证 (Efficient Verification)：通过比较 trie 的根哈希，可以快速验证整个状态的完整性。
// 按需下载 (On-Demand Download)：只需要下载实际需要访问的状态数据的部分分支，而不需要下载整个 trie。
// 证明存在性 (Proof of Existence)：可以生成 Merkle 证明，证明某个特定的状态数据存在于 trie 中。

// 状态同步的过程
//
// 当调用 NewStateSync 创建了 trie.Sync 对象后，该对象会开始根据指定的根哈希和下载方案，从对等节点请求状态 trie 的节点数据。这个过程通常是并行的，以提高下载速度。
//
// 下载账户节点: trie.Sync 首先下载状态 trie 的账户节点。当下载到一个账户的叶子节点时，onAccount 回调会被触发。
// 下载存储节点: 在 onAccount 回调中，如果账户是一个合约账户（拥有存储），则其存储 trie 的根哈希会被添加到下载队列。trie.Sync 会继续下载这些存储 trie 的节点。当下载到存储槽的叶子节点时，onSlot 回调（最终调用外部的 onLeaf）会被触发。
// 下载代码: 同样在 onAccount 回调中，合约账户的代码哈希会被添加到下载队列，trie.Sync 会负责下载合约的代码。

// NewStateSync creates a new state trie download scheduler.
// NewStateSync 创建一个新的状态 trie 下载调度器。
func NewStateSync(root common.Hash, database ethdb.KeyValueReader, onLeaf func(keys [][]byte, leaf []byte) error, scheme string) *trie.Sync {
	// Register the storage slot callback if the external callback is specified.
	// 如果指定了外部回调函数，则注册存储槽回调。
	var onSlot func(keys [][]byte, path []byte, leaf []byte, parent common.Hash, parentPath []byte) error
	if onLeaf != nil {
		onSlot = func(keys [][]byte, path []byte, leaf []byte, parent common.Hash, parentPath []byte) error {
			return onLeaf(keys, leaf) // Call the provided leaf callback for storage slots.
			// 为存储槽调用提供的叶子节点回调函数。
		}
	}
	// Register the account callback to connect the state trie and the storage
	// trie belongs to the contract.
	// 注册账户回调，以连接状态 trie 和属于合约的存储 trie。
	var syncer *trie.Sync
	onAccount := func(keys [][]byte, path []byte, leaf []byte, parent common.Hash, parentPath []byte) error {
		if onLeaf != nil {
			if err := onLeaf(keys, leaf); err != nil {
				return err // Call the provided leaf callback for accounts.
				// 为账户调用提供的叶子节点回调函数。
			}
		}
		var obj types.StateAccount
		if err := rlp.DecodeBytes(leaf, &obj); err != nil {
			return err // Decode the RLP-encoded account data.
			// 解码 RLP 编码的账户数据。
		}
		syncer.AddSubTrie(obj.Root, path, parent, parentPath, onSlot) // Add the storage trie of the account as a sub-trie to download.
		// 将账户的存储 trie 作为子 trie 添加到下载队列。
		syncer.AddCodeEntry(common.BytesToHash(obj.CodeHash), path, parent, parentPath) // Add the code of the account to download.
		// 将账户的代码添加到下载队列。
		return nil
	}
	syncer = trie.NewSync(root, database, onAccount, scheme) // Create a new trie synchronization object.
	// 创建一个新的 trie 同步对象。
	return syncer
}
