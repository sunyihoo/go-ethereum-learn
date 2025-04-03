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

package pathdb

import (
	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

// 所有者 (Owner):
// 在以太坊的状态 Trie 中，存在两种主要的 Trie：账户 Trie 和存储 Trie。
// 账户 Trie 存储了所有账户的信息，它的“所有者”可以认为是全局的，通常用零哈希 (common.Hash{}) 表示。
// 存储 Trie 则与特定的账户相关联，存储了该账户的合约存储数据，其“所有者”是该账户的地址。
//
// 路径 (Path): 路径表示从 Trie 的根节点到目标节点的遍历路径，通常是一系列 nibbles（半字节）。

// nodeCacheKey constructs the unique key of clean cache. The assumption is held
// that zero address does not have any associated storage slots.
//
// nodeCacheKey 构建干净缓存的唯一键。假设零地址没有任何关联的存储槽。
func nodeCacheKey(owner common.Hash, path []byte) []byte {
	// 如果所有者是零哈希（表示账户 Trie），则直接使用路径作为缓存键。
	if owner == (common.Hash{}) {
		return path
	}
	// 否则（表示存储 Trie），将所有者的字节和路径拼接起来作为缓存键。
	return append(owner.Bytes(), path...)
}

// 账户 Trie: 如果 owner 是零哈希，则说明是账户 Trie 的节点，直接使用 path 作为缓存键。这是因为账户 Trie 是全局唯一的，路径本身就足以唯一标识一个账户。
// 存储 Trie: 如果 owner 不是零哈希，则说明是某个账户的存储 Trie 的节点。由于不同的账户可能有相同的存储路径，因此需要将账户的地址（作为 owner）和 path 拼接在一起，以确保缓存键的唯一性。

// writeNodes writes the trie nodes into the provided database batch.
// Note this function will also inject all the newly written nodes
// into clean cache.
//
// writeNodes 将 trie 节点写入提供的数据库批处理中。
// 注意：此函数还会将所有新写入的节点注入到干净缓存中。
func writeNodes(batch ethdb.Batch, nodes map[common.Hash]map[string]*trienode.Node, clean *fastcache.Cache) (total int) {
	// 遍历所有者（通常是账户地址，对于账户 Trie 所有者是零哈希）。
	for owner, subset := range nodes {
		// 遍历每个所有者下的所有路径和对应的 trie 节点。
		for path, n := range subset {
			// 如果节点被标记为已删除。
			if n.IsDeleted() {
				// 如果所有者是零哈希，则表示是账户 Trie 的节点，使用 rawdb 删除账户 Trie 节点。
				if owner == (common.Hash{}) {
					rawdb.DeleteAccountTrieNode(batch, []byte(path))
				} else {
					// 否则，是存储 Trie 的节点，使用 rawdb 删除存储 Trie 节点。
					rawdb.DeleteStorageTrieNode(batch, owner, []byte(path))
				}
				// 如果提供了干净缓存，则从缓存中删除该节点。
				if clean != nil {
					clean.Del(nodeCacheKey(owner, []byte(path)))
				}
			} else { // 如果节点不是已删除状态，表示需要写入或更新。
				// 如果所有者是零哈希，则表示是账户 Trie 的节点，使用 rawdb 写入账户 Trie 节点。
				if owner == (common.Hash{}) {
					rawdb.WriteAccountTrieNode(batch, []byte(path), n.Blob)
				} else {
					// 否则，是存储 Trie 的节点，使用 rawdb 写入存储 Trie 节点。
					rawdb.WriteStorageTrieNode(batch, owner, []byte(path), n.Blob)
				}
				// 如果提供了干净缓存，则将该节点及其数据写入缓存。
				if clean != nil {
					clean.Set(nodeCacheKey(owner, []byte(path)), n.Blob)
				}
			}
		}
		// 累加当前所有者下的节点数量。
		total += len(subset)
	}
	// 返回写入或删除的节点总数。
	return total
}
