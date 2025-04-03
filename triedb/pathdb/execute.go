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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package pathdb

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// 状态转换: 这些函数是实现以太坊状态转换逻辑的关键部分。当执行交易时，状态会从一个版本（prevRoot）更新到另一个版本（postRoot）。这里的代码似乎是在执行一个回溯或者状态重置的操作。
// Merkle-Patricia Trie: 以太坊使用 Merkle-Patricia Trie 来高效地存储和检索状态数据（账户和存储）。trie.Trie 类型是 go-ethereum 中对这种数据结构的实现。
// 账户和存储: 以太坊中的每个账户都有一个状态，包括余额、代码（对于合约账户）、nonce 和存储根。存储根指向该账户的存储 Trie，其中存储了合约的状态数据。
// RLP 编码: RLP 是一种用于序列化和反序列化数据的编码格式，在以太坊中广泛使用，例如编码账户数据。
// 状态根哈希: 每个区块都有一个关联的状态根哈希，它是当前以太坊状态的唯一标识符。通过比较不同状态的根哈希，可以判断它们是否相同。

// context wraps all fields for executing state diffs.
// context 封装了执行状态差异所需的所有字段。
type context struct {
	prevRoot common.Hash                               // 前一个状态的根哈希。
	postRoot common.Hash                               // 后一个状态的根哈希。
	accounts map[common.Address][]byte                 // 账户地址到账户数据的映射。这里的账户数据通常是经过 RLP 编码的精简格式。
	storages map[common.Address]map[common.Hash][]byte // 账户地址到存储映射的映射。内层映射是存储哈希到存储值的映射。
	nodes    *trienode.MergedNodeSet                   // 合并的 trie 节点集合，用于跟踪在状态差异应用过程中修改过的 trie 节点。

	// TODO (rjl493456442) abstract out the state hasher
	// for supporting verkle tree. 抽象出状态哈希器以支持 Verkle 树。
	accountTrie *trie.Trie // 用于操作账户状态的 trie 实例。
}

// apply processes the given state diffs, updates the corresponding post-state
// and returns the trie nodes that have been modified.
// apply 处理给定的状态差异，更新相应的后状态，并返回已修改的 trie 节点。
func apply(db database.NodeDatabase, prevRoot common.Hash, postRoot common.Hash, accounts map[common.Address][]byte, storages map[common.Address]map[common.Hash][]byte) (map[common.Hash]map[string]*trienode.Node, error) {
	// 使用后状态的根哈希创建一个新的 trie 实例。
	tr, err := trie.New(trie.TrieID(postRoot), db)
	if err != nil {
		return nil, err
	}
	// 创建一个 context 实例，用于在状态差异应用过程中传递相关数据。
	ctx := &context{
		prevRoot:    prevRoot,
		postRoot:    postRoot,
		accounts:    accounts,
		storages:    storages,
		accountTrie: tr,
		nodes:       trienode.NewMergedNodeSet(),
	}
	// 遍历提供的账户差异。
	for addr, account := range accounts {
		var err error
		// 如果账户数据为空，则表示该账户应该被删除。
		if len(account) == 0 {
			err = deleteAccount(ctx, db, addr)
		} else {
			// 否则，表示该账户应该被更新。
			err = updateAccount(ctx, db, addr)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to revert state, err: %w", err)
		}
	}
	// 提交对 trie 的更改，获取新的根哈希和修改过的节点。这里 commit(false) 表示不持久化到数据库，只是在内存中操作。
	root, result := tr.Commit(false)
	// 验证提交后的根哈希是否与预期的前一个状态的根哈希一致。这表明状态差异被正确地“反向”应用了。
	if root != prevRoot {
		return nil, fmt.Errorf("failed to revert state, want %#x, got %#x", prevRoot, root)
	}
	// 将修改过的节点合并到 context 的节点集合中。
	if err := ctx.nodes.Merge(result); err != nil {
		return nil, err
	}
	// 将 context 中的节点集合扁平化并返回。
	return ctx.nodes.Flatten(), nil
}

// updateAccount the account was present in prev-state, and may or may not
// existent in post-state. Apply the reverse diff and verify if the storage
// root matches the one in prev-state account.
// updateAccount：该账户存在于前一个状态中，并且可能存在或不存在于后一个状态中。应用反向差异并验证存储根是否与前一个状态账户中的存储根匹配。
func updateAccount(ctx *context, db database.NodeDatabase, addr common.Address) error {
	// The account was present in prev-state, decode it from the
	// 'slim-rlp' format bytes.
	// 该账户存在于前一个状态中，从 'slim-rlp' 格式的字节中解码它。
	h := newHasher()
	defer h.release()

	addrHash := h.hash(addr.Bytes())
	prev, err := types.FullAccount(ctx.accounts[addr])
	if err != nil {
		return err
	}
	// The account may or may not existent in post-state, try to
	// load it and decode if it's found.
	// 该账户可能存在或不存在于后一个状态中，尝试加载它并在找到时进行解码。
	blob, err := ctx.accountTrie.Get(addrHash.Bytes())
	if err != nil {
		return err
	}
	post := types.NewEmptyStateAccount()
	if len(blob) != 0 {
		if err := rlp.DecodeBytes(blob, &post); err != nil {
			return err
		}
	}
	// Apply all storage changes into the post-state storage trie.
	// 将所有存储更改应用到后状态的存储 trie 中。
	st, err := trie.New(trie.StorageTrieID(ctx.postRoot, addrHash, post.Root), db)
	if err != nil {
		return err
	}
	// 遍历该账户的存储差异。
	for key, val := range ctx.storages[addr] {
		var err error
		// 如果存储值为空，则表示该存储槽应该被删除。
		if len(val) == 0 {
			err = st.Delete(key.Bytes())
		} else {
			// 否则，表示该存储槽应该被更新。
			err = st.Update(key.Bytes(), val)
		}
		if err != nil {
			return err
		}
	}
	// 提交对存储 trie 的更改，获取新的根哈希和修改过的节点。
	root, result := st.Commit(false)
	// 验证提交后的存储根哈希是否与前一个状态账户中的存储根哈希一致。
	if root != prev.Root {
		return errors.New("failed to reset storage trie")
	}
	// The returned set can be nil if storage trie is not changed
	// at all.
	// 如果存储 trie 根本没有更改，则返回的集合可能为 nil。
	if result != nil {
		if err := ctx.nodes.Merge(result); err != nil {
			return err
		}
	}
	// Write the prev-state account into the main trie
	// 将前一个状态的账户写入主 trie。
	full, err := rlp.EncodeToBytes(prev)
	if err != nil {
		return err
	}
	return ctx.accountTrie.Update(addrHash.Bytes(), full)
}

// deleteAccount the account was not present in prev-state, and is expected
// to be existent in post-state. Apply the reverse diff and verify if the
// account and storage is wiped out correctly.
//
// deleteAccount：该账户不存在于前一个状态中，并且预计存在于后一个状态中。应用反向差异并验证账户和存储是否已正确清除。
func deleteAccount(ctx *context, db database.NodeDatabase, addr common.Address) error {
	// The account must be existent in post-state, load the account.
	// 该账户必须存在于后一个状态中，加载该账户。
	h := newHasher()
	defer h.release()

	addrHash := h.hash(addr.Bytes())
	blob, err := ctx.accountTrie.Get(addrHash.Bytes())
	if err != nil {
		return err
	}
	// 如果在后状态中找不到该账户，则返回错误。
	if len(blob) == 0 {
		return fmt.Errorf("account is non-existent %#x", addrHash)
	}
	var post types.StateAccount
	if err := rlp.DecodeBytes(blob, &post); err != nil {
		return err
	}
	// 为该账户创建一个新的存储 trie。
	st, err := trie.New(trie.StorageTrieID(ctx.postRoot, addrHash, post.Root), db)
	if err != nil {
		return err
	}
	// 遍历该账户的存储差异，预期所有存储值都为空，表示应该被删除。
	for key, val := range ctx.storages[addr] {
		// 如果存在非空的存储值，则返回错误，因为预期是删除账户。
		if len(val) != 0 {
			return errors.New("expect storage deletion")
		}
		// 删除存储槽。
		if err := st.Delete(key.Bytes()); err != nil {
			return err
		}
	}
	// 提交对存储 trie 的更改，验证根哈希是否为空根哈希，表示存储已被清除。
	root, result := st.Commit(false)
	if root != types.EmptyRootHash {
		return errors.New("failed to clear storage trie")
	}
	// The returned set can be nil if storage trie is not changed
	// at all.
	// 如果存储 trie 根本没有更改，则返回的集合可能为 nil。
	if result != nil {
		if err := ctx.nodes.Merge(result); err != nil {
			return err
		}
	}
	// Delete the post-state account from the main trie.
	// 从主 trie 中删除后状态的账户。
	return ctx.accountTrie.Delete(addrHash.Bytes())
}
