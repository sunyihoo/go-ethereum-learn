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
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// 状态 Trie 遍历与后序遍历
//
// 在以太坊中，世界状态存储在 Merkle Patricia Trie 中。为了能够访问和处理所有状态数据，例如在生成状态快照或进行状态同步时，需要一种遍历整个状态 Trie 的机制。
//
// 后序遍历是一种树的遍历方式，其顺序是：先遍历左子树，然后遍历右子树，最后访问根节点。在状态 Trie 的上下文中，这意味着会先处理一个账户的所有存储槽，然后是账户本身，最后是包含该账户的更高层级的 Trie 节点。
//
// nodeIterator 结构体的作用
//
// nodeIterator 的目的是提供一个以后序方式遍历整个以太坊状态 Trie 的迭代器。这包括了账户信息、每个账户的存储 Trie，以及合约的字节码。为了能够确定合约的地址，它还依赖于账户哈希的 preimage (原始数据)。

// 状态 Trie: nodeIterator 的核心功能是遍历以太坊的状态 Trie，这是存储所有账户状态（包括余额、nonce、代码哈希和存储根哈希）的关键数据结构。
// 存储 Trie: 每个合约账户都有一个独立的存储 Trie，用于存储合约的状态数据。nodeIterator 会递归地遍历这些存储 Trie。
// 合约代码: 对于合约账户，其代码哈希指向存储在数据库中的实际字节码。nodeIterator 会在遍历到合约账户时获取并包含其代码。
// 后序遍历: 后序遍历的顺序确保了在访问一个账户之前，会先访问其所有的存储槽。这在某些需要先处理子节点再处理父节点的场景下非常有用，例如在计算状态 Trie 的 Merkle 证明时。
// Preimage: 为了将账户 Trie 中的键（账户哈希）转换回实际的以太坊地址，需要使用 preimage。nodeIterator 在遇到账户节点时会查找其 preimage。

// nodeIterator is an iterator to traverse the entire state trie post-order,
// including all of the contract code and contract state tries. Preimage is
// required in order to resolve the contract address.
// nodeIterator 是一个以后序遍历整个状态 Trie 的迭代器，
// 包括所有合约代码和合约状态 Trie。需要 preimage 来解析合约地址。
type nodeIterator struct {
	state *StateDB // State being iterated
	// state 正在迭代的状态

	stateIt trie.NodeIterator // Primary iterator for the global state trie
	// stateIt 全局状态 Trie 的主要迭代器
	dataIt trie.NodeIterator // Secondary iterator for the data trie of a contract
	// dataIt 合约数据 Trie 的辅助迭代器

	accountHash common.Hash // Hash of the node containing the account
	// accountHash 包含账户的节点的哈希
	codeHash common.Hash // Hash of the contract source code
	// codeHash 合约源代码的哈希
	code []byte // Source code associated with a contract
	// code 与合约关联的源代码

	Hash common.Hash // Hash of the current entry being iterated (nil if not standalone)
	// Hash 当前正在迭代的条目的哈希（如果不是独立的则为 nil）
	Parent common.Hash // Hash of the first full ancestor node (nil if current is the root)
	// Parent 第一个完整祖先节点的哈希（如果当前是根节点则为 nil）

	Error error // Failure set in case of an internal error in the iterator
	// Error 如果迭代器内部发生错误则设置此字段
}

// newNodeIterator creates a post-order state node iterator.
// newNodeIterator 创建一个后序状态节点迭代器。
func newNodeIterator(state *StateDB) *nodeIterator {
	// newNodeIterator 函数创建一个新的 nodeIterator。
	return &nodeIterator{
		state: state,
	}
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure.
// Next 将迭代器移动到下一个节点，返回是否还有更多节点。
// 如果发生内部错误，此方法返回 false 并将 Error 字段设置为遇到的错误。
func (it *nodeIterator) Next() bool {
	// Next 方法将迭代器移动到状态 Trie 的下一个节点。
	// If the iterator failed previously, don't do anything
	// 如果迭代器之前失败了，则不执行任何操作
	if it.Error != nil {
		return false
	}
	// Otherwise step forward with the iterator and report any errors
	// 否则，向前移动迭代器并报告任何错误
	if err := it.step(); err != nil {
		it.Error = err
		return false
	}
	return it.retrieve()
}

// step moves the iterator to the next entry of the state trie.
// step 将迭代器移动到状态 Trie 的下一个条目。
func (it *nodeIterator) step() error {
	// step 方法在状态 Trie 中向前移动迭代器。
	// Abort if we reached the end of the iteration
	// 如果我们到达迭代的末尾则中止
	if it.state == nil {
		return nil
	}
	// Initialize the iterator if we've just started
	// 如果我们刚刚开始，则初始化迭代器
	var err error
	if it.stateIt == nil {
		it.stateIt, err = it.state.trie.NodeIterator(nil)
		if err != nil {
			return err
		}
	}
	// If we had data nodes previously, we surely have at least state nodes
	// 如果我们之前有数据节点，那么我们肯定至少有状态节点
	if it.dataIt != nil {
		if cont := it.dataIt.Next(true); !cont {
			if it.dataIt.Error() != nil {
				return it.dataIt.Error()
			}
			it.dataIt = nil
		}
		return nil
	}
	// If we had source code previously, discard that
	// 如果我们之前有源代码，则丢弃它
	if it.code != nil {
		it.code = nil
		return nil
	}
	// Step to the next state trie node, terminating if we're out of nodes
	// 移动到下一个状态 Trie 节点，如果没有更多节点则终止
	if cont := it.stateIt.Next(true); !cont {
		if it.stateIt.Error() != nil {
			return it.stateIt.Error()
		}
		it.state, it.stateIt = nil, nil
		return nil
	}
	// If the state trie node is an internal entry, leave as is
	// 如果状态 Trie 节点是内部条目，则保持原样
	if !it.stateIt.Leaf() {
		return nil
	}
	// Otherwise we've reached an account node, initiate data iteration
	// 否则，我们已经到达一个账户节点，启动数据迭代
	var account types.StateAccount
	if err := rlp.DecodeBytes(it.stateIt.LeafBlob(), &account); err != nil {
		return err
	}
	// Lookup the preimage of account hash
	// 查找账户哈希的 preimage
	preimage := it.state.trie.GetKey(it.stateIt.LeafKey())
	if preimage == nil {
		return errors.New("account address is not available")
	}
	address := common.BytesToAddress(preimage)

	// Traverse the storage slots belong to the account
	// 遍历属于该账户的存储槽
	dataTrie, err := it.state.db.OpenStorageTrie(it.state.originalRoot, address, account.Root, it.state.trie)
	if err != nil {
		return err
	}
	it.dataIt, err = dataTrie.NodeIterator(nil)
	if err != nil {
		return err
	}
	if !it.dataIt.Next(true) {
		it.dataIt = nil
	}
	if !bytes.Equal(account.CodeHash, types.EmptyCodeHash.Bytes()) {
		it.codeHash = common.BytesToHash(account.CodeHash)
		it.code, err = it.state.reader.Code(address, common.BytesToHash(account.CodeHash))
		if err != nil {
			return fmt.Errorf("code %x: %v", account.CodeHash, err)
		}
		if len(it.code) == 0 {
			return fmt.Errorf("code is not found: %x", account.CodeHash)
		}
	}
	it.accountHash = it.stateIt.Parent()
	return nil
}

// retrieve pulls and caches the current state entry the iterator is traversing.
// The method returns whether there are any more data left for inspection.
// retrieve 拉取并缓存迭代器正在遍历的当前状态条目。
// 该方法返回是否还有更多数据可供检查。
func (it *nodeIterator) retrieve() bool {
	// retrieve 方法获取当前迭代到的状态条目。
	// Clear out any previously set values
	// 清除任何先前设置的值
	it.Hash = common.Hash{}

	// If the iteration's done, return no available data
	// 如果迭代完成，则返回没有可用数据
	if it.state == nil {
		return false
	}
	// Otherwise retrieve the current entry
	// 否则检索当前条目
	switch {
	case it.dataIt != nil:
		it.Hash, it.Parent = it.dataIt.Hash(), it.dataIt.Parent()
		if it.Parent == (common.Hash{}) {
			it.Parent = it.accountHash
		}
	case it.code != nil:
		it.Hash, it.Parent = it.codeHash, it.accountHash
	case it.stateIt != nil:
		it.Hash, it.Parent = it.stateIt.Hash(), it.stateIt.Parent()
	}
	return true
}
