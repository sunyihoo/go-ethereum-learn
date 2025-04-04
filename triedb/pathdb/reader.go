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
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// 状态读取: reader 结构体及其方法是 go-ethereum 中用于读取以太坊状态的核心组件。它封装了对不同状态层（内存缓存和磁盘存储）的访问逻辑。
// 分层存储: 代码中提到的 locDirtyCache, locCleanCache, locDiskLayer, locDiffLayer 体现了以太坊状态的分层存储架构。reader 需要能够从这些不同的层中检索数据。
// Merkle-Patricia Trie: Node 方法用于检索构成状态 trie 的节点。哈希检查的目的是确保检索到的节点与期望的哈希一致，维护 trie 的完整性。
// 账户和存储: AccountRLP, Account, 和 Storage 方法提供了访问以太坊账户和合约存储数据的能力。
// 状态根: NodeReader 和 StateReader 方法都接受一个状态根哈希作为参数。状态根是 Merkle-Patricia Trie 的根哈希，它唯一地标识了一个特定时刻的以太坊状态。通过指定状态根，可以读取该特定状态快照的数据.
// Verkle 树: noHashCheck 字段暗示了 go-ethereum 正在或计划支持 Verkle 树作为状态存储的替代方案。Verkle 树的哈希检查机制可能与 Merkle-Patricia Trie 不同。

// The types of locations where the node is found.
// 节点被发现的位置类型。
const (
	locDirtyCache = "dirty" // dirty cache
	// 脏缓存。
	locCleanCache = "clean" // clean cache
	// 干净缓存。
	locDiskLayer = "disk" // persistent state
	// 持久化状态（磁盘层）。
	locDiffLayer = "diff" // diff layers
	// 差异层。
)

// nodeLoc is a helpful structure that contains the location where the node
// is found, as it's useful for debugging purposes.
// nodeLoc 是一个有用的结构体，包含节点被发现的位置，这对于调试很有用。
type nodeLoc struct {
	loc string
	// 节点所在的位置（dirty/clean 缓存、磁盘层、差异层）。
	depth int
	// 节点在层叠中的深度（仅对差异层有意义）。
}

// string returns the string representation of node location.
// string 返回节点位置的字符串表示。
func (loc *nodeLoc) string() string {
	return fmt.Sprintf("loc: %s, depth: %d", loc.loc, loc.depth)
}

// reader implements the database.NodeReader interface, providing the functionalities to
// retrieve trie nodes by wrapping the internal state layer.
// reader 实现了 database.NodeReader 接口，通过封装内部状态层提供检索 trie 节点的功能。
type reader struct {
	layer layer
	// 底层状态层接口实例。
	noHashCheck bool
	// 是否禁用哈希检查，用于某些特定的场景（例如 Verkle 树）。
}

// Node implements database.NodeReader interface, retrieving the node with specified
// node info. Don't modify the returned byte slice since it's not deep-copied
// and still be referenced by database.
// Node 实现了 database.NodeReader 接口，检索具有指定节点信息的节点。
// 不要修改返回的字节切片，因为它不是深拷贝，并且仍然被数据库引用。
func (r *reader) Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error) {
	blob, got, loc, err := r.layer.node(owner, path, 0)
	if err != nil {
		return nil, err
	}
	// Error out if the local one is inconsistent with the target.
	// 如果本地检索到的节点与目标哈希不一致，则返回错误。
	if !r.noHashCheck && got != hash {
		// Location is always available even if the node
		// is not found.
		// 即使找不到节点，位置信息也总是可用的。
		switch loc.loc {
		case locCleanCache:
			nodeCleanFalseMeter.Mark(1)
		case locDirtyCache:
			nodeDirtyFalseMeter.Mark(1)
		case locDiffLayer:
			nodeDiffFalseMeter.Mark(1)
		case locDiskLayer:
			nodeDiskFalseMeter.Mark(1)
		}
		blobHex := "nil"
		if len(blob) > 0 {
			blobHex = hexutil.Encode(blob)
		}
		log.Error("Unexpected trie node", "location", loc.loc, "owner", owner.Hex(), "path", path, "expect", hash.Hex(), "got", got.Hex(), "blob", blobHex)
		return nil, fmt.Errorf("unexpected node: (%x %v), %x!=%x, %s, blob: %s", owner, path, hash, got, loc.string(), blobHex)
	}
	return blob, nil
}

// AccountRLP directly retrieves the account associated with a particular hash.
// An error will be returned if the read operation exits abnormally. Specifically,
// if the layer is already stale.
// 直接检索与特定哈希关联的账户 RLP 编码数据。
// 如果读取操作异常退出（特别是当层已经过时时），将返回错误。
//
// Note:
// - the returned account data is not a copy, please don't modify it
// - no error will be returned if the requested account is not found in database
// 注意：
// - 返回的账户数据不是副本，请不要修改它。
// - 如果在数据库中找不到请求的账户，不会返回错误。
func (r *reader) AccountRLP(hash common.Hash) ([]byte, error) {
	return r.layer.account(hash, 0)
}

// Account directly retrieves the account associated with a particular hash in
// the slim data format. An error will be returned if the read operation exits
// abnormally. Specifically, if the layer is already stale.
// 直接以精简数据格式检索与特定哈希关联的账户。
// 如果读取操作异常退出（特别是当层已经过时时），将返回错误。
//
// Note:
// - the returned account object is safe to modify
// - no error will be returned if the requested account is not found in database
// 注意：
// - 返回的账户对象可以安全地修改。
// - 如果在数据库中找不到请求的账户，不会返回错误。
func (r *reader) Account(hash common.Hash) (*types.SlimAccount, error) {
	blob, err := r.layer.account(hash, 0)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, nil
	}
	account := new(types.SlimAccount)
	if err := rlp.DecodeBytes(blob, account); err != nil {
		panic(err)
	}
	return account, nil
}

// Storage directly retrieves the storage data associated with a particular hash,
// within a particular account. An error will be returned if the read operation
// exits abnormally. Specifically, if the layer is already stale.
// 直接检索与特定账户中的特定哈希关联的存储数据。
// 如果读取操作异常退出（特别是当层已经过时时），将返回错误。
//
// Note:
// - the returned storage data is not a copy, please don't modify it
// - no error will be returned if the requested slot is not found in database
// 注意：
// - 返回的存储数据不是副本，请不要修改它。
// - 如果在数据库中找不到请求的槽位，不会返回错误。
func (r *reader) Storage(accountHash, storageHash common.Hash) ([]byte, error) {
	return r.layer.storage(accountHash, storageHash, 0)
}

// NodeReader retrieves a layer belonging to the given state root.
// NodeReader 检索属于给定状态根的层。
func (db *Database) NodeReader(root common.Hash) (database.NodeReader, error) {
	layer := db.tree.get(root)
	if layer == nil {
		return nil, fmt.Errorf("state %#x is not available", root)
	}
	return &reader{layer: layer, noHashCheck: db.isVerkle}, nil
}

// StateReader returns a reader that allows access to the state data associated
// with the specified state.
// StateReader 返回一个允许访问与指定状态关联的状态数据的 reader。
func (db *Database) StateReader(root common.Hash) (database.StateReader, error) {
	layer := db.tree.get(root)
	if layer == nil {
		return nil, fmt.Errorf("state %#x is not available", root)
	}
	return &reader{layer: layer}, nil
}
