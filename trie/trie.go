// Copyright 2014 The go-ethereum Authors
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

// Package trie implements Merkle Patricia Tries.
package trie

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// MPT 是以太坊状态树（State Trie）、交易树（Transaction Trie）和收据树（Receipt Trie）的核心实现。
// 状态树存储了所有账户的状态（如余额、nonce、代码等），通过根哈希记录在区块头中。

// Trie is a Merkle Patricia Trie. Use New to create a trie that sits on
// top of a database. Whenever trie performs a commit operation, the generated
// nodes will be gathered and returned in a set. Once the trie is committed,
// it's not usable anymore. Callers have to re-create the trie with new root
// based on the updated trie database.
//
// Trie is not safe for concurrent use.
// Trie 是一个 Merkle Patricia Trie。使用 New 创建一个位于数据库之上的 trie。
// 每当 trie 执行提交操作时，生成的新节点将被收集并以集合的形式返回。
// 一旦 trie 被提交，它将无法再次使用。调用者需要根据更新的 trie 数据库重新创建具有新根的 trie。
//
// Trie 不支持并发使用。
//
// 定义了一个 Merkle Patricia Trie（MPT），这是以太坊中用于存储和验证状态数据（如账户余额、合约存储等）的核心数据结构。
// MPT 结合了 Patricia Trie（前缀树）和 Merkle Tree 的特性，具有高效存储和加密验证的能力。
type Trie struct {
	root  node        // root 是 trie 的根节点。表示 MPT 的根节点，是整个树的起点。通过根节点的哈希值，可以验证整个树的状态。
	owner common.Hash // owner 是 trie 的所有者标识，使用 common.Hash 类型。标识 trie 的所有者，通常是以太坊地址的哈希形式，用于区分不同的 trie 实例。

	// Flag whether the commit operation is already performed. If so the
	// trie is not usable(latest states is invisible).
	// 是否已执行提交操作的标志。如果已提交，trie 将不可用（最新的状态将不可见）。
	committed bool // 标记 trie 是否已提交。提交后，trie 不可用，需要重新基于更新后的数据库创建新实例。

	// Keep track of the number leaves which have been inserted since the last
	// hashing operation. This number will not directly map to the number of
	// actually unhashed nodes.
	// 跟踪自上次哈希操作以来插入的叶子节点数量。这个数字并不直接对应实际未哈希的节点数量。
	unhashed int // 记录自上次哈希以来插入的叶子节点数量，用于优化哈希计算。

	// uncommitted is the number of updates since last commit.
	// 自上次提交以来更新的次数
	uncommitted int // 记录自上次提交以来的更新次数，反映 trie 的修改状态。

	// reader is the handler trie can retrieve nodes from.
	// reader 是 trie 可以从中检索节点的处理器
	reader *trieReader // 提供从底层数据库读取节点的能力，是 trie 与存储层交互的关键。

	// tracer is the tool to track the trie changes.
	// tracer 是用于跟踪 trie 变化的工具
	tracer *tracer // 用于调试或跟踪 trie 的变化，可能用于开发或分析。
}

// 节点标志与 MPT 的更新机制：
// 在 Merkle Patricia Trie（MPT）中，节点的 dirty 状态用于区分内存中的临时修改与已持久化的数据。
// 以太坊的状态树在区块处理过程中会频繁创建新节点（如账户状态更新），这些节点在提交前都处于 dirty 状态。
// newFlag 的设计支持这种机制，确保新节点在生成时被正确标记为未哈希状态。

// newFlag returns the cache flag value for a newly created node.
// newFlag 返回新创建节点的缓存标志值。
func (t *Trie) newFlag() nodeFlag {
	// dirty 表示节点是否已被修改（脏状态）。新创建的节点默认是“脏”的，因为它还未被哈希或持久化。
	return nodeFlag{dirty: true}
}

// 状态快照与回滚：
// 在以太坊中，状态树的拷贝常用于事务执行的临时快照。
// 例如，EVM（以太坊虚拟机）在执行交易时需要创建状态副本，以便在失败时回滚。
// Copy 方法的设计支持这种需求，通过复制 Trie 提供一个隔离的修改环境。

// Copy returns a copy of Trie.
// Copy 返回 Trie 的一个副本。
func (t *Trie) Copy() *Trie {
	return &Trie{
		root:        t.root,
		owner:       t.owner,
		committed:   t.committed,
		reader:      t.reader,
		tracer:      t.tracer.copy(),
		uncommitted: t.uncommitted,
		unhashed:    t.unhashed,
	}
}

// New creates the trie instance with provided trie id and the read-only
// database. The state specified by trie id must be available, otherwise
// an error will be returned. The trie root specified by trie id can be
// zero hash or the sha3 hash of an empty string, then trie is initially
// empty, otherwise, the root node must be present in database or returns
// a MissingNodeError if not.
//
// New 创建一个带有指定 trie id 和只读数据库的 trie 实例。
// 由 trie id 指定的状态必须可用，否则将返回错误。
// trie id 指定的 trie 根可以是零哈希或空字符串的 sha3 哈希，此时 trie 初始为空；
// 否则，根节点必须存在于数据库中，如果不存在将返回 MissingNodeError。
func New(id *ID, db database.NodeDatabase) (*Trie, error) {
	// 创建一个 trie 读取器，基于状态根和所有者从数据库中读取数据
	reader, err := newTrieReader(id.StateRoot, id.Owner, db)
	if err != nil {
		return nil, err
	}
	trie := &Trie{
		owner:  id.Owner,
		reader: reader,
		tracer: newTracer(),
	}
	// 如果根哈希不是零哈希或空根哈希，则解析并跟踪根节点
	if id.Root != (common.Hash{}) && id.Root != types.EmptyRootHash {
		rootnode, err := trie.resolveAndTrack(id.Root[:], nil)
		if err != nil {
			return nil, err
		}
		trie.root = rootnode
	}
	return trie, nil
}

// NewEmpty is a shortcut to create empty tree. It's mostly used in tests.
// NewEmpty 是创建空树的快捷方式，主要用于测试。
func NewEmpty(db database.NodeDatabase) *Trie {
	// 使用空根哈希创建空的 trie 实例，忽略错误（测试用）
	tr, _ := New(TrieID(types.EmptyRootHash), db)
	return tr
}

// MustNodeIterator is a wrapper of NodeIterator and will omit any encountered
// error but just print out an error message.
//
// MustNodeIterator 是 NodeIterator 的包装器，将忽略遇到的任何错误，仅打印错误消息。
func (t *Trie) MustNodeIterator(start []byte) NodeIterator {
	it, err := t.NodeIterator(start)
	if err != nil {
		log.Error("Unhandled trie error in Trie.NodeIterator", "err", err)
	}
	return it
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration starts at
// the key after the given start key.
// NodeIterator 返回一个迭代器，用于返回 trie 的节点。迭代从给定的起始键之后的键开始。
// 用于遍历 trie 的节点，从指定 start 键之后的键开始。
//
// MPT 遍历： Merkle Patricia Trie（MPT）在以太坊中存储状态数据，NodeIterator 提供了一种顺序访问 trie 节点的方式。这在状态导出、验证或同步中非常有用。
func (t *Trie) NodeIterator(start []byte) (NodeIterator, error) {
	// Short circuit if the trie is already committed and not usable.
	// 如果 trie 已提交且不可用，则短路返回。
	if t.committed {
		return nil, ErrCommitted
	}
	return newNodeIterator(t, start), nil
}

// MustGet is a wrapper of Get and will omit any encountered error but just
// print out an error message.
// MustGet 是 Get 的包装器，将忽略遇到的任何错误，仅打印错误消息。
func (t *Trie) MustGet(key []byte) []byte {
	res, err := t.Get(key)
	if err != nil {
		log.Error("Unhandled trie error in Trie.Get", "err", err)
	}
	return res
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
//
// Get 返回存储在 trie 中的 key 对应的值。
// 调用者不得修改返回的值字节。
//
// 如果请求的节点不在 trie 中，将不会返回错误。
// 如果 trie 已损坏，将返回 MissingNodeError。
func (t *Trie) Get(key []byte) ([]byte, error) {
	// Short circuit if the trie is already committed and not usable.
	// 如果 trie 已提交且不可用，则短路返回。
	if t.committed {
		return nil, ErrCommitted
	}
	value, newroot, didResolve, err := t.get(t.root, keybytesToHex(key), 0)
	if err == nil && didResolve {
		t.root = newroot
	}
	return value, err
}

// MPT 的值检索： Merkle Patricia Trie（MPT）在以太坊中存储状态数据（如账户余额、合约存储）。get 方法通过半字节路径（key）遍历 trie，检索目标值，是状态查询的核心实现。
// 路径匹配： bytes.HasPrefix 检查 key 是否匹配 shortNode 的键，体现了 Patricia Trie 的前缀共享特性。这种设计减少存储冗余，优化以太坊状态树。

// 按节点类型处理：
// nil：键不存在，返回空结果。
// valueNode：到达值节点，返回其值。
// shortNode：检查 key[pos:] 是否匹配 n.Key，递归处理子节点。
// fullNode：根据 key[pos] 索引子节点，递归处理。
// hashNode：解析节点后递归处理。
// default：抛出异常。

// get 从 trie 中检索键对应的值。
// 返回值包括：
// - value: 找到的值（如果存在）。
// - newnode: 更新后的节点（可能是原始节点的副本）。
// - didResolve: 是否解析了 hashNode。
// - err: 操作中的错误。
func (t *Trie) get(origNode node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		// 找到值节点，直接返回其值
		return n, n, false, nil
	case *shortNode:
		if !bytes.HasPrefix(key[pos:], n.Key) {
			// key not found in trie
			// trie 中未找到 key
			return nil, n, false, nil
		}
		value, newnode, didResolve, err = t.get(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.get(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		// 遇到 hashNode，解析并继续检索
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustGetNode is a wrapper of GetNode and will omit any encountered error but
// just print out an error message.
//
// MustGetNode 是 GetNode 的包装器，将忽略遇到的任何错误，仅打印错误消息。
func (t *Trie) MustGetNode(path []byte) ([]byte, int) {
	item, resolved, err := t.GetNode(path)
	if err != nil {
		log.Error("Unhandled trie error in Trie.GetNode", "err", err)
	}
	return item, resolved
}

// GetNode retrieves a trie node by compact-encoded path. It is not possible
// to use keybyte-encoding as the path might contain odd nibbles.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
//
// GetNode 通过紧凑编码的路径检索 trie 节点。不能使用 keybyte 编码，因为路径可能包含奇数半字节。
//
// 如果请求的节点不在 trie 中，将不会返回错误。
// 如果 trie 已损坏，将返回 MissingNodeError。
//
// 状态检索： GetNode 返回节点的 RLP 编码数据（item），支持状态查询和 Merkle 证明生成，用于以太坊的轻客户端验证。
func (t *Trie) GetNode(path []byte) ([]byte, int, error) {
	// Short circuit if the trie is already committed and not usable.
	// 如果 trie 已提交且不可用，则短路返回。
	if t.committed {
		return nil, 0, ErrCommitted
	}
	item, newroot, resolved, err := t.getNode(t.root, compactToHex(path), 0)
	if err != nil {
		return nil, resolved, err
	}
	if resolved > 0 {
		t.root = newroot
	}
	return item, resolved, nil
}

// 按节点类型处理：
// valueNode：路径提前结束，返回空结果。
// shortNode：检查路径是否匹配 n.Key，递归处理子节点。
// fullNode：根据 path[pos] 索引子节点，递归处理。
// hashNode：解析节点后递归处理。
// default：抛出异常。

// getNode 沿着路径检索节点及其对应的 RLP 编码 blob，用于状态查询或验证。。
// 返回值包括：
// - item: 从数据库加载的 RLP 编码的节点数据（如果找到）。
// - newnode: 更新后的节点（可能是原始节点的副本）。
// - resolved: 已解析的 hashNode 数量。
// - err: 操作中的错误。
func (t *Trie) getNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
	// If non-existent path requested, abort
	// 如果请求的路径不存在，则中止
	if origNode == nil {
		return nil, nil, 0, nil
	}
	// If we reached the requested path, return the current node
	// 如果到达请求的路径，返回当前节点
	if pos >= len(path) {
		// Although we most probably have the original node expanded, encoding
		// that into consensus form can be nasty (needs to cascade down) and
		// time consuming. Instead, just pull the hash up from disk directly.
		// 虽然我们很可能已经扩展了原始节点，但将其编码为共识形式可能很麻烦（需要向下级联）且耗时。
		// 相反，直接从磁盘拉取哈希。
		var hash hashNode
		if node, ok := origNode.(hashNode); ok {
			hash = node
		} else {
			hash, _ = origNode.cache()
		}
		if hash == nil {
			return nil, origNode, 0, errors.New("non-consensus node")
		}
		blob, err := t.reader.node(path, common.BytesToHash(hash))
		return blob, origNode, 1, err
	}
	// Path still needs to be traversed, descend into children
	// 路径仍需遍历，继续进入子节点
	switch n := (origNode).(type) {
	case valueNode:
		// Path prematurely ended, abort
		// 路径提前结束，中止
		return nil, nil, 0, nil

	case *shortNode:
		if !bytes.HasPrefix(path[pos:], n.Key) {
			// Path branches off from short node
			// 路径从 shortNode 分支出去
			return nil, n, 0, nil
		}
		item, newnode, resolved, err = t.getNode(n.Val, path, pos+len(n.Key))
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Val = newnode
		}
		return item, n, resolved, err

	case *fullNode:
		item, newnode, resolved, err = t.getNode(n.Children[path[pos]], path, pos+1)
		if err == nil && resolved > 0 {
			n = n.copy()
			n.Children[path[pos]] = newnode
		}
		return item, n, resolved, err

	case hashNode:
		child, err := t.resolveAndTrack(n, path[:pos])
		if err != nil {
			return nil, n, 1, err
		}
		item, newnode, resolved, err := t.getNode(child, path, pos)
		return item, newnode, resolved + 1, err

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}

// MustUpdate is a wrapper of Update and will omit any encountered error but
// just print out an error message.
// MustUpdate 是 Update 的包装器，将忽略遇到的任何错误，仅打印错误消息。
func (t *Trie) MustUpdate(key, value []byte) {
	if err := t.Update(key, value); err != nil {
		log.Error("Unhandled trie error in Trie.Update", "err", err)
	}
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
//
// Update 将 key 与 value 关联到 trie 中。后续对 Get 的调用将返回 value。如果 value 长度为零，则从 trie 中删除任何现有值，并且 Get 将返回 nil。
//
// 调用者不得修改存储在 trie 中的 value 字节。
//
// 如果请求的节点不在 trie 中，将不会返回错误。
// 如果 trie 已损坏，将返回 MissingNodeError。
func (t *Trie) Update(key, value []byte) error {
	// Short circuit if the trie is already committed and not usable.
	// 如果 trie 已提交且不可用，则短路返回。
	if t.committed {
		return ErrCommitted
	}
	return t.update(key, value)
}

// MPT 更新机制： MPT 在以太坊中通过插入或删除操作管理状态。update 的设计将空值视为删除请求，符合以太坊的存储清理逻辑（如将存储槽设为零值表示删除）。
// update 根据 value 的长度决定插入或删除操作，更新 trie 的根节点。
func (t *Trie) update(key, value []byte) error {
	// 递增 t.unhashed 和 t.uncommitted，标记 trie 被修改。
	t.unhashed++
	t.uncommitted++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(value))
		if err != nil {
			return err
		}
		t.root = n
	} else {
		_, n, err := t.delete(t.root, nil, k)
		if err != nil {
			return err
		}
		t.root = n
	}
	return nil
}

// MPT 的插入机制：
// Merkle Patricia Trie（MPT）在以太坊中用于存储状态数据（如账户余额、合约存储）。
// insert 方法实现了键值对的动态插入，通过 shortNode（扩展/叶子节点）和 fullNode（分支节点）调整结构，保持前缀共享特性。

// insert 将键值对插入到 trie 中，返回是否修改、新节点和可能的错误。
// 如果 key 为空，则直接处理值节点；否则根据节点类型递归插入。
func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			// 如果当前节点是 valueNode，检查值是否相同，若不同则返回新值
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		// 如果当前节点不是 valueNode，直接插入新值
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		// 如果整个 key 匹配，保持此 shortNode 不变，仅更新值
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		// 否则在差异处分支
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		// 如果差异在索引 0 处，用分支替换此 shortNode
		if matchlen == 0 {
			return true, branch, nil
		}
		// New branch node is created as a child of the original short node.
		// Track the newly inserted node in the tracer. The node identifier
		// passed is the path from the root node.
		// 新分支节点作为原始 shortNode 的子节点创建。在 tracer 中跟踪新插入的节点，节点标识符是从根节点起的路径。
		t.tracer.onInsert(append(prefix, key[:matchlen]...))

		// Replace it with a short node leading up to the branch.
		// 用通向分支的 shortNode 替换它
		return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// New short node is created and track it in the tracer. The node identifier
		// passed is the path from the root node. Note the valueNode won't be tracked
		// since it's always embedded in its parent.
		// 创建新的 shortNode 并在 tracer 中跟踪它。节点标识符是从根节点起的路径。注意 valueNode 不会被跟踪，因为它总是嵌入其父节点中。
		t.tracer.onInsert(prefix)

		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and insert into it. This leaves all child nodes on
		// the path to the value in the trie.
		// 遇到尚未加载的 trie 部分。加载节点并插入其中。这会保留通向值的路径上的所有子节点。
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// MustDelete is a wrapper of Delete and will omit any encountered error but
// just print out an error message.
//
// MustDelete 是 Delete 的包装器，将忽略遇到的任何错误，仅打印错误消息。
// 忽略错误并仅记录日志，适用于不希望中断执行的场景。
func (t *Trie) MustDelete(key []byte) {
	if err := t.Delete(key); err != nil {
		log.Error("Unhandled trie error in Trie.Delete", "err", err)
	}
}

// MPT 删除机制：
// Delete 是 Merkle Patricia Trie（MPT）中删除操作的高层接口，依赖底层的 delete 方法实现递归删除和节点简化。
// 在以太坊中，这用于移除账户状态或合约存储。

// Delete removes any existing value for key from the trie.
//
// If the requested node is not present in trie, no error will be returned.
// If the trie is corrupted, a MissingNodeError is returned.
//
// Delete 从 trie 中删除 key 对应的任何现有值。
//
// 如果请求的节点不在 trie 中，将不会返回错误。
// 如果 trie 已损坏，将返回 MissingNodeError。
func (t *Trie) Delete(key []byte) error {
	// Short circuit if the trie is already committed and not usable.
	// 如果 trie 已提交且不可用，则短路返回。
	if t.committed {
		return ErrCommitted
	}
	t.uncommitted++
	t.unhashed++
	k := keybytesToHex(key)
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// delete returns the new root of the trie with key deleted.
// It reduces the trie to minimal form by simplifying
// nodes on the way up after deleting recursively.
//
// delete 返回删除 key 后的 trie 新根节点。
// 它通过在递归删除后向上简化节点，将 trie 缩减到最小形式。
func (t *Trie) delete(n node, prefix, key []byte) (bool, node, error) {
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key) // 比较 key 和 n.Key 的匹配长度
		if matchlen < len(n.Key) {        // 未完全匹配：返回未修改。
			return false, n, nil // don't replace n on mismatch  不匹配时不替换 n
		}
		if matchlen == len(key) { // 完全匹配：删除节点，跟踪删除，返回 nil。
			// The matched short node is deleted entirely and track
			// it in the deletion set. The same the valueNode doesn't
			// need to be tracked at all since it's always embedded.
			//
			// 完全匹配的 shortNode 被删除，并在删除集合中跟踪它。valueNode 不需要跟踪，因为它总是嵌入的。
			t.tracer.onDelete(prefix)

			return true, nil, nil // remove n entirely for whole matches 完全匹配时删除整个 n
		}
		// 部分匹配：递归删除子节点，合并或更新节点。

		// The key is longer than n.Key. Remove the remaining suffix
		// from the subtrie. Child can never be nil here since the
		// subtrie must contain at least two other values with keys
		// longer than n.Key.
		//
		// key 比 n.Key 长。从子 trie 中删除剩余的后缀。此处 child 永远不会为 nil，因为子 trie 至少包含两个键长于 n.Key 的值。
		dirty, child, err := t.delete(n.Val, append(prefix, key[:len(n.Key)]...), key[len(n.Key):])
		if !dirty || err != nil {
			return false, n, err
		}
		switch child := child.(type) {
		case *shortNode:
			// The child shortNode is merged into its parent, track
			// is deleted as well.
			//
			// 子 shortNode 被合并到父节点中，跟踪其删除。
			t.tracer.onDelete(append(prefix, n.Key...))

			// Deleting from the subtrie reduced it to another
			// short node. Merge the nodes to avoid creating a
			// shortNode{..., shortNode{...}}. Use concat (which
			// always creates a new slice) instead of append to
			// avoid modifying n.Key since it might be shared with
			// other nodes.
			//
			// 从子 trie 删除后缩减为另一个 shortNode。合并节点以避免创建 shortNode{..., shortNode{...}}。
			// 使用 concat（始终创建新切片）而不是 append，以避免修改 n.Key，因为它可能与其他节点共享。
			return true, &shortNode{concat(n.Key, child.Key...), child.Val, t.newFlag()}, nil
		default:
			return true, &shortNode{n.Key, child, t.newFlag()}, nil
		}

	case *fullNode: // 递归删除子节点。
		dirty, nn, err := t.delete(n.Children[key[0]], append(prefix, key[0]), key[1:])
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn

		// Because n is a full node, it must've contained at least two children
		// before the delete operation. If the new child value is non-nil, n still
		// has at least two children after the deletion, and cannot be reduced to
		// a short node.
		//
		// 因为 n 是 fullNode，删除前至少包含两个子节点。如果新的子节点值非 nil，删除后 n 仍至少有两个子节点，无法缩减为 shortNode。
		if nn != nil { // 如果子节点变为空，检查剩余非空子节点数：
			return true, n, nil
		}
		// Reduction:
		// Check how many non-nil entries are left after deleting and
		// reduce the full node to a short node if only one entry is
		// left. Since n must've contained at least two children
		// before deletion (otherwise it would not be a full node) n
		// can never be reduced to nil.
		//
		// When the loop is done, pos contains the index of the single
		// value that is left in n or -2 if n contains at least two
		// values.
		//
		// 缩减：
		// 检查删除后剩余的非 nil 条目数量，如果只剩一个条目，则将 fullNode 缩减为 shortNode。
		// 因为删除前 n 至少有两个子节点（否则不会是 fullNode），n 永远不会缩减为 nil。
		//
		// 循环结束后，pos 包含 n 中剩余单一值的索引，或者如果 n 至少包含两个值，则为 -2。
		pos := -1
		for i, cld := range &n.Children {
			if cld != nil {
				if pos == -1 {
					pos = i
				} else {
					pos = -2
					break
				}
			}
		}
		if pos >= 0 {
			if pos != 16 {
				// If the remaining entry is a short node, it replaces
				// n and its key gets the missing nibble tacked to the
				// front. This avoids creating an invalid
				// shortNode{..., shortNode{...}}.  Since the entry
				// might not be loaded yet, resolve it just for this
				// check.
				//
				// 如果剩余条目是 shortNode，则替换 n，并将缺失的 nibble 添加到键的前面。
				// 这避免创建无效的 shortNode{..., shortNode{...}}。由于条目可能尚未加载，仅为此检查解析它。
				cnode, err := t.resolve(n.Children[pos], append(prefix, byte(pos)))
				if err != nil {
					return false, nil, err
				}
				if cnode, ok := cnode.(*shortNode); ok {
					// Replace the entire full node with the short node.
					// Mark the original short node as deleted since the
					// value is embedded into the parent now.
					// 用 shortNode 替换整个 fullNode。因为值现已嵌入父节点，标记原始 shortNode 为已删除。
					t.tracer.onDelete(append(prefix, byte(pos)))

					k := append([]byte{byte(pos)}, cnode.Key...)
					return true, &shortNode{k, cnode.Val, t.newFlag()}, nil
				}
			}
			// Otherwise, n is replaced by a one-nibble short node
			// containing the child.
			// 否则，n 被替换为一个包含子节点的单 nibble shortNode。
			return true, &shortNode{[]byte{byte(pos)}, n.Children[pos], t.newFlag()}, nil
		}
		// n still contains at least two values and cannot be reduced.
		// n 仍至少包含两个值，无法缩减。
		return true, n, nil

	case valueNode:
		return true, nil, nil

	case nil:
		return false, nil, nil

	case hashNode:
		// We've hit a part of the trie that isn't loaded yet. Load
		// the node and delete from it. This leaves all child nodes on
		// the path to the value in the trie.
		//
		// 遇到尚未加载的 trie 部分。加载节点并从中删除。这会保留通向值的路径上的所有子节点。
		rn, err := t.resolveAndTrack(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.delete(rn, prefix, key)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil

	default:
		panic(fmt.Sprintf("%T: invalid node: %v (%v)", n, n, key))
	}
}

func concat(s1 []byte, s2 ...byte) []byte {
	r := make([]byte, len(s1)+len(s2))
	copy(r, s1)
	copy(r[len(s1):], s2)
	return r
}

// MPT 中的节点类型：
// 在 Merkle Patricia Trie（MPT）中，节点可以是实际数据（如分支节点、扩展节点、叶子节点）或哈希引用（hashNode）。
// resolve 方法的作用是处理这种引用关系，将 hashNode 解析为具体的节点结构。

// 检查输入节点是否为 hashNode，如果是，则调用 resolveAndTrack 从存储中加载实际节点；否则直接返回输入节点。
func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if n, ok := n.(hashNode); ok {
		return t.resolveAndTrack(n, prefix)
	}
	return n, nil
}

// resolveAndTrack loads node from the underlying store with the given node hash
// and path prefix and also tracks the loaded node blob in tracer treated as the
// node's original value. The rlp-encoded blob is preferred to be loaded from
// database because it's easy to decode node while complex to encode node to blob.
//
// resolveAndTrack 从底层存储中加载具有给定节点哈希和路径前缀的节点，
// 并同时在 tracer 中跟踪加载的节点 blob，将其视为节点的原始值。
// 优先从数据库加载 rlp 编码的 blob，因为解码节点较容易，而将节点编码为 blob 较复杂。
func (t *Trie) resolveAndTrack(n hashNode, prefix []byte) (node, error) {
	// 使用 t.reader.node 从存储中加载节点数据（blob），参数为路径前缀 prefix 和节点哈希（common.BytesToHash(n)）。
	blob, err := t.reader.node(prefix, common.BytesToHash(n))
	if err != nil {
		return nil, err
	}
	// 跟踪加载的节点，用于生成状态证明（witness）或调试。
	t.tracer.onRead(prefix, blob)
	return mustDecodeNode(n, blob), nil
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
// Hash 返回 trie 的根哈希。它不会写入数据库，即使 trie 没有数据库也可以使用。
func (t *Trie) Hash() common.Hash {
	hash, cached := t.hashRoot()
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// 状态提交与 MPT：
// 在以太坊中，状态树的提交是将内存中的修改（脏节点）写入数据库（如 LevelDB）的过程。
// Commit 方法实现了这一逻辑，生成新的根哈希并收集变更节点，反映了以太坊状态转换的原子性。

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage
//
// Commit 收集 trie 中的所有脏节点并将其替换为对应的节点哈希。
// 所有收集的节点（如果 collectLeaf 为 true，则包括脏叶子节点）将被封装到一个节点集合中返回。
// 如果 trie 是干净的（没有需要提交的内容），返回的节点集合可以为 nil。
// 一旦 trie 被提交，它将无法再次使用。
// 必须使用新的根和更新的 trie 数据库创建一个新的 trie 以供后续使用。
func (t *Trie) Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet) {
	defer func() {
		t.committed = true // 提交后 trie 失效（t.committed = true），符合区块链数据不可变原则。
	}()
	// Trie is empty and can be classified into two types of situations:
	// (a) The trie was empty and no update happens => return nil
	// (b) The trie was non-empty and all nodes are dropped => return
	//     the node set includes all deleted nodes
	//
	// trie 为空，可以分为两种情况：
	// (a) trie 原本为空且没有更新 => 返回 nil
	// (b) trie 原本非空但所有节点都被删除 => 返回包含所有删除节点的节点集合
	if t.root == nil {
		paths := t.tracer.deletedNodes()
		if len(paths) == 0 {
			return types.EmptyRootHash, nil // case (a)
		}
		nodes := trienode.NewNodeSet(t.owner)
		for _, path := range paths {
			nodes.AddNode([]byte(path), trienode.NewDeleted())
		}
		return types.EmptyRootHash, nodes // case (b)
	}
	// Derive the hash for all dirty nodes first. We hold the assumption
	// in the following procedure that all nodes are hashed.
	// 首先为所有脏节点计算哈希。我们假设在接下来的步骤中所有节点都已被哈希。
	rootHash := t.Hash()

	// Do a quick check if we really need to commit. This can happen e.g.
	// if we load a trie for reading storage values, but don't write to it.
	// 快速检查是否真的需要提交。例如，如果我们加载 trie 以读取存储值但未写入，则可能发生这种情况。
	if hashedNode, dirty := t.root.cache(); !dirty {
		// Replace the root node with the origin hash in order to
		// ensure all resolved nodes are dropped after the commit.
		// 将根节点替换为原始哈希，以确保在提交后丢弃所有已解析的节点。
		t.root = hashedNode
		return rootHash, nil
	}
	nodes := trienode.NewNodeSet(t.owner)
	for _, path := range t.tracer.deletedNodes() {
		nodes.AddNode([]byte(path), trienode.NewDeleted())
	}
	// If the number of changes is below 100, we let one thread handle it
	// 如果更改数量低于 100，我们让一个线程处理它
	t.root = newCommitter(nodes, t.tracer, collectLeaf).Commit(t.root, t.uncommitted > 100)
	t.uncommitted = 0
	return rootHash, nodes
}

// 根哈希与 MPT： 在以太坊中，MPT 的根哈希是状态树、交易树和收据树的唯一标识，记录在区块头中。hashRoot 的作用是递归计算整个树的哈希，确保所有节点的状态被正确封装。
// 空根哈希： types.EmptyRootHash 是以太坊定义的空 MPT 的根哈希值（一个固定的 32 字节值），用于表示空状态树。这是 MPT 的标准行为，确保即使树为空也能生成有效的哈希。

// hashRoot calculates the root hash of the given trie
// hashRoot 计算给定 trie 的根哈希，并返回哈希后的节点和缓存节点。
func (t *Trie) hashRoot() (node, node) {
	if t.root == nil {
		return hashNode(types.EmptyRootHash.Bytes()), nil
	}
	// If the number of changes is below 100, we let one thread handle it
	// 如果更改数量低于 100，我们让一个线程处理它
	h := newHasher(t.unhashed >= 100)
	defer func() {
		returnHasherToPool(h)
		t.unhashed = 0
	}()
	hashed, cached := h.hash(t.root, true)
	return hashed, cached
}

// Witness 与状态证明：
// 在以太坊中，“witness” 通常与状态证明（State Proof）或 Merkle 证明相关。
// MPT 的节点访问记录可以用来生成证明，验证特定账户或存储数据的正确性。
// Witness 方法通过 tracer 收集访问过的节点，为构建这种证明提供了基础。
//
// 轻客户端支持： 轻客户端依赖状态树的子集来验证数据，而无需下载整个状态树。
// Witness 返回的节点集合可以用来构造轻客户端所需的证明数据，符合以太坊的去中心化验证设计。

// Witness returns a set containing all trie nodes that have been accessed.
// Witness 返回一个包含所有被访问过的 trie 节点的集合。用于记录或分析状态树的访问路径。
func (t *Trie) Witness() map[string]struct{} {
	if len(t.tracer.accessList) == 0 { // 若为空则返回 nil，避免不必要的内存分配。
		return nil
	}
	witness := make(map[string]struct{}, len(t.tracer.accessList))
	for _, node := range t.tracer.accessList {
		witness[string(node)] = struct{}{} // 将每个节点（以字节形式存储）转换为字符串并添加到 witness 中。
	}
	return witness
}

// 状态清理与回滚：
// 在以太坊客户端中，状态树的清理和重置是常见操作。
// 例如，交易失败时需要回滚状态，或者在测试环境中重置 trie 以模拟新状态。
// Reset 方法提供了这种能力，确保 trie 可以从干净的状态重新开始。

// Reset drops the referenced root node and cleans all internal state.
// Reset 丢弃引用的根节点并清理所有内部状态。
func (t *Trie) Reset() {
	t.root = nil
	t.owner = common.Hash{}
	t.unhashed = 0
	t.uncommitted = 0
	t.tracer.reset()
	t.committed = false
}
