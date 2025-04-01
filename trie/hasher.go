// Copyright 2016 The go-ethereum Authors
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

package trie

import (
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// 在以太坊的 Merkle Patricia Trie（MPT）中，每个节点的哈希是其内容的 Keccak-256 值，用于验证数据完整性。

// hasher is a type used for the trie Hash operation. A hasher has some
// internal preallocated temp space
// hasher 是用于 trie 哈希操作的类型。hasher 内部有一些预分配的临时空间
type hasher struct {
	sha      crypto.KeccakState // Keccak 哈希状态，用于计算哈希值（以太坊使用 Keccak-256）。
	tmp      []byte             // 临时字节切片，用于存储中间数据。
	encbuf   rlp.EncoderBuffer  // RLP 编码缓冲区，用于序列化 Trie 节点。
	parallel bool               // Whether to use parallel threads when hashing // 是否在哈希时使用并行线程，指示是否使用并行线程进行哈希计算。
}

// hasherPool holds pureHashers
// hasherPool 持有纯 hasher 实例
var hasherPool = sync.Pool{
	New: func() interface{} {
		return &hasher{
			tmp:    make([]byte, 0, 550),      // cap is as large as a full fullNode. 容量足以容纳一个完整的 fullNode
			sha:    crypto.NewKeccakState(),   // 创建新的 Keccak 状态
			encbuf: rlp.NewEncoderBuffer(nil), // 初始化 RLP 编码缓冲区
		}
	},
}

func newHasher(parallel bool) *hasher {
	// 从对象池中获取一个 hasher 实例，并设置是否并行
	h := hasherPool.Get().(*hasher)
	h.parallel = parallel
	return h
}

func returnHasherToPool(h *hasher) {
	hasherPool.Put(h)
}

// hash collapses a node down into a hash node, also returning a copy of the
// original node initialized with the computed hash to replace the original one.
//
// hash 将节点折叠为 hashNode，同时返回原始节点的副本，初始化为计算出的哈希以替换原始节点。
func (h *hasher) hash(n node, force bool) (hashed node, cached node) {
	// Return the cached hash if it's available
	// 如果缓存哈希可用，则直接返回
	if hash, _ := n.cache(); hash != nil {
		return hash, n // 返回缓存哈希和原节点
	}
	// Trie not processed yet, walk the children
	// Trie 尚未处理，遍历子节点
	switch n := n.(type) {
	case *shortNode:
		collapsed, cached := h.hashShortNodeChildren(n) // 折叠 shortNode 的子节点
		hashed := h.shortnodeToHash(collapsed, force)   // 计算哈希
		// We need to retain the possibly _not_ hashed node, in case it was too
		// small to be hashed
		// 需要保留可能未哈希的节点，以防它太小而未被哈希
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn // 如果哈希成功，更新缓存哈希
		} else {
			cached.flags.hash = nil // 否则清空缓存哈希
		}
		return hashed, cached // 返回哈希节点和更新后的副本
	case *fullNode:
		collapsed, cached := h.hashFullNodeChildren(n) // 折叠 fullNode 的子节点
		hashed = h.fullnodeToHash(collapsed, force)    // 计算哈希
		if hn, ok := hashed.(hashNode); ok {
			cached.flags.hash = hn // 如果哈希成功，更新缓存哈希
		} else {
			cached.flags.hash = nil // 否则清空缓存哈希
		}
		return hashed, cached // 返回哈希节点和更新后的副本
	default:
		// Value and hash nodes don't have children, so they're left as were
		// valueNode 和 hashNode 没有子节点，因此保持不变
		return n, n
	}
}

// hashShortNodeChildren collapses the short node. The returned collapsed node
// holds a live reference to the Key, and must not be modified.
//
// hashShortNodeChildren 折叠短节点。返回的折叠节点持有对 Key 的实时引用，且不得被修改。
func (h *hasher) hashShortNodeChildren(n *shortNode) (collapsed, cached *shortNode) {
	// Hash the short node's child, caching the newly hashed subtree
	// 对短节点的子节点进行哈希，缓存新哈希后的子树
	collapsed, cached = n.copy(), n.copy()
	// Previously, we did copy this one. We don't seem to need to actually
	// do that, since we don't overwrite/reuse keys
	// cached.Key = common.CopyBytes(n.Key)
	// 之前我们复制了这个键，但似乎不需要这样做，因为我们不会覆盖或重用键
	collapsed.Key = hexToCompact(n.Key)
	// Unless the child is a valuenode or hashnode, hash it
	// 除非子节点是值节点或哈希节点，否则对其进行哈希
	switch n.Val.(type) {
	case *fullNode, *shortNode:
		collapsed.Val, cached.Val = h.hash(n.Val, false)
	}
	return collapsed, cached
}

func (h *hasher) hashFullNodeChildren(n *fullNode) (collapsed *fullNode, cached *fullNode) {
	// Hash the full node's children, caching the newly hashed subtrees
	// 对完整节点的子节点进行哈希，缓存新哈希后的子树
	cached = n.copy()
	collapsed = n.copy()
	if h.parallel {
		var wg sync.WaitGroup
		wg.Add(16)
		for i := 0; i < 16; i++ {
			go func(i int) {
				hasher := newHasher(false)
				if child := n.Children[i]; child != nil {
					collapsed.Children[i], cached.Children[i] = hasher.hash(child, false)
				} else {
					collapsed.Children[i] = nilValueNode
				}
				returnHasherToPool(hasher)
				wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i := 0; i < 16; i++ {
			if child := n.Children[i]; child != nil {
				collapsed.Children[i], cached.Children[i] = h.hash(child, false)
			} else {
				collapsed.Children[i] = nilValueNode
			}
		}
	}
	return collapsed, cached
}

// 以太坊 MPT 规定，小于 32 字节的 RLP 编码节点直接嵌入父节点，不计算哈希。

// shortnodeToHash creates a hashNode from a shortNode. The supplied shortnode
// should have hex-type Key, which will be converted (without modification)
// into compact form for RLP encoding.
// If the rlp data is smaller than 32 bytes, `nil` is returned.
//
// shortnodeToHash 从 shortNode 创建一个 hashNode。提供的 shortNode 应该具有十六进制类型的 Key，
// 该 Key 将被转换为紧凑形式（不修改内容）以进行 RLP 编码。
// 如果 RLP 数据小于 32 字节，则返回 `nil`。
func (h *hasher) shortnodeToHash(n *shortNode, force bool) node {
	n.encode(h.encbuf)      // 将 shortNode 编码到缓冲区
	enc := h.encodedBytes() // 获取编码后的字节

	if len(enc) < 32 && !force { // 如果编码小于 32 字节且不强制哈希
		return n // Nodes smaller than 32 bytes are stored inside their parent // 小于 32 字节的节点存储在其父节点中
	}
	return h.hashData(enc) // 计算并返回哈希节点
}

// fullnodeToHash is used to create a hashNode from a fullNode, (which
// may contain nil values)
// fullnodeToHash 用于从 fullNode 创建一个 hashNode（可能包含 nil 值）
func (h *hasher) fullnodeToHash(n *fullNode, force bool) node {
	n.encode(h.encbuf)      // 将 fullNode 编码到缓冲区
	enc := h.encodedBytes() // 获取编码后的字节

	if len(enc) < 32 && !force { // 如果编码小于 32 字节且不强制哈希
		return n // Nodes smaller than 32 bytes are stored inside their parent // 小于 32 字节的节点存储在其父节点中
	}
	return h.hashData(enc) // 计算并返回哈希节点
}

// encodedBytes returns the result of the last encoding operation on h.encbuf.
// This also resets the encoder buffer.
//
// All node encoding must be done like this:
//
//	node.encode(h.encbuf)
//	enc := h.encodedBytes()
//
// This convention exists because node.encode can only be inlined/escape-analyzed when
// called on a concrete receiver type.
//
// encodedBytes 返回 h.encbuf 上最后一次编码操作的结果。
// 这也会重置编码器缓冲区。
//
// 所有节点编码必须按以下方式进行：
//
//	node.encode(h.encbuf)
//	enc := h.encodedBytes()
//
// 这种约定存在的原因是 node.encode 只有在具体接收者类型上调用时才能被内联/逃逸分析。
func (h *hasher) encodedBytes() []byte {
	h.tmp = h.encbuf.AppendToBytes(h.tmp[:0]) // 将缓冲区内容追加到 h.tmp 并清空原切片
	h.encbuf.Reset(nil)                       // 重置编码缓冲区
	return h.tmp                              // 返回编码结果
}

// hashData hashes the provided data
// hashData 对提供的数据进行哈希计算
func (h *hasher) hashData(data []byte) hashNode {
	n := make(hashNode, 32) // 创建 32 字节的 hashNode
	h.sha.Reset()           // 重置 Keccak 状态
	h.sha.Write(data)       // 写入数据
	h.sha.Read(n)           // 读取哈希值到 n
	return n                // 返回哈希结果
}

// Trie 证明（Merkle Proof）:
// 在以太坊中，Trie 证明用于验证特定键值对的存在性。
// proofHash 折叠子节点并计算哈希，生成证明路径中的节点：
//  collapsed 是编码前的节点。
//  hashed 是哈希后的节点（或原节点，若小于 32 字节）。

// proofHash is used to construct trie proofs, and returns the 'collapsed'
// node (for later RLP encoding) as well as the hashed node -- unless the
// node is smaller than 32 bytes, in which case it will be returned as is.
// This method does not do anything on value- or hash-nodes.
//
// proofHash 用于构造 trie 证明，返回“折叠”后的节点（供后续 RLP 编码）以及哈希后的节点，
// 除非节点小于 32 字节，在这种情况下将按原样返回。
// 此方法对 valueNode 或 hashNode 不执行任何操作。
func (h *hasher) proofHash(original node) (collapsed, hashed node) {
	switch n := original.(type) {
	case *shortNode:
		sn, _ := h.hashShortNodeChildren(n)     // 折叠 shortNode 的子节点
		return sn, h.shortnodeToHash(sn, false) // 返回折叠节点和哈希结果
	case *fullNode:
		fn, _ := h.hashFullNodeChildren(n)     // 折叠 fullNode 的子节点
		return fn, h.fullnodeToHash(fn, false) // 返回折叠节点和哈希结果
	default:
		// Value and hash nodes don't have children, so they're left as were
		// valueNode 和 hashNode 没有子节点，因此保持不变
		return n, n
	}
}
