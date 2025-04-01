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

package trie

import (
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// indices 定义了一个字符串切片，表示 Trie 节点的索引，从 0 到 f（十六进制）加上一个额外的 [17]
// 长度 17 对应 fullNode 的子节点数量。
var indices = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "[17]"}

// node 是 trie 节点的接口类型
type node interface {
	cache() (hashNode, bool)    // 返回节点的缓存哈希和是否存在标志
	encode(w rlp.EncoderBuffer) // 将节点编码到 RLP 缓冲区
	fstring(string) string      // 返回节点的格式化字符串表示，使用给定的前缀
}

// Merkle Patricia Trie 结构:
// MPT 是以太坊状态 Trie 的核心，包含以下节点类型：
// 分支节点（Branch Node）:
//  - fullNode 对应分支节点，Children 数组有 17 个槽：16 个用于十六进制路径（0-f），第 17 个存储值。
// 扩展节点（Extension Node）:
//  - shortNode 表示扩展节点，Key 是共享路径前缀，Val 指向下一个节点。
// 叶子节点（Leaf Node）:
//  - valueNode 存储实际数据（如账户状态）。
// 哈希节点（Hash Node）:
//  - hashNode 表示已计算的子树哈希，用于压缩或引用。
// indices 的 0-f 和 [17] 对应 fullNode 的子节点索引。

type (
	// 表示 MPT 中的分支节点（Branch Node），有 16 个十六进制分支加 1 个值槽。
	// 表示完整分支，17 个子节点覆盖所有路径。
	fullNode struct {
		Children [17]node // Actual trie node data to encode/decode (needs custom encoder) // 实际的 trie 节点数据，用于编码/解码（需要自定义编码器）
		flags    nodeFlag // 节点标志，包含哈希值（若已计算）或脏标记（表示节点是否修改）等元数据。
	}
	// 表示 MPT 中的扩展节点（Extension Node）或部分叶子节点。
	// 表示路径压缩，键值对指向子树。
	shortNode struct {
		Key   []byte   // 键，表示路径片段。
		Val   node     // 值（子节点）
		flags nodeFlag // 节点标志
	}
	hashNode  []byte // 哈希节点，表示已计算的哈希值，表示已哈希的子树，用于节省空间或延迟计算。
	valueNode []byte // 值节点，表示存储的实际数据，表示 MPT 中的叶子节点（Leaf Node）的值。
)

// nilValueNode is used when collapsing internal trie nodes for hashing, since
// unset children need to serialize correctly.
// nilValueNode 用于在折叠内部 trie 节点以进行哈希计算时使用，因为未设置的子节点需要正确序列化。
var nilValueNode = valueNode(nil) // 表示空的 valueNode

// EncodeRLP encodes a full node into the consensus RLP format.
// EncodeRLP 将 fullNode 编码为共识 RLP 格式。
// EncodeRLP 是以太坊中节点序列化的标准方法，生成“共识 RLP 格式”，即 MPT 节点在网络传输或存储时的格式。
func (n *fullNode) EncodeRLP(w io.Writer) error {
	eb := rlp.NewEncoderBuffer(w) // 创建 RLP 编码缓冲区，写入目标为 w
	n.encode(eb)                  // 调用 fullNode 的 encode 方法进行编码
	return eb.Flush()             // 将缓冲区内容写入 w 并返回错误（若有）
}

func (n *fullNode) copy() *fullNode   { copy := *n; return &copy } // 创建 fullNode 的副本
func (n *shortNode) copy() *shortNode { copy := *n; return &copy } // 创建 shortNode 的副本

// nodeFlag contains caching-related metadata about a node.
// nodeFlag 包含与节点缓存相关的元数据。
type nodeFlag struct {
	hash  hashNode // cached hash of the node (may be nil) // 节点的缓存哈希（可能为 nil）
	dirty bool     // whether the node has changes that must be written to the database // 节点是否有更改，必须写入数据库
}

// 返回 fullNode\ shortNode\ hashNode\ valueNode 的缓存哈希和脏状态
func (n *fullNode) cache() (hashNode, bool)  { return n.flags.hash, n.flags.dirty }
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }
func (n hashNode) cache() (hashNode, bool)   { return nil, true }
func (n valueNode) cache() (hashNode, bool)  { return nil, true }

// Pretty printing.
// 美化打印
func (n *fullNode) String() string  { return n.fstring("") }
func (n *shortNode) String() string { return n.fstring("") }
func (n hashNode) String() string   { return n.fstring("") }
func (n valueNode) String() string  { return n.fstring("") }

// 返回 fullNode 的格式化字符串表示，带缩进
func (n *fullNode) fstring(ind string) string {
	resp := fmt.Sprintf("[\n%s  ", ind) // 开始列表并添加缩进
	for i, node := range &n.Children {  // 遍历子节点
		if node == nil {
			resp += fmt.Sprintf("%s: <nil> ", indices[i]) // 空子节点打印 <nil>
		} else {
			resp += fmt.Sprintf("%s: %v", indices[i], node.fstring(ind+"  ")) // 非空子节点递归格式化
		}
	}
	return resp + fmt.Sprintf("\n%s] ", ind) // 结束列表并添加缩进
}
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %v} ", n.Key, n.Val.fstring(ind+"  ")) // 键值对格式化
}
func (n hashNode) fstring(ind string) string {
	return fmt.Sprintf("<%x> ", []byte(n)) // 哈希值格式化
}
func (n valueNode) fstring(ind string) string {
	return fmt.Sprintf("%x ", []byte(n)) // 值格式化
}

// 在以太坊的 Merkle Patricia Trie（MPT）中，折叠（collapse）是指将子树编码为单一的 RLP 数据块，通常用于哈希计算或存储。
// rawNode 表示这种已折叠的状态，与未折叠的 fullNode 或 shortNode 区分开。

// rawNode is a simple binary blob used to differentiate between collapsed trie
// nodes and already encoded RLP binary blobs (while at the same time store them
// in the same cache fields).
// rawNode 是一个简单的二进制数据块，用于区分已折叠的 trie 节点和已编码的 RLP 二进制数据块（同时将它们存储在相同的缓存字段中）。
// 区分已折叠的 Trie 节点和已编码的 RLP 数据，同时允许它们共用缓存字段。
type rawNode []byte

// rawNode 的 cache 方法，触发 panic，因为它不应出现在活跃的 trie 中
func (n rawNode) cache() (hashNode, bool) { panic("this should never end up in a live trie") }

// rawNode 的 fstring 方法，触发 panic，因为它不应出现在活跃的 trie 中
func (n rawNode) fstring(ind string) string { panic("this should never end up in a live trie") }

// EncodeRLP 将 rawNode 编码为 RLP 格式，直接写入
func (n rawNode) EncodeRLP(w io.Writer) error {
	_, err := w.Write(n) // 将字节数据写入 io.Writer
	return err
}

// mustDecodeNode is a wrapper of decodeNode and panic if any error is encountered.
// mustDecodeNode 是 decodeNode 的包装函数，如果遇到任何错误则触发 panic。
func mustDecodeNode(hash, buf []byte) node {
	n, err := decodeNode(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// mustDecodeNodeUnsafe is a wrapper of decodeNodeUnsafe and panic if any error is
// encountered.
// mustDecodeNodeUnsafe 是 decodeNodeUnsafe 的包装函数，如果遇到任何错误则触发 panic。
func mustDecodeNodeUnsafe(hash, buf []byte) node {
	n, err := decodeNodeUnsafe(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("node %x: %v", hash, err))
	}
	return n
}

// decodeNode parses the RLP encoding of a trie node. It will deep-copy the passed
// byte slice for decoding, so it's safe to modify the byte slice afterwards. The-
// decode performance of this function is not optimal, but it is suitable for most
// scenarios with low performance requirements and hard to determine whether the
// byte slice be modified or not.
//
// decodeNode 解析 trie 节点的 RLP 编码。它会深拷贝传入的字节切片进行解码，因此之后修改字节切片是安全的。
// 此函数的解码性能不是最佳的，但适用于大多数性能要求不高且难以确定字节切片是否会被修改的场景。
func decodeNode(hash, buf []byte) (node, error) {
	return decodeNodeUnsafe(hash, common.CopyBytes(buf)) // 深拷贝字节后调用不安全解码
}

// 在以太坊的 MPT 中，节点以 RLP 格式存储：
//  shortNode（扩展或叶子节点）：编码为 2 项列表 [key, value]。
//  fullNode（分支节点）：编码为 17 项列表（16 个分支 + 1 个值槽）。
// decodeNodeUnsafe 根据元素数量区分类型，符合 MPT 规范。

// decodeNodeUnsafe parses the RLP encoding of a trie node. The passed byte slice
// will be directly referenced by node without bytes deep copy, so the input MUST
// not be changed after.
//
// decodeNodeUnsafe 解析 trie 节点的 RLP 编码。传入的字节切片会被节点直接引用，不进行字节深拷贝，因此之后不得修改输入。
func decodeNodeUnsafe(hash, buf []byte) (node, error) {
	if len(buf) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	elems, _, err := rlp.SplitList(buf) // 分割 RLP 列表
	if err != nil {
		return nil, fmt.Errorf("decode error: %v", err)
	}
	switch c, _ := rlp.CountValues(elems); c { // 根据元素数量判断节点类型
	case 2:
		n, err := decodeShort(hash, elems) // 解码 shortNode（2 个元素）
		return n, wrapError(err, "short")  // 返回节点并包装错误
	case 17:
		n, err := decodeFull(hash, elems) // 解码 fullNode（17 个元素）
		return n, wrapError(err, "full")  // 返回节点并包装错误
	default:
		return nil, fmt.Errorf("invalid number of list elements: %v", c) // 无效元素数量
	}
}

// Merkle Patricia Trie 结构:
//  shortNode:
//   表示扩展节点（[key, ref]）或叶子节点（[key, value]）。
//   hasTerm 检查键的终止符（通常为 0x10），区分叶子和扩展。
//  fullNode:
//   表示分支节点，17 个槽：16 个分支（0-f）+ 1 个值槽。

// 解码 shortNode，从 RLP 编码的字节中解析
func decodeShort(hash, elems []byte) (node, error) {
	kbuf, rest, err := rlp.SplitString(elems) // 分割键部分
	if err != nil {
		return nil, err
	}
	flag := nodeFlag{hash: hash} // 初始化节点标志，设置哈希
	key := compactToHex(kbuf)    // 将键从紧凑格式转换为十六进制
	if hasTerm(key) {            // 检查键是否包含终止符（叶子节点）
		// value node
		// 值节点
		val, _, err := rlp.SplitString(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid value node: %v", err)
		}
		return &shortNode{key, valueNode(val), flag}, nil // 返回 shortNode（叶子）
	}
	r, _, err := decodeRef(rest) // 解码子节点引用
	if err != nil {
		return nil, wrapError(err, "val")
	}
	return &shortNode{key, r, flag}, nil // 返回 shortNode（扩展节点）
}

// 解码 fullNode，从 RLP 编码的字节中解析
func decodeFull(hash, elems []byte) (*fullNode, error) {
	n := &fullNode{flags: nodeFlag{hash: hash}} // 初始化 fullNode，设置哈希
	for i := 0; i < 16; i++ {                   // 遍历前 16 个分支
		cld, rest, err := decodeRef(elems) // 解码子节点引用
		if err != nil {
			return n, wrapError(err, fmt.Sprintf("[%d]", i)) // 包装子节点解码错误
		}
		n.Children[i], elems = cld, rest // 设置子节点并更新剩余字节
	}
	val, _, err := rlp.SplitString(elems) // 分割第 17 个值槽
	if err != nil {
		return n, err
	}
	if len(val) > 0 { // 如果值非空
		n.Children[16] = valueNode(val) // 设置第 17 个槽为值节点
	}
	return n, nil
}

// hashLen 是 common.Hash 的长度常量，通常为 32 字节
const hashLen = len(common.Hash{})

// Merkle Patricia Trie 引用:
// 在 MPT 中，节点引用可以是：
// 嵌入节点: 直接内嵌的子节点（RLP 列表）。
// 哈希节点: 32 字节哈希，指向子树。
// 空节点: 表示无子节点（空字符串）。

// 解码 RLP 编码的节点引用，返回节点、剩余字节和错误
// 用于解码 RLP 编码的节点引用，支持嵌入节点、空节点和哈希节点。
func decodeRef(buf []byte) (node, []byte, error) {
	kind, val, rest, err := rlp.Split(buf) // 分割 RLP 数据，获取类型、值和剩余部分
	if err != nil {
		return nil, buf, err
	}
	switch {
	case kind == rlp.List: // 如果是列表类型（嵌入节点）
		// 'embedded' node reference. The encoding must be smaller
		// than a hash in order to be valid.
		// '嵌入式' 节点引用。编码大小必须小于哈希长度才有效。
		if size := len(buf) - len(rest); size > hashLen { // 检查编码大小
			err := fmt.Errorf("oversized embedded node (size is %d bytes, want size < %d)", size, hashLen)
			return nil, buf, err // 返回超大节点错误
		}
		n, err := decodeNode(nil, buf) // 解码嵌入节点
		return n, rest, err            // 返回节点和剩余字节
	case kind == rlp.String && len(val) == 0: // 如果是空字符串
		// empty node
		// 空节点
		return nil, rest, nil // 返回空节点
	case kind == rlp.String && len(val) == 32: // 如果是 32 字节字符串
		return hashNode(val), rest, nil // 返回哈希节点
	default:
		return nil, nil, fmt.Errorf("invalid RLP string size %d (want 0 or 32)", len(val))
	}
}

// wraps a decoding error with information about the path to the
// invalid child node (for debugging encoding issues).
//
// decodeError 包装了解码错误，并附带了指向无效子节点的路径信息（用于调试编码问题）。
// MPT 的编码和解码复杂，涉及嵌套节点。 decodeError 通过路径栈追踪问题节点（如无效的 fullNode 子节点或 shortNode 键）
type decodeError struct {
	what  error    // 原始错误
	stack []string // 错误发生的路径栈
}

func wrapError(err error, ctx string) error {
	if err == nil {
		return nil
	}
	// 如果错误已经是 decodeError 类型，则追加上下文到栈中
	if decErr, ok := err.(*decodeError); ok {
		decErr.stack = append(decErr.stack, ctx)
		return decErr
	}
	// 否则，创建一个新的 decodeError，包含错误和初始上下文
	return &decodeError{err, []string{ctx}}
}

func (err *decodeError) Error() string {
	// 返回格式化的错误字符串，包含原始错误和解码路径
	return fmt.Sprintf("%v (decode path: %s)", err.what, strings.Join(err.stack, "<-"))
}
