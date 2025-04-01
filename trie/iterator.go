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
	"bytes"
	"container/heap"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// NodeResolver is used for looking up trie nodes before reaching into the real
// persistent layer. This is not mandatory, rather is an optimization for cases
// where trie nodes can be recovered from some external mechanism without reading
// from disk. In those cases, this resolver allows short circuiting accesses and
// returning them from memory.
//
// 用于在访问真实的持久层之前查找trie节点。这不是必需的，而是一种优化手段，
// 适用于trie节点可以从某些外部机制恢复而无需从磁盘读取的情况。在这种情况下，
// 该解析器允许短路访问并从内存中返回它们。
// 通过自定义逻辑在访问底层持久存储（如 LevelDB）之前获取节点数据。
//
// owner common.Hash：表示节点的“拥有者”标识，通常是与该节点关联的账户地址或合约地址的哈希。
// path []byte：节点的路径，十六进制编码，表示从根节点到目标节点的键序列。
// hash common.Hash：目标节点的哈希值，用于标识具体的节点。
type NodeResolver func(owner common.Hash, path []byte, hash common.Hash) []byte

// Iterator is a key-value trie iterator that traverses a Trie.
// Iterator 是一个键值对trie迭代器，用于遍历Trie树。
type Iterator struct {
	nodeIt NodeIterator // 底层节点迭代器，用于遍历 MPT 的节点。

	Key   []byte // Current data key on which the iterator is positioned on    当前迭代器定位的数据键，当前叶子节点的键，例如账户地址的哈希或存储槽的键。
	Value []byte // Current data value on which the iterator is positioned on  当前迭代器定位的数据值，当前叶子节点的值，例如账户状态或存储内容。
	Err   error  // 迭代器的错误状态
}

// NewIterator creates a new key-value iterator from a node iterator.
// Note that the value returned by the iterator is raw. If the content is encoded
// (e.g. storage value is RLP-encoded), it's caller's duty to decode it.
//
// NewIterator 从一个节点迭代器创建一个新的键值对迭代器。
// 请注意，迭代器返回的值是原始数据。如果内容是编码的（例如存储值是RLP编码的），
// 调用者有责任对其进行解码。
func NewIterator(it NodeIterator) *Iterator {
	return &Iterator{
		nodeIt: it,
	}
}

// Next moves the iterator forward one key-value entry.
// Next 将迭代器向前移动一个键值对条目。
//
// 叶子节点：MPT 的叶子节点存储实际数据，例如状态树中的账户信息（余额、nonce 等）或存储树中的合约变量。
func (it *Iterator) Next() bool {
	// Next(true) 表示深度优先遍历（包括子节点），移动到 MPT 的下一个节点。
	// 循环持续，直到找到叶子节点或遍历结束。
	// 过滤非叶子节点：仅关注叶子节点，跳过分支节点和扩展节点，符合键值对迭代器的目标。
	for it.nodeIt.Next(true) {
		if it.nodeIt.Leaf() { // 如果当前节点是叶子节点
			it.Key = it.nodeIt.LeafKey()    // 获取叶子节点的键
			it.Value = it.nodeIt.LeafBlob() // 获取叶子节点的值
			return true                     // 返回true表示成功移动到下一个键值对
		}
	}
	it.Key = nil               // 重置键为nil
	it.Value = nil             // 重置值为nil
	it.Err = it.nodeIt.Error() // 设置错误状态
	return false               // 返回false表示遍历结束
}

// Prove generates the Merkle proof for the leaf node the iterator is currently
// positioned on.
// Prove 为迭代器当前定位的叶子节点生成Merkle证明。
func (it *Iterator) Prove() [][]byte {
	return it.nodeIt.LeafProof() // 返回叶子节点的Merkle证明
}

// NodeIterator is an iterator to traverse the trie pre-order.
// NodeIterator 是一个用于前序遍历trie树的迭代器。
//
// 叶子节点存储实际数据（如账户状态），而内部节点用于导航。
type NodeIterator interface {
	// Next moves the iterator to the next node. If the parameter is false, any child
	// nodes will be skipped.
	// Next 将迭代器移动到下一个节点。如果参数为false，则会跳过所有子节点。
	//
	// 支持两种遍历模式:
	// 深度优先（参数为 true）：访问当前节点后递归访问其子节点。
	// 仅访问当前层（参数为 false）：跳过子节点，仅移动到兄弟节点或父节点的下一个节点。
	Next(bool) bool

	// Error returns the error status of the iterator.
	// Error 返回迭代器的错误状态。
	Error() error

	// Hash returns the hash of the current node.
	// Hash 返回当前节点的哈希值。
	Hash() common.Hash

	// Parent returns the hash of the parent of the current node. The hash may be the one
	// grandparent if the immediate parent is an internal node with no hash.
	// Parent 返回当前节点的父节点的哈希值。如果直接父节点是内部节点且没有哈希值，则可能返回祖父节点的哈希值。
	// 父节点哈希的跳跃设计反映了 MPT 中“扩展节点”（Extension Node）或“分支节点”（Branch Node）的优化。
	Parent() common.Hash

	// Path returns the hex-encoded path to the current node.
	// Callers must not retain references to the return value after calling Next.
	// For leaf nodes, the last element of the path is the 'terminator symbol' 0x10.
	//
	// Path 返回当前节点的十六进制编码路径。
	// 调用者在调用Next后不得保留对返回值的引用。
	// 对于叶子节点，路径的最后一个元素是“终止符”0x10。
	//
	// 路径是从根节点到当前节点的键序列，叶子节点的路径以 0x10 终止。
	// MPT 使用路径来定位数据。例如，账户地址或存储槽的键经过哈希后形成路径，0x10 是叶子节点的标记，符合 MPT 的编码规范。
	Path() []byte

	// NodeBlob returns the rlp-encoded value of the current iterated node.
	// If the node is an embedded node in its parent, nil is returned then.
	// NodeBlob 返回当前迭代节点的RLP编码值。
	// 如果节点是嵌入其父节点的节点，则返回nil。
	NodeBlob() []byte

	// Leaf returns true if the current node is a leaf node.
	// Leaf 如果当前节点是叶子节点，则返回true。
	Leaf() bool

	// LeafKey returns the key of the leaf. The method panics if the iterator is not
	// positioned at a leaf. Callers must not retain references to the value after
	// calling Next.
	//
	// LeafKey 返回叶子节点的键。如果迭代器未定位在叶子节点上，该方法会引发panic。
	// 调用者在调用Next后不得保留对返回值的引用。
	LeafKey() []byte

	// LeafBlob returns the content of the leaf. The method panics if the iterator
	// is not positioned at a leaf. Callers must not retain references to the value
	// after calling Next.
	//
	// LeafBlob 返回叶子节点的内容。如果迭代器未定位在叶子节点上，该方法会引发panic。
	// 调用者在调用Next后不得保留对返回值的引用。
	LeafBlob() []byte

	// LeafProof returns the Merkle proof of the leaf. The method panics if the
	// iterator is not positioned at a leaf. Callers must not retain references
	// to the value after calling Next.
	//
	// LeafProof 返回叶子节点的Merkle证明。如果迭代器未定位在叶子节点上，该方法会引发panic。
	// 调用者在调用Next后不得保留对返回值的引用。
	LeafProof() [][]byte

	// AddResolver sets a node resolver to use for looking up trie nodes before
	// reaching into the real persistent layer.
	//
	// This is not required for normal operation, rather is an optimization for
	// cases where trie nodes can be recovered from some external mechanism without
	// reading from disk. In those cases, this resolver allows short circuiting
	// accesses and returning them from memory.
	//
	// Before adding a similar mechanism to any other place in Geth, consider
	// making trie.Database an interface and wrapping at that level. It's a huge
	// refactor, but it could be worth it if another occurrence arises.
	//
	// AddResolver 设置一个节点解析器，用于在访问真实持久层之前查找trie节点。
	//
	// 这对于正常操作不是必需的，而是一种优化手段，适用于trie节点可以从外部机制恢复而无需从磁盘读取的情况。
	// 在这种情况下，该解析器允许短路访问并从内存中返回它们。
	//
	// 在Geth的其他地方添加类似机制之前，请考虑将trie.Database改为接口并在该层进行封装。
	// 这是一个巨大的重构，但如果再次出现类似需求，可能值得这样做。
	AddResolver(NodeResolver)
}

// MPT 节点类型：
// 叶子节点（Leaf Node）：存储键值对。
// 扩展节点（Extension Node）：包含共享路径前缀，指向下一个节点。
// 分支节点（Branch Node）：包含最多 16 个子节点（对应十六进制字符 0-f）。

// 状态保存：通过记录 hash、node 和 parent，结构体完整保存了当前节点及其在树中的位置。
// 遍历控制：index 用于深度优先遍历（DFS）时跟踪子节点的处理顺序。
// 路径跟踪：pathlen 帮助维护从根到当前节点的路径长度，便于生成路径或回溯。

// 哈希与嵌入：独立节点的哈希存储在数据库中，嵌入式节点则直接嵌在父节点中，减少存储开销。

// nodeIteratorState represents the iteration state at one particular node of the
// trie, which can be resumed at a later invocation.
//
// nodeIteratorState 表示在trie树中某个特定节点的迭代状态，
// 该状态可以在后续调用中恢复。
// 保存遍历过程中某个节点的上下文信息，以便在中断后恢复遍历。
type nodeIteratorState struct {
	hash    common.Hash // Hash of the node being iterated (nil if not standalone)   正在迭代的节点的哈希值（如果不是独立节点，则为nil）
	node    node        // Trie node being iterated   正在迭代的trie节点
	parent  common.Hash // Hash of the first full ancestor node (nil if current is the root)   第一个完整祖先节点的哈希值（如果当前节点是根节点，则为nil）
	index   int         // Child to be processed next 下一个要处理的子节点索引
	pathlen int         // Length of the path to the parent node 到父节点的路径长度
}

// nodeIterator 是用于遍历Trie树的迭代器实现。
// 通过栈结构和状态管理支持前序遍历（pre-order traversal），并结合优化机制（如 NodeResolver）提升性能
// 遍历管理：stack 实现前序遍历的深度优先搜索（DFS），通过入栈和出栈跟踪节点层次。
// 状态机：stack 和 path 共同构成一个状态机，支持暂停和恢复。
type nodeIterator struct {
	trie  *Trie                // Trie being iterated 正在迭代的Trie树，指向被遍历的 MPT 实例，提供根节点和访问接口。
	stack []*nodeIteratorState // Hierarchy of trie nodes persisting the iteration state 持久化迭代状态的Trie节点层次栈，一个栈，存储遍历过程中的节点状态（nodeIteratorState），用于记录层次关系和恢复。
	path  []byte               // Path to the current node 到当前节点的路径，从根节点到当前节点的路径，十六进制编码。
	err   error                // Failure set in case of an internal error in the iterator 迭代器内部错误时设置的失败状态，记录遍历中的错误，例如节点加载失败。

	resolver NodeResolver         // optional node resolver for avoiding disk hits 可选的节点解析器，用于避免磁盘访问，用于从内存或其他外部机制获取节点数据。
	pool     []*nodeIteratorState // local pool for iterator states 迭代器状态的本地池，本地状态池，用于复用 nodeIteratorState 实例，减少内存分配。
}

// errIteratorEnd is stored in nodeIterator.err when iteration is done.
// errIteratorEnd 表示迭代结束的错误，表示迭代器已到达末尾。。
var errIteratorEnd = errors.New("end of iteration")

// seekError is stored in nodeIterator.err if the initial seek has failed.
// seekError 在初始查找失败时存储在 nodeIterator.err 中。
type seekError struct {
	key []byte
	err error
}

func (e seekError) Error() string {
	return "seek error: " + e.err.Error()
}

func newNodeIterator(trie *Trie, start []byte) NodeIterator {
	if trie.Hash() == types.EmptyRootHash {
		return &nodeIterator{
			trie: trie,
			err:  errIteratorEnd,
		}
	}
	it := &nodeIterator{trie: trie}
	it.err = it.seek(start)
	return it
}

// putInPool 将一个 nodeIteratorState 对象放入对象池中，以便复用。
func (it *nodeIterator) putInPool(item *nodeIteratorState) {
	if len(it.pool) < 40 { // 如果对象池未满（上限为40）
		item.node = nil                 // 清空节点引用以避免内存泄漏
		it.pool = append(it.pool, item) // 将对象加入池中
	}
}

// getFromPool 从对象池中获取一个 nodeIteratorState 对象，如果池为空则新建。
func (it *nodeIterator) getFromPool() *nodeIteratorState {
	idx := len(it.pool) - 1 // 获取池中最后一个元素的索引
	if idx < 0 {            // 如果池为空
		return new(nodeIteratorState) // 创建并返回一个新的对象
	}
	el := it.pool[idx]      // 获取最后一个元素
	it.pool[idx] = nil      // 清空该位置的引用
	it.pool = it.pool[:idx] // 缩小池的大小
	return el               // 返回获取的对象
}

// AddResolver 设置迭代器的节点解析器。
func (it *nodeIterator) AddResolver(resolver NodeResolver) {
	it.resolver = resolver
}

// Hash 返回当前节点的哈希值。
func (it *nodeIterator) Hash() common.Hash {
	if len(it.stack) == 0 { // 如果栈为空
		return common.Hash{} // 返回零哈希
	}
	return it.stack[len(it.stack)-1].hash // 返回栈顶节点的哈希
}

// Parent 返回当前节点的父节点哈希。
func (it *nodeIterator) Parent() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].parent // 返回栈顶节点的父哈希
}

// Leaf 检查当前节点是否为叶子节点。
func (it *nodeIterator) Leaf() bool {
	return hasTerm(it.path) // 检查路径是否包含终止符
}

// LeafKey 返回当前叶子节点的键。
func (it *nodeIterator) LeafKey() []byte {
	if len(it.stack) > 0 { // 如果栈不为空
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok { // 如果栈顶是值节点
			return hexToKeybytes(it.path) // 将路径转换为键字节
		}
	}
	panic("not at leaf") // 不在叶子节点，抛出异常
}

// LeafBlob 返回当前叶子节点的值。
func (it *nodeIterator) LeafBlob() []byte {
	if len(it.stack) > 0 { // 如果栈不为空
		if node, ok := it.stack[len(it.stack)-1].node.(valueNode); ok { // 如果栈顶是值节点
			return node // 返回值节点的字节数据
		}
	}
	panic("not at leaf") // 不在叶子节点，抛出异常
}

// LeafProof 返回当前叶子节点的 Merkle 证明。
func (it *nodeIterator) LeafProof() [][]byte {
	if len(it.stack) > 0 { // 如果栈不为空
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok { // 如果栈顶是值节点
			hasher := newHasher(false)                 // 创建哈希器
			defer returnHasherToPool(hasher)           // 延迟归还哈希器到池
			proofs := make([][]byte, 0, len(it.stack)) // 初始化证明切片

			for i, item := range it.stack[:len(it.stack)-1] { // 遍历除叶子外的节点
				// Gather nodes that end up as hash nodes (or the root)
				node, hashed := hasher.proofHash(item.node)   //  计算节点哈希
				if _, ok := hashed.(hashNode); ok || i == 0 { // 如果是哈希节点或根节点
					proofs = append(proofs, nodeToBytes(node)) // 添加到证明中
				}
			}
			return proofs // 返回证明
		}
	}
	panic("not at leaf") // 不在叶子节点，抛出异常
}

// Path 返回当前节点的路径。
func (it *nodeIterator) Path() []byte {
	return it.path
}

// NodeBlob 返回当前节点的原始数据。
func (it *nodeIterator) NodeBlob() []byte {
	if it.Hash() == (common.Hash{}) { // 如果哈希为空
		return nil // skip the non-standalone node 返回 nil，跳过非独立节点
	}
	blob, err := it.resolveBlob(it.Hash().Bytes(), it.Path()) // 解析节点数据
	if err != nil {
		it.err = err
		return nil
	}
	return blob // 返回原始数据
}

// Error 返回迭代器的错误状态。
func (it *nodeIterator) Error() error {
	if it.err == errIteratorEnd { // 迭代结束
		return nil
	}
	if seek, ok := it.err.(seekError); ok { //  seek 错误
		return seek.err
	}
	return it.err // 返回原始错误
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure. If `descend` is false,
// skips iterating over any subnodes of the current node.
//
// Next 将迭代器移动到下一个节点，并返回是否还有更多节点。
// 如果发生内部错误，此方法返回 false 并将 Error 字段设置为遇到的故障。
// 如果 `descend` 为 false，则跳过当前节点的任何子节点的迭代。
func (it *nodeIterator) Next(descend bool) bool {
	if it.err == errIteratorEnd { // 如果已到达迭代结束
		return false
	}
	if seek, ok := it.err.(seekError); ok { // 如果错误是 seekError
		if it.err = it.seek(seek.key); it.err != nil { // 重新执行 seek 操作
			return false
		}
	}
	// Otherwise step forward with the iterator and report any errors.
	// 否则，使用迭代器向前移动并报告任何错误。
	state, parentIndex, path, err := it.peek(descend) // 预览下一个状态
	it.err = err                                      // 设置错误状态
	if it.err != nil {                                // 如果有错误
		return false
	}
	it.push(state, parentIndex, path) // 压入新状态
	return true
}

// seek 将迭代器定位到接近指定前缀的位置。
// 用于将迭代器定位到接近指定前缀（prefix）的位置。
// 它通过循环调用 peekSeek 和 push 在 MPT（Merkle Patricia Trie）中查找目标键的最近节点，支持从特定键开始遍历。
func (it *nodeIterator) seek(prefix []byte) error {
	// The path we're looking for is the hex encoded key without terminator.
	// 我们寻找的路径是十六进制编码的键，不含终止符。
	key := keybytesToHex(prefix) // 将前缀转换为十六进制
	key = key[:len(key)-1]       // 移除终止符

	// Move forward until we're just before the closest match to key.
	// 前进直到刚好在最接近键的位置之前。
	for {
		state, parentIndex, path, err := it.peekSeek(key) // 预览下一个状态
		if err == errIteratorEnd {                        // 如果遍历结束
			return errIteratorEnd // 返回结束错误
		} else if err != nil { // 如果发生其他错误
			return seekError{prefix, err}
		} else if reachedPath(path, key) { // 如果到达或超过目标键
			return nil
		}
		it.push(state, parentIndex, path) // 压入状态，继续遍历
	}
}

// init initializes the iterator.
// init 初始化迭代器。
// 用于创建并设置迭代器的起始状态。它从 MPT（Merkle Patricia Trie）的根节点开始，为遍历准备初始的 nodeIteratorState。
// MPT 的根哈希是状态树或存储树的入口，存储在区块头中。
// 遍历从根节点开始，可能是实际节点或哈希引用（hashNode）。
func (it *nodeIterator) init() (*nodeIteratorState, error) {
	root := it.trie.Hash()                                     // 获取trie的根哈希
	state := &nodeIteratorState{node: it.trie.root, index: -1} // 创建初始状态，索引为-1
	if root != types.EmptyRootHash {                           // 如果根不是空根哈希
		state.hash = root // 设置状态的哈希值
	}
	return state, state.resolve(it, nil) // 返回状态并解析根节点
}

// peek creates the next state of the iterator.
// peek 创建迭代器的下一个状态。
// 用于预览（peek）迭代器的下一个状态，而不实际推进迭代器。
// 它支持 MPT（Merkle Patricia Trie）的前序遍历，根据 descend 参数决定是否深入子节点。
//
// 返回迭代器的下一个状态，包括节点状态、父索引和路径。它用于初始化或继续遍历 MPT，支持深度优先搜索（DFS），并在遍历结束时返回 errIteratorEnd。
func (it *nodeIterator) peek(descend bool) (*nodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	// 如果刚开始，初始化迭代器。
	if len(it.stack) == 0 {
		state, err := it.init()     // 初始化并返回根节点状态
		return state, nil, nil, err // 返回状态，无父索引和路径
	}
	if !descend { // 如果不向下遍历
		// If we're skipping children, pop the current node first
		// 如果跳过子节点，先弹出当前节点
		it.pop()
	}
	// Continue iteration to the next child
	// 继续迭代到下一个子节点
	for len(it.stack) > 0 { // 当栈不为空时
		parent := it.stack[len(it.stack)-1] // 获取栈顶父节点
		ancestor := parent.hash             // 获取祖先哈希
		if (ancestor == common.Hash{}) {    // 如果哈希为空
			ancestor = parent.parent // 使用父节点的父哈希
		}
		state, path, ok := it.nextChild(parent, ancestor) // 获取下一个子节点
		if ok {                                           // 如果找到子节点
			if err := state.resolve(it, path); err != nil { // 解析子节点
				return parent, &parent.index, path, err // 解析失败，返回父节点状态
			}
			return state, &parent.index, path, nil // 成功，返回子节点状态
		}
		// No more child nodes, move back up.
		// 没有更多子节点，回溯
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd // 遍历结束，返回错误
}

// peekSeek is like peek, but it also tries to skip resolving hashes by skipping
// over the siblings that do not lead towards the desired seek position.
// peekSeek 类似于 peek，但它还会尝试通过跳过不指向所需查找位置的兄弟节点来避免解析哈希。
func (it *nodeIterator) peekSeek(seekKey []byte) (*nodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	// 如果刚开始，初始化迭代器
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !bytes.HasPrefix(seekKey, it.path) {
		// If we're skipping children, pop the current node first
		// 如果查找键不以当前路径为前缀，弹出当前节点
		it.pop()
	}
	// Continue iteration to the next child
	// 继续迭代到下一个子节点
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		// 获取下一个符合查找键的子节点状态和路径
		state, path, ok := it.nextChildAt(parent, ancestor, seekKey)
		if ok {
			// 解析子节点状态，如果出错则返回父节点信息
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		// 没有更多子节点，回退到上一级
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

// resolveHash 根据给定的哈希值和路径解析并返回对应的trie节点。
func (it *nodeIterator) resolveHash(hash hashNode, path []byte) (node, error) {
	if it.resolver != nil { // 如果存在节点解析器
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 {
			if resolved, err := decodeNode(hash, blob); err == nil { // 解码节点数据
				return resolved, nil // 返回解析后的节点
			}
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	//
	// 从底层节点读取器检索指定的节点。
	// 这里未使用 it.trie.resolveAndTrack，因为该函数会跟踪加载的节点数据，
	// 而在此处不需要跟踪，因为所有加载的节点不会与trie关联，
	// 跟踪节点可能会导致内存溢出问题。
	blob, err := it.trie.reader.node(path, common.BytesToHash(hash)) // 从底层读取节点数据
	if err != nil {
		return nil, err
	}
	// The raw-blob format nodes are loaded either from the
	// clean cache or the database, they are all in their own
	// copy and safe to use unsafe decoder.
	// 从干净缓存或数据库加载的原始数据格式节点都是独立的副本，
	// 使用不安全的解码器是安全的。
	return mustDecodeNodeUnsafe(hash, blob), nil // 使用不安全解码器解码并返回节点
}

// resolveBlob 根据给定的哈希值和路径解析并返回节点的原始数据（blob）。
func (it *nodeIterator) resolveBlob(hash hashNode, path []byte) ([]byte, error) {
	if it.resolver != nil { // 如果存在节点解析器
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 { // 使用解析器尝试获取节点数据
			return blob, nil // 返回获取到的原始数据
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	//
	// 从底层节点读取器检索指定的节点。
	// 这里未使用 it.trie.resolveAndTrack，因为该函数会跟踪加载的节点数据，
	// 而在此处不需要跟踪，因为所有加载的节点不会与trie关联，
	// 跟踪节点可能会导致内存溢出问题。
	return it.trie.reader.node(path, common.BytesToHash(hash)) // 从底层读取节点数据并返回
}

// resolve 解析nodeIteratorState中的节点，如果节点是hashNode类型，则通过迭代器解析其实际内容。
// resolve 的核心目标是动态解析 MPT 中的节点。
// 当 nodeIteratorState 中的 node 是一个 hashNode（仅包含哈希引用）时，
// 通过调用 nodeIterator 的解析机制加载实际节点内容，并更新状态。
// 这种设计支持 MPT 的高效遍历，避免在初始化时加载所有节点数据。
func (st *nodeIteratorState) resolve(it *nodeIterator, path []byte) error {
	if hash, ok := st.node.(hashNode); ok { // 如果节点是hashNode类型
		resolved, err := it.resolveHash(hash, path) // 解析哈希值为实际节点
		if err != nil {
			return err
		}
		st.node = resolved                 // 更新节点为解析后的内容
		st.hash = common.BytesToHash(hash) // 设置哈希值为原始哈希
	}
	return nil // 返回nil表示成功或无需解析
}

// findChild 在完整节点（fullNode）中查找下一个非空子节点，返回子节点、状态、路径和索引。
//
// 从 fullNode 的子节点数组中找到下一个有效子节点，并为遍历准备状态和路径。它是 nodeIterator 前序遍历的关键步骤，用于向下扩展到子节点。
// MPT 的 fullNode 有 17 个槽位（0-15 为子节点，16 为值槽），findChild 遍历这些槽位。
// 前序遍历需要从分支节点扩展到子节点，路径逐步拼接。
func (it *nodeIterator) findChild(n *fullNode, index int, ancestor common.Hash) (node, *nodeIteratorState, []byte, int) {
	var (
		path      = it.path          // 当前路径
		child     node               // 子节点
		state     *nodeIteratorState // 子节点的状态
		childPath []byte             // 子节点的路径
	)
	for ; index < len(n.Children); index = nextChildIndex(index) { // 遍历子节点
		if n.Children[index] != nil { // 如果子节点非空
			child = n.Children[index] // 获取子节点
			hash, _ := child.cache()  // 获取子节点的哈希值

			state = it.getFromPool()              // 从对象池获取状态对象
			state.hash = common.BytesToHash(hash) // 设置状态的哈希值
			state.node = child                    // 设置状态的节点
			state.parent = ancestor               // 设置父节点哈希
			state.index = -1                      // 初始化子节点索引
			state.pathlen = len(path)             // 设置路径长度

			childPath = append(childPath, path...)     // 构建子节点路径：父路径
			childPath = append(childPath, byte(index)) // 追加子节点索引
			return child, state, childPath, index      // 返回子节点、状态、路径和索引
		}
	}
	return nil, nil, nil, 0 // 未找到子节点，返回空值
}

// nextChild 返回父节点的下一个子节点状态和路径，按前序遍历顺序移动。
// 按照前序遍历顺序，从父节点移动到下一个子节点。它返回子节点的状态和路径，或者在无子节点时返回父节点状态，用于驱动 MPT 的深度优先遍历。
// MPT 的遍历需要按顺序访问子节点，fullNode 有多个子节点，shortNode 只有一个。
// 前序遍历在以太坊中用于状态树或存储树的完整访问。
func (it *nodeIterator) nextChild(parent *nodeIteratorState, ancestor common.Hash) (*nodeIteratorState, []byte, bool) {
	switch node := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child.
		// 完整节点，移动到第一个非空子节点
		if child, state, path, index := it.findChild(node, nextChildIndex(parent.index), ancestor); child != nil {
			parent.index = prevChildIndex(index) // 更新父节点索引为前一个
			return state, path, true             // 返回子节点状态、路径和成功标志
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		// 短节点，返回其唯一的子节点
		if parent.index < 0 { // 如果尚未遍历
			hash, _ := node.Val.cache()           // 获取子节点哈希
			state := it.getFromPool()             // 从对象池获取状态
			state.hash = common.BytesToHash(hash) // 设置哈希
			state.node = node.Val                 // 设置节点
			state.parent = ancestor               // 设置父节点哈希
			state.index = -1                      // 初始化子节点索引
			state.pathlen = len(it.path)          // 设置路径长度
			path := append(it.path, node.Key...)  // 拼接子节点路径
			return state, path, true              // 返回子节点状态、路径和成功标志
		}
	}
	return parent, it.path, false // 未找到子节点，返回父节点状态
}

// nextChildAt is similar to nextChild, except that it targets a child as close to the
// target key as possible, thus skipping siblings.
// nextChildAt 类似于 nextChild，但它会尽可能定位到接近目标键的子节点，跳过无关的兄弟节点。
//
// 根据目标键 key，在父节点的子节点中找到最接近的非空子节点。它处理 fullNode（分支节点）和 shortNode（扩展节点）两种情况，优先返回接近或等于目标的子节点状态和路径，用于支持 MPT 的定向遍历。
func (it *nodeIterator) nextChildAt(parent *nodeIteratorState, ancestor common.Hash, key []byte) (*nodeIteratorState, []byte, bool) {
	switch n := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child before the desired key position
		// 完整节点，移动到目标键位置前的第一个非空子节点
		child, state, path, index := it.findChild(n, nextChildIndex(parent.index), ancestor)
		if child == nil {
			// No more children in this fullnode
			// 该完整节点中没有更多子节点
			return parent, it.path, false
		}
		// If the child we found is already past the seek position, just return it.
		// 如果找到的子节点已经超过目标位置，直接返回
		if reachedPath(path, key) {
			parent.index = prevChildIndex(index)
			return state, path, true
		}
		// The child is before the seek position. Try advancing
		// 子节点在目标位置之前，继续尝试前进
		for {
			nextChild, nextState, nextPath, nextIndex := it.findChild(n, nextChildIndex(index), ancestor)
			// If we run out of children, or skipped past the target, return the
			// previous one
			// 如果没有更多子节点或已超过目标，返回前一个子节点
			if nextChild == nil || reachedPath(nextPath, key) {
				parent.index = prevChildIndex(index)
				return state, path, true
			}
			// We found a better child closer to the target
			// 找到更接近目标的子节点，更新状态
			state, path, index = nextState, nextPath, nextIndex
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		// 短节点，返回其唯一的子节点
		if parent.index < 0 {
			hash, _ := n.Val.cache()
			state := it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = n.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, n.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false // 未找到合适子节点，返回父节点状态
}

// push 将一个 nodeIteratorState 状态压入迭代器的栈中，更新路径并调整父节点索引。
// push：将新的节点状态压入栈，更新路径，并调整父节点的子节点索引，用于向下遍历 MPT。
func (it *nodeIterator) push(state *nodeIteratorState, parentIndex *int, path []byte) {
	it.path = path                     // 更新当前路径
	it.stack = append(it.stack, state) // 将状态压入栈中
	if parentIndex != nil {            // 如果提供了父节点索引
		*parentIndex = nextChildIndex(*parentIndex) // 更新父节点的下一个子节点索引
	}
}

// pop 从迭代器的栈中弹出一个状态，恢复路径并将弹出的状态放入对象池。
// pop：从栈中移除当前节点状态，恢复路径到父节点，并复用状态对象，用于回溯。
func (it *nodeIterator) pop() {
	last := it.stack[len(it.stack)-1]     // 获取栈顶状态
	it.path = it.path[:last.pathlen]      // 恢复路径到父节点长度
	it.stack[len(it.stack)-1] = nil       // 清空栈顶引用
	it.stack = it.stack[:len(it.stack)-1] // 缩小栈大小

	it.putInPool(last) // last is now unused 将不再使用的状态放入对象池
}

// reachedPath normalizes a path by truncating a terminator if present, and
// returns true if it is greater than or equal to the target. Using this,
// the path of a value node embedded a full node will compare less than the
// full node's children.
//
// reachedPath 通过截断路径中的终止符（如果存在）来标准化路径，
// 并返回它是否大于或等于目标路径。通过这种方式，
// 嵌入在完整节点中的值节点的路径将比完整节点的子节点路径小。
func reachedPath(path, target []byte) bool {
	if hasTerm(path) { // 如果路径包含终止符
		path = path[:len(path)-1] // 截断终止符
	}
	return bytes.Compare(path, target) >= 0 // 比较路径是否大于或等于目标
}

// A value embedded in a full node occupies the last slot (16) of the array of
// children. In order to produce a pre-order traversal when iterating children,
// we jump to this last slot first, then go back iterate the child nodes (and
// skip the last slot at the end):
//
// 在完整节点中嵌入的值占用子节点数组的最后一个槽（16）。
// 为了在迭代子节点时产生前序遍历，我们首先跳转到这个最后一个槽，
// 然后返回去迭代子节点（并在最后跳过这个槽）：

// prevChildIndex returns the index of a child in a full node which precedes
// the given index when performing a pre-order traversal.
//
// prevChildIndex 返回在执行前序遍历时，完整节点中某个子节点的前一个索引。
//
// 反向（prevChildIndex）：17 -> 15 -> ... -> 1 -> 0 -> 16 -> -1
func prevChildIndex(index int) int {
	switch index {
	// 表示刚开始遍历子节点（索引 0），前一个是值槽（返回 16）。
	// 对应 nextChildIndex 中从 16 跳转到 0 的反向操作。
	case 0: // We jumped back to iterate the children, from the value slot   我们从值槽跳回以迭代子节点
		return 16
	// 表示当前在值槽，前一个是占位索引（返回 -1）。
	// 对应遍历的起点（nextChildIndex 从 -1 到 16）。
	case 16: // We jumped to the embedded value slot at the end, from the placeholder index 我们从占位索引跳转到嵌入的值槽
		return -1
	// 表示已结束遍历（超出范围），前一个是最后一个子节点（返回 15）。
	// 对应 nextChildIndex 中从 15 到 17 的反向。
	case 17: // We skipped the value slot after iterating all the children 我们迭代完所有子节点后跳过了值槽
		return 15
	// 正常情况下，子节点按顺序递减（index - 1）。
	// 适用于索引 1-15 的连续回溯。
	default: // We are iterating the children in sequence 我们按顺序迭代子节点
		return index - 1
	}
}

// MPT 的 fullNode（分支节点）最多有 17 个元素：16 个子节点（索引 0-15）和 1 个值槽（索引 16）。
// 前序遍历要求先访问根节点（此处为分支节点的值槽），再依次访问子节点。

// nextChildIndex returns the index of a child in a full node which follows
// the given index when performing a pre-order traversal.
// nextChildIndex 返回在执行前序遍历时，完整节点中某个子节点的下一个索引。
//
// 根据 nextChildIndex，前序遍历的顺序为：
//
// 从 -1 开始 -> 跳转到 16（访问值槽）。
// 从 16 -> 跳转到 0（开始子节点）。
// 从 0 -> 1 -> 2 -> ... -> 15（依次访问子节点）。
// 从 15 -> 17（结束分支节点）。
// 这确保先访问值槽（如果存在），再遍历所有子节点。
// 正向（nextChildIndex）：-1 -> 16 -> 0 -> 1 -> ... -> 15 -> 17
func nextChildIndex(index int) int {
	switch index {
	// 表示起始状态（占位索引），跳转到值槽（索引 16），这是遍历的起点，通常从分支节点的值开始。
	case -1: // Jump from the placeholder index to the embedded value slot  从占位索引跳转到嵌入的值槽
		return 16
	// 表示已遍历完所有子节点（0-15），跳过值槽（返回 17）。
	// 17 表示分支节点的结束，超出正常范围，用于退出。
	case 15: // Skip the value slot after iterating the children  在迭代完子节点后跳过值槽
		return 17
	// 表示刚访问完值槽，跳转回子节点起点（索引 0）。
	// 开始遍历子节点。
	case 16: // From the embedded value slot, jump back to iterate the children  从嵌入的值槽跳回以迭代子节点
		return 0
	// 正常情况下，子节点按顺序递增（index + 1）。
	// 适用于索引 0-14 的连续遍历。
	default: // Iterate children in sequence  按顺序迭代子节点
		return index + 1
	}
}

// compareNodes 比较两个节点迭代器，返回它们的相对顺序。
func compareNodes(a, b NodeIterator) int {
	if cmp := bytes.Compare(a.Path(), b.Path()); cmp != 0 { // 首先比较路径
		return cmp // 如果不同，返回比较结果
	}
	if a.Leaf() && !b.Leaf() { // 如果 a 是叶子而 b 不是
		return -1 // a 排在 b 前
	} else if b.Leaf() && !a.Leaf() { // 如果 b 是叶子而 a 不是
		return 1 // b 排在 a 前
	}
	if cmp := bytes.Compare(a.Hash().Bytes(), b.Hash().Bytes()); cmp != 0 { // 比较哈希
		return cmp // 如果不同，返回比较结果
	}
	if a.Leaf() && b.Leaf() { // 如果两者都是叶子
		return bytes.Compare(a.LeafBlob(), b.LeafBlob()) // 比较叶子值
	}
	return 0 // 相等，返回 0
}

// differenceIterator 定义了一个迭代器，用于遍历 b 中不在 a 中的元素。
type differenceIterator struct {
	a, b  NodeIterator // Nodes returned are those in b - a.  a 和 b 是输入迭代器，返回 b - a 的差集
	eof   bool         // Indicates a has run out of elements 表示 a 是否已遍历完
	count int          // Number of nodes scanned on either trie 记录扫描的节点数
}

// NewDifferenceIterator constructs a NodeIterator that iterates over elements in b that
// are not in a. Returns the iterator, and a pointer to an integer recording the number
// of nodes seen.
//
// NewDifferenceIterator 创建一个遍历 b 中不在 a 中的元素的迭代器。
func NewDifferenceIterator(a, b NodeIterator) (NodeIterator, *int) {
	a.Next(true) // 初始化 a，移动到第一个节点
	it := &differenceIterator{ // 创建差集迭代器
		a: a,
		b: b,
	}
	return it, &it.count // 返回迭代器和计数指针
}

// Hash 返回当前节点的哈希值。
func (it *differenceIterator) Hash() common.Hash {
	return it.b.Hash() // 委托给 b 的 Hash 方法
}

// Parent 返回当前节点的父哈希。
func (it *differenceIterator) Parent() common.Hash {
	return it.b.Parent() // 委托给 b 的 Parent 方法
}

// Leaf 检查当前节点是否为叶子节点。
func (it *differenceIterator) Leaf() bool {
	return it.b.Leaf() // 委托给 b 的 Leaf 方法
}

// LeafKey 返回当前叶子节点的键。
func (it *differenceIterator) LeafKey() []byte {
	return it.b.LeafKey() // 委托给 b 的 LeafKey 方法
}

// LeafBlob 返回当前叶子节点的值。
func (it *differenceIterator) LeafBlob() []byte {
	return it.b.LeafBlob() // 委托给 b 的 LeafBlob 方法
}

// LeafProof 返回当前叶子节点的 Merkle 证明。
func (it *differenceIterator) LeafProof() [][]byte {
	return it.b.LeafProof() // 委托给 b 的 LeafProof 方法
}

// Path 返回当前节点的路径。
func (it *differenceIterator) Path() []byte {
	return it.b.Path() // 委托给 b 的 Path 方法
}

// NodeBlob 返回当前节点的原始数据。
func (it *differenceIterator) NodeBlob() []byte {
	return it.b.NodeBlob() // 委托给 b 的 NodeBlob 方法
}

// AddResolver 设置节点解析器（未实现）。
func (it *differenceIterator) AddResolver(resolver NodeResolver) {
	panic("not implemented")
}

// Next 将迭代器推进到下一个节点，返回是否还有更多节点。
func (it *differenceIterator) Next(bool) bool {
	// Invariants:
	// - We always advance at least one element in b.
	// - At the start of this function, a's path is lexically greater than b's.
	// 不变量：
	// - 每次调用至少推进 b 中的一个元素。
	// - 函数开始时，a 的路径在字典序上大于 b 的路径。
	if !it.b.Next(true) { // 如果 b 无法推进
		return false
	}
	it.count++ // 增加扫描计数

	if it.eof { // 如果 a 已遍历完
		// a has reached eof, so we just return all elements from b
		// a 已到达末尾，直接返回 b 的所有元素
		return true
	}

	for { // 循环比较 a 和 b
		switch compareNodes(it.a, it.b) {
		case -1:
			// b jumped past a; advance a
			//  b 跳过了 a；推进 a
			if !it.a.Next(true) {
				it.eof = true // a 结束，标记 eof
				return true   // 返回 true，继续返回 b
			}
			it.count++ // 增加计数
		case 1:
			// b is before a
			// b 在 a 之前
			return true // 返回 true，表示找到差集元素
		case 0:
			// a and b are identical; skip this whole subtree if the nodes have hashes
			// a 和 b 相同，跳过子树（若有哈希）
			hasHash := it.a.Hash() == common.Hash{}
			if !it.b.Next(hasHash) {
				return false
			}
			it.count++
			if !it.a.Next(hasHash) {
				it.eof = true
				return true
			}
			it.count++
		}
	}
}

// Error 返回迭代器的错误状态。
func (it *differenceIterator) Error() error {
	if err := it.a.Error(); err != nil {
		return err
	}
	return it.b.Error()
}

// nodeIteratorHeap 是 NodeIterator 的堆结构，用于按顺序管理多个迭代器。
// 提供一个小顶堆（min-heap），以便高效地从多个 NodeIterator 中提取按顺序排列的最小元素。
// 它支持多路合并（multi-way merge）或优先级队列操作，常用于 MPT 的同步或差分计算。
type nodeIteratorHeap []NodeIterator

func (h nodeIteratorHeap) Len() int           { return len(h) }
func (h nodeIteratorHeap) Less(i, j int) bool { return compareNodes(h[i], h[j]) < 0 }
func (h nodeIteratorHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

// Push 将一个新的迭代器加入堆中。
func (h *nodeIteratorHeap) Push(x interface{}) { *h = append(*h, x.(NodeIterator)) }

// Pop 从堆中移除并返回最后一个迭代器。
func (h *nodeIteratorHeap) Pop() interface{} {
	n := len(*h)
	x := (*h)[n-1]
	*h = (*h)[0 : n-1]
	return x
}

// unionIterator 结构体表示一个联合迭代器，用于遍历多个 NodeIterator 的并集元素。
type unionIterator struct {
	items *nodeIteratorHeap // Nodes returned are the union of the ones in these iterators 包含所有迭代器返回的节点的堆
	count int               // Number of nodes scanned across all tries    跨所有 trie 扫描的节点总数
}

// NewUnionIterator constructs a NodeIterator that iterates over elements in the union
// of the provided NodeIterators. Returns the iterator, and a pointer to an integer
// recording the number of nodes visited.
//
// NewUnionIterator 构造一个 NodeIterator，遍历提供的 NodeIterators 的并集中的元素。
// 返回该迭代器和一个指向整数的指针，该整数记录访问的节点数。
func NewUnionIterator(iters []NodeIterator) (NodeIterator, *int) {
	// 创建一个 nodeIteratorHeap，大小与输入迭代器数组一致
	h := make(nodeIteratorHeap, len(iters))
	// 将输入迭代器复制到堆中
	copy(h, iters)
	// 初始化堆，确保最小堆性质
	heap.Init(&h)

	ui := &unionIterator{items: &h}
	return ui, &ui.count
}

// Hash 返回堆顶节点的哈希值
func (it *unionIterator) Hash() common.Hash {
	return (*it.items)[0].Hash()
}

func (it *unionIterator) Parent() common.Hash {
	return (*it.items)[0].Parent()
}

func (it *unionIterator) Leaf() bool {
	return (*it.items)[0].Leaf()
}

func (it *unionIterator) LeafKey() []byte {
	return (*it.items)[0].LeafKey()
}

func (it *unionIterator) LeafBlob() []byte {
	return (*it.items)[0].LeafBlob()
}

func (it *unionIterator) LeafProof() [][]byte {
	return (*it.items)[0].LeafProof()
}

func (it *unionIterator) Path() []byte {
	return (*it.items)[0].Path()
}

func (it *unionIterator) NodeBlob() []byte {
	return (*it.items)[0].NodeBlob()
}

func (it *unionIterator) AddResolver(resolver NodeResolver) {
	panic("not implemented")
}

// Next returns the next node in the union of tries being iterated over.
//
// It does this by maintaining a heap of iterators, sorted by the iteration
// order of their next elements, with one entry for each source trie. Each
// time Next() is called, it takes the least element from the heap to return,
// advancing any other iterators that also point to that same element. These
// iterators are called with descend=false, since we know that any nodes under
// these nodes will also be duplicates, found in the currently selected iterator.
// Whenever an iterator is advanced, it is pushed back into the heap if it still
// has elements remaining.
//
// In the case that descend=false - eg, we're asked to ignore all subnodes of the
// current node - we also advance any iterators in the heap that have the current
// path as a prefix.
//
// Next 返回正在迭代的 trie 并集中的下一个节点。
// 它通过维护一个迭代器堆来实现这一点，堆按照下一个元素的迭代顺序排序，每个源 trie 有一个条目。
// 每次调用 Next() 时，它从堆中取出最小元素返回，并推进其他也指向同一元素的迭代器。
// 这些迭代器以 descend=false 调用，因为我们知道这些节点下的任何子节点也将是重复的，存在于当前选定的迭代器中。
// 每当一个迭代器被推进时，如果它仍有剩余元素，则被推回堆中。
// 如果 descend=false，例如我们被要求忽略当前节点的所有子节点，我们还会推进堆中以当前路径为前缀的任何迭代器。
func (it *unionIterator) Next(descend bool) bool {
	// 如果堆中没有元素，返回 false
	if len(*it.items) == 0 {
		return false
	}

	// Get the next key from the union
	// 从并集中获取下一个键
	least := heap.Pop(it.items).(NodeIterator)

	// Skip over other nodes as long as they're identical, or, if we're not descending, as
	// long as they have the same prefix as the current node.
	// 跳过其他节点，只要它们相同，或者如果不下降，则只要它们与当前节点具有相同的前缀
	for len(*it.items) > 0 && ((!descend && bytes.HasPrefix((*it.items)[0].Path(), least.Path())) || compareNodes(least, (*it.items)[0]) == 0) {
		skipped := heap.Pop(it.items).(NodeIterator)
		// Skip the whole subtree if the nodes have hashes; otherwise just skip this node
		// 如果节点有哈希，则跳过整个子树；否则只跳过此节点
		if skipped.Next(skipped.Hash() == common.Hash{}) {
			it.count++
			// If there are more elements, push the iterator back on the heap
			// 如果还有更多元素，将迭代器推回堆中
			heap.Push(it.items, skipped)
		}
	}
	if least.Next(descend) {
		it.count++
		heap.Push(it.items, least)
	}
	return len(*it.items) > 0
}

func (it *unionIterator) Error() error {
	for i := 0; i < len(*it.items); i++ {
		if err := (*it.items)[i].Error(); err != nil {
			return err
		}
	}
	return nil
}
