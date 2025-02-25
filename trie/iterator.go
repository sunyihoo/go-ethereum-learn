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
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// NodeResolver is used for looking up trie nodes before reaching into the real
// persistent layer. This is not mandatory, rather is an optimization for cases
// where trie nodes can be recovered from some external mechanism without reading
// from disk. In those cases, this resolver allows short circuiting accesses and
// returning them from memory.
type NodeResolver func(owner common.Hash, path []byte, hash common.Hash) []byte

// Iterator is a key-value trie iterator that traverses a Trie.
type Iterator struct {
	nodeIt NodeIterator

	Key   []byte // Current data key on which the iterator is positioned on
	Value []byte // Current data value on which the iterator is positioned on
	Err   error
}

// NewIterator creates a new key-value iterator from a node iterator.
// Note that the value returned by the iterator is raw. If the content is encoded
// (e.g. storage value is RLP-encoded), it's caller's duty to decode it.
func NewIterator(it NodeIterator) *Iterator {
	return &Iterator{
		nodeIt: it,
	}
}

// Next moves the iterator forward one key-value entry.
func (it *Iterator) Next() bool {
	for it.nodeIt.Next(true) {
		if it.nodeIt.Leaf() {
			it.Key = it.nodeIt.LeafKey()
			it.Value = it.nodeIt.LeafBlob()
			return true
		}
	}
	it.Key = nil
	it.Value = nil
	it.Err = it.nodeIt.Error()
	return false
}

// NodeIterator is an iterator to traverse the trie pre-order.
type NodeIterator interface {
	// Next moves the iterator to the next node. If the parameter is false, any child
	// nodes will be skipped.
	Next(bool) bool

	// Error returns the error status of the iterator.
	Error() error

	// Hash returns the hash of the current node.
	Hash() common.Hash

	// Parent returns the hash of the parent of the current node. The hash may be the one
	// grandparent if the immediate parent is an internal node with no hash.
	Parent() common.Hash

	// Path returns the hex-encoded path to the current node.
	// Callers must not retain references to the return value after calling Next.
	// For leaf nodes, the last element of the path is the 'terminator symbol' 0x10.
	Path() []byte

	// NodeBlob returns the rlp-encoded value of the current iterated node.
	// If the node is an embedded node in its parent, nil is returned then.
	NodeBlob() []byte

	// Leaf returns true if the current node is a leaf node.
	Leaf() bool

	// LeafKey returns the key of the leaf. The method panics if the iterator is not
	// positioned at a leaf. Callers must not retain references to the value after
	// calling Next.
	LeafKey() []byte

	// LeafBlob returns the content of the leaf. The method panics if the iterator
	// is not positioned at a leaf. Callers must not retain references to the value
	// after calling Next.
	LeafBlob() []byte

	// LeafProof returns the Merkle proof of the leaf. The method panics if the
	// iterator is not positioned at a leaf. Callers must not retain references
	// to the value after calling Next.
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
	AddResolver(NodeResolver)
}

// nodeIteratorState represents the iteration state at one particular node of the
// trie, which can be resumed at a later invocation.
type nodeIteratorState struct {
	hash    common.Hash // Hash of the node being iterated (nil if not standalone)
	node    node        // Trie node being iterated
	parent  common.Hash // Hash of the first full ancestor node (nil if current is the root)
	index   int         // Child to be processed next
	pathlen int         // Length of the path to the parent node
}

type nodeIterator struct {
	trie  *Trie                // Trie being iterated
	stack []*nodeIteratorState // Hierarchy of trie nodes persisting the iteration state
	path  []byte               // Path to the current node
	err   error                // Failure set in case of an internal error in the iterator

	resolver NodeResolver         // optional node resolver for avoiding disk hits
	pool     []*nodeIteratorState // local pool for iterator states
}

// errIteratorEnd is stored in nodeIterator.err when iteration is done.
var errIteratorEnd = errors.New("end of iteration")

// seekError is stored in nodeIterator.err if the initial seek has failed.
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

func (it *nodeIterator) putInPool(item *nodeIteratorState) {
	if len(it.pool) < 40 {
		item.node = nil
		it.pool = append(it.pool, item)
	}
}

func (it *nodeIterator) getFromPool() *nodeIteratorState {
	idx := len(it.pool) - 1
	if idx < 0 {
		return new(nodeIteratorState)
	}
	el := it.pool[idx]
	it.pool[idx] = nil
	it.pool = it.pool[:idx]
	return el
}

func (it *nodeIterator) AddResolver(resolver NodeResolver) {
	it.resolver = resolver
}

func (it *nodeIterator) Hash() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].hash
}

func (it *nodeIterator) Parent() common.Hash {
	if len(it.stack) == 0 {
		return common.Hash{}
	}
	return it.stack[len(it.stack)-1].parent
}

func (it *nodeIterator) Leaf() bool {
	return hasTerm(it.path)
}

func (it *nodeIterator) LeafKey() []byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return hexToKeybytes(it.path)
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) LeafBlob() []byte {
	if len(it.stack) > 0 {
		if node, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			return node
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) LeafProof() [][]byte {
	if len(it.stack) > 0 {
		if _, ok := it.stack[len(it.stack)-1].node.(valueNode); ok {
			hasher := newHasher(false)
			defer returnHasherToPool(hasher)
			proofs := make([][]byte, 0, len(it.stack))

			for i, item := range it.stack[:len(it.stack)-1] {
				// Gather nodes that end up as hash nodes (or the root)
				node, hashed := hasher.proofHash(item.node)
				if _, ok := hashed.(hashNode); ok || i == 0 {
					proofs = append(proofs, nodeToBytes(node))
				}
			}
			return proofs
		}
	}
	panic("not at leaf")
}

func (it *nodeIterator) Path() []byte {
	return it.path
}

func (it *nodeIterator) NodeBlob() []byte {
	if it.Hash() == (common.Hash{}) {
		return nil // skip the non-standalone node
	}
	blob, err := it.resolveBlob(it.Hash().Bytes(), it.Path())
	if err != nil {
		it.err = err
		return nil
	}
	return blob
}

func (it *nodeIterator) Error() error {
	if it.err == errIteratorEnd {
		return nil
	}
	if seek, ok := it.err.(seekError); ok {
		return seek.err
	}
	return it.err
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure. If `descend` is false,
// skips iterating over any subnodes of the current node.
func (it *nodeIterator) Next(descend bool) bool {
	if it.err == errIteratorEnd {
		return false
	}
	if seek, ok := it.err.(seekError); ok {
		if it.err = it.seek(seek.key); it.err != nil {
			return false
		}
	}
	// Otherwise step forward with the iterator and report any errors.
	state, parentIndex, path, err := it.peek(descend)
	it.err = err
	if it.err != nil {
		return false
	}
	it.push(state, parentIndex, path)
	return true
}

func (it *nodeIterator) seek(prefix []byte) error {
	// The path we're looking for is the hex encoded key without terminator.
	key := keybytesToHex(prefix)
	key = key[:len(key)-1]

	// Move forward until we're just before the closest match to key.
	for {
		state, parentIndex, path, err := it.peekSeek(key)
		if err == errIteratorEnd {
			return errIteratorEnd
		} else if err != nil {
			return seekError{prefix, err}
		} else if reachedPath(path, key) {
			return nil
		}
		it.push(state, parentIndex, path)
	}
}

// init initializes the iterator.
func (it *nodeIterator) init() (*nodeIteratorState, error) {
	root := it.trie.Hash()
	state := &nodeIteratorState{node: it.trie.root, index: -1}
	if root != types.EmptyRootHash {
		state.hash = root
	}
	return state, state.resolve(it, nil)
}

// peek creates the next state of the iterator.
func (it *nodeIterator) peek(descend bool) (*nodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !descend {
		// If we're skipping children, pop the current node first
		it.pop()
	}
	// Continue iteration to the next child
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChild(parent, ancestor)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

// peekSeek is like peek, but it also tries to skip resolving hashes by skipping
// over the siblings that do not lead towards the desired seek position.
func (it *nodeIterator) peekSeek(seekKey []byte) (*nodeIteratorState, *int, []byte, error) {
	// Initialize the iterator if we've just started.
	if len(it.stack) == 0 {
		state, err := it.init()
		return state, nil, nil, err
	}
	if !bytes.HasPrefix(seekKey, it.path) {
		// If we're skipping children, pop the current node first
		it.pop()
	}
	// Continue iteration to the next child
	for len(it.stack) > 0 {
		parent := it.stack[len(it.stack)-1]
		ancestor := parent.hash
		if (ancestor == common.Hash{}) {
			ancestor = parent.parent
		}
		state, path, ok := it.nextChildAt(parent, ancestor, seekKey)
		if ok {
			if err := state.resolve(it, path); err != nil {
				return parent, &parent.index, path, err
			}
			return state, &parent.index, path, nil
		}
		// No more child nodes, move back up.
		it.pop()
	}
	return nil, nil, nil, errIteratorEnd
}

func (it *nodeIterator) resolveHash(hash hashNode, path []byte) (node, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 {
			if resolved, err := decodeNode(hash, blob); err == nil {
				return resolved, nil
			}
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	blob, err := it.trie.reader.node(path, common.BytesToHash(hash))
	if err != nil {
		return nil, err
	}
	// The raw-blob format nodes are loaded either from the
	// clean cache or the database, they are all in their own
	// copy and safe to use unsafe decoder.
	return mustDecodeNodeUnsafe(hash, blob), nil
}

func (it *nodeIterator) resolveBlob(hash hashNode, path []byte) ([]byte, error) {
	if it.resolver != nil {
		if blob := it.resolver(it.trie.owner, path, common.BytesToHash(hash)); len(blob) > 0 {
			return blob, nil
		}
	}
	// Retrieve the specified node from the underlying node reader.
	// it.trie.resolveAndTrack is not used since in that function the
	// loaded blob will be tracked, while it's not required here since
	// all loaded nodes won't be linked to trie at all and track nodes
	// may lead to out-of-memory issue.
	return it.trie.reader.node(path, common.BytesToHash(hash))
}

func (st *nodeIteratorState) resolve(it *nodeIterator, path []byte) error {
	if hash, ok := st.node.(hashNode); ok {
		resolved, err := it.resolveHash(hash, path)
		if err != nil {
			return err
		}
		st.node = resolved
		st.hash = common.BytesToHash(hash)
	}
	return nil
}

func (it *nodeIterator) findChild(n *fullNode, index int, ancestor common.Hash) (node, *nodeIteratorState, []byte, int) {
	var (
		path      = it.path
		child     node
		state     *nodeIteratorState
		childPath []byte
	)
	for ; index < len(n.Children); index = nextChildIndex(index) {
		if n.Children[index] != nil {
			child = n.Children[index]
			hash, _ := child.cache()

			state = it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = child
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(path)

			childPath = append(childPath, path...)
			childPath = append(childPath, byte(index))
			return child, state, childPath, index
		}
	}
	return nil, nil, nil, 0
}

func (it *nodeIterator) nextChild(parent *nodeIteratorState, ancestor common.Hash) (*nodeIteratorState, []byte, bool) {
	switch node := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child.
		if child, state, path, index := it.findChild(node, nextChildIndex(parent.index), ancestor); child != nil {
			parent.index = prevChildIndex(index)
			return state, path, true
		}
	case *shortNode:
		// Short node, return the pointer singleton child
		if parent.index < 0 {
			hash, _ := node.Val.cache()
			state := it.getFromPool()
			state.hash = common.BytesToHash(hash)
			state.node = node.Val
			state.parent = ancestor
			state.index = -1
			state.pathlen = len(it.path)
			path := append(it.path, node.Key...)
			return state, path, true
		}
	}
	return parent, it.path, false
}

// nextChildAt is similar to nextChild, except that it targets a child as close to the
// target key as possible, thus skipping siblings.
func (it *nodeIterator) nextChildAt(parent *nodeIteratorState, ancestor common.Hash, key []byte) (*nodeIteratorState, []byte, bool) {
	switch n := parent.node.(type) {
	case *fullNode:
		// Full node, move to the first non-nil child before the desired key position
		child, state, path, index := it.findChild(n, nextChildIndex(parent.index), ancestor)
		if child == nil {
			// No more children in this fullnode
			return parent, it.path, false
		}
		// If the child we found is already past the seek position, just return it.
		if reachedPath(path, key) {
			parent.index = prevChildIndex(index)
			return state, path, true
		}
		// The child is before the seek position. Try advancing
		for {
			nextChild, nextState, nextPath, nextIndex := it.findChild(n, nextChildIndex(index), ancestor)
			// If we run out of children, or skipped past the target, return the
			// previous one
			if nextChild == nil || reachedPath(nextPath, key) {
				parent.index = prevChildIndex(index)
				return state, path, true
			}
			// We found a better child closer to the target
			state, path, index = nextState, nextPath, nextIndex
		}
	case *shortNode:
		// Short node, return the pointer singleton child
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
	return parent, it.path, false
}

func (it *nodeIterator) push(state *nodeIteratorState, parentIndex *int, path []byte) {
	it.path = path
	it.stack = append(it.stack, state)
	if parentIndex != nil {
		*parentIndex = nextChildIndex(*parentIndex)
	}
}

func (it *nodeIterator) pop() {
	last := it.stack[len(it.stack)-1]
	it.path = it.path[:last.pathlen]
	it.stack[len(it.stack)-1] = nil
	it.stack = it.stack[:len(it.stack)-1]

	it.putInPool(last) // last is now unused
}

// reachedPath normalizes a path by truncating a terminator if present, and
// returns true if it is greater than or equal to the target. Using this,
// the path of a value node embedded a full node will compare less than the
// full node's children.
func reachedPath(path, target []byte) bool {
	if hasTerm(path) {
		path = path[:len(path)-1]
	}
	return bytes.Compare(path, target) >= 0
}

// A value embedded in a full node occupies the last slot (16) of the array of
// children. In order to produce a pre-order traversal when iterating children,
// we jump to this last slot first, then go back iterate the child nodes (and
// skip the last slot at the end):

// prevChildIndex returns the index of a child in a full node which precedes
// the given index when performing a pre-order traversal.
func prevChildIndex(index int) int {
	switch index {
	case 0: // We jumped back to iterate the children, from the value slot
		return 16
	case 16: // We jumped to the embedded value slot at the end, from the placeholder index
		return -1
	case 17: // We skipped the value slot after iterating all the children
		return 15
	default: // We are iterating the children in sequence
		return index - 1
	}
}

// nextChildIndex returns the index of a child in a full node which follows
// the given index when performing a pre-order traversal.
func nextChildIndex(index int) int {
	switch index {
	case -1: // Jump from the placeholder index to the embedded value slot
		return 16
	case 15: // Skip the value slot after iterating the children
		return 17
	case 16: // From the embedded value slot, jump back to iterate the children
		return 0
	default: // Iterate children in sequence
		return index + 1
	}
}
