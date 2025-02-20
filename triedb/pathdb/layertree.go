// Copyright 2022 The go-ethereum Authors
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
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// layerTree is a group of state layers identified by the state root.
// This structure defines a few basic operations for manipulating
// state layers linked with each other in a tree structure. It's
// thread-safe to use. However, callers need to ensure the thread-safety
// of the referenced layer by themselves.
type layerTree struct {
	lock   sync.RWMutex
	layers map[common.Hash]layer
}

// newLayerTree constructs the layerTree with the given head layer.
func newLayerTree(head layer) *layerTree {
	tree := new(layerTree)
	tree.reset(head)
	return tree
}

// reset initializes the layerTree by the given head layer.
// All the ancestors will be iterated out and linked in the tree.
func (tree *layerTree) reset(head layer) {
	tree.lock.Lock()
	defer tree.lock.Unlock()

	var layers = make(map[common.Hash]layer)
	for head != nil {
		layers[head.rootHash()] = head
		head = head.parentLayer()
	}
	tree.layers = layers
}
