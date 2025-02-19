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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package lru implements generically-typed LRU caches.
package lru

// BasicLRU is a simple LRU cache.
//
// This type is not safe for concurrent use.
// The zero value is not valid, instances must be created using NewCache.
type BasicLRU[K comparable, V any] struct {
	list  *list[K]
	items map[K]cacheItem[K, V]
	cap   int
}
type cacheItem[K any, V any] struct {
	elem  *listElem[K]
	value V
}

// list is a doubly-linked list holding items of type he.
// The zero value is not valid, use newList to create lists.
type list[T any] struct {
	root listElem[T]
}

type listElem[T any] struct {
	next *listElem[T]
	prev *listElem[T]
	v    T
}
