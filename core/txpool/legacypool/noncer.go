// Copyright 2019 The go-ethereum Authors
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

package legacypool

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

// 交易池中的 Nonce 管理 (noncer)
//
// 这段代码定义了一个名为 noncer 的结构体，它在以太坊节点的交易池（Mempool）中扮演着重要的角色，用于管理账户的 Nonce 值。让我们深入了解一下 Nonce 的概念以及为什么需要在交易池中进行专门的管理。
//
// # Nonce 的概念
//
// 在以太坊中，Nonce 是一个由每个账户维护的计数器，用于跟踪从该账户发送的交易数量。对于每个新发送的交易，Nonce 值都会递增。Nonce 的主要作用是防止交易被重放（Replay Attack）。由于每个交易都包含发送者的 Nonce，并且一个具有特定 Nonce 的交易在链上只能被成功执行一次，因此攻击者无法简单地复制并重新广播一个已经执行过的交易。
//
// 为什么交易池需要管理 Nonce？
//
// 当用户发送多笔交易时，这些交易可能会在不同的时间到达交易池。为了确保这些交易能够按照正确的顺序被矿工打包到区块中（即按照 Nonce 的顺序），交易池需要对每个账户的待处理交易进行排序和管理。此外，交易池还需要知道每个账户的下一个预期 Nonce 值，以便接受新的交易。

// noncer is a tiny virtual state database to manage the executable nonces of
// accounts in the pool, falling back to reading from a real state database if
// an account is unknown.
// noncer 是一个微型的虚拟状态数据库，用于管理池中账户的可执行 Nonce，如果账户未知，则回退到从真实状态数据库读取。
type noncer struct {
	fallback *state.StateDB // Real state database to fall back to if an account is unknown.
	// fallback 如果账户未知，则回退到的真实状态数据库。
	nonces map[common.Address]uint64 // In-memory cache of account nonces.
	// nonces 账户 Nonce 的内存缓存。
	lock sync.Mutex // Mutex to protect concurrent access to the nonces map.
	// lock 用于保护对 nonces map 的并发访问的互斥锁。
}

// newNoncer creates a new virtual state database to track the pool nonces.
// newNoncer 创建一个新的虚拟状态数据库来跟踪池中的 Nonce。
func newNoncer(statedb *state.StateDB) *noncer {
	return &noncer{
		fallback: statedb.Copy(), // Create a copy of the provided state database for fallback.
		// 创建提供的状态数据库的副本作为回退。
		nonces: make(map[common.Address]uint64),
	}
}

// get returns the current nonce of an account, falling back to a real state
// database if the account is unknown.
// get 返回一个账户的当前 Nonce，如果账户未知，则回退到真实状态数据库。
func (txn *noncer) get(addr common.Address) uint64 {
	// We use mutex for get operation is the underlying
	// state will mutate db even for read access.
	// 我们使用互斥锁进行 get 操作，因为底层的状态即使是读访问也会修改数据库。
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		// If the nonce for the address is not in the cache, fetch it from the fallback state database.
		// 如果地址的 Nonce 不在缓存中，则从回退状态数据库中获取。
		if nonce := txn.fallback.GetNonce(addr); nonce != 0 {
			txn.nonces[addr] = nonce // Cache the fetched nonce.
			// 缓存获取到的 Nonce。
		}
	}
	return txn.nonces[addr] // Return the cached nonce (or 0 if not found in either cache or fallback).
	// 返回缓存的 Nonce（如果在缓存或回退中都未找到，则返回 0）。
}

// set inserts a new virtual nonce into the virtual state database to be returned
// whenever the pool requests it instead of reaching into the real state database.
// set 将一个新的虚拟 Nonce 插入到虚拟状态数据库中，每当池请求时都会返回该 Nonce，而不是访问真实状态数据库。
func (txn *noncer) set(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.nonces[addr] = nonce // Set the nonce for the given address in the cache.
	// 在缓存中设置给定地址的 Nonce。
}

// setIfLower updates a new virtual nonce into the virtual state database if the
// new one is lower.
// setIfLower 如果新的 Nonce 更小，则更新虚拟状态数据库中的虚拟 Nonce。
func (txn *noncer) setIfLower(addr common.Address, nonce uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	if _, ok := txn.nonces[addr]; !ok {
		// If the nonce for the address is not in the cache, fetch it from the fallback state database.
		// 如果地址的 Nonce 不在缓存中，则从回退状态数据库中获取。
		if nonce := txn.fallback.GetNonce(addr); nonce != 0 {
			txn.nonces[addr] = nonce // Cache the fetched nonce.
			// 缓存获取到的 Nonce。
		}
	}
	if txn.nonces[addr] <= nonce {
		return // Don't update if the existing nonce is already lower or equal.
		// 如果现有的 Nonce 已经更低或相等，则不更新。
	}
	txn.nonces[addr] = nonce // Update the nonce in the cache if the new one is lower.
	// 如果新的 Nonce 更低，则更新缓存中的 Nonce。
}

// setAll sets the nonces for all accounts to the given map.
// setAll 将所有账户的 Nonce 设置为给定的 map。
func (txn *noncer) setAll(all map[common.Address]uint64) {
	txn.lock.Lock()
	defer txn.lock.Unlock()

	txn.nonces = all // Replace the entire nonce cache with the given map.
	// 使用给定的 map 替换整个 Nonce 缓存。
}
