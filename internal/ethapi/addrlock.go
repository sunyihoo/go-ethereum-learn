// Copyright 2017 The go-ethereum Authors
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

package ethapi

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// AddrLocker is a struct that manages mutex locks for Ethereum addresses.
// It ensures that only one transaction can be signed or processed for a given address at a time.
// AddrLocker 是一个管理以太坊地址互斥锁的结构体。
// 它确保在任何时候，只有一个交易可以为给定地址进行签名或处理。
type AddrLocker struct {
	mu    sync.Mutex                     // 保护 locks 映射的互斥锁，确保并发安全。
	locks map[common.Address]*sync.Mutex // 存储每个地址对应的互斥锁，键是 Ethereum 地址，值是指向互斥锁的指针。
}

// lock returns the lock of the given address.
// If the lock does not exist, it creates a new one and stores it in the map.
// lock 返回给定地址的互斥锁。如果该锁不存在，则创建一个新的锁并存储在映射中。
func (l *AddrLocker) lock(address common.Address) *sync.Mutex {
	l.mu.Lock() // 加锁以保护对 locks 映射的访问。
	defer l.mu.Unlock()
	if l.locks == nil { // 如果 locks 映射尚未初始化，则初始化它。
		l.locks = make(map[common.Address]*sync.Mutex)
	}
	if _, ok := l.locks[address]; !ok { // 如果给定地址的锁不存在，则创建一个新的锁。
		l.locks[address] = new(sync.Mutex)
	}
	return l.locks[address] // 返回与地址关联的互斥锁。
}

// LockAddr locks an account's mutex.
// This is used to prevent another tx getting the same nonce until the lock is released.
// The mutex prevents the (an identical nonce) from being read again during the time that the first transaction is being signed.
// LockAddr 锁定给定账户的互斥锁。
// 这用于防止另一个交易在锁释放之前获取相同的 nonce。
// 互斥锁确保在第一个交易被签名期间，不会再次读取相同的 nonce。
func (l *AddrLocker) LockAddr(address common.Address) {
	l.lock(address).Lock() // 获取地址对应的互斥锁并加锁。
}

// UnlockAddr unlocks the mutex of the given account.
// UnlockAddr 解锁给定账户的互斥锁。
func (l *AddrLocker) UnlockAddr(address common.Address) {
	l.lock(address).Unlock() // 获取地址对应的互斥锁并解锁。
}
