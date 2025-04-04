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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// PoS 共识机制下的区块生成 ：
//  在 PoS（权益证明）机制下，区块提议者需要定期生成新的待处理区块。由于信标链的 slot 时间（12 秒），执行层需要在短时间内生成并提交区块。pending 的设计允许快速复用已有区块，减少重复计算的开销。
// 重新提交间隔（Recommit Interval） ：
//  pendingTTL 的值（2 秒）与重新提交间隔对齐。这是为了确保在每个重新提交周期内，缓存的待处理区块仍然有效，同时不会占用过多内存。
// RPC 接口的需求 ：
//  RPC 接口通常需要获取当前的待处理区块信息（如区块头、交易列表等）。resolve 方法通过缓存机制满足了这一需求，同时确保返回的结果是最新且有效的。

// pendingTTL indicates the period of time a generated pending block should
// exist to serve RPC requests before being discarded if the parent block
// has not changed yet. The value is chosen to align with the recommit interval.
// pendingTTL 表示生成的待处理区块在被丢弃之前可以存在的时间段，
// 用于服务 RPC 请求（前提是父区块尚未更改）。该值与重新提交间隔对齐。
const pendingTTL = 2 * time.Second

// pending wraps a pending block with additional metadata.
// pending 封装了一个待处理区块及其附加的元数据。
type pending struct {
	created    time.Time         // 待处理区块的创建时间
	parentHash common.Hash       // 父区块哈希
	result     *newPayloadResult // 包含区块结果的数据结构
	lock       sync.Mutex        // 保护并发访问的锁
}

// resolve retrieves the cached pending result if it's available. Nothing will be
// returned if the parentHash is not matched or the result is already too old.
//
// Note, don't modify the returned payload result.
// resolve 方法检索缓存的待处理结果（如果可用）。如果父区块哈希不匹配或结果已经过期，则返回 nil。
//
// 注意：不要修改返回的有效载荷结果。
func (p *pending) resolve(parentHash common.Hash) *newPayloadResult {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.result == nil {
		return nil // 如果没有缓存的结果，直接返回 nil
	}
	if parentHash != p.parentHash {
		return nil // 如果父区块哈希不匹配，返回 nil
	}
	if time.Since(p.created) > pendingTTL {
		return nil // 如果结果已经超过 TTL 时间限制，返回 nil
	}
	return p.result
}

// update refreshes the cached pending block with newly created one.
// update 方法用新创建的区块刷新缓存的待处理区块。
func (p *pending) update(parent common.Hash, result *newPayloadResult) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.parentHash = parent  // 更新父区块哈希
	p.result = result      // 更新区块结果
	p.created = time.Now() // 更新创建时间
}
