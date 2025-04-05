// Copyright 2023 The go-ethereum Authors
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

package light

import (
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/log"
)

// HeadTracker keeps track of the latest validated head and the "prefetch" head
// which is the (not necessarily validated) head announced by the majority of
// servers.
// HeadTracker 跟踪最新的已验证头部和“预取头部”，后者是由大多数服务器宣布的（不一定经过验证）头部。
type HeadTracker struct {
	lock                sync.RWMutex           // 锁，用于线程安全
	committeeChain      *CommitteeChain        // 委员会链，用于验证签名头部
	minSignerCount      int                    // 最小签名者数量阈值
	optimisticUpdate    types.OptimisticUpdate // 最新的乐观更新
	hasOptimisticUpdate bool                   // 是否有已验证的乐观更新
	finalityUpdate      types.FinalityUpdate   // 最新的最终性更新
	hasFinalityUpdate   bool                   // 是否有已验证的最终性更新
	prefetchHead        types.HeadInfo         // 预取头部信息
	changeCounter       uint64                 // 变更计数器，用于检测状态变化
}

// NewHeadTracker creates a new HeadTracker.
// NewHeadTracker 创建一个新的 HeadTracker 实例。
func NewHeadTracker(committeeChain *CommitteeChain, minSignerCount int) *HeadTracker {
	return &HeadTracker{
		committeeChain: committeeChain,
		minSignerCount: minSignerCount,
	}
}

// ValidatedOptimistic returns the latest validated optimistic update.
// ValidatedOptimistic 返回最新的已验证乐观更新。
func (h *HeadTracker) ValidatedOptimistic() (types.OptimisticUpdate, bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return h.optimisticUpdate, h.hasOptimisticUpdate
}

// ValidatedFinality returns the latest validated finality update.
// ValidatedFinality 返回最新的已验证最终性更新。
func (h *HeadTracker) ValidatedFinality() (types.FinalityUpdate, bool) {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return h.finalityUpdate, h.hasFinalityUpdate
}

// ValidateOptimistic validates the given optimistic update. If the update is
// successfully validated and it is better than the old validated update (higher
// slot or same slot and more signers) then ValidatedOptimistic is updated.
// The boolean return flag signals if ValidatedOptimistic has been changed.
// ValidateOptimistic 验证给定的乐观更新。如果更新成功验证并且优于旧的已验证更新（更高的槽位或相同槽位且更多签名者），则更新 ValidatedOptimistic。
// 返回的布尔值标志 ValidatedOptimistic 是否已更改。
func (h *HeadTracker) ValidateOptimistic(update types.OptimisticUpdate) (bool, error) {
	if err := update.Validate(); err != nil {
		return false, err
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	replace, err := h.validate(update.SignedHeader(), h.optimisticUpdate.SignedHeader())
	if replace {
		h.optimisticUpdate, h.hasOptimisticUpdate = update, true
		h.changeCounter++
	}
	return replace, err
}

// ValidateFinality validates the given finality update. If the update is
// successfully validated and it is better than the old validated update (higher
// slot or same slot and more signers) then ValidatedFinality is updated.
// The boolean return flag signals if ValidatedFinality has been changed.
// ValidateFinality 验证给定的最终性更新。如果更新成功验证并且优于旧的已验证更新（更高的槽位或相同槽位且更多签名者），则更新 ValidatedFinality。
// 返回的布尔值标志 ValidatedFinality 是否已更改。
func (h *HeadTracker) ValidateFinality(update types.FinalityUpdate) (bool, error) {
	if err := update.Validate(); err != nil {
		return false, err
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	replace, err := h.validate(update.SignedHeader(), h.finalityUpdate.SignedHeader())
	if replace {
		h.finalityUpdate, h.hasFinalityUpdate = update, true
		h.changeCounter++
	}
	return replace, err
}

// validate compares the given header with the old header and determines if the
// new header should replace the old one based on slot number and signer count.
// validate 比较给定的头部与旧头部，并根据槽位号和签名者数量决定新头部是否应替换旧头部。
func (h *HeadTracker) validate(head, oldHead types.SignedHeader) (bool, error) {
	signerCount := head.Signature.SignerCount()
	if signerCount < h.minSignerCount {
		return false, errors.New("low signer count") // 签名者数量不足
	}
	if head.Header.Slot < oldHead.Header.Slot || (head.Header.Slot == oldHead.Header.Slot && signerCount <= oldHead.Signature.SignerCount()) {
		return false, nil // 新头部不如旧头部
	}
	sigOk, age, err := h.committeeChain.VerifySignedHeader(head)
	if err != nil {
		return false, err
	}
	if age < 0 {
		log.Warn("Future signed head received", "age", age) // 收到未来的签名头部
	}
	if age > time.Minute*2 {
		log.Warn("Old signed head received", "age", age) // 收到过时的签名头部
	}
	if !sigOk {
		return false, errors.New("invalid header signature") // 无效的头部签名
	}
	return true, nil
}

// PrefetchHead returns the latest known prefetch head's head info.
// This head can be used to start fetching related data hoping that it will be
// validated soon.
// Note that the prefetch head cannot be validated cryptographically so it should
// only be used as a performance optimization hint.
// PrefetchHead 返回最新的已知预取头部信息。
// 此头部可用于开始获取相关数据，期望它很快会被验证。
// 注意，预取头部无法通过加密方式验证，因此仅应作为性能优化提示使用。
func (h *HeadTracker) PrefetchHead() types.HeadInfo {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return h.prefetchHead
}

// SetPrefetchHead sets the prefetch head info.
// Note that HeadTracker does not verify the prefetch head, just acts as a thread
// safe bulletin board.
// SetPrefetchHead 设置预取头部信息。
// 注意，HeadTracker 不会验证预取头部，仅作为一个线程安全的公告板。
func (h *HeadTracker) SetPrefetchHead(head types.HeadInfo) {
	h.lock.Lock()
	defer h.lock.Unlock()

	if head == h.prefetchHead {
		return
	}
	h.prefetchHead = head
	h.changeCounter++
}

// ChangeCounter implements request.targetData
// ChangeCounter 实现了 request.targetData 接口。
func (h *HeadTracker) ChangeCounter() uint64 {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return h.changeCounter
}
