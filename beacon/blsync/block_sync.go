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

package blsync

import (
	"github.com/ethereum/go-ethereum/beacon/light/request"
	"github.com/ethereum/go-ethereum/beacon/light/sync"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
)

// beaconBlockSync implements request.Module; it fetches the beacon blocks belonging
// to the validated and prefetch heads.
// beaconBlockSync 实现了 request.Module 接口；它获取属于已验证和预取头部的信标区块。
type beaconBlockSync struct {
	recentBlocks *lru.Cache[common.Hash, *types.BeaconBlock] // 最近获取的信标区块缓存
	locked       map[common.Hash]request.ServerAndID         // 当前正在请求的区块锁
	serverHeads  map[request.Server]common.Hash              // 每个服务器的最新头部区块哈希
	headTracker  headTracker                                 // 跟踪头部信息的接口

	lastHeadInfo  types.HeadInfo                     // 上一次处理的头部信息
	chainHeadFeed event.FeedOf[types.ChainHeadEvent] // 链头部事件的发布器
}

type headTracker interface {
	PrefetchHead() types.HeadInfo                        // 获取预取头部信息
	ValidatedOptimistic() (types.OptimisticUpdate, bool) // 获取已验证的乐观更新
	ValidatedFinality() (types.FinalityUpdate, bool)     // 获取已验证的最终性更新
}

// newBeaconBlockSync returns a new beaconBlockSync.
// newBeaconBlockSync 返回一个新的 beaconBlockSync 实例。
func newBeaconBlockSync(headTracker headTracker) *beaconBlockSync {
	return &beaconBlockSync{
		headTracker:  headTracker,
		recentBlocks: lru.NewCache[common.Hash, *types.BeaconBlock](10), // 初始化最近区块缓存，容量为 10
		locked:       make(map[common.Hash]request.ServerAndID),         // 初始化锁定映射
		serverHeads:  make(map[request.Server]common.Hash),              // 初始化服务器头部映射
	}
}

func (s *beaconBlockSync) SubscribeChainHead(ch chan<- types.ChainHeadEvent) event.Subscription {
	return s.chainHeadFeed.Subscribe(ch) // 订阅链头部事件
}

// Process implements request.Module.
// Process 实现了 request.Module 接口。
func (s *beaconBlockSync) Process(requester request.Requester, events []request.Event) {
	for _, event := range events {
		switch event.Type {
		case request.EvResponse, request.EvFail, request.EvTimeout:
			sid, req, resp := event.RequestInfo()
			blockRoot := common.Hash(req.(sync.ReqBeaconBlock)) // 获取区块根哈希
			log.Debug("Beacon block event", "type", event.Type.Name, "hash", blockRoot)
			if resp != nil {
				s.recentBlocks.Add(blockRoot, resp.(*types.BeaconBlock)) // 将响应的区块加入缓存
			}
			if s.locked[blockRoot] == sid {
				delete(s.locked, blockRoot) // 解锁当前请求的区块
			}
		case sync.EvNewHead:
			s.serverHeads[event.Server] = event.Data.(types.HeadInfo).BlockRoot // 更新服务器的最新头部区块
		case request.EvUnregistered:
			delete(s.serverHeads, event.Server) // 删除未注册的服务器
		}
	}
	s.updateEventFeed() // 更新事件发布器
	// request validated head block if unavailable and not yet requested
	// 如果已验证的头部区块不可用且尚未请求，则尝试请求
	if vh, ok := s.headTracker.ValidatedOptimistic(); ok {
		s.tryRequestBlock(requester, vh.Attested.Hash(), false)
	}
	// request prefetch head if the given server has announced it
	// 如果给定的服务器已经宣布了预取头部，则尝试请求
	if prefetchHead := s.headTracker.PrefetchHead().BlockRoot; prefetchHead != (common.Hash{}) {
		s.tryRequestBlock(requester, prefetchHead, true)
	}
}

func (s *beaconBlockSync) tryRequestBlock(requester request.Requester, blockRoot common.Hash, needSameHead bool) {
	if _, ok := s.recentBlocks.Get(blockRoot); ok {
		return // 如果区块已在缓存中，直接返回
	}
	if _, ok := s.locked[blockRoot]; ok {
		return // 如果区块已被锁定，直接返回
	}
	for _, server := range requester.CanSendTo() {
		if needSameHead && (s.serverHeads[server] != blockRoot) {
			continue // 如果需要相同头部但服务器头部不匹配，跳过
		}
		id := requester.Send(server, sync.ReqBeaconBlock(blockRoot))      // 发送请求
		s.locked[blockRoot] = request.ServerAndID{Server: server, ID: id} // 锁定区块
		return
	}
}

func blockHeadInfo(block *types.BeaconBlock) types.HeadInfo {
	if block == nil {
		return types.HeadInfo{}
	}
	return types.HeadInfo{Slot: block.Slot(), BlockRoot: block.Root()} // 提取区块的头部信息
}

func (s *beaconBlockSync) updateEventFeed() {
	optimistic, ok := s.headTracker.ValidatedOptimistic()
	if !ok {
		return
	}

	validatedHead := optimistic.Attested.Hash()
	headBlock, ok := s.recentBlocks.Get(validatedHead)
	if !ok {
		return
	}

	var finalizedHash common.Hash
	if finality, ok := s.headTracker.ValidatedFinality(); ok {
		he := optimistic.Attested.Epoch()
		fe := finality.Attested.Header.Epoch()
		switch {
		case he == fe:
			finalizedHash = finality.Finalized.PayloadHeader.BlockHash() // 如果乐观更新和最终性更新在同一纪元，提取最终区块哈希
		case he < fe:
			return // 如果乐观更新落后于最终性更新，等待
		case he == fe+1:
			parent, ok := s.recentBlocks.Get(optimistic.Attested.ParentRoot)
			if !ok || parent.Slot()/params.EpochLength == fe {
				return // head is at first slot of next epoch, wait for finality update 如果头部在下一纪元的第一个槽位，等待最终性更新
			}
		}
	}

	headInfo := blockHeadInfo(headBlock)
	if headInfo == s.lastHeadInfo {
		return
	}
	s.lastHeadInfo = headInfo

	// new head block and finality info available; extract executable data and send event to feed
	// 新的头部区块和最终性信息可用；提取可执行数据并发送事件到发布器
	execBlock, err := headBlock.ExecutionPayload()
	if err != nil {
		log.Error("Error extracting execution block from validated beacon block", "error", err)
		return
	}
	s.chainHeadFeed.Send(types.ChainHeadEvent{
		BeaconHead: optimistic.Attested.Header,
		Block:      execBlock,
		Finalized:  finalizedHash,
	})
}
