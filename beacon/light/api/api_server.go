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

package api

import (
	"reflect"

	"github.com/ethereum/go-ethereum/beacon/light/request"
	"github.com/ethereum/go-ethereum/beacon/light/sync"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

// 信标链事件 ：
// 信标链的头部事件（如新区块、乐观更新和最终性更新）是轻客户端同步和验证的关键。
// 合并后的架构 ：
// 在合并后的以太坊中，ApiServer 可用于实现信标链与执行层之间的高效协作。

// ApiServer is a wrapper around BeaconLightApi that implements request.requestServer.
// ApiServer 是 BeaconLightApi 的包装器，实现了 request.requestServer 接口。
type ApiServer struct {
	api           *BeaconLightApi           // 包装的 BeaconLightApi 实例
	eventCallback func(event request.Event) // 事件回调函数，用于处理接收到的事件
	unsubscribe   func()                    // 取消订阅函数
}

// NewApiServer creates a new ApiServer.
// NewApiServer 创建一个新的 ApiServer 实例。
func NewApiServer(api *BeaconLightApi) *ApiServer {
	return &ApiServer{api: api}
}

// Subscribe implements request.requestServer.
// Subscribe 实现了 request.requestServer 接口。
func (s *ApiServer) Subscribe(eventCallback func(event request.Event)) {
	s.eventCallback = eventCallback
	listener := HeadEventListener{
		OnNewHead: func(slot uint64, blockRoot common.Hash) {
			log.Debug("New head received", "slot", slot, "blockRoot", blockRoot)
			eventCallback(request.Event{Type: sync.EvNewHead, Data: types.HeadInfo{Slot: slot, BlockRoot: blockRoot}})
		},
		OnOptimistic: func(update types.OptimisticUpdate) {
			log.Debug("New optimistic update received", "slot", update.Attested.Slot, "blockRoot", update.Attested.Hash(), "signerCount", update.Signature.SignerCount())
			eventCallback(request.Event{Type: sync.EvNewOptimisticUpdate, Data: update})
		},
		OnFinality: func(update types.FinalityUpdate) {
			log.Debug("New finality update received", "slot", update.Attested.Slot, "blockRoot", update.Attested.Hash(), "signerCount", update.Signature.SignerCount())
			eventCallback(request.Event{Type: sync.EvNewFinalityUpdate, Data: update})
		},
		OnError: func(err error) {
			log.Warn("Head event stream error", "err", err)
		},
	}
	s.unsubscribe = s.api.StartHeadListener(listener)
}

// SendRequest implements request.requestServer.
// SendRequest 实现了 request.requestServer 接口。
func (s *ApiServer) SendRequest(id request.ID, req request.Request) {
	go func() {
		var resp request.Response
		var err error
		switch data := req.(type) {
		case sync.ReqUpdates:
			log.Debug("Beacon API: requesting light client update", "reqid", id, "period", data.FirstPeriod, "count", data.Count)
			var r sync.RespUpdates
			r.Updates, r.Committees, err = s.api.GetBestUpdatesAndCommittees(data.FirstPeriod, data.Count)
			resp = r
		case sync.ReqHeader:
			var r sync.RespHeader
			log.Debug("Beacon API: requesting header", "reqid", id, "hash", common.Hash(data))
			r.Header, r.Canonical, r.Finalized, err = s.api.GetHeader(common.Hash(data))
			resp = r
		case sync.ReqCheckpointData:
			log.Debug("Beacon API: requesting checkpoint data", "reqid", id, "hash", common.Hash(data))
			resp, err = s.api.GetCheckpointData(common.Hash(data))
		case sync.ReqBeaconBlock:
			log.Debug("Beacon API: requesting block", "reqid", id, "hash", common.Hash(data))
			resp, err = s.api.GetBeaconBlock(common.Hash(data))
		case sync.ReqFinality:
			log.Debug("Beacon API: requesting finality update")
			resp, err = s.api.GetFinalityUpdate()
		default:
			// 未知请求类型
		}

		if err != nil {
			log.Warn("Beacon API request failed", "type", reflect.TypeOf(req), "reqid", id, "err", err)
			s.eventCallback(request.Event{Type: request.EvFail, Data: request.RequestResponse{ID: id, Request: req}})
		} else {
			log.Debug("Beacon API request answered", "type", reflect.TypeOf(req), "reqid", id)
			s.eventCallback(request.Event{Type: request.EvResponse, Data: request.RequestResponse{ID: id, Request: req, Response: resp}})
		}
	}()
}

// Unsubscribe implements request.requestServer.
// Note: Unsubscribe should not be called concurrently with Subscribe.
// Unsubscribe 实现了 request.requestServer 接口。
// 注意：Unsubscribe 不应与 Subscribe 并发调用。
func (s *ApiServer) Unsubscribe() {
	if s.unsubscribe != nil {
		s.unsubscribe()
		s.unsubscribe = nil
	}
}

// Name implements request.Server
// Name 实现了 request.Server 接口。
func (s *ApiServer) Name() string {
	return s.api.url
}
