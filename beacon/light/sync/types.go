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

package sync

import (
	"github.com/ethereum/go-ethereum/beacon/light/request"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
)

var (
	// EvNewHead is an event type for new head announcements.
	// EvNewHead 是新区块头部公告的事件类型。
	EvNewHead = &request.EventType{Name: "newHead"} // data: types.HeadInfo

	// EvNewOptimisticUpdate is an event type for new optimistic updates.
	// EvNewOptimisticUpdate 是新乐观更新的事件类型。
	EvNewOptimisticUpdate = &request.EventType{Name: "newOptimisticUpdate"} // data: types.OptimisticUpdate

	// EvNewFinalityUpdate is an event type for new finality updates.
	// EvNewFinalityUpdate 是新最终性更新的事件类型。
	EvNewFinalityUpdate = &request.EventType{Name: "newFinalityUpdate"} // data: types.FinalityUpdate
)

type (
	// ReqUpdates represents a request for light client updates and committees.
	// ReqUpdates 表示对轻客户端更新和委员会的请求。
	ReqUpdates struct {
		FirstPeriod, Count uint64 // FirstPeriod 是第一个周期，Count 是请求的数量
	}

	// RespUpdates represents the response containing light client updates and committees.
	// RespUpdates 表示包含轻客户端更新和委员会的响应。
	RespUpdates struct {
		Updates    []*types.LightClientUpdate       // 轻客户端更新列表
		Committees []*types.SerializedSyncCommittee // 序列化的同步委员会列表
	}

	// ReqHeader represents a request for a specific block header by hash.
	// ReqHeader 表示通过哈希请求特定区块头部。
	ReqHeader common.Hash

	// RespHeader represents the response containing the requested block header and its status.
	// RespHeader 表示包含请求的区块头部及其状态的响应。
	RespHeader struct {
		Header               types.Header // 区块头部
		Canonical, Finalized bool         // 是否为规范链上的头部，是否已最终化
	}

	// ReqCheckpointData represents a request for checkpoint data by hash.
	// ReqCheckpointData 表示通过哈希请求检查点数据。
	ReqCheckpointData common.Hash

	// ReqBeaconBlock represents a request for a beacon block by hash.
	// ReqBeaconBlock 表示通过哈希请求信标区块。
	ReqBeaconBlock common.Hash

	// ReqFinality represents a request for the latest finality update.
	// ReqFinality 表示请求最新的最终性更新。
	ReqFinality struct{}
)
