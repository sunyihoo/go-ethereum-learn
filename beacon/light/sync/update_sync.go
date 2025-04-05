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
	"sort"

	"github.com/ethereum/go-ethereum/beacon/light"
	"github.com/ethereum/go-ethereum/beacon/light/request"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const maxUpdateRequest = 8 // maximum number of updates requested in a single request
// 单个请求中请求的最大更新数量

type committeeChain interface {
	CheckpointInit(bootstrap types.BootstrapData) error
	InsertUpdate(update *types.LightClientUpdate, nextCommittee *types.SerializedSyncCommittee) error
	NextSyncPeriod() (uint64, bool)
}

// CheckpointInit implements request.Module; it fetches the light client bootstrap
// data belonging to the given checkpoint hash and initializes the committee chain
// if successful.
// CheckpointInit 实现了 request.Module 接口；它获取属于给定检查点哈希的轻客户端引导数据，并在成功的情况下初始化委员会链。
type CheckpointInit struct {
	chain          committeeChain
	checkpointHash common.Hash
	locked         request.ServerAndID
	initialized    bool
	// per-server state is used to track the state of requesting checkpoint header
	// info. Part of this info (canonical and finalized state) is not validated
	// and therefore it is requested from each server separately after it has
	// reported a missing checkpoint (which is also not validated info).
	// 每个服务器的状态用于跟踪请求检查点头信息的请求状态。这部分信息（规范状态和最终确定状态）未经过验证，
	// 因此在服务器报告缺少检查点（这也是未经验证的信息）后，需要从每个服务器单独请求。
	serverState map[request.Server]serverState
	// the following fields are used to determine whether the checkpoint is on
	// epoch boundary. This information is validated and therefore stored globally.
	// 以下字段用于确定检查点是否位于 epoch 边界。此信息经过验证，因此全局存储。
	parentHash                  common.Hash
	hasEpochInfo, epochBoundary bool
	cpSlot, parentSlot          uint64
}

const (
	ssDefault = iota // no action yet or checkpoint requested
	// 默认状态：尚未采取任何操作或已请求检查点
	ssNeedHeader // checkpoint req failed, need cp header
	// 需要头部状态：检查点请求失败，需要检查点头部
	ssHeaderRequested // cp header requested
	// 头部已请求状态：已请求检查点头部
	ssNeedParent // cp header slot %32 != 0, need parent to check epoch boundary
	// 需要父级状态：检查点头部 slot % 32 != 0，需要父级来检查 epoch 边界（注意：这里假设 EpochLength 为 32，实际应为 params.EpochLength）
	ssParentRequested // cp parent header requested
	// 父级已请求状态：已请求检查点父级头部
	ssPrintStatus // has all necessary info, print log message if init still not successful
	// 打印状态：已拥有所有必要信息，如果初始化仍然不成功，则打印日志消息
	ssDone // log message printed, no more action required
	// 完成状态：日志消息已打印，不再需要任何操作
)

type serverState struct {
	state                           int
	hasHeader, canonical, finalized bool // stored per server because not validated
	// hasHeader：是否拥有头部，canonical：是否规范，finalized：是否已最终确定。这些状态每个服务器单独存储，因为它们未经过验证。
}

// NewCheckpointInit creates a new CheckpointInit.
func NewCheckpointInit(chain committeeChain, checkpointHash common.Hash) *CheckpointInit {
	return &CheckpointInit{
		chain:          chain,
		checkpointHash: checkpointHash,
		serverState:    make(map[request.Server]serverState),
	}
}

// Process implements request.Module.
func (s *CheckpointInit) Process(requester request.Requester, events []request.Event) {
	if s.initialized {
		return
	}

	for _, event := range events {
		switch event.Type {
		case request.EvResponse, request.EvFail, request.EvTimeout:
			sid, req, resp := event.RequestInfo()
			if s.locked == sid {
				s.locked = request.ServerAndID{}
			}
			if event.Type == request.EvTimeout {
				continue
			}
			switch s.serverState[sid.Server].state {
			case ssDefault:
				if resp != nil {
					if checkpoint := resp.(*types.BootstrapData); checkpoint.Header.Hash() == common.Hash(req.(ReqCheckpointData)) {
						s.chain.CheckpointInit(*checkpoint)
						s.initialized = true
						return
					}
					requester.Fail(event.Server, "invalid checkpoint data")
				}
				s.serverState[sid.Server] = serverState{state: ssNeedHeader}
			case ssHeaderRequested:
				if resp == nil {
					s.serverState[sid.Server] = serverState{state: ssPrintStatus}
					continue
				}
				newState := serverState{
					hasHeader: true,
					canonical: resp.(RespHeader).Canonical,
					finalized: resp.(RespHeader).Finalized,
				}
				s.cpSlot, s.parentHash = resp.(RespHeader).Header.Slot, resp.(RespHeader).Header.ParentRoot
				if s.cpSlot%params.EpochLength == 0 {
					s.hasEpochInfo, s.epochBoundary = true, true
				}
				if s.hasEpochInfo {
					newState.state = ssPrintStatus
				} else {
					newState.state = ssNeedParent
				}
				s.serverState[sid.Server] = newState
			case ssParentRequested:
				s.parentSlot = resp.(RespHeader).Header.Slot
				s.hasEpochInfo, s.epochBoundary = true, s.cpSlot/params.EpochLength > s.parentSlot/params.EpochLength
				newState := s.serverState[sid.Server]
				newState.state = ssPrintStatus
				s.serverState[sid.Server] = newState
			}

		case request.EvUnregistered:
			delete(s.serverState, event.Server)
		}
	}

	// start a request if possible
	// 如果可能，启动一个新的请求
	for _, server := range requester.CanSendTo() {
		switch s.serverState[server].state {
		case ssDefault:
			if s.locked == (request.ServerAndID{}) {
				id := requester.Send(server, ReqCheckpointData(s.checkpointHash))
				s.locked = request.ServerAndID{Server: server, ID: id}
			}
		case ssNeedHeader:
			requester.Send(server, ReqHeader(s.checkpointHash))
			newState := s.serverState[server]
			newState.state = ssHeaderRequested
			s.serverState[server] = newState
		case ssNeedParent:
			requester.Send(server, ReqHeader(s.parentHash))
			newState := s.serverState[server]
			newState.state = ssParentRequested
			s.serverState[server] = newState
		}
	}

	// print log message if necessary
	// 如果必要，打印日志消息
	for server, state := range s.serverState {
		if state.state != ssPrintStatus {
			continue
		}
		switch {
		case !state.hasHeader:
			log.Error("blsync: checkpoint block is not available, reported as unknown", "server", server.Name())
			// blsync: 检查点区块不可用，报告为未知
		case !state.canonical:
			log.Error("blsync: checkpoint block is not available, reported as non-canonical", "server", server.Name())
			// blsync: 检查点区块不可用，报告为非规范
		case !s.hasEpochInfo:
			// should be available if hasHeader is true and state is ssPrintStatus
			// 如果 hasHeader 为 true 且状态为 ssPrintStatus，则应该可用
			panic("checkpoint epoch info not available when printing retrieval status")
			// 在打印检索状态时，检查点 epoch 信息不可用
		case !s.epochBoundary:
			log.Error("blsync: checkpoint block is not first of epoch", "slot", s.cpSlot, "parent", s.parentSlot, "server", server.Name())
			// blsync: 检查点区块不是 epoch 的第一个区块
		case !state.finalized:
			log.Error("blsync: checkpoint block is reported as non-finalized", "server", server.Name())
			// blsync: 检查点区块被报告为未最终确定
		default:
			log.Error("blsync: checkpoint not available, but reported as finalized; specified checkpoint hash might be too old", "server", server.Name())
			// blsync: 检查点不可用，但报告为已最终确定；指定的检查点哈希可能太旧
		}
		s.serverState[server] = serverState{state: ssDone}
	}
}

// ForwardUpdateSync implements request.Module; it fetches updates between the
// committee chain head and each server's announced head. Updates are fetched
// in batches and multiple batches can also be requested in parallel.
// Out of order responses are also handled; if a batch of updates cannot be added
// to the chain immediately because of a gap then the future updates are
// remembered until they can be processed.
// ForwardUpdateSync 实现了 request.Module 接口；它获取委员会链头部和每个服务器声明的头部之间的更新。
// 更新以批处理方式获取，并且可以并行请求多个批处理。
// 还会处理乱序的响应；如果由于存在间隙而无法立即将一批更新添加到链中，则会记住未来的更新，直到可以处理它们为止。
type ForwardUpdateSync struct {
	chain          committeeChain
	rangeLock      rangeLock
	lockedIDs      map[request.ServerAndID]struct{}
	processQueue   []updateResponse
	nextSyncPeriod map[request.Server]uint64
}

// NewForwardUpdateSync creates a new ForwardUpdateSync.
func NewForwardUpdateSync(chain committeeChain) *ForwardUpdateSync {
	return &ForwardUpdateSync{
		chain:          chain,
		rangeLock:      make(rangeLock),
		lockedIDs:      make(map[request.ServerAndID]struct{}),
		nextSyncPeriod: make(map[request.Server]uint64),
	}
}

// rangeLock allows locking sections of an integer space, preventing the syncing
// mechanism from making requests again for sections where a not timed out request
// is already pending or where already fetched and unprocessed data is available.
// rangeLock 允许锁定整数空间的部分区域，防止同步机制针对已存在未超时请求或已获取但未处理数据的区域再次发出请求。
type rangeLock map[uint64]int

// lock locks or unlocks the given section, depending on the sign of the add parameter.
// lock 根据 add 参数的符号锁定或解锁给定的部分区域。
func (r rangeLock) lock(first, count uint64, add int) {
	for i := first; i < first+count; i++ {
		if v := r[i] + add; v > 0 {
			r[i] = v
		} else {
			delete(r, i)
		}
	}
}

// firstUnlocked returns the first unlocked section starting at or after start
// and not longer than maxCount.
// firstUnlocked 返回从 start 或之后开始的第一个未锁定区域，且长度不超过 maxCount。
func (r rangeLock) firstUnlocked(start, maxCount uint64) (first, count uint64) {
	first = start
	for {
		if _, ok := r[first]; !ok {
			break
		}
		first++
	}
	for {
		count++
		if count == maxCount {
			break
		}
		if _, ok := r[first+count]; ok {
			break
		}
	}
	return
}

// lockRange locks the range belonging to the given update request, unless the
// same request has already been locked
// lockRange 锁定属于给定更新请求的范围，除非相同的请求已被锁定。
func (s *ForwardUpdateSync) lockRange(sid request.ServerAndID, req ReqUpdates) {
	if _, ok := s.lockedIDs[sid]; ok {
		return
	}
	s.lockedIDs[sid] = struct{}{}
	s.rangeLock.lock(req.FirstPeriod, req.Count, 1)
}

// unlockRange unlocks the range belonging to the given update request, unless
// same request has already been unlocked
// unlockRange 解锁属于给定更新请求的范围，除非相同的请求已被解锁。
func (s *ForwardUpdateSync) unlockRange(sid request.ServerAndID, req ReqUpdates) {
	if _, ok := s.lockedIDs[sid]; !ok {
		return
	}
	delete(s.lockedIDs, sid)
	s.rangeLock.lock(req.FirstPeriod, req.Count, -1)
}

// verifyRange returns true if the number of updates and the individual update
// periods in the response match the requested section.
// verifyRange 如果响应中的更新数量和各个更新周期与请求的部分匹配，则返回 true。
func (s *ForwardUpdateSync) verifyRange(request ReqUpdates, response RespUpdates) bool {
	if uint64(len(response.Updates)) != request.Count || uint64(len(response.Committees)) != request.Count {
		return false
	}
	for i, update := range response.Updates {
		if update.AttestedHeader.Header.SyncPeriod() != request.FirstPeriod+uint64(i) {
			return false
		}
	}
	return true
}

// updateResponse is a response that has passed initial verification and has been
// queued for processing. Note that an update response cannot be processed until
// the previous updates have also been added to the chain.
// updateResponse 是一个通过了初步验证并已排队等待处理的响应。
// 注意：在之前的更新也添加到链中之前，无法处理更新响应。
type updateResponse struct {
	sid      request.ServerAndID
	request  ReqUpdates
	response RespUpdates
}

// updateResponseList implements sort.Sort and sorts update request/response events by FirstPeriod.
// updateResponseList 实现了 sort.Sort 接口，并按 FirstPeriod 对更新请求/响应事件进行排序。
type updateResponseList []updateResponse

func (u updateResponseList) Len() int      { return len(u) }
func (u updateResponseList) Swap(i, j int) { u[i], u[j] = u[j], u[i] }
func (u updateResponseList) Less(i, j int) bool {
	return u[i].request.FirstPeriod < u[j].request.FirstPeriod
}

// Process implements request.Module.
func (s *ForwardUpdateSync) Process(requester request.Requester, events []request.Event) {
	for _, event := range events {
		switch event.Type {
		case request.EvResponse, request.EvFail, request.EvTimeout:
			sid, rq, rs := event.RequestInfo()
			req := rq.(ReqUpdates)
			var queued bool
			if event.Type == request.EvResponse {
				resp := rs.(RespUpdates)
				if s.verifyRange(req, resp) {
					// there is a response with a valid format; put it in the process queue
					// 存在格式有效的响应；将其放入处理队列
					s.processQueue = append(s.processQueue, updateResponse{sid: sid, request: req, response: resp})
					s.lockRange(sid, req)
					queued = true
				} else {
					requester.Fail(event.Server, "invalid update range")
					// 请求者：更新范围无效
				}
			}
			if !queued {
				s.unlockRange(sid, req)
			}
		case EvNewOptimisticUpdate:
			update := event.Data.(types.OptimisticUpdate)
			s.nextSyncPeriod[event.Server] = types.SyncPeriod(update.SignatureSlot + 256)
		case request.EvUnregistered:
			delete(s.nextSyncPeriod, event.Server)
		}
	}

	// try processing ordered list of available responses
	// 尝试处理已排序的可用响应列表
	sort.Sort(updateResponseList(s.processQueue))
	for s.processQueue != nil {
		u := s.processQueue[0]
		if !s.processResponse(requester, u) {
			break
		}
		s.unlockRange(u.sid, u.request)
		s.processQueue = s.processQueue[1:]
		if len(s.processQueue) == 0 {
			s.processQueue = nil
		}
	}

	// start new requests if possible
	// 如果可能，启动新的请求
	startPeriod, chainInit := s.chain.NextSyncPeriod()
	if !chainInit {
		return
	}
	for {
		firstPeriod, maxCount := s.rangeLock.firstUnlocked(startPeriod, maxUpdateRequest)
		var (
			sendTo    request.Server
			bestCount uint64
		)
		for _, server := range requester.CanSendTo() {
			nextPeriod := s.nextSyncPeriod[server]
			if nextPeriod <= firstPeriod {
				continue
			}
			count := maxCount
			if nextPeriod < firstPeriod+maxCount {
				count = nextPeriod - firstPeriod
			}
			if count > bestCount {
				sendTo, bestCount = server, count
			}
		}
		if sendTo == nil {
			return
		}
		req := ReqUpdates{FirstPeriod: firstPeriod, Count: bestCount}
		id := requester.Send(sendTo, req)
		s.lockRange(request.ServerAndID{Server: sendTo, ID: id}, req)
	}
}

// processResponse adds the fetched updates and committees to the committee chain.
// Returns true in case of full or partial success.
// processResponse 将获取的更新和委员会添加到委员会链。如果完全或部分成功，则返回 true。
func (s *ForwardUpdateSync) processResponse(requester request.Requester, u updateResponse) (success bool) {
	for i, update := range u.response.Updates {
		if err := s.chain.InsertUpdate(update, u.response.Committees[i]); err != nil {
			if err == light.ErrInvalidPeriod {
				// there is a gap in the update periods; stop processing without
				// failing and try again next time
				// 更新周期存在间隙；停止处理但不失败，下次再试
				return
			}
			if err == light.ErrInvalidUpdate || err == light.ErrWrongCommitteeRoot || err == light.ErrCannotReorg {
				requester.Fail(u.sid.Server, "invalid update received")
				// 请求者：收到无效的更新
			} else {
				log.Error("Unexpected InsertUpdate error", "error", err)
				// 意外的 InsertUpdate 错误
			}
			return
		}
		success = true
	}
	return
}
