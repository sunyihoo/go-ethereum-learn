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
// GNU Lesser General Public License for more detaiapi.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/donovanhide/eventsource"
	"github.com/ethereum/go-ethereum/beacon/merkle"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

// 这是以太坊 PoS 机制的一部分，轻客户端通过同步委员会和 Merkle 证明验证链状态，降低信任需求。
// 事件流基于 Server-Sent Events (SSE)，是信标链实时更新的标准方式。
// HeadEventListener 支持动态跟踪链状态。

var (
	ErrNotFound = errors.New("404 Not Found")             // 404 未找到错误。
	ErrInternal = errors.New("500 Internal Server Error") // 500 内部服务器错误。
)

type CommitteeUpdate struct {
	Version           string                        // 更新版本。
	Update            types.LightClientUpdate       // 轻客户端更新数据。
	NextSyncCommittee types.SerializedSyncCommittee // 下一个同步委员会。
}

// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
// 请查看此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
type committeeUpdateJson struct {
	Version string              `json:"version"` // 版本号。
	Data    committeeUpdateData `json:"data"`    // 更新数据。
}

type committeeUpdateData struct {
	Header                  jsonBeaconHeader              `json:"attested_header"`            // 被证明的头部。
	NextSyncCommittee       types.SerializedSyncCommittee `json:"next_sync_committee"`        // 下一个同步委员会。
	NextSyncCommitteeBranch merkle.Values                 `json:"next_sync_committee_branch"` // 下一个同步委员会分支。
	FinalizedHeader         *jsonBeaconHeader             `json:"finalized_header,omitempty"` // 最终化头部（可选）。
	FinalityBranch          merkle.Values                 `json:"finality_branch,omitempty"`  // 最终性分支（可选）。
	SyncAggregate           types.SyncAggregate           `json:"sync_aggregate"`             // 同步聚合签名。
	SignatureSlot           common.Decimal                `json:"signature_slot"`             // 签名槽位。
}

type jsonBeaconHeader struct {
	Beacon types.Header `json:"beacon"` // 信标链头部。
}

type jsonHeaderWithExecProof struct {
	Beacon          types.Header    `json:"beacon"`           // 信标链头部。
	Execution       json.RawMessage `json:"execution"`        // 执行层数据。
	ExecutionBranch merkle.Values   `json:"execution_branch"` // 执行层分支。
}

// UnmarshalJSON unmarshals from JSON.
// UnmarshalJSON 从 JSON 反序列化。
func (u *CommitteeUpdate) UnmarshalJSON(input []byte) error {
	var dec committeeUpdateJson
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	u.Version = dec.Version
	u.NextSyncCommittee = dec.Data.NextSyncCommittee
	u.Update = types.LightClientUpdate{
		AttestedHeader: types.SignedHeader{
			Header:        dec.Data.Header.Beacon,
			Signature:     dec.Data.SyncAggregate,
			SignatureSlot: uint64(dec.Data.SignatureSlot),
		},
		NextSyncCommitteeRoot:   u.NextSyncCommittee.Root(),
		NextSyncCommitteeBranch: dec.Data.NextSyncCommitteeBranch,
		FinalityBranch:          dec.Data.FinalityBranch,
	}
	if dec.Data.FinalizedHeader != nil {
		u.Update.FinalizedHeader = &dec.Data.FinalizedHeader.Beacon
	}
	return nil
}

// fetcher is an interface useful for debug-harnessing the http api.
// fetcher 是一个有助于调试 HTTP API 的接口。
type fetcher interface {
	Do(req *http.Request) (*http.Response, error)
}

// BeaconLightApi requests light client information from a beacon node REST API.
// Note: all required API endpoints are currently only implemented by Lodestar.
// BeaconLightApi 从信标节点 REST API 请求轻客户端信息。
// 注意：所有必需的 API 端点目前仅由 Lodestar 实现。
type BeaconLightApi struct {
	url           string            // API 的 URL。
	client        fetcher           // HTTP 客户端。
	customHeaders map[string]string // 自定义 HTTP 头。
}

func NewBeaconLightApi(url string, customHeaders map[string]string) *BeaconLightApi {
	return &BeaconLightApi{
		url: url,
		client: &http.Client{
			Timeout: time.Second * 10, // 超时时间设为 10 秒。
		},
		customHeaders: customHeaders,
	}
}

func (api *BeaconLightApi) httpGet(path string, params url.Values) ([]byte, error) {
	uri, err := api.buildURL(path, params)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range api.customHeaders {
		req.Header.Set(k, v)
	}
	resp, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return io.ReadAll(resp.Body)
	case 404:
		return nil, ErrNotFound
	case 500:
		return nil, ErrInternal
	default:
		return nil, fmt.Errorf("unexpected error from API endpoint \"%s\": status code %d", path, resp.StatusCode)
	}
}

// GetBestUpdatesAndCommittees fetches and validates LightClientUpdate for given
// period and full serialized committee for the next period (committee root hash
// equals update.NextSyncCommitteeRoot).
// Note that the results are validated but the update signature should be verified
// by the caller as its validity depends on the update chain.
// GetBestUpdatesAndCommittees 获取并验证给定周期的 LightClientUpdate 以及下一周期的完整序列化委员会（委员会根哈希等于 update.NextSyncCommitteeRoot）。
// 注意：结果已验证，但更新签名应由调用者验证，因为其有效性取决于更新链。
func (api *BeaconLightApi) GetBestUpdatesAndCommittees(firstPeriod, count uint64) ([]*types.LightClientUpdate, []*types.SerializedSyncCommittee, error) {
	resp, err := api.httpGet("/eth/v1/beacon/light_client/updates", map[string][]string{
		"start_period": {strconv.FormatUint(firstPeriod, 10)},
		"count":        {strconv.FormatUint(count, 10)},
	})
	if err != nil {
		return nil, nil, err
	}

	var data []CommitteeUpdate
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, nil, err
	}
	if len(data) != int(count) {
		return nil, nil, errors.New("invalid number of committee updates") // 更新数量无效。
	}
	updates := make([]*types.LightClientUpdate, int(count))
	committees := make([]*types.SerializedSyncCommittee, int(count))
	for i, d := range data {
		if d.Update.AttestedHeader.Header.SyncPeriod() != firstPeriod+uint64(i) {
			return nil, nil, errors.New("wrong committee update header period") // 委员会更新头部周期错误。
		}
		if err := d.Update.Validate(); err != nil {
			return nil, nil, err
		}
		if d.NextSyncCommittee.Root() != d.Update.NextSyncCommitteeRoot {
			return nil, nil, errors.New("wrong sync committee root") // 同步委员会根错误。
		}
		updates[i], committees[i] = new(types.LightClientUpdate), new(types.SerializedSyncCommittee)
		*updates[i], *committees[i] = d.Update, d.NextSyncCommittee
	}
	return updates, committees, nil
}

// GetOptimisticUpdate fetches the latest available optimistic update.
// Note that the signature should be verified by the caller as its validity
// depends on the update chain.
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
// GetOptimisticUpdate 获取最新的乐观更新。
// 注意：签名应由调用者验证，因为其有效性取决于更新链。
// 请查看此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
func (api *BeaconLightApi) GetOptimisticUpdate() (types.OptimisticUpdate, error) {
	resp, err := api.httpGet("/eth/v1/beacon/light_client/optimistic_update", nil)
	if err != nil {
		return types.OptimisticUpdate{}, err
	}
	return decodeOptimisticUpdate(resp)
}

func decodeOptimisticUpdate(enc []byte) (types.OptimisticUpdate, error) {
	var data struct {
		Version string
		Data    struct {
			Attested      jsonHeaderWithExecProof `json:"attested_header"` // 被证明的头部。
			Aggregate     types.SyncAggregate     `json:"sync_aggregate"`  // 同步聚合签名。
			SignatureSlot common.Decimal          `json:"signature_slot"`  // 签名槽位。
		} `json:"data"`
	}
	if err := json.Unmarshal(enc, &data); err != nil {
		return types.OptimisticUpdate{}, err
	}
	// Decode the execution payload headers.
	// 解码执行层负载头部。
	attestedExecHeader, err := types.ExecutionHeaderFromJSON(data.Version, data.Data.Attested.Execution)
	if err != nil {
		return types.OptimisticUpdate{}, fmt.Errorf("invalid attested header: %v", err) // 无效的被证明头部。
	}
	if data.Data.Attested.Beacon.StateRoot == (common.Hash{}) {
		// workaround for different event encoding format in Lodestar
		// Lodestar 不同事件编码格式的解决方法。
		if err := json.Unmarshal(enc, &data.Data); err != nil {
			return types.OptimisticUpdate{}, err
		}
	}

	if len(data.Data.Aggregate.Signers) != params.SyncCommitteeBitmaskSize {
		return types.OptimisticUpdate{}, errors.New("invalid sync_committee_bits length") // 无效的同步委员会位掩码长度。
	}
	if len(data.Data.Aggregate.Signature) != params.BLSSignatureSize {
		return types.OptimisticUpdate{}, errors.New("invalid sync_committee_signature length") // 无效的同步委员会签名长度。
	}
	return types.OptimisticUpdate{
		Attested: types.HeaderWithExecProof{
			Header:        data.Data.Attested.Beacon,
			PayloadHeader: attestedExecHeader,
			PayloadBranch: data.Data.Attested.ExecutionBranch,
		},
		Signature:     data.Data.Aggregate,
		SignatureSlot: uint64(data.Data.SignatureSlot),
	}, nil
}

// GetFinalityUpdate fetches the latest available finality update.
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
// GetFinalityUpdate 获取最新的最终性更新。
// 请查看此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
func (api *BeaconLightApi) GetFinalityUpdate() (types.FinalityUpdate, error) {
	resp, err := api.httpGet("/eth/v1/beacon/light_client/finality_update", nil)
	if err != nil {
		return types.FinalityUpdate{}, err
	}
	return decodeFinalityUpdate(resp)
}

func decodeFinalityUpdate(enc []byte) (types.FinalityUpdate, error) {
	var data struct {
		Version string
		Data    struct {
			Attested       jsonHeaderWithExecProof `json:"attested_header"`  // 被证明的头部。
			Finalized      jsonHeaderWithExecProof `json:"finalized_header"` // 最终化头部。
			FinalityBranch merkle.Values           `json:"finality_branch"`  // 最终性分支。
			Aggregate      types.SyncAggregate     `json:"sync_aggregate"`   // 同步聚合签名。
			SignatureSlot  common.Decimal          `json:"signature_slot"`   // 签名槽位。
		}
	}
	if err := json.Unmarshal(enc, &data); err != nil {
		return types.FinalityUpdate{}, err
	}
	// Decode the execution payload headers.
	// 解码执行层负载头部。
	attestedExecHeader, err := types.ExecutionHeaderFromJSON(data.Version, data.Data.Attested.Execution)
	if err != nil {
		return types.FinalityUpdate{}, fmt.Errorf("invalid attested header: %v", err) // 无效的被证明头部。
	}
	finalizedExecHeader, err := types.ExecutionHeaderFromJSON(data.Version, data.Data.Finalized.Execution)
	if err != nil {
		return types.FinalityUpdate{}, fmt.Errorf("invalid finalized header: %v", err) // 无效的最终化头部。
	}
	// Perform sanity checks.
	// 执行健全性检查。
	if len(data.Data.Aggregate.Signers) != params.SyncCommitteeBitmaskSize {
		return types.FinalityUpdate{}, errors.New("invalid sync_committee_bits length") // 无效的同步委员会位掩码长度。
	}
	if len(data.Data.Aggregate.Signature) != params.BLSSignatureSize {
		return types.FinalityUpdate{}, errors.New("invalid sync_committee_signature length") // 无效的同步委员会签名长度。
	}

	return types.FinalityUpdate{
		Attested: types.HeaderWithExecProof{
			Header:        data.Data.Attested.Beacon,
			PayloadHeader: attestedExecHeader,
			PayloadBranch: data.Data.Attested.ExecutionBranch,
		},
		Finalized: types.HeaderWithExecProof{
			Header:        data.Data.Finalized.Beacon,
			PayloadHeader: finalizedExecHeader,
			PayloadBranch: data.Data.Finalized.ExecutionBranch,
		},
		FinalityBranch: data.Data.FinalityBranch,
		Signature:      data.Data.Aggregate,
		SignatureSlot:  uint64(data.Data.SignatureSlot),
	}, nil
}

// GetHeader fetches and validates the beacon header with the given blockRoot.
// If blockRoot is null hash then the latest head header is fetched.
// The values of the canonical and finalized flags are also returned. Note that
// these flags are not validated.
// GetHeader 获取并验证给定 blockRoot 的信标头部。
// 如果 blockRoot 是空哈希，则获取最新的头部。
// 同时返回 canonical 和 finalized 标志的值。注意，这些标志未被验证。
func (api *BeaconLightApi) GetHeader(blockRoot common.Hash) (types.Header, bool, bool, error) {
	var blockId string
	if blockRoot == (common.Hash{}) {
		blockId = "head"
	} else {
		blockId = blockRoot.Hex()
	}
	resp, err := api.httpGet(fmt.Sprintf("/eth/v1/beacon/headers/%s", blockId), nil)
	if err != nil {
		return types.Header{}, false, false, err
	}

	var data struct {
		Finalized bool `json:"finalized"` // 是否最终化。
		Data      struct {
			Root      common.Hash `json:"root"`      // 根哈希。
			Canonical bool        `json:"canonical"` // 是否规范。
			Header    struct {
				Message   types.Header  `json:"message"`   // 头部消息。
				Signature hexutil.Bytes `json:"signature"` // 签名。
			} `json:"header"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &data); err != nil {
		return types.Header{}, false, false, err
	}
	header := data.Data.Header.Message
	if blockRoot == (common.Hash{}) {
		blockRoot = data.Data.Root
	}
	if header.Hash() != blockRoot {
		return types.Header{}, false, false, errors.New("retrieved beacon header root does not match") // 检索到的信标头部根不匹配。
	}
	return header, data.Data.Canonical, data.Finalized, nil
}

// GetCheckpointData fetches and validates bootstrap data belonging to the given checkpoint.
// GetCheckpointData 获取并验证属于给定检查点的引导数据。
func (api *BeaconLightApi) GetCheckpointData(checkpointHash common.Hash) (*types.BootstrapData, error) {
	resp, err := api.httpGet(fmt.Sprintf("/eth/v1/beacon/light_client/bootstrap/0x%x", checkpointHash[:]), nil)
	if err != nil {
		return nil, err
	}

	// See data structure definition here:
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
	// 请查看此处的数据结构定义：
	// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
	type bootstrapData struct {
		Data struct {
			Header          jsonBeaconHeader               `json:"header"`                        // 头部。
			Committee       *types.SerializedSyncCommittee `json:"current_sync_committee"`        // 当前同步委员会。
			CommitteeBranch merkle.Values                  `json:"current_sync_committee_branch"` // 当前同步委员会分支。
		} `json:"data"`
	}

	var data bootstrapData
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, err
	}
	if data.Data.Committee == nil {
		return nil, errors.New("sync committee is missing") // 同步委员会缺失。
	}
	header := data.Data.Header.Beacon
	if header.Hash() != checkpointHash {
		return nil, fmt.Errorf("invalid checkpoint block header, have %v want %v", header.Hash(), checkpointHash) // 无效的检查点区块头部。
	}
	checkpoint := &types.BootstrapData{
		Header:          header,
		CommitteeBranch: data.Data.CommitteeBranch,
		CommitteeRoot:   data.Data.Committee.Root(),
		Committee:       data.Data.Committee,
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, fmt.Errorf("invalid checkpoint: %w", err) // 无效的检查点。
	}
	if checkpoint.Header.Hash() != checkpointHash {
		return nil, errors.New("wrong checkpoint hash") // 错误的检查点哈希。
	}
	return checkpoint, nil
}

func (api *BeaconLightApi) GetBeaconBlock(blockRoot common.Hash) (*types.BeaconBlock, error) {
	resp, err := api.httpGet(fmt.Sprintf("/eth/v2/beacon/blocks/0x%x", blockRoot), nil)
	if err != nil {
		return nil, err
	}

	var beaconBlockMessage struct {
		Version string
		Data    struct {
			Message json.RawMessage `json:"message"` // 区块消息。
		}
	}
	if err := json.Unmarshal(resp, &beaconBlockMessage); err != nil {
		return nil, fmt.Errorf("invalid block json data: %v", err) // 无效的区块 JSON 数据。
	}
	block, err := types.BlockFromJSON(beaconBlockMessage.Version, beaconBlockMessage.Data.Message)
	if err != nil {
		return nil, err
	}
	computedRoot := block.Root()
	if computedRoot != blockRoot {
		return nil, fmt.Errorf("Beacon block root hash mismatch (expected: %x, got: %x)", blockRoot, computedRoot) // 信标区块根哈希不匹配。
	}
	return block, nil
}

func decodeHeadEvent(enc []byte) (uint64, common.Hash, error) {
	var data struct {
		Slot  common.Decimal `json:"slot"`  // 槽位。
		Block common.Hash    `json:"block"` // 区块哈希。
	}
	if err := json.Unmarshal(enc, &data); err != nil {
		return 0, common.Hash{}, err
	}
	return uint64(data.Slot), data.Block, nil
}

type HeadEventListener struct {
	OnNewHead    func(slot uint64, blockRoot common.Hash) // 新头部事件回调。
	OnOptimistic func(head types.OptimisticUpdate)        // 乐观更新事件回调。
	OnFinality   func(head types.FinalityUpdate)          // 最终性更新事件回调。
	OnError      func(err error)                          // 错误事件回调。
}

// StartHeadListener creates an event subscription for heads and signed (optimistic)
// head updates and calls the specified callback functions when they are received.
// The callbacks are also called for the current head and optimistic head at startup.
// They are never called concurrently.
// StartHeadListener 创建一个事件订阅，用于头部和签名（乐观）头部更新，并在接收到时调用指定的回调函数。
// 在启动时也会为当前头部和乐观头部调用回调函数。
// 这些回调函数不会并发调用。
func (api *BeaconLightApi) StartHeadListener(listener HeadEventListener) func() {
	var (
		ctx, closeCtx = context.WithCancel(context.Background())
		streamCh      = make(chan *eventsource.Stream, 1)
		wg            sync.WaitGroup
	)

	// When connected to a Lodestar node the subscription blocks until the first actual
	// event arrives; therefore we create the subscription in a separate goroutine while
	// letting the main goroutine sync up to the current head.
	// 当连接到 Lodestar 节点时，订阅会阻塞直到第一个实际事件到达；因此我们在单独的 goroutine 中创建订阅，同时让主 goroutine 同步到当前头部。
	wg.Add(1)
	go func() {
		defer wg.Done()
		stream := api.startEventStream(ctx, &listener)
		if stream == nil {
			// This case happens when the context was closed.
			// 当上下文关闭时会发生这种情况。
			return
		}
		// Stream was opened, wait for close signal.
		// 流已打开，等待关闭信号。
		streamCh <- stream
		<-ctx.Done()
		stream.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Request initial data.
		// 请求初始数据。
		log.Trace("Requesting initial head header")
		if head, _, _, err := api.GetHeader(common.Hash{}); err == nil {
			log.Trace("Retrieved initial head header", "slot", head.Slot, "hash", head.Hash())
			listener.OnNewHead(head.Slot, head.Hash())
		} else {
			log.Debug("Failed to retrieve initial head header", "error", err)
		}
		log.Trace("Requesting initial optimistic update")
		if optimisticUpdate, err := api.GetOptimisticUpdate(); err == nil {
			log.Trace("Retrieved initial optimistic update", "slot", optimisticUpdate.Attested.Slot, "hash", optimisticUpdate.Attested.Hash())
			listener.OnOptimistic(optimisticUpdate)
		} else {
			log.Debug("Failed to retrieve initial optimistic update", "error", err)
		}
		log.Trace("Requesting initial finality update")
		if finalityUpdate, err := api.GetFinalityUpdate(); err == nil {
			log.Trace("Retrieved initial finality update", "slot", finalityUpdate.Finalized.Slot, "hash", finalityUpdate.Finalized.Hash())
			listener.OnFinality(finalityUpdate)
		} else {
			log.Debug("Failed to retrieve initial finality update", "error", err)
		}

		log.Trace("Starting event stream processing loop")
		// Receive the stream.
		// 接收流。
		var stream *eventsource.Stream
		select {
		case stream = <-streamCh:
		case <-ctx.Done():
			log.Trace("Stopping event stream processing loop")
			return
		}

		for {
			select {
			case event, ok := <-stream.Events:
				if !ok {
					log.Trace("Event stream closed")
					return
				}
				log.Trace("New event received from event stream", "type", event.Event())
				switch event.Event() {
				case "head":
					slot, blockRoot, err := decodeHeadEvent([]byte(event.Data()))
					if err == nil {
						listener.OnNewHead(slot, blockRoot)
					} else {
						listener.OnError(fmt.Errorf("error decoding head event: %v", err))
					}
				case "light_client_optimistic_update":
					optimisticUpdate, err := decodeOptimisticUpdate([]byte(event.Data()))
					if err == nil {
						listener.OnOptimistic(optimisticUpdate)
					} else {
						listener.OnError(fmt.Errorf("error decoding optimistic update event: %v", err))
					}
				case "light_client_finality_update":
					finalityUpdate, err := decodeFinalityUpdate([]byte(event.Data()))
					if err == nil {
						listener.OnFinality(finalityUpdate)
					} else {
						listener.OnError(fmt.Errorf("error decoding finality update event: %v", err))
					}
				default:
					listener.OnError(fmt.Errorf("unexpected event: %s", event.Event()))
				}

			case err, ok := <-stream.Errors:
				if !ok {
					return
				}
				listener.OnError(err)
			}
		}
	}()

	return func() {
		closeCtx()
		wg.Wait()
	}
}

// startEventStream establishes an event stream. This will keep retrying until the stream has been
// established. It can only return nil when the context is canceled.
// startEventStream 建立一个事件流。此函数将持续重试直到流建立成功。只有当上下文取消时才会返回 nil。
func (api *BeaconLightApi) startEventStream(ctx context.Context, listener *HeadEventListener) *eventsource.Stream {
	for retry := true; retry; retry = ctxSleep(ctx, 5*time.Second) {
		log.Trace("Sending event subscription request")
		uri, err := api.buildURL("/eth/v1/events", map[string][]string{"topics": {"head", "light_client_finality_update", "light_client_optimistic_update"}})
		if err != nil {
			listener.OnError(fmt.Errorf("error creating event subscription URL: %v", err))
			continue
		}
		req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
		if err != nil {
			listener.OnError(fmt.Errorf("error creating event subscription request: %v", err))
			continue
		}
		for k, v := range api.customHeaders {
			req.Header.Set(k, v)
		}
		stream, err := eventsource.SubscribeWithRequest("", req)
		if err != nil {
			listener.OnError(fmt.Errorf("error creating event subscription: %v", err))
			continue
		}
		log.Trace("Successfully created event stream")
		return stream
	}
	return nil
}

func ctxSleep(ctx context.Context, timeout time.Duration) (ok bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (api *BeaconLightApi) buildURL(path string, params url.Values) (string, error) {
	uri, err := url.Parse(api.url)
	if err != nil {
		return "", err
	}
	uri = uri.JoinPath(path)
	if params != nil {
		uri.RawQuery = params.Encode()
	}
	return uri.String(), nil
}
