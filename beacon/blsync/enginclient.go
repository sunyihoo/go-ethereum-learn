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

package blsync

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	ctypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

// engineClient represents a client that interacts with the execution layer via RPC.
// engineClient 表示一个通过 RPC 与执行层交互的客户端。
type engineClient struct {
	config     *params.ClientConfig // 客户端配置
	rpc        *rpc.Client          // 执行层 RPC 客户端
	rootCtx    context.Context      // 根上下文，用于控制生命周期
	cancelRoot context.CancelFunc   // 取消函数，用于停止客户端
	wg         sync.WaitGroup       // 等待组，用于确保 goroutine 安全退出
}

// startEngineClient starts a new engineClient and begins processing chain head events.
// startEngineClient 启动一个新的 engineClient 并开始处理链头部事件。
func startEngineClient(config *params.ClientConfig, rpc *rpc.Client, headCh <-chan types.ChainHeadEvent) *engineClient {
	ctx, cancel := context.WithCancel(context.Background())
	ec := &engineClient{
		config:     config,
		rpc:        rpc,
		rootCtx:    ctx,
		cancelRoot: cancel,
	}
	ec.wg.Add(1)
	go ec.updateLoop(headCh) // 启动更新循环
	return ec
}

// stop stops the engineClient and waits for all goroutines to exit.
// stop 停止 engineClient 并等待所有 goroutine 退出。
func (ec *engineClient) stop() {
	ec.cancelRoot() // 取消根上下文，通知所有 goroutine 停止
	ec.wg.Wait()    // 等待所有 goroutine 完成
}

// updateLoop is the main loop for processing chain head events and interacting with the execution layer.
// updateLoop 是处理链头部事件并与执行层交互的主循环。
func (ec *engineClient) updateLoop(headCh <-chan types.ChainHeadEvent) {
	defer ec.wg.Done()

	for {
		select {
		case <-ec.rootCtx.Done():
			log.Debug("Stopping engine API update loop") // 收到取消信号，停止更新循环
			return

		case event := <-headCh:
			if ec.rpc == nil { // dry run, no engine API specified 如果没有指定执行层 RPC 客户端，仅记录日志（干运行模式）
				log.Info("New execution block retrieved", "number", event.Block.NumberU64(), "hash", event.Block.Hash(), "finalized", event.Finalized)
				continue
			}

			fork := ec.config.ForkAtEpoch(event.BeaconHead.Epoch()) // 获取当前纪元对应的分叉
			forkName := strings.ToLower(fork.Name)

			log.Debug("Calling NewPayload", "number", event.Block.NumberU64(), "hash", event.Block.Hash())
			if status, err := ec.callNewPayload(forkName, event); err == nil {
				log.Info("Successful NewPayload", "number", event.Block.NumberU64(), "hash", event.Block.Hash(), "status", status)
			} else {
				log.Error("Failed NewPayload", "number", event.Block.NumberU64(), "hash", event.Block.Hash(), "error", err)
			}

			log.Debug("Calling ForkchoiceUpdated", "head", event.Block.Hash())
			if status, err := ec.callForkchoiceUpdated(forkName, event); err == nil {
				log.Info("Successful ForkchoiceUpdated", "head", event.Block.Hash(), "status", status)
			} else {
				log.Error("Failed ForkchoiceUpdated", "head", event.Block.Hash(), "error", err)
			}
		}
	}
}

// callNewPayload sends the NewPayload RPC call to the execution layer.
// callNewPayload 向执行层发送 NewPayload RPC 调用。
func (ec *engineClient) callNewPayload(fork string, event types.ChainHeadEvent) (string, error) {
	execData := engine.BlockToExecutableData(event.Block, nil, nil, nil).ExecutionPayload // 将区块转换为可执行数据

	var (
		method string
		params = []any{execData}
	)
	switch fork {
	case "deneb": // Deneb 分叉支持 Blob 数据
		method = "engine_newPayloadV3"
		parentBeaconRoot := event.BeaconHead.ParentRoot
		blobHashes := collectBlobHashes(event.Block)
		params = append(params, blobHashes, parentBeaconRoot)
	case "capella": // Capella 分叉
		method = "engine_newPayloadV2"
	default: // 默认分叉
		method = "engine_newPayloadV1"
	}

	ctx, cancel := context.WithTimeout(ec.rootCtx, time.Second*5) // 设置超时时间为 5 秒
	defer cancel()
	var resp engine.PayloadStatusV1
	err := ec.rpc.CallContext(ctx, &resp, method, params...) // 发送 RPC 调用
	return resp.Status, err
}

// collectBlobHashes collects all blob hashes from the transactions in the block.
// collectBlobHashes 从区块的交易中收集所有 Blob 哈希。
func collectBlobHashes(b *ctypes.Block) []common.Hash {
	list := make([]common.Hash, 0)
	for _, tx := range b.Transactions() {
		list = append(list, tx.BlobHashes()...) // 遍历交易并提取 Blob 哈希
	}
	return list
}

// callForkchoiceUpdated sends the ForkchoiceUpdated RPC call to the execution layer.
// callForkchoiceUpdated 向执行层发送 ForkchoiceUpdated RPC 调用。
func (ec *engineClient) callForkchoiceUpdated(fork string, event types.ChainHeadEvent) (string, error) {
	update := engine.ForkchoiceStateV1{
		HeadBlockHash:      event.Block.Hash(), // 当前头部区块哈希
		SafeBlockHash:      event.Finalized,    // 安全区块哈希
		FinalizedBlockHash: event.Finalized,    // 最终化区块哈希
	}

	var method string
	switch fork {
	case "deneb": // Deneb 分叉
		method = "engine_forkchoiceUpdatedV3"
	case "capella": // Capella 分叉
		method = "engine_forkchoiceUpdatedV2"
	default: // 默认分叉
		method = "engine_forkchoiceUpdatedV1"
	}

	ctx, cancel := context.WithTimeout(ec.rootCtx, time.Second*5) // 设置超时时间为 5 秒
	defer cancel()
	var resp engine.ForkChoiceResponse
	err := ec.rpc.CallContext(ctx, &resp, method, update, nil) // 发送 RPC 调用
	return resp.PayloadStatus.Status, err
}
