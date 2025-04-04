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
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package miner

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// EIP-4844（Blob Transactions） ：
// sidecars 字段与 EIP-4844 引入的 Blob 交易相关，用于支持分片数据存储。
// MEV（矿工可提取价值） ：
// 在合并后的阶段，交易费用成为矿工的主要收入来源之一。update 方法通过比较交易费用确保区块收益最大化。
// Cancun 升级 ：
// BeaconRoot 字段与 Cancun 升级相关，支持新的信标链功能。

// 空区块与完整区块的动态更新
// 空区块的作用 ：
// 空区块是一个快速生成的初始版本，确保即使没有足够时间完成完整区块的构建，执行层仍然能够向共识层提供一个有效的区块。
// 完整区块的优化 ：
// 完整区块通过后台线程不断更新，优先选择高费用的交易，以最大化矿工收益。update 方法确保只有更高收益的区块才会被接受。

// BuildPayloadArgs contains the provided parameters for building payload.
// Check engine-api specification for more details.
// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#payloadattributesv3
// BuildPayloadArgs 包含构建区块有效载荷所需的参数。
// 更多细节请参考 Engine API 规范：
// https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#payloadattributesv3
type BuildPayloadArgs struct {
	Parent common.Hash // The parent block to build payload on top
	// 要在其上构建有效载荷的父区块
	Timestamp uint64 // The provided timestamp of generated payload
	// 生成的有效载荷的时间戳
	FeeRecipient common.Address // The provided recipient address for collecting transaction fee
	// 收集交易费用的接收地址
	Random common.Hash // The provided randomness value
	// 提供的随机性值
	Withdrawals types.Withdrawals // The provided withdrawals
	// 提供的提款信息
	BeaconRoot *common.Hash // The provided beaconRoot (Cancun)
	// 提供的信标根（Cancun 升级相关）
	Version engine.PayloadVersion // Versioning byte for payload id calculation.
	// 用于计算有效载荷 ID 的版本字节
}

// Id computes an 8-byte identifier by hashing the components of the payload arguments.
// Id 方法通过对有效载荷参数的组件进行哈希计算生成一个 8 字节的标识符。
func (args *BuildPayloadArgs) Id() engine.PayloadID {
	hasher := sha256.New()
	hasher.Write(args.Parent[:])
	binary.Write(hasher, binary.BigEndian, args.Timestamp)
	hasher.Write(args.Random[:])
	hasher.Write(args.FeeRecipient[:])
	rlp.Encode(hasher, args.Withdrawals)
	if args.BeaconRoot != nil {
		hasher.Write(args.BeaconRoot[:])
	}
	var out engine.PayloadID
	copy(out[:], hasher.Sum(nil)[:8])
	out[0] = byte(args.Version)
	return out
}

// Payload wraps the built payload(block waiting for sealing). According to the
// engine-api specification, EL should build the initial version of the payload
// which has an empty transaction set and then keep update it in order to maximize
// the revenue. Therefore, the empty-block here is always available and full-block
// will be set/updated afterwards.
// Payload 封装了待密封的区块（即有效载荷）。根据 Engine API 规范，
// EL（执行层）应首先构建一个初始版本的有效载荷（包含空交易集），然后不断更新以最大化收益。
// 因此，这里的空区块始终可用，而完整区块将在之后设置或更新。
type Payload struct {
	id            engine.PayloadID
	empty         *types.Block
	emptyWitness  *stateless.Witness
	full          *types.Block
	fullWitness   *stateless.Witness
	sidecars      []*types.BlobTxSidecar
	emptyRequests [][]byte
	requests      [][]byte
	fullFees      *big.Int
	stop          chan struct{}
	lock          sync.Mutex
	cond          *sync.Cond
}

// newPayload initializes the payload object.
// newPayload 初始化有效载荷对象。
func newPayload(empty *types.Block, emptyRequests [][]byte, witness *stateless.Witness, id engine.PayloadID) *Payload {
	payload := &Payload{
		id:            id,
		empty:         empty,
		emptyRequests: emptyRequests,
		emptyWitness:  witness,
		stop:          make(chan struct{}),
	}
	log.Info("Starting work on payload", "id", payload.id)
	payload.cond = sync.NewCond(&payload.lock)
	return payload
}

// update updates the full-block with latest built version.
// update 方法使用最新构建的版本更新完整区块。
func (payload *Payload) update(r *newPayloadResult, elapsed time.Duration) {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	select {
	case <-payload.stop:
		return // reject stale update
		// 拒绝过期的更新
	default:
	}
	// Ensure the newly provided full block has a higher transaction fee.
	// In post-merge stage, there is no uncle reward anymore and transaction
	// fee(apart from the mev revenue) is the only indicator for comparison.
	// 确保新提供的完整区块具有更高的交易费用。
	// 在合并后的阶段，不再有叔块奖励，交易费用（除了 MEV 收益外）是唯一的比较指标。
	if payload.full == nil || r.fees.Cmp(payload.fullFees) > 0 {
		payload.full = r.block
		payload.fullFees = r.fees
		payload.sidecars = r.sidecars
		payload.requests = r.requests
		payload.fullWitness = r.witness

		feesInEther := new(big.Float).Quo(new(big.Float).SetInt(r.fees), big.NewFloat(params.Ether))
		log.Info("Updated payload",
			"id", payload.id,
			"number", r.block.NumberU64(),
			"hash", r.block.Hash(),
			"txs", len(r.block.Transactions()),
			"withdrawals", len(r.block.Withdrawals()),
			"gas", r.block.GasUsed(),
			"fees", feesInEther,
			"root", r.block.Root(),
			"elapsed", common.PrettyDuration(elapsed),
		)
	}
	payload.cond.Broadcast() // fire signal for notifying full block
	// 广播信号以通知完整区块已更新
}

// Resolve returns the latest built payload and also terminates the background
// thread for updating payload. It's safe to be called multiple times.
// Resolve 方法返回最新构建的有效载荷，并终止后台更新线程。可以安全地多次调用。
func (payload *Payload) Resolve() *engine.ExecutionPayloadEnvelope {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	select {
	case <-payload.stop:
	default:
		close(payload.stop)
	}
	if payload.full != nil {
		envelope := engine.BlockToExecutableData(payload.full, payload.fullFees, payload.sidecars, payload.requests)
		if payload.fullWitness != nil {
			envelope.Witness = new(hexutil.Bytes)
			*envelope.Witness, _ = rlp.EncodeToBytes(payload.fullWitness) // cannot fail
			// 编码见证数据到字节数组（不会失败）
		}
		return envelope
	}
	envelope := engine.BlockToExecutableData(payload.empty, big.NewInt(0), nil, payload.emptyRequests)
	if payload.emptyWitness != nil {
		envelope.Witness = new(hexutil.Bytes)
		*envelope.Witness, _ = rlp.EncodeToBytes(payload.emptyWitness) // cannot fail
		// 编码见证数据到字节数组（不会失败）
	}
	return envelope
}

// ResolveEmpty is basically identical to Resolve, but it expects empty block only.
// It's only used in tests.
// ResolveEmpty 基本上与 Resolve 相同，但它仅返回空区块。仅用于测试。
func (payload *Payload) ResolveEmpty() *engine.ExecutionPayloadEnvelope {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	envelope := engine.BlockToExecutableData(payload.empty, big.NewInt(0), nil, payload.emptyRequests)
	if payload.emptyWitness != nil {
		envelope.Witness = new(hexutil.Bytes)
		*envelope.Witness, _ = rlp.EncodeToBytes(payload.emptyWitness) // cannot fail
		// 编码见证数据到字节数组（不会失败）
	}
	return envelope
}

// ResolveFull is basically identical to Resolve, but it expects full block only.
// Don't call Resolve until ResolveFull returns, otherwise it might block forever.
// ResolveFull 基本上与 Resolve 相同，但它仅返回完整区块。
// 在 ResolveFull 返回之前不要调用 Resolve，否则可能会永久阻塞。
func (payload *Payload) ResolveFull() *engine.ExecutionPayloadEnvelope {
	payload.lock.Lock()
	defer payload.lock.Unlock()

	if payload.full == nil {
		select {
		case <-payload.stop:
			return nil
		default:
		}
		// Wait the full payload construction. Note it might block
		// forever if Resolve is called in the meantime which
		// terminates the background construction process.
		// 等待完整有效载荷的构建。注意，如果在此期间调用了 Resolve，
		// 可能会终止后台构建过程，从而导致永久阻塞。
		payload.cond.Wait()
	}
	// Terminate the background payload construction
	// 终止后台有效载荷构建
	select {
	case <-payload.stop:
	default:
		close(payload.stop)
	}
	envelope := engine.BlockToExecutableData(payload.full, payload.fullFees, payload.sidecars, payload.requests)
	if payload.fullWitness != nil {
		envelope.Witness = new(hexutil.Bytes)
		*envelope.Witness, _ = rlp.EncodeToBytes(payload.fullWitness) // cannot fail
		// 编码见证数据到字节数组（不会失败）
	}
	return envelope
}

// buildPayload builds the payload according to the provided parameters.
// buildPayload 根据提供的参数构建有效载荷。
func (miner *Miner) buildPayload(args *BuildPayloadArgs, witness bool) (*Payload, error) {
	// Build the initial version with no transaction included. It should be fast
	// enough to run. The empty payload can at least make sure there is something
	// to deliver for not missing slot.
	// 构建一个不包含任何交易的初始版本。这个过程应该足够快。
	// 空有效载荷至少可以确保不会错过时隙（slot）。
	emptyParams := &generateParams{
		timestamp:   args.Timestamp,
		forceTime:   true,
		parentHash:  args.Parent,
		coinbase:    args.FeeRecipient,
		random:      args.Random,
		withdrawals: args.Withdrawals,
		beaconRoot:  args.BeaconRoot,
		noTxs:       true,
	}
	empty := miner.generateWork(emptyParams, witness)
	if empty.err != nil {
		return nil, empty.err
	}
	// Construct a payload object for return.
	// 构造一个有效载荷对象以返回。
	payload := newPayload(empty.block, empty.requests, empty.witness, args.Id())

	// Spin up a routine for updating the payload in background. This strategy
	// can maximum the revenue for including transactions with highest fee.
	// 启动一个后台例程来更新有效载荷。这种策略可以最大化包含最高费用交易的收益。
	go func() {
		// Setup the timer for re-building the payload. The initial clock is kept
		// for triggering process immediately.
		// 设置重新构建有效载荷的计时器。初始时钟保持为立即触发。
		timer := time.NewTimer(0)
		defer timer.Stop()

		// Setup the timer for terminating the process if SECONDS_PER_SLOT (12s in
		// the Mainnet configuration) have passed since the point in time identified
		// by the timestamp parameter.
		// 如果从时间戳参数标识的时间点开始已经过去了 SECONDS_PER_SLOT（主网配置中为 12 秒），
		// 则设置计时器以终止该过程。
		endTimer := time.NewTimer(time.Second * 12)

		fullParams := &generateParams{
			timestamp:   args.Timestamp,
			forceTime:   true,
			parentHash:  args.Parent,
			coinbase:    args.FeeRecipient,
			random:      args.Random,
			withdrawals: args.Withdrawals,
			beaconRoot:  args.BeaconRoot,
			noTxs:       false,
		}

		for {
			select {
			case <-timer.C:
				start := time.Now()
				r := miner.generateWork(fullParams, witness)
				if r.err == nil {
					payload.update(r, time.Since(start))
				} else {
					log.Info("Error while generating work", "id", payload.id, "err", r.err)
				}
				timer.Reset(miner.config.Recommit)
			case <-payload.stop:
				log.Info("Stopping work on payload", "id", payload.id, "reason", "delivery")
				return
			case <-endTimer.C:
				log.Info("Stopping work on payload", "id", payload.id, "reason", "timeout")
				return
			}
		}
	}()
	return payload, nil
}
