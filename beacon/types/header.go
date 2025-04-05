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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package types implements a few types of the beacon chain for light client usage.
package types

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/ethereum/go-ethereum/beacon/merkle"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/common"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
)

// 这段代码定义了信标链中核心的数据结构 Header，它包含了信标区块的关键元信息，例如区块在时间轴上的位置（槽位）、提议者、以及指向父区块、状态和主体的哈希值。SignedHeader 则是在此基础上添加了同步委员会的签名，为轻客户端提供了一种可信的方式来跟踪信标链的状态。
//
// 信标链 (Beacon Chain): 以太坊 PoS 共识的核心。
// 槽位 (Slot): 信标链上的一个 12 秒的时间单位，每个槽位可能会产生一个新的区块。
// 纪元 (Epoch): 由 32 个连续的槽位组成，是信标链中许多状态转换和验证者操作的周期。
// 同步周期 (Sync Period): 比纪元更长的时间单位，用于管理同步委员会的更替。
// SSZ (Simple Serialize): 以太坊 2.0 使用的主要序列化格式，其哈希被广泛用于标识信标链的数据结构。虽然代码中 Hash 方法的实现不是 SSZ，但注释表明未来会替换为 SSZ 编码。
// Merkle 树: 一种树状数据结构，用于高效地验证大量数据的完整性。信标头部的字段被组织成 Merkle 树来计算根哈希。
// 同步委员会 (Sync Committee): 信标链验证者中的一个小型子集，负责对信标链的头部进行签名，为轻客户端提供快速的最终性证明。
// 轻客户端 (Light Client): 只下载和验证区块链的一小部分数据的客户端，依赖于例如同步委员会的签名来获取链的状态。

//go:generate go run github.com/fjl/gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

const (
	headerIndexSlot          = 8
	headerIndexProposerIndex = 9
	headerIndexParentRoot    = 10
	headerIndexStateRoot     = 11
	headerIndexBodyRoot      = 12
)

// Header defines a beacon header.
// Header 定义了一个信标头部。
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
// 请参阅此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#beaconblockheader
type Header struct {
	// Monotonically increasing slot number for the beacon block (may be gapped)
	// 信标区块单调递增的槽位号（可能存在间隔）。
	Slot uint64 `gencodec:"required" json:"slot"`

	// Index into the validator table who created the beacon block
	// 创建信标区块的验证者在验证者表中的索引。
	ProposerIndex uint64 `gencodec:"required" json:"proposer_index"`

	// SSZ hash of the parent beacon header
	// 父信标头部的 SSZ 哈希。
	ParentRoot common.Hash `gencodec:"required" json:"parent_root"`

	// SSZ hash of the beacon state (https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#beacon-state)
	// 信标状态的 SSZ 哈希。
	StateRoot common.Hash `gencodec:"required" json:"state_root"`

	// SSZ hash of the beacon block body (https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#beaconblockbody)
	// 信标区块主体的 SSZ 哈希。
	BodyRoot common.Hash `gencodec:"required" json:"body_root"`
}

// headerFromZRNT converts a zrnt BeaconBlockHeader to a local Header.
// headerFromZRNT 将一个 zrnt 的 BeaconBlockHeader 转换为本地的 Header 类型。
func headerFromZRNT(zh *zrntcommon.BeaconBlockHeader) Header {
	return Header{
		Slot:          uint64(zh.Slot),
		ProposerIndex: uint64(zh.ProposerIndex),
		ParentRoot:    common.Hash(zh.ParentRoot),
		StateRoot:     common.Hash(zh.StateRoot),
		BodyRoot:      common.Hash(zh.BodyRoot),
	}
}

// headerMarshaling is a field type overrides for gencodec.
// headerMarshaling 是 gencodec 的字段类型重写。
type headerMarshaling struct {
	Slot          common.Decimal
	ProposerIndex common.Decimal
}

// Hash calculates the block root of the header.
// Hash 计算头部的区块根哈希。
//
// TODO(zsfelfoldi): Remove this when an SSZ encoder lands.
// TODO(zsfelfoldi): 当 SSZ 编码实现后，移除此方法。
func (h *Header) Hash() common.Hash {
	var values [16]merkle.Value // values corresponding to indices 8 to 15 of the beacon header tree
	// 对应于信标头部树索引 8 到 15 的值。
	binary.LittleEndian.PutUint64(values[headerIndexSlot][:8], h.Slot)
	binary.LittleEndian.PutUint64(values[headerIndexProposerIndex][:8], h.ProposerIndex)
	values[headerIndexParentRoot] = merkle.Value(h.ParentRoot)
	values[headerIndexStateRoot] = merkle.Value(h.StateRoot)
	values[headerIndexBodyRoot] = merkle.Value(h.BodyRoot)
	hasher := sha256.New()
	for i := 7; i > 0; i-- {
		hasher.Reset()
		hasher.Write(values[i*2][:])
		hasher.Write(values[i*2+1][:])
		hasher.Sum(values[i][:0])
	}
	return common.Hash(values[1])
}

// Epoch returns the epoch the header belongs to.
// Epoch 返回头部所属的纪元。
func (h *Header) Epoch() uint64 {
	return h.Slot / params.EpochLength
}

// SyncPeriod returns the sync period the header belongs to.
// SyncPeriod 返回头部所属的同步周期。
func (h *Header) SyncPeriod() uint64 {
	return SyncPeriod(h.Slot)
}

// SyncPeriodStart returns the first slot of the given period.
// SyncPeriodStart 返回给定同步周期的第一个槽位。
func SyncPeriodStart(period uint64) uint64 {
	return period * params.SyncPeriodLength
}

// SyncPeriod returns the sync period that the given slot belongs to.
// SyncPeriod 返回给定槽位所属的同步周期。
func SyncPeriod(slot uint64) uint64 {
	return slot / params.SyncPeriodLength
}

// SignedHeader represents a beacon header signed by a sync committee.
// SignedHeader 表示由同步委员会签名的信标头部。
//
// This structure is created from either an optimistic update or an instant update:
// 此结构体由乐观更新或即时更新创建：
//   - https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
//   - https://github.com/zsfelfoldi/beacon-APIs/blob/instant_update/apis/beacon/light_client/instant_update.yaml
type SignedHeader struct {
	// Beacon header being signed
	// 被签名的信标头部。
	Header Header

	// Sync committee BLS signature aggregate
	// 同步委员会的 BLS 聚合签名。
	Signature SyncAggregate

	// Slot in which the signature has been created (newer than Header.Slot,
	// determines the signing sync committee)
	// 签名创建的槽位（比 Header.Slot 新，决定了签名的同步委员会）。
	SignatureSlot uint64
}
