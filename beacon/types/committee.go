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

package types

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/bits"

	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	bls "github.com/protolambda/bls12-381-util"
)

// 信标链 (Beacon Chain): 以太坊 PoS 共识的核心，负责协调验证者和处理共识。
// 同步委员会 (Sync Committee): 是信标链验证者中的一个小型子集（当前大小为 512），每个纪元（大约 6.4 分钟）都会更新。同步委员会的主要作用是为轻客户端提供快速且可信的对信标链状态的证明，使得轻客户端无需下载完整的区块链数据也能验证链的状态。
// BLS 签名: 信标链使用 BLS 签名算法，这种算法支持签名的聚合，可以将多个签名者的签名合并成一个更小的签名，从而提高效率。
// 聚合公钥 (Aggregate Public Key): 同步委员会所有成员的公钥可以聚合为一个单一的公钥，用于验证由委员会成员（或其子集）生成的聚合签名。
// 同步聚合 (Sync Aggregate): 包含了参与签名的同步委员会成员的位掩码以及他们的聚合 BLS 签名。轻客户端可以使用同步聚合和同步委员会的聚合公钥来验证某个信标链区块的最终性。
// 轻客户端 (Light Client): 资源受限的客户端，例如手机钱包或浏览器插件，它们不下载完整的区块链数据，而是依赖于轻量级的证明来验证链的状态。同步委员会机制是实现安全且高效的以太坊轻客户端的关键。
// 最终性 (Finality): 在区块链中，最终性是指一旦一个区块被认为是最终的，就不能再被撤销或修改。同步委员会通过定期对信标链状态进行签名，为轻客户端提供了对最终性的保证。

// SerializedSyncCommitteeSize is the size of the sync committee plus the
// aggregate public key.
// SerializedSyncCommitteeSize 是同步委员会的大小加上聚合公钥的大小。
const SerializedSyncCommitteeSize = (params.SyncCommitteeSize + 1) * params.BLSPubkeySize

// SerializedSyncCommittee is the serialized version of a sync committee
// plus the aggregate public key.
// SerializedSyncCommittee 是同步委员会及其聚合公钥的序列化版本。
type SerializedSyncCommittee [SerializedSyncCommitteeSize]byte

// jsonSyncCommittee is the JSON representation of a sync committee.
// jsonSyncCommittee 是同步委员会的 JSON 表示形式。
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
// 请参阅此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
type jsonSyncCommittee struct {
	Pubkeys []hexutil.Bytes `json:"pubkeys"`
	// Pubkeys 是同步委员会成员的公钥列表。
	Aggregate hexutil.Bytes `json:"aggregate_pubkey"`
	// Aggregate 是同步委员会所有成员公钥的聚合公钥。
}

// MarshalJSON implements json.Marshaler.
// MarshalJSON 实现了 json.Marshaler 接口，用于将 SerializedSyncCommittee 序列化为 JSON。
func (s *SerializedSyncCommittee) MarshalJSON() ([]byte, error) {
	sc := jsonSyncCommittee{Pubkeys: make([]hexutil.Bytes, params.SyncCommitteeSize)}
	for i := range sc.Pubkeys {
		sc.Pubkeys[i] = make(hexutil.Bytes, params.BLSPubkeySize)
		copy(sc.Pubkeys[i][:], s[i*params.BLSPubkeySize:(i+1)*params.BLSPubkeySize])
	}
	sc.Aggregate = make(hexutil.Bytes, params.BLSPubkeySize)
	copy(sc.Aggregate[:], s[params.SyncCommitteeSize*params.BLSPubkeySize:])
	return json.Marshal(&sc)
}

// UnmarshalJSON implements json.Marshaler.
// UnmarshalJSON 实现了 json.Marshaler 接口，用于从 JSON 反序列化 SerializedSyncCommittee。
func (s *SerializedSyncCommittee) UnmarshalJSON(input []byte) error {
	var sc jsonSyncCommittee
	if err := json.Unmarshal(input, &sc); err != nil {
		return err
	}
	if len(sc.Pubkeys) != params.SyncCommitteeSize {
		return fmt.Errorf("invalid number of pubkeys %d", len(sc.Pubkeys))
	}
	for i, key := range sc.Pubkeys {
		if len(key) != params.BLSPubkeySize {
			return fmt.Errorf("pubkey %d has invalid size %d", i, len(key))
		}
		copy(s[i*params.BLSPubkeySize:], key[:])
	}
	if len(sc.Aggregate) != params.BLSPubkeySize {
		return fmt.Errorf("invalid aggregate pubkey size %d", len(sc.Aggregate))
	}
	copy(s[params.SyncCommitteeSize*params.BLSPubkeySize:], sc.Aggregate[:])
	return nil
}

// Root calculates the root hash of the binary tree representation of a sync
// committee provided in serialized format.
// Root 计算以序列化格式提供的同步委员会的二叉树表示的根哈希。
//
// TODO(zsfelfoldi): Get rid of this when SSZ encoding lands.
// TODO(zsfelfoldi): 当 SSZ 编码实现后，移除此方法。
func (s *SerializedSyncCommittee) Root() common.Hash {
	var (
		hasher  = sha256.New()
		padding [64 - params.BLSPubkeySize]byte
		data    [params.SyncCommitteeSize]common.Hash
		l       = params.SyncCommitteeSize
	)
	for i := range data {
		hasher.Reset()
		hasher.Write(s[i*params.BLSPubkeySize : (i+1)*params.BLSPubkeySize])
		hasher.Write(padding[:])
		hasher.Sum(data[i][:0])
	}
	for l > 1 {
		for i := 0; i < l/2; i++ {
			hasher.Reset()
			hasher.Write(data[i*2][:])
			hasher.Write(data[i*2+1][:])
			hasher.Sum(data[i][:0])
		}
		l /= 2
	}
	hasher.Reset()
	hasher.Write(s[SerializedSyncCommitteeSize-params.BLSPubkeySize : SerializedSyncCommitteeSize])
	hasher.Write(padding[:])
	hasher.Sum(data[1][:0])
	hasher.Reset()
	hasher.Write(data[0][:])
	hasher.Write(data[1][:])
	hasher.Sum(data[0][:0])
	return data[0]
}

// Deserialize splits open the pubkeys into proper BLS key types.
// Deserialize 将公钥拆分为正确的 BLS 密钥类型。
func (s *SerializedSyncCommittee) Deserialize() (*SyncCommittee, error) {
	sc := new(SyncCommittee)
	for i := 0; i <= params.SyncCommitteeSize; i++ {
		key := new(bls.Pubkey)

		var bytes [params.BLSPubkeySize]byte
		copy(bytes[:], s[i*params.BLSPubkeySize:(i+1)*params.BLSPubkeySize])

		if err := key.Deserialize(&bytes); err != nil {
			return nil, err
		}
		if i < params.SyncCommitteeSize {
			sc.keys[i] = key
		} else {
			sc.aggregate = key
		}
	}
	return sc, nil
}

// SyncCommittee is a set of sync committee signer pubkeys and the aggregate key.
// SyncCommittee 是一组同步委员会签名者的公钥和聚合公钥。
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
// 请参阅此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
type SyncCommittee struct {
	keys [params.SyncCommitteeSize]*bls.Pubkey
	// keys 是同步委员会成员的公钥数组。
	aggregate *bls.Pubkey
	// aggregate 是同步委员会所有成员公钥的聚合公钥。
}

// VerifySignature returns true if the given sync aggregate is a valid signature
// or the given hash.
// VerifySignature 如果给定的同步聚合是针对给定哈希的有效签名，则返回 true。
func (sc *SyncCommittee) VerifySignature(signingRoot common.Hash, signature *SyncAggregate) bool {
	var (
		sig  bls.Signature
		keys = make([]*bls.Pubkey, 0, params.SyncCommitteeSize)
	)
	if err := sig.Deserialize(&signature.Signature); err != nil {
		return false
	}
	for i, key := range sc.keys {
		if signature.Signers[i/8]&(byte(1)<<(i%8)) != 0 {
			keys = append(keys, key)
		}
	}
	return bls.FastAggregateVerify(keys, signingRoot[:], &sig)
}

//go:generate go run github.com/fjl/gencodec -type SyncAggregate -field-override syncAggregateMarshaling -out gen_syncaggregate_json.go

// SyncAggregate represents an aggregated BLS signature with Signers referring
// to a subset of the corresponding sync committee.
// SyncAggregate 表示一个聚合的 BLS 签名，Signers 指的是相应同步委员会的一个子集。
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
// 请参阅此处的数据结构定义：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/beacon-chain.md#syncaggregate
type SyncAggregate struct {
	Signers [params.SyncCommitteeBitmaskSize]byte `gencodec:"required" json:"sync_committee_bits"`
	// Signers 是一个位掩码，指示同步委员会中的哪些成员参与了签名。
	Signature [params.BLSSignatureSize]byte `gencodec:"required" json:"sync_committee_signature"`
	// Signature 是由参与签名的同步委员会成员的签名聚合而成的 BLS 签名。
}

type syncAggregateMarshaling struct {
	Signers   hexutil.Bytes
	Signature hexutil.Bytes
}

// SignerCount returns the number of signers in the aggregate signature.
// SignerCount 返回聚合签名中的签名者数量。
func (s *SyncAggregate) SignerCount() int {
	var count int
	for _, v := range s.Signers {
		count += bits.OnesCount8(v)
	}
	return count
}
