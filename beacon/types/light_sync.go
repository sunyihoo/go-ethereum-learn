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

package types

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/beacon/merkle"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/common"
	ctypes "github.com/ethereum/go-ethereum/core/types"
)

// HeadInfo represents an unvalidated new head announcement.
// HeadInfo 代表一个未经验证的新区块头广播。
type HeadInfo struct {
	Slot uint64 // The slot number of the block.
	// 区块的槽位号。
	BlockRoot common.Hash // The root hash of the block.
	// 区块的根哈希。
}

// BootstrapData contains a sync committee where light sync can be started,
// together with a proof through a beacon header and corresponding state.
// Note: BootstrapData is fetched from a server based on a known checkpoint hash.
// BootstrapData 包含一个可以启动轻客户端同步的同步委员会，
// 以及通过信标头和相应的状态进行的证明。
// 注意：BootstrapData 是基于已知的检查点哈希从服务器获取的。
type BootstrapData struct {
	Header Header // The beacon header.
	// 信标头。
	CommitteeRoot common.Hash // The root hash of the sync committee.
	// 同步委员会的根哈希。
	Committee *SerializedSyncCommittee `rlp:"-"` // The serialized sync committee. This field is not RLP encoded.
	// 序列化的同步委员会。此字段不进行 RLP 编码。
	CommitteeBranch merkle.Values // The Merkle proof for the sync committee.
	// 同步委员会的 Merkle 证明。
}

// Validate verifies the proof included in BootstrapData.
// Validate 验证 BootstrapData 中包含的证明。
func (c *BootstrapData) Validate() error {
	// Check if the calculated root of the provided sync committee matches the expected root.
	// 检查提供的同步委员会计算出的根是否与预期的根匹配。
	if c.CommitteeRoot != c.Committee.Root() {
		return errors.New("wrong committee root") // Return an error if the roots do not match.
		// 如果根不匹配，则返回错误。
	}
	// Verify the Merkle proof that the sync committee root is included in the state root of the beacon header.
	// 使用 Merkle 证明验证同步委员会的根是否包含在信标头的状态根中。
	return merkle.VerifyProof(c.Header.StateRoot, params.StateIndexSyncCommittee, c.CommitteeBranch, merkle.Value(c.CommitteeRoot))
}

// LightClientUpdate is a proof of the next sync committee root based on a header
// signed by the sync committee of the given period. Optionally, the update can
// prove quasi-finality by the signed header referring to a previous, finalized
// header from the same period, and the finalized header referring to the next
// sync committee root.
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
// LightClientUpdate 是基于给定周期的同步委员会签名的区块头，对下一个同步委员会根的证明。
// 可选地，该更新可以通过签名头引用同一周期的先前已最终确定的区块头，
// 并且已最终确定的区块头引用下一个同步委员会根来证明准最终性。
//
// 有关数据结构定义，请参见此处：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
type LightClientUpdate struct {
	AttestedHeader SignedHeader // Arbitrary header out of the period signed by the sync committee
	// 由同步委员会签名的该周期外的任意区块头。
	NextSyncCommitteeRoot common.Hash // Sync committee of the next period advertised in the current one
	// 当前周期中声明的下一个周期的同步委员会。
	NextSyncCommitteeBranch merkle.Values // Proof for the next period's sync committee
	// 下一个周期的同步委员会的证明。

	FinalizedHeader *Header `rlp:"nil"` // Optional header to announce a point of finality
	// 可选的区块头，用于声明最终确定的点。
	FinalityBranch merkle.Values // Proof for the announced finality
	// 声明的最终性的证明。

	score *UpdateScore // Weight of the update to compare between competing ones
	// 用于比较竞争更新的权重。
}

// Validate verifies the validity of the update.
// Validate 验证更新的有效性。
func (update *LightClientUpdate) Validate() error {
	// Get the sync period of the attested header.
	// 获取被证明区块头的同步周期。
	period := update.AttestedHeader.Header.SyncPeriod()
	// Check if the signature slot of the attested header belongs to the same sync period as the header itself.
	// 检查被证明区块头的签名槽位是否与区块头本身属于同一个同步周期。
	if SyncPeriod(update.AttestedHeader.SignatureSlot) != period {
		return errors.New("signature slot and signed header are from different periods") // Return an error if the periods do not match.
		// 如果周期不匹配，则返回错误。
	}
	// If a finalized header is included in the update.
	// 如果更新中包含已最终确定的区块头。
	if update.FinalizedHeader != nil {
		// Check if the finalized header belongs to the same sync period as the attested header.
		// 检查已最终确定的区块头是否与被证明的区块头属于同一个同步周期。
		if update.FinalizedHeader.SyncPeriod() != period {
			return errors.New("finalized header is from different period") // Return an error if the periods do not match.
			// 如果周期不匹配，则返回错误。
		}
		// Verify the Merkle proof that the finalized header is included in the state root of the attested header at the FinalizedBlock index.
		// 验证 Merkle 证明，以确保已最终确定的区块头包含在被证明区块头的状态根中，位于 FinalizedBlock 索引处。
		if err := merkle.VerifyProof(update.AttestedHeader.Header.StateRoot, params.StateIndexFinalBlock, update.FinalityBranch, merkle.Value(update.FinalizedHeader.Hash())); err != nil {
			return fmt.Errorf("invalid finalized header proof: %w", err) // Return an error if the proof is invalid.
			// 如果证明无效，则返回错误。
		}
	}
	// Verify the Merkle proof that the next sync committee root is included in the state root of the attested header at the NextSyncCommittee index.
	// 验证 Merkle 证明，以确保下一个同步委员会的根包含在被证明区块头的状态根中，位于 NextSyncCommittee 索引处。
	if err := merkle.VerifyProof(update.AttestedHeader.Header.StateRoot, params.StateIndexNextSyncCommittee, update.NextSyncCommitteeBranch, merkle.Value(update.NextSyncCommitteeRoot)); err != nil {
		return fmt.Errorf("invalid next sync committee proof: %w", err) // Return an error if the proof is invalid.
		// 如果证明无效，则返回错误。
	}
	return nil // Return nil if all validations pass.
	// 如果所有验证都通过，则返回 nil。
}

// Score returns the UpdateScore describing the proof strength of the update
// Note: thread safety can be ensured by always calling Score on a newly received
// or decoded update before making it potentially available for other threads
// Score 返回描述更新的证明强度的 UpdateScore
// 注意：通过在将新接收或解码的更新可能提供给其他线程之前始终调用 Score，可以确保线程安全。
func (update *LightClientUpdate) Score() UpdateScore {
	// If the score has not been calculated yet.
	// 如果尚未计算分数。
	if update.score == nil {
		// Calculate and store the update score.
		// 计算并存储更新分数。
		update.score = &UpdateScore{
			SignerCount: uint32(update.AttestedHeader.Signature.SignerCount()), // Number of signers in the attested header's signature.
			// 被证明区块头签名中的签名者数量。
			SubPeriodIndex: uint32(update.AttestedHeader.Header.Slot & 0x1fff), // Sub-period index of the attested header's slot.
			// 被证明区块头槽位的子周期索引。
			FinalizedHeader: update.FinalizedHeader != nil, // Indicates if the update includes a finalized header.
			// 指示更新是否包含已最终确定的区块头。
		}
	}
	return *update.score // Return the calculated update score.
	// 返回计算出的更新分数。
}

// UpdateScore allows the comparison between updates at the same period in order
// to find the best update chain that provides the strongest proof of being canonical.
//
// UpdateScores have a tightly packed binary encoding format for efficient p2p
// protocol transmission. Each UpdateScore is encoded in 3 bytes.
// When interpreted as a 24 bit little indian unsigned integer:
//   - the lowest 10 bits contain the number of signers in the header signature aggregate
//   - the next 13 bits contain the "sub-period index" which is he signed header's
//     slot modulo params.SyncPeriodLength (which is correlated with the risk of the chain being
//     re-orged before the previous period boundary in case of non-finalized updates)
//   - the highest bit is set when the update is finalized (meaning that the finality
//     header referenced by the signed header is in the same period as the signed
//     header, making reorgs before the period boundary impossible
//
// UpdateScore 允许在同一周期内的更新之间进行比较，以便找到提供最强规范链证明的最佳更新链。
//
// UpdateScore 具有紧凑的二进制编码格式，用于高效的 p2p 协议传输。每个 UpdateScore 编码为 3 个字节。
// 当解释为 24 位小端无符号整数时：
//   - 最低的 10 位包含区块头签名聚合中的签名者数量
//   - 接下来的 13 位包含“子周期索引”，它是签名区块头的槽位模 params.SyncPeriodLength 的结果
//     （在非最终确定更新的情况下，这与链在先前周期边界之前被重组的风险相关）
//   - 最高位在更新被最终确定时设置（意味着签名区块头引用的最终确定区块头与签名区块头在同一周期内，
//     从而使得在周期边界之前进行重组成为不可能）
type UpdateScore struct {
	SignerCount uint32 // number of signers in the header signature aggregate
	// 区块头签名聚合中的签名者数量。
	SubPeriodIndex uint32 // signed header's slot modulo params.SyncPeriodLength
	// 签名区块头的槽位模 params.SyncPeriodLength 的结果。
	FinalizedHeader bool // update is considered finalized if has finalized header from the same period and 2/3 signatures
	// 如果更新具有来自同一周期的已最终确定的区块头且包含 2/3 的签名，则认为该更新已最终确定。
}

// finalized returns true if the update has a header signed by at least 2/3 of
// the committee, referring to a finalized header that refers to the next sync
// committee. This condition is a close approximation of the actual finality
// condition that can only be verified by full beacon nodes.
// finalized 如果更新具有由至少 2/3 的委员会签名的区块头，并且该区块头引用了引用下一个同步委员会的已最终确定的区块头，则返回 true。
// 此条件是对实际最终确定条件的近似估计，实际最终确定条件只能由完整的信标节点验证。
func (u *UpdateScore) finalized() bool {
	// Returns true if the update has a finalized header and the signer count is greater than or equal to the sync committee supermajority threshold.
	// 如果更新具有已最终确定的区块头且签名者数量大于或等于同步委员会的超级多数阈值，则返回 true。
	return u.FinalizedHeader && u.SignerCount >= params.SyncCommitteeSupermajority
}

// BetterThan returns true if update u is considered better than w.
// BetterThan 如果更新 u 被认为比 w 更好，则返回 true。
func (u UpdateScore) BetterThan(w UpdateScore) bool {
	var (
		uFinalized = u.finalized() // Check if update u is finalized.
		// 检查更新 u 是否已最终确定。
		wFinalized = w.finalized() // Check if update w is finalized.
		// 检查更新 w 是否已最终确定。
	)
	// If the finality status is different, the finalized update is considered better.
	// 如果最终确定状态不同，则已最终确定的更新被认为更好。
	if uFinalized != wFinalized {
		return uFinalized
	}
	// If both updates have the same finality status, the one with more signers is considered better.
	// 如果两个更新具有相同的最终确定状态，则签名者更多的那个被认为更好。
	return u.SignerCount > w.SignerCount
}

// HeaderWithExecProof contains a beacon header and proves the belonging execution
// payload header with a Merkle proof.
// HeaderWithExecProof 包含一个信标头，并通过 Merkle 证明证明其所属的执行负载头。
type HeaderWithExecProof struct {
	Header // The beacon header.
	// 信标头。
	PayloadHeader *ExecutionHeader // The execution payload header.
	// 执行负载头。
	PayloadBranch merkle.Values // The Merkle proof for the execution payload header.
	// 执行负载头的 Merkle 证明。
}

// Validate verifies the Merkle proof of the execution payload header.
// Validate 验证执行负载头的 Merkle 证明。
func (h *HeaderWithExecProof) Validate() error {
	// Verify the Merkle proof that the execution payload header's root is included in the beacon header's body root.
	// 验证 Merkle 证明，以确保执行负载头的根包含在信标头的 BodyRoot 中。
	return merkle.VerifyProof(h.BodyRoot, params.BodyIndexExecPayload, h.PayloadBranch, h.PayloadHeader.PayloadRoot())
}

// OptimisticUpdate proves sync committee commitment on the attested beacon header.
// It also proves the belonging execution payload header with a Merkle proof.
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
// OptimisticUpdate 证明了被证明的信标头上的同步委员会承诺。
// 它还通过 Merkle 证明证明了其所属的执行负载头。
//
// 有关数据结构定义，请参见此处：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
type OptimisticUpdate struct {
	Attested HeaderWithExecProof // The attested beacon header with execution payload proof.
	// 带有执行负载证明的被证明的信标头。
	// Sync committee BLS signature aggregate
	Signature SyncAggregate // The aggregated BLS signature from the sync committee.
	// 来自同步委员会的聚合 BLS 签名。
	// Slot in which the signature has been created (newer than Header.Slot,
	// determines the signing sync committee)
	SignatureSlot uint64 // The slot number where the signature was created.
	// 创建签名的槽位号。
}

// SignedHeader returns the signed attested header of the update.
// SignedHeader 返回更新的已签名的被证明区块头。
func (u *OptimisticUpdate) SignedHeader() SignedHeader {
	return SignedHeader{ // Construct a SignedHeader struct.
		// 构建一个 SignedHeader 结构体。
		Header: u.Attested.Header, // The beacon header.
		// 信标头。
		Signature: u.Signature, // The sync committee signature.
		// 同步委员会签名。
		SignatureSlot: u.SignatureSlot, // The slot of the signature.
		// 签名的槽位。
	}
}

// Validate verifies the Merkle proof proving the execution payload header.
// Note that the sync committee signature of the attested header should be
// verified separately by a synced committee chain.
// Validate 验证证明执行负载头的 Merkle 证明。
// 注意：被证明区块头的同步委员会签名应由同步的委员会链单独验证。
func (u *OptimisticUpdate) Validate() error {
	return u.Attested.Validate() // Validate the Merkle proof of the execution payload header.
	// 验证执行负载头的 Merkle 证明。
}

// FinalityUpdate proves a finalized beacon header by a sync committee commitment
// on an attested beacon header, referring to the latest finalized header with a
// Merkle proof.
// It also proves the execution payload header belonging to both the attested and
// the finalized beacon header with Merkle proofs.
//
// See data structure definition here:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
// FinalityUpdate 通过对被证明的信标头上的同步委员会承诺来证明已最终确定的信标头，
// 该承诺通过 Merkle 证明引用了最新的已最终确定的信标头。
// 它还通过 Merkle 证明证明了属于被证明的和已最终确定的信标头的执行负载头。
//
// 有关数据结构定义，请参见此处：
// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
type FinalityUpdate struct {
	Attested, Finalized HeaderWithExecProof // The attested and finalized beacon headers with execution payload proofs.
	// 带有执行负载证明的被证明的和已最终确定的信标头。
	FinalityBranch merkle.Values // The Merkle proof for the finalized header.
	// 已最终确定的区块头的 Merkle 证明。
	// Sync committee BLS signature aggregate
	Signature SyncAggregate // The aggregated BLS signature from the sync committee.
	// 来自同步委员会的聚合 BLS 签名。
	// Slot in which the signature has been created (newer than Header.Slot,
	// determines the signing sync committee)
	SignatureSlot uint64 // The slot number where the signature was created.
	// 创建签名的槽位号。
}

// SignedHeader returns the signed attested header of the update.
// SignedHeader 返回更新的已签名的被证明区块头。
func (u *FinalityUpdate) SignedHeader() SignedHeader {
	return SignedHeader{ // Construct a SignedHeader struct.
		// 构建一个 SignedHeader 结构体。
		Header: u.Attested.Header, // The attested beacon header.
		// 被证明的信标头。
		Signature: u.Signature, // The sync committee signature.
		// 同步委员会签名。
		SignatureSlot: u.SignatureSlot, // The slot of the signature.
		// 签名的槽位。
	}
}

// Validate verifies the Merkle proofs proving the finalized beacon header and
// the execution payload headers belonging to the attested and finalized headers.
// Note that the sync committee signature of the attested header should be
// verified separately by a synced committee chain.
// Validate 验证证明已最终确定的信标头以及属于被证明的和已最终确定的信标头的执行负载头的 Merkle 证明。
// 注意：被证明区块头的同步委员会签名应由同步的委员会链单独验证。
func (u *FinalityUpdate) Validate() error {
	// Validate the Merkle proof for the attested header's execution payload.
	// 验证被证明区块头的执行负载的 Merkle 证明。
	if err := u.Attested.Validate(); err != nil {
		return err
	}
	// Validate the Merkle proof for the finalized header's execution payload.
	// 验证已最终确定的区块头的执行负载的 Merkle 证明。
	if err := u.Finalized.Validate(); err != nil {
		return err
	}
	// Verify the Merkle proof that the finalized header is included in the state root of the attested header at the FinalBlock index.
	// 验证 Merkle 证明，以确保已最终确定的区块头包含在被证明区块头的状态根中，位于 FinalBlock 索引处。
	return merkle.VerifyProof(u.Attested.StateRoot, params.StateIndexFinalBlock, u.FinalityBranch, merkle.Value(u.Finalized.Hash()))
}

// ChainHeadEvent returns an authenticated execution payload associated with the
// latest accepted head of the beacon chain, along with the hash of the latest
// finalized execution block.
// ChainHeadEvent 返回与信标链最新接受的头相关联的经过身份验证的执行负载，以及最新最终确定的执行块的哈希。
type ChainHeadEvent struct {
	BeaconHead Header // The latest accepted head of the beacon chain.
	// 信标链最新接受的头。
	Block *ctypes.Block // The authenticated execution payload.
	// 经过身份验证的执行负载。
	Finalized common.Hash // The hash of the latest finalized execution block.
	// 最新最终确定的执行块的哈希。
}
