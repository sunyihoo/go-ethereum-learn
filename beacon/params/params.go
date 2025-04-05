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

package params

// EpochLength: 32。这定义了一个 Epoch（纪元）的长度，以槽位（Slot）为单位。在以太坊信标链中，一个 Epoch 包含 32 个槽位，每个槽位持续 12 秒。因此，一个 Epoch 的持续时间是 32 * 12 = 384 秒（6.4 分钟）。Epoch 是信标链中许多关键操作的时间单位，例如验证者奖励和惩罚的计算、最终性的确定等。
// SyncPeriodLength: 8192。这定义了一个同步周期（Sync Period）的长度，以槽位为单位。同步委员会（Sync Committee）的成员每 SyncPeriodLength 个槽位（即 8192 * 12 秒 ≈ 27.3 小时）轮换一次。轻客户端依赖同步委员会来安全地跟踪信标链的状态。
// BLSSignatureSize: 96。这定义了 BLS 签名的字节大小。BLS (Boneh–Lynn–Shacham) 签名是一种高效的签名方案，被以太坊 2.0 用于验证者的签名和同步委员会的聚合签名。
// BLSPubkeySize: 48。这定义了 BLS 公钥的字节大小。每个验证者都拥有一个 BLS 公钥，用于验证其签名。
// SyncCommitteeSize: 512。这定义了同步委员会的成员数量。同步委员会由 512 个验证者组成，他们负责对信标链的区块进行签名，为轻客户端提供信任锚点。
// SyncCommitteeBitmaskSize: SyncCommitteeSize / 8，即 512 / 8 = 64。这定义了用于跟踪同步委员会中哪些成员参与签名的位掩码（Bitmask）的字节大小。由于同步委员会由 512 个成员组成，需要 512 位来表示每个成员是否参与签名。512 位等于 64 字节。
// SyncCommitteeSupermajority: (SyncCommitteeSize*2 + 2) / 3，即 (512 * 2 + 2) / 3 = 1026 / 3 = 342。这定义了被认为是同步委员会超级多数的签名数量阈值。通常，需要超过 2/3 的同步委员会成员签名才能认为某个状态是可信的，例如在轻客户端更新中。这个公式 (n*2 + 2) / 3 是计算大于 2/3 的最小整数的常用方法。
const (
	EpochLength      = 32
	SyncPeriodLength = 8192

	BLSSignatureSize = 96
	BLSPubkeySize    = 48

	SyncCommitteeSize          = 512
	SyncCommitteeBitmaskSize   = SyncCommitteeSize / 8
	SyncCommitteeSupermajority = (SyncCommitteeSize*2 + 2) / 3
)

// Epoch 和 Slot: 这些是信标链的基本时间单位，用于协调验证者的行为和协议的运作。
// 同步委员会 (Sync Committee): Altair 升级引入了同步委员会，这是一个小型的验证者集合，他们的签名用于轻客户端的快速和安全同步。SyncCommitteeSize 和 SyncCommitteeSupermajority 定义了其关键参数。
// BLS 签名: 以太坊 2.0 使用 BLS 签名来实现高效的签名聚合，这对于拥有大量验证者的信标链至关重要。
// 信标状态 (Beacon State): 这是信标链的核心数据结构，包含了当前区块链的状态信息，例如验证者集、余额、历史根哈希等。StateIndex 常量定义了如何通过 Merkle 证明访问状态中的特定信息。
// 信标区块主体 (Beacon Block Body): 这是信标区块中包含交易和协议相关信息的部分。BodyIndex 常量定义了如何在区块主体中定位特定的数据。
// Merkle 证明: 以太坊广泛使用 Merkle 树来高效地验证数据的完整性和存在性。通过提供 Merkle 证明，节点可以证明某个特定的数据片段是信标状态或区块主体的一部分，而无需发送整个状态或区块。

// StateIndexGenesisTime: 32。这是在信标状态的 Merkle 树中存储创世时间的索引。
// StateIndexGenesisValidators: 33。这是在信标状态的 Merkle 树中存储创世验证者列表的索引。
// StateIndexForkVersion: 141。这是在信标状态的 Merkle 树中存储当前分叉版本信息的索引。以太坊通过分叉进行协议升级，此索引指向当前激活的分叉版本。
// StateIndexLatestHeader: 36。这是在信标状态的 Merkle 树中存储最新的信标区块头的索引。
// StateIndexBlockRoots: 37。这是在信标状态的 Merkle 树中存储最近的区块根哈希历史记录的索引。
// StateIndexStateRoots: 38。这是在信标状态的 Merkle 树中存储最近的状态根哈希历史记录的索引。
// StateIndexHistoricRoots: 39。这是在信标状态的 Merkle 树中存储更久远的历史区块根和状态根哈希的根哈希的索引。
// StateIndexFinalBlock: 105。这是在信标状态的 Merkle 树中存储最终确定的区块哈希的索引。最终性是信标链的一个关键属性，表示某个区块及其之前的历史不太可能被回滚。
// StateIndexSyncCommittee: 54。这是在信标状态的 Merkle 树中存储当前同步委员会的索引。
// StateIndexNextSyncCommittee: 55。这是在信标状态的 Merkle 树中存储下一个同步委员会的索引。
// StateIndexExecPayload: 56。在合并（The Merge）之后，信标状态中包含了对执行负载（Execution Payload）的承诺。此索引指向存储该承诺的 Merkle 树节点。
// StateIndexExecHead: 908。这是在信标状态的 Merkle 树中存储最新的执行引擎头的索引。
// BodyIndexExecPayload: 25。这是在信标区块主体的 Merkle 树中存储执行负载的索引。信标区块头中的 BodyRoot 是对信标区块主体的 Merkle 树根的承诺，通过此索引可以证明区块主体中包含了特定的执行负载。
const (
	StateIndexGenesisTime       = 32
	StateIndexGenesisValidators = 33
	StateIndexForkVersion       = 141
	StateIndexLatestHeader      = 36
	StateIndexBlockRoots        = 37
	StateIndexStateRoots        = 38
	StateIndexHistoricRoots     = 39
	StateIndexFinalBlock        = 105
	StateIndexSyncCommittee     = 54
	StateIndexNextSyncCommittee = 55
	StateIndexExecPayload       = 56
	StateIndexExecHead          = 908

	BodyIndexExecPayload = 25
)
