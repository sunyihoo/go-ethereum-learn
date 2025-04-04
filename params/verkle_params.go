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

package params

// 以太坊背景：Verkle Tree 和 EIP-4762
// Verkle Tree：Verkle 树是以太坊计划引入的一种新型状态树结构，旨在替代当前的 Merkle Patricia Trie（MPT）。它使用向量承诺（Vector Commitments）来显著减少状态证明（witness）的大小，从而提高同步效率和降低存储需求。
// EIP-4762：这是提议将 Verkle 树集成到以太坊执行层的改进提案（Ethereum Improvement Proposal）。它定义了新的 Gas 计费规则，以反映 Verkle 树中状态访问的计算成本。
// 见证（Witness）：在 Verkle 树中，见证是证明特定状态（如账户余额或存储槽）存在的加密数据。访问和修改状态需要读取或写入分支（branch）和块（chunk），这些操作的成本由上述常量定义。
// 历史重放：在以太坊客户端（如 go-ethereum）中，重放历史区块是验证链状态一致性的重要步骤。由于 Verkle 树是未来升级，在重放旧区块时需要禁用相关成本。
// 历史重放：以太坊客户端需要从创世区块开始重放所有交易，以验证状态树的一致性。Verkle 树引入后，旧区块的状态访问逻辑（基于 MPT）与新逻辑（基于 Verkle）不兼容，因此需要禁用新成本。

// Verkle tree EIP: costs associated to witness accesses
// Verkle 树 EIP：与见证访问相关的成本
var (
	WitnessBranchReadCost  uint64 = 1900 // 见证分支读取成本
	WitnessChunkReadCost   uint64 = 200  // 见证块读取成本
	WitnessBranchWriteCost uint64 = 3000 // 见证分支写入成本
	WitnessChunkWriteCost  uint64 = 500  // 见证块写入成本
	WitnessChunkFillCost   uint64 = 6200 // 见证块填充成本
)

// ClearVerkleWitnessCosts sets all witness costs to 0, which is necessary
// for historical block replay simulations.
// ClearVerkleWitnessCosts 将所有见证成本设置为 0，这对于历史区块重放模拟是必要的。
func ClearVerkleWitnessCosts() {
	WitnessBranchReadCost = 0  // 将见证分支读取成本设为 0
	WitnessChunkReadCost = 0   // 将见证块读取成本设为 0
	WitnessBranchWriteCost = 0 // 将见证分支写入成本设为 0
	WitnessChunkWriteCost = 0  // 将见证块写入成本设为 0
	WitnessChunkFillCost = 0   // 将见证块填充成本设为 0
}
