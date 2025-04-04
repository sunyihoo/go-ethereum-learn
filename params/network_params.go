// Copyright 2017 The go-ethereum Authors
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

// 布隆过滤器支持：BloomBitsBlocks 和 BloomConfirms 用于高效查询历史日志（logs），支持轻客户端和服务器端数据服务。
// 链段不可变性：FullImmutabilityThreshold 定义了链段被视为“不可变”的区块深度，用于优化同步、防止重组和数据存储。
// 以太坊背景
// 布隆过滤器（Bloom Filter）：以太坊使用布隆过滤器存储区块中的事件日志（logs），以便快速查询交易收据中的事件数据。BloomBits 是布隆过滤器的分段表示，用于服务器端索引。
// 软终局性（Soft Finality）：以太坊的 PoW（工作量证明）或 PoS（权益证明）机制中，区块并非立即“最终确定”（finalized）。随着区块深度增加，其被重组的可能性降低，FullImmutabilityThreshold 定义了这种“软终局性”的阈值。
// 客户端同步：以太坊节点通过下载器（downloader）和冻结器（freezer）管理链数据，这些参数确保同步和存储逻辑一致。

// These are network parameters that need to be constant between clients, but
// aren't necessarily consensus related.
// 这些是客户端之间需要保持一致的网络参数，但并不一定与共识机制相关。
const (
	// BloomBitsBlocks is the number of blocks a single bloom bit section vector
	// contains on the server side.
	// BloomBitsBlocks 是服务器端单个布隆位段向量包含的区块数。
	// 布隆位段（Bloom Bits）：
	// 以太坊区块头的 logsBloom 字段是一个 256 字节（2048 位）的布隆过滤器，记录该区块中所有日志的索引。
	// BloomBits 是将多个区块的 logsBloom 数据按位（bit-wise）分段存储的向量，每个向量覆盖固定数量的区块（这里是 4096）。
	BloomBitsBlocks uint64 = 4096

	// BloomConfirms is the number of confirmation blocks before a bloom section is
	// considered probably final and its rotated bits are calculated.
	// BloomConfirms 是布隆段在被认为可能最终确定并计算其旋转位之前的确认区块数。
	//确认机制：
	//在生成 BloomBits 时，客户端等待 256 个后续区块确认，以降低因链重组而导致数据无效的风险。
	//确认后，计算“旋转位”（rotated bits），即对布隆过滤器数据进行某种变换或索引优化。
	BloomConfirms = 256

	// FullImmutabilityThreshold is the number of blocks after which a chain segment is
	// considered immutable (i.e. soft finality). It is used by the downloader as a
	// hard limit against deep ancestors, by the blockchain against deep reorgs, by
	// the freezer as the cutoff threshold and by clique as the snapshot trust limit.
	// FullImmutabilityThreshold 是链段被认为不可变（即软终局性）所需的区块数。
	// 它被下载器用作防止深度祖先的硬限制，被区块链用作防止深度重组的限制，
	// 被冻结器用作截止阈值，被 Clique 共识用作快照信任限制。
	//
	// 软终局性：
	//  在 90000 个区块（约 15 天，假设 15 秒/块）后，链段被认为极不可能发生重组，达到“软终局性”。
	// 多组件应用：
	//   下载器（Downloader）：限制同步时追溯的深度，避免处理过深的祖先区块。
	//   区块链（Blockchain）：防止深度重组（deep reorgs），确保状态一致性。
	//   冻结器（Freezer）：将早于 90000 块的数据存入冷存储（不可变数据），减少活跃数据库负担。
	// Clique 共识：在 Clique PoA（权威证明）中，90000 块是快照信任的阈值，限制历史状态回滚。
	//
	// 重组与终局性：PoW 中重组深度受算力和网络条件影响，90000 块（约 2 周）远超典型重组范围。
	// 冻结器：以太坊客户端将旧数据“冻结”到只读文件中，优化性能，90000 是一个经验阈值。
	// Clique：以太坊的 PoA 共识机制，90000 块限制了快照回溯深度，增强安全性。
	FullImmutabilityThreshold = 90000
)
