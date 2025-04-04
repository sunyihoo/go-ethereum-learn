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

package forks

// 以太坊通过硬分叉（hard fork）引入重大协议变更，这些变更通常涉及新的功能、性能优化或安全修复。
// 每个分叉都有一个名称（通常是城市名或特定术语），并在特定区块高度激活。
// 分叉的实现需要客户端软件（如 go-ethereum）识别当前区块对应的分叉版本，以便应用正确的规则。例如：
//
// 状态转换规则：某些 EIP（如 EIP-1559）改变了交易费机制。
// 共识机制：巴黎分叉（The Merge）将以太坊从工作量证明（PoW）切换到权益证明（PoS）。

// Fork is a numerical identifier of specific network upgrades (forks).
// Fork 是特定网络升级（分叉）的数字标识符。
type Fork int

const (
	// Frontier 表示以太坊网络的初始版本，以太坊网络的首次发布（2015年7月30日），标志着主网启动。
	Frontier = iota
	// FrontierThawing 表示初始解冻阶段，解冻阶段，允许创世块中冻结的资金提取。
	FrontierThawing
	// Homestead 表示以太坊的第二个主要版本，第一个稳定版本（2016年3月14日），引入新功能和改进。
	Homestead
	// DAO 表示因 DAO 攻击而实施的分叉，因 DAO 攻击（2016年7月20日）而实施的紧急分叉，恢复被盗资金。
	DAO
	// TangerineWhistle 表示修复 gas 成本漏洞的分叉，修复 gas 成本漏洞（2016年10月18日，EIP-150）。
	TangerineWhistle
	// SpuriousDragon 表示清理状态和防止重放攻击的分叉，清理状态并防止重放攻击（2016年11月22日，EIP-155 等）。
	SpuriousDragon
	// Byzantium 表示 Metropolis 升级的一部分，Metropolis 升级的一部分（2017年10月16日），引入 zk-SNARKs 等功能（EIP-198）。
	Byzantium
	// Constantinople 表示 Metropolis 升级的另一部分，Metropolis 的第二部分（2019年2月28日），优化 gas 成本（EIP-1234）。
	Constantinople
	// Petersburg 表示修复 Constantinople 中问题的分叉，修复 Constantinople 中的问题（2019年2月28日，移除 EIP-1283）。
	Petersburg
	// Istanbul 表示性能提升和互操作性改进的分叉，提升性能和互操作性（2019年12月8日，EIP-152）。
	Istanbul
	// MuirGlacier 表示延迟难度炸弹的分叉，延迟难度炸弹（2020年1月2日，EIP-2384）。
	MuirGlacier
	// Berlin 表示优化 gas 成本和交易类型的分叉，优化 gas 和交易类型（2021年4月15日，EIP-2930）。
	Berlin
	// London 表示引入 EIP-1559 的主要升级，引入 EIP-1559（2021年8月5日），改革交易费市场。
	London
	// ArrowGlacier 表示再次延迟难度炸弹的分叉，再次延迟难度炸弹（2021年12月9日，EIP-4345）。
	ArrowGlacier
	// GrayGlacier 表示进一步延迟难度炸弹的分叉，进一步延迟难度炸弹（2022年6月30日，EIP-5133）。
	GrayGlacier
	// Paris 表示以太坊从 PoW 转为 PoS 的合并（The Merge），The Merge（2022年9月15日），从 PoW 切换到 PoS（EIP-3675）。
	Paris
	// Shanghai 表示启用质押 ETH 提款的分叉，启用质押 ETH 提款（2023年4月12日，EIP-4895）。
	Shanghai
	// Cancun 表示引入分片 blob 交易的分叉（EIP-4844），引入分片 blob 交易（2024年3月13日，EIP-4844）。
	Cancun
	// Prague 表示计划中的未来分叉，计划中的未来分叉，可能包含新的 EIP（如 Verkle Trees）。
	Prague
)
