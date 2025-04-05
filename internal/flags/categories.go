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

package flags

import "github.com/urfave/cli/v2"

// BeaconCategory：指的是以太坊 2.0 的 Beacon Chain（信标链），它是 PoS（权益证明）共识机制的核心，负责管理验证者、区块提议和分片协调。
// TxPoolCategory 和 BlobPoolCategory：交易池分别存储待处理的 EVM 交易和 Blob 交易。Blob 交易源自 EIP-4844（Proto-Danksharding），旨在通过引入 Blob 数据降低 Layer 2 Rollup 的成本。
// GasPriceCategory：Gas Price Oracle 是一个提供 Gas 价格建议的机制，帮助用户根据网络拥堵情况设置合理的交易费用。

// Beacon Chain（信标链）
// 背景：信标链是以太坊从 PoW（工作量证明）转向 PoS 的关键组件，引入于 2020 年 12 月的以太坊 2.0 第一阶段。
// 作用：管理验证者注册、随机分配职责、协调分片数据。
// EIP-4844 和 Blob 交易
// 背景：EIP-4844 提出了一种新的交易类型（Blob 交易），用于存储大块数据（约 128 KB），旨在降低 Rollup 的数据存储成本。
// 关联：BlobPoolCategory 表明代码支持处理这类交易。
// Gas Price Oracle
// 背景：Gas 是以太坊执行交易和智能合约的燃料，Gas Price Oracle 根据历史数据和网络状态提供价格建议。
// 作用：帮助用户避免过高或过低的 Gas 费用。

const (
	// EthCategory 是与以太坊相关的标志的类别。
	EthCategory = "ETHEREUM"
	// BeaconCategory 是与 Beacon Chain 相关的标志的类别。
	BeaconCategory = "BEACON CHAIN"
	// DevCategory 是与 Developer Chain 相关的标志的类别。
	DevCategory = "DEVELOPER CHAIN"
	// StateCategory 是与 State History Management 相关的标志的类别。
	StateCategory = "STATE HISTORY MANAGEMENT"
	// TxPoolCategory 是与 Transaction Pool (EVM) 相关的标志的类别。
	TxPoolCategory = "TRANSACTION POOL (EVM)"
	// BlobPoolCategory 是与 Transaction Pool (BLOB) 相关的标志的类别。
	BlobPoolCategory = "TRANSACTION POOL (BLOB)"
	// PerfCategory 是与 Performance Tuning 相关的标志的类别。
	PerfCategory = "PERFORMANCE TUNING"
	// AccountCategory 是与 Account 相关的标志的类别。
	AccountCategory = "ACCOUNT"
	// APICategory 是与 API and Console 相关的标志的类别。
	APICategory = "API AND CONSOLE"
	// NetworkingCategory 是与 Networking 相关的标志的类别。
	NetworkingCategory = "NETWORKING"
	// MinerCategory 是与 Miner 相关的标志的类别。
	MinerCategory = "MINER"
	// GasPriceCategory 是与 Gas Price Oracle 相关的标志的类别。
	GasPriceCategory = "GAS PRICE ORACLE"
	// VMCategory 是与 Virtual Machine 相关的标志的类别。
	VMCategory = "VIRTUAL MACHINE"
	// LoggingCategory 是与 Logging and Debugging 相关的标志的类别。
	LoggingCategory = "LOGGING AND DEBUGGING"
	// MetricsCategory 是与 Metrics and Stats 相关的标志的类别。
	MetricsCategory = "METRICS AND STATS"
	// MiscCategory 是与 Miscellaneous 相关的标志的类别。
	MiscCategory = "MISC"
	// TestingCategory 是与 Testing 相关的标志的类别。
	TestingCategory = "TESTING"
	// DeprecatedCategory 是与 Aliased (deprecated) 相关的标志的类别。
	DeprecatedCategory = "ALIASED (deprecated)"
)

func init() {
	// 将帮助标志的类别设置为 MiscCategory。
	cli.HelpFlag.(*cli.BoolFlag).Category = MiscCategory
	// 将版本标志的类别设置为 MiscCategory。
	cli.VersionFlag.(*cli.BoolFlag).Category = MiscCategory
}
