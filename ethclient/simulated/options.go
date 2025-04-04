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

package simulated

import (
	"math/big"

	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/node"
)

// 在 EIP-1559 之前，交易的 gas 价格由用户设置，矿工通常会优先打包 gas 价格较高的交易。
// EIP-1559 引入了基础费用 (Base Fee) 和小费 (Tip)。
// 基础费用由协议根据网络拥堵情况自动调整，而小费则由用户设置，用于激励矿工优先处理自己的交易。
// ethConf.Miner.GasPrice 在这里被设置为 tip，这在模拟环境中可以理解为设置矿工愿意打包交易的最低有效 gas 价格（在没有 EIP-1559 的情况下，或者作为 EIP-1559 实施后的小费）。

// WithBlockGasLimit configures the simulated backend to target a specific gas limit
// when producing blocks.
// WithBlockGasLimit 配置模拟后端在生产区块时以特定的 gas 限制为目标。
func WithBlockGasLimit(gaslimit uint64) func(nodeConf *node.Config, ethConf *ethconfig.Config) {
	return func(nodeConf *node.Config, ethConf *ethconfig.Config) {
		ethConf.Genesis.GasLimit = gaslimit
		ethConf.Miner.GasCeil = gaslimit
	}
}

// WithCallGasLimit configures the simulated backend to cap eth_calls to a specific
// gas limit when running client operations.
// WithCallGasLimit 配置模拟后端在运行客户端操作时，将 eth_calls 的 gas 限制设置为特定的值。
func WithCallGasLimit(gaslimit uint64) func(nodeConf *node.Config, ethConf *ethconfig.Config) {
	return func(nodeConf *node.Config, ethConf *ethconfig.Config) {
		ethConf.RPCGasCap = gaslimit
	}
}

// WithMinerMinTip configures the simulated backend to require a specific minimum
// gas tip for a transaction to be included.
//
// 0 is not possible as a live Geth node would reject that due to DoS protection,
// so the simulated backend will replicate that behavior for consistency.
// WithMinerMinTip 配置模拟后端，要求交易包含特定的最低 gas 小费才能被包含。
//
// 0 是不可能的，因为活动的 Geth 节点会由于 DoS 保护而拒绝它，因此模拟后端将复制该行为以保持一致性。
func WithMinerMinTip(tip *big.Int) func(nodeConf *node.Config, ethConf *ethconfig.Config) {
	if tip == nil || tip.Sign() <= 0 {
		panic("invalid miner minimum tip")
	}
	return func(nodeConf *node.Config, ethConf *ethconfig.Config) {
		ethConf.Miner.GasPrice = tip
	}
}
