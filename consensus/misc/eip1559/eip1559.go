// Copyright 2021 The go-ethereum Authors
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

package eip1559

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// 1. EIP-1559 的核心机制
// 动态基础费用（Base Fee） ：EIP-1559 引入了动态调整的基础费用机制，旨在通过市场供需关系优化交易费用。基础费用由父区块的 GasUsed 和 GasTarget 决定。
// 如果父区块的 GasUsed 超过目标值，基础费用增加。
// 如果父区块的 GasUsed 低于目标值，基础费用减少。
// 弹性气体限制 ：ElasticityMultiplier 参数允许气体限制在一定范围内波动，从而适应网络负载的变化。
// 2. VerifyEIP1559Header 的功能
// 气体限制检查 ：确保新区块的气体限制在允许范围内，避免极端值导致网络不稳定。
// 基础费用验证 ：根据父区块的头部信息计算预期的基础费用，并与新区块的实际基础费用进行比较，确保一致性。

// VerifyEIP1559Header verifies some header attributes which were changed in EIP-1559,
// - gas limit check
// - basefee check
// VerifyEIP1559Header 验证在 EIP-1559 中更改的一些区块头部属性：
// - 气体限制检查
// - 基础费用（baseFee）检查
func VerifyEIP1559Header(config *params.ChainConfig, parent, header *types.Header) error {
	// Verify that the gas limit remains within allowed bounds
	// 验证气体限制是否保持在允许范围内
	parentGasLimit := parent.GasLimit
	if !config.IsLondon(parent.Number) {
		parentGasLimit = parent.GasLimit * config.ElasticityMultiplier()
	}
	if err := misc.VerifyGaslimit(parentGasLimit, header.GasLimit); err != nil {
		return err
	}
	// Verify the header is not malformed
	// 验证头部未被恶意构造
	if header.BaseFee == nil {
		return errors.New("header is missing baseFee") // 如果缺少 baseFee，返回错误
	}
	// Verify the baseFee is correct based on the parent header.
	// 根据父区块头部验证 baseFee 是否正确。
	expectedBaseFee := CalcBaseFee(config, parent)
	if header.BaseFee.Cmp(expectedBaseFee) != 0 {
		return fmt.Errorf("invalid baseFee: have %s, want %s, parentBaseFee %s, parentGasUsed %d",
			header.BaseFee, expectedBaseFee, parent.BaseFee, parent.GasUsed)
	}
	return nil
}

// CalcBaseFee calculates the basefee of the header.
// CalcBaseFee 计算区块头部的基础费用（baseFee）。
func CalcBaseFee(config *params.ChainConfig, parent *types.Header) *big.Int {
	// If the current block is the first EIP-1559 block, return the InitialBaseFee.
	// 如果当前区块是第一个 EIP-1559 区块，返回初始基础费用（InitialBaseFee）。
	if !config.IsLondon(parent.Number) {
		return new(big.Int).SetUint64(params.InitialBaseFee)
	}

	parentGasTarget := parent.GasLimit / config.ElasticityMultiplier()
	// If the parent gasUsed is the same as the target, the baseFee remains unchanged.
	// 如果父区块使用的气体量等于目标值，则基础费用保持不变。
	if parent.GasUsed == parentGasTarget {
		return new(big.Int).Set(parent.BaseFee)
	}

	var (
		num   = new(big.Int) // 分子
		denom = new(big.Int) // 分母
	)

	if parent.GasUsed > parentGasTarget {
		// If the parent block used more gas than its target, the baseFee should increase.
		// max(1, parentBaseFee * gasUsedDelta / parentGasTarget / baseFeeChangeDenominator)
		// 如果父区块使用的气体量超过目标值，基础费用应增加。
		num.SetUint64(parent.GasUsed - parentGasTarget)
		num.Mul(num, parent.BaseFee)
		num.Div(num, denom.SetUint64(parentGasTarget))
		num.Div(num, denom.SetUint64(config.BaseFeeChangeDenominator()))
		if num.Cmp(common.Big1) < 0 {
			return num.Add(parent.BaseFee, common.Big1) // 最小增加值为 1
		}
		return num.Add(parent.BaseFee, num)
	} else {
		// Otherwise if the parent block used less gas than its target, the baseFee should decrease.
		// max(0, parentBaseFee * gasUsedDelta / parentGasTarget / baseFeeChangeDenominator)
		// 如果父区块使用的气体量低于目标值，基础费用应减少。
		num.SetUint64(parentGasTarget - parent.GasUsed)
		num.Mul(num, parent.BaseFee)
		num.Div(num, denom.SetUint64(parentGasTarget))
		num.Div(num, denom.SetUint64(config.BaseFeeChangeDenominator()))

		baseFee := num.Sub(parent.BaseFee, num)
		if baseFee.Cmp(common.Big0) < 0 {
			baseFee = common.Big0 // 基础费用最小值为 0
		}
		return baseFee
	}
}
