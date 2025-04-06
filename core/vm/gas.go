// Copyright 2015 The go-ethereum Authors
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

package vm

import (
	"github.com/holiman/uint256"
)

// Gas costs
// Gas成本
const (
	GasQuickStep   uint64 = 2  // 快速步骤的Gas成本
	GasFastestStep uint64 = 3  // 最快步骤的Gas成本
	GasFastishStep uint64 = 4  // 较快步骤的Gas成本
	GasFastStep    uint64 = 5  // 快步骤的Gas成本
	GasMidStep     uint64 = 8  // 中等步骤的Gas成本
	GasSlowStep    uint64 = 10 // 慢步骤的Gas成本
	GasExtStep     uint64 = 20 // 扩展步骤的Gas成本
)

// callGas returns the actual gas cost of the call.
//
// The cost of gas was changed during the homestead price change HF.
// As part of EIP 150 (TangerineWhistle), the returned gas is gas - base * 63 / 64.
// callGas 返回调用的实际Gas成本。
//
// Gas成本在Homestead价格变更硬分叉期间发生了变化。
// 作为EIP 150（TangerineWhistle）的一部分，返回的Gas是 gas - base * 63 / 64。
func callGas(isEip150 bool, availableGas, base uint64, callCost *uint256.Int) (uint64, error) { // 计算调用Gas成本的函数
	if isEip150 { // 如果启用了EIP-150
		availableGas = availableGas - base    // 减去基础Gas成本
		gas := availableGas - availableGas/64 // 计算EIP-150调整后的Gas：保留63/64的部分
		// If the bit length exceeds 64 bit we know that the newly calculated "gas" for EIP150
		// is smaller than the requested amount. Therefore we return the new gas instead
		// of returning an error.
		// 如果位长度超过64位，我们知道为EIP-150新计算的“gas”小于请求的量。因此我们返回新的Gas而不是错误。
		if !callCost.IsUint64() || gas < callCost.Uint64() { // 如果callCost不是uint64或新Gas小于请求值
			return gas, nil // 返回调整后的Gas
		}
	}
	if !callCost.IsUint64() { // 如果callCost无法转换为uint64
		return 0, ErrGasUintOverflow // 返回Gas溢出错误
	}

	return callCost.Uint64(), nil // 返回请求的Gas成本
}
