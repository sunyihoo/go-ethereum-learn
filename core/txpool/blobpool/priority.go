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

package blobpool

import (
	"math"
	"math/bits"

	"github.com/holiman/uint256"
)

// 交易池驱逐 (Transaction Pool Eviction)
//
// 以太坊节点维护一个交易池（也称为 Mempool），用于存放尚未被包含到区块中的待处理交易。由于内存资源有限，交易池通常会设置一个容量上限。当新的交易到达导致交易池超出容量时，节点需要根据一定的策略来决定哪些交易应该被移除。常见的驱逐策略包括基于 Gas 价格、交易到达时间、以及其他自定义的优先级规则。
//
// 影响驱逐优先级的因素
//
// 在这段代码中，驱逐优先级是基于交易的费用（Gas 价格）与当前网络的基准费用之间的差异来计算的。对于 Blob 交易，涉及到两种费用：
//
// 基础费用 (Base Fee)：这是以太坊主执行层交易的标准 Gas 费用，由 EIP-1559 引入，根据前一个区块的 Gas 使用情况动态调整。
// Blob 费用 (Blob Fee)：这是与 Blob 交易相关的额外费用，由 EIP-4844 引入，用于支付 Blob 数据的存储成本。Blob 费用也具有动态调整的机制。

// log1_125 is used in the eviction priority calculation.
// log1_125 用于驱逐优先级计算。
var log1_125 = math.Log(1.125)

// evictionPriority calculates the eviction priority based on the algorithm
// described in the BlobPool docs for both fee components.
//
// This method takes about 8ns on a very recent laptop CPU, recalculating about
// 125 million transaction priority values per second.
// evictionPriority 基于 BlobPool 文档中描述的算法，计算两种费用组成的驱逐优先级。
//
// 此方法在最新的笔记本电脑 CPU 上大约需要 8 纳秒，每秒可以重新计算大约 1.25 亿个交易优先级值。
func evictionPriority(basefeeJumps float64, txBasefeeJumps, blobfeeJumps, txBlobfeeJumps float64) int {
	var (
		basefeePriority = evictionPriority1D(basefeeJumps, txBasefeeJumps) // Calculate priority based on base fee jumps.
		// 基于基础费用跳跃计算优先级。
		blobfeePriority = evictionPriority1D(blobfeeJumps, txBlobfeeJumps) // Calculate priority based on blob fee jumps.
		// 基于 Blob 费用跳跃计算优先级。
	)
	if basefeePriority < blobfeePriority {
		return basefeePriority // Return the lower priority between base fee and blob fee.
		// 返回基础费用和 Blob 费用中较低的优先级。
	}
	return blobfeePriority
}

// evictionPriority1D calculates the eviction priority based on the algorithm
// described in the BlobPool docs for a single fee component.
// evictionPriority1D 基于 BlobPool 文档中描述的算法，计算单个费用组成的驱逐优先级。
func evictionPriority1D(basefeeJumps float64, txfeeJumps float64) int {
	jumps := txfeeJumps - basefeeJumps // Calculate the difference in fee jumps between the transaction and the base.
	// 计算交易费用跳跃与基础费用跳跃之间的差值。
	if int(jumps) == 0 {
		return 0 // can't log2 0
		// 不能对 0 取 log2。
	}
	if jumps < 0 {
		return -intLog2(uint(-math.Floor(jumps))) // Negative jumps mean lower priority.
		// 负跳跃意味着更低的优先级。
	}
	return intLog2(uint(math.Ceil(jumps))) // Positive jumps mean higher priority.
	// 正跳跃意味着更高的优先级。
}

// dynamicFeeJumps calculates the log1.125(fee), namely the number of fee jumps
// needed to reach the requested one. We only use it when calculating the jumps
// between 2 fees, so it doesn't matter from what exact number it returns.
// It returns the result from (0, 1, 1.125).
//
// This method is very expensive, taking about 75ns on a very recent laptop CPU,
// but the result does not change with the lifetime of a transaction, so it can
// be cached.
// dynamicFeeJumps 计算 log1.125(fee)，即达到请求费用所需的费用跳跃次数。我们只在计算两个费用之间的跳跃时使用它，
// 因此它从哪个确切的数字返回并不重要。它从 (0, 1, 1.125) 返回结果。
//
// 此方法非常耗时，在最新的笔记本电脑 CPU 上大约需要 75 纳秒，但结果在交易的整个生命周期内不会改变，因此可以缓存。
func dynamicFeeJumps(fee *uint256.Int) float64 {
	if fee.IsZero() {
		return 0 // can't log2 zero, should never happen outside tests, but don't choke
		// 不能对零取 log2，这在测试之外不应该发生，但不要阻塞。
	}
	return math.Log(fee.Float64()) / log1_125 // Calculate the logarithm base 1.125 of the fee.
	// 计算以 1.125 为底的费用的对数。
}

// intLog2 is a helper to calculate the integral part of a log2 of an unsigned
// integer. It is a very specific calculation that's not particularly useful in
// general, but it's what we need here (it's fast).
// intLog2 是一个辅助函数，用于计算无符号整数以 2 为底的对数的整数部分。这是一个非常具体的计算，通常不是特别有用，
// 但这是我们这里需要的（它很快）。
func intLog2(n uint) int {
	switch {
	case n == 0:
		panic("log2(0) is undefined")
		// log2(0) 是未定义的。

	case n < 2048:
		return bits.UintSize - bits.LeadingZeros(n) - 1 // Efficiently calculate floor(log2(n)).
		// 高效地计算 floor(log2(n))。

	default:
		// The input is log1.125(uint256) = log2(uint256) / log2(1.125). At the
		// most extreme, log2(uint256) will be a bit below 257, and the constant
		// log2(1.125) ~= 0.17. The larges input thus is ~257 / ~0.17 ~= ~1511.
		// 这里的输入是 log1.125(uint256) = log2(uint256) / log2(1.125)。在最极端的情况下，
		// log2(uint256) 将略低于 257，而常数 log2(1.125) ~= 0.17。因此，最大的输入约为 ~257 / ~0.17 ~= ~1511。
		panic("dynamic fee jump diffs cannot reach this")
		// 动态费用跳跃差异不应达到此值。
	}
}
