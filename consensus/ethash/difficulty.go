// Copyright 2020 The go-ethereum Authors
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

package ethash

import (
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

const (
	// frontierDurationLimit is for Frontier:
	// The decision boundary on the blocktime duration used to determine
	// whether difficulty should go up or down.
	// frontierDurationLimit 用于 Frontier：
	// 决定区块时间间隔的边界，用于判断难度是否应上升或下降。
	frontierDurationLimit = 13

	// minimumDifficulty The minimum that the difficulty may ever be.
	// minimumDifficulty 难度的最小值。
	minimumDifficulty = 131072

	// expDiffPeriod is the exponential difficulty period
	// expDiffPeriod 是指数难度周期。
	expDiffPeriodUint = 100000

	// difficultyBoundDivisorBitShift is the bound divisor of the difficulty (2048),
	// This constant is the right-shifts to use for the division.
	// difficultyBoundDivisorBitShift 是难度的边界除数（2048），
	// 此常量是用于除法操作的右移位数。
	difficultyBoundDivisor = 11
)

// CalcDifficultyFrontierU256 is the difficulty adjustment algorithm. It returns the
// difficulty that a new block should have when created at time given the parent
// block's time and difficulty. The calculation uses the Frontier rules.
// CalcDifficultyFrontierU256 是难度调整算法。它返回在给定父区块时间和难度的情况下，
// 新区块在指定时间创建时应有的难度。该计算使用 Frontier 规则。
func CalcDifficultyFrontierU256(time uint64, parent *types.Header) *big.Int {
	/*
		Algorithm
		block_diff = pdiff + pdiff / 2048 * (1 if time - ptime < 13 else -1) + int(2^((num // 100000) - 2))

		Where:
		- pdiff  = parent.difficulty
		- ptime = parent.time
		- time = block.timestamp
		- num = block.number
	*/

	pDiff, _ := uint256.FromBig(parent.Difficulty) // pDiff: pdiff
	adjust := pDiff.Clone()
	adjust.Rsh(adjust, difficultyBoundDivisor) // adjust: pDiff / 2048

	if time-parent.Time < frontierDurationLimit {
		pDiff.Add(pDiff, adjust)
	} else {
		pDiff.Sub(pDiff, adjust)
	}
	if pDiff.LtUint64(minimumDifficulty) {
		pDiff.SetUint64(minimumDifficulty)
	}
	// 'pdiff' now contains:
	// pdiff + pdiff / 2048 * (1 if time - ptime < 13 else -1)

	if periodCount := (parent.Number.Uint64() + 1) / expDiffPeriodUint; periodCount > 1 {
		// diff = diff + 2^(periodCount - 2)
		expDiff := adjust.SetOne()
		expDiff.Lsh(expDiff, uint(periodCount-2)) // expdiff: 2 ^ (periodCount -2)
		pDiff.Add(pDiff, expDiff)
	}
	return pDiff.ToBig()
}

// CalcDifficultyHomesteadU256 is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Homestead rules.
// CalcDifficultyHomesteadU256 是难度调整算法。它返回在给定父区块时间和难度的情况下，
// 新区块在指定时间创建时应有的难度。该计算使用 Homestead 规则。
func CalcDifficultyHomesteadU256(time uint64, parent *types.Header) *big.Int {
	/*
		https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
		Algorithm:
		block_diff = pdiff + pdiff / 2048 * max(1 - (time - ptime) / 10, -99) + 2 ^ int((num / 100000) - 2))

		Our modification, to use unsigned ints:
		block_diff = pdiff - pdiff / 2048 * max((time - ptime) / 10 - 1, 99) + 2 ^ int((num / 100000) - 2))

		Where:
		- pdiff  = parent.difficulty
		- ptime = parent.time
		- time = block.timestamp
		- num = block.number
	*/

	pDiff, _ := uint256.FromBig(parent.Difficulty) // pDiff: pdiff
	adjust := pDiff.Clone()
	adjust.Rsh(adjust, difficultyBoundDivisor) // adjust: pDiff / 2048

	x := (time - parent.Time) / 10 // (time - ptime) / 10)
	var neg = true
	if x == 0 {
		x = 1
		neg = false
	} else if x >= 100 {
		x = 99
	} else {
		x = x - 1
	}
	z := new(uint256.Int).SetUint64(x)
	adjust.Mul(adjust, z) // adjust: (pdiff / 2048) * max((time - ptime) / 10 - 1, 99)
	if neg {
		pDiff.Sub(pDiff, adjust) // pdiff - pdiff / 2048 * max((time - ptime) / 10 - 1, 99)
	} else {
		pDiff.Add(pDiff, adjust) // pdiff + pdiff / 2048 * max((time - ptime) / 10 - 1, 99)
	}
	if pDiff.LtUint64(minimumDifficulty) {
		pDiff.SetUint64(minimumDifficulty)
	}
	// for the exponential factor, a.k.a "the bomb"
	// diff = diff + 2^(periodCount - 2)
	if periodCount := (1 + parent.Number.Uint64()) / expDiffPeriodUint; periodCount > 1 {
		expFactor := adjust.Lsh(adjust.SetOne(), uint(periodCount-2))
		pDiff.Add(pDiff, expFactor)
	}
	return pDiff.ToBig()
}

// MakeDifficultyCalculatorU256 creates a difficultyCalculator with the given bomb-delay.
// the difficulty is calculated with Byzantium rules, which differs from Homestead in
// how uncles affect the calculation
// MakeDifficultyCalculatorU256 创建一个带有给定难度炸弹延迟的难度计算器。
// 该难度按照拜占庭规则计算，与 Homestead 的区别在于叔块如何影响计算。
func MakeDifficultyCalculatorU256(bombDelay *big.Int) func(time uint64, parent *types.Header) *big.Int {
	// Note, the calculations below looks at the parent number, which is 1 below
	// the block number. Thus we remove one from the delay given
	// 注意，以下计算查看的是父区块号，比当前区块号小 1。因此我们从给定延迟中减去 1。
	bombDelayFromParent := bombDelay.Uint64() - 1
	return func(time uint64, parent *types.Header) *big.Int {
		/*
			https://github.com/ethereum/EIPs/issues/100
			pDiff = parent.difficulty
			BLOCK_DIFF_FACTOR = 9
			a = pDiff + (pDiff // BLOCK_DIFF_FACTOR) * adj_factor
			b = min(parent.difficulty, MIN_DIFF)
			child_diff = max(a,b )
		*/
		x := (time - parent.Time) / 9 // (block_timestamp - parent_timestamp) // 9
		c := uint64(1)                // if parent.unclehash == emptyUncleHashHash
		if parent.UncleHash != types.EmptyUncleHash {
			c = 2
		}
		xNeg := x >= c
		if xNeg {
			// x is now _negative_ adjustment factor
			x = x - c // - ( (t-p)/p -( 2 or 1) )
		} else {
			x = c - x // (2 or 1) - (t-p)/9
		}
		if x > 99 {
			x = 99 // max(x, 99)
		}
		// parent_diff + (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
		y := new(uint256.Int)
		y.SetFromBig(parent.Difficulty)    // y: p_diff
		pDiff := y.Clone()                 // pdiff: p_diff
		z := new(uint256.Int).SetUint64(x) //z : +-adj_factor (either pos or negative)
		y.Rsh(y, difficultyBoundDivisor)   // y: p__diff / 2048
		z.Mul(y, z)                        // z: (p_diff / 2048 ) * (+- adj_factor)

		if xNeg {
			y.Sub(pDiff, z) // y: parent_diff + parent_diff/2048 * adjustment_factor
		} else {
			y.Add(pDiff, z) // y: parent_diff + parent_diff/2048 * adjustment_factor
		}
		// minimum difficulty can ever be (before exponential factor)
		if y.LtUint64(minimumDifficulty) {
			y.SetUint64(minimumDifficulty)
		}
		// calculate a fake block number for the ice-age delay
		// Specification: https://eips.ethereum.org/EIPS/eip-1234
		var pNum = parent.Number.Uint64()
		if pNum >= bombDelayFromParent {
			if fakeBlockNumber := pNum - bombDelayFromParent; fakeBlockNumber >= 2*expDiffPeriodUint {
				z.SetOne()
				z.Lsh(z, uint(fakeBlockNumber/expDiffPeriodUint-2))
				y.Add(z, y)
			}
		}
		return y.ToBig()
	}
}
