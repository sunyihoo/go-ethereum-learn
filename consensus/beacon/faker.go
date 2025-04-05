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

package beacon

import (
	"math/big"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

// NewFaker creates a fake consensus engine for testing.
// The fake engine simulates a merged network.
// It can not be used to test the merge transition.
// This type is needed since the fakeChainReader can not be used with
// a normal beacon consensus engine.
// NewFaker 创建一个用于测试的假共识引擎。
// 该假引擎模拟了一个已完成合并（The Merge）的网络。
// 它不能用于测试合并过渡（merge transition）。
// 这种类型是必要的，因为 fakeChainReader 无法与普通的信标链共识引擎一起使用。
func NewFaker() consensus.Engine {
	return new(faker) // 返回一个新的 faker 实例作为共识引擎。
}

type faker struct {
	Beacon // 匿名嵌套 Beacon 类型，继承其方法和字段。
}

// CalcDifficulty 是难度调整算法。对于假引擎，返回固定的信标链难度值。
func (f *faker) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return beaconDifficulty // 返回固定的信标链难度值。
}
