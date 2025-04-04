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

// These are the multipliers for ether denominations.
// Example: To get the wei value of an amount in 'gwei', use
//
//	new(big.Int).Mul(value, big.NewInt(params.GWei))
//
// 这些是以太币单位的乘数。
// 示例：要获取以 'gwei' 为单位的数量的 wei 值，使用
//
//	new(big.Int).Mul(value, big.NewInt(params.GWei))
const (
	Wei   = 1    // Wei 是以太坊的最小单位，值为 1
	GWei  = 1e9  // GWei 是 10亿 Wei，即 1,000,000,000 Wei
	Ether = 1e18 // Ether 是 1万亿亿 Wei，即 1,000,000,000,000,000,000 Wei
)
