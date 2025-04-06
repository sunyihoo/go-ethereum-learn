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

package vm

import (
	"github.com/ethereum/go-ethereum/params"
)

func minSwapStack(n int) int { // 计算SWAP操作的最小栈需求
	return minStack(n, n) // 调用minStack，弹出和推送数量相等
}

func maxSwapStack(n int) int { // 计算SWAP操作的最大栈需求
	return maxStack(n, n) // 调用maxStack，弹出和推送数量相等
}

func minDupStack(n int) int { // 计算DUP操作的最小栈需求
	return minStack(n, n+1) // 调用minStack，弹出n个，推送n+1个
}

func maxDupStack(n int) int { // 计算DUP操作的最大栈需求
	return maxStack(n, n+1) // 调用maxStack，弹出n个，推送n+1个
}

func maxStack(pop, push int) int { // 计算最大栈深度
	return int(params.StackLimit) + pop - push // 返回栈限制加上弹出减去推送的数量
}

func minStack(pops, push int) int { // 计算最小栈深度
	return pops // 返回弹出的数量作为最小需求
}
