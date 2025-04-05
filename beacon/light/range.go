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

package light

// periodRange represents a (possibly zero-length) range of integers (sync periods).
// periodRange 表示一个（可能长度为零）的整数范围（同步周期）。
type periodRange struct {
	Start, End uint64 // 范围的起始和结束周期
}

// isEmpty returns true if the length of the range is zero.
// isEmpty 返回 true 如果范围的长度为零。
func (a periodRange) isEmpty() bool {
	return a.End == a.Start // 如果起始周期等于结束周期，则范围为空
}

// contains returns true if the range includes the given period.
// contains 返回 true 如果范围包含给定的周期。
func (a periodRange) contains(period uint64) bool {
	return period >= a.Start && period < a.End // 检查周期是否在范围内
}

// canExpand returns true if the range includes or can be expanded with the given
// period (either the range is empty or the given period is inside, right before or
// right after the range).
// canExpand 返回 true 如果范围包含或可以扩展到给定的周期（范围为空，或者给定的周期在范围内、紧邻之前或紧邻之后）。
func (a periodRange) canExpand(period uint64) bool {
	return a.isEmpty() || (period+1 >= a.Start && period <= a.End)
}

// expand expands the range with the given period.
// This method assumes that canExpand returned true: otherwise this is a no-op.
// expand 用给定的周期扩展范围。
// 此方法假定 canExpand 返回 true：否则该操作无效。
func (a *periodRange) expand(period uint64) {
	if a.isEmpty() {
		a.Start, a.End = period, period+1 // 如果范围为空，初始化为单个周期
		return
	}
	if a.Start == period+1 {
		a.Start-- // 如果给定周期紧邻范围之前，向左扩展
	}
	if a.End == period {
		a.End++ // 如果给定周期紧邻范围之后，向右扩展
	}
}

// split splits the range into two ranges. The 'fromPeriod' will be the first
// element in the second range (if present).
// The original range is unchanged by this operation.
// split 将范围拆分为两个范围。`fromPeriod` 将是第二个范围的第一个元素（如果存在）。
// 原始范围在该操作中保持不变。
func (a *periodRange) split(fromPeriod uint64) (periodRange, periodRange) {
	if fromPeriod <= a.Start {
		// First range empty, everything in second range,
		// 第一个范围为空，所有内容都在第二个范围中，
		return periodRange{}, *a
	}
	if fromPeriod >= a.End {
		// Second range empty, everything in first range,
		// 第二个范围为空，所有内容都在第一个范围中，
		return *a, periodRange{}
	}
	x := periodRange{a.Start, fromPeriod} // 第一个范围从 Start 到 fromPeriod
	y := periodRange{fromPeriod, a.End}   // 第二个范围从 fromPeriod 到 End
	return x, y
}

// each invokes the supplied function fn once per period in range.
// each 对范围内的每个周期调用一次提供的函数 fn。
func (a *periodRange) each(fn func(uint64)) {
	for p := a.Start; p < a.End; p++ { // 遍历范围内的每个周期
		fn(p) // 调用回调函数
	}
}
