// Copyright 2014 The go-ethereum Authors
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
	"sync"

	"github.com/holiman/uint256"
)

var stackPool = sync.Pool{ // 栈对象池
	New: func() interface{} { // 新建函数
		return &Stack{data: make([]uint256.Int, 0, 16)} // 创建初始容量为16的栈
	},
}

// Stack is an object for basic stack operations. Items popped to the stack are
// expected to be changed and modified. stack does not take care of adding newly
// initialized objects.
// Stack 是一个用于基本栈操作的对象。从栈中弹出的项预计会被更改和修改。
// 栈不负责添加新初始化的对象。
type Stack struct {
	data []uint256.Int // 栈数据，存储uint256整数
}

func newstack() *Stack { // 创建新栈
	return stackPool.Get().(*Stack) // 从对象池获取栈实例
}

func returnStack(s *Stack) { // 归还栈
	s.data = s.data[:0] // 清空栈数据
	stackPool.Put(s)    // 将栈放回对象池
}

// Data returns the underlying uint256.Int array.
// Data 返回底层的uint256.Int数组。
func (st *Stack) Data() []uint256.Int { // 获取栈数据
	return st.data // 返回栈的底层数组
}

func (st *Stack) push(d *uint256.Int) { // 入栈
	// NOTE push limit (1024) is checked in baseCheck
	// 注意：推送限制（1024）在baseCheck中检查
	st.data = append(st.data, *d) // 将数据追加到栈中
}

func (st *Stack) pop() (ret uint256.Int) { // 出栈
	ret = st.data[len(st.data)-1]      // 获取栈顶元素
	st.data = st.data[:len(st.data)-1] // 移除栈顶元素
	return                             // 返回弹出的元素
}

func (st *Stack) len() int { // 获取栈长度
	return len(st.data) // 返回当前栈的元素数量
}

func (st *Stack) swap1() { // 交换栈顶和倒数第1个元素
	st.data[st.len()-2], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-2] // 交换位置
}
func (st *Stack) swap2() { // 交换栈顶和倒数第2个元素
	st.data[st.len()-3], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-3] // 交换位置
}
func (st *Stack) swap3() { // 交换栈顶和倒数第3个元素
	st.data[st.len()-4], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-4] // 交换位置
}
func (st *Stack) swap4() { // 交换栈顶和倒数第4个元素
	st.data[st.len()-5], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-5] // 交换位置
}
func (st *Stack) swap5() { // 交换栈顶和倒数第5个元素
	st.data[st.len()-6], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-6] // 交换位置
}
func (st *Stack) swap6() { // 交换栈顶和倒数第6个元素
	st.data[st.len()-7], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-7] // 交换位置
}
func (st *Stack) swap7() { // 交换栈顶和倒数第7个元素
	st.data[st.len()-8], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-8] // 交换位置
}
func (st *Stack) swap8() { // 交换栈顶和倒数第8个元素
	st.data[st.len()-9], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-9] // 交换位置
}
func (st *Stack) swap9() { // 交换栈顶和倒数第9个元素
	st.data[st.len()-10], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-10] // 交换位置
}
func (st *Stack) swap10() { // 交换栈顶和倒数第10个元素
	st.data[st.len()-11], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-11] // 交换位置
}
func (st *Stack) swap11() { // 交换栈顶和倒数第11个元素
	st.data[st.len()-12], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-12] // 交换位置
}
func (st *Stack) swap12() { // 交换栈顶和倒数第12个元素
	st.data[st.len()-13], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-13] // 交换位置
}
func (st *Stack) swap13() { // 交换栈顶和倒数第13个元素
	st.data[st.len()-14], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-14] // 交换位置
}
func (st *Stack) swap14() { // 交换栈顶和倒数第14个元素
	st.data[st.len()-15], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-15] // 交换位置
}
func (st *Stack) swap15() { // 交换栈顶和倒数第15个元素
	st.data[st.len()-16], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-16] // 交换位置
}
func (st *Stack) swap16() { // 交换栈顶和倒数第16个元素
	st.data[st.len()-17], st.data[st.len()-1] = st.data[st.len()-1], st.data[st.len()-17] // 交换位置
}

func (st *Stack) dup(n int) { // 复制栈中第n个元素到栈顶
	st.push(&st.data[st.len()-n]) // 将指定位置的元素推入栈顶
}

func (st *Stack) peek() *uint256.Int { // 查看栈顶元素
	return &st.data[st.len()-1] // 返回栈顶元素的指针
}

// Back returns the n'th item in stack
// Back 返回栈中的第n个元素
func (st *Stack) Back(n int) *uint256.Int { // 获取栈中倒数第n+1个元素
	return &st.data[st.len()-n-1] // 返回指定位置元素的指针
}
