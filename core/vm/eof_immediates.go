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

package vm

// 为何需要 EOF：传统字节码缺乏结构，容易出现难以检测的错误（如无效跳转）。EOF 通过静态验证（检查 immediates 和 terminals）提高了安全性，减少了运行时错误。
//
// RJUMPV 的变长设计：RJUMPV 的立即数最小为 3 字节，但实际大小取决于跳转表项数。这种设计类似于 switch-case 语句，支持复杂的控制流。
//
// 分叉无关性：代码注释提到“fork-agnostic”，意味着这些定义适用于所有支持 EOF 的分叉，但验证逻辑需结合具体分叉规则（如哪些操作码有效）。

// EOF（Ethereum Object Format） 是以太坊改进提案 EIP-3540 和 EIP-3670 的核心内容，旨在为 EVM 引入结构化的字节码格式。传统字节码是连续的、无结构的，而 EOF 引入了代码段（code section）、数据段（data section）等概念，提高了代码的可验证性和安全性。
//
// immediates 和 terminals 是 EOF 验证过程中的关键数据结构。immediates 定义了每个操作码的立即字节数（即直接嵌入在代码中的参数字节数），而 terminals 标记哪些操作码可以作为代码段的终点。这些信息在运行时不直接使用，而是在部署合约时进行静态验证。

// immediates：
//  传统操作码如 PUSH1 到 PUSH32 将 1 到 32 字节的数据压入栈中，其立即字节数对应数据长度（1 到 32）。
//
//  新 EOF 操作码（如 RJUMP、CALLF 等）是 EOF 格式的一部分，设计目的是支持更结构化的控制流。例如：
//   RJUMP（相对跳转）：使用 2 字节偏移量实现跳转。
//   RJUMPV（相对跳转表）：使用变长操作数，最小 3 字节（1 字节计数 + 2 字节偏移）。
//   CALLF 和 JUMPF：支持函数调用和跳转，类似于高级语言中的函数概念。
//
//  这些操作码的立即字节数在 EOF 验证中用于确保代码格式正确，避免越界或无效跳转。
//
// terminals：
//  标记终止指令（如 STOP、RETURN、REVERT 等），这些指令表示代码段的结束。EOF 要求每个代码段必须以终止指令结尾，以确保执行流的完整性。
//  新增的 RETF（函数返回）和 JUMPF（跳转到函数）反映了 EOF 对函数式编程的支持。

// immediate denotes how many immediate bytes an operation uses. This information
// is not required during runtime, only during EOF-validation, so is not
// places into the op-struct in the instruction table.
// Note: the immediates is fork-agnostic, and assumes that validity of opcodes at
// the given time is performed elsewhere.
// immediate表示一个操作使用的立即字节数。此信息在运行时不需要，仅在EOF验证期间需要，因此未放入指令表中的op结构体。
// 注意：immediates与分叉无关，并假设操作码的有效性在其他地方进行验证。
var immediates [256]uint8 // 定义一个256字节的数组，用于存储每个操作码的立即字节数

// terminals denotes whether instructions can be the final opcode in a code section.
// Note: the terminals is fork-agnostic, and assumes that validity of opcodes at
// the given time is performed elsewhere.
// terminals表示指令是否可以是代码段中的最后一个操作码。
// 注意：terminals与分叉无关，并假设操作码的有效性在其他地方进行验证。
var terminals [256]bool // 定义一个256元素的布尔数组，用于标记操作码是否为终止指令

// 初始化函数，用于设置immediates和terminals的值
func init() {
	// The legacy pushes
	// 传统的PUSH操作码
	for i := uint8(1); i < 33; i++ { // 循环设置PUSH1到PUSH32的立即字节数
		immediates[int(PUSH0)+int(i)] = i // 将PUSH0+i的操作码对应的立即字节数设置为i
	}
	// And new eof opcodes.
	// 新的EOF操作码
	// 设置DATALOADN的立即字节数为2
	immediates[DATALOADN] = 2 // DATALOADN需要2字节的立即数，用于指定数据加载偏移量
	// 设置RJUMP的立即字节数为2
	immediates[RJUMP] = 2 // RJUMP需要2字节的立即数，表示相对跳转偏移量
	// 设置RJUMPI的立即字节数为2
	immediates[RJUMPI] = 2 // RJUMPI需要2字节的立即数，表示条件相对跳转偏移量
	// 设置RJUMPV的立即字节数为3
	immediates[RJUMPV] = 3 // RJUMPV需要3字节的立即数（最小值），包括计数字节和跳转表
	// 设置CALLF的立即字节数为2
	immediates[CALLF] = 2 // CALLF需要2字节的立即数，表示调用函数的索引
	// 设置JUMPF的立即字节数为2
	immediates[JUMPF] = 2 // JUMPF需要2字节的立即数，表示跳转到函数的索引
	// 设置DUPN的立即字节数为1
	immediates[DUPN] = 1 // DUPN需要1字节的立即数，指定复制的栈深度
	// 设置SWAPN的立即字节数为1
	immediates[SWAPN] = 1 // SWAPN需要1字节的立即数，指定交换的栈深度
	// 设置EXCHANGE的立即字节数为1
	immediates[EXCHANGE] = 1 // EXCHANGE需要1字节的立即数，指定交换的栈位置
	// 设置EOFCREATE的立即字节数为1
	immediates[EOFCREATE] = 1 // EOFCREATE需要1字节的立即数，指定创建的容器索引
	// 设置RETURNCONTRACT的立即字节数为1
	immediates[RETURNCONTRACT] = 1 // RETURNCONTRACT需要1字节的立即数，指定返回的容器索引

	// Define the terminals.
	// 定义终止指令
	// 设置STOP为终止指令
	terminals[STOP] = true // STOP表示停止执行，是代码段的终点
	// 设置RETF为终止指令
	terminals[RETF] = true // RETF表示函数返回，是代码段的终点
	// 设置JUMPF为终止指令
	terminals[JUMPF] = true // JUMPF表示跳转到函数并结束当前段，是代码段的终点
	// 设置RETURNCONTRACT为终止指令
	terminals[RETURNCONTRACT] = true // RETURNCONTRACT表示返回合约部署结果，是代码段的终点
	// 设置RETURN为终止指令
	terminals[RETURN] = true // RETURN表示返回数据并结束执行，是代码段的终点
	// 设置REVERT为终止指令
	terminals[REVERT] = true // REVERT表示回滚状态并结束执行，是代码段的终点
	// 设置INVALID为终止指令
	terminals[INVALID] = true // INVALID表示无效操作码，终止执行
}

// Immediates returns the number bytes of immediates (argument not from
// stack but from code) a given opcode has.
// Immediates返回给定操作码的立即字节数（参数不是从栈中获取，而是从代码中获取）。
// OBS:
//   - This function assumes EOF instruction-set. It cannot be upon in
//     a. pre-EOF code
//     b. post-EOF but legacy code
//   - RJUMPV is unique as it has a variable sized operand. The total size is
//     determined by the count byte which immediately follows RJUMPV. This method
//     will return '3' for RJUMPV, which is the minimum.
//
// 注意：
//   - 此函数假设使用EOF指令集，不能用于：
//     a. EOF之前的代码
//     b. EOF之后但使用旧代码
//   - RJUMPV是独特的，因为它具有可变大小的操作数。总大小由紧随RJUMPV的计数字节决定。此方法为RJUMPV返回“3”，这是最小值。
func Immediates(op OpCode) int { // 返回指定操作码的立即字节数
	return int(immediates[op]) // 从immediates数组中获取对应操作码的立即字节数并返回
}
