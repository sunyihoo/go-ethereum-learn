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

// 功能：eofCodeBitmap 和 eofCodeBitmapInternal 用于生成一个位图（bitvec），标记以太坊字节码（code）中哪些位置是数据（立即数），哪些是可执行指令。这在 EOF 验证中至关重要，因为 EOF 是一种新的代码格式，旨在分离代码和数据，提升安全性。
// EOF 是什么：EOF 是以太坊改进提案（EIP）中提出的新格式，最早见于 EIP-3540（EOF - Ethereum Object Format）和 EIP-3670（EOF - Code Validation）。它要求代码明确区分指令和数据，避免传统 EVM 字节码中数据和代码混淆的问题。
// 位图作用：这里的位图用于标识操作码后的立即数位置。例如，PUSH1 后跟 1 字节立即数，PUSH32 后跟 32 字节立即数。通过位图，可以快速验证代码是否符合 EOF 的结构要求。

// RJUMPV：这是 EOF 引入的新操作码（见 EIP-4200，Relative Jumps），用于相对跳转。它的操作数大小是可变的，由紧跟其后的计数字节（count）决定。代码中 numbits = uint16(code[pc])*2 + 3 表示跳转表的长度计算方式：每个跳转目标占 2 字节，加上 1 字节的 count，总共 count*2+3。
// 位图生成算法：算法遍历字节码，识别每个操作码及其立即数长度，并在位图中标记立即数位置。bits.setN 等方法高效地按位设置标记，优化了内存使用。
// 边界处理：代码考虑了字节码截断的情况（如 PUSH32 超出代码长度），通过多分配 4 字节位图空间（len(code)/8+1+4）避免越界。这是 EOF 验证中鲁棒性的体现。

// eofCodeBitmap collects data locations in code.
// eofCodeBitmap 收集代码中的数据位置。
func eofCodeBitmap(code []byte) bitvec {
	// The bitmap is 4 bytes longer than necessary, in case the code
	// ends with a PUSH32, the algorithm will push zeroes onto the
	// bitvector outside the bounds of the actual code.
	// 位图比实际需要多出 4 个字节，以防代码以 PUSH32 结尾，算法会将零推入超出实际代码边界的位向量。
	bits := make(bitvec, len(code)/8+1+4)
	return eofCodeBitmapInternal(code, bits)
}

// eofCodeBitmapInternal is the internal implementation of codeBitmap for EOF
// code validation.
// eofCodeBitmapInternal 是为 EOF 代码验证实现的 codeBitmap 的内部实现。
func eofCodeBitmapInternal(code, bits bitvec) bitvec {
	// 初始化程序计数器 pc，用于遍历代码字节。
	for pc := uint64(0); pc < uint64(len(code)); {
		var (
			op      = OpCode(code[pc]) // 获取当前操作码。
			numbits uint16             // 记录操作码后的立即数位数。
		)
		pc++ // 程序计数器前进一位，指向下一字节。

		if op == RJUMPV {
			// RJUMPV is unique as it has a variable sized operand.
			// The total size is determined by the count byte which
			// immediate follows RJUMPV. Truncation will be caught
			// in other validation steps -- for now, just return a
			// valid bitmap for as much of the code as is
			// available.
			// RJUMPV 是独特的，因为它有一个可变大小的操作数。
			// 总大小由紧跟 RJUMPV 的计数字节决定。截断将在其他验证步骤中被捕获——目前，只返回可用代码的有效位图。
			end := uint64(len(code))
			if pc >= end {
				// Count missing, no more bits to mark.
				// 计数缺失，无法标记更多位。
				return bits
			}
			numbits = uint16(code[pc])*2 + 3 // 计算 RJUMPV 的操作数位数，count*2+3。
			if pc+uint64(numbits) > end {
				// Jump table is truncated, mark as many bits
				// as possible.
				// 跳转表被截断，尽可能标记更多位。
				numbits = uint16(end - pc) // 调整 numbits 为剩余可用位数。
			}
		} else {
			numbits = uint16(Immediates(op)) // 获取普通操作码的立即数位数。
			if numbits == 0 {
				continue // 若无立即数，则跳至下一次循环。
			}
		}

		// 关键步骤 - 根据 numbits 设置位图中的标记。
		if numbits >= 8 {
			for ; numbits >= 16; numbits -= 16 {
				bits.set16(pc) // 标记 16 位数据位置。
				pc += 16
			}
			for ; numbits >= 8; numbits -= 8 {
				bits.set8(pc) // 标记 8 位数据位置。
				pc += 8
			}
		}
		switch numbits {
		case 1:
			bits.set1(pc) // 标记 1 位数据位置。
			pc += 1
		case 2:
			bits.setN(set2BitsMask, pc) // 标记 2 位数据位置。
			pc += 2
		case 3:
			bits.setN(set3BitsMask, pc) // 标记 3 位数据位置。
			pc += 3
		case 4:
			bits.setN(set4BitsMask, pc) // 标记 4 位数据位置。
			pc += 4
		case 5:
			bits.setN(set5BitsMask, pc) // 标记 5 位数据位置。
			pc += 5
		case 6:
			bits.setN(set6BitsMask, pc) // 标记 6 位数据位置。
			pc += 6
		case 7:
			bits.setN(set7BitsMask, pc) // 标记 7 位数据位置。
			pc += 7
		}
	}
	return bits
}
