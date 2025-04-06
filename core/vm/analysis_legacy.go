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

const (
	set2BitsMask = uint16(0b11)       // 2位掩码，用于标记2位数据。
	set3BitsMask = uint16(0b111)      // 3位掩码，用于标记3位数据。
	set4BitsMask = uint16(0b1111)     // 4位掩码，用于标记4位数据。
	set5BitsMask = uint16(0b1_1111)   // 5位掩码，用于标记5位数据。
	set6BitsMask = uint16(0b11_1111)  // 6位掩码，用于标记6位数据。
	set7BitsMask = uint16(0b111_1111) // 7位掩码，用于标记7位数据。
)

// bitvec is a bit vector which maps bytes in a program.
// An unset bit means the byte is an opcode, a set bit means
// it's data (i.e. argument of PUSHxx).
// bitvec 是一个位向量，用于映射程序中的字节。
// 未置位表示该字节是操作码，已置位表示该字节是数据（例如 PUSHxx 的参数）。
type bitvec []byte

// set1 在位向量中标记 1 位数据位置。
func (bits bitvec) set1(pos uint64) {
	bits[pos/8] |= 1 << (pos % 8) // 关键步骤 - 使用位运算标记单个位。
}

// setN 根据指定掩码标记 N 位数据位置，可能跨字节。
func (bits bitvec) setN(flag uint16, pos uint64) {
	a := flag << (pos % 8)         // 关键步骤 - 将掩码左移至正确位置。
	bits[pos/8] |= byte(a)         // 关键步骤 - 设置当前字节的位。
	if b := byte(a >> 8); b != 0 { // 检查是否跨字节。
		bits[pos/8+1] = b // 关键步骤 - 设置下一字节的位。
	}
}

// set8 在位向量中标记 8 位数据位置。
func (bits bitvec) set8(pos uint64) {
	a := byte(0xFF << (pos % 8)) // 关键步骤 - 生成 8 位掩码并左移。
	bits[pos/8] |= a             // 关键步骤 - 设置当前字节。
	bits[pos/8+1] = ^a           // 关键步骤 - 设置下一字节（补码处理跨字节）。
}

// set16 在位向量中标记 16 位数据位置。
func (bits bitvec) set16(pos uint64) {
	a := byte(0xFF << (pos % 8)) // 关键步骤 - 生成 8 位掩码并左移。
	bits[pos/8] |= a             // 关键步骤 - 设置当前字节。
	bits[pos/8+1] = 0xFF         // 关键步骤 - 设置下一完整字节。
	bits[pos/8+2] = ^a           // 关键步骤 - 设置下下字节（补码处理跨字节）。
}

// codeSegment checks if the position is in a code segment.
// codeSegment 检查指定位置是否在代码段中。
func (bits *bitvec) codeSegment(pos uint64) bool {
	return (((*bits)[pos/8] >> (pos % 8)) & 1) == 0 // 关键步骤 - 检查位是否为 0（代码段）。
}

// codeBitmap collects data locations in code.
// codeBitmap 收集代码中的数据位置。
func codeBitmap(code []byte) bitvec {
	// The bitmap is 4 bytes longer than necessary, in case the code
	// ends with a PUSH32, the algorithm will set bits on the
	// bitvector outside the bounds of the actual code.
	// 位图比实际需要多出 4 个字节，以防代码以 PUSH32 结尾，算法会在位向量上设置超出实际代码边界的位。
	bits := make(bitvec, len(code)/8+1+4)
	return codeBitmapInternal(code, bits)
}

// codeBitmapInternal is the internal implementation of codeBitmap.
// It exists for the purpose of being able to run benchmark tests
// without dynamic allocations affecting the results.
// codeBitmapInternal 是 codeBitmap 的内部实现。
// 它的存在是为了能够在不因动态分配影响结果的情况下运行基准测试。
func codeBitmapInternal(code, bits bitvec) bitvec {
	// 初始化程序计数器 pc，用于遍历代码字节。
	for pc := uint64(0); pc < uint64(len(code)); {
		op := OpCode(code[pc])      // 获取当前操作码。
		pc++                        // 程序计数器前进一位。
		if int8(op) < int8(PUSH1) { // If not PUSH (the int8(op) > int(PUSH32) is always false).
			// 如果不是 PUSH 操作码（int8(op) > int(PUSH32) 始终为假）。
			continue // 非 PUSH 操作码则跳过。
		}
		numbits := op - PUSH1 + 1 // 关键步骤 - 计算 PUSH 操作的立即数位数。
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
