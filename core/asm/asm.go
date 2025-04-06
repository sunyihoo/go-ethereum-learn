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

// Package asm provides support for dealing with EVM assembly instructions (e.g., disassembling them).
package asm

import (
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/core/vm"
)

// EVM 字节码 (EVM Bytecode): 智能合约在以太坊虚拟机上执行时所使用的低级代码。它由一系列操作码组成，每个操作码执行特定的操作。
// 反汇编 (Disassembly): 将低级机器代码（如 EVM 字节码）转换回人类可读的汇编语言的过程。这有助于理解智能合约的功能和逻辑。
// 操作码 (Opcode): EVM 字节码中的单个指令，用一个字节表示。每个操作码对应一个特定的操作，例如算术运算、逻辑运算、内存访问、存储访问、合约调用等。
// 程序计数器 (Program Counter, PC): 一个指示当前正在执行的指令在代码中的位置的计数器。
// 参数 (Arguments): 某些 EVM 指令需要额外的参数才能执行。例如，PUSH 指令需要指定要压入堆栈的值。
// 以太坊对象格式 (Ethereum Object Format, EOF): 一种更结构化的 EVM 字节码格式，旨在解决传统格式的一些限制，并为未来的 EVM 升级提供更好的扩展性。EOF 将代码和数据部分分开，并引入了新的指令和结构。RJUMPV 是 EOF 中引入的一个新的跳转指令。
// PUSH 指令: 一组用于将常量值压入 EVM 堆栈的指令。PUSH1 到 PUSH32 分别用于压入 1 到 32 字节的值。在遗留代码中，PUSH0 表示压入 0。
// RJUMPV 指令: EOF 中引入的一个相对跳转指令，其目标地址是根据一个跳转向量计算出来的。跳转向量的长度是可变的，由紧随 RJUMPV 后的一个字节指定。

// Iterator for disassembled EVM instructions
// EVM 反汇编指令的迭代器
type instructionIterator struct {
	code []byte // The EVM bytecode to iterate over
	// 要迭代的 EVM 字节码
	pc uint64 // The current program counter
	// 当前程序计数器
	arg []byte // The arguments of the current instruction
	// 当前指令的参数
	op vm.OpCode // The opcode of the current instruction
	// 当前指令的操作码
	error error // Any error encountered during iteration
	// 迭代过程中遇到的任何错误
	started bool // Flag indicating if the iteration has started
	// 标记迭代是否已开始
	eofEnabled bool // Flag indicating if EOF-specific decoding is enabled
	// 标记是否启用 EOF 特定的解码
}

// NewInstructionIterator creates a new instruction iterator.
// NewInstructionIterator 创建一个新的指令迭代器。
func NewInstructionIterator(code []byte) *instructionIterator {
	it := new(instructionIterator)
	it.code = code
	return it
}

// NewEOFInstructionIterator creates a new instruction iterator for EOF-code.
// NewEOFInstructionIterator 为 EOF 代码创建一个新的指令迭代器。
func NewEOFInstructionIterator(code []byte) *instructionIterator {
	it := NewInstructionIterator(code)
	it.eofEnabled = true
	return it
}

// Next returns true if there is a next instruction and moves on.
// Next 如果存在下一条指令则返回 true 并继续移动。
func (it *instructionIterator) Next() bool {
	if it.error != nil || uint64(len(it.code)) <= it.pc {
		// We previously reached an error or the end.
		// 我们之前遇到了错误或到达了末尾。
		return false
	}

	if it.started {
		// Since the iteration has been already started we move to the next instruction.
		// 由于迭代已经开始，我们移动到下一条指令。
		if it.arg != nil {
			it.pc += uint64(len(it.arg))
		}
		it.pc++
	} else {
		// We start the iteration from the first instruction.
		// 我们从第一条指令开始迭代。
		it.started = true
	}

	if uint64(len(it.code)) <= it.pc {
		// We reached the end.
		// 我们到达了末尾。
		return false
	}
	it.op = vm.OpCode(it.code[it.pc])
	var a int
	if !it.eofEnabled { // Legacy code
		// 旧代码
		if it.op.IsPush() {
			a = int(it.op) - int(vm.PUSH0)
		}
	} else { // EOF code
		// EOF 代码
		if it.op == vm.RJUMPV {
			// RJUMPV is unique as it has a variable sized operand. The total size is
			// determined by the count byte which immediately follows RJUMPV.
			// RJUMPV 是独一无二的，因为它有一个可变大小的操作数。总大小由紧随 RJUMPV 的计数字节确定。
			maxIndex := int(it.code[it.pc+1])
			a = (maxIndex+1)*2 + 1
		} else {
			a = vm.Immediates(it.op)
		}
	}
	if a > 0 {
		u := it.pc + 1 + uint64(a)
		if uint64(len(it.code)) <= it.pc || uint64(len(it.code)) < u {
			it.error = fmt.Errorf("incomplete instruction at %v", it.pc)
			return false
		}
		it.arg = it.code[it.pc+1 : u]
	} else {
		it.arg = nil
	}
	return true
}

// Error returns any error that may have been encountered.
// Error 返回可能遇到的任何错误。
func (it *instructionIterator) Error() error {
	return it.error
}

// PC returns the PC of the current instruction.
// PC 返回当前指令的程序计数器。
func (it *instructionIterator) PC() uint64 {
	return it.pc
}

// Op returns the opcode of the current instruction.
// Op 返回当前指令的操作码。
func (it *instructionIterator) Op() vm.OpCode {
	return it.op
}

// Arg returns the argument of the current instruction.
// Arg 返回当前指令的参数。
func (it *instructionIterator) Arg() []byte {
	return it.arg
}

// PrintDisassembled pretty-print all disassembled EVM instructions to stdout.
// PrintDisassembled 将所有反汇编的 EVM 指令漂亮地打印到标准输出。
func PrintDisassembled(code string) error {
	script, err := hex.DecodeString(code)
	if err != nil {
		return err
	}
	it := NewInstructionIterator(script)
	for it.Next() {
		if it.Arg() != nil && 0 < len(it.Arg()) {
			fmt.Printf("%05x: %v %#x\n", it.PC(), it.Op(), it.Arg())
		} else {
			fmt.Printf("%05x: %v\n", it.PC(), it.Op())
		}
	}
	return it.Error()
}

// Disassemble returns all disassembled EVM instructions in human-readable format.
// Disassemble 以人类可读的格式返回所有反汇编的 EVM 指令。
func Disassemble(script []byte) ([]string, error) {
	instrs := make([]string, 0)

	it := NewInstructionIterator(script)
	for it.Next() {
		if it.Arg() != nil && 0 < len(it.Arg()) {
			instrs = append(instrs, fmt.Sprintf("%05x: %v %#x\n", it.PC(), it.Op(), it.Arg()))
		} else {
			instrs = append(instrs, fmt.Sprintf("%05x: %v\n", it.PC(), it.Op()))
		}
	}
	if err := it.Error(); err != nil {
		return nil, err
	}
	return instrs, nil
}
