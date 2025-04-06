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

package asm

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/vm"
)

// EVM 字节码 (Bytecode): 这是以太坊智能合约最终在 EVM 上执行的格式。Compiler 的主要目标就是生成这种字节码并存储在 out 字段中。
// 程序计数器 (Program Counter, PC): 在 EVM 执行字节码时，程序计数器跟踪当前正在执行的指令的位置。Compiler 在编译过程中也需要维护一个程序计数器 (pc)，用于计算跳转指令的目标地址。
// 标签 (Labels): 在汇编语言中，标签用于标记代码中的特定位置，通常作为跳转指令的目标。labels 映射存储了标签名称和它们在生成的字节码中的偏移量。
// EVM 操作码 (Opcodes): element 类型的标记通常会对应一个 EVM 操作码，例如 ADD、SUB、PUSH 等。每个操作码在 EVM 中都有特定的功能和 gas 消耗。
// JUMP 和 JUMPI 指令: 这些是 EVM 中的跳转指令。JUMP 是无条件跳转，而 JUMPI 是条件跳转（根据堆栈顶部的值决定是否跳转）。在编译时，需要确定这些指令的目标地址。
// JUMPDEST 操作码: 这是标记跳转目标位置的操作码。在 Feed 阶段，当遇到 labelDef 时，会记录下当前 pc 值，并在第二阶段编译时，在对应位置生成 JUMPDEST 操作码。
// PUSH 操作码: PUSH4 是 EVM 中用于将 4 个字节的数据推送到堆栈上的操作码。在这里，它用于将跳转目标地址推送到堆栈上，供后续的 JUMP 或 JUMPI 指令使用。
// 堆栈 (Stack): EVM 是一个基于堆栈的虚拟机。操作码通常从堆栈中获取操作数，并将结果放回堆栈中。
// PUSH1-PUSH32 操作码: 这些操作码用于将常量值加载到 EVM 的堆栈上。智能合约经常使用 PUSH 指令来准备操作数。
// JUMPDEST 操作码: 这个操作码标记了代码中可以作为 JUMP 或 JUMPI 指令的目标位置。只有在 JUMPDEST 指令之后的位置才能被安全地跳转到。

// Compiler contains information about the parsed source
// and holds the tokens for the program.
// Compiler 包含有关已解析源的信息，并保存程序的标记。
type Compiler struct {
	tokens []token
	out    []byte

	labels map[string]int

	pc, pos int

	debug bool
}

// NewCompiler returns a new allocated compiler.
// NewCompiler 返回一个新的已分配的编译器。
func NewCompiler(debug bool) *Compiler {
	return &Compiler{
		labels: make(map[string]int),
		debug:  debug,
	}
}

// Feed feeds tokens into ch and are interpreted by
// the compiler.
// Feed 将标记输入到 ch 中，并由编译器解释。
//
// feed is the first pass in the compile stage as it collects the used labels in the
// program and keeps a program counter which is used to determine the locations of the
// jump dests. The labels can than be used in the second stage to push labels and
// determine the right position.
// feed 是编译阶段的第一遍，因为它收集程序中使用的标签，并维护一个程序计数器，该计数器用于确定跳转目标的位置。然后可以在第二阶段使用这些标签来推送标签并确定正确的位置。
func (c *Compiler) Feed(ch <-chan token) {
	var prev token
	for i := range ch {
		switch i.typ {
		case number:
			num := math.MustParseBig256(i.text).Bytes()
			if len(num) == 0 {
				num = []byte{0}
			}
			c.pc += len(num)
		case stringValue:
			c.pc += len(i.text) - 2
		case element:
			c.pc++
		case labelDef:
			c.labels[i.text] = c.pc
			c.pc++
		case label:
			c.pc += 4
			if prev.typ == element && isJump(prev.text) {
				c.pc++
			}
		}
		c.tokens = append(c.tokens, i)
		prev = i
	}
	if c.debug {
		fmt.Fprintln(os.Stderr, "found", len(c.labels), "labels")
	}
}

// Compile compiles the current tokens and returns a binary string that can be interpreted
// by the EVM and an error if it failed.
// Compile 编译当前标记并返回一个可以被 EVM 解释的二进制字符串，如果失败则返回错误。
//
// compile is the second stage in the compile phase which compiles the tokens to EVM
// instructions.
// compile 是编译阶段的第二遍，它将标记编译为 EVM 指令。
func (c *Compiler) Compile() (string, []error) {
	var errors []error
	// continue looping over the tokens until
	// the stack has been exhausted.
	// 继续循环遍历标记，直到堆栈耗尽。
	for c.pos < len(c.tokens) {
		if err := c.compileLine(); err != nil {
			errors = append(errors, err)
		}
	}

	// turn the binary to hex
	// 将二进制转换为十六进制。
	h := hex.EncodeToString(c.out)
	return h, errors
}

// next returns the next token and increments the
// position.
// next 返回下一个标记并递增位置。
func (c *Compiler) next() token {
	token := c.tokens[c.pos]
	c.pos++
	return token
}

// compileLine compiles a single line instruction e.g.
// "push 1", "jump @label".
// compileLine 编译单行指令，例如 "push 1", "jump @label"。
func (c *Compiler) compileLine() error {
	n := c.next()
	if n.typ != lineStart {
		return compileErr(n, n.typ.String(), lineStart.String())
	}

	lvalue := c.next()
	switch lvalue.typ {
	case eof:
		return nil
	case element:
		if err := c.compileElement(lvalue); err != nil {
			return err
		}
	case labelDef:
		c.compileLabel()
	case lineEnd:
		return nil
	default:
		return compileErr(lvalue, lvalue.text, fmt.Sprintf("%v or %v", labelDef, element))
	}

	if n := c.next(); n.typ != lineEnd {
		return compileErr(n, n.text, lineEnd.String())
	}

	return nil
}

// parseNumber compiles the number to bytes
// parseNumber 将数字编译为字节。
func parseNumber(tok token) ([]byte, error) {
	if tok.typ != number {
		panic("parseNumber of non-number token")
	}
	num, ok := math.ParseBig256(tok.text)
	if !ok {
		return nil, errors.New("invalid number")
	}
	bytes := num.Bytes()
	if len(bytes) == 0 {
		bytes = []byte{0}
	}
	return bytes, nil
}

// compileElement compiles the element (push & label or both)
// to a binary representation and may error if incorrect statements
// where fed.
// compileElement 将元素（push 和 label 或两者）编译为二进制表示，如果输入了不正确的语句可能会出错。
func (c *Compiler) compileElement(element token) error {
	switch {
	case isJump(element.text):
		return c.compileJump(element.text)
	case isPush(element.text):
		return c.compilePush()
	default:
		c.outputOpcode(toBinary(element.text))
		return nil
	}
}

func (c *Compiler) compileJump(jumpType string) error {
	rvalue := c.next()
	switch rvalue.typ {
	case number:
		numBytes, err := parseNumber(rvalue)
		if err != nil {
			return err
		}
		c.outputBytes(numBytes)

	case stringValue:
		// strings are quoted, remove them.
		// 字符串被引号包裹，移除它们。
		str := rvalue.text[1 : len(rvalue.text)-2]
		c.outputBytes([]byte(str))

	case label:
		c.outputOpcode(vm.PUSH4)
		pos := big.NewInt(int64(c.labels[rvalue.text])).Bytes()
		pos = append(make([]byte, 4-len(pos)), pos...)
		c.outputBytes(pos)

	case lineEnd:
		// push without argument is supported, it just takes the destination from the stack.
		// 支持没有参数的 push 操作，它只是从堆栈中获取目标地址。
		c.pos--

	default:
		return compileErr(rvalue, rvalue.text, "number, string or label")
	}
	// push the operation
	// 推送操作码。
	c.outputOpcode(toBinary(jumpType))
	return nil
}

func (c *Compiler) compilePush() error {
	// handle pushes. pushes are read from left to right.
	// 处理 push 操作。push 操作从左到右读取。
	var value []byte
	rvalue := c.next()
	switch rvalue.typ {
	case number:
		value = math.MustParseBig256(rvalue.text).Bytes()
		if len(value) == 0 {
			value = []byte{0}
		}
	case stringValue:
		value = []byte(rvalue.text[1 : len(rvalue.text)-1])
	case label:
		value = big.NewInt(int64(c.labels[rvalue.text])).Bytes()
		value = append(make([]byte, 4-len(value)), value...)
	default:
		return compileErr(rvalue, rvalue.text, "number, string or label")
	}
	if len(value) > 32 {
		return fmt.Errorf("%d: string or number size > 32 bytes", rvalue.lineno+1)
	}
	// PUSH1 (0x60) to PUSH32 (0x7f)
	// The opcode is calculated based on the length of the value being pushed.
	// PUSH1 (0x60) 到 PUSH32 (0x7f)
	// 操作码根据要推送的值的长度计算得出。
	c.outputOpcode(vm.OpCode(int(vm.PUSH1) - 1 + len(value)))
	c.outputBytes(value)
	return nil
}

// compileLabel pushes a jumpdest to the binary slice.
// compileLabel 将一个 jumpdest 推送到二进制切片中。
func (c *Compiler) compileLabel() {
	c.outputOpcode(vm.JUMPDEST)
}

func (c *Compiler) outputOpcode(op vm.OpCode) {
	if c.debug {
		fmt.Printf("%d: %v\n", len(c.out), op)
	}
	c.out = append(c.out, byte(op))
}

// output pushes the value v to the binary stack.
// output 将值 v 推送到二进制堆栈中。
func (c *Compiler) outputBytes(b []byte) {
	if c.debug {
		fmt.Printf("%d: %x\n", len(c.out), b)
	}
	c.out = append(c.out, b...)
}

// isPush returns whether the string op is either any of
// push(N).
// isPush 返回字符串 op 是否为 push(N) 中的任何一个。
func isPush(op string) bool {
	return strings.EqualFold(op, "PUSH")
}

// isJump returns whether the string op is jump(i)
// isJump 返回字符串 op 是否为 jump(i)。
func isJump(op string) bool {
	return strings.EqualFold(op, "JUMPI") || strings.EqualFold(op, "JUMP")
}

// toBinary converts text to a vm.OpCode
// toBinary 将文本转换为 vm.OpCode。
func toBinary(text string) vm.OpCode {
	return vm.StringToOp(strings.ToUpper(text))
}

type compileError struct {
	got  string
	want string

	lineno int
}

func (err compileError) Error() string {
	return fmt.Sprintf("%d: syntax error: unexpected %v, expected %v", err.lineno, err.got, err.want)
}

func compileErr(c token, got, want string) error {
	return compileError{
		got:    got,
		want:   want,
		lineno: c.lineno + 1,
	}
}
