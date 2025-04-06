// Copyright 2024 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the goevmlab library. If not, see <http://www.gnu.org/licenses/>.

// package program is a utility to create EVM bytecode for testing, but _not_ for production. As such:
//
// - There are not package guarantees. We might iterate heavily on this package, and do backwards-incompatible changes without warning
// - There are no quality-guarantees. These utilities may produce evm-code that is non-functional. YMMV.
// - There are no stability-guarantees. The utility will `panic` if the inputs do not align / make sense.

package program

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// 1. Program 的作用与以太坊白皮书
// Program 是 go-ethereum 中的一个测试工具，用于动态生成 EVM（Ethereum Virtual Machine）字节码。以太坊白皮书（Vitalik Buterin, 2013）提出 EVM 作为图灵完备的执行环境，支持智能合约的运行。Program 通过方法如 Push、Op 和 Call 模拟 Solidity 或 Vyper 编译器生成的字节码，允许开发者在测试中构造自定义合约逻辑，而无需编写高级语言代码。这与白皮书中“可编程区块链”的核心理念一致。
//
// 2. EVM 操作码与黄皮书
// Program 直接操作 EVM 操作码（如 PUSH1、CALL、SSTORE），这些操作码在以太坊黄皮书中定义。例如：
//
// PUSHX（doPush）：黄皮书定义了 PUSH1 到 PUSH32（0x60-0x7f），将 1 到 32 字节数据推入栈中。doPush 动态选择合适的 PUSHX，并处理向后兼容（避免 PUSH0）。
// CALL、DELEGATECALL、STATICCALL：黄皮书描述了这些调用指令，用于合约间交互。Program 的实现（如 Call 方法）按照栈参数顺序（Gas、地址、值等）生成字节码，符合 EVM 规范。
// JUMP 和 JUMPI：支持控制流跳转，黄皮书中定义为条件和无条件跳转，JumpIf 和 Jump 方法实现了这一逻辑。
// 3. EIP-3541 和向后兼容性
// Push 方法避免使用 PUSH0（0x5f，EIP-3541 引入，Shanghai 升级，2023 年），而是用 [PUSH1 0] 确保向后兼容。这反映了以太坊对旧版本客户端的支持，避免在不支持 PUSH0 的网络上运行时出错。EIP-3541 优化了零值推送的 Gas 成本，Program 的设计展示了测试工具如何适应协议演进。
//
// 4. EIP-3855 与 PUSH0
// Push0 方法直接支持 PUSH0 操作码（EIP-3855），将零值推入栈中，Gas 成本比 PUSH1 0 低。这是 Shanghai 升级的一部分，Program 通过提供两种推送零的方式（Push(0) 和 Push0），让开发者测试新旧行为的差异。
//
// 5. EIP-1153 与 TSTORE
// Tstore 方法实现 TSTORE（0x5c，EIP-1153，Cancun 升级，2024 年），用于临时存储（Transient Storage）。与 SSTORE（永久存储）不同，TSTORE 的值仅在当前交易中有效，重置于交易结束时。这优化了合约状态管理，Program 支持测试此新功能，符合以太坊扩展性的发展方向。
//
// 6. EIP-211 与 RETURN 和 CODECOPY
// ReturnViaCodeCopy 使用 CODECOPY 和 RETURN 构造典型的合约构造函数逻辑。黄皮书定义了 RETURN（0xf3）从内存返回数据，CODECOPY（0x39）从代码复制到内存。EIP-211（2017 年）扩展了返回数据处理，Program 通过动态计算偏移量（offsetPos）实现自包含的字节码生成，模拟 Solidity 部署模式。
//
// 7. EIP-1014 与 CREATE2
// Create2 方法实现 CREATE2（0xf5，EIP-1014，Constantinople 升级，2019 年），通过盐值（salt）生成确定性合约地址。黄皮书中定义了其栈参数（值、偏移、大小、盐），Program 将初始化代码存储到内存并调用 CREATE2，支持测试可预测地址的合约部署（如代理模式）。
//
// 8. EIP-170 与字节码大小限制
// ReturnViaCodeCopy 注释提到代码大小限制为 0xc000（48KB），这是 EIP-170（Spurious Dragon 升级，2016 年）引入的合约大小上限（24,576 字节）。Program 使用 PUSH2 确保偏移量适应此限制，反映了以太坊对资源使用的约束。

// 栈操作：EVM 栈深度限制为 1024（黄皮书），Push 和调用方法（如 Call）按顺序压栈，符合栈机模型。
// Gas 成本：每个操作码有固定 Gas 成本（黄皮书附录 H），Program 不直接计算 Gas，但生成的字节码可在测试中验证 Gas 使用。
// 测试用途：注释明确指出 Program 不适合生产环境，因其错误处理使用 panic，这与以太坊测试驱动开发的实践一致。

// Program is a simple bytecode container. It can be used to construct
// simple EVM programs. Errors during construction of a Program typically
// cause panics: so avoid using these programs in production settings or on
// untrusted input.
// This package is mainly meant to aid in testing. This is not a production
// -level "compiler".
// Program 是一个简单的字节码容器，可用于构建简单的 EVM 程序。在构建 Program 时发生的错误通常会导致 panic，因此避免在生产环境或不受信任的输入上使用这些程序。
// 这个包主要用于辅助测试，不是生产级别的“编译器”。
type Program struct {
	code []byte // 字节码
}

// New creates a new Program
// New 创建一个新的 Program
func New() *Program {
	return &Program{
		code: make([]byte, 0), // 初始化空字节码
	}
}

// add adds the op to the code.
// add 将操作码添加到字节码。
func (p *Program) add(op byte) *Program {
	p.code = append(p.code, op)
	return p
}

// pushBig creates a PUSHX instruction and pushes the given val.
// - If the val is nil, it pushes zero
// - If the val is bigger than 32 bytes, it panics
// pushBig 创建一个 PUSHX 指令并推送给定的值。
// - 如果 val 为 nil，则推送零
// - 如果 val 大于 32 字节，则抛出 panic
func (p *Program) doPush(val *uint256.Int) {
	if val == nil {
		val = new(uint256.Int) // 如果为空，设为零
	}
	valBytes := val.Bytes()
	if len(valBytes) == 0 {
		valBytes = append(valBytes, 0) // 空值补零
	}
	bLen := len(valBytes)
	p.add(byte(vm.PUSH1) - 1 + byte(bLen)) // 计算对应的 PUSHX 操作码
	p.Append(valBytes)                     // 添加数据
}

// Append appends the given data to the code.
// Append 将给定数据追加到字节码。
func (p *Program) Append(data []byte) *Program {
	p.code = append(p.code, data...)
	return p
}

// Bytes returns the Program bytecode. OBS: This is not a copy.
// Bytes 返回 Program 的字节码。注意：这不是副本。
func (p *Program) Bytes() []byte {
	return p.code
}

// SetBytes sets the Program bytecode. The combination of Bytes and SetBytes means
// that external callers can implement missing functionality:
//
//	...
//	prog.Push(1)
//	code := prog.Bytes()
//	manipulate(code)
//	prog.SetBytes(code)
//
// SetBytes 设置 Program 的字节码。Bytes 和 SetBytes 的组合意味着外部调用者可以实现缺失的功能。
func (p *Program) SetBytes(code []byte) {
	p.code = code
}

// Hex returns the Program bytecode as a hex string.
// Hex 将 Program 的字节码作为十六进制字符串返回。
func (p *Program) Hex() string {
	return fmt.Sprintf("%02x", p.Bytes())
}

// Op appends the given opcode(s).
// Op 追加给定的操作码。
func (p *Program) Op(ops ...vm.OpCode) *Program {
	for _, op := range ops {
		p.add(byte(op))
	}
	return p
}

// Push creates a PUSHX instruction with the data provided. If zero is being pushed,
// PUSH0 will be avoided in favour of [PUSH1 0], to ensure backwards compatibility.
// Push 创建一个带有提供数据的 PUSHX 指令。如果推送的是零，将避免使用 PUSH0，而使用 [PUSH1 0] 以确保向后兼容。
func (p *Program) Push(val any) *Program {
	switch v := val.(type) {
	case int:
		p.doPush(new(uint256.Int).SetUint64(uint64(v)))
	case uint64:
		p.doPush(new(uint256.Int).SetUint64(v))
	case uint32:
		p.doPush(new(uint256.Int).SetUint64(uint64(v)))
	case uint16:
		p.doPush(new(uint256.Int).SetUint64(uint64(v)))
	case *big.Int:
		p.doPush(uint256.MustFromBig(v))
	case *uint256.Int:
		p.doPush(v)
	case uint256.Int:
		p.doPush(&v)
	case []byte:
		p.doPush(new(uint256.Int).SetBytes(v))
	case byte:
		p.doPush(new(uint256.Int).SetUint64(uint64(v)))
	case interface{ Bytes() []byte }:
		// Here, we jump through some hoops in order to avoid depending on
		// go-ethereum types.Address and common.Hash, and instead use the
		// interface. This works on both values and pointers!
		// 这里我们通过一些技巧避免依赖 go-ethereum 的 types.Address 和 common.Hash，而是使用接口。这对值和指针都有效！
		p.doPush(new(uint256.Int).SetBytes(v.Bytes()))
	case nil:
		p.doPush(nil)
	default:
		panic(fmt.Sprintf("unsupported type %T", v))
		// "不支持的类型 %T"
	}
	return p
}

// Push0 implements PUSH0 (0x5f).
// Push0 实现 PUSH0 (0x5f)。
func (p *Program) Push0() *Program {
	return p.Op(vm.PUSH0)
}

// ExtcodeCopy performs an extcodecopy invocation.
// ExtcodeCopy 执行 EXTCODECOPY 调用。
func (p *Program) ExtcodeCopy(address, memOffset, codeOffset, length any) *Program {
	p.Push(length)
	p.Push(codeOffset)
	p.Push(memOffset)
	p.Push(address)
	return p.Op(vm.EXTCODECOPY)
}

// Call is a convenience function to make a call. If 'gas' is nil, the opcode GAS will
// be used to provide all gas.
// Call 是一个方便函数，用于发起调用。如果 'gas' 为 nil，将使用 GAS 操作码提供所有 gas。
func (p *Program) Call(gas *uint256.Int, address, value, inOffset, inSize, outOffset, outSize any) *Program {
	if outOffset == outSize && inSize == outSize && inOffset == outSize && value == outSize {
		p.Push(outSize).Op(vm.DUP1, vm.DUP1, vm.DUP1, vm.DUP1) // 优化重复参数
	} else {
		p.Push(outSize).Push(outOffset).Push(inSize).Push(inOffset).Push(value)
	}
	p.Push(address)
	if gas == nil {
		p.Op(vm.GAS) // 使用全部可用 gas
	} else {
		p.doPush(gas)
	}
	return p.Op(vm.CALL)
}

// DelegateCall is a convenience function to make a delegatecall. If 'gas' is nil, the opcode GAS will
// be used to provide all gas.
// DelegateCall 是一个方便函数，用于发起委托调用。如果 'gas' 为 nil，将使用 GAS 操作码提供所有 gas。
func (p *Program) DelegateCall(gas *uint256.Int, address, inOffset, inSize, outOffset, outSize any) *Program {
	if outOffset == outSize && inSize == outSize && inOffset == outSize {
		p.Push(outSize).Op(vm.DUP1, vm.DUP1, vm.DUP1) // 优化重复参数
	} else {
		p.Push(outSize).Push(outOffset).Push(inSize).Push(inOffset)
	}
	p.Push(address)
	if gas == nil {
		p.Op(vm.GAS) // 使用全部可用 gas
	} else {
		p.doPush(gas)
	}
	return p.Op(vm.DELEGATECALL)
}

// StaticCall is a convenience function to make a staticcall. If 'gas' is nil, the opcode GAS will
// be used to provide all gas.
// StaticCall 是一个方便函数，用于发起静态调用。如果 'gas' 为 nil，将使用 GAS 操作码提供所有 gas。
func (p *Program) StaticCall(gas *uint256.Int, address, inOffset, inSize, outOffset, outSize any) *Program {
	if outOffset == outSize && inSize == outSize && inOffset == outSize {
		p.Push(outSize).Op(vm.DUP1, vm.DUP1, vm.DUP1) // 优化重复参数
	} else {
		p.Push(outSize).Push(outOffset).Push(inSize).Push(inOffset)
	}
	p.Push(address)
	if gas == nil {
		p.Op(vm.GAS) // 使用全部可用 gas
	} else {
		p.doPush(gas)
	}
	return p.Op(vm.STATICCALL)
}

// CallCode is a convenience function to make a callcode. If 'gas' is nil, the opcode GAS will
// be used to provide all gas.
// CallCode 是一个方便函数，用于发起 callcode 调用。如果 'gas' 为 nil，将使用 GAS 操作码提供所有 gas。
func (p *Program) CallCode(gas *uint256.Int, address, value, inOffset, inSize, outOffset, outSize any) *Program {
	if outOffset == outSize && inSize == outSize && inOffset == outSize {
		p.Push(outSize).Op(vm.DUP1, vm.DUP1, vm.DUP1) // 优化重复参数
	} else {
		p.Push(outSize).Push(outOffset).Push(inSize).Push(inOffset)
	}
	p.Push(value)
	p.Push(address)
	if gas == nil {
		p.Op(vm.GAS) // 使用全部可用 gas
	} else {
		p.doPush(gas)
	}
	return p.Op(vm.CALLCODE)
}

// Label returns the PC (of the next instruction).
// Label 返回下一条指令的程序计数器 (PC)。
func (p *Program) Label() uint64 {
	return uint64(len(p.code))
}

// Jumpdest adds a JUMPDEST op, and returns the PC of that instruction.
// Jumpdest 添加一个 JUMPDEST 操作码，并返回该指令的 PC。
func (p *Program) Jumpdest() (*Program, uint64) {
	here := p.Label()
	p.Op(vm.JUMPDEST)
	return p, here
}

// Jump pushes the destination and adds a JUMP.
// Jump 推送目标地址并添加 JUMP。
func (p *Program) Jump(loc any) *Program {
	p.Push(loc)
	p.Op(vm.JUMP)
	return p
}

// JumpIf implements JUMPI.
// JumpIf 实现 JUMPI。
func (p *Program) JumpIf(loc any, condition any) *Program {
	p.Push(condition)
	p.Push(loc)
	p.Op(vm.JUMPI)
	return p
}

// Size returns the current size of the bytecode.
// Size 返回字节码的当前大小。
func (p *Program) Size() int {
	return len(p.code)
}

// InputAddressToStack stores the input (calldata) to memory as address (20 bytes).
// InputAddressToStack 将输入 (calldata) 存储到栈中作为地址 (20 字节)。
func (p *Program) InputAddressToStack(inputOffset uint32) *Program {
	p.Push(inputOffset)
	p.Op(vm.CALLDATALOAD) // Loads [n -> n + 32] of input data to stack top
	mask, _ := big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p.Push(mask) // turn into address
	return p.Op(vm.AND)
}

// Mstore stores the provided data (into the memory area starting at memStart).
// Mstore 将提供的数据存储到以 memStart 开始的内存区域。
func (p *Program) Mstore(data []byte, memStart uint32) *Program {
	var idx = 0
	// We need to store it in chunks of 32 bytes
	// 我们需要按 32 字节的块存储
	for ; idx+32 <= len(data); idx += 32 {
		chunk := data[idx : idx+32]
		// push the value
		p.Push(chunk)
		// push the memory index
		p.Push(uint32(idx) + memStart)
		p.Op(vm.MSTORE)
	}
	// Remainders become stored using MSTORE8
	// 余数使用 MSTORE8 存储
	for ; idx < len(data); idx++ {
		b := data[idx]
		// push the byte
		p.Push(b)
		p.Push(uint32(idx) + memStart)
		p.Op(vm.MSTORE8)
	}
	return p
}

// MstoreSmall stores the provided data, which must be smaller than 32 bytes,
// into the memory area starting at memStart.
// The data will be LHS zero-added to align on 32 bytes.
// For example, providing data 0x1122, it will do a PUSH2:
// PUSH2 0x1122, resulting in
// stack: 0x0000000000000000000000000000000000000000000000000000000000001122
// followed by MSTORE(0,0)
// And thus, the resulting memory will be
// [ 0000000000000000000000000000000000000000000000000000000000001122 ]
// MstoreSmall 存储提供的数据（必须小于 32 字节），到以 memStart 开始的内存区域。
// 数据将在左侧补零以对齐 32 字节。
func (p *Program) MstoreSmall(data []byte, memStart uint32) *Program {
	if len(data) > 32 {
		// For larger sizes, use Mstore instead.
		panic("only <=32 byte data size supported")
		// "仅支持 <=32 字节的数据大小"
	}
	if len(data) == 0 {
		// Storing 0-length data smells of an error somewhere.
		panic("data is zero length")
		// "数据长度为零"
	}
	// push the value
	p.Push(data)
	// push the memory index
	p.Push(memStart)
	p.Op(vm.MSTORE)
	return p
}

// MemToStorage copies the given memory area into SSTORE slots,
// It expects data to be aligned to 32 byte, and does not zero out
// remainders if some data is not
// I.e, if given a 1-byte area, it will still copy the full 32 bytes to storage.
// MemToStorage 将给定的内存区域复制到 SSTORE 槽中，
// 它期望数据对齐到 32 字节，如果某些数据未对齐，不会清零余数。
func (p *Program) MemToStorage(memStart, memSize, startSlot int) *Program {
	// We need to store it in chunks of 32 bytes
	// 我们需要按 32 字节的块存储
	for idx := memStart; idx < (memStart + memSize); idx += 32 {
		dataStart := idx
		// Mload the chunk
		p.Push(dataStart)
		p.Op(vm.MLOAD)
		// Value is now on stack,
		p.Push(startSlot)
		p.Op(vm.SSTORE)
		startSlot++
	}
	return p
}

// ReturnViaCodeCopy utilises CODECOPY to place the given data in the bytecode of
// p, loads into memory (offset 0) and returns the code.
// This is a typical "constructor".
// Note: since all indexing is calculated immediately, the preceding bytecode
// must not be expanded or shortened.
// ReturnViaCodeCopy 使用 CODECOPY 将给定数据放入 p 的字节码中，加载到内存（偏移 0）并返回代码。
// 这是一个典型的“构造函数”。
// 注意：由于所有索引立即计算，前面的字节码不得扩展或缩短。
func (p *Program) ReturnViaCodeCopy(data []byte) *Program {
	p.Push(len(data))
	// For convenience, we'll use PUSH2 for the offset. Then we know we can always
	// fit, since code is limited to 0xc000
	// 为方便起见，我们将使用 PUSH2 表示偏移量。因为代码限制在 0xc000 以内，这样总是能适应
	p.Op(vm.PUSH2)
	offsetPos := p.Size()  // Need to update this position later on 需要稍后更新此位置
	p.Append([]byte{0, 0}) // Offset of the code to be copied 要复制的代码偏移量
	p.Push(0)              // Offset in memory (destination) 内存中的偏移量（目标）
	p.Op(vm.CODECOPY)      // Copy from code[offset:offset+len] to memory[0:] 从 code[offset:offset+len] 复制到 memory[0:]
	p.Return(0, len(data)) // Return memory[0:len] 返回 memory[0:len]
	offset := p.Size()
	p.Append(data) // And add the data 添加数据

	// Now, go back and fix the offset
	// 现在，回去修复偏移量
	p.code[offsetPos] = byte(offset >> 8)
	p.code[offsetPos+1] = byte(offset)
	return p
}

// Sstore stores the given byte array to the given slot.
// OBS! Does not verify that the value indeed fits into 32 bytes.
// If it does not, it will panic later on via doPush.
// Sstore 将给定的字节数组存储到给定槽中。
// 注意！不验证值是否确实适合 32 字节。如果不适合，将通过 doPush 抛出 panic。
func (p *Program) Sstore(slot any, value any) *Program {
	p.Push(value)
	p.Push(slot)
	return p.Op(vm.SSTORE)
}

// Tstore stores the given byte array to the given t-slot.
// OBS! Does not verify that the value indeed fits into 32 bytes.
// If it does not, it will panic later on via doPush.
// Tstore 将给定的字节数组存储到给定 t-槽中。
// 注意！不验证值是否确实适合 32 字节。如果不适合，将通过 doPush 抛出 panic。
func (p *Program) Tstore(slot any, value any) *Program {
	p.Push(value)
	p.Push(slot)
	return p.Op(vm.TSTORE)
}

// Return implements RETURN
// Return 实现 RETURN
func (p *Program) Return(offset, len int) *Program {
	p.Push(len)
	p.Push(offset)
	return p.Op(vm.RETURN)
}

// ReturnData loads the given data into memory, and does a return with it
// ReturnData 将给定数据加载到内存中，并返回它
func (p *Program) ReturnData(data []byte) *Program {
	p.Mstore(data, 0)
	return p.Return(0, len(data))
}

// Create2 uses create2 to construct a contract with the given bytecode.
// This operation leaves either '0' or address on the stack.
// Create2 使用 CREATE2 构造具有给定字节码的合约。
// 此操作会在栈上留下 '0' 或地址。
func (p *Program) Create2(code []byte, salt any) *Program {
	var (
		value  = 0         // 值
		offset = 0         // 偏移量
		size   = len(code) // 大小
	)
	// Load the code into mem
	// 将代码加载到内存
	p.Mstore(code, 0)
	// Create it
	return p.Push(salt).
		Push(size).
		Push(offset).
		Push(value).
		Op(vm.CREATE2)
	// On the stack now, is either
	// - zero: in case of failure, OR
	// - address: in case of success
	// 现在栈上的值是：
	// - 零：如果失败，或者
	// - 地址：如果成功
}

// Create2ThenCall calls create2 with the given initcode and salt, and then calls
// into the created contract (or calls into zero, if the creation failed).
// Create2ThenCall 使用给定的初始化代码和 salt 调用 CREATE2，然后调用创建的合约（如果创建失败，则调用零地址）。
func (p *Program) Create2ThenCall(code []byte, salt any) *Program {
	p.Create2(code, salt)
	// If there happen to be a zero on the stack, it doesn't matter, we're
	// not sending any value anyway
	// 如果栈上恰好有零，没关系，我们无论如何都不发送值
	p.Push(0).Push(0) // mem out
	p.Push(0).Push(0) // mem in
	p.Push(0)         // value
	p.Op(vm.DUP6)     // address
	p.Op(vm.GAS)
	p.Op(vm.CALL)
	p.Op(vm.POP)        // pop the retval
	return p.Op(vm.POP) // pop the address
}

// Selfdestruct pushes beneficiary and invokes selfdestruct.
// Selfdestruct 推送受益人并调用 SELFDESTRUCT。
func (p *Program) Selfdestruct(beneficiary any) *Program {
	p.Push(beneficiary)
	return p.Op(vm.SELFDESTRUCT)
}
