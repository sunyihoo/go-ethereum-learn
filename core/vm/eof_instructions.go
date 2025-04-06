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

// 栈模型：EVM 是基于栈的虚拟机，每个操作码从栈中读取输入或写入输出。新指令如 DUPN 和 SWAPN 通过立即数指定栈深度，优化了栈操作效率。
//
// Gas 机制：黄皮书中定义了传统操作码的 Gas 成本，EOF 新操作码的 Gas 成本需通过 EIP 更新，但通常与操作复杂度（如跳转表大小）相关。
//
// 验证与安全性：EOF 的静态验证（EIP-3670）确保操作码的立即数和跳转目标有效，减少运行时错误。

// opRjump implements the RJUMP opcode.
// opRjump 实现了 RJUMP 操作码。
func opRjump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RJUMP操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opRjumpi implements the RJUMPI opcode
// opRjumpi 实现了 RJUMPI 操作码。
func opRjumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RJUMPI操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opRjumpv implements the RJUMPV opcode
// opRjumpv 实现了 RJUMPV 操作码。
func opRjumpv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RJUMPV操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opCallf implements the CALLF opcode
// opCallf 实现了 CALLF 操作码。
func opCallf(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义CALLF操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opRetf implements the RETF opcode
// opRetf 实现了 RETF 操作码。
func opRetf(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RETF操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opJumpf implements the JUMPF opcode
// opJumpf 实现了 JUMPF 操作码。
func opJumpf(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义JUMPF操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opEOFCreate implements the EOFCREATE opcode
// opEOFCreate 实现了 EOFCREATE 操作码。
func opEOFCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义EOFCREATE操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opReturnContract implements the RETURNCONTRACT opcode
// opReturnContract 实现了 RETURNCONTRACT 操作码。
func opReturnContract(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RETURNCONTRACT操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opDataLoad implements the DATALOAD opcode
// opDataLoad 实现了 DATALOAD 操作码。
func opDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义DATALOAD操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opDataLoadN implements the DATALOADN opcode
// opDataLoadN 实现了 DATALOADN 操作码。
func opDataLoadN(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义DATALOADN操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opDataSize implements the DATASIZE opcode
// opDataSize 实现了 DATASIZE 操作码。
func opDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义DATASIZE操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opDataCopy implements the DATACOPY opcode
// opDataCopy 实现了 DATACOPY 操作码。
func opDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义DATACOPY操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opDupN implements the DUPN opcode
// opDupN 实现了 DUPN 操作码。
func opDupN(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义DUPN操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opSwapN implements the SWAPN opcode
// opSwapN 实现了 SWAPN 操作码。
func opSwapN(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义SWAPN操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opExchange implements the EXCHANGE opcode
// opExchange 实现了 EXCHANGE 操作码。
func opExchange(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义EXCHANGE操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opReturnDataLoad implements the RETURNDATALOAD opcode
// opReturnDataLoad 实现了 RETURNDATALOAD 操作码。
func opReturnDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义RETURNDATALOAD操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opExtCall implements the EOFCREATE opcode
// opExtCall 实现了 EOFCREATE 操作码。// 注意：注释可能有误，应为EXTCALL
func opExtCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义EXTCALL操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opExtDelegateCall implements the EXTDELEGATECALL opcode
// opExtDelegateCall 实现了 EXTDELEGATECALL 操作码。
func opExtDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义EXTDELEGATECALL操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}

// opExtStaticCall implements the EXTSTATICCALL opcode
// opExtStaticCall 实现了 EXTSTATICCALL 操作码。
func opExtStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) { // 定义EXTSTATICCALL操作码的执行函数
	panic("not implemented") // 未实现，触发panic
}
