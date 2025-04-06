// Copyright 2015 The go-ethereum Authors
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
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// opAdd 执行 ADD 操作码：栈顶两个元素相加，结果存回栈顶。
func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Add(&x, y)
	return nil, nil
}

// opSub 执行 SUB 操作码：栈顶两个元素相减，结果存回栈顶。
func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Sub(&x, y)
	return nil, nil
}

// opMul 执行 MUL 操作码：栈顶两个元素相乘，结果存回栈顶。
func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mul(&x, y)
	return nil, nil
}

// opDiv 执行 DIV 操作码：栈顶两个元素相除，结果存回栈顶。
func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Div(&x, y)
	return nil, nil
}

// opSdiv 执行 SDIV 操作码：栈顶两个元素的有符号除法，结果存回栈顶。
func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SDiv(&x, y)
	return nil, nil
}

// opMod 执行 MOD 操作码：栈顶两个元素的取模，结果存回栈顶。
func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Mod(&x, y)
	return nil, nil
}

// opSmod 执行 SMOD 操作码：栈顶两个元素的有符号取模，结果存回栈顶。
func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.SMod(&x, y)
	return nil, nil
}

// opExp 执行 EXP 操作码：栈顶两个元素的指数运算，结果存回栈顶。
func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	exponent.Exp(&base, exponent)
	return nil, nil
}

// opSignExtend 执行 SIGNEXTEND 操作码：对栈顶元素进行符号扩展。
func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	num.ExtendSign(num, &back)
	return nil, nil
}

// opNot 执行 NOT 操作码：对栈顶元素按位取反。
func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	x.Not(x)
	return nil, nil
}

// opLt 执行 LT 操作码：比较栈顶两个元素，若 x < y 则 y = 1，否则 y = 0。
func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Lt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

// opGt 执行 GT 操作码：比较栈顶两个元素，若 x > y 则 y = 1，否则 y = 0。
func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Gt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

// opSlt 执行 SLT 操作码：有符号比较栈顶两个元素，若 x < y 则 y = 1，否则 y = 0。
func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Slt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

// opSgt 执行 SGT 操作码：有符号比较栈顶两个元素，若 x > y 则 y = 1，否则 y = 0。
func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Sgt(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

// opEq 执行 EQ 操作码：比较栈顶两个元素是否相等，若相等 y = 1，否则 y = 0。
func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(y) {
		y.SetOne()
	} else {
		y.Clear()
	}
	return nil, nil
}

// opIszero 执行 ISZERO 操作码：检查栈顶元素是否为零，若是则设为 1，否则设为 0。
func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if x.IsZero() {
		x.SetOne()
	} else {
		x.Clear()
	}
	return nil, nil
}

// opAnd 执行 AND 操作码：对栈顶两个元素按位与，结果存回栈顶。
func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.And(&x, y)
	return nil, nil
}

// opOr 执行 OR 操作码：对栈顶两个元素按位或，结果存回栈顶。
func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Or(&x, y)
	return nil, nil
}

// opXor 执行 XOR 操作码：对栈顶两个元素按位异或，结果存回栈顶。
func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	y.Xor(&x, y)
	return nil, nil
}

// opByte 执行 BYTE 操作码：从栈顶第二个元素中提取指定字节。
func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	val.Byte(&th)
	return nil, nil
}

// opAddmod 执行 ADDMOD 操作码：对栈顶三个元素执行 (x + y) mod z，结果存回栈顶。
func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.AddMod(&x, &y, z)
	return nil, nil
}

// opMulmod 执行 MULMOD 操作码：对栈顶三个元素执行 (x * y) mod z，结果存回栈顶。
func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	z.MulMod(&x, &y, z)
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
// opSHL 实现左移操作：从栈中弹出两个值，arg1 和 arg2，将 arg2 左移 arg1 位。
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	// 注意，第二个操作数留在栈中；将结果累积到其中，之后无需再次压栈
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Lsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
// opSHR 实现逻辑右移：从栈中弹出两个值，arg1 和 arg2，将 arg2 右移 arg1 位，零填充。
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	// 注意，第二个操作数留在栈中；将结果累积到其中，之后无需再次压栈
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.LtUint64(256) {
		value.Rsh(value, uint(shift.Uint64()))
	} else {
		value.Clear()
	}
	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
// opSAR 实现算术右移：从栈中弹出两个值，arg1 和 arg2，将 arg2 右移 arg1 位，符号扩展。
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.GtUint64(256) {
		if value.Sign() >= 0 {
			value.Clear()
		} else {
			// Max negative shift: all bits set
			// 最大负移位：所有位都设置为1
			value.SetAllOne()
		}
		return nil, nil
	}
	n := uint(shift.Uint64())
	value.SRsh(value, n)
	return nil, nil
}

// opKeccak256 执行 KECCAK256 操作码：对内存中的数据计算 Keccak256 哈希。
func opKeccak256(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	data := scope.Memory.GetPtr(offset.Uint64(), size.Uint64())

	if interpreter.hasher == nil {
		interpreter.hasher = crypto.NewKeccakState()
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	evm := interpreter.evm
	if evm.Config.EnablePreimageRecording {
		evm.StateDB.AddPreimage(interpreter.hasherBuf, data)
	}
	size.SetBytes(interpreter.hasherBuf[:])
	return nil, nil
}

// opAddress 执行 ADDRESS 操作码：将当前合约地址压入栈。
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	return nil, nil
}

// opBalance 执行 BALANCE 操作码：获取指定地址的余额。
func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	slot.Set(interpreter.evm.StateDB.GetBalance(address))
	return nil, nil
}

// opOrigin 执行 ORIGIN 操作码：将交易发起者地址压入栈。
func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))
	return nil, nil
}

// opCaller 执行 CALLER 操作码：将调用者地址压入栈。
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	return nil, nil
}

// opCallValue 执行 CALLVALUE 操作码：将调用时附带的价值（wei）压入栈。
func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(scope.Contract.value)
	return nil, nil
}

// opCallDataLoad 执行 CALLDATALOAD 操作码：从调用数据中加载 32 字节。
func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
	} else {
		x.Clear()
	}
	return nil, nil
}

// opCallDataSize 执行 CALLDATASIZE 操作码：将调用数据大小压入栈。
func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	return nil, nil
}

// opCallDataCopy 执行 CALLDATACOPY 操作码：将调用数据复制到内存。
func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = math.MaxUint64
	}
	// These values are checked for overflow during gas cost calculation
	// 这些值在 gas 成本计算期间检查溢出
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))

	return nil, nil
}

// opReturnDataSize 执行 RETURNDATASIZE 操作码：将返回数据大小压入栈。
func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	return nil, nil
}

// opReturnDataCopy 执行 RETURNDATACOPY 操作码：将返回数据复制到内存。
func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)

	offset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	// 现在我们可以重用 dataOffset（为其起别名以提高清晰度）
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, ErrReturnDataOutOfBounds
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	return nil, nil
}

// opExtCodeSize 执行 EXTCODESIZE 操作码：获取外部合约代码大小。
func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	slot.SetUint64(uint64(interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())))
	return nil, nil
}

// opCodeSize 执行 CODESIZE 操作码：获取当前合约代码大小。
func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Code))))
	return nil, nil
}

// opCodeCopy 执行 CODECOPY 操作码：将当前合约代码复制到内存。
func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = math.MaxUint64
	}

	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
	return nil, nil
}

// opExtCodeCopy 执行 EXTCODECOPY 操作码：将外部合约代码复制到内存。
func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = math.MaxUint64
	}
	addr := common.Address(a.Bytes20())
	code := interpreter.evm.StateDB.GetCode(addr)
	codeCopy := getData(code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//
//  1. Caller tries to get the code hash of a normal contract account, state
//     should return the relative code hash and set it as the result.
//
//  2. Caller tries to get the code hash of a non-existent account, state should
//     return common.Hash{} and zero will be set as the result.
//
//  3. Caller tries to get the code hash for an account without contract code, state
//     should return emptyCodeHash(0xc5d246...) as the result.
//
//  4. Caller tries to get the code hash of a precompiled account, the result should be
//     zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean, all precompile
// accounts on mainnet have been transferred 1 wei, so the return here should be
// emptyCodeHash. If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//  5. Caller tries to get the code hash for an account which is marked as self-destructed
//     in the current transaction, the code hash of this account should be returned.
//
//  6. Caller tries to get the code hash for an account which is marked as deleted, this
//     account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	address := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(address) {
		slot.Clear()
	} else {
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
	}
	return nil, nil
}

// opGasprice 执行 GASPRICE 操作码：将当前 gas 价格压入栈。
func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	return nil, nil
}

// opBlockhash 执行 BLOCKHASH 操作码：获取指定块的哈希。
func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	num := scope.Stack.peek()
	num64, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		return nil, nil
	}

	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		res := interpreter.evm.Context.GetHash(num64)
		if witness := interpreter.evm.StateDB.Witness(); witness != nil {
			witness.AddBlockHash(num64)
		}
		num.SetBytes(res[:])
	} else {
		num.Clear()
	}
	return nil, nil
}

// opCoinbase 执行 COINBASE 操作码：将区块的 coinbase 地址压入栈。
func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	return nil, nil
}

// opTimestamp 执行 TIMESTAMP 操作码：将区块的时间戳压入栈。
func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.Time))
	return nil, nil
}

// opNumber 执行 NUMBER 操作码：将区块号压入栈。
func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	return nil, nil
}

// opDifficulty 执行 DIFFICULTY 操作码：将区块难度压入栈。
func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	return nil, nil
}

// opRandom 执行 RANDOM 操作码：将区块的随机数（PREVRANDAO）压入栈。
func opRandom(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := new(uint256.Int).SetBytes(interpreter.evm.Context.Random.Bytes())
	scope.Stack.push(v)
	return nil, nil
}

// opGasLimit 执行 GASLIMIT 操作码：将区块的 gas 限制压入栈。
func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	return nil, nil
}

// opPop 执行 POP 操作码：弹出栈顶元素。
func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.pop()
	return nil, nil
}

// opMload 执行 MLOAD 操作码：从内存中加载 32 字节到栈。
func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := scope.Stack.peek()
	offset := v.Uint64()
	v.SetBytes(scope.Memory.GetPtr(offset, 32))
	return nil, nil
}

// opMstore 执行 MSTORE 操作码：将栈顶元素存储到内存。
func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.Set32(mStart.Uint64(), &val)
	return nil, nil
}

// opMstore8 执行 MSTORE8 操作码：将栈顶元素的低 8 位存储到内存。
func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	scope.Memory.store[off.Uint64()] = byte(val.Uint64())
	return nil, nil
}

// opSload 执行 SLOAD 操作码：从存储中加载值到栈。
func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())
	return nil, nil
}

// opSstore 执行 SSTORE 操作码：将值存储到存储中。
func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := scope.Stack.pop()
	val := scope.Stack.pop()
	interpreter.evm.StateDB.SetState(scope.Contract.Address(), loc.Bytes32(), val.Bytes32())
	return nil, nil
}

// opJump 执行 JUMP 操作码：跳转到指定位置。
func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.evm.abort.Load() {
		return nil, errStopToken
	}
	pos := scope.Stack.pop()
	if !scope.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump
	}
	*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	return nil, nil
}

// opJumpi 执行 JUMPI 操作码：条件跳转。
func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.evm.abort.Load() {
		return nil, errStopToken
	}
	pos, cond := scope.Stack.pop(), scope.Stack.pop()
	if !cond.IsZero() {
		if !scope.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump
		}
		*pc = pos.Uint64() - 1 // pc will be increased by the interpreter loop
	}
	return nil, nil
}

// opJumpdest 执行 JUMPDEST 操作码：跳转目的地，空操作。
func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, nil
}

// opPc 执行 PC 操作码：将程序计数器压入栈。
func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	return nil, nil
}

// opMsize 执行 MSIZE 操作码：将内存大小压入栈。
func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	return nil, nil
}

// opGas 执行 GAS 操作码：将剩余 gas 压入栈。
func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	return nil, nil
}

// opSwap1 执行 SWAP1 操作码：交换栈顶和栈顶以下第一个元素。
func opSwap1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap1()
	return nil, nil
}

// opSwap2 执行 SWAP2 操作码：交换栈顶和栈顶以下第二个元素。
func opSwap2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap2()
	return nil, nil
}

// opSwap3 执行 SWAP3 操作码：交换栈顶和栈顶以下第三个元素。
func opSwap3(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap3()
	return nil, nil
}

// opSwap4 执行 SWAP4 操作码：交换栈顶和栈顶以下第四个元素。
func opSwap4(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap4()
	return nil, nil
}

// opSwap5 执行 SWAP5 操作码：交换栈顶和栈顶以下第五个元素。
func opSwap5(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap5()
	return nil, nil
}

// opSwap6 执行 SWAP6 操作码：交换栈顶和栈顶以下第六个元素。
func opSwap6(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap6()
	return nil, nil
}

// opSwap7 执行 SWAP7 操作码：交换栈顶和栈顶以下第七个元素。
func opSwap7(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap7()
	return nil, nil
}

// opSwap8 执行 SWAP8 操作码：交换栈顶和栈顶以下第八个元素。
func opSwap8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap8()
	return nil, nil
}

// opSwap9 执行 SWAP9 操作码：交换栈顶和栈顶以下第九个元素。
func opSwap9(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap9()
	return nil, nil
}

// opSwap10 执行 SWAP10 操作码：交换栈顶和栈顶以下第十个元素。
func opSwap10(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap10()
	return nil, nil
}

// opSwap11 执行 SWAP11 操作码：交换栈顶和栈顶以下第十一个元素。
func opSwap11(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap11()
	return nil, nil
}

// opSwap12 执行 SWAP12 操作码：交换栈顶和栈顶以下第十二个元素。
func opSwap12(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap12()
	return nil, nil
}

// opSwap13 执行 SWAP13 操作码：交换栈顶和栈顶以下第十三个元素。
func opSwap13(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap13()
	return nil, nil
}

// opSwap14 执行 SWAP14 操作码：交换栈顶和栈顶以下第十四个元素。
func opSwap14(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap14()
	return nil, nil
}

// opSwap15 执行 SWAP15 操作码：交换栈顶和栈顶以下第十五个元素。
func opSwap15(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap15()
	return nil, nil
}

// opSwap16 执行 SWAP16 操作码：交换栈顶和栈顶以下第十六个元素。
func opSwap16(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.swap16()
	return nil, nil
}

// opCreate 执行 CREATE 操作码：创建新合约。
func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(offset.Uint64(), size.Uint64())
		gas          = scope.Contract.Gas
	)
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}

	// reuse size int for stackvalue
	// 重用 size int 作为 stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas, interpreter.evm.Config.Tracer, tracing.GasChangeCallContractCreation)

	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, &value)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	// 根据返回的错误将项压入栈。如果规则集是 homestead，我们必须检查 CodeStoreOutOfGasError（仅 homestead 规则）
	// 并将其视为错误，如果规则集是 frontier，我们必须忽略此错误并假装操作成功。
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)

	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

// opCreate2 执行 CREATE2 操作码：使用 salt 创建新合约。
func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(offset.Uint64(), size.Uint64())
		gas          = scope.Contract.Gas
	)

	// Apply EIP150
	// 应用 EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas, interpreter.evm.Config.Tracer, tracing.GasChangeCallContractCreation2)
	// reuse size int for stackvalue
	// 重用 size int 作为 stackvalue
	stackvalue := size
	res, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		&endowment, &salt)
	// Push item on the stack based on the returned error.
	// 根据返回的错误将项压入栈。
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	if suberr == ErrExecutionReverted {
		interpreter.returnData = res // set REVERT data to return data buffer
		return res, nil
	}
	interpreter.returnData = nil // clear dirty return data buffer
	return nil, nil
}

// opCall 执行 CALL 操作码：调用另一个合约。
func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	// 弹出 gas。实际 gas 在 interpreter.evm.callGasTemp 中。
	// 我们可以将其用作临时值
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	// 弹出其他调用参数。
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	// 从内存中获取参数。
	args := scope.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())

	if interpreter.readOnly && !value.IsZero() {
		return nil, ErrWriteProtection
	}
	if !value.IsZero() {
		gas += params.CallStipend
	}
	ret, returnGas, err := interpreter.evm.Call(scope.Contract, toAddr, args, gas, &value)

	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	interpreter.returnData = ret
	return ret, nil
}

// opCallCode 执行 CALLCODE 操作码：以当前合约上下文执行目标合约代码。
func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// 弹出 gas。实际 gas 在 interpreter.evm.callGasTemp 中。
	stack := scope.Stack
	// We use it as a temporary value
	// 我们将其用作临时值
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	// 弹出其他调用参数。
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	// 从内存中获取参数。
	args := scope.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())

	if !value.IsZero() {
		gas += params.CallStipend
	}

	ret, returnGas, err := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, &value)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	interpreter.returnData = ret
	return ret, nil
}

// opDelegateCall 执行 DELEGATECALL 操作码：以调用者上下文执行目标合约代码。
func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// 弹出 gas。实际 gas 在 interpreter.evm.callGasTemp 中。
	// We use it as a temporary value
	// 我们将其用作临时值
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	// 弹出其他调用参数。
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	// 从内存中获取参数。
	args := scope.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())

	ret, returnGas, err := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	interpreter.returnData = ret
	return ret, nil
}

// opStaticCall 执行 STATICCALL 操作码：静态调用目标合约，禁止状态修改。
func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// 弹出 gas。实际 gas 在 interpreter.evm.callGasTemp 中。
	stack := scope.Stack
	// We use it as a temporary value
	// 我们将其用作临时值
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	// 弹出其他调用参数。
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()
	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	// 从内存中获取参数。
	args := scope.Memory.GetPtr(inOffset.Uint64(), inSize.Uint64())

	ret, returnGas, err := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}

	scope.Contract.RefundGas(returnGas, interpreter.evm.Config.Tracer, tracing.GasChangeCallLeftOverRefunded)

	interpreter.returnData = ret
	return ret, nil
}

// opReturn 执行 RETURN 操作码：返回内存中的数据。
func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetCopy(offset.Uint64(), size.Uint64())

	return ret, errStopToken
}

// opRevert 执行 REVERT 操作码：回滚状态并返回数据。
func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	ret := scope.Memory.GetCopy(offset.Uint64(), size.Uint64())

	interpreter.returnData = ret
	return ret, ErrExecutionReverted
}

// opUndefined 执行未定义操作码：返回错误。
func opUndefined(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, &ErrInvalidOpCode{opcode: OpCode(scope.Contract.Code[*pc])}
}

// opStop 执行 STOP 操作码：停止执行。
func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, errStopToken
}

// opSelfdestruct 执行 SELFDESTRUCT 操作码：自毁合约。
func opSelfdestruct(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	beneficiary := scope.Stack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance, tracing.BalanceIncreaseSelfdestruct)
	interpreter.evm.StateDB.SelfDestruct(scope.Contract.Address())
	if tracer := interpreter.evm.Config.Tracer; tracer != nil {
		if tracer.OnEnter != nil {
			tracer.OnEnter(interpreter.evm.depth, byte(SELFDESTRUCT), scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance.ToBig())
		}
		if tracer.OnExit != nil {
			tracer.OnExit(interpreter.evm.depth, []byte{}, 0, nil, false)
		}
	}
	return nil, errStopToken
}

// opSelfdestruct6780 执行 SELFDESTRUCT 操作码（EIP-6780 版本）：自毁合约。
func opSelfdestruct6780(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	beneficiary := scope.Stack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.SubBalance(scope.Contract.Address(), balance, tracing.BalanceDecreaseSelfdestruct)
	interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance, tracing.BalanceIncreaseSelfdestruct)
	interpreter.evm.StateDB.SelfDestruct6780(scope.Contract.Address())
	if tracer := interpreter.evm.Config.Tracer; tracer != nil {
		if tracer.OnEnter != nil {
			tracer.OnEnter(interpreter.evm.depth, byte(SELFDESTRUCT), scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance.ToBig())
		}
		if tracer.OnExit != nil {
			tracer.OnExit(interpreter.evm.depth, []byte{}, 0, nil, false)
		}
	}
	return nil, errStopToken
}

// following functions are used by the instruction jump  table
// 以下函数由指令跳转表使用

// make log instruction function
// 创建 log 指令函数
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		if interpreter.readOnly {
			return nil, ErrWriteProtection
		}
		topics := make([]common.Hash, size)
		stack := scope.Stack
		mStart, mSize := stack.pop(), stack.pop()
		for i := 0; i < size; i++ {
			addr := stack.pop()
			topics[i] = addr.Bytes32()
		}

		d := scope.Memory.GetCopy(mStart.Uint64(), mSize.Uint64())
		interpreter.evm.StateDB.AddLog(&types.Log{
			Address: scope.Contract.Address(),
			Topics:  topics,
			Data:    d,
			// This is a non-consensus field, but assigned here because
			// core/state doesn't know the current block number.
			// 这是一个非共识字段，但在这里分配，因为 core/state 不知道当前的块号。
			BlockNumber: interpreter.evm.Context.BlockNumber.Uint64(),
		})

		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
// opPush1 是 pushN 的特化版本
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
	} else {
		scope.Stack.push(integer.Clear())
	}
	return nil, nil
}

// make push instruction function
// 创建 push 指令函数
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		var (
			codeLen = len(scope.Contract.Code)
			start   = min(codeLen, int(*pc+1))
			end     = min(codeLen, start+pushByteSize)
		)
		a := new(uint256.Int).SetBytes(scope.Contract.Code[start:end])

		// Missing bytes: pushByteSize - len(pushData)
		// 缺失的字节：pushByteSize - len(pushData)
		if missing := pushByteSize - (end - start); missing > 0 {
			a.Lsh(a, uint(8*missing))
		}
		scope.Stack.push(a)
		*pc += size
		return nil, nil
	}
}

// make dup instruction function
// 创建 dup 指令函数
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.dup(int(size))
		return nil, nil
	}
}
