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

package vm

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

// memoryGasCost calculates the quadratic gas for memory expansion. It does so
// only for the memory region that is expanded, not the total memory.
// memoryGasCost 计算内存扩展的二次方 gas 成本。它只计算扩展的内存区域，而不是总内存。
func memoryGasCost(mem *Memory, newMemSize uint64) (uint64, error) {
	if newMemSize == 0 {
		return 0, nil
	}
	// The maximum that will fit in a uint64 is max_word_count - 1. Anything above
	// that will result in an overflow. Additionally, a newMemSize which results in
	// a newMemSizeWords larger than 0xFFFFFFFF will cause the square operation to
	// overflow. The constant 0x1FFFFFFFE0 is the highest number that can be used
	// without overflowing the gas calculation.
	// 能放入 uint64 的最大值是 max_word_count - 1。超出此值将导致溢出。此外，如果 newMemSize 导致
	// newMemSizeWords 大于 0xFFFFFFFF，则平方运算将溢出。常数 0x1FFFFFFFE0 是在不溢出 gas 计算的情况下可以使用的最大值。
	if newMemSize > 0x1FFFFFFFE0 {
		return 0, ErrGasUintOverflow
	}
	// 计算新内存大小的字数
	newMemSizeWords := toWordSize(newMemSize)
	// 将字数转换为字节数（每个字 32 字节）
	newMemSize = newMemSizeWords * 32

	if newMemSize > uint64(mem.Len()) {
		// 计算二次方项
		square := newMemSizeWords * newMemSizeWords
		// 计算线性系数
		linCoef := newMemSizeWords * params.MemoryGas
		// 计算二次方系数
		quadCoef := square / params.QuadCoeffDiv
		// 计算新的总费用
		newTotalFee := linCoef + quadCoef

		// 计算实际费用（新总费用减去上次记录的费用）
		fee := newTotalFee - mem.lastGasCost
		// 更新上次记录的 gas 成本
		mem.lastGasCost = newTotalFee

		return fee, nil
	}
	return 0, nil
}

// memoryCopierGas creates the gas functions for the following opcodes, and takes
// the stack position of the operand which determines the size of the data to copy
// as argument:
// CALLDATACOPY (stack position 2)
// CODECOPY (stack position 2)
// MCOPY (stack position 2)
// EXTCODECOPY (stack position 3)
// RETURNDATACOPY (stack position 2)
// memoryCopierGas 为以下操作码创建 gas 函数，并将决定要复制的数据大小的操作数在栈中的位置作为参数：
// CALLDATACOPY（栈位置 2）
// CODECOPY（栈位置 2）
// MCOPY（栈位置 2）
// EXTCODECOPY（栈位置 3）
// RETURNDATACOPY（栈位置 2）
func memoryCopierGas(stackpos int) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		// Gas for expanding the memory
		// 内存扩展的 gas
		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		// And gas for copying data, charged per word at param.CopyGas
		// 以及复制数据的 gas，按每个字 param.CopyGas 收费
		// 从栈中获取要复制的字数
		words, overflow := stack.Back(stackpos).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}

		// 计算复制数据的 gas 成本
		if words, overflow = math.SafeMul(toWordSize(words), params.CopyGas); overflow {
			return 0, ErrGasUintOverflow
		}

		// 将内存扩展和复制的 gas 相加
		if gas, overflow = math.SafeAdd(gas, words); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

// 中文注解：定义多个全局变量，用于存储不同操作码的 gas 计算函数
var (
	gasCallDataCopy   = memoryCopierGas(2) // CALLDATACOPY 的 gas 函数
	gasCodeCopy       = memoryCopierGas(2) // CODECOPY 的 gas 函数
	gasMcopy          = memoryCopierGas(2) // MCOPY 的 gas 函数
	gasExtCodeCopy    = memoryCopierGas(3) // EXTCODECOPY 的 gas 函数
	gasReturnDataCopy = memoryCopierGas(2) // RETURNDATACOPY 的 gas 函数
)

func gasSStore(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		y, x    = stack.Back(1), stack.Back(0)
		current = evm.StateDB.GetState(contract.Address(), x.Bytes32())
	)
	// The legacy gas metering only takes into consideration the current state
	// Legacy rules should be applied if we are in Petersburg (removal of EIP-1283)
	// OR Constantinople is not active
	// 旧版 gas 计量仅考虑当前状态
	// 如果我们在 Petersburg（移除了 EIP-1283）或 Constantinople 未激活，则应应用旧版规则
	if evm.chainRules.IsPetersburg || !evm.chainRules.IsConstantinople {
		// This checks for 3 scenarios and calculates gas accordingly:
		//
		// 1. From a zero-value address to a non-zero value         (NEW VALUE)
		// 2. From a non-zero value address to a zero-value address (DELETE)
		// 3. From a non-zero to a non-zero                         (CHANGE)
		// 这检查了 3 种情况并相应地计算 gas：
		//
		// 1. 从零值地址到非零值（新值）
		// 2. 从非零值地址到零值地址（删除）
		// 3. 从非零到非零（更改）
		switch {
		case current == (common.Hash{}) && y.Sign() != 0: // 0 => non 0
			return params.SstoreSetGas, nil
		case current != (common.Hash{}) && y.Sign() == 0: // non 0 => 0
			evm.StateDB.AddRefund(params.SstoreRefundGas)
			return params.SstoreClearGas, nil
		default: // non 0 => non 0 (or 0 => 0)
			return params.SstoreResetGas, nil
		}
	}

	// The new gas metering is based on net gas costs (EIP-1283):
	//
	// (1.) If current value equals new value (this is a no-op), 200 gas is deducted.
	// (2.) If current value does not equal new value
	//	(2.1.) If original value equals current value (this storage slot has not been changed by the current execution context)
	//		(2.1.1.) If original value is 0, 20000 gas is deducted.
	//		(2.1.2.) Otherwise, 5000 gas is deducted. If new value is 0, add 15000 gas to refund counter.
	//	(2.2.) If original value does not equal current value (this storage slot is dirty), 200 gas is deducted. Apply both of the following clauses.
	//		(2.2.1.) If original value is not 0
	//			(2.2.1.1.) If current value is 0 (also means that new value is not 0), remove 15000 gas from refund counter. We can prove that refund counter will never go below 0.
	//			(2.2.1.2.) If new value is 0 (also means that current value is not 0), add 15000 gas to refund counter.
	//		(2.2.2.) If original value equals new value (this storage slot is reset)
	//			(2.2.2.1.) If original value is 0, add 19800 gas to refund counter.
	//			(2.2.2.2.) Otherwise, add 4800 gas to refund counter.
	// 新的 gas 计量基于净 gas 成本（EIP-1283）：
	//
	// (1.) 如果当前值等于新值（这是无操作），扣除 200 gas。
	// (2.) 如果当前值不等于新值
	//	(2.1.) 如果原始值等于当前值（此存储槽未被当前执行上下文更改）
	//		(2.1.1.) 如果原始值为 0，扣除 20000 gas。
	//		(2.1.2.) 否则，扣除 5000 gas。如果新值为 0，则将 15000 gas 添加到退款计数器。
	//	(2.2.) 如果原始值不等于当前值（此存储槽是脏的），扣除 200 gas。应用以下两个子句。
	//		(2.2.1.) 如果原始值不为 0
	//			(2.2.1.1.) 如果当前值为 0（也意味着新值不为 0），从退款计数器中减去 15000 gas。我们可以证明退款计数器永远不会低于 0。
	//			(2.2.1.2.) 如果新值为 0（也意味着当前值不为 0），将 15000 gas 添加到退款计数器。
	//		(2.2.2.) 如果原始值等于新值（此存储槽被重置）
	//			(2.2.2.1.) 如果原始值为 0，将 19800 gas 添加到退款计数器。
	//			(2.2.2.2.) 否则，将 4800 gas 添加到退款计数器。
	// 获取新值
	value := common.Hash(y.Bytes32())
	if current == value { // noop (1)
		return params.NetSstoreNoopGas, nil
	}
	// 获取原始值
	original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return params.NetSstoreInitGas, nil
		}
		if value == (common.Hash{}) { // delete slot (2.1.2b)
			evm.StateDB.AddRefund(params.NetSstoreClearRefund)
		}
		return params.NetSstoreCleanGas, nil // write existing slot (2.1.2)
	}
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			evm.StateDB.SubRefund(params.NetSstoreClearRefund)
		} else if value == (common.Hash{}) { // delete slot (2.2.1.2)
			evm.StateDB.AddRefund(params.NetSstoreClearRefund)
		}
	}
	if original == value {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			evm.StateDB.AddRefund(params.NetSstoreResetClearRefund)
		} else { // reset to original existing slot (2.2.2.2)
			evm.StateDB.AddRefund(params.NetSstoreResetRefund)
		}
	}
	return params.NetSstoreDirtyGas, nil
}

// Here come the EIP2200 rules:
//
//	(0.) If *gasleft* is less than or equal to 2300, fail the current call.
//	(1.) If current value equals new value (this is a no-op), SLOAD_GAS is deducted.
//	(2.) If current value does not equal new value:
//		(2.1.) If original value equals current value (this storage slot has not been changed by the current execution context):
//			(2.1.1.) If original value is 0, SSTORE_SET_GAS (20K) gas is deducted.
//			(2.1.2.) Otherwise, SSTORE_RESET_GAS gas is deducted. If new value is 0, add SSTORE_CLEARS_SCHEDULE to refund counter.
//		(2.2.) If original value does not equal current value (this storage slot is dirty), SLOAD_GAS gas is deducted. Apply both of the following clauses:
//			(2.2.1.) If original value is not 0:
//				(2.2.1.1.) If current value is 0 (also means that new value is not 0), subtract SSTORE_CLEARS_SCHEDULE gas from refund counter.
//				(2.2.1.2.) If new value is 0 (also means that current value is not 0), add SSTORE_CLEARS_SCHEDULE gas to refund counter.
//			(2.2.2.) If original value equals new value (this storage slot is reset):
//				(2.2.2.1.) If original value is 0, add SSTORE_SET_GAS - SLOAD_GAS to refund counter.
//				(2.2.2.2.) Otherwise, add SSTORE_RESET_GAS - SLOAD_GAS gas to refund counter.
//
// 以下是 EIP2200 规则：
//
//	(0.) 如果 *gasleft* 小于或等于 2300，则当前调用失败。
//	(1.) 如果当前值等于新值（这是无操作），扣除 SLOAD_GAS。
//	(2.) 如果当前值不等于新值：
//		(2.1.) 如果原始值等于当前值（此存储槽未被当前执行上下文更改）：
//			(2.1.1.) 如果原始值为 0，扣除 SSTORE_SET_GAS (20K) gas。
//			(2.1.2.) 否则，扣除 SSTORE_RESET_GAS gas。如果新值为 0，则将 SSTORE_CLEARS_SCHEDULE 添加到退款计数器。
//		(2.2.) 如果原始值不等于当前值（此存储槽是脏的），扣除 SLOAD_GAS gas。应用以下两个子句：
//			(2.2.1.) 如果原始值不为 0：
//				(2.2.1.1.) 如果当前值为 0（也意味着新值不为 0），从退款计数器中减去 SSTORE_CLEARS_SCHEDULE gas。
//				(2.2.1.2.) 如果新值为 0（也意味着当前值不为 0），将 SSTORE_CLEARS_SCHEDULE gas 添加到退款计数器。
//			(2.2.2.) 如果原始值等于新值（此存储槽被重置）：
//				(2.2.2.1.) 如果原始值为 0，将 SSTORE_SET_GAS - SLOAD_GAS 添加到退款计数器。
//				(2.2.2.2.) 否则，将 SSTORE_RESET_GAS - SLOAD_GAS gas 添加到退款计数器。
func gasSStoreEIP2200(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// If we fail the minimum gas availability invariant, fail (0)
	// 如果我们未能满足最小 gas 可用性不变式，则失败 (0)
	if contract.Gas <= params.SstoreSentryGasEIP2200 {
		return 0, errors.New("not enough gas for reentrancy sentry")
	}
	// Gas sentry honoured, do the actual gas calculation based on the stored value
	// Gas 哨兵已遵守，根据存储的值进行实际的 gas 计算
	var (
		y, x    = stack.Back(1), stack.Back(0)
		current = evm.StateDB.GetState(contract.Address(), x.Bytes32())
	)
	// 获取新值
	value := common.Hash(y.Bytes32())

	if current == value { // noop (1)
		return params.SloadGasEIP2200, nil
	}
	// 获取原始值
	original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
	if original == current {
		if original == (common.Hash{}) { // create slot (2.1.1)
			return params.SstoreSetGasEIP2200, nil
		}
		if value == (common.Hash{}) { // delete slot (2.1.2b)
			evm.StateDB.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
		return params.SstoreResetGasEIP2200, nil // write existing slot (2.1.2)
	}
	if original != (common.Hash{}) {
		if current == (common.Hash{}) { // recreate slot (2.2.1.1)
			evm.StateDB.SubRefund(params.SstoreClearsScheduleRefundEIP2200)
		} else if value == (common.Hash{}) { // delete slot (2.2.1.2)
			evm.StateDB.AddRefund(params.SstoreClearsScheduleRefundEIP2200)
		}
	}
	if original == value {
		if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
			evm.StateDB.AddRefund(params.SstoreSetGasEIP2200 - params.SloadGasEIP2200)
		} else { // reset to original existing slot (2.2.2.2)
			evm.StateDB.AddRefund(params.SstoreResetGasEIP2200 - params.SloadGasEIP2200)
		}
	}
	return params.SloadGasEIP2200, nil // dirty update (2.2)
}

// 中文注解：创建日志操作的 gas 计算函数，n 表示主题数量
func makeGasLog(n uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		requestedSize, overflow := stack.Back(1).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}

		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}

		// 添加基础日志 gas
		if gas, overflow = math.SafeAdd(gas, params.LogGas); overflow {
			return 0, ErrGasUintOverflow
		}
		// 添加主题相关的 gas
		if gas, overflow = math.SafeAdd(gas, n*params.LogTopicGas); overflow {
			return 0, ErrGasUintOverflow
		}

		var memorySizeGas uint64
		// 计算数据部分的 gas
		if memorySizeGas, overflow = math.SafeMul(requestedSize, params.LogDataGas); overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = math.SafeAdd(gas, memorySizeGas); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

// 中文注解：计算 Keccak256 哈希操作的 gas 成本
func gasKeccak256(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 获取要哈希的数据字数
	wordGas, overflow := stack.Back(1).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if wordGas, overflow = math.SafeMul(toWordSize(wordGas), params.Keccak256WordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = math.SafeAdd(gas, wordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// pureMemoryGascost is used by several operations, which aside from their
// static cost have a dynamic cost which is solely based on the memory
// expansion
// pureMemoryGascost 由几个操作使用，这些操作除了静态成本外，还有一个仅基于内存扩展的动态成本
func pureMemoryGascost(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryGasCost(mem, memorySize)
}

// 中文注解：定义多个全局变量，用于存储仅依赖内存扩展的 gas 计算函数
var (
	gasReturn  = pureMemoryGascost // RETURN 操作的 gas 函数
	gasRevert  = pureMemoryGascost // REVERT 操作的 gas 函数
	gasMLoad   = pureMemoryGascost // MLOAD 操作的 gas 函数
	gasMStore8 = pureMemoryGascost // MSTORE8 操作的 gas 函数
	gasMStore  = pureMemoryGascost // MSTORE 操作的 gas 函数
	gasCreate  = pureMemoryGascost // CREATE 操作的 gas 函数
)

// 中文注解：计算 CREATE2 操作的 gas 成本
func gasCreate2(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 获取初始化代码的字数
	wordGas, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	// 计算 Keccak256 哈希的 gas 成本
	if wordGas, overflow = math.SafeMul(toWordSize(wordGas), params.Keccak256WordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = math.SafeAdd(gas, wordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算基于 EIP-3860 的 CREATE 操作的 gas 成本
func gasCreateEip3860(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 获取初始化代码大小
	size, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if size > params.MaxInitCodeSize {
		return 0, fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
	}
	// Since size <= params.MaxInitCodeSize, these multiplication cannot overflow
	// 由于 size <= params.MaxInitCodeSize，这些乘法不会溢出
	// 计算额外的初始化代码 gas
	moreGas := params.InitCodeWordGas * ((size + 31) / 32)
	if gas, overflow = math.SafeAdd(gas, moreGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算基于 EIP-3860 的 CREATE2 操作的 gas 成本
func gasCreate2Eip3860(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 获取初始化代码大小
	size, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if size > params.MaxInitCodeSize {
		return 0, fmt.Errorf("%w: size %d", ErrMaxInitCodeSizeExceeded, size)
	}
	// Since size <= params.MaxInitCodeSize, these multiplication cannot overflow
	// 由于 size <= params.MaxInitCodeSize，这些乘法不会溢出
	// 计算额外的初始化代码和 Keccak256 的 gas
	moreGas := (params.InitCodeWordGas + params.Keccak256WordGas) * ((size + 31) / 32)
	if gas, overflow = math.SafeAdd(gas, moreGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 Frontier 版本的 EXP 操作的 gas 成本
func gasExpFrontier(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// 计算指数的字节长度
	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)

	var (
		gas      = expByteLen * params.ExpByteFrontier // no overflow check required. Max is 256 * ExpByte gas
		overflow bool
	)
	if gas, overflow = math.SafeAdd(gas, params.ExpGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 EIP-158 版本的 EXP 操作的 gas 成本
func gasExpEIP158(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// 计算指数的字节长度
	expByteLen := uint64((stack.data[stack.len()-2].BitLen() + 7) / 8)

	var (
		gas      = expByteLen * params.ExpByteEIP158 // no overflow check required. Max is 256 * ExpByte gas
		overflow bool
	)
	if gas, overflow = math.SafeAdd(gas, params.ExpGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 CALL 操作的 gas 成本
func gasCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var (
		gas            uint64
		transfersValue = !stack.Back(2).IsZero()
		address        = common.Address(stack.Back(1).Bytes20())
	)
	// 根据 EIP-158 规则检查新账户创建
	if evm.chainRules.IsEIP158 {
		if transfersValue && evm.StateDB.Empty(address) {
			gas += params.CallNewAccountGas
		}
	} else if !evm.StateDB.Exist(address) {
		gas += params.CallNewAccountGas
	}
	// 如果有值转移且未激活 EIP-4762，增加转移 gas
	if transfersValue && !evm.chainRules.IsEIP4762 {
		gas += params.CallValueTransferGas
	}
	memoryGas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = math.SafeAdd(gas, memoryGas); overflow {
		return 0, ErrGasUintOverflow
	}
	// 如果激活 EIP-4762，计算值转移的额外 gas
	if evm.chainRules.IsEIP4762 {
		if transfersValue {
			gas, overflow = math.SafeAdd(gas, evm.AccessEvents.ValueTransferGas(contract.Address(), address))
			if overflow {
				return 0, ErrGasUintOverflow
			}
		}
	}
	// 计算调用所需的 gas
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	if gas, overflow = math.SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}

	return gas, nil
}

// 中文注解：计算 CALLCODE 操作的 gas 成本
func gasCallCode(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	memoryGas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	var (
		gas      uint64
		overflow bool
	)
	// 如果有值转移且未激活 EIP-4762，增加转移 gas
	if stack.Back(2).Sign() != 0 && !evm.chainRules.IsEIP4762 {
		gas += params.CallValueTransferGas
	}
	if gas, overflow = math.SafeAdd(gas, memoryGas); overflow {
		return 0, ErrGasUintOverflow
	}
	// 如果激活 EIP-4762，计算值转移的额外 gas
	if evm.chainRules.IsEIP4762 {
		address := common.Address(stack.Back(1).Bytes20())
		transfersValue := !stack.Back(2).IsZero()
		if transfersValue {
			gas, overflow = math.SafeAdd(gas, evm.AccessEvents.ValueTransferGas(contract.Address(), address))
			if overflow {
				return 0, ErrGasUintOverflow
			}
		}
	}
	// 计算调用所需的 gas
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	if gas, overflow = math.SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 DELEGATECALL 操作的 gas 成本
func gasDelegateCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 计算调用所需的 gas
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = math.SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 STATICCALL 操作的 gas 成本
func gasStaticCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 计算调用所需的 gas
	evm.callGasTemp, err = callGas(evm.chainRules.IsEIP150, contract.Gas, gas, stack.Back(0))
	if err != nil {
		return 0, err
	}
	var overflow bool
	if gas, overflow = math.SafeAdd(gas, evm.callGasTemp); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// 中文注解：计算 SELFDESTRUCT 操作的 gas 成本
func gasSelfdestruct(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	var gas uint64
	// EIP150 homestead gas reprice fork:
	// EIP150 homestead gas 重新定价分叉：
	if evm.chainRules.IsEIP150 {
		gas = params.SelfdestructGasEIP150
		var address = common.Address(stack.Back(0).Bytes20())

		if evm.chainRules.IsEIP158 {
			// if empty and transfers value
			// 如果为空且转移值
			if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
				gas += params.CreateBySelfdestructGas
			}
		} else if !evm.StateDB.Exist(address) {
			gas += params.CreateBySelfdestructGas
		}
	}

	// 如果合约未自毁，添加退款
	if !evm.StateDB.HasSelfDestructed(contract.Address()) {
		evm.StateDB.AddRefund(params.SelfdestructRefundGas)
	}
	return gas, nil
}

// 中文注解：计算扩展调用操作的 gas 成本（未实现）
func gasExtCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	panic("not implemented")
}

// 中文注解：计算扩展委托调用操作的 gas 成本（未实现）
func gasExtDelegateCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	panic("not implemented")
}

// 中文注解：计算扩展静态调用操作的 gas 成本（未实现）
func gasExtStaticCall(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	panic("not implemented")
}

// gasEOFCreate returns the gas-cost for EOF-Create. Hashing charge needs to be
// deducted in the opcode itself, since it depends on the immediate
// gasEOFCreate 返回 EOF-Create 的 gas 成本。哈希费用需要在操作码本身中扣除，因为它取决于立即数
func gasEOFCreate(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	panic("not implemented")
}
