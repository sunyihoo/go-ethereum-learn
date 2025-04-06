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

import (
	gomath "math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

func gasSStore4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算SSTORE的EIP-4762 Gas成本
	gas := evm.AccessEvents.SlotGas(contract.Address(), stack.peek().Bytes32(), true) // 获取槽的Gas成本（写操作）
	if gas == 0 {                                                                     // 如果未定义Gas成本
		gas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	return gas, nil // 返回Gas成本和无错误
}

func gasSLoad4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算SLOAD的EIP-4762 Gas成本
	gas := evm.AccessEvents.SlotGas(contract.Address(), stack.peek().Bytes32(), false) // 获取槽的Gas成本（读操作）
	if gas == 0 {                                                                      // 如果未定义Gas成本
		gas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	return gas, nil // 返回Gas成本和无错误
}

func gasBalance4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算BALANCE的EIP-4762 Gas成本
	address := stack.peek().Bytes20()                    // 从栈顶获取地址（20字节）
	gas := evm.AccessEvents.BasicDataGas(address, false) // 获取基本数据Gas成本（读操作）
	if gas == 0 {                                        // 如果未定义Gas成本
		gas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	return gas, nil // 返回Gas成本和无错误
}

func gasExtCodeSize4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算EXTCODESIZE的EIP-4762 Gas成本
	address := stack.peek().Bytes20()                             // 从栈顶获取地址（20字节）
	if _, isPrecompile := evm.precompile(address); isPrecompile { // 如果是预编译合约
		return 0, nil // 返回0 Gas成本
	}
	gas := evm.AccessEvents.BasicDataGas(address, false) // 获取基本数据Gas成本（读操作）
	if gas == 0 {                                        // 如果未定义Gas成本
		gas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	return gas, nil // 返回Gas成本和无错误
}

func gasExtCodeHash4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算EXTCODEHASH的EIP-4762 Gas成本
	address := stack.peek().Bytes20()                             // 从栈顶获取地址（20字节）
	if _, isPrecompile := evm.precompile(address); isPrecompile { // 如果是预编译合约
		return 0, nil // 返回0 Gas成本
	}
	gas := evm.AccessEvents.CodeHashGas(address, false) // 获取代码哈希Gas成本（读操作）
	if gas == 0 {                                       // 如果未定义Gas成本
		gas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	return gas, nil // 返回Gas成本和无错误
}

func makeCallVariantGasEIP4762(oldCalculator gasFunc) gasFunc { // 创建EIP-4762调用变体的Gas计算函数
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 返回新的Gas计算函数
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize) // 调用旧的Gas计算器
		if err != nil {                                                  // 如果出错
			return 0, err // 返回错误
		}
		if _, isPrecompile := evm.precompile(contract.Address()); isPrecompile { // 如果是预编译合约
			return gas, nil // 直接返回旧Gas成本
		}
		witnessGas := evm.AccessEvents.MessageCallGas(contract.Address()) // 获取消息调用Gas成本
		if witnessGas == 0 {                                              // 如果未定义Gas成本
			witnessGas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
		}
		return witnessGas + gas, nil // 返回总Gas成本（旧成本+见证Gas）
	}
}

var (
	gasCallEIP4762         = makeCallVariantGasEIP4762(gasCall)         // EIP-4762的CALL Gas计算
	gasCallCodeEIP4762     = makeCallVariantGasEIP4762(gasCallCode)     // EIP-4762的CALLCODE Gas计算
	gasStaticCallEIP4762   = makeCallVariantGasEIP4762(gasStaticCall)   // EIP-4762的STATICCALL Gas计算
	gasDelegateCallEIP4762 = makeCallVariantGasEIP4762(gasDelegateCall) // EIP-4762的DELEGATECALL Gas计算
)

func gasSelfdestructEIP4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算SELFDESTRUCT的EIP-4762 Gas成本
	beneficiaryAddr := common.Address(stack.peek().Bytes20())             // 从栈顶获取受益人地址
	if _, isPrecompile := evm.precompile(beneficiaryAddr); isPrecompile { // 如果受益人是预编译合约
		return 0, nil // 返回0 Gas成本
	}
	contractAddr := contract.Address()                                 // 获取合约地址
	statelessGas := evm.AccessEvents.BasicDataGas(contractAddr, false) // 获取合约的基本数据Gas成本（读操作）
	if contractAddr != beneficiaryAddr {                               // 如果合约地址和受益人地址不同
		statelessGas += evm.AccessEvents.BasicDataGas(beneficiaryAddr, false) // 增加受益人的基本数据Gas成本
	}
	// Charge write costs if it transfers value
	// 如果转移价值，则收取写操作成本
	if evm.StateDB.GetBalance(contractAddr).Sign() != 0 { // 如果合约余额非零
		statelessGas += evm.AccessEvents.BasicDataGas(contractAddr, true) // 增加合约的写操作Gas成本
		if contractAddr != beneficiaryAddr {                              // 如果合约地址和受益人地址不同
			statelessGas += evm.AccessEvents.BasicDataGas(beneficiaryAddr, true) // 增加受益人的写操作Gas成本
		}
	}
	return statelessGas, nil // 返回总Gas成本
}

func gasCodeCopyEip4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算CODECOPY的EIP-4762 Gas成本
	gas, err := gasCodeCopy(evm, contract, stack, mem, memorySize) // 调用旧的CODECOPY Gas计算
	if err != nil {                                                // 如果出错
		return 0, err // 返回错误
	}
	var (
		codeOffset = stack.Back(1) // 获取代码偏移量（栈第2项）
		length     = stack.Back(2) // 获取复制长度（栈第3项）
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow() // 转换为uint64并检查溢出
	if overflow {                                                 // 如果溢出
		uint64CodeOffset = gomath.MaxUint64 // 设置为最大值
	}
	_, copyOffset, nonPaddedCopyLength := getDataAndAdjustedBounds(contract.Code, uint64CodeOffset, length.Uint64()) // 获取调整后的复制范围
	if !contract.IsDeployment {                                                                                      // 如果不是部署交易
		gas += evm.AccessEvents.CodeChunksRangeGas(contract.Address(), copyOffset, nonPaddedCopyLength, uint64(len(contract.Code)), false) // 增加代码块范围Gas成本
	}
	return gas, nil // 返回总Gas成本
}

func gasExtCodeCopyEIP4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) { // 计算EXTCODECOPY的EIP-4762 Gas成本
	// memory expansion first (dynamic part of pre-2929 implementation)
	// 首先处理内存扩展（EIP-2929前的动态部分）
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize) // 调用旧的EXTCODECOPY Gas计算
	if err != nil {                                                   // 如果出错
		return 0, err // 返回错误
	}
	addr := common.Address(stack.peek().Bytes20())     // 从栈顶获取目标地址
	wgas := evm.AccessEvents.BasicDataGas(addr, false) // 获取基本数据Gas成本（读操作）
	if wgas == 0 {                                     // 如果未定义Gas成本
		wgas = params.WarmStorageReadCostEIP2929 // 使用EIP-2929的暖存储读取成本
	}
	var overflow bool // 溢出标志
	// We charge (cold-warm), since 'warm' is already charged as constantGas
	// 我们收取(冷-暖)差值，因为“暖”成本已作为constantGas计入
	if gas, overflow = math.SafeAdd(gas, wgas); overflow { // 安全加法并检查溢出
		return 0, ErrGasUintOverflow // 返回Gas溢出错误
	}
	return gas, nil // 返回总Gas成本
}
