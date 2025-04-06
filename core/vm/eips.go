// Copyright 2019 The go-ethereum Authors
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
	"fmt"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// 1. 代码功能与背景
// 跳转表（Jump Table）：EVM 使用跳转表来映射操作码到其执行函数、gas 成本等。不同 EIP 引入了新的操作码或修改了现有操作码的行为，因此需要动态调整跳转表。
// EIP 支持：activators 映射表将 EIP 编号与启用函数关联，EnableEIP 函数根据 EIP 编号调用相应的启用函数，修改跳转表以支持该 EIP 的功能。
// 操作码实现：代码中定义了多个 enableXXX 函数，每个函数负责应用特定 EIP 的更改，如修改 gas 成本、添加新操作码等。
// 2. 与以太坊白皮书和黄皮书的关联
// 白皮书：以太坊白皮书中描述了 EVM 作为图灵完备的虚拟机，支持智能合约执行。操作码是 EVM 的指令集，跳转表是其执行引擎的核心。
// 黄皮书：黄皮书定义了 EVM 的操作码、gas 成本和执行规则。EIP 通过修改黄皮书中的规范来改进 EVM，例如 EIP-1884 调整了 BALANCE、EXTCODEHASH 和 SLOAD 的 gas 成本。
// EIP 机制：EIP 是以太坊社区提出的改进建议，涵盖新功能、性能优化、安全增强等。go-ethereum 通过 EnableEIP 等函数实现对这些 EIP 的支持。
// 3. 关键 EIP 解析
// EIP-1884：调整了 BALANCE、EXTCODEHASH 和 SLOAD 的 gas 成本，以反映其实际资源消耗，并引入 SELFBALANCE 操作码，提供更高效的余额查询。
// EIP-1344：引入 CHAINID 操作码，返回当前链的 ID，有助于防止跨链重放攻击。
// EIP-2929：引入 "warm" 和 "cold" 存储访问的概念，调整了状态访问操作码的 gas 成本，以激励更高效的状态管理。
// EIP-1153：引入临时存储（transient storage），通过 TLOAD 和 TSTORE 操作码，允许合约在执行期间临时存储数据，执行结束后自动清除。
// EIP-3855：引入 PUSH0 操作码，将 0 压入栈中，优化了合约代码中的 0 值处理。
// EIP-4762：与 EOF（Ethereum Object Format）相关，调整了操作码的行为以支持新的代码格式和验证机制。
// EIP-7702：支持委托设计符，修改了 EXTCODECOPY、EXTCODESIZE 和 EXTCODEHASH 的行为，以处理委托合约的代码。
// 4. 加深理解的知识点
// Gas 机制：EVM 中的 gas 是执行操作的成本单位，EIP 常通过调整 gas 成本来优化资源使用或防止滥用。例如，EIP-1884 提高了 SLOAD 的 gas 成本，以反映其对状态树的访问开销。
// 操作码扩展：EIP 引入新操作码以扩展 EVM 功能，如 CHAINID、BASEFEE 等，增强了合约的表达能力。
// EOF（EIP-3540）：EOF 是一种新的代码格式，旨在分离代码和数据，提升安全性。enableEOF 函数禁用了传统操作码（如 JUMP），并引入了新的跳转指令（如 RJUMP），以支持 EOF 合约。
// 临时存储（EIP-1153）：临时存储在合约执行期间存在，执行结束后自动清除，适用于需要跨调用共享状态的场景，如 reentrancy 锁。
// 委托设计符（EIP-7702）：允许合约指定委托逻辑，opExtCodeCopyEIP7702 等函数处理委托合约的代码获取逻辑。

// activators 是一个映射表，键是 EIP 编号，值是启用该 EIP 的函数。
var activators = map[int]func(*JumpTable){
	5656: enable5656,
	6780: enable6780,
	3855: enable3855,
	3860: enable3860,
	3529: enable3529,
	3198: enable3198,
	2929: enable2929,
	2200: enable2200,
	1884: enable1884,
	1344: enable1344,
	1153: enable1153,
	4762: enable4762,
	7702: enable7702,
}

// EnableEIP enables the given EIP on the config.
// This operation writes in-place, and callers need to ensure that the globally
// defined jump tables are not polluted.
// EnableEIP 在配置中启用指定的 EIP。
// 此操作会就地修改，调用者需要确保全局定义的跳转表不被污染。
func EnableEIP(eipNum int, jt *JumpTable) error {
	enablerFn, ok := activators[eipNum]
	if !ok {
		return fmt.Errorf("undefined eip %d", eipNum)
	}
	enablerFn(jt)
	return nil
}

// ValidEip checks if the given EIP number is valid.
// ValidEip 检查给定的 EIP 编号是否有效。
func ValidEip(eipNum int) bool {
	_, ok := activators[eipNum]
	return ok
}

// ActivateableEips returns a list of all activateable EIPs.
// ActivateableEips 返回所有可激活的 EIP 列表。
func ActivateableEips() []string {
	var nums []string
	for k := range activators {
		nums = append(nums, fmt.Sprintf("%d", k))
	}
	sort.Strings(nums)
	return nums
}

// enable1884 applies EIP-1884 to the given jump table:
// - Increase cost of BALANCE to 700
// - Increase cost of EXTCODEHASH to 700
// - Increase cost of SLOAD to 800
// - Define SELFBALANCE, with cost GasFastStep (5)
// enable1884 将 EIP-1884 应用于给定的跳转表：
// - 增加 BALANCE 的 gas 成本到 700
// - 增加 EXTCODEHASH 的 gas 成本到 700
// - 增加 SLOAD 的 gas 成本到 800
// - 定义 SELFBALANCE，gas 成本为 GasFastStep (5)
func enable1884(jt *JumpTable) {
	// Gas cost changes
	// 更改 gas 成本
	jt[SLOAD].constantGas = params.SloadGasEIP1884
	jt[BALANCE].constantGas = params.BalanceGasEIP1884
	jt[EXTCODEHASH].constantGas = params.ExtcodeHashGasEIP1884

	// New opcode
	// 新增操作码
	jt[SELFBALANCE] = &operation{
		execute:     opSelfBalance,
		constantGas: GasFastStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
}

// opSelfBalance implements the SELFBALANCE opcode.
// opSelfBalance 实现 SELFBALANCE 操作码。
func opSelfBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	scope.Stack.push(balance)
	return nil, nil
}

// enable1344 applies EIP-1344 (ChainID Opcode)
// - Adds an opcode that returns the current chain’s EIP-155 unique identifier
// enable1344 应用 EIP-1344（ChainID 操作码）
// - 添加一个返回当前链的 EIP-155 唯一标识符的操作码
func enable1344(jt *JumpTable) {
	// New opcode
	// 新增操作码
	jt[CHAINID] = &operation{
		execute:     opChainID,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
}

// opChainID implements CHAINID opcode
// opChainID 实现 CHAINID 操作码
func opChainID(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	chainId, _ := uint256.FromBig(interpreter.evm.chainConfig.ChainID)
	scope.Stack.push(chainId)
	return nil, nil
}

// enable2200 applies EIP-2200 (Rebalance net-metered SSTORE)
// enable2200 应用 EIP-2200（重新平衡网络计量的 SSTORE）
func enable2200(jt *JumpTable) {
	jt[SLOAD].constantGas = params.SloadGasEIP2200
	jt[SSTORE].dynamicGas = gasSStoreEIP2200
}

// enable2929 enables "EIP-2929: Gas cost increases for state access opcodes"
// https://eips.ethereum.org/EIPS/eip-2929
// enable2929 启用 "EIP-2929: 状态访问操作码的 gas 成本增加"
// https://eips.ethereum.org/EIPS/eip-2929
func enable2929(jt *JumpTable) {
	jt[SSTORE].dynamicGas = gasSStoreEIP2929

	jt[SLOAD].constantGas = 0
	jt[SLOAD].dynamicGas = gasSLoadEIP2929

	jt[EXTCODECOPY].constantGas = params.WarmStorageReadCostEIP2929
	jt[EXTCODECOPY].dynamicGas = gasExtCodeCopyEIP2929

	jt[EXTCODESIZE].constantGas = params.WarmStorageReadCostEIP2929
	jt[EXTCODESIZE].dynamicGas = gasEip2929AccountCheck

	jt[EXTCODEHASH].constantGas = params.WarmStorageReadCostEIP2929
	jt[EXTCODEHASH].dynamicGas = gasEip2929AccountCheck

	jt[BALANCE].constantGas = params.WarmStorageReadCostEIP2929
	jt[BALANCE].dynamicGas = gasEip2929AccountCheck

	jt[CALL].constantGas = params.WarmStorageReadCostEIP2929
	jt[CALL].dynamicGas = gasCallEIP2929

	jt[CALLCODE].constantGas = params.WarmStorageReadCostEIP2929
	jt[CALLCODE].dynamicGas = gasCallCodeEIP2929

	jt[STATICCALL].constantGas = params.WarmStorageReadCostEIP2929
	jt[STATICCALL].dynamicGas = gasStaticCallEIP2929

	jt[DELEGATECALL].constantGas = params.WarmStorageReadCostEIP2929
	jt[DELEGATECALL].dynamicGas = gasDelegateCallEIP2929

	// This was previously part of the dynamic cost, but we're using it as a constantGas
	// factor here
	// 这原本是动态成本的一部分，但在这里我们将其用作 constantGas 因子
	jt[SELFDESTRUCT].constantGas = params.SelfdestructGasEIP150
	jt[SELFDESTRUCT].dynamicGas = gasSelfdestructEIP2929
}

// enable3529 enabled "EIP-3529: Reduction in refunds":
// - Removes refunds for selfdestructs
// - Reduces refunds for SSTORE
// - Reduces max refunds to 20% gas
// enable3529 启用 "EIP-3529: 减少退款":
// - 移除 selfdestructs 的退款
// - 减少 SSTORE 的退款
// - 将最大退款减少到 20% gas
func enable3529(jt *JumpTable) {
	jt[SSTORE].dynamicGas = gasSStoreEIP3529
	jt[SELFDESTRUCT].dynamicGas = gasSelfdestructEIP3529
}

// enable3198 applies EIP-3198 (BASEFEE Opcode)
// - Adds an opcode that returns the current block's base fee.
// enable3198 应用 EIP-3198（BASEFEE 操作码）
// - 添加一个返回当前块的基础费用的操作码。
func enable3198(jt *JumpTable) {
	// New opcode
	// 新增操作码
	jt[BASEFEE] = &operation{
		execute:     opBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
}

// enable1153 applies EIP-1153 "Transient Storage"
// - Adds TLOAD that reads from transient storage
// - Adds TSTORE that writes to transient storage
// enable1153 应用 EIP-1153 "临时存储"
// - 添加从临时存储读取的 TLOAD
// - 添加写入临时存储的 TSTORE
func enable1153(jt *JumpTable) {
	jt[TLOAD] = &operation{
		execute:     opTload,
		constantGas: params.WarmStorageReadCostEIP2929,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}

	jt[TSTORE] = &operation{
		execute:     opTstore,
		constantGas: params.WarmStorageReadCostEIP2929,
		minStack:    minStack(2, 0),
		maxStack:    maxStack(2, 0),
	}
}

// opTload implements TLOAD opcode
// opTload 实现 TLOAD 操作码
func opTload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	hash := common.Hash(loc.Bytes32())
	val := interpreter.evm.StateDB.GetTransientState(scope.Contract.Address(), hash)
	loc.SetBytes(val.Bytes())
	return nil, nil
}

// opTstore implements TSTORE opcode
// opTstore 实现 TSTORE 操作码
func opTstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	if interpreter.readOnly {
		return nil, ErrWriteProtection
	}
	loc := scope.Stack.pop()
	val := scope.Stack.pop()
	interpreter.evm.StateDB.SetTransientState(scope.Contract.Address(), loc.Bytes32(), val.Bytes32())
	return nil, nil
}

// opBaseFee implements BASEFEE opcode
// opBaseFee 实现 BASEFEE 操作码
func opBaseFee(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	baseFee, _ := uint256.FromBig(interpreter.evm.Context.BaseFee)
	scope.Stack.push(baseFee)
	return nil, nil
}

// enable3855 applies EIP-3855 (PUSH0 opcode)
// enable3855 应用 EIP-3855（PUSH0 操作码）
func enable3855(jt *JumpTable) {
	// New opcode
	// 新增操作码
	jt[PUSH0] = &operation{
		execute:     opPush0,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
}

// opPush0 implements the PUSH0 opcode
// opPush0 实现 PUSH0 操作码
func opPush0(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int))
	return nil, nil
}

// enable3860 enables "EIP-3860: Limit and meter initcode"
// https://eips.ethereum.org/EIPS/eip-3860
// enable3860 启用 "EIP-3860: 限制和计量 initcode"
// https://eips.ethereum.org/EIPS/eip-3860
func enable3860(jt *JumpTable) {
	jt[CREATE].dynamicGas = gasCreateEip3860
	jt[CREATE2].dynamicGas = gasCreate2Eip3860
}

// enable5656 enables EIP-5656 (MCOPY opcode)
// https://eips.ethereum.org/EIPS/eip-5656
// enable5656 启用 EIP-5656（MCOPY 操作码）
// https://eips.ethereum.org/EIPS/eip-5656
func enable5656(jt *JumpTable) {
	jt[MCOPY] = &operation{
		execute:     opMcopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasMcopy,
		minStack:    minStack(3, 0),
		maxStack:    maxStack(3, 0),
		memorySize:  memoryMcopy,
	}
}

// opMcopy implements the MCOPY opcode (https://eips.ethereum.org/EIPS/eip-5656)
// opMcopy 实现 MCOPY 操作码 (https://eips.ethereum.org/EIPS/eip-5656)
func opMcopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		dst    = scope.Stack.pop()
		src    = scope.Stack.pop()
		length = scope.Stack.pop()
	)
	// These values are checked for overflow during memory expansion calculation
	// (the memorySize function on the opcode).
	// 这些值在内存扩展计算期间会检查溢出（在操作码的 memorySize 函数中）。
	scope.Memory.Copy(dst.Uint64(), src.Uint64(), length.Uint64())
	return nil, nil
}

// opBlobHash implements the BLOBHASH opcode
// opBlobHash 实现 BLOBHASH 操作码
func opBlobHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	index := scope.Stack.peek()
	if index.LtUint64(uint64(len(interpreter.evm.TxContext.BlobHashes))) {
		blobHash := interpreter.evm.TxContext.BlobHashes[index.Uint64()]
		index.SetBytes32(blobHash[:])
	} else {
		index.Clear()
	}
	return nil, nil
}

// opBlobBaseFee implements BLOBBASEFEE opcode
// opBlobBaseFee 实现 BLOBBASEFEE 操作码
func opBlobBaseFee(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	blobBaseFee, _ := uint256.FromBig(interpreter.evm.Context.BlobBaseFee)
	scope.Stack.push(blobBaseFee)
	return nil, nil
}

// enable4844 applies EIP-4844 (BLOBHASH opcode)
// enable4844 应用 EIP-4844（BLOBHASH 操作码）
func enable4844(jt *JumpTable) {
	jt[BLOBHASH] = &operation{
		execute:     opBlobHash,
		constantGas: GasFastestStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
}

// enable7516 applies EIP-7516 (BLOBBASEFEE opcode)
// enable7516 应用 EIP-7516（BLOBBASEFEE 操作码）
func enable7516(jt *JumpTable) {
	jt[BLOBBASEFEE] = &operation{
		execute:     opBlobBaseFee,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
}

// enable6780 applies EIP-6780 (deactivate SELFDESTRUCT)
// enable6780 应用 EIP-6780（停用 SELFDESTRUCT）
func enable6780(jt *JumpTable) {
	jt[SELFDESTRUCT] = &operation{
		execute:     opSelfdestruct6780,
		dynamicGas:  gasSelfdestructEIP3529,
		constantGas: params.SelfdestructGasEIP150,
		minStack:    minStack(1, 0),
		maxStack:    maxStack(1, 0),
	}
}

// opExtCodeCopyEIP4762 implements the EXTCODECOPY opcode for EIP-4762
// opExtCodeCopyEIP4762 实现 EIP-4762 的 EXTCODECOPY 操作码
func opExtCodeCopyEIP4762(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
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
	contract := &Contract{
		Code: code,
		self: AccountRef(addr),
	}
	paddedCodeCopy, copyOffset, nonPaddedCopyLength := getDataAndAdjustedBounds(code, uint64CodeOffset, length.Uint64())
	statelessGas := interpreter.evm.AccessEvents.CodeChunksRangeGas(addr, copyOffset, nonPaddedCopyLength, uint64(len(contract.Code)), false)
	if !scope.Contract.UseGas(statelessGas, interpreter.evm.Config.Tracer, tracing.GasChangeUnspecified) {
		scope.Contract.Gas = 0
		return nil, ErrOutOfGas
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), paddedCodeCopy)

	return nil, nil
}

// opPush1EIP4762 handles the special case of PUSH1 opcode for EIP-4762, which
// need not worry about the adjusted bound logic when adding the PUSHDATA to
// the list of access events.
// opPush1EIP4762 处理 EIP-4762 的 PUSH1 操作码的特殊情况，
// 在将 PUSHDATA 添加到访问事件列表时不需要担心调整后的边界逻辑。
func opPush1EIP4762(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))

		if !scope.Contract.IsDeployment && *pc%31 == 0 {
			// touch next chunk if PUSH1 is at the boundary. if so, *pc has
			// advanced past this boundary.
			// 如果 PUSH1 位于边界，则触及下一个块。如果是，则 *pc 已前进到该边界之外。
			contractAddr := scope.Contract.Address()
			statelessGas := interpreter.evm.AccessEvents.CodeChunksRangeGas(contractAddr, *pc+1, uint64(1), uint64(len(scope.Contract.Code)), false)
			if !scope.Contract.UseGas(statelessGas, interpreter.evm.Config.Tracer, tracing.GasChangeUnspecified) {
				scope.Contract.Gas = 0
				return nil, ErrOutOfGas
			}
		}
	} else {
		scope.Stack.push(integer.Clear())
	}
	return nil, nil
}

// makePushEIP4762 creates an execution function for PUSH opcodes in EIP-4762
// makePushEIP4762 为 EIP-4762 中的 PUSH 操作码创建执行函数
func makePushEIP4762(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		var (
			codeLen = len(scope.Contract.Code)
			start   = min(codeLen, int(*pc+1))
			end     = min(codeLen, start+pushByteSize)
		)
		scope.Stack.push(new(uint256.Int).SetBytes(
			common.RightPadBytes(
				scope.Contract.Code[start:end],
				pushByteSize,
			)),
		)

		if !scope.Contract.IsDeployment {
			contractAddr := scope.Contract.Address()
			statelessGas := interpreter.evm.AccessEvents.CodeChunksRangeGas(contractAddr, uint64(start), uint64(pushByteSize), uint64(len(scope.Contract.Code)), false)
			if !scope.Contract.UseGas(statelessGas, interpreter.evm.Config.Tracer, tracing.GasChangeUnspecified) {
				scope.Contract.Gas = 0
				return nil, ErrOutOfGas
			}
		}

		*pc += size
		return nil, nil
	}
}

// enable4762 applies EIP-4762 changes to the jump table
// enable4762 将 EIP-4762 的更改应用于跳转表
func enable4762(jt *JumpTable) {
	jt[SSTORE] = &operation{
		dynamicGas: gasSStore4762,
		execute:    opSstore,
		minStack:   minStack(2, 0),
		maxStack:   maxStack(2, 0),
	}
	jt[SLOAD] = &operation{
		dynamicGas: gasSLoad4762,
		execute:    opSload,
		minStack:   minStack(1, 1),
		maxStack:   maxStack(1, 1),
	}

	jt[BALANCE] = &operation{
		execute:    opBalance,
		dynamicGas: gasBalance4762,
		minStack:   minStack(1, 1),
		maxStack:   maxStack(1, 1),
	}

	jt[EXTCODESIZE] = &operation{
		execute:    opExtCodeSize,
		dynamicGas: gasExtCodeSize4762,
		minStack:   minStack(1, 1),
		maxStack:   maxStack(1, 1),
	}

	jt[EXTCODEHASH] = &operation{
		execute:    opExtCodeHash,
		dynamicGas: gasExtCodeHash4762,
		minStack:   minStack(1, 1),
		maxStack:   maxStack(1, 1),
	}

	jt[EXTCODECOPY] = &operation{
		execute:    opExtCodeCopyEIP4762,
		dynamicGas: gasExtCodeCopyEIP4762,
		minStack:   minStack(4, 0),
		maxStack:   maxStack(4, 0),
		memorySize: memoryExtCodeCopy,
	}

	jt[CODECOPY] = &operation{
		execute:     opCodeCopy,
		constantGas: GasFastestStep,
		dynamicGas:  gasCodeCopyEip4762,
		minStack:    minStack(3, 0),
		maxStack:    maxStack(3, 0),
		memorySize:  memoryCodeCopy,
	}

	jt[SELFDESTRUCT] = &operation{
		execute:     opSelfdestruct6780,
		dynamicGas:  gasSelfdestructEIP4762,
		constantGas: params.SelfdestructGasEIP150,
		minStack:    minStack(1, 0),
		maxStack:    maxStack(1, 0),
	}

	jt[CREATE] = &operation{
		execute:     opCreate,
		constantGas: params.CreateNGasEip4762,
		dynamicGas:  gasCreateEip3860,
		minStack:    minStack(3, 1),
		maxStack:    maxStack(3, 1),
		memorySize:  memoryCreate,
	}

	jt[CREATE2] = &operation{
		execute:     opCreate2,
		constantGas: params.CreateNGasEip4762,
		dynamicGas:  gasCreate2Eip3860,
		minStack:    minStack(4, 1),
		maxStack:    maxStack(4, 1),
		memorySize:  memoryCreate2,
	}

	jt[CALL] = &operation{
		execute:    opCall,
		dynamicGas: gasCallEIP4762,
		minStack:   minStack(7, 1),
		maxStack:   maxStack(7, 1),
		memorySize: memoryCall,
	}

	jt[CALLCODE] = &operation{
		execute:    opCallCode,
		dynamicGas: gasCallCodeEIP4762,
		minStack:   minStack(7, 1),
		maxStack:   maxStack(7, 1),
		memorySize: memoryCall,
	}

	jt[STATICCALL] = &operation{
		execute:    opStaticCall,
		dynamicGas: gasStaticCallEIP4762,
		minStack:   minStack(6, 1),
		maxStack:   maxStack(6, 1),
		memorySize: memoryStaticCall,
	}

	jt[DELEGATECALL] = &operation{
		execute:    opDelegateCall,
		dynamicGas: gasDelegateCallEIP4762,
		minStack:   minStack(6, 1),
		maxStack:   maxStack(6, 1),
		memorySize: memoryDelegateCall,
	}

	jt[PUSH1] = &operation{
		execute:     opPush1EIP4762,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	for i := 1; i < 32; i++ {
		jt[PUSH1+OpCode(i)] = &operation{
			execute:     makePushEIP4762(uint64(i+1), i+1),
			constantGas: GasFastestStep,
			minStack:    minStack(0, 1),
			maxStack:    maxStack(0, 1),
		}
	}
}

// enableEOF applies the EOF changes.
// OBS! For EOF, there are two changes:
//  1. Two separate jumptables are required. One, EOF-jumptable, is used by
//     eof contracts. This one contains things like RJUMP.
//  2. The regular non-eof jumptable also needs to be modified, specifically to
//     modify how EXTCODECOPY works under the hood.
//
// This method _only_ deals with case 1.
// enableEOF 应用 EOF 更改。
// 注意！对于 EOF，有两个更改：
//  1. 需要两个单独的跳转表。一个是 EOF-jumptable，由 eof 合约使用，包含 RJUMP 等。
//  2. 常规的 non-eof 跳转表也需要修改，具体是修改 EXTCODECOPY 的底层工作方式。
//
// 此方法 _仅_ 处理情况 1。
func enableEOF(jt *JumpTable) {
	// Deprecate opcodes
	// 弃用操作码
	undefined := &operation{
		execute:     opUndefined,
		constantGas: 0,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
		undefined:   true,
	}
	jt[CALL] = undefined
	jt[CALLCODE] = undefined
	jt[DELEGATECALL] = undefined
	jt[STATICCALL] = undefined
	jt[SELFDESTRUCT] = undefined
	jt[JUMP] = undefined
	jt[JUMPI] = undefined
	jt[PC] = undefined
	jt[CREATE] = undefined
	jt[CREATE2] = undefined
	jt[CODESIZE] = undefined
	jt[CODECOPY] = undefined
	jt[EXTCODESIZE] = undefined
	jt[EXTCODECOPY] = undefined
	jt[EXTCODEHASH] = undefined
	jt[GAS] = undefined
	// Allow 0xFE to terminate sections
	// 允许 0xFE 终止 sections
	jt[INVALID] = &operation{
		execute:     opUndefined,
		constantGas: 0,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}

	// New opcodes
	// 新增操作码
	jt[RJUMP] = &operation{
		execute:     opRjump,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[RJUMPI] = &operation{
		execute:     opRjumpi,
		constantGas: GasFastishStep,
		minStack:    minStack(1, 0),
		maxStack:    maxStack(1, 0),
	}
	jt[RJUMPV] = &operation{
		execute:     opRjumpv,
		constantGas: GasFastishStep,
		minStack:    minStack(1, 0),
		maxStack:    maxStack(1, 0),
	}
	jt[CALLF] = &operation{
		execute:     opCallf,
		constantGas: GasFastStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[RETF] = &operation{
		execute:     opRetf,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[JUMPF] = &operation{
		execute:     opJumpf,
		constantGas: GasFastStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[EOFCREATE] = &operation{
		execute:     opEOFCreate,
		constantGas: params.Create2Gas,
		dynamicGas:  gasEOFCreate,
		minStack:    minStack(4, 1),
		maxStack:    maxStack(4, 1),
		memorySize:  memoryEOFCreate,
	}
	jt[RETURNCONTRACT] = &operation{
		execute: opReturnContract,
		// returncontract has zero constant gas cost
		// returncontract 没有 constant gas 成本
		dynamicGas: pureMemoryGascost,
		minStack:   minStack(2, 0),
		maxStack:   maxStack(2, 0),
		memorySize: memoryReturnContract,
	}
	jt[DATALOAD] = &operation{
		execute:     opDataLoad,
		constantGas: GasFastishStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	jt[DATALOADN] = &operation{
		execute:     opDataLoadN,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	jt[DATASIZE] = &operation{
		execute:     opDataSize,
		constantGas: GasQuickStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	jt[DATACOPY] = &operation{
		execute:     opDataCopy,
		constantGas: GasFastestStep,
		dynamicGas:  memoryCopierGas(2),
		minStack:    minStack(3, 0),
		maxStack:    maxStack(3, 0),
		memorySize:  memoryDataCopy,
	}
	jt[DUPN] = &operation{
		execute:     opDupN,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 1),
		maxStack:    maxStack(0, 1),
	}
	jt[SWAPN] = &operation{
		execute:     opSwapN,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[EXCHANGE] = &operation{
		execute:     opExchange,
		constantGas: GasFastestStep,
		minStack:    minStack(0, 0),
		maxStack:    maxStack(0, 0),
	}
	jt[RETURNDATALOAD] = &operation{
		execute:     opReturnDataLoad,
		constantGas: GasFastestStep,
		minStack:    minStack(1, 1),
		maxStack:    maxStack(1, 1),
	}
	jt[EXTCALL] = &operation{
		execute:     opExtCall,
		constantGas: params.WarmStorageReadCostEIP2929,
		dynamicGas:  makeCallVariantGasCallEIP2929(gasExtCall, 0),
		minStack:    minStack(4, 1),
		maxStack:    maxStack(4, 1),
		memorySize:  memoryExtCall,
	}
	jt[EXTDELEGATECALL] = &operation{
		execute:     opExtDelegateCall,
		dynamicGas:  makeCallVariantGasCallEIP2929(gasExtDelegateCall, 0),
		constantGas: params.WarmStorageReadCostEIP2929,
		minStack:    minStack(3, 1),
		maxStack:    maxStack(3, 1),
		memorySize:  memoryExtCall,
	}
	jt[EXTSTATICCALL] = &operation{
		execute:     opExtStaticCall,
		constantGas: params.WarmStorageReadCostEIP2929,
		dynamicGas:  makeCallVariantGasCallEIP2929(gasExtStaticCall, 0),
		minStack:    minStack(3, 1),
		maxStack:    maxStack(3, 1),
		memorySize:  memoryExtCall,
	}
}

// opExtCodeCopyEIP7702 implements the EIP-7702 variation of opExtCodeCopy.
// opExtCodeCopyEIP7702 实现 EIP-7702 变体的 opExtCodeCopy。
func opExtCodeCopyEIP7702(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
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
	code := interpreter.evm.StateDB.GetCode(common.Address(a.Bytes20()))
	if _, ok := types.ParseDelegation(code); ok {
		code = types.DelegationPrefix[:2]
	}
	codeCopy := getData(code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

// opExtCodeSizeEIP7702 implements the EIP-7702 variation of opExtCodeSize.
// opExtCodeSizeEIP7702 实现 EIP-7702 变体的 opExtCodeSize。
func opExtCodeSizeEIP7702(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	code := interpreter.evm.StateDB.GetCode(common.Address(slot.Bytes20()))
	if _, ok := types.ParseDelegation(code); ok {
		code = types.DelegationPrefix[:2]
	}
	slot.SetUint64(uint64(len(code)))
	return nil, nil
}

// opExtCodeHashEIP7702 implements the EIP-7702 variation of opExtCodeHash.
// opExtCodeHashEIP7702 实现 EIP-7702 变体的 opExtCodeHash。
func opExtCodeHashEIP7702(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	addr := common.Address(slot.Bytes20())
	if interpreter.evm.StateDB.Empty(addr) {
		slot.Clear()
		return nil, nil
	}
	code := interpreter.evm.StateDB.GetCode(addr)
	if _, ok := types.ParseDelegation(code); ok {
		// If the code is a delegation, return the prefix without version.
		// 如果代码是委托，则返回不带版本的前缀。
		slot.SetBytes(crypto.Keccak256(types.DelegationPrefix[:2]))
	} else {
		// Otherwise, return normal code hash.
		// 否则，返回正常的代码哈希。
		slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(addr).Bytes())
	}
	return nil, nil
}

// enable7702 the EIP-7702 changes to support delegation designators.
// enable7702 启用 EIP-7702 更改以支持委托设计符。
func enable7702(jt *JumpTable) {
	jt[EXTCODECOPY].execute = opExtCodeCopyEIP7702
	jt[EXTCODESIZE].execute = opExtCodeSizeEIP7702
	jt[EXTCODEHASH].execute = opExtCodeHashEIP7702

	jt[CALL].dynamicGas = gasCallEIP7702
	jt[CALLCODE].dynamicGas = gasCallCodeEIP7702
	jt[STATICCALL].dynamicGas = gasStaticCallEIP7702
	jt[DELEGATECALL].dynamicGas = gasDelegateCallEIP7702
}
