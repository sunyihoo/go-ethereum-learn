// Copyright 2020 The go-ethereum Authors
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// makeGasSStoreFunc 创建一个基于特定退款值的 SSTORE 动态 gas 计算函数。
func makeGasSStoreFunc(clearingRefund uint64) gasFunc {
	// makeGasSStoreFunc 创建一个基于特定退款值的 SSTORE 动态 gas 计算函数。
	// clearingRefund: 用于清理退款的 gas 值，影响状态变化时的退款逻辑。
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		// If we fail the minimum gas availability invariant, fail (0)
		// 如果我们无法满足最小 gas 可用性不变性，则失败 (0)
		// 步骤 1: 检查是否有足够的 gas 用于重入保护
		if contract.Gas <= params.SstoreSentryGasEIP2200 {
			return 0, errors.New("not enough gas for reentrancy sentry")
			// 返回错误：没有足够的 gas 用于重入保护
		}
		// Gas sentry honoured, do the actual gas calculation based on the stored value
		// Gas 哨兵已满足，根据存储的值进行实际的 gas 计算
		var (
			y, x    = stack.Back(1), stack.peek()                    // 从栈中获取键和值
			slot    = common.Hash(x.Bytes32())                       // 将键转换为哈希
			current = evm.StateDB.GetState(contract.Address(), slot) // 获取当前存储值
			cost    = uint64(0)                                      // 初始化 gas 成本
		)
		// Check slot presence in the access list
		// 检查插槽是否在访问列表中
		// 步骤 2: 检查访问列表并计算初始 gas 成本
		if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
			cost = params.ColdSloadCostEIP2929
			// 如果调用者无法支付成本，此更改将被回滚
			// If the caller cannot afford the cost, this change will be rolled back
			// 步骤 3: 将插槽添加到访问列表
			evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
		}
		value := common.Hash(y.Bytes32()) // 将新值转换为哈希

		// 步骤 4: 检查新值是否与当前值相同（无操作情况）
		if current == value { // noop (1)
			// EIP 2200 original clause:
			//		return params.SloadGasEIP2200, nil
			// EIP 2200 原始条款：
			//		return params.SloadGasEIP2200, nil
			return cost + params.WarmStorageReadCostEIP2929, nil // SLOAD_GAS
			// 返回成本加上热存储读取成本
		}
		// 步骤 5: 获取原始值并比较状态变化
		original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())
		if original == current {
			if original == (common.Hash{}) { // create slot (2.1.1)
				// 创建插槽 (2.1.1)
				return cost + params.SstoreSetGasEIP2200, nil
				// 返回创建插槽的 gas 成本
			}
			if value == (common.Hash{}) { // delete slot (2.1.2b)
				// 删除插槽 (2.1.2b)
				// 步骤 6: 删除插槽时增加退款
				evm.StateDB.AddRefund(clearingRefund)
			}
			// EIP-2200 original clause:
			//		return params.SstoreResetGasEIP2200, nil // write existing slot (2.1.2)
			// EIP-2200 原始条款：
			//		return params.SstoreResetGasEIP2200, nil // 写入现有插槽 (2.1.2)
			return cost + (params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929), nil // write existing slot (2.1.2)
			// 返回重置插槽的 gas 成本
		}
		// 步骤 7: 处理复杂状态变化（原始值、当前值和新值不同）
		if original != (common.Hash{}) {
			if current == (common.Hash{}) { // recreate slot (2.2.1.1)
				// 重新创建插槽 (2.2.1.1)
				evm.StateDB.SubRefund(clearingRefund)
				// 减少退款
			} else if value == (common.Hash{}) { // delete slot (2.2.1.2)
				// 删除插槽 (2.2.1.2)
				evm.StateDB.AddRefund(clearingRefund)
				// 增加退款
			}
		}
		if original == value {
			if original == (common.Hash{}) { // reset to original inexistent slot (2.2.2.1)
				// 重置到原始不存在的插槽 (2.2.2.1)
				// EIP 2200 Original clause:
				//evm.StateDB.AddRefund(params.SstoreSetGasEIP2200 - params.SloadGasEIP2200)
				// EIP 2200 原始条款：
				//evm.StateDB.AddRefund(params.SstoreSetGasEIP2200 - params.SloadGasEIP2200)
				evm.StateDB.AddRefund(params.SstoreSetGasEIP2200 - params.WarmStorageReadCostEIP2929)
				// 增加退款以补偿创建成本
			} else { // reset to original existing slot (2.2.2.2)
				// 重置到原始存在的插槽 (2.2.2.2)
				// EIP 2200 Original clause:
				//	evm.StateDB.AddRefund(params.SstoreResetGasEIP2200 - params.SloadGasEIP2200)
				// EIP 2200 原始条款：
				//	evm.StateDB.AddRefund(params.SstoreResetGasEIP2200 - params.SloadGasEIP2200)
				// - SSTORE_RESET_GAS redefined as (5000 - COLD_SLOAD_COST)
				// - SLOAD_GAS redefined as WARM_STORAGE_READ_COST
				// - SSTORE_RESET_GAS 重定义为 (5000 - COLD_SLOAD_COST)
				// - SLOAD_GAS 重定义为 WARM_STORAGE_READ_COST
				// Final: (5000 - COLD_SLOAD_COST) - WARM_STORAGE_READ_COST
				// 最终：(5000 - COLD_SLOAD_COST) - WARM_STORAGE_READ_COST
				evm.StateDB.AddRefund((params.SstoreResetGasEIP2200 - params.ColdSloadCostEIP2929) - params.WarmStorageReadCostEIP2929)
				// 增加退款以补偿重置成本
			}
		}
		// EIP-2200 original clause:
		//return params.SloadGasEIP2200, nil // dirty update (2.2)
		// EIP-2200 原始条款：
		//return params.SloadGasEIP2200, nil // 脏更新 (2.2)
		return cost + params.WarmStorageReadCostEIP2929, nil // dirty update (2.2)
		// 返回脏更新的 gas 成本
	}
}

// gasSLoadEIP2929 calculates dynamic gas for SLOAD according to EIP-2929
// gasSLoadEIP2929 根据 EIP-2929 计算 SLOAD 的动态 gas
// For SLOAD, if the (address, storage_key) pair (where address is the address of the contract
// whose storage is being read) is not yet in accessed_storage_keys,
// charge 2100 gas and add the pair to accessed_storage_keys.
// If the pair is already in accessed_storage_keys, charge 100 gas.
// 对于 SLOAD，如果 (address, storage_key) 对（其中 address 是存储被读取的合约地址）
// 尚未在 accessed_storage_keys 中，则收取 2100 gas 并将该对添加到 accessed_storage_keys。
// 如果该对已在 accessed_storage_keys 中，则收取 100 gas。
func gasSLoadEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// 步骤 1: 获取栈顶的插槽位置并转换为哈希
	loc := stack.peek()
	slot := common.Hash(loc.Bytes32())
	// Check slot presence in the access list
	// 检查插槽是否在访问列表中
	// 步骤 2: 检查插槽是否已在访问列表中
	if _, slotPresent := evm.StateDB.SlotInAccessList(contract.Address(), slot); !slotPresent {
		// If the caller cannot afford the cost, this change will be rolled back
		// If he does afford it, we can skip checking the same thing later on, during execution
		// 如果调用者无法支付成本，此更改将被回滚
		// 如果他能支付，我们可以在执行期间跳过再次检查相同内容
		// 步骤 3: 将插槽添加到访问列表并返回冷访问成本
		evm.StateDB.AddSlotToAccessList(contract.Address(), slot)
		return params.ColdSloadCostEIP2929, nil
	}
	// 步骤 4: 返回热访问成本
	return params.WarmStorageReadCostEIP2929, nil
}

// gasExtCodeCopyEIP2929 implements extcodecopy according to EIP-2929
// gasExtCodeCopyEIP2929 根据 EIP-2929 实现 extcodecopy
// EIP spec:
// > If the target is not in accessed_addresses,
// > charge COLD_ACCOUNT_ACCESS_COST gas, and add the address to accessed_addresses.
// > Otherwise, charge WARM_STORAGE_READ_COST gas.
// EIP 规范：
// > 如果目标不在 accessed_addresses 中，
// > 收取 COLD_ACCOUNT_ACCESS_COST gas，并将地址添加到 accessed_addresses。
// > 否则，收取 WARM_STORAGE_READ_COST gas。
func gasExtCodeCopyEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// memory expansion first (dynamic part of pre-2929 implementation)
	// 首先进行内存扩展（2929 之前的动态部分实现）
	// 步骤 1: 调用旧的 gas 计算函数处理内存扩展
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	// 步骤 2: 获取目标地址
	addr := common.Address(stack.peek().Bytes20())
	// Check slot presence in the access list
	// 检查插槽是否在访问列表中
	// 步骤 3: 检查地址是否在访问列表中
	if !evm.StateDB.AddressInAccessList(addr) {
		// 步骤 4: 添加地址到访问列表并计算冷访问成本
		evm.StateDB.AddAddressToAccessList(addr)
		var overflow bool
		// We charge (cold-warm), since 'warm' is already charged as constantGas
		// 我们收取 (cold-warm)，因为 'warm' 已作为常量 gas 被收取
		if gas, overflow = math.SafeAdd(gas, params.ColdAccountAccessCostEIP2929-params.WarmStorageReadCostEIP2929); overflow {
			return 0, ErrGasUintOverflow
			// 返回错误：gas 溢出
		}
		return gas, nil
	}
	// 步骤 5: 返回热访问的 gas 成本
	return gas, nil
}

// gasEip2929AccountCheck checks whether the first stack item (as address) is present in the access list.
// If it is, this method returns '0', otherwise 'cold-warm' gas, presuming that the opcode using it
// is also using 'warm' as constant factor.
// This method is used by:
// - extcodehash,
// - extcodesize,
// - (ext) balance
// gasEip2929AccountCheck 检查栈顶项（作为地址）是否在访问列表中。
// 如果在，则此方法返回 '0'，否则返回 'cold-warm' gas，假定使用它的操作码也将 'warm' 作为常量因子。
// 此方法被以下操作使用：
// - extcodehash,
// - extcodesize,
// - (ext) balance
// 步骤 1: 获取栈顶地址
func gasEip2929AccountCheck(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	addr := common.Address(stack.peek().Bytes20())
	// Check slot presence in the access list
	// 检查插槽是否在访问列表中
	// 步骤 2: 检查地址是否在访问列表中
	if !evm.StateDB.AddressInAccessList(addr) {
		// If the caller cannot afford the cost, this change will be rolled back
		// 如果调用者无法支付成本，此更改将被回滚
		// 步骤 3: 添加地址到访问列表并返回冷访问成本
		evm.StateDB.AddAddressToAccessList(addr)
		// The warm storage read cost is already charged as constantGas
		// 热存储读取成本已作为常量 gas 被收取
		return params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929, nil
	}
	// 步骤 4: 返回 0 表示热访问
	return 0, nil
}

// makeCallVariantGasCallEIP2929 创建基于 EIP-2929 的调用变体的 gas 计算函数。
func makeCallVariantGasCallEIP2929(oldCalculator gasFunc, addressPosition int) gasFunc {
	// makeCallVariantGasCallEIP2929 创建基于 EIP-2929 的调用变体的 gas 计算函数。
	// oldCalculator: 旧的 gas 计算函数，addressPosition: 栈中地址的位置。
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		// 步骤 1: 获取目标地址
		addr := common.Address(stack.Back(addressPosition).Bytes20())
		// Check slot presence in the access list
		// 检查插槽是否在访问列表中
		// 步骤 2: 检查地址是否在访问列表中
		warmAccess := evm.StateDB.AddressInAccessList(addr)
		// The WarmStorageReadCostEIP2929 (100) is already deducted in the form of a constant cost, so
		// the cost to charge for cold access, if any, is Cold - Warm
		// WarmStorageReadCostEIP2929 (100) 已作为常量成本被扣除，因此
		// 如果有冷访问，则收取的成本是 Cold - Warm
		coldCost := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
		if !warmAccess {
			// 步骤 3: 添加地址到访问列表并扣除冷访问成本
			evm.StateDB.AddAddressToAccessList(addr)
			// Charge the remaining difference here already, to correctly calculate available
			// gas for call
			// 在此已收取剩余差异，以正确计算调用可用的 gas
			if !contract.UseGas(coldCost, evm.Config.Tracer, tracing.GasChangeCallStorageColdAccess) {
				return 0, ErrOutOfGas
				// 返回错误：gas 不足
			}
		}
		// Now call the old calculator, which takes into account
		// - create new account
		// - transfer value
		// - memory expansion
		// - 63/64ths rule
		// 现在调用旧的计算器，它考虑了：
		// - 创建新账户
		// - 转移价值
		// - 内存扩展
		// - 63/64 规则
		// 步骤 4: 调用旧的 gas 计算函数
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if warmAccess || err != nil {
			return gas, err
		}
		// In case of a cold access, we temporarily add the cold charge back, and also
		// add it to the returned gas. By adding it to the return, it will be charged
		// outside of this function, as part of the dynamic gas, and that will make it
		// also become correctly reported to tracers.
		// 在冷访问的情况下，我们临时将冷访问费用加回去，并将其添加到返回的 gas 中。
		// 通过将其添加到返回中，它将在此函数外部作为动态 gas 的一部分被收取，
		// 这也将使其正确报告给追踪器。
		// 步骤 5: 调整 gas 并返回
		contract.Gas += coldCost

		var overflow bool
		if gas, overflow = math.SafeAdd(gas, coldCost); overflow {
			return 0, ErrGasUintOverflow
			// 返回错误：gas 溢出
		}
		return gas, nil
	}
}

// 定义全局 gas 计算函数变量
var (
	gasCallEIP2929         = makeCallVariantGasCallEIP2929(gasCall, 1)         // EIP-2929 的 CALL gas 计算
	gasDelegateCallEIP2929 = makeCallVariantGasCallEIP2929(gasDelegateCall, 1) // EIP-2929 的 DELEGATECALL gas 计算
	gasStaticCallEIP2929   = makeCallVariantGasCallEIP2929(gasStaticCall, 1)   // EIP-2929 的 STATICCALL gas 计算
	gasCallCodeEIP2929     = makeCallVariantGasCallEIP2929(gasCallCode, 1)     // EIP-2929 的 CALLCODE gas 计算
	gasSelfdestructEIP2929 = makeSelfdestructGasFn(true)                       // EIP-2929 的 SELFDESTRUCT gas 计算（支持退款）
	// gasSelfdestructEIP3529 implements the changes in EIP-3529 (no refunds)
	// gasSelfdestructEIP3529 实现了 EIP-3529 的更改（无退款）
	gasSelfdestructEIP3529 = makeSelfdestructGasFn(false) // EIP-3529 的 SELFDESTRUCT gas 计算（无退款）

	// gasSStoreEIP2929 implements gas cost for SSTORE according to EIP-2929
	//
	// When calling SSTORE, check if the (address, storage_key) pair is in accessed_storage_keys.
	// If it is not, charge an additional COLD_SLOAD_COST gas, and add the pair to accessed_storage_keys.
	// Additionally, modify the parameters defined in EIP 2200 as follows:
	//
	// Parameter 	Old value 	New value
	// SLOAD_GAS 	800 	= WARM_STORAGE_READ_COST
	// SSTORE_RESET_GAS 	5000 	5000 - COLD_SLOAD_COST
	//
	//The other parameters defined in EIP 2200 are unchanged.
	// see gasSStoreEIP2200(...) in core/vm/gas_table.go for more info about how EIP 2200 is specified
	// gasSStoreEIP2929 根据 EIP-2929 实现 SSTORE 的 gas 成本
	//
	// 调用 SSTORE 时，检查 (address, storage_key) 对是否在 accessed_storage_keys 中。
	// 如果不在，额外收取 COLD_SLOAD_COST gas，并将该对添加到 accessed_storage_keys。
	// 此外，按如下方式修改 EIP 2200 中定义的参数：
	//
	// 参数         旧值        新值
	// SLOAD_GAS    800         = WARM_STORAGE_READ_COST
	// SSTORE_RESET_GAS 5000    5000 - COLD_SLOAD_COST
	//
	// EIP 2200 中定义的其他参数保持不变。
	// 有关 EIP 2200 如何指定的更多信息，请参见 core/vm/gas_table.go 中的 gasSStoreEIP2200(...)
	gasSStoreEIP2929 = makeGasSStoreFunc(params.SstoreClearsScheduleRefundEIP2200) // EIP-2929 的 SSTORE gas 计算

	// gasSStoreEIP3529 implements gas cost for SSTORE according to EIP-3529
	// Replace `SSTORE_CLEARS_SCHEDULE` with `SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST` (4,800)
	// gasSStoreEIP3529 根据 EIP-3529 实现 SSTORE 的 gas 成本
	// 将 `SSTORE_CLEARS_SCHEDULE` 替换为 `SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST` (4,800)
	gasSStoreEIP3529 = makeGasSStoreFunc(params.SstoreClearsScheduleRefundEIP3529) // EIP-3529 的 SSTORE gas 计算
)

// makeSelfdestructGasFn can create the selfdestruct dynamic gas function for EIP-2929 and EIP-3529
// makeSelfdestructGasFn 可为 EIP-2929 和 EIP-3529 创建 SELFDESTRUCT 动态 gas 函数
func makeSelfdestructGasFn(refundsEnabled bool) gasFunc {
	// makeSelfdestructGasFn 可为 EIP-2929 和 EIP-3529 创建 SELFDESTRUCT 动态 gas 函数
	// refundsEnabled: 是否启用退款逻辑
	gasFunc := func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		var (
			gas     uint64                                   // gas 成本
			address = common.Address(stack.peek().Bytes20()) // 受益地址
		)
		// 步骤 1: 检查受益地址是否在访问列表中
		if !evm.StateDB.AddressInAccessList(address) {
			// If the caller cannot afford the cost, this change will be rolled back
			// 如果调用者无法支付成本，此更改将被回滚
			// 步骤 2: 添加地址到访问列表并设置冷访问成本
			evm.StateDB.AddAddressToAccessList(address)
			gas = params.ColdAccountAccessCostEIP2929
		}
		// if empty and transfers value
		// 如果为空且转移价值
		// 步骤 3: 检查是否创建新账户并增加相应成本
		if evm.StateDB.Empty(address) && evm.StateDB.GetBalance(contract.Address()).Sign() != 0 {
			gas += params.CreateBySelfdestructGas
		}
		// 步骤 4: 如果启用退款且未自毁，增加退款
		if refundsEnabled && !evm.StateDB.HasSelfDestructed(contract.Address()) {
			evm.StateDB.AddRefund(params.SelfdestructRefundGas)
		}
		return gas, nil
	}
	return gasFunc
}

// 定义 EIP-7702 的全局 gas 计算函数变量
var (
	gasCallEIP7702         = makeCallVariantGasCallEIP7702(gasCall)         // EIP-7702 的 CALL gas 计算
	gasDelegateCallEIP7702 = makeCallVariantGasCallEIP7702(gasDelegateCall) // EIP-7702 的 DELEGATECALL gas 计算
	gasStaticCallEIP7702   = makeCallVariantGasCallEIP7702(gasStaticCall)   // EIP-7702 的 STATICCALL gas 计算
	gasCallCodeEIP7702     = makeCallVariantGasCallEIP7702(gasCallCode)     // EIP-7702 的 CALLCODE gas 计算
)

// makeCallVariantGasCallEIP7702 创建基于 EIP-7702 的调用变体的 gas 计算函数。
func makeCallVariantGasCallEIP7702(oldCalculator gasFunc) gasFunc {
	// makeCallVariantGasCallEIP7702 创建基于 EIP-7702 的调用变体的 gas 计算函数。
	// oldCalculator: 旧的 gas 计算函数。
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		var (
			total uint64 // total dynamic gas used
			// total: 使用的总动态 gas
			addr = common.Address(stack.Back(1).Bytes20()) // 目标地址
		)

		// Check slot presence in the access list
		// 检查插槽是否在访问列表中
		// 步骤 1: 检查目标地址是否在访问列表中
		if !evm.StateDB.AddressInAccessList(addr) {
			// 步骤 2: 添加地址到访问列表并扣除冷访问成本
			evm.StateDB.AddAddressToAccessList(addr)
			// The WarmStorageReadCostEIP2929 (100) is already deducted in the form of a constant cost, so
			// the cost to charge for cold access, if any, is Cold - Warm
			// WarmStorageReadCostEIP2929 (100) 已作为常量成本被扣除，因此
			// 如果有冷访问，则收取的成本是 Cold - Warm
			coldCost := params.ColdAccountAccessCostEIP2929 - params.WarmStorageReadCostEIP2929
			// Charge the remaining difference here already, to correctly calculate available
			// gas for call
			// 在此已收取剩余差异，以正确计算调用可用的 gas
			if !contract.UseGas(coldCost, evm.Config.Tracer, tracing.GasChangeCallStorageColdAccess) {
				return 0, ErrOutOfGas
				// 返回错误：gas 不足
			}
			total += coldCost
		}

		// Check if code is a delegation and if so, charge for resolution.
		// 检查代码是否是委托，如果是，则收取解析费用。
		// 步骤 3: 检查是否为委托代码并计算解析成本
		if target, ok := types.ParseDelegation(evm.StateDB.GetCode(addr)); ok {
			var cost uint64
			if evm.StateDB.AddressInAccessList(target) {
				cost = params.WarmStorageReadCostEIP2929
			} else {
				// 步骤 4: 添加委托目标地址到访问列表并设置冷访问成本
				evm.StateDB.AddAddressToAccessList(target)
				cost = params.ColdAccountAccessCostEIP2929
			}
			if !contract.UseGas(cost, evm.Config.Tracer, tracing.GasChangeCallStorageColdAccess) {
				return 0, ErrOutOfGas
				// 返回错误：gas 不足
			}
			total += cost
		}

		// Now call the old calculator, which takes into account
		// - create new account
		// - transfer value
		// - memory expansion
		// - 63/64ths rule
		// 现在调用旧的计算器，它考虑了：
		// - 创建新账户
		// - 转移价值
		// - 内存扩展
		// - 63/64 规则
		// 步骤 5: 调用旧的 gas 计算函数
		old, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return old, err
		}

		// Temporarily add the gas charge back to the contract and return value. By
		// adding it to the return, it will be charged outside of this function, as
		// part of the dynamic gas. This will ensure it is correctly reported to
		// tracers.
		// 临时将 gas 费用加回到合约和返回值中。
		// 通过将其添加到返回中，它将在此函数外部作为动态 gas 的一部分被收取。
		// 这将确保它正确报告给追踪器。
		// 步骤 6: 调整 gas 并返回
		contract.Gas += total

		var overflow bool
		if total, overflow = math.SafeAdd(old, total); overflow {
			return 0, ErrGasUintOverflow
			// 返回错误：gas 溢出
		}
		return total, nil
	}
}
