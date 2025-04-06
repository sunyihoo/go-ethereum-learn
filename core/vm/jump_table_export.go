// Copyright 2023 The go-ethereum Authors
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

	"github.com/ethereum/go-ethereum/params"
)

// LookupInstructionSet returns the instruction set for the fork configured by
// the rules.
// LookupInstructionSet 返回由规则配置的分叉对应的指令集。
func LookupInstructionSet(rules params.Rules) (JumpTable, error) { // 根据规则查找指令集
	switch { // 根据链规则选择指令集
	case rules.IsVerkle: // 如果是Verkle分叉
		return newCancunInstructionSet(), errors.New("verkle-fork not defined yet") // 返回Cancun指令集并提示Verkle未定义
	case rules.IsPrague: // 如果是Prague分叉
		return newCancunInstructionSet(), errors.New("prague-fork not defined yet") // 返回Cancun指令集并提示Prague未定义
	case rules.IsCancun: // 如果是Cancun分叉
		return newCancunInstructionSet(), nil // 返回Cancun指令集
	case rules.IsShanghai: // 如果是Shanghai分叉
		return newShanghaiInstructionSet(), nil // 返回Shanghai指令集
	case rules.IsMerge: // 如果是Merge分叉
		return newMergeInstructionSet(), nil // 返回Merge指令集
	case rules.IsLondon: // 如果是London分叉
		return newLondonInstructionSet(), nil // 返回London指令集
	case rules.IsBerlin: // 如果是Berlin分叉
		return newBerlinInstructionSet(), nil // 返回Berlin指令集
	case rules.IsIstanbul: // 如果是Istanbul分叉
		return newIstanbulInstructionSet(), nil // 返回Istanbul指令集
	case rules.IsConstantinople: // 如果是Constantinople分叉
		return newConstantinopleInstructionSet(), nil // 返回Constantinople指令集
	case rules.IsByzantium: // 如果是Byzantium分叉
		return newByzantiumInstructionSet(), nil // 返回Byzantium指令集
	case rules.IsEIP158: // 如果是EIP-158分叉（Spurious Dragon）
		return newSpuriousDragonInstructionSet(), nil // 返回Spurious Dragon指令集
	case rules.IsEIP150: // 如果是EIP-150分叉（Tangerine Whistle）
		return newTangerineWhistleInstructionSet(), nil // 返回Tangerine Whistle指令集
	case rules.IsHomestead: // 如果是Homestead分叉
		return newHomesteadInstructionSet(), nil // 返回Homestead指令集
	}
	return newFrontierInstructionSet(), nil // 默认返回Frontier指令集
}

// Stack returns the minimum and maximum stack requirements.
// Stack 返回最小和最大栈要求。
func (op *operation) Stack() (int, int) { // 获取操作的栈需求
	return op.minStack, op.maxStack // 返回最小最小和最大栈深度
}

// HasCost returns true if the opcode has a cost. Opcodes which do _not_ have
// a cost assigned are one of two things:
// - undefined, a.k.a invalid opcodes,
// - the STOP opcode.
// This method can thus be used to check if an opcode is "Invalid (or STOP)".
// HasCost 如果操作码有成本则返回true。没有分配成本的操作码是以下两种之一：
// - 未定义，即无效操作码，
// - STOP操作码。
// 因此，此方法可用于检查操作码是否为“无效（或STOP）”。
func (op *operation) HasCost() bool { // 检查操作码是否有成本
	// Ideally, we'd check this:
	//	return op.execute == opUndefined
	// However, go-lang does now allow that. So we'll just check some other
	// 'indicators' that this is an invalid op. Alas, STOP is impossible to
	// filter out
	// 理想情况下，我们会检查：
	//	return op.execute == opUndefined
	// 然而，Go语言不允许这样做。所以我们只检查其他表明这是无效操作的“指示器”。
	// 可惜无法过滤掉STOP
	return op.dynamicGas != nil || op.constantGas != 0 // 如果有动态Gas或固定Gas成本，返回true
}
