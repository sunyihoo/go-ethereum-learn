// Copyright 2024 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"fmt"

	"github.com/ethereum/go-ethereum/params"
)

// validateControlFlow 验证代码的控制流是否有效，返回访问计数和可能的错误
func validateControlFlow(code []byte, section int, metadata []*functionMetadata, jt *JumpTable) (int, error) {
	var (
		maxStackHeight = int(metadata[section].inputs) // 最大栈高度，初始化为当前段的输入数量
		visitCount     = 0                             // 访问计数，用于跟踪代码位置的访问次数
		next           = make([]int, 0, 1)             // 下一步跳转位置的列表
	)
	var (
		stackBoundsMax = make([]uint16, len(code)) // 每个位置的最大栈高度边界
		stackBoundsMin = make([]uint16, len(code)) // 每个位置的最小栈高度边界
	)
	// setBounds 设置指定位置的栈边界
	setBounds := func(pos, min, maxi int) {
		// The stackboundMax slice is a bit peculiar. We use `0` to denote
		// not set. Therefore, we use `1` to represent the value `0`, and so on.
		// So if the caller wants to store `1` as max bound, we internally store it as
		// `2`.
		// stackboundMax 切片有些特殊。我们用 `0` 表示未设置。
		// 因此，我们用 `1` 表示值 `0`，依此类推。
		// 所以如果调用者想存储 `1` 作为最大边界，我们内部存储为 `2`。
		if stackBoundsMax[pos] == 0 { // Not yet set
			// 如果尚未设置
			visitCount++
		}
		if maxi < 65535 {
			stackBoundsMax[pos] = uint16(maxi + 1)
		}
		stackBoundsMin[pos] = uint16(min)
		maxStackHeight = max(maxStackHeight, maxi)
	}
	// getStackMaxMin 获取指定位置的最大和最小栈高度
	getStackMaxMin := func(pos int) (ok bool, min, max int) {
		maxi := stackBoundsMax[pos]
		if maxi == 0 { // Not yet set
			// 如果尚未设置
			return false, 0, 0
		}
		return true, int(stackBoundsMin[pos]), int(maxi - 1)
	}
	// set the initial stack bounds
	// 设置初始栈边界
	setBounds(0, int(metadata[section].inputs), int(metadata[section].inputs))

	qualifiedExit := false // 是否有合格的退出标志
	for pos := 0; pos < len(code); pos++ {
		op := OpCode(code[pos])
		ok, currentStackMin, currentStackMax := getStackMaxMin(pos)
		if !ok {
			return 0, errUnreachableCode // 错误：不可达代码
		}

		switch op {
		case CALLF:
			arg, _ := parseUint16(code[pos+1:])
			newSection := metadata[arg]
			if err := newSection.checkInputs(currentStackMin); err != nil {
				return 0, fmt.Errorf("%w: at pos %d", err, pos)
			}
			if err := newSection.checkStackMax(currentStackMax); err != nil {
				return 0, fmt.Errorf("%w: at pos %d", err, pos)
			}
			delta := newSection.stackDelta()
			currentStackMax += delta
			currentStackMin += delta
		case RETF:
			/* From the spec:
			> for RETF the following must hold: stack_height_max == stack_height_min == types[current_code_index].outputs,

			In other words: RETF must unambiguously return all items remaining on the stack.
			*/
			/* 根据规范：
			   > 对于 RETF，必须满足以下条件：stack_height_max == stack_height_min == types[current_code_index].outputs,

			   换句话说：RETF 必须明确返回栈上剩余的所有项。
			*/
			if currentStackMax != currentStackMin {
				return 0, fmt.Errorf("%w: max %d, min %d, at pos %d", errInvalidOutputs, currentStackMax, currentStackMin, pos)
			}
			numOutputs := int(metadata[section].outputs)
			if numOutputs >= maxOutputItems {
				return 0, fmt.Errorf("%w: at pos %d", errInvalidNonReturningFlag, pos)
			}
			if numOutputs != currentStackMin {
				return 0, fmt.Errorf("%w: have %d, want %d, at pos %d", errInvalidOutputs, numOutputs, currentStackMin, pos)
			}
			qualifiedExit = true
		case JUMPF:
			arg, _ := parseUint16(code[pos+1:])
			newSection := metadata[arg]

			if err := newSection.checkStackMax(currentStackMax); err != nil {
				return 0, fmt.Errorf("%w: at pos %d", err, pos)
			}

			if newSection.outputs == 0x80 {
				if err := newSection.checkInputs(currentStackMin); err != nil {
					return 0, fmt.Errorf("%w: at pos %d", err, pos)
				}
			} else {
				if currentStackMax != currentStackMin {
					return 0, fmt.Errorf("%w: max %d, min %d, at pos %d", errInvalidOutputs, currentStackMax, currentStackMin, pos)
				}
				wantStack := int(metadata[section].outputs) - newSection.stackDelta()
				if currentStackMax != wantStack {
					return 0, fmt.Errorf("%w: at pos %d", errInvalidOutputs, pos)
				}
			}
			qualifiedExit = qualifiedExit || newSection.outputs < maxOutputItems
		case DUPN:
			arg := int(code[pos+1]) + 1
			if want, have := arg, currentStackMin; want > have {
				return 0, fmt.Errorf("%w: at pos %d", ErrStackUnderflow{stackLen: have, required: want}, pos)
			}
		case SWAPN:
			arg := int(code[pos+1]) + 1
			if want, have := arg+1, currentStackMin; want > have {
				return 0, fmt.Errorf("%w: at pos %d", ErrStackUnderflow{stackLen: have, required: want}, pos)
			}
		case EXCHANGE:
			arg := int(code[pos+1])
			n := arg>>4 + 1
			m := arg&0x0f + 1
			if want, have := n+m+1, currentStackMin; want > have {
				return 0, fmt.Errorf("%w: at pos %d", ErrStackUnderflow{stackLen: have, required: want}, pos)
			}
		default:
			if want, have := jt[op].minStack, currentStackMin; want > have {
				return 0, fmt.Errorf("%w: at pos %d", ErrStackUnderflow{stackLen: have, required: want}, pos)
			}
		}
		if !terminals[op] && op != CALLF {
			change := int(params.StackLimit) - jt[op].maxStack
			currentStackMax += change
			currentStackMin += change
		}
		next = next[:0]
		switch op {
		case RJUMP:
			// 关键步骤：计算相对跳转的目标位置
			nextPos := pos + 2 + parseInt16(code[pos+1:])
			next = append(next, nextPos)
			// We set the stack bounds of the destination
			// and skip the argument, only for RJUMP, all other opcodes are handled later
			// 我们设置目标位置的栈边界
			// 并跳过参数，仅适用于 RJUMP，其他操作码稍后处理
			if nextPos+1 < pos {
				ok, nextMin, nextMax := getStackMaxMin(nextPos + 1)
				if !ok {
					return 0, errInvalidBackwardJump
				}
				if nextMax != currentStackMax || nextMin != currentStackMin {
					return 0, errInvalidMaxStackHeight
				}
			} else {
				ok, nextMin, nextMax := getStackMaxMin(nextPos + 1)
				if !ok {
					setBounds(nextPos+1, currentStackMin, currentStackMax)
				} else {
					setBounds(nextPos+1, min(nextMin, currentStackMin), max(nextMax, currentStackMax))
				}
			}
		case RJUMPI:
			arg := parseInt16(code[pos+1:])
			next = append(next, pos+2)
			next = append(next, pos+2+arg)
		case RJUMPV:
			count := int(code[pos+1]) + 1
			next = append(next, pos+1+2*count)
			for i := 0; i < count; i++ {
				arg := parseInt16(code[pos+2+2*i:])
				next = append(next, pos+1+2*count+arg)
			}
		default:
			if imm := int(immediates[op]); imm != 0 {
				next = append(next, pos+imm)
			} else {
				// Simple op, no operand.
				// 简单操作码，无操作数
				next = append(next, pos)
			}
		}

		if op != RJUMP && !terminals[op] {
			for _, instr := range next {
				nextPC := instr + 1
				if nextPC >= len(code) {
					return 0, fmt.Errorf("%w: end with %s, pos %d", errInvalidCodeTermination, op, pos)
				}
				if nextPC > pos {
					// target reached via forward jump or seq flow
					// 通过前向跳转或顺序流到达目标
					ok, nextMin, nextMax := getStackMaxMin(nextPC)
					if !ok {
						setBounds(nextPC, currentStackMin, currentStackMax)
					} else {
						setBounds(nextPC, min(nextMin, currentStackMin), max(nextMax, currentStackMax))
					}
				} else {
					// target reached via backwards jump
					// 通过后向跳转到达目标
					ok, nextMin, nextMax := getStackMaxMin(nextPC)
					if !ok {
						return 0, errInvalidBackwardJump
					}
					if currentStackMax != nextMax {
						return 0, fmt.Errorf("%w want %d as current max got %d at pos %d,", errInvalidBackwardJump, currentStackMax, nextMax, pos)
					}
					if currentStackMin != nextMin {
						return 0, fmt.Errorf("%w want %d as current min got %d at pos %d,", errInvalidBackwardJump, currentStackMin, nextMin, pos)
					}
				}
			}
		}

		if op == RJUMP {
			pos += 2 // skip the immediate
			// 跳过立即数
		} else {
			pos = next[0]
		}
	}
	if qualifiedExit != (metadata[section].outputs < maxOutputItems) {
		return 0, fmt.Errorf("%w no RETF or qualified JUMPF", errInvalidNonReturningFlag)
	}
	if maxStackHeight >= int(params.StackLimit) {
		return 0, ErrStackOverflow{maxStackHeight, int(params.StackLimit)}
	}
	if maxStackHeight != int(metadata[section].maxStackHeight) {
		return 0, fmt.Errorf("%w in code section %d: have %d, want %d", errInvalidMaxStackHeight, section, maxStackHeight, metadata[section].maxStackHeight)
	}
	return visitCount, nil
}
