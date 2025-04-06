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
	"errors"
	"fmt"
	"io"
)

// Below are all possible errors that can occur during validation of
// EOF containers.
// 以下是在验证EOF容器期间可能发生的所有错误。
var (
	errInvalidMagic                  = errors.New("invalid magic")                                                                    // 无效魔数
	errUndefinedInstruction          = errors.New("undefined instruction")                                                            // 未定义指令
	errTruncatedImmediate            = errors.New("truncated immediate")                                                              // 截断的立即数
	errInvalidSectionArgument        = errors.New("invalid section argument")                                                         // 无效的段参数
	errInvalidCallArgument           = errors.New("callf into non-returning section")                                                 // CALLF进入非返回段
	errInvalidDataloadNArgument      = errors.New("invalid dataloadN argument")                                                       // 无效的DATALOADN参数
	errInvalidJumpDest               = errors.New("invalid jump destination")                                                         // 无效的跳转目标
	errInvalidBackwardJump           = errors.New("invalid backward jump")                                                            // 无效的后向跳转
	errInvalidOutputs                = errors.New("invalid number of outputs")                                                        // 无效的输出数量
	errInvalidMaxStackHeight         = errors.New("invalid max stack height")                                                         // 无效的最大栈高度
	errInvalidCodeTermination        = errors.New("invalid code termination")                                                         // 无效的代码终止
	errEOFCreateWithTruncatedSection = errors.New("eofcreate with truncated section")                                                 // EOFCREATE使用截断的段
	errOrphanedSubcontainer          = errors.New("subcontainer not referenced at all")                                               // 未被引用的子容器
	errIncompatibleContainerKind     = errors.New("incompatible container kind")                                                      // 不兼容的容器类型
	errStopAndReturnContract         = errors.New("Stop/Return and Returncontract in the same code section")                          // STOP/RETURN与RETURNCONTRACT在同一代码段
	errStopInInitCode                = errors.New("initcode contains a RETURN or STOP opcode")                                        // 初始化代码包含RETURN或STOP操作码
	errTruncatedTopLevelContainer    = errors.New("truncated top level container")                                                    // 截断的顶级容器
	errUnreachableCode               = errors.New("unreachable code")                                                                 // 不可达代码
	errInvalidNonReturningFlag       = errors.New("invalid non-returning flag, bad RETF")                                             // 无效的非返回标志，错误的RETF
	errInvalidVersion                = errors.New("invalid version")                                                                  // 无效的版本
	errMissingTypeHeader             = errors.New("missing type header")                                                              // 缺少类型头
	errInvalidTypeSize               = errors.New("invalid type section size")                                                        // 无效的类型段大小
	errMissingCodeHeader             = errors.New("missing code header")                                                              // 缺少代码头
	errInvalidCodeSize               = errors.New("invalid code size")                                                                // 无效的代码大小
	errInvalidContainerSectionSize   = errors.New("invalid container section size")                                                   // 无效的容器段大小
	errMissingDataHeader             = errors.New("missing data header")                                                              // 缺少数据头
	errMissingTerminator             = errors.New("missing header terminator")                                                        // 缺少头终止符
	errTooManyInputs                 = errors.New("invalid type content, too many inputs")                                            // 无效的类型内容，输入过多
	errTooManyOutputs                = errors.New("invalid type content, too many outputs")                                           // 无效的类型内容，输出过多
	errInvalidSection0Type           = errors.New("invalid section 0 type, input and output should be zero and non-returning (0x80)") // 无效的第0段类型，输入和输出应为零且非返回(0x80)
	errTooLargeMaxStackHeight        = errors.New("invalid type content, max stack height exceeds limit")                             // 无效的类型内容，最大栈高度超出限制
	errInvalidContainerSize          = errors.New("invalid container size")                                                           // 无效的容器大小
)

const ( // 定义子容器引用类型的常量
	notRefByEither      = iota // 未被任何方式引用
	refByReturnContract        // 被RETURNCONTRACT引用
	refByEOFCreate             // 被EOFCREATE引用
)

type validationResult struct { // 定义验证结果结构体
	visitedCode          map[int]struct{} // 已访问的代码段
	visitedSubContainers map[int]int      // 已访问的子容器及其引用类型
	isInitCode           bool             // 是否为初始化代码
	isRuntime            bool             // 是否为运行时代码
}

// validateCode validates the code parameter against the EOF v1 validity requirements.
// validateCode 根据EOF v1有效性要求验证代码参数。
func validateCode(code []byte, section int, container *Container, jt *JumpTable, isInitCode bool) (*validationResult, error) { // 验证代码函数
	var (
		i = 0 // 代码索引
		// Tracks the number of actual instructions in the code (e.g.
		// non-immediate values). This is used at the end to determine
		// if each instruction is reachable.
		// 跟踪代码中实际指令的数量（例如非立即值）。这在最后用于确定每个指令是否可达。
		count                = 0              // 指令计数器
		op                   OpCode           // 当前操作码
		analysis             bitvec           // 代码分析位向量
		visitedCode          map[int]struct{} // 已访问的代码段映射
		visitedSubcontainers map[int]int      // 已访问的子容器映射
		hasReturnContract    bool             // 是否包含RETURNCONTRACT
		hasStop              bool             // 是否包含STOP
	)
	// This loop visits every single instruction and verifies:
	// * if the instruction is valid for the given jump table.
	// * if the instruction has an immediate value, it is not truncated.
	// * if performing a relative jump, all jump destinations are valid.
	// * if changing code sections, the new code section index is valid and
	//   will not cause a stack overflow.
	// 该循环访问每个指令并验证：
	// * 指令对于给定的跳转表是否有效。
	// * 如果指令有立即值，则未被截断。
	// * 如果执行相对跳转，所有跳转目标是否有效。
	// * 如果更改代码段，新代码段索引是否有效且不会导致栈溢出。
	for i < len(code) { // 遍历代码
		count++               // 增加指令计数
		op = OpCode(code[i])  // 获取当前操作码
		if jt[op].undefined { // 检查操作码是否未定义
			return nil, fmt.Errorf("%w: op %s, pos %d", errUndefinedInstruction, op, i) // 返回未定义指令错误
		}
		size := int(immediates[op])           // 获取操作码的立即数大小
		if size != 0 && len(code) <= i+size { // 检查立即数是否截断
			return nil, fmt.Errorf("%w: op %s, pos %d", errTruncatedImmediate, op, i) // 返回截断立即数错误
		}
		switch op { // 根据操作码类型处理
		case RJUMP, RJUMPI: // 处理RJUMP和RJUMPI
			if err := checkDest(code, &analysis, i+1, i+3, len(code)); err != nil { // 验证跳转目标
				return nil, err // 返回跳转目标错误
			}
		case RJUMPV: // 处理RJUMPV
			maxSize := int(code[i+1])  // 获取跳转表大小
			length := maxSize + 1      // 计算总长度
			if len(code) <= i+length { // 检查跳转表是否截断
				return nil, fmt.Errorf("%w: jump table truncated, op %s, pos %d", errTruncatedImmediate, op, i) // 返回截断错误
			}
			offset := i + 2               // 跳转表偏移
			for j := 0; j < length; j++ { // 验证每个跳转目标
				if err := checkDest(code, &analysis, offset+j*2, offset+(length*2), len(code)); err != nil {
					return nil, err // 返回跳转目标错误
				}
			}
			i += 2 * maxSize // 更新索引
		case CALLF: // 处理CALLF
			arg, _ := parseUint16(code[i+1:]) // 解析调用参数
			if arg >= len(container.types) {  // 检查参数是否超出类型段范围
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errInvalidSectionArgument, arg, len(container.types), i) // 返回无效段参数错误
			}
			if container.types[arg].outputs == 0x80 { // 检查是否调用非返回段
				return nil, fmt.Errorf("%w: section %v", errInvalidCallArgument, arg) // 返回无效调用参数错误
			}
			if visitedCode == nil { // 初始化已访问代码段映射
				visitedCode = make(map[int]struct{})
			}
			visitedCode[arg] = struct{}{} // 标记已访问
		case JUMPF: // 处理JUMPF
			arg, _ := parseUint16(code[i+1:]) // 解析跳转参数
			if arg >= len(container.types) {  // 检查参数是否超出类型段范围
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errInvalidSectionArgument, arg, len(container.types), i) // 返回无效段参数错误
			}
			if container.types[arg].outputs != 0x80 && container.types[arg].outputs > container.types[section].outputs { // 检查输出数量是否有效
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errInvalidOutputs, arg, len(container.types), i) // 返回无效输出数量错误
			}
			if visitedCode == nil { // 初始化已访问代码段映射
				visitedCode = make(map[int]struct{})
			}
			visitedCode[arg] = struct{}{} // 标记已访问
		case DATALOADN: // 处理DATALOADN
			arg, _ := parseUint16(code[i+1:]) // 解析数据加载参数
			// TODO why are we checking this? We should just pad
			if arg+32 > len(container.data) { // 检查数据加载是否超出数据段
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errInvalidDataloadNArgument, arg, len(container.data), i) // 返回无效DATALOADN参数错误
			}
		case RETURNCONTRACT: // 处理RETURNCONTRACT
			if !isInitCode { // 检查是否在初始化代码中
				return nil, errIncompatibleContainerKind // 返回不兼容容器类型错误
			}
			arg := int(code[i+1])                    // 解析子容器索引
			if arg >= len(container.subContainers) { // 检查索引是否超出子容器范围
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errUnreachableCode, arg, len(container.subContainers), i) // 返回不可达代码错误
			}
			if visitedSubcontainers == nil { // 初始化已访问子容器映射
				visitedSubcontainers = make(map[int]int)
			}
			// We need to store per subcontainer how it was referenced
			// 我们需要存储每个子容器的引用方式
			if v, ok := visitedSubcontainers[arg]; ok && v != refByReturnContract { // 检查子容器是否已被其他方式引用
				return nil, fmt.Errorf("section already referenced, arg :%d", arg) // 返回已被引用错误
			}
			if hasStop { // 检查是否与STOP共存
				return nil, errStopAndReturnContract // 返回STOP和RETURNCONTRACT共存错误
			}
			hasReturnContract = true                        // 标记包含RETURNCONTRACT
			visitedSubcontainers[arg] = refByReturnContract // 记录引用方式
		case EOFCREATE: // 处理EOFCREATE
			arg := int(code[i+1])                    // 解析子容器索引
			if arg >= len(container.subContainers) { // 检查索引是否超出子容器范围
				return nil, fmt.Errorf("%w: arg %d, last %d, pos %d", errUnreachableCode, arg, len(container.subContainers), i) // 返回不可达代码错误
			}
			if ct := container.subContainers[arg]; len(ct.data) != ct.dataSize { // 检查子容器数据是否截断
				return nil, fmt.Errorf("%w: container %d, have %d, claimed %d, pos %d", errEOFCreateWithTruncatedSection, arg, len(ct.data), ct.dataSize, i) // 返回截断段错误
			}
			if visitedSubcontainers == nil { // 初始化已访问子容器映射
				visitedSubcontainers = make(map[int]int)
			}
			// We need to store per subcontainer how it was referenced
			// 我们需要存储每个子容器的引用方式
			if v, ok := visitedSubcontainers[arg]; ok && v != refByEOFCreate { // 检查子容器是否已被其他方式引用
				return nil, fmt.Errorf("section already referenced, arg :%d", arg) // 返回已被引用错误
			}
			visitedSubcontainers[arg] = refByEOFCreate // 记录引用方式
		case STOP, RETURN: // 处理STOP和RETURN
			if isInitCode { // 检查是否在初始化代码中
				return nil, errStopInInitCode // 返回初始化代码中包含STOP错误
			}
			if hasReturnContract { // 检查是否与RETURNCONTRACT共存
				return nil, errStopAndReturnContract // 返回STOP和RETURNCONTRACT共存错误
			}
			hasStop = true // 标记包含STOP
		}
		i += size + 1 // 更新索引到下一指令
	}
	// Code sections may not "fall through" and require proper termination.
	// Therefore, the last instruction must be considered terminal or RJUMP.
	// 代码段不得“落空”且需要正确终止。
	// 因此，最后一条指令必须是终止指令或RJUMP。
	if !terminals[op] && op != RJUMP { // 检查代码是否正确终止
		return nil, fmt.Errorf("%w: end with %s, pos %d", errInvalidCodeTermination, op, i) // 返回无效代码终止错误
	}
	if paths, err := validateControlFlow(code, section, container.types, jt); err != nil { // 验证控制流
		return nil, err // 返回控制流验证错误
	} else if paths != count { // 检查是否有不可达代码
		// TODO(matt): return actual position of unreachable code
		return nil, errUnreachableCode // 返回不可达代码错误
	}
	return &validationResult{ // 返回验证结果
		visitedCode:          visitedCode,          // 已访问的代码段
		visitedSubContainers: visitedSubcontainers, // 已访问的子容器
		isInitCode:           hasReturnContract,    // 是否为初始化代码
		isRuntime:            hasStop,              // 是否为运行时代码
	}, nil
}

// checkDest parses a relative offset at code[0:2] and checks if it is a valid jump destination.
// checkDest 解析code[0:2]处的相对偏移量并检查其是否为有效的跳转目标。
func checkDest(code []byte, analysis *bitvec, imm, from, length int) error { // 检查跳转目标函数
	if len(code) < imm+2 { // 检查代码是否足够长
		return io.ErrUnexpectedEOF // 返回意外的EOF错误
	}
	if analysis != nil && *analysis == nil { // 初始化分析位向量
		*analysis = eofCodeBitmap(code) // 生成代码位图
	}
	offset := parseInt16(code[imm:]) // 解析偏移量
	dest := from + offset            // 计算跳转目标
	if dest < 0 || dest >= length {  // 检查目标是否超出范围
		return fmt.Errorf("%w: out-of-bounds offset: offset %d, dest %d, pos %d", errInvalidJumpDest, offset, dest, imm) // 返回无效跳转目标错误
	}
	if !analysis.codeSegment(uint64(dest)) { // 检查目标是否为有效代码段
		return fmt.Errorf("%w: offset into immediate: offset %d, dest %d, pos %d", errInvalidJumpDest, offset, dest, imm) // 返回跳转目标错误
	}
	return nil
}

//// disasm is a helper utility to show a sequence of comma-separated operations,
//// with immediates shown inline,
//// e.g: PUSH1(0x00),EOFCREATE(0x00),
//func disasm(code []byte) string {
//	var ops []string
//	for i := 0; i < len(code); i++ {
//		var op string
//		if args := immediates[code[i]]; args > 0 {
//			op = fmt.Sprintf("%v(%#x)", OpCode(code[i]).String(), code[i+1:i+1+int(args)])
//			i += int(args)
//		} else {
//			op = OpCode(code[i]).String()
//		}
//		ops = append(ops, op)
//	}
//	return strings.Join(ops, ",")
//}
