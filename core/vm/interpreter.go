// Copyright 2014 The go-ethereum Authors
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

// Config are the configuration options for the Interpreter
// Config 是解释器的配置选项
type Config struct {
	Tracer                  *tracing.Hooks // 跟踪钩子，用于调试和日志记录
	NoBaseFee               bool           // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls) 强制将EIP-1559的基础费用设置为0（用于0价格调用）
	EnablePreimageRecording bool           // Enables recording of SHA3/keccak preimages 启用SHA3/keccak前映像的记录
	ExtraEips               []int          // Additional EIPS that are to be enabled 要启用的额外EIP

	StatelessSelfValidation bool // Generate execution witnesses and self-check against them (testing purpose)生成执行见证并进行自我检查（测试用途）
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
// ScopeContext 包含每次调用的内容，例如栈和内存，
// 但不包括瞬态内容如pc和gas
type ScopeContext struct {
	Memory   *Memory   // 调用中的内存
	Stack    *Stack    // 调用中的栈
	Contract *Contract // 调用中的合约
}

// MemoryData returns the underlying memory slice. Callers must not modify the contents
// of the returned data.
// MemoryData 返回底层的内存切片。调用者不得修改返回数据的内容。
func (ctx *ScopeContext) MemoryData() []byte { // 获取内存数据
	if ctx.Memory == nil { // 如果内存为空
		return nil // 返回nil
	}
	return ctx.Memory.Data() // 返回内存数据
}

// StackData returns the stack data. Callers must not modify the contents
// of the returned data.
// StackData 返回栈数据。调用者不得修改返回数据的内容。
func (ctx *ScopeContext) StackData() []uint256.Int { // 获取栈数据
	if ctx.Stack == nil { // 如果栈为空
		return nil // 返回nil
	}
	return ctx.Stack.Data() // 返回栈数据
}

// Caller returns the current caller.
// Caller 返回当前调用者。
func (ctx *ScopeContext) Caller() common.Address { // 获取调用者地址
	return ctx.Contract.Caller() // 返回合约的调用者地址
}

// Address returns the address where this scope of execution is taking place.
// Address 返回执行此范围的地址。
func (ctx *ScopeContext) Address() common.Address { // 获取执行地址
	return ctx.Contract.Address() // 返回合约的执行地址
}

// CallValue returns the value supplied with this call.
// CallValue 返回此次调用提供的价值。
func (ctx *ScopeContext) CallValue() *uint256.Int { // 获取调用价值
	return ctx.Contract.Value() // 返回合约的调用价值
}

// CallInput returns the input/calldata with this call. Callers must not modify
// the contents of the returned data.
// CallInput 返回此次调用的输入/调用数据。调用者不得修改返回数据的内容。
func (ctx *ScopeContext) CallInput() []byte { // 获取调用输入
	return ctx.Contract.Input // 返回合约的输入数据
}

// ContractCode returns the code of the contract being executed.
// ContractCode 返回正在执行的合约代码。
func (ctx *ScopeContext) ContractCode() []byte { // 获取合约代码
	return ctx.Contract.Code // 返回合约的代码
}

// EVMInterpreter represents an EVM interpreter
// EVMInterpreter 表示一个EVM解释器
type EVMInterpreter struct {
	evm   *EVM       // 关联的EVM实例
	table *JumpTable // 操作码跳转表

	hasher    crypto.KeccakState // Keccak256 hasher instance shared across opcodes Keccak256哈希实例，在操作码间共享
	hasherBuf common.Hash        // Keccak256 hasher result array shared across opcodes Keccak256哈希结果数组，在操作码间共享

	readOnly   bool   // Whether to throw on stateful modifications 是否禁止状态修改
	returnData []byte // Last CALL's return data for subsequent reuse 上次CALL的返回数据，用于后续重用
}

// NewEVMInterpreter returns a new instance of the Interpreter.
// NewEVMInterpreter 返回一个新的解释器实例。
func NewEVMInterpreter(evm *EVM) *EVMInterpreter { // 创建新的EVM解释器
	// If jump table was not initialised we set the default one.
	// 如果跳转表未初始化，我们设置默认的跳转表。
	var table *JumpTable // 跳转表变量
	switch {             // 根据链规则选择跳转表
	case evm.chainRules.IsVerkle: // 如果是Verkle分叉
		// TODO replace with proper instruction set when fork is specified
		// TODO 当分叉指定时替换为正确的指令集
		table = &verkleInstructionSet // Verkle指令集
	case evm.chainRules.IsPrague: // 如果是Prague分叉
		table = &pragueInstructionSet // Prague指令集
	case evm.chainRules.IsCancun: // 如果是Cancun分叉
		table = &cancunInstructionSet // Cancun指令集
	case evm.chainRules.IsShanghai: // 如果是Shanghai分叉
		table = &shanghaiInstructionSet // Shanghai指令集
	case evm.chainRules.IsMerge: // 如果是Merge分叉
		table = &mergeInstructionSet // Merge指令集
	case evm.chainRules.IsLondon: // 如果是London分叉
		table = &londonInstructionSet // London指令集
	case evm.chainRules.IsBerlin: // 如果是Berlin分叉
		table = &berlinInstructionSet // Berlin指令集
	case evm.chainRules.IsIstanbul: // 如果是Istanbul分叉
		table = &istanbulInstructionSet // Istanbul指令集
	case evm.chainRules.IsConstantinople: // 如果是Constantinople分叉
		table = &constantinopleInstructionSet // Constantinople指令集
	case evm.chainRules.IsByzantium: // 如果是Byzantium分叉
		table = &byzantiumInstructionSet // Byzantium指令集
	case evm.chainRules.IsEIP158: // 如果是EIP-158分叉
		table = &spuriousDragonInstructionSet // Spurious Dragon指令集
	case evm.chainRules.IsEIP150: // 如果是EIP-150分叉
		table = &tangerineWhistleInstructionSet // Tangerine Whistle指令集
	case evm.chainRules.IsHomestead: // 如果是Homestead分叉
		table = &homesteadInstructionSet // Homestead指令集
	default: // 默认情况
		table = &frontierInstructionSet // Frontier指令集
	}
	var extraEips []int                // 额外的EIP列表
	if len(evm.Config.ExtraEips) > 0 { // 如果配置了额外EIP
		// Deep-copy jumptable to prevent modification of opcodes in other tables
		// 深拷贝跳转表以防止修改其他表的操作码
		table = copyJumpTable(table) // 复制跳转表
	}
	for _, eip := range evm.Config.ExtraEips { // 遍历额外EIP
		if err := EnableEIP(eip, table); err != nil { // 启用EIP
			// Disable it, so caller can check if it's activated or not
			// 禁用它，以便调用者检查是否已激活
			log.Error("EIP activation failed", "eip", eip, "error", err) // 记录错误
		} else {
			extraEips = append(extraEips, eip) // 添加成功的EIP
		}
	}
	evm.Config.ExtraEips = extraEips               // 更新配置中的EIP列表
	return &EVMInterpreter{evm: evm, table: table} // 返回新的解释器实例
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// ErrExecutionReverted which means revert-and-keep-gas-left.
// Run 循环并评估合约的代码，使用给定的输入数据，并返回返回字节切片和发生的错误。
//
// 需要注意的是，解释器返回的任何错误都应视为回滚并消耗所有Gas的操作，
// 除了 ErrExecutionReverted，它表示回滚并保留剩余Gas。
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) { // 执行合约代码
	// Increment the call depth which is restricted to 1024
	// 增加调用深度，限制为1024
	in.evm.depth++                    // 增加调用深度
	defer func() { in.evm.depth-- }() // 延迟减少调用深度

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This also makes sure that the readOnly flag isn't removed for child calls.
	// 确保readOnly仅在我们尚未处于readOnly状态时设置。
	// 这也确保子调用不会移除readOnly标志。
	if readOnly && !in.readOnly { // 如果要求只读且当前不是只读
		in.readOnly = true                     // 设置为只读
		defer func() { in.readOnly = false }() // 延迟恢复非只读状态
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	// 重置前一次调用的返回数据。保留旧缓冲区并不重要，
	// 因为每次返回的调用都会返回新数据。
	in.returnData = nil // 重置返回数据

	// Don't bother with the execution if there's no code.
	// 如果没有代码，就不执行。
	if len(contract.Code) == 0 { // 如果合约代码为空
		return nil, nil // 返回空结果和无错误
	}

	var (
		op          OpCode           // current opcode 当前操作码
		mem         = NewMemory()    // bound memory 绑定的内存
		stack       = newstack()     // local stack 本地栈
		callContext = &ScopeContext{ // 调用上下文
			Memory:   mem,      // 设置内存
			Stack:    stack,    // 设置栈
			Contract: contract, // 设置合约
		}
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		// 出于优化原因，我们使用uint64作为程序计数器。
		// 理论上可能超过2^64。黄皮书定义PC为uint256。实际上远不那么可行。
		pc   = uint64(0) // program counter 程序计数器
		cost uint64      // 操作成本
		// copies used by tracer
		// 跟踪器使用的副本
		pcCopy  uint64                        // needed for the deferred EVMLogger 用于延迟的EVMLogger的PC副本
		gasCopy uint64                        // for EVMLogger to log gas remaining before execution 用于EVMLogger记录执行前的剩余Gas
		logged  bool                          // deferred EVMLogger should ignore already logged steps 延迟的EVMLogger应忽略已记录的步骤
		res     []byte                        // result of the opcode execution function 操作码执行函数的结果
		debug   = in.evm.Config.Tracer != nil // 是否启用调试
	)
	// Don't move this deferred function, it's placed before the OnOpcode-deferred method,
	// so that it gets executed _after_: the OnOpcode needs the stacks before
	// they are returned to the pools
	// 不要移动这个延迟函数，它被放置在OnOpcode延迟方法之前，
	// 以便在之后执行：OnOpcode需要在栈归还到池之前使用。
	defer func() {
		returnStack(stack) // 归还栈到池中
		mem.Free()         // 释放内存
	}()
	contract.Input = input // 设置合约输入

	if debug { // 如果启用调试
		defer func() { // this deferred method handles exit-with-error  这个延迟方法处理错误退出
			if err == nil { // 如果没有错误
				return // 直接返回
			}
			if !logged && in.evm.Config.Tracer.OnOpcode != nil { // 如果未记录且有OnOpcode钩子
				in.evm.Config.Tracer.OnOpcode(pcCopy, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err)) // 调用OnOpcode钩子
			}
			if logged && in.evm.Config.Tracer.OnFault != nil { // 如果已记录且有OnFault钩子
				in.evm.Config.Tracer.OnFault(pcCopy, byte(op), gasCopy, cost, callContext, in.evm.depth, VMErrorFromErr(err)) // 调用OnFault钩子
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	// 解释器的主运行循环（上下文相关）。此循环运行直到执行显式的STOP、RETURN或SELFDESTRUCT，
	// 或在执行某个操作期间发生错误，或直到父上下文设置了完成标志。
	for { // 主执行循环
		if debug { // 如果启用调试
			// Capture pre-execution values for tracing.
			// 捕获执行前的值用于跟踪。
			logged, pcCopy, gasCopy = false, pc, contract.Gas // 重置记录状态并保存PC和Gas副本
		}

		if in.evm.chainRules.IsEIP4762 && !contract.IsDeployment { // 如果启用EIP-4762且不是部署
			// if the PC ends up in a new "chunk" of verkleized code, charge the
			// associated costs.
			// 如果PC进入新的“verkle化”代码块，收取相关成本。
			contractAddr := contract.Address()                                                                                       // 获取合约地址
			contract.Gas -= in.evm.TxContext.AccessEvents.CodeChunksRangeGas(contractAddr, pc, 1, uint64(len(contract.Code)), false) // 扣除代码块访问Gas
		}

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		// 从跳转表获取操作并验证栈，确保有足够的栈项可执行操作。
		op = contract.GetOp(pc)      // 获取当前操作码
		operation := in.table[op]    // 从跳转表获取操作
		cost = operation.constantGas // For tracing 用于跟踪的固定Gas成本
		// Validate stack
		// 验证栈
		if sLen := stack.len(); sLen < operation.minStack { // 如果栈长度小于最小要求
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack} // 返回栈下溢错误
		} else if sLen > operation.maxStack { // 如果栈长度超过最大限制
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack} // 返回栈溢出错误
		}
		// for tracing: this gas consumption event is emitted below in the debug section.
		// 用于跟踪：此Gas消耗事件在下面的调试部分发出。
		if contract.Gas < cost { // 如果Gas不足以支付固定成本
			return nil, ErrOutOfGas // 返回Gas不足错误
		} else {
			contract.Gas -= cost // 扣除固定Gas成本
		}

		if operation.dynamicGas != nil { // 如果操作有动态Gas成本
			// All ops with a dynamic memory usage also has a dynamic gas cost.
			// 所有具有动态内存使用的操作也有动态Gas成本。
			var memorySize uint64 // 内存大小
			// calculate the new memory size and expand the memory to fit
			// the operation
			// 计算新的内存大小并扩展内存以适应操作
			// Memory check needs to be done prior to evaluating the dynamic gas portion,
			// to detect calculation overflows
			// 在评估动态Gas部分之前需要检查内存，以检测计算溢出
			if operation.memorySize != nil { // 如果操作需要计算内存大小
				memSize, overflow := operation.memorySize(stack) // 计算内存大小
				if overflow {                                    // 如果溢出
					return nil, ErrGasUintOverflow // 返回Gas溢出错误
				}
				// memory is expanded in words of 32 bytes. Gas
				// is also calculated in words.
				// 内存以32字节的字扩展。Gas也以字计算。
				if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow { // 将内存大小转换为字节并检查溢出
					return nil, ErrGasUintOverflow // 返回Gas溢出错误
				}
			}
			// Consume the gas and return an error if not enough gas is available.
			// cost is explicitly set so that the capture state defer method can get the proper cost
			// 消耗Gas，如果Gas不足则返回错误。
			// cost被显式设置，以便捕获状态的延迟方法可以获取正确的成本
			var dynamicCost uint64                                                            // 动态Gas成本
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize) // 计算动态Gas成本
			cost += dynamicCost                                                               // 用于跟踪的总成本
			if err != nil {                                                                   // 如果计算出错
				return nil, fmt.Errorf("%w: %v", ErrOutOfGas, err) // 返回Gas不足错误
			}
			// for tracing: this gas consumption event is emitted below in the debug section.
			// 用于跟踪：此Gas消耗事件在下面的调试部分发出。
			if contract.Gas < dynamicCost { // 如果Gas不足以支付动态成本
				return nil, ErrOutOfGas // 返回Gas不足错误
			} else {
				contract.Gas -= dynamicCost // 扣除动态Gas成本
			}

			// Do tracing before memory expansion
			// 在内存扩展之前进行跟踪
			if debug { // 如果启用调试
				if in.evm.Config.Tracer.OnGasChange != nil { // 如果有Gas变化钩子
					in.evm.Config.Tracer.OnGasChange(gasCopy, gasCopy-cost, tracing.GasChangeCallOpCode) // 调用Gas变化钩子
				}
				if in.evm.Config.Tracer.OnOpcode != nil { // 如果有操作码钩子
					in.evm.Config.Tracer.OnOpcode(pc, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err)) // 调用操作码钩子
					logged = true                                                                                                             // 标记已记录
				}
			}
			if memorySize > 0 { // 如果需要扩展内存
				mem.Resize(memorySize) // 调整内存大小
			}
		} else if debug { // 如果没有动态Gas但启用调试
			if in.evm.Config.Tracer.OnGasChange != nil { // 如果有Gas变化钩子
				in.evm.Config.Tracer.OnGasChange(gasCopy, gasCopy-cost, tracing.GasChangeCallOpCode) // 调用Gas变化钩子
			}
			if in.evm.Config.Tracer.OnOpcode != nil { // 如果有操作码钩子
				in.evm.Config.Tracer.OnOpcode(pc, byte(op), gasCopy, cost, callContext, in.returnData, in.evm.depth, VMErrorFromErr(err)) // 调用操作码钩子
				logged = true                                                                                                             // 标记已记录
			}
		}

		// execute the operation
		// 执行操作
		res, err = operation.execute(&pc, in, callContext) // 执行操作码
		if err != nil {                                    // 如果执行出错
			break // 退出循环
		}
		pc++ // 增加程序计数器
	}

	if err == errStopToken { // 如果错误是停止标记
		err = nil // clear stop token error清除停止标记错误
	}

	return res, err // 返回结果和错误
}
