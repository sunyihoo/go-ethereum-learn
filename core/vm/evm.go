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
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type (
	// CanTransferFunc is the signature of a transfer guard function
	// CanTransferFunc 是转账保护函数的签名
	CanTransferFunc func(StateDB, common.Address, *uint256.Int) bool
	// TransferFunc is the signature of a transfer function
	// TransferFunc 是转账函数的签名
	TransferFunc func(StateDB, common.Address, common.Address, *uint256.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	// GetHashFunc 返回区块链中第 n 个块的哈希，用于 BLOCKHASH EVM 操作码。
	GetHashFunc func(uint64) common.Hash
)

// precompile 返回与给定地址关联的预编译合约。
func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	p, ok := evm.precompiles[addr]
	return p, ok
}

// BlockContext provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
// BlockContext 提供 EVM 辅助信息。一旦提供，不应修改。
type BlockContext struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	// CanTransfer 返回账户是否包含足够的 ether 来转账该值
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	// Transfer 从一个账户转账 ether 到另一个账户
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	// GetHash 返回与 n 对应的哈希
	GetHash GetHashFunc

	// Block information
	// 块信息
	Coinbase common.Address // Provides information for COINBASE
	// 提供 COINBASE 的信息
	GasLimit uint64 // Provides information for GASLIMIT
	// 提供 GASLIMIT 的信息
	BlockNumber *big.Int // Provides information for NUMBER
	// 提供 NUMBER 的信息
	Time uint64 // Provides information for TIME
	// 提供 TIME 的信息
	Difficulty *big.Int // Provides information for DIFFICULTY
	// 提供 DIFFICULTY 的信息
	BaseFee *big.Int // Provides information for BASEFEE (0 if vm runs with NoBaseFee flag and 0 gas price)
	// 提供 BASEFEE 的信息（如果 vm 运行时设置了 NoBaseFee 标志且 gas price 为 0，则为 0）
	BlobBaseFee *big.Int // Provides information for BLOBBASEFEE (0 if vm runs with NoBaseFee flag and 0 blob gas price)
	// 提供 BLOBBASEFEE 的信息（如果 vm 运行时设置了 NoBaseFee 标志且 blob gas price 为 0，则为 0）
	Random *common.Hash // Provides information for PREVRANDAO
	// 提供 PREVRANDAO 的信息
}

// TxContext provides the EVM with information about a transaction.
// All fields can change between transactions.
// TxContext 提供关于交易的信息。所有字段在交易之间可以改变。
type TxContext struct {
	// Message information
	// 消息信息
	Origin common.Address // Provides information for ORIGIN
	// 提供 ORIGIN 的信息
	GasPrice *big.Int // Provides information for GASPRICE (and is used to zero the basefee if NoBaseFee is set)
	// 提供 GASPRICE 的信息（如果设置了 NoBaseFee，则用于将 basefee 置为零）
	BlobHashes []common.Hash // Provides information for BLOBHASH
	// 提供 BLOBHASH 的信息
	BlobFeeCap *big.Int // Is used to zero the blobbasefee if NoBaseFee is set
	// 如果设置了 NoBaseFee，则用于将 blobbasefee 置为零
	AccessEvents *state.AccessEvents // Capture all state accesses for this tx
	// 捕获此交易的所有状态访问
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
// EVM 是以太坊虚拟机的基础对象，提供在给定状态和上下文中运行合约的必要工具。
// 应该注意，通过任何调用生成的任何错误都应被视为 revert-state-and-consume-all-gas 操作，
// 不应对特定错误进行检查。解释器确保生成的任何错误都被视为有缺陷的代码。
//
// EVM 不应被重用，也不是线程安全的。
type EVM struct {
	// Context provides auxiliary blockchain related information
	// Context 提供辅助的区块链相关信息
	Context BlockContext
	TxContext
	// StateDB gives access to the underlying state
	// StateDB 提供对底层状态的访问
	StateDB StateDB
	// Depth is the current call stack
	// depth 是当前的调用栈深度
	depth int

	// chainConfig contains information about the current chain
	// chainConfig 包含当前链的信息
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	// chainRules 包含当前 epoch 的链规则
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	// Config 是用于初始化 evm 的虚拟机配置选项
	Config Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	// interpreter 是全局（对此上下文）以太坊虚拟机，在整个 tx 执行过程中使用
	interpreter *EVMInterpreter
	// abort is used to abort the EVM calling operations
	// abort 用于中止 EVM 调用操作
	abort atomic.Bool
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	// callGasTemp 保持当前调用的可用 gas。这是因为在 gasCall* 中根据 63/64 规则计算可用 gas，然后在 opCall* 中应用。
	callGasTemp uint64
	// precompiles holds the precompiled contracts for the current epoch
	// precompiles 包含当前 epoch 的预编译合约
	precompiles map[common.Address]PrecompiledContract
}

// NewEVM constructs an EVM instance with the supplied block context, state
// database and several configs. It meant to be used throughout the entire
// state transition of a block, with the transaction context switched as
// needed by calling evm.SetTxContext.
// NewEVM 使用提供的块上下文、状态数据库和多个配置构造 EVM 实例。
// 它旨在在整个块的状态转换中使用，通过调用 evm.SetTxContext 按需切换交易上下文。
func NewEVM(blockCtx BlockContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	evm := &EVM{
		Context:     blockCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time),
	}
	evm.precompiles = activePrecompiledContracts(evm.chainRules)
	evm.interpreter = NewEVMInterpreter(evm)
	return evm
}

// SetTracer sets the tracer for following state transition.
// SetTracer 设置tracer以进行状态转换。
func (evm *EVM) SetTracer(tracer *tracing.Hooks) {
	evm.Config.Tracer = tracer
}

// SetPrecompiles sets the precompiled contracts for the EVM.
// This method is only used through RPC calls.
// It is not thread-safe.
// SetPrecompiles 设置 EVM 的预编译合约。
// 此方法仅通过 RPC 调用使用。
// 它不是线程安全的。
func (evm *EVM) SetPrecompiles(precompiles PrecompiledContracts) {
	evm.precompiles = precompiles
}

// SetTxContext resets the EVM with a new transaction context.
// This is not threadsafe and should only be done very cautiously.
// SetTxContext 使用新的交易上下文重置 EVM。
// 这不是线程安全的，应非常谨慎地执行。
func (evm *EVM) SetTxContext(txCtx TxContext) {
	if evm.chainRules.IsEIP4762 {
		txCtx.AccessEvents = state.NewAccessEvents(evm.StateDB.PointCache())
	}
	evm.TxContext = txCtx
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
// Cancel 取消任何正在运行的 EVM 操作。可以并发调用，并且多次调用是安全的。
func (evm *EVM) Cancel() {
	evm.abort.Store(true)
}

// Cancelled returns true if Cancel has been called
// Cancelled 返回 true 如果 Cancel 已被调用
func (evm *EVM) Cancelled() bool {
	return evm.abort.Load()
}

// Interpreter returns the current interpreter
// Interpreter 返回当前的解释器
func (evm *EVM) Interpreter() *EVMInterpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
// Call 执行与 addr 关联的合约，并将 input 作为参数。
// 它还处理所需的任何必要值转移，并采取必要步骤创建账户，
// 并在执行错误或失败的值转移时反转状态。
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// Capture the tracer start/end events in debug mode
	// 在调试模式下捕获 tracer 的 start/end 事件
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALL, caller.Address(), addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	// 如果试图在调用深度限制之上执行，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// 如果试图转移超过可用余额，则失败
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	// 步骤1：创建状态快照，用于可能的回滚
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP4762 {
			// add proof of absence to witness
			// 将 absence 证明添加到 witness
			wgas := evm.AccessEvents.AddAccount(addr, false)
			if gas < wgas {
				evm.StateDB.RevertToSnapshot(snapshot)
				return nil, 0, ErrOutOfGas
			}
			gas -= wgas
		}

		if !isPrecompile && evm.chainRules.IsEIP158 && value.IsZero() {
			// Calling a non-existing account, don't do anything.
			// 调用不存在的账户，不做任何事情。
			return nil, gas, nil
		}
		// 步骤2：如果账户不存在，则创建新账户
		evm.StateDB.CreateAccount(addr)
	}
	// 步骤3：执行转账操作
	evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)

	if isPrecompile {
		// 步骤4：如果是预编译合约，直接运行
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		// 初始化一个新合约并设置 EVM 将使用的代码。
		// 合约是仅为此执行上下文的 scoped 环境。
		code := evm.resolveCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged
		} else {
			addrCopy := addr
			// If the account has no code, we can abort here
			// The depth-check is already done, and precompiles handled above
			// 如果账户没有代码，我们可以在这里中止
			// 深度检查已经完成，预编译已经在上面处理
			contract := NewContract(caller, AccountRef(addrCopy), value, gas)
			contract.SetCallCode(&addrCopy, evm.resolveCodeHash(addrCopy), code)
			// 步骤5：运行普通合约代码
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally,
	// when we're in homestead this also counts for code storage gas errors.
	// 当 EVM 返回错误或在上面设置创建代码时，我们反转到快照并消耗任何剩余的 gas。
	// 此外，当我们在 homestead 时，这也包括代码存储 gas 错误。
	if err != nil {
		// 步骤6：如果执行出错，回滚状态
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
// CallCode 执行与 addr 关联的合约，并将 input 作为参数。
// 它还处理所需的任何必要值转移，并采取必要步骤创建账户，
// 并在执行错误或失败的值转移时反转状态。
//
// CallCode 与 Call 的区别在于它以 caller 作为上下文执行给定地址的代码。
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *uint256.Int) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	// 调用 tracer 钩子，信号进入/退出调用帧
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, CALLCODE, caller.Address(), addr, input, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	// 如果试图在调用深度限制之上执行，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// Note although it's noop to transfer X ether to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	// 如果试图转移超过可用余额，则失败
	// 注意，虽然将 X ether 转移给 caller 本身是无操作的。
	// 但如果 caller 没有足够的余额，允许超额收费将是一个错误。
	// 因此这里的检查是必要的。
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	// 步骤1：创建状态快照，用于可能的回滚
	var snapshot = evm.StateDB.Snapshot()

	// It is allowed to call precompiles, even via delegatecall
	// 允许通过 delegatecall 调用预编译
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		// 步骤2：如果是预编译合约，直接运行
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		// 初始化一个新合约并设置 EVM 将使用的代码。
		// 合约是仅为此执行上下文的 scoped 环境。
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		contract.SetCallCode(&addrCopy, evm.resolveCodeHash(addrCopy), evm.resolveCode(addrCopy))
		// 步骤3：运行普通合约代码
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		// 步骤4：如果执行出错，回滚状态
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
// DelegateCall 执行与 addr 关联的合约，并将 input 作为参数。
// 它在执行错误时反转状态。
//
// DelegateCall 与 CallCode 的区别在于它以 caller 作为上下文执行给定地址的代码，
// 并且 caller 被设置为 caller 的 caller。
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	// 调用 tracer 钩子，信号进入/退出调用帧
	if evm.Config.Tracer != nil {
		// NOTE: caller must, at all times be a contract. It should never happen
		// that caller is something other than a Contract.
		// 注意：caller 必须始终是一个合约。不应该发生 caller 是其他类型的情况。
		parent := caller.(*Contract)
		// DELEGATECALL inherits value from parent call
		// DELEGATECALL 从父调用继承 value
		evm.captureBegin(evm.depth, DELEGATECALL, caller.Address(), addr, input, gas, parent.value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	// 如果试图在调用深度限制之上执行，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// 步骤1：创建状态快照，用于可能的回滚
	var snapshot = evm.StateDB.Snapshot()

	// It is allowed to call precompiles, even via delegatecall
	// 允许通过 delegatecall 调用预编译
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		// 步骤2：如果是预编译合约，直接运行
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		addrCopy := addr
		// Initialise a new contract and make initialise the delegate values
		// 初始化一个新合约并使 delegate 值初始化
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, evm.resolveCodeHash(addrCopy), evm.resolveCode(addrCopy))
		// 步骤3：运行普通合约代码
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		// 步骤4：如果执行出错，回滚状态
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
// StaticCall 执行与 addr 关联的合约，并将 input 作为参数，
// 同时不允许在调用期间对状态进行任何修改。
// 尝试执行此类修改的操作码将导致异常，而不是执行修改。
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Invoke tracer hooks that signal entering/exiting a call frame
	// 调用 tracer 钩子，信号进入/退出调用帧
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, STATICCALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Fail if we're trying to execute above the call depth limit
	// 如果试图在调用深度限制之上执行，则失败
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	// 我们在这里拍摄快照。这有点违反直觉，可能可以跳过。
	// 然而，即使是 staticcall 也被视为 'touch'。在主网上，static calls 是在所有空账户被删除后引入的，
	// 因此这不是必需的。然而，如果我们省略这一点，某些测试将开始失败；stRevertTest/RevertPrecompiledTouchExactOOG.json。
	// 我们可以改变这一点，但现在为了遗留原因而保留。
	// 步骤1：创建状态快照，即使是静态调用也需要
	var snapshot = evm.StateDB.Snapshot()

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	// 我们在这里执行 zero 的 AddBalance，只是为了触发 touch。
	// 这在主网上不重要，因为在 Byzantium 时所有空账户都已删除，
	// 但在其他网络、测试和潜在的未来场景中是正确的。
	// 步骤2：触发账户 touch，即使不改变余额
	evm.StateDB.AddBalance(addr, new(uint256.Int), tracing.BalanceChangeTouchAccount)

	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		// 步骤3：如果是预编译合约，直接运行
		ret, gas, err = RunPrecompiledContract(p, input, gas, evm.Config.Tracer)
	} else {
		// At this point, we use a copy of address. If we don't, the go compiler will
		// leak the 'contract' to the outer scope, and make allocation for 'contract'
		// even if the actual execution ends on RunPrecompiled above.
		// 在这一点上，我们使用地址的副本。如果不这样做，go 编译器会将 'contract' 泄漏到外部作用域，
		// 即使实际执行在上面的 RunPrecompiled 中结束，也会为 'contract' 分配内存。
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		// 初始化一个新合约并设置 EVM 将使用的代码。
		// 合约是仅为此执行上下文的 scoped 环境。
		contract := NewContract(caller, AccountRef(addrCopy), new(uint256.Int), gas)
		contract.SetCallCode(&addrCopy, evm.resolveCodeHash(addrCopy), evm.resolveCode(addrCopy))
		// When an error was returned by the EVM or when setting the creation code
		// above we revert to the snapshot and consume any gas remaining. Additionally
		// when we're in Homestead this also counts for code storage gas errors.
		// 当 EVM 返回错误或在上面设置创建代码时，我们反转到快照并消耗任何剩余的 gas。
		// 此外，当我们在 Homestead 时，这也包括代码存储 gas 错误。
		// 步骤4：运行普通合约代码，禁止状态修改
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		// 步骤5：如果执行出错，回滚状态
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
				evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
			}

			gas = 0
		}
	}
	return ret, gas, err
}

// codeAndHash 结构体用于存储代码及其哈希。
type codeAndHash struct {
	code []byte
	hash common.Hash
}

// Hash 返回代码的哈希，如果尚未计算，则计算它。
func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
// create 使用 code 作为部署代码创建新合约。
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *uint256.Int, address common.Address, typ OpCode) (ret []byte, createAddress common.Address, leftOverGas uint64, err error) {
	if evm.Config.Tracer != nil {
		evm.captureBegin(evm.depth, typ, caller.Address(), address, codeAndHash.code, gas, value.ToBig())
		defer func(startGas uint64) {
			evm.captureEnd(evm.depth, startGas, leftOverGas, ret, err)
		}(gas)
	}
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	// 深度检查执行。如果试图在限制之上执行，则失败。
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	// 步骤1：增加调用者的 nonce
	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	// Charge the contract creation init gas in verkle mode
	// 在 verkle 模式下收取合约创建 init gas
	if evm.chainRules.IsEIP4762 {
		statelessGas := evm.AccessEvents.ContractCreatePreCheckGas(address)
		if statelessGas > gas {
			return nil, common.Address{}, 0, ErrOutOfGas
		}
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, gas-statelessGas, tracing.GasChangeWitnessContractCollisionCheck)
		}
		gas = gas - statelessGas
	}

	// We add this to the access list _before_ taking a snapshot. Even if the
	// creation fails, the access-list change should not be rolled back.
	// 我们将此添加到访问列表 _before_ 拍摄快照。即使创建失败，访问列表更改也不应回滚。
	if evm.chainRules.IsEIP2929 {
		// 步骤2：将目标地址添加到访问列表
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address.
	// Account is regarded as existent if any of these three conditions is met:
	// - the nonce is non-zero
	// - the code is non-empty
	// - the storage is non-empty
	// 确保指定地址上没有现有的合约。
	// 如果以下任一条件成立，则账户被视为存在：
	// - nonce 非零
	// - 代码非空
	// - 存储非空
	contractHash := evm.StateDB.GetCodeHash(address)
	storageRoot := evm.StateDB.GetStorageRoot(address)
	if evm.StateDB.GetNonce(address) != 0 ||
		(contractHash != (common.Hash{}) && contractHash != types.EmptyCodeHash) || // non-empty code
		(storageRoot != (common.Hash{}) && storageRoot != types.EmptyRootHash) { // non-empty storage
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, 0, tracing.GasChangeCallFailedExecution)
		}
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state only if the object was not present.
	// It might be possible the contract code is deployed to a pre-existent
	// account with non-zero balance.
	// 仅当对象不存在时，在状态上创建新账户。
	// 可能合约代码部署到具有非零余额的预先存在的账户。
	// 步骤3：创建状态快照
	snapshot := evm.StateDB.Snapshot()
	if !evm.StateDB.Exist(address) {
		// 步骤4：如果账户不存在，创建新账户
		evm.StateDB.CreateAccount(address)
	}
	// CreateContract means that regardless of whether the account previously existed
	// in the state trie or not, it _now_ becomes created as a _contract_ account.
	// This is performed _prior_ to executing the initcode,  since the initcode
	// acts inside that account.
	// CreateContract 意味着无论账户之前是否存在于状态 trie 中，
	// 它 _now_ 作为 _contract_ 账户被创建。
	// 这是在执行 initcode 之前执行的，因为 initcode 在该账户内操作。
	// 步骤5：标记账户为合约账户
	evm.StateDB.CreateContract(address)

	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	// Charge the contract creation init gas in verkle mode
	// 在 verkle 模式下收取合约创建 init gas
	if evm.chainRules.IsEIP4762 {
		statelessGas := evm.AccessEvents.ContractCreateInitGas(address)
		if statelessGas > gas {
			return nil, common.Address{}, 0, ErrOutOfGas
		}
		if evm.Config.Tracer != nil && evm.Config.Tracer.OnGasChange != nil {
			evm.Config.Tracer.OnGasChange(gas, gas-statelessGas, tracing.GasChangeWitnessContractInit)
		}
		gas = gas - statelessGas
	}
	// 步骤6：执行转账操作
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	// 初始化一个新合约并设置 EVM 将使用的代码。
	// 合约是仅为此执行上下文的 scoped 环境。
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)
	contract.IsDeployment = true

	// 步骤7：运行初始化代码并设置合约代码
	ret, err = evm.initNewContract(contract, address, value)
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		// 步骤8：如果出错且满足条件，回滚状态
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas, evm.Config.Tracer, tracing.GasChangeCallFailedExecution)
		}
	}
	return ret, address, contract.Gas, err
}

// initNewContract runs a new contract's creation code, performs checks on the
// resulting code that is to be deployed, and consumes necessary gas.
// initNewContract 运行新合约的创建代码，对将要部署的代码执行检查，并消耗必要的 gas。
func (evm *EVM) initNewContract(contract *Contract, address common.Address, value *uint256.Int) ([]byte, error) {
	// 步骤1：运行合约初始化代码
	ret, err := evm.interpreter.Run(contract, nil, false)
	if err != nil {
		return ret, err
	}

	// Check whether the max code size has been exceeded, assign err if the case.
	// 检查是否超过了最大代码大小，如果是，则分配 err。
	if evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		return ret, ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	// 如果启用了 EIP-3541，拒绝以 0xEF 开头的代码。
	if len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		return ret, ErrInvalidCode
	}

	if !evm.chainRules.IsEIP4762 {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if !contract.UseGas(createDataGas, evm.Config.Tracer, tracing.GasChangeCallCodeStorage) {
			return ret, ErrCodeStoreOutOfGas
		}
	} else {
		if len(ret) > 0 && !contract.UseGas(evm.AccessEvents.CodeChunksRangeGas(address, 0, uint64(len(ret)), uint64(len(ret)), true), evm.Config.Tracer, tracing.GasChangeWitnessCodeChunk) {
			return ret, ErrCodeStoreOutOfGas
		}
	}

	// 步骤2：将初始化代码的结果设置为合约代码
	evm.StateDB.SetCode(address, ret)
	return ret, nil
}

// Create creates a new contract using code as deployment code.
// Create 使用 code 作为部署代码创建新合约。
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
// Create2 使用 code 作为部署代码创建新合约。
//
// Create2 与 Create 的不同之处在于 Create2 使用 keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// 而不是通常的 sender-and-nonce-hash 作为合约初始化的地址。
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *uint256.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}

// resolveCode returns the code associated with the provided account. After
// Prague, it can also resolve code pointed to by a delegation designator.
// resolveCode 返回与提供的账户关联的代码。在 Prague 之后，它还可以解析由委托设计符指向的代码。
func (evm *EVM) resolveCode(addr common.Address) []byte {
	code := evm.StateDB.GetCode(addr)
	if !evm.chainRules.IsPrague {
		return code
	}
	if target, ok := types.ParseDelegation(code); ok {
		// Note we only follow one level of delegation.
		// 注意，我们只跟随一级委托。
		return evm.StateDB.GetCode(target)
	}
	return code
}

// resolveCodeHash returns the code hash associated with the provided address.
// After Prague, it can also resolve code hash of the account pointed to by a
// delegation designator. Although this is not accessible in the EVM it is used
// internally to associate jumpdest analysis to code.
// resolveCodeHash 返回与提供的地址关联的代码哈希。
// 在 Prague 之后，它还可以解析由委托设计符指向的账户的代码哈希。
// 虽然这在 EVM 中不可访问，但它在内部用于将 jumpdest 分析关联到代码。
func (evm *EVM) resolveCodeHash(addr common.Address) common.Hash {
	if evm.chainRules.IsPrague {
		code := evm.StateDB.GetCode(addr)
		if target, ok := types.ParseDelegation(code); ok {
			// Note we only follow one level of delegation.
			// 注意，我们只跟随一级委托。
			return evm.StateDB.GetCodeHash(target)
		}
	}
	return evm.StateDB.GetCodeHash(addr)
}

// ChainConfig returns the environment's chain configuration
// ChainConfig 返回环境的链配置
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// captureBegin 捕获 tracer 的开始事件。
func (evm *EVM) captureBegin(depth int, typ OpCode, from common.Address, to common.Address, input []byte, startGas uint64, value *big.Int) {
	tracer := evm.Config.Tracer
	if tracer.OnEnter != nil {
		tracer.OnEnter(depth, byte(typ), from, to, input, startGas, value)
	}
	if tracer.OnGasChange != nil {
		tracer.OnGasChange(0, startGas, tracing.GasChangeCallInitialBalance)
	}
}

// captureEnd 捕获 tracer 的结束事件。
func (evm *EVM) captureEnd(depth int, startGas uint64, leftOverGas uint64, ret []byte, err error) {
	tracer := evm.Config.Tracer
	if leftOverGas != 0 && tracer.OnGasChange != nil {
		tracer.OnGasChange(leftOverGas, 0, tracing.GasChangeCallLeftOverReturned)
	}
	var reverted bool
	if err != nil {
		reverted = true
	}
	if !evm.chainRules.IsHomestead && errors.Is(err, ErrCodeStoreOutOfGas) {
		reverted = false
	}
	if tracer.OnExit != nil {
		tracer.OnExit(depth, ret, startGas-leftOverGas, VMErrorFromErr(err), reverted)
	}
}

// GetVMContext provides context about the block being executed as well as state
// to the tracers.
// GetVMContext 向 tracers 提供关于正在执行的块的上下文以及状态。
func (evm *EVM) GetVMContext() *tracing.VMContext {
	return &tracing.VMContext{
		Coinbase:    evm.Context.Coinbase,
		BlockNumber: evm.Context.BlockNumber,
		Time:        evm.Context.Time,
		Random:      evm.Context.Random,
		BaseFee:     evm.Context.BaseFee,
		StateDB:     evm.StateDB,
	}
}
