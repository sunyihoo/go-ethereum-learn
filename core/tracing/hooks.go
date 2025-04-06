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

package tracing

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// 1. 以太坊 EVM 与追踪的背景
// 以太坊的 EVM 是执行智能合约的核心组件，状态变更通过交易和区块处理实现。白皮书中提到 EVM 的状态转换由操作码驱动，黄皮书定义了操作码和 Gas 机制。追踪器通过钩子捕获这些过程的细节，用于调试、分析和审计。Hooks 结构体提供了全面的事件监听能力，覆盖 VM、链和状态变更。
//
// 2. 代码中的核心逻辑
// OpContext：
// 提供操作码执行的上下文（栈、内存、合约信息），支持低级别追踪。
// StateDB：
// 抽象状态访问接口，允许追踪器查询账户余额、nonce、代码和存储。
// VMContext：
// 封装区块级上下文（如 Coinbase、BaseFee），为交易和系统调用提供环境。
// Hooks：
// 分三类钩子：
// VM 事件：追踪交易（OnTxStart/End）、调用（OnEnter/Exit）、操作码（OnOpcode/Fault）和 Gas 变更（OnGasChange）。
// 链事件：追踪区块链初始化（OnBlockchainInit）、区块处理（OnBlockStart/End）、系统调用（OnSystemCall*）等。
// 状态事件：追踪余额（OnBalanceChange）、nonce（OnNonceChange）、代码（OnCodeChange）、存储（OnStorageChange）和日志（OnLog）。
// BalanceChangeReason：
// 枚举余额变更原因（如挖矿奖励、交易费用、自毁），支持细粒度分析。
// GasChangeReason：
// 区分交易级（GasChangeTx*）和调用级（GasChangeCall*）Gas 变更，涵盖内在成本、退款、操作码等场景。
// 3. 与以太坊改进提案（EIP）的关系
// EIP-1559（Fee Market Change）：
// BaseFee 在 VMContext 中支持追踪基础费用，BalanceIncreaseRewardTransactionFee 和 BalanceDecreaseGasBuy 反映新费用模型。
// EIP-2929（Gas Cost Increases for State Access）：
// GasChangeCallStorageColdAccess 捕获冷存储访问的 Gas 成本。
// EIP-4788（Beacon Block Root in EVM）：
// OnSystemCallStartHook 和 OnSystemCallEndHook 支持追踪信标链根设置的系统调用。
// EIP-3074（Cancun 分叉影响）：
// 自毁（SELFDESTRUCT）相关钩子（Balance*Selfdestruct）保留历史兼容性，但未来可能废弃。

// OpContext provides the context at which the opcode is being
// executed in, including the memory, stack and various contract-level information.
// OpContext 提供操作码执行时的上下文，包括内存、栈和各种合约级信息。
type OpContext interface {
	MemoryData() []byte       // 返回内存数据
	StackData() []uint256.Int // 返回栈数据
	Caller() common.Address   // 返回调用者地址
	Address() common.Address  // 返回合约地址
	CallValue() *uint256.Int  // 返回调用值
	CallInput() []byte        // 返回调用输入数据
	ContractCode() []byte     // 返回合约代码
}

// StateDB gives tracers access to the whole state.
// StateDB 提供追踪器对整个状态的访问。
type StateDB interface {
	GetBalance(common.Address) *uint256.Int                    // 获取账户余额
	GetNonce(common.Address) uint64                            // 获取账户 nonce
	GetCode(common.Address) []byte                             // 获取账户代码
	GetCodeHash(common.Address) common.Hash                    // 获取代码哈希
	GetState(common.Address, common.Hash) common.Hash          // 获取存储状态
	GetTransientState(common.Address, common.Hash) common.Hash // 获取临时存储状态
	Exist(common.Address) bool                                 // 检查账户是否存在
	GetRefund() uint64                                         // 获取退款值
}

// VMContext provides the context for the EVM execution.
// VMContext 提供 EVM 执行的上下文。
type VMContext struct {
	Coinbase    common.Address // 矿工地址
	BlockNumber *big.Int       // 区块号
	Time        uint64         // 时间戳
	Random      *common.Hash   // 随机数（例如 prevRandao）
	BaseFee     *big.Int       // 基础费用（EIP-1559）
	StateDB     StateDB        // 状态数据库
}

// BlockEvent is emitted upon tracing an incoming block.
// It contains the block as well as consensus related information.
// BlockEvent 在追踪传入区块时发出。
// 它包含区块以及共识相关信息。
type BlockEvent struct {
	Block     *types.Block  // 区块
	TD        *big.Int      // 总难度
	Finalized *types.Header // 最终确定的区块头
	Safe      *types.Header // 安全的区块头
}

type (
	/*
		- VM events -
		- VM 事件 -
	*/

	// TxStartHook is called before the execution of a transaction starts.
	// Call simulations don't come with a valid signature. `from` field
	// to be used for address of the caller.
	// TxStartHook 在交易执行开始前调用。
	// 调用模拟不带有效签名。`from` 字段用于调用者地址。
	TxStartHook = func(vm *VMContext, tx *types.Transaction, from common.Address)

	// TxEndHook is called after the execution of a transaction ends.
	// TxEndHook 在交易执行结束后调用。
	TxEndHook = func(receipt *types.Receipt, err error)

	// EnterHook is invoked when the processing of a message starts.
	//
	// Take note that EnterHook, when in the context of a live tracer, can be invoked
	// outside of the `OnTxStart` and `OnTxEnd` hooks when dealing with system calls,
	// see [OnSystemCallStartHook] and [OnSystemCallEndHook] for more information.
	// EnterHook 在消息处理开始时调用。
	//
	// 请注意，在实时追踪器上下文中，EnterHook 在处理系统调用时可能在 `OnTxStart` 和 `OnTxEnd` 钩子之外调用，
	// 更多信息见 [OnSystemCallStartHook] 和 [OnSystemCallEndHook]。
	EnterHook = func(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int)

	// ExitHook is invoked when the processing of a message ends.
	// `revert` is true when there was an error during the execution.
	// Exceptionally, before the homestead hardfork a contract creation that
	// ran out of gas when attempting to persist the code to database did not
	// count as a call failure and did not cause a revert of the call. This will
	// be indicated by `reverted == false` and `err == ErrCodeStoreOutOfGas`.
	//
	// Take note that ExitHook, when in the context of a live tracer, can be invoked
	// outside of the `OnTxStart` and `OnTxEnd` hooks when dealing with system calls,
	// see [OnSystemCallStartHook] and [OnSystemCallEndHook] for more information.
	// ExitHook 在消息处理结束时调用。
	// 当执行期间发生错误时，`revert` 为 true。
	// 例外情况，在 Homestead 硬分叉之前，合约创建因尝试将代码持久化到数据库时耗尽 Gas 不视为调用失败，
	// 也不会导致调用回滚。这将由 `reverted == false` 和 `err == ErrCodeStoreOutOfGas` 表示。
	//
	// 请注意，在实时追踪器上下文中，ExitHook 在处理系统调用时可能在 `OnTxStart` 和 `OnTxEnd` 钩子之外调用，
	// 更多信息见 [OnSystemCallStartHook] 和 [OnSystemCallEndHook]。
	ExitHook = func(depth int, output []byte, gasUsed uint64, err error, reverted bool)

	// OpcodeHook is invoked just prior to the execution of an opcode.
	// OpcodeHook 在操作码执行前调用。
	OpcodeHook = func(pc uint64, op byte, gas, cost uint64, scope OpContext, rData []byte, depth int, err error)

	// FaultHook is invoked when an error occurs during the execution of an opcode.
	// FaultHook 在操作码执行期间发生错误时调用。
	FaultHook = func(pc uint64, op byte, gas, cost uint64, scope OpContext, depth int, err error)

	// GasChangeHook is invoked when the gas changes.
	// GasChangeHook 在 Gas 变更时调用。
	GasChangeHook = func(old, new uint64, reason GasChangeReason)

	/*
		- Chain events -
		- 链事件 -
	*/

	// BlockchainInitHook is called when the blockchain is initialized.
	// BlockchainInitHook 在区块链初始化时调用。
	BlockchainInitHook = func(chainConfig *params.ChainConfig)

	// CloseHook is called when the blockchain closes.
	// CloseHook 在区块链关闭时调用。
	CloseHook = func()

	// BlockStartHook is called before executing `block`.
	// `td` is the total difficulty prior to `block`.
	// BlockStartHook 在执行 `block` 前调用。
	// `td` 是 `block` 之前的总难度。
	BlockStartHook = func(event BlockEvent)

	// BlockEndHook is called after executing a block.
	// BlockEndHook 在执行区块后调用。
	BlockEndHook = func(err error)

	// SkippedBlockHook indicates a block was skipped during processing
	// due to it being known previously. This can happen e.g. when recovering
	// from a crash.
	// SkippedBlockHook 表示在处理期间跳过了一个已知的区块。
	// 这种情况可能发生在例如从崩溃中恢复时。
	SkippedBlockHook = func(event BlockEvent)

	// GenesisBlockHook is called when the genesis block is being processed.
	// GenesisBlockHook 在处理创世区块时调用。
	GenesisBlockHook = func(genesis *types.Block, alloc types.GenesisAlloc)

	// OnSystemCallStartHook is called when a system call is about to be executed. Today,
	// this hook is invoked when the EIP-4788 system call is about to be executed to set the
	// beacon block root.
	//
	// After this hook, the EVM call tracing will happened as usual so you will receive a `OnEnter/OnExit`
	// as well as state hooks between this hook and the `OnSystemCallEndHook`.
	//
	// Note that system call happens outside normal transaction execution, so the `OnTxStart/OnTxEnd` hooks
	// will not be invoked.
	// OnSystemCallStartHook 在系统调用即将执行时调用。
	// 当前，此钩子在 EIP-4788 系统调用即将执行以设置信标区块根时调用。
	//
	// 在此钩子之后，EVM 调用追踪将照常进行，因此你将在此钩子和 `OnSystemCallEndHook` 之间接收到 `OnEnter/OnExit`
	// 以及状态钩子。
	//
	// 注意，系统调用发生在正常交易执行之外，因此不会调用 `OnTxStart/OnTxEnd` 钩子。
	OnSystemCallStartHook = func()

	// OnSystemCallStartHookV2 is called when a system call is about to be executed. Refer
	// to `OnSystemCallStartHook` for more information.
	// OnSystemCallStartHookV2 在系统调用即将执行时调用。更多信息参考 `OnSystemCallStartHook`。
	OnSystemCallStartHookV2 = func(vm *VMContext)

	// OnSystemCallEndHook is called when a system call has finished executing. Today,
	// this hook is invoked when the EIP-4788 system call is about to be executed to set the
	// beacon block root.
	// OnSystemCallEndHook 在系统调用完成执行时调用。
	// 当前，此钩子在 EIP-4788 系统调用完成设置信标区块根时调用。
	OnSystemCallEndHook = func()

	/*
		- State events -
		- 状态事件 -
	*/

	// BalanceChangeHook is called when the balance of an account changes.
	// BalanceChangeHook 在账户余额变更时调用。
	BalanceChangeHook = func(addr common.Address, prev, new *big.Int, reason BalanceChangeReason)

	// NonceChangeHook is called when the nonce of an account changes.
	// NonceChangeHook 在账户 nonce 变更时调用。
	NonceChangeHook = func(addr common.Address, prev, new uint64)

	// CodeChangeHook is called when the code of an account changes.
	// CodeChangeHook 在账户代码变更时调用。
	CodeChangeHook = func(addr common.Address, prevCodeHash common.Hash, prevCode []byte, codeHash common.Hash, code []byte)

	// StorageChangeHook is called when the storage of an account changes.
	// StorageChangeHook 在账户存储变更时调用。
	StorageChangeHook = func(addr common.Address, slot common.Hash, prev, new common.Hash)

	// LogHook is called when a log is emitted.
	// LogHook 在日志发出时调用。
	LogHook = func(log *types.Log)
)

// Hooks struct aggregates all tracing hooks.
// Hooks 结构体聚合了所有追踪钩子。
type Hooks struct {
	// VM events
	// VM 事件
	OnTxStart   TxStartHook
	OnTxEnd     TxEndHook
	OnEnter     EnterHook
	OnExit      ExitHook
	OnOpcode    OpcodeHook
	OnFault     FaultHook
	OnGasChange GasChangeHook
	// Chain events
	// 链事件
	OnBlockchainInit    BlockchainInitHook
	OnClose             CloseHook
	OnBlockStart        BlockStartHook
	OnBlockEnd          BlockEndHook
	OnSkippedBlock      SkippedBlockHook
	OnGenesisBlock      GenesisBlockHook
	OnSystemCallStart   OnSystemCallStartHook
	OnSystemCallStartV2 OnSystemCallStartHookV2
	OnSystemCallEnd     OnSystemCallEndHook
	// State events
	// 状态事件
	OnBalanceChange BalanceChangeHook
	OnNonceChange   NonceChangeHook
	OnCodeChange    CodeChangeHook
	OnStorageChange StorageChangeHook
	OnLog           LogHook
}

// BalanceChangeReason is used to indicate the reason for a balance change, useful
// for tracing and reporting.
// BalanceChangeReason 用于指示余额变更的原因，对追踪和报告有用。
type BalanceChangeReason byte

//go:generate go run golang.org/x/tools/cmd/stringer -type=BalanceChangeReason -output gen_balance_change_reason_stringer.go

const (
	BalanceChangeUnspecified BalanceChangeReason = 0 // 未指定的余额变更

	// Issuance
	// BalanceIncreaseRewardMineUncle is a reward for mining an uncle block.
	BalanceIncreaseRewardMineUncle BalanceChangeReason = 1
	// BalanceIncreaseRewardMineBlock is a reward for mining a block.
	BalanceIncreaseRewardMineBlock BalanceChangeReason = 2
	// BalanceIncreaseWithdrawal is ether withdrawn from the beacon chain.
	BalanceIncreaseWithdrawal BalanceChangeReason = 3
	// BalanceIncreaseGenesisBalance is ether allocated at the genesis block.
	BalanceIncreaseGenesisBalance BalanceChangeReason = 4

	// Transaction fees
	// BalanceIncreaseRewardTransactionFee is the transaction tip increasing block builder's balance.
	BalanceIncreaseRewardTransactionFee BalanceChangeReason = 5
	// BalanceDecreaseGasBuy is spent to purchase gas for execution a transaction.
	// Part of this gas will be burnt as per EIP-1559 rules.
	BalanceDecreaseGasBuy BalanceChangeReason = 6
	// BalanceIncreaseGasReturn is ether returned for unused gas at the end of execution.
	BalanceIncreaseGasReturn BalanceChangeReason = 7

	// DAO fork
	// BalanceIncreaseDaoContract is ether sent to the DAO refund contract.
	BalanceIncreaseDaoContract BalanceChangeReason = 8
	// BalanceDecreaseDaoAccount is ether taken from a DAO account to be moved to the refund contract.
	BalanceDecreaseDaoAccount BalanceChangeReason = 9

	// BalanceChangeTransfer is ether transferred via a call.
	// it is a decrease for the sender and an increase for the recipient.
	BalanceChangeTransfer BalanceChangeReason = 10
	// BalanceChangeTouchAccount is a transfer of zero value. It is only there to
	// touch-create an account.
	BalanceChangeTouchAccount BalanceChangeReason = 11

	// BalanceIncreaseSelfdestruct is added to the recipient as indicated by a selfdestructing account.
	BalanceIncreaseSelfdestruct BalanceChangeReason = 12
	// BalanceDecreaseSelfdestruct is deducted from a contract due to self-destruct.
	BalanceDecreaseSelfdestruct BalanceChangeReason = 13
	// BalanceDecreaseSelfdestructBurn is ether that is sent to an already self-destructed
	// account within the same tx (captured at end of tx).
	// Note it doesn't account for a self-destruct which appoints itself as recipient.
	BalanceDecreaseSelfdestructBurn BalanceChangeReason = 14
)

// GasChangeReason is used to indicate the reason for a gas change, useful
// for tracing and reporting.
//
// There is essentially two types of gas changes, those that can be emitted once per transaction
// and those that can be emitted on a call basis, so possibly multiple times per transaction.
//
// They can be recognized easily by their name, those that start with `GasChangeTx` are emitted
// once per transaction, while those that start with `GasChangeCall` are emitted on a call basis.
// GasChangeReason 用于指示 Gas 变更的原因，对追踪和报告有用。
//
// 基本上有两种类型的 Gas 变更：每笔交易发出一次的变更和基于调用发出的变更，可能在每笔交易中多次发出。
//
// 通过名称可以轻松识别，以 `GasChangeTx` 开头的每笔交易发出一次，以 `GasChangeCall` 开头的基于调用发出。
type GasChangeReason byte

const (
	GasChangeUnspecified GasChangeReason = 0 // 未指定的 Gas 变更

	// GasChangeTxInitialBalance is the initial balance for the call which will be equal to the gasLimit of the call. There is only
	// one such gas change per transaction.
	// GasChangeTxInitialBalance 是调用的初始余额，等于调用的 Gas 限制。每笔交易只有一次此类 Gas 变更。
	GasChangeTxInitialBalance GasChangeReason = 1
	// GasChangeTxIntrinsicGas is the amount of gas that will be charged for the intrinsic cost of the transaction, there is
	// always exactly one of those per transaction.
	// GasChangeTxIntrinsicGas 是交易内在成本将收取的 Gas 量，每笔交易始终有且仅有一次。
	GasChangeTxIntrinsicGas GasChangeReason = 2
	// GasChangeTxRefunds is the sum of all refunds which happened during the tx execution (e.g. storage slot being cleared)
	// this generates an increase in gas. There is at most one of such gas change per transaction.
	// GasChangeTxRefunds 是交易执行期间发生的所有退款总和（例如存储槽被清除），这会增加 Gas。每笔交易最多有一次此类 Gas 变更。
	GasChangeTxRefunds GasChangeReason = 3
	// GasChangeTxLeftOverReturned is the amount of gas left over at the end of transaction's execution that will be returned
	// to the chain. This change will always be a negative change as we "drain" left over gas towards 0. If there was no gas
	// left at the end of execution, no such even will be emitted. The returned gas's value in Wei is returned to caller.
	// There is at most one of such gas change per transaction.
	// GasChangeTxLeftOverReturned 是交易执行结束时剩余的 Gas 量，将返回给链。此变更始终为负值，因为我们将剩余 Gas “耗尽”至 0。
	// 如果执行结束时没有剩余 Gas，则不会发出此类事件。返回的 Gas 以 Wei 为单位返还给调用者。每笔交易最多有一次此类 Gas 变更。
	GasChangeTxLeftOverReturned GasChangeReason = 4

	// GasChangeCallInitialBalance is the initial balance for the call which will be equal to the gasLimit of the call. There is only
	// one such gas change per call.
	// GasChangeCallInitialBalance 是调用的初始余额，等于调用的 Gas 限制。每次调用只有一次此类 Gas 变更。
	GasChangeCallInitialBalance GasChangeReason = 5
	// GasChangeCallLeftOverReturned is the amount of gas left over that will be returned to the caller, this change will always
	// be a negative change as we "drain" left over gas towards 0. If there was no gas left at the end of execution, no such even
	// will be emitted.
	// GasChangeCallLeftOverReturned 是剩余的 Gas 量，将返回给调用者，此变更始终为负值，因为我们将剩余 Gas “耗尽”至 0。
	// 如果执行结束时没有剩余 Gas，则不会发出此类事件。
	GasChangeCallLeftOverReturned GasChangeReason = 6
	// GasChangeCallLeftOverRefunded is the amount of gas that will be refunded to the call after the child call execution it
	// executed completed. This value is always positive as we are giving gas back to the you, the left over gas of the child.
	// If there was no gas left to be refunded, no such even will be emitted.
	// GasChangeCallLeftOverRefunded 是子调用执行完成后将退还给调用的 Gas 量。此值始终为正，因为我们将子调用的剩余 Gas 返还给你。
	// 如果没有剩余 Gas 可退还，则不会发出此类事件。
	GasChangeCallLeftOverRefunded GasChangeReason = 7
	// GasChangeCallContractCreation is the amount of gas that will be burned for a CREATE.
	// GasChangeCallContractCreation 是 CREATE 将消耗的 Gas 量。
	GasChangeCallContractCreation GasChangeReason = 8
	// GasChangeCallContractCreation2 is the amount of gas that will be burned for a CREATE2.
	// GasChangeCallContractCreation2 是 CREATE2 将消耗的 Gas 量。
	GasChangeCallContractCreation2 GasChangeReason = 9
	// GasChangeCallCodeStorage is the amount of gas that will be charged for code storage.
	// GasChangeCallCodeStorage 是代码存储将收取的 Gas 量。
	GasChangeCallCodeStorage GasChangeReason = 10
	// GasChangeCallOpCode is the amount of gas that will be charged for an opcode executed by the EVM, exact opcode that was
	// performed can be check by `OnOpcode` handling.
	// GasChangeCallOpCode 是 EVM 执行的操作码将收取的 Gas 量，具体执行的操作码可通过 `OnOpcode` 处理检查。
	GasChangeCallOpCode GasChangeReason = 11
	// GasChangeCallPrecompiledContract is the amount of gas that will be charged for a precompiled contract execution.
	// GasChangeCallPrecompiledContract 是预编译合约执行将收取的 Gas 量。
	GasChangeCallPrecompiledContract GasChangeReason = 12
	// GasChangeCallStorageColdAccess is the amount of gas that will be charged for a cold storage access as controlled by EIP2929 rules.
	// GasChangeCallStorageColdAccess 是根据 EIP-2929 规则为冷存储访问收取的 Gas 量。
	GasChangeCallStorageColdAccess GasChangeReason = 13
	// GasChangeCallFailedExecution is the burning of the remaining gas when the execution failed without a revert.
	// GasChangeCallFailedExecution 是执行失败但未回滚时剩余 Gas 的销毁。
	GasChangeCallFailedExecution GasChangeReason = 14
	// GasChangeWitnessContractInit flags the event of adding to the witness during the contract creation initialization step.
	// GasChangeWitnessContractInit 标记在合约创建初始化步骤中添加到见证的事件。
	GasChangeWitnessContractInit GasChangeReason = 15
	// GasChangeWitnessContractCreation flags the event of adding to the witness during the contract creation finalization step.
	// GasChangeWitnessContractCreation 标记在合约创建最终化步骤中添加到见证的事件。
	GasChangeWitnessContractCreation GasChangeReason = 16
	// GasChangeWitnessCodeChunk flags the event of adding one or more contract code chunks to the witness.
	// GasChangeWitnessCodeChunk 标记将一个或多个合约代码块添加到见证的事件。
	GasChangeWitnessCodeChunk GasChangeReason = 17
	// GasChangeWitnessContractCollisionCheck flags the event of adding to the witness when checking for contract address collision.
	// GasChangeWitnessContractCollisionCheck 标记在检查合约地址冲突时添加到见证的事件。
	GasChangeWitnessContractCollisionCheck GasChangeReason = 18

	// GasChangeIgnored is a special value that can be used to indicate that the gas change should be ignored as
	// it will be "manually" tracked by a direct emit of the gas change event.
	// GasChangeIgnored 是一个特殊值，可用于指示应忽略 Gas 变更，因为它将通过直接发出 Gas 变更事件“手动”跟踪。
	GasChangeIgnored GasChangeReason = 0xFF
)
