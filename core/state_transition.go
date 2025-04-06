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

package core

import (
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// 1. 交易池和状态转换（白皮书）
// 以太坊白皮书中提到，交易池和状态转换是节点处理交易的核心机制。交易池（如 LegacyPool）负责收集未确认交易，而状态转换（如 stateTransition）则将交易应用于当前世界状态，生成新的状态根。ApplyMessage 和 stateTransition 实现了白皮书中描述的状态转换模型：
//
// Nonce 处理：确保交易顺序一致，避免重放攻击（见 preCheck 中的 nonce 检查）。
// Gas 机制：预付 Gas（buyGas）、计算内在 Gas（IntrinsicGas）并执行退款（refundGas），体现了以太坊的经济模型，防止资源滥用。
// 价值转移和合约创建：execute 方法处理普通调用和合约创建，符合白皮书中对状态更改的定义。
// 2. 黄皮书中的 Gas 计算（Appendix G）
// 黄皮书定义了 Gas 作为以太坊计算资源的计量单位。IntrinsicGas 函数实现了黄皮书中 Appendix G 的 Gas 计算规则：
//
// 基础 Gas：普通交易（TxGas）和合约创建（TxGasContractCreation）的固定成本。
// 数据 Gas：区分零字节（TxDataZeroGas）和非零字节（TxDataNonZeroGas），EIP-2028 修改了非零字节成本。
// EIP-3860：为初始化代码引入按字（32 字节）计费（InitCodeWordGas），防止过大的合约部署。
// 访问列表（EIP-2930）：为地址（TxAccessListAddressGas）和存储键（TxAccessListStorageKeyGas）分配额外 Gas。
// 授权列表（EIP-7702）：为每个授权项分配 Gas（CallNewAccountGas）。
// 3. EIP 的影响
// 代码中多个函数反映了以太坊改进提案（EIP）的实现：
//
// EIP-1559（伦敦硬分叉）：preCheck 检查 GasFeeCap 和 GasTipCap，execute 计算有效小费并支付给矿工（Coinbase），引入基础费用机制。
// EIP-2930：AccessList 支持在交易中预声明访问的地址和存储槽，降低 Gas 成本（见 IntrinsicGas）。
// EIP-3529：修改退款规则，从 Gas 使用量的 1/2（RefundQuotient）变为 1/5（RefundQuotientEIP3529），见 refundGas。
// EIP-3860（上海硬分叉）：限制初始化代码大小（MaxInitCodeSize）并引入字计费，见 IntrinsicGas 和 execute。
// EIP-4844（Cancun 硬分叉）：引入 Blob 交易，blobGasUsed 计算 Blob Gas，buyGas 和 preCheck 验证 Blob 费用。
// EIP-7702：支持代码授权（SetCodeAuthorizations），applyAuthorization 处理委托逻辑，允许账户动态更改代码。
// 4. EVM 执行（黄皮书 Section 9）
// execute 方法调用 EVM 的 Create 或 Call，实现了黄皮书中 Section 9 描述的虚拟机执行过程：
//
// 合约创建：运行初始化代码，返回结果作为合约代码。
// 普通调用：执行目标地址的代码，处理返回值或错误（如 ErrExecutionReverted）。
// 错误处理：区分共识错误（返回 nil 结果）和执行错误（如 ErrOutOfGas），符合 EVM 的容错设计。
// 5. 状态数据库和访问列表
// stateTransition 使用 StateDB 管理状态（如余额、nonce、代码），Prepare 方法支持 EIP-2930 的访问列表和 EIP-1153 的临时存储重置，确保状态一致性。EIP-4762 的访问事件（AccessEvents）进一步优化了状态见证生成。
//
// 6. Gas 退款和经济激励
// refundGas 实现了以太坊的经济激励机制：
//
// 退款上限：EIP-3529 前为 Gas 使用量的 1/2，之后为 1/5，鼓励存储清理操作。
// 剩余 Gas：退还给发送者并返还到 Gas 池（gp.AddGas），确保区块 Gas 限额的有效利用。
// 7. Blob 交易（EIP-4844）
// blobGasUsed 和 buyGas 支持 EIP-4844 的 Blob 交易，引入独立于普通 Gas 的 Blob Gas 机制，用于数据可用性分片（如 rollups），降低 Layer 2 成本。

// ExecutionResult includes all output after executing given evm
// message no matter the execution itself is successful or not.
// ExecutionResult 包含执行给定 EVM 消息后的所有输出，无论执行本身是否成功。
type ExecutionResult struct {
	UsedGas uint64 // Total used gas, not including the refunded gas
	// 已使用的总 gas，不包括退还的 gas
	RefundedGas uint64 // Total gas refunded after execution
	// 执行后退还的总 gas
	Err error // Any error encountered during the execution(listed in core/vm/errors.go)
	// 执行期间遇到的任何错误（列在 core/vm/errors.go 中）
	ReturnData []byte // Returned data from evm(function result or data supplied with revert opcode)
	// 从 EVM 返回的数据（函数结果或随 revert 操作码提供的数据）
}

// Unwrap returns the internal evm error which allows us for further
// analysis outside.
// Unwrap 返回内部 EVM 错误，以便我们在外部进行进一步分析。
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns the indicator whether the execution is successful or not
// Failed 返回执行是否成功的指示器
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// Return is a helper function to help caller distinguish between revert reason
// and function return. Return returns the data after execution if no error occurs.
// Return 是一个辅助函数，帮助调用者区分 revert 原因和函数返回。如果没有错误发生，Return 返回执行后的数据。
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the concrete revert reason if the execution is aborted by `REVERT`
// opcode. Note the reason can be nil if no data supplied with revert opcode.
// Revert 返回由 `REVERT` 操作码中止执行时的具体 revert 原因。注意，如果 revert 操作码未提供数据，原因可能是 nil。
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
// IntrinsicGas 计算给定数据的消息的“内在 gas”。
func IntrinsicGas(data []byte, accessList types.AccessList, authList []types.SetCodeAuthorization, isContractCreation, isHomestead, isEIP2028, isEIP3860 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	// 设置原始交易的起始 gas
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation // 合约创建时的 gas
	} else {
		gas = params.TxGas // 普通交易的 gas
	}
	dataLen := uint64(len(data))
	// Bump the required gas by the amount of transactional data
	// 根据交易数据量增加所需 gas
	if dataLen > 0 {
		// Zero and non-zero bytes are priced differently
		// 零字节和非零字节的定价不同
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++ // 计算非零字节数
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		// 确保所有数据组合不会超过 uint64
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028 // EIP-2028 修改后的非零字节 gas
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow // 如果计算溢出，返回错误
		}
		gas += nz * nonZeroGas // 增加非零字节的 gas

		z := dataLen - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow // 如果计算溢出，返回错误
		}
		gas += z * params.TxDataZeroGas // 增加零字节的 gas

		if isContractCreation && isEIP3860 {
			lenWords := toWordSize(dataLen)
			if (math.MaxUint64-gas)/params.InitCodeWordGas < lenWords {
				return 0, ErrGasUintOverflow // 如果计算溢出，返回错误
			}
			gas += lenWords * params.InitCodeWordGas // EIP-3860 初始化代码的额外 gas
		}
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas             // 访问列表中地址的 gas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas // 访问列表中存储键的 gas
	}
	if authList != nil {
		gas += uint64(len(authList)) * params.CallNewAccountGas // EIP-7702 授权列表的 gas
	}
	return gas, nil
}

// toWordSize returns the ceiled word size required for init code payment calculation.
// toWordSize 返回初始化代码支付计算所需的向上取整的字大小。
func toWordSize(size uint64) uint64 {
	if size > math.MaxUint64-31 {
		return math.MaxUint64/32 + 1
	}
	return (size + 31) / 32 // 向上取整到 32 字节的倍数
}

// A Message contains the data derived from a single transaction that is relevant to state
// processing.
// Message 包含从单个交易中派生的与状态处理相关的数据。
type Message struct {
	To                    *common.Address              // 接收地址
	From                  common.Address               // 发送地址
	Nonce                 uint64                       // nonce 值
	Value                 *big.Int                     // 转账金额
	GasLimit              uint64                       // Gas 限制
	GasPrice              *big.Int                     // Gas 价格
	GasFeeCap             *big.Int                     // Gas 费用上限（EIP-1559）
	GasTipCap             *big.Int                     // Gas 小费上限（EIP-1559）
	Data                  []byte                       // 数据
	AccessList            types.AccessList             // 访问列表（EIP-2930）
	BlobGasFeeCap         *big.Int                     // Blob Gas 费用上限（EIP-4844）
	BlobHashes            []common.Hash                // Blob 哈希（EIP-4844）
	SetCodeAuthorizations []types.SetCodeAuthorization // 代码授权（EIP-7702）

	// When SkipNonceChecks is true, the message nonce is not checked against the
	// account nonce in state.
	// This field will be set to true for operations like RPC eth_call.
	// 当 SkipNonceChecks 为 true 时，不检查消息 nonce 与状态中的账户 nonce。
	// 此字段在诸如 RPC eth_call 的操作中设置为 true。
	SkipNonceChecks bool

	// When SkipFromEOACheck is true, the message sender is not checked to be an EOA.
	// 当 SkipFromEOACheck 为 true 时，不检查消息发送者是否为 EOA。
	SkipFromEOACheck bool
}

// TransactionToMessage converts a transaction into a Message.
// TransactionToMessage 将交易转换为 Message。
func TransactionToMessage(tx *types.Transaction, s types.Signer, baseFee *big.Int) (*Message, error) {
	msg := &Message{
		Nonce:                 tx.Nonce(),                       // 交易的 nonce
		GasLimit:              tx.Gas(),                         // 交易的 Gas 限制
		GasPrice:              new(big.Int).Set(tx.GasPrice()),  // 交易的 Gas 价格
		GasFeeCap:             new(big.Int).Set(tx.GasFeeCap()), // 交易的 Gas 费用上限
		GasTipCap:             new(big.Int).Set(tx.GasTipCap()), // 交易的 Gas 小费上限
		To:                    tx.To(),                          // 交易的接收地址
		Value:                 tx.Value(),                       // 交易的转账金额
		Data:                  tx.Data(),                        // 交易的数据
		AccessList:            tx.AccessList(),                  // 交易的访问列表
		SetCodeAuthorizations: tx.SetCodeAuthorizations(),       // 交易的代码授权
		SkipNonceChecks:       false,                            // 默认不跳过 nonce 检查
		SkipFromEOACheck:      false,                            // 默认不跳过 EOA 检查
		BlobHashes:            tx.BlobHashes(),                  // 交易的 Blob 哈希
		BlobGasFeeCap:         tx.BlobGasFeeCap(),               // 交易的 Blob Gas 费用上限
	}
	// If baseFee provided, set gasPrice to effectiveGasPrice.
	// 如果提供了 baseFee，将 gasPrice 设置为有效 Gas 价格。
	if baseFee != nil {
		msg.GasPrice = msg.GasPrice.Add(msg.GasTipCap, baseFee) // 有效 Gas 价格 = 小费 + 基础费用
		if msg.GasPrice.Cmp(msg.GasFeeCap) > 0 {
			msg.GasPrice = msg.GasFeeCap // 如果超过费用上限，则使用上限
		}
	}
	var err error
	msg.From, err = types.Sender(s, tx) // 从交易中恢复发送者地址
	return msg, err
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
// ApplyMessage 通过在环境中对旧状态应用给定消息来计算新状态。
//
// ApplyMessage 返回任何 EVM 执行返回的字节（如果执行发生）、使用的 gas（包括 gas 退款）以及失败时的错误。错误始终表示核心错误，意味着该消息在特定状态下始终会失败，且永远不会被区块接受。
func ApplyMessage(evm *vm.EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	evm.SetTxContext(NewEVMTxContext(msg))            // 设置交易上下文
	return newStateTransition(evm, msg, gp).execute() // 执行状态转换
}

// stateTransition represents a state transition.
//
// == The State Transitioning Model
//
// A state transition is a change made when a transaction is applied to the current world
// state. The state transitioning model does all the necessary work to work out a valid new
// state root.
//
//  1. Nonce handling
//  2. Pre pay gas
//  3. Create a new state object if the recipient is nil
//  4. Value transfer
//
// == If contract creation ==
//
//	4a. Attempt to run transaction data
//	4b. If valid, use result as code for the new state object
//
// == end ==
//
//  5. Run Script section
//  6. Derive new state root
//
// stateTransition 表示状态转换。
//
// == 状态转换模型 ==
//
// 状态转换是将交易应用于当前世界状态时所做的更改。状态转换模型完成所有必要工作，以计算出有效的新状态根。
//
//  1. 处理 nonce
//  2. 预付 gas
//  3. 如果接收者为 nil，则创建新状态对象
//  4. 价值转移
//
// == 如果是合约创建 ==
//
//	4a. 尝试运行交易数据
//	4b. 如果有效，将结果用作新状态对象的代码
//
// == 结束 ==
//
//  5. 运行脚本部分
//  6. 派生新的状态根
type stateTransition struct {
	gp           *GasPool   // Gas 池
	msg          *Message   // 消息
	gasRemaining uint64     // 剩余 Gas
	initialGas   uint64     // 初始 Gas
	state        vm.StateDB // 状态数据库
	evm          *vm.EVM    // EVM 实例
}

// newStateTransition initialises and returns a new state transition object.
// newStateTransition 初始化并返回一个新的状态转换对象。
func newStateTransition(evm *vm.EVM, msg *Message, gp *GasPool) *stateTransition {
	return &stateTransition{
		gp:    gp,          // Gas 池
		evm:   evm,         // EVM 实例
		msg:   msg,         // 消息
		state: evm.StateDB, // 状态数据库
	}
}

// to returns the recipient of the message.
// to 返回消息的接收者。
func (st *stateTransition) to() common.Address {
	if st.msg == nil || st.msg.To == nil /* contract creation */ {
		return common.Address{} // 如果是合约创建，返回零地址
	}
	return *st.msg.To // 返回接收地址
}

func (st *stateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.GasLimit) // 计算 Gas 费用
	mgval.Mul(mgval, st.msg.GasPrice)
	balanceCheck := new(big.Int).Set(mgval)
	if st.msg.GasFeeCap != nil {
		balanceCheck.SetUint64(st.msg.GasLimit)
		balanceCheck = balanceCheck.Mul(balanceCheck, st.msg.GasFeeCap) // 使用 Gas 费用上限检查余额
	}
	balanceCheck.Add(balanceCheck, st.msg.Value) // 加上转账金额

	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time) {
		if blobGas := st.blobGasUsed(); blobGas > 0 {
			// Check that the user has enough funds to cover blobGasUsed * tx.BlobGasFeeCap
			// 检查用户是否有足够的资金支付 blobGasUsed * tx.BlobGasFeeCap
			blobBalanceCheck := new(big.Int).SetUint64(blobGas)
			blobBalanceCheck.Mul(blobBalanceCheck, st.msg.BlobGasFeeCap)
			balanceCheck.Add(balanceCheck, blobBalanceCheck)
			// Pay for blobGasUsed * actual blob fee
			// 支付 blobGasUsed * 实际 blob 费用
			blobFee := new(big.Int).SetUint64(blobGas)
			blobFee.Mul(blobFee, st.evm.Context.BlobBaseFee)
			mgval.Add(mgval, blobFee)
		}
	}
	balanceCheckU256, overflow := uint256.FromBig(balanceCheck)
	if overflow {
		return fmt.Errorf("%w: address %v required balance exceeds 256 bits", ErrInsufficientFunds, st.msg.From.Hex())
		// 如果余额检查溢出，返回错误
	}
	if have, want := st.state.GetBalance(st.msg.From), balanceCheckU256; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
		// 如果余额不足，返回错误
	}
	if err := st.gp.SubGas(st.msg.GasLimit); err != nil {
		return err // 如果 Gas 池不足，返回错误
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil {
		st.evm.Config.Tracer.OnGasChange(0, st.msg.GasLimit, tracing.GasChangeTxInitialBalance)
		// 如果启用了追踪器，记录 Gas 变化
	}
	st.gasRemaining = st.msg.GasLimit // 设置剩余 Gas

	st.initialGas = st.msg.GasLimit // 设置初始 Gas
	mgvalU256, _ := uint256.FromBig(mgval)
	st.state.SubBalance(st.msg.From, mgvalU256, tracing.BalanceDecreaseGasBuy) // 扣除 Gas 费用
	return nil
}

func (st *stateTransition) preCheck() error {
	// Only check transactions that are not fake
	// 仅检查非伪造的交易
	msg := st.msg
	if !msg.SkipNonceChecks {
		// Make sure this transaction's nonce is correct.
		// 确保交易的 nonce 正确。
		stNonce := st.state.GetNonce(msg.From)
		if msgNonce := msg.Nonce; stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				msg.From.Hex(), msgNonce, stNonce)
			// 如果 nonce 过高，返回错误
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				msg.From.Hex(), msgNonce, stNonce)
			// 如果 nonce 过低，返回错误
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				msg.From.Hex(), stNonce)
			// 如果 nonce 达到最大值，返回错误
		}
	}
	if !msg.SkipFromEOACheck {
		// Make sure the sender is an EOA
		// 确保发送者是 EOA
		code := st.state.GetCode(msg.From)
		_, delegated := types.ParseDelegation(code)
		if len(code) > 0 && !delegated {
			return fmt.Errorf("%w: address %v, len(code): %d", ErrSenderNoEOA, msg.From.Hex(), len(code))
			// 如果发送者不是 EOA，返回错误
		}
	}
	// Make sure that transaction gasFeeCap is greater than the baseFee (post london)
	// 确保交易的 gasFeeCap 大于基础费用（伦敦硬分叉后）
	if st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Skip the checks if gas fields are zero and baseFee was explicitly disabled (eth_call)
		// 如果 gas 字段为零且基础费用被显式禁用（eth_call），跳过检查
		skipCheck := st.evm.Config.NoBaseFee && msg.GasFeeCap.BitLen() == 0 && msg.GasTipCap.BitLen() == 0
		if !skipCheck {
			if l := msg.GasFeeCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxFeePerGas bit length: %d", ErrFeeCapVeryHigh,
					msg.From.Hex(), l)
				// 如果 gasFeeCap 过高，返回错误
			}
			if l := msg.GasTipCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas bit length: %d", ErrTipVeryHigh,
					msg.From.Hex(), l)
				// 如果 gasTipCap 过高，返回错误
			}
			if msg.GasFeeCap.Cmp(msg.GasTipCap) < 0 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas: %s, maxFeePerGas: %s", ErrTipAboveFeeCap,
					msg.From.Hex(), msg.GasTipCap, msg.GasFeeCap)
				// 如果 gasTipCap 超过 gasFeeCap，返回错误
			}
			// This will panic if baseFee is nil, but basefee presence is verified
			// as part of header validation.
			// 如果 baseFee 为 nil 会引发 panic，但 baseFee 的存在已在头部验证中确认。
			if msg.GasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
				return fmt.Errorf("%w: address %v, maxFeePerGas: %s, baseFee: %s", ErrFeeCapTooLow,
					msg.From.Hex(), msg.GasFeeCap, st.evm.Context.BaseFee)
				// 如果 gasFeeCap 低于基础费用，返回错误
			}
		}
	}
	// Check the blob version validity
	// 检查 blob 版本的有效性
	if msg.BlobHashes != nil {
		// The to field of a blob tx type is mandatory, and a `BlobTx` transaction internally
		// has it as a non-nillable value, so any msg derived from blob transaction has it non-nil.
		// However, messages created through RPC (eth_call) don't have this restriction.
		// Blob 交易类型的 to 字段是必需的，`BlobTx` 交易内部将其作为非空值，因此从 blob 交易派生的任何消息都有非空值。
		// 但是，通过 RPC（eth_call）创建的消息没有此限制。
		if msg.To == nil {
			return ErrBlobTxCreate // 如果没有接收者，返回错误
		}
		if len(msg.BlobHashes) == 0 {
			return ErrMissingBlobHashes // 如果缺少 blob 哈希，返回错误
		}
		for i, hash := range msg.BlobHashes {
			if !kzg4844.IsValidVersionedHash(hash[:]) {
				return fmt.Errorf("blob %d has invalid hash version", i)
				// 如果 blob 哈希版本无效，返回错误
			}
		}
	}
	// Check that the user is paying at least the current blob fee
	// 检查用户支付的 blob 费用是否至少达到当前 blob 费用
	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time) {
		if st.blobGasUsed() > 0 {
			// Skip the checks if gas fields are zero and blobBaseFee was explicitly disabled (eth_call)
			// 如果 gas 字段为零且 blobBaseFee 被显式禁用（eth_call），跳过检查
			skipCheck := st.evm.Config.NoBaseFee && msg.BlobGasFeeCap.BitLen() == 0
			if !skipCheck {
				// This will panic if blobBaseFee is nil, but blobBaseFee presence
				// is verified as part of header validation.
				// 如果 blobBaseFee 为 nil 会引发 panic，但 blobBaseFee 的存在已在头部验证中确认。
				if msg.BlobGasFeeCap.Cmp(st.evm.Context.BlobBaseFee) < 0 {
					return fmt.Errorf("%w: address %v blobGasFeeCap: %v, blobBaseFee: %v", ErrBlobFeeCapTooLow,
						msg.From.Hex(), msg.BlobGasFeeCap, st.evm.Context.BlobBaseFee)
					// 如果 blobGasFeeCap 低于 blobBaseFee，返回错误
				}
			}
		}
	}
	// Check that EIP-7702 authorization list signatures are well formed.
	// 检查 EIP-7702 授权列表签名是否格式正确。
	if msg.SetCodeAuthorizations != nil {
		if msg.To == nil {
			return fmt.Errorf("%w (sender %v)", ErrSetCodeTxCreate, msg.From)
			// 如果没有接收者，返回错误
		}
		if len(msg.SetCodeAuthorizations) == 0 {
			return fmt.Errorf("%w (sender %v)", ErrEmptyAuthList, msg.From)
			// 如果授权列表为空，返回错误
		}
	}
	return st.buyGas() // 执行 Gas 购买
}

// execute will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
//   - used gas: total gas used (including gas being refunded)
//   - returndata: the returned data from evm
//   - concrete execution error: various EVM errors which abort the execution, e.g.
//     ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
// execute 将通过应用当前消息转换状态，并返回带有以下字段的 EVM 执行结果。
//
//   - used gas: 已使用的总 gas（包括被退还的 gas）
//   - returndata: 从 EVM 返回的数据
//   - concrete execution error: 各种中止执行的 EVM 错误，例如 ErrOutOfGas, ErrExecutionReverted
//
// 但是，如果遇到任何共识问题，直接返回错误并带有 nil 的 EVM 执行结果。
func (st *stateTransition) execute() (*ExecutionResult, error) {
	// First check this message satisfies all consensus rules before
	// applying the message. The rules include these clauses
	//
	// 1. the nonce of the message caller is correct
	// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
	// 3. the amount of gas required is available in the block
	// 4. the purchased gas is enough to cover intrinsic usage
	// 5. there is no overflow when calculating intrinsic gas
	// 6. caller has enough balance to cover asset transfer for **topmost** call
	//
	// 在应用消息之前，首先检查该消息是否满足所有共识规则。这些规则包括以下条款：
	//
	// 1. 消息调用者的 nonce 正确
	// 2. 调用者有足够的余额支付交易费用（gaslimit * gasprice）
	// 3. 区块中有足够的 gas 可用
	// 4. 购买的 gas 足以覆盖内在使用
	// 5. 计算内在 gas 时没有溢出
	// 6. 调用者有足够的余额覆盖最顶层调用的资产转移

	// Check clauses 1-3, buy gas if everything is correct
	// 检查条款 1-3，如果一切正确则购买 gas
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	var (
		msg              = st.msg
		sender           = vm.AccountRef(msg.From)                                                                                   // 发送者账户引用
		rules            = st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time) // 链规则
		contractCreation = msg.To == nil                                                                                             // 是否为合约创建
	)

	// Check clauses 4-5, subtract intrinsic gas if everything is correct
	// 检查条款 4-5，如果一切正确则减去内在 gas
	gas, err := IntrinsicGas(msg.Data, msg.AccessList, msg.SetCodeAuthorizations, contractCreation, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai)
	if err != nil {
		return nil, err
	}
	if st.gasRemaining < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gasRemaining, gas)
		// 如果剩余 gas 不足以支付内在 gas，返回错误
	}
	if t := st.evm.Config.Tracer; t != nil && t.OnGasChange != nil {
		t.OnGasChange(st.gasRemaining, st.gasRemaining-gas, tracing.GasChangeTxIntrinsicGas)
		// 如果启用了追踪器，记录 Gas 变化
	}
	st.gasRemaining -= gas // 减去内在 gas

	if rules.IsEIP4762 {
		st.evm.AccessEvents.AddTxOrigin(msg.From) // 添加交易发起者到访问事件

		if targetAddr := msg.To; targetAddr != nil {
			st.evm.AccessEvents.AddTxDestination(*targetAddr, msg.Value.Sign() != 0) // 添加目标地址到访问事件
		}
	}

	// Check clause 6
	// 检查条款 6
	value, overflow := uint256.FromBig(msg.Value)
	if overflow {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
		// 如果价值溢出，返回错误
	}
	if !value.IsZero() && !st.evm.Context.CanTransfer(st.state, msg.From, value) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
		// 如果余额不足以转移价值，返回错误
	}

	// Check whether the init code size has been exceeded.
	// 检查初始化代码大小是否超过限制。
	if rules.IsShanghai && contractCreation && len(msg.Data) > params.MaxInitCodeSize {
		return nil, fmt.Errorf("%w: code size %v limit %v", ErrMaxInitCodeSizeExceeded, len(msg.Data), params.MaxInitCodeSize)
		// 如果超过最大初始化代码大小，返回错误
	}

	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	// 执行状态转换的准备步骤，包括：
	// - 准备访问列表（柏林硬分叉后）
	// - 重置临时存储（EIP-1153）
	st.state.Prepare(rules, msg.From, st.evm.Context.Coinbase, msg.To, vm.ActivePrecompiles(rules), msg.AccessList)

	var (
		ret   []byte // 返回数据
		vmerr error  // vm errors do not effect consensus and are therefore not assigned to err 错误不会影响共识，因此不赋值给 err
	)
	if contractCreation {
		ret, _, st.gasRemaining, vmerr = st.evm.Create(sender, msg.Data, st.gasRemaining, value) // 创建合约
	} else {
		// Increment the nonce for the next transaction.
		// 为下一笔交易递增 nonce。
		st.state.SetNonce(msg.From, st.state.GetNonce(msg.From)+1)

		// Apply EIP-7702 authorizations.
		// 应用 EIP-7702 授权。
		if msg.SetCodeAuthorizations != nil {
			for _, auth := range msg.SetCodeAuthorizations {
				// Note errors are ignored, we simply skip invalid authorizations here.
				// 注意错误被忽略，我们在这里简单跳过无效授权。
				st.applyAuthorization(&auth)
			}
		}

		// Perform convenience warming of sender's delegation target. Although the
		// sender is already warmed in Prepare(..), it's possible a delegation to
		// the account was deployed during this transaction. To handle correctly,
		// simply wait until the final state of delegations is determined before
		// performing the resolution and warming.
		// 执行发送者委托目标的便利预热。尽管发送者已在 Prepare(..) 中预热，但在此交易期间可能部署了对账户的委托。
		// 为正确处理，简单等到委托的最终状态确定后再执行解析和预热。
		if addr, ok := types.ParseDelegation(st.state.GetCode(*msg.To)); ok {
			st.state.AddAddressToAccessList(addr) // 添加委托地址到访问列表
		}

		// Execute the transaction's call.
		// 执行交易的调用。
		ret, st.gasRemaining, vmerr = st.evm.Call(sender, st.to(), msg.Data, st.gasRemaining, value)
	}

	var gasRefund uint64
	if !rules.IsLondon {
		// Before EIP-3529: refunds were capped to gasUsed / 2
		// 在 EIP-3529 之前：退款上限为 gasUsed / 2
		gasRefund = st.refundGas(params.RefundQuotient)
	} else {
		// After EIP-3529: refunds are capped to gasUsed / 5
		// 在 EIP-3529 之后：退款上限为 gasUsed / 5
		gasRefund = st.refundGas(params.RefundQuotientEIP3529)
	}
	effectiveTip := msg.GasPrice // 有效小费
	if rules.IsLondon {
		effectiveTip = new(big.Int).Sub(msg.GasFeeCap, st.evm.Context.BaseFee) // 伦敦硬分叉后计算有效小费
		if effectiveTip.Cmp(msg.GasTipCap) > 0 {
			effectiveTip = msg.GasTipCap // 如果超过小费上限，使用上限
		}
	}
	effectiveTipU256, _ := uint256.FromBig(effectiveTip)

	if st.evm.Config.NoBaseFee && msg.GasFeeCap.Sign() == 0 && msg.GasTipCap.Sign() == 0 {
		// Skip fee payment when NoBaseFee is set and the fee fields
		// are 0. This avoids a negative effectiveTip being applied to
		// the coinbase when simulating calls.
		// 当 NoBaseFee 设置且费用字段为 0 时，跳过费用支付。这避免在模拟调用时将负有效小费应用于 coinbase。
	} else {
		fee := new(uint256.Int).SetUint64(st.gasUsed())
		fee.Mul(fee, effectiveTipU256)                                                                 // 计算交易费用
		st.state.AddBalance(st.evm.Context.Coinbase, fee, tracing.BalanceIncreaseRewardTransactionFee) // 将费用添加到 coinbase

		// add the coinbase to the witness iff the fee is greater than 0
		// 如果费用大于 0，则将 coinbase 添加到见证中
		if rules.IsEIP4762 && fee.Sign() != 0 {
			st.evm.AccessEvents.AddAccount(st.evm.Context.Coinbase, true)
		}
	}

	return &ExecutionResult{
		UsedGas:     st.gasUsed(), // 已使用的 Gas
		RefundedGas: gasRefund,    // 退还的 Gas
		Err:         vmerr,        // 执行错误
		ReturnData:  ret,          // 返回数据
	}, nil
}

// validateAuthorization validates an EIP-7702 authorization against the state.
// validateAuthorization 根据状态验证 EIP-7702 授权。
func (st *stateTransition) validateAuthorization(auth *types.SetCodeAuthorization) (authority common.Address, err error) {
	// Verify chain ID is null or equal to current chain ID.
	// 验证链 ID 为 null 或等于当前链 ID。
	if !auth.ChainID.IsZero() && auth.ChainID.CmpBig(st.evm.ChainConfig().ChainID) != 0 {
		return authority, ErrAuthorizationWrongChainID // 如果链 ID 不匹配，返回错误
	}
	// Limit nonce to 2^64-1 per EIP-2681.
	// 根据 EIP-2681 将 nonce 限制为 2^64-1。
	if auth.Nonce+1 < auth.Nonce {
		return authority, ErrAuthorizationNonceOverflow // 如果 nonce 溢出，返回错误
	}
	// Validate signature values and recover authority.
	// 验证签名值并恢复授权者。
	authority, err = auth.Authority()
	if err != nil {
		return authority, fmt.Errorf("%w: %v", ErrAuthorizationInvalidSignature, err)
		// 如果签名无效，返回错误
	}
	// Check the authority account
	//  1) doesn't have code or has exisiting delegation
	//  2) matches the auth's nonce
	//
	// Note it is added to the access list even if the authorization is invalid.
	// 检查授权账户：
	//  1) 没有代码或具有现有委托
	//  2) 与授权的 nonce 匹配
	//
	// 注意，即使授权无效，也会将其添加到访问列表。
	st.state.AddAddressToAccessList(authority)
	code := st.state.GetCode(authority)
	if _, ok := types.ParseDelegation(code); len(code) != 0 && !ok {
		return authority, ErrAuthorizationDestinationHasCode // 如果目标有代码且不是委托，返回错误
	}
	if have := st.state.GetNonce(authority); have != auth.Nonce {
		return authority, ErrAuthorizationNonceMismatch // 如果 nonce 不匹配，返回错误
	}
	return authority, nil
}

// applyAuthorization applies an EIP-7702 code delegation to the state.
// applyAuthorization 将 EIP-7702 代码委托应用于状态。
func (st *stateTransition) applyAuthorization(auth *types.SetCodeAuthorization) error {
	authority, err := st.validateAuthorization(auth)
	if err != nil {
		return err // 如果验证失败，返回错误
	}

	// If the account already exists in state, refund the new account cost
	// charged in the intrinsic calculation.
	// 如果账户已存在于状态中，退还内在计算中收取的新账户成本。
	if st.state.Exist(authority) {
		st.state.AddRefund(params.CallNewAccountGas - params.TxAuthTupleGas)
	}

	// Update nonce and account code.
	// 更新 nonce 和账户代码。
	st.state.SetNonce(authority, auth.Nonce+1)
	if auth.Address == (common.Address{}) {
		// Delegation to zero address means clear.
		// 委托到零地址意味着清除。
		st.state.SetCode(authority, nil)
		return nil
	}

	// Otherwise install delegation to auth.Address.
	// 否则将委托安装到 auth.Address。
	st.state.SetCode(authority, types.AddressToDelegation(auth.Address))

	return nil
}

func (st *stateTransition) refundGas(refundQuotient uint64) uint64 {
	// Apply refund counter, capped to a refund quotient
	// 应用退款计数器，上限为退款商数
	refund := st.gasUsed() / refundQuotient
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund() // 如果退款超过状态中的退款值，使用状态值
	}

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && refund > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, st.gasRemaining+refund, tracing.GasChangeTxRefunds)
		// 如果启用了追踪器且有退款，记录 Gas 变化
	}

	st.gasRemaining += refund // 增加剩余 Gas

	// Return ETH for remaining gas, exchanged at the original rate.
	// 将剩余 Gas 按原价退还 ETH。
	remaining := uint256.NewInt(st.gasRemaining)
	remaining.Mul(remaining, uint256.MustFromBig(st.msg.GasPrice))
	st.state.AddBalance(st.msg.From, remaining, tracing.BalanceIncreaseGasReturn) // 退还余额

	if st.evm.Config.Tracer != nil && st.evm.Config.Tracer.OnGasChange != nil && st.gasRemaining > 0 {
		st.evm.Config.Tracer.OnGasChange(st.gasRemaining, 0, tracing.GasChangeTxLeftOverReturned)
		// 如果启用了追踪器且剩余 Gas 大于 0，记录 Gas 变化
	}

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	// 还将剩余 Gas 返回到区块 Gas 计数器，以便下一笔交易使用。
	st.gp.AddGas(st.gasRemaining)

	return refund // 返回退还的 Gas 量
}

// gasUsed returns the amount of gas used up by the state transition.
// gasUsed 返回状态转换使用的 Gas 量。
func (st *stateTransition) gasUsed() uint64 {
	return st.initialGas - st.gasRemaining // 初始 Gas 减去剩余 Gas
}

// blobGasUsed returns the amount of blob gas used by the message.
// blobGasUsed 返回消息使用的 Blob Gas 量。
func (st *stateTransition) blobGasUsed() uint64 {
	return uint64(len(st.msg.BlobHashes) * params.BlobTxBlobGasPerBlob) // Blob 哈希数量乘以每个 Blob 的 Gas
}
