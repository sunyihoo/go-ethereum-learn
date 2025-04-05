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

package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi/override"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

const (
	// maxSimulateBlocks is the maximum number of blocks that can be simulated
	// in a single request.
	// maxSimulateBlocks 是单个请求中可以模拟的最大区块数。
	maxSimulateBlocks = 256

	// timestampIncrement is the default increment between block timestamps.
	// timestampIncrement 是区块时间戳之间的默认增量（以秒为单位）。
	timestampIncrement = 12
)

// simBlock is a batch of calls to be simulated sequentially.
// simBlock 是一批按顺序模拟的调用。
type simBlock struct {
	BlockOverrides *override.BlockOverrides // Block header fields to override. 要覆盖的区块头字段。
	StateOverrides *override.StateOverride  // State overrides to apply before the block. 在区块执行前应用的状态覆盖。
	Calls          []TransactionArgs        // Transactions to execute in this block. 在此区块中执行的交易列表。
}

// simCallResult is the result of a simulated call.
// simCallResult 是模拟调用的结果。
type simCallResult struct {
	ReturnValue hexutil.Bytes  `json:"returnData"`      // Return value of the call. 调用的返回值。
	Logs        []*types.Log   `json:"logs"`            // Logs emitted during the call. 调用期间发出的日志。
	GasUsed     hexutil.Uint64 `json:"gasUsed"`         // Gas used by the call. 调用使用的 Gas 量。
	Status      hexutil.Uint64 `json:"status"`          // Status of the call (1 for success, 0 for failure). 调用状态（1 表示成功，0 表示失败）。
	Error       *callError     `json:"error,omitempty"` // Error information if the call failed. 如果调用失败，则包含错误信息。
}

func (r *simCallResult) MarshalJSON() ([]byte, error) {
	type callResultAlias simCallResult
	// Marshal logs to be an empty array instead of nil when empty
	// 当日志为空时，将其序列化为空数组而不是 nil。
	if r.Logs == nil {
		r.Logs = []*types.Log{}
	}
	return json.Marshal((*callResultAlias)(r))
}

// simOpts are the inputs to eth_simulateV1.
// simOpts 是 eth_simulateV1 的输入参数。
type simOpts struct {
	BlockStateCalls        []simBlock // List of blocks to simulate. 要模拟的区块列表。
	TraceTransfers         bool       // Whether to trace value transfers. 是否跟踪价值转移。
	Validation             bool       // Whether to run EVM in validation mode (e.g., check nonce). 是否在验证模式下运行 EVM（例如，检查 Nonce）。
	ReturnFullTransactions bool       // Whether to return full transaction objects in the result. 是否在结果中返回完整的交易对象。
}

// simulator is a stateful object that simulates a series of blocks.
// it is not safe for concurrent use.
// simulator 是一个有状态的对象，用于模拟一系列区块。它不是并发安全的。
type simulator struct {
	b              Backend             // Backend to interact with the blockchain. 用于与区块链交互的后端。
	state          *state.StateDB      // State database for the simulation. 模拟的状态数据库。
	base           *types.Header       // Header of the base block for the simulation. 模拟的基础区块头。
	chainConfig    *params.ChainConfig // Chain configuration. 链配置。
	gp             *core.GasPool       // Gas pool for the simulation. 模拟的 Gas 池。
	traceTransfers bool                // Whether to trace value transfers. 是否跟踪价值转移。
	validate       bool                // Whether to run EVM in validation mode. 是否在验证模式下运行 EVM。
	fullTx         bool                // Whether to return full transaction objects. 是否返回完整的交易对象。
}

// execute runs the simulation of a series of blocks.
// execute 方法运行一系列区块的模拟。
func (sim *simulator) execute(ctx context.Context, blocks []simBlock) ([]map[string]interface{}, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var (
		cancel  context.CancelFunc
		timeout = sim.b.RPCEVMTimeout() // Get the global timeout for eth_call over RPC. 获取通过 RPC 进行 eth_call 的全局超时时间。
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout) // Apply timeout to the context if it's set. 如果设置了超时时间，则将其应用于上下文。
	} else {
		ctx, cancel = context.WithCancel(ctx) // Create a cancellable context if no timeout is set. 如果未设置超时时间，则创建一个可取消的上下文。
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	// 确保在调用完成后取消上下文，以清理资源。
	defer cancel()

	var err error
	blocks, err = sim.sanitizeChain(blocks) // Sanitize the chain of blocks to ensure consistency. 对区块链进行清理以确保一致性。
	if err != nil {
		return nil, err
	}
	// Prepare block headers with preliminary fields for the response.
	// 为响应准备包含初步字段的区块头。
	headers, err := sim.makeHeaders(blocks)
	if err != nil {
		return nil, err
	}
	var (
		results = make([]map[string]interface{}, len(blocks)) // Slice to store the simulation results for each block. 用于存储每个区块的模拟结果的切片。
		parent  = sim.base                                    // The parent header, initially the base header. 父区块头，初始为基础区块头。
	)
	// Iterate through each block to be simulated. 遍历要模拟的每个区块。
	for bi, block := range blocks {
		// Process the current block, simulating its execution. 处理当前区块，模拟其执行。
		result, callResults, err := sim.processBlock(ctx, &block, headers[bi], parent, headers[:bi], timeout)
		if err != nil {
			return nil, err
		}
		// Encode the block result to RPC format. 将区块结果编码为 RPC 格式。
		enc := RPCMarshalBlock(result, true, sim.fullTx, sim.chainConfig)
		enc["calls"] = callResults // Add the results of the simulated calls to the encoded block. 将模拟调用的结果添加到编码后的区块中。
		results[bi] = enc

		parent = headers[bi] // Set the current header as the parent for the next block. 将当前区块头设置为下一个区块的父区块头。
	}
	return results, nil
}

func (sim *simulator) processBlock(ctx context.Context, block *simBlock, header, parent *types.Header, headers []*types.Header, timeout time.Duration) (*types.Block, []simCallResult, error) {
	// Set header fields that depend only on parent block.
	// Parent hash is needed for evm.GetHashFn to work.
	// 设置仅依赖于父区块的区块头字段。EVM 的 GetHashFn 需要父哈希。
	header.ParentHash = parent.Hash()
	// Handle base fee calculation if London fork is active.
	// 如果伦敦分叉已激活，则处理基础费用计算。伦敦分叉引入了 EIP-1559。
	if sim.chainConfig.IsLondon(header.Number) {
		// In non-validation mode base fee is set to 0 if it is not overridden.
		// This is because it creates an edge case in EVM where gasPrice < baseFee.
		// Base fee could have been overridden.
		// 在非验证模式下，如果未覆盖，则基础费用设置为 0。
		// 这是因为在 EVM 中创建了一个 gasPrice < baseFee 的极端情况。
		// 基础费用可能已被覆盖。
		if header.BaseFee == nil {
			if sim.validate {
				header.BaseFee = eip1559.CalcBaseFee(sim.chainConfig, parent) // Calculate base fee according to EIP-1559. 根据 EIP-1559 计算基础费用。
			} else {
				header.BaseFee = big.NewInt(0)
			}
		}
	}
	// Handle excess blob gas calculation if Cancun fork is active.
	// 如果 Cancun 分叉已激活，则处理过量的 Blob Gas 计算。Cancun 分叉引入了 EIP-4844。
	if sim.chainConfig.IsCancun(header.Number, header.Time) {
		var excess uint64
		if sim.chainConfig.IsCancun(parent.Number, parent.Time) {
			excess = eip4844.CalcExcessBlobGas(*parent.ExcessBlobGas, *parent.BlobGasUsed) // Calculate excess blob gas based on parent block. 根据父区块计算过量的 Blob Gas。
		} else {
			excess = eip4844.CalcExcessBlobGas(0, 0)
		}
		header.ExcessBlobGas = &excess
	}
	// Create EVM block context. 创建 EVM 区块上下文。
	blockContext := core.NewEVMBlockContext(header, sim.newSimulatedChainContext(ctx, headers), nil)
	// Apply blob base fee override if provided. 如果提供了 Blob 基础费用覆盖，则应用它。
	if block.BlockOverrides.BlobBaseFee != nil {
		blockContext.BlobBaseFee = block.BlockOverrides.BlobBaseFee.ToInt()
	}
	// Get active precompiled contracts for the base block. 获取基础区块的活动预编译合约。
	precompiles := sim.activePrecompiles(sim.base)
	// State overrides are applied prior to execution of a block
	// 在执行区块之前应用状态覆盖。状态覆盖允许在模拟中修改特定的账户状态。
	if err := block.StateOverrides.Apply(sim.state, precompiles); err != nil {
		return nil, nil, err
	}
	var (
		gasUsed, blobGasUsed uint64
		txes                 = make([]*types.Transaction, len(block.Calls)) // Slice to store the transactions of the block. 用于存储区块交易的切片。
		callResults          = make([]simCallResult, len(block.Calls))      // Slice to store the results of the simulated calls. 用于存储模拟调用结果的切片。
		receipts             = make([]*types.Receipt, len(block.Calls))     // Slice to store the receipts of the simulated calls. 用于存储模拟调用收据的切片。
		// Block hash will be repaired after execution.
		// 区块哈希将在执行后修复。在模拟执行期间，区块哈希通常是未知的，直到所有交易都处理完毕。
		tracer   = newTracer(sim.traceTransfers, blockContext.BlockNumber.Uint64(), common.Hash{}, common.Hash{}, 0) // Create a tracer for transaction execution. 为交易执行创建一个跟踪器。
		vmConfig = &vm.Config{
			NoBaseFee: !sim.validate,  // Disable base fee check if not in validation mode. 如果不在验证模式下，则禁用基础费用检查。
			Tracer:    tracer.Hooks(), // Attach the tracer hooks to the VM configuration. 将跟踪器钩子附加到 VM 配置。
		}
	)
	// Create a state database with tracing hooks if tracing is enabled.
	// 如果启用了跟踪，则创建一个带有跟踪钩子的状态数据库。
	tracingStateDB := vm.StateDB(sim.state)
	if hooks := tracer.Hooks(); hooks != nil {
		tracingStateDB = state.NewHookedState(sim.state, hooks)
	}
	// Create a new EVM instance for the block execution. 为区块执行创建一个新的 EVM 实例。
	evm := vm.NewEVM(blockContext, tracingStateDB, sim.chainConfig, *vmConfig)
	// It is possible to override precompiles with EVM bytecode, or
	// move them to another address.
	// 可以使用 EVM 字节码覆盖预编译合约，或将其移动到另一个地址。
	if precompiles != nil {
		evm.SetPrecompiles(precompiles)
	}
	// Iterate through each call (transaction) in the block. 遍历区块中的每个调用（交易）。
	for i, call := range block.Calls {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// Sanitize the call arguments, setting default values for nonce and gas.
		// 清理调用参数，为 Nonce 和 Gas 设置默认值。
		if err := sim.sanitizeCall(&call, sim.state, header, blockContext, &gasUsed); err != nil {
			return nil, nil, err
		}
		// Convert the TransactionArgs to a types.Transaction. 将 TransactionArgs 转换为 types.Transaction。
		tx := call.ToTransaction(types.DynamicFeeTxType)
		txes[i] = tx
		tracer.reset(tx.Hash(), uint(i)) // Reset the tracer for the current transaction. 为当前交易重置跟踪器。
		// EoA check is always skipped, even in validation mode.
		// 即使在验证模式下，也始终跳过外部账户 (EOA) 检查。在模拟环境中，通常不需要严格的签名者验证。
		msg := call.ToMessage(header.BaseFee, !sim.validate, true)
		// Apply the message (simulate the transaction execution). 应用消息（模拟交易执行）。
		result, err := applyMessageWithEVM(ctx, evm, msg, timeout, sim.gp)
		if err != nil {
			txErr := txValidationError(err)
			return nil, nil, txErr
		}
		// Update the state with pending changes.
		// 使用待处理的更改更新状态。
		var root []byte
		if sim.chainConfig.IsByzantium(blockContext.BlockNumber) {
			tracingStateDB.Finalise(true) // Finalize the state for Byzantium fork. 为拜占庭分叉最终确定状态。
		} else {
			root = sim.state.IntermediateRoot(sim.chainConfig.IsEIP158(blockContext.BlockNumber)).Bytes() // Get the intermediate state root. 获取中间状态根。
		}
		gasUsed += result.UsedGas // Accumulate the gas used by the transaction. 累积交易使用的 Gas 量。
		// Create a receipt for the transaction. 为交易创建一个收据。
		receipts[i] = core.MakeReceipt(evm, result, sim.state, blockContext.BlockNumber, common.Hash{}, tx, gasUsed, root)
		blobGasUsed += receipts[i].BlobGasUsed // Accumulate the blob gas used by the transaction. 累积交易使用的 Blob Gas 量。
		logs := tracer.Logs()                  // Get the logs emitted by the transaction. 获取交易发出的日志。
		callRes := simCallResult{ReturnValue: result.Return(), Logs: logs, GasUsed: hexutil.Uint64(result.UsedGas)}
		if result.Failed() {
			callRes.Status = hexutil.Uint64(types.ReceiptStatusFailed) // Set status to failed if the call resulted in an error. 如果调用导致错误，则将状态设置为失败。
			if errors.Is(result.Err, vm.ErrExecutionReverted) {
				// If the result contains a revert reason, try to unpack it.
				// 如果结果包含回滚原因，则尝试解包它。
				revertErr := newRevertError(result.Revert())
				callRes.Error = &callError{Message: revertErr.Error(), Code: errCodeReverted, Data: revertErr.ErrorData().(string)}
			} else {
				callRes.Error = &callError{Message: result.Err.Error(), Code: errCodeVMError}
			}
		} else {
			callRes.Status = hexutil.Uint64(types.ReceiptStatusSuccessful) // Set status to successful if the call executed without errors. 如果调用执行没有错误，则将状态设置为成功。
		}
		callResults[i] = callRes
	}
	// Set the final state root of the block. 设置区块的最终状态根。
	header.Root = sim.state.IntermediateRoot(true)
	header.GasUsed = gasUsed // Set the total gas used by all transactions in the block. 设置区块中所有交易使用的总 Gas 量。
	// Set the total blob gas used by all transactions in the block if Cancun is active.
	// 如果 Cancun 已激活，则设置区块中所有交易使用的总 Blob Gas 量。
	if sim.chainConfig.IsCancun(header.Number, header.Time) {
		header.BlobGasUsed = &blobGasUsed
	}
	var withdrawals types.Withdrawals
	// Initialize withdrawals if Shanghai fork is active. 上海分叉引入了提款功能 (EIP-4895)。
	if sim.chainConfig.IsShanghai(header.Number, header.Time) {
		withdrawals = make([]*types.Withdrawal, 0)
	}
	// Create the new block with the header, body (transactions and withdrawals), and receipts.
	// 使用区块头、主体（交易和提款）和收据创建新的区块。
	b := types.NewBlock(header, &types.Body{Transactions: txes, Withdrawals: withdrawals}, receipts, trie.NewStackTrie(nil))
	// Repair the block hash in the logs of the simulated calls.
	// 修复模拟调用日志中的区块哈希。
	repairLogs(callResults, b.Hash())
	return b, callResults, nil
}

// repairLogs updates the block hash in the logs present in the result of
// a simulated block. This is needed as during execution when logs are collected
// the block hash is not known.
// repairLogs 方法更新模拟区块结果中日志的区块哈希。
// 这是必需的，因为在执行期间收集日志时，区块哈希是未知的。
func repairLogs(calls []simCallResult, hash common.Hash) {
	for i := range calls {
		for j := range calls[i].Logs {
			calls[i].Logs[j].BlockHash = hash // Set the block hash for each log entry. 为每个日志条目设置区块哈希。
		}
	}
}

func (sim *simulator) sanitizeCall(call *TransactionArgs, state vm.StateDB, header *types.Header, blockContext vm.BlockContext, gasUsed *uint64) error {
	// If nonce is not set, fetch it from the current state.
	// 如果未设置 Nonce，则从当前状态获取它。Nonce 是发送者账户的交易计数器。
	if call.Nonce == nil {
		nonce := state.GetNonce(call.from())
		call.Nonce = (*hexutil.Uint64)(&nonce)
	}
	// Let the call run wild unless explicitly specified.
	// 除非明确指定，否则允许调用消耗剩余的所有 Gas。
	if call.Gas == nil {
		remaining := blockContext.GasLimit - *gasUsed
		call.Gas = (*hexutil.Uint64)(&remaining)
	}
	// Ensure that the total gas used so far plus the gas requested by the current call
	// does not exceed the block gas limit.
	// 确保到目前为止使用的总 Gas 加上当前调用请求的 Gas 不超过区块 Gas 限制。
	if *gasUsed+uint64(*call.Gas) > blockContext.GasLimit {
		return &blockGasLimitReachedError{fmt.Sprintf("block gas limit reached: %d >= %d", gasUsed, blockContext.GasLimit)}
	}
	// Apply default values for the call arguments.
	// 为调用参数应用默认值。这包括处理 Gas 价格和费用上限。
	if err := call.CallDefaults(sim.gp.Gas(), header.BaseFee, sim.chainConfig.ChainID); err != nil {
		return err
	}
	return nil
}

func (sim *simulator) activePrecompiles(base *types.Header) vm.PrecompiledContracts {
	var (
		isMerge = (base.Difficulty.Sign() == 0)                          // Check if the block is post-Merge (using difficulty as an indicator). 检查区块是否为合并后区块（使用难度作为指标）。
		rules   = sim.chainConfig.Rules(base.Number, isMerge, base.Time) // Get the chain rules for the given block number and time. 获取给定区块号和时间的链规则。
	)
	return vm.ActivePrecompiledContracts(rules) // Get the active precompiled contracts based on the chain rules. 根据链规则获取活动的预编译合约。
}

// sanitizeChain checks the chain integrity. Specifically it checks that
// block numbers and timestamp are strictly increasing, setting default values
// when necessary. Gaps in block numbers are filled with empty blocks.
// Note: It modifies the block's override object.
// sanitizeChain 方法检查链的完整性。具体来说，它检查区块号和时间戳是否严格递增，并在必要时设置默认值。
// 区块号之间的间隙用空区块填充。注意：它会修改区块的覆盖对象。
func (sim *simulator) sanitizeChain(blocks []simBlock) ([]simBlock, error) {
	var (
		res           = make([]simBlock, 0, len(blocks)) // Slice to store the sanitized blocks. 用于存储清理后的区块的切片。
		base          = sim.base                         // The base block header. 基础区块头。
		prevNumber    = base.Number                      // The number of the previous block, initialized with the base block number. 前一个区块的编号，初始化为基础区块的编号。
		prevTimestamp = base.Time                        // The timestamp of the previous block, initialized with the base block timestamp. 前一个区块的时间戳，初始化为基础区块的时间戳。
	)
	// Iterate through each block to be simulated. 遍历要模拟的每个区块。
	for _, block := range blocks {
		// Initialize BlockOverrides if it's nil. 如果 BlockOverrides 为 nil，则初始化它。
		if block.BlockOverrides == nil {
			block.BlockOverrides = new(override.BlockOverrides)
		}
		// If block number is not overridden, increment the previous block number.
		// 如果未覆盖区块号，则将前一个区块号递增。
		if block.BlockOverrides.Number == nil {
			n := new(big.Int).Add(prevNumber, big.NewInt(1))
			block.BlockOverrides.Number = (*hexutil.Big)(n)
		}
		// Check if the block number is strictly increasing.
		// 检查区块号是否严格递增。
		diff := new(big.Int).Sub(block.BlockOverrides.Number.ToInt(), prevNumber)
		if diff.Cmp(common.Big0) <= 0 {
			return nil, &invalidBlockNumberError{fmt.Sprintf("block numbers must be in order: %d <= %d", block.BlockOverrides.Number.ToInt().Uint64(), prevNumber)}
		}
		// Check if the number of simulated blocks exceeds the limit.
		// 检查模拟的区块数是否超过限制。
		if total := new(big.Int).Sub(block.BlockOverrides.Number.ToInt(), base.Number); total.Cmp(big.NewInt(maxSimulateBlocks)) > 0 {
			return nil, &clientLimitExceededError{message: "too many blocks"}
		}
		// If there's a gap in block numbers, fill it with empty blocks.
		// 如果区块号之间存在间隙，则用空区块填充它。
		if diff.Cmp(big.NewInt(1)) > 0 {
			gap := new(big.Int).Sub(diff, big.NewInt(1))
			// Assign block number to the empty blocks.
			for i := uint64(0); i < gap.Uint64(); i++ {
				n := new(big.Int).Add(prevNumber, big.NewInt(int64(i+1)))
				t := prevTimestamp + timestampIncrement
				b := simBlock{BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(n), Time: (*hexutil.Uint64)(&t)}}
				prevTimestamp = t
				res = append(res, b)
			}
		}
		// Only append block after filling a potential gap.
		// 仅在填充潜在的间隙后才附加区块。
		prevNumber = block.BlockOverrides.Number.ToInt()
		var t uint64
		// If timestamp is not overridden, increment the previous timestamp.
		// 如果未覆盖时间戳，则将前一个时间戳递增。
		if block.BlockOverrides.Time == nil {
			t = prevTimestamp + timestampIncrement
			block.BlockOverrides.Time = (*hexutil.Uint64)(&t)
		} else {
			t = uint64(*block.BlockOverrides.Time)
			// Check if the timestamp is strictly increasing.
			// 检查时间戳是否严格递增。
			if t <= prevTimestamp {
				return nil, &invalidBlockTimestampError{fmt.Sprintf("block timestamps must be in order: %d <= %d", t, prevTimestamp)}
			}
		}
		prevTimestamp = t
		res = append(res, block)
	}
	return res, nil
}

// makeHeaders makes header object with preliminary fields based on a simulated block.
// Some fields have to be filled post-execution.
// It assumes blocks are in order and numbers have been validated.
// makeHeaders 方法基于模拟区块创建包含初步字段的区块头对象。
// 某些字段必须在执行后填充。它假定区块是有序的并且编号已验证。
func (sim *simulator) makeHeaders(blocks []simBlock) ([]*types.Header, error) {
	var (
		res    = make([]*types.Header, len(blocks)) // Slice to store the created headers. 用于存储创建的区块头的切片。
		base   = sim.base                           // The base block header. 基础区块头。
		header = base                               // The current header, initialized with the base header. 当前区块头，初始化为基础区块头。
	)
	// Iterate through each block to create its header. 遍历每个区块以创建其区块头。
	for bi, block := range blocks {
		// BlockOverrides should not be nil and must contain a block number.
		// BlockOverrides 不应为 nil 且必须包含区块号。
		if block.BlockOverrides == nil || block.BlockOverrides.Number == nil {
			return nil, errors.New("empty block number")
		}
		overrides := block.BlockOverrides

		var withdrawalsHash *common.Hash
		// Initialize withdrawals hash if Shanghai fork is active for this block.
		// 如果上海分叉对此区块激活，则初始化提款哈希。
		if sim.chainConfig.IsShanghai(overrides.Number.ToInt(), (uint64)(*overrides.Time)) {
			withdrawalsHash = &types.EmptyWithdrawalsHash
		}
		var parentBeaconRoot *common.Hash
		// Initialize parent beacon root if Cancun fork is active for this block.
		// 如果 Cancun 分叉对此区块激活，则初始化父信标根。
		if sim.chainConfig.IsCancun(overrides.Number.ToInt(), (uint64)(*overrides.Time)) {
			parentBeaconRoot = &common.Hash{}
		}
		// Create the header by applying the overrides to a base header.
		// 通过将覆盖应用于基础区块头来创建区块头。
		header = overrides.MakeHeader(&types.Header{
			UncleHash:        types.EmptyUncleHash,    // No uncles are expected in simulation. 模拟中不应有叔块。
			ReceiptHash:      types.EmptyReceiptsHash, // Receipt hash will be calculated after execution. 收据哈希将在执行后计算。
			TxHash:           types.EmptyTxsHash,      // Transaction hash will be calculated after execution. 交易哈希将在执行后计算。
			Coinbase:         header.Coinbase,         // Inherit coinbase address from the previous header. 从上一个区块头继承矿工地址。
			Difficulty:       header.Difficulty,       // Inherit difficulty from the previous header. 从上一个区块头继承难度。
			GasLimit:         header.GasLimit,         // Inherit gas limit from the previous header. 从上一个区块头继承 Gas 限制。
			WithdrawalsHash:  withdrawalsHash,         // Set the withdrawals hash. 设置提款哈希。
			ParentBeaconRoot: parentBeaconRoot,        // Set the parent beacon root. 设置父信标根。
		})
		res[bi] = header
	}
	return res, nil
}

func (sim *simulator) newSimulatedChainContext(ctx context.Context, headers []*types.Header) *ChainContext {
	return NewChainContext(ctx, &simBackend{base: sim.base, b: sim.b, headers: headers})
}

type simBackend struct {
	b       ChainContextBackend // The underlying backend. 底层后端。
	base    *types.Header       // The base block header. 基础区块头。
	headers []*types.Header     // The headers of the simulated blocks. 模拟区块的区块头。
}

func (b *simBackend) Engine() consensus.Engine {
	return b.b.Engine() // Return the consensus engine of the underlying backend. 返回底层后端的共识引擎。
}

func (b *simBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// If the requested number is the base block number, return the base header.
	// 如果请求的编号是基础区块编号，则返回基础区块头。
	if uint64(number) == b.base.Number.Uint64() {
		return b.base, nil
	}
	// If the requested number is less than the base block number, resolve the canonical header.
	// 如果请求的编号小于基础区块编号，则解析规范区块头。
	if uint64(number) < b.base.Number.Uint64() {
		return b.b.HeaderByNumber(ctx, number)
	}
	// If the requested number corresponds to a simulated block, return its header.
	// 如果请求的编号对应于模拟区块，则返回其区块头。
	for _, header := range b.headers {
		if header.Number.Uint64() == uint64(number) {
			return header, nil
		}
	}
	return nil, errors.New("header not found")
}
