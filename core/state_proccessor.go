// Copyright 2015 The go-ethereum Authors
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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// 状态转换: StateProcessor 的核心职责是根据以太坊的交易执行规则，将区块链的状态从一个区块的高度转换到下一个区块的高度。
// 以太坊虚拟机 (EVM): EVM 是以太坊的智能合约执行环境。StateProcessor 通过与 EVM 交互来执行交易并更新状态。
// 交易收据和日志: 交易执行后会生成收据，其中包含了交易的状态、使用的 Gas 量以及交易执行过程中产生的事件日志。这些信息对于用户和应用程序来说非常重要。
// 硬分叉: 以太坊会定期进行硬分叉，引入新的特性和协议变更。StateProcessor 需要根据当前的区块号和链配置来应用相应的硬分叉规则。
// 共识引擎: 不同的以太坊共识引擎（例如，PoW 和 PoS）在区块的最终确定和奖励机制上有所不同。StateProcessor 通过调用 chain.engine.Finalize 方法来处理这些共识引擎特定的逻辑.
// 系统调用: 在以太坊的某些硬分叉中，引入了可以通过特殊交易与预编译合约进行交互的系统调用，例如用于访问信标链信息的 EIP-4788。StateProcessor 负责处理这些系统调用。

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
// StateProcessor 是一个基本的处理器，负责将状态从一个点转换到另一个点。
//
// StateProcessor implements Processor.
// StateProcessor 实现了 Processor 接口。
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	// config 链配置选项。
	chain *HeaderChain // Canonical header chain
	// chain 规范头部链。
}

// NewStateProcessor initialises a new StateProcessor.
// NewStateProcessor 初始化一个新的 StateProcessor。
func NewStateProcessor(config *params.ChainConfig, chain *HeaderChain) *StateProcessor {
	return &StateProcessor{
		config: config,
		chain:  chain,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
// Process 通过使用 statedb 运行交易消息并向处理器（coinbase）和任何包含的叔块应用奖励，
// 根据以太坊规则处理状态更改。
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
// Process 返回在此过程中累积的收据和日志，并返回在此过程中使用的 gas 量。
// 如果任何交易由于 gas 不足而未能执行，它将返回一个错误。
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (*ProcessResult, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	// Mutate the block and state according to any hard-fork specs
	// 根据任何硬分叉规范更改区块和状态。
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context vm.BlockContext
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)

	// Apply pre-execution system calls.
	// 应用预执行系统调用。
	var tracingStateDB = vm.StateDB(statedb)
	if hooks := cfg.Tracer; hooks != nil {
		tracingStateDB = state.NewHookedState(statedb, hooks)
	}
	context = NewEVMBlockContext(header, p.chain, nil)
	evm := vm.NewEVM(context, tracingStateDB, p.config, cfg)

	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, evm)
	}
	if p.config.IsPrague(block.Number(), block.Time()) {
		ProcessParentBlockHash(block.ParentHash(), evm)
	}

	// Iterate over and process the individual transactions
	// 迭代并处理单个交易。
	for i, tx := range block.Transactions() {
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := ApplyTransactionWithEVM(msg, gp, statedb, blockNumber, blockHash, tx, usedGas, evm)
		if err != nil {
			return nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Read requests if Prague is enabled.
	// 如果 Prague 已启用，则读取请求。
	var requests [][]byte
	if p.config.IsPrague(block.Number(), block.Time()) {
		requests = [][]byte{}
		// EIP-6110
		if err := ParseDepositLogs(&requests, allLogs, p.config); err != nil {
			return nil, err
		}
		// EIP-7002
		ProcessWithdrawalQueue(&requests, evm)
		// EIP-7251
		ProcessConsolidationQueue(&requests, evm)
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	// 完成区块，应用任何共识引擎特定的额外操作（例如，区块奖励）。
	p.chain.engine.Finalize(p.chain, header, tracingStateDB, block.Body())

	return &ProcessResult{
		Receipts: receipts,
		Requests: requests,
		Logs:     allLogs,
		GasUsed:  *usedGas,
	}, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
// ApplyTransactionWithEVM 尝试将交易应用于给定的状态数据库，并使用类似于 ApplyTransaction 的输入参数作为其环境。
// 但是，此方法将已创建的 EVM 实例作为输入。
func ApplyTransactionWithEVM(msg *Message, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, err error) {
	if hooks := evm.Config.Tracer; hooks != nil {
		if hooks.OnTxStart != nil {
			hooks.OnTxStart(evm.GetVMContext(), tx, msg.From)
		}
		if hooks.OnTxEnd != nil {
			defer func() { hooks.OnTxEnd(receipt, err) }()
		}
	}
	// Apply the transaction to the current state (included in the env).
	// 将交易应用于当前状态（包含在 env 中）。
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}
	// Update the state with pending changes.
	// 使用挂起的更改更新状态。
	var root []byte
	if evm.ChainConfig().IsByzantium(blockNumber) {
		evm.StateDB.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(evm.ChainConfig().IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	return MakeReceipt(evm, result, statedb, blockNumber, blockHash, tx, *usedGas, root), nil
}

// MakeReceipt generates the receipt object for a transaction given its execution result.
// MakeReceipt 根据交易的执行结果生成收据对象。
func MakeReceipt(evm *vm.EVM, result *ExecutionResult, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas uint64, root []byte) *types.Receipt {
	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	// 为交易创建一个新的收据，存储中间根和交易使用的 gas。
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	// 如果交易创建了一个合约，则将创建地址存储在收据中。
	if tx.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Merge the tx-local access event into the "block-local" one, in order to collect
	// all values, so that the witness can be built.
	// 将交易本地的访问事件合并到“区块本地”的访问事件中，以便收集所有值，从而可以构建见证。
	if statedb.GetTrie().IsVerkle() {
		statedb.AccessEvents().Merge(evm.AccessEvents)
	}

	// Set the receipt logs and create the bloom filter.
	// 设置收据日志并创建 bloom 过滤器。
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
// ApplyTransaction 尝试将交易应用于给定的状态数据库，并使用输入参数作为其环境。
// 如果交易失败（表明区块无效），它将返回交易的收据、使用的 gas 和一个错误。
func ApplyTransaction(evm *vm.EVM, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(evm.ChainConfig(), header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	// 创建一个将在 EVM 环境中使用的新上下文。
	return ApplyTransactionWithEVM(msg, gp, statedb, header.Number, header.Hash(), tx, usedGas, evm)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
// ProcessBeaconBlockRoot 将 EIP-4788 系统调用应用于信标区块根合约。
// 此方法已导出，可在测试中使用。
func ProcessBeaconBlockRoot(beaconRoot common.Hash, evm *vm.EVM) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.BeaconRootsAddress,
		Data:      beaconRoot[:],
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(params.BeaconRootsAddress)
	_, _, _ = evm.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	evm.StateDB.Finalise(true)
}

// ProcessParentBlockHash stores the parent block hash in the history storage contract
// as per EIP-2935.
// ProcessParentBlockHash 根据 EIP-2935 将父区块哈希存储在历史存储合约中。
func ProcessParentBlockHash(prevHash common.Hash, evm *vm.EVM) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.HistoryStorageAddress,
		Data:      prevHash.Bytes(),
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(params.HistoryStorageAddress)
	_, _, _ = evm.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	evm.StateDB.Finalise(true)
}

// ProcessWithdrawalQueue calls the EIP-7002 withdrawal queue contract.
// It returns the opaque request data returned by the contract.
// ProcessWithdrawalQueue 调用 EIP-7002 提款队列合约。
// 它返回合约返回的不透明请求数据。
func ProcessWithdrawalQueue(requests *[][]byte, evm *vm.EVM) {
	processRequestsSystemCall(requests, evm, 0x01, params.WithdrawalQueueAddress)
}

// ProcessConsolidationQueue calls the EIP-7251 consolidation queue contract.
// It returns the opaque request data returned by the contract.
// ProcessConsolidationQueue 调用 EIP-7251 合并队列合约。
// 它返回合约返回的不透明请求数据。
func ProcessConsolidationQueue(requests *[][]byte, evm *vm.EVM) {
	processRequestsSystemCall(requests, evm, 0x02, params.ConsolidationQueueAddress)
}

func processRequestsSystemCall(requests *[][]byte, evm *vm.EVM, requestType byte, addr common.Address) {
	if tracer := evm.Config.Tracer; tracer != nil {
		onSystemCallStart(tracer, evm.GetVMContext())
		if tracer.OnSystemCallEnd != nil {
			defer tracer.OnSystemCallEnd()
		}
	}
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &addr,
	}
	evm.SetTxContext(NewEVMTxContext(msg))
	evm.StateDB.AddAddressToAccessList(addr)
	ret, _, _ := evm.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	evm.StateDB.Finalise(true)
	if len(ret) == 0 {
		return // skip empty output
		// 跳过空输出。
	}

	// Append prefixed requestsData to the requests list.
	// 将带有前缀的 requestsData 追加到 requests 列表中。
	requestsData := make([]byte, len(ret)+1)
	requestsData[0] = requestType
	copy(requestsData[1:], ret)
	*requests = append(*requests, requestsData)
}

// ParseDepositLogs extracts the EIP-6110 deposit values from logs emitted by
// BeaconDepositContract.
// ParseDepositLogs 从 BeaconDepositContract 发出的日志中提取 EIP-6110 的存款值。
func ParseDepositLogs(requests *[][]byte, logs []*types.Log, config *params.ChainConfig) error {
	deposits := make([]byte, 1) // note: first byte is 0x00 (== deposit request type)
	// 注意：第一个字节是 0x00（== 存款请求类型）。
	for _, log := range logs {
		if log.Address == config.DepositContractAddress {
			request, err := types.DepositLogToRequest(log.Data)
			if err != nil {
				return fmt.Errorf("unable to parse deposit data: %v", err)
			}
			deposits = append(deposits, request...)
		}
	}
	if len(deposits) > 1 {
		*requests = append(*requests, deposits)
	}
	return nil
}

func onSystemCallStart(tracer *tracing.Hooks, ctx *tracing.VMContext) {
	if tracer.OnSystemCallStartV2 != nil {
		tracer.OnSystemCallStartV2(ctx)
	} else if tracer.OnSystemCallStart != nil {
		tracer.OnSystemCallStart()
	}
}
