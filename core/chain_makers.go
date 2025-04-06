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
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

// 1. BlockGen 和 GenerateChain 的作用与以太坊白皮书
// BlockGen 和 GenerateChain 是 go-ethereum 中用于测试的工具，模拟以太坊区块生成过程。以太坊白皮书（Vitalik Buterin, 2013）描述了区块链的核心机制：通过链接区块（包含头部、交易和状态）形成链。GenerateChain 创建一个确定性的区块链，允许开发者在不运行完整网络的情况下测试共识、交易执行和状态转换。这与白皮书中“去中心化账本”的概念一致，区块生成是网络运行的基础。
//
// 2. 共识引擎与 PoW/PoS 过渡
// BlockGen 使用 consensus.Engine 接口支持不同共识算法。以太坊最初采用 PoW（Ethash），通过 engine.CalcDifficulty 计算难度（黄皮书定义）。SetPoS 和 GenerateChain 中的难度处理反映了 EIP-3675（2022 年合并）后的 PoS 过渡，PoS 区块难度固定为 0。FinalizeAndAssemble 方法调用共识引擎完成区块，体现了以太坊模块化设计，支持从 PoW 到 PoS 的平滑切换。
//
// 3. EIP-1559 与基础费用
// BaseFee 和 makeHeader 中的 eip1559.CalcBaseFee 实现了 EIP-1559（伦敦升级，2021 年），引入动态调整的基础费用机制。黄皮书更新了 Gas 定价公式，CalcBaseFee 根据父区块 Gas 使用量计算新费用。BlockGen 支持测试此机制，确保交易费用随网络负载变化，符合白皮书中“经济激励”的设计目标。
//
// 4. EIP-4844 与 Blob Gas
// GenerateChain 和 makeHeader 支持 EIP-4844（Cancun 升级，2024 年），引入 Blob 数据存储以降低 Rollup 成本。ExcessBlobGas 和 BlobGasUsed 字段由 eip4844.CalcExcessBlobGas 计算，addTx 更新 Blob Gas 使用量。这种机制优化了数据可用性，与以太坊扩展性愿景（白皮书提及的“可扩展性挑战”）一致。
//
// 5. EIP-2935、6110、7002、7251 与 Prague 升级
// collectRequests 支持 Prague 升级的相关 EIP：
//
// EIP-2935：保存历史区块哈希，增强 BLOCKHASH 指令，支持智能合约回溯查询。
// EIP-6110：处理存款日志（ParseDepositLogs），支持 PoS 验证者存款。
// EIP-7002：管理提款队列（ProcessWithdrawalQueue），优化验证者退出。
// EIP-7251：处理合并队列（ProcessConsolidationQueue），提升 staking 效率。 这些功能通过 ConsensusLayerRequests 返回共识层请求，体现了以太坊向 PoS 和分片架构演进的努力。
// 6. Verkle Tree 与状态管理
// GenerateVerkleChain 引入 Verkle Tree（EIP-3102 提案），替代 Merkle Patricia Trie，优化状态存储和证明生成。VerkleProof 和 StateDiff 用于生成高效的状态证明，支持轻客户端和无状态节点。这是白皮书中“轻客户端验证”理念的延伸，解决状态膨胀问题。
//
// 7. DAO 分叉与历史兼容性
// GenerateChain 中的 DAO 分叉处理（ApplyDAOHardFork）重现了 2016 年以太坊分叉逻辑，确保测试链兼容历史硬分叉。黄皮书中定义了状态转换规则，BlockGen 通过 Extra 和状态调整支持此功能，反映了以太坊对社区治理的响应。

// BlockGen creates blocks for testing.
// See GenerateChain for a detailed explanation.
// BlockGen 用于创建测试用的区块。
// 请参阅 GenerateChain 获取详细说明。
type BlockGen struct {
	i       int            // 当前区块索引
	cm      *chainMaker    // 链生成器
	parent  *types.Block   // 父区块
	header  *types.Header  // 当前区块头部
	statedb *state.StateDB // 状态数据库

	gasPool     *GasPool             // Gas 池
	txs         []*types.Transaction // 交易列表
	receipts    []*types.Receipt     // 收据列表
	uncles      []*types.Header      // 叔块头部列表
	withdrawals []*types.Withdrawal  // 提款列表

	engine consensus.Engine // 共识引擎
}

// SetCoinbase sets the coinbase of the generated block.
// It can be called at most once.
// SetCoinbase 设置生成区块的 coinbase。
// 最多只能调用一次。
func (b *BlockGen) SetCoinbase(addr common.Address) {
	if b.gasPool != nil {
		if len(b.txs) > 0 {
			panic("coinbase must be set before adding transactions")
			// "coinbase 必须在添加交易之前设置"
		}
		panic("coinbase can only be set once")
		// "coinbase 只能设置一次"
	}
	b.header.Coinbase = addr
	b.gasPool = new(GasPool).AddGas(b.header.GasLimit) // 初始化 Gas 池
}

// SetExtra sets the extra data field of the generated block.
// SetExtra 设置生成区块的额外数据字段。
func (b *BlockGen) SetExtra(data []byte) {
	b.header.Extra = data
}

// SetNonce sets the nonce field of the generated block.
// SetNonce 设置生成区块的 nonce 字段。
func (b *BlockGen) SetNonce(nonce types.BlockNonce) {
	b.header.Nonce = nonce
}

// SetDifficulty sets the difficulty field of the generated block. This method is
// useful for Clique tests where the difficulty does not depend on time. For the
// ethash tests, please use OffsetTime, which implicitly recalculates the diff.
// SetDifficulty 设置生成区块的难度字段。此方法适用于 Clique 测试，其中难度不依赖时间。对于 ethash 测试，请使用 OffsetTime，它会隐式重新计算难度。
func (b *BlockGen) SetDifficulty(diff *big.Int) {
	b.header.Difficulty = diff
}

// SetPoS makes the header a PoS-header (0 difficulty)
// SetPoS 将头部设置为 PoS 头部（难度为 0）
func (b *BlockGen) SetPoS() {
	b.header.Difficulty = new(big.Int) // 设置难度为 0
}

// Difficulty returns the currently calculated difficulty of the block.
// Difficulty 返回当前计算的区块难度。
func (b *BlockGen) Difficulty() *big.Int {
	return new(big.Int).Set(b.header.Difficulty) // 返回难度副本
}

// SetParentBeaconRoot sets the parent beacon root field of the generated
// block.
// SetParentBeaconRoot 设置生成区块的父信标根字段。
func (b *BlockGen) SetParentBeaconRoot(root common.Hash) {
	b.header.ParentBeaconRoot = &root
	blockContext := NewEVMBlockContext(b.header, b.cm, &b.header.Coinbase)
	ProcessBeaconBlockRoot(root, vm.NewEVM(blockContext, b.statedb, b.cm.config, vm.Config{}))
	// 处理信标区块根
}

// addTx adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
//
// There are a few options can be passed as well in order to run some
// customized rules.
// - bc:       enables the ability to query historical block hashes for BLOCKHASH
// - vmConfig: extends the flexibility for customizing evm rules, e.g. enable extra EIPs
// addTx 将交易添加到生成区块。如果未设置 coinbase，则区块的 coinbase 将设置为零地址。
//
// 还可以传递一些选项以运行自定义规则：
// - bc:       启用查询历史区块哈希用于 BLOCKHASH
// - vmConfig: 扩展自定义 EVM 规则的灵活性，例如启用额外的 EIP
func (b *BlockGen) addTx(bc *BlockChain, vmConfig vm.Config, tx *types.Transaction) {
	if b.gasPool == nil {
		b.SetCoinbase(common.Address{}) // 默认设置为零地址
	}
	var (
		blockContext = NewEVMBlockContext(b.header, bc, &b.header.Coinbase)
		evm          = vm.NewEVM(blockContext, b.statedb, b.cm.config, vmConfig)
	)
	b.statedb.SetTxContext(tx.Hash(), len(b.txs)) // 设置交易上下文
	receipt, err := ApplyTransaction(evm, b.gasPool, b.statedb, b.header, tx, &b.header.GasUsed)
	if err != nil {
		panic(err) // 如果交易应用失败，抛出异常
	}
	b.txs = append(b.txs, tx)
	b.receipts = append(b.receipts, receipt)
	if b.header.BlobGasUsed != nil {
		*b.header.BlobGasUsed += receipt.BlobGasUsed // 更新 Blob Gas 使用量
	}
}

// AddTx adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
//
// AddTx panics if the transaction cannot be executed. In addition to the protocol-imposed
// limitations (gas limit, etc.), there are some further limitations on the content of
// transactions that can be added. Notably, contract code relying on the BLOCKHASH
// instruction will panic during execution if it attempts to access a block number outside
// of the range created by GenerateChain.
// AddTx 将交易添加到生成区块。如果未设置 coinbase，则区块的 coinbase 将设置为零地址。
//
// 如果交易无法执行，AddTx 会抛出异常。除了协议施加的限制（gas 限制等）外，添加的交易内容还有进一步限制。特别是，依赖 BLOCKHASH 指令的合约代码如果尝试访问 GenerateChain 创建范围外的区块号，将在执行期间抛出异常。
func (b *BlockGen) AddTx(tx *types.Transaction) {
	b.addTx(nil, vm.Config{}, tx) // 使用默认配置添加交易
}

// AddTxWithChain adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
//
// AddTxWithChain panics if the transaction cannot be executed. In addition to the
// protocol-imposed limitations (gas limit, etc.), there are some further limitations on
// the content of transactions that can be added. If contract code relies on the BLOCKHASH
// instruction, the block in chain will be returned.
// AddTxWithChain 将交易添加到生成区块。如果未设置 coinbase，则区块的 coinbase 将设置为零地址。
//
// 如果交易无法执行，AddTxWithChain 会抛出异常。除了协议施加的限制（gas 限制等）外，添加的交易内容还有进一步限制。如果合约代码依赖 BLOCKHASH 指令，将返回链中的区块。
func (b *BlockGen) AddTxWithChain(bc *BlockChain, tx *types.Transaction) {
	b.addTx(bc, vm.Config{}, tx) // 使用区块链上下文添加交易
}

// AddTxWithVMConfig adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
// The evm interpreter can be customized with the provided vm config.
// AddTxWithVMConfig 将交易添加到生成区块。如果未设置 coinbase，则区块的 coinbase 将设置为零地址。
// 可以通过提供的 vm 配置自定义 EVM 解释器。
func (b *BlockGen) AddTxWithVMConfig(tx *types.Transaction, config vm.Config) {
	b.addTx(nil, config, tx) // 使用自定义 VM 配置添加交易
}

// GetBalance returns the balance of the given address at the generated block.
// GetBalance 返回生成区块中给定地址的余额。
func (b *BlockGen) GetBalance(addr common.Address) *uint256.Int {
	return b.statedb.GetBalance(addr)
}

// AddUncheckedTx forcefully adds a transaction to the block without any validation.
//
// AddUncheckedTx will cause consensus failures when used during real
// chain processing. This is best used in conjunction with raw block insertion.
// AddUncheckedTx 强制将交易添加到区块，不进行任何验证。
//
// 在真实链处理中使用 AddUncheckedTx 会导致共识失败。最好与原始区块插入一起使用。
func (b *BlockGen) AddUncheckedTx(tx *types.Transaction) {
	b.txs = append(b.txs, tx) // 直接添加交易
}

// Number returns the block number of the block being generated.
// Number 返回正在生成的区块的区块号。
func (b *BlockGen) Number() *big.Int {
	return new(big.Int).Set(b.header.Number)
}

// Timestamp returns the timestamp of the block being generated.
// Timestamp 返回正在生成的区块的时间戳。
func (b *BlockGen) Timestamp() uint64 {
	return b.header.Time
}

// BaseFee returns the EIP-1559 base fee of the block being generated.
// BaseFee 返回正在生成的区块的 EIP-1559 基础费用。
func (b *BlockGen) BaseFee() *big.Int {
	return new(big.Int).Set(b.header.BaseFee)
}

// Gas returns the amount of gas left in the current block.
// Gas 返回当前区块剩余的 Gas 量。
func (b *BlockGen) Gas() uint64 {
	return b.header.GasLimit - b.header.GasUsed
}

// Signer returns a valid signer instance for the current block.
// Signer 返回当前区块的有效签名者实例。
func (b *BlockGen) Signer() types.Signer {
	return types.MakeSigner(b.cm.config, b.header.Number, b.header.Time)
}

// AddUncheckedReceipt forcefully adds a receipts to the block without a
// backing transaction.
//
// AddUncheckedReceipt will cause consensus failures when used during real
// chain processing. This is best used in conjunction with raw block insertion.
// AddUncheckedReceipt 强制将收据添加到区块，不需要支持的交易。
//
// 在真实链处理中使用 AddUncheckedReceipt 会导致共识失败。最好与原始区块插入一起使用。
func (b *BlockGen) AddUncheckedReceipt(receipt *types.Receipt) {
	b.receipts = append(b.receipts, receipt) // 直接添加收据
}

// TxNonce returns the next valid transaction nonce for the
// account at addr. It panics if the account does not exist.
// TxNonce 返回给定地址在当前区块的下一个有效交易 nonce。如果账户不存在，则抛出异常。
func (b *BlockGen) TxNonce(addr common.Address) uint64 {
	if !b.statedb.Exist(addr) {
		panic("account does not exist")
		// "账户不存在"
	}
	return b.statedb.GetNonce(addr)
}

// AddUncle adds an uncle header to the generated block.
// AddUncle 将叔块头部添加到生成区块。
func (b *BlockGen) AddUncle(h *types.Header) {
	// The uncle will have the same timestamp and auto-generated difficulty
	// 叔块将具有相同的时间戳和自动生成的难度
	h.Time = b.header.Time

	var parent *types.Header
	for i := b.i - 1; i >= 0; i-- {
		if b.cm.chain[i].Hash() == h.ParentHash {
			parent = b.cm.chain[i].Header()
			break
		}
	}
	h.Difficulty = b.engine.CalcDifficulty(b.cm, b.header.Time, parent) // 计算叔块难度

	// The gas limit and price should be derived from the parent
	// Gas 限制和价格应从父区块派生
	h.GasLimit = parent.GasLimit
	if b.cm.config.IsLondon(h.Number) {
		h.BaseFee = eip1559.CalcBaseFee(b.cm.config, parent) // 计算基础费用
		if !b.cm.config.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * b.cm.config.ElasticityMultiplier()
			h.GasLimit = CalcGasLimit(parentGasLimit, parentGasLimit) // 计算 Gas 限制
		}
	}
	b.uncles = append(b.uncles, h)
}

// AddWithdrawal adds a withdrawal to the generated block.
// It returns the withdrawal index.
// AddWithdrawal 将提款添加到生成区块。
// 返回提款索引。
func (b *BlockGen) AddWithdrawal(w *types.Withdrawal) uint64 {
	cpy := *w
	cpy.Index = b.nextWithdrawalIndex() // 设置提款索引
	b.withdrawals = append(b.withdrawals, &cpy)
	return cpy.Index
}

// nextWithdrawalIndex computes the index of the next withdrawal.
// nextWithdrawalIndex 计算下一个提款的索引。
func (b *BlockGen) nextWithdrawalIndex() uint64 {
	if len(b.withdrawals) != 0 {
		return b.withdrawals[len(b.withdrawals)-1].Index + 1 // 返回最后一个提款索引 + 1
	}
	for i := b.i - 1; i >= 0; i-- {
		if wd := b.cm.chain[i].Withdrawals(); len(wd) != 0 {
			return wd[len(wd)-1].Index + 1 // 从链中找到最后一个提款索引 + 1
		}
		if i == 0 {
			// Correctly set the index if no parent had withdrawals.
			// 如果父区块没有提款，正确设置索引
			if wd := b.cm.bottom.Withdrawals(); len(wd) != 0 {
				return wd[len(wd)-1].Index + 1
			}
		}
	}
	return 0 // 默认返回 0
}

// PrevBlock returns a previously generated block by number. It panics if
// num is greater or equal to the number of the block being generated.
// For index -1, PrevBlock returns the parent block given to GenerateChain.
// PrevBlock 按编号返回先前生成的区块。如果 num 大于或等于正在生成的区块号，则抛出异常。
// 对于索引 -1，PrevBlock 返回 GenerateChain 给定的父区块。
func (b *BlockGen) PrevBlock(index int) *types.Block {
	if index >= b.i {
		panic(fmt.Errorf("block index %d out of range (%d,%d)", index, -1, b.i))
		// "区块索引 %d 超出范围 (%d,%d)"
	}
	if index == -1 {
		return b.cm.bottom // 返回初始父区块
	}
	return b.cm.chain[index]
}

// OffsetTime modifies the time instance of a block, implicitly changing its
// associated difficulty. It's useful to test scenarios where forking is not
// tied to chain length directly.
// OffsetTime 修改区块的时间实例，隐式更改其关联的难度。用于测试分叉不直接与链长度相关的场景。
func (b *BlockGen) OffsetTime(seconds int64) {
	b.header.Time += uint64(seconds)
	if b.header.Time <= b.cm.bottom.Header().Time {
		panic("block time out of range")
		// "区块时间超出范围"
	}
	b.header.Difficulty = b.engine.CalcDifficulty(b.cm, b.header.Time, b.parent.Header()) // 重新计算难度
}

// ConsensusLayerRequests returns the EIP-7685 requests which have accumulated so far.
// ConsensusLayerRequests 返回迄今为止累积的 EIP-7685 请求。
func (b *BlockGen) ConsensusLayerRequests() [][]byte {
	return b.collectRequests(true)
}

func (b *BlockGen) collectRequests(readonly bool) (requests [][]byte) {
	statedb := b.statedb
	if readonly {
		// The system contracts clear themselves on a system-initiated read.
		// When reading the requests mid-block, we don't want this behavior, so fork
		// off the statedb before executing the system calls.
		// 系统合约在系统发起的读取时会清除自身。
		// 在区块中间读取请求时，我们不希望这种行为，因此在执行系统调用前分叉 statedb。
		statedb = statedb.Copy()
	}

	if b.cm.config.IsPrague(b.header.Number, b.header.Time) {
		requests = [][]byte{}
		// EIP-6110 deposits
		// EIP-6110 存款
		var blockLogs []*types.Log
		for _, r := range b.receipts {
			blockLogs = append(blockLogs, r.Logs...)
		}
		if err := ParseDepositLogs(&requests, blockLogs, b.cm.config); err != nil {
			panic(fmt.Sprintf("failed to parse deposit log: %v", err))
			// "解析存款日志失败: %v"
		}
		// create EVM for system calls
		// 为系统调用创建 EVM
		blockContext := NewEVMBlockContext(b.header, b.cm, &b.header.Coinbase)
		evm := vm.NewEVM(blockContext, statedb, b.cm.config, vm.Config{})
		// EIP-7002
		ProcessWithdrawalQueue(&requests, evm) // 处理提款队列
		// EIP-7251
		ProcessConsolidationQueue(&requests, evm) // 处理合并队列
	}
	return requests
}

// GenerateChain creates a chain of n blocks. The first block's
// parent will be the provided parent. db is used to store
// intermediate states and should contain the parent's state trie.
//
// The generator function is called with a new block generator for
// every block. Any transactions and uncles added to the generator
// become part of the block. If gen is nil, the blocks will be empty
// and their coinbase will be the zero address.
//
// Blocks created by GenerateChain do not contain valid proof of work
// values. Inserting them into BlockChain requires use of FakePow or
// a similar non-validating proof of work implementation.
// GenerateChain 创建一个包含 n 个区块的链。第一个区块的父区块将是提供的父区块。db 用于存储中间状态，应包含父区块的状态树。
//
// 对于每个区块，生成器函数都会被调用并传入一个新的区块生成器。添加到生成器的任何交易和叔块将成为区块的一部分。如果 gen 为 nil，区块将为空，其 coinbase 将为零地址。
//
// GenerateChain 创建的区块不包含有效的工作量证明值。将它们插入 BlockChain 需要使用 FakePow 或类似的不验证工作量证明实现。
func GenerateChain(config *params.ChainConfig, parent *types.Block, engine consensus.Engine, db ethdb.Database, n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	if config == nil {
		config = params.TestChainConfig // 默认测试链配置
	}
	if engine == nil {
		panic("nil consensus engine")
		// "共识引擎为空"
	}
	cm := newChainMaker(parent, config, engine) // 创建链生成器

	genblock := func(i int, parent *types.Block, triedb *triedb.Database, statedb *state.StateDB) (*types.Block, types.Receipts) {
		b := &BlockGen{i: i, cm: cm, parent: parent, statedb: statedb, engine: engine}
		b.header = cm.makeHeader(parent, statedb, b.engine) // 生成头部

		// Set the difficulty for clique block. The chain maker doesn't have access
		// to a chain, so the difficulty will be left unset (nil). Set it here to the
		// correct value.
		// 为 Clique 区块设置难度。链生成器无法访问链，因此难度将未设置（nil）。在此处设置为正确值。
		if b.header.Difficulty == nil {
			if config.TerminalTotalDifficulty == nil {
				// Clique chain
				b.header.Difficulty = big.NewInt(2)
			} else {
				// Post-merge chain
				b.header.Difficulty = big.NewInt(0)
			}
		}

		// Mutate the state and block according to any hard-fork specs
		// 根据任何硬分叉规范修改状态和区块
		if daoBlock := config.DAOForkBlock; daoBlock != nil {
			limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
			if b.header.Number.Cmp(daoBlock) >= 0 && b.header.Number.Cmp(limit) < 0 {
				if config.DAOForkSupport {
					b.header.Extra = common.CopyBytes(params.DAOForkBlockExtra) // 设置 DAO 分叉额外数据
				}
			}
		}
		if config.DAOForkSupport && config.DAOForkBlock != nil && config.DAOForkBlock.Cmp(b.header.Number) == 0 {
			misc.ApplyDAOHardFork(statedb) // 应用 DAO 硬分叉
		}

		if config.IsPrague(b.header.Number, b.header.Time) {
			// EIP-2935
			blockContext := NewEVMBlockContext(b.header, cm, &b.header.Coinbase)
			blockContext.Random = &common.Hash{} // enable post-merge instruction set 启用合并后指令集
			evm := vm.NewEVM(blockContext, statedb, cm.config, vm.Config{})
			ProcessParentBlockHash(b.header.ParentHash, evm) // 处理父区块哈希
		}

		// Execute any user modifications to the block
		// 执行用户对区块的任何修改
		if gen != nil {
			gen(i, b)
		}

		requests := b.collectRequests(false)
		if requests != nil {
			reqHash := types.CalcRequestsHash(requests)
			b.header.RequestsHash = &reqHash // 设置请求哈希
		}

		body := types.Body{Transactions: b.txs, Uncles: b.uncles, Withdrawals: b.withdrawals}
		block, err := b.engine.FinalizeAndAssemble(cm, b.header, statedb, &body, b.receipts)
		if err != nil {
			panic(err) // 如果最终化和组装失败，抛出异常
		}

		// Write state changes to db
		// 将状态更改写入数据库
		root, err := statedb.Commit(b.header.Number.Uint64(), config.IsEIP158(b.header.Number))
		if err != nil {
			panic(fmt.Sprintf("state write error: %v", err))
			// "状态写入错误: %v"
		}
		if err = triedb.Commit(root, false); err != nil {
			panic(fmt.Sprintf("trie write error: %v", err))
			// "树写入错误: %v"
		}
		return block, b.receipts
	}

	// Forcibly use hash-based state scheme for retaining all nodes in disk.
	// 强制使用基于哈希的状态方案以在磁盘上保留所有节点。
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)
	defer triedb.Close()

	for i := 0; i < n; i++ {
		statedb, err := state.New(parent.Root(), state.NewDatabase(triedb, nil))
		if err != nil {
			panic(err) // 如果状态创建失败，抛出异常
		}
		block, receipts := genblock(i, parent, triedb, statedb)

		// Post-process the receipts.
		// Here we assign the final block hash and other info into the receipt.
		// In order for DeriveFields to work, the transaction and receipt lists need to be
		// of equal length. If AddUncheckedTx or AddUncheckedReceipt are used, there will be
		// extra ones, so we just trim the lists here.
		// Post-process the receipts.
		// 这里我们将最终区块哈希和其他信息分配到收据中。
		// 为了使 DeriveFields 正常工作，交易和收据列表的长度需要相等。如果使用了 AddUncheckedTx 或 AddUncheckedReceipt，会出现多余的条目，因此我们在此修剪列表。
		receiptsCount := len(receipts)
		txs := block.Transactions()
		if len(receipts) > len(txs) {
			receipts = receipts[:len(txs)]
		} else if len(receipts) < len(txs) {
			txs = txs[:len(receipts)]
		}
		var blobGasPrice *big.Int
		if block.ExcessBlobGas() != nil {
			blobGasPrice = eip4844.CalcBlobFee(*block.ExcessBlobGas()) // 计算 Blob Gas 价格
		}
		if err := receipts.DeriveFields(config, block.Hash(), block.NumberU64(), block.Time(), block.BaseFee(), blobGasPrice, txs); err != nil {
			panic(err) // 如果收据字段派生失败，抛出异常
		}

		// Re-expand to ensure all receipts are returned.
		// 重新扩展以确保返回所有收据。
		receipts = receipts[:receiptsCount]

		// Advance the chain.
		// 前进链。
		cm.add(block, receipts)
		parent = block
	}
	return cm.chain, cm.receipts
}

// GenerateChainWithGenesis is a wrapper of GenerateChain which will initialize
// genesis block to database first according to the provided genesis specification
// then generate chain on top.
// GenerateChainWithGenesis 是 GenerateChain 的包装器，它将首先根据提供的创世规范初始化创世区块到数据库，然后在其上生成链。
func GenerateChainWithGenesis(genesis *Genesis, engine consensus.Engine, n int, gen func(int, *BlockGen)) (ethdb.Database, []*types.Block, []types.Receipts) {
	db := rawdb.NewMemoryDatabase()
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)
	defer triedb.Close()
	_, err := genesis.Commit(db, triedb)
	if err != nil {
		panic(err) // 如果创世区块提交失败，抛出异常
	}
	blocks, receipts := GenerateChain(genesis.Config, genesis.ToBlock(), engine, db, n, gen)
	return db, blocks, receipts
}

func GenerateVerkleChain(config *params.ChainConfig, parent *types.Block, engine consensus.Engine, db ethdb.Database, trdb *triedb.Database, n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts, []*verkle.VerkleProof, []verkle.StateDiff) {
	if config == nil {
		config = params.TestChainConfig // 默认测试链配置
	}
	proofs := make([]*verkle.VerkleProof, 0, n) // Verkle 证明列表
	keyvals := make([]verkle.StateDiff, 0, n)   // 状态差异列表
	cm := newChainMaker(parent, config, engine)

	genblock := func(i int, parent *types.Block, triedb *triedb.Database, statedb *state.StateDB) (*types.Block, types.Receipts) {
		b := &BlockGen{i: i, cm: cm, parent: parent, statedb: statedb, engine: engine}
		b.header = cm.makeHeader(parent, statedb, b.engine)

		// TODO uncomment when proof generation is merged
		// Save pre state for proof generation
		// 保存前状态以生成证明
		// preState := statedb.Copy()

		// Pre-execution system calls.
		// 执行前系统调用。
		if config.IsPrague(b.header.Number, b.header.Time) {
			// EIP-2935
			blockContext := NewEVMBlockContext(b.header, cm, &b.header.Coinbase)
			evm := vm.NewEVM(blockContext, statedb, cm.config, vm.Config{})
			ProcessParentBlockHash(b.header.ParentHash, evm) // 处理父区块哈希
		}

		// Execute any user modifications to the block.
		// 执行用户对区块的任何修改。
		if gen != nil {
			gen(i, b)
		}
		body := &types.Body{
			Transactions: b.txs,
			Uncles:       b.uncles,
			Withdrawals:  b.withdrawals,
		}
		block, err := b.engine.FinalizeAndAssemble(cm, b.header, statedb, body, b.receipts)
		if err != nil {
			panic(err) // 如果最终化和组装失败，抛出异常
		}

		// Write state changes to DB.
		// 将状态更改写入数据库。
		root, err := statedb.Commit(b.header.Number.Uint64(), config.IsEIP158(b.header.Number))
		if err != nil {
			panic(fmt.Sprintf("state write error: %v", err))
			// "状态写入错误: %v"
		}
		if err = triedb.Commit(root, false); err != nil {
			panic(fmt.Sprintf("trie write error: %v", err))
			// "树写入错误: %v"
		}

		proofs = append(proofs, block.ExecutionWitness().VerkleProof) // 添加 Verkle 证明
		keyvals = append(keyvals, block.ExecutionWitness().StateDiff) // 添加状态差异

		return block, b.receipts
	}

	for i := 0; i < n; i++ {
		statedb, err := state.New(parent.Root(), state.NewDatabase(trdb, nil))
		if err != nil {
			panic(err) // 如果状态创建失败，抛出异常
		}
		block, receipts := genblock(i, parent, trdb, statedb)

		// Post-process the receipts.
		// Here we assign the final block hash and other info into the receipt.
		// In order for DeriveFields to work, the transaction and receipt lists need to be
		// of equal length. If AddUncheckedTx or AddUncheckedReceipt are used, there will be
		// extra ones, so we just trim the lists here.
		//
		// Post-process the receipts.
		// 这里我们将最终区块哈希和其他信息分配到收据中。
		// 为了使 DeriveFields 正常工作，交易和收据列表的长度需要相等。如果使用了 AddUncheckedTx 或 AddUncheckedReceipt，会出现多余的条目，因此我们在此修剪列表。
		receiptsCount := len(receipts)
		txs := block.Transactions()
		if len(receipts) > len(txs) {
			receipts = receipts[:len(txs)]
		} else if len(receipts) < len(txs) {
			txs = txs[:len(receipts)]
		}
		var blobGasPrice *big.Int
		if block.ExcessBlobGas() != nil {
			blobGasPrice = eip4844.CalcBlobFee(*block.ExcessBlobGas()) // 计算 Blob Gas 价格
		}
		if err := receipts.DeriveFields(config, block.Hash(), block.NumberU64(), block.Time(), block.BaseFee(), blobGasPrice, txs); err != nil {
			panic(err) // 如果收据字段派生失败，抛出异常
		}

		// Re-expand to ensure all receipts are returned.
		// 重新扩展以确保返回所有收据。
		receipts = receipts[:receiptsCount]

		// Advance the chain.
		// 前进链。
		cm.add(block, receipts)
		parent = block
	}
	return cm.chain, cm.receipts, proofs, keyvals
}

func GenerateVerkleChainWithGenesis(genesis *Genesis, engine consensus.Engine, n int, gen func(int, *BlockGen)) (ethdb.Database, []*types.Block, []types.Receipts, []*verkle.VerkleProof, []verkle.StateDiff) {
	db := rawdb.NewMemoryDatabase()
	cacheConfig := DefaultCacheConfigWithScheme(rawdb.PathScheme)
	cacheConfig.SnapshotLimit = 0
	triedb := triedb.NewDatabase(db, cacheConfig.triedbConfig(true))
	defer triedb.Close()
	genesisBlock, err := genesis.Commit(db, triedb)
	if err != nil {
		panic(err) // 如果创世区块提交失败，抛出异常
	}
	blocks, receipts, proofs, keyvals := GenerateVerkleChain(genesis.Config, genesisBlock, engine, db, triedb, n, gen)
	return db, blocks, receipts, proofs, keyvals
}

func (cm *chainMaker) makeHeader(parent *types.Block, state *state.StateDB, engine consensus.Engine) *types.Header {
	time := parent.Time() + 10 // block time is fixed at 10 seconds
	// 区块时间固定为 10 秒
	header := &types.Header{
		Root:       state.IntermediateRoot(cm.config.IsEIP158(parent.Number())),
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(cm, time, parent.Header()),
		GasLimit:   parent.GasLimit(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		Time:       time,
	}

	if cm.config.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(cm.config, parent.Header()) // 计算基础费用
		if !cm.config.IsLondon(parent.Number()) {
			parentGasLimit := parent.GasLimit() * cm.config.ElasticityMultiplier()
			header.GasLimit = CalcGasLimit(parentGasLimit, parentGasLimit) // 计算 Gas 限制
		}
	}
	if cm.config.IsCancun(header.Number, header.Time) {
		var (
			parentExcessBlobGas uint64
			parentBlobGasUsed   uint64
		)
		if parent.ExcessBlobGas() != nil {
			parentExcessBlobGas = *parent.ExcessBlobGas()
			parentBlobGasUsed = *parent.BlobGasUsed()
		}
		excessBlobGas := eip4844.CalcExcessBlobGas(parentExcessBlobGas, parentBlobGasUsed) // 计算超额 Blob Gas
		header.ExcessBlobGas = &excessBlobGas
		header.BlobGasUsed = new(uint64)
		header.ParentBeaconRoot = new(common.Hash)
	}
	return header
}

// makeHeaderChain creates a deterministic chain of headers rooted at parent.
// makeHeaderChain 创建以父区块为根的确定性头部链。
func makeHeaderChain(chainConfig *params.ChainConfig, parent *types.Header, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.Header {
	blocks := makeBlockChain(chainConfig, types.NewBlockWithHeader(parent), n, engine, db, seed)
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	return headers
}

// makeHeaderChainWithGenesis creates a deterministic chain of headers from genesis.
// makeHeaderChainWithGenesis 从创世区块创建确定性头部链。
func makeHeaderChainWithGenesis(genesis *Genesis, n int, engine consensus.Engine, seed int) (ethdb.Database, []*types.Header) {
	db, blocks := makeBlockChainWithGenesis(genesis, n, engine, seed)
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	return db, headers
}

// makeBlockChain creates a deterministic chain of blocks rooted at parent.
// makeBlockChain 创建以父区块为根的确定性区块链。
func makeBlockChain(chainConfig *params.ChainConfig, parent *types.Block, n int, engine consensus.Engine, db ethdb.Database, seed int) []*types.Block {
	blocks, _ := GenerateChain(chainConfig, parent, engine, db, n, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)}) // 设置 coinbase
	})
	return blocks
}

// makeBlockChainWithGenesis creates a deterministic chain of blocks from genesis
// makeBlockChainWithGenesis 从创世区块创建确定性区块链
func makeBlockChainWithGenesis(genesis *Genesis, n int, engine consensus.Engine, seed int) (ethdb.Database, []*types.Block) {
	db, blocks, _ := GenerateChainWithGenesis(genesis, engine, n, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)}) // 设置 coinbase
	})
	return db, blocks
}

// chainMaker contains the state of chain generation.
// chainMaker 包含链生成的状态。
type chainMaker struct {
	bottom      *types.Block                 // 初始父区块
	engine      consensus.Engine             // 共识引擎
	config      *params.ChainConfig          // 链配置
	chain       []*types.Block               // 区块链
	chainByHash map[common.Hash]*types.Block // 按哈希索引的区块
	receipts    []types.Receipts             // 收据列表
}

func newChainMaker(bottom *types.Block, config *params.ChainConfig, engine consensus.Engine) *chainMaker {
	return &chainMaker{
		bottom:      bottom,
		config:      config,
		engine:      engine,
		chainByHash: make(map[common.Hash]*types.Block),
	}
}

func (cm *chainMaker) add(b *types.Block, r []*types.Receipt) {
	cm.chain = append(cm.chain, b)
	cm.chainByHash[b.Hash()] = b
	cm.receipts = append(cm.receipts, r)
}

func (cm *chainMaker) blockByNumber(number uint64) *types.Block {
	if number == cm.bottom.NumberU64() {
		return cm.bottom
	}
	cur := cm.CurrentHeader().Number.Uint64()
	lowest := cm.bottom.NumberU64() + 1
	if number < lowest || number > cur {
		return nil
	}
	return cm.chain[number-lowest]
}

// ChainReader/ChainContext implementation

// Config returns the chain configuration (for consensus.ChainReader).
// Config 返回链配置（用于 consensus.ChainReader）。
func (cm *chainMaker) Config() *params.ChainConfig {
	return cm.config
}

// Engine returns the consensus engine (for ChainContext).
// Engine 返回共识引擎（用于 ChainContext）。
func (cm *chainMaker) Engine() consensus.Engine {
	return cm.engine
}

func (cm *chainMaker) CurrentHeader() *types.Header {
	if len(cm.chain) == 0 {
		return cm.bottom.Header() // 返回初始父区块头部
	}
	return cm.chain[len(cm.chain)-1].Header() // 返回最新区块头部
}

func (cm *chainMaker) GetHeaderByNumber(number uint64) *types.Header {
	b := cm.blockByNumber(number)
	if b == nil {
		return nil
	}
	return b.Header()
}

func (cm *chainMaker) GetHeaderByHash(hash common.Hash) *types.Header {
	b := cm.chainByHash[hash]
	if b == nil {
		return nil
	}
	return b.Header()
}

func (cm *chainMaker) GetHeader(hash common.Hash, number uint64) *types.Header {
	return cm.GetHeaderByNumber(number)
}

func (cm *chainMaker) GetBlock(hash common.Hash, number uint64) *types.Block {
	return cm.blockByNumber(number)
}

func (cm *chainMaker) GetTd(hash common.Hash, number uint64) *big.Int {
	return nil // not supported
}
