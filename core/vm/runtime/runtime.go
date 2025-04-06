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

package runtime

import (
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// 以下是基于以太坊白皮书、黄皮书、EIP 和相关算法对上述代码的背景知识解释，帮助你理解其与以太坊生态的关系。
//
// 1. EVM 配置（白皮书）
// 以太坊白皮书中提到，EVM 是以太坊的核心执行引擎，运行智能合约需要特定的上下文和状态。Config 结构体提供了这种配置：
//
// 链参数：ChainConfig 定义硬分叉（如 LondonBlock、ShanghaiTime），影响 EVM 行为。
// 块信息：BlockNumber、Time、GasLimit 等模拟当前块环境，供合约访问（如 block.number）。
// 交易信息：Origin、GasPrice、Value 定义调用者上下文。
// 2. 默认值设置（go-ethereum 实现）
// setDefaults 确保配置完整：
//
// ChainConfig：默认模拟主网（ChainID: 1），支持所有硬分叉，适配测试场景。
// GetHashFn：默认使用 Keccak256 生成块哈希，模拟链历史。
// EIP 参数：BaseFee（EIP-1559）、BlobBaseFee（EIP-4844）设为初始值，Random（EIP-4399）设为零哈希。
// 3. EVM 执行（黄皮书 Section 9）
// 黄皮书 Section 9 定义了 EVM 的 CALL 和 CREATE 操作，代码中的 Execute、Create 和 Call 实现了这些：
//
// Execute：在内存中创建临时合约并调用，适合测试，不依赖现有状态。
// Create：执行合约部署，返回部署后的代码和地址，符合黄皮书中合约创建流程。
// Call：调用已有合约地址，依赖外部提供的状态数据库（State）。
// 4. EIP 的影响
// 代码支持多个 EIP，反映以太坊的演进：
//
// EIP-1559（伦敦硬分叉）：BaseFee 控制动态费用，默认值为 InitialBaseFee。
// EIP-2930（柏林硬分叉）：State.Prepare 支持访问列表，优化 Gas 成本。
// EIP-1153：State.Prepare 重置临时存储，支持瞬态数据。
// EIP-4844（Cancun 硬分叉）：BlobBaseFee 和 BlobHashes 支持 Blob 交易，适配数据分片。
// EIP-4399：Random 提供 PoS 下的随机数，增强合约功能。
// 5. 状态管理（白皮书）
// 白皮书中描述的状态转换由 StateDB 实现：
//
// 准备步骤：Prepare 设置访问列表和预编译合约地址，确保状态一致性。
// 账户操作：CreateAccount 和 SetCode 初始化合约账户，模拟链上部署。
// 6. 追踪功能（go-ethereum 扩展）
// EVMConfig.Tracer 支持交易追踪：
//
// OnTxStart：记录交易开始，传递模拟的 LegacyTx。
// OnTxEnd：记录交易结束，计算 Gas 使用量（GasLimit - leftOverGas），便于调试和分析。
// 7. 执行环境（黄皮书）
// NewEnv（未在代码中显示，但假定创建 vm.EVM 实例）基于 Config 构建 EVM 环境，结合 BlockContext 和 TxContext，提供完整的执行上下文。

// Config is a basic type specifying certain configuration flags for running
// the EVM.
// Config 是一个基本类型，指定运行 EVM 的某些配置标志。
type Config struct {
	ChainConfig *params.ChainConfig // 链配置
	Difficulty  *big.Int            // 难度
	Origin      common.Address      // 发起者地址
	Coinbase    common.Address      // Coinbase 地址（受益人）
	BlockNumber *big.Int            // 块高度
	Time        uint64              // 时间戳
	GasLimit    uint64              // Gas 限制
	GasPrice    *big.Int            // Gas 价格
	Value       *big.Int            // 转账金额
	Debug       bool                // 调试模式
	EVMConfig   vm.Config           // EVM 配置
	BaseFee     *big.Int            // 基础费用（EIP-1559）
	BlobBaseFee *big.Int            // Blob 基础费用（EIP-4844）
	BlobHashes  []common.Hash       // Blob 哈希（EIP-4844）
	BlobFeeCap  *big.Int            // Blob Gas 费用上限（EIP-4844）
	Random      *common.Hash        // 随机值（EIP-4399）

	State     *state.StateDB             // 状态数据库
	GetHashFn func(n uint64) common.Hash // 获取块哈希的函数
}

// sets defaults on the config
// setDefaults 为配置设置默认值
func setDefaults(cfg *Config) {
	if cfg.ChainConfig == nil {
		var (
			shanghaiTime = uint64(0) // 上海硬分叉时间
			cancunTime   = uint64(0) // Cancun 硬分叉时间
		)
		cfg.ChainConfig = &params.ChainConfig{
			ChainID:                 big.NewInt(1), // 链 ID
			HomesteadBlock:          new(big.Int),  // Homestead 分叉块
			DAOForkBlock:            new(big.Int),  // DAO 分叉块
			DAOForkSupport:          false,         // 是否支持 DAO 分叉
			EIP150Block:             new(big.Int),  // EIP-150 分叉块
			EIP155Block:             new(big.Int),  // EIP-155 分叉块
			EIP158Block:             new(big.Int),  // EIP-158 分叉块
			ByzantiumBlock:          new(big.Int),  // 拜占庭分叉块
			ConstantinopleBlock:     new(big.Int),  // 君士坦丁堡分叉块
			PetersburgBlock:         new(big.Int),  // 彼得堡分叉块
			IstanbulBlock:           new(big.Int),  // 伊斯坦布尔分叉块
			MuirGlacierBlock:        new(big.Int),  // Muir Glacier 分叉块
			BerlinBlock:             new(big.Int),  // 柏林分叉块
			LondonBlock:             new(big.Int),  // 伦敦分叉块
			ArrowGlacierBlock:       nil,           // Arrow Glacier 分叉块
			GrayGlacierBlock:        nil,           // Gray Glacier 分叉块
			TerminalTotalDifficulty: big.NewInt(0), // 终端总难度（PoS 转换）
			MergeNetsplitBlock:      nil,           // 合并网络分裂块
			ShanghaiTime:            &shanghaiTime, // 上海硬分叉时间
			CancunTime:              &cancunTime}   // Cancun 硬分叉时间
	}
	if cfg.Difficulty == nil {
		cfg.Difficulty = new(big.Int) // 如果难度为空，设置为 0
	}
	if cfg.GasLimit == 0 {
		cfg.GasLimit = math.MaxUint64 // 如果 Gas 限制为 0，设置为最大值
	}
	if cfg.GasPrice == nil {
		cfg.GasPrice = new(big.Int) // 如果 Gas 价格为空，设置为 0
	}
	if cfg.Value == nil {
		cfg.Value = new(big.Int) // 如果转账金额为空，设置为 0
	}
	if cfg.BlockNumber == nil {
		cfg.BlockNumber = new(big.Int) // 如果块高度为空，设置为 0
	}
	if cfg.GetHashFn == nil {
		cfg.GetHashFn = func(n uint64) common.Hash {
			return common.BytesToHash(crypto.Keccak256([]byte(new(big.Int).SetUint64(n).String())))
			// 如果未提供 GetHashFn，默认返回基于高度的 Keccak256 哈希
		}
	}
	if cfg.BaseFee == nil {
		cfg.BaseFee = big.NewInt(params.InitialBaseFee) // 如果基础费用为空，设置为初始值
	}
	if cfg.BlobBaseFee == nil {
		cfg.BlobBaseFee = big.NewInt(params.BlobTxMinBlobGasprice) // 如果 Blob 基础费用为空，设置为最小值
	}
	cfg.Random = &(common.Hash{}) // 设置默认随机值为零哈希
}

// Execute executes the code using the input as call data during the execution.
// It returns the EVM's return value, the new state and an error if it failed.
//
// Execute sets up an in-memory, temporary, environment for the execution of
// the given code. It makes sure that it's restored to its original state afterwards.
// Execute 使用输入作为调用数据执行代码。
// 它返回 EVM 的返回值、新状态以及如果失败则返回错误。
//
// Execute 为给定代码的执行设置一个临时的内存环境。
// 它确保之后恢复到原始状态。
func Execute(code, input []byte, cfg *Config) ([]byte, *state.StateDB, error) {
	if cfg == nil {
		cfg = new(Config) // 如果配置为空，创建新配置
	}
	setDefaults(cfg) // 设置默认值

	if cfg.State == nil {
		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		// 如果状态数据库为空，创建新的测试状态数据库
	}
	var (
		address = common.BytesToAddress([]byte("contract")) // 合约地址
		vmenv   = NewEnv(cfg)                               // 创建 EVM 环境
		sender  = vm.AccountRef(cfg.Origin)                 // 发送者账户引用
		rules   = cfg.ChainConfig.Rules(vmenv.Context.BlockNumber, vmenv.Context.Random != nil, vmenv.Context.Time)
		// 获取链规则
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxStart != nil {
		cfg.EVMConfig.Tracer.OnTxStart(vmenv.GetVMContext(), types.NewTx(&types.LegacyTx{To: &address, Data: input, Value: cfg.Value, Gas: cfg.GasLimit}), cfg.Origin)
		// 如果启用了追踪器，记录交易开始
	}
	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	// 执行状态转换的准备步骤，包括：
	// - 准备访问列表（柏林硬分叉后）
	// - 重置临时存储（EIP-1153）
	cfg.State.Prepare(rules, cfg.Origin, cfg.Coinbase, &address, vm.ActivePrecompiles(rules), nil)
	cfg.State.CreateAccount(address) // 创建合约账户
	// set the receiver's (the executing contract) code for execution.
	// 设置接收者（执行合约）的代码以供执行。
	cfg.State.SetCode(address, code)
	// Call the code with the given configuration.
	// 使用给定配置调用代码。
	ret, leftOverGas, err := vmenv.Call(
		sender,
		common.BytesToAddress([]byte("contract")),
		input,
		cfg.GasLimit,
		uint256.MustFromBig(cfg.Value),
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxEnd != nil {
		cfg.EVMConfig.Tracer.OnTxEnd(&types.Receipt{GasUsed: cfg.GasLimit - leftOverGas}, err)
		// 如果启用了追踪器，记录交易结束
	}
	return ret, cfg.State, err // 返回执行结果、新状态和错误
}

// Create executes the code using the EVM create method
// Create 使用 EVM 的创建方法执行代码
func Create(input []byte, cfg *Config) ([]byte, common.Address, uint64, error) {
	if cfg == nil {
		cfg = new(Config) // 如果配置为空，创建新配置
	}
	setDefaults(cfg) // 设置默认值

	if cfg.State == nil {
		cfg.State, _ = state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
		// 如果状态数据库为空，创建新的测试状态数据库
	}
	var (
		vmenv  = NewEnv(cfg)               // 创建 EVM 环境
		sender = vm.AccountRef(cfg.Origin) // 发送者账户引用
		rules  = cfg.ChainConfig.Rules(vmenv.Context.BlockNumber, vmenv.Context.Random != nil, vmenv.Context.Time)
		// 获取链规则
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxStart != nil {
		cfg.EVMConfig.Tracer.OnTxStart(vmenv.GetVMContext(), types.NewTx(&types.LegacyTx{Data: input, Value: cfg.Value, Gas: cfg.GasLimit}), cfg.Origin)
		// 如果启用了追踪器，记录交易开始
	}
	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	// 执行状态转换的准备步骤，包括：
	// - 准备访问列表（柏林硬分叉后）
	// - 重置临时存储（EIP-1153）
	cfg.State.Prepare(rules, cfg.Origin, cfg.Coinbase, nil, vm.ActivePrecompiles(rules), nil)
	// Call the code with the given configuration.
	// 使用给定配置调用代码。
	code, address, leftOverGas, err := vmenv.Create(
		sender,
		input,
		cfg.GasLimit,
		uint256.MustFromBig(cfg.Value),
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxEnd != nil {
		cfg.EVMConfig.Tracer.OnTxEnd(&types.Receipt{GasUsed: cfg.GasLimit - leftOverGas}, err)
		// 如果启用了追踪器，记录交易结束
	}
	return code, address, leftOverGas, err // 返回代码、合约地址、剩余 Gas 和错误
}

// Call executes the code given by the contract's address. It will return the
// EVM's return value or an error if it failed.
//
// Call, unlike Execute, requires a config and also requires the State field to
// be set.
// Call 执行由合约地址给定的代码。它将返回 EVM 的返回值或如果失败则返回错误。
//
// 与 Execute 不同，Call 需要配置并且要求 State 字段已设置。
func Call(address common.Address, input []byte, cfg *Config) ([]byte, uint64, error) {
	setDefaults(cfg) // 设置默认值

	var (
		vmenv   = NewEnv(cfg)               // 创建 EVM 环境
		sender  = vm.AccountRef(cfg.Origin) // 发送者账户引用
		statedb = cfg.State                 // 状态数据库
		rules   = cfg.ChainConfig.Rules(vmenv.Context.BlockNumber, vmenv.Context.Random != nil, vmenv.Context.Time)
		// 获取链规则
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxStart != nil {
		cfg.EVMConfig.Tracer.OnTxStart(vmenv.GetVMContext(), types.NewTx(&types.LegacyTx{To: &address, Data: input, Value: cfg.Value, Gas: cfg.GasLimit}), cfg.Origin)
		// 如果启用了追踪器，记录交易开始
	}
	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	// 执行状态转换的准备步骤，包括：
	// - 准备访问列表（柏林硬分叉后）
	// - 重置临时存储（EIP-1153）
	statedb.Prepare(rules, cfg.Origin, cfg.Coinbase, &address, vm.ActivePrecompiles(rules), nil)

	// Call the code with the given configuration.
	// 使用给定配置调用代码。
	ret, leftOverGas, err := vmenv.Call(
		sender,
		address,
		input,
		cfg.GasLimit,
		uint256.MustFromBig(cfg.Value),
	)
	if cfg.EVMConfig.Tracer != nil && cfg.EVMConfig.Tracer.OnTxEnd != nil {
		cfg.EVMConfig.Tracer.OnTxEnd(&types.Receipt{GasUsed: cfg.GasLimit - leftOverGas}, err)
		// 如果启用了追踪器，记录交易结束
	}
	return ret, leftOverGas, err // 返回执行结果、剩余 Gas 和错误
}
