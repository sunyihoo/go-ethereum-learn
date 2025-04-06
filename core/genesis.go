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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/holiman/uint256"
)

// 1. 创世块的概念（白皮书）
// 以太坊白皮书中将创世块定义为区块链的起点，包含初始状态（如账户余额和合约代码）以及链的配置参数。Genesis 结构体和 SetupGenesisBlock 函数实现了这一概念：
//
// 字段：Nonce、Timestamp、GasLimit 等定义了创世块头，Alloc 指定初始状态，Config 配置硬分叉时间。
// 初始化：Commit 方法将创世块写入数据库，设置规范头部块（WriteCanonicalHash），符合白皮书中对区块链初始化的描述。
// 2. 状态根计算（黄皮书 Section 4）
// 黄皮书 Section 4 定义了状态树（通常为 MPT，Merkle Patricia Trie）存储账户状态，状态根是其哈希。hashAlloc 和 flushAlloc 计算创世状态根：
//
// MPT vs Verkle：默认使用 MPT（EmptyRootHash），支持 Verkle 树（EmptyVerkleHash），后者是更高效的状态存储方案（EIP 未完全标准化）。
// 过程：遍历 GenesisAlloc，设置余额、代码、Nonce 和存储，提交后生成状态根（statedb.Commit）。
// 3. EIP 的影响
// 代码中支持多个 EIP，体现了以太坊的演进：
//
// EIP-1559（伦敦硬分叉）：BaseFee 字段和 ToBlock 中的逻辑支持基础费用机制，创世块可指定初始 BaseFee。
// EIP-4844（Cancun 硬分叉）：ExcessBlobGas 和 BlobGasUsed 支持 Blob 交易，用于数据分片（如 rollups），降低 Layer 2 成本。
// EIP-4788：ParentBeaconRoot 在创世块设为零哈希，适配信标链集成。
// EIP-4895（上海硬分叉）：WithdrawalsHash 支持提款机制，创世块初始化为空。
// 4. 链配置与硬分叉（黄皮书 Section 11）
// Config（params.ChainConfig）定义了硬分叉（如 London、Shanghai、Cancun）的激活时间。SetupGenesisBlockWithOverride 和 ChainOverrides 允许动态调整分叉时间：
//
// 兼容性检查：CheckCompatible 确保新配置与当前链状态兼容，避免分叉冲突。
// Verkle 支持：IsVerkle 和 EnableVerkleAtGenesis 为测试网（如 Verkle 开发网）提供创世时启用 Verkle 树的能力。
// 5. 数据库存储（go-ethereum 实现）
// rawdb 模块管理创世块和状态的持久化：
//
// 键值对：WriteGenesisStateSpec 存储分配 JSON，WriteChainConfig 存储链配置，WriteBlock 存储块数据。
// 恢复机制：ReadGenesis 从数据库重建 Genesis，getGenesisState 为遗失分配提供默认值（如主网、Sepolia）。
// 6. 默认网络
// DefaultGenesisBlock、DefaultSepoliaGenesisBlock 等定义了以太坊主网和测试网的创世块：
//
// 主网：难度高（17179869184），分配基于 mainnetAllocData，反映以太坊 2015 年启动时的状态。
// Sepolia/Holesky：测试网配置，Gas 限制和时间戳适配现代需求。
// 开发链：DeveloperGenesisBlock 为开发者提供简化的创世块，预分配预编译合约和水龙头账户。

//go:generate go run github.com/fjl/gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go

var errGenesisNoConfig = errors.New("genesis has no chain configuration")

// errGenesisNoConfig 表示创世块没有链配置的错误

// Deprecated: use types.Account instead.
// 已弃用：请使用 types.Account 替代。
type GenesisAccount = types.Account

// Deprecated: use types.GenesisAlloc instead.
// 已弃用：请使用 types.GenesisAlloc 替代。
type GenesisAlloc = types.GenesisAlloc

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
// Genesis 指定了创世块的头部字段和状态。它还通过链配置定义了硬分叉切换块。
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`                         // 链配置
	Nonce      uint64              `json:"nonce"`                          // Nonce 值
	Timestamp  uint64              `json:"timestamp"`                      // 时间戳
	ExtraData  []byte              `json:"extraData"`                      // 额外数据
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"` // Gas 限制（必需）
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"` // 难度（必需）
	Mixhash    common.Hash         `json:"mixHash"`                        // 混合哈希
	Coinbase   common.Address      `json:"coinbase"`                       // Coinbase 地址
	Alloc      types.GenesisAlloc  `json:"alloc"      gencodec:"required"` // 创世分配（必需）

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	// 这些字段用于共识测试。请勿在实际创世块中使用它们。
	Number        uint64      `json:"number"`        // 块高度
	GasUsed       uint64      `json:"gasUsed"`       // 已使用的 Gas
	ParentHash    common.Hash `json:"parentHash"`    // 父块哈希
	BaseFee       *big.Int    `json:"baseFeePerGas"` // 基础费用（EIP-1559）
	ExcessBlobGas *uint64     `json:"excessBlobGas"` // 超额 Blob Gas（EIP-4844）
	BlobGasUsed   *uint64     `json:"blobGasUsed"`   // 已使用的 Blob Gas（EIP-4844）
}

func ReadGenesis(db ethdb.Database) (*Genesis, error) {
	var genesis Genesis
	stored := rawdb.ReadCanonicalHash(db, 0) // 从数据库读取第 0 块的规范哈希
	if (stored == common.Hash{}) {
		return nil, fmt.Errorf("invalid genesis hash in database: %x", stored)
		// 如果数据库中的创世哈希无效，返回错误
	}
	blob := rawdb.ReadGenesisStateSpec(db, stored) // 读取创世状态规范
	if blob == nil {
		return nil, errors.New("genesis state missing from db")
		// 如果数据库中缺少创世状态，返回错误
	}
	if len(blob) != 0 {
		if err := genesis.Alloc.UnmarshalJSON(blob); err != nil {
			return nil, fmt.Errorf("could not unmarshal genesis state json: %s", err)
			// 如果无法解析创世状态 JSON，返回错误
		}
	}
	genesis.Config = rawdb.ReadChainConfig(db, stored) // 从数据库读取链配置
	if genesis.Config == nil {
		return nil, errors.New("genesis config missing from db")
		// 如果数据库中缺少创世配置，返回错误
	}
	genesisBlock := rawdb.ReadBlock(db, stored, 0) // 从数据库读取创世块
	if genesisBlock == nil {
		return nil, errors.New("genesis block missing from db")
		// 如果数据库中缺少创世块，返回错误
	}
	genesisHeader := genesisBlock.Header()              // 获取创世块头部
	genesis.Nonce = genesisHeader.Nonce.Uint64()        // 设置 Nonce
	genesis.Timestamp = genesisHeader.Time              // 设置时间戳
	genesis.ExtraData = genesisHeader.Extra             // 设置额外数据
	genesis.GasLimit = genesisHeader.GasLimit           // 设置 Gas 限制
	genesis.Difficulty = genesisHeader.Difficulty       // 设置难度
	genesis.Mixhash = genesisHeader.MixDigest           // 设置混合哈希
	genesis.Coinbase = genesisHeader.Coinbase           // 设置 Coinbase 地址
	genesis.BaseFee = genesisHeader.BaseFee             // 设置基础费用
	genesis.ExcessBlobGas = genesisHeader.ExcessBlobGas // 设置超额 Blob Gas
	genesis.BlobGasUsed = genesisHeader.BlobGasUsed     // 设置已使用的 Blob Gas

	return &genesis, nil
}

// hashAlloc computes the state root according to the genesis specification.
// hashAlloc 根据创世规范计算状态根。
func hashAlloc(ga *types.GenesisAlloc, isVerkle bool) (common.Hash, error) {
	// If a genesis-time verkle trie is requested, create a trie config
	// with the verkle trie enabled so that the tree can be initialized
	// as such.
	// 如果请求在创世时使用 Verkle 树，则创建一个启用 Verkle 树的 trie 配置，以便树可以以此方式初始化。
	var config *triedb.Config
	if isVerkle {
		config = &triedb.Config{
			PathDB:   pathdb.Defaults, // 默认路径数据库配置
			IsVerkle: true,            // 启用 Verkle 树
		}
	}
	// Create an ephemeral in-memory database for computing hash,
	// all the derived states will be discarded to not pollute disk.
	// 创建一个临时的内存数据库来计算哈希，所有派生状态将被丢弃，以避免污染磁盘。
	emptyRoot := types.EmptyRootHash // 空状态根
	if isVerkle {
		emptyRoot = types.EmptyVerkleHash // Verkle 树的空状态根
	}
	db := rawdb.NewMemoryDatabase()                                                              // 创建内存数据库
	statedb, err := state.New(emptyRoot, state.NewDatabase(triedb.NewDatabase(db, config), nil)) // 初始化状态数据库
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance), tracing.BalanceIncreaseGenesisBalance)
			// 如果有余额，添加到状态数据库
		}
		statedb.SetCode(addr, account.Code)   // 设置账户代码
		statedb.SetNonce(addr, account.Nonce) // 设置账户 Nonce
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value) // 设置账户存储
		}
	}
	return statedb.Commit(0, false) // 提交状态并返回状态根
}

// flushAlloc is very similar with hash, but the main difference is all the
// generated states will be persisted into the given database.
// flushAlloc 与 hashAlloc 非常相似，但主要区别是所有生成的状态将持久化到给定数据库中。
func flushAlloc(ga *types.GenesisAlloc, triedb *triedb.Database) (common.Hash, error) {
	emptyRoot := types.EmptyRootHash // 空状态根
	if triedb.IsVerkle() {
		emptyRoot = types.EmptyVerkleHash // Verkle 树的空状态根
	}
	statedb, err := state.New(emptyRoot, state.NewDatabase(triedb, nil)) // 初始化状态数据库
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			// This is not actually logged via tracer because OnGenesisBlock
			// already captures the allocations.
			// 这实际上不会通过追踪器记录，因为 OnGenesisBlock 已捕获分配。
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance), tracing.BalanceIncreaseGenesisBalance)
			// 如果有余额，添加到状态数据库
		}
		statedb.SetCode(addr, account.Code)   // 设置账户代码
		statedb.SetNonce(addr, account.Nonce) // 设置账户 Nonce
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value) // 设置账户存储
		}
	}
	root, err := statedb.Commit(0, false) // 提交状态并获取状态根
	if err != nil {
		return common.Hash{}, err
	}
	// Commit newly generated states into disk if it's not empty.
	// 如果状态根不为空，将新生成的状态提交到磁盘。
	if root != types.EmptyRootHash {
		if err := triedb.Commit(root, true); err != nil {
			return common.Hash{}, err
		}
	}
	return root, nil
}

func getGenesisState(db ethdb.Database, blockhash common.Hash) (alloc types.GenesisAlloc, err error) {
	blob := rawdb.ReadGenesisStateSpec(db, blockhash) // 从数据库读取创世状态规范
	if len(blob) != 0 {
		if err := alloc.UnmarshalJSON(blob); err != nil {
			return nil, err // 如果无法解析 JSON，返回错误
		}
		return alloc, nil
	}

	// Genesis allocation is missing and there are several possibilities:
	// the node is legacy which doesn't persist the genesis allocation or
	// the persisted allocation is just lost.
	// - supported networks(mainnet, testnets), recover with defined allocations
	// - private network, can't recover
	// 创世分配缺失，可能有以下几种情况：
	// 节点是旧版本，未持久化创世分配，或者持久化的分配丢失。
	// - 支持的网络（主网、测试网），使用定义的分配恢复
	// - 私有网络，无法恢复
	var genesis *Genesis
	switch blockhash {
	case params.MainnetGenesisHash:
		genesis = DefaultGenesisBlock() // 主网创世块
	case params.SepoliaGenesisHash:
		genesis = DefaultSepoliaGenesisBlock() // Sepolia 创世块
	case params.HoleskyGenesisHash:
		genesis = DefaultHoleskyGenesisBlock() // Holesky 创世块
	}
	if genesis != nil {
		return genesis.Alloc, nil // 返回预定义网络的创世分配
	}

	return nil, nil // 私有网络返回 nil
}

// field type overrides for gencodec
// 用于 gencodec 的字段类型覆盖
type genesisSpecMarshaling struct {
	Nonce         math.HexOrDecimal64                        // Nonce，支持十六进制或十进制
	Timestamp     math.HexOrDecimal64                        // 时间戳，支持十六进制或十进制
	ExtraData     hexutil.Bytes                              // 额外数据，十六进制字节
	GasLimit      math.HexOrDecimal64                        // Gas 限制，支持十六进制或十进制
	GasUsed       math.HexOrDecimal64                        // 已使用 Gas，支持十六进制或十进制
	Number        math.HexOrDecimal64                        // 块高度，支持十六进制或十进制
	Difficulty    *math.HexOrDecimal256                      // 难度，支持十六进制或十进制
	Alloc         map[common.UnprefixedAddress]types.Account // 创世分配映射
	BaseFee       *math.HexOrDecimal256                      // 基础费用，支持十六进制或十进制
	ExcessBlobGas *math.HexOrDecimal64                       // 超额 Blob Gas，支持十六进制或十进制
	BlobGasUsed   *math.HexOrDecimal64                       // 已使用 Blob Gas，支持十六进制或十进制
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
// GenesisMismatchError 在尝试用不兼容的创世块覆盖现有创世块时触发。
type GenesisMismatchError struct {
	Stored, New common.Hash // 存储的和新提供的哈希
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
	// 返回错误信息：数据库包含不兼容的创世块（现有 %x，新 %x）
}

// ChainOverrides contains the changes to chain config.
// ChainOverrides 包含对链配置的更改。
type ChainOverrides struct {
	OverrideCancun *uint64 // 覆盖 Cancun 硬分叉时间
	OverrideVerkle *uint64 // 覆盖 Verkle 硬分叉时间
}

// apply applies the chain overrides on the supplied chain config.
// apply 将链覆盖应用到提供的链配置上。
func (o *ChainOverrides) apply(cfg *params.ChainConfig) (*params.ChainConfig, error) {
	if o == nil || cfg == nil {
		return cfg, nil // 如果覆盖或配置为空，返回原配置
	}
	cpy := *cfg // 创建配置副本
	if o.OverrideCancun != nil {
		cpy.CancunTime = o.OverrideCancun // 覆盖 Cancun 时间
	}
	if o.OverrideVerkle != nil {
		cpy.VerkleTime = o.OverrideVerkle // 覆盖 Verkle 时间
	}
	if err := cpy.CheckConfigForkOrder(); err != nil {
		return nil, err // 检查分叉顺序，如果出错返回错误
	}
	return &cpy, nil // 返回修改后的配置
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// The stored chain configuration will be updated if it is compatible (i.e. does not
// specify a fork block below the local head block). In case of a conflict, the
// error is a *params.ConfigCompatError and the new, unwritten config is returned.
// SetupGenesisBlock 将创世块写入或更新到数据库中。
// 将使用的块如下：
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	数据库无创世块    |  主网默认           |  提供的 genesis
//	数据库有创世块    |  从数据库读取       |  提供的 genesis（如果兼容）
//
// 如果存储的链配置兼容（即不指定低于本地头部块的分叉块），将被更新。如果有冲突，返回 *params.ConfigCompatError 错误和新未写入的配置。
func SetupGenesisBlock(db ethdb.Database, triedb *triedb.Database, genesis *Genesis) (*params.ChainConfig, common.Hash, *params.ConfigCompatError, error) {
	return SetupGenesisBlockWithOverride(db, triedb, genesis, nil)
}

func SetupGenesisBlockWithOverride(db ethdb.Database, triedb *triedb.Database, genesis *Genesis, overrides *ChainOverrides) (*params.ChainConfig, common.Hash, *params.ConfigCompatError, error) {
	// Sanitize the supplied genesis, ensuring it has the associated chain
	// config attached.
	// 清理提供的创世块，确保其附带相关链配置。
	if genesis != nil && genesis.Config == nil {
		return nil, common.Hash{}, nil, errGenesisNoConfig // 如果没有链配置，返回错误
	}
	// Commit the genesis if the database is empty
	// 如果数据库为空，提交创世块
	ghash := rawdb.ReadCanonicalHash(db, 0) // 读取第 0 块的规范哈希
	if (ghash == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			// 写入默认主网创世块
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
			// 写入自定义创世块
		}
		chainCfg, err := overrides.apply(genesis.Config) // 应用覆盖配置
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		genesis.Config = chainCfg

		block, err := genesis.Commit(db, triedb) // 提交创世块
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return chainCfg, block.Hash(), nil, nil // 返回链配置和块哈希
	}
	// Commit the genesis if the genesis block exists in the ancient database
	// but the key-value database is empty without initializing the genesis
	// fields. This scenario can occur when the node is created from scratch
	// with an existing ancient store.
	// 如果创世块存在于旧数据库中，但键值数据库为空且未初始化创世字段，则提交创世块。
	// 这种情况可能发生在节点从头创建并具有现有旧存储时。
	storedCfg := rawdb.ReadChainConfig(db, ghash) // 读取存储的链配置
	if storedCfg == nil {
		// Ensure the stored genesis block matches with the given genesis. Private
		// networks must explicitly specify the genesis in the config file, mainnet
		// genesis will be used as default and the initialization will always fail.
		// 确保存储的创世块与给定的创世块匹配。私有网络必须在配置文件中明确指定创世块，主网创世块将作为默认值，且初始化始终失败。
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			// 写入默认主网创世块
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
			// 写入自定义创世块
		}
		chainCfg, err := overrides.apply(genesis.Config) // 应用覆盖配置
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		genesis.Config = chainCfg

		if hash := genesis.ToBlock().Hash(); hash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
			// 如果哈希不匹配，返回不兼容错误
		}
		block, err := genesis.Commit(db, triedb) // 提交创世块
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return chainCfg, block.Hash(), nil, nil // 返回链配置和块哈希
	}
	// The genesis block has already been committed previously. Verify that the
	// provided genesis with chain overrides matches the existing one, and update
	// the stored chain config if necessary.
	// 创世块之前已提交。验证提供的创世块和链覆盖与现有块匹配，并根据需要更新存储的链配置。
	if genesis != nil {
		chainCfg, err := overrides.apply(genesis.Config) // 应用覆盖配置
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		genesis.Config = chainCfg

		if hash := genesis.ToBlock().Hash(); hash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
			// 如果哈希不匹配，返回不兼容错误
		}
	}
	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	// 检查配置兼容性并写入配置。除非已在第 0 块，否则返回兼容性错误给调用者。
	head := rawdb.ReadHeadHeader(db) // 读取头部块
	if head == nil {
		return nil, common.Hash{}, nil, errors.New("missing head header")
		// 如果缺少头部块，返回错误
	}
	newCfg := genesis.chainConfigOrDefault(ghash, storedCfg) // 获取新配置或默认配置

	// TODO(rjl493456442) better to define the comparator of chain config
	// and short circuit if the chain config is not changed.
	// TODO(rjl493456442) 最好定义链配置的比较器，并在链配置未更改时短路。
	compatErr := storedCfg.CheckCompatible(newCfg, head.Number.Uint64(), head.Time) // 检查兼容性
	if compatErr != nil && ((head.Number.Uint64() != 0 && compatErr.RewindToBlock != 0) || (head.Time != 0 && compatErr.RewindToTime != 0)) {
		return newCfg, ghash, compatErr, nil // 如果不兼容，返回新配置和错误
	}
	// Don't overwrite if the old is identical to the new. It's useful
	// for the scenarios that database is opened in the read-only mode.
	// 如果旧配置与新配置相同，则不覆盖。这对于数据库以只读模式打开的场景很有用。
	storedData, _ := json.Marshal(storedCfg)
	if newData, _ := json.Marshal(newCfg); !bytes.Equal(storedData, newData) {
		rawdb.WriteChainConfig(db, ghash, newCfg) // 写入新配置
	}
	return newCfg, ghash, nil, nil // 返回配置和哈希
}

// LoadChainConfig loads the stored chain config if it is already present in
// database, otherwise, return the config in the provided genesis specification.
// LoadChainConfig 如果数据库中已有存储的链配置，则加载它，否则返回提供的创世规范中的配置。
func LoadChainConfig(db ethdb.Database, genesis *Genesis) (*params.ChainConfig, error) {
	// Load the stored chain config from the database. It can be nil
	// in case the database is empty. Notably, we only care about the
	// chain config corresponds to the canonical chain.
	// 从数据库加载存储的链配置。如果数据库为空，可能为 nil。注意，我们只关心对应规范链的链配置。
	stored := rawdb.ReadCanonicalHash(db, 0) // 读取第 0 块的规范哈希
	if stored != (common.Hash{}) {
		storedcfg := rawdb.ReadChainConfig(db, stored) // 读取链配置
		if storedcfg != nil {
			return storedcfg, nil // 如果存在，返回存储的配置
		}
	}
	// Load the config from the provided genesis specification
	// 从提供的创世规范加载配置
	if genesis != nil {
		// Reject invalid genesis spec without valid chain config
		// 拒绝没有有效链配置的无效创世规范
		if genesis.Config == nil {
			return nil, errGenesisNoConfig
		}
		// If the canonical genesis header is present, but the chain
		// config is missing(initialize the empty leveldb with an
		// external ancient chain segment), ensure the provided genesis
		// is matched.
		// 如果规范创世头部存在，但链配置缺失（用外部旧链段初始化空 leveldb），确保提供的创世块匹配。
		if stored != (common.Hash{}) && genesis.ToBlock().Hash() != stored {
			return nil, &GenesisMismatchError{stored, genesis.ToBlock().Hash()}
			// 如果哈希不匹配，返回不兼容错误
		}
		return genesis.Config, nil // 返回创世配置
	}
	// There is no stored chain config and no new config provided,
	// In this case the default chain config(mainnet) will be used
	// 没有存储的链配置且未提供新配置，在此情况下将使用默认链配置（主网）
	return params.MainnetChainConfig, nil
}

// chainConfigOrDefault retrieves the attached chain configuration. If the genesis
// object is null, it returns the default chain configuration based on the given
// genesis hash, or the locally stored config if it's not a pre-defined network.
// chainConfigOrDefault 检索附带的链配置。如果创世对象为 null，则根据给定的创世哈希返回默认链配置，如果不是预定义网络，则返回本地存储的配置。
func (g *Genesis) chainConfigOrDefault(ghash common.Hash, stored *params.ChainConfig) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config // 如果创世对象不为空，返回其配置
	case ghash == params.MainnetGenesisHash:
		return params.MainnetChainConfig // 主网配置
	case ghash == params.HoleskyGenesisHash:
		return params.HoleskyChainConfig // Holesky 配置
	case ghash == params.SepoliaGenesisHash:
		return params.SepoliaChainConfig // Sepolia 配置
	default:
		return stored // 返回存储的配置
	}
}

// IsVerkle indicates whether the state is already stored in a verkle
// tree at genesis time.
// IsVerkle 指示状态在创世时是否已存储在 Verkle 树中。
func (g *Genesis) IsVerkle() bool {
	return g.Config.IsVerkleGenesis() // 检查是否在创世时启用 Verkle
}

// ToBlock returns the genesis block according to genesis specification.
// ToBlock 根据创世规范返回创世块。
func (g *Genesis) ToBlock() *types.Block {
	root, err := hashAlloc(&g.Alloc, g.IsVerkle()) // 计算状态根
	if err != nil {
		panic(err) // 如果出错，抛出 panic
	}
	return g.toBlockWithRoot(root) // 用状态根构建创世块
}

// toBlockWithRoot constructs the genesis block with the given genesis state root.
// toBlockWithRoot 用给定的创世状态根构造创世块。
func (g *Genesis) toBlockWithRoot(root common.Hash) *types.Block {
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number), // 块高度
		Nonce:      types.EncodeNonce(g.Nonce),       // Nonce
		Time:       g.Timestamp,                      // 时间戳
		ParentHash: g.ParentHash,                     // 父块哈希
		Extra:      g.ExtraData,                      // 额外数据
		GasLimit:   g.GasLimit,                       // Gas 限制
		GasUsed:    g.GasUsed,                        // 已使用 Gas
		BaseFee:    g.BaseFee,                        // 基础费用
		Difficulty: g.Difficulty,                     // 难度
		MixDigest:  g.Mixhash,                        // 混合哈希
		Coinbase:   g.Coinbase,                       // Coinbase 地址
		Root:       root,                             // 状态根
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit // 如果 Gas 限制为 0，使用默认值
	}
	if g.Difficulty == nil && g.Mixhash == (common.Hash{}) {
		head.Difficulty = params.GenesisDifficulty // 如果难度为空且混合哈希为零，使用默认难度
	}
	if g.Config != nil && g.Config.IsLondon(common.Big0) {
		if g.BaseFee != nil {
			head.BaseFee = g.BaseFee // 设置基础费用
		} else {
			head.BaseFee = new(big.Int).SetUint64(params.InitialBaseFee) // 使用初始基础费用
		}
	}
	var (
		withdrawals []*types.Withdrawal // 提款列表
	)
	if conf := g.Config; conf != nil {
		num := big.NewInt(int64(g.Number))
		if conf.IsShanghai(num, g.Timestamp) {
			head.WithdrawalsHash = &types.EmptyWithdrawalsHash // 上海硬分叉启用提款哈希
			withdrawals = make([]*types.Withdrawal, 0)         // 初始化空提款列表
		}
		if conf.IsCancun(num, g.Timestamp) {
			// EIP-4788: The parentBeaconBlockRoot of the genesis block is always
			// the zero hash. This is because the genesis block does not have a parent
			// by definition.
			// EIP-4788：创世块的 parentBeaconBlockRoot 始终为零哈希，因为创世块按定义没有父块。
			head.ParentBeaconRoot = new(common.Hash) // 设置父信标块根为零
			// EIP-4844 fields
			// EIP-4844 字段
			head.ExcessBlobGas = g.ExcessBlobGas // 设置超额 Blob Gas
			head.BlobGasUsed = g.BlobGasUsed     // 设置已使用 Blob Gas
			if head.ExcessBlobGas == nil {
				head.ExcessBlobGas = new(uint64) // 如果未设置，初始化为 0
			}
			if head.BlobGasUsed == nil {
				head.BlobGasUsed = new(uint64) // 如果未设置，初始化为 0
			}
		}
		if conf.IsPrague(num, g.Timestamp) {
			head.RequestsHash = &types.EmptyRequestsHash // 布拉格硬分叉启用请求哈希
		}
	}
	return types.NewBlock(head, &types.Body{Withdrawals: withdrawals}, nil, trie.NewStackTrie(nil))
	// 创建并返回新块
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
// Commit 将创世规范的块和状态写入数据库。块将作为规范头部块提交。
func (g *Genesis) Commit(db ethdb.Database, triedb *triedb.Database) (*types.Block, error) {
	if g.Number != 0 {
		return nil, errors.New("can't commit genesis block with number > 0")
		// 如果块高度不为 0，返回错误
	}
	config := g.Config
	if config == nil {
		return nil, errors.New("invalid genesis without chain config")
		// 如果没有链配置，返回错误
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return nil, err // 检查分叉顺序，如果出错返回错误
	}
	if config.Clique != nil && len(g.ExtraData) < 32+crypto.SignatureLength {
		return nil, errors.New("can't start clique chain without signers")
		// 如果是 Clique 共识且缺少签名者，返回错误
	}
	// flush the data to disk and compute the state root
	// 将数据刷新到磁盘并计算状态根
	root, err := flushAlloc(&g.Alloc, triedb)
	if err != nil {
		return nil, err
	}
	block := g.toBlockWithRoot(root) // 用状态根构建创世块

	// Marshal the genesis state specification and persist.
	// 序列化创世状态规范并持久化。
	blob, err := json.Marshal(g.Alloc)
	if err != nil {
		return nil, err // 如果序列化出错，返回错误
	}
	batch := db.NewBatch()                                                    // 创建批处理
	rawdb.WriteGenesisStateSpec(batch, block.Hash(), blob)                    // 写入创世状态规范
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), block.Difficulty()) // 写入总难度
	rawdb.WriteBlock(batch, block)                                            // 写入块
	rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), nil)          // 写入空收据
	rawdb.WriteCanonicalHash(batch, block.Hash(), block.NumberU64())          // 写入规范哈希
	rawdb.WriteHeadBlockHash(batch, block.Hash())                             // 写入头部块哈希
	rawdb.WriteHeadFastBlockHash(batch, block.Hash())                         // 写入快速同步头部块哈希
	rawdb.WriteHeadHeaderHash(batch, block.Hash())                            // 写入头部块头部哈希
	rawdb.WriteChainConfig(batch, block.Hash(), config)                       // 写入链配置
	return block, batch.Write()                                               // 返回块并执行批写入
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
// MustCommit 将创世块和状态写入数据库，如果出错则抛出 panic。块将作为规范头部块提交。
func (g *Genesis) MustCommit(db ethdb.Database, triedb *triedb.Database) *types.Block {
	block, err := g.Commit(db, triedb)
	if err != nil {
		panic(err) // 如果出错，抛出 panic
	}
	return block
}

// EnableVerkleAtGenesis indicates whether the verkle fork should be activated
// at genesis. This is a temporary solution only for verkle devnet testing, where
// verkle fork is activated at genesis, and the configured activation date has
// already passed.
//
// In production networks (mainnet and public testnets), verkle activation always
// occurs after the genesis block, making this function irrelevant in those cases.
// EnableVerkleAtGenesis 指示是否应在创世时激活 Verkle 分叉。这是仅用于 Verkle 开发网测试的临时解决方案，
// 在开发网中 Verkle 分叉在创世时激活，且配置的激活日期已过去。
//
// 在生产网络（主网和公共测试网）中，Verkle 激活始终在创世块之后发生，因此此函数在这些情况下无关紧要。
func EnableVerkleAtGenesis(db ethdb.Database, genesis *Genesis) (bool, error) {
	if genesis != nil {
		if genesis.Config == nil {
			return false, errGenesisNoConfig // 如果没有链配置，返回错误
		}
		return genesis.Config.EnableVerkleAtGenesis, nil // 返回是否在创世时启用 Verkle
	}
	if ghash := rawdb.ReadCanonicalHash(db, 0); ghash != (common.Hash{}) {
		chainCfg := rawdb.ReadChainConfig(db, ghash) // 读取链配置
		if chainCfg != nil {
			return chainCfg.EnableVerkleAtGenesis, nil // 返回是否在创世时启用 Verkle
		}
	}
	return false, nil // 默认返回 false
}

// DefaultGenesisBlock returns the Ethereum main net genesis block.
// DefaultGenesisBlock 返回以太坊主网创世块。
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.MainnetChainConfig,                                                                // 主网链配置
		Nonce:      66,                                                                                       // Nonce
		ExtraData:  hexutil.MustDecode("0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"), // 额外数据
		GasLimit:   5000,                                                                                     // Gas 限制
		Difficulty: big.NewInt(17179869184),                                                                  // 难度
		Alloc:      decodePrealloc(mainnetAllocData),                                                         // 主网创世分配
	}
}

// DefaultSepoliaGenesisBlock returns the Sepolia network genesis block.
// DefaultSepoliaGenesisBlock 返回 Sepolia 网络创世块。
func DefaultSepoliaGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.SepoliaChainConfig,                  // Sepolia 链配置
		Nonce:      0,                                          // Nonce
		ExtraData:  []byte("Sepolia, Athens, Attica, Greece!"), // 额外数据
		GasLimit:   0x1c9c380,                                  // Gas 限制
		Difficulty: big.NewInt(0x20000),                        // 难度
		Timestamp:  1633267481,                                 // 时间戳
		Alloc:      decodePrealloc(sepoliaAllocData),           // Sepolia 创世分配
	}
}

// DefaultHoleskyGenesisBlock returns the Holesky network genesis block.
// DefaultHoleskyGenesisBlock 返回 Holesky 网络创世块。
func DefaultHoleskyGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.HoleskyChainConfig,        // Holesky 链配置
		Nonce:      0x1234,                           // Nonce
		GasLimit:   0x17d7840,                        // Gas 限制
		Difficulty: big.NewInt(0x01),                 // 难度
		Timestamp:  1695902100,                       // 时间戳
		Alloc:      decodePrealloc(holeskyAllocData), // Holesky 创世分配
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block.
// DeveloperGenesisBlock 返回 'geth --dev' 创世块。
func DeveloperGenesisBlock(gasLimit uint64, faucet *common.Address) *Genesis {
	// Override the default period to the user requested one
	// 将默认周期覆盖为用户请求的周期
	config := *params.AllDevChainProtocolChanges

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	// 组装并返回带有预编译合约和预资助水龙头的创世块
	genesis := &Genesis{
		Config:     &config,                           // 开发链配置
		GasLimit:   gasLimit,                          // Gas 限制
		BaseFee:    big.NewInt(params.InitialBaseFee), // 基础费用
		Difficulty: big.NewInt(0),                     // 难度
		Alloc: map[common.Address]types.Account{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			common.BytesToAddress([]byte{9}): {Balance: big.NewInt(1)}, // BLAKE2b
			// Pre-deploy system contracts
			// 预部署系统合约
			params.BeaconRootsAddress:        {Nonce: 1, Code: params.BeaconRootsCode, Balance: common.Big0},        // 信标根地址
			params.HistoryStorageAddress:     {Nonce: 1, Code: params.HistoryStorageCode, Balance: common.Big0},     // 历史存储地址
			params.WithdrawalQueueAddress:    {Nonce: 1, Code: params.WithdrawalQueueCode, Balance: common.Big0},    // 提款队列地址
			params.ConsolidationQueueAddress: {Nonce: 1, Code: params.ConsolidationQueueCode, Balance: common.Big0}, // 整合队列地址
		},
	}
	if faucet != nil {
		genesis.Alloc[*faucet] = types.Account{Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))}
		// 如果提供了水龙头地址，为其分配余额
	}
	return genesis
}

func decodePrealloc(data string) types.GenesisAlloc {
	var p []struct {
		Addr    *big.Int // 地址
		Balance *big.Int // 余额
		Misc    *struct {
			Nonce uint64 // Nonce
			Code  []byte // 代码
			Slots []struct {
				Key common.Hash // 存储键
				Val common.Hash // 存储值
			}
		} `rlp:"optional"` // 可选的杂项字段
	}
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err) // 如果解码出错，抛出 panic
	}
	ga := make(types.GenesisAlloc, len(p)) // 创建创世分配映射
	for _, account := range p {
		acc := types.Account{Balance: account.Balance} // 初始化账户
		if account.Misc != nil {
			acc.Nonce = account.Misc.Nonce // 设置 Nonce
			acc.Code = account.Misc.Code   // 设置代码

			acc.Storage = make(map[common.Hash]common.Hash) // 初始化存储
			for _, slot := range account.Misc.Slots {
				acc.Storage[slot.Key] = slot.Val // 设置存储键值对
			}
		}
		ga[common.BigToAddress(account.Addr)] = acc // 将账户添加到分配映射
	}
	return ga
}
