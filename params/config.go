// Copyright 2016 The go-ethereum Authors
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

package params

import (
	"fmt"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params/forks"
)

// Genesis hashes to enforce below configs on.
// 用于强制执行以下配置的创世哈希。
var (
	MainnetGenesisHash = common.HexToHash("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
	// 主网创世哈希
	HoleskyGenesisHash = common.HexToHash("0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4")
	// Holesky 测试网创世哈希
	SepoliaGenesisHash = common.HexToHash("0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9")
	// Sepolia 测试网创世哈希
)

func newUint64(val uint64) *uint64 { return &val }

// newUint64 创建一个指向 uint64 的指针
// newUint64 创建一个指向 uint64 的指针

var (
	MainnetTerminalTotalDifficulty, _ = new(big.Int).SetString("58_750_000_000_000_000_000_000", 0)
	// 主网终端总难度，用于触发共识升级（The Merge）

	// MainnetChainConfig is the chain parameters to run a node on the main network.
	// MainnetChainConfig 是运行主网节点的链参数。
	MainnetChainConfig = &ChainConfig{
		ChainID: big.NewInt(1),
		// 链 ID，主网为 1
		HomesteadBlock: big.NewInt(1_150_000),
		// Homestead 分叉区块号
		DAOForkBlock: big.NewInt(1_920_000),
		// DAO 分叉区块号
		DAOForkSupport: true,
		// 是否支持 DAO 分叉
		EIP150Block: big.NewInt(2_463_000),
		// EIP-150 分叉区块号
		EIP155Block: big.NewInt(2_675_000),
		// EIP-155 分叉区块号
		EIP158Block: big.NewInt(2_675_000),
		// EIP-158 分叉区块号
		ByzantiumBlock: big.NewInt(4_370_000),
		// Byzantium 分叉区块号
		ConstantinopleBlock: big.NewInt(7_280_000),
		// Constantinople 分叉区块号
		PetersburgBlock: big.NewInt(7_280_000),
		// Petersburg 分叉区块号
		IstanbulBlock: big.NewInt(9_069_000),
		// Istanbul 分叉区块号
		MuirGlacierBlock: big.NewInt(9_200_000),
		// Muir Glacier 分叉区块号
		BerlinBlock: big.NewInt(12_244_000),
		// Berlin 分叉区块号
		LondonBlock: big.NewInt(12_965_000),
		// London 分叉区块号
		ArrowGlacierBlock: big.NewInt(13_773_000),
		// Arrow Glacier 分叉区块号
		GrayGlacierBlock: big.NewInt(15_050_000),
		// Gray Glacier 分叉区块号
		TerminalTotalDifficulty: MainnetTerminalTotalDifficulty, // 58_750_000_000_000_000_000_000
		// 终端总难度，触发 The Merge
		ShanghaiTime: newUint64(1681338455),
		// Shanghai 分叉时间戳
		CancunTime: newUint64(1710338135),
		// Cancun 分叉时间戳
		DepositContractAddress: common.HexToAddress("0x00000000219ab540356cbb839cbe05303d7705fa"),
		// 存款合约地址，用于 PoS
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置
	}
	// HoleskyChainConfig contains the chain parameters to run a node on the Holesky test network.
	// HoleskyChainConfig 包含运行 Holesky 测试网节点的链参数。
	HoleskyChainConfig = &ChainConfig{
		ChainID: big.NewInt(17000),
		// 链 ID，Holesky 测试网为 17000
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: true,
		// 是否支持 DAO 分叉（默认支持，但无分叉）
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: nil,
		// Muir Glacier 分叉区块号，无此分叉
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: nil,
		// Arrow Glacier 分叉区块号，无此分叉
		GrayGlacierBlock: nil,
		// Gray Glacier 分叉区块号，无此分叉
		TerminalTotalDifficulty: big.NewInt(0),
		// 终端总难度，从创世块即为 PoS
		MergeNetsplitBlock: nil,
		// Merge 分叉区块号，无此分叉
		ShanghaiTime: newUint64(1696000704),
		// Shanghai 分叉时间戳
		CancunTime: newUint64(1707305664),
		// Cancun 分叉时间戳
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置（仅用于历史兼容）
	}
	// SepoliaChainConfig contains the chain parameters to run a node on the Sepolia test network.
	// SepoliaChainConfig 包含运行 Sepolia 测试网节点的链参数。
	SepoliaChainConfig = &ChainConfig{
		ChainID: big.NewInt(11155111),
		// 链 ID，Sepolia 测试网为 11155111
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: true,
		// 是否支持 DAO 分叉（默认支持，但无分叉）
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: nil,
		// Arrow Glacier 分叉区块号，无此分叉
		GrayGlacierBlock: nil,
		// Gray Glacier 分叉区块号，无此分叉
		TerminalTotalDifficulty: big.NewInt(17_000_000_000_000_000),
		// 终端总难度，触发 The Merge
		MergeNetsplitBlock: big.NewInt(1735371),
		// Merge 分叉区块号
		ShanghaiTime: newUint64(1677557088),
		// Shanghai 分叉时间戳
		CancunTime: newUint64(1706655072),
		// Cancun 分叉时间戳
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置（仅用于历史兼容）
	}
	// AllEthashProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Ethash consensus.
	// AllEthashProtocolChanges 包含以太坊核心开发者引入并接受的 Ethash 共识的所有协议变更（EIPs）。
	AllEthashProtocolChanges = &ChainConfig{
		ChainID: big.NewInt(1337),
		// 链 ID，测试用默认值 1337
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: false,
		// 是否支持 DAO 分叉，不支持
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: big.NewInt(0),
		// Arrow Glacier 分叉区块号，从创世块开始
		GrayGlacierBlock: big.NewInt(0),
		// Gray Glacier 分叉区块号，从创世块开始
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		// 终端总难度，设为最大值（不触发 PoS）
		MergeNetsplitBlock: nil,
		// Merge 分叉区块号，无此分叉
		ShanghaiTime: nil,
		// Shanghai 分叉时间戳，无此分叉
		CancunTime: nil,
		// Cancun 分叉时间戳，无此分叉
		PragueTime: nil,
		// Prague 分叉时间戳，无此分叉
		VerkleTime: nil,
		// Verkle 分叉时间戳，无此分叉
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置
		Clique: nil,
		// 无 Clique 共识引擎配置
	}

	AllDevChainProtocolChanges = &ChainConfig{
		ChainID: big.NewInt(1337),
		// 链 ID，开发链默认值 1337
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: big.NewInt(0),
		// Arrow Glacier 分叉区块号，从创世块开始
		GrayGlacierBlock: big.NewInt(0),
		// Gray Glacier 分叉区块号，从创世块开始
		ShanghaiTime: newUint64(0),
		// Shanghai 分叉时间戳，从创世块开始
		CancunTime: newUint64(0),
		// Cancun 分叉时间戳，从创世块开始
		TerminalTotalDifficulty: big.NewInt(0),
		// 终端总难度，从创世块即为 PoS
		PragueTime: newUint64(0),
		// Prague 分叉时间戳，从创世块开始
	}

	// AllCliqueProtocolChanges contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers into the Clique consensus.
	// AllCliqueProtocolChanges 包含以太坊核心开发者引入并接受的 Clique 共识的所有协议变更（EIPs）。
	AllCliqueProtocolChanges = &ChainConfig{
		ChainID: big.NewInt(1337),
		// 链 ID，测试用默认值 1337
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: false,
		// 是否支持 DAO 分叉，不支持
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: nil,
		// Arrow Glacier 分叉区块号，无此分叉
		GrayGlacierBlock: nil,
		// Gray Glacier 分叉区块号，无此分叉
		MergeNetsplitBlock: nil,
		// Merge 分叉区块号，无此分叉
		ShanghaiTime: nil,
		// Shanghai 分叉时间戳，无此分叉
		CancunTime: nil,
		// Cancun 分叉时间戳，无此分叉
		PragueTime: nil,
		// Prague 分叉时间戳，无此分叉
		VerkleTime: nil,
		// Verkle 分叉时间戳，无此分叉
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		// 终端总难度，设为最大值（不触发 PoS）
		Ethash: nil,
		// 无 Ethash 共识引擎配置
		Clique: &CliqueConfig{Period: 0, Epoch: 30000},
		// Clique 共识引擎配置，周期为 0，纪元长度为 30000
	}

	// TestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	// TestChainConfig 包含以太坊核心开发者为测试目的引入并接受的所有协议变更（EIPs）。
	TestChainConfig = &ChainConfig{
		ChainID: big.NewInt(1),
		// 链 ID，测试用默认值 1
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: false,
		// 是否支持 DAO 分叉，不支持
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: big.NewInt(0),
		// Arrow Glacier 分叉区块号，从创世块开始
		GrayGlacierBlock: big.NewInt(0),
		// Gray Glacier 分叉区块号，从创世块开始
		MergeNetsplitBlock: nil,
		// Merge 分叉区块号，无此分叉
		ShanghaiTime: nil,
		// Shanghai 分叉时间戳，无此分叉
		CancunTime: nil,
		// Cancun 分叉时间戳，无此分叉
		PragueTime: nil,
		// Prague 分叉时间戳，无此分叉
		VerkleTime: nil,
		// Verkle 分叉时间戳，无此分叉
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		// 终端总难度，设为最大值（不触发 PoS）
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置
		Clique: nil,
		// 无 Clique 共识引擎配置
	}

	// MergedTestChainConfig contains every protocol change (EIPs) introduced
	// and accepted by the Ethereum core developers for testing purposes.
	// MergedTestChainConfig 包含以太坊核心开发者为测试目的引入并接受的所有协议变更（EIPs）。
	MergedTestChainConfig = &ChainConfig{
		ChainID: big.NewInt(1),
		// 链 ID，测试用默认值 1
		HomesteadBlock: big.NewInt(0),
		// Homestead 分叉区块号，从创世块开始
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: false,
		// 是否支持 DAO 分叉，不支持
		EIP150Block: big.NewInt(0),
		// EIP-150 分叉区块号，从创世块开始
		EIP155Block: big.NewInt(0),
		// EIP-155 分叉区块号，从创世块开始
		EIP158Block: big.NewInt(0),
		// EIP-158 分叉区块号，从创世块开始
		ByzantiumBlock: big.NewInt(0),
		// Byzantium 分叉区块号，从创世块开始
		ConstantinopleBlock: big.NewInt(0),
		// Constantinople 分叉区块号，从创世块开始
		PetersburgBlock: big.NewInt(0),
		// Petersburg 分叉区块号，从创世块开始
		IstanbulBlock: big.NewInt(0),
		// Istanbul 分叉区块号，从创世块开始
		MuirGlacierBlock: big.NewInt(0),
		// Muir Glacier 分叉区块号，从创世块开始
		BerlinBlock: big.NewInt(0),
		// Berlin 分叉区块号，从创世块开始
		LondonBlock: big.NewInt(0),
		// London 分叉区块号，从创世块开始
		ArrowGlacierBlock: big.NewInt(0),
		// Arrow Glacier 分叉区块号，从创世块开始
		GrayGlacierBlock: big.NewInt(0),
		// Gray Glacier 分叉区块号，从创世块开始
		MergeNetsplitBlock: big.NewInt(0),
		// Merge 分叉区块号，从创世块开始
		ShanghaiTime: newUint64(0),
		// Shanghai 分叉时间戳，从创世块开始
		CancunTime: newUint64(0),
		// Cancun 分叉时间戳，从创世块开始
		PragueTime: newUint64(0),
		// Prague 分叉时间戳，从创世块开始
		VerkleTime: nil,
		// Verkle 分叉时间戳，无此分叉
		TerminalTotalDifficulty: big.NewInt(0),
		// 终端总难度，从创世块即为 PoS
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置（仅用于历史兼容）
		Clique: nil,
		// 无 Clique 共识引擎配置
	}

	// NonActivatedConfig defines the chain configuration without activating
	// any protocol change (EIPs).
	// NonActivatedConfig 定义不激活任何协议变更（EIPs）的链配置。
	NonActivatedConfig = &ChainConfig{
		ChainID: big.NewInt(1),
		// 链 ID，默认值 1
		HomesteadBlock: nil,
		// Homestead 分叉区块号，无此分叉
		DAOForkBlock: nil,
		// DAO 分叉区块号，无此分叉
		DAOForkSupport: false,
		// 是否支持 DAO 分叉，不支持
		EIP150Block: nil,
		// EIP-150 分叉区块号，无此分叉
		EIP155Block: nil,
		// EIP-155 分叉区块号，无此分叉
		EIP158Block: nil,
		// EIP-158 分叉区块号，无此分叉
		ByzantiumBlock: nil,
		// Byzantium 分叉区块号，无此分叉
		ConstantinopleBlock: nil,
		// Constantinople 分叉区块号，无此分叉
		PetersburgBlock: nil,
		// Petersburg 分叉区块号，无此分叉
		IstanbulBlock: nil,
		// Istanbul 分叉区块号，无此分叉
		MuirGlacierBlock: nil,
		// Muir Glacier 分叉区块号，无此分叉
		BerlinBlock: nil,
		// Berlin 分叉区块号，无此分叉
		LondonBlock: nil,
		// London 分叉区块号，无此分叉
		ArrowGlacierBlock: nil,
		// Arrow Glacier 分叉区块号，无此分叉
		GrayGlacierBlock: nil,
		// Gray Glacier 分叉区块号，无此分叉
		MergeNetsplitBlock: nil,
		// Merge 分叉区块号，无此分叉
		ShanghaiTime: nil,
		// Shanghai 分叉时间戳，无此分叉
		CancunTime: nil,
		// Cancun 分叉时间戳，无此分叉
		PragueTime: nil,
		// Prague 分叉时间戳，无此分叉
		VerkleTime: nil,
		// Verkle 分叉时间戳，无此分叉
		TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
		// 终端总难度，设为最大值（不触发 PoS）
		Ethash: new(EthashConfig),
		// Ethash 共识引擎配置
		Clique: nil,
		// 无 Clique 共识引擎配置
	}
	TestRules = TestChainConfig.Rules(new(big.Int), false, 0)
	// TestRules 是 TestChainConfig 的规则集
)

// NetworkNames are user friendly names to use in the chain spec banner.
// NetworkNames 是链规格横幅中使用的用户友好名称。
var NetworkNames = map[string]string{
	MainnetChainConfig.ChainID.String(): "mainnet",
	// 主网
	SepoliaChainConfig.ChainID.String(): "sepolia",
	// Sepolia 测试网
	HoleskyChainConfig.ChainID.String(): "holesky",
	// Holesky 测试网
}

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
// ChainConfig 是核心配置，决定了区块链的设置。
// ChainConfig 按区块存储在数据库中，这意味着任何由其创世块标识的网络都可以有自己的配置选项。
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // chainId identifies the current chain and is used for replay protection
	// ChainID 标识当前链，用于重放保护

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)
	// Homestead 切换区块（nil = 无分叉，0 = 已启用 Homestead）

	DAOForkBlock *big.Int `json:"daoForkBlock,omitempty"` // TheDAO hard-fork switch block (nil = no fork)
	// TheDAO 硬分叉切换区块（nil = 无分叉）
	DAOForkSupport bool `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork
	// 节点是否支持或反对 DAO 硬分叉

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	// EIP150 实现了 Gas 价格变更（https://github.com/ethereum/EIPs/issues/150）
	EIP150Block *big.Int `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	// EIP150 硬分叉区块（nil = 无分叉）
	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	// EIP155 硬分叉区块
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block
	// EIP158 硬分叉区块

	ByzantiumBlock *big.Int `json:"byzantiumBlock,omitempty"` // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	// Byzantium 切换区块（nil = 无分叉，0 = 已启用 Byzantium）
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)
	// Constantinople 切换区块（nil = 无分叉，0 = 已激活）
	PetersburgBlock *big.Int `json:"petersburgBlock,omitempty"` // Petersburg switch block (nil = same as Constantinople)
	// Petersburg 切换区块（nil = 与 Constantinople 相同）
	IstanbulBlock *big.Int `json:"istanbulBlock,omitempty"` // Istanbul switch block (nil = no fork, 0 = already on istanbul)
	// Istanbul 切换区块（nil = 无分叉，0 = 已启用 Istanbul）
	MuirGlacierBlock *big.Int `json:"muirGlacierBlock,omitempty"` // Eip-2384 (bomb delay) switch block (nil = no fork, 0 = already activated)
	// EIP-2384（难度炸弹延迟）切换区块（nil = 无分叉，0 = 已激活）
	BerlinBlock *big.Int `json:"berlinBlock,omitempty"` // Berlin switch block (nil = no fork, 0 = already on berlin)
	// Berlin 切换区块（nil = 无分叉，0 = 已启用 Berlin）
	LondonBlock *big.Int `json:"londonBlock,omitempty"` // London switch block (nil = no fork, 0 = already on london)
	// London 切换区块（nil = 无分叉，0 = 已启用 London）
	ArrowGlacierBlock *big.Int `json:"arrowGlacierBlock,omitempty"` // Eip-4345 (bomb delay) switch block (nil = no fork, 0 = already activated)
	// EIP-4345（难度炸弹延迟）切换区块（nil = 无分叉，0 = 已激活）
	GrayGlacierBlock *big.Int `json:"grayGlacierBlock,omitempty"` // Eip-5133 (bomb delay) switch block (nil = no fork, 0 = already activated)
	// EIP-5133（难度炸弹延迟）切换区块（nil = 无分叉，0 = 已激活）
	MergeNetsplitBlock *big.Int `json:"mergeNetsplitBlock,omitempty"` // Virtual fork after The Merge to use as a network splitter
	// The Merge 后的虚拟分叉，用于网络分割

	// Fork scheduling was switched from blocks to timestamps here
	// 分叉调度从此处由区块切换为时间戳

	ShanghaiTime *uint64 `json:"shanghaiTime,omitempty"` // Shanghai switch time (nil = no fork, 0 = already on shanghai)
	// Shanghai 切换时间（nil = 无分叉，0 = 已启用 Shanghai）
	CancunTime *uint64 `json:"cancunTime,omitempty"` // Cancun switch time (nil = no fork, 0 = already on cancun)
	// Cancun 切换时间（nil = 无分叉，0 = 已启用 Cancun）
	PragueTime *uint64 `json:"pragueTime,omitempty"` // Prague switch time (nil = no fork, 0 = already on prague)
	// Prague 切换时间（nil = 无分叉，0 = 已启用 Prague）
	VerkleTime *uint64 `json:"verkleTime,omitempty"` // Verkle switch time (nil = no fork, 0 = already on verkle)
	// Verkle 切换时间（nil = 无分叉，0 = 已启用 Verkle）

	// TerminalTotalDifficulty is the amount of total difficulty reached by
	// the network that triggers the consensus upgrade.
	// TerminalTotalDifficulty 是网络达到的总难度，触发共识升级。
	TerminalTotalDifficulty *big.Int `json:"terminalTotalDifficulty,omitempty"`

	DepositContractAddress common.Address `json:"depositContractAddress,omitempty"`
	// 存款合约地址

	// EnableVerkleAtGenesis is a flag that specifies whether the network uses
	// the Verkle tree starting from the genesis block. If set to true, the
	// genesis state will be committed using the Verkle tree, eliminating the
	// need for any Verkle transition later.
	//
	// This is a temporary flag only for verkle devnet testing, where verkle is
	// activated at genesis, and the configured activation date has already passed.
	//
	// In production networks (mainnet and public testnets), verkle activation
	// always occurs after the genesis block, making this flag irrelevant in
	// those cases.
	// EnableVerkleAtGenesis 是一个标志，指定网络是否从创世块开始使用 Verkle 树。
	// 如果设置为 true，创世状态将使用 Verkle 树提交，无需后续 Verkle 转换。
	//
	// 这是一个仅用于 Verkle 开发网测试的临时标志，其中 Verkle 在创世块激活，
	// 配置的激活日期已过去。
	//
	// 在生产网络（主网和公共测试网）中，Verkle 激活总是在创世块之后发生，
	// 因此此标志在这些情况下无关紧要。
	EnableVerkleAtGenesis bool `json:"enableVerkleAtGenesis,omitempty"`

	// Various consensus engines
	// 各种共识引擎
	Ethash *EthashConfig `json:"ethash,omitempty"`
	// Ethash 共识引擎配置
	Clique *CliqueConfig `json:"clique,omitempty"`
	// Clique 共识引擎配置
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
// EthashConfig 是基于工作量证明的密封的共识引擎配置。
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
// String 实现了 stringer 接口，返回共识引擎详情。
func (c EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
// CliqueConfig 是基于权威证明的密封的共识引擎配置。
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	// 区块之间的秒数，用于强制执行
	Epoch uint64 `json:"epoch"` // Epoch length to reset votes and checkpoint
	// 重置投票和检查点的纪元长度
}

// String implements the stringer interface, returning the consensus engine details.
// String 实现了 stringer 接口，返回共识引擎详情。
func (c CliqueConfig) String() string {
	return fmt.Sprintf("clique(period: %d, epoch: %d)", c.Period, c.Epoch)
}

// Description returns a human-readable description of ChainConfig.
// Description 返回 ChainConfig 的可读描述。
func (c *ChainConfig) Description() string {
	var banner string

	// Create some basic network config output
	// 创建一些基本的网络配置输出
	network := NetworkNames[c.ChainID.String()]
	if network == "" {
		network = "unknown"
	}
	banner += fmt.Sprintf("Chain ID:  %v (%s)\n", c.ChainID, network)
	switch {
	case c.Ethash != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Ethash (proof-of-work)\n"
		// 共识：Beacon（权益证明），从 Ethash（工作量证明）合并
	case c.Clique != nil:
		banner += "Consensus: Beacon (proof-of-stake), merged from Clique (proof-of-authority)\n"
		// 共识：Beacon（权益证明），从 Clique（权威证明）合并
	default:
		banner += "Consensus: unknown\n"
		// 共识：未知
	}
	banner += "\n"

	// Create a list of forks with a short description of them. Forks that only
	// makes sense for mainnet should be optional at printing to avoid bloating
	// the output for testnets and private networks.
	// 创建一个分叉列表及其简短描述。仅对主网有意义的分叉在打印时应可选，以避免测试网和私有网络的输出冗长。
	banner += "Pre-Merge hard forks (block based):\n"
	// Merge 前的硬分叉（基于区块）
	banner += fmt.Sprintf(" - Homestead:                   #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/homestead.md)\n", c.HomesteadBlock)
	if c.DAOForkBlock != nil {
		banner += fmt.Sprintf(" - DAO Fork:                    #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/dao-fork.md)\n", c.DAOForkBlock)
	}
	banner += fmt.Sprintf(" - Tangerine Whistle (EIP 150): #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/tangerine-whistle.md)\n", c.EIP150Block)
	banner += fmt.Sprintf(" - Spurious Dragon/1 (EIP 155): #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md)\n", c.EIP155Block)
	banner += fmt.Sprintf(" - Spurious Dragon/2 (EIP 158): #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/spurious-dragon.md)\n", c.EIP155Block)
	banner += fmt.Sprintf(" - Byzantium:                   #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/byzantium.md)\n", c.ByzantiumBlock)
	banner += fmt.Sprintf(" - Constantinople:              #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/constantinople.md)\n", c.ConstantinopleBlock)
	banner += fmt.Sprintf(" - Petersburg:                  #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/petersburg.md)\n", c.PetersburgBlock)
	banner += fmt.Sprintf(" - Istanbul:                    #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/istanbul.md)\n", c.IstanbulBlock)
	if c.MuirGlacierBlock != nil {
		banner += fmt.Sprintf(" - Muir Glacier:                #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/muir-glacier.md)\n", c.MuirGlacierBlock)
	}
	banner += fmt.Sprintf(" - Berlin:                      #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md)\n", c.BerlinBlock)
	banner += fmt.Sprintf(" - London:                      #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/london.md)\n", c.LondonBlock)
	if c.ArrowGlacierBlock != nil {
		banner += fmt.Sprintf(" - Arrow Glacier:               #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/arrow-glacier.md)\n", c.ArrowGlacierBlock)
	}
	if c.GrayGlacierBlock != nil {
		banner += fmt.Sprintf(" - Gray Glacier:                #%-8v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/gray-glacier.md)\n", c.GrayGlacierBlock)
	}
	banner += "\n"

	// Add a special section for the merge as it's non-obvious
	// 为 Merge 添加特殊部分，因为它并不明显
	banner += "Merge configured:\n"
	// Merge 配置
	banner += " - Hard-fork specification:    https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/paris.md\n"
	banner += " - Network known to be merged\n"
	banner += fmt.Sprintf(" - Total terminal difficulty:  %v\n", c.TerminalTotalDifficulty)
	if c.MergeNetsplitBlock != nil {
		banner += fmt.Sprintf(" - Merge netsplit block:       #%-8v\n", c.MergeNetsplitBlock)
	}
	banner += "\n"

	// Create a list of forks post-merge
	// 创建 Merge 后的分叉列表
	banner += "Post-Merge hard forks (timestamp based):\n"
	// Merge 后的硬分叉（基于时间戳）
	if c.ShanghaiTime != nil {
		banner += fmt.Sprintf(" - Shanghai:                    @%-10v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/shanghai.md)\n", *c.ShanghaiTime)
	}
	if c.CancunTime != nil {
		banner += fmt.Sprintf(" - Cancun:                      @%-10v (https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/cancun.md)\n", *c.CancunTime)
	}
	if c.PragueTime != nil {
		banner += fmt.Sprintf(" - Prague:                      @%-10v\n", *c.PragueTime)
	}
	if c.VerkleTime != nil {
		banner += fmt.Sprintf(" - Verkle:                      @%-10v\n", *c.VerkleTime)
	}
	return banner
}

// IsHomestead returns whether num is either equal to the homestead block or greater.
// IsHomestead 返回 num 是否等于或大于 Homestead 区块。
func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isBlockForked(c.HomesteadBlock, num)
}

// IsDAOFork returns whether num is either equal to the DAO fork block or greater.
// IsDAOFork 返回 num 是否等于或大于 DAO 分叉区块。
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isBlockForked(c.DAOForkBlock, num)
}

// IsEIP150 returns whether num is either equal to the EIP150 fork block or greater.
// IsEIP150 返回 num 是否等于或大于 EIP150 分叉区块。
func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isBlockForked(c.EIP150Block, num)
}

// IsEIP155 returns whether num is either equal to the EIP155 fork block or greater.
// IsEIP155 返回 num 是否等于或大于 EIP155 分叉区块。
func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isBlockForked(c.EIP155Block, num)
}

// IsEIP158 returns whether num is either equal to the EIP158 fork block or greater.
// IsEIP158 返回 num 是否等于或大于 EIP158 分叉区块。
func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isBlockForked(c.EIP158Block, num)
}

// IsByzantium returns whether num is either equal to the Byzantium fork block or greater.
// IsByzantium 返回 num 是否等于或大于 Byzantium 分叉区块。
func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isBlockForked(c.ByzantiumBlock, num)
}

// IsConstantinople returns whether num is either equal to the Constantinople fork block or greater.
// IsConstantinople 返回 num 是否等于或大于 Constantinople 分叉区块。
func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isBlockForked(c.ConstantinopleBlock, num)
}

// IsMuirGlacier returns whether num is either equal to the Muir Glacier (EIP-2384) fork block or greater.
// IsMuirGlacier 返回 num 是否等于或大于 Muir Glacier（EIP-2384）分叉区块。
func (c *ChainConfig) IsMuirGlacier(num *big.Int) bool {
	return isBlockForked(c.MuirGlacierBlock, num)
}

// IsPetersburg returns whether num is either
// - equal to or greater than the PetersburgBlock fork block,
// - OR is nil, and Constantinople is active
// IsPetersburg 返回 num 是否满足以下任一条件：
// - 等于或大于 Petersburg 分叉区块，
// - 或为 nil，且 Constantinople 已激活
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isBlockForked(c.PetersburgBlock, num) || c.PetersburgBlock == nil && isBlockForked(c.ConstantinopleBlock, num)
}

// IsIstanbul returns whether num is either equal to the Istanbul fork block or greater.
// IsIstanbul 返回 num 是否等于或大于 Istanbul 分叉区块。
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isBlockForked(c.IstanbulBlock, num)
}

// IsBerlin returns whether num is either equal to the Berlin fork block or greater.
// IsBerlin 返回 num 是否等于或大于 Berlin 分叉区块。
func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	return isBlockForked(c.BerlinBlock, num)
}

// IsLondon returns whether num is either equal to the London fork block or greater.
// IsLondon 返回 num 是否等于或大于 London 分叉区块。
func (c *ChainConfig) IsLondon(num *big.Int) bool {
	return isBlockForked(c.LondonBlock, num)
}

// IsArrowGlacier returns whether num is either equal to the Arrow Glacier (EIP-4345) fork block or greater.
// IsArrowGlacier 返回 num 是否等于或大于 Arrow Glacier（EIP-4345）分叉区块。
func (c *ChainConfig) IsArrowGlacier(num *big.Int) bool {
	return isBlockForked(c.ArrowGlacierBlock, num)
}

// IsGrayGlacier returns whether num is either equal to the Gray Glacier (EIP-5133) fork block or greater.
// IsGrayGlacier 返回 num 是否等于或大于 Gray Glacier（EIP-5133）分叉区块。
func (c *ChainConfig) IsGrayGlacier(num *big.Int) bool {
	return isBlockForked(c.GrayGlacierBlock, num)
}

// IsTerminalPoWBlock returns whether the given block is the last block of PoW stage.
// IsTerminalPoWBlock 返回给定区块是否为 PoW 阶段的最后一个区块。
func (c *ChainConfig) IsTerminalPoWBlock(parentTotalDiff *big.Int, totalDiff *big.Int) bool {
	if c.TerminalTotalDifficulty == nil {
		return false
	}
	return parentTotalDiff.Cmp(c.TerminalTotalDifficulty) < 0 && totalDiff.Cmp(c.TerminalTotalDifficulty) >= 0
}

// IsShanghai returns whether time is either equal to the Shanghai fork time or greater.
// IsShanghai 返回时间是否等于或大于 Shanghai 分叉时间。
func (c *ChainConfig) IsShanghai(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.ShanghaiTime, time)
}

// IsCancun returns whether time is either equal to the Cancun fork time or greater.
// IsCancun 返回时间是否等于或大于 Cancun 分叉时间。
func (c *ChainConfig) IsCancun(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.CancunTime, time)
}

// IsPrague returns whether time is either equal to the Prague fork time or greater.
// IsPrague 返回时间是否等于或大于 Prague 分叉时间。
func (c *ChainConfig) IsPrague(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.PragueTime, time)
}

// IsVerkle returns whether time is either equal to the Verkle fork time or greater.
// IsVerkle 返回时间是否等于或大于 Verkle 分叉时间。
func (c *ChainConfig) IsVerkle(num *big.Int, time uint64) bool {
	return c.IsLondon(num) && isTimestampForked(c.VerkleTime, time)
}

// IsVerkleGenesis checks whether the verkle fork is activated at the genesis block.
//
// Verkle mode is considered enabled if the verkle fork time is configured,
// regardless of whether the local time has surpassed the fork activation time.
// This is a temporary workaround for verkle devnet testing, where verkle is
// activated at genesis, and the configured activation date has already passed.
//
// In production networks (mainnet and public testnets), verkle activation
// always occurs after the genesis block, making this function irrelevant in
// those cases.
// IsVerkleGenesis 检查 Verkle 分叉是否在创世块激活。
//
// 如果 Verkle 分叉时间已配置，则认为 Verkle 模式已启用，无论本地时间是否超过分叉激活时间。
// 这是 Verkle 开发网测试的临时解决方法，其中 Verkle 在创世块激活，且配置的激活日期已过去。
//
// 在生产网络（主网和公共测试网）中，Verkle 激活总是在创世块之后发生，因此此函数在这些情况下无关紧要。
func (c *ChainConfig) IsVerkleGenesis() bool {
	return c.EnableVerkleAtGenesis
}

// IsEIP4762 returns whether eip 4762 has been activated at given block.
// IsEIP4762 返回给定区块是否已激活 EIP-4762。
func (c *ChainConfig) IsEIP4762(num *big.Int, time uint64) bool {
	return c.IsVerkle(num, time)
}

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
// CheckCompatible 检查预定的分叉转换是否因链配置不匹配而被导入。
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64, time uint64) *ConfigCompatError {
	var (
		bhead = new(big.Int).SetUint64(height)
		btime = time
	)
	// Iterate checkCompatible to find the lowest conflict.
	// 迭代 checkCompatible 以找到最低冲突。
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead, btime)
		if err == nil || (lasterr != nil && err.RewindToBlock == lasterr.RewindToBlock && err.RewindToTime == lasterr.RewindToTime) {
			break
		}
		lasterr = err

		if err.RewindToTime > 0 {
			btime = err.RewindToTime
		} else {
			bhead.SetUint64(err.RewindToBlock)
		}
	}
	return lasterr
}

// CheckConfigForkOrder checks that we don't "skip" any forks, geth isn't pluggable enough
// to guarantee that forks can be implemented in a different order than on official networks
// CheckConfigForkOrder 检查我们没有“跳过”任何分叉，geth 的可插拔性不足以保证分叉可以按官方网络以外的顺序实现。
func (c *ChainConfig) CheckConfigForkOrder() error {
	type fork struct {
		name  string
		block *big.Int // forks up to - and including the merge - were defined with block numbers
		// 到 Merge 之前（包括 Merge）的分叉使用区块号定义
		timestamp *uint64 // forks after the merge are scheduled using timestamps
		// Merge 后的分叉使用时间戳调度
		optional bool // if true, the fork may be nil and next fork is still allowed
		// 如果为 true，分叉可以为 nil，且下一个分叉仍然允许
	}
	var lastFork fork
	for _, cur := range []fork{
		{name: "homesteadBlock", block: c.HomesteadBlock},
		{name: "daoForkBlock", block: c.DAOForkBlock, optional: true},
		{name: "eip150Block", block: c.EIP150Block},
		{name: "eip155Block", block: c.EIP155Block},
		{name: "eip158Block", block: c.EIP158Block},
		{name: "byzantiumBlock", block: c.ByzantiumBlock},
		{name: "constantinopleBlock", block: c.ConstantinopleBlock},
		{name: "petersburgBlock", block: c.PetersburgBlock},
		{name: "istanbulBlock", block: c.IstanbulBlock},
		{name: "muirGlacierBlock", block: c.MuirGlacierBlock, optional: true},
		{name: "berlinBlock", block: c.BerlinBlock},
		{name: "londonBlock", block: c.LondonBlock},
		{name: "arrowGlacierBlock", block: c.ArrowGlacierBlock, optional: true},
		{name: "grayGlacierBlock", block: c.GrayGlacierBlock, optional: true},
		{name: "mergeNetsplitBlock", block: c.MergeNetsplitBlock, optional: true},
		{name: "shanghaiTime", timestamp: c.ShanghaiTime},
		{name: "cancunTime", timestamp: c.CancunTime, optional: true},
		{name: "pragueTime", timestamp: c.PragueTime, optional: true},
		{name: "verkleTime", timestamp: c.VerkleTime, optional: true},
	} {
		if lastFork.name != "" {
			switch {
			// Non-optional forks must all be present in the chain config up to the last defined fork
			// 非可选分叉必须在链配置中全部存在，直到最后一个定义的分叉
			case lastFork.block == nil && lastFork.timestamp == nil && (cur.block != nil || cur.timestamp != nil):
				if cur.block != nil {
					return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at block %v",
						lastFork.name, cur.name, cur.block)
				} else {
					return fmt.Errorf("unsupported fork ordering: %v not enabled, but %v enabled at timestamp %v",
						lastFork.name, cur.name, *cur.timestamp)
				}

			// Fork (whether defined by block or timestamp) must follow the fork definition sequence
			// 分叉（无论是区块还是时间戳定义）必须遵循分叉定义顺序
			case (lastFork.block != nil && cur.block != nil) || (lastFork.timestamp != nil && cur.timestamp != nil):
				if lastFork.block != nil && lastFork.block.Cmp(cur.block) > 0 {
					return fmt.Errorf("unsupported fork ordering: %v enabled at block %v, but %v enabled at block %v",
						lastFork.name, lastFork.block, cur.name, cur.block)
				} else if lastFork.timestamp != nil && *lastFork.timestamp > *cur.timestamp {
					return fmt.Errorf("unsupported fork ordering: %v enabled at timestamp %v, but %v enabled at timestamp %v",
						lastFork.name, *lastFork.timestamp, cur.name, *cur.timestamp)
				}

				// Timestamp based forks can follow block based ones, but not the other way around
				// 基于时间戳的分叉可以跟在基于区块的分叉之后，但反之不行
				if lastFork.timestamp != nil && cur.block != nil {
					return fmt.Errorf("unsupported fork ordering: %v used timestamp ordering, but %v reverted to block ordering",
						lastFork.name, cur.name)
				}
			}
		}
		// If it was optional and not set, then ignore it
		// 如果它是可选的且未设置，则忽略它
		if !cur.optional || (cur.block != nil || cur.timestamp != nil) {
			lastFork = cur
		}
	}
	return nil
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, headNumber *big.Int, headTimestamp uint64) *ConfigCompatError {
	if isForkBlockIncompatible(c.HomesteadBlock, newcfg.HomesteadBlock, headNumber) {
		return newBlockCompatError("Homestead fork block", c.HomesteadBlock, newcfg.HomesteadBlock)
	}
	if isForkBlockIncompatible(c.DAOForkBlock, newcfg.DAOForkBlock, headNumber) {
		return newBlockCompatError("DAO fork block", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if c.IsDAOFork(headNumber) && c.DAOForkSupport != newcfg.DAOForkSupport {
		return newBlockCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if isForkBlockIncompatible(c.EIP150Block, newcfg.EIP150Block, headNumber) {
		return newBlockCompatError("EIP150 fork block", c.EIP150Block, newcfg.EIP150Block)
	}
	if isForkBlockIncompatible(c.EIP155Block, newcfg.EIP155Block, headNumber) {
		return newBlockCompatError("EIP155 fork block", c.EIP155Block, newcfg.EIP155Block)
	}
	if isForkBlockIncompatible(c.EIP158Block, newcfg.EIP158Block, headNumber) {
		return newBlockCompatError("EIP158 fork block", c.EIP158Block, newcfg.EIP158Block)
	}
	if c.IsEIP158(headNumber) && !configBlockEqual(c.ChainID, newcfg.ChainID) {
		return newBlockCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
	}
	if isForkBlockIncompatible(c.ByzantiumBlock, newcfg.ByzantiumBlock, headNumber) {
		return newBlockCompatError("Byzantium fork block", c.ByzantiumBlock, newcfg.ByzantiumBlock)
	}
	if isForkBlockIncompatible(c.ConstantinopleBlock, newcfg.ConstantinopleBlock, headNumber) {
		return newBlockCompatError("Constantinople fork block", c.ConstantinopleBlock, newcfg.ConstantinopleBlock)
	}
	if isForkBlockIncompatible(c.PetersburgBlock, newcfg.PetersburgBlock, headNumber) {
		// the only case where we allow Petersburg to be set in the past is if it is equal to Constantinople
		// mainly to satisfy fork ordering requirements which state that Petersburg fork be set if Constantinople fork is set
		if isForkBlockIncompatible(c.ConstantinopleBlock, newcfg.PetersburgBlock, headNumber) {
			return newBlockCompatError("Petersburg fork block", c.PetersburgBlock, newcfg.PetersburgBlock)
		}
	}
	if isForkBlockIncompatible(c.IstanbulBlock, newcfg.IstanbulBlock, headNumber) {
		return newBlockCompatError("Istanbul fork block", c.IstanbulBlock, newcfg.IstanbulBlock)
	}
	if isForkBlockIncompatible(c.MuirGlacierBlock, newcfg.MuirGlacierBlock, headNumber) {
		return newBlockCompatError("Muir Glacier fork block", c.MuirGlacierBlock, newcfg.MuirGlacierBlock)
	}
	if isForkBlockIncompatible(c.BerlinBlock, newcfg.BerlinBlock, headNumber) {
		return newBlockCompatError("Berlin fork block", c.BerlinBlock, newcfg.BerlinBlock)
	}
	if isForkBlockIncompatible(c.LondonBlock, newcfg.LondonBlock, headNumber) {
		return newBlockCompatError("London fork block", c.LondonBlock, newcfg.LondonBlock)
	}
	if isForkBlockIncompatible(c.ArrowGlacierBlock, newcfg.ArrowGlacierBlock, headNumber) {
		return newBlockCompatError("Arrow Glacier fork block", c.ArrowGlacierBlock, newcfg.ArrowGlacierBlock)
	}
	if isForkBlockIncompatible(c.GrayGlacierBlock, newcfg.GrayGlacierBlock, headNumber) {
		return newBlockCompatError("Gray Glacier fork block", c.GrayGlacierBlock, newcfg.GrayGlacierBlock)
	}
	if isForkBlockIncompatible(c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock, headNumber) {
		return newBlockCompatError("Merge netsplit fork block", c.MergeNetsplitBlock, newcfg.MergeNetsplitBlock)
	}
	if isForkTimestampIncompatible(c.ShanghaiTime, newcfg.ShanghaiTime, headTimestamp) {
		return newTimestampCompatError("Shanghai fork timestamp", c.ShanghaiTime, newcfg.ShanghaiTime)
	}
	if isForkTimestampIncompatible(c.CancunTime, newcfg.CancunTime, headTimestamp) {
		return newTimestampCompatError("Cancun fork timestamp", c.CancunTime, newcfg.CancunTime)
	}
	if isForkTimestampIncompatible(c.PragueTime, newcfg.PragueTime, headTimestamp) {
		return newTimestampCompatError("Prague fork timestamp", c.PragueTime, newcfg.PragueTime)
	}
	if isForkTimestampIncompatible(c.VerkleTime, newcfg.VerkleTime, headTimestamp) {
		return newTimestampCompatError("Verkle fork timestamp", c.VerkleTime, newcfg.VerkleTime)
	}
	return nil
}

// BaseFeeChangeDenominator bounds the amount the base fee can change between blocks.
// BaseFeeChangeDenominator 限制基础费用在区块之间的变化量。
func (c *ChainConfig) BaseFeeChangeDenominator() uint64 {
	return DefaultBaseFeeChangeDenominator
}

// ElasticityMultiplier bounds the maximum gas limit an EIP-1559 block may have.
// ElasticityMultiplier 限制 EIP-1559 区块的最大 Gas 限制。
func (c *ChainConfig) ElasticityMultiplier() uint64 {
	return DefaultElasticityMultiplier
}

// LatestFork returns the latest time-based fork that would be active for the given time.
// LatestFork 返回给定时间的最新基于时间戳的分叉。
func (c *ChainConfig) LatestFork(time uint64) forks.Fork {
	// Assume last non-time-based fork has passed.
	// 假设最后一个非基于时间戳的分叉已通过。
	london := c.LondonBlock

	switch {
	case c.IsPrague(london, time):
		return forks.Prague
	case c.IsCancun(london, time):
		return forks.Cancun
	case c.IsShanghai(london, time):
		return forks.Shanghai
	default:
		return forks.Paris
	}
}

// isForkBlockIncompatible returns true if a fork scheduled at block s1 cannot be
// rescheduled to block s2 because head is already past the fork.
// isForkBlockIncompatible 如果在区块 s1 计划的分叉无法重新调度到区块 s2，因为头区块已超过分叉，则返回 true。
func isForkBlockIncompatible(s1, s2, head *big.Int) bool {
	return (isBlockForked(s1, head) || isBlockForked(s2, head)) && !configBlockEqual(s1, s2)
}

// isBlockForked returns whether a fork scheduled at block s is active at the
// given head block. Whilst this method is the same as isTimestampForked, they
// are explicitly separate for clearer reading.
// isBlockForked 返回在区块 s 计划的分叉是否在给定的头区块激活。虽然此方法与 isTimestampForked 相同，但为清晰起见明确分开。
func isBlockForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

func configBlockEqual(x, y *big.Int) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return x.Cmp(y) == 0
}

// isForkTimestampIncompatible returns true if a fork scheduled at timestamp s1
// cannot be rescheduled to timestamp s2 because head is already past the fork.
// isForkTimestampIncompatible 如果在时间戳 s1 计划的分叉无法重新调度到时间戳 s2，因为头时间戳已超过分叉，则返回 true。
func isForkTimestampIncompatible(s1, s2 *uint64, head uint64) bool {
	return (isTimestampForked(s1, head) || isTimestampForked(s2, head)) && !configTimestampEqual(s1, s2)
}

// isTimestampForked returns whether a fork scheduled at timestamp s is active
// at the given head timestamp. Whilst this method is the same as isBlockForked,
// they are explicitly separate for clearer reading.
// isTimestampForked 返回在时间戳 s 计划的分叉是否在给定的头时间戳激活。虽然此方法与 isBlockForked 相同，但为清晰起见明确分开。
func isTimestampForked(s *uint64, head uint64) bool {
	if s == nil {
		return false
	}
	return *s <= head
}

func configTimestampEqual(x, y *uint64) bool {
	if x == nil {
		return y == nil
	}
	if y == nil {
		return x == nil
	}
	return *x == *y
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
// ConfigCompatError 如果本地存储的区块链使用会改变过去的 ChainConfig 初始化，则抛出此错误。
type ConfigCompatError struct {
	What string

	// block numbers of the stored and new configurations if block based forking
	// 如果基于区块分叉，存储和新配置的区块号
	StoredBlock, NewBlock *big.Int

	// timestamps of the stored and new configurations if time based forking
	// 如果基于时间戳分叉，存储和新配置的时间戳
	StoredTime, NewTime *uint64

	// the block number to which the local chain must be rewound to correct the error
	// 本地链必须回滚到的区块号以纠正错误
	RewindToBlock uint64

	// the timestamp to which the local chain must be rewound to correct the error
	// 本地链必须回滚到的时间戳以纠正错误
	RewindToTime uint64
}

func newBlockCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{
		What:          what,
		StoredBlock:   storedblock,
		NewBlock:      newblock,
		RewindToBlock: 0,
	}
	if rew != nil && rew.Sign() > 0 {
		err.RewindToBlock = rew.Uint64() - 1
	}
	return err
}

func newTimestampCompatError(what string, storedtime, newtime *uint64) *ConfigCompatError {
	var rew *uint64
	switch {
	case storedtime == nil:
		rew = newtime
	case newtime == nil || *storedtime < *newtime:
		rew = storedtime
	default:
		rew = newtime
	}
	err := &ConfigCompatError{
		What:         what,
		StoredTime:   storedtime,
		NewTime:      newtime,
		RewindToTime: 0,
	}
	if rew != nil && *rew != 0 {
		err.RewindToTime = *rew - 1
	}
	return err
}

func (err *ConfigCompatError) Error() string {
	if err.StoredBlock != nil {
		return fmt.Sprintf("mismatching %s in database (have block %d, want block %d, rewindto block %d)", err.What, err.StoredBlock, err.NewBlock, err.RewindToBlock)
	}

	if err.StoredTime == nil && err.NewTime == nil {
		return ""
	} else if err.StoredTime == nil && err.NewTime != nil {
		return fmt.Sprintf("mismatching %s in database (have timestamp nil, want timestamp %d, rewindto timestamp %d)", err.What, *err.NewTime, err.RewindToTime)
	} else if err.StoredTime != nil && err.NewTime == nil {
		return fmt.Sprintf("mismatching %s in database (have timestamp %d, want timestamp nil, rewindto timestamp %d)", err.What, *err.StoredTime, err.RewindToTime)
	}
	return fmt.Sprintf("mismatching %s in database (have timestamp %d, want timestamp %d, rewindto timestamp %d)", err.What, *err.StoredTime, *err.NewTime, err.RewindToTime)
}

// Rules wraps ChainConfig and is merely syntactic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
// phases.
// Rules 封装了 ChainConfig，仅为语法糖，或可用于不需要区块信息的函数。
//
// Rules 是一次性接口，意味着它不应在过渡阶段之间使用。
type Rules struct {
	ChainID                                                 *big.Int
	IsHomestead, IsEIP150, IsEIP155, IsEIP158               bool
	IsEIP2929, IsEIP4762                                    bool
	IsByzantium, IsConstantinople, IsPetersburg, IsIstanbul bool
	IsBerlin, IsLondon                                      bool
	IsMerge, IsShanghai, IsCancun, IsPrague                 bool
	IsVerkle                                                bool
}

// Rules ensures c's ChainID is not nil.
// Rules 确保 c 的 ChainID 不为 nil。
func (c *ChainConfig) Rules(num *big.Int, isMerge bool, timestamp uint64) Rules {
	chainID := c.ChainID
	if chainID == nil {
		chainID = new(big.Int)
	}
	// disallow setting Merge out of order
	// 禁止无序设置 Merge
	isMerge = isMerge && c.IsLondon(num)
	isVerkle := isMerge && c.IsVerkle(num, timestamp)
	return Rules{
		ChainID:          new(big.Int).Set(chainID),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsBerlin:         c.IsBerlin(num),
		IsEIP2929:        c.IsBerlin(num) && !isVerkle,
		IsLondon:         c.IsLondon(num),
		IsMerge:          isMerge,
		IsShanghai:       isMerge && c.IsShanghai(num, timestamp),
		IsCancun:         isMerge && c.IsCancun(num, timestamp),
		IsPrague:         isMerge && c.IsPrague(num, timestamp),
		IsVerkle:         isVerkle,
		IsEIP4762:        isVerkle,
	}
}
