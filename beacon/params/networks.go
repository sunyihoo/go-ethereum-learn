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
	"github.com/ethereum/go-ethereum/common"
)

//MainnetLightConfig: 这是以太坊主网的轻客户端配置。主网是主要的、实际价值转移发生的以太坊网络。
//ChainConfig: 这是一个结构体（在代码中未给出定义，但可以推测其用途），用于存储链的配置参数。在这里，它通过链式调用 AddFork 方法来构建配置。
//GenesisValidatorsRoot: common.HexToHash("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")。这是信标链创世状态的验证者根哈希。对于轻客户端来说，这是一个至关重要的初始信任锚点。通过验证接收到的第一个信标区块头的验证者根是否与此哈希匹配，轻客户端可以确保它们连接到正确的链。这就像区块链的“指纹”。
//GenesisTime: 1606824023。这是信标链的创世时间，以 Unix 时间戳表示（UTC 12:00:23 PM on December 1, 2020）。它标志着信标链的启动时间。
//Checkpoint: common.HexToHash("0x6509b691f4de4f7b083f2784938fd52f0e131675432b3fd85ea549af9aebd3d0")。这是一个已知的、可信的信标链状态的哈希值。轻客户端通常会从一个检查点开始同步，而不是从创世区块开始，以节省时间和资源。这个检查点提供了一个近期且经过验证的状态，作为同步的起点。
//.AddFork("GENESIS", 0, []byte{0, 0, 0, 0}): 这行代码定义了 "GENESIS" 分叉（即信标链的启动）。它在槽位 0 激活，并且与字节数组 []byte{0, 0, 0, 0} 相关联，这可能代表了该分叉的版本号。
//.AddFork("ALTAIR", 74240, []byte{1, 0, 0, 0}): 这定义了 "ALTAIR" 分叉，这是信标链的第一次重大升级，引入了轻客户端支持和同步委员会等特性。它在槽位 74240 激活，版本号可能是 []byte{1, 0, 0, 0}。
//.AddFork("BELLATRIX", 144896, []byte{2, 0, 0, 0}): 这是 "BELLATRIX" 分叉，是以太坊合并（The Merge）的一部分，它将执行层（原以太坊 PoW 链）与信标链的共识层合并。它在槽位 144896 激活，版本号可能是 []byte{2, 0, 0, 0}。
//.AddFork("CAPELLA", 194048, []byte{3, 0, 0, 0}): 这是 "CAPELLA" 分叉，在合并后进行，引入了对提款功能的支持。它在槽位 194048 激活，版本号可能是 []byte{3, 0, 0, 0}。
//.AddFork("DENEB", 269568, []byte{4, 0, 0, 0}): 这是 "DENEB" 分叉，是最近的一次升级，主要引入了数据可用性采样（Data Availability Sampling, DAS）以支持 Danksharding。它在槽位 269568 激活，版本号可能是 []byte{4, 0, 0, 0}。

var (
	MainnetLightConfig = (&ChainConfig{
		GenesisValidatorsRoot: common.HexToHash("0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
		GenesisTime:           1606824023,
		Checkpoint:            common.HexToHash("0x6509b691f4de4f7b083f2784938fd52f0e131675432b3fd85ea549af9aebd3d0"),
	}).
		AddFork("GENESIS", 0, []byte{0, 0, 0, 0}).
		AddFork("ALTAIR", 74240, []byte{1, 0, 0, 0}).
		AddFork("BELLATRIX", 144896, []byte{2, 0, 0, 0}).
		AddFork("CAPELLA", 194048, []byte{3, 0, 0, 0}).
		AddFork("DENEB", 269568, []byte{4, 0, 0, 0})

	SepoliaLightConfig = (&ChainConfig{
		GenesisValidatorsRoot: common.HexToHash("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"),
		GenesisTime:           1655733600,
		Checkpoint:            common.HexToHash("0x456e85f5608afab3465a0580bff8572255f6d97af0c5f939e3f7536b5edb2d3f"),
	}).
		AddFork("GENESIS", 0, []byte{144, 0, 0, 105}).
		AddFork("ALTAIR", 50, []byte{144, 0, 0, 112}).
		AddFork("BELLATRIX", 100, []byte{144, 0, 0, 113}).
		AddFork("CAPELLA", 56832, []byte{144, 0, 0, 114}).
		AddFork("DENEB", 132608, []byte{144, 0, 0, 115})

	HoleskyLightConfig = (&ChainConfig{
		GenesisValidatorsRoot: common.HexToHash("0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1"),
		GenesisTime:           1695902400,
		Checkpoint:            common.HexToHash("0x6456a1317f54d4b4f2cb5bc9d153b5af0988fe767ef0609f0236cf29030bcff7"),
	}).
		AddFork("GENESIS", 0, []byte{1, 1, 112, 0}).
		AddFork("ALTAIR", 0, []byte{2, 1, 112, 0}).
		AddFork("BELLATRIX", 0, []byte{3, 1, 112, 0}).
		AddFork("CAPELLA", 256, []byte{4, 1, 112, 0}).
		AddFork("DENEB", 29696, []byte{5, 1, 112, 0})
)
