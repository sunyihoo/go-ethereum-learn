// Copyright 2017 The go-ethereum Authors
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

// Package ethash implements the ethash proof-of-work consensus engine.
package ethash

import (
	"time"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Ethash is a consensus engine based on proof-of-work implementing the ethash
// algorithm.
// Ethash 是一种基于工作量证明（Proof-of-Work, PoW）的共识引擎，实现了 ethash 算法。
type Ethash struct {
	fakeFail  *uint64        // Block number which fails PoW check even in fake mode 即使在伪造模式下也会导致 PoW 检查失败的区块号
	fakeDelay *time.Duration // Time delay to sleep for before returning from verify 在验证前延迟的时间
	fakeFull  bool           // Accepts everything as valid 接受所有内容为有效
}

// NewFaker creates an ethash consensus engine with a fake PoW scheme that accepts
// all blocks' seal as valid, though they still have to conform to the Ethereum
// consensus rules.
// NewFaker 创建一个带有伪造 PoW 方案的 ethash 共识引擎，该方案接受所有区块的封印为有效，
// 但它们仍然必须符合以太坊的共识规则。
func NewFaker() *Ethash {
	return new(Ethash)
}

// NewFakeFailer creates a ethash consensus engine with a fake PoW scheme that
// accepts all blocks as valid apart from the single one specified, though they
// still have to conform to the Ethereum consensus rules.
// NewFakeFailer 创建一个带有伪造 PoW 方案的 ethash 共识引擎，该方案接受所有区块为有效，
// 除了指定的单个区块，但它们仍然必须符合以太坊的共识规则。
func NewFakeFailer(fail uint64) *Ethash {
	return &Ethash{
		fakeFail: &fail,
	}
}

// NewFakeDelayer creates a ethash consensus engine with a fake PoW scheme that
// accepts all blocks as valid, but delays verifications by some time, though
// they still have to conform to the Ethereum consensus rules.
// NewFakeDelayer 创建一个带有伪造 PoW 方案的 ethash 共识引擎，该方案接受所有区块为有效，
// 但在验证时会延迟一段时间，且它们仍然必须符合以太坊的共识规则。
func NewFakeDelayer(delay time.Duration) *Ethash {
	return &Ethash{
		fakeDelay: &delay,
	}
}

// NewFullFaker creates an ethash consensus engine with a full fake scheme that
// accepts all blocks as valid, without checking any consensus rules whatsoever.
// NewFullFaker 创建一个完全伪造的 ethash 共识引擎，该方案接受所有区块为有效，
// 并且不检查任何共识规则。
func NewFullFaker() *Ethash {
	return &Ethash{
		fakeFull: true,
	}
}

// Close closes the exit channel to notify all backend threads exiting.
// Close 关闭退出通道以通知所有后台线程退出。
func (ethash *Ethash) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning no APIs as ethash is an empty
// shell in the post-merge world.
// APIs 实现了 consensus.Engine 接口，在合并后的世界中，ethash 是一个空壳，因此不返回任何 API。
func (ethash *Ethash) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{}
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel. For the ethash engine, this method will
// just panic as sealing is not supported anymore.
// Seal 为给定的输入区块生成一个新的密封请求，并将结果推送到给定的通道中。
// 对于 ethash 引擎，此方法会直接引发 panic，因为密封功能已不再支持。
func (ethash *Ethash) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	panic("ethash (pow) sealing not supported any more")
}
