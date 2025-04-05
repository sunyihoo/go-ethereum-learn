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

package backends

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
)

// SimulatedBackend is a simulated blockchain.
// Deprecated: use package github.com/ethereum/go-ethereum/ethclient/simulated instead.
// SimulatedBackend 是一个模拟的区块链。
// 已弃用：请改用 github.com/ethereum/go-ethereum/ethclient/simulated 包中的 simulated.Backend。
type SimulatedBackend struct {
	*simulated.Backend // 嵌套的模拟后端
	simulated.Client   // 模拟的客户端
}

// Fork sets the head to a new block, which is based on the provided parentHash.
// Fork 将头部设置为一个新的区块，该区块基于提供的 parentHash。
func (b *SimulatedBackend) Fork(ctx context.Context, parentHash common.Hash) error {
	return b.Backend.Fork(parentHash)
}

// NewSimulatedBackend creates a new binding backend using a simulated blockchain
// for testing purposes.
//
// A simulated backend always uses chainID 1337.
//
// Deprecated: please use simulated.Backend from package
// github.com/ethereum/go-ethereum/ethclient/simulated instead.
// NewSimulatedBackend 创建一个新的绑定后端，使用模拟的区块链进行测试。
//
// 模拟后端始终使用链 ID 1337。
//
// 已弃用：请改用 github.com/ethereum/go-ethereum/ethclient/simulated 包中的 simulated.Backend。
func NewSimulatedBackend(alloc types.GenesisAlloc, gasLimit uint64) *SimulatedBackend {
	b := simulated.NewBackend(alloc, simulated.WithBlockGasLimit(gasLimit))
	return &SimulatedBackend{
		Backend: b,
		Client:  b.Client(),
	}
}
