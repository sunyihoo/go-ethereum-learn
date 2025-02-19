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
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
)

// HeaderChain implements the basic block header chain logic. It is not usable
// in itself, but rather an internal structure of core.Blockchain.
//
// HeaderChain is responsible for maintaining the header chain including the
// header query and updating.
//
// The data components maintained by HeaderChain include:
//
// - total difficulty
// - header
// - block hash -> number mapping
// - canonical number -> hash mapping
// - head header flag.
//
// It is not thread safe, the encapsulating chain structures should do the
// necessary mutex locking/unlocking.
type HeaderChain struct {
	config        *params.ChainConfig
	chainDb       ethdb.Database
	genesisHeader *types.Header

	currentHeader     atomic.Pointer[types.Header] // Current head of the header chain (maybe above the block chain!)
	currentHeaderHash common.Hash                  // Hash of the current head of the header chain (prevent recomputing all the time)

	headerCache *lru.Cache[common.Hash, *types.Header]
	tdCache     *lru.Cache[common.Hash, *big.Int] // most recent total difficulties
	numberCache *lru.Cache[common.Hash, uint64]   // most recent block numbers

	procInterrupt func() bool

	engine consensus.Engine
}
