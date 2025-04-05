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

package clique

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the proof-of-authority scheme.
// API 是一个面向用户的 RPC API，用于控制权威证明（Proof-of-Authority, PoA）机制中的签名者和投票机制。
type API struct {
	chain  consensus.ChainHeaderReader // 区块链头部读取器，用于访问区块链的头部信息。
	clique *Clique                     // Clique 是 PoA 共识引擎的具体实现。
}

// GetSnapshot retrieves the state snapshot at a given block.
// GetSnapshot 检索指定区块的状态快照。
func (api *API) GetSnapshot(number *rpc.BlockNumber) (*Snapshot, error) {
	// Retrieve the requested block number (or current if none requested)
	// 获取请求的区块号（如果未指定，则默认为最新区块）。
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader() // 获取当前最新的区块头部。
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64())) // 根据区块号获取区块头部。
	}
	// Ensure we have an actually valid block and return its snapshot
	// 确保我们有一个有效的区块，并返回其快照。
	if header == nil {
		return nil, errUnknownBlock // 如果区块不存在，返回错误。
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil) // 调用 Clique 的快照方法生成状态快照。
}

// GetSnapshotAtHash retrieves the state snapshot at a given block.
// GetSnapshotAtHash 检索指定区块哈希对应的状态快照。
func (api *API) GetSnapshotAtHash(hash common.Hash) (*Snapshot, error) {
	header := api.chain.GetHeaderByHash(hash) // 根据区块哈希获取区块头部。
	if header == nil {
		return nil, errUnknownBlock // 如果区块不存在，返回错误。
	}
	return api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil) // 调用 Clique 的快照方法生成状态快照。
}

// GetSigners retrieves the list of authorized signers at the specified block.
// GetSigners 检索指定区块的授权签名者列表。
func (api *API) GetSigners(number *rpc.BlockNumber) ([]common.Address, error) {
	// Retrieve the requested block number (or current if none requested)
	// 获取请求的区块号（如果未指定，则默认为最新区块）。
	var header *types.Header
	if number == nil || *number == rpc.LatestBlockNumber {
		header = api.chain.CurrentHeader() // 获取当前最新的区块头部。
	} else {
		header = api.chain.GetHeaderByNumber(uint64(number.Int64())) // 根据区块号获取区块头部。
	}
	// Ensure we have an actually valid block and return the signers from its snapshot
	// 确保我们有一个有效的区块，并从其快照中返回签名者列表。
	if header == nil {
		return nil, errUnknownBlock // 如果区块不存在，返回错误。
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil) // 获取区块快照。
	if err != nil {
		return nil, err // 如果快照生成失败，返回错误。
	}
	return snap.signers(), nil // 返回快照中的签名者列表。
}

// GetSignersAtHash retrieves the list of authorized signers at the specified block.
// GetSignersAtHash 检索指定区块哈希对应的授权签名者列表。
func (api *API) GetSignersAtHash(hash common.Hash) ([]common.Address, error) {
	header := api.chain.GetHeaderByHash(hash) // 根据区块哈希获取区块头部。
	if header == nil {
		return nil, errUnknownBlock // 如果区块不存在，返回错误。
	}
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil) // 获取区块快照。
	if err != nil {
		return nil, err // 如果快照生成失败，返回错误。
	}
	return snap.signers(), nil // 返回快照中的签名者列表。
}

// Proposals returns the current proposals the node tries to uphold and vote on.
// Proposals 返回节点当前正在维护并投票的提案。
func (api *API) Proposals() map[common.Address]bool {
	api.clique.lock.RLock() // 加读锁，确保并发安全。
	defer api.clique.lock.RUnlock()

	proposals := make(map[common.Address]bool)        // 创建一个映射，用于存储提案。
	for address, auth := range api.clique.proposals { // 遍历 Clique 中的提案。
		proposals[address] = auth // 将提案地址及其授权状态存入映射。
	}
	return proposals // 返回提案映射。
}

// Propose injects a new authorization proposal that the signer will attempt to
// push through.
// Propose 注入一个新的授权提案，签名者将尝试推动该提案通过。
func (api *API) Propose(address common.Address, auth bool) {
	api.clique.lock.Lock() // 加写锁，确保并发安全。
	defer api.clique.lock.Unlock()

	api.clique.proposals[address] = auth // 将提案地址及其授权状态存入 Clique 的提案映射。
}

// Discard drops a currently running proposal, stopping the signer from casting
// further votes (either for or against).
// Discard 删除当前运行的提案，阻止签名者继续投票（无论是支持还是反对）。
func (api *API) Discard(address common.Address) {
	api.clique.lock.Lock() // 加写锁，确保并发安全。
	defer api.clique.lock.Unlock()

	delete(api.clique.proposals, address) // 从 Clique 的提案映射中删除指定地址的提案。
}

type status struct {
	InturnPercent float64                `json:"inturnPercent"`  // 当前轮次签名者的百分比。
	SigningStatus map[common.Address]int `json:"sealerActivity"` // 每个签名者的活跃状态。
	NumBlocks     uint64                 `json:"numBlocks"`      // 统计的区块数量。
}

// Status returns the status of the last N blocks,
// - the number of active signers,
// - the number of signers,
// - the percentage of in-turn blocks
// Status 返回最近 N 个区块的状态：
// - 活跃签名者的数量，
// - 签名者的总数，
// - 轮次内区块的百分比。
func (api *API) Status() (*status, error) {
	var (
		numBlocks = uint64(64)                // 默认统计最近 64 个区块。
		header    = api.chain.CurrentHeader() // 获取当前最新的区块头部。
		diff      = uint64(0)                 // 用于累加区块难度。
		optimals  = 0                         // 用于统计轮次内的区块数量。
	)
	snap, err := api.clique.snapshot(api.chain, header.Number.Uint64(), header.Hash(), nil) // 获取当前区块的快照。
	if err != nil {
		return nil, err // 如果快照生成失败，返回错误。
	}
	var (
		signers = snap.signers()         // 获取快照中的签名者列表。
		end     = header.Number.Uint64() // 结束区块号。
		start   = end - numBlocks        // 起始区块号。
	)
	if numBlocks > end {
		start = 1 // 如果区块总数小于统计数量，调整起始区块号。
		numBlocks = end - start
	}
	signStatus := make(map[common.Address]int) // 创建一个映射，用于记录每个签名者的活跃状态。
	for _, s := range signers {
		signStatus[s] = 0 // 初始化每个签名者的活跃状态为 0。
	}
	for n := start; n < end; n++ {
		h := api.chain.GetHeaderByNumber(n) // 根据区块号获取区块头部。
		if h == nil {
			return nil, fmt.Errorf("missing block %d", n) // 如果区块不存在，返回错误。
		}
		if h.Difficulty.Cmp(diffInTurn) == 0 { // 如果区块难度等于轮次内难度，说明是轮次内区块。
			optimals++
		}
		diff += h.Difficulty.Uint64()       // 累加区块难度。
		sealer, err := api.clique.Author(h) // 获取区块的签名者。
		if err != nil {
			return nil, err // 如果获取签名者失败，返回错误。
		}
		signStatus[sealer]++ // 更新签名者的活跃状态。
	}
	return &status{
		InturnPercent: float64(100*optimals) / float64(numBlocks), // 计算轮次内区块的百分比。
		SigningStatus: signStatus,                                 // 返回每个签名者的活跃状态。
		NumBlocks:     numBlocks,                                  // 返回统计的区块数量。
	}, nil
}

type blockNumberOrHashOrRLP struct {
	*rpc.BlockNumberOrHash               // 包含区块号或哈希的结构体。
	RLP                    hexutil.Bytes `json:"rlp,omitempty"` // RLP 编码的区块或头部数据。
}

func (sb *blockNumberOrHashOrRLP) UnmarshalJSON(data []byte) error {
	bnOrHash := new(rpc.BlockNumberOrHash)
	// Try to unmarshal bNrOrHash
	// 尝试反序列化为区块号或哈希。
	if err := bnOrHash.UnmarshalJSON(data); err == nil {
		sb.BlockNumberOrHash = bnOrHash // 如果成功，赋值给 BlockNumberOrHash。
		return nil
	}
	// Try to unmarshal RLP
	// 尝试反序列化为 RLP 数据。
	var input string
	if err := json.Unmarshal(data, &input); err != nil {
		return err
	}
	blob, err := hexutil.Decode(input) // 解码十六进制字符串为字节数组。
	if err != nil {
		return err
	}
	sb.RLP = blob // 如果成功，赋值给 RLP。
	return nil
}

// GetSigner returns the signer for a specific clique block.
// Can be called with a block number, a block hash or a rlp encoded blob.
// The RLP encoded blob can either be a block or a header.
// GetSigner 返回特定 Clique 区块的签名者。
// 可以通过区块号、区块哈希或 RLP 编码的数据调用。
// RLP 编码的数据可以是区块或头部。
func (api *API) GetSigner(rlpOrBlockNr *blockNumberOrHashOrRLP) (common.Address, error) {
	if len(rlpOrBlockNr.RLP) == 0 {
		blockNrOrHash := rlpOrBlockNr.BlockNumberOrHash
		var header *types.Header
		if blockNrOrHash == nil {
			header = api.chain.CurrentHeader() // 如果未指定区块号或哈希，默认获取当前最新的区块头部。
		} else if hash, ok := blockNrOrHash.Hash(); ok {
			header = api.chain.GetHeaderByHash(hash) // 根据区块哈希获取区块头部。
		} else if number, ok := blockNrOrHash.Number(); ok {
			header = api.chain.GetHeaderByNumber(uint64(number.Int64())) // 根据区块号获取区块头部。
		}
		if header == nil {
			return common.Address{}, fmt.Errorf("missing block %v", blockNrOrHash.String()) // 如果区块不存在，返回错误。
		}
		return api.clique.Author(header) // 返回区块的签名者。
	}
	block := new(types.Block)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, block); err == nil {
		return api.clique.Author(block.Header()) // 如果 RLP 数据是区块，返回区块头部的签名者。
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(rlpOrBlockNr.RLP, header); err != nil {
		return common.Address{}, err // 如果解码失败，返回错误。
	}
	return api.clique.Author(header) // 如果 RLP 数据是头部，返回头部的签名者。
}
