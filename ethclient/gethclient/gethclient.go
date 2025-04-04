// Copyright 2021 The go-ethereum Authors
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

// Package gethclient provides an RPC client for geth-specific APIs.
package gethclient

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"runtime/debug"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client is a wrapper around rpc.Client that implements geth-specific functionality.
//
// If you want to use the standardized Ethereum RPC functionality, use ethclient.Client instead.
// Client 是对 rpc.Client 的封装，实现了 Geth 特有的功能。
//
// 如果你想使用标准的以太坊 RPC 功能，请使用 ethclient.Client。
type Client struct {
	c *rpc.Client
}

// New creates a client that uses the given RPC client.
// New 创建一个使用给定 RPC 客户端的 client。
func New(c *rpc.Client) *Client {
	return &Client{c}
}

// CreateAccessList tries to create an access list for a specific transaction based on the
// current pending state of the blockchain.
// CreateAccessList 尝试基于当前区块链的待处理状态，为特定的交易创建一个访问列表。
func (ec *Client) CreateAccessList(ctx context.Context, msg ethereum.CallMsg) (*types.AccessList, uint64, string, error) {
	type accessListResult struct {
		Accesslist *types.AccessList `json:"accessList"`
		Error      string            `json:"error,omitempty"`
		GasUsed    hexutil.Uint64    `json:"gasUsed"`
	}
	var result accessListResult
	if err := ec.c.CallContext(ctx, &result, "eth_createAccessList", toCallArg(msg)); err != nil {
		return nil, 0, "", err
	}
	return result.Accesslist, uint64(result.GasUsed), result.Error, nil
}

// AccountResult is the result of a GetProof operation.
// AccountResult 是 GetProof 操作的结果。
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *big.Int        `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        uint64          `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

// StorageResult provides a proof for a key-value pair.
// StorageResult 为一个键值对提供证明。
type StorageResult struct {
	Key   string   `json:"key"`
	Value *big.Int `json:"value"`
	Proof []string `json:"proof"`
}

// GetProof returns the account and storage values of the specified account including the Merkle-proof.
// The block number can be nil, in which case the value is taken from the latest known block.
// GetProof 返回指定账户的账户和存储值，包括 Merkle 证明。
// 区块号可以为 nil，在这种情况下，该值取自最新的已知区块。
func (ec *Client) GetProof(ctx context.Context, account common.Address, keys []string, blockNumber *big.Int) (*AccountResult, error) {
	type storageResult struct {
		Key   string       `json:"key"`
		Value *hexutil.Big `json:"value"`
		Proof []string     `json:"proof"`
	}

	type accountResult struct {
		Address      common.Address  `json:"address"`
		AccountProof []string        `json:"accountProof"`
		Balance      *hexutil.Big    `json:"balance"`
		CodeHash     common.Hash     `json:"codeHash"`
		Nonce        hexutil.Uint64  `json:"nonce"`
		StorageHash  common.Hash     `json:"storageHash"`
		StorageProof []storageResult `json:"storageProof"`
	}

	// Avoid keys being 'null'.
	// 避免 keys 为 'null'。
	if keys == nil {
		keys = []string{}
	}

	var res accountResult
	err := ec.c.CallContext(ctx, &res, "eth_getProof", account, keys, toBlockNumArg(blockNumber))
	// Turn hexutils back to normal datatypes
	// 将 hexutils 转换回普通数据类型
	storageResults := make([]StorageResult, 0, len(res.StorageProof))
	for _, st := range res.StorageProof {
		storageResults = append(storageResults, StorageResult{
			Key:   st.Key,
			Value: st.Value.ToInt(),
			Proof: st.Proof,
		})
	}
	result := AccountResult{
		Address:      res.Address,
		AccountProof: res.AccountProof,
		Balance:      res.Balance.ToInt(),
		Nonce:        uint64(res.Nonce),
		CodeHash:     res.CodeHash,
		StorageHash:  res.StorageHash,
		StorageProof: storageResults,
	}
	return &result, err
}

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
//
// overrides specifies a map of contract states that should be overwritten before executing
// the message call.
// Please use ethclient.CallContract instead if you don't need the override functionality.
// CallContract 执行一个消息调用交易，该交易直接在节点的 VM 中执行，但不会被挖矿到区块链中。
//
// blockNumber 选择运行调用的区块高度。它可以为 nil，在这种情况下，代码取自最新的已知区块。请注意，非常旧的区块的状态可能不可用。
//
// overrides 指定一个合约状态的映射，在执行消息调用之前应该覆盖这些状态。
// 如果你不需要覆盖功能，请使用 ethclient.CallContract。
func (ec *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int, overrides *map[common.Address]OverrideAccount) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(
		ctx, &hex, "eth_call", toCallArg(msg),
		toBlockNumArg(blockNumber), overrides,
	)
	return hex, err
}

// CallContractWithBlockOverrides executes a message call transaction, which is directly executed
// in the VM  of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
//
// overrides specifies a map of contract states that should be overwritten before executing
// the message call.
//
// blockOverrides specifies block fields exposed to the EVM that can be overridden for the call.
//
// Please use ethclient.CallContract instead if you don't need the override functionality.
// CallContractWithBlockOverrides 执行一个消息调用交易，该交易直接在节点的 VM 中执行，但不会被挖矿到区块链中。
//
// blockNumber 选择运行调用的区块高度。它可以为 nil，在这种情况下，代码取自最新的已知区块。请注意，非常旧的区块的状态可能不可用。
//
// overrides 指定一个合约状态的映射，在执行消息调用之前应该覆盖这些状态。
//
// blockOverrides 指定暴露给 EVM 的区块字段，可以在调用时被覆盖。
//
// 如果你不需要覆盖功能，请使用 ethclient.CallContract。
func (ec *Client) CallContractWithBlockOverrides(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int, overrides *map[common.Address]OverrideAccount, blockOverrides BlockOverrides) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(
		ctx, &hex, "eth_call", toCallArg(msg),
		toBlockNumArg(blockNumber), overrides, blockOverrides,
	)
	return hex, err
}

// GCStats retrieves the current garbage collection stats from a geth node.
// GCStats 从 Geth 节点检索当前的垃圾回收统计信息。
func (ec *Client) GCStats(ctx context.Context) (*debug.GCStats, error) {
	var result debug.GCStats
	err := ec.c.CallContext(ctx, &result, "debug_gcStats")
	return &result, err
}

// MemStats retrieves the current memory stats from a geth node.
// MemStats 从 Geth 节点检索当前的内存统计信息。
func (ec *Client) MemStats(ctx context.Context) (*runtime.MemStats, error) {
	var result runtime.MemStats
	err := ec.c.CallContext(ctx, &result, "debug_memStats")
	return &result, err
}

// SetHead sets the current head of the local chain by block number.
// Note, this is a destructive action and may severely damage your chain.
// Use with extreme caution.
// SetHead 通过区块号设置本地链的当前头部。
// 注意，这是一个破坏性操作，可能会严重损坏你的链。请谨慎使用。
func (ec *Client) SetHead(ctx context.Context, number *big.Int) error {
	return ec.c.CallContext(ctx, nil, "debug_setHead", toBlockNumArg(number))
}

// GetNodeInfo retrieves the node info of a geth node.
// GetNodeInfo 检索 Geth 节点的节点信息。
func (ec *Client) GetNodeInfo(ctx context.Context) (*p2p.NodeInfo, error) {
	var result p2p.NodeInfo
	err := ec.c.CallContext(ctx, &result, "admin_nodeInfo")
	return &result, err
}

// SubscribeFullPendingTransactions subscribes to new pending transactions.
// SubscribeFullPendingTransactions 订阅新的待处理交易。
func (ec *Client) SubscribeFullPendingTransactions(ctx context.Context, ch chan<- *types.Transaction) (*rpc.ClientSubscription, error) {
	return ec.c.EthSubscribe(ctx, ch, "newPendingTransactions", true)
}

// SubscribePendingTransactions subscribes to new pending transaction hashes.
// SubscribePendingTransactions 订阅新的待处理交易哈希。
func (ec *Client) SubscribePendingTransactions(ctx context.Context, ch chan<- common.Hash) (*rpc.ClientSubscription, error) {
	return ec.c.EthSubscribe(ctx, ch, "newPendingTransactions")
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	// It's negative.
	// 是负数。
	if number.IsInt64() {
		return rpc.BlockNumber(number.Int64()).String()
	}
	// It's negative and large, which is invalid.
	// 它是负数且很大，这是无效的。
	return fmt.Sprintf("<invalid %d>", number)
}

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["input"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	if msg.GasFeeCap != nil {
		arg["maxFeePerGas"] = (*hexutil.Big)(msg.GasFeeCap)
	}
	if msg.GasTipCap != nil {
		arg["maxPriorityFeePerGas"] = (*hexutil.Big)(msg.GasTipCap)
	}
	if msg.AccessList != nil {
		arg["accessList"] = msg.AccessList
	}
	if msg.BlobGasFeeCap != nil {
		arg["maxFeePerBlobGas"] = (*hexutil.Big)(msg.BlobGasFeeCap)
	}
	if msg.BlobHashes != nil {
		arg["blobVersionedHashes"] = msg.BlobHashes
	}
	return arg
}

// OverrideAccount specifies the state of an account to be overridden.
// OverrideAccount 指定要覆盖的账户状态。
type OverrideAccount struct {
	// Nonce sets nonce of the account. Note: the nonce override will only
	// be applied when it is set to a non-zero value.
	// Nonce 设置账户的 nonce 值。注意：只有当 nonce 设置为非零值时，覆盖才会被应用。
	Nonce uint64

	// Code sets the contract code. The override will be applied
	// when the code is non-nil, i.e. setting empty code is possible
	// using an empty slice.
	// Code 设置合约代码。当代码为非 nil 时，覆盖将被应用，即可以使用空切片设置空代码。
	Code []byte

	// Balance sets the account balance.
	// Balance 设置账户余额。
	Balance *big.Int

	// State sets the complete storage. The override will be applied
	// when the given map is non-nil. Using an empty map wipes the
	// entire contract storage during the call.
	// State 设置完整的存储。当给定的 map 为非 nil 时，覆盖将被应用。在调用期间使用空 map 会清除整个合约存储。
	State map[common.Hash]common.Hash

	// StateDiff allows overriding individual storage slots.
	// StateDiff 允许覆盖单个存储槽。
	StateDiff map[common.Hash]common.Hash
}

func (a OverrideAccount) MarshalJSON() ([]byte, error) {
	type acc struct {
		Nonce     hexutil.Uint64              `json:"nonce,omitempty"`
		Code      string                      `json:"code,omitempty"`
		Balance   *hexutil.Big                `json:"balance,omitempty"`
		State     interface{}                 `json:"state,omitempty"`
		StateDiff map[common.Hash]common.Hash `json:"stateDiff,omitempty"`
	}

	output := acc{
		Nonce:     hexutil.Uint64(a.Nonce),
		Balance:   (*hexutil.Big)(a.Balance),
		StateDiff: a.StateDiff,
	}
	if a.Code != nil {
		output.Code = hexutil.Encode(a.Code)
	}
	if a.State != nil {
		output.State = a.State
	}
	return json.Marshal(output)
}

// BlockOverrides specifies the  set of header fields to override.
// BlockOverrides 指定要覆盖的区块头字段集合。
type BlockOverrides struct {
	// Number overrides the block number.
	// Number 覆盖区块号。
	Number *big.Int
	// Difficulty overrides the block difficulty.
	// Difficulty 覆盖区块难度。
	Difficulty *big.Int
	// Time overrides the block timestamp. Time is applied only when
	// it is non-zero.
	// Time 覆盖区块时间戳。只有当时间为非零值时才应用。
	Time uint64
	// GasLimit overrides the block gas limit. GasLimit is applied only when
	// it is non-zero.
	// GasLimit 覆盖区块 gas 限制。只有当 gas 限制为非零值时才应用。
	GasLimit uint64
	// Coinbase overrides the block coinbase. Coinbase is applied only when
	// it is different from the zero address.
	// Coinbase 覆盖区块 coinbase。只有当 coinbase 与零地址不同时才应用。
	Coinbase common.Address
	// Random overrides the block extra data which feeds into the RANDOM opcode.
	// Random is applied only when it is a non-zero hash.
	// Random 覆盖区块额外数据，该数据会输入到 RANDOM 操作码中。只有当 Random 为非零哈希时才应用。
	Random common.Hash
	// BaseFee overrides the block base fee.
	// BaseFee 覆盖区块基础费用。
	BaseFee *big.Int
}

func (o BlockOverrides) MarshalJSON() ([]byte, error) {
	type override struct {
		Number     *hexutil.Big    `json:"number,omitempty"`
		Difficulty *hexutil.Big    `json:"difficulty,omitempty"`
		Time       hexutil.Uint64  `json:"time,omitempty"`
		GasLimit   hexutil.Uint64  `json:"gasLimit,omitempty"`
		Coinbase   *common.Address `json:"feeRecipient,omitempty"`
		Random     *common.Hash    `json:"prevRandao,omitempty"`
		BaseFee    *hexutil.Big    `json:"baseFeePerGas,omitempty"`
	}

	output := override{
		Number:     (*hexutil.Big)(o.Number),
		Difficulty: (*hexutil.Big)(o.Difficulty),
		Time:       hexutil.Uint64(o.Time),
		GasLimit:   hexutil.Uint64(o.GasLimit),
		BaseFee:    (*hexutil.Big)(o.BaseFee),
	}
	if o.Coinbase != (common.Address{}) {
		output.Coinbase = &o.Coinbase
	}
	if o.Random != (common.Hash{}) {
		output.Random = &o.Random
	}
	return json.Marshal(output)
}
