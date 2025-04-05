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

// Package ethclient provides a client for the Ethereum RPC API.
package ethclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client defines typed wrappers for the Ethereum RPC API.
// Client 结构体定义了对以太坊 RPC API 的类型化包装。
// Client 结构体封装了以太坊 RPC API 的调用，提供类型化的方法以访问区块链数据。
type Client struct {
	c *rpc.Client // 底层 RPC 客户端
}

// Dial connects a client to the given URL.
// Dial 函数连接到给定的 URL。
// Dial 函数使用默认上下文连接到指定的 URL，返回一个 Client 实例。
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

// DialContext connects a client to the given URL with context.
// DialContext 函数使用提供的上下文连接到指定的 URL。
// DialContext 函数允许指定上下文来连接到 URL，返回 Client 实例。
func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
// NewClient 函数创建一个使用给定 RPC 客户端的 Client 实例。
// NewClient 函数通过传入已有的 RPC 客户端来创建 Client 实例。
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

// Close closes the underlying RPC connection.
// Close 方法关闭底层的 RPC 连接。
// Close 方法用于关闭与 RPC 服务器的连接。
func (ec *Client) Close() {
	ec.c.Close()
}

// Client gets the underlying RPC client.
// Client 方法返回底层的 RPC 客户端。
// Client 方法用于获取封装的 RPC 客户端实例。
func (ec *Client) Client() *rpc.Client {
	return ec.c
}

// Blockchain Access
// 区块链访问

// ChainID retrieves the current chain ID for transaction replay protection.
// ChainID 方法检索当前的链 ID，用于交易重放保护。
// ChainID 方法通过调用 "eth_chainId" RPC 方法获取链 ID，用于防止交易在不同链上重放。
func (ec *Client) ChainID(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_chainId")
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&result), err
}

// BlockByHash returns the given full block.
//
// Note that loading full blocks requires two requests. Use HeaderByHash
// if you don't need all transactions or uncle headers.
// BlockByHash 方法返回给定哈希的完整区块。
// BlockByHash 方法通过哈希获取完整的区块信息，包括交易和叔块。
func (ec *Client) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return ec.getBlock(ctx, "eth_getBlockByHash", hash, true)
}

// BlockByNumber returns a block from the current canonical chain. If number is nil, the
// latest known block is returned.
//
// Note that loading full blocks requires two requests. Use HeaderByNumber
// if you don't need all transactions or uncle headers.
// BlockByNumber 方法从当前规范链中返回指定区块号的区块。
// BlockByNumber 方法根据区块号获取区块，若区块号为 nil，则返回最新区块。
func (ec *Client) BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error) {
	return ec.getBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(number), true)
}

// BlockNumber returns the most recent block number
// BlockNumber 方法返回最新的区块号。
// BlockNumber 方法通过 "eth_blockNumber" RPC 方法获取当前链的最新区块号。
func (ec *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_blockNumber")
	return uint64(result), err
}

// PeerCount returns the number of p2p peers as reported by the net_peerCount method.
// PeerCount 方法返回 P2P 对等节点的数量。
// PeerCount 方法通过 "net_peerCount" RPC 方法获取当前连接的对等节点数量。
func (ec *Client) PeerCount(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "net_peerCount")
	return uint64(result), err
}

// BlockReceipts returns the receipts of a given block number or hash.
// BlockReceipts 方法返回给定区块号或哈希的交易收据。
// BlockReceipts 方法通过 "eth_getBlockReceipts" RPC 方法获取指定区块的所有交易收据。
func (ec *Client) BlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]*types.Receipt, error) {
	var r []*types.Receipt
	err := ec.c.CallContext(ctx, &r, "eth_getBlockReceipts", blockNrOrHash.String())
	if err == nil && r == nil {
		return nil, ethereum.NotFound
	}
	return r, err
}

type rpcBlock struct {
	Hash         common.Hash         `json:"hash"`                  // 区块哈希
	Transactions []rpcTransaction    `json:"transactions"`          // 交易列表
	UncleHashes  []common.Hash       `json:"uncles"`                // 叔块哈希列表
	Withdrawals  []*types.Withdrawal `json:"withdrawals,omitempty"` // 提款列表（可选）
}

// getBlock 获取指定区块的完整信息
// getBlock 方法是 BlockByHash 和 BlockByNumber 的辅助函数，处理区块获取的通用逻辑。
// **详细解释**：
// 1. 调用指定的 RPC 方法（如 "eth_getBlockByHash" 或 "eth_getBlockByNumber"）获取原始数据。
// 2. 解码区块头（header）和主体（body，包括交易和叔块哈希）。
// 3. 验证交易列表和叔块列表与区块头中的哈希一致。
// 4. 如果存在叔块，批量调用 "eth_getUncleByBlockHashAndIndex" 获取叔块头。
// 5. 组装交易、叔块和提款信息，返回完整的区块对象。
func (ec *Client) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, error) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	}

	// Decode header and transactions.
	var head *types.Header
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	// When the block is not found, the API returns JSON null.
	if head == nil {
		return nil, ethereum.NotFound
	}

	var body rpcBlock
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, errors.New("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, errors.New("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyTxsHash && len(body.Transactions) > 0 {
		return nil, errors.New("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyTxsHash && len(body.Transactions) == 0 {
		return nil, errors.New("server returned empty transaction list but block header indicates transactions")
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header
	if len(body.UncleHashes) > 0 {
		uncles = make([]*types.Header, len(body.UncleHashes))
		reqs := make([]rpc.BatchElem, len(body.UncleHashes))
		for i := range reqs {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getUncleByBlockHashAndIndex",
				Args:   []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				Result: &uncles[i],
			}
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}
		for i := range reqs {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			if uncles[i] == nil {
				return nil, fmt.Errorf("got null header for uncle %d of block %x", i, body.Hash[:])
			}
		}
	}
	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.tx, *tx.From, body.Hash)
		}
		txs[i] = tx.tx
	}

	return types.NewBlockWithHeader(head).WithBody(
		types.Body{
			Transactions: txs,
			Uncles:       uncles,
			Withdrawals:  body.Withdrawals,
		}), nil
}

// HeaderByHash returns the block header with the given hash.
// HeaderByHash 方法返回给定哈希的区块头。
// HeaderByHash 方法通过 "eth_getBlockByHash" RPC 方法获取指定哈希的区块头。
func (ec *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByHash", hash, false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

// HeaderByNumber returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
// HeaderByNumber 方法从当前规范链中返回指定区块号的区块头。
// HeaderByNumber 方法根据区块号获取区块头，若区块号为 nil，则返回最新区块头。
func (ec *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

type rpcTransaction struct {
	tx          *types.Transaction // 交易对象
	txExtraInfo                    // 额外交易信息
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"` // 区块号（可选）
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`   // 区块哈希（可选）
	From        *common.Address `json:"from,omitempty"`        // 发送者地址（可选）
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// TransactionByHash returns the transaction with the given hash.
// TransactionByHash 方法返回给定哈希的交易。
// TransactionByHash 方法通过 "eth_getTransactionByHash" RPC 方法获取指定哈希的交易，并判断其是否待处理。
func (ec *Client) TransactionByHash(ctx context.Context, hash common.Hash) (tx *types.Transaction, isPending bool, err error) {
	var json *rpcTransaction
	err = ec.c.CallContext(ctx, &json, "eth_getTransactionByHash", hash)
	if err != nil {
		return nil, false, err
	} else if json == nil {
		return nil, false, ethereum.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, false, errors.New("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, json.BlockNumber == nil, nil
}

// TransactionSender returns the sender address of the given transaction. The transaction
// must be known to the remote node and included in the blockchain at the given block and
// index. The sender is the one derived by the protocol at the time of inclusion.
//
// There is a fast-path for transactions retrieved by TransactionByHash and
// TransactionInBlock. Getting their sender address can be done without an RPC interaction.
// TransactionSender 方法返回给定交易的发送者地址。
// TransactionSender 方法尝试从缓存或服务器获取交易的发送者地址。
func (ec *Client) TransactionSender(ctx context.Context, tx *types.Transaction, block common.Hash, index uint) (common.Address, error) {
	// Try to load the address from the cache.
	sender, err := types.Sender(&senderFromServer{blockhash: block}, tx)
	if err == nil {
		return sender, nil
	}

	// It was not found in cache, ask the server.
	var meta struct {
		Hash common.Hash
		From common.Address
	}
	if err = ec.c.CallContext(ctx, &meta, "eth_getTransactionByBlockHashAndIndex", block, hexutil.Uint64(index)); err != nil {
		return common.Address{}, err
	}
	if meta.Hash == (common.Hash{}) || meta.Hash != tx.Hash() {
		return common.Address{}, errors.New("wrong inclusion block/index")
	}
	return meta.From, nil
}

// TransactionCount returns the total number of transactions in the given block.
// TransactionCount 方法返回给定区块中的交易总数。
// TransactionCount 方法通过 "eth_getBlockTransactionCountByHash" RPC 方法获取区块中的交易数量。
func (ec *Client) TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "eth_getBlockTransactionCountByHash", blockHash)
	return uint(num), err
}

// TransactionInBlock returns a single transaction at index in the given block.
// TransactionInBlock 方法返回给定区块中指定索引的交易。
// TransactionInBlock 方法通过 "eth_getTransactionByBlockHashAndIndex" RPC 方法获取区块中的特定交易。
func (ec *Client) TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) {
	var json *rpcTransaction
	err := ec.c.CallContext(ctx, &json, "eth_getTransactionByBlockHashAndIndex", blockHash, hexutil.Uint64(index))
	if err != nil {
		return nil, err
	}
	if json == nil {
		return nil, ethereum.NotFound
	} else if _, r, _ := json.tx.RawSignatureValues(); r == nil {
		return nil, errors.New("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.tx, *json.From, *json.BlockHash)
	}
	return json.tx, err
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
// TransactionReceipt 方法返回交易的收据。
// TransactionReceipt 方法通过 "eth_getTransactionReceipt" RPC 方法获取交易的收据，待处理交易无收据。
func (ec *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, "eth_getTransactionReceipt", txHash)
	if err == nil && r == nil {
		return nil, ethereum.NotFound
	}
	return r, err
}

// SyncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
// SyncProgress 方法检索同步算法的当前进度。
// SyncProgress 方法通过 "eth_syncing" RPC 方法获取同步进度，若无同步则返回 nil。
func (ec *Client) SyncProgress(ctx context.Context) (*ethereum.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "eth_syncing"); err != nil {
		return nil, err
	}
	// Handle the possible response types
	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}
	var p *rpcProgress
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return p.toSyncProgress(), nil
}

// SubscribeNewHead subscribes to notifications about the current blockchain head
// on the given channel.
// SubscribeNewHead 方法订阅当前区块链头的通知。
// SubscribeNewHead 方法通过 "newHeads" 订阅区块链头的更新通知。
func (ec *Client) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
	sub, err := ec.c.EthSubscribe(ctx, ch, "newHeads")
	if err != nil {
		// Defensively prefer returning nil interface explicitly on error-path, instead
		// of letting default golang behavior wrap it with non-nil interface that stores
		// nil concrete type value.
		return nil, err
	}
	return sub, nil
}

// State Access
// 状态访问

// NetworkID returns the network ID for this client.
// NetworkID 方法返回此客户端的网络 ID。
// NetworkID 方法通过 "net_version" RPC 方法获取网络 ID。
func (ec *Client) NetworkID(ctx context.Context) (*big.Int, error) {
	version := new(big.Int)
	var ver string
	if err := ec.c.CallContext(ctx, &ver, "net_version"); err != nil {
		return nil, err
	}
	if _, ok := version.SetString(ver, 0); !ok {
		return nil, fmt.Errorf("invalid net_version result %q", ver)
	}
	return version, nil
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
// BalanceAt 方法返回给定账户的 wei 余额。
// BalanceAt 方法通过 "eth_getBalance" RPC 方法获取账户在指定区块的余额。
func (ec *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

// BalanceAtHash returns the wei balance of the given account.
// BalanceAtHash 方法返回给定账户在指定区块哈希的 wei 余额。
// BalanceAtHash 方法通过区块哈希获取账户余额。
func (ec *Client) BalanceAtHash(ctx context.Context, account common.Address, blockHash common.Hash) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_getBalance", account, rpc.BlockNumberOrHashWithHash(blockHash, false))
	return (*big.Int)(&result), err
}

// StorageAt returns the value of key in the contract storage of the given account.
// The block number can be nil, in which case the value is taken from the latest known block.
// StorageAt 方法返回给定账户的合约存储中键的值。
// StorageAt 方法通过 "eth_getStorageAt" RPC 方法获取合约存储中的数据。
func (ec *Client) StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getStorageAt", account, key, toBlockNumArg(blockNumber))
	return result, err
}

// StorageAtHash returns the value of key in the contract storage of the given account.
// StorageAtHash 方法返回给定账户在指定区块哈希的合约存储中键的值。
// StorageAtHash 方法通过区块哈希获取合约存储数据。
func (ec *Client) StorageAtHash(ctx context.Context, account common.Address, key common.Hash, blockHash common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getStorageAt", account, key, rpc.BlockNumberOrHashWithHash(blockHash, false))
	return result, err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
// CodeAt 方法返回给定账户的合约代码。
// CodeAt 方法通过 "eth_getCode" RPC 方法获取合约字节码。
func (ec *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// CodeAtHash returns the contract code of the given account.
// CodeAtHash 方法返回给定账户在指定区块哈希的合约代码。
// CodeAtHash 方法通过区块哈希获取合约字节码。
func (ec *Client) CodeAtHash(ctx context.Context, account common.Address, blockHash common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getCode", account, rpc.BlockNumberOrHashWithHash(blockHash, false))
	return result, err
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
// NonceAt 方法返回给定账户的 nonce。
// NonceAt 方法通过 "eth_getTransactionCount" RPC 方法获取账户的交易计数（nonce）。
func (ec *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// NonceAtHash returns the account nonce of the given account.
// NonceAtHash 方法返回给定账户在指定区块哈希的 nonce。
// NonceAtHash 方法通过区块哈希获取账户的 nonce。
func (ec *Client) NonceAtHash(ctx context.Context, account common.Address, blockHash common.Hash) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, rpc.BlockNumberOrHashWithHash(blockHash, false))
	return uint64(result), err
}

// Filters
// 过滤器

// FilterLogs executes a filter query.
// FilterLogs 方法执行过滤器查询。
// FilterLogs 方法通过 "eth_getLogs" RPC 方法执行日志过滤查询。
func (ec *Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	var result []types.Log
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	err = ec.c.CallContext(ctx, &result, "eth_getLogs", arg)
	return result, err
}

// SubscribeFilterLogs subscribes to the results of a streaming filter query.
// SubscribeFilterLogs 方法订阅流式过滤器查询的结果。
// SubscribeFilterLogs 方法通过 "logs" 订阅实时日志事件。
func (ec *Client) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	arg, err := toFilterArg(q)
	if err != nil {
		return nil, err
	}
	sub, err := ec.c.EthSubscribe(ctx, ch, "logs", arg)
	if err != nil {
		// Defensively prefer returning nil interface explicitly on error-path, instead
		// of letting default golang behavior wrap it with non-nil interface that stores
		// nil concrete type value.
		return nil, err
	}
	return sub, nil
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, errors.New("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

// Pending State
// 待处理状态

// PendingBalanceAt returns the wei balance of the given account in the pending state.
// PendingBalanceAt 方法返回给定账户在待处理状态下的 wei 余额。
// PendingBalanceAt 方法获取账户在待处理区块中的余额。
func (ec *Client) PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_getBalance", account, "pending")
	return (*big.Int)(&result), err
}

// PendingStorageAt returns the value of key in the contract storage of the given account in the pending state.
// PendingStorageAt 方法返回给定账户在待处理状态下合约存储中键的值。
// PendingStorageAt 方法获取合约在待处理区块中的存储数据。
func (ec *Client) PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getStorageAt", account, key, "pending")
	return result, err
}

// PendingCodeAt returns the contract code of the given account in the pending state.
// PendingCodeAt 方法返回给定账户在待处理状态下的合约代码。
// PendingCodeAt 方法获取账户在待处理区块中的合约字节码。
func (ec *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getCode", account, "pending")
	return result, err
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
// PendingNonceAt 方法返回给定账户在待处理状态下的 nonce。
// PendingNonceAt 方法获取账户在待处理区块中的 nonce，用于下一次交易。
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, "pending")
	return uint64(result), err
}

// PendingTransactionCount returns the total number of transactions in the pending state.
// PendingTransactionCount 方法返回待处理状态下的交易总数。
// PendingTransactionCount 方法通过 "eth_getBlockTransactionCountByNumber" RPC 方法获取待处理区块中的交易数量。
func (ec *Client) PendingTransactionCount(ctx context.Context) (uint, error) {
	var num hexutil.Uint
	err := ec.c.CallContext(ctx, &num, "eth_getBlockTransactionCountByNumber", "pending")
	return uint(num), err
}

// Contract Calling
// 合约调用

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
// CallContract 方法执行消息调用交易，直接在节点的 VM 中执行，但不会被挖矿到区块链中。
// CallContract 方法通过 "eth_call" RPC 方法模拟合约调用，返回执行结果。
func (ec *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "eth_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// CallContractAtHash is almost the same as CallContract except that it selects
// the block by block hash instead of block height.
// CallContractAtHash 方法与 CallContract 类似，但通过区块哈希选择区块。
// CallContractAtHash 方法通过区块哈希指定调用时的状态。
func (ec *Client) CallContractAtHash(ctx context.Context, msg ethereum.CallMsg, blockHash common.Hash) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "eth_call", toCallArg(msg), rpc.BlockNumberOrHashWithHash(blockHash, false))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// PendingCallContract executes a message call transaction using the EVM.
// The state seen by the contract call is the pending state.
// PendingCallContract 方法使用 EVM 执行消息调用交易，状态为待处理状态。
// PendingCallContract 方法在待处理状态下模拟合约调用。
func (ec *Client) PendingCallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error) {
	var hex hexutil.Bytes
	err := ec.c.CallContext(ctx, &hex, "eth_call", toCallArg(msg), "pending")
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
// SuggestGasPrice 方法检索当前建议的 gas 价格，以允许交易及时执行。
// SuggestGasPrice 方法通过 "eth_gasPrice" RPC 方法获取建议的 gas 价格。
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// SuggestGasTipCap retrieves the currently suggested gas tip cap after 1559 to
// allow a timely execution of a transaction.
// SuggestGasTipCap 方法检索 1559 后的当前建议 gas tip cap。
// SuggestGasTipCap 方法通过 "eth_maxPriorityFeePerGas" RPC 方法获取建议的 gas tip cap。
func (ec *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "eth_maxPriorityFeePerGas"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

type feeHistoryResultMarshaling struct {
	OldestBlock  *hexutil.Big     `json:"oldestBlock"`             // 最早的区块
	Reward       [][]*hexutil.Big `json:"reward,omitempty"`        // 奖励
	BaseFee      []*hexutil.Big   `json:"baseFeePerGas,omitempty"` // 基础费用
	GasUsedRatio []float64        `json:"gasUsedRatio"`            // Gas 使用率
}

// FeeHistory retrieves the fee market history.
// FeeHistory 方法检索费用市场历史。
// FeeHistory 方法通过 "eth_feeHistory" RPC 方法获取费用市场历史数据。
func (ec *Client) FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*ethereum.FeeHistory, error) {
	var res feeHistoryResultMarshaling
	if err := ec.c.CallContext(ctx, &res, "eth_feeHistory", hexutil.Uint(blockCount), toBlockNumArg(lastBlock), rewardPercentiles); err != nil {
		return nil, err
	}
	reward := make([][]*big.Int, len(res.Reward))
	for i, r := range res.Reward {
		reward[i] = make([]*big.Int, len(r))
		for j, r := range r {
			reward[i][j] = (*big.Int)(r)
		}
	}
	baseFee := make([]*big.Int, len(res.BaseFee))
	for i, b := range res.BaseFee {
		baseFee[i] = (*big.Int)(b)
	}
	return &ethereum.FeeHistory{
		OldestBlock:  (*big.Int)(res.OldestBlock),
		Reward:       reward,
		BaseFee:      baseFee,
		GasUsedRatio: res.GasUsedRatio,
	}, nil
}

// EstimateGas tries to estimate the gas needed to execute a specific transaction based on
// the current pending state of the backend blockchain. There is no guarantee that this is
// the true gas limit requirement as other transactions may be added or removed by miners,
// but it should provide a basis for setting a reasonable default.
// EstimateGas 方法尝试估计执行特定交易所需的 gas。
// EstimateGas 方法通过 "eth_estimateGas" RPC 方法估计交易的 gas 消耗。
func (ec *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	var hex hexutil.Uint64
	err := ec.c.CallContext(ctx, &hex, "eth_estimateGas", toCallArg(msg))
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
// SendTransaction 方法将已签名的交易注入待处理池以执行。
// SendTransaction 方法通过 "eth_sendRawTransaction" RPC 方法发送已签名的交易。
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data))
}

// RevertErrorData returns the 'revert reason' data of a contract call.
//
// This can be used with CallContract and EstimateGas, and only when the server is Geth.
// RevertErrorData 函数返回合约调用的 'revert reason' 数据。
// RevertErrorData 函数从错误中提取合约调用的 revert 原因数据。
func RevertErrorData(err error) ([]byte, bool) {
	var ec rpc.Error
	var ed rpc.DataError
	if errors.As(err, &ec) && errors.As(err, &ed) && ec.ErrorCode() == 3 {
		if eds, ok := ed.ErrorData().(string); ok {
			revertData, err := hexutil.Decode(eds)
			if err == nil {
				return revertData, true
			}
		}
	}
	return nil, false
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	if number.Sign() >= 0 {
		return hexutil.EncodeBig(number)
	}
	// It's negative.
	if number.IsInt64() {
		return rpc.BlockNumber(number.Int64()).String()
	}
	// It's negative and large, which is invalid.
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

// rpcProgress is a copy of SyncProgress with hex-encoded fields.
// rpcProgress 结构体是 SyncProgress 的副本，字段为 hex 编码。
// rpcProgress 结构体用于从 RPC 响应中解析同步进度数据。
type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64

	PulledStates hexutil.Uint64
	KnownStates  hexutil.Uint64

	SyncedAccounts         hexutil.Uint64
	SyncedAccountBytes     hexutil.Uint64
	SyncedBytecodes        hexutil.Uint64
	SyncedBytecodeBytes    hexutil.Uint64
	SyncedStorage          hexutil.Uint64
	SyncedStorageBytes     hexutil.Uint64
	HealedTrienodes        hexutil.Uint64
	HealedTrienodeBytes    hexutil.Uint64
	HealedBytecodes        hexutil.Uint64
	HealedBytecodeBytes    hexutil.Uint64
	HealingTrienodes       hexutil.Uint64
	HealingBytecode        hexutil.Uint64
	TxIndexFinishedBlocks  hexutil.Uint64
	TxIndexRemainingBlocks hexutil.Uint64
}

func (p *rpcProgress) toSyncProgress() *ethereum.SyncProgress {
	if p == nil {
		return nil
	}
	return &ethereum.SyncProgress{
		StartingBlock:          uint64(p.StartingBlock),
		CurrentBlock:           uint64(p.CurrentBlock),
		HighestBlock:           uint64(p.HighestBlock),
		PulledStates:           uint64(p.PulledStates),
		KnownStates:            uint64(p.KnownStates),
		SyncedAccounts:         uint64(p.SyncedAccounts),
		SyncedAccountBytes:     uint64(p.SyncedAccountBytes),
		SyncedBytecodes:        uint64(p.SyncedBytecodes),
		SyncedBytecodeBytes:    uint64(p.SyncedBytecodeBytes),
		SyncedStorage:          uint64(p.SyncedStorage),
		SyncedStorageBytes:     uint64(p.SyncedStorageBytes),
		HealedTrienodes:        uint64(p.HealedTrienodes),
		HealedTrienodeBytes:    uint64(p.HealedTrienodeBytes),
		HealedBytecodes:        uint64(p.HealedBytecodes),
		HealedBytecodeBytes:    uint64(p.HealedBytecodeBytes),
		HealingTrienodes:       uint64(p.HealingTrienodes),
		HealingBytecode:        uint64(p.HealingBytecode),
		TxIndexFinishedBlocks:  uint64(p.TxIndexFinishedBlocks),
		TxIndexRemainingBlocks: uint64(p.TxIndexRemainingBlocks),
	}
}
