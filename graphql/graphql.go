// Copyright 2019 The go-ethereum Authors
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

// Package graphql provides a GraphQL interface to Ethereum node data.
package graphql

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	errBlockInvariant = errors.New("block objects must be instantiated with at least one of num or hash")
	// errBlockInvariant: 区块对象必须至少使用区块号或哈希值之一进行实例化。
	errInvalidBlockRange = errors.New("invalid from and to block combination: from > to")
	// errInvalidBlockRange: 无效的起始和结束区块组合：起始区块大于结束区块。
)

// Long is a custom scalar type for GraphQL representing a 64-bit integer.
// Long 是 GraphQL 的自定义标量类型，表示一个 64 位整数。
type Long int64

// ImplementsGraphQLType returns true if Long implements the provided GraphQL type.
// ImplementsGraphQLType 如果 Long 类型实现了提供的 GraphQL 类型，则返回 true。
func (b Long) ImplementsGraphQLType(name string) bool { return name == "Long" }

// UnmarshalGraphQL unmarshals the provided GraphQL query data.
// UnmarshalGraphQL 将提供的 GraphQL 查询数据解组到 Long 类型。
func (b *Long) UnmarshalGraphQL(input interface{}) error {
	var err error
	switch input := input.(type) {
	case string:
		// uncomment to support hex values
		// 取消注释以支持十六进制值
		if strings.HasPrefix(input, "0x") {
			// apply leniency and support hex representations of longs.
			// 宽松处理并支持 Long 类型的十六进制表示。
			value, err := hexutil.DecodeUint64(input)
			*b = Long(value)
			return err
		} else {
			value, err := strconv.ParseInt(input, 10, 64)
			*b = Long(value)
			return err
		}
	case int32:
		*b = Long(input)
	case int64:
		*b = Long(input)
	case float64:
		*b = Long(input)
	default:
		err = fmt.Errorf("unexpected type %T for Long", input)
		// err: Long 类型遇到意外的类型 %T。
	}
	return err
}

// Account represents an Ethereum account at a particular block.
// Account 代表特定区块上的一个以太坊账户。
type Account struct {
	r             *Resolver
	address       common.Address
	blockNrOrHash rpc.BlockNumberOrHash
}

// getState fetches the StateDB object for an account.
// getState 获取账户的 StateDB 对象。StateDB 包含了指定区块的账户状态。
func (a *Account) getState(ctx context.Context) (*state.StateDB, error) {
	state, _, err := a.r.backend.StateAndHeaderByNumberOrHash(ctx, a.blockNrOrHash)
	return state, err
}

// Address returns the address of the account.
// Address 返回账户的地址。
func (a *Account) Address(ctx context.Context) (common.Address, error) {
	return a.address, nil
}

// Balance returns the balance of the account at the given block number or hash.
// Balance 返回给定区块号或哈希时账户的余额。
func (a *Account) Balance(ctx context.Context) (hexutil.Big, error) {
	state, err := a.getState(ctx)
	if err != nil {
		return hexutil.Big{}, err
	}
	balance := state.GetBalance(a.address).ToBig()
	if balance == nil {
		return hexutil.Big{}, fmt.Errorf("failed to load balance %x", a.address)
		// 错误：加载地址 %x 的余额失败。
	}
	return hexutil.Big(*balance), nil
}

// TransactionCount returns the number of transactions sent from this account.
// TransactionCount 返回从此账户发送的交易数量（即 nonce 值）。
func (a *Account) TransactionCount(ctx context.Context) (hexutil.Uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	// 如果请求的是 pending 状态，则从交易池获取包含待处理交易的 nonce。
	if blockNr, ok := a.blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := a.r.backend.GetPoolNonce(ctx, a.address)
		if err != nil {
			return 0, err
		}
		return hexutil.Uint64(nonce), nil
	}
	state, err := a.getState(ctx)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(state.GetNonce(a.address)), nil
}

// Code returns the bytecode of the account at the given block number or hash.
// Code 返回给定区块号或哈希时账户的字节码（对于合约账户）。
func (a *Account) Code(ctx context.Context) (hexutil.Bytes, error) {
	state, err := a.getState(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return state.GetCode(a.address), nil
}

// Storage returns the value of the storage slot at the given index for the account
// at the given block number or hash.
// Storage 返回给定区块号或哈希时，账户在给定存储槽索引处的值。
func (a *Account) Storage(ctx context.Context, args struct{ Slot common.Hash }) (common.Hash, error) {
	state, err := a.getState(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return state.GetState(a.address, args.Slot), nil
}

// Log represents an individual log message. All arguments are mandatory.
// Log 代表一个独立的日志消息。所有参数都是必需的。
type Log struct {
	r           *Resolver
	transaction *Transaction
	log         *types.Log
}

// Transaction returns the transaction object that generated this log.
// Transaction 返回生成此日志的交易对象。
func (l *Log) Transaction(ctx context.Context) *Transaction {
	return l.transaction
}

// Account returns the account object that emitted this log.
// Account 返回发出此日志的账户对象（通常是合约地址）。
func (l *Log) Account(ctx context.Context, args BlockNumberArgs) *Account {
	return &Account{
		r:             l.r,
		address:       l.log.Address,
		blockNrOrHash: args.NumberOrLatest(),
	}
}

// Index returns the index of this log within the block.
// Index 返回此日志在区块中的索引。
func (l *Log) Index(ctx context.Context) hexutil.Uint64 {
	return hexutil.Uint64(l.log.Index)
}

// Topics returns the list of topics associated with this log.
// Topics 返回与此日志关联的主题列表。
func (l *Log) Topics(ctx context.Context) []common.Hash {
	return l.log.Topics
}

// Data returns the data payload of this log.
// Data 返回此日志的数据载荷。
func (l *Log) Data(ctx context.Context) hexutil.Bytes {
	return l.log.Data
}

// AccessTuple represents EIP-2930 access list entry.
// AccessTuple 代表 EIP-2930 访问列表条目。
type AccessTuple struct {
	address     common.Address
	storageKeys []common.Hash
}

// Address returns the address in the access tuple.
// Address 返回访问元组中的地址。
func (at *AccessTuple) Address(ctx context.Context) common.Address {
	return at.address
}

// StorageKeys returns the storage keys in the access tuple.
// StorageKeys 返回访问元组中的存储键列表。
func (at *AccessTuple) StorageKeys(ctx context.Context) []common.Hash {
	return at.storageKeys
}

// Withdrawal represents a withdrawal of value from the beacon chain
// by a validator. For details see EIP-4895.
// Withdrawal 代表验证者从信标链提取的价值。详情请参阅 EIP-4895。
type Withdrawal struct {
	index     uint64
	validator uint64
	address   common.Address
	amount    uint64
}

// Index returns the index of the withdrawal.
// Index 返回提款的索引。
func (w *Withdrawal) Index(ctx context.Context) hexutil.Uint64 {
	return hexutil.Uint64(w.index)
}

// Validator returns the validator index of the withdrawal.
// Validator 返回提款的验证者索引。
func (w *Withdrawal) Validator(ctx context.Context) hexutil.Uint64 {
	return hexutil.Uint64(w.validator)
}

// Address returns the address of the withdrawal.
// Address 返回提款的地址。
func (w *Withdrawal) Address(ctx context.Context) common.Address {
	return w.address
}

// Amount returns the amount of the withdrawal.
// Amount 返回提款的金额。
func (w *Withdrawal) Amount(ctx context.Context) hexutil.Uint64 {
	return hexutil.Uint64(w.amount)
}

// Transaction represents an Ethereum transaction.
// backend and hash are mandatory; all others will be fetched when required.
// Transaction 代表一个以太坊交易。backend 和 hash 是必需的；所有其他字段将在需要时获取。
type Transaction struct {
	r    *Resolver
	hash common.Hash // Must be present after initialization
	// hash: 初始化后必须存在。
	mu sync.Mutex
	// mu protects following resources
	// mu 保护以下资源。
	tx    *types.Transaction
	block *Block
	index uint64
}

// resolve returns the internal transaction object, fetching it if needed.
// It also returns the block the tx belongs to, unless it is a pending tx.
// resolve 返回内部交易对象，如果需要则获取。它还返回交易所属的区块，除非它是待处理交易。
func (t *Transaction) resolve(ctx context.Context) (*types.Transaction, *Block) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tx != nil {
		return t.tx, t.block
	}
	// Try to return an already finalized transaction
	// 尝试返回一个已经最终确定的交易。
	found, tx, blockHash, _, index, _ := t.r.backend.GetTransaction(ctx, t.hash)
	if found {
		t.tx = tx
		blockNrOrHash := rpc.BlockNumberOrHashWithHash(blockHash, false)
		t.block = &Block{
			r:            t.r,
			numberOrHash: &blockNrOrHash,
			hash:         blockHash,
		}
		t.index = index
		return t.tx, t.block
	}
	// No finalized transaction, try to retrieve it from the pool
	// 没有最终确定的交易，尝试从交易池中检索。
	t.tx = t.r.backend.GetPoolTransaction(t.hash)
	return t.tx, nil
}

// Hash returns the hash of the transaction.
// Hash 返回交易的哈希。
func (t *Transaction) Hash(ctx context.Context) common.Hash {
	return t.hash
}

// InputData returns the input data of the transaction.
// InputData 返回交易的输入数据。对于合约创建交易，这是合约的字节码；对于合约调用，这是函数选择器和参数。
func (t *Transaction) InputData(ctx context.Context) hexutil.Bytes {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Bytes{}
	}
	return tx.Data()
}

// Gas returns the gas limit of the transaction.
// Gas 返回交易的 gas 限制。
func (t *Transaction) Gas(ctx context.Context) hexutil.Uint64 {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return 0
	}
	return hexutil.Uint64(tx.Gas())
}

// GasPrice returns the gas price of the transaction.
// GasPrice 返回交易的 gas 价格。对于 EIP-1559 交易，它会根据基础费用和矿工小费上限计算有效 gas 价格。
func (t *Transaction) GasPrice(ctx context.Context) hexutil.Big {
	tx, block := t.resolve(ctx)
	if tx == nil {
		return hexutil.Big{}
	}
	switch tx.Type() {
	case types.DynamicFeeTxType: // EIP-1559 交易类型
		if block != nil {
			if baseFee, _ := block.BaseFeePerGas(ctx); baseFee != nil {
				// price = min(gasTipCap + baseFee, gasFeeCap)
				gasFeeCap, effectivePrice := tx.GasFeeCap(), new(big.Int).Add(tx.GasTipCap(), baseFee.ToInt())
				if effectivePrice.Cmp(gasFeeCap) < 0 {
					return (hexutil.Big)(*effectivePrice)
				}
				return (hexutil.Big)(*gasFeeCap)
			}
		}
		return hexutil.Big(*tx.GasPrice())
	default: // Legacy 交易类型
		return hexutil.Big(*tx.GasPrice())
	}
}

// EffectiveGasPrice returns the effective gas price of the transaction.
// EffectiveGasPrice 返回交易的有效 gas 价格。
func (t *Transaction) EffectiveGasPrice(ctx context.Context) (*hexutil.Big, error) {
	tx, block := t.resolve(ctx)
	if tx == nil {
		return nil, nil
	}
	// Pending tx
	// 待处理交易
	if block == nil {
		return nil, nil
	}
	header, err := block.resolveHeader(ctx)
	if err != nil || header == nil {
		return nil, err
	}
	if header.BaseFee == nil {
		return (*hexutil.Big)(tx.GasPrice()), nil
	}
	gasFeeCap, effectivePrice := tx.GasFeeCap(), new(big.Int).Add(tx.GasTipCap(), header.BaseFee)
	if effectivePrice.Cmp(gasFeeCap) < 0 {
		return (*hexutil.Big)(effectivePrice), nil
	}
	return (*hexutil.Big)(gasFeeCap), nil
}

// MaxFeePerGas returns the maximum fee per gas for EIP-1559 and blob transactions.
// MaxFeePerGas 返回 EIP-1559 和 blob 交易的最大每 gas 费用。
func (t *Transaction) MaxFeePerGas(ctx context.Context) *hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	switch tx.Type() {
	case types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType: // EIP-1559 和 Blob 交易类型
		return (*hexutil.Big)(tx.GasFeeCap())
	default: // Legacy 交易类型
		return nil
	}
}

// MaxPriorityFeePerGas returns the maximum priority fee per gas for EIP-1559 and blob transactions.
// MaxPriorityFeePerGas 返回 EIP-1559 和 blob 交易的最大每 gas 优先级费用（矿工小费）。
func (t *Transaction) MaxPriorityFeePerGas(ctx context.Context) *hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	switch tx.Type() {
	case types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType: // EIP-1559 和 Blob 交易类型
		return (*hexutil.Big)(tx.GasTipCap())
	default: // Legacy 交易类型
		return nil
	}
}

// MaxFeePerBlobGas returns the maximum fee per blob gas for blob transactions (EIP-4844).
// MaxFeePerBlobGas 返回 blob 交易的最大每 blob gas 费用 (EIP-4844)。
func (t *Transaction) MaxFeePerBlobGas(ctx context.Context) *hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	return (*hexutil.Big)(tx.BlobGasFeeCap())
}

// BlobVersionedHashes returns the versioned hashes of the blobs for blob transactions (EIP-4844).
// BlobVersionedHashes 返回 blob 交易的数据 blob 的版本化哈希列表 (EIP-4844)。
func (t *Transaction) BlobVersionedHashes(ctx context.Context) *[]common.Hash {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	if tx.Type() != types.BlobTxType {
		return nil
	}
	blobHashes := tx.BlobHashes()
	return &blobHashes
}

// EffectiveTip returns the effective miner tip for EIP-1559 transactions.
// EffectiveTip 返回 EIP-1559 交易的有效矿工小费。
func (t *Transaction) EffectiveTip(ctx context.Context) (*hexutil.Big, error) {
	tx, block := t.resolve(ctx)
	if tx == nil {
		return nil, nil
	}
	// Pending tx
	// 待处理交易
	if block == nil {
		return nil, nil
	}
	header, err := block.resolveHeader(ctx)
	if err != nil || header == nil {
		return nil, err
	}
	if header.BaseFee == nil {
		return (*hexutil.Big)(tx.GasPrice()), nil
	}

	tip, err := tx.EffectiveGasTip(header.BaseFee)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(tip), nil
}

// Value returns the amount of Ether transferred in the transaction.
// Value 返回交易中转移的以太币数量。
func (t *Transaction) Value(ctx context.Context) (hexutil.Big, error) {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Big{}, nil
	}
	if tx.Value() == nil {
		return hexutil.Big{}, fmt.Errorf("invalid transaction value %x", t.hash)
		// 错误：无效的交易 value %x。
	}
	return hexutil.Big(*tx.Value()), nil
}

// Nonce returns the nonce of the transaction.
// Nonce 返回交易的 nonce 值。
func (t *Transaction) Nonce(ctx context.Context) hexutil.Uint64 {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return 0
	}
	return hexutil.Uint64(tx.Nonce())
}

// To returns the recipient account of the transaction.
// To 返回交易的接收者账户。
func (t *Transaction) To(ctx context.Context, args BlockNumberArgs) *Account {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	to := tx.To()
	if to == nil {
		return nil // Contract creation transaction
	}
	return &Account{
		r:             t.r,
		address:       *to,
		blockNrOrHash: args.NumberOrLatest(),
	}
}

// From returns the sender account of the transaction.
// From 返回交易的发送者账户。
func (t *Transaction) From(ctx context.Context, args BlockNumberArgs) *Account {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	signer := types.LatestSigner(t.r.backend.ChainConfig())
	from, _ := types.Sender(signer, tx)
	return &Account{
		r:             t.r,
		address:       from,
		blockNrOrHash: args.NumberOrLatest(),
	}
}

// Block returns the block containing the transaction.
// Block 返回包含该交易的区块。
func (t *Transaction) Block(ctx context.Context) *Block {
	_, block := t.resolve(ctx)
	return block
}

// Index returns the index of the transaction within the block.
// Index 返回交易在区块中的索引。
func (t *Transaction) Index(ctx context.Context) *hexutil.Uint64 {
	_, block := t.resolve(ctx)
	// Pending tx
	// 待处理交易
	if block == nil {
		return nil
	}
	index := hexutil.Uint64(t.index)
	return &index
}

// getReceipt returns the receipt associated with this transaction, if any.
// getReceipt 返回与此交易关联的回执（如果存在）。
func (t *Transaction) getReceipt(ctx context.Context) (*types.Receipt, error) {
	_, block := t.resolve(ctx)
	// Pending tx
	// 待处理交易
	if block == nil {
		return nil, nil
	}
	receipts, err := block.resolveReceipts(ctx)
	if err != nil {
		return nil, err
	}
	return receipts[t.index], nil
}

// Status returns the status of the transaction execution. 1 for success, 0 for failure.
// Status 返回交易执行的状态。1 表示成功，0 表示失败。
func (t *Transaction) Status(ctx context.Context) (*hexutil.Uint64, error) {
	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return nil, err
	}
	if len(receipt.PostState) != 0 { // Homestead or later
		return nil, nil
	}
	ret := hexutil.Uint64(receipt.Status)
	return &ret, nil
}

// GasUsed returns the amount of gas used by the transaction.
// GasUsed 返回交易使用的 gas 量。
func (t *Transaction) GasUsed(ctx context.Context) (*hexutil.Uint64, error) {
	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return nil, err
	}
	ret := hexutil.Uint64(receipt.GasUsed)
	return &ret, nil
}

// CumulativeGasUsed returns the total gas used in the block up to and including this transaction.
// CumulativeGasUsed 返回区块中直到并包括此交易为止所使用的总 gas 量。
func (t *Transaction) CumulativeGasUsed(ctx context.Context) (*hexutil.Uint64, error) {
	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return nil, err
	}
	ret := hexutil.Uint64(receipt.CumulativeGasUsed)
	return &ret, nil
}

// BlobGasUsed returns the amount of blob gas used by the transaction (EIP-4844).
// BlobGasUsed 返回交易使用的 blob gas 量 (EIP-4844)。
func (t *Transaction) BlobGasUsed(ctx context.Context) (*hexutil.Uint64, error) {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil, nil
	}
	if tx.Type() != types.BlobTxType {
		return nil, nil
	}

	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return nil, err
	}
	ret := hexutil.Uint64(receipt.BlobGasUsed)
	return &ret, nil
}

// BlobGasPrice returns the price paid per unit of blob gas (EIP-4844).
// BlobGasPrice 返回每单位 blob gas 的支付价格 (EIP-4844)。
func (t *Transaction) BlobGasPrice(ctx context.Context) (*hexutil.Big, error) {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil, nil
	}
	if tx.Type() != types.BlobTxType {
		return nil, nil
	}

	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return nil, err
	}
	ret := (*hexutil.Big)(receipt.BlobGasPrice)
	return ret, nil
}

// CreatedContract returns the account object for the contract created by this transaction (if any).
// CreatedContract 返回由此交易创建的合约的账户对象（如果存在）。
func (t *Transaction) CreatedContract(ctx context.Context, args BlockNumberArgs) (*Account, error) {
	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil || receipt.ContractAddress == (common.Address{}) {
		return nil, err
	}
	return &Account{
		r:             t.r,
		address:       receipt.ContractAddress,
		blockNrOrHash: args.NumberOrLatest(),
	}, nil
}

// Logs returns the list of log messages generated by this transaction.
// Logs 返回由此交易生成的消息日志列表。
func (t *Transaction) Logs(ctx context.Context) (*[]*Log, error) {
	_, block := t.resolve(ctx)
	// Pending tx
	// 待处理交易
	if block == nil {
		return nil, nil
	}
	h, err := block.Hash(ctx)
	if err != nil {
		return nil, err
	}
	return t.getLogs(ctx, h)
}

// getLogs returns log objects for the given tx.
// Assumes block hash is resolved.
// getLogs 返回给定交易的日志对象。假设区块哈希已解析。
func (t *Transaction) getLogs(ctx context.Context, hash common.Hash) (*[]*Log, error) {
	var (
		filter    = t.r.filterSystem.NewBlockFilter(hash, nil, nil)
		logs, err = filter.Logs(ctx)
	)
	if err != nil {
		return nil, err
	}
	var ret []*Log
	// Select tx logs from all block logs
	// 从所有区块日志中选择交易日志。
	ix := sort.Search(len(logs), func(i int) bool { return uint64(logs[i].TxIndex) >= t.index })
	for ix < len(logs) && uint64(logs[ix].TxIndex) == t.index {
		ret = append(ret, &Log{
			r:           t.r,
			transaction: t,
			log:         logs[ix],
		})
		ix++
	}
	return &ret, nil
}

// Type returns the type of the transaction.
// Type 返回交易的类型。
func (t *Transaction) Type(ctx context.Context) *hexutil.Uint64 {
	tx, _ := t.resolve(ctx)
	txType := hexutil.Uint64(tx.Type())
	return &txType
}

// AccessList returns the access list of the transaction (EIP-2930).
// AccessList 返回交易的访问列表 (EIP-2930)。
func (t *Transaction) AccessList(ctx context.Context) *[]*AccessTuple {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return nil
	}
	accessList := tx.AccessList()
	ret := make([]*AccessTuple, 0, len(accessList))
	for _, al := range accessList {
		ret = append(ret, &AccessTuple{
			address:     al.Address,
			storageKeys: al.StorageKeys,
		})
	}
	return &ret
}

// R returns the R component of the ECDSA signature.
// R 返回 ECDSA 签名的 R 分量。
func (t *Transaction) R(ctx context.Context) hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Big{}
	}
	_, r, _ := tx.RawSignatureValues()
	return hexutil.Big(*r)
}

// S returns the S component of the ECDSA signature.
// S 返回 ECDSA 签名的 S 分量。
func (t *Transaction) S(ctx context.Context) hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Big{}
	}
	_, _, s := tx.RawSignatureValues()
	return hexutil.Big(*s)
}

// V returns the recovery ID of the ECDSA signature.
// V 返回 ECDSA 签名的恢复 ID。
func (t *Transaction) V(ctx context.Context) hexutil.Big {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Big{}
	}
	v, _, _ := tx.RawSignatureValues()
	return hexutil.Big(*v)
}

// YParity returns the y-parity of the transaction's signature.
// YParity 返回交易签名的 y 奇偶性。
func (t *Transaction) YParity(ctx context.Context) (*hexutil.Big, error) {
	tx, _ := t.resolve(ctx)
	if tx == nil || tx.Type() == types.LegacyTxType {
		return nil, nil
	}
	v, _, _ := tx.RawSignatureValues()
	ret := hexutil.Big(*v)
	return &ret, nil
}

// Raw returns the RLP-encoded transaction.
// Raw 返回 RLP 编码的交易。
func (t *Transaction) Raw(ctx context.Context) (hexutil.Bytes, error) {
	tx, _ := t.resolve(ctx)
	if tx == nil {
		return hexutil.Bytes{}, nil
	}
	return tx.MarshalBinary()
}

// RawReceipt returns the RLP-encoded transaction receipt.
// RawReceipt 返回 RLP 编码的交易回执。
func (t *Transaction) RawReceipt(ctx context.Context) (hexutil.Bytes, error) {
	receipt, err := t.getReceipt(ctx)
	if err != nil || receipt == nil {
		return hexutil.Bytes{}, err
	}
	return receipt.MarshalBinary()
}

// BlockType represents the type of a block (e.g., full, header). Not currently used.
// BlockType 代表区块的类型（例如，完整区块，区块头）。目前未使用。
type BlockType int

// Block represents an Ethereum block.
// backend, and numberOrHash are mandatory. All other fields are lazily fetched
// when required.
// Block 代表一个以太坊区块。backend 和 numberOrHash 是必需的。所有其他字段在需要时延迟获取。
type Block struct {
	r            *Resolver
	numberOrHash *rpc.BlockNumberOrHash // Field resolvers assume numberOrHash is always present
	// numberOrHash: 字段解析器假定 numberOrHash 始终存在。
	mu sync.Mutex
	// mu protects following resources
	// mu 保护以下资源。
	hash common.Hash // Must be resolved during initialization
	// hash: 初始化期间必须解析。
	header   *types.Header
	block    *types.Block
	receipts []*types.Receipt
}

// resolve returns the internal Block object representing this block, fetching
// it if necessary.
// resolve 返回表示此区块的内部 Block 对象，如果需要则获取。
func (b *Block) resolve(ctx context.Context) (*types.Block, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.block != nil {
		return b.block, nil
	}
	if b.numberOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		b.numberOrHash = &latest
	}
	var err error
	b.block, err = b.r.backend.BlockByNumberOrHash(ctx, *b.numberOrHash)
	if b.block != nil {
		b.hash = b.block.Hash()
		if b.header == nil {
			b.header = b.block.Header()
		}
	}
	return b.block, err
}

// resolveHeader returns the internal Header object for this block, fetching it
// if necessary. Call this function instead of `resolve` unless you need the
// additional data (transactions and uncles).
// resolveHeader 返回此区块的内部 Header 对象，如果需要则获取。除非需要额外的数据（交易和叔块），否则调用此函数而不是 `resolve`。
func (b *Block) resolveHeader(ctx context.Context) (*types.Header, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.header != nil {
		return b.header, nil
	}
	if b.numberOrHash == nil && b.hash == (common.Hash{}) {
		return nil, errBlockInvariant
	}
	var err error
	b.header, err = b.r.backend.HeaderByNumberOrHash(ctx, *b.numberOrHash)
	if err != nil {
		return nil, err
	}
	if b.hash == (common.Hash{}) {
		b.hash = b.header.Hash()
	}
	return b.header, nil
}

// resolveReceipts returns the list of receipts for this block, fetching them
// if necessary.
// resolveReceipts 返回此区块的交易回执列表，如果需要则获取。
func (b *Block) resolveReceipts(ctx context.Context) ([]*types.Receipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.receipts != nil {
		return b.receipts, nil
	}
	receipts, err := b.r.backend.GetReceipts(ctx, b.hash)
	if err != nil {
		return nil, err
	}
	b.receipts = receipts
	return receipts, nil
}

// Number returns the block number.
// Number 返回区块号。
func (b *Block) Number(ctx context.Context) (hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return 0, err
	}

	return hexutil.Uint64(header.Number.Uint64()), nil
}

// Hash returns the block hash.
// Hash 返回区块哈希。
func (b *Block) Hash(ctx context.Context) (common.Hash, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hash, nil
}

// GasLimit returns the block gas limit.
// GasLimit 返回区块 gas 上限。
func (b *Block) GasLimit(ctx context.Context) (hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(header.GasLimit), nil
}

// GasUsed returns the total gas used by all transactions in the block.
// GasUsed 返回区块中所有交易使用的总 gas 量。
func (b *Block) GasUsed(ctx context.Context) (hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(header.GasUsed), nil
}

// BaseFeePerGas returns the base fee per gas of the block (EIP-1559).
// BaseFeePerGas 返回区块的基础 gas 费 (EIP-1559)。
func (b *Block) BaseFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	if header.BaseFee == nil {
		return nil, nil
	}
	return (*hexutil.Big)(header.BaseFee), nil
}

// NextBaseFeePerGas returns the base fee per gas for the next block (EIP-1559).
// NextBaseFeePerGas 返回下一个区块的基础 gas 费 (EIP-1559)。
func (b *Block) NextBaseFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	chaincfg := b.r.backend.ChainConfig()
	if header.BaseFee == nil {
		// Make sure next block doesn't enable EIP-1559
		// 确保下一个区块未启用 EIP-1559。
		if !chaincfg.IsLondon(new(big.Int).Add(header.Number, common.Big1)) {
			return nil, nil
		}
	}
	nextBaseFee := eip1559.CalcBaseFee(chaincfg, header)
	return (*hexutil.Big)(nextBaseFee), nil
}

// Parent returns the parent block.
// Parent 返回父区块。
func (b *Block) Parent(ctx context.Context) (*Block, error) {
	if _, err := b.resolveHeader(ctx); err != nil {
		return nil, err
	}
	if b.header == nil || b.header.Number.Uint64() < 1 {
		return nil, nil
	}
	var (
		num       = rpc.BlockNumber(b.header.Number.Uint64() - 1)
		hash      = b.header.ParentHash
		numOrHash = rpc.BlockNumberOrHash{
			BlockNumber: &num,
			BlockHash:   &hash,
		}
	)
	return &Block{
		r:            b.r,
		numberOrHash: &numOrHash,
		hash:         hash,
	}, nil
}

// Difficulty returns the block difficulty.
// Difficulty 返回区块难度。
func (b *Block) Difficulty(ctx context.Context) (hexutil.Big, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return hexutil.Big{}, err
	}
	return hexutil.Big(*header.Difficulty), nil
}

// Timestamp returns the block timestamp.
// Timestamp 返回区块时间戳。
func (b *Block) Timestamp(ctx context.Context) (hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return 0, err
	}
	return hexutil.Uint64(header.Time), nil
}

// Nonce returns the block nonce.
// Nonce 返回区块 nonce 值。
func (b *Block) Nonce(ctx context.Context) (hexutil.Bytes, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return header.Nonce[:], nil
}

// MixHash returns the mix hash of the block (used in proof-of-work).
// MixHash 返回区块的 mix 哈希（用于工作量证明）。
func (b *Block) MixHash(ctx context.Context) (common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return header.MixDigest, nil
}

// TransactionsRoot returns the root hash of the transactions in the block.
// TransactionsRoot 返回区块中交易的根哈希。
func (b *Block) TransactionsRoot(ctx context.Context) (common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return header.TxHash, nil
}

// StateRoot returns the state root hash of the block.
// StateRoot 返回区块的状态根哈希。
func (b *Block) StateRoot(ctx context.Context) (common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return header.Root, nil
}

// ReceiptsRoot returns the receipts root hash of the block.
// ReceiptsRoot 返回区块的交易回执根哈希。
func (b *Block) ReceiptsRoot(ctx context.Context) (common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return header.ReceiptHash, nil
}

// OmmerHash returns the Keccak-256 hash of the RLP encoded uncle headers.
// OmmerHash 返回 RLP 编码的叔块头列表的 Keccak-256 哈希。
func (b *Block) OmmerHash(ctx context.Context) (common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	return header.UncleHash, nil
}

// OmmerCount returns the number of uncle blocks in the block.
// OmmerCount 返回区块中叔块的数量。
func (b *Block) OmmerCount(ctx context.Context) (*hexutil.Uint64, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	count := hexutil.Uint64(len(block.Uncles()))
	return &count, err
}

// Ommers returns the uncle blocks of the block.
// Ommers 返回区块的叔块列表。
func (b *Block) Ommers(ctx context.Context) (*[]*Block, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	ret := make([]*Block, 0, len(block.Uncles()))
	for _, uncle := range block.Uncles() {
		blockNumberOrHash := rpc.BlockNumberOrHashWithHash(uncle.Hash(), false)
		ret = append(ret, &Block{
			r:            b.r,
			numberOrHash: &blockNumberOrHash,
			header:       uncle,
			hash:         uncle.Hash(),
		})
	}
	return &ret, nil
}

// ExtraData returns the extra data field of the block.
// ExtraData 返回区块的额外数据字段。
func (b *Block) ExtraData(ctx context.Context) (hexutil.Bytes, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return header.Extra, nil
}

// LogsBloom returns the bloom filter of the logs in the block.
// LogsBloom 返回区块中日志的布隆过滤器。
func (b *Block) LogsBloom(ctx context.Context) (hexutil.Bytes, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return header.Bloom.Bytes(), nil
}

// RawHeader returns the RLP encoded block header.
// RawHeader 返回 RLP 编码的区块头。
func (b *Block) RawHeader(ctx context.Context) (hexutil.Bytes, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return rlp.EncodeToBytes(header)
}

// Raw returns the RLP encoded block.
// Raw 返回 RLP 编码的区块。
func (b *Block) Raw(ctx context.Context) (hexutil.Bytes, error) {
	block, err := b.resolve(ctx)
	if err != nil {
		return hexutil.Bytes{}, err
	}
	return rlp.EncodeToBytes(block)
}

// BlockNumberArgs encapsulates arguments to accessors that specify a block number.
// BlockNumberArgs 封装了指定区块号的访问器的参数。
type BlockNumberArgs struct {
	// TODO: Ideally we could use input unions to allow the query to specify the
	// TODO: 理想情况下，我们可以使用输入联合来允许查询通过哈希、区块号或标签指定区块参数，
	// block parameter by hash, block number, or tag but input unions aren't part of the
	// 但输入联合尚不是标准 GraphQL schema SDL 的一部分，请参阅：https://github.com/graphql/graphql-spec/issues/488
	// standard GraphQL schema SDL yet, see: https://github.com/graphql/graphql-spec/issues/488
	Block *Long
}

// NumberOr returns the provided block number argument, or the "current" block number or hash if none
// was provided.
// NumberOr 返回提供的区块号参数，如果未提供，则返回“当前”区块号或哈希。
func (a BlockNumberArgs) NumberOr(current rpc.BlockNumberOrHash) rpc.BlockNumberOrHash {
	if a.Block != nil {
		blockNr := rpc.BlockNumber(*a.Block)
		return rpc.BlockNumberOrHashWithNumber(blockNr)
	}
	return current
}

// NumberOrLatest returns the provided block number argument, or the "latest" block number if none
// was provided.
// NumberOrLatest 返回提供的区块号参数，如果未提供，则返回“最新”区块号。
func (a BlockNumberArgs) NumberOrLatest() rpc.BlockNumberOrHash {
	return a.NumberOr(rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
}

// Miner returns the address of the miner who mined the block.
// Miner 返回挖出该区块的矿工地址。
func (b *Block) Miner(ctx context.Context, args BlockNumberArgs) (*Account, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	return &Account{
		r:             b.r,
		address:       header.Coinbase,
		blockNrOrHash: args.NumberOrLatest(),
	}, nil
}

// TransactionCount returns the number of transactions in the block.
// TransactionCount 返回区块中的交易数量。
func (b *Block) TransactionCount(ctx context.Context) (*hexutil.Uint64, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	count := hexutil.Uint64(len(block.Transactions()))
	return &count, err
}

// Transactions returns the list of transactions in the block.
// Transactions 返回区块中的交易列表。
func (b *Block) Transactions(ctx context.Context) (*[]*Transaction, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	ret := make([]*Transaction, 0, len(block.Transactions()))
	for i, tx := range block.Transactions() {
		ret = append(ret, &Transaction{
			r:     b.r,
			hash:  tx.Hash(),
			tx:    tx,
			block: b,
			index: uint64(i),
		})
	}
	return &ret, nil
}

// TransactionAt returns a specific transaction in the block by index.
// TransactionAt 返回区块中指定索引的交易。
func (b *Block) TransactionAt(ctx context.Context, args struct{ Index Long }) (*Transaction, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	txs := block.Transactions()
	if args.Index < 0 || int(args.Index) >= len(txs) {
		return nil, nil
	}
	tx := txs[args.Index]
	return &Transaction{
		r:     b.r,
		hash:  tx.Hash(),
		tx:    tx,
		block: b,
		index: uint64(args.Index),
	}, nil
}

// OmmerAt returns a specific uncle block in the block by index.
// OmmerAt 返回区块中指定索引的叔块。
func (b *Block) OmmerAt(ctx context.Context, args struct{ Index Long }) (*Block, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	uncles := block.Uncles()
	if args.Index < 0 || int(args.Index) >= len(uncles) {
		return nil, nil
	}
	uncle := uncles[args.Index]
	blockNumberOrHash := rpc.BlockNumberOrHashWithHash(uncle.Hash(), false)
	return &Block{
		r:            b.r,
		numberOrHash: &blockNumberOrHash,
		header:       uncle,
		hash:         uncle.Hash(),
	}, nil
}

// WithdrawalsRoot returns the root hash of the withdrawals in the block (introduced in Shanghai upgrade).
// WithdrawalsRoot 返回区块中提款的根哈希（在上海升级中引入）。
func (b *Block) WithdrawalsRoot(ctx context.Context) (*common.Hash, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	// Pre-shanghai blocks
	// 上海升级之前的区块
	if header.WithdrawalsHash == nil {
		return nil, nil
	}
	return header.WithdrawalsHash, nil
}

// Withdrawals returns the list of withdrawals in the block (introduced in Shanghai upgrade).
// Withdrawals 返回区块中的提款列表（在上海升级中引入）。
func (b *Block) Withdrawals(ctx context.Context) (*[]*Withdrawal, error) {
	block, err := b.resolve(ctx)
	if err != nil || block == nil {
		return nil, err
	}
	// Pre-shanghai blocks
	// 上海升级之前的区块
	if block.Header().WithdrawalsHash == nil {
		return nil, nil
	}
	ret := make([]*Withdrawal, 0, len(block.Withdrawals()))
	for _, w := range block.Withdrawals() {
		ret = append(ret, &Withdrawal{
			index:     w.Index,
			validator: w.Validator,
			address:   w.Address,
			amount:    w.Amount,
		})
	}
	return &ret, nil
}

// BlobGasUsed returns the amount of blob gas used by the transactions in the block (introduced in Cancun upgrade).
// BlobGasUsed 返回区块中交易使用的 blob gas 量（在坎昆升级中引入）。
func (b *Block) BlobGasUsed(ctx context.Context) (*hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	if header.BlobGasUsed == nil {
		return nil, nil
	}
	ret := hexutil.Uint64(*header.BlobGasUsed)
	return &ret, nil
}

// ExcessBlobGas returns the excess blob gas in the block (introduced in Cancun upgrade).
// ExcessBlobGas 返回区块中剩余的 blob gas 量（在坎昆升级中引入）。
func (b *Block) ExcessBlobGas(ctx context.Context) (*hexutil.Uint64, error) {
	header, err := b.resolveHeader(ctx)
	if err != nil {
		return nil, err
	}
	if header.ExcessBlobGas == nil {
		return nil, nil
	}
	ret := hexutil.Uint64(*header.ExcessBlobGas)
	return &ret, nil
}

// BlockFilterCriteria encapsulates criteria passed to a `logs` accessor inside
// a block.
// BlockFilterCriteria 封装了传递给区块内 `logs` 访问器的条件。
type BlockFilterCriteria struct {
	Addresses *[]common.Address // restricts matches to events created by specific contracts
	// 将匹配限制为由特定合约创建的事件。

	// The Topic list restricts matches to particular event topics. Each event has a list
	// of topics. Topics matches a prefix of that list. An empty element slice matches any
	// topic. Non-empty elements represent an alternative that matches any of the
	// contained topics.
	// Topic 列表将匹配限制为特定的事件主题。每个事件都有一个主题列表。Topics 匹配该列表的前缀。
	// 空元素切片匹配任何主题。非空元素表示匹配任何包含主题的替代方案。
	//
	// Examples:
	// {} or nil           matches any topic list
	// {} 或 nil            匹配任何主题列表
	// {{A}}               matches topic A in first position
	// {{A}}               匹配第一个位置的主题 A
	// {{}, {B}}          matches any topic in first position, B in second position
	// {{}, {B}}          匹配第一个位置的任何主题，第二个位置的主题 B
	// {{A}, {B}}          matches topic A in first position, B in second position
	// {{A}, {B}}          匹配第一个位置的主题 A，第二个位置的主题 B
	// {{A, B}}, {C, D}}  matches topic (A OR B) in first position, (C OR D) in second position
	// {{A, B}}, {C, D}}  匹配第一个位置的主题 A 或 B，第二个位置的主题 C 或 D
	Topics *[][]common.Hash
}

// runFilter accepts a filter and executes it, returning all its results as
// `Log` objects.
// runFilter 接收一个过滤器并执行它，将其所有结果作为 `Log` 对象返回。
func runFilter(ctx context.Context, r *Resolver, filter *filters.Filter) ([]*Log, error) {
	logs, err := filter.Logs(ctx)
	if err != nil || logs == nil {
		return nil, err
	}
	ret := make([]*Log, 0, len(logs))
	for _, log := range logs {
		ret = append(ret, &Log{
			r:           r,
			transaction: &Transaction{r: r, hash: log.TxHash},
			log:         log,
		})
	}
	return ret, nil
}

// Logs returns the logs matching the given filter criteria within the block.
// Logs 返回区块内与给定过滤条件匹配的日志。
func (b *Block) Logs(ctx context.Context, args struct{ Filter BlockFilterCriteria }) ([]*Log, error) {
	var addresses []common.Address
	if args.Filter.Addresses != nil {
		addresses = *args.Filter.Addresses
	}
	var topics [][]common.Hash
	if args.Filter.Topics != nil {
		topics = *args.Filter.Topics
	}
	// Construct the range filter
	// 构建范围过滤器
	hash, err := b.Hash(ctx)
	if err != nil {
		return nil, err
	}
	filter := b.r.filterSystem.NewBlockFilter(hash, addresses, topics)

	// Run the filter and return all the logs
	// 运行过滤器并返回所有日志
	return runFilter(ctx, b.r, filter)
}

// Account returns the account information for a given address at the block's state.
// Account 返回给定地址在区块状态下的账户信息。
func (b *Block) Account(ctx context.Context, args struct {
	Address common.Address
}) (*Account, error) {
	return &Account{
		r:             b.r,
		address:       args.Address,
		blockNrOrHash: *b.numberOrHash,
	}, nil
}

// CallData encapsulates arguments to `call` or `estimateGas`.
// All arguments are optional.
// CallData 封装了 `call` 或 `estimateGas` 的参数。所有参数都是可选的。
type CallData struct {
	From *common.Address // The Ethereum address the call is from.
	// 发起调用的以太坊地址。
	To *common.Address // The Ethereum address the call is to.
	// 调用的目标以太坊地址。
	Gas *Long // The amount of gas provided for the call.
	// 为调用提供的 gas 量。
	GasPrice *hexutil.Big // The price of each unit of gas, in wei.
	// 每个 gas 单位的价格，以 wei 为单位。
	MaxFeePerGas *hexutil.Big // The max price of each unit of gas, in wei (1559).
	// 每个 gas 单位的最高价格，以 wei 为单位 (EIP-1559)。
	MaxPriorityFeePerGas *hexutil.Big // The max tip of each unit of gas, in wei (1559).
	// 每个 gas 单位的最高小费，以 wei 为单位 (EIP-1559)。
	Value *hexutil.Big // The value sent along with the call.
	// 随调用一起发送的 value。
	Data *hexutil.Bytes // Any data sent with the call.
	// 随调用一起发送的任何数据。
}

// CallResult encapsulates the result of an invocation of the `call` accessor.
// CallResult 封装了 `call` 访问器调用的结果。
type CallResult struct {
	data hexutil.Bytes // The return data from the call
	// 来自调用的返回数据。
	gasUsed hexutil.Uint64 // The amount of gas used
	// 使用的 gas 量。
	status hexutil.Uint64 // The return status of the call - 0 for failure or 1 for success.
	// 调用的返回状态 - 0 表示失败，1 表示成功。
}

// Data returns the return data of the call.
// Data 返回调用的返回数据。
func (c *CallResult) Data() hexutil.Bytes {
	return c.data
}

// GasUsed returns the amount of gas used by the call.
// GasUsed 返回调用使用的 gas 量。
func (c *CallResult) GasUsed() hexutil.Uint64 {
	return c.gasUsed
}

// Status returns the status of the call (0 for failure, 1 for success).
// Status 返回调用的状态（0 表示失败，1 表示成功）。
func (c *CallResult) Status() hexutil.Uint64 {
	return c.status
}

// Call executes a message call transaction on the state of the given block.
// Call 在给定区块的状态下执行消息调用交易。
func (b *Block) Call(ctx context.Context, args struct {
	Data ethapi.TransactionArgs
}) (*CallResult, error) {
	// ethapi.DoCall executes the call based on the provided arguments and block number/hash.
	// ethapi.DoCall 根据提供的参数和区块号/哈希执行调用。
	result, err := ethapi.DoCall(ctx, b.r.backend, args.Data, *b.numberOrHash, nil, nil, b.r.backend.RPCEVMTimeout(), b.r.backend.RPCGasCap())
	if err != nil {
		return nil, err
	}
	status := hexutil.Uint64(1)
	if result.Failed() {
		status = 0
	}

	return &CallResult{
		data:    result.ReturnData,
		gasUsed: hexutil.Uint64(result.UsedGas),
		status:  status,
	}, nil
}

// EstimateGas executes a message call transaction on the state of the given block and returns the used gas.
// EstimateGas 在给定区块的状态下执行消息调用交易，并返回使用的 gas 量。
func (b *Block) EstimateGas(ctx context.Context, args struct {
	Data ethapi.TransactionArgs
}) (hexutil.Uint64, error) {
	// ethapi.DoEstimateGas estimates the gas required for the transaction.
	// ethapi.DoEstimateGas 估计交易所需的 gas 量。
	return ethapi.DoEstimateGas(ctx, b.r.backend, args.Data, *b.numberOrHash, nil, nil, b.r.backend.RPCGasCap())
}

// Pending represents the pending state of the Ethereum blockchain.
// Pending 代表以太坊区块链的待处理状态。
type Pending struct {
	r *Resolver // Resolver instance for accessing backend functionalities.
	// 用于访问后端功能的 Resolver 实例。
}

// TransactionCount returns the number of pending transactions in the transaction pool.
// TransactionCount 返回交易池中待处理交易的数量。
func (p *Pending) TransactionCount(ctx context.Context) (hexutil.Uint64, error) {
	txs, err := p.r.backend.GetPoolTransactions()
	return hexutil.Uint64(len(txs)), err
}

// Transactions returns the list of pending transactions in the transaction pool.
// Transactions 返回交易池中待处理交易的列表。
func (p *Pending) Transactions(ctx context.Context) (*[]*Transaction, error) {
	txs, err := p.r.backend.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	ret := make([]*Transaction, 0, len(txs))
	for i, tx := range txs {
		ret = append(ret, &Transaction{
			r:     p.r,
			hash:  tx.Hash(),
			tx:    tx,
			index: uint64(i),
		})
	}
	return &ret, nil
}

// Account returns the account information for a given address in the pending state.
// Account 返回给定地址在待处理状态下的账户信息。
func (p *Pending) Account(ctx context.Context, args struct {
	Address common.Address
}) *Account {
	pendingBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	return &Account{
		r:             p.r,
		address:       args.Address,
		blockNrOrHash: pendingBlockNr,
	}
}

// Call executes a message call transaction on the pending state.
// Call 在待处理状态下执行消息调用交易。
func (p *Pending) Call(ctx context.Context, args struct {
	Data ethapi.TransactionArgs
}) (*CallResult, error) {
	pendingBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	result, err := ethapi.DoCall(ctx, p.r.backend, args.Data, pendingBlockNr, nil, nil, p.r.backend.RPCEVMTimeout(), p.r.backend.RPCGasCap())
	if err != nil {
		return nil, err
	}
	status := hexutil.Uint64(1)
	if result.Failed() {
		status = 0
	}

	return &CallResult{
		data:    result.ReturnData,
		gasUsed: hexutil.Uint64(result.UsedGas),
		status:  status,
	}, nil
}

// EstimateGas executes a message call transaction on the latest state and returns the used gas.
// EstimateGas 在最新状态下执行消息调用交易，并返回使用的 gas 量。
func (p *Pending) EstimateGas(ctx context.Context, args struct {
	Data ethapi.TransactionArgs
}) (hexutil.Uint64, error) {
	latestBlockNr := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	return ethapi.DoEstimateGas(ctx, p.r.backend, args.Data, latestBlockNr, nil, nil, p.r.backend.RPCGasCap())
}

// Resolver is the top-level object in the GraphQL hierarchy.
// Resolver 是 GraphQL 层级结构的顶层对象。
type Resolver struct {
	backend ethapi.Backend // Backend interface for interacting with the Ethereum node.
	// 用于与以太坊节点交互的后端接口。
	filterSystem *filters.FilterSystem // Filter system for handling log and block filters.
	// 用于处理日志和区块过滤器的过滤系统。
}

// Block retrieves a specific block by number or hash. If neither is provided, it returns the latest block.
// Block 通过号码或哈希检索特定的区块。如果两者都未提供，则返回最新的区块。
func (r *Resolver) Block(ctx context.Context, args struct {
	Number *Long
	Hash   *common.Hash
}) (*Block, error) {
	if args.Number != nil && args.Hash != nil {
		return nil, errors.New("only one of number or hash must be specified")
	}
	var numberOrHash rpc.BlockNumberOrHash
	if args.Number != nil {
		if *args.Number < 0 {
			return nil, nil
		}
		number := rpc.BlockNumber(*args.Number)
		numberOrHash = rpc.BlockNumberOrHashWithNumber(number)
	} else if args.Hash != nil {
		numberOrHash = rpc.BlockNumberOrHashWithHash(*args.Hash, false)
	} else {
		numberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}
	block := &Block{
		r:            r,
		numberOrHash: &numberOrHash,
	}
	// Resolve the header, return nil if it doesn't exist.
	// Note we don't resolve block directly here since it will require an
	// additional network request for light client.
	// 解析区块头，如果不存在则返回 nil。
	// 注意我们在此不直接解析区块，因为它需要为轻客户端进行额外的网络请求。
	h, err := block.resolveHeader(ctx)
	if err != nil {
		return nil, err
	} else if h == nil {
		return nil, nil
	}
	return block, nil
}

// Blocks retrieves a range of blocks by number.
// Blocks 通过号码检索一系列区块。
func (r *Resolver) Blocks(ctx context.Context, args struct {
	From *Long
	To   *Long
}) ([]*Block, error) {
	if args.From == nil {
		return nil, errors.New("from block number must be specified")
	}
	from := rpc.BlockNumber(*args.From)

	var to rpc.BlockNumber
	if args.To != nil {
		to = rpc.BlockNumber(*args.To)
	} else {
		to = rpc.BlockNumber(r.backend.CurrentBlock().Number.Int64())
	}
	if to < from {
		return nil, errInvalidBlockRange
	}
	var ret []*Block
	for i := from; i <= to; i++ {
		numberOrHash := rpc.BlockNumberOrHashWithNumber(i)
		block := &Block{
			r:            r,
			numberOrHash: &numberOrHash,
		}
		// Resolve the header to check for existence.
		// Note we don't resolve block directly here since it will require an
		// additional network request for light client.
		// 解析区块头以检查是否存在。
		// 注意我们在此不直接解析区块，因为它需要为轻客户端进行额外的网络请求。
		h, err := block.resolveHeader(ctx)
		if err != nil {
			return nil, err
		} else if h == nil {
			// Blocks after must be non-existent too, break.
			// 后续的区块也必定不存在，中断循环。
			break
		}
		ret = append(ret, block)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// Pending returns the pending state object.
// Pending 返回待处理状态对象。
func (r *Resolver) Pending(ctx context.Context) *Pending {
	return &Pending{r}
}

// Transaction retrieves a specific transaction by hash.
// Transaction 通过哈希检索特定的交易。
func (r *Resolver) Transaction(ctx context.Context, args struct{ Hash common.Hash }) *Transaction {
	tx := &Transaction{
		r:    r,
		hash: args.Hash,
	}
	// Resolve the transaction; if it doesn't exist, return nil.
	// 解析交易；如果不存在，则返回 nil。
	t, _ := tx.resolve(ctx)
	if t == nil {
		return nil
	}
	return tx
}

// SendRawTransaction submits a raw transaction to the network.
// SendRawTransaction 向网络提交一个原始交易。
func (r *Resolver) SendRawTransaction(ctx context.Context, args struct{ Data hexutil.Bytes }) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(args.Data); err != nil {
		return common.Hash{}, err
	}
	hash, err := ethapi.SubmitTransaction(ctx, r.backend, tx)
	return hash, err
}

// FilterCriteria encapsulates the arguments to `logs` on the root resolver object.
// FilterCriteria 封装了根解析器对象上 `logs` 的参数。
type FilterCriteria struct {
	FromBlock *Long // beginning of the queried range, nil means genesis block
	// 查询范围的开始，nil 表示创世区块。
	ToBlock *Long // end of the range, nil means latest block
	// 查询范围的结束，nil 表示最新区块。
	Addresses *[]common.Address // restricts matches to events created by specific contracts
	// 将匹配限制为由特定合约创建的事件。

	// The Topic list restricts matches to particular event topics. Each event has a list
	// of topics. Topics matches a prefix of that list. An empty element slice matches any
	// topic. Non-empty elements represent an alternative that matches any of the
	// contained topics.
	// Topic 列表将匹配限制为特定的事件主题。每个事件都有一个主题列表。Topics 匹配该列表的前缀。
	// 空元素切片匹配任何主题。非空元素表示匹配任何包含主题的替代方案。
	//
	// Examples:
	// {} or nil           matches any topic list
	// {} 或 nil            匹配任何主题列表
	// {{A}}               matches topic A in first position
	// {{A}}               匹配第一个位置的主题 A
	// {{}, {B}}          matches any topic in first position, B in second position
	// {{}, {B}}          匹配第一个位置的任何主题，第二个位置的主题 B
	// {{A}, {B}}          matches topic A in first position, B in second position
	// {{A}, {B}}          匹配第一个位置的主题 A，第二个位置的主题 B
	// {{A, B}}, {C, D}}  matches topic (A OR B) in first position, (C OR D) in second position
	// {{A, B}}, {C, D}}  匹配第一个位置的主题 A 或 B，第二个位置的主题 C 或 D
	Topics *[][]common.Hash
}

// Logs retrieves the logs matching the given filter criteria.
// Logs 检索与给定过滤条件匹配的日志。
func (r *Resolver) Logs(ctx context.Context, args struct{ Filter FilterCriteria }) ([]*Log, error) {
	// Convert the RPC block numbers into internal representations
	// 将 RPC 区块号转换为内部表示形式。
	begin := rpc.LatestBlockNumber.Int64()
	if args.Filter.FromBlock != nil {
		begin = int64(*args.Filter.FromBlock)
	}
	end := rpc.LatestBlockNumber.Int64()
	if args.Filter.ToBlock != nil {
		end = int64(*args.Filter.ToBlock)
	}
	if begin > 0 && end > 0 && begin > end {
		return nil, errInvalidBlockRange
	}
	var addresses []common.Address
	if args.Filter.Addresses != nil {
		addresses = *args.Filter.Addresses
	}
	var topics [][]common.Hash
	if args.Filter.Topics != nil {
		topics = *args.Filter.Topics
	}
	// Construct the range filter
	// 构建范围过滤器。
	filter := r.filterSystem.NewRangeFilter(begin, end, addresses, topics)
	return runFilter(ctx, r, filter)
}

// GasPrice retrieves the current suggested gas price.
// GasPrice 检索当前建议的 gas 价格。
func (r *Resolver) GasPrice(ctx context.Context) (hexutil.Big, error) {
	tipcap, err := r.backend.SuggestGasTipCap(ctx)
	if err != nil {
		return hexutil.Big{}, err
	}
	if head := r.backend.CurrentHeader(); head.BaseFee != nil {
		tipcap.Add(tipcap, head.BaseFee)
	}
	return (hexutil.Big)(*tipcap), nil
}

// MaxPriorityFeePerGas retrieves the current suggested max priority fee per gas.
// MaxPriorityFeePerGas 检索当前建议的每 gas 最高优先级费用。
func (r *Resolver) MaxPriorityFeePerGas(ctx context.Context) (hexutil.Big, error) {
	tipcap, err := r.backend.SuggestGasTipCap(ctx)
	if err != nil {
		return hexutil.Big{}, err
	}
	return (hexutil.Big)(*tipcap), nil
}

// ChainID retrieves the current chain ID.
// ChainID 检索当前的链 ID。
func (r *Resolver) ChainID(ctx context.Context) (hexutil.Big, error) {
	return hexutil.Big(*r.backend.ChainConfig().ChainID), nil
}

// SyncState represents the synchronisation status returned from the `syncing` accessor.
// SyncState 表示从 `syncing` 访问器返回的同步状态。
type SyncState struct {
	progress ethereum.SyncProgress
}

// StartingBlock returns the block number this node started to synchronize from.
// StartingBlock 返回此节点开始同步的区块号。
func (s *SyncState) StartingBlock() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.StartingBlock)
}

// CurrentBlock returns the block number this node is currently importing.
// CurrentBlock 返回此节点当前正在导入的区块号。
func (s *SyncState) CurrentBlock() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.CurrentBlock)
}

// HighestBlock returns the block number of the highest block header this node has received from peers.
// HighestBlock 返回此节点从对等节点收到的最高区块头的区块号。
func (s *SyncState) HighestBlock() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HighestBlock)
}

// SyncedAccounts returns the number of accounts downloaded.
// SyncedAccounts 返回已下载的账户数量。
func (s *SyncState) SyncedAccounts() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedAccounts)
}

// SyncedAccountBytes returns the number of account trie bytes persisted to disk.
// SyncedAccountBytes 返回持久化到磁盘的账户 trie 字节数。
func (s *SyncState) SyncedAccountBytes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedAccountBytes)
}

// SyncedBytecodes returns the number of bytecodes downloaded.
// SyncedBytecodes 返回已下载的字节码数量。
func (s *SyncState) SyncedBytecodes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedBytecodes)
}

// SyncedBytecodeBytes returns the number of bytecode bytes downloaded.
// SyncedBytecodeBytes 返回已下载的字节码字节数。
func (s *SyncState) SyncedBytecodeBytes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedBytecodeBytes)
}

// SyncedStorage returns the number of storage slots downloaded.
// SyncedStorage 返回已下载的存储槽数量。
func (s *SyncState) SyncedStorage() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedStorage)
}

// SyncedStorageBytes returns the number of storage trie bytes persisted to disk.
// SyncedStorageBytes 返回持久化到磁盘的存储 trie 字节数。
func (s *SyncState) SyncedStorageBytes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.SyncedStorageBytes)
}

// HealedTrienodes returns the number of state trie nodes downloaded.
// HealedTrienodes 返回已下载的状态 trie 节点数。
func (s *SyncState) HealedTrienodes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealedTrienodes)
}

// HealedTrienodeBytes returns the number of state trie bytes persisted to disk.
// HealedTrienodeBytes 返回持久化到磁盘的状态 trie 字节数。
func (s *SyncState) HealedTrienodeBytes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealedTrienodeBytes)
}

// HealedBytecodes returns the number of bytecodes downloaded.
// HealedBytecodes 返回已下载的字节码数量。
func (s *SyncState) HealedBytecodes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealedBytecodes)
}

// HealedBytecodeBytes returns the number of bytecodes persisted to disk.
// HealedBytecodeBytes 返回持久化到磁盘的字节码字节数。
func (s *SyncState) HealedBytecodeBytes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealedBytecodeBytes)
}

// HealingTrienodes returns the number of state trie nodes pending.
// HealingTrienodes 返回待处理的状态 trie 节点数。
func (s *SyncState) HealingTrienodes() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealingTrienodes)
}

// HealingBytecode returns the number of bytecodes pending.
// HealingBytecode 返回待处理的字节码数量。
func (s *SyncState) HealingBytecode() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.HealingBytecode)
}

// TxIndexFinishedBlocks returns the number of blocks whose transactions are indexed.
// TxIndexFinishedBlocks 返回其交易已被索引的区块数量。
func (s *SyncState) TxIndexFinishedBlocks() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.TxIndexFinishedBlocks)
}

// TxIndexRemainingBlocks returns the number of blocks whose transactions are not indexed yet.
// TxIndexRemainingBlocks 返回其交易尚未索引的区块数量。
func (s *SyncState) TxIndexRemainingBlocks() hexutil.Uint64 {
	return hexutil.Uint64(s.progress.TxIndexRemainingBlocks)
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up-to-date or has not
// yet received the latest block headers from its peers. In case it is synchronizing:
// Syncing 在节点当前未与网络同步时返回 false。它可能已是最新状态，或者尚未收到来自其对等节点的最新区块头。
// 如果正在同步：
// - startingBlock:         block number this node started to synchronize from
// - startingBlock:         此节点开始同步的区块号
// - currentBlock:          block number this node is currently importing
// - currentBlock:          此节点当前正在导入的区块号
// - highestBlock:          block number of the highest block header this node has received from peers
// - highestBlock:          此节点从对等节点收到的最高区块头的区块号
// - syncedAccounts:        number of accounts downloaded
// - syncedAccounts:        已下载的账户数量
// - syncedAccountBytes:    number of account trie bytes persisted to disk
// - syncedAccountBytes:    持久化到磁盘的账户 trie 字节数
// - syncedBytecodes:       number of bytecodes downloaded
// - syncedBytecodes:       已下载的字节码数量
// - syncedBytecodeBytes:   number of bytecode bytes downloaded
// - syncedBytecodeBytes:   已下载的字节码字节数
// - syncedStorage:         number of storage slots downloaded
// - syncedStorage:         已下载的存储槽数量
// - syncedStorageBytes:    number of storage trie bytes persisted to disk
// - syncedStorageBytes:    持久化到磁盘的存储 trie 字节数
// - healedTrienodes:       number of state trie nodes downloaded
// - healedTrienodes:       已下载的状态 trie 节点数
// - healedTrienodeBytes:   number of state trie bytes persisted to disk
// - healedTrienodeBytes:   持久化到磁盘的状态 trie 字节数
// - healedBytecodes:       number of bytecodes downloaded
// - healedBytecodes:       已下载的字节码数量
// - healedBytecodeBytes:   number of bytecodes persisted to disk
// - healedBytecodeBytes:   持久化到磁盘的字节码字节数
// - healingTrienodes:      number of state trie nodes pending
// - healingTrienodes:      待处理的状态 trie 节点数
// - healingBytecode:       number of bytecodes pending
// - healingBytecode:       待处理的字节码数量
// - txIndexFinishedBlocks:   number of blocks whose transactions are indexed
// - txIndexFinishedBlocks:   其交易已被索引的区块数量
// - txIndexRemainingBlocks:  number of blocks whose transactions are not indexed yet
// - txIndexRemainingBlocks:  其交易尚未索引的区块数量
func (r *Resolver) Syncing() (*SyncState, error) {
	progress := r.backend.SyncProgress()

	// Return not syncing if the synchronisation already completed
	// 如果同步已完成，则返回未同步。
	if progress.Done() {
		return nil, nil
	}
	// Otherwise gather the block sync stats
	// 否则收集区块同步统计信息。
	return &SyncState{progress}, nil
}
