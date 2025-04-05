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

package ethapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	gomath "math"
	"math/big"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/gasestimator"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/internal/ethapi/override"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
)

// estimateGasErrorRatio is the amount of overestimation eth_estimateGas is
// allowed to produce in order to speed up calculations.
// estimateGasErrorRatio 是 eth_estimateGas 为加速计算允许产生的过高估计量。
const estimateGasErrorRatio = 0.015

var errBlobTxNotSupported = errors.New("signing blob transactions not supported")

// errBlobTxNotSupported 错误表示不支持签署 blob 交易。

// EthereumAPI provides an API to access Ethereum related information.
// EthereumAPI 提供访问以太坊相关信息的 API。
type EthereumAPI struct {
	b Backend
}

// NewEthereumAPI creates a new Ethereum protocol API.
// NewEthereumAPI 创建一个新的以太坊协议 API。
func NewEthereumAPI(b Backend) *EthereumAPI {
	return &EthereumAPI{b}
}

// GasPrice returns a suggestion for a gas price for legacy transactions.
// GasPrice 返回对遗留交易的 gas 价格的建议。
func (api *EthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := api.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	if head := api.b.CurrentHeader(); head.BaseFee != nil {
		tipcap.Add(tipcap, head.BaseFee)
	}
	return (*hexutil.Big)(tipcap), err
}

// MaxPriorityFeePerGas returns a suggestion for a gas tip cap for dynamic fee transactions.
// MaxPriorityFeePerGas 返回对动态费用交易的 gas tip cap 的建议。
func (api *EthereumAPI) MaxPriorityFeePerGas(ctx context.Context) (*hexutil.Big, error) {
	tipcap, err := api.b.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, err
	}
	return (*hexutil.Big)(tipcap), err
}

type feeHistoryResult struct {
	OldestBlock      *hexutil.Big     `json:"oldestBlock"`
	Reward           [][]*hexutil.Big `json:"reward,omitempty"`
	BaseFee          []*hexutil.Big   `json:"baseFeePerGas,omitempty"`
	GasUsedRatio     []float64        `json:"gasUsedRatio"`
	BlobBaseFee      []*hexutil.Big   `json:"baseFeePerBlobGas,omitempty"`
	BlobGasUsedRatio []float64        `json:"blobGasUsedRatio,omitempty"`
}

// FeeHistory returns the fee market history.
// FeeHistory 返回费用市场历史。
func (api *EthereumAPI) FeeHistory(ctx context.Context, blockCount math.HexOrDecimal64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*feeHistoryResult, error) {
	oldest, reward, baseFee, gasUsed, blobBaseFee, blobGasUsed, err := api.b.FeeHistory(ctx, uint64(blockCount), lastBlock, rewardPercentiles)
	if err != nil {
		return nil, err
	}
	results := &feeHistoryResult{
		OldestBlock:  (*hexutil.Big)(oldest),
		GasUsedRatio: gasUsed,
	}
	if reward != nil {
		results.Reward = make([][]*hexutil.Big, len(reward))
		for i, w := range reward {
			results.Reward[i] = make([]*hexutil.Big, len(w))
			for j, v := range w {
				results.Reward[i][j] = (*hexutil.Big)(v)
			}
		}
	}
	if baseFee != nil {
		results.BaseFee = make([]*hexutil.Big, len(baseFee))
		for i, v := range baseFee {
			results.BaseFee[i] = (*hexutil.Big)(v)
		}
	}
	if blobBaseFee != nil {
		results.BlobBaseFee = make([]*hexutil.Big, len(blobBaseFee))
		for i, v := range blobBaseFee {
			results.BlobBaseFee[i] = (*hexutil.Big)(v)
		}
	}
	if blobGasUsed != nil {
		results.BlobGasUsedRatio = blobGasUsed
	}
	return results, nil
}

// BlobBaseFee returns the base fee for blob gas at the current head.
// BlobBaseFee 返回当前头部 blob gas 的基础费用。
func (api *EthereumAPI) BlobBaseFee(ctx context.Context) *hexutil.Big {
	return (*hexutil.Big)(api.b.BlobBaseFee(ctx))
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up-to-date or has not
// yet received the latest block headers from its peers. In case it is synchronizing:
// - startingBlock: block number this node started to synchronize from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
// Syncing 如果节点当前没有与网络同步，则返回 false。它可能是最新的，或者尚未从 peers 接收到最新的块头。如果正在同步：
// - startingBlock: 节点开始同步的块号
// - currentBlock:  节点当前正在导入的块号
// - highestBlock:  节点从 peers 接收到的最高块头的块号
// - pulledStates:  迄今为止处理的状态条目数
// - knownStates:   仍需要拉取的已知状态条目数
func (api *EthereumAPI) Syncing() (interface{}, error) {
	progress := api.b.SyncProgress()

	// Return not syncing if the synchronisation already completed
	if progress.Done() {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock":          hexutil.Uint64(progress.StartingBlock),
		"currentBlock":           hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":           hexutil.Uint64(progress.HighestBlock),
		"syncedAccounts":         hexutil.Uint64(progress.SyncedAccounts),
		"syncedAccountBytes":     hexutil.Uint64(progress.SyncedAccountBytes),
		"syncedBytecodes":        hexutil.Uint64(progress.SyncedBytecodes),
		"syncedBytecodeBytes":    hexutil.Uint64(progress.SyncedBytecodeBytes),
		"syncedStorage":          hexutil.Uint64(progress.SyncedStorage),
		"syncedStorageBytes":     hexutil.Uint64(progress.SyncedStorageBytes),
		"healedTrienodes":        hexutil.Uint64(progress.HealedTrienodes),
		"healedTrienodeBytes":    hexutil.Uint64(progress.HealedTrienodeBytes),
		"healedBytecodes":        hexutil.Uint64(progress.HealedBytecodes),
		"healedBytecodeBytes":    hexutil.Uint64(progress.HealedBytecodeBytes),
		"healingTrienodes":       hexutil.Uint64(progress.HealingTrienodes),
		"healingBytecode":        hexutil.Uint64(progress.HealingBytecode),
		"txIndexFinishedBlocks":  hexutil.Uint64(progress.TxIndexFinishedBlocks),
		"txIndexRemainingBlocks": hexutil.Uint64(progress.TxIndexRemainingBlocks),
	}, nil
}

// TxPoolAPI offers and API for the transaction pool. It only operates on data that is non-confidential.
// TxPoolAPI 提供交易池的 API。它仅对非机密数据进行操作。
type TxPoolAPI struct {
	b Backend
}

// NewTxPoolAPI creates a new tx pool service that gives information about the transaction pool.
// NewTxPoolAPI 创建一个新的交易池服务，提供有关交易池的信息。
func NewTxPoolAPI(b Backend) *TxPoolAPI {
	return &TxPoolAPI{b}
}

// Content returns the transactions contained within the transaction pool.
// Content 返回交易池中包含的交易。
func (api *TxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := api.b.TxPoolContent()
	curHeader := api.b.CurrentHeader()
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, api.b.ChainConfig())
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, api.b.ChainConfig())
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// ContentFrom returns the transactions contained within the transaction pool.
// ContentFrom 返回交易池中包含的交易。
func (api *TxPoolAPI) ContentFrom(addr common.Address) map[string]map[string]*RPCTransaction {
	content := make(map[string]map[string]*RPCTransaction, 2)
	pending, queue := api.b.TxPoolContentFrom(addr)
	curHeader := api.b.CurrentHeader()

	// Build the pending transactions
	dump := make(map[string]*RPCTransaction, len(pending))
	for _, tx := range pending {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, api.b.ChainConfig())
	}
	content["pending"] = dump

	// Build the queued transactions
	dump = make(map[string]*RPCTransaction, len(queue))
	for _, tx := range queue {
		dump[fmt.Sprintf("%d", tx.Nonce())] = NewRPCPendingTransaction(tx, curHeader, api.b.ChainConfig())
	}
	content["queued"] = dump

	return content
}

// Status returns the number of pending and queued transaction in the pool.
// Status 返回池中挂起和排队的交易数量。
func (api *TxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := api.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the transaction pool and flattens it into an
// easily inspectable list.
// Inspect 检索交易池的内容并将其扁平化为易于检查的列表。
func (api *TxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := api.b.TxPoolContent()

	// Define a formatter to flatten a transaction into a string
	format := func(tx *types.Transaction) string {
		if to := tx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v gas × %v wei", tx.To().Hex(), tx.Value(), tx.Gas(), tx.GasPrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v gas × %v wei", tx.Value(), tx.Gas(), tx.GasPrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// EthereumAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
// EthereumAccountAPI 提供访问此节点管理的账户的 API。
// 它仅提供可以检索账户的方法。
type EthereumAccountAPI struct {
	am *accounts.Manager
}

// NewEthereumAccountAPI creates a new EthereumAccountAPI.
// NewEthereumAccountAPI 创建一个新的 EthereumAccountAPI。
func NewEthereumAccountAPI(am *accounts.Manager) *EthereumAccountAPI {
	return &EthereumAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages.
// Accounts 返回此节点管理的账户集合。
func (api *EthereumAccountAPI) Accounts() []common.Address {
	return api.am.Accounts()
}

// BlockChainAPI provides an API to access Ethereum blockchain data.
// BlockChainAPI 提供访问以太坊区块链数据的 API。
type BlockChainAPI struct {
	b Backend
}

// NewBlockChainAPI creates a new Ethereum blockchain API.
// NewBlockChainAPI 创建一个新的以太坊区块链 API。
func NewBlockChainAPI(b Backend) *BlockChainAPI {
	return &BlockChainAPI{b}
}

// ChainId is the EIP-155 replay-protection chain id for the current Ethereum chain config.
//
// Note, this method does not conform to EIP-695 because the configured chain ID is always
// returned, regardless of the current head block. We used to return an error when the chain
// wasn't synced up to a block where EIP-155 is enabled, but this behavior caused issues
// in CL clients.
// ChainId 是当前以太坊链配置的 EIP-155 重放保护链 ID。
//
// 注意，此方法不符合 EIP-695，因为始终返回配置的链 ID，而不考虑当前头部块。
// 我们过去在链未同步到启用 EIP-155 的块时返回错误，但这种行为在 CL 客户端中引起了问题。
func (api *BlockChainAPI) ChainId() *hexutil.Big {
	return (*hexutil.Big)(api.b.ChainConfig().ChainID)
}

// BlockNumber returns the block number of the chain head.
// BlockNumber 返回链头部的块号。
func (api *BlockChainAPI) BlockNumber() hexutil.Uint64 {
	header, _ := api.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64())
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
// GetBalance 返回给定块号状态下给定地址的 wei 数量。rpc.LatestBlockNumber 和 rpc.PendingBlockNumber 元块号也是允许的。
func (api *BlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Big, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	b := state.GetBalance(address).ToBig()
	return (*hexutil.Big)(b), state.Error()
}

// AccountResult structs for GetProof
// AccountResult 用于 GetProof 的结构
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}

type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// proofList implements ethdb.KeyValueWriter and collects the proofs as
// hex-strings for delivery to rpc-caller.
// proofList 实现 ethdb.KeyValueWriter 并收集证明为十六进制字符串以传递给 rpc 调用者。
type proofList []string

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
// GetProof 返回给定账户的 Merkle 证明，以及可选的某些存储键。
func (api *BlockChainAPI) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNrOrHash rpc.BlockNumberOrHash) (*AccountResult, error) {
	var (
		keys         = make([]common.Hash, len(storageKeys))
		keyLengths   = make([]int, len(storageKeys))
		storageProof = make([]StorageResult, len(storageKeys))
	)
	// Deserialize all keys. This prevents state access on invalid input.
	for i, hexKey := range storageKeys {
		var err error
		keys[i], keyLengths[i], err = decodeHash(hexKey)
		if err != nil {
			return nil, err
		}
	}
	statedb, header, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if statedb == nil || err != nil {
		return nil, err
	}
	codeHash := statedb.GetCodeHash(address)
	storageRoot := statedb.GetStorageRoot(address)

	if len(keys) > 0 {
		var storageTrie state.Trie
		if storageRoot != types.EmptyRootHash && storageRoot != (common.Hash{}) {
			id := trie.StorageTrieID(header.Root, crypto.Keccak256Hash(address.Bytes()), storageRoot)
			st, err := trie.NewStateTrie(id, statedb.Database().TrieDB())
			if err != nil {
				return nil, err
			}
			storageTrie = st
		}
		// Create the proofs for the storageKeys.
		for i, key := range keys {
			// Output key encoding is a bit special: if the input was a 32-byte hash, it is
			// returned as such. Otherwise, we apply the QUANTITY encoding mandated by the
			// JSON-RPC spec for getProof. This behavior exists to preserve backwards
			// compatibility with older client versions.
			var outputKey string
			if keyLengths[i] != 32 {
				outputKey = hexutil.EncodeBig(key.Big())
			} else {
				outputKey = hexutil.Encode(key[:])
			}
			if storageTrie == nil {
				storageProof[i] = StorageResult{outputKey, &hexutil.Big{}, []string{}}
				continue
			}
			var proof proofList
			if err := storageTrie.Prove(crypto.Keccak256(key.Bytes()), &proof); err != nil {
				return nil, err
			}
			value := (*hexutil.Big)(statedb.GetState(address, key).Big())
			storageProof[i] = StorageResult{outputKey, value, proof}
		}
	}
	// Create the accountProof.
	tr, err := trie.NewStateTrie(trie.StateTrieID(header.Root), statedb.Database().TrieDB())
	if err != nil {
		return nil, err
	}
	var accountProof proofList
	if err := tr.Prove(crypto.Keccak256(address.Bytes()), &accountProof); err != nil {
		return nil, err
	}
	balance := statedb.GetBalance(address).ToBig()
	return &AccountResult{
		Address:      address,
		AccountProof: accountProof,
		Balance:      (*hexutil.Big)(balance),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(statedb.GetNonce(address)),
		StorageHash:  storageRoot,
		StorageProof: storageProof,
	}, statedb.Error()
}

// decodeHash parses a hex-encoded 32-byte hash. The input may optionally
// be prefixed by 0x and can have a byte length up to 32.
// decodeHash 解析一个十六进制编码的 32 字节哈希。输入可以选择性地以 0x 为前缀，并且字节长度最多为 32。
func decodeHash(s string) (h common.Hash, inputLength int, err error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if (len(s) & 1) > 0 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, 0, errors.New("hex string invalid")
	}
	if len(b) > 32 {
		return common.Hash{}, len(b), errors.New("hex string too long, want at most 32 bytes")
	}
	return common.BytesToHash(b), len(b), nil
}

// GetHeaderByNumber returns the requested canonical block header.
//   - When blockNr is -1 the chain pending header is returned.
//   - When blockNr is -2 the chain latest header is returned.
//   - When blockNr is -3 the chain finalized header is returned.
//   - When blockNr is -4 the chain safe header is returned.
//
// GetHeaderByNumber 返回请求的规范块头。
//   - 当 blockNr 为 -1 时，返回链的挂起块头。
//   - 当 blockNr 为 -2 时，返回链的最新块头。
//   - 当 blockNr 为 -3 时，返回链的最终化块头。
//   - 当 blockNr 为 -4 时，返回链的安全块头。
func (api *BlockChainAPI) GetHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (map[string]interface{}, error) {
	header, err := api.b.HeaderByNumber(ctx, number)
	if header != nil && err == nil {
		response := RPCMarshalHeader(header)
		if number == rpc.PendingBlockNumber {
			// Pending header need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetHeaderByHash returns the requested header by hash.
// GetHeaderByHash 按哈希返回请求的块头。
func (api *BlockChainAPI) GetHeaderByHash(ctx context.Context, hash common.Hash) map[string]interface{} {
	header, _ := api.b.HeaderByHash(ctx, hash)
	if header != nil {
		return RPCMarshalHeader(header)
	}
	return nil
}

// GetBlockByNumber returns the requested canonical block.
//   - When blockNr is -1 the chain pending block is returned.
//   - When blockNr is -2 the chain latest block is returned.
//   - When blockNr is -3 the chain finalized block is returned.
//   - When blockNr is -4 the chain safe block is returned.
//   - When fullTx is true all transactions in the block are returned, otherwise
//     only the transaction hash is returned.
//
// GetBlockByNumber 返回请求的规范块。
//   - 当 blockNr 为 -1 时，返回链的挂起块。
//   - 当 blockNr 为 -2 时，返回链的最新块。
//   - 当 blockNr 为 -3 时，返回链的最终化块。
//   - 当 blockNr 为 -4 时，返回链的安全块。
//   - 当 fullTx 为 true 时，返回块中的所有交易，否则只返回交易哈希。
func (api *BlockChainAPI) GetBlockByNumber(ctx context.Context, number rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := api.b.BlockByNumber(ctx, number)
	if block != nil && err == nil {
		response := RPCMarshalBlock(block, true, fullTx, api.b.ChainConfig())
		if number == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, nil
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
// GetBlockByHash 返回请求的块。当 fullTx 为 true 时，返回块中的所有交易的完整细节，否则只返回交易哈希。
func (api *BlockChainAPI) GetBlockByHash(ctx context.Context, hash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := api.b.BlockByHash(ctx, hash)
	if block != nil {
		return RPCMarshalBlock(block, true, fullTx, api.b.ChainConfig()), nil
	}
	return nil, err
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index.
// GetUncleByBlockNumberAndIndex 返回给定块哈希和索引的叔块。
func (api *BlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := api.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return RPCMarshalBlock(block, false, false, api.b.ChainConfig()), nil
	}
	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index.
// GetUncleByBlockHashAndIndex 返回给定块哈希和索引的叔块。
func (api *BlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := api.b.BlockByHash(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return RPCMarshalBlock(block, false, false, api.b.ChainConfig()), nil
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
// GetUncleCountByBlockNumber 返回给定块号的块中的叔块数量
func (api *BlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := api.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
// GetUncleCountByBlockHash 返回给定块哈希的块中的叔块数量
func (api *BlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := api.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
// GetCode 返回给定块号状态下给定地址存储的代码。
func (api *BlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
// GetStorageAt 返回给定地址、键和块号的状态中的存储。rpc.LatestBlockNumber 和 rpc.PendingBlockNumber 元块号也是允许的。
func (api *BlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, hexKey string, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	key, _, err := decodeHash(hexKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode storage key: %s", err)
	}
	res := state.GetState(address, key)
	return res[:], state.Error()
}

// GetBlockReceipts returns the block receipts for the given block hash or number or tag.
// GetBlockReceipts 返回给定块哈希、块号或标签的块收据。
func (api *BlockChainAPI) GetBlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]map[string]interface{}, error) {
	block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
	if block == nil || err != nil {
		// When the block doesn't exist, the RPC method should return JSON null
		// as per specification.
		return nil, nil
	}
	receipts, err := api.b.GetReceipts(ctx, block.Hash())
	if err != nil {
		return nil, err
	}
	txs := block.Transactions()
	if len(txs) != len(receipts) {
		return nil, fmt.Errorf("receipts length mismatch: %d vs %d", len(txs), len(receipts))
	}

	// Derive the sender.
	signer := types.MakeSigner(api.b.ChainConfig(), block.Number(), block.Time())

	result := make([]map[string]interface{}, len(receipts))
	for i, receipt := range receipts {
		result[i] = marshalReceipt(receipt, block.Hash(), block.NumberU64(), signer, txs[i], i)
	}

	return result, nil
}

// ChainContextBackend provides methods required to implement ChainContext.
// ChainContextBackend 提供实现 ChainContext 所需的方法。
type ChainContextBackend interface {
	Engine() consensus.Engine
	HeaderByNumber(context.Context, rpc.BlockNumber) (*types.Header, error)
}

// ChainContext is an implementation of core.ChainContext. It's main use-case
// is instantiating a vm.BlockContext without having access to the BlockChain object.
// ChainContext 是 core.ChainContext 的实现。它的主要用例是在没有访问 BlockChain 对象的情况下实例化 vm.BlockContext。
type ChainContext struct {
	b   ChainContextBackend
	ctx context.Context
}

// NewChainContext creates a new ChainContext object.
// NewChainContext 创建一个新的 ChainContext 对象。
func NewChainContext(ctx context.Context, backend ChainContextBackend) *ChainContext {
	return &ChainContext{ctx: ctx, b: backend}
}

func (context *ChainContext) Engine() consensus.Engine {
	return context.b.Engine()
}

func (context *ChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	// This method is called to get the hash for a block number when executing the BLOCKHASH
	// opcode. Hence no need to search for non-canonical blocks.
	// 此方法在执行 BLOCKHASH 操作码时被调用以获取块号的哈希。因此无需搜索非规范块。
	header, err := context.b.HeaderByNumber(context.ctx, rpc.BlockNumber(number))
	if err != nil || header.Hash() != hash {
		return nil
	}
	return header
}

func doCall(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if blockOverrides != nil {
		blockOverrides.Apply(&blockCtx)
	}
	rules := b.ChainConfig().Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time)
	precompiles := vm.ActivePrecompiledContracts(rules)
	if err := overrides.Apply(state, precompiles); err != nil {
		return nil, err
	}

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	// 设置上下文，以便在调用完成时可以取消，或者在无计量 gas 的情况下，设置带有超时的上下文。
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	// 确保在调用完成时取消上下文，以确保资源被清理。
	defer cancel()
	gp := new(core.GasPool)
	if globalGasCap == 0 {
		gp.AddGas(gomath.MaxUint64)
	} else {
		gp.AddGas(globalGasCap)
	}
	return applyMessage(ctx, b, args, state, header, timeout, gp, &blockCtx, &vm.Config{NoBaseFee: true}, precompiles, true)
}

func applyMessage(ctx context.Context, b Backend, args TransactionArgs, state *state.StateDB, header *types.Header, timeout time.Duration, gp *core.GasPool, blockContext *vm.BlockContext, vmConfig *vm.Config, precompiles vm.PrecompiledContracts, skipChecks bool) (*core.ExecutionResult, error) {
	// Get a new instance of the EVM.
	// 获取 EVM 的新实例。
	if err := args.CallDefaults(gp.Gas(), blockContext.BaseFee, b.ChainConfig().ChainID); err != nil {
		return nil, err
	}
	msg := args.ToMessage(header.BaseFee, skipChecks, skipChecks)
	// Lower the basefee to 0 to avoid breaking EVM
	// invariants (basefee < feecap).
	// 将 basefee 降低到 0，以避免破坏 EVM 不变性（basefee < feecap）。
	if msg.GasPrice.Sign() == 0 {
		blockContext.BaseFee = new(big.Int)
	}
	if msg.BlobGasFeeCap != nil && msg.BlobGasFeeCap.BitLen() == 0 {
		blockContext.BlobBaseFee = new(big.Int)
	}
	evm := b.GetEVM(ctx, state, header, vmConfig, blockContext)
	if precompiles != nil {
		evm.SetPrecompiles(precompiles)
	}
	res, err := applyMessageWithEVM(ctx, evm, msg, timeout, gp)
	// If an internal state error occurred, let that have precedence. Otherwise,
	// a "trie root missing" type of error will masquerade as e.g. "insufficient gas"
	// 如果发生内部状态错误，则优先处理。否则，“trie root missing” 类型的错误会伪装成“gas 不足”等。
	if err := state.Error(); err != nil {
		return nil, err
	}
	return res, err
}

func applyMessageWithEVM(ctx context.Context, evm *vm.EVM, msg *core.Message, timeout time.Duration, gp *core.GasPool) (*core.ExecutionResult, error) {
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	// 等待上下文完成并取消 EVM。即使 EVM 已完成，取消操作也可以进行（重复）。
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Execute the message.
	// 执行消息。
	result, err := core.ApplyMessage(evm, msg, gp)

	// If the timer caused an abort, return an appropriate error message
	// 如果计时器导致中止，返回适当的错误消息。
	if evm.Cancelled() {
		return nil, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	if err != nil {
		return result, fmt.Errorf("err: %w (supplied gas %d)", err, msg.GasLimit)
	}
	return result, nil
}

func DoCall(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, timeout time.Duration, globalGasCap uint64) (*core.ExecutionResult, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	return doCall(ctx, b, args, state, header, overrides, blockOverrides, timeout, globalGasCap)
}

// Call executes the given transaction on the state for the given block number.
// Additionally, the caller can specify a batch of contract for fields overriding.
// Note, this function doesn't make and changes in the state/blockchain and is
// useful to execute and retrieve values.
// Call 在给定块号的状态上执行给定的交易。
// 此外，调用者可以指定一批合约字段覆盖。
// 注意，此函数不会在状态/区块链中进行任何更改，适用于执行和检索值。
func (api *BlockChainAPI) Call(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides) (hexutil.Bytes, error) {
	if blockNrOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &latest
	}
	result, err := DoCall(ctx, api.b, args, *blockNrOrHash, overrides, blockOverrides, api.b.RPCEVMTimeout(), api.b.RPCGasCap())
	if err != nil {
		return nil, err
	}
	// If the result contains a revert reason, try to unpack and return it.
	// 如果结果包含 revert 原因，尝试解包并返回。
	if len(result.Revert()) > 0 {
		return nil, newRevertError(result.Revert())
	}
	return result.Return(), result.Err
}

// SimulateV1 executes series of transactions on top of a base state.
// The transactions are packed into blocks. For each block, block header
// fields can be overridden. The state can also be overridden prior to
// execution of each block.
// Note, this function doesn't make any changes in the state/blockchain and is
// useful to execute and retrieve values.
// SimulateV1 在基础状态之上执行一系列交易。
// 交易被打包成块。对于每个块，块头字段可以被覆盖。状态也可以在每个块执行之前被覆盖。
// 注意，此函数不会在状态/区块链中进行任何更改，适用于执行和检索值。
func (api *BlockChainAPI) SimulateV1(ctx context.Context, opts simOpts, blockNrOrHash *rpc.BlockNumberOrHash) ([]map[string]interface{}, error) {
	if len(opts.BlockStateCalls) == 0 {
		return nil, &invalidParamsError{message: "empty input"}
	} else if len(opts.BlockStateCalls) > maxSimulateBlocks {
		return nil, &clientLimitExceededError{message: "too many blocks"}
	}
	if blockNrOrHash == nil {
		n := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &n
	}
	state, base, err := api.b.StateAndHeaderByNumberOrHash(ctx, *blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	gasCap := api.b.RPCGasCap()
	if gasCap == 0 {
		gasCap = gomath.MaxUint64
	}
	sim := &simulator{
		b:           api.b,
		state:       state,
		base:        base,
		chainConfig: api.b.ChainConfig(),
		// Each tx and all the series of txes shouldn't consume more gas than cap
		// 每个 tx 和所有 tx 系列不应该消耗超过 cap 的 gas
		gp:             new(core.GasPool).AddGas(gasCap),
		traceTransfers: opts.TraceTransfers,
		validate:       opts.Validation,
		fullTx:         opts.ReturnFullTransactions,
	}
	return sim.execute(ctx, opts.BlockStateCalls)
}

// DoEstimateGas returns the lowest possible gas limit that allows the transaction to run
// successfully at block `blockNrOrHash`. It returns error if the transaction would revert, or if
// there are unexpected failures. The gas limit is capped by both `args.Gas` (if non-nil &
// non-zero) and `gasCap` (if non-zero).
// DoEstimateGas 返回允许交易在块 `blockNrOrHash` 成功运行的最低 gas 限制。
// 如果交易会 revert 或发生意外失败，则返回错误。gas 限制由 `args.Gas`（如果非 nil 且非零）和 `gasCap`（如果非零）限制。
func DoEstimateGas(ctx context.Context, b Backend, args TransactionArgs, blockNrOrHash rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides, gasCap uint64) (hexutil.Uint64, error) {
	// Retrieve the base state and mutate it with any overrides
	// 获取基础状态并使用任何覆盖进行变异
	state, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return 0, err
	}
	if err := overrides.Apply(state, nil); err != nil {
		return 0, err
	}
	// Construct the gas estimator option from the user input
	// 从用户输入构建 gas 估算器选项
	opts := &gasestimator.Options{
		Config:         b.ChainConfig(),
		Chain:          NewChainContext(ctx, b),
		Header:         header,
		BlockOverrides: blockOverrides,
		State:          state,
		ErrorRatio:     estimateGasErrorRatio,
	}
	// Set any required transaction default, but make sure the gas cap itself is not messed with
	// if it was not specified in the original argument list.
	// 设置任何所需的交易默认值，但确保 gas cap 本身不会被修改，如果它未在原始参数列表中指定。
	if args.Gas == nil {
		args.Gas = new(hexutil.Uint64)
	}
	if err := args.CallDefaults(gasCap, header.BaseFee, b.ChainConfig().ChainID); err != nil {
		return 0, err
	}
	call := args.ToMessage(header.BaseFee, true, true)

	// Run the gas estimation and wrap any revertals into a custom return
	// 运行 gas 估算并将任何 revert 包装到自定义返回中
	estimate, revert, err := gasestimator.Estimate(ctx, call, opts, gasCap)
	if err != nil {
		if len(revert) > 0 {
			return 0, newRevertError(revert)
		}
		return 0, err
	}
	return hexutil.Uint64(estimate), nil
}

// EstimateGas returns the lowest possible gas limit that allows the transaction to run
// successfully at block `blockNrOrHash`, or the latest block if `blockNrOrHash` is unspecified. It
// returns error if the transaction would revert or if there are unexpected failures. The returned
// value is capped by both `args.Gas` (if non-nil & non-zero) and the backend's RPCGasCap
// configuration (if non-zero).
// Note: Required blob gas is not computed in this method.
// EstimateGas 返回允许交易在块 `blockNrOrHash`（如果未指定则为最新块）成功运行的最低 gas 限制。
// 如果交易会 revert 或发生意外失败，则返回错误。返回值由 `args.Gas`（如果非 nil 且非零）和后端的 RPCGasCap 配置（如果非零）限制。
// 注意：此方法中不计算所需的 blob gas。
func (api *BlockChainAPI) EstimateGas(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides) (hexutil.Uint64, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}
	return DoEstimateGas(ctx, api.b, args, bNrOrHash, overrides, blockOverrides, api.b.RPCGasCap())
}

// RPCMarshalHeader converts the given header to the RPC output .
// RPCMarshalHeader 将给定的 header 转换为 RPC 输出。
func RPCMarshalHeader(head *types.Header) map[string]interface{} {
	result := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             head.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        hexutil.Uint64(head.Time),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}
	if head.BaseFee != nil {
		result["baseFeePerGas"] = (*hexutil.Big)(head.BaseFee)
	}
	if head.WithdrawalsHash != nil {
		result["withdrawalsRoot"] = head.WithdrawalsHash
	}
	if head.BlobGasUsed != nil {
		result["blobGasUsed"] = hexutil.Uint64(*head.BlobGasUsed)
	}
	if head.ExcessBlobGas != nil {
		result["excessBlobGas"] = hexutil.Uint64(*head.ExcessBlobGas)
	}
	if head.ParentBeaconRoot != nil {
		result["parentBeaconBlockRoot"] = head.ParentBeaconRoot
	}
	if head.RequestsHash != nil {
		result["requestsHash"] = head.RequestsHash
	}
	return result
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
// RPCMarshalBlock 将给定的块转换为 RPC 输出，具体取决于 fullTx。如果 inclTx 为 true，则返回交易。
// 当 fullTx 为 true 时，返回的块包含完整的交易详情，否则只包含交易哈希。
func RPCMarshalBlock(block *types.Block, inclTx bool, fullTx bool, config *params.ChainConfig) map[string]interface{} {
	fields := RPCMarshalHeader(block.Header())
	fields["size"] = hexutil.Uint64(block.Size())

	if inclTx {
		formatTx := func(idx int, tx *types.Transaction) interface{} {
			return tx.Hash()
		}
		if fullTx {
			formatTx = func(idx int, tx *types.Transaction) interface{} {
				return newRPCTransactionFromBlockIndex(block, uint64(idx), config)
			}
		}
		txs := block.Transactions()
		transactions := make([]interface{}, len(txs))
		for i, tx := range txs {
			transactions[i] = formatTx(i, tx)
		}
		fields["transactions"] = transactions
	}
	uncles := block.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes
	if block.Withdrawals() != nil {
		fields["withdrawals"] = block.Withdrawals()
	}
	return fields
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
// RPCTransaction 表示一个交易，将序列化为交易的 RPC 表示
type RPCTransaction struct {
	BlockHash           *common.Hash                 `json:"blockHash"`
	BlockNumber         *hexutil.Big                 `json:"blockNumber"`
	From                common.Address               `json:"from"`
	Gas                 hexutil.Uint64               `json:"gas"`
	GasPrice            *hexutil.Big                 `json:"gasPrice"`
	GasFeeCap           *hexutil.Big                 `json:"maxFeePerGas,omitempty"`
	GasTipCap           *hexutil.Big                 `json:"maxPriorityFeePerGas,omitempty"`
	MaxFeePerBlobGas    *hexutil.Big                 `json:"maxFeePerBlobGas,omitempty"`
	Hash                common.Hash                  `json:"hash"`
	Input               hexutil.Bytes                `json:"input"`
	Nonce               hexutil.Uint64               `json:"nonce"`
	To                  *common.Address              `json:"to"`
	TransactionIndex    *hexutil.Uint64              `json:"transactionIndex"`
	Value               *hexutil.Big                 `json:"value"`
	Type                hexutil.Uint64               `json:"type"`
	Accesses            *types.AccessList            `json:"accessList,omitempty"`
	ChainID             *hexutil.Big                 `json:"chainId,omitempty"`
	BlobVersionedHashes []common.Hash                `json:"blobVersionedHashes,omitempty"`
	AuthorizationList   []types.SetCodeAuthorization `json:"authorizationList,omitempty"`
	V                   *hexutil.Big                 `json:"v"`
	R                   *hexutil.Big                 `json:"r"`
	S                   *hexutil.Big                 `json:"s"`
	YParity             *hexutil.Uint64              `json:"yParity,omitempty"`
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
// newRPCTransaction 返回一个将序列化为 RPC 表示的交易，并设置给定的位置元数据（如果可用）。
func newRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, blockTime uint64, index uint64, baseFee *big.Int, config *params.ChainConfig) *RPCTransaction {
	signer := types.MakeSigner(config, new(big.Int).SetUint64(blockNumber), blockTime)
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()
	result := &RPCTransaction{
		Type:     hexutil.Uint64(tx.Type()),
		From:     from,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    hexutil.Bytes(tx.Data()),
		Nonce:    hexutil.Uint64(tx.Nonce()),
		To:       tx.To(),
		Value:    (*hexutil.Big)(tx.Value()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = &blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = (*hexutil.Uint64)(&index)
	}

	switch tx.Type() {
	case types.LegacyTxType:
		// if a legacy transaction has an EIP-155 chain id, include it explicitly
		// 如果遗留交易有 EIP-155 链 ID，显式包含它
		if id := tx.ChainId(); id.Sign() != 0 {
			result.ChainID = (*hexutil.Big)(id)
		}

	case types.AccessListTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity

	case types.DynamicFeeTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		// 如果交易已被挖矿，计算有效的 gas 价格
		if baseFee != nil && blockHash != (common.Hash{}) {
			// price = min(gasTipCap + baseFee, gasFeeCap)
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}

	case types.BlobTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		// 如果交易已被挖矿，计算有效的 gas 价格
		if baseFee != nil && blockHash != (common.Hash{}) {
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
		result.MaxFeePerBlobGas = (*hexutil.Big)(tx.BlobGasFeeCap())
		result.BlobVersionedHashes = tx.BlobHashes()

	case types.SetCodeTxType:
		al := tx.AccessList()
		yparity := hexutil.Uint64(v.Sign())
		result.Accesses = &al
		result.ChainID = (*hexutil.Big)(tx.ChainId())
		result.YParity = &yparity
		result.GasFeeCap = (*hexutil.Big)(tx.GasFeeCap())
		result.GasTipCap = (*hexutil.Big)(tx.GasTipCap())
		// if the transaction has been mined, compute the effective gas price
		// 如果交易已被挖矿，计算有效的 gas 价格
		if baseFee != nil && blockHash != (common.Hash{}) {
			result.GasPrice = (*hexutil.Big)(effectiveGasPrice(tx, baseFee))
		} else {
			result.GasPrice = (*hexutil.Big)(tx.GasFeeCap())
		}
		result.AuthorizationList = tx.SetCodeAuthorizations()
	}
	return result
}

// effectiveGasPrice computes the transaction gas fee, based on the given basefee value.
// price = min(gasTipCap + baseFee, gasFeeCap)
// effectiveGasPrice 基于给定的 basefee 值计算交易 gas 费用。
// price = min(gasTipCap + baseFee, gasFeeCap)
func effectiveGasPrice(tx *types.Transaction, baseFee *big.Int) *big.Int {
	fee := tx.GasTipCap()
	fee = fee.Add(fee, baseFee)
	if tx.GasFeeCapIntCmp(fee) < 0 {
		return tx.GasFeeCap()
	}
	return fee
}

// NewRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
// NewRPCPendingTransaction 返回一个待处理的交易，将序列化为 RPC 表示
func NewRPCPendingTransaction(tx *types.Transaction, current *types.Header, config *params.ChainConfig) *RPCTransaction {
	var (
		baseFee     *big.Int
		blockNumber = uint64(0)
		blockTime   = uint64(0)
	)
	if current != nil {
		baseFee = eip1559.CalcBaseFee(config, current)
		blockNumber = current.Number.Uint64()
		blockTime = current.Time
	}
	return newRPCTransaction(tx, common.Hash{}, blockNumber, blockTime, 0, baseFee, config)
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
// newRPCTransactionFromBlockIndex 返回一个将序列化为 RPC 表示的交易。
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64, config *params.ChainConfig) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	return newRPCTransaction(txs[index], b.Hash(), b.NumberU64(), b.Time(), index, b.BaseFee(), config)
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
// newRPCRawTransactionFromBlockIndex 返回给定块和交易索引的交易字节。
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := txs[index].MarshalBinary()
	return blob
}

// accessListResult returns an optional accesslist
// It's the result of the `debug_createAccessList` RPC call.
// It contains an error if the transaction itself failed.
// accessListResult 返回一个可选的 accesslist
// 它是 `debug_createAccessList` RPC 调用的结果。
// 如果交易本身失败，则包含错误。
type accessListResult struct {
	Accesslist *types.AccessList `json:"accessList"`
	Error      string            `json:"error,omitempty"`
	GasUsed    hexutil.Uint64    `json:"gasUsed"`
}

// CreateAccessList creates an EIP-2930 type AccessList for the given transaction.
// Reexec and BlockNrOrHash can be specified to create the accessList on top of a certain state.
// CreateAccessList 为给定的交易创建 EIP-2930 类型的 AccessList。
// 可以指定 Reexec 和 BlockNrOrHash 以在特定状态上创建 accessList。
func (api *BlockChainAPI) CreateAccessList(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash) (*accessListResult, error) {
	bNrOrHash := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	if blockNrOrHash != nil {
		bNrOrHash = *blockNrOrHash
	}
	acl, gasUsed, vmerr, err := AccessList(ctx, api.b, bNrOrHash, args)
	if err != nil {
		return nil, err
	}
	result := &accessListResult{Accesslist: &acl, GasUsed: hexutil.Uint64(gasUsed)}
	if vmerr != nil {
		result.Error = vmerr.Error()
	}
	return result, nil
}

// AccessList creates an access list for the given transaction.
// If the accesslist creation fails an error is returned.
// If the transaction itself fails, an vmErr is returned.
// AccessList 为给定的交易创建 access list。
// 如果 accesslist 创建失败，则返回错误。
// 如果交易本身失败，则返回 vmErr。
func AccessList(ctx context.Context, b Backend, blockNrOrHash rpc.BlockNumberOrHash, args TransactionArgs) (acl types.AccessList, gasUsed uint64, vmErr error, err error) {
	// Retrieve the execution context
	// 获取执行上下文
	db, header, err := b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if db == nil || err != nil {
		return nil, 0, nil, err
	}

	// Ensure any missing fields are filled, extract the recipient and input data
	// 确保填充任何缺失的字段，提取接收者和输入数据
	if err = args.setFeeDefaults(ctx, b, header); err != nil {
		return nil, 0, nil, err
	}
	if args.Nonce == nil {
		nonce := hexutil.Uint64(db.GetNonce(args.from()))
		args.Nonce = &nonce
	}
	blockCtx := core.NewEVMBlockContext(header, NewChainContext(ctx, b), nil)
	if err = args.CallDefaults(b.RPCGasCap(), blockCtx.BaseFee, b.ChainConfig().ChainID); err != nil {
		return nil, 0, nil, err
	}

	var to common.Address
	if args.To != nil {
		to = *args.To
	} else {
		to = crypto.CreateAddress(args.from(), uint64(*args.Nonce))
	}
	isPostMerge := header.Difficulty.Sign() == 0
	// Retrieve the precompiles since they don't need to be added to the access list
	// 获取预编译合约，因为它们不需要添加到 access list
	precompiles := vm.ActivePrecompiles(b.ChainConfig().Rules(header.Number, isPostMerge, header.Time))

	// Create an initial tracer
	// 创建初始跟踪器
	prevTracer := logger.NewAccessListTracer(nil, args.from(), to, precompiles)
	if args.AccessList != nil {
		prevTracer = logger.NewAccessListTracer(*args.AccessList, args.from(), to, precompiles)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, nil, err
		}
		// Retrieve the current access list to expand
		// 获取当前的 access list 以扩展
		accessList := prevTracer.AccessList()
		log.Trace("Creating access list", "input", accessList)

		// Copy the original db so we don't modify it
		// 复制原始 db 以免修改它
		statedb := db.Copy()
		// Set the accesslist to the last al
		// 将 accesslist 设置为最后一个 al
		args.AccessList = &accessList
		msg := args.ToMessage(header.BaseFee, true, true)

		// Apply the transaction with the access list tracer
		// 使用 access list 跟踪器应用交易
		tracer := logger.NewAccessListTracer(accessList, args.from(), to, precompiles)
		config := vm.Config{Tracer: tracer.Hooks(), NoBaseFee: true}
		evm := b.GetEVM(ctx, statedb, header, &config, nil)

		// Lower the basefee to 0 to avoid breaking EVM
		// invariants (basefee < feecap).
		// 将 basefee 降低到 0，以避免破坏 EVM 不变性（basefee < feecap）。
		if msg.GasPrice.Sign() == 0 {
			evm.Context.BaseFee = new(big.Int)
		}
		if msg.BlobGasFeeCap != nil && msg.BlobGasFeeCap.BitLen() == 0 {
			evm.Context.BlobBaseFee = new(big.Int)
		}
		res, err := core.ApplyMessage(evm, msg, new(core.GasPool).AddGas(msg.GasLimit))
		if err != nil {
			return nil, 0, nil, fmt.Errorf("failed to apply transaction: %v err: %v", args.ToTransaction(types.LegacyTxType).Hash(), err)
		}
		if tracer.Equal(prevTracer) {
			return accessList, res.UsedGas, res.Err, nil
		}
		prevTracer = tracer
	}
}

// TransactionAPI exposes methods for reading and creating transaction data.
// TransactionAPI 暴露用于读取和创建交易数据的方法。
type TransactionAPI struct {
	b         Backend
	nonceLock *AddrLocker
	signer    types.Signer
}

// NewTransactionAPI creates a new RPC service with methods for interacting with transactions.
// NewTransactionAPI 创建一个新的 RPC 服务，包含与交易交互的方法。
func NewTransactionAPI(b Backend, nonceLock *AddrLocker) *TransactionAPI {
	// The signer used by the API should always be the 'latest' known one because we expect
	// signers to be backwards-compatible with old transactions.
	// API 使用的 signer 应始终是最新的已知 signer，因为我们期望 signer 与旧交易向后兼容。
	signer := types.LatestSigner(b.ChainConfig())
	return &TransactionAPI{b, nonceLock, signer}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
// GetBlockTransactionCountByNumber 返回具有给定块号的块中的交易数量。
func (api *TransactionAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := api.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
// GetBlockTransactionCountByHash 返回具有给定哈希的块中的交易数量。
func (api *TransactionAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := api.b.BlockByHash(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
// GetTransactionByBlockNumberAndIndex 返回给定块号和索引的交易。
func (api *TransactionAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := api.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index), api.b.ChainConfig())
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
// GetTransactionByBlockHashAndIndex 返回给定块哈希和索引的交易。
func (api *TransactionAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := api.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index), api.b.ChainConfig())
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
// GetRawTransactionByBlockNumberAndIndex 返回给定块号和索引的交易字节。
func (api *TransactionAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := api.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
// GetRawTransactionByBlockHashAndIndex 返回给定块哈希和索引的交易字节。
func (api *TransactionAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := api.b.BlockByHash(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
// GetTransactionCount 返回给定地址在给定块号时发送的交易数量
func (api *TransactionAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNrOrHash rpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	// Ask transaction pool for the nonce which includes pending transactions
	// 向交易池询问 nonce，其中包括待处理的交易
	if blockNr, ok := blockNrOrHash.Number(); ok && blockNr == rpc.PendingBlockNumber {
		nonce, err := api.b.GetPoolNonce(ctx, address)
		if err != nil {
			return nil, err
		}
		return (*hexutil.Uint64)(&nonce), nil
	}
	// Resolve block number and use its state to ask for the nonce
	// 解析块号并使用其状态询问 nonce
	state, _, err := api.b.StateAndHeaderByNumberOrHash(ctx, blockNrOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the transaction for the given hash
// GetTransactionByHash 返回给定哈希的交易
func (api *TransactionAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	// 尝试返回已完成的交易
	found, tx, blockHash, blockNumber, index, err := api.b.GetTransaction(ctx, hash)
	if !found {
		// No finalized transaction, try to retrieve it from the pool
		// 没有完成的交易，尝试从池中检索
		if tx := api.b.GetPoolTransaction(hash); tx != nil {
			return NewRPCPendingTransaction(tx, api.b.CurrentHeader(), api.b.ChainConfig()), nil
		}
		if err == nil {
			return nil, nil
		}
		return nil, NewTxIndexingError()
	}
	header, err := api.b.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	return newRPCTransaction(tx, blockHash, blockNumber, header.Time, index, header.BaseFee, api.b.ChainConfig()), nil
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
// GetRawTransactionByHash 返回给定哈希的交易字节。
func (api *TransactionAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	// 检索已完成的交易，或从池中检索
	found, tx, _, _, _, err := api.b.GetTransaction(ctx, hash)
	if !found {
		if tx = api.b.GetPoolTransaction(hash); tx != nil {
			return tx.MarshalBinary()
		}
		if err == nil {
			return nil, nil
		}
		return nil, NewTxIndexingError()
	}
	return tx.MarshalBinary()
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
// GetTransactionReceipt 返回给定交易哈希的交易收据。
func (api *TransactionAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	found, tx, blockHash, blockNumber, index, err := api.b.GetTransaction(ctx, hash)
	if err != nil {
		return nil, NewTxIndexingError() // transaction is not fully indexed
	}
	if !found {
		return nil, nil // transaction is not existent or reachable
	}
	header, err := api.b.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	receipts, err := api.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if uint64(len(receipts)) <= index {
		return nil, nil
	}
	receipt := receipts[index]

	// Derive the sender.
	// 推导发送者。
	signer := types.MakeSigner(api.b.ChainConfig(), header.Number, header.Time)
	return marshalReceipt(receipt, blockHash, blockNumber, signer, tx, int(index)), nil
}

// marshalReceipt marshals a transaction receipt into a JSON object.
// marshalReceipt 将交易收据编组为 JSON 对象。
func marshalReceipt(receipt *types.Receipt, blockHash common.Hash, blockNumber uint64, signer types.Signer, tx *types.Transaction, txIndex int) map[string]interface{} {
	from, _ := types.Sender(signer, tx)

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   tx.Hash(),
		"transactionIndex":  hexutil.Uint64(txIndex),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
		"type":              hexutil.Uint(tx.Type()),
		"effectiveGasPrice": (*hexutil.Big)(receipt.EffectiveGasPrice),
	}

	// Assign receipt status or post state.
	// 分配收据状态或 post state。
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = []*types.Log{}
	}

	if tx.Type() == types.BlobTxType {
		fields["blobGasUsed"] = hexutil.Uint64(receipt.BlobGasUsed)
		fields["blobGasPrice"] = (*hexutil.Big)(receipt.BlobGasPrice)
	}

	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	// 如果 ContractAddress 是 20 字节的 0x0，假设它不是合约创建
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields
}

// sign is a helper function that signs a transaction with the private key of the given address.
// sign 是一个辅助函数，使用给定地址的私钥签署交易。
func (api *TransactionAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	// 查找包含请求的 signer 的钱包
	account := accounts.Account{Address: addr}

	wallet, err := api.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	// 请求钱包签署交易
	return wallet.SignTx(account, tx, api.b.ChainConfig().ChainID)
}

// SubmitTransaction is a helper function that submits tx to txPool and logs a message.
// SubmitTransaction 是一个辅助函数，将 tx 提交到 txPool 并记录消息。
func SubmitTransaction(ctx context.Context, b Backend, tx *types.Transaction) (common.Hash, error) {
	// If the transaction fee cap is already specified, ensure the
	// fee of the given transaction is _reasonable_.
	// 如果已经指定了交易费用上限，确保给定交易的费用是合理的。
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	if !b.UnprotectedAllowed() && !tx.Protected() {
		// Ensure only eip155 signed transactions are submitted if EIP155Required is set.
		// 如果设置了 EIP155Required，确保只提交 eip155 签名的交易。
		return common.Hash{}, errors.New("only replay-protected (EIP-155) transactions allowed over RPC")
	}
	if err := b.SendTx(ctx, tx); err != nil {
		return common.Hash{}, err
	}
	// Print a log with full tx details for manual investigations and interventions
	// 打印包含完整 tx 详细信息的日志，以便手动调查和干预
	head := b.CurrentBlock()
	signer := types.MakeSigner(b.ChainConfig(), head.Number, head.Time)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return common.Hash{}, err
	}

	if tx.To() == nil {
		addr := crypto.CreateAddress(from, tx.Nonce())
		log.Info("Submitted contract creation", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "contract", addr.Hex(), "value", tx.Value())
	} else {
		log.Info("Submitted transaction", "hash", tx.Hash().Hex(), "from", from, "nonce", tx.Nonce(), "recipient", tx.To(), "value", tx.Value())
	}
	return tx.Hash(), nil
}

// SendTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
// SendTransaction 为给定的参数创建交易，签署并提交到交易池。
func (api *TransactionAPI) SendTransaction(ctx context.Context, args TransactionArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	// 查找包含请求的 signer 的钱包
	account := accounts.Account{Address: args.from()}

	wallet, err := api.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		// 在签署周围持有互斥锁，以防止并发分配相同的 nonce 给多个账户。
		api.nonceLock.LockAddr(args.from())
		defer api.nonceLock.UnlockAddr(args.from())
	}
	if args.IsEIP4844() {
		return common.Hash{}, errBlobTxNotSupported
	}

	// Set some sanity defaults and terminate on failure
	// 设置一些理智的默认值并在失败时终止
	if err := args.setDefaults(ctx, api.b, false); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	// 组装交易并用钱包签署
	tx := args.ToTransaction(types.LegacyTxType)

	signed, err := wallet.SignTx(account, tx, api.b.ChainConfig().ChainID)
	if err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, api.b, signed)
}

// FillTransaction fills the defaults (nonce, gas, gasPrice or 1559 fields)
// on a given unsigned transaction, and returns it to the caller for further
// processing (signing + broadcast).
// FillTransaction 在给定的未签名交易上填充默认值（nonce、gas、gasPrice 或 1559 字段），
// 并将其返回给调用者以进行进一步处理（签署 + 广播）。
func (api *TransactionAPI) FillTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	args.blobSidecarAllowed = true

	// Set some sanity defaults and terminate on failure
	// 设置一些理智的默认值并在失败时终止
	if err := args.setDefaults(ctx, api.b, false); err != nil {
		return nil, err
	}
	// Assemble the transaction and obtain rlp
	// 组装交易并获取 rlp
	tx := args.ToTransaction(types.LegacyTxType)
	data, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
// SendRawTransaction 将签署的交易添加到交易池。
// 发送者负责签署交易并使用正确的 nonce。
func (api *TransactionAPI) SendRawTransaction(ctx context.Context, input hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(input); err != nil {
		return common.Hash{}, err
	}
	return SubmitTransaction(ctx, api.b, tx)
}

// Sign calculates an ECDSA signature for:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign
// Sign 为以下内容计算 ECDSA 签名：
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message).
// 注意，生成的签名符合 secp256k1 曲线的 R、S 和 V 值，
// 其中 V 值将为 27 或 28（传统原因）。
// 与 addr 关联的账户必须解锁。
func (api *TransactionAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	// 查找包含请求的 signer 的钱包
	account := accounts.Account{Address: addr}

	wallet, err := api.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	// 用钱包签署请求的哈希
	signature, err := wallet.SignText(account, data)
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
		// 根据黄皮书将 V 从 0/1 转换为 27/28
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
// SignTransactionResult 表示一个 RLP 编码的签署交易。
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will sign the given transaction with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
// SignTransaction 将使用 from 账户签署给定的交易。
// 节点需要拥有与给定 from 地址对应的账户的私钥，并且需要解锁。
func (api *TransactionAPI) SignTransaction(ctx context.Context, args TransactionArgs) (*SignTransactionResult, error) {
	args.blobSidecarAllowed = true

	if args.Gas == nil {
		return nil, errors.New("gas not specified")
	}
	if args.GasPrice == nil && (args.MaxPriorityFeePerGas == nil || args.MaxFeePerGas == nil) {
		return nil, errors.New("missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")
	}
	if args.Nonce == nil {
		return nil, errors.New("nonce not specified")
	}
	if err := args.setDefaults(ctx, api.b, false); err != nil {
		return nil, err
	}
	// Before actually sign the transaction, ensure the transaction fee is reasonable.
	// 在实际签署交易之前，确保交易费用合理。
	tx := args.ToTransaction(types.LegacyTxType)
	if err := checkTxFee(tx.GasPrice(), tx.Gas(), api.b.RPCTxFeeCap()); err != nil {
		return nil, err
	}
	signed, err := api.sign(args.from(), tx)
	if err != nil {
		return nil, err
	}
	// If the transaction-to-sign was a blob transaction, then the signed one
	// no longer retains the blobs, only the blob hashes. In this step, we need
	// to put back the blob(s).
	// 如果要签署的交易是 blob 交易，则签署的交易不再保留 blobs，仅保留 blob 哈希。
	// 在这一步，我们需要放回 blob(s)。
	if args.IsEIP4844() {
		signed = signed.WithBlobTxSidecar(&types.BlobTxSidecar{
			Blobs:       args.Blobs,
			Commitments: args.Commitments,
			Proofs:      args.Proofs,
		})
	}
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// PendingTransactions returns the transactions that are in the transaction pool
// and have a from address that is one of the accounts this node manages.
// PendingTransactions 返回交易池中的交易，
// 并且 from 地址是此节点管理的账户之一。
func (api *TransactionAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := api.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	accounts := make(map[common.Address]struct{})
	for _, wallet := range api.b.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			accounts[account.Address] = struct{}{}
		}
	}
	curHeader := api.b.CurrentHeader()
	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, tx := range pending {
		from, _ := types.Sender(api.signer, tx)
		if _, exists := accounts[from]; exists {
			transactions = append(transactions, NewRPCPendingTransaction(tx, curHeader, api.b.ChainConfig()))
		}
	}
	return transactions, nil
}

// Resend accepts an existing transaction and a new gas price and limit. It will remove
// the given transaction from the pool and reinsert it with the new gas price and limit.
// Resend 接受一个现有交易和新的 gas 价格和限制。
// 它将从池中移除给定交易，并使用新的 gas 价格和限制重新插入。
func (api *TransactionAPI) Resend(ctx context.Context, sendArgs TransactionArgs, gasPrice *hexutil.Big, gasLimit *hexutil.Uint64) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, errors.New("missing transaction nonce in transaction spec")
	}
	if err := sendArgs.setDefaults(ctx, api.b, false); err != nil {
		return common.Hash{}, err
	}
	matchTx := sendArgs.ToTransaction(types.LegacyTxType)

	// Before replacing the old transaction, ensure the _new_ transaction fee is reasonable.
	// 在替换旧交易之前，确保新交易费用合理。
	price := matchTx.GasPrice()
	if gasPrice != nil {
		price = gasPrice.ToInt()
	}
	gas := matchTx.Gas()
	if gasLimit != nil {
		gas = uint64(*gasLimit)
	}
	if err := checkTxFee(price, gas, api.b.RPCTxFeeCap()); err != nil {
		return common.Hash{}, err
	}
	// Iterate the pending list for replacement
	// 遍历待处理列表以进行替换
	pending, err := api.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}
	for _, p := range pending {
		wantSigHash := api.signer.Hash(matchTx)
		pFrom, err := types.Sender(api.signer, p)
		if err == nil && pFrom == sendArgs.from() && api.signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the transaction.
			// 匹配。重新签署并发送交易。
			if gasPrice != nil && (*big.Int)(gasPrice).Sign() != 0 {
				sendArgs.GasPrice = gasPrice
			}
			if gasLimit != nil && *gasLimit != 0 {
				sendArgs.Gas = gasLimit
			}
			signedTx, err := api.sign(sendArgs.from(), sendArgs.ToTransaction(types.LegacyTxType))
			if err != nil {
				return common.Hash{}, err
			}
			if err = api.b.SendTx(ctx, signedTx); err != nil {
				return common.Hash{}, err
			}
			return signedTx.Hash(), nil
		}
	}
	return common.Hash{}, fmt.Errorf("transaction %#x not found", matchTx.Hash())
}

// DebugAPI is the collection of Ethereum APIs exposed over the debugging
// namespace.
// DebugAPI 是在调试命名空间中暴露的以太坊 API 集合。
type DebugAPI struct {
	b Backend
}

// NewDebugAPI creates a new instance of DebugAPI.
// NewDebugAPI 创建一个新的 DebugAPI 实例。
func NewDebugAPI(b Backend) *DebugAPI {
	return &DebugAPI{b: b}
}

// GetRawHeader retrieves the RLP encoding for a single header.
// GetRawHeader 检索单个 header 的 RLP 编码。
func (api *DebugAPI) GetRawHeader(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	header, _ := api.b.HeaderByHash(ctx, hash)
	if header == nil {
		return nil, fmt.Errorf("header #%d not found", hash)
	}
	return rlp.EncodeToBytes(header)
}

// GetRawBlock retrieves the RLP encoded for a single block.
// GetRawBlock 检索单个块的 RLP 编码。
func (api *DebugAPI) GetRawBlock(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	block, _ := api.b.BlockByHash(ctx, hash)
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", hash)
	}
	return rlp.EncodeToBytes(block)
}

// GetRawReceipts retrieves the binary-encoded receipts of a single block.
// GetRawReceipts 检索单个块的二进制编码收据。
func (api *DebugAPI) GetRawReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]hexutil.Bytes, error) {
	var hash common.Hash
	if h, ok := blockNrOrHash.Hash(); ok {
		hash = h
	} else {
		block, err := api.b.BlockByNumberOrHash(ctx, blockNrOrHash)
		if err != nil {
			return nil, err
		}
		hash = block.Hash()
	}
	receipts, err := api.b.GetReceipts(ctx, hash)
	if err != nil {
		return nil, err
	}
	result := make([]hexutil.Bytes, len(receipts))
	for i, receipt := range receipts {
		b, err := receipt.MarshalBinary()
		if err != nil {
			return nil, err
		}
		result[i] = b
	}
	return result, nil
}

// GetRawTransaction returns the bytes of the transaction for the given hash.
// GetRawTransaction 返回给定哈希的交易字节。
func (api *DebugAPI) GetRawTransaction(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	// Retrieve a finalized transaction, or a pooled otherwise
	// 检索已完成的交易，或从池中检索
	found, tx, _, _, _, err := api.b.GetTransaction(ctx, hash)
	if !found {
		if tx = api.b.GetPoolTransaction(hash); tx != nil {
			return tx.MarshalBinary()
		}
		if err == nil {
			return nil, nil
		}
		return nil, NewTxIndexingError()
	}
	return tx.MarshalBinary()
}

// PrintBlock retrieves a block and returns its pretty printed form.
// PrintBlock 检索块并返回其漂亮打印的形式。
func (api *DebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return spew.Sdump(block), nil
}

// ChaindbProperty returns leveldb properties of the key-value database.
// ChaindbProperty 返回键值数据库的 leveldb 属性。
func (api *DebugAPI) ChaindbProperty() (string, error) {
	return api.b.ChainDb().Stat()
}

// ChaindbCompact flattens the entire key-value database into a single level,
// removing all unused slots and merging all keys.
// ChaindbCompact 将整个键值数据库展平为单个级别，
// 移除所有未使用的槽位并合并所有键。
func (api *DebugAPI) ChaindbCompact() error {
	cstart := time.Now()
	for b := 0; b <= 255; b++ {
		var (
			start = []byte{byte(b)}
			end   = []byte{byte(b + 1)}
		)
		if b == 255 {
			end = nil
		}
		log.Info("Compacting database", "range", fmt.Sprintf("%#X-%#X", start, end), "elapsed", common.PrettyDuration(time.Since(cstart)))
		if err := api.b.ChainDb().Compact(start, end); err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
// SetHead 将区块链的头部回退到先前的块。
func (api *DebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

// NetAPI offers network related RPC methods
// NetAPI 提供网络相关的 RPC 方法
type NetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewNetAPI creates a new net API instance.
// NewNetAPI 创建一个新的 net API 实例。
func NewNetAPI(net *p2p.Server, networkVersion uint64) *NetAPI {
	return &NetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
// Listening 返回节点是否正在监听网络连接的指示。
func (api *NetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
// PeerCount 返回连接的 peers 数量
func (api *NetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(api.net.PeerCount())
}

// Version returns the current ethereum protocol version.
// Version 返回当前的以太坊协议版本。
func (api *NetAPI) Version() string {
	return fmt.Sprintf("%d", api.networkVersion)
}

// checkTxFee is an internal function used to check whether the fee of
// the given transaction is _reasonable_(under the cap).
// checkTxFee 是一个内部函数，用于检查给定交易的费用是否合理（在上限内）。
func checkTxFee(gasPrice *big.Int, gas uint64, cap float64) error {
	// Short circuit if there is no cap for transaction fee at all.
	// 如果交易费用根本没有上限，则短路。
	if cap == 0 {
		return nil
	}
	feeEth := new(big.Float).Quo(new(big.Float).SetInt(new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gas))), new(big.Float).SetInt(big.NewInt(params.Ether)))
	feeFloat, _ := feeEth.Float64()
	if feeFloat > cap {
		return fmt.Errorf("tx fee (%.2f ether) exceeds the configured cap (%.2f ether)", feeFloat, cap)
	}
	return nil
}
