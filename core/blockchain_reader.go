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

package core

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
)

// BlockChain 的核心作用
//
// BlockChain 结构体的主要作用是作为与底层区块链数据存储（通常是数据库）交互的抽象层。它提供了各种方法，使得节点软件的其他部分（例如交易池、共识引擎、API 等）可以方便地查询和操作区块链数据，而无需直接与复杂的数据库交互。
//
// 管理的不同类型的数据
//
// BlockChain 结构体管理着以下几种关键的区块链数据：
//
// 区块头 (types.Header): 每个区块都包含一个头部，其中包含了关于区块的元数据，例如区块号、父哈希、交易根哈希、状态根哈希、时间戳、矿工地址等。
// 区块体 (types.Body): 每个区块还包含一个主体，其中包含了该区块中的所有交易和叔块。
// 完整的区块 (types.Block): 包含了区块头和区块体。
// 交易收据 (types.Receipt): 当一个交易被成功执行后，会生成一个收据，其中包含了交易的状态、使用的 Gas 量、产生的日志事件等信息。
// 状态 (state.StateDB): 以太坊的状态是一个巨大的键值对数据库，存储了所有账户的余额、合约代码、存储等信息。每个区块执行后都会导致状态的更新。
// 总难度 (big.Int): 从创世区块到当前区块的所有区块的难度之和，用于确定区块链中哪个链是“最长”或“最重”的规范链。

// 规范链
//
// 以太坊网络中可能会出现临时性的分叉，即在同一高度存在多个不同的区块。然而，共识机制最终会选择其中一条链作为“规范链”，即被网络中大多数节点认可的主链。BlockChain 结构体主要关注和管理这条规范链。

// CurrentHeader retrieves the current head header of the canonical chain. The
// header is retrieved from the HeaderChain's internal cache.
// CurrentHeader 检索规范链的当前头部区块头。该头部信息从 HeaderChain 的内部缓存中检索。
func (bc *BlockChain) CurrentHeader() *types.Header {
	return bc.hc.CurrentHeader()
}

// CurrentBlock retrieves the current head block of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
// CurrentBlock 检索规范链的当前头部区块。该区块从区块链的内部缓存中检索。
func (bc *BlockChain) CurrentBlock() *types.Header {
	return bc.currentBlock.Load()
}

// CurrentSnapBlock retrieves the current snap-sync head block of the canonical
// chain. The block is retrieved from the blockchain's internal cache.
// CurrentSnapBlock 检索规范链的当前快照同步头部区块。该区块从区块链的内部缓存中检索。
func (bc *BlockChain) CurrentSnapBlock() *types.Header {
	return bc.currentSnapBlock.Load()
}

// CurrentFinalBlock retrieves the current finalized block of the canonical
// chain. The block is retrieved from the blockchain's internal cache.
// CurrentFinalBlock 检索规范链的当前最终确定区块。该区块从区块链的内部缓存中检索。
func (bc *BlockChain) CurrentFinalBlock() *types.Header {
	return bc.currentFinalBlock.Load()
}

// CurrentSafeBlock retrieves the current safe block of the canonical
// chain. The block is retrieved from the blockchain's internal cache.
// CurrentSafeBlock 检索规范链的当前安全区块。该区块从区块链的内部缓存中检索。
func (bc *BlockChain) CurrentSafeBlock() *types.Header {
	return bc.currentSafeBlock.Load()
}

// HasHeader checks if a block header is present in the database or not, caching
// it if present.
// HasHeader 检查区块头是否存在于数据库中，如果存在则进行缓存。
func (bc *BlockChain) HasHeader(hash common.Hash, number uint64) bool {
	return bc.hc.HasHeader(hash, number)
}

// GetHeader retrieves a block header from the database by hash and number,
// caching it if found.
// GetHeader 通过哈希和区块号从数据库中检索区块头，如果找到则进行缓存。
func (bc *BlockChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return bc.hc.GetHeader(hash, number)
}

// GetHeaderByHash retrieves a block header from the database by hash, caching it if
// found.
// GetHeaderByHash 通过哈希从数据库中检索区块头，如果找到则进行缓存。
func (bc *BlockChain) GetHeaderByHash(hash common.Hash) *types.Header {
	return bc.hc.GetHeaderByHash(hash)
}

// GetHeaderByNumber retrieves a block header from the database by number,
// caching it (associated with its hash) if found.
// GetHeaderByNumber 通过区块号从数据库中检索区块头，如果找到则将其缓存（与其哈希关联）。
func (bc *BlockChain) GetHeaderByNumber(number uint64) *types.Header {
	return bc.hc.GetHeaderByNumber(number)
}

// GetHeadersFrom returns a contiguous segment of headers, in rlp-form, going
// backwards from the given number.
// GetHeadersFrom 返回一个连续的区块头段，以 RLP 格式，从给定的区块号向后获取。
func (bc *BlockChain) GetHeadersFrom(number, count uint64) []rlp.RawValue {
	return bc.hc.GetHeadersFrom(number, count)
}

// GetBody retrieves a block body (transactions and uncles) from the database by
// hash, caching it if found.
// GetBody 通过哈希从数据库中检索区块体（交易和叔块），如果找到则进行缓存。
func (bc *BlockChain) GetBody(hash common.Hash) *types.Body {
	// Short circuit if the body's already in the cache, retrieve otherwise
	// 如果区块体已在缓存中，则直接返回；否则从数据库检索。
	if cached, ok := bc.bodyCache.Get(hash); ok {
		return cached
	}
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	body := rawdb.ReadBody(bc.db, hash, *number)
	if body == nil {
		return nil
	}
	// Cache the found body for next time and return
	// 缓存找到的区块体以便下次使用并返回。
	bc.bodyCache.Add(hash, body)
	return body
}

// GetBodyRLP retrieves a block body in RLP encoding from the database by hash,
// caching it if found.
// GetBodyRLP 通过哈希从数据库中检索 RLP 编码的区块体，如果找到则进行缓存。
func (bc *BlockChain) GetBodyRLP(hash common.Hash) rlp.RawValue {
	// Short circuit if the body's already in the cache, retrieve otherwise
	// 如果区块体已在缓存中，则直接返回；否则从数据库检索。
	if cached, ok := bc.bodyRLPCache.Get(hash); ok {
		return cached
	}
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	body := rawdb.ReadBodyRLP(bc.db, hash, *number)
	if len(body) == 0 {
		return nil
	}
	// Cache the found body for next time and return
	// 缓存找到的区块体以便下次使用并返回。
	bc.bodyRLPCache.Add(hash, body)
	return body
}

// HasBlock checks if a block is fully present in the database or not.
// HasBlock 检查区块是否完整地存在于数据库中。
func (bc *BlockChain) HasBlock(hash common.Hash, number uint64) bool {
	if bc.blockCache.Contains(hash) {
		return true
	}
	if !bc.HasHeader(hash, number) {
		return false
	}
	return rawdb.HasBody(bc.db, hash, number)
}

// HasFastBlock checks if a fast block is fully present in the database or not.
// HasFastBlock 检查快速同步区块是否完整地存在于数据库中。
func (bc *BlockChain) HasFastBlock(hash common.Hash, number uint64) bool {
	if !bc.HasBlock(hash, number) {
		return false
	}
	if bc.receiptsCache.Contains(hash) {
		return true
	}
	return rawdb.HasReceipts(bc.db, hash, number)
}

// GetBlock retrieves a block from the database by hash and number,
// caching it if found.
// GetBlock 通过哈希和区块号从数据库中检索区块，如果找到则进行缓存。
func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	// Short circuit if the block's already in the cache, retrieve otherwise
	// 如果区块已在缓存中，则直接返回；否则从数据库检索。
	if block, ok := bc.blockCache.Get(hash); ok {
		return block
	}
	block := rawdb.ReadBlock(bc.db, hash, number)
	if block == nil {
		return nil
	}
	// Cache the found block for next time and return
	// 缓存找到的区块以便下次使用并返回。
	bc.blockCache.Add(block.Hash(), block)
	return block
}

// GetBlockByHash retrieves a block from the database by hash, caching it if found.
// GetBlockByHash 通过哈希从数据库中检索区块，如果找到则进行缓存。
func (bc *BlockChain) GetBlockByHash(hash common.Hash) *types.Block {
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	return bc.GetBlock(hash, *number)
}

// GetBlockByNumber retrieves a block from the database by number, caching it
// (associated with its hash) if found.
// GetBlockByNumber 通过区块号从数据库中检索区块，如果找到则将其缓存（与其哈希关联）。
func (bc *BlockChain) GetBlockByNumber(number uint64) *types.Block {
	hash := rawdb.ReadCanonicalHash(bc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return bc.GetBlock(hash, number)
}

// GetBlocksFromHash returns the block corresponding to hash and up to n-1 ancestors.
// [deprecated by eth/62]
// GetBlocksFromHash 返回与哈希对应的区块以及最多 n-1 个祖先区块。
// [已被 eth/62 弃用]
func (bc *BlockChain) GetBlocksFromHash(hash common.Hash, n int) (blocks []*types.Block) {
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	for i := 0; i < n; i++ {
		block := bc.GetBlock(hash, *number)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		hash = block.ParentHash()
		*number--
	}
	return
}

// GetReceiptsByHash retrieves the receipts for all transactions in a given block.
// GetReceiptsByHash 检索给定区块中所有交易的收据。
func (bc *BlockChain) GetReceiptsByHash(hash common.Hash) types.Receipts {
	if receipts, ok := bc.receiptsCache.Get(hash); ok {
		return receipts
	}
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}
	header := bc.GetHeader(hash, *number)
	if header == nil {
		return nil
	}
	receipts := rawdb.ReadReceipts(bc.db, hash, *number, header.Time, bc.chainConfig)
	if receipts == nil {
		return nil
	}
	bc.receiptsCache.Add(hash, receipts)
	return receipts
}

// GetUnclesInChain retrieves all the uncles from a given block backwards until
// a specific distance is reached.
// GetUnclesInChain 从给定的区块向后检索所有叔块，直到达到指定的距离。
func (bc *BlockChain) GetUnclesInChain(block *types.Block, length int) []*types.Header {
	uncles := []*types.Header{}
	for i := 0; block != nil && i < length; i++ {
		uncles = append(uncles, block.Uncles()...)
		block = bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
	}
	return uncles
}

// GetCanonicalHash returns the canonical hash for a given block number
// GetCanonicalHash 返回给定区块号的规范哈希。
func (bc *BlockChain) GetCanonicalHash(number uint64) common.Hash {
	return bc.hc.GetCanonicalHash(number)
}

// GetAncestor retrieves the Nth ancestor of a given block. It assumes that either the given block or
// a close ancestor of it is canonical. maxNonCanonical points to a downwards counter limiting the
// number of blocks to be individually checked before we reach the canonical chain.
//
// Note: ancestor == 0 returns the same block, 1 returns its parent and so on.
// GetAncestor 检索给定区块的第 N 个祖先。它假定给定的区块或其近期的祖先是规范的。
// maxNonCanonical 指向下行计数器，限制在到达规范链之前需要单独检查的区块数量。
//
// 注意：ancestor == 0 返回相同的区块，1 返回其父区块，依此类推。
func (bc *BlockChain) GetAncestor(hash common.Hash, number, ancestor uint64, maxNonCanonical *uint64) (common.Hash, uint64) {
	return bc.hc.GetAncestor(hash, number, ancestor, maxNonCanonical)
}

// GetTransactionLookup retrieves the lookup along with the transaction
// itself associate with the given transaction hash.
//
// An error will be returned if the transaction is not found, and background
// indexing for transactions is still in progress. The transaction might be
// reachable shortly once it's indexed.
//
// A null will be returned in the transaction is not found and background
// transaction indexing is already finished. The transaction is not existent
// from the node's perspective.
// GetTransactionLookup 检索与给定交易哈希关联的查找信息以及交易本身。
//
// 如果未找到交易且后台交易索引仍在进行中，则会返回错误。交易可能在索引完成后很快就能找到。
//
// 如果未找到交易且后台交易索引已完成，则会返回 null。从节点的角度来看，该交易不存在。
func (bc *BlockChain) GetTransactionLookup(hash common.Hash) (*rawdb.LegacyTxLookupEntry, *types.Transaction, error) {
	bc.txLookupLock.RLock()
	defer bc.txLookupLock.RUnlock()

	// Short circuit if the txlookup already in the cache, retrieve otherwise
	// 如果交易查找信息已在缓存中，则直接返回；否则从数据库检索。
	if item, exist := bc.txLookupCache.Get(hash); exist {
		return item.lookup, item.transaction, nil
	}
	tx, blockHash, blockNumber, txIndex := rawdb.ReadTransaction(bc.db, hash)
	if tx == nil {
		progress, err := bc.TxIndexProgress()
		if err != nil {
			// No error is returned if the transaction indexing progress is unreachable
			// due to unexpected internal errors. In such cases, it is impossible to
			// determine whether the transaction does not exist or has simply not been
			// indexed yet without a progress marker.
			//
			// In such scenarios, the transaction is treated as unreachable, though
			// this is clearly an unintended and unexpected situation.
			// 如果由于意外的内部错误而无法获取交易索引的进度，则不会返回错误。
			// 在这种情况下，如果没有进度标记，则无法确定交易是不存在还是尚未被索引。
			//
			// 在这种情况下，交易被视为不可达，但这显然是一种非预期的情况。
			return nil, nil, nil
		}
		// The transaction indexing is not finished yet, returning an
		// error to explicitly indicate it.
		// 交易索引尚未完成，返回一个错误明确指示这一点。
		if !progress.Done() {
			return nil, nil, errors.New("transaction indexing still in progress")
		}
		// The transaction is already indexed, the transaction is either
		// not existent or not in the range of index, returning null.
		// 交易已索引完毕，该交易要么不存在，要么不在索引范围内，返回 null。
		return nil, nil, nil
	}
	lookup := &rawdb.LegacyTxLookupEntry{
		BlockHash:  blockHash,
		BlockIndex: blockNumber,
		Index:      txIndex,
	}
	bc.txLookupCache.Add(hash, txLookup{
		lookup:      lookup,
		transaction: tx,
	})
	return lookup, tx, nil
}

// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number, caching it if found.
// GetTd 通过哈希和区块号从数据库中检索规范链中区块的总难度，如果找到则进行缓存。
func (bc *BlockChain) GetTd(hash common.Hash, number uint64) *big.Int {
	return bc.hc.GetTd(hash, number)
}

// HasState checks if state trie is fully present in the database or not.
// HasState 检查状态 Trie 是否完整地存在于数据库中。
func (bc *BlockChain) HasState(hash common.Hash) bool {
	_, err := bc.statedb.OpenTrie(hash)
	return err == nil
}

// HasBlockAndState checks if a block and associated state trie is fully present
// in the database or not, caching it if present.
// HasBlockAndState 检查区块及其关联的状态 Trie 是否完整地存在于数据库中，如果存在则进行缓存。
func (bc *BlockChain) HasBlockAndState(hash common.Hash, number uint64) bool {
	// Check first that the block itself is known
	// 首先检查区块本身是否已知。
	block := bc.GetBlock(hash, number)
	if block == nil {
		return false
	}
	return bc.HasState(block.Root())
}

// stateRecoverable checks if the specified state is recoverable.
// Note, this function assumes the state is not present, because
// state is not treated as recoverable if it's available, thus
// false will be returned in this case.
// stateRecoverable 检查指定的状态是否可恢复。
// 注意：此函数假定状态不存在，因为如果状态可用则不会将其视为可恢复，因此在这种情况下将返回 false。
func (bc *BlockChain) stateRecoverable(root common.Hash) bool {
	if bc.triedb.Scheme() == rawdb.HashScheme {
		return false
	}
	result, _ := bc.triedb.Recoverable(root)
	return result
}

// ContractCodeWithPrefix retrieves a blob of data associated with a contract
// hash either from ephemeral in-memory cache, or from persistent storage.
// ContractCodeWithPrefix 检索与合约哈希关联的数据 blob，可以从临时的内存缓存或持久存储中检索。
func (bc *BlockChain) ContractCodeWithPrefix(hash common.Hash) []byte {
	// TODO(rjl493456442) The associated account address is also required
	// in Verkle scheme. Fix it once snap-sync is supported for Verkle.
	// TODO(rjl493456442) 在 Verkle 方案中也需要关联的账户地址。一旦 Verkle 支持快照同步，就修复它。
	return bc.statedb.ContractCodeWithPrefix(common.Address{}, hash)
}

// State returns a new mutable state based on the current HEAD block.
// State 基于当前头部区块返回一个新的可变状态。
func (bc *BlockChain) State() (*state.StateDB, error) {
	return bc.StateAt(bc.CurrentBlock().Root)
}

// StateAt returns a new mutable state based on a particular point in time.
// StateAt 基于特定的时间点返回一个新的可变状态。
func (bc *BlockChain) StateAt(root common.Hash) (*state.StateDB, error) {
	return state.New(root, bc.statedb)
}

// Config retrieves the chain's fork configuration.
// Config 检索链的分叉配置。
func (bc *BlockChain) Config() *params.ChainConfig { return bc.chainConfig }

// Engine retrieves the blockchain's consensus engine.
// Engine 检索区块链的共识引擎。
func (bc *BlockChain) Engine() consensus.Engine { return bc.engine }

// Snapshots returns the blockchain snapshot tree.
// Snapshots 返回区块链的快照树。
func (bc *BlockChain) Snapshots() *snapshot.Tree {
	return bc.snaps
}

// Validator returns the current validator.
// Validator 返回当前的验证器。
func (bc *BlockChain) Validator() Validator {
	return bc.validator
}

// Processor returns the current processor.
// Processor 返回当前的处理器。
func (bc *BlockChain) Processor() Processor {
	return bc.processor
}

// StateCache returns the caching database underpinning the blockchain instance.
// StateCache 返回支持区块链实例的缓存数据库。
func (bc *BlockChain) StateCache() state.Database {
	return bc.statedb
}

// GasLimit returns the gas limit of the current HEAD block.
// GasLimit 返回当前头部区块的 Gas 限制。
func (bc *BlockChain) GasLimit() uint64 {
	return bc.CurrentBlock().GasLimit
}

// Genesis retrieves the chain's genesis block.
// Genesis 检索链的创世区块。
func (bc *BlockChain) Genesis() *types.Block {
	return bc.genesisBlock
}

// GetVMConfig returns the block chain VM config.
// GetVMConfig 返回区块链 VM 配置。
func (bc *BlockChain) GetVMConfig() *vm.Config {
	return &bc.vmConfig
}

// TxIndexProgress returns the transaction indexing progress.
// TxIndexProgress 返回交易索引的进度。
func (bc *BlockChain) TxIndexProgress() (TxIndexProgress, error) {
	if bc.txIndexer == nil {
		return TxIndexProgress{}, errors.New("tx indexer is not enabled")
	}
	return bc.txIndexer.txIndexProgress()
}

// TrieDB retrieves the low level trie database used for data storage.
// TrieDB 检索用于数据存储的底层 Trie 数据库。
func (bc *BlockChain) TrieDB() *triedb.Database {
	return bc.triedb
}

// HeaderChain returns the underlying header chain.
// HeaderChain 返回底层的头部链。
func (bc *BlockChain) HeaderChain() *HeaderChain {
	return bc.hc
}

// SubscribeRemovedLogsEvent registers a subscription of RemovedLogsEvent.
// SubscribeRemovedLogsEvent 注册一个 RemovedLogsEvent 的订阅。
func (bc *BlockChain) SubscribeRemovedLogsEvent(ch chan<- RemovedLogsEvent) event.Subscription {
	return bc.scope.Track(bc.rmLogsFeed.Subscribe(ch))
}

// SubscribeChainEvent registers a subscription of ChainEvent.
// SubscribeChainEvent 注册一个 ChainEvent 的订阅。
func (bc *BlockChain) SubscribeChainEvent(ch chan<- ChainEvent) event.Subscription {
	return bc.scope.Track(bc.chainFeed.Subscribe(ch))
}

// SubscribeChainHeadEvent registers a subscription of ChainHeadEvent.
// SubscribeChainHeadEvent 注册一个 ChainHeadEvent 的订阅。
func (bc *BlockChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.scope.Track(bc.chainHeadFeed.Subscribe(ch))
}

// SubscribeLogsEvent registers a subscription of []*types.Log.
// SubscribeLogsEvent 注册一个 []*types.Log 的订阅。
func (bc *BlockChain) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return bc.scope.Track(bc.logsFeed.Subscribe(ch))
}

// SubscribeBlockProcessingEvent registers a subscription of bool where true means
// block processing has started while false means it has stopped.
// SubscribeBlockProcessingEvent 注册一个 bool 类型的订阅，true 表示区块处理已开始，false 表示已停止。
func (bc *BlockChain) SubscribeBlockProcessingEvent(ch chan<- bool) event.Subscription {
	return bc.scope.Track(bc.blockProcFeed.Subscribe(ch))
}
