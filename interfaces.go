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

// Package ethereum defines interfaces for interacting with Ethereum.
package ethereum

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// NotFound is returned by API methods if the requested item does not exist.
// NotFound 由 API 方法返回，如果请求的项不存在。
var NotFound = errors.New("not found")

// Subscription represents an event subscription where events are
// delivered on a data channel.
// Subscription 表示事件订阅，其中事件通过数据通道传递。
//
// 支持以太坊客户端中的异步事件通知机制，例如订阅新区块头（chain head）或新交易。
type Subscription interface {
	// Unsubscribe cancels the sending of events to the data channel
	// and closes the error channel.
	// Unsubscribe 取消向数据通道发送事件，并关闭错误通道。
	//
	// 在以太坊中，订阅通常通过 RPC（如 eth_subscribe）实现，例如订阅 newHeads（新区块头）。取消订阅是必要的，以避免资源泄漏或接收不需要的事件。
	Unsubscribe()
	// Err returns the subscription error channel. The error channel receives
	// a value if there is an issue with the subscription (e.g. the network connection
	// delivering the events has been closed). Only one value will ever be sent.
	// The error channel is closed by Unsubscribe.
	// Err 返回订阅的错误通道。如果订阅出现问题（例如传递事件的网络连接已关闭），错误通道会接收到一个值。
	// 仅会发送一个值。
	// 错误通道由 Unsubscribe 关闭。
	//
	// 以太坊客户端可能因网络断开或节点故障导致订阅失败，Err 方法允许调用者优雅地处理这些情况。
	Err() <-chan error
}

// ChainReader provides access to the blockchain. The methods in this interface access raw
// data from either the canonical chain (when requesting by block number) or any
// blockchain fork that was previously downloaded and processed by the node. The block
// number argument can be nil to select the latest canonical block. Reading block headers
// should be preferred over full blocks whenever possible.
//
// The returned error is NotFound if the requested item does not exist.
//
// ChainReader 提供对区块链的访问。此接口中的方法可以访问原始数据，
// 来自规范链（按区块号请求时）或节点之前下载并处理过的任何区块链分叉。
// 区块号参数可以为 nil 以选择最新的规范区块。尽可能优先读取区块头而不是完整区块。
//
// 如果请求的项不存在，则返回的错误是 NotFound。
//
// 用于读取以太坊区块链的数据。它的目的是：
// 数据访问：提供对区块、区块头和交易的查询功能，支持按哈希或区块号访问。
// 实时通知：通过订阅机制（SubscribeNewHead）支持监听规范链头部区块的变化。
// 灵活性：支持访问规范链或历史分叉的数据，适用于不同的使用场景。
//
// 以太坊节点存储完整区块链历史，包括分叉数据。
// ChainReader 区分了按区块号（主链）和按哈希（可能分叉）的查询。
// 以太坊区块包含头部（Header）、交易列表和叔块，Header 是最轻量的数据单元。
// 此接口支持的基础功能与 EIP-1474（RPC 规范）相关，
type ChainReader interface {
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)                               // 根据区块哈希查询完整区块。
	BlockByNumber(ctx context.Context, number *big.Int) (*types.Block, error)                              // 根据区块号查询完整区块。规范链（canonical chain）是以太坊共识认可的主链，区块号是其顺序标识。
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)                             // 根据哈希查询区块头。区块头比完整区块轻量，适合快速验证或同步。
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)                            // 根据区块号查询区块头。优先读取区块头是性能优化的推荐实践，避免加载完整交易数据。
	TransactionCount(ctx context.Context, blockHash common.Hash) (uint, error)                             // 返回指定区块中的交易数量。交易计数是区块头的一部分（txRoot 指向交易树的根），用于验证区块完整性。
	TransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, error) // 根据区块哈希和交易索引查询特定交易。交易按顺序存储在区块中，索引从 0 开始。

	// SubscribeNewHead This method subscribes to notifications about changes of the head block of
	// the canonical chain.
	// 此方法订阅有关规范链头部区块变更的通知。
	SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (Subscription, error)
}

// TransactionReader provides access to past transactions and their receipts.
// Implementations may impose arbitrary restrictions on the transactions and receipts that
// can be retrieved. Historic transactions may not be available.
//
// Avoid relying on this interface if possible. Contract logs (through the LogFilterer
// interface) are more reliable and usually safer in the presence of chain
// reorganisations.
//
// The returned error is NotFound if the requested item does not exist.
//
// TransactionReader 提供对历史交易及其收据的访问。实现可能会对可检索的交易和收据施加任意限制。历史交易可能不可用。
//
// 如果可能，避免依赖此接口。合约日志（通过 LogFilterer 接口）更可靠，并且在链重组时通常更安全。
//
// 如果请求的项不存在，则返回的错误是 NotFound。
//
// 链重组（Reorganization）：以太坊 PoW（现已转为 PoS）中，较长的分叉可能取代当前链，导致交易状态变化。注释建议使用 LogFilterer（日志过滤器）查询事件日志，因日志更稳定。
// 交易生命周期：交易从待处理池广播到被矿工打包上链，收据在区块确认后生成。
type TransactionReader interface {
	// TransactionByHash checks the pool of pending transactions in addition to the
	// blockchain. The isPending return value indicates whether the transaction has been
	// mined yet. Note that the transaction may not be part of the canonical chain even if
	// it's not pending.
	// TransactionByHash 检查待处理交易池以及区块链。
	// isPending 返回值指示交易是否已被挖出。注意，即使交易不是待处理的，它也可能不属于规范链。
	//
	// 待处理交易池（mempool）：存储未确认的交易，isPending 为 true 表示交易尚未上链。
	// 链重组：即使交易已上链（isPending 为 false），也可能因分叉未被包含在规范链中。
	TransactionByHash(ctx context.Context, txHash common.Hash) (tx *types.Transaction, isPending bool, err error) // 根据交易哈希查询交易，检查区块链和待处理交易池。
	// TransactionReceipt returns the receipt of a mined transaction. Note that the
	// transaction may not be included in the current canonical chain even if a receipt
	// exists.
	// TransactionReceipt 返回已挖出交易的收据。注意，即使收据存在，交易也可能不包含在当前规范链中。
	//
	// 交易收据：记录交易的执行结果，包括 Gas 使用量、日志（events）等。
	// 非规范链风险：收据存在并不保证交易在当前主链中，因链重组可能导致区块被丢弃。
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) // 返回已挖出交易的收据。
}

// 状态树（State Trie）：以太坊使用 Merkle Patricia Trie 存储所有账户的状态（余额、nonce、代码、存储）。每个区块都有一个状态根（state root），记录当前状态。
// 历史数据限制：全节点可能修剪旧状态（pruning），导致无法查询早期区块的状态。归档节点（archive node）则保留完整历史。
// CallContract 替代：通过模拟合约调用（eth_call）读取状态更可靠，因它直接执行合约逻辑，而非依赖底层存储布局。

// ChainStateReader wraps access to the state trie of the canonical blockchain. Note that
// implementations of the interface may be unable to return state values for old blocks.
// In many cases, using CallContract can be preferable to reading raw contract storage.
//
// ChainStateReader 封装了对规范区块链状态树的访问。注意，该接口的实现可能无法返回旧区块的状态值。
// 在许多情况下，使用 CallContract 比读取原始合约存储更可取。
//
// 提供对以太坊状态树（state trie）的访问，用于查询账户余额、存储、代码和 nonce。
type ChainStateReader interface {
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)                // 查询指定账户在特定区块高度的余额。余额是状态树中账户的基本属性，单位为 Wei（1 ETH = 10^18 Wei）。
	StorageAt(ctx context.Context, account common.Address, key common.Hash, blockNumber *big.Int) ([]byte, error) // 查询合约账户在特定区块高度的存储槽值。key：存储槽的哈希键（32 字节）。[]byte 是存储值（通常 32 字节）。状态树存储合约的键值对，key 是经过 Keccak-256 哈希的槽索引，值由合约逻辑定义。
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)                     // 查询账户的合约代码。合约账户存储其部署时的字节码，EOA（外部拥有账户）返回空字节。
	NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error)                    // 查询账户的 nonce 值。Nonce 是账户发送交易的序号，用于防止重放攻击。
}

// 同步模式：
// 快速同步：下载区块头和最新状态，适用于轻量节点，现已废弃。
// 快照同步：下载状态快照并逐步修复完整状态树，效率更高。
// 完整同步：下载所有区块和状态，适用于归档节点。

// SyncProgress gives progress indications when the node is synchronising with
// the Ethereum network.
//
// SyncProgress 提供节点与以太坊网络同步时的进度指示。
type SyncProgress struct {
	// 这些字段反映了区块同步进度，HighestBlock 可能因网络分叉而动态变化。
	StartingBlock uint64 // Block number where sync began    		  同步开始时的区块号
	CurrentBlock  uint64 // Current block number where sync is at     同步当前所在的区块号
	HighestBlock  uint64 // Highest alleged block number in the chain 链中声称的最高区块号

	// "fast sync" fields. These used to be sent by geth, but are no longer used
	// since version v1.10.
	// "快速同步"字段。这些字段曾由 Geth 发送，但自 v1.10 版本后不再使用。
	// 快速同步是 Geth 早期使用的模式，通过下载区块头和部分状态加速同步，自 v1.10 起被快照同步取代。
	PulledStates uint64 // Number of state trie entries already downloaded  已下载的状态树条目数量
	KnownStates  uint64 // Total number of state trie entries known about   已知的状态树条目总数

	// "snap sync" fields.
	// "快照同步"字段。
	// 快照同步（snap sync）是 Geth 的新同步模式，从快照下载状态树，Healing 表示修复不完整数据的阶段。
	SyncedAccounts      uint64 // Number of accounts downloaded    				 已下载的账户数量
	SyncedAccountBytes  uint64 // Number of account trie bytes persisted to disk 已持久化到磁盘的账户树字节数
	SyncedBytecodes     uint64 // Number of bytecodes downloaded				 已下载的字节码数量
	SyncedBytecodeBytes uint64 // Number of bytecode bytes downloaded 		     已下载的字节码字节数
	SyncedStorage       uint64 // Number of storage slots downloaded             已下载的存储槽数量
	SyncedStorageBytes  uint64 // Number of storage trie bytes persisted to disk 已持久化到磁盘的存储树字节数

	HealedTrienodes     uint64 // Number of state trie nodes downloaded    已下载的状态树节点数量
	HealedTrienodeBytes uint64 // Number of state trie bytes persisted to disk 已持久化到磁盘的状态树字节数
	HealedBytecodes     uint64 // Number of bytecodes downloaded   已下载的字节码数量
	HealedBytecodeBytes uint64 // Number of bytecodes persisted to disk  已持久化到磁盘的字节码字节数

	HealingTrienodes uint64 // Number of state trie nodes pending  待处理的状态树节点数量
	HealingBytecode  uint64 // Number of bytecodes pending         待处理的字节码数量

	// "transaction indexing" fields
	// "交易索引"字段
	// 交易索引用于快速查询历史交易，默认关闭，开启后需额外同步。
	TxIndexFinishedBlocks  uint64 // Number of blocks whose transactions are already indexed 交易已完成索引的区块数量
	TxIndexRemainingBlocks uint64 // Number of blocks whose transactions are not indexed yet 交易尚未索引的区块数量
}

// Done returns the indicator if the initial sync is finished or not.
// Done 返回初始同步是否完成的指示器。
// 同步完成不仅要求区块同步到最新，还要确保交易索引（若启用）完成。
func (prog SyncProgress) Done() bool {
	if prog.CurrentBlock < prog.HighestBlock {
		return false
	}
	return prog.TxIndexRemainingBlocks == 0
}

// ChainSyncReader wraps access to the node's current sync status. If there's no
// sync currently running, it returns nil.
// ChainSyncReader 封装了对节点当前同步状态的访问。如果当前没有同步在运行，则返回 nil。
//
// 以太坊节点需从网络下载区块链数据以保持最新状态。新节点可能进行完整同步（full sync）、快照同步（snap sync）或快速同步（fast sync，已废弃）。
//
// 节点状态：
//   - 同步中：节点正在下载数据，SyncProgress 返回非空值。
//   - 已同步：节点达到最新区块且无待处理任务，SyncProgress 返回 nil。
type ChainSyncReader interface {
	SyncProgress(ctx context.Context) (*SyncProgress, error)
}

// EIP-1559：引入动态费用市场，分为基础费用和小费，优化交易成本。
// EIP-2930：访问列表减少 Gas 消耗，提升性能。
// EIP-4844：引入 Blob 交易，支持 Rollup 数据存储，降低 Layer 2 成本。

// CallMsg contains parameters for contract calls.
// CallMsg 包含合约调用的参数。
//
// 合约调用：eth_call 使用 CallMsg 模拟执行，不改变链上状态，常用于查询合约数据。
type CallMsg struct {
	From      common.Address  // the sender of the 'transaction' '交易'的发送者，From 表示交易的发起者，通常是外部拥有账户（EOA），用于签名验证或状态更新。
	To        *common.Address // the destination contract (nil for contract creation) 目标合约地址（若为 nil，则表示合约创建）。合约创建时，To 为空，Data 包含字节码；调用时，指向已有合约地址。
	Gas       uint64          // if 0, the call executes with near-infinite gas 如果为 0，调用将以近乎无限的 Gas 执行。Gas 是执行成本的计量单位，eth_call 中设为 0 表示不限制，用于模拟执行。
	GasPrice  *big.Int        // wei <-> gas exchange ratio   Wei 与 Gas 的交换比率。传统交易的 Gas 价格（Wei/Gas）。在 EIP-1559 之前，GasPrice 直接决定交易费用。
	GasFeeCap *big.Int        // EIP-1559 fee cap per gas.   EIP-1559 每单位 Gas 的费用上限。EIP-1559 引入基础费用（base fee）和上限，GasFeeCap 是用户愿意支付的最大值。
	GasTipCap *big.Int        // EIP-1559 tip per gas.       EIP-1559 每单位 Gas 的小费。小费（priority fee）激励矿工优先打包交易。
	Value     *big.Int        // amount of wei sent along with the call 调用时发送的 Wei 数量。随调用发送的 Ether 数量（以 Wei 为单位）。Value 用于向合约转账，通常与 payable 函数配合。
	Data      []byte          // input data, usually an ABI-encoded contract method invocation 输入数据，通常是 ABI 编码的合约方法调用

	AccessList types.AccessList // EIP-2930 access list. EIP-2930 访问列表，指定预加载的状态。访问列表优化 Gas 成本，预先声明访问的账户和存储槽。

	// For BlobTxType
	BlobGasFeeCap *big.Int // 支持 EIP-4844 Blob 交易的 Gas 费用上限和 Blob 数据哈希。EIP-4844（分片 Blob 数据）是为以太坊 Rollup 设计的扩展，BlobHashes 指向链下数据。
	BlobHashes    []common.Hash
}

// A ContractCaller provides contract calls, essentially transactions that are executed by
// the EVM but not mined into the blockchain. ContractCall is a low-level method to
// execute such calls. For applications which are structured around specific contracts,
// the abigen tool provides a nicer, properly typed way to perform calls.
//
// ContractCaller 提供合约调用，实质上是 EVM 执行但不被挖入区块链的交易。ContractCall 是一个低级方法，用于执行此类调用。
// 对于围绕特定合约构建的应用程序，abigen 工具提供了更友好、类型正确的方式来进行调用。
//
// 用于在以太坊虚拟机（EVM）中模拟执行合约调用，而不将结果写入区块链。
// 模拟执行：允许开发者测试合约逻辑或查询状态，而无需发送真实交易。
type ContractCaller interface {
	CallContract(ctx context.Context, call CallMsg, blockNumber *big.Int) ([]byte, error)
}

// FilterQuery contains options for contract log filtering.
// FilterQuery 包含合约日志过滤的选项。
type FilterQuery struct {
	// BlockHash 用于精确查询某区块的事件，与 eth_getLogs 的行为一致。若设置，则忽略 FromBlock 和 ToBlock。
	BlockHash *common.Hash // used by eth_getLogs, return logs only from block with this hash 用于 eth_getLogs，仅返回此哈希对应区块的日志。
	// 查询范围的起始区块，nil 表示从创世区块（0 号区块）开始。创世区块是以太坊链的起点，日志查询通常从特定高度开始以减少范围。
	FromBlock *big.Int // beginning of the queried range, nil means genesis block    	  查询范围的起始区块，nil 表示创世区块
	// 查询范围的结束区块，nil 表示最新区块。最新区块是当前规范链的头部，动态变化。
	ToBlock *big.Int // end of the range, nil means latest block   				  	  查询范围的结束区块，nil 表示最新区块
	// 限制日志来源为特定合约地址列表。日志由合约通过 emit 语句生成，Addresses 过滤特定合约的事件。
	Addresses []common.Address // restricts matches to events created by specific contracts  	  限制匹配特定合约创建的事件

	// The Topic list restricts matches to particular event topics. Each event has a list
	// of topics. Topics matches a prefix of that list. An empty element slice matches any
	// topic. Non-empty elements represent an alternative that matches any of the
	// contained topics.
	//
	// Examples:
	// {} or nil          matches any topic list
	// {{A}}              matches topic A in first position
	// {{}, {B}}          matches any topic in first position AND B in second position
	// {{A}, {B}}         matches topic A in first position AND B in second position
	// {{A, B}, {C, D}}   matches topic (A OR B) in first position AND (C OR D) in second position
	//
	// Topics 列表限制匹配特定的事件主题。每个事件有一个主题列表。Topics 匹配该列表的前缀。
	// 空元素切片匹配任何主题。非空元素表示匹配其中包含的任一主题的替代选项。
	//
	// 示例：
	// {} 或 nil          匹配任何主题列表
	// {{A}}              匹配第一个位置的主题 A
	// {{}, {B}}          匹配第一个位置的任何主题 AND 第二个位置的主题 B
	// {{A}, {B}}         匹配第一个位置的主题 A AND 第二个位置的主题 B
	// {{A, B}, {C, D}}   匹配第一个位置的主题 (A 或 B) AND 第二个位置的主题 (C 或 D)
	//
	// 按事件主题过滤日志，支持复杂匹配规则。
	// 每个事件有多个主题（Topics），第一个是事件签名哈希，后续是索引参数。
	// Topics 是二维数组，每一行对应一个位置的主题匹配。
	// 空切片（{} 或 nil）匹配任何值，非空切片表示 OR 条件。主题是事件的 Keccak-256 哈希，用于高效索引和过滤。
	Topics [][]common.Hash
}

// 日志（Logs）：由合约通过 emit 语句生成，存储在交易收据中，包含地址、主题和数据。
// 链重组：以太坊 PoW（现为 PoS）中，分叉可能导致区块被替换，订阅的日志可能标记为 Removed。

// LogFilterer provides access to contract log events using a one-off query or continuous
// event subscription.
//
// Logs received through a streaming query subscription may have Removed set to true,
// indicating that the log was reverted due to a chain reorganisation.
//
// LogFilterer 提供对合约日志事件的访问，支持一次性查询或持续的事件订阅。
//
// 通过流式查询订阅接收的日志可能将 Removed 设置为 true，表示由于链重组，日志已被回滚。
//
// 日志访问：支持一次性获取历史日志（FilterLogs）和实时订阅新日志（SubscribeFilterLogs）。
type LogFilterer interface {
	FilterLogs(ctx context.Context, q FilterQuery) ([]types.Log, error)                                // 根据过滤条件查询历史日志。对应 eth_getLogs，用于批量获取历史事件，例如查询某合约的 Transfer 事件。
	SubscribeFilterLogs(ctx context.Context, q FilterQuery, ch chan<- types.Log) (Subscription, error) // 订阅符合条件的日志事件。对应 eth_subscribe 的 logs 类型，实时推送新事件，Removed 字段标记重组回滚。
}

// TransactionSender wraps transaction sending. The SendTransaction method injects a
// signed transaction into the pending transaction pool for execution. If the transaction
// was a contract creation, the TransactionReceipt method can be used to retrieve the
// contract address after the transaction has been mined.
//
// The transaction must be signed and have a valid nonce to be included. Consumers of the
// API can use package accounts to maintain local private keys and need can retrieve the
// next available nonce using PendingNonceAt.
//
// TransactionSender 封装了交易发送。SendTransaction 方法将已签名的交易注入待处理交易池以执行。
// 如果交易是合约创建，可以在交易被挖出后使用 TransactionReceipt 方法检索合约地址。
//
// 交易必须经过签名并具有有效的 nonce 才能被包含。API 的使用者可以使用 accounts 包维护本地私钥，
// 并通过 PendingNonceAt 获取下一个可用 nonce。
//
// 交易从签名到广播至待处理池，再被矿工打包上链。若 tx.To 为 nil，交易部署新合约，地址在收据（TransactionReceipt）中返回。
type TransactionSender interface {
	SendTransaction(ctx context.Context, tx *types.Transaction) error // 将签名交易发送到待处理池。
}

// 传统 Gas 价格：在 EIP-1559 之前，交易费用由 GasPrice * GasUsed 决定。
// 预言机：监控区块链（如最近区块的 Gas 价格）以估计合理值。

// GasPricer wraps the gas price oracle, which monitors the blockchain to determine the
// optimal gas price given current fee market conditions.
//
// GasPricer 封装了 Gas 价格预言机，它监控区块链以根据当前费用市场条件确定最佳 Gas 价格。
// 为传统交易（pre-EIP-1559）建议 Gas 价格。
type GasPricer interface {
	SuggestGasPrice(ctx context.Context) (*big.Int, error) // 建议当前最佳 Gas 价格。
}

// EIP-1559：引入基础费用（base fee）和小费机制，小费激励矿工优先打包。
// 动态调整：小费建议基于网络拥堵程度动态变化。

// GasPricer1559 provides access to the EIP-1559 gas price oracle.
// GasPricer1559 提供对 EIP-1559 Gas 价格预言机的访问。
// 为 EIP-1559 交易建议 Gas 小费（tip）。
type GasPricer1559 interface {
	SuggestGasTipCap(ctx context.Context) (*big.Int, error) // 建议 EIP-1559 交易的 Gas 小费上限。
}

// FeeHistoryReader provides access to the fee history oracle.
// FeeHistoryReader 提供对费用历史预言机的访问。
// 查询历史费用数据，帮助分析市场趋势。
type FeeHistoryReader interface {
	FeeHistory(ctx context.Context, blockCount uint64, lastBlock *big.Int, rewardPercentiles []float64) (*FeeHistory, error) // 查询指定区块范围的费用历史。对应 eth_feeHistory(EIP-3198)，提供过去区块的费用统计。
}

// FeeHistory provides recent fee market data that consumers can use to determine
// a reasonable maxPriorityFeePerGas value.
// FeeHistory 提供最近的费用市场数据，使用者可利用这些数据确定合理的 maxPriorityFeePerGas 值。
type FeeHistory struct {
	OldestBlock  *big.Int     // block corresponding to first response value 		   对应于第一个响应值的区块。记录返回数据中最老的区块号，对应 eth_feeHistory 请求的起始点，表示数据的第一个区块。
	Reward       [][]*big.Int // list every txs priority fee per block       		   每个区块中每笔交易的小费列表
	BaseFee      []*big.Int   // list of each block's base fee				  		   每个区块的基础费用列表
	GasUsedRatio []float64    // ratio of gas used out of the total available limit    Gas 使用量与总可用限制的比例
}

// 待处理状态：基于交易池中的交易模拟的状态，不保证最终上链（可能因重组或丢弃而变化）。
// 交易池（mempool）：节点存储未确认交易的地方。

// A PendingStateReader provides access to the pending state, which is the result of all
// known executable transactions which have not yet been included in the blockchain. It is
// commonly used to display the result of ’unconfirmed’ actions (e.g. wallet value
// transfers) initiated by the user. The PendingNonceAt operation is a good way to
// retrieve the next available transaction nonce for a specific account.
//
// PendingStateReader 提供对待处理状态的访问，待处理状态是所有已知但尚未包含在区块链中的可执行交易的结果。
// 它通常用于显示用户发起的“未确认”操作的结果（例如钱包价值转移）。
// PendingNonceAt 操作是获取特定账户下一个可用交易 nonce 的好方法。
//
// 基于待处理交易池（mempool）中交易的临时状态。
type PendingStateReader interface {
	PendingBalanceAt(ctx context.Context, account common.Address) (*big.Int, error)                // 查询账户的待处理余额。反映待处理交易后的余额，例如转账后的临时值。
	PendingStorageAt(ctx context.Context, account common.Address, key common.Hash) ([]byte, error) // 查询合约账户的待处理存储槽值。待处理状态包括未确认交易对合约存储的修改。
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)                     // 查询账户的待处理合约代码。若待处理交易包含合约部署，返回新代码。
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)                    // 查询账户的下一个可用 nonce。nonce 是交易序号，PendingNonceAt 返回当前链上 nonce 加上待处理交易数。
	PendingTransactionCount(ctx context.Context) (uint, error)                                     // 查询待处理交易池中的交易总数。反映交易池的活跃度。
}

// PendingContractCaller can be used to perform calls against the pending state.
// PendingContractCaller 可用于针对待处理状态执行调用。
// 在待处理状态下模拟合约调用。
type PendingContractCaller interface {
	PendingCallContract(ctx context.Context, call CallMsg) ([]byte, error) // 基于待处理状态执行合约调用。类似 eth_call，但使用待处理状态（如未确认交易的结果）。
}

// GasEstimator wraps EstimateGas, which tries to estimate the gas needed to execute a
// specific transaction based on the pending state. There is no guarantee that this is the
// true gas limit requirement as other transactions may be added or removed by miners, but
// it should provide a basis for setting a reasonable default.
//
// GasEstimator 封装了 EstimateGas，它尝试根据待处理状态估算执行特定交易所需的 Gas。
// 无法保证这是真实的 Gas 限制需求，因为矿工可能会添加或移除其他交易，但它应为设置合理默认值提供基础。
type GasEstimator interface {
	EstimateGas(ctx context.Context, call CallMsg) (uint64, error) // 估算交易所需的 Gas。对应 eth_estimateGas，基于当前状态模拟执行。因交易池动态变化，估算值仅供参考。
}

// A PendingStateEventer provides access to real time notifications about changes to the
// pending state.
// PendingStateEventer 提供对有关待处理状态变更的实时通知的访问。
type PendingStateEventer interface {
	SubscribePendingTransactions(ctx context.Context, ch chan<- *types.Transaction) (Subscription, error) // 订阅待处理交易池的新交易。：对应 eth_subscribe 的 newPendingTransactions，实时监控交易池。
}

// BlockNumberReader provides access to the current block number.
// BlockNumberReader 提供对当前区块号的访问。
type BlockNumberReader interface {
	BlockNumber(ctx context.Context) (uint64, error) // 获取当前区块号。对应 eth_blockNumber，反映链头状态。
}

// ChainIDReader provides access to the chain ID.
// ChainIDReader 提供对链 ID 的访问。
type ChainIDReader interface {
	ChainID(ctx context.Context) (*big.Int, error) // 获取当前链的 ID。链 ID 用于区分网络（如主网、测试网），EIP-155 引入。
}
