// Copyright 2023 The go-ethereum Authors
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

package txpool

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/event"
	"github.com/holiman/uint256"
)

// 延迟加载: LazyTransaction 和 LazyResolver 的引入是一种性能优化策略。在处理大量交易时，只加载必要的信息可以减少内存占用和 CPU 使用。例如，矿工可能只需要交易的 Gas 价格和 Gas 限制来决定是否打包，而不需要完整的交易数据。
// 模块化设计: SubPool 接口使得交易池可以被划分为多个专门的子池，每个子池可以处理特定类型的交易。这在引入新的交易类型（如 EIP-4844 的 blob 交易）时非常有用，可以将 blob 交易的管理逻辑与传统的 EVM 交易分开。
// EIP-4844: BlobGas 字段和 GetBlobs 方法是为支持 EIP-4844 而引入的。Blob 交易需要额外的 blob 数据和相应的证明，这些都需要在交易池中进行管理。
// 交易过滤: PendingFilter 允许根据不同的标准（例如，最小小费、基础费用、交易类型）选择待处理的交易，这对于优化广播效率和区块构建过程非常重要。
// 地址预留: AddressReserver 机制可能用于实现更高级的交易优先级或拥塞控制策略，允许子池为某些关键账户预留处理能力。

// LazyTransaction contains a small subset of the transaction properties that is
// enough for the miner and other APIs to handle large batches of transactions;
// and supports pulling up the entire transaction when really needed.
// LazyTransaction 包含交易属性的一个小子集，该子集足以供矿工和其他 API 处理大量交易；
// 并且支持在真正需要时拉取整个交易。
type LazyTransaction struct {
	Pool LazyResolver // Transaction resolver to pull the real transaction up
	// Pool 交易解析器，用于拉取真实的交易。
	Hash common.Hash // Transaction hash to pull up if needed
	// Hash 交易哈希，如果需要则拉取。
	Tx *types.Transaction // Transaction if already resolved
	// Tx 如果已解析，则为交易。

	Time time.Time // Time when the transaction was first seen
	// Time 首次看到交易的时间。
	GasFeeCap *uint256.Int // Maximum fee per gas the transaction may consume
	// GasFeeCap 交易可能消耗的每单位 gas 的最大费用。
	GasTipCap *uint256.Int // Maximum miner tip per gas the transaction can pay
	// GasTipCap 交易可以支付的每单位 gas 的最大矿工小费。

	Gas uint64 // Amount of gas required by the transaction
	// Gas 交易所需的 gas 量。
	BlobGas uint64 // Amount of blob gas required by the transaction
	// BlobGas 交易所需的 blob gas 量。
}

// Resolve retrieves the full transaction belonging to a lazy handle if it is still
// maintained by the transaction pool.
// Resolve 检索属于延迟句柄的完整交易（如果它仍然由交易池维护）。
//
// Note, the method will *not* cache the retrieved transaction if the original
// pool has not cached it. The idea being, that if the tx was too big to insert
// originally, silently saving it will cause more trouble down the line (and
// indeed seems to have caused a memory bloat in the original implementation
// which did just that).
// 注意，如果原始池没有缓存检索到的交易，该方法将 *不会* 缓存它。
// 这样做的想法是，如果交易最初太大而无法插入，则静默保存它会在以后引起更多麻烦
// （并且实际上似乎在原始实现中引起了内存膨胀，而原始实现正是这样做的）。
func (ltx *LazyTransaction) Resolve() *types.Transaction {
	if ltx.Tx != nil {
		return ltx.Tx
	}
	return ltx.Pool.Get(ltx.Hash)
}

// LazyResolver is a minimal interface needed for a transaction pool to satisfy
// resolving lazy transactions. It's mostly a helper to avoid the entire sub-
// pool being injected into the lazy transaction.
// LazyResolver 是交易池满足解析延迟交易所需的最小接口。
// 它主要是为了避免将整个子池注入到延迟交易中的辅助工具。
type LazyResolver interface {
	// Get returns a transaction if it is contained in the pool, or nil otherwise.
	// Get 如果交易池中包含具有给定哈希的交易，则返回该交易，否则返回 nil。
	Get(hash common.Hash) *types.Transaction
}

// AddressReserver is passed by the main transaction pool to subpools, so they
// may request (and relinquish) exclusive access to certain addresses.
// AddressReserver 由主交易池传递给子池，以便它们可以请求（和放弃）对某些地址的独占访问权。
type AddressReserver func(addr common.Address, reserve bool) error

// PendingFilter is a collection of filter rules to allow retrieving a subset
// of transactions for announcement or mining.
// PendingFilter 是一个过滤器规则集合，用于允许检索用于广播或挖矿的交易子集。
//
// Note, the entries here are not arbitrary useful filters, rather each one has
// a very specific call site in mind and each one can be evaluated very cheaply
// by the pool implementations. Only add new ones that satisfy those constraints.
// 注意，这里的条目不是任意有用的过滤器，而是每个都有非常特定的调用点，并且每个都可以由池实现非常廉价地评估。
// 只有添加满足这些约束的新过滤器。
type PendingFilter struct {
	MinTip *uint256.Int // Minimum miner tip required to include a transaction
	// MinTip 包含交易所需的最小矿工小费。
	BaseFee *uint256.Int // Minimum 1559 basefee needed to include a transaction
	// BaseFee 包含交易所需的最小 1559 基础费用。
	BlobFee *uint256.Int // Minimum 4844 blobfee needed to include a blob transaction
	// BlobFee 包含 blob 交易所需的最小 4844 blob 费用。

	OnlyPlainTxs bool // Return only plain EVM transactions (peer-join announces, block space filling)
	// OnlyPlainTxs 如果为 true，则仅返回普通的 EVM 交易（用于对等节点加入广播，填充区块空间）。
	OnlyBlobTxs bool // Return only blob transactions (block blob-space filling)
	// OnlyBlobTxs 如果为 true，则仅返回 blob 交易（用于填充区块 blob 空间）。
}

// SubPool represents a specialized transaction pool that lives on its own (e.g.
// blob pool). Since independent of how many specialized pools we have, they do
// need to be updated in lockstep and assemble into one coherent view for block
// production, this interface defines the common methods that allow the primary
// transaction pool to manage the subpools.
// SubPool 表示一个独立的专用交易池（例如，blob 池）。
// 由于无论我们有多少个专用池，它们都需要同步更新并组合成一个连贯的视图以用于区块生产，
// 因此该接口定义了允许主交易池管理子池的通用方法。
type SubPool interface {
	// Filter is a selector used to decide whether a transaction would be added
	// to this particular subpool.
	// Filter 是一个选择器，用于决定是否将交易添加到此特定的子池。
	Filter(tx *types.Transaction) bool

	// Init sets the base parameters of the subpool, allowing it to load any saved
	// transactions from disk and also permitting internal maintenance routines to
	// start up.
	// Init 设置子池的基本参数，允许它从磁盘加载任何已保存的交易，并允许内部维护例程启动。
	//
	// These should not be passed as a constructor argument - nor should the pools
	// start by themselves - in order to keep multiple subpools in lockstep with
	// one another.
	// 这些不应该作为构造函数参数传递 - 池也不应该自行启动 - 以便保持多个子池彼此同步。
	Init(gasTip uint64, head *types.Header, reserve AddressReserver) error

	// Close terminates any background processing threads and releases any held
	// resources.
	// Close 终止任何后台处理线程并释放任何持有的资源。
	Close() error

	// Reset retrieves the current state of the blockchain and ensures the content
	// of the transaction pool is valid with regard to the chain state.
	// Reset 检索区块链的当前状态，并确保交易池的内容在链状态方面是有效的。
	Reset(oldHead, newHead *types.Header)

	// SetGasTip updates the minimum price required by the subpool for a new
	// transaction, and drops all transactions below this threshold.
	// SetGasTip 更新子池对新交易所需的最低价格，并删除所有低于此阈值的交易。
	SetGasTip(tip *big.Int)

	// Has returns an indicator whether subpool has a transaction cached with the
	// given hash.
	// Has 返回一个指示器，指示子池是否缓存了具有给定哈希的交易。
	Has(hash common.Hash) bool

	// Get returns a transaction if it is contained in the pool, or nil otherwise.
	// Get 如果交易池中包含具有给定哈希的交易，则返回该交易，否则返回 nil。
	Get(hash common.Hash) *types.Transaction

	// GetBlobs returns a number of blobs are proofs for the given versioned hashes.
	// This is a utility method for the engine API, enabling consensus clients to
	// retrieve blobs from the pools directly instead of the network.
	// GetBlobs 返回给定版本化哈希的若干 blob 及其证明。
	// 这是引擎 API 的一个实用方法，使共识客户端能够直接从池中检索 blob，而不是从网络检索。
	GetBlobs(vhashes []common.Hash) ([]*kzg4844.Blob, []*kzg4844.Proof)

	// Add enqueues a batch of transactions into the pool if they are valid. Due
	// to the large transaction churn, add may postpone fully integrating the tx
	// to a later point to batch multiple ones together.
	// Add 如果一批交易有效，则将其加入到池中。由于交易的大量 churn，add 可能会推迟完全集成交易到稍后的时间点，以便批量处理多个交易。
	Add(txs []*types.Transaction, local bool, sync bool) []error

	// Pending retrieves all currently processable transactions, grouped by origin
	// account and sorted by nonce.
	// Pending 检索所有当前可处理的交易，按来源账户分组，并按 nonce 排序。
	//
	// The transactions can also be pre-filtered by the dynamic fee components to
	// reduce allocations and load on downstream subsystems.
	// 交易也可以通过动态费用组件进行预过滤，以减少下游子系统的分配和负载。
	Pending(filter PendingFilter) map[common.Address][]*LazyTransaction

	// SubscribeTransactions subscribes to new transaction events. The subscriber
	// can decide whether to receive notifications only for newly seen transactions
	// or also for reorged out ones.
	// SubscribeTransactions 订阅新的交易事件。订阅者可以决定是否只接收新看到的交易的通知，还是也接收因重组而失效的交易的通知。
	SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription

	// Nonce returns the next nonce of an account, with all transactions executable
	// by the pool already applied on top.
	// Nonce 返回一个账户的下一个 nonce，其中池中所有可执行的交易都已应用。
	Nonce(addr common.Address) uint64

	// Stats retrieves the current pool stats, namely the number of pending and the
	// number of queued (non-executable) transactions.
	// Stats 检索当前的池统计信息，即待处理（pending）和排队（queued，不可执行）的交易数量。
	Stats() (int, int)

	// Content retrieves the data content of the transaction pool, returning all the
	// pending as well as queued transactions, grouped by account and sorted by nonce.
	// Content 检索交易池的数据内容，返回所有待处理和排队的交易，按账户分组并按 nonce 排序。
	Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction)

	// ContentFrom retrieves the data content of the transaction pool, returning the
	// pending as well as queued transactions of this address, grouped by nonce.
	// ContentFrom 检索交易池的数据内容，返回此地址的待处理和排队的交易，按 nonce 分组。
	ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction)

	// Locals retrieves the accounts currently considered local by the pool.
	// Locals 检索池中当前被认为是本地的账户。
	Locals() []common.Address

	// Status returns the known status (unknown/pending/queued) of a transaction
	// identified by their hashes.
	// Status 返回由其哈希标识的交易的已知状态（未知/待处理/排队）。
	Status(hash common.Hash) TxStatus

	// Clear removes all tracked transactions from the pool
	// Clear 从池中删除所有跟踪的交易。
	Clear()
}
