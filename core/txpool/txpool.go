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
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
)

// TxStatus is the current status of a transaction as seen by the pool.
// TxStatus 是交易在交易池中看到的当前状态。
type TxStatus uint

const (
	TxStatusUnknown TxStatus = iota // Transaction is not present in the pool.
	// TxStatusUnknown 交易不在池中。
	TxStatusQueued // Transaction is known but cannot be executed yet (e.g., missing previous nonce).
	// TxStatusQueued 交易已知，但由于某些原因（例如，缺少之前的 Nonce）目前无法执行。
	TxStatusPending // Transaction is ready for execution and has a valid nonce.
	// TxStatusPending 交易已准备好执行，并且具有有效的 Nonce。
	TxStatusIncluded // Transaction has been included in a block.
	// TxStatusIncluded 交易已包含在区块中。
)

var (
	// reservationsGaugeName is the prefix of a per-subpool address reservation
	// metric.
	//
	// This is mostly a sanity metric to ensure there's no bug that would make
	// some subpool hog all the reservations due to mis-accounting.
	// reservationsGaugeName 是每个子池地址预留指标的前缀。
	//
	// 这主要是一个健全性指标，用于确保没有错误会导致某些子池由于错误记账而占用所有预留。
	reservationsGaugeName = "txpool/reservations"
)

// BlockChain defines the minimal set of methods needed to back a tx pool with
// a chain. Exists to allow mocking the live chain out of tests.
// BlockChain 定义了使用链来支持交易池所需的最小方法集合。它的存在是为了允许在测试中模拟真实的链。
type BlockChain interface {
	// CurrentBlock returns the current head of the chain.
	// CurrentBlock 方法返回链的当前头部区块。
	CurrentBlock() *types.Header

	// SubscribeChainHeadEvent subscribes to new blocks being added to the chain.
	// SubscribeChainHeadEvent 订阅向链添加新区块的事件。
	SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription
}

// TxPool is an aggregator for various transaction specific pools, collectively
// tracking all the transactions deemed interesting by the node. Transactions
// enter the pool when they are received from the network or submitted locally.
// They exit the pool when they are included in the blockchain or evicted due to
// resource constraints.
// TxPool 是各种特定交易池的聚合器，共同跟踪节点认为所有有趣的交易。交易在从网络接收或本地提交时进入池中。
// 当它们包含在区块链中或由于资源限制而被驱逐时，它们会退出池中。
type TxPool struct {
	subpools []SubPool // List of subpools for specialized transaction handling
	// subpools 用于专门处理交易的子池列表。

	reservations map[common.Address]SubPool // Map with the account to pool reservations
	// reservations 将账户地址映射到预留给它的子池。
	reserveLock sync.Mutex // Lock protecting the account reservations
	// reserveLock 保护账户预留的互斥锁。

	subs event.SubscriptionScope // Subscription scope to unsubscribe all on shutdown
	// subs 用于在关闭时取消所有订阅的订阅范围。
	quit chan chan error // Quit channel to tear down the head updater
	// quit 用于关闭头部更新器的退出通道。
	term chan struct{} // Termination channel to detect a closed pool
	// term 用于检测池是否已关闭的终止通道。

	sync chan chan error // Testing / simulator channel to block until internal reset is done
	// sync 测试/模拟器通道，用于阻塞直到内部重置完成。
}

// New creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
// New 创建一个新的交易池，用于收集、排序和过滤来自网络的入站交易。
func New(gasTip uint64, chain BlockChain, subpools []SubPool) (*TxPool, error) {
	// Retrieve the current head so that all subpools and this main coordinator
	// pool will have the same starting state, even if the chain moves forward
	// during initialization.
	// 检索当前头部区块，以便所有子池和这个主协调池都具有相同的起始状态，即使在初始化期间链向前移动也是如此。
	head := chain.CurrentBlock()

	pool := &TxPool{
		subpools:     subpools,
		reservations: make(map[common.Address]SubPool),
		quit:         make(chan chan error),
		term:         make(chan struct{}),
		sync:         make(chan chan error),
	}
	for i, subpool := range subpools {
		if err := subpool.Init(gasTip, head, pool.reserver(i, subpool)); err != nil {
			for j := i - 1; j >= 0; j-- {
				subpools[j].Close()
			}
			return nil, err
		}
	}
	go pool.loop(head, chain) // Start the main event loop of the transaction pool.
	// 启动交易池的主事件循环。
	return pool, nil
}

// reserver is a method to create an address reservation callback to exclusively
// assign/deassign addresses to/from subpools. This can ensure that at any point
// in time, only a single subpool is able to manage an account, avoiding cross
// subpool eviction issues and nonce conflicts.
// reserver 是一个创建地址预留回调的方法，用于将地址独占地分配给或从子池中取消分配。
// 这可以确保在任何时间点，只有一个子池能够管理一个账户，从而避免跨子池的驱逐问题和 Nonce 冲突。
func (p *TxPool) reserver(id int, subpool SubPool) AddressReserver {
	return func(addr common.Address, reserve bool) error {
		p.reserveLock.Lock()
		defer p.reserveLock.Unlock()

		owner, exists := p.reservations[addr]
		if reserve {
			// Double reservations are forbidden even from the same pool to
			// avoid subtle bugs in the long term.
			// 即使来自同一个池，也不允许重复预留，以避免长期的潜在错误。
			if exists {
				if owner == subpool {
					log.Error("pool attempted to reserve already-owned address", "address", addr)
					return nil // Ignore fault to give the pool a chance to recover while the bug gets fixed
					// 忽略错误，以便在修复错误的同时给池一个恢复的机会。
				}
				return ErrAlreadyReserved
			}
			p.reservations[addr] = subpool
			if metrics.Enabled() {
				m := fmt.Sprintf("%s/%d", reservationsGaugeName, id)
				metrics.GetOrRegisterGauge(m, nil).Inc(1)
			}
			return nil
		}
		// Ensure subpools only attempt to unreserve their own owned addresses,
		// otherwise flag as a programming error.
		// 确保子池只尝试取消预留它们自己拥有的地址，否则标记为编程错误。
		if !exists {
			log.Error("pool attempted to unreserve non-reserved address", "address", addr)
			return errors.New("address not reserved")
		}
		if subpool != owner {
			log.Error("pool attempted to unreserve non-owned address", "address", addr)
			return errors.New("address not owned")
		}
		delete(p.reservations, addr)
		if metrics.Enabled() {
			m := fmt.Sprintf("%s/%d", reservationsGaugeName, id)
			metrics.GetOrRegisterGauge(m, nil).Dec(1)
		}
		return nil
	}
}

// Close terminates the transaction pool and all its subpools.
// Close 终止交易池及其所有子池。
func (p *TxPool) Close() error {
	var errs []error

	// Terminate the reset loop and wait for it to finish
	// 终止重置循环并等待其完成。
	errc := make(chan error)
	p.quit <- errc
	if err := <-errc; err != nil {
		errs = append(errs, err)
	}
	// Terminate each subpool
	// 终止每个子池。
	for _, subpool := range p.subpools {
		if err := subpool.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	// Unsubscribe anyone still listening for tx events
	// 取消订阅所有仍在监听交易事件的订阅者。
	p.subs.Close()

	if len(errs) > 0 {
		return fmt.Errorf("subpool close errors: %v", errs)
	}
	return nil
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
// loop 是交易池的主事件循环，等待并响应外部区块链事件以及各种报告和交易驱逐事件。
func (p *TxPool) loop(head *types.Header, chain BlockChain) {
	// Close the termination marker when the pool stops
	// 当池停止时，关闭终止标记。
	defer close(p.term)

	// Subscribe to chain head events to trigger subpool resets
	// 订阅链头部事件以触发子池重置。
	var (
		newHeadCh  = make(chan core.ChainHeadEvent)
		newHeadSub = chain.SubscribeChainHeadEvent(newHeadCh)
	)
	defer newHeadSub.Unsubscribe()

	// Track the previous and current head to feed to an idle reset
	// 跟踪前一个和当前的头部，以便在空闲时进行重置。
	var (
		oldHead = head
		newHead = oldHead
	)
	// Consume chain head events and start resets when none is running
	// 消费链头部事件，并在没有正在运行的重置时启动重置。
	var (
		resetBusy = make(chan struct{}, 1) // Allow 1 reset to run concurrently
		// 允许并发运行 1 个重置操作。
		resetDone = make(chan *types.Header)

		resetForced bool // Whether a forced reset was requested, only used in simulator mode
		// 是否请求了强制重置，仅在模拟器模式下使用。
		resetWaiter chan error // Channel waiting on a forced reset, only used in simulator mode
		// 等待强制重置的通道，仅在模拟器模式下使用。
	)
	// Notify the live reset waiter to not block if the txpool is closed.
	// 如果交易池已关闭，通知活动的重置等待者不要阻塞。
	defer func() {
		if resetWaiter != nil {
			resetWaiter <- errors.New("pool already terminated")
			resetWaiter = nil
		}
	}()
	var errc chan error
	for errc == nil {
		// Something interesting might have happened, run a reset if there is
		// one needed but none is running. The resetter will run on its own
		// goroutine to allow chain head events to be consumed contiguously.
		// 可能发生了一些有趣的事情，如果需要重置但没有正在运行的重置，则运行重置。
		// 重置器将在其自己的 goroutine 上运行，以允许连续消费链头部事件。
		if newHead != oldHead || resetForced {
			// Try to inject a busy marker and start a reset if successful
			// 尝试注入繁忙标记，如果成功则启动重置。
			select {
			case resetBusy <- struct{}{}:
				// Busy marker injected, start a new subpool reset
				// 繁忙标记已注入，启动新的子池重置。
				go func(oldHead, newHead *types.Header) {
					for _, subpool := range p.subpools {
						subpool.Reset(oldHead, newHead)
					}
					resetDone <- newHead
				}(oldHead, newHead)

				// If the reset operation was explicitly requested, consider it
				// being fulfilled and drop the request marker. If it was not,
				// this is a noop.
				// 如果显式请求了重置操作，则认为它已完成并删除请求标记。如果不是，则这是一个空操作。
				resetForced = false

			default:
				// Reset already running, wait until it finishes.
				//
				// Note, this will not drop any forced reset request. If a forced
				// reset was requested, but we were busy, then when the currently
				// running reset finishes, a new one will be spun up.
				// 重置已在运行，等待其完成。
				//
				// 注意，这不会删除任何强制重置请求。如果请求了强制重置，但我们正忙，
				// 那么当当前正在运行的重置完成时，将启动一个新的重置。
			}
		}
		// Wait for the next chain head event or a previous reset finish
		// 等待下一个链头部事件或上一个重置完成。
		select {
		case event := <-newHeadCh:
			// Chain moved forward, store the head for later consumption
			// 链向前移动，存储头部以供以后使用。
			newHead = event.Header

		case head := <-resetDone:
			// Previous reset finished, update the old head and allow a new reset
			// 上一个重置完成，更新旧的头部并允许新的重置。
			oldHead = head
			<-resetBusy

			// If someone is waiting for a reset to finish, notify them, unless
			// the forced op is still pending. In that case, wait another round
			// of resets.
			// 如果有人正在等待重置完成，则通知他们，除非强制操作仍在挂起。
			// 在这种情况下，等待另一轮重置。
			if resetWaiter != nil && !resetForced {
				resetWaiter <- nil
				resetWaiter = nil
			}

		case errc = <-p.quit:
			// Termination requested, break out on the next loop round
			// 请求终止，在下一个循环中跳出。

		case syncc := <-p.sync:
			// Transaction pool is running inside a simulator, and we are about
			// to create a new block. Request a forced sync operation to ensure
			// that any running reset operation finishes to make block imports
			// deterministic. On top of that, run a new reset operation to make
			// transaction insertions deterministic instead of being stuck in a
			// queue waiting for a reset.
			// 交易池在模拟器中运行，我们即将创建一个新区块。请求强制同步操作以确保任何正在运行的重置操作完成，
			// 以使区块导入具有确定性。最重要的是，运行一个新的重置操作以使交易插入具有确定性，
			// 而不是卡在队列中等待重置。
			resetForced = true
			resetWaiter = syncc
		}
	}
	// todo who receive the channel?
	// Notify the closer of termination (no error possible for now)
	errc <- nil
}

// SetGasTip updates the minimum gas tip required by the transaction pool for a
// new transaction, and drops all transactions below this threshold.
// SetGasTip 更新交易池对新交易所需的最低 Gas 费小费，并删除所有低于此阈值的交易。
func (p *TxPool) SetGasTip(tip *big.Int) {
	for _, subpool := range p.subpools {
		subpool.SetGasTip(tip)
	}
}

// Has returns an indicator whether the pool has a transaction cached with the
// given hash.
// Has 返回一个指示器，表示池是否缓存了具有给定哈希的交易。
func (p *TxPool) Has(hash common.Hash) bool {
	for _, subpool := range p.subpools {
		if subpool.Has(hash) {
			return true
		}
	}
	return false
}

// Get returns a transaction if it is contained in the pool, or nil otherwise.
// Get 如果池中包含具有给定哈希的交易，则返回该交易，否则返回 nil。
func (p *TxPool) Get(hash common.Hash) *types.Transaction {
	for _, subpool := range p.subpools {
		if tx := subpool.Get(hash); tx != nil {
			return tx
		}
	}
	return nil
}

// GetBlobs returns a number of blobs are proofs for the given versioned hashes.
// This is a utility method for the engine API, enabling consensus clients to
// retrieve blobs from the pools directly instead of the network.
// GetBlobs 返回给定版本化哈希的若干 Blob 和证明。
// 这是一个引擎 API 的实用方法，使共识客户端能够直接从池中检索 Blob，而不是通过网络。
func (p *TxPool) GetBlobs(vhashes []common.Hash) ([]*kzg4844.Blob, []*kzg4844.Proof) {
	for _, subpool := range p.subpools {
		// It's an ugly to assume that only one pool will be capable of returning
		// anything meaningful for this call, but anythingh else requires merging
		// partial responses and that's too annoying to do until we get a second
		// blobpool (probably never).
		// 假设只有一个池能够为此调用返回任何有意义的内容是很糟糕的，但其他任何操作都需要合并部分响应，
		// 这太麻烦了，直到我们有第二个 Blob 池（可能永远不会有）之前都不会这样做。
		if blobs, proofs := subpool.GetBlobs(vhashes); blobs != nil {
			return blobs, proofs
		}
	}
	return nil, nil
}

// Add enqueues a batch of transactions into the pool if they are valid. Due
// to the large transaction churn, add may postpone fully integrating the tx
// to a later point to batch multiple ones together.
// Add 如果一批交易有效，则将其加入到池的队列中。由于大量的交易变动，add 可能会推迟完全集成交易到稍后的某个时间，以便将多个交易批量处理。
func (p *TxPool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	// Split the input transactions between the subpools. It shouldn't really
	// happen that we receive merged batches, but better graceful than strange
	// errors.
	//
	// We also need to track how the transactions were split across the subpools,
	// so we can piece back the returned errors into the original order.
	// 将输入的交易拆分到各个子池中。我们实际上不应该接收到合并的批次，但优雅处理总比出现奇怪的错误要好。
	//
	// 我们还需要跟踪交易是如何在各个子池之间拆分的，这样我们就可以将返回的错误重新组合成原始顺序。
	txsets := make([][]*types.Transaction, len(p.subpools))
	splits := make([]int, len(txs))

	for i, tx := range txs {
		// Mark this transaction belonging to no-subpool
		// 标记此交易属于哪个子池（初始标记为无子池）。
		splits[i] = -1

		// Try to find a subpool that accepts the transaction
		// 尝试找到一个接受该交易的子池。
		for j, subpool := range p.subpools {
			if subpool.Filter(tx) {
				txsets[j] = append(txsets[j], tx)
				splits[i] = j
				break
			}
		}
	}
	// Add the transactions split apart to the individual subpools and piece
	// back the errors into the original sort order.
	// 将拆分后的交易添加到各个子池中，并将错误重新组合成原始排序顺序。
	errsets := make([][]error, len(p.subpools))
	for i := 0; i < len(p.subpools); i++ {
		errsets[i] = p.subpools[i].Add(txsets[i], local, sync)
	}
	errs := make([]error, len(txs))
	for i, split := range splits {
		// If the transaction was rejected by all subpools, mark it unsupported
		// 如果交易被所有子池拒绝，则标记为不支持。
		if split == -1 {
			errs[i] = fmt.Errorf("%w: received type %d", core.ErrTxTypeNotSupported, txs[i].Type())
			continue
		}
		// Find which subpool handled it and pull in the corresponding error
		// 找到处理该交易的子池，并获取相应的错误。
		errs[i] = errsets[split][0]
		errsets[split] = errsets[split][1:]
	}
	return errs
}

// Pending retrieves all currently processable transactions, grouped by origin
// account and sorted by nonce.
//
// The transactions can also be pre-filtered by the dynamic fee components to
// reduce allocations and load on downstream subsystems.
// Pending 检索所有当前可处理的交易，按来源账户分组并按 Nonce 排序。
//
// 交易也可以通过动态费用组件进行预先过滤，以减少下游子系统的分配和负载。
func (p *TxPool) Pending(filter PendingFilter) map[common.Address][]*LazyTransaction {
	txs := make(map[common.Address][]*LazyTransaction)
	for _, subpool := range p.subpools {
		for addr, set := range subpool.Pending(filter) {
			txs[addr] = set
		}
	}
	return txs
}

// SubscribeTransactions registers a subscription for new transaction events,
// supporting feeding only newly seen or also resurrected transactions.
// SubscribeTransactions 注册一个新交易事件的订阅，支持仅提供新看到的交易或也包括重新出现的交易。
func (p *TxPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	subs := make([]event.Subscription, len(p.subpools))
	for i, subpool := range p.subpools {
		subs[i] = subpool.SubscribeTransactions(ch, reorgs)
	}
	return p.subs.Track(event.JoinSubscriptions(subs...))
}

// Nonce returns the next nonce of an account, with all transactions executable
// by the pool already applied on top.
// Nonce 返回一个账户的下一个 Nonce，其中池中所有可执行的交易都已应用。
func (p *TxPool) Nonce(addr common.Address) uint64 {
	// Since (for now) accounts are unique to subpools, only one pool will have
	// (at max) a non-state nonce. To avoid stateful lookups, just return the
	// highest nonce for now.
	// 由于（目前）账户对于子池是唯一的，只有一个池（最多）会有一个非状态 Nonce。
	// 为了避免状态查找，现在只返回最高的 Nonce。
	var nonce uint64
	for _, subpool := range p.subpools {
		if next := subpool.Nonce(addr); nonce < next {
			nonce = next
		}
	}
	return nonce
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
// Stats 检索当前池的统计信息，即待处理（可执行）交易的数量和排队（不可执行）交易的数量。
func (p *TxPool) Stats() (int, int) {
	var runnable, blocked int
	for _, subpool := range p.subpools {
		run, block := subpool.Stats()

		runnable += run
		blocked += block
	}
	return runnable, blocked
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
// Content 检索交易池的数据内容，返回所有待处理和排队的交易，按账户分组并按 Nonce 排序。
func (p *TxPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	var (
		runnable = make(map[common.Address][]*types.Transaction)
		blocked  = make(map[common.Address][]*types.Transaction)
	)
	for _, subpool := range p.subpools {
		run, block := subpool.Content()

		for addr, txs := range run {
			runnable[addr] = txs
		}
		for addr, txs := range block {
			blocked[addr] = txs
		}
	}
	return runnable, blocked
}

// ContentFrom retrieves the data content of the transaction pool, returning the
// pending as well as queued transactions of this address, grouped by nonce.
// ContentFrom 检索交易池的数据内容，返回此地址的待处理和排队的交易，按 Nonce 分组。
func (p *TxPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	for _, subpool := range p.subpools {
		run, block := subpool.ContentFrom(addr)
		if len(run) != 0 || len(block) != 0 {
			return run, block
		}
	}
	return []*types.Transaction{}, []*types.Transaction{}
}

// Locals retrieves the accounts currently considered local by the pool.
// Locals 检索池中当前被认为是本地的账户。
func (p *TxPool) Locals() []common.Address {
	// Retrieve the locals from each subpool and deduplicate them
	// 从每个子池检索本地账户并去重。
	locals := make(map[common.Address]struct{})
	for _, subpool := range p.subpools {
		for _, local := range subpool.Locals() {
			locals[local] = struct{}{}
		}
	}
	// Flatten and return the deduplicated local set
	// 扁平化并返回去重后的本地账户集合。
	flat := make([]common.Address, 0, len(locals))
	for local := range locals {
		flat = append(flat, local)
	}
	return flat
}

// Status returns the known status (unknown/pending/queued) of a transaction
// identified by its hash.
// Status 返回由其哈希标识的交易的已知状态（未知/待处理/排队）。
func (p *TxPool) Status(hash common.Hash) TxStatus {
	for _, subpool := range p.subpools {
		if status := subpool.Status(hash); status != TxStatusUnknown {
			return status
		}
	}
	return TxStatusUnknown
}

// Sync is a helper method for unit tests or simulator runs where the chain events
// are arriving in quick succession, without any time in between them to run the
// internal background reset operations. This method will run an explicit reset
// operation to ensure the pool stabilises, thus avoiding flakey behavior.
//
// Note, do not use this in production / live code. In live code, the pool is
// meant to reset on a separate thread to avoid DoS vectors.
// Sync 是一个用于单元测试或模拟器运行的辅助方法，在这些场景中，链事件快速连续到达，之间没有时间运行内部后台重置操作。
// 此方法将运行显式重置操作以确保池稳定，从而避免不稳定的行为。
//
// 注意：不要在生产/线上代码中使用此方法。在生产代码中，池应该在单独的线程上重置，以避免拒绝服务攻击。
func (p *TxPool) Sync() error {
	sync := make(chan error)
	select {
	case p.sync <- sync:
		return <-sync
	case <-p.term:
		return errors.New("pool already terminated")
	}
}

// Clear removes all tracked txs from the subpools.
// Clear 从所有子池中移除所有跟踪的交易。
func (p *TxPool) Clear() {
	for _, subpool := range p.subpools {
		subpool.Clear()
	}
}
