// Copyright 2014 The go-ethereum Authors
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

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
	"golang.org/x/sync/errgroup"
)

// 以太坊白皮书中的状态概念
// 以太坊白皮书（Vitalik Buterin, 2013）提出，区块链是一个“状态机”，每个区块通过交易更新全局状态。StateDB 是 go-ethereum 中对状态机的实现，负责管理账户余额、nonce、代码和存储等状态。
// stateObjects 和 stateObjectsDestruct 映射分别追踪“活动”和“已销毁”账户，反映了白皮书中状态变更的动态性。SelfDestruct 方法实现了账户的自毁逻辑，符合白皮书中“账户可以被销毁”的描述。
// 黄皮书中的状态 Trie 和数据结构
// 黄皮书（Ethereum Yellow Paper）定义了状态 Trie（State Trie）作为全局状态的存储结构，账户数据通过 Merkle Patricia Trie 组织。StateDB 中的 trie 字段直接操作这个 Trie，updateStateObject 和 deleteStateObject 方法分别将账户数据写入或删除。
// 黄皮书中账户包含四个字段：nonce、balance、storageRoot 和 codeHash，这些字段通过 stateObject（未在此代码中展示，但被 StateDB 引用）管理，GetNonce、GetBalance 等方法实现了对这些字段的访问。
// originalRoot 字段记录初始状态根哈希，符合黄皮书中“状态根”是区块头的一部分的要求。
// 相关 EIP（以太坊改进提案）
// EIP-161（状态清理）：定义了“空账户”（balance = nonce = code = 0），Empty 方法实现了这一规范，用于判断账户是否为空。
// EIP-2929（Gas 成本调整）：引入了访问列表（accessList），用于优化 Gas 成本计算，StateDB 中的 accessList 字段支持这一功能。
// EIP-1153（临时存储）：引入了临时存储（transientStorage），用于在交易内存储临时数据，SetTransientState 和 GetTransientState 方法实现了这一特性。
// EIP-6780（自毁改进）：限制了自毁（SELFDESTRUCT）操作的影响，SelfDestruct6780 方法根据新合约标志（newContract）处理自毁逻辑，确保仅在同一交易内创建的合约可以被销毁。
// 算法与实现细节
// Merkle Trie 操作：StateDB 使用 trie（Trie 接口）操作状态 Trie，updateStateObject 调用 UpdateAccount 将账户数据编码并写入 Trie，体现了 Merkle Trie 的增量更新特性。
// 预取优化（Prefetching）：StartPrefetcher 和 newTriePrefetcher 实现了状态数据的并发预取，减少提交阶段的磁盘 I/O，提高性能。这是对以太坊性能优化的实践体现。
// 日志与回滚（Journaling）：journal 字段记录状态变更（如余额、日志、临时存储等），支持快照和回滚功能，Copy 方法的深度复制确保状态独立性，符合状态机的“可逆性”要求。
// 无状态客户端支持：witness 字段用于收集状态见证数据，支持无状态客户端（Stateless Ethereum），这是以太坊未来发展的方向。

// TriesInMemory represents the number of layers that are kept in RAM.
// TriesInMemory 表示保存在内存中的层数。
const TriesInMemory = 128

type mutationType int

const (
	update   mutationType = iota // 更新操作类型
	deletion                     // 删除操作类型
)

type mutation struct {
	typ     mutationType // 操作类型（更新或删除）
	applied bool         // 是否已应用该操作
}

// copy 创建并返回 mutation 的副本
func (m *mutation) copy() *mutation {
	return &mutation{typ: m.typ, applied: m.applied} // 返回一个新的 mutation 实例，复制原有的 typ 和 applied 字段
	// 通过结构体字面量创建副本并返回指针
}

// isDelete 判断该操作是否为删除操作
func (m *mutation) isDelete() bool {
	return m.typ == deletion // 返回布尔值，判断 typ 是否等于 deletion
	// 检查 mutation 的类型是否表示删除操作
}

// StateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
//
// * Contracts
// * Accounts
//
// Once the state is committed, tries cached in stateDB (including account
// trie, storage tries) will no longer be functional. A new state instance
// must be created with new root and updated database for accessing post-
// commit states.
// StateDB 结构在以太坊协议中用于存储 Merkle Trie 中的任何内容。
// StateDB 负责缓存和存储嵌套状态。它是检索以下内容的通用查询接口：
// * 合约
// * 账户
//
// 一旦状态被提交，StateDB 中缓存的 Trie（包括账户 Trie 和存储 Trie）将不再可用。
// 必须使用新的根哈希和更新的数据库创建一个新的状态实例，以访问提交后的状态。
type StateDB struct {
	db         Database        // 底层数据库接口，用于访问 Trie 数据
	prefetcher *triePrefetcher // Trie 预取器，用于并发加载状态数据
	trie       Trie            // 当前状态的 Merkle Trie
	reader     Reader          // 用于从数据库读取状态的只读接口

	// originalRoot is the pre-state root, before any changes were made.
	// It will be updated when the Commit is called.
	// originalRoot 是状态更改前的原始根哈希。
	// 它将在调用 Commit 时更新。
	originalRoot common.Hash // 原始状态根哈希，在提交前保持不变

	// This map holds 'live' objects, which will get modified while
	// processing a state transition.
	// 这个映射保存“活动”对象，这些对象在处理状态转换时会被修改。
	stateObjects map[common.Address]*stateObject // 存储当前活动的账户状态对象

	// This map holds 'deleted' objects. An object with the same address
	// might also occur in the 'stateObjects' map due to account
	// resurrection. The account value is tracked as the original value
	// before the transition. This map is populated at the transaction
	// boundaries.
	// 这个映射保存“已删除”对象。由于账户复活，同一地址的对象可能也会出现在 'stateObjects' 映射中。
	// 账户值被追踪为转换前的原始值。此映射在交易边界时填充。
	stateObjectsDestruct map[common.Address]*stateObject // 存储在当前交易中被标记为删除的账户状态对象

	// This map tracks the account mutations that occurred during the
	// transition. Uncommitted mutations belonging to the same account
	// can be merged into a single one which is equivalent from database's
	// perspective. This map is populated at the transaction boundaries.
	// 这个映射追踪在转换期间发生的账户变更。
	// 属于同一账户的未提交变更可以合并为一个等效的变更，从数据库的角度来看。
	// 此映射在交易边界时填充。
	mutations map[common.Address]*mutation // 记录账户的变更类型（如更新或删除）

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be
	// returned by StateDB.Commit. Notably, this error is also shared
	// by all cached state objects in case the database failure occurs
	// when accessing state of accounts.
	// 数据库错误。
	// 状态对象被共识核心和虚拟机使用，它们无法处理数据库级别的错误。
	// 在数据库读取期间发生的任何错误都会被记录在此，并最终由 StateDB.Commit 返回。
	// 值得注意的是，如果在访问账户状态时发生数据库故障，此错误也会被所有缓存的状态对象共享。
	dbErr error // 记录数据库操作中发生的错误

	// The refund counter, also used by state transitioning.
	// 退款计数器，也用于状态转换。
	refund uint64 // 退款计数器，用于追踪退还的 gas

	// The tx context and all occurred logs in the scope of transaction.
	// 交易上下文和交易范围内发生的所有日志。
	thash   common.Hash                  // 当前交易的哈希
	txIndex int                          // 当前交易的索引
	logs    map[common.Hash][]*types.Log // 存储交易日志，按交易哈希分组
	logSize uint                         // 日志总数

	// Preimages occurred seen by VM in the scope of block.
	// 虚拟机在区块范围内看到的预镜像。
	preimages map[common.Hash][]byte // 存储 SHA3 预镜像

	// Per-transaction access list
	// 每个交易的访问列表
	accessList   *accessList   // 交易的访问列表，用于 EIP-2929
	accessEvents *AccessEvents // 访问事件，用于追踪状态访问

	// Transient storage
	// 临时存储
	transientStorage transientStorage // 临时存储，用于 EIP-1153

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	// 状态修改的日志。这是快照和恢复快照的核心。
	journal *journal // 日志对象，用于记录状态变更以支持回滚

	// State witness if cross validation is needed
	// 如果需要交叉验证，则记录状态见证数据
	witness *stateless.Witness // 无状态客户端的见证数据

	// Measurements gathered during execution for debugging purposes
	// 执行期间收集的测量数据，用于调试目的
	AccountReads    time.Duration // 账户读取耗时
	AccountHashes   time.Duration // 账户哈希计算耗时
	AccountUpdates  time.Duration // 账户更新耗时
	AccountCommits  time.Duration // 账户提交耗时
	StorageReads    time.Duration // 存储读取耗时
	StorageUpdates  time.Duration // 存储更新耗时
	StorageCommits  time.Duration // 存储提交耗时
	SnapshotCommits time.Duration // 快照提交耗时
	TrieDBCommits   time.Duration // Trie 数据库提交耗时

	AccountLoaded  int          // Number of accounts retrieved from the database during the state transition 在状态转换期间从数据库检索的账户数
	AccountUpdated int          // Number of accounts updated during the state transition 在状态转换期间更新的账户数
	AccountDeleted int          // Number of accounts deleted during the state transition 在状态转换期间删除的账户数
	StorageLoaded  int          // Number of storage slots retrieved from the database during the state transition 在状态转换期间从数据库检索的存储槽数
	StorageUpdated atomic.Int64 // Number of storage slots updated during the state transition 在状态转换期间更新的存储槽数
	StorageDeleted atomic.Int64 // Number of storage slots deleted during the state transition 在状态转换期间删除的存储槽数
}

// New creates a new state from a given trie.
// New 从给定的 Trie 创建一个新的状态。
func New(root common.Hash, db Database) (*StateDB, error) {
	tr, err := db.OpenTrie(root) // 打开指定根哈希的 Trie
	if err != nil {              // 如果打开 Trie 失败，返回错误
		return nil, err
	}
	reader, err := db.Reader(root) // 创建指定根哈希的只读接口
	if err != nil {                // 如果创建只读接口失败，返回错误
		return nil, err
	}
	sdb := &StateDB{ // 初始化 StateDB 实例
		db:                   db,                                    // 设置底层数据库
		trie:                 tr,                                    // 设置当前 Trie
		originalRoot:         root,                                  // 设置原始根哈希
		reader:               reader,                                // 设置只读接口
		stateObjects:         make(map[common.Address]*stateObject), // 初始化活动状态对象映射
		stateObjectsDestruct: make(map[common.Address]*stateObject), // 初始化已删除状态对象映射
		mutations:            make(map[common.Address]*mutation),    // 初始化变更映射
		logs:                 make(map[common.Hash][]*types.Log),    // 初始化日志映射
		preimages:            make(map[common.Hash][]byte),          // 初始化预镜像映射
		journal:              newJournal(),                          // 创建新的日志对象
		accessList:           newAccessList(),                       // 创建新的访问列表
		transientStorage:     newTransientStorage(),                 // 创建新的临时存储
	}
	if db.TrieDB().IsVerkle() { // 如果使用 Verkle Trie，则初始化访问事件
		sdb.accessEvents = NewAccessEvents(db.PointCache())
	}
	return sdb, nil // 返回初始化后的 StateDB 实例和 nil 错误
}

// StartPrefetcher initializes a new trie prefetcher to pull in nodes from the
// state trie concurrently while the state is mutated so that when we reach the
// commit phase, most of the needed data is already hot.
// StartPrefetcher 初始化一个新的 Trie 预取器，以便在状态变更时并发拉取状态 Trie 中的节点，
// 以便在提交阶段时，大多数所需数据已经是热的（已缓存）。
func (s *StateDB) StartPrefetcher(namespace string, witness *stateless.Witness) {
	// Terminate any previously running prefetcher
	// 终止任何先前运行的预取器
	s.StopPrefetcher()

	// Enable witness collection if requested
	// 如果请求了，则启用见证数据收集
	s.witness = witness

	// With the switch to the Proof-of-Stake consensus algorithm, block production
	// rewards are now Rainled at the consensus layer. Consequently, a block may
	// have no state transitions if it contains no transactions and no withdrawals.
	// In such cases, the account trie won't be scheduled for prefetching, leading
	// to unnecessary error logs.
	//
	// To prevent this, the account trie is always scheduled for prefetching once
	// the prefetcher is constructed. For more details, see:
	// https://github.com/ethereum/go-ethereum/issues/29880
	// 随着向权益证明共识算法的切换，区块生产奖励现在在共识层处理。
	// 因此，如果一个区块不包含交易和提款，则可能没有状态转换。
	// 在这种情况下，账户 Trie 不会被调度进行预取，导致不必要的错误日志。
	//
	// 为防止这种情况，一旦预取器构建完成，账户 Trie 总是会被调度进行预取。
	// 更多详情见：https://github.com/ethereum/go-ethereum/issues/29880
	s.prefetcher = newTriePrefetcher(s.db, s.originalRoot, namespace, witness == nil)                               // 创建新的预取器实例
	if err := s.prefetcher.prefetch(common.Hash{}, s.originalRoot, common.Address{}, nil, nil, false); err != nil { // 预取账户 Trie
		log.Error("Failed to prefetch account trie", "root", s.originalRoot, "err", err) // 如果预取失败，记录错误日志
	}
}

// StopPrefetcher terminates a running prefetcher and reports any leftover stats
// from the gathered metrics.
// StopPrefetcher 终止运行中的预取器，并报告从收集的指标中剩余的任何统计数据。
func (s *StateDB) StopPrefetcher() {
	if s.prefetcher != nil { // 如果存在预取器
		s.prefetcher.terminate(false) // 终止预取器运行
		s.prefetcher.report()         // 报告预取器的统计数据
		s.prefetcher = nil            // 清空预取器指针
	}
}

// setError remembers the first non-nil error it is called with.
// setError 记录第一次调用时传入的非 nil 错误。
func (s *StateDB) setError(err error) {
	if s.dbErr == nil { // 如果当前没有记录错误
		s.dbErr = err // 设置错误
	}
}

// Error returns the memorized database failure occurred earlier.
// Error 返回之前记录的数据库故障。
func (s *StateDB) Error() error {
	return s.dbErr // 返回记录的错误
}

func (s *StateDB) AddLog(log *types.Log) { // 添加交易日志
	s.journal.logChange(s.thash) // 记录日志变更到 journal

	log.TxHash = s.thash                           // 设置日志的交易哈希
	log.TxIndex = uint(s.txIndex)                  // 设置日志的交易索引
	log.Index = s.logSize                          // 设置日志的全局索引
	s.logs[s.thash] = append(s.logs[s.thash], log) // 将日志追加到对应交易哈希的日志列表
	s.logSize++                                    // 增加日志总数
}

// GetLogs returns the logs matching the specified transaction hash, and annotates
// them with the given blockNumber and blockHash.
// GetLogs 返回与指定交易哈希匹配的日志，并使用给定的区块编号和区块哈希进行标注。
func (s *StateDB) GetLogs(hash common.Hash, blockNumber uint64, blockHash common.Hash) []*types.Log {
	logs := s.logs[hash]     // 获取指定交易哈希的日志列表
	for _, l := range logs { // 遍历日志列表
		l.BlockNumber = blockNumber // 设置区块编号
		l.BlockHash = blockHash     // 设置区块哈希
	}
	return logs // 返回标注后的日志列表
}

func (s *StateDB) Logs() []*types.Log { // 获取所有日志
	var logs []*types.Log        // 定义日志切片
	for _, lgs := range s.logs { // 遍历所有交易的日志
		logs = append(logs, lgs...) // 将每个交易的日志追加到结果中
	}
	return logs // 返回所有日志
}

// AddPreimage records a SHA3 preimage seen by the VM.
// AddPreimage 记录虚拟机看到的 SHA3 预镜像。
func (s *StateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := s.preimages[hash]; !ok { // 如果该哈希尚未记录
		s.preimages[hash] = slices.Clone(preimage) // 克隆并存储预镜像数据
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
// Preimages 返回已提交的 SHA3 预镜像列表。
func (s *StateDB) Preimages() map[common.Hash][]byte {
	return s.preimages // 返回预镜像映射
}

// AddRefund adds gas to the refund counter
// AddRefund 将 gas 添加到退款计数器
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.refundChange(s.refund) // 记录退款变更到 journal
	s.refund += gas                  // 增加退款计数器的值
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
// SubRefund 从退款计数器中移除 gas。
// 如果退款计数器低于零，此方法将引发 panic
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.refundChange(s.refund) // 记录退款变更到 journal
	if gas > s.refund {              // 如果要减去的 gas 超过当前退款值
		panic(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund)) // 抛出 panic
	}
	s.refund -= gas // 减少退款计数器的值
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for self-destructed accounts.
// Exist 报告给定账户地址在状态中是否存在。
// 值得注意的是，这对于自毁账户也会返回 true。
func (s *StateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil // 检查指定地址的状态对象是否存在
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
// Empty 返回状态对象是否不存在或根据 EIP161 规范为空（余额 = nonce = 代码 = 0）
func (s *StateDB) Empty(addr common.Address) bool {
	so := s.getStateObject(addr)   // 获取指定地址的状态对象
	return so == nil || so.empty() // 返回是否为空（不存在或满足 EIP161 空条件）
}

// GetBalance retrieves the balance from the given address or 0 if object not found
// GetBalance 从给定地址检索余额，如果对象未找到则返回 0
func (s *StateDB) GetBalance(addr common.Address) *uint256.Int {
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.Balance() // 返回账户余额
	}
	return common.U2560 // 如果对象不存在，返回 0
}

// GetNonce retrieves the nonce from the given address or 0 if object not found
// GetNonce 从给定地址检索 nonce，如果对象未找到则返回 0
func (s *StateDB) GetNonce(addr common.Address) uint64 {
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.Nonce() // 返回账户 nonce
	}
	return 0 // 如果对象不存在，返回 0
}

// GetStorageRoot retrieves the storage root from the given address or empty
// if object not found.
// GetStorageRoot 从给定地址检索存储根，如果对象未找到则返回空值
func (s *StateDB) GetStorageRoot(addr common.Address) common.Hash {
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.Root() // 返回存储根哈希
	}
	return common.Hash{} // 如果对象不存在，返回空哈希
}

// TxIndex returns the current transaction index set by SetTxContext.
// TxIndex 返回由 SetTxContext 设置的当前交易索引。
func (s *StateDB) TxIndex() int {
	return s.txIndex // 返回当前交易索引
}

func (s *StateDB) GetCode(addr common.Address) []byte { // 获取账户代码
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		if s.witness != nil { // 如果启用了见证数据收集
			s.witness.AddCode(stateObject.Code()) // 将代码添加到见证数据
		}
		return stateObject.Code() // 返回账户代码
	}
	return nil // 如果对象不存在，返回 nil
}

func (s *StateDB) GetCodeSize(addr common.Address) int { // 获取账户代码大小
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		if s.witness != nil { // 如果启用了见证数据收集
			s.witness.AddCode(stateObject.Code()) // 将代码添加到见证数据
		}
		return stateObject.CodeSize() // 返回代码大小
	}
	return 0 // 如果对象不存在，返回 0
}

func (s *StateDB) GetCodeHash(addr common.Address) common.Hash { // 获取账户代码哈希
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return common.BytesToHash(stateObject.CodeHash()) // 将代码哈希转换为 common.Hash 类型并返回
	}
	return common.Hash{} // 如果对象不存在，返回空哈希
}

// GetState retrieves the value associated with the specific key.
// GetState 检索与特定键关联的值。
func (s *StateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.GetState(hash) // 返回指定键的存储值
	}
	return common.Hash{} // 如果对象不存在，返回空哈希
}

// GetCommittedState retrieves the value associated with the specific key
// without any mutations caused in the current execution.
// GetCommittedState 检索与特定键关联的值，不包括当前执行中引起的任何变更。
func (s *StateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.GetCommittedState(hash) // 返回指定键的已提交存储值
	}
	return common.Hash{} // 如果对象不存在，返回空哈希
}

// Database retrieves the low level database supporting the lower level trie ops.
// Database 检索支持低级 Trie 操作的底层数据库。
func (s *StateDB) Database() Database {
	return s.db // 返回底层数据库接口
}

func (s *StateDB) HasSelfDestructed(addr common.Address) bool { // 检查账户是否已自毁
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject != nil {               // 如果对象存在
		return stateObject.selfDestructed // 返回自毁标记
	}
	return false // 如果对象不存在，返回 false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
// AddBalance 将金额添加到与地址关联的账户。
func (s *StateDB) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	stateObject := s.getOrNewStateObject(addr) // 获取或创建状态对象
	if stateObject == nil {                    // 如果对象不存在
		return uint256.Int{} // 返回空值
	}
	return stateObject.AddBalance(amount) // 增加账户余额并返回结果
}

// SubBalance subtracts amount from the account associated with addr.
// SubBalance 从与地址关联的账户中减去金额。
func (s *StateDB) SubBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	stateObject := s.getOrNewStateObject(addr) // 获取或创建状态对象
	if stateObject == nil {                    // 如果对象不存在
		return uint256.Int{} // 返回空值
	}
	if amount.IsZero() { // 如果减去的金额为 0
		return *(stateObject.Balance()) // 返回当前余额
	}
	return stateObject.SetBalance(new(uint256.Int).Sub(stateObject.Balance(), amount)) // 减去金额并设置新余额，返回结果
}

func (s *StateDB) SetBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) { // 设置账户余额
	stateObject := s.getOrNewStateObject(addr) // 获取或创建状态对象
	if stateObject != nil {                    // 如果对象存在
		stateObject.SetBalance(amount) // 设置账户余额
	}
}

func (s *StateDB) SetNonce(addr common.Address, nonce uint64) { // 设置账户 nonce
	stateObject := s.getOrNewStateObject(addr) // 获取或创建状态对象
	if stateObject != nil {                    // 如果对象存在
		stateObject.SetNonce(nonce) // 设置账户 nonce
	}
}

func (s *StateDB) SetCode(addr common.Address, code []byte) (prev []byte) { // 设置账户代码
	stateObject := s.getOrNewStateObject(addr) // 获取或创建状态对象
	if stateObject != nil {                    // 如果对象存在
		return stateObject.SetCode(crypto.Keccak256Hash(code), code) // 设置代码并返回之前的代码
	}
	return nil // 如果对象不存在，返回 nil
}

func (s *StateDB) SetState(addr common.Address, key, value common.Hash) common.Hash { // 设置存储值
	if stateObject := s.getOrNewStateObject(addr); stateObject != nil {               // 获取或创建状态对象
		return stateObject.SetState(key, value) // 设置存储值并返回之前的存储值
	}
	return common.Hash{} // 如果对象不存在，返回空哈希
}

// SetStorage replaces the entire storage for the specified account with given
// storage. This function should only be used for debugging and the mutations
// must be discarded afterwards.
// SetStorage 用给定的存储替换指定账户的整个存储。此函数仅用于调试，之后的变更必须丢弃。
func (s *StateDB) SetStorage(addr common.Address, storage map[common.Hash]common.Hash) {
	// SetStorage needs to wipe the existing storage. We achieve this by marking
	// the account as self-destructed in this block. The effect is that storage
	// lookups will not hit the disk, as it is assumed that the disk data belongs
	// to a previous incarnation of the object.
	//
	// TODO (rjl493456442): This function should only be supported by 'unwritable'
	// state, and all mutations made should be discarded afterward.
	// SetStorage 需要擦除现有存储。我们通过在此区块中将账户标记为自毁来实现这一点。
	// 其效果是存储查找不会命中磁盘，因为假设磁盘数据属于对象的先前版本。
	//
	// TODO (rjl493456442)：此函数应仅由“不可写”状态支持，并且之后所做的所有变更都应丢弃。
	obj := s.getStateObject(addr) // 获取状态对象
	if obj != nil {               // 如果对象存在
		if _, ok := s.stateObjectsDestruct[addr]; !ok { // 如果账户尚未标记为已销毁
			s.stateObjectsDestruct[addr] = obj // 将其标记为已销毁
		}
	}
	newObj := s.createObject(addr) // 创建新的状态对象
	for k, v := range storage {    // 遍历给定的存储映射
		newObj.SetState(k, v) // 设置每个键值对到新对象
	}
	// Inherit the metadata of original object if it was existent
	// 如果原始对象存在，则继承其元数据
	if obj != nil { // 如果原始对象存在
		newObj.SetCode(common.BytesToHash(obj.CodeHash()), obj.code) // 设置代码
		newObj.SetNonce(obj.Nonce())                                 // 设置 nonce
		newObj.SetBalance(obj.Balance())                             // 设置余额
	}
}

// SelfDestruct marks the given account as selfdestructed.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after SelfDestruct.
// SelfDestruct 将给定账户标记为自毁。
// 这会清除账户余额。
//
// 在状态提交之前，账户的状态对象仍然可用，SelfDestruct 后 getStateObject 将返回非 nil 的账户。
func (s *StateDB) SelfDestruct(addr common.Address) uint256.Int {
	stateObject := s.getStateObject(addr) // 获取状态对象
	var prevBalance uint256.Int           // 定义前余额变量
	if stateObject == nil {               // 如果对象不存在
		return prevBalance // 返回空余额
	}
	prevBalance = *(stateObject.Balance()) // 记录当前余额
	// Regardless of whether it is already destructed or not, we do have to
	// journal the balance-change, if we set it to zero here.
	// 无论账户是否已销毁，如果我们在此将其设置为零，则必须记录余额变更。
	if !stateObject.Balance().IsZero() { // 如果余额不为零
		stateObject.SetBalance(new(uint256.Int)) // 将余额设置为零
	}
	// If it is already marked as self-destructed, we do not need to add it
	// for journalling a second time.
	// 如果账户已被标记为自毁，则无需再次将其添加到日志中。
	if !stateObject.selfDestructed { // 如果尚未标记为自毁
		s.journal.destruct(addr)         // 记录自毁操作到 journal
		stateObject.markSelfdestructed() // 标记账户为自毁
	}
	return prevBalance // 返回之前的余额
}

func (s *StateDB) SelfDestruct6780(addr common.Address) (uint256.Int, bool) { // 根据 EIP-6780 处理自毁
	stateObject := s.getStateObject(addr) // 获取状态对象
	if stateObject == nil {               // 如果对象不存在
		return uint256.Int{}, false // 返回空余额和 false
	}
	if stateObject.newContract { // 如果是新创建的合约
		return s.SelfDestruct(addr), true // 执行自毁并返回 true
	}
	return *(stateObject.Balance()), false // 返回当前余额和 false
}

// SetTransientState sets transient storage for a given account. It
// adds the change to the journal so that it can be rolled back
// to its previous value if there is a revert.
// SetTransientState 为给定账户设置临时存储。
// 它将变更添加到日志中，以便在回滚时可以恢复到之前的值。
func (s *StateDB) SetTransientState(addr common.Address, key, value common.Hash) {
	prev := s.GetTransientState(addr, key) // 获取当前的临时存储值
	if prev == value {                     // 如果新值与旧值相同
		return // 直接返回，不做任何操作
	}
	s.journal.transientStateChange(addr, key, prev) // 记录临时存储变更到 journal
	s.setTransientState(addr, key, value)           // 设置新的临时存储值
}

// setTransientState is a lower level setter for transient storage. It
// is called during a revert to prevent modifications to the journal.
// setTransientState 是临时存储的低级设置器。
// 它在回滚期间被调用，以防止修改日志。
func (s *StateDB) setTransientState(addr common.Address, key, value common.Hash) {
	s.transientStorage.Set(addr, key, value) // 直接设置临时存储值
}

// GetTransientState gets transient storage for a given account.
// GetTransientState 获取给定账户的临时存储。
func (s *StateDB) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	return s.transientStorage.Get(addr, key) // 返回指定地址和键的临时存储值
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
// updateStateObject 将给定对象写入 Trie。
func (s *StateDB) updateStateObject(obj *stateObject) {
	// Encode the account and update the account trie
	// 编码账户并更新账户 Trie
	addr := obj.Address()                                                        // 获取账户地址
	if err := s.trie.UpdateAccount(addr, &obj.data, len(obj.code)); err != nil { // 更新账户到 Trie
		s.setError(fmt.Errorf("updateStateObject (%x) error: %v", addr[:], err)) // 如果出错，记录错误
	}
	if obj.dirtyCode { // 如果代码被修改
		s.trie.UpdateContractCode(obj.Address(), common.BytesToHash(obj.CodeHash()), obj.code) // 更新合约代码
	}
}

// deleteStateObject removes the given object from the state trie.
// deleteStateObject 从状态 Trie 中移除给定对象。
func (s *StateDB) deleteStateObject(addr common.Address) {
	if err := s.trie.DeleteAccount(addr); err != nil { // 从 Trie 中删除账户
		s.setError(fmt.Errorf("deleteStateObject (%x) error: %v", addr[:], err)) // 如果出错，记录错误
	}
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context.
// getStateObject 检索由地址给定的状态对象，如果对象未找到或在此执行上下文中被删除，则返回 nil。
func (s *StateDB) getStateObject(addr common.Address) *stateObject {
	// Prefer live objects if any is available
	// 如果有活动对象，则优先使用
	if obj := s.stateObjects[addr]; obj != nil { // 检查活动对象映射中是否存在
		return obj // 返回活动对象
	}
	// Short circuit if the account is already destructed in this block.
	// 如果账户在此区块中已被销毁，则短路返回
	if _, ok := s.stateObjectsDestruct[addr]; ok { // 检查销毁对象映射中是否存在
		return nil // 返回 nil
	}
	s.AccountLoaded++ // 增加已加载账户计数器

	start := time.Now()                 // 记录开始时间
	acct, err := s.reader.Account(addr) // 从只读接口读取账户数据
	if err != nil {                     // 如果读取出错
		s.setError(fmt.Errorf("getStateObject (%x) error: %w", addr.Bytes(), err)) // 记录错误
		return nil                                                                 // 返回 nil
	}
	s.AccountReads += time.Since(start) // 更新账户读取耗时

	// Short circuit if the account is not found
	// 如果账户未找到，则短路返回
	if acct == nil { // 如果账户数据为空
		return nil // 返回 nil
	}
	// Schedule the resolved account for prefetching if it's enabled.
	// 如果启用了预取，则调度解析的账户进行预取
	if s.prefetcher != nil { // 如果预取器存在
		if err = s.prefetcher.prefetch(common.Hash{}, s.originalRoot, common.Address{}, []common.Address{addr}, nil, true); err != nil { // 预取账户
			log.Error("Failed to prefetch account", "addr", addr, "err", err) // 如果预取失败，记录错误日志
		}
	}
	// Insert into the live set
	// 插入到活动集合中
	obj := newObject(s, addr, acct) // 创建新的状态对象
	s.setStateObject(obj)           // 设置到活动对象映射
	s.AccountLoaded++               // 再次增加已加载账户计数器（可能是统计加载次数）
	return obj                      // 返回状态对象
}

func (s *StateDB) setStateObject(object *stateObject) { // 设置状态对象到活动映射
	s.stateObjects[object.Address()] = object // 将对象存储到活动对象映射中
}

// getOrNewStateObject retrieves a state object or create a new state object if nil.
// getOrNewStateObject 检索状态对象，如果为 nil 则创建新的状态对象。
func (s *StateDB) getOrNewStateObject(addr common.Address) *stateObject {
	obj := s.getStateObject(addr) // 获取状态对象
	if obj == nil {               // 如果对象不存在
		obj = s.createObject(addr) // 创建新对象
	}
	return obj // 返回状态对象
}

// createObject creates a new state object. The assumption is held there is no
// existing account with the given address, otherwise it will be silently overwritten.
// createObject 创建一个新的状态对象。假设给定地址没有现有账户，否则将被默默覆盖。
func (s *StateDB) createObject(addr common.Address) *stateObject {
	obj := newObject(s, addr, nil) // 创建新的状态对象，初始数据为 nil
	s.journal.createObject(addr)   // 记录创建操作到 journal
	s.setStateObject(obj)          // 设置到活动对象映射
	return obj                     // 返回新创建的对象
}

// CreateAccount explicitly creates a new state object, assuming that the
// account did not previously exist in the state. If the account already
// exists, this function will silently overwrite it which might lead to a
// consensus bug eventually.
// CreateAccount 显式创建新的状态对象，假设该账户之前在状态中不存在。
// 如果账户已存在，此函数将默默覆盖它，最终可能导致共识错误。
func (s *StateDB) CreateAccount(addr common.Address) {
	s.createObject(addr) // 创建新账户
}

// CreateContract is used whenever a contract is created. This may be preceded
// by CreateAccount, but that is not required if it already existed in the
// state due to funds sent beforehand.
// This operation sets the 'newContract'-flag, which is required in order to
// correctly handle EIP-6780 'delete-in-same-transaction' logic.
// CreateContract 在创建合约时使用。这可能之前已调用 CreateAccount，
// 但如果账户由于之前发送的资金已存在于状态中，则不需要。
// 此操作设置 'newContract' 标志，这是正确处理 EIP-6780“同一交易内删除”逻辑所需的。
func (s *StateDB) CreateContract(addr common.Address) {
	obj := s.getStateObject(addr) // 获取状态对象
	if !obj.newContract {         // 如果不是新合约
		obj.newContract = true         // 设置新合约标志
		s.journal.createContract(addr) // 记录创建合约操作到 journal
	}
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
// Copy 创建状态的深度、独立副本。
// 复制状态的快照无法应用于副本。
func (s *StateDB) Copy() *StateDB {
	// Copy all the basic fields, initialize the memory ones
	// 复制所有基本字段，初始化内存字段
	reader, _ := s.db.Reader(s.originalRoot) // impossible to fail 创建原始根哈希的只读接口，不可能失败
	state := &StateDB{ // 创建新的 StateDB 实例
		db:                   s.db,                                                               // 复制底层数据库
		trie:                 mustCopyTrie(s.trie),                                               // 深度复制 Trie
		reader:               reader,                                                             // 设置只读接口
		originalRoot:         s.originalRoot,                                                     // 复制原始根哈希
		stateObjects:         make(map[common.Address]*stateObject, len(s.stateObjects)),         // 初始化活动对象映射
		stateObjectsDestruct: make(map[common.Address]*stateObject, len(s.stateObjectsDestruct)), // 初始化销毁对象映射
		mutations:            make(map[common.Address]*mutation, len(s.mutations)),               // 初始化变更映射
		dbErr:                s.dbErr,                                                            // 复制数据库错误
		refund:               s.refund,                                                           // 复制退款计数器
		thash:                s.thash,                                                            // 复制交易哈希
		txIndex:              s.txIndex,                                                          // 复制交易索引
		logs:                 make(map[common.Hash][]*types.Log, len(s.logs)),                    // 初始化日志映射
		logSize:              s.logSize,                                                          // 复制日志大小
		preimages:            maps.Clone(s.preimages),                                            // 克隆预镜像映射

		// Do we need to copy the access list and transient storage?
		// In practice: No. At the start of a transaction, these two lists are empty.
		// In practice, we only ever copy state _between_ transactions/blocks, never
		// in the middle of a transaction. However, it doesn't cost us much to copy
		// empty lists, so we do it anyway to not blow up if we ever decide copy them
		// in the middle of a transaction.
		// 我们需要复制访问列表和临时存储吗？
		// 实际上：不需要。在交易开始时，这两个列表是空的。
		// 实际上，我们只在交易/区块之间复制状态，从不在交易中间。
		// 然而，复制空列表的成本不高，所以我们还是复制了，以防将来决定在交易中间复制时不会出错。
		accessList:       s.accessList.Copy(),       // 复制访问列表
		transientStorage: s.transientStorage.Copy(), // 复制临时存储
		journal:          s.journal.copy(),          // 复制日志对象
	}
	if s.witness != nil { // 如果存在见证数据
		state.witness = s.witness.Copy() // 复制见证数据
	}
	if s.accessEvents != nil { // 如果存在访问事件
		state.accessEvents = s.accessEvents.Copy() // 复制访问事件
	}
	// Deep copy cached state objects.
	// 深度复制缓存的状态对象
	for addr, obj := range s.stateObjects { // 遍历活动对象
		state.stateObjects[addr] = obj.deepCopy(state) // 深度复制并存储到新实例
	}
	// Deep copy destructed state objects.
	// 深度复制销毁的状态对象
	for addr, obj := range s.stateObjectsDestruct { // 遍历销毁对象
		state.stateObjectsDestruct[addr] = obj.deepCopy(state) // 深度复制并存储到新实例
	}
	// Deep copy the object state markers.
	// 深度复制对象状态标记
	for addr, op := range s.mutations { // 遍历变更映射
		state.mutations[addr] = op.copy() // 复制变更并存储到新实例
	}
	// Deep copy the logs occurred in the scope of block
	// 深度复制区块范围内发生的日志
	for hash, logs := range s.logs { // 遍历日志映射
		cpy := make([]*types.Log, len(logs)) // 创建日志副本切片
		for i, l := range logs {             // 遍历每个日志
			cpy[i] = new(types.Log) // 创建新的日志实例
			*cpy[i] = *l            // 复制日志内容
		}
		state.logs[hash] = cpy // 存储日志副本
	}
	return state // 返回新的 StateDB 实例
}

// 以太坊白皮书中的状态管理
// 白皮书（Vitalik Buterin, 2013）将以太坊描述为一个“状态转换系统”，每个交易更新全局状态。Snapshot 和 RevertToSnapshot 方法实现了状态的版本控制，支持回滚到特定修订版本，符合白皮书中“状态可逆”的理念。
// Commit 方法将状态变更写入数据库并更新状态根，体现了白皮书中“状态通过交易更新并持久化”的核心概念。状态根（root）是区块头的一部分，用于验证状态一致性。
// 黄皮书中的状态 Trie 和根哈希
// 黄皮书（Ethereum Yellow Paper）定义了状态 Trie 作为全局状态的存储结构，根哈希通过 IntermediateRoot 和 Commit 计算。IntermediateRoot 在交易间计算临时根哈希，用于交易收据，而 Commit 提交最终状态，更新 originalRoot。
// Finalise 方法清理销毁对象并标记变更，但不直接写入 Trie，符合黄皮书中“状态变更分阶段处理”的逻辑。handleDestruction 处理账户销毁的四种场景，确保状态 Trie 的正确更新。
// 相关 EIP（以太坊改进提案）
// EIP-161（状态清理）：Finalise 中的 deleteEmptyObjects 参数决定是否删除空账户（balance = nonce = code = 0），实现了 EIP-161 的规范。
// EIP-2929（Gas 成本调整）：Prepare 和 AddAddressToAccessList 方法管理访问列表，优化 Gas 成本计算，减少冷访问的开销。
// EIP-2930（可选访问列表）：Prepare 支持交易提供的访问列表（list types.AccessList），允许预声明状态访问。
// EIP-3651（温暖 coinbase）：在上海分叉（rules.IsShanghai）中，Prepare 将 coinbase 添加到访问列表，降低对 coinbase 的访问成本。
// EIP-1153（临时存储）：Prepare 重置 transientStorage，确保交易开始时临时存储为空，符合 EIP-1153 的要求。
// EIP-6780（自毁改进）：handleDestruction 处理销毁和复活逻辑，确保自毁账户的存储被正确清理，遵循 EIP-6780 的限制。

// Snapshot returns an identifier for the current revision of the state.
// Snapshot 返回当前状态修订的标识符。
func (s *StateDB) Snapshot() int {
	return s.journal.snapshot() // 调用 journal 的 snapshot 方法，返回当前状态的快照 ID
	// 生成并返回一个标识符，表示当前状态的版本
}

// RevertToSnapshot reverts all state changes made since the given revision.
// RevertToSnapshot 回滚自给定修订以来所做的所有状态更改。
func (s *StateDB) RevertToSnapshot(revid int) {
	s.journal.revertToSnapshot(revid, s) // 调用 journal 的 revertToSnapshot 方法，回滚到指定修订版本
	// 使用指定的快照 ID 恢复状态，撤销此后的所有变更
}

// GetRefund returns the current value of the refund counter.
// GetRefund 返回退款计数器的当前值。
func (s *StateDB) GetRefund() uint64 {
	return s.refund // 返回当前的退款计数器值
	// 直接返回 StateDB 中的 refund 字段，表示当前可退还的 gas 量
}

// Finalise finalises the state by removing the destructed objects and clears
// the journal as well as the refunds. Finalise, however, will not push any updates
// into the tries just yet. Only IntermediateRoot or Commit will do that.
// Finalise 通过移除已销毁的对象并清除日志和退款来完成状态的最终化。
// 然而，Finalise 不会立即将任何更新推送到 Trie 中，只有 IntermediateRoot 或 Commit 会这样做。
func (s *StateDB) Finalise(deleteEmptyObjects bool) {
	addressesToPrefetch := make([]common.Address, 0, len(s.journal.dirties)) // 创建地址切片，用于预取
	// 初始化一个空的地址列表，用于后续预取操作，容量基于脏对象数量
	for addr := range s.journal.dirties { // 遍历 journal 中的脏对象（已修改的账户）
		obj, exist := s.stateObjects[addr] // 从 stateObjects 中获取状态对象
		if !exist {                        // 如果状态对象不存在
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			// ripeMD 在区块 1714175 的交易 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2 中被“触碰”。
			// 该交易耗尽了 gas，尽管那里不存在“触碰”的概念，但触碰事件仍会记录在日志中。
			// 由于 ripeMD 是一个特殊情况，即使日志被回滚，它仍会保留在日志中。
			// 在这种特殊情况下，它可能存在于 `s.journal.dirties` 中，但不在 `s.stateObjects` 中。
			// 因此，我们可以在这里安全地忽略它。
			continue // 跳过不存在的对象（特殊情况处理，如 ripeMD）
		}
		if obj.selfDestructed || (deleteEmptyObjects && obj.empty()) { // 如果对象已自毁或满足删除空对象的条件
			delete(s.stateObjects, obj.address) // 从 stateObjects 中删除该对象
			s.markDelete(addr)                  // 标记该地址为删除状态
			// We need to maintain account deletions explicitly (will remain
			// set indefinitely). Note only the first occurred self-destruct
			// event is tracked.
			// 我们需要显式地维护账户删除（将无限期保持设置）。
			// 注意，仅跟踪第一次发生的自毁事件。
			if _, ok := s.stateObjectsDestruct[obj.address]; !ok { // 如果该地址尚未在销毁映射中
				s.stateObjectsDestruct[obj.address] = obj // 将其添加到销毁对象映射中
			}
		} else { // 如果对象未被销毁
			obj.finalise()     // 完成该对象的最终化（清理临时数据）
			s.markUpdate(addr) // 标记该地址为更新状态
		}
		// At this point, also ship the address off to the precacher. The precacher
		// will start loading tries, and when the change is eventually committed,
		// the commit-phase will be a lot faster
		// 在这一点上，也将地址发送到预缓存器。预缓存器将开始加载 Trie，
		// 当更改最终提交时，提交阶段将快得多。
		addressesToPrefetch = append(addressesToPrefetch, addr) // Copy needed for closure 将地址添加到预取列表
	}
	if s.prefetcher != nil && len(addressesToPrefetch) > 0 { // 如果预取器存在且有地址需要预取
		if err := s.prefetcher.prefetch(common.Hash{}, s.originalRoot, common.Address{}, addressesToPrefetch, nil, false); err != nil { // 执行预取操作
			log.Error("Failed to prefetch addresses", "addresses", len(addressesToPrefetch), "err", err) // 如果预取失败，记录错误日志
		}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	// 因为不允许跨交易回滚，所以使日志失效。
	s.clearJournalAndRefund() // 清除日志和退款计数器
	// 重置 journal 和 refund 为初始状态
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
// IntermediateRoot 计算状态 Trie 的当前根哈希。
// 它在交易之间被调用，以获取进入交易收据的根哈希。
func (s *StateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	// Finalise all the dirty storage states and write them into the tries
	// 最终化所有脏存储状态并将它们写入 Trie
	s.Finalise(deleteEmptyObjects) // 调用 Finalise 方法，清理状态并标记变更

	// If there was a trie prefetcher operating, terminate it async so that the
	// individual storage tries can be updated as soon as the disk load finishes.
	// 如果有 Trie 预取器在运行，异步终止它，以便在磁盘加载完成后立即更新各个存储 Trie。
	if s.prefetcher != nil { // 如果预取器存在
		s.prefetcher.terminate(true) // 异步终止预取器
		defer func() { // 在函数结束时执行
			s.prefetcher.report() // 报告预取器的统计数据
			s.prefetcher = nil    // Pre-byzantium, unset any used up prefetcher 清空预取器（Pre-byzantium 阶段的处理）
		}()
	}
	// Process all storage updates concurrently. The state object update root
	// method will internally call a blocking trie fetch from the prefetcher,
	// so there's no need to explicitly wait for the prefetchers to finish.
	// 并发处理所有存储更新。状态对象的 updateRoot 方法会在内部调用预取器的阻塞式 Trie 获取，
	// 因此无需显式等待预取器完成。
	var (
		start   = time.Now()   // 记录开始时间
		workers errgroup.Group // 创建并发工作组
	)
	if s.db.TrieDB().IsVerkle() { // 如果使用 Verkle Trie
		// Whilst MPT storage tries are independent, Verkle has one single trie
		// for all the accounts and all the storage slots merged together. The
		// former can thus be simply parallelized, but updating the latter will
		// need concurrency support within the trie itself. That's a TODO for a
		// later time.
		// 虽然 MPT 存储 Trie 是独立的，但 Verkle 将所有账户和存储槽合并到一个单一的 Trie 中。
		// 前者因此可以简单地并行化，但更新后者需要在 Trie 内部支持并发。这是未来的待办事项。
		workers.SetLimit(1) // 设置并发限制为 1（Verkle Trie 不支持并行更新）
	}
	for addr, op := range s.mutations { // 遍历所有变更
		if op.applied || op.isDelete() { // 如果变更已应用或为删除操作
			continue // 跳过
		}
		obj := s.stateObjects[addr] // closure for the task runner below 获取对应的状态对象（闭包使用）
		workers.Go(func() error {         // 并发执行更新任务
			if s.db.TrieDB().IsVerkle() { // 如果是 Verkle Trie
				obj.updateTrie() // 更新 Verkle Trie
			} else { // 如果是 MPT Trie
				obj.updateRoot() // 更新存储根

				// If witness building is enabled and the state object has a trie,
				// gather the witnesses for its specific storage trie
				// 如果启用了见证构建且状态对象有 Trie，则收集其特定存储 Trie 的见证数据
				if s.witness != nil && obj.trie != nil { // 如果启用了见证且 Trie 存在
					s.witness.AddState(obj.trie.Witness()) // 添加存储 Trie 的见证数据
				}
			}
			return nil // 返回 nil 表示无错误
		})
	}
	// If witness building is enabled, gather all the read-only accesses.
	// Skip witness collection in Verkle mode, they will be gathered
	// together at the end.
	// 如果启用了见证构建，收集所有只读访问。
	// 在 Verkle 模式下跳过见证收集，它们将在最后一起收集。
	if s.witness != nil && !s.db.TrieDB().IsVerkle() { // 如果启用了见证且不是 Verkle 模式
		// Pull in anything that has been accessed before destruction
		// 收集所有销毁前访问的内容
		for _, obj := range s.stateObjectsDestruct { // 遍历销毁对象
			// Skip any objects that haven't touched their storage
			// 跳过未触碰存储的对象
			if len(obj.originStorage) == 0 { // 如果原始存储为空
				continue // 跳过
			}
			if trie := obj.getPrefetchedTrie(); trie != nil { // 如果有预取的 Trie
				s.witness.AddState(trie.Witness()) // 添加见证数据
			} else if obj.trie != nil { // 如果有普通 Trie
				s.witness.AddState(obj.trie.Witness()) //添加见证数据
			}
		}
		// Pull in only-read and non-destructed trie witnesses
		// 收集只读且未销毁的 Trie 见证数据
		for _, obj := range s.stateObjects { // 遍历活动对象
			// Skip any objects that have been updated
			// 跳过已更新的对象
			if _, ok := s.mutations[obj.address]; ok { // 如果对象有变更
				continue // 跳过
			}
			// Skip any objects that haven't touched their storage
			// 跳过未触碰存储的对象
			if len(obj.originStorage) == 0 { // 如果原始存储为空
				continue // 跳过
			}
			if trie := obj.getPrefetchedTrie(); trie != nil { // 如果有预取的 Trie
				s.witness.AddState(trie.Witness()) // 添加见证数据
			} else if obj.trie != nil { // 如果有普通 Trie
				s.witness.AddState(obj.trie.Witness()) // 添加见证数据
			}
		}
	}
	workers.Wait()                        // 等待所有并发任务完成
	s.StorageUpdates += time.Since(start) // 更新存储更新耗时

	// Now we're about to start to write changes to the trie. The trie is so far
	// _untouched_. We can check with the prefetcher, if it can give us a trie
	// which has the same root, but also has some content loaded into it.
	//
	// Don't check prefetcher if verkle trie has been used. In the context of verkle,
	// only a single trie is used for state hashing. Replacing a non-nil verkle tree
	// here could result in losing uncommitted changes from storage.
	// 现在我们将开始将更改写入 Trie。目前 Trie 尚未被触碰。
	// 我们可以检查预取器，看它是否能给我们一个具有相同根但已加载部分内容的 Trie。
	//
	// 如果使用了 Verkle Trie，则不检查预取器。在 Verkle 上下文中，仅使用单一 Trie 进行状态哈希。
	// 在此处替换非空的 Verkle 树可能会导致丢失未提交的存储更改。
	start = time.Now()       // 记录开始时间
	if s.prefetcher != nil { // 如果预取器存在
		if trie := s.prefetcher.trie(common.Hash{}, s.originalRoot); trie == nil { // 获取预取的 Trie
			log.Error("Failed to retrieve account pre-fetcher trie") // 如果获取失败，记录错误日志
		} else {
			s.trie = trie // 使用预取的 Trie 替换当前 Trie
		}
	}
	// Perform updates before deletions.  This prevents resolution of unnecessary trie nodes
	// in circumstances similar to the following:
	//
	// Consider nodes `A` and `B` who share the same full node parent `P` and have no other siblings.
	// During the execution of a block:
	// - `A` self-destructs,
	// - `C` is created, and also shares the parent `P`.
	// If the self-destruct is handled first, then `P` would be left with only one child, thus collapsed
	// into a shortnode. This requires `B` to be resolved from disk.
	// Whereas if the created node is handled first, then the collapse is avoided, and `B` is not resolved.
	// 先执行更新再执行删除。这可以防止在类似以下情况中解析不必要的 Trie 节点：
	//
	// 考虑节点 `A` 和 `B`，它们共享同一个完整节点父节点 `P`，且没有其他兄弟节点。
	// 在一个区块的执行期间：
	// - `A` 自毁，
	// - `C` 被创建，并且也共享父节点 `P`。
	// 如果先处理自毁，那么 `P` 将只剩一个子节点，因此会折叠成短节点。这需要从磁盘解析 `B`。
	// 而如果先处理创建的节点，则避免了折叠，`B` 无需解析。
	var (
		usedAddrs    []common.Address // 已使用的地址列表
		deletedAddrs []common.Address // 已删除的地址列表
	)
	for addr, op := range s.mutations { // 遍历所有变更
		if op.applied { // 如果变更已应用
			continue // 跳过
		}
		op.applied = true // 标记为已应用

		if op.isDelete() { // 如果是删除操作
			deletedAddrs = append(deletedAddrs, addr) // 添加到删除列表
		} else { // 如果是更新操作
			s.updateStateObject(s.stateObjects[addr]) // 更新状态对象到 Trie
			s.AccountUpdated += 1                     // 增加更新账户计数器
		}
		usedAddrs = append(usedAddrs, addr) // Copy needed for closure 添加到已使用地址列表
	}
	for _, deletedAddr := range deletedAddrs { // 处理所有删除操作
		s.deleteStateObject(deletedAddr) // 从 Trie 中删除状态对象
		s.AccountDeleted += 1            // 增加删除账户计数器
	}
	s.AccountUpdates += time.Since(start) // 更新账户更新耗时

	if s.prefetcher != nil { // 如果预取器存在
		s.prefetcher.used(common.Hash{}, s.originalRoot, usedAddrs, nil) // 通知预取器已使用的地址
	}
	// Track the amount of time wasted on hashing the account trie
	// 跟踪在账户 Trie 哈希上浪费的时间
	defer func(start time.Time) { s.AccountHashes += time.Since(start) }(time.Now()) // 在函数结束时更新账户哈希耗时

	hash := s.trie.Hash() // 计算并获取当前 Trie 的根哈希

	// If witness building is enabled, gather the account trie witness
	// 如果启用了见证构建，收集账户 Trie 的见证数据
	if s.witness != nil { // 如果启用了见证
		s.witness.AddState(s.trie.Witness()) // 添加账户 Trie 的见证数据
	}
	return hash // 返回计算得到的根哈希
}

// SetTxContext sets the current transaction hash and index which are
// used when the EVM emits new state logs. It should be invoked before
// transaction execution.
// SetTxContext 设置当前交易哈希和索引，这些是在 EVM 发出新状态日志时使用的。
// 它应该在交易执行前调用。
func (s *StateDB) SetTxContext(thash common.Hash, ti int) {
	s.thash = thash // 设置当前交易哈希
	s.txIndex = ti  // 设置当前交易索引
}

func (s *StateDB) clearJournalAndRefund() { // 清除日志和退款计数器
	s.journal.reset() // 重置 journal，清除所有日志记录
	s.refund = 0      // 将退款计数器重置为 0
}

// fastDeleteStorage is the function that efficiently deletes the storage trie
// of a specific account. It leverages the associated state snapshot for fast
// storage iteration and constructs trie node deletion markers by creating
// stack trie with iterated slots.
// fastDeleteStorage 是高效删除特定账户存储 Trie 的函数。
// 它利用关联的状态快照进行快速存储迭代，并通过创建带有迭代槽的堆栈 Trie 来构造 Trie 节点删除标记。
func (s *StateDB) fastDeleteStorage(snaps *snapshot.Tree, addrHash common.Hash, root common.Hash) (map[common.Hash][]byte, map[common.Hash][]byte, *trienode.NodeSet, error) {
	iter, err := snaps.StorageIterator(s.originalRoot, addrHash, common.Hash{}) // 创建存储迭代器
	if err != nil {                                                             // 如果创建迭代器失败
		return nil, nil, nil, err // 返回错误
	}
	defer iter.Release() // 在函数结束时释放迭代器

	var (
		nodes = trienode.NewNodeSet(addrHash) // the set for trie node mutations (value is nil) 创建 Trie 节点变更集（值为 nil 表示删除）
		// 用于记录需要删除的 Trie 节点
		storages = make(map[common.Hash][]byte) // the set for storage mutations (value is nil) 创建存储变更集（值为 nil 表示删除）
		// 用于记录被删除的存储槽
		storageOrigins = make(map[common.Hash][]byte) // the set for tracking the original value of slot 创建存储原始值集
		// 用于追踪存储槽的原始值
	)
	stack := trie.NewStackTrie(func(path []byte, hash common.Hash, blob []byte) { // 创建堆栈 Trie 用于构建删除标记
		nodes.AddNode(path, trienode.NewDeleted()) // 添加删除标记到节点集
	})
	for iter.Next() { // 遍历存储槽
		slot := common.CopyBytes(iter.Slot()) // 复制当前存储槽的值
		if err := iter.Error(); err != nil {  // error might occur after Slot function 检查迭代过程中是否有错误
			return nil, nil, nil, err // 如果有错误，返回
		}
		key := iter.Hash()         // 获取存储槽的哈希键
		storages[key] = nil        // 标记该存储槽为删除
		storageOrigins[key] = slot // 记录存储槽的原始值

		if err := stack.Update(key.Bytes(), slot); err != nil { // 更新堆栈 Trie
			return nil, nil, nil, err // 如果更新失败，返回错误
		}
	}
	if err := iter.Error(); err != nil { // error might occur during iteration
		return nil, nil, nil, err
	}
	if stack.Hash() != root { // 验证堆栈 Trie 的根哈希是否与预期一致
		return nil, nil, nil, fmt.Errorf("snapshot is not matched, exp %x, got %x", root, stack.Hash()) // 如果不匹配，返回错误
	}
	return storages, storageOrigins, nodes, nil // 返回存储变更集、原始值集和节点变更集
}

// slowDeleteStorage serves as a less-efficient alternative to "fastDeleteStorage,"
// employed when the associated state snapshot is not available. It iterates the
// storage slots along with all internal trie nodes via trie directly.
// slowDeleteStorage 作为“fastDeleteStorage”的低效替代方案，
// 在关联的状态快照不可用时使用。它直接通过 Trie 迭代存储槽及其所有内部 Trie 节点。
func (s *StateDB) slowDeleteStorage(addr common.Address, addrHash common.Hash, root common.Hash) (map[common.Hash][]byte, map[common.Hash][]byte, *trienode.NodeSet, error) {
	tr, err := s.db.OpenStorageTrie(s.originalRoot, addr, root, s.trie) // 打开存储 Trie
	if err != nil {                                                     // 如果打开失败
		return nil, nil, nil, fmt.Errorf("failed to open storage trie, err: %w", err) // 返回错误
	}
	it, err := tr.NodeIterator(nil) // 创建 Trie 节点迭代器
	if err != nil {                 // 如果创建失败
		return nil, nil, nil, fmt.Errorf("failed to open storage iterator, err: %w", err) // 返回错误
	}
	var (
		nodes = trienode.NewNodeSet(addrHash) // the set for trie node mutations (value is nil) 创建 Trie 节点变更集（值为 nil 表示删除）
		// 用于记录需要删除的 Trie 节点
		storages = make(map[common.Hash][]byte) // the set for storage mutations (value is nil) 创建存储变更集（值为 nil 表示删除）
		// 用于记录被删除的存储槽
		storageOrigins = make(map[common.Hash][]byte) // the set for tracking the original value of slot 创建存储原始值集
		// 用于追踪存储槽的原始值
	)
	for it.Next(true) { // 遍历 Trie 节点
		if it.Leaf() { // 如果是叶子节点（存储槽）
			key := common.BytesToHash(it.LeafKey())               // 获取存储槽的键
			storages[key] = nil                                   // 标记该存储槽为删除
			storageOrigins[key] = common.CopyBytes(it.LeafBlob()) // 记录存储槽的原始值
			continue                                              // 继续下一次迭代
		}
		if it.Hash() == (common.Hash{}) { // 如果是空哈希
			continue // 跳过
		}
		nodes.AddNode(it.Path(), trienode.NewDeleted()) // 添加删除标记到节点集
	}
	if err := it.Error(); err != nil { // 检查迭代结束时的错误
		return nil, nil, nil, err // 如果有错误，返回
	}
	return storages, storageOrigins, nodes, nil // 返回存储变更集、原始值集和节点变更集
}

// deleteStorage is designed to delete the storage trie of a designated account.
// The function will make an attempt to utilize an efficient strategy if the
// associated state snapshot is reachable; otherwise, it will resort to a less
// efficient approach.
// deleteStorage 旨在删除指定账户的存储 Trie。
// 如果关联的状态快照可用，该函数将尝试使用高效策略；否则，它将采用低效方法。
func (s *StateDB) deleteStorage(addr common.Address, addrHash common.Hash, root common.Hash) (map[common.Hash][]byte, map[common.Hash][]byte, *trienode.NodeSet, error) {
	var (
		err            error
		nodes          *trienode.NodeSet      // the set for trie node mutations (value is nil)
		storages       map[common.Hash][]byte // the set for storage mutations (value is nil)
		storageOrigins map[common.Hash][]byte // the set for tracking the original value of slot
	)
	// The fast approach can be failed if the snapshot is not fully
	// generated, or it's internally corrupted. Fallback to the slow
	// one just in case.
	// 如果快照未完全生成或内部损坏，快速方法可能会失败。在这种情况下回退到慢速方法。
	snaps := s.db.Snapshot() // 获取状态快照
	if snaps != nil {        // 如果快照存在
		storages, storageOrigins, nodes, err = s.fastDeleteStorage(snaps, addrHash, root) // 尝试快速删除
	}
	if snaps == nil || err != nil { // 如果快照不可用或快速删除失败
		storages, storageOrigins, nodes, err = s.slowDeleteStorage(addr, addrHash, root) // 使用慢速删除
	}
	if err != nil { // 如果仍有错误
		return nil, nil, nil, err // 返回错误
	}
	return storages, storageOrigins, nodes, nil // 返回存储变更集、原始值集和节点变更集
}

// handleDestruction processes all destruction markers and deletes the account
// and associated storage slots if necessary. There are four potential scenarios
// as following:
//
//	(a) the account was not existent and be marked as destructed
//	(b) the account was not existent and be marked as destructed,
//	    however, it's resurrected later in the same block.
//	(c) the account was existent and be marked as destructed
//	(d) the account was existent and be marked as destructed,
//	    however it's resurrected later in the same block.
//
// In case (a), nothing needs be deleted, nil to nil transition can be ignored.
// In case (b), nothing needs be deleted, nil is used as the original value for
// newly created account and storages
// In case (c), **original** account along with its storages should be deleted,
// with their values be tracked as original value.
// In case (d), **original** account along with its storages should be deleted,
// with their values be tracked as original value.
// handleDestruction 处理所有销毁标记，并在必要时删除账户及其关联的存储槽。可能有以下四种情况：
//
//	(a) 账户不存在并被标记为销毁
//	(b) 账户不存在并被标记为销毁，但后来在同一区块中复活
//	(c) 账户存在并被标记为销毁
//	(d) 账户存在并被标记为销毁，但后来在同一区块中复活
//
// 在情况 (a) 中，无需删除任何内容，nil 到 nil 的转换可以忽略。
// 在情况 (b) 中，无需删除任何内容，nil 用作新创建的账户和存储的原始值。
// 在情况 (c) 中，应删除**原始**账户及其存储，并将其值追踪为原始值。
// 在情况 (d) 中，应删除**原始**账户及其存储，并将其值追踪为原始值。
func (s *StateDB) handleDestruction() (map[common.Hash]*accountDelete, []*trienode.NodeSet, error) {
	var (
		nodes   []*trienode.NodeSet                    // Trie 节点变更集列表
		buf     = crypto.NewKeccakState()              // 创建 Keccak 哈希状态
		deletes = make(map[common.Hash]*accountDelete) // 创建账户删除映射
	)
	for addr, prevObj := range s.stateObjectsDestruct { // 遍历所有销毁对象
		prev := prevObj.origin // 获取原始账户数据

		// The account was non-existent, and it's marked as destructed in the scope
		// of block. It can be either case (a) or (b) and will be interpreted as
		// null->null state transition.
		// - for (a), skip it without doing anything
		// - for (b), the resurrected account with nil as original will be handled afterwards
		// 账户不存在，且在区块范围内被标记为销毁。可以是情况 (a) 或 (b)，将被解释为 null->null 状态转换。
		// - 对于 (a)，跳过，不做任何操作
		// - 对于 (b)，稍后处理以 nil 为原始值的复活账户
		if prev == nil { // 如果原始账户数据为空
			continue // 跳过
		}
		// The account was existent, it can be either case (c) or (d).
		// 账户存在，可以是情况 (c) 或 (d)。
		addrHash := crypto.HashData(buf, addr.Bytes()) // 计算地址的哈希
		op := &accountDelete{ // 创建账户删除对象
			address: addr,                        // 设置账户地址
			origin:  types.SlimAccountRLP(*prev), // 设置原始账户数据的 RLP 编码
		}
		deletes[addrHash] = op // 添加到删除映射

		// Short circuit if the origin storage was empty.
		// 如果原始存储为空，则短路返回
		if prev.Root == types.EmptyRootHash || s.db.TrieDB().IsVerkle() { // 如果存储根为空或使用 Verkle Trie
			continue // 跳过
		}
		// Remove storage slots belonging to the account.
		// 移除属于该账户的存储槽。
		storages, storagesOrigin, set, err := s.deleteStorage(addr, addrHash, prev.Root) // 删除存储 Trie
		if err != nil {                                                                  // 如果删除失败
			return nil, nil, fmt.Errorf("failed to delete storage, err: %w", err) // 返回错误
		}
		op.storages = storages             // 设置存储变更集
		op.storagesOrigin = storagesOrigin // 设置存储原始值集

		// Aggregate the associated trie node changes.
		// 聚合关联的 Trie 节点变更。
		nodes = append(nodes, set) // 添加节点变更集到列表
	}
	return deletes, nodes, nil // 返回账户删除映射和节点变更集列表
}

// GetTrie returns the account trie.
// GetTrie 返回账户 Trie。
func (s *StateDB) GetTrie() Trie {
	return s.trie // 返回当前的账户 Trie
}

// commit gathers the state mutations accumulated along with the associated
// trie changes, resetting all internal flags with the new state as the base.
// commit 收集累积的状态变更及其关联的 Trie 更改，并以新状态为基础重置所有内部标志。
func (s *StateDB) commit(deleteEmptyObjects bool) (*stateUpdate, error) {
	// Short circuit in case any database failure occurred earlier.
	// 如果之前发生了任何数据库故障，则短路返回。
	if s.dbErr != nil { // 如果存在数据库错误
		return nil, fmt.Errorf("commit aborted due to earlier error: %v", s.dbErr) // 返回错误
	}
	// Finalize any pending changes and merge everything into the tries
	// 最终化所有待处理的更改并将其合并到 Trie 中
	s.IntermediateRoot(deleteEmptyObjects) // 调用 IntermediateRoot，计算中间根并应用变更

	// Short circuit if any error occurs within the IntermediateRoot.
	// 如果 IntermediateRoot 中发生任何错误，则短路返回。
	if s.dbErr != nil { // 如果存在数据库错误
		return nil, fmt.Errorf("commit aborted due to database error: %v", s.dbErr) // 返回错误
	}
	// Commit objects to the trie, measuring the elapsed time
	// 将对象提交到 Trie 中，测量经过的时间
	var (
		accountTrieNodesUpdated int // 账户 Trie 节点更新计数
		accountTrieNodesDeleted int // 账户 Trie 节点删除计数
		storageTrieNodesUpdated int // 存储 Trie 节点更新计数
		storageTrieNodesDeleted int // 存储 Trie 节点删除计数

		lock    sync.Mutex                                               // protect two maps below
		nodes   = trienode.NewMergedNodeSet()                            // aggregated trie nodes
		updates = make(map[common.Hash]*accountUpdate, len(s.mutations)) // aggregated account updates

		// merge aggregates the dirty trie nodes into the global set.
		//
		// Given that some accounts may be destroyed and then recreated within
		// the same block, it's possible that a node set with the same owner
		// may already exists. In such cases, these two sets are combined, with
		// the later one overwriting the previous one if any nodes are modified
		// or deleted in both sets.
		//
		// merge run concurrently across  all the state objects and account trie.
		// merge 将脏 Trie 节点聚合到全局集合中。
		//
		// 考虑到某些账户可能在同一区块内被销毁然后重新创建，可能存在具有相同所有者的节点集。
		// 在这种情况下，这两个集合将被合并，如果两个集合中的任何节点都被修改或删除，则后面的集合将覆盖前面的集合。
		//
		// merge 在所有状态对象和账户 Trie 上并发运行。
		merge = func(set *trienode.NodeSet) error { // 定义合并函数
			if set == nil {                         // 如果节点集为空
				return nil // 返回 nil
			}
			lock.Lock()         // 加锁
			defer lock.Unlock() // 延迟解锁

			updates, deletes := set.Size()    // 获取更新和删除的节点数
			if set.Owner == (common.Hash{}) { // 如果是账户 Trie（无所有者）
				accountTrieNodesUpdated += updates // 更新账户 Trie 更新计数
				accountTrieNodesDeleted += deletes // 更新账户 Trie 删除计数
			} else { // 如果是存储 Trie
				storageTrieNodesUpdated += updates // 更新存储 Trie 更新计数
				storageTrieNodesDeleted += deletes // 更新存储 Trie 删除计数
			}
			return nodes.Merge(set) // 合并节点集到全局集合
		}
	)
	// Given that some accounts could be destroyed and then recreated within
	// the same block, account deletions must be processed first. This ensures
	// that the storage trie nodes deleted during destruction and recreated
	// during subsequent resurrection can be combined correctly.
	// 考虑到某些账户可能在同一区块内被销毁然后重新创建，必须首先处理账户删除。
	// 这确保在销毁期间删除并在随后复活期间重新创建的存储 Trie 节点能够正确合并。
	deletes, delNodes, err := s.handleDestruction() // 处理销毁操作
	if err != nil {                                 // 如果处理失败
		return nil, err // 返回错误
	}
	for _, set := range delNodes { // 遍历销毁节点的集合
		if err := merge(set); err != nil { // 合并节点集
			return nil, err // 如果合并失败，返回错误
		}
	}
	// Handle all state updates afterwards, concurrently to one another to shave
	// off some milliseconds from the commit operation. Also accumulate the code
	// writes to run in parallel with the computations.
	// 之后处理所有状态更新，彼此并发执行，以从提交操作中节省几毫秒。
	// 同时累积代码写入，与计算并行运行。
	var (
		start   = time.Now()   // 记录开始时间
		root    common.Hash    // 新的根哈希
		workers errgroup.Group // 创建并发工作组
	)
	// Schedule the account trie first since that will be the biggest, so give
	// it the most time to crunch.
	//
	// TODO(karalabe): This account trie commit is *very* heavy. 5-6ms at chain
	// heads, which seems excessive given that it doesn't do hashing, it just
	// shuffles some data. For comparison, the *hashing* at chain head is 2-3ms.
	// We need to investigate what's happening as it seems something's wonky.
	// Obviously it's not an end of the world issue, just something the original
	// code didn't anticipate for.
	// 首先调度账户 Trie，因为它将是最大的，所以给它最多的处理时间。
	//
	// TODO(karalabe)：这个账户 Trie 提交非常重。在链头需要 5-6 毫秒，这似乎过多，
	// 因为它不进行哈希计算，只是移动一些数据。相比之下，链头的*哈希计算*是 2-3 毫秒。
	// 我们需要调查发生了什么，似乎有些问题。显然这不是世界末日的问题，只是原始代码未预料到的东西。
	workers.Go(func() error { // 并发提交账户 Trie
		// Write the account trie changes, measuring the amount of wasted time
		// 写入账户 Trie 更改，测量浪费的时间
		newroot, set := s.trie.Commit(true) // 提交账户 Trie 并获取新根和节点集
		root = newroot                      // 设置新的根哈希

		if err := merge(set); err != nil { // 合并节点集
			return err // 如果合并失败，返回错误
		}
		s.AccountCommits = time.Since(start) // 更新账户提交耗时
		return nil                           // 返回 nil 表示无错误
	})
	// Schedule each of the storage tries that need to be updated, so they can
	// run concurrently to one another.
	//
	// TODO(karalabe): Experimentally, the account commit takes approximately the
	// same time as all the storage commits combined, so we could maybe only have
	// 2 threads in total. But that kind of depends on the account commit being
	// more expensive than it should be, so let's fix that and revisit this todo.
	// 调度每个需要更新的存储 Trie，使它们可以彼此并发运行。
	//
	// TODO(karalabe)：实验表明，账户提交大约需要所有存储提交的总和时间，
	// 所以我们可能只需要 2 个线程。但这取决于账户提交比预期更昂贵，所以先修复这个问题再重新审视这个待办事项。
	for addr, op := range s.mutations { // 遍历所有变更
		if op.isDelete() { // 如果是删除操作
			continue // 跳过
		}
		// Write any contract code associated with the state object
		// 写入与状态对象关联的任何合约代码
		obj := s.stateObjects[addr] // 获取状态对象
		if obj == nil {             // 如果对象不存在
			return nil, errors.New("missing state object") // 返回错误
		}
		// Run the storage updates concurrently to one another
		// 并发运行存储更新
		workers.Go(func() error { // 并发提交存储 Trie
			// Write any storage changes in the state object to its storage trie
			// 将状态对象中的任何存储更改写入其存储 Trie
			update, set, err := obj.commit() // 提交存储 Trie 并获取更新和节点集
			if err != nil {                  // 如果提交失败
				return err // 返回错误
			}
			if err := merge(set); err != nil { // 合并节点集
				return err // 如果合并失败，返回错误
			}
			lock.Lock()
			updates[obj.addrHash] = update
			s.StorageCommits = time.Since(start) // overwrite with the longest storage commit runtime
			lock.Unlock()
			return nil
		})
	}
	// Wait for everything to finish and update the metrics
	// 等待所有任务完成并更新指标
	if err := workers.Wait(); err != nil { // 等待并发任务完成
		return nil, err // 如果有错误，返回
	}
	accountReadMeters.Mark(int64(s.AccountLoaded))                // 更新账户读取计数器
	storageReadMeters.Mark(int64(s.StorageLoaded))                // 更新存储读取计数器
	accountUpdatedMeter.Mark(int64(s.AccountUpdated))             // 更新账户更新计数器
	storageUpdatedMeter.Mark(s.StorageUpdated.Load())             // 更新存储更新计数器
	accountDeletedMeter.Mark(int64(s.AccountDeleted))             // 更新账户删除计数器
	storageDeletedMeter.Mark(s.StorageDeleted.Load())             // 更新存储删除计数器
	accountTrieUpdatedMeter.Mark(int64(accountTrieNodesUpdated))  // 更新账户 Trie 更新节点计数器
	accountTrieDeletedMeter.Mark(int64(accountTrieNodesDeleted))  // 更新账户 Trie 删除节点计数器
	storageTriesUpdatedMeter.Mark(int64(storageTrieNodesUpdated)) // 更新存储 Trie 更新节点计数器
	storageTriesDeletedMeter.Mark(int64(storageTrieNodesDeleted)) // 更新存储 Trie 删除节点计数器

	// Clear the metric markers
	// 清除指标标记
	s.AccountLoaded, s.AccountUpdated, s.AccountDeleted = 0, 0, 0 // 重置账户相关计数器
	s.StorageLoaded = 0                                           // 重置存储加载计数器
	s.StorageUpdated.Store(0)                                     // 重置存储更新计数器
	s.StorageDeleted.Store(0)                                     // 重置存储删除计数器

	// Clear all internal flags and update state root at the end.
	// 清除所有内部标志并在最后更新状态根。
	s.mutations = make(map[common.Address]*mutation)               // 重置变更映射
	s.stateObjectsDestruct = make(map[common.Address]*stateObject) // 重置销毁对象映射

	origin := s.originalRoot                                          // 记录原始根哈希
	s.originalRoot = root                                             // 更新原始根哈希为新根
	return newStateUpdate(origin, root, deletes, updates, nodes), nil // 返回状态更新对象
}

// commitAndFlush is a wrapper of commit which also commits the state mutations
// to the configured data stores.
// commitAndFlush 是 commit 的包装器，它还将状态变更提交到配置的数据存储中。
func (s *StateDB) commitAndFlush(block uint64, deleteEmptyObjects bool) (*stateUpdate, error) {
	ret, err := s.commit(deleteEmptyObjects) // 调用 commit 方法提交状态变更
	if err != nil {                          // 如果提交失败
		return nil, err // 返回错误
	}
	// Commit dirty contract code if any exists
	// 如果存在脏合约代码，则提交
	if db := s.db.TrieDB().Disk(); db != nil && len(ret.codes) > 0 { // 如果磁盘数据库存在且有代码需要提交
		batch := db.NewBatch()           // 创建批量写入对象
		for _, code := range ret.codes { // 遍历所有代码
			rawdb.WriteCode(batch, code.hash, code.blob) // 写入代码到批量对象
		}
		if err := batch.Write(); err != nil { // 执行批量写入
			return nil, err // 如果写入失败，返回错误
		}
	}
	if !ret.empty() { // 如果状态更新不为空
		// If snapshotting is enabled, update the snapshot tree with this new version
		// 如果启用了快照功能，则使用此新版本更新快照树
		if snap := s.db.Snapshot(); snap != nil && snap.Snapshot(ret.originRoot) != nil { // 如果快照存在且原始根有效
			start := time.Now()                                                                       // 记录开始时间
			if err := snap.Update(ret.root, ret.originRoot, ret.accounts, ret.storages); err != nil { // 更新快照树
				log.Warn("Failed to update snapshot tree", "from", ret.originRoot, "to", ret.root, "err", err) // 如果更新失败，记录警告
			}
			// Keep 128 diff layers in the memory, persistent layer is 129th.
			// - head layer is paired with HEAD state
			// - head-1 layer is paired with HEAD-1 state
			// - head-127 layer(bottom-most diff layer) is paired with HEAD-127 state
			// 在内存中保留 128 个差异层，第 129 层是持久层。
			// - 头层与 HEAD 状态配对
			// - 头-1 层与 HEAD-1 状态配对
			// - 头-127 层（自定义最大差异层）与 HEAD-127 状态配对
			if err := snap.Cap(ret.root, TriesInMemory); err != nil { // 限制快照层数
				log.Warn("Failed to cap snapshot tree", "root", ret.root, "layers", TriesInMemory, "err", err) // 如果限制失败，记录警告
			}
			s.SnapshotCommits += time.Since(start) // 更新快照提交耗时
		}
		// If trie database is enabled, commit the state update as a new layer
		// 如果启用了 Trie 数据库，则将状态更新提交为新层
		if db := s.db.TrieDB(); db != nil { // 如果 Trie 数据库存在
			start := time.Now()                                                                           // 记录开始时间
			if err := db.Update(ret.root, ret.originRoot, block, ret.nodes, ret.stateSet()); err != nil { // 更新 Trie 数据库
				return nil, err // 如果更新失败，返回错误
			}
			s.TrieDBCommits += time.Since(start) // 更新 Trie 数据库提交耗时
		}
	}
	s.reader, _ = s.db.Reader(s.originalRoot) // 更新只读接口为新根
	return ret, err                           // 返回状态更新对象和错误（如果有）
}

// Commit writes the state mutations into the configured data stores.
//
// Once the state is committed, tries cached in stateDB (including account
// trie, storage tries) will no longer be functional. A new state instance
// must be created with new root and updated database for accessing post-
// commit states.
//
// The associated block number of the state transition is also provided
// for more chain context.
// Commit 将状态变更写入配置的数据存储中。
//
// 一旦状态被提交，StateDB 中缓存的 Trie（包括账户 Trie 和存储 Trie）将不再可用。
// 必须使用新的根哈希和更新的数据库创建一个新的状态实例，以访问提交后的状态。
//
// 还提供了状态转换的关联区块号，以提供更多链上下文。
func (s *StateDB) Commit(block uint64, deleteEmptyObjects bool) (common.Hash, error) {
	ret, err := s.commitAndFlush(block, deleteEmptyObjects) // 调用 commitAndFlush 提交并刷新状态
	if err != nil {                                         // 如果提交失败
		return common.Hash{}, err // 返回空哈希和错误
	}
	return ret.root, nil // 返回新的根哈希和 nil 错误
}

// Prepare handles the preparatory steps for executing a state transition with.
// This method must be invoked before state transition.
//
// Berlin fork:
// - Add sender to access list (2929)
// - Add destination to access list (2929)
// - Add precompiles to access list (2929)
// - Add the contents of the optional tx access list (2930)
//
// Potential EIPs:
// - Reset access list (Berlin)
// - Add coinbase to access list (EIP-3651)
// - Reset transient storage (EIP-1153)
// Prepare 处理执行状态转换的准备步骤。
// 此方法必须在状态转换前调用。
//
// Berlin 分叉：
// - 将发送者添加到访问列表 (2929)
// - 将目标地址添加到访问列表 (2929)
// - 将预编译地址添加到访问列表 (2929)
// - 添加可选交易访问列表的内容 (2930)
//
// 潜在的 EIP：
// - 重置访问列表 (Berlin)
// - 将 coinbase 添加到访问列表 (EIP-3651)
// - 重置临时存储 (EIP-1153)
func (s *StateDB) Prepare(rules params.Rules, sender, coinbase common.Address, dst *common.Address, precompiles []common.Address, list types.AccessList) {
	if rules.IsEIP2929 && rules.IsEIP4762 { // 如果同时启用了 EIP-2929 和 EIP-4762
		panic("eip2929 and eip4762 are both activated") // 抛出 panic（两者冲突）
	}
	if rules.IsEIP2929 { // 如果启用了 EIP-2929
		// Clear out any leftover from previous executions
		// 清除前一次执行的任何残留数据
		al := newAccessList() // 创建新的访问列表
		s.accessList = al     // 设置到 StateDB

		al.AddAddress(sender) // 添加发送者地址到访问列表
		if dst != nil {       // 如果目标地址存在
			al.AddAddress(*dst) // 添加目标地址到访问列表
			// If it's a create-tx, the destination will be added inside evm.create
			// 如果是创建交易，目标地址将在 evm.create 中添加
		}
		for _, addr := range precompiles { // 遍历预编译地址
			al.AddAddress(addr) // 添加到访问列表
		}
		for _, el := range list { // 遍历交易访问列表
			al.AddAddress(el.Address)            // 添加地址到访问列表
			for _, key := range el.StorageKeys { // 遍历存储键
				al.AddSlot(el.Address, key) // 添加存储槽到访问列表
			}
		}
		if rules.IsShanghai { // EIP-3651: warm coinbase 如果是上海分叉（EIP-3651）
			al.AddAddress(coinbase) // 添加 coinbase 地址到访问列表
		}
	}
	// Reset transient storage at the beginning of transaction execution
	// 在交易执行开始时重置临时存储
	s.transientStorage = newTransientStorage() // 重置临时存储为新实例
}

// AddAddressToAccessList adds the given address to the access list
// AddAddressToAccessList 将给定地址添加到访问列表
func (s *StateDB) AddAddressToAccessList(addr common.Address) {
	if s.accessList.AddAddress(addr) { // 将地址添加到访问列表，如果成功
		s.journal.accessListAddAccount(addr) // 记录到日志
	}
}

// AddSlotToAccessList adds the given (address, slot)-tuple to the access list
// AddSlotToAccessList 将给定的（地址，槽）元组添加到访问列表
func (s *StateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	addrMod, slotMod := s.accessList.AddSlot(addr, slot) // 添加存储槽到访问列表，返回地址和槽的修改状态
	if addrMod {                                         // 如果地址被修改
		// In practice, this should not happen, since there is no way to enter the
		// scope of 'address' without having the 'address' become already added
		// to the access list (via call-variant, create, etc).
		// Better safe than sorry, though
		// 在实践中，这不应该发生，因为没有办法在不将“地址”添加到访问列表的情况下进入“地址”的范围
		// （通过调用变体、创建等方式）。
		// 不过，为了安全起见，还是记录。
		s.journal.accessListAddAccount(addr) // 记录地址添加日志
	}
	if slotMod { // 如果槽被修改
		s.journal.accessListAddSlot(addr, slot) // 记录槽添加日志
	}
}

// AddressInAccessList returns true if the given address is in the access list.
// AddressInAccessList 如果给定地址在访问列表中，则返回 true。
func (s *StateDB) AddressInAccessList(addr common.Address) bool {
	return s.accessList.ContainsAddress(addr) // 检查地址是否在访问列表中
}

// SlotInAccessList returns true if the given (address, slot)-tuple is in the access list.
// SlotInAccessList 如果给定的（地址，槽）元组在访问列表中，则返回 true。
func (s *StateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressPresent bool, slotPresent bool) {
	return s.accessList.Contains(addr, slot) // 检查地址和槽是否在访问列表中，返回两个布尔值
}

// markDelete is invoked when an account is deleted but the deletion is
// not yet committed. The pending mutation is cached and will be applied
// all together
// markDelete 在账户被删除但尚未提交时调用。待处理的变更将被缓存并一起应用。
func (s *StateDB) markDelete(addr common.Address) {
	if _, ok := s.mutations[addr]; !ok { // 如果该地址的变更不存在
		s.mutations[addr] = &mutation{} // 创建新的变更对象
	}
	s.mutations[addr].applied = false // 标记为未应用
	s.mutations[addr].typ = deletion  // 设置变更类型为删除
}

func (s *StateDB) markUpdate(addr common.Address) { // 标记账户为更新状态
	if _, ok := s.mutations[addr]; !ok {            // 如果该地址的变更不存在
		s.mutations[addr] = &mutation{} // 创建新的变更对象
	}
	s.mutations[addr].applied = false // 标记为未应用
	s.mutations[addr].typ = update    // 设置变更类型为更新
}

// PointCache returns the point cache used by verkle tree.
// PointCache 返回 Verkle 树使用的点缓存。
func (s *StateDB) PointCache() *utils.PointCache {
	return s.db.PointCache() // 返回数据库中的点缓存
}

// Witness retrieves the current state witness being collected.
// Witness 检索当前正在收集的状态见证数据。
func (s *StateDB) Witness() *stateless.Witness {
	return s.witness // 返回当前的见证数据
}

func (s *StateDB) AccessEvents() *AccessEvents { // 获取访问事件
	return s.accessEvents // 返回当前的访问事件对象
}
