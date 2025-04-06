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

package state

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// EIP-2930（Optional Access Lists）：
// 引入访问列表以降低 Gas 成本，accessListAddAccountChange 和 accessListAddSlotChange 支持在日志中记录这些变更，确保回滚时正确处理。
// EIP-3198（Transient Storage Opcodes）：
// 引入临时存储（Transient Storage），transientStorageChange 记录此类变更。临时存储在交易结束时重置，不影响持久状态。
// EIP-3074（Cancun 分叉）：
// 废弃自毁操作（SELFDESTRUCT），但 selfDestructChange 仍保留以兼容历史数据。

// 状态回滚：
// EVM 执行可能因 Gas 不足或异常中止，journal 确保状态恢复到交易开始时的状态，符合以太坊的原子性要求。
// 临时存储：
// 临时存储是 EIP-3198 的创新，仅在交易生命周期内有效，transientStorageChange 支持其实现。
// 访问列表：
// 访问列表优化了状态访问成本，journal 的支持确保其在回滚时保持一致性。

type revision struct {
	id           int // 修订版本的唯一标识符
	journalIndex int // 日志中对应的索引位置
}

// journalEntry is a modification entry in the state change journal that can be
// reverted on demand.
// journalEntry 是状态变更日志中的修改条目，可以按需撤销。
type journalEntry interface {
	// revert undoes the changes introduced by this journal entry.
	// revert 撤销此日志条目引入的更改。
	revert(*StateDB)

	// dirtied returns the Ethereum address modified by this journal entry.
	// dirtied 返回此日志条目修改的以太坊地址。
	dirtied() *common.Address

	// copy returns a deep-copied journal entry.
	// copy 返回深拷贝的日志条目。
	copy() journalEntry
}

// journal contains the list of state modifications applied since the last state
// commit. These are tracked to be able to be reverted in the case of an execution
// exception or request for reversal.
// journal 包含自上次状态提交以来应用的状态修改列表。这些修改被跟踪，以便在执行异常或请求撤销时能够回滚。
type journal struct {
	entries []journalEntry         // Current changes tracked by the journal 当前由日志跟踪的更改
	dirties map[common.Address]int // Dirty accounts and the number of changes 被修改的账户及其更改次数

	validRevisions []revision // 有效的修订版本列表
	nextRevisionId int        // 下一个修订版本的 ID
}

// newJournal creates a new initialized journal.
// newJournal 创建一个新的初始化日志。
func newJournal() *journal {
	return &journal{
		dirties: make(map[common.Address]int), // 初始化脏账户映射
	}
}

// reset clears the journal, after this operation the journal can be used anew.
// It is semantically similar to calling 'newJournal', but the underlying slices
// can be reused.
// reset 清除日志，此操作后日志可以重新使用。
// 它在语义上类似于调用 'newJournal'，但底层切片可以重用。
func (j *journal) reset() {
	j.entries = j.entries[:0]               // 清空日志条目
	j.validRevisions = j.validRevisions[:0] // 清空修订版本
	clear(j.dirties)                        // 清空脏账户映射
	j.nextRevisionId = 0                    // 重置修订 ID
}

// snapshot returns an identifier for the current revision of the state.
// snapshot 返回当前状态修订版本的标识符。
func (j *journal) snapshot() int {
	id := j.nextRevisionId
	j.nextRevisionId++                                                    // 增加修订 ID
	j.validRevisions = append(j.validRevisions, revision{id, j.length()}) // 添加新的修订版本
	return id
}

// revertToSnapshot reverts all state changes made since the given revision.
// revertToSnapshot 撤销自给定修订版本以来所做的所有状态更改。
func (j *journal) revertToSnapshot(revid int, s *StateDB) {
	// Find the snapshot in the stack of valid snapshots.
	// 在有效快照栈中查找快照。
	idx := sort.Search(len(j.validRevisions), func(i int) bool {
		return j.validRevisions[i].id >= revid
	})
	if idx == len(j.validRevisions) || j.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid)) // 未找到修订 ID，抛出异常
	}
	snapshot := j.validRevisions[idx].journalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	// 重放日志以撤销更改并移除无效的快照
	j.revert(s, snapshot)
	j.validRevisions = j.validRevisions[:idx] // 移除后续的修订版本
}

// append inserts a new modification entry to the end of the change journal.
// append 将新的修改条目插入到变更日志的末尾。
func (j *journal) append(entry journalEntry) {
	j.entries = append(j.entries, entry) // 添加新条目
	if addr := entry.dirtied(); addr != nil {
		j.dirties[*addr]++ // 增加脏账户的更改计数
	}
}

// revert undoes a batch of journalled modifications along with any reverted
// dirty handling too.
// revert 撤销一批记录的修改，同时处理任何撤销的脏状态。
func (j *journal) revert(statedb *StateDB, snapshot int) {
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		// Undo the changes made by the operation
		// 撤销操作所做的更改
		j.entries[i].revert(statedb)

		// Drop any dirty tracking induced by the change
		// 删除由更改引起的任何脏跟踪
		if addr := j.entries[i].dirtied(); addr != nil {
			if j.dirties[*addr]--; j.dirties[*addr] == 0 {
				delete(j.dirties, *addr) // 如果计数为零，删除脏账户
			}
		}
	}
	j.entries = j.entries[:snapshot] // 截断日志到快照位置
}

// dirty explicitly sets an address to dirty, even if the change entries would
// otherwise suggest it as clean. This method is an ugly hack to handle the RIPEMD
// precompile consensus exception.
// dirty 显式地将地址设置为脏，即使变更条目表明它是干净的。此方法是处理 RIPEMD 预编译共识异常的临时解决方案。
func (j *journal) dirty(addr common.Address) {
	j.dirties[addr]++ // 增加脏计数
}

// length returns the current number of entries in the journal.
// length 返回日志中当前的条目数。
func (j *journal) length() int {
	return len(j.entries)
}

// copy returns a deep-copied journal.
// copy 返回深拷贝的日志。
func (j *journal) copy() *journal {
	entries := make([]journalEntry, 0, j.length())
	for i := 0; i < j.length(); i++ {
		entries = append(entries, j.entries[i].copy()) // 深拷贝每个条目
	}
	return &journal{
		entries:        entries,
		dirties:        maps.Clone(j.dirties),          // 克隆脏账户映射
		validRevisions: slices.Clone(j.validRevisions), // 克隆修订版本列表
		nextRevisionId: j.nextRevisionId,
	}
}

// 日志变更方法
func (j *journal) logChange(txHash common.Hash) {
	j.append(addLogChange{txhash: txHash})
}

func (j *journal) createObject(addr common.Address) {
	j.append(createObjectChange{account: addr})
}

func (j *journal) createContract(addr common.Address) {
	j.append(createContractChange{account: addr})
}

func (j *journal) destruct(addr common.Address) {
	j.append(selfDestructChange{account: addr})
}

func (j *journal) storageChange(addr common.Address, key, prev, origin common.Hash) {
	j.append(storageChange{
		account:   addr,
		key:       key,
		prevvalue: prev,
		origvalue: origin,
	})
}

func (j *journal) transientStateChange(addr common.Address, key, prev common.Hash) {
	j.append(transientStorageChange{
		account:  addr,
		key:      key,
		prevalue: prev,
	})
}

func (j *journal) refundChange(previous uint64) {
	j.append(refundChange{prev: previous})
}

func (j *journal) balanceChange(addr common.Address, previous *uint256.Int) {
	j.append(balanceChange{
		account: addr,
		prev:    previous.Clone(),
	})
}

func (j *journal) setCode(address common.Address, prevCode []byte) {
	j.append(codeChange{
		account:  address,
		prevCode: prevCode,
	})
}

func (j *journal) nonceChange(address common.Address, prev uint64) {
	j.append(nonceChange{
		account: address,
		prev:    prev,
	})
}

func (j *journal) touchChange(address common.Address) {
	j.append(touchChange{
		account: address,
	})
	if address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		// 显式地将 RIPEMD 地址放入脏缓存中，否则它将从平坦化的日志中生成。
		j.dirty(address)
	}
}

func (j *journal) accessListAddAccount(addr common.Address) {
	j.append(accessListAddAccountChange{addr})
}

func (j *journal) accessListAddSlot(addr common.Address, slot common.Hash) {
	j.append(accessListAddSlotChange{
		address: addr,
		slot:    slot,
	})
}

// 定义各种变更类型
type (
	// Changes to the account trie.
	// 账户 trie 的更改
	createObjectChange struct {
		account common.Address
	}
	// createContractChange represents an account becoming a contract-account.
	// This event happens prior to executing initcode. The journal-event simply
	// manages the created-flag, in order to allow same-tx destruction.
	// createContractChange 表示账户变为合约账户。
	// 此事件在执行初始化代码之前发生。日志事件仅管理创建标志，以允许同一交易内的销毁。
	createContractChange struct {
		account common.Address
	}
	selfDestructChange struct {
		account common.Address
	}

	// Changes to individual accounts.
	// 对单个账户的更改
	balanceChange struct {
		account common.Address
		prev    *uint256.Int // 之前的余额
	}
	nonceChange struct {
		account common.Address
		prev    uint64 // 之前的 nonce 值
	}
	storageChange struct {
		account   common.Address
		key       common.Hash
		prevvalue common.Hash // 之前的值
		origvalue common.Hash // 原始值
	}
	codeChange struct {
		account  common.Address
		prevCode []byte // 之前的代码
	}

	// Changes to other state values.
	// 其他状态值的更改
	refundChange struct {
		prev uint64 // 之前的退款值
	}
	addLogChange struct {
		txhash common.Hash // 交易哈希
	}
	touchChange struct {
		account common.Address
	}

	// Changes to the access list
	// 访问列表的更改
	accessListAddAccountChange struct {
		address common.Address
	}
	accessListAddSlotChange struct {
		address common.Address
		slot    common.Hash
	}

	// Changes to transient storage
	// 临时存储的更改
	transientStorageChange struct {
		account       common.Address
		key, prevalue common.Hash // 键和之前的值
	}
)

// createObjectChange 的实现
func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, ch.account) // 删除状态对象
}

func (ch createObjectChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch createObjectChange) copy() journalEntry {
	return createObjectChange{
		account: ch.account,
	}
}

// createContractChange 的实现
func (ch createContractChange) revert(s *StateDB) {
	s.getStateObject(ch.account).newContract = false // 撤销合约创建标志
}

func (ch createContractChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch createContractChange) copy() journalEntry {
	return createContractChange{
		account: ch.account,
	}
}

// selfDestructChange 的实现
func (ch selfDestructChange) revert(s *StateDB) {
	obj := s.getStateObject(ch.account)
	if obj != nil {
		obj.selfDestructed = false // 撤销自毁标志
	}
}

func (ch selfDestructChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch selfDestructChange) copy() journalEntry {
	return selfDestructChange{
		account: ch.account,
	}
}

var ripemd = common.HexToAddress("0000000000000000000000000000000000000003") // RIPEMD 预编译地址

// touchChange 的实现
func (ch touchChange) revert(s *StateDB) {
	// 无需撤销操作
}

func (ch touchChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch touchChange) copy() journalEntry {
	return touchChange{
		account: ch.account,
	}
}

// balanceChange 的实现
func (ch balanceChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setBalance(ch.prev) // 恢复之前的余额
}

func (ch balanceChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch balanceChange) copy() journalEntry {
	return balanceChange{
		account: ch.account,
		prev:    new(uint256.Int).Set(ch.prev), // 深拷贝余额
	}
}

// nonceChange 的实现
func (ch nonceChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setNonce(ch.prev) // 恢复之前的 nonce
}

func (ch nonceChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch nonceChange) copy() journalEntry {
	return nonceChange{
		account: ch.account,
		prev:    ch.prev,
	}
}

// codeChange 的实现
func (ch codeChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setCode(crypto.Keccak256Hash(ch.prevCode), ch.prevCode) // 恢复之前的代码
}

func (ch codeChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch codeChange) copy() journalEntry {
	return codeChange{
		account:  ch.account,
		prevCode: ch.prevCode, // 注意：这里应深拷贝 prevCode，但当前实现未做，可能是个潜在问题
	}
}

// storageChange 的实现
func (ch storageChange) revert(s *StateDB) {
	s.getStateObject(ch.account).setState(ch.key, ch.prevvalue, ch.origvalue) // 恢复之前的状态
}

func (ch storageChange) dirtied() *common.Address {
	return &ch.account // 返回被修改的地址
}

func (ch storageChange) copy() journalEntry {
	return storageChange{
		account:   ch.account,
		key:       ch.key,
		prevvalue: ch.prevvalue,
		origvalue: ch.origvalue,
	}
}

// transientStorageChange 的实现
func (ch transientStorageChange) revert(s *StateDB) {
	s.setTransientState(ch.account, ch.key, ch.prevalue) // 恢复之前的临时存储状态
}

func (ch transientStorageChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch transientStorageChange) copy() journalEntry {
	return transientStorageChange{
		account:  ch.account,
		key:      ch.key,
		prevalue: ch.prevalue,
	}
}

// refundChange 的实现
func (ch refundChange) revert(s *StateDB) {
	s.refund = ch.prev // 恢复之前的退款值
}

func (ch refundChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch refundChange) copy() journalEntry {
	return refundChange{
		prev: ch.prev,
	}
}

// addLogChange 的实现
func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txhash]
	if len(logs) == 1 {
		delete(s.logs, ch.txhash) // 删除日志
	} else {
		s.logs[ch.txhash] = logs[:len(logs)-1] // 移除最后一个日志
	}
	s.logSize-- // 减少日志计数
}

func (ch addLogChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch addLogChange) copy() journalEntry {
	return addLogChange{
		txhash: ch.txhash,
	}
}

// accessListAddAccountChange 的实现
func (ch accessListAddAccountChange) revert(s *StateDB) {
	/*
		One important invariant here, is that whenever a (addr, slot) is added, if the
		addr is not already present, the add causes two journal entries:
		- one for the address,
		- one for the (address,slot)
		Therefore, when unrolling the change, we can always blindly delete the
		(addr) at this point, since no storage adds can remain when come upon
		a single (addr) change.
	*/
	// 这里的一个重要不变性是，每当添加 (addr, slot) 时，如果 addr 尚未存在，
	// 添加会产生两个日志条目：
	// - 一个用于地址，
	// - 一个用于 (address, slot)
	// 因此，在回滚更改时，我们总是可以盲目删除 (addr)，因为在遇到单个 (addr) 更改时，
	// 不会有剩余的存储添加。
	s.accessList.DeleteAddress(ch.address) // 删除访问列表中的地址
}

func (ch accessListAddAccountChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch accessListAddAccountChange) copy() journalEntry {
	return accessListAddAccountChange{
		address: ch.address,
	}
}

// accessListAddSlotChange 的实现
func (ch accessListAddSlotChange) revert(s *StateDB) {
	s.accessList.DeleteSlot(ch.address, ch.slot) // 删除访问列表中的槽
}

func (ch accessListAddSlotChange) dirtied() *common.Address {
	return nil // 不标记为脏
}

func (ch accessListAddSlotChange) copy() journalEntry {
	return accessListAddSlotChange{
		address: ch.address,
		slot:    ch.slot,
	}
}
