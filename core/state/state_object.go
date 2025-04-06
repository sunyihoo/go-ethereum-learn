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

package state

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/holiman/uint256"
)

//以太坊白皮书：白皮书中描述了状态树存储所有账户的状态，stateObject 是单个账户的内存表示，支持高效的读写操作。
//黄皮书：黄皮书中定义了账户的结构（nonce、balance、storageRoot、codeHash），stateObject.data 直接对应这一定义。
//EIP-161（State Trie Clearing）：引入了账户清空机制，AddBalance 和 empty 方法实现了此逻辑，确保空账户（0,0,0）被正确处理。

// Storage 表示存储映射，键和值均为 common.Hash 类型。
type Storage map[common.Hash]common.Hash

// Copy 创建并返回 Storage 的深拷贝。
func (s Storage) Copy() Storage {
	return maps.Clone(s) // 使用 maps.Clone 创建映射的副本
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// - First you need to obtain a state object.
// - Account values as well as storages can be accessed and modified through the object.
// - Finally, call commit to return the changes of storage trie and update account data.
//
// stateObject 表示正在修改的以太坊账户。
//
// 使用模式如下：
// - 首先需要获取一个状态对象。
// - 通过该对象可以访问和修改账户值以及存储。
// - 最后调用 commit 方法返回存储 trie 的更改并更新账户数据。
type stateObject struct {
	db       *StateDB            // 关联的 StateDB 实例
	address  common.Address      // address of ethereum account 以太坊账户的地址
	addrHash common.Hash         // hash of ethereum address of the account 账户地址的哈希值
	origin   *types.StateAccount // Account original data without any change applied, nil means it was not existent 未应用任何更改的账户原始数据，若为 nil 则表示账户不存在
	data     types.StateAccount  // Account data with all mutations applied in the scope of block 在块范围内应用所有变更后的账户数据

	// Write caches. 写缓存。
	trie Trie   // storage trie, which becomes non-nil on first access 存储 trie，首次访问时变为非 nil
	code []byte // contract bytecode, which gets set when code is loaded 合约字节码，在加载代码时设置

	originStorage  Storage // Storage entries that have been accessed within the current block 在当前块内访问过的存储条目
	dirtyStorage   Storage // Storage entries that have been modified within the current transaction 在当前交易内修改过的存储条目
	pendingStorage Storage // Storage entries that have been modified within the current block 在当前块内修改过的存储条目

	// uncommittedStorage tracks a set of storage entries that have been modified
	// but not yet committed since the "last commit operation", along with their
	// original values before mutation.
	//
	// Specifically, the commit will be performed after each transaction before
	// the byzantium fork, therefore the map is already reset at the transaction
	// boundary; however post the byzantium fork, the commit will only be performed
	// at the end of block, this set essentially tracks all the modifications
	// made within the block.
	//
	// uncommittedStorage 跟踪自“最后提交操作”以来修改但尚未提交的存储条目集合，
	// 以及它们在变更前的原始值。
	//
	// 具体来说，在拜占庭分叉前，每次交易后都会执行提交，因此该映射在交易边界处已重置；
	// 但在拜占庭分叉后，仅在块结束时执行提交，此集合实质上跟踪块内的所有修改。
	uncommittedStorage Storage

	// Cache flags. 缓存标志。
	dirtyCode bool // true if the code was updated 如果代码被更新，则为 true

	// Flag whether the account was marked as self-destructed. The self-destructed
	// account is still accessible in the scope of same transaction.
	// 标志账户是否被标记为自毁。自毁账户在同一交易范围内仍可访问。
	selfDestructed bool

	// This is an EIP-6780 flag indicating whether the object is eligible for
	// self-destruct according to EIP-6780. The flag could be set either when
	// the contract is just created within the current transaction, or when the
	// object was previously existent and is being deployed as a contract within
	// the current transaction.
	// 这是 EIP-6780 标志，指示对象是否根据 EIP-6780 有资格自毁。
	// 该标志可以在以下情况下设置：
	// - 合约在当前交易内刚创建；
	// - 对象之前存在并在当前交易内被部署为合约。
	newContract bool
}

// empty returns whether the account is considered empty.
// empty 返回账户是否被视为空。
func (s *stateObject) empty() bool {
	// 检查账户的 nonce 是否为 0，余额是否为 0，代码哈希是否为空代码哈希
	return s.data.Nonce == 0 && s.data.Balance.IsZero() && bytes.Equal(s.data.CodeHash, types.EmptyCodeHash.Bytes())
}

// newObject creates a state object.
// newObject 创建一个状态对象。
func newObject(db *StateDB, address common.Address, acct *types.StateAccount) *stateObject {
	origin := acct // 保存原始账户数据
	if acct == nil {
		acct = types.NewEmptyStateAccount() // 如果账户为空，创建空账户
	}
	return &stateObject{
		db:                 db,                               // 设置关联的 StateDB
		address:            address,                          // 设置账户地址
		addrHash:           crypto.Keccak256Hash(address[:]), // 计算地址哈希
		origin:             origin,                           // 设置原始数据
		data:               *acct,                            // 设置当前数据
		originStorage:      make(Storage),                    // 初始化原始存储映射
		dirtyStorage:       make(Storage),                    // 初始化脏存储映射
		pendingStorage:     make(Storage),                    // 初始化待提交存储映射
		uncommittedStorage: make(Storage),                    // 初始化未提交存储映射
	}
}

// markSelfdestructed 将账户标记为自毁。
func (s *stateObject) markSelfdestructed() {
	s.selfDestructed = true // 设置自毁标志
}

// touch 标记账户为已触碰，记录到日志中。
func (s *stateObject) touch() {
	s.db.journal.touchChange(s.address) // 在日志中记录触碰更改
}

// getTrie returns the associated storage trie. The trie will be opened if it's
// not loaded previously. An error will be returned if trie can't be loaded.
//
// If a new trie is opened, it will be cached within the state object to allow
// subsequent reads to expand the same trie instead of reloading from disk.
//
// getTrie 返回关联的存储 trie。如果 trie 未加载，将打开它。
// 如果无法加载 trie，则返回错误。
//
// 如果打开了新 trie，将在状态对象中缓存，以允许后续读取扩展同一 trie，而不是从磁盘重新加载。
func (s *stateObject) getTrie() (Trie, error) {
	if s.trie == nil { // 如果 trie 未初始化
		// 打开存储 trie，使用原始根、地址和当前根
		tr, err := s.db.db.OpenStorageTrie(s.db.originalRoot, s.address, s.data.Root, s.db.trie)
		if err != nil {
			return nil, err // 如果打开失败，返回错误
		}
		s.trie = tr // 缓存 trie
	}
	return s.trie, nil // 返回 trie
}

// getPrefetchedTrie returns the associated trie, as populated by the prefetcher
// if it's available.
//
// Note, opposed to getTrie, this method will *NOT* blindly cache the resulting
// trie in the state object. The caller might want to do that, but it's cleaner
// to break the hidden interdependency between retrieving tries from the db or
// from the prefetcher.
//
// getPrefetchedTrie 返回由预取器填充的关联 trie（如果可用）。
//
// 注意，与 getTrie 不同，此方法不会盲目缓存结果 trie 到状态对象中。
// 调用者可能希望这样做，但打破从数据库或预取器检索 trie 的隐藏依赖关系更干净。
func (s *stateObject) getPrefetchedTrie() Trie {
	// If there's nothing to meaningfully return, let the user figure it out by
	// pulling the trie from disk.
	// 如果根为空且不是 Verkle trie，或者没有预取器，则返回 nil
	if (s.data.Root == types.EmptyRootHash && !s.db.db.TrieDB().IsVerkle()) || s.db.prefetcher == nil {
		return nil
	}
	// Attempt to retrieve the trie from the prefetcher
	// 尝试从预取器检索 trie
	return s.db.prefetcher.trie(s.addrHash, s.data.Root)
}

// GetState retrieves a value associated with the given storage key.
// GetState 检索与给定存储键关联的值。
func (s *stateObject) GetState(key common.Hash) common.Hash {
	value, _ := s.getState(key) // 调用 getState 获取值
	return value                // 返回当前值
}

// getState retrieves a value associated with the given storage key, along with
// its original value.
// getState 检索与给定存储键关联的值及其原始值。
func (s *stateObject) getState(key common.Hash) (common.Hash, common.Hash) {
	origin := s.GetCommittedState(key)  // 获取已提交的值
	value, dirty := s.dirtyStorage[key] // 检查脏存储中是否有值
	if dirty {
		return value, origin // 如果是脏数据，返回当前值和原始值
	}
	return origin, origin // 如果不是脏数据，返回原始值
}

// GetCommittedState retrieves the value associated with the specific key
// without any mutations caused in the current execution.
// GetCommittedState 检索与特定键关联的值，不包含当前执行中的任何变更。
func (s *stateObject) GetCommittedState(key common.Hash) common.Hash {
	// If we have a pending write or clean cached, return that
	// 如果有待提交的写入或干净缓存，返回该值
	if value, pending := s.pendingStorage[key]; pending {
		return value
	}
	if value, cached := s.originStorage[key]; cached {
		return value
	}
	// If the object was destructed in *this* block (and potentially resurrected),
	// the storage has been cleared out, and we should *not* consult the previous
	// database about any storage values. The only possible alternatives are:
	//   1) resurrect happened, and new slot values were set -- those should
	//      have been handles via pendingStorage above.
	//   2) we don't have new values, and can deliver empty response back
	//
	// 如果对象在 *此* 块中被销毁（并可能复活），存储已被清除，不应查询之前的数据库。
	// 可能的替代情况：
	// 1) 复活发生，新槽值已设置——应通过 pendingStorage 处理。
	// 2) 没有新值，返回空响应。
	if _, destructed := s.db.stateObjectsDestruct[s.address]; destructed {
		s.originStorage[key] = common.Hash{} // track the empty slot as origin value 跟踪空槽作为原始值
		return common.Hash{}
	}
	s.db.StorageLoaded++ // 增加存储加载计数

	start := time.Now()                               // 记录开始时间
	value, err := s.db.reader.Storage(s.address, key) // 从数据库读取存储值
	if err != nil {
		s.db.setError(err) // 如果读取失败，设置错误
		return common.Hash{}
	}
	s.db.StorageReads += time.Since(start) // 累加存储读取时间

	// Schedule the resolved storage slots for prefetching if it's enabled.
	// 如果启用预取，则调度已解析的存储槽进行预取
	if s.db.prefetcher != nil && s.data.Root != types.EmptyRootHash {
		err = s.db.prefetcher.prefetch(s.addrHash, s.origin.Root, s.address, nil, []common.Hash{key}, true)
		if err != nil {
			log.Error("Failed to prefetch storage slot", "addr", s.address, "key", key, "err", err) // 记录预取失败日志
		}
	}
	s.originStorage[key] = value // 缓存读取的值
	return value                 // 返回值
}

// SetState updates a value in account storage.
// It returns the previous value
// SetState 更新账户存储中的值，返回前值。
func (s *stateObject) SetState(key, value common.Hash) common.Hash {
	// If the new value is the same as old, don't set. Otherwise, track only the
	// dirty changes, supporting reverting all of it back to no change.
	// 如果新值与旧值相同，不设置。否则，仅跟踪脏变更，支持全部回滚到无变更状态。
	prev, origin := s.getState(key) // 获取当前值和原始值
	if prev == value {
		return prev // 如果值未变，返回前值
	}
	// New value is different, update and journal the change
	// 新值不同，更新并记录变更到日志
	s.db.journal.storageChange(s.address, key, prev, origin)
	s.setState(key, value, origin) // 设置新值
	return prev                    // 返回前值
}

// setState updates a value in account dirty storage. The dirtiness will be
// removed if the value being set equals to the original value.
// setState 更新账户脏存储中的值。如果设置的值等于原始值，则移除脏标记。
func (s *stateObject) setState(key common.Hash, value common.Hash, origin common.Hash) {
	// Storage slot is set back to its original value, undo the dirty marker
	// 如果存储槽被设置为原始值，撤销脏标记
	if value == origin {
		delete(s.dirtyStorage, key) // 删除脏存储条目
		return
	}
	s.dirtyStorage[key] = value // 设置脏存储值
}

// finalise moves all dirty storage slots into the pending area to be hashed or
// committed later. It is invoked at the end of every transaction.
// finalise 将所有脏存储槽移动到待提交区域，以供后续哈希或提交。在每笔交易结束时调用。
func (s *stateObject) finalise() {
	slotsToPrefetch := make([]common.Hash, 0, len(s.dirtyStorage)) // 初始化预取槽列表
	for key, value := range s.dirtyStorage {
		if origin, exist := s.uncommittedStorage[key]; exist && origin == value {
			// The slot is reverted to its original value, delete the entry
			// to avoid thrashing the data structures.
			// 槽恢复到原始值，删除条目以避免数据结构抖动
			delete(s.uncommittedStorage, key)
		} else if exist {
			// The slot is modified to another value and the slot has been
			// tracked for commit, do nothing here.
			// 槽被修改为另一值且已跟踪用于提交，此处无需操作
		} else {
			// The slot is different from its original value and hasn't been
			// tracked for commit yet.
			// 槽与原始值不同且尚未跟踪用于提交
			s.uncommittedStorage[key] = s.GetCommittedState(key) // 记录原始值
			slotsToPrefetch = append(slotsToPrefetch, key)       // Copy needed for closure 添加到预取列表
		}
		// Aggregate the dirty storage slots into the pending area. It might
		// be possible that the value of tracked slot here is same with the
		// one in originStorage (e.g. the slot was modified in tx_a and then
		// modified back in tx_b). We can't blindly remove it from pending
		// map as the dirty slot might have been committed already (before the
		// byzantium fork) and entry is necessary to modify the value back.
		// 将脏存储槽聚合到待提交区域
		s.pendingStorage[key] = value
	}
	// 如果启用预取器且有槽需要预取，则执行预取
	if s.db.prefetcher != nil && len(slotsToPrefetch) > 0 && s.data.Root != types.EmptyRootHash {
		if err := s.db.prefetcher.prefetch(s.addrHash, s.data.Root, s.address, nil, slotsToPrefetch, false); err != nil {
			log.Error("Failed to prefetch slots", "addr", s.address, "slots", len(slotsToPrefetch), "err", err) // 记录预取失败日志
		}
	}
	if len(s.dirtyStorage) > 0 {
		s.dirtyStorage = make(Storage) // 清空脏存储
	}
	// Revoke the flag at the end of the transaction. It finalizes the status
	// of the newly-created object as it's no longer eligible for self-destruct
	// by EIP-6780. For non-newly-created objects, it's a no-op.
	// 在交易结束时撤销标志，完成新创建对象状态，不再符合 EIP-6780 自毁条件
	s.newContract = false
}

// updateTrie is responsible for persisting cached storage changes into the
// object's storage trie. In case the storage trie is not yet loaded, this
// function will load the trie automatically. If any issues arise during the
// loading or updating of the trie, an error will be returned. Furthermore,
// this function will return the mutated storage trie, or nil if there is no
// storage change at all.
//
// It assumes all the dirty storage slots have been finalized before.
//
// updateTrie 负责将缓存的存储变更持久化到对象的存储 trie 中。
// 如果存储 trie 未加载，此函数将自动加载。如果加载或更新 trie 时出现问题，将返回错误。
// 此外，此函数将返回变更后的存储 trie，如果没有存储变更则返回 nil。
//
// 假设所有脏存储槽已在之前完成 finalise。
func (s *stateObject) updateTrie() (Trie, error) {
	// Short circuit if nothing was accessed, don't trigger a prefetcher warning
	// 如果没有访问任何内容，短路返回，不触发预取器警告
	if len(s.uncommittedStorage) == 0 {
		// Nothing was written, so we could stop early. Unless we have both reads
		// and witness collection enabled, in which case we need to fetch the trie.
		// 没有写入，可以提前停止，除非同时启用了读取和见证收集
		if s.db.witness == nil || len(s.originStorage) == 0 {
			return s.trie, nil
		}
	}
	// Retrieve a pretecher populated trie, or fall back to the database. This will
	// block until all prefetch tasks are done, which are needed for witnesses even
	// for unmodified state objects.
	tr := s.getPrefetchedTrie()
	if tr != nil {
		// Prefetcher returned a live trie, swap it out for the current one
		s.trie = tr
	} else {
		// Fetcher not running or empty trie, fallback to the database trie
		var err error
		tr, err = s.getTrie()
		if err != nil {
			s.db.setError(err) // 设置错误
			return nil, err
		}
	}
	// Short circuit if nothing changed, don't bother with hashing anything
	if len(s.uncommittedStorage) == 0 {
		return s.trie, nil
	}
	// Perform trie updates before deletions. This prevents resolution of unnecessary trie nodes
	// in circumstances similar to the following:
	//
	// Consider nodes `A` and `B` who share the same full node parent `P` and have no other siblings.
	// During the execution of a block:
	// - `A` is deleted,
	// - `C` is created, and also shares the parent `P`.
	// If the deletion is handled first, then `P` would be left with only one child, thus collapsed
	// into a shortnode. This requires `B` to be resolved from disk.
	// Whereas if the created node is handled first, then the collapse is avoided, and `B` is not resolved.
	var (
		deletions []common.Hash                                       // 删除列表
		used      = make([]common.Hash, 0, len(s.uncommittedStorage)) // 已使用槽列表
	)
	for key, origin := range s.uncommittedStorage {
		// Skip noop changes, persist actual changes
		value, exist := s.pendingStorage[key]
		if value == origin {
			log.Error("Storage update was noop", "address", s.address, "slot", key) // 记录空操作日志
			continue
		}
		if !exist {
			log.Error("Storage slot is not found in pending area", s.address, "slot", key) // 记录未找到槽日志
			continue
		}
		if (value != common.Hash{}) { // 如果值非空
			if err := tr.UpdateStorage(s.address, key[:], common.TrimLeftZeroes(value[:])); err != nil {
				s.db.setError(err) // 设置错误
				return nil, err
			}
			s.db.StorageUpdated.Add(1) // 增加存储更新计数
		} else {
			deletions = append(deletions, key) // 添加到删除列表
		}
		// Cache the items for preloading
		used = append(used, key) // Copy needed for closure
	}
	for _, key := range deletions {
		if err := tr.DeleteStorage(s.address, key[:]); err != nil {
			s.db.setError(err) // 设置错误
			return nil, err
		}
		s.db.StorageDeleted.Add(1) // 增加存储删除计数
	}
	// 如果启用预取器，标记已使用的槽
	if s.db.prefetcher != nil {
		s.db.prefetcher.used(s.addrHash, s.data.Root, nil, used)
	}
	s.uncommittedStorage = make(Storage) // empties the commit markers
	return tr, nil
}

// updateRoot flushes all cached storage mutations to trie, recalculating the
// new storage trie root.
func (s *stateObject) updateRoot() {
	// Flush cached storage mutations into trie, short circuit if any error
	// is occurred or there is no change in the trie.
	tr, err := s.updateTrie()
	if err != nil || tr == nil {
		return
	}
	s.data.Root = tr.Hash() // 更新存储根
}

// commitStorage overwrites the clean storage with the storage changes and
// fulfills the storage diffs into the given accountUpdate struct.
func (s *stateObject) commitStorage(op *accountUpdate) {
	var (
		buf    = crypto.NewKeccakState()        // 创建 Keccak 状态缓冲区
		encode = func(val common.Hash) []byte { // 编码函数
			if val == (common.Hash{}) {
				return nil // 如果值为空，返回 nil
			}
			blob, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(val[:])) // RLP 编码并移除左侧零
			return blob
		}
	)
	for key, val := range s.pendingStorage {
		// Skip the noop storage changes, it might be possible the value
		// of tracked slot is same in originStorage and pendingStorage
		// map, e.g. the storage slot is modified in tx_a and then reset
		// back in tx_b.
		if val == s.originStorage[key] {
			continue
		}
		hash := crypto.HashData(buf, key[:]) // 计算键的哈希
		if op.storages == nil {
			op.storages = make(map[common.Hash][]byte) // 初始化存储映射
		}
		op.storages[hash] = encode(val) // 存储变更值
		if op.storagesOrigin == nil {
			op.storagesOrigin = make(map[common.Hash][]byte) // 初始化原始存储映射
		}
		op.storagesOrigin[hash] = encode(s.originStorage[key]) // 存储原始值

		// Overwrite the clean value of storage slots
		s.originStorage[key] = val
	}
	s.pendingStorage = make(Storage) // 清空待提交存储
}

// commit obtains the account changes (metadata, storage slots, code) caused by
// state execution along with the dirty storage trie nodes.
//
// Note, commit may run concurrently across all the state objects. Do not assume
// thread-safe access to the statedb.
func (s *stateObject) commit() (*accountUpdate, *trienode.NodeSet, error) {
	// commit the account metadata changes
	op := &accountUpdate{
		address: s.address,                    // 设置地址
		data:    types.SlimAccountRLP(s.data), // RLP 编码当前数据
	}
	if s.origin != nil {
		op.origin = types.SlimAccountRLP(*s.origin) // RLP 编码原始数据
	}
	// commit the contract code if it's modified
	if s.dirtyCode {
		op.code = &contractCode{
			hash: common.BytesToHash(s.CodeHash()), // 设置代码哈希
			blob: s.code,                           // 设置代码内容
		}
		s.dirtyCode = false // reset the dirty flag
	}
	// Commit storage changes and the associated storage trie
	s.commitStorage(op)
	if len(op.storages) == 0 {
		// nothing changed, don't bother to commit the trie
		s.origin = s.data.Copy()
		return op, nil, nil
	}
	root, nodes := s.trie.Commit(false) // 提交 trie 并获取根和节点集
	s.data.Root = root                  // 更新存储根
	s.origin = s.data.Copy()            // 更新原始数据
	return op, nodes, nil               // 返回更新结果、节点集和错误
}

// AddBalance adds amount to s's balance.
// It is used to add funds to the destination account of a transfer.
// returns the previous balance
func (s *stateObject) AddBalance(amount *uint256.Int) uint256.Int {
	// EIP161: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.IsZero() {
		if s.empty() {
			s.touch() // 如果为空且金额为 0，标记触碰
		}
		return *(s.Balance()) // 返回当前余额
	}
	return s.SetBalance(new(uint256.Int).Add(s.Balance(), amount)) // 设置新余额并返回前值
}

// SetBalance sets the balance for the object, and returns the previous balance.
func (s *stateObject) SetBalance(amount *uint256.Int) uint256.Int {
	prev := *s.data.Balance                               // 保存前余额
	s.db.journal.balanceChange(s.address, s.data.Balance) // 记录余额变更
	s.setBalance(amount)                                  // 设置新余额
	return prev                                           // 返回前余额
}

// setBalance 设置余额。
func (s *stateObject) setBalance(amount *uint256.Int) {
	s.data.Balance = amount // 更新余额
}

// deepCopy 创建状态对象的深拷贝。
func (s *stateObject) deepCopy(db *StateDB) *stateObject {
	obj := &stateObject{
		db:                 db,                          // 设置新 StateDB
		address:            s.address,                   // 复制地址
		addrHash:           s.addrHash,                  // 复制地址哈希
		origin:             s.origin,                    // 复制原始数据
		data:               s.data,                      // 复制当前数据
		code:               s.code,                      // 复制代码
		originStorage:      s.originStorage.Copy(),      // 复制原始存储
		pendingStorage:     s.pendingStorage.Copy(),     // 复制待提交存储
		dirtyStorage:       s.dirtyStorage.Copy(),       // 复制脏存储
		uncommittedStorage: s.uncommittedStorage.Copy(), // 复制未提交存储
		dirtyCode:          s.dirtyCode,                 // 复制脏代码标志
		selfDestructed:     s.selfDestructed,            // 复制自毁标志
		newContract:        s.newContract,               // 复制新合约标志
	}
	if s.trie != nil {
		obj.trie = mustCopyTrie(s.trie) // 如果 trie 存在，复制 trie
	}
	return obj // 返回深拷贝对象
}

//
// Attribute accessors
//

// Address returns the address of the contract/account
func (s *stateObject) Address() common.Address {
	return s.address // 返回地址
}

// Code returns the contract code associated with this object, if any.
func (s *stateObject) Code() []byte {
	if len(s.code) != 0 {
		return s.code // 如果代码已缓存，返回
	}
	if bytes.Equal(s.CodeHash(), types.EmptyCodeHash.Bytes()) {
		return nil // 如果代码哈希为空，返回 nil
	}
	// 从数据库读取代码
	code, err := s.db.reader.Code(s.address, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.db.setError(fmt.Errorf("can't load code hash %x: %v", s.CodeHash(), err)) // 设置错误
	}
	if len(code) == 0 {
		s.db.setError(fmt.Errorf("code is not found %x", s.CodeHash())) // 设置错误
	}
	s.code = code // 缓存代码
	return code   // 返回代码
}

// CodeSize returns the size of the contract code associated with this object,
// or zero if none. This method is an almost mirror of Code, but uses a cache
// inside the database to avoid loading codes seen recently.
func (s *stateObject) CodeSize() int {
	if len(s.code) != 0 {
		return len(s.code) // 如果代码已缓存，返回长度
	}
	if bytes.Equal(s.CodeHash(), types.EmptyCodeHash.Bytes()) {
		return 0 // 如果代码哈希为空，返回 0
	}
	// 从数据库读取代码大小
	size, err := s.db.reader.CodeSize(s.address, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.db.setError(fmt.Errorf("can't load code size %x: %v", s.CodeHash(), err)) // 设置错误
	}
	if size == 0 {
		s.db.setError(fmt.Errorf("code is not found %x", s.CodeHash())) // 设置错误
	}
	return size // 返回代码大小
}

// SetCode 设置代码哈希和代码，返回前代码。
func (s *stateObject) SetCode(codeHash common.Hash, code []byte) (prev []byte) {
	prev = slices.Clone(s.code)           // 复制前代码
	s.db.journal.setCode(s.address, prev) // 记录代码变更
	s.setCode(codeHash, code)             // 设置新代码
	return prev                           // 返回前代码
}

// setCode 设置代码和代码哈希。
func (s *stateObject) setCode(codeHash common.Hash, code []byte) {
	s.code = code                 // 设置代码
	s.data.CodeHash = codeHash[:] // 设置代码哈希
	s.dirtyCode = true            // 标记代码为脏
}

// SetNonce 设置 nonce。
func (s *stateObject) SetNonce(nonce uint64) {
	s.db.journal.nonceChange(s.address, s.data.Nonce) // 记录 nonce 变更
	s.setNonce(nonce)                                 // 设置新 nonce
}

// setNonce 设置 nonce。
func (s *stateObject) setNonce(nonce uint64) {
	s.data.Nonce = nonce // 更新 nonce
}

// CodeHash 返回代码哈希。
func (s *stateObject) CodeHash() []byte {
	return s.data.CodeHash // 返回代码哈希
}

// Balance 返回余额。
func (s *stateObject) Balance() *uint256.Int {
	return s.data.Balance // 返回余额
}

// Nonce 返回 nonce。
func (s *stateObject) Nonce() uint64 {
	return s.data.Nonce // 返回 nonce
}

// Root 返回存储根。
func (s *stateObject) Root() common.Hash {
	return s.data.Root // 返回存储根
}
