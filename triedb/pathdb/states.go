// Copyright 2024 The go-ethereum Authors
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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package pathdb

import (
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/exp/maps"
)

// 状态修改: stateSet 是表示以太坊状态在交易执行过程中发生变化的核心数据结构。它记录了哪些账户被创建、修改或删除，以及哪些合约的存储被更改。
// 高效数据管理: 使用 map 可以高效地查找和存储修改过的账户和存储槽。
// 状态迭代: 排序的账户列表和存储槽列表允许按可预测的顺序迭代状态更改，这在某些场景下很有用。
// 状态回滚: StateSetWithOrigin 存储了状态更改之前的原始值，这对于在区块链发生重组时回滚状态至关重要。当一个区块从链中移除时，需要撤销该区块执行导致的状态更改。
// 状态日志: encode 和 decode 方法使得 stateSet 和 StateSetWithOrigin 的内容可以被序列化和反序列化，这对于将状态更改记录到日志中以便在节点崩溃后恢复状态非常重要。

// counter helps in tracking items and their corresponding sizes.
// counter 帮助跟踪条目及其对应的大小。
type counter struct {
	n int
	// 条目数量。
	size int
	// 总大小。
}

// add size to the counter and increase the item counter.
// add 将大小添加到 counter 并增加条目计数器。
func (c *counter) add(size int) {
	c.n++
	c.size += size
}

// report uploads the cached statistics to meters.
// report 将缓存的统计信息上传到 meters。
func (c *counter) report(count, size *metrics.Meter) {
	count.Mark(int64(c.n))
	size.Mark(int64(c.size))
}

// stateSet represents a collection of state modifications associated with a
// transition (e.g., a block execution) or multiple aggregated transitions.
// stateSet 表示与一次转换（例如，区块执行）或多个聚合转换相关联的状态修改集合。
//
// A stateSet can only reside within a diffLayer or the buffer of a diskLayer,
// serving as the envelope for the set. Lock protection is not required for
// accessing or mutating the account set and storage set, as the associated
// envelope is always marked as stale before any mutation is applied. Any
// subsequent state access will be denied due to the stale flag. Therefore,
// state access and mutation won't happen at the same time with guarantee.
// stateSet 只能存在于 diffLayer 或 diskLayer 的缓冲区中，作为该集合的信封。
// 访问或修改账户集合和存储集合不需要锁保护，因为在应用任何修改之前，关联的信封总是被标记为过时的。
// 任何后续的状态访问都将由于过时标志而被拒绝。因此，状态访问和修改不会同时发生，这是有保证的。
type stateSet struct {
	accountData map[common.Hash][]byte // Keyed accounts for direct retrieval (nil means deleted)
	// 用于直接检索的键控账户数据（nil 表示已删除）。
	storageData map[common.Hash]map[common.Hash][]byte // Keyed storage slots for direct retrieval. one per account (nil means deleted)
	// 用于直接检索的键控存储槽。每个账户一个（nil 表示已删除）。
	size uint64 // Memory size of the state data (accountData and storageData)
	// 状态数据的内存大小（accountData 和 storageData）。

	accountListSorted []common.Hash // List of account for iteration. If it exists, it's sorted, otherwise it's nil
	// 用于迭代的账户列表。如果存在，则已排序，否则为 nil。
	storageListSorted map[common.Hash][]common.Hash // List of storage slots for iterated retrievals, one per account. Any existing lists are sorted if non-nil
	// 用于迭代检索的存储槽列表，每个账户一个。任何现有的列表如果非 nil 则已排序。

	// Lock for guarding the two lists above. These lists might be accessed
	// concurrently and lock protection is essential to avoid concurrent
	// slice or map read/write.
	// 用于保护上面两个列表的锁。这些列表可能被并发访问，锁保护对于避免并发的切片或 map 读/写至关重要。
	listLock sync.RWMutex
}

// newStates constructs the state set with the provided account and storage data.
// newStates 使用提供的账户和存储数据构造状态集。
func newStates(accounts map[common.Hash][]byte, storages map[common.Hash]map[common.Hash][]byte) *stateSet {
	// Don't panic for the lazy callers, initialize the nil maps instead.
	// 为了方便调用者，如果传入 nil，则初始化空的 map。
	if accounts == nil {
		accounts = make(map[common.Hash][]byte)
	}
	if storages == nil {
		storages = make(map[common.Hash]map[common.Hash][]byte)
	}
	s := &stateSet{
		accountData:       accounts,
		storageData:       storages,
		storageListSorted: make(map[common.Hash][]common.Hash),
	}
	s.size = s.check()
	return s
}

// account returns the account data associated with the specified address hash.
// account 返回与指定地址哈希关联的账户数据。
func (s *stateSet) account(hash common.Hash) ([]byte, bool) {
	// If the account is known locally, return it
	// 如果本地已知该账户，则返回它。
	if data, ok := s.accountData[hash]; ok {
		return data, true
	}
	return nil, false // account is unknown in this set
	// 该集合中未知此账户。
}

// mustAccount returns the account data associated with the specified address
// hash. The difference is this function will return an error if the account
// is not found.
// mustAccount 返回与指定地址哈希关联的账户数据。不同之处在于如果找不到该账户，此函数将返回错误。
func (s *stateSet) mustAccount(hash common.Hash) ([]byte, error) {
	// If the account is known locally, return it
	// 如果本地已知该账户，则返回它。
	if data, ok := s.accountData[hash]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("account is not found, %x", hash)
	// 找不到账户。
}

// storage returns the storage slot associated with the specified address hash
// and storage key hash.
// storage 返回与指定地址哈希和存储键哈希关联的存储槽。
func (s *stateSet) storage(accountHash, storageHash common.Hash) ([]byte, bool) {
	// If the account is known locally, try to resolve the slot locally
	// 如果本地已知该账户，则尝试在本地解析该槽。
	if storage, ok := s.storageData[accountHash]; ok {
		if data, ok := storage[storageHash]; ok {
			return data, true
		}
	}
	return nil, false // storage is unknown in this set
	// 该集合中未知此存储槽。
}

// mustStorage returns the storage slot associated with the specified address
// hash and storage key hash. The difference is this function will return an
// error if the storage slot is not found.
// mustStorage 返回与指定地址哈希和存储键哈希关联的存储槽。不同之处在于如果找不到该存储槽，此函数将返回错误。
func (s *stateSet) mustStorage(accountHash, storageHash common.Hash) ([]byte, error) {
	// If the account is known locally, try to resolve the slot locally
	// 如果本地已知该账户，则尝试在本地解析该槽。
	if storage, ok := s.storageData[accountHash]; ok {
		if data, ok := storage[storageHash]; ok {
			return data, nil
		}
	}
	return nil, fmt.Errorf("storage slot is not found, %x %x", accountHash, storageHash)
	// 找不到存储槽。
}

// check sanitizes accounts and storage slots to ensure the data validity.
// Additionally, it computes the total memory size occupied by the maps.
// check 清理账户和存储槽以确保数据有效性。此外，它还计算 map 占用的总内存大小。
func (s *stateSet) check() uint64 {
	var size int
	for _, blob := range s.accountData {
		size += common.HashLength + len(blob)
	}
	for accountHash, slots := range s.storageData {
		if slots == nil {
			panic(fmt.Sprintf("storage %#x nil", accountHash)) // nil slots is not permitted
			// 不允许 nil 的槽。
		}
		for _, blob := range slots {
			size += 2*common.HashLength + len(blob)
		}
	}
	return uint64(size)
}

// accountList returns a sorted list of all accounts in this state set, including
// the deleted ones.
// accountList 返回此状态集中所有账户（包括已删除的账户）的排序列表。
//
// Note, the returned slice is not a copy, so do not modify it.
// 注意，返回的切片不是副本，请不要修改它。
func (s *stateSet) accountList() []common.Hash {
	// If an old list already exists, return it
	// 如果旧列表已存在，则返回它。
	s.listLock.RLock()
	list := s.accountListSorted
	s.listLock.RUnlock()

	if list != nil {
		return list
	}
	// No old sorted account list exists, generate a new one. It's possible that
	// multiple threads waiting for the write lock may regenerate the list
	// multiple times, which is acceptable.
	// 不存在旧的排序账户列表，生成一个新的。等待写锁的多个线程可能会多次重新生成列表，这是可以接受的。
	s.listLock.Lock()
	defer s.listLock.Unlock()

	list = maps.Keys(s.accountData)
	slices.SortFunc(list, common.Hash.Cmp)
	s.accountListSorted = list
	return list
}

// StorageList returns a sorted list of all storage slot hashes in this state set
// for the given account. The returned list will include the hash of deleted
// storage slot.
// StorageList 返回给定账户在此状态集中所有存储槽哈希的排序列表。返回的列表将包括已删除存储槽的哈希。
//
// Note, the returned slice is not a copy, so do not modify it.
// 注意，返回的切片不是副本，请不要修改它。
func (s *stateSet) storageList(accountHash common.Hash) []common.Hash {
	s.listLock.RLock()
	if _, ok := s.storageData[accountHash]; !ok {
		// Account not tracked by this layer
		// 该层未跟踪此账户。
		s.listLock.RUnlock()
		return nil
	}
	// If an old list already exists, return it
	// 如果旧列表已存在，则返回它。
	if list, exist := s.storageListSorted[accountHash]; exist {
		s.listLock.RUnlock()
		return list // the cached list can't be nil
		// 缓存的列表不能为 nil。
	}
	s.listLock.RUnlock()

	// No old sorted account list exists, generate a new one. It's possible that
	// multiple threads waiting for the write lock may regenerate the list
	// multiple times, which is acceptable.
	// 不存在旧的排序账户列表，生成一个新的。等待写锁的多个线程可能会多次重新生成列表，这是可以接受的。
	s.listLock.Lock()
	defer s.listLock.Unlock()

	list := maps.Keys(s.storageData[accountHash])
	slices.SortFunc(list, common.Hash.Cmp)
	s.storageListSorted[accountHash] = list
	return list
}

// clearLists invalidates the cached account list and storage lists.
// clearLists 使缓存的账户列表和存储列表无效。
func (s *stateSet) clearLists() {
	s.listLock.Lock()
	defer s.listLock.Unlock()

	s.accountListSorted = nil
	s.storageListSorted = make(map[common.Hash][]common.Hash)
}

// merge integrates the accounts and storages from the external set into the
// local set, ensuring the combined set reflects the combined state of both.
// merge 将外部集合中的账户和存储集成到本地集合中，确保合并后的集合反映了两者的组合状态。
//
// The stateSet supplied as parameter set will not be mutated by this operation,
// as it may still be referenced by other layers.
// 作为参数提供的 stateSet 不会被此操作修改，因为它可能仍被其他层引用。
func (s *stateSet) merge(other *stateSet) {
	var (
		delta             int
		accountOverwrites counter
		storageOverwrites counter
	)
	// Apply the updated account data
	// 应用更新的账户数据。
	for accountHash, data := range other.accountData {
		if origin, ok := s.accountData[accountHash]; ok {
			delta += len(data) - len(origin)
			accountOverwrites.add(common.HashLength + len(origin))
		} else {
			delta += common.HashLength + len(data)
		}
		s.accountData[accountHash] = data
	}
	// Apply all the updated storage slots (individually)
	// 应用所有更新的存储槽（单独地）。
	for accountHash, storage := range other.storageData {
		// If storage didn't exist in the set, overwrite blindly
		// 如果存储在集合中不存在，则盲目覆盖。
		if _, ok := s.storageData[accountHash]; !ok {
			// To prevent potential concurrent map read/write issues, allocate a
			// new map for the storage instead of claiming it directly from the
			// passed external set. Even after merging, the slots belonging to the
			// external state set remain accessible, so ownership of the map should
			// not be taken, and any mutation on it should be avoided.
			// 为了防止潜在的并发 map 读/写问题，为存储分配一个新的 map，而不是直接从传递的外部集合中获取。
			// 即使在合并之后，属于外部状态集的槽仍然可以访问，因此不应该取得 map 的所有权，并且应该避免对其进行任何修改。
			slots := make(map[common.Hash][]byte, len(storage))
			for storageHash, data := range storage {
				slots[storageHash] = data
				delta += 2*common.HashLength + len(data)
			}
			s.storageData[accountHash] = slots
			continue
		}
		// Storage exists in both local and external set, merge the slots
		// 存储存在于本地和外部集合中，合并槽。
		slots := s.storageData[accountHash]
		for storageHash, data := range storage {
			if origin, ok := slots[storageHash]; ok {
				delta += len(data) - len(origin)
				storageOverwrites.add(2*common.HashLength + len(origin))
			} else {
				delta += 2*common.HashLength + len(data)
			}
			slots[storageHash] = data
		}
	}
	accountOverwrites.report(gcAccountMeter, gcAccountBytesMeter)
	storageOverwrites.report(gcStorageMeter, gcStorageBytesMeter)
	s.clearLists()
	s.updateSize(delta)
}

// revertTo takes the original value of accounts and storages as input and reverts
// the latest state transition applied on the state set.
// revertTo 接受账户和存储的原始值作为输入，并撤销应用于状态集的最新状态转换。
//
// Notably, this operation may result in the set containing more entries after a
// revert. For example, if account x did not exist and was created during transition
// w, reverting w will retain an x=nil entry in the set. And also if account x along
// with its storage slots was deleted in the transition w, reverting w will retain
// a list of additional storage slots with their original value.
// 值得注意的是，此操作可能会导致在还原后集合包含更多条目。例如，如果账户 x 不存在并且在转换 w 期间创建，
// 则还原 w 将在集合中保留一个 x=nil 条目。并且，如果在转换 w 中删除了账户 x 及其存储槽，则还原 w 将保留一个包含其原始值的额外存储槽列表。
func (s *stateSet) revertTo(accountOrigin map[common.Hash][]byte, storageOrigin map[common.Hash]map[common.Hash][]byte) {
	var delta int // size tracking
	for addrHash, blob := range accountOrigin {
		data, ok := s.accountData[addrHash]
		if !ok {
			panic(fmt.Sprintf("non-existent account for reverting, %x", addrHash))
		}
		if len(data) == 0 && len(blob) == 0 {
			panic(fmt.Sprintf("invalid account mutation (null to null), %x", addrHash))
		}
		delta += len(blob) - len(data)
		s.accountData[addrHash] = blob
	}
	// Overwrite the storage data with original value blindly
	// 盲目地用原始值覆盖存储数据。
	for addrHash, storage := range storageOrigin {
		slots := s.storageData[addrHash]
		if len(slots) == 0 {
			panic(fmt.Sprintf("non-existent storage set for reverting, %x", addrHash))
		}
		for storageHash, blob := range storage {
			data, ok := slots[storageHash]
			if !ok {
				panic(fmt.Sprintf("non-existent storage slot for reverting, %x-%x", addrHash, storageHash))
			}
			if len(blob) == 0 && len(data) == 0 {
				panic(fmt.Sprintf("invalid storage slot mutation (null to null), %x-%x", addrHash, storageHash))
			}
			delta += len(blob) - len(data)
			slots[storageHash] = blob
		}
	}
	s.clearLists()
	s.updateSize(delta)
}

// updateSize updates the total cache size by the given delta.
// updateSize 按给定的增量更新总缓存大小。
func (s *stateSet) updateSize(delta int) {
	size := int64(s.size) + int64(delta)
	if size >= 0 {
		s.size = uint64(size)
		return
	}
	log.Error("Stateset size underflow", "prev", common.StorageSize(s.size), "delta", common.StorageSize(delta))
	s.size = 0
}

// encode serializes the content of state set into the provided writer.
// encode 将状态集的内容序列化到提供的 writer 中。
func (s *stateSet) encode(w io.Writer) error {
	// Encode accounts
	// 编码账户。
	type accounts struct {
		AddrHashes []common.Hash
		Accounts   [][]byte
	}
	var enc accounts
	for addrHash, blob := range s.accountData {
		enc.AddrHashes = append(enc.AddrHashes, addrHash)
		enc.Accounts = append(enc.Accounts, blob)
	}
	if err := rlp.Encode(w, enc); err != nil {
		return err
	}
	// Encode storages
	// 编码存储。
	type Storage struct {
		AddrHash common.Hash
		Keys     []common.Hash
		Vals     [][]byte
	}
	storages := make([]Storage, 0, len(s.storageData))
	for addrHash, slots := range s.storageData {
		keys := make([]common.Hash, 0, len(slots))
		vals := make([][]byte, 0, len(slots))
		for key, val := range slots {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storages = append(storages, Storage{
			AddrHash: addrHash,
			Keys:     keys,
			Vals:     vals,
		})
	}
	return rlp.Encode(w, storages)
}

// decode deserializes the content from the rlp stream into the state set.
// decode 从 rlp 流中反序列化内容到状态集。
func (s *stateSet) decode(r *rlp.Stream) error {
	type accounts struct {
		AddrHashes []common.Hash
		Accounts   [][]byte
	}
	var (
		dec        accounts
		accountSet = make(map[common.Hash][]byte)
	)
	if err := r.Decode(&dec); err != nil {
		return fmt.Errorf("load diff accounts: %v", err)
	}
	for i := 0; i < len(dec.AddrHashes); i++ {
		accountSet[dec.AddrHashes[i]] = dec.Accounts[i]
	}
	s.accountData = accountSet

	// Decode storages
	// 解码存储。
	type storage struct {
		AddrHash common.Hash
		Keys     []common.Hash
		Vals     [][]byte
	}
	var (
		storages   []storage
		storageSet = make(map[common.Hash]map[common.Hash][]byte)
	)
	if err := r.Decode(&storages); err != nil {
		return fmt.Errorf("load diff storage: %v", err)
	}
	for _, entry := range storages {
		storageSet[entry.AddrHash] = make(map[common.Hash][]byte, len(entry.Keys))
		for i := 0; i < len(entry.Keys); i++ {
			storageSet[entry.AddrHash][entry.Keys[i]] = entry.Vals[i]
		}
	}
	s.storageData = storageSet
	s.storageListSorted = make(map[common.Hash][]common.Hash)

	s.size = s.check()
	return nil
}

// reset clears all cached state data, including any optional sorted lists that
// may have been generated.
// reset 清除所有缓存的状态数据，包括任何可能已生成的可选排序列表。
func (s *stateSet) reset() {
	s.accountData = make(map[common.Hash][]byte)
	s.storageData = make(map[common.Hash]map[common.Hash][]byte)
	s.size = 0
	s.accountListSorted = nil
	s.storageListSorted = make(map[common.Hash][]common.Hash)
}

// dbsize returns the approximate size for db write.
// dbsize 返回数据库写入的近似大小。
//
// nolint:unused
func (s *stateSet) dbsize() int {
	m := len(s.accountData) * len(rawdb.SnapshotAccountPrefix)
	for _, slots := range s.storageData {
		m += len(slots) * len(rawdb.SnapshotStoragePrefix)
	}
	return m + int(s.size)
}

// StateSetWithOrigin wraps the state set with additional original values of the
// mutated states.
// StateSetWithOrigin 使用被修改状态的额外原始值包装状态集。
type StateSetWithOrigin struct {
	*stateSet

	// AccountOrigin represents the account data before the state transition,
	// corresponding to both the accountData and destructSet. It's keyed by the
	// account address. The nil value means the account was not present before.
	// AccountOrigin 表示状态转换之前的账户数据，对应于 accountData 和 destructSet。
	// 它以账户地址为键。nil 值表示该账户之前不存在。
	accountOrigin map[common.Address][]byte

	// StorageOrigin represents the storage data before the state transition,
	// corresponding to storageData and deleted slots of destructSet. It's keyed
	// by the account address and slot key hash. The nil value means the slot was
	// not present.
	// StorageOrigin 表示状态转换之前的存储数据，对应于 storageData 和 destructSet 中已删除的槽。
	// 它以账户地址和槽键哈希为键。nil 值表示该槽之前不存在。
	storageOrigin map[common.Address]map[common.Hash][]byte

	// Memory size of the state data (accountOrigin and storageOrigin)
	// 状态数据的内存大小（accountOrigin 和 storageOrigin）。
	size uint64
}

// NewStateSetWithOrigin constructs the state set with the provided data.
// NewStateSetWithOrigin 使用提供的数据构造状态集。
func NewStateSetWithOrigin(accounts map[common.Hash][]byte, storages map[common.Hash]map[common.Hash][]byte, accountOrigin map[common.Address][]byte, storageOrigin map[common.Address]map[common.Hash][]byte) *StateSetWithOrigin {
	// Don't panic for the lazy callers, initialize the nil maps instead.
	// 为了方便调用者，如果传入 nil，则初始化空的 map。
	if accountOrigin == nil {
		accountOrigin = make(map[common.Address][]byte)
	}
	if storageOrigin == nil {
		storageOrigin = make(map[common.Address]map[common.Hash][]byte)
	}
	// Count the memory size occupied by the set. Note that each slot key here
	// uses 2*common.HashLength to keep consistent with the calculation method
	// of stateSet.
	// 计算集合占用的内存大小。请注意，这里的每个槽键都使用 2*common.HashLength，以与 stateSet 的计算方法保持一致。
	var size int
	for _, data := range accountOrigin {
		size += common.HashLength + len(data)
	}
	for _, slots := range storageOrigin {
		for _, data := range slots {
			size += 2*common.HashLength + len(data)
		}
	}
	set := newStates(accounts, storages)
	return &StateSetWithOrigin{
		stateSet:      set,
		accountOrigin: accountOrigin,
		storageOrigin: storageOrigin,
		size:          set.size + uint64(size),
	}
}

// encode serializes the content of state set into the provided writer.
// encode 将状态集的内容序列化到提供的 writer 中。
func (s *StateSetWithOrigin) encode(w io.Writer) error {
	// Encode state set
	// 编码状态集。
	if err := s.stateSet.encode(w); err != nil {
		return err
	}
	// Encode accounts
	// 编码账户。
	type Accounts struct {
		Addresses []common.Address
		Accounts  [][]byte
	}
	var accounts Accounts
	for address, blob := range s.accountOrigin {
		accounts.Addresses = append(accounts.Addresses, address)
		accounts.Accounts = append(accounts.Accounts, blob)
	}
	if err := rlp.Encode(w, accounts); err != nil {
		return err
	}
	// Encode storages
	// 编码存储。
	type Storage struct {
		Address common.Address
		Keys    []common.Hash
		Vals    [][]byte
	}
	storages := make([]Storage, 0, len(s.storageOrigin))
	for address, slots := range s.storageOrigin {
		keys := make([]common.Hash, 0, len(slots))
		vals := make([][]byte, 0, len(slots))
		for key, val := range slots {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storages = append(storages, Storage{Address: address, Keys: keys, Vals: vals})
	}
	return rlp.Encode(w, storages)
}

// decode deserializes the content from the rlp stream into the state set.
// decode 从 rlp 流中反序列化内容到状态集。
func (s *StateSetWithOrigin) decode(r *rlp.Stream) error {
	if s.stateSet == nil {
		s.stateSet = &stateSet{}
	}
	if err := s.stateSet.decode(r); err != nil {
		return err
	}
	// Decode account origin
	// 解码账户原始值。
	type Accounts struct {
		Addresses []common.Address
		Accounts  [][]byte
	}
	var (
		accounts   Accounts
		accountSet = make(map[common.Address][]byte)
	)
	if err := r.Decode(&accounts); err != nil {
		return fmt.Errorf("load diff account origin set: %v", err)
	}
	for i := 0; i < len(accounts.Accounts); i++ {
		accountSet[accounts.Addresses[i]] = accounts.Accounts[i]
	}
	s.accountOrigin = accountSet

	// Decode storage origin
	// 解码存储原始值。
	type Storage struct {
		Address common.Address
		Keys    []common.Hash
		Vals    [][]byte
	}
	var (
		storages   []Storage
		storageSet = make(map[common.Address]map[common.Hash][]byte)
	)
	if err := r.Decode(&storages); err != nil {
		return fmt.Errorf("load diff storage origin: %v", err)
	}
	for _, storage := range storages {
		storageSet[storage.Address] = make(map[common.Hash][]byte)
		for i := 0; i < len(storage.Keys); i++ {
			storageSet[storage.Address][storage.Keys[i]] = storage.Vals[i]
		}
	}
	s.storageOrigin = storageSet
	return nil
}
