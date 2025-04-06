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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package state

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/database"
)

// 状态存储: 以太坊的状态（账户余额、合约代码、存储等）存储在 Merkle Patricia Trie 这种高效的数据结构中。trieReader 用于直接与这种 Trie 结构交互。
// 状态快照: 为了提高同步速度，以太坊客户端通常会使用状态快照。flatReader 可能是用于读取这些快照的优化表示。
// 代码存储: 合约的字节码存储在专门的数据库中，通过其哈希值进行索引。cachingCodeReader 负责从这个存储中检索代码，并使用缓存来提高性能。
// 分层读取: multiStateReader 提供了一种灵活的方式来组合不同的状态读取器。例如，可以先尝试从内存中的缓存读取，然后从快照读取，最后从 Trie 数据库读取，从而实现性能和数据一致性的平衡。
// 接口驱动的设计: 这些接口的定义使得 go-ethereum 的状态访问逻辑具有高度的灵活性和可扩展性。不同的状态后端或优化策略可以通过实现这些接口来集成到系统中。

// ContractCodeReader defines the interface for accessing contract code.
// ContractCodeReader 定义了访问合约代码的接口。
type ContractCodeReader interface {
	// Code retrieves a particular contract's code.
	// Code 检索特定合约的代码。
	//
	// - Returns nil code along with nil error if the requested contract code
	//   doesn't exist
	//   如果请求的合约代码不存在，则返回 nil 代码和 nil 错误。
	// - Returns an error only if an unexpected issue occurs
	//   只有在发生意外问题时才返回错误。
	Code(addr common.Address, codeHash common.Hash) ([]byte, error)

	// CodeSize retrieves a particular contracts code's size.
	// CodeSize 检索特定合约代码的大小。
	//
	// - Returns zero code size along with nil error if the requested contract code
	//   doesn't exist
	//   如果请求的合约代码不存在，则返回零代码大小和 nil 错误。
	// - Returns an error only if an unexpected issue occurs
	//   只有在发生意外问题时才返回错误。
	CodeSize(addr common.Address, codeHash common.Hash) (int, error)
}

// StateReader defines the interface for accessing accounts and storage slots
// associated with a specific state.
// StateReader 定义了访问与特定状态关联的账户和存储槽的接口。
type StateReader interface {
	// Account retrieves the account associated with a particular address.
	// Account 检索与特定地址关联的账户。
	//
	// - Returns a nil account if it does not exist
	//   如果账户不存在则返回 nil。
	// - Returns an error only if an unexpected issue occurs
	//   只有在发生意外问题时才返回错误。
	// - The returned account is safe to modify after the call
	//   返回的账户在调用后可以安全地修改。
	Account(addr common.Address) (*types.StateAccount, error)

	// Storage retrieves the storage slot associated with a particular account
	// address and slot key.
	// Storage 检索与特定账户地址和槽位键关联的存储槽。
	//
	// - Returns an empty slot if it does not exist
	//   如果不存在则返回一个空槽。
	// - Returns an error only if an unexpected issue occurs
	//   只有在发生意外问题时才返回错误。
	// - The returned storage slot is safe to modify after the call
	//   返回的存储槽在调用后可以安全地修改。
	Storage(addr common.Address, slot common.Hash) (common.Hash, error)
}

// Reader defines the interface for accessing accounts, storage slots and contract
// code associated with a specific state.
// Reader 定义了访问与特定状态关联的账户、存储槽和合约代码的接口。
type Reader interface {
	ContractCodeReader
	StateReader
}

// cachingCodeReader implements ContractCodeReader, accessing contract code either in
// local key-value store or the shared code cache.
// cachingCodeReader 实现了 ContractCodeReader 接口，通过本地键值存储或共享代码缓存访问合约代码。
type cachingCodeReader struct {
	db ethdb.KeyValueReader

	// These caches could be shared by multiple code reader instances,
	// they are natively thread-safe.
	// 这些缓存可以被多个代码读取器实例共享，它们本身是线程安全的。
	codeCache     *lru.SizeConstrainedCache[common.Hash, []byte]
	codeSizeCache *lru.Cache[common.Hash, int]
}

// newCachingCodeReader constructs the code reader.
// newCachingCodeReader 构造代码读取器。
func newCachingCodeReader(db ethdb.KeyValueReader, codeCache *lru.SizeConstrainedCache[common.Hash, []byte], codeSizeCache *lru.Cache[common.Hash, int]) *cachingCodeReader {
	// newCachingCodeReader 函数创建一个新的 cachingCodeReader 实例。
	return &cachingCodeReader{
		db:            db,
		codeCache:     codeCache,
		codeSizeCache: codeSizeCache,
	}
}

// Code implements ContractCodeReader, retrieving a particular contract's code.
// If the contract code doesn't exist, no error will be returned.
// Code 实现了 ContractCodeReader 接口，检索特定合约的代码。
// 如果合约代码不存在，则不会返回错误。
func (r *cachingCodeReader) Code(addr common.Address, codeHash common.Hash) ([]byte, error) {
	// Code 方法从缓存或数据库中检索合约代码。
	code, _ := r.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code, nil
	}
	code = rawdb.ReadCode(r.db, codeHash)
	if len(code) > 0 {
		r.codeCache.Add(codeHash, code)
		r.codeSizeCache.Add(codeHash, len(code))
	}
	return code, nil
}

// CodeSize implements ContractCodeReader, retrieving a particular contracts code's size.
// If the contract code doesn't exist, no error will be returned.
// CodeSize 实现了 ContractCodeReader 接口，检索特定合约代码的大小。
// 如果合约代码不存在，则不会返回错误。
func (r *cachingCodeReader) CodeSize(addr common.Address, codeHash common.Hash) (int, error) {
	// CodeSize 方法从缓存或数据库中检索合约代码的大小。
	if cached, ok := r.codeSizeCache.Get(codeHash); ok {
		return cached, nil
	}
	code, err := r.Code(addr, codeHash)
	if err != nil {
		return 0, err
	}
	return len(code), nil
}

// flatReader wraps a database StateReader.
// flatReader 封装了一个数据库 StateReader。
type flatReader struct {
	reader database.StateReader
	buff   crypto.KeccakState
}

// newFlatReader constructs a state reader with on the given state root.
// newFlatReader 使用给定的状态根构造一个状态读取器。
func newFlatReader(reader database.StateReader) *flatReader {
	// newFlatReader 函数创建一个新的 flatReader 实例。
	return &flatReader{
		reader: reader,
		buff:   crypto.NewKeccakState(),
	}
}

// Account implements StateReader, retrieving the account specified by the address.
//
// An error will be returned if the associated snapshot is already stale or
// the requested account is not yet covered by the snapshot.
//
// The returned account might be nil if it's not existent.
// Account 实现了 StateReader 接口，检索由地址指定的账户。
//
// 如果关联的快照已经过时或请求的账户尚未被快照覆盖，则会返回错误。
//
// 如果账户不存在，则返回的账户可能为 nil。
func (r *flatReader) Account(addr common.Address) (*types.StateAccount, error) {
	// Account 方法从底层的数据库状态读取器中检索账户信息。
	account, err := r.reader.Account(crypto.HashData(r.buff, addr.Bytes()))
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, nil
	}
	acct := &types.StateAccount{
		Nonce:    account.Nonce,
		Balance:  account.Balance,
		CodeHash: account.CodeHash,
		Root:     common.BytesToHash(account.Root),
	}
	if len(acct.CodeHash) == 0 {
		acct.CodeHash = types.EmptyCodeHash.Bytes()
	}
	if acct.Root == (common.Hash{}) {
		acct.Root = types.EmptyRootHash
	}
	return acct, nil
}

// Storage implements StateReader, retrieving the storage slot specified by the
// address and slot key.
//
// An error will be returned if the associated snapshot is already stale or
// the requested storage slot is not yet covered by the snapshot.
//
// The returned storage slot might be empty if it's not existent.
// Storage 实现了 StateReader 接口，检索由地址和槽位键指定的存储槽。
//
// 如果关联的快照已经过时或请求的存储槽尚未被快照覆盖，则会返回错误。
//
// 如果存储槽不存在，则返回的存储槽可能为空。
func (r *flatReader) Storage(addr common.Address, key common.Hash) (common.Hash, error) {
	// Storage 方法从底层的数据库状态读取器中检索存储槽信息。
	addrHash := crypto.HashData(r.buff, addr.Bytes())
	slotHash := crypto.HashData(r.buff, key.Bytes())
	ret, err := r.reader.Storage(addrHash, slotHash)
	if err != nil {
		return common.Hash{}, err
	}
	if len(ret) == 0 {
		return common.Hash{}, nil
	}
	// Perform the rlp-decode as the slot value is RLP-encoded in the state
	// snapshot.
	// 由于槽位值在状态快照中是 RLP 编码的，因此执行 RLP 解码。
	_, content, _, err := rlp.Split(ret)
	if err != nil {
		return common.Hash{}, err
	}
	var value common.Hash
	value.SetBytes(content)
	return value, nil
}

// trieReader implements the StateReader interface, providing functions to access
// state from the referenced trie.
// trieReader 实现了 StateReader 接口，提供了从引用的 Trie 访问状态的函数。
type trieReader struct {
	root common.Hash // State root which uniquely represent a state
	// root 唯一表示状态的状态根
	db *triedb.Database // Database for loading trie
	// db 用于加载 Trie 的数据库
	buff crypto.KeccakState // Buffer for keccak256 hashing
	// buff 用于 keccak256 哈希的缓冲区
	mainTrie Trie // Main trie, resolved in constructor
	// mainTrie 主要的 Trie，在构造函数中解析
	subRoots map[common.Address]common.Hash // Set of storage roots, cached when the account is resolved
	// subRoots 存储根的集合，在解析账户时缓存
	subTries map[common.Address]Trie // Group of storage tries, cached when it's resolved
	// subTries 存储 Trie 的集合，在解析时缓存
}

// trieReader constructs a trie reader of the specific state. An error will be
// returned if the associated trie specified by root is not existent.
// trieReader 构造特定状态的 Trie 读取器。如果指定的根关联的 Trie 不存在，则会返回错误。
func newTrieReader(root common.Hash, db *triedb.Database, cache *utils.PointCache) (*trieReader, error) {
	// newTrieReader 函数创建一个新的 trieReader 实例。
	var (
		tr  Trie
		err error
	)
	if !db.IsVerkle() {
		tr, err = trie.NewStateTrie(trie.StateTrieID(root), db)
	} else {
		tr, err = trie.NewVerkleTrie(root, db, cache)
	}
	if err != nil {
		return nil, err
	}
	return &trieReader{
		root:     root,
		db:       db,
		buff:     crypto.NewKeccakState(),
		mainTrie: tr,
		subRoots: make(map[common.Address]common.Hash),
		subTries: make(map[common.Address]Trie),
	}, nil
}

// Account implements StateReader, retrieving the account specified by the address.
//
// An error will be returned if the trie state is corrupted. An nil account
// will be returned if it's not existent in the trie.
// Account 实现了 StateReader 接口，检索由地址指定的账户。
//
// 如果 Trie 状态损坏，则会返回错误。如果 Trie 中不存在该账户，则返回 nil 账户。
func (r *trieReader) Account(addr common.Address) (*types.StateAccount, error) {
	// Account 方法从状态 Trie 中检索账户信息。
	account, err := r.mainTrie.GetAccount(addr)
	if err != nil {
		return nil, err
	}
	if account == nil {
		r.subRoots[addr] = types.EmptyRootHash
	} else {
		r.subRoots[addr] = account.Root
	}
	return account, nil
}

// Storage implements StateReader, retrieving the storage slot specified by the
// address and slot key.
//
// An error will be returned if the trie state is corrupted. An empty storage
// slot will be returned if it's not existent in the trie.
// Storage 实现了 StateReader 接口，检索由地址和槽位键指定的存储槽。
//
// 如果 Trie 状态损坏，则会返回错误。如果 Trie 中不存在该存储槽，则返回一个空存储槽。
func (r *trieReader) Storage(addr common.Address, key common.Hash) (common.Hash, error) {
	// Storage 方法从状态 Trie 中检索存储槽信息。
	var (
		tr    Trie
		found bool
		value common.Hash
	)
	if r.db.IsVerkle() {
		tr = r.mainTrie
	} else {
		tr, found = r.subTries[addr]
		if !found {
			root, ok := r.subRoots[addr]

			// The storage slot is accessed without account caching. It's unexpected
			// behavior but try to resolve the account first anyway.
			// 存储槽在没有账户缓存的情况下被访问。这是一个意外的行为，但无论如何先尝试解析账户。
			if !ok {
				_, err := r.Account(addr)
				if err != nil {
					return common.Hash{}, err
				}
				root = r.subRoots[addr]
			}
			var err error
			tr, err = trie.NewStateTrie(trie.StorageTrieID(r.root, crypto.HashData(r.buff, addr.Bytes()), root), r.db)
			if err != nil {
				return common.Hash{}, err
			}
			r.subTries[addr] = tr
		}
	}
	ret, err := tr.GetStorage(addr, key.Bytes())
	if err != nil {
		return common.Hash{}, err
	}
	value.SetBytes(ret)
	return value, nil
}

// multiStateReader is the aggregation of a list of StateReader interface,
// providing state access by leveraging all readers. The checking priority
// is determined by the position in the reader list.
// multiStateReader 是 StateReader 接口列表的聚合，通过利用所有读取器提供状态访问。
// 检查优先级由读取器列表中的位置决定。
type multiStateReader struct {
	readers []StateReader // List of state readers, sorted by checking priority
	// readers 状态读取器列表，按检查优先级排序
}

// newMultiStateReader constructs a multiStateReader instance with the given
// readers. The priority among readers is assumed to be sorted. Note, it must
// contain at least one reader for constructing a multiStateReader.
// newMultiStateReader 使用给定的读取器构造一个 multiStateReader 实例。
// 假定读取器之间的优先级已排序。注意，它必须包含至少一个读取器才能构造 multiStateReader。
func newMultiStateReader(readers ...StateReader) (*multiStateReader, error) {
	// newMultiStateReader 函数创建一个新的 multiStateReader 实例。
	if len(readers) == 0 {
		return nil, errors.New("empty reader set")
	}
	return &multiStateReader{
		readers: readers,
	}, nil
}

// Account implementing StateReader interface, retrieving the account associated
// with a particular address.
//
// - Returns a nil account if it does not exist
// - Returns an error only if an unexpected issue occurs
// - The returned account is safe to modify after the call
// Account 实现了 StateReader 接口，检索与特定地址关联的账户。
//
// - 如果账户不存在则返回 nil。
// - 只有在发生意外问题时才返回错误。
// - 返回的账户在调用后可以安全地修改。
func (r *multiStateReader) Account(addr common.Address) (*types.StateAccount, error) {
	// Account 方法遍历内部的 StateReader 列表，并返回第一个成功检索到的账户。
	var errs []error
	for _, reader := range r.readers {
		acct, err := reader.Account(addr)
		if err == nil {
			return acct, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// Storage implementing StateReader interface, retrieving the storage slot
// associated with a particular account address and slot key.
//
// - Returns an empty slot if it does not exist
// - Returns an error only if an unexpected issue occurs
// - The returned storage slot is safe to modify after the call
// Storage 实现了 StateReader 接口，检索与特定账户地址和槽位键关联的存储槽。
//
// - 如果不存在则返回一个空槽。
// - 只有在发生意外问题时才返回错误。
// - 返回的存储槽在调用后可以安全地修改。
func (r *multiStateReader) Storage(addr common.Address, slot common.Hash) (common.Hash, error) {
	// Storage 方法遍历内部的 StateReader 列表，并返回第一个成功检索到的存储槽。
	var errs []error
	for _, reader := range r.readers {
		slot, err := reader.Storage(addr, slot)
		if err == nil {
			return slot, nil
		}
		errs = append(errs, err)
	}
	return common.Hash{}, errors.Join(errs...)
}

// reader is the wrapper of ContractCodeReader and StateReader interface.
// reader 是 ContractCodeReader 和 StateReader 接口的包装器。
type reader struct {
	ContractCodeReader
	StateReader
}

// newReader constructs a reader with the supplied code reader and state reader.
// newReader 使用提供的代码读取器和状态读取器构造一个读取器。
func newReader(codeReader ContractCodeReader, stateReader StateReader) *reader {
	// newReader 函数创建一个新的 reader 实例。
	return &reader{
		ContractCodeReader: codeReader,
		StateReader:        stateReader,
	}
}
