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
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// 以太坊状态树 (State Trie)
//
// 以太坊的状态（包括所有账户的余额、Nonce、合约代码和存储）存储在一个称为 Merkle-Patricia Trie 的数据结构中。这个 trie 以根哈希（State Root）为标识，每个区块头都包含当前状态的根哈希。状态 trie 是一种高效的数据结构，可以快速查找和验证状态数据。
//
// 状态转储 (State Dumping) 的目的
//
// 状态转储的主要目的是将当前以太坊节点的状态数据导出，这在多种场景下非常有用：
//
// 调试和分析 (Debugging and Analysis)：开发者可以使用状态转储来检查特定时间点的账户状态、合约代码和存储，用于调试智能合约或分析区块链行为。
// 备份和恢复 (Backup and Recovery)：状态转储可以作为区块链状态的备份，在需要时进行恢复。
// 测试 (Testing)：在开发和测试以太坊客户端或相关工具时，可以使用状态转储来创建特定的测试场景。
// 数据迁移 (Data Migration)：在进行协议升级或需要迁移数据时，可以使用状态转储作为中间格式。

// DumpConfig is a set of options to control what portions of the state will be
// iterated and collected.
// DumpConfig 是一组选项，用于控制将迭代和收集状态的哪些部分。
type DumpConfig struct {
	SkipCode bool // Whether to skip contract code.
	// SkipCode 是否跳过合约代码。
	SkipStorage bool // Whether to skip contract storage.
	// SkipStorage 是否跳过合约存储。
	OnlyWithAddresses bool // Whether to only dump accounts with known addresses (skips preimages).
	// OnlyWithAddresses 是否只转储具有已知地址的账户（跳过预映像）。
	Start []byte // Starting key for the trie iteration.
	// Start 状态 trie 迭代的起始键。
	Max uint64 // Maximum number of accounts to dump.
	// Max 要转储的最大账户数量。
}

// DumpCollector interface which the state trie calls during iteration
// DumpCollector 是状态 trie 在迭代期间调用的接口。
type DumpCollector interface {
	// OnRoot is called with the state root
	// OnRoot 方法使用状态根哈希进行调用。
	OnRoot(common.Hash)
	// OnAccount is called once for each account in the trie
	// OnAccount 方法对于 trie 中的每个账户调用一次。
	OnAccount(*common.Address, DumpAccount)
}

// DumpAccount represents an account in the state.
// DumpAccount 代表状态中的一个账户。
type DumpAccount struct {
	Balance string `json:"balance"` // Account balance in string format.
	// Balance 账户余额，字符串格式。
	Nonce uint64 `json:"nonce"` // Account nonce.
	// Nonce 账户 nonce 值。
	Root hexutil.Bytes `json:"root"` // Storage root hash.
	// Root 存储根哈希。
	CodeHash hexutil.Bytes `json:"codeHash"` // Bytecode hash.
	// CodeHash 合约代码哈希。
	Code hexutil.Bytes `json:"code,omitempty"` // Contract bytecode (optional).
	// Code 合约字节码（可选）。
	Storage map[common.Hash]string `json:"storage,omitempty"` // Contract storage (optional).
	// Storage 合约存储（可选）。
	Address *common.Address `json:"address,omitempty"` // Address only present in iterative (line-by-line) mode
	// Address 账户地址（可选，在迭代模式下存在）。
	AddressHash hexutil.Bytes `json:"key,omitempty"` // If we don't have address, we can output the key
	// AddressHash 如果地址不可用，则输出 trie 键。
}

// Dump represents the full dump in a collected format, as one large map.
// Dump 代表以收集格式的完整转储，作为一个大的 map。
type Dump struct {
	Root string `json:"root"` // State root hash in string format.
	// Root 状态根哈希，字符串格式。
	Accounts map[string]DumpAccount `json:"accounts"` // Map of account address to account data.
	// Accounts 账户地址到账户数据的映射。
	// Next can be set to represent that this dump is only partial, and Next
	// is where an iterator should be positioned in order to continue the dump.
	// Next 可以设置为表示此转储只是部分转储，Next 是迭代器应定位以继续转储的位置。
	Next []byte `json:"next,omitempty"` // nil if no more accounts
	// Next 如果没有更多账户，则为 nil。
}

// OnRoot implements DumpCollector interface
// OnRoot 实现了 DumpCollector 接口。
func (d *Dump) OnRoot(root common.Hash) {
	d.Root = fmt.Sprintf("%x", root) // Format the root hash as a hexadecimal string.
	// 将根哈希格式化为十六进制字符串。
}

// OnAccount implements DumpCollector interface
// OnAccount 实现了 DumpCollector 接口。
func (d *Dump) OnAccount(addr *common.Address, account DumpAccount) {
	if addr == nil {
		// Handle accounts without a resolved address (preimages).
		// 处理没有解析地址的账户（预映像）。
		d.Accounts[fmt.Sprintf("pre(%s)", account.AddressHash)] = account
	}
	if addr != nil {
		// Handle accounts with resolved addresses.
		// 处理具有解析地址的账户。
		d.Accounts[(*addr).String()] = account
	}
}

// iterativeDump is a DumpCollector-implementation which dumps output line-by-line iteratively.
// iterativeDump 是 DumpCollector 的一个实现，它以迭代方式逐行转储输出。
type iterativeDump struct {
	*json.Encoder // Embedded JSON encoder for line-by-line output.
	// 嵌入的 JSON 编码器，用于逐行输出。
}

// OnAccount implements DumpCollector interface
// OnAccount 实现了 DumpCollector 接口。
func (d iterativeDump) OnAccount(addr *common.Address, account DumpAccount) {
	dumpAccount := &DumpAccount{
		Balance:     account.Balance,
		Nonce:       account.Nonce,
		Root:        account.Root,
		CodeHash:    account.CodeHash,
		Code:        account.Code,
		Storage:     account.Storage,
		AddressHash: account.AddressHash,
		Address:     addr,
	}
	d.Encode(dumpAccount) // Encode and write the account data as a JSON object.
	// 将账户数据编码并写入为 JSON 对象。
}

// OnRoot implements DumpCollector interface
// OnRoot 实现了 DumpCollector 接口。
func (d iterativeDump) OnRoot(root common.Hash) {
	d.Encode(struct { // Encode and write the root hash as a JSON object.
		Root common.Hash `json:"root"`
	}{root})
}

// DumpToCollector iterates the state according to the given options and inserts
// the items into a collector for aggregation or serialization.
// DumpToCollector 根据给定的选项迭代状态，并将条目插入到收集器中以进行聚合或序列化。
func (s *StateDB) DumpToCollector(c DumpCollector, conf *DumpConfig) (nextKey []byte) {
	// Sanitize the input to allow nil configs
	// 清理输入以允许 nil 配置。
	if conf == nil {
		conf = new(DumpConfig)
	}
	var (
		missingPreimages int
		accounts         uint64
		start            = time.Now()
		logged           = time.Now()
	)
	log.Info("Trie dumping started", "root", s.trie.Hash())
	c.OnRoot(s.trie.Hash()) // Notify the collector about the state root.
	// 通知收集器状态根哈希。

	trieIt, err := s.trie.NodeIterator(conf.Start) // Create an iterator over the state trie.
	// 创建状态 trie 的迭代器。
	if err != nil {
		log.Error("Trie dumping error", "err", err)
		return nil
	}
	it := trie.NewIterator(trieIt) // Wrap the node iterator with a standard trie iterator.
	// 使用标准的 trie 迭代器包装节点迭代器。
	for it.Next() {
		var data types.StateAccount
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}
		var (
			account = DumpAccount{
				Balance:     data.Balance.String(),
				Nonce:       data.Nonce,
				Root:        data.Root[:],
				CodeHash:    data.CodeHash,
				AddressHash: it.Key,
			}
			address   *common.Address
			addr      common.Address
			addrBytes = s.trie.GetKey(it.Key) // Retrieve the address associated with the trie key.
			// 检索与 trie 键关联的地址。
		)
		if addrBytes == nil {
			missingPreimages++
			if conf.OnlyWithAddresses {
				continue
			}
		} else {
			addr = common.BytesToAddress(addrBytes)
			address = &addr
			account.Address = address
		}
		obj := newObject(s, addr, &data) // Create a state object for accessing account data.
		// 创建一个状态对象以访问账户数据。
		if !conf.SkipCode {
			account.Code = obj.Code() // Retrieve and set the account's bytecode if not skipped.
			// 如果没有跳过，则检索并设置账户的字节码。
		}
		if !conf.SkipStorage {
			account.Storage = make(map[common.Hash]string)
			tr, err := obj.getTrie() // Get the storage trie for the account.
			// 获取账户的存储 trie。
			if err != nil {
				log.Error("Failed to load storage trie", "err", err)
				continue
			}
			trieIt, err := tr.NodeIterator(nil) // Create an iterator for the storage trie.
			// 为存储 trie 创建一个迭代器。
			if err != nil {
				log.Error("Failed to create trie iterator", "err", err)
				continue
			}
			storageIt := trie.NewIterator(trieIt) // Wrap the storage trie node iterator.
			// 包装存储 trie 节点迭代器。
			for storageIt.Next() {
				_, content, _, err := rlp.Split(storageIt.Value) // Decode the storage value.
				// 解码存储值。
				if err != nil {
					log.Error("Failed to decode the value returned by iterator", "error", err)
					continue
				}
				account.Storage[common.BytesToHash(s.trie.GetKey(storageIt.Key))] = common.Bytes2Hex(content) // Store the storage value.
				// 存储存储值。
			}
		}
		c.OnAccount(address, account) // Notify the collector about the processed account.
		// 通知收集器已处理的账户。
		accounts++
		if time.Since(logged) > 8*time.Second {
			log.Info("Trie dumping in progress", "at", it.Key, "accounts", accounts,
				"elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
		if conf.Max > 0 && accounts >= conf.Max {
			if it.Next() {
				nextKey = it.Key // Store the next key if the maximum number of accounts is reached.
				// 如果达到最大账户数，则存储下一个键。
			}
			break
		}
	}
	if missingPreimages > 0 {
		log.Warn("Dump incomplete due to missing preimages", "missing", missingPreimages)
	}
	log.Info("Trie dumping complete", "accounts", accounts,
		"elapsed", common.PrettyDuration(time.Since(start)))

	return nextKey
}

// RawDump returns the state. If the processing is aborted e.g. due to options
// reaching Max, the `Next` key is set on the returned Dump.
// RawDump 返回状态。如果处理由于选项（例如达到 Max）而中止，则在返回的 Dump 中设置 `Next` 键。
func (s *StateDB) RawDump(opts *DumpConfig) Dump {
	dump := &Dump{
		Accounts: make(map[string]DumpAccount),
	}
	dump.Next = s.DumpToCollector(dump, opts) // Use the collector to populate the Dump struct.
	// 使用收集器填充 Dump 结构体。
	return *dump
}

// Dump returns a JSON string representing the entire state as a single json-object
// Dump 返回一个 JSON 字符串，表示整个状态作为一个单独的 JSON 对象。
func (s *StateDB) Dump(opts *DumpConfig) []byte {
	dump := s.RawDump(opts)
	json, err := json.MarshalIndent(dump, "", "    ") // Marshal the Dump struct into a JSON string.
	// 将 Dump 结构体编组为 JSON 字符串。
	if err != nil {
		log.Error("Error dumping state", "err", err)
	}
	return json
}

// IterativeDump dumps out accounts as json-objects, delimited by linebreaks on stdout
// IterativeDump 将账户作为 JSON 对象转储到 stdout，并用换行符分隔。
func (s *StateDB) IterativeDump(opts *DumpConfig, output *json.Encoder) {
	s.DumpToCollector(iterativeDump{output}, opts) // Use the iterative collector for line-by-line output.
	// 使用迭代收集器进行逐行输出。
}
