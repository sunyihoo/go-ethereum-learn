// Copyright 2019 The go-ethereum Authors
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

package snapshot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/triedb"
)

// 以太坊的状态快照（Snapshot）是一种优化机制，用于加速状态查询和节点同步。快照系统将 Merkle Patricia Trie（MPT）的状态数据平面化存储在键值数据库中，并通过日志（Journal）记录生成进度和差异层（Diff Layer）数据。日志的作用类似于数据库的事务日志，确保快照可以在节点重启或崩溃后恢复。

const (
	journalV0 uint64 = 0 // initial version
	// journalV0 初始版本
	journalV1 uint64 = 1 // current version, with destruct flag (in diff layers) removed
	// journalV1 当前版本，已移除差异层中的销毁标志
	journalCurrentVersion = journalV1 // 当前使用的日志版本
)

// journalGenerator is a disk layer entry containing the generator progress marker.
// journalGenerator 是磁盘层中的一个条目，包含生成器的进度标记。
type journalGenerator struct {
	// Indicator that whether the database was in progress of being wiped.
	// It's deprecated but keep it here for background compatibility.
	// 指示数据库是否正在被擦除的标志。
	// 该字段已废弃，但为了向后兼容而保留。
	Wiping bool

	Done bool // Whether the generator finished creating the snapshot
	// Done 生成器是否已完成快照创建
	Marker   []byte // 生成进度标记
	Accounts uint64 // 已处理的账户数量
	Slots    uint64 // 已处理的存储槽数量
	Storage  uint64 // 已处理的存储数据大小（字节）
}

// journalDestruct is an account deletion entry in a diffLayer's disk journal.
// journalDestruct 是差异层磁盘日志中的账户删除条目。
type journalDestruct struct {
	Hash common.Hash // 被删除账户的哈希
}

// journalAccount is an account entry in a diffLayer's disk journal.
// journalAccount 是差异层磁盘日志中的账户条目。
type journalAccount struct {
	Hash common.Hash // 账户的哈希
	Blob []byte      // 账户数据的二进制表示
}

// journalStorage is an account's storage map in a diffLayer's disk journal.
// journalStorage 是差异层磁盘日志中账户的存储映射。
type journalStorage struct {
	Hash common.Hash   // 账户的哈希
	Keys []common.Hash // 存储槽的键列表
	Vals [][]byte      // 存储槽的值列表
}

// ParseGeneratorStatus parses the generator blob and returns a human-readable status string.
// ParseGeneratorStatus 解析生成器数据并返回人类可读的状态字符串。
func ParseGeneratorStatus(generatorBlob []byte) string {
	if len(generatorBlob) == 0 {
		return "" // 如果数据为空，返回空字符串
	}
	var generator journalGenerator
	// 解码 RLP 格式的生成器数据
	if err := rlp.DecodeBytes(generatorBlob, &generator); err != nil {
		log.Warn("failed to decode snapshot generator", "err", err)
		return "" // 解码失败，返回空字符串
	}
	// Figure out whether we're after or within an account
	// 判断当前标记是在账户之后还是账户内部
	var m string
	switch marker := generator.Marker; len(marker) {
	case common.HashLength: // 标记长度为哈希长度（32字节）
		m = fmt.Sprintf("at %#x", marker) // 在某个账户位置
	case 2 * common.HashLength: // 标记长度为两个哈希长度（64字节）
		m = fmt.Sprintf("in %#x at %#x", marker[:common.HashLength], marker[common.HashLength:]) // 在某个账户内的存储位置
	default:
		m = fmt.Sprintf("%#x", marker) // 其他情况，直接显示标记
	}
	// 返回格式化的状态字符串
	return fmt.Sprintf(`Done: %v, Accounts: %d, Slots: %d, Storage: %d, Marker: %s`,
		generator.Done, generator.Accounts, generator.Slots, generator.Storage, m)
}

// loadAndParseJournal tries to parse the snapshot journal in latest format.
// loadAndParseJournal 尝试以最新格式解析快照日志。
func loadAndParseJournal(db ethdb.KeyValueStore, base *diskLayer) (snapshot, journalGenerator, error) {
	// Retrieve the disk layer generator. It must exist, no matter the
	// snapshot is fully generated or not. Otherwise the entire disk
	// layer is invalid.
	// 获取磁盘层的生成器数据。无论快照是否完全生成，该数据必须存在，否则整个磁盘层无效。
	generatorBlob := rawdb.ReadSnapshotGenerator(db)
	if len(generatorBlob) == 0 {
		return nil, journalGenerator{}, errors.New("missing snapshot generator") // 缺少生成器数据，返回错误
	}
	var generator journalGenerator
	// 解码生成器数据
	if err := rlp.DecodeBytes(generatorBlob, &generator); err != nil {
		return nil, journalGenerator{}, fmt.Errorf("failed to decode snapshot generator: %v", err) // 解码失败，返回错误
	}
	// Retrieve the diff layer journal. It's possible that the journal is
	// not existent, e.g. the disk layer is generating while that the Geth
	// crashes without persisting the diff journal.
	// So if there is no journal, or the journal is invalid(e.g. the journal
	// is not matched with disk layer; or the it's the legacy-format journal,
	// etc.), we just discard all diffs and try to recover them later.
	// 获取差异层日志。日志可能不存在，例如磁盘层正在生成时 Geth 崩溃，未持久化差异日志。
	// 如果日志不存在或无效（例如与磁盘层不匹配，或是旧格式日志等），则丢弃所有差异并稍后尝试恢复。
	var current snapshot = base // 当前快照从基础磁盘层开始
	err := iterateJournal(db, func(parent common.Hash, root common.Hash, accountData map[common.Hash][]byte, storageData map[common.Hash]map[common.Hash][]byte) error {
		// 为每个差异层创建新的 diffLayer
		current = newDiffLayer(current, root, accountData, storageData)
		return nil
	})
	if err != nil {
		return base, generator, nil // 如果迭代日志失败，仅返回基础层和生成器数据
	}
	return current, generator, nil // 返回完整的快照、生成器数据和无错误
}

// loadSnapshot loads a pre-existing state snapshot backed by a key-value store.
// loadSnapshot 加载由键值存储支持的预先存在的状态快照。
func loadSnapshot(diskdb ethdb.KeyValueStore, triedb *triedb.Database, root common.Hash, cache int, recovery bool, noBuild bool) (snapshot, bool, error) {
	// If snapshotting is disabled (initial sync in progress), don't do anything,
	// wait for the chain to permit us to do something meaningful
	// 如果快照功能被禁用（初始同步正在进行），则不执行任何操作，等待链允许执行有意义的动作。
	if rawdb.ReadSnapshotDisabled(diskdb) {
		return nil, true, nil // 返回 nil 和禁用标志
	}
	// Retrieve the block number and hash of the snapshot, failing if no snapshot
	// is present in the database (or crashed mid-update).
	// 获取快照的区块号和哈希，如果数据库中没有快照（或更新中崩溃），则失败。
	baseRoot := rawdb.ReadSnapshotRoot(diskdb)
	if baseRoot == (common.Hash{}) {
		return nil, false, errors.New("missing or corrupted snapshot") // 缺少或损坏的快照，返回错误
	}
	// 初始化磁盘层
	base := &diskLayer{
		diskdb: diskdb,
		triedb: triedb,
		cache:  fastcache.New(cache * 1024 * 1024), // 初始化缓存，大小为 cache MB
		root:   baseRoot,                           // 快照根哈希
	}
	// 加载并解析日志
	snapshot, generator, err := loadAndParseJournal(diskdb, base)
	if err != nil {
		log.Warn("Failed to load journal", "error", err)
		return nil, false, err // 加载日志失败，返回错误
	}
	// Entire snapshot journal loaded, sanity check the head. If the loaded
	// snapshot is not matched with current state root, print a warning log
	// or discard the entire snapshot it's legacy snapshot.
	//
	// Possible scenario: Geth was crashed without persisting journal and then
	// restart, the head is rewound to the point with available state(trie)
	// which is below the snapshot. In this case the snapshot can be recovered
	// by re-executing blocks but right now it's unavailable.
	// 整个快照日志已加载，检查头部是否合理。如果加载的快照与当前状态根不匹配，
	// 则打印警告日志或丢弃整个快照（如果是旧快照）。
	//
	// 可能的情景：Geth 在未持久化日志的情况下崩溃然后重启，头部回滚到可用状态（trie）的点，
	// 该点低于快照。此时可以通过重新执行区块恢复快照，但当前不可用。
	if head := snapshot.Root(); head != root {
		// If it's legacy snapshot, or it's new-format snapshot but
		// it's not in recovery mode, returns the error here for
		// rebuilding the entire snapshot forcibly.
		// 如果是旧快照，或是新格式快照但不在恢复模式，则返回错误以强制重建整个快照。
		if !recovery {
			return nil, false, fmt.Errorf("head doesn't match snapshot: have %#x, want %#x", head, root)
		}
		// It's in snapshot recovery, the assumption is held that
		// the disk layer is always higher than chain head. It can
		// be eventually recovered when the chain head beyonds the
		// disk layer.
		// 在快照恢复模式中，假设磁盘层始终高于链头部。当链头部超过磁盘层时可以最终恢复。
		log.Warn("Snapshot is not continuous with chain", "snaproot", head, "chainroot", root)
	}
	// Load the disk layer status from the generator if it's not complete
	// 如果生成未完成，从生成器加载磁盘层状态
	if !generator.Done {
		base.genMarker = generator.Marker
		if base.genMarker == nil {
			base.genMarker = []byte{} // 如果标记为空，初始化为空字节
		}
	}
	// Everything loaded correctly, resume any suspended operations
	// if the background generation is allowed
	// 一切加载正确，如果允许后台生成，则恢复任何暂停的操作
	if !generator.Done && !noBuild {
		base.genPending = make(chan struct{})           // 初始化挂起通道
		base.genAbort = make(chan chan *generatorStats) // 初始化中止通道

		var origin uint64
		if len(generator.Marker) >= 8 {
			origin = binary.BigEndian.Uint64(generator.Marker) // 从标记中解析起始位置
		}
		// 在后台启动生成过程
		go base.generate(&generatorStats{
			origin:   origin,
			start:    time.Now(),
			accounts: generator.Accounts,
			slots:    generator.Slots,
			storage:  common.StorageSize(generator.Storage),
		})
	}
	return snapshot, false, nil // 返回快照、无禁用标志和无错误
}

// Journal terminates any in-progress snapshot generation, also implicitly pushing
// the progress into the database.
// Journal 终止任何正在进行的快照生成，同时隐式地将进度推送到数据库。
func (dl *diskLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	// If the snapshot is currently being generated, abort it
	// 如果快照当前正在生成，则中止它
	var stats *generatorStats
	if dl.genAbort != nil {
		abort := make(chan *generatorStats)
		dl.genAbort <- abort // 发送中止信号

		if stats = <-abort; stats != nil {
			stats.Log("Journalling in-progress snapshot", dl.root, dl.genMarker) // 记录中止日志
		}
	}
	// Ensure the layer didn't get stale
	// 确保层未过期
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.stale {
		return common.Hash{}, ErrSnapshotStale // 如果层已过期，返回错误
	}
	// Ensure the generator stats is written even if none was ran this cycle
	// 确保生成器统计数据被写入，即使本周期未运行生成
	journalProgress(dl.diskdb, dl.genMarker, stats)

	log.Debug("Journalled disk layer", "root", dl.root)
	return dl.root, nil // 返回磁盘层根哈希和无错误
}

// Journal writes the memory layer contents into a buffer to be stored in the
// database as the snapshot journal.
// Journal 将内存层内容写入缓冲区，以存储到数据库中作为快照日志。
func (dl *diffLayer) Journal(buffer *bytes.Buffer) (common.Hash, error) {
	// Journal the parent first
	// 首先记录父层的日志
	base, err := dl.parent.Journal(buffer)
	if err != nil {
		return common.Hash{}, err // 如果父层记录失败，返回错误
	}
	// Ensure the layer didn't get stale
	// 确保层未过期
	dl.lock.RLock()
	defer dl.lock.RUnlock()

	if dl.Stale() {
		return common.Hash{}, ErrSnapshotStale // 如果层已过期，返回错误
	}
	// Everything below was journalled, persist this layer too
	// 以下所有内容已记录，也持久化此层
	if err := rlp.Encode(buffer, dl.root); err != nil {
		return common.Hash{}, err // 编码根哈希失败，返回错误
	}
	// 将账户数据转换为日志格式
	accounts := make([]journalAccount, 0, len(dl.accountData))
	for hash, blob := range dl.accountData {
		accounts = append(accounts, journalAccount{
			Hash: hash,
			Blob: blob,
		})
	}
	if err := rlp.Encode(buffer, accounts); err != nil {
		return common.Hash{}, err // 编码账户数据失败，返回错误
	}
	// 将存储数据转换为日志格式
	storage := make([]journalStorage, 0, len(dl.storageData))
	for hash, slots := range dl.storageData {
		keys := make([]common.Hash, 0, len(slots))
		vals := make([][]byte, 0, len(slots))
		for key, val := range slots {
			keys = append(keys, key)
			vals = append(vals, val)
		}
		storage = append(storage, journalStorage{Hash: hash, Keys: keys, Vals: vals})
	}
	if err := rlp.Encode(buffer, storage); err != nil {
		return common.Hash{}, err // 编码存储数据失败，返回错误
	}
	log.Debug("Journalled diff layer", "root", dl.root, "parent", dl.parent.Root())
	return base, nil // 返回父层根哈希和无错误
}

// journalCallback is a function which is invoked by iterateJournal, every
// time a difflayer is loaded from disk.
// journalCallback 是 iterateJournal 调用的函数，每次从磁盘加载差异层时调用。
type journalCallback = func(parent common.Hash, root common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) error

// iterateJournal iterates through the journalled difflayers, loading them from
// the database, and invoking the callback for each loaded layer.
// The order is incremental; starting with the bottom-most difflayer, going towards
// the most recent layer.
// This method returns error either if there was some error reading from disk,
// OR if the callback returns an error when invoked.
// iterateJournal 迭代记录的差异层，从数据库加载它们，并为每个加载的层调用回调函数。
// 顺序是递增的，从最底层的差异层开始，向最新的层前进。
// 如果从磁盘读取时出错，或回调函数返回错误，则此方法返回错误。
func iterateJournal(db ethdb.KeyValueReader, callback journalCallback) error {
	journal := rawdb.ReadSnapshotJournal(db)
	if len(journal) == 0 {
		log.Warn("Loaded snapshot journal", "diffs", "missing") // 日志为空，记录警告
		return nil
	}
	r := rlp.NewStream(bytes.NewReader(journal), 0) // 创建 RLP 流读取器
	// Firstly, resolve the first element as the journal version
	// 首先，解析第一个元素作为日志版本
	version, err := r.Uint64()
	if err != nil {
		log.Warn("Failed to resolve the journal version", "error", err)
		return errors.New("failed to resolve journal version") // 解析版本失败，返回错误
	}
	if version != journalV0 && version != journalCurrentVersion {
		log.Warn("Discarded journal with wrong version", "required", journalCurrentVersion, "got", version)
		return errors.New("wrong journal version") // 版本不匹配，返回错误
	}
	// Secondly, resolve the disk layer root, ensure it's continuous
	// with disk layer. Note now we can ensure it's the snapshot journal
	// correct version, so we expect everything can be resolved properly.
	// 其次，解析磁盘层根，确保与磁盘层连续。
	// 现在可以确保是正确的快照日志版本，因此期望一切都能正确解析。
	var parent common.Hash
	if err := r.Decode(&parent); err != nil {
		return errors.New("missing disk layer root") // 缺少磁盘层根，返回错误
	}
	if baseRoot := rawdb.ReadSnapshotRoot(db); baseRoot != parent {
		log.Warn("Loaded snapshot journal", "diskroot", baseRoot, "diffs", "unmatched")
		return errors.New("mismatched disk and diff layers") // 磁盘层与差异层不匹配，返回错误
	}
	for {
		var (
			root        common.Hash                                    // 差异层根哈希
			accounts    []journalAccount                               // 账户数据列表
			storage     []journalStorage                               // 存储数据列表
			accountData = make(map[common.Hash][]byte)                 // 账户数据映射
			storageData = make(map[common.Hash]map[common.Hash][]byte) // 存储数据映射
		)
		// Read the next diff journal entry
		// 读取下一个差异日志条目
		if err := r.Decode(&root); err != nil {
			// The first read may fail with EOF, marking the end of the journal
			// 第一次读取可能因 EOF 失败，标记日志结束
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("load diff root: %v", err) // 加载差异根失败，返回错误
		}
		// If a legacy journal is detected, decode the destruct set from the stream.
		// The destruct set has been deprecated. If the journal contains non-empty
		// destruct set, then it is deemed incompatible.
		//
		// Since self-destruction has been deprecated following the cancun fork,
		// the destruct set is expected to be nil for layers above the fork block.
		// However, an exception occurs during contract deployment: pre-funded accounts
		// may self-destruct, causing accounts with non-zero balances to be removed
		// from the state. For example,
		// https://etherscan.io/tx/0xa087333d83f0cd63b96bdafb686462e1622ce25f40bd499e03efb1051f31fe49).
		//
		// For nodes with a fully synced state, the legacy journal is likely compatible
		// with the updated definition, eliminating the need for regeneration. Unfortunately,
		// nodes performing a full sync of historical chain segments or encountering
		// pre-funded account deletions may face incompatibilities, leading to automatic
		// snapshot regeneration.
		//
		// This approach minimizes snapshot regeneration for Geth nodes upgrading from a
		// legacy version that are already synced. The workaround can be safely removed
		// after the next hard fork.
		// 如果检测到旧日志，从流中解码销毁集合。
		// 销毁集合已废弃。如果日志包含非空的销毁集合，则认为其不兼容。
		//
		// 自 Cancun 分叉后，自毁功能已废弃，对于分叉区块以上的层，销毁集合应为 nil。
		// 然而，在合约部署期间存在例外：预资助账户可能自毁，导致余额非零的账户从状态中移除。例如，
		// https://etherscan.io/tx/0xa087333d83f0cd63b96bdafb686462e1622ce25f40bd499e03efb1051f31fe49)。
		//
		// 对于状态完全同步的节点，旧日志可能与更新后的定义兼容，无需重新生成。
		// 不幸的是，执行历史链段完全同步或遇到预资助账户删除的节点可能会面临不兼容，导致自动快照重新生成。
		//
		// 这种方法最大限度地减少了从旧版本升级且已同步的 Geth 节点的快照重新生成。
		// 在下一次硬分叉后，此解决方法可以安全移除。
		if version == journalV0 {
			var destructs []journalDestruct
			if err := r.Decode(&destructs); err != nil {
				return fmt.Errorf("load diff destructs: %v", err) // 加载销毁集合失败，返回错误
			}
			if len(destructs) > 0 {
				log.Warn("Incompatible legacy journal detected", "version", journalV0)
				return fmt.Errorf("incompatible legacy journal detected") // 检测到不兼容的旧日志，返回错误
			}
		}
		// 解码账户数据
		if err := r.Decode(&accounts); err != nil {
			return fmt.Errorf("load diff accounts: %v", err) // 加载账户数据失败，返回错误
		}
		// 解码存储数据
		if err := r.Decode(&storage); err != nil {
			return fmt.Errorf("load diff storage: %v", err) // 加载存储数据失败，返回错误
		}
		// 将账户数据填充到映射中
		for _, entry := range accounts {
			if len(entry.Blob) > 0 { // RLP loses nil-ness, but `[]byte{}` is not a valid item, so reinterpret that
				// RLP 丢失了 nil 属性，但 `[]byte{}` 不是有效项，因此重新解释
				accountData[entry.Hash] = entry.Blob
			} else {
				accountData[entry.Hash] = nil
			}
		}
		// 将存储数据填充到映射中
		for _, entry := range storage {
			slots := make(map[common.Hash][]byte)
			for i, key := range entry.Keys {
				if len(entry.Vals[i]) > 0 { // RLP loses nil-ness, but `[]byte{}` is not a valid item, so reinterpret that
					// RLP 丢失了 nil 属性，但 `[]byte{}` 不是有效项，因此重新解释
					slots[key] = entry.Vals[i]
				} else {
					slots[key] = nil
				}
			}
			storageData[entry.Hash] = slots
		}
		// 调用回调函数处理加载的层
		if err := callback(parent, root, accountData, storageData); err != nil {
			return err // 回调返回错误时，返回该错误
		}
		parent = root // 更新父层根哈希
	}
}
