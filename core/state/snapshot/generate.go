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
	"errors"
	"fmt"
	"time"

	"github.com/VictoriaMetrics/fastcache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// 1. 以太坊状态与 Merkle Patricia Trie
// 以太坊的状态存储在 Merkle Patricia Trie（MPT）中，这是一种结合了 Merkle Tree 和 Patricia Trie 的数据结构，用于高效存储键值对并提供密码学证明（Merkle Proof）。白皮书中提到，状态包括所有账户的余额、合约代码和存储数据，黄皮书中进一步定义了其结构：
//
// 账户状态：包含 nonce、余额、存储根（Storage Root）和代码哈希（Code Hash）。
// 存储状态：每个合约的存储槽，键值对形式。
// 代码中的 generateSnapshot 和 generateRange 函数通过迭代 MPT，生成平面化的快照数据（Flat State），并将其存储在键值数据库（如 LevelDB）中。这种快照形式避免了直接查询 MPT 的复杂性，提升了查询效率。
//
// 2. 快照生成的核心逻辑
// 异步生成：generateSnapshot 创建了一个 diskLayer 对象，并通过 go base.generate(stats) 在后台异步生成快照。这是为了不阻塞主线程，适用于节点同步或启动时的状态恢复。
// 范围证明（Range Proof）：proveRange 函数实现了范围证明机制，验证快照数据的正确性。范围证明是 Merkle Proof 的扩展，用于确保某个范围内的键值对与 MPT 的根哈希一致。如果验证失败（如根哈希不匹配），会触发重新生成（如 generateRange 的逻辑）。
// 增量更新：通过 genMarker 和 journalProgress，代码支持从中断点恢复生成。这与以太坊节点的动态性相关，因为状态可能因新区块而改变，增量更新减少了重复工作。
// 3. 与以太坊改进提案（EIP）的关系
// EIP-2929（Gas Cost Increases for State Access Opcodes）：此提案调整了状态访问的 Gas 成本，促使节点优化状态存储和访问。快照机制通过缓存平面化数据，减少了对 MPT 的直接访问，与此优化目标一致。
// EIP-2930（Optional Access Lists）：支持访问列表的交易类型也依赖高效的状态查询，快照生成的 diskLayer 和缓存机制为此提供了底层支持。
// 4. 算法与优化
// accountCheckRange 和 storageCheckRange：这两个变量（128 和 1024）定义了每次范围检查的账户和存储槽上限。这是基于经验的折中选择，平衡了证明失败率和生成效率。过大的范围可能导致 Merkle Proof 复杂度过高，过小则增加迭代次数。
// Merkle 证明验证：trie.VerifyRangeProof 使用了 Merkle 树的性质，通过边缘证明（Edge Proof）验证范围内的数据完整性。这与以太坊黄皮书中描述的状态根验证一致。
// 缓存机制：fastcache.New(cache * 1024 * 1024) 初始化了一个内存缓存，用于加速键值访问。这是对 MPT 查询的一种优化，减少了磁盘 I/O。
// 5. 代码中的关键概念
// diskLayer：表示快照的磁盘层，包含状态根、trie 数据库和生成标记。它是快照系统的核心结构，负责协调生成和验证。
// proofResult：封装了范围证明的结果，包括键值对和错误状态。它体现了以太坊对数据一致性的严格要求。
// generateAccounts 和 generateStorages：分别处理账户和存储槽的生成，体现了以太坊状态的层次性（账户层和存储层）。
// 6. 背景知识补充
// 状态膨胀问题：以太坊的状态不断增长（截至 2025 年可能已超过数百 GB），快照机制是解决状态膨胀的一种方案，通过平面化存储减少冗余。
// 同步优化：传统的全节点同步需要下载并验证所有历史状态，而快照同步（Snap Sync）允许节点快速获取最新状态并验证其正确性。这段代码是 Snap Sync 的核心实现之一。
// 安全性：通过 Merkle 证明和根哈希校验，快照生成确保了数据不可篡改，符合以太坊的密码学设计原则。

var (
	// accountCheckRange is the upper limit of the number of accounts involved in
	// each range check. This is a value estimated based on experience. If this
	// range is too large, the failure rate of range proof will increase. Otherwise,
	// if the range is too small, the efficiency of the state recovery will decrease.
	// accountCheckRange 是每次范围检查中涉及的账户数量上限。这个值是根据经验估计的。如果这个范围太大，范围证明的失败率会增加。反之，如果范围太小，状态恢复的效率会降低。
	accountCheckRange = 128

	// storageCheckRange is the upper limit of the number of storage slots involved
	// in each range check. This is a value estimated based on experience. If this
	// range is too large, the failure rate of range proof will increase. Otherwise,
	// if the range is too small, the efficiency of the state recovery will decrease.
	// storageCheckRange 是每次范围检查中涉及的存储槽数量上限。这个值是根据经验估计的。如果这个范围太大，范围证明的失败率会增加。反之，如果范围太小，状态恢复的效率会降低。
	storageCheckRange = 1024

	// errMissingTrie is returned if the target trie is missing while the generation
	// is running. In this case the generation is aborted and wait the new signal.
	// errMissingTrie 在生成过程中如果目标 trie 缺失时返回。在这种情况下，生成过程会中止并等待新的信号。
	errMissingTrie = errors.New("missing trie")
)

// generateSnapshot regenerates a brand new snapshot based on an existing state
// database and head block asynchronously. The snapshot is returned immediately
// and generation is continued in the background until done.
// generateSnapshot 根据现有的状态数据库和头部区块异步重新生成一个全新的快照。快照会立即返回，并在后台继续生成直到完成。
func generateSnapshot(diskdb ethdb.KeyValueStore, triedb *triedb.Database, cache int, root common.Hash) *diskLayer {
	// Create a new disk layer with an initialized state marker at zero
	// 创建一个新的磁盘层，状态标记初始化为零
	var (
		stats     = &generatorStats{start: time.Now()} // 统计生成过程的数据，记录开始时间
		batch     = diskdb.NewBatch()                  // 创建一个新的批量写入对象，用于批量操作数据库
		genMarker = []byte{}                           // Initialized but empty! 初始化但为空的状态生成标记
	)
	// 将快照的根哈希写入数据库
	rawdb.WriteSnapshotRoot(batch, root)
	// 将当前的生成进度写入数据库
	journalProgress(batch, genMarker, stats)
	// 检查批量写入是否成功
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write initialized state marker", "err", err)
	}
	// 创建并初始化 diskLayer 结构
	base := &diskLayer{
		diskdb:     diskdb,                             // 底层键值存储数据库
		triedb:     triedb,                             // trie 数据库，用于状态查询
		root:       root,                               // 快照的根哈希
		cache:      fastcache.New(cache * 1024 * 1024), // 初始化缓存，大小为 cache MB
		genMarker:  genMarker,                          // 当前生成标记
		genPending: make(chan struct{}),                // 用于标记生成是否挂起
		genAbort:   make(chan chan *generatorStats),    // 用于中止生成的信号通道
	}
	// 在后台启动快照生成过程
	go base.generate(stats)
	log.Debug("Start snapshot generation", "root", root)
	return base
}

// journalProgress persists the generator stats into the database to resume later.
// journalProgress 将生成器的统计数据持久化到数据库，以便稍后恢复。
func journalProgress(db ethdb.KeyValueWriter, marker []byte, stats *generatorStats) {
	// Write out the generator marker. Note it's a standalone disk layer generator
	// which is not mixed with journal. It's ok if the generator is persisted while
	// journal is not.
	// 写入生成标记。注意这是一个独立的磁盘层生成器，不会与日志混合。即使日志未持久化，生成器持久化也是可以的。
	// 创建一个日志条目，记录生成状态
	entry := journalGenerator{
		Done:   marker == nil, // 如果 marker 为 nil，表示生成已完成
		Marker: marker,        // 当前的生成标记
	}
	// 如果统计数据不为空，填充账户数、槽数和存储大小
	if stats != nil {
		entry.Accounts = stats.accounts
		entry.Slots = stats.slots
		entry.Storage = uint64(stats.storage)
	}
	// 将日志条目编码为 RLP 格式
	blob, err := rlp.EncodeToBytes(entry)
	if err != nil {
		panic(err) // Cannot happen, here to catch dev errors // 这里不会发生错误，用于捕获开发错误
	}
	// 根据 marker 的值生成日志字符串，用于调试
	var logstr string
	switch {
	case marker == nil:
		logstr = "done" // 已完成
	case bytes.Equal(marker, []byte{}):
		logstr = "empty" // 空标记
	case len(marker) == common.HashLength:
		logstr = fmt.Sprintf("%#x", marker) // 哈希长度的情况
	default:
		logstr = fmt.Sprintf("%#x:%#x", marker[:common.HashLength], marker[common.HashLength:]) // 混合标记
	}
	log.Debug("Journalled generator progress", "progress", logstr)
	// 将编码后的日志写入数据库
	rawdb.WriteSnapshotGenerator(db, blob)
}

// proofResult contains the output of range proving which can be used
// for further processing regardless if it is successful or not.
// proofResult 包含范围证明的输出，无论证明是否成功都可以用于进一步处理。
type proofResult struct {
	keys [][]byte // The key set of all elements being iterated, even proving is failed
	// keys 被迭代的所有元素的键集合，即使证明失败也包含在内
	vals [][]byte // The val set of all elements being iterated, even proving is failed
	// vals 被迭代的所有元素的值集合，即使证明失败也包含在内
	diskMore bool // Set when the database has extra snapshot states since last iteration
	// diskMore 当数据库自上次迭代以来有额外的快照状态时设置为 true
	trieMore bool // Set when the trie has extra snapshot states(only meaningful for successful proving)
	// trieMore 当 trie 有额外的快照状态时设置为 true（仅在证明成功时有意义）
	proofErr error // Indicator whether the given state range is valid or not
	// proofErr 指示给定状态范围是否有效的错误
	tr *trie.Trie // The trie, in case the trie was resolved by the prover (may be nil)
	// tr 如果证明者解析了 trie，则为该 trie（可能为 nil）
}

// valid returns the indicator that range proof is successful or not.
// valid 返回范围证明是否成功的指示。
func (result *proofResult) valid() bool {
	return result.proofErr == nil // 如果 proofErr 为 nil，则证明成功
}

// last returns the last verified element key regardless of whether the range proof is
// successful or not. Nil is returned if nothing involved in the proving.
// last 返回最后一个经过验证的元素键，无论范围证明是否成功。如果证明中没有任何元素，则返回 nil。
func (result *proofResult) last() []byte {
	var last []byte
	if len(result.keys) > 0 {
		last = result.keys[len(result.keys)-1] // 返回最后一个键
	}
	return last
}

// forEach iterates all the visited elements and applies the given callback on them.
// The iteration is aborted if the callback returns non-nil error.
// forEach 迭代所有访问过的元素，并对它们应用给定的回调函数。如果回调返回非 nil 错误，则迭代中止。
func (result *proofResult) forEach(callback func(key []byte, val []byte) error) error {
	for i := 0; i < len(result.keys); i++ {
		key, val := result.keys[i], result.vals[i]
		if err := callback(key, val); err != nil {
			return err // 如果回调返回错误，则中止并返回该错误
		}
	}
	return nil
}

// proveRange proves the snapshot segment with particular prefix is "valid".
// The iteration start point will be assigned if the iterator is restored from
// the last interruption. Max will be assigned in order to limit the maximum
// amount of data involved in each iteration.
//
// The proof result will be returned if the range proving is finished, otherwise
// the error will be returned to abort the entire procedure.
// proveRange 证明具有特定前缀的快照段是“有效的”。如果迭代器是从上次中断恢复的，则会指定迭代起点。max 将被指定以限制每次迭代涉及的最大数据量。
// 如果范围证明完成，则返回证明结果，否则返回错误以中止整个过程。
func (dl *diskLayer) proveRange(ctx *generatorContext, trieId *trie.ID, prefix []byte, kind string, origin []byte, max int, valueConvertFn func([]byte) ([]byte, error)) (*proofResult, error) {
	var (
		keys     [][]byte                    // 存储迭代的键
		vals     [][]byte                    // 存储迭代的值
		proof    = rawdb.NewMemoryDatabase() // 创建内存数据库用于存储证明
		diskMore = false                     // 标记数据库是否还有更多数据
		iter     = ctx.iterator(kind)        // 获取对应类型的迭代器
		start    = time.Now()                // 记录开始时间
		min      = append(prefix, origin...) // 计算迭代的最小键值
	)
	// 遍历迭代器
	for iter.Next() {
		// Ensure the iterated item is always equal or larger than the given origin.
		// 确保迭代的项始终等于或大于给定的起点。
		key := iter.Key()
		if bytes.Compare(key, min) < 0 {
			return nil, errors.New("invalid iteration position") // 如果键小于起点，返回错误
		}
		// Ensure the iterated item still fall in the specified prefix. If
		// not which means the items in the specified area are all visited.
		// Move the iterator a step back since we iterate one extra element
		// out.
		// 确保迭代的项仍在指定前缀内。如果不是，则意味着指定区域内的所有项都已访问。
		// 将迭代器回退一步，因为我们多迭代了一个元素。
		if !bytes.Equal(key[:len(prefix)], prefix) {
			iter.Hold() // 暂停迭代器
			break
		}
		// Break if we've reached the max size, and signal that we're not
		// done yet. Move the iterator a step back since we iterate one
		// extra element out.
		// 如果达到最大限制，退出循环，并标记尚未完成。将迭代器回退一步。
		if len(keys) == max {
			iter.Hold()
			diskMore = true
			break
		}
		// 将键添加到结果中，去掉前缀部分
		keys = append(keys, common.CopyBytes(key[len(prefix):]))

		// 根据是否有值转换函数处理值
		if valueConvertFn == nil {
			vals = append(vals, common.CopyBytes(iter.Value()))
		} else {
			val, err := valueConvertFn(iter.Value())
			if err != nil {
				// Special case, the state data is corrupted (invalid slim-format account),
				// don't abort the entire procedure directly. Instead, let the fallback
				// generation to heal the invalid data.
				//
				// Here append the original value to ensure that the number of key and
				// value are aligned.
				// 特殊情况，状态数据损坏（无效的 slim 格式账户），不直接中止整个过程。
				// 而是让备用生成过程修复无效数据。
				// 这里追加原始值以确保键和值的数量对齐。
				vals = append(vals, common.CopyBytes(iter.Value()))
				log.Error("Failed to convert account state data", "err", err)
			} else {
				vals = append(vals, val)
			}
		}
	}
	// Update metrics for database iteration and merkle proving 更新数据库迭代和 Merkle 证明的指标
	if kind == snapStorage {
		snapStorageSnapReadCounter.Inc(time.Since(start).Nanoseconds())
	} else {
		snapAccountSnapReadCounter.Inc(time.Since(start).Nanoseconds())
	}
	// 延迟更新证明耗时指标
	defer func(start time.Time) {
		if kind == snapStorage {
			snapStorageProveCounter.Inc(time.Since(start).Nanoseconds())
		} else {
			snapAccountProveCounter.Inc(time.Since(start).Nanoseconds())
		}
	}(time.Now())

	// The snap state is exhausted, pass the entire key/val set for verification
	// 如果快照状态已耗尽，将整个键/值集合传递进行验证
	root := trieId.Root
	if origin == nil && !diskMore {
		stackTr := trie.NewStackTrie(nil) // 创建一个栈式 trie
		// 更新栈式 trie 中的键值对
		for i, key := range keys {
			if err := stackTr.Update(key, vals[i]); err != nil {
				return nil, err
			}
		}
		// 检查根哈希是否匹配
		if gotRoot := stackTr.Hash(); gotRoot != root {
			return &proofResult{
				keys:     keys,
				vals:     vals,
				proofErr: fmt.Errorf("wrong root: have %#x want %#x", gotRoot, root),
			}, nil
		}
		return &proofResult{keys: keys, vals: vals}, nil
	}
	// Snap state is chunked, generate edge proofs for verification.
	// 如果快照状态是分块的，生成边缘证明进行验证。
	tr, err := trie.New(trieId, dl.triedb)
	if err != nil {
		ctx.stats.Log("Trie missing, state snapshotting paused", dl.root, dl.genMarker)
		return nil, errMissingTrie
	}
	// Generate the Merkle proofs for the first and last element
	// 为第一个和最后一个元素生成 Merkle 证明
	if origin == nil {
		origin = common.Hash{}.Bytes() // 如果起点为空，使用全零哈希
	}
	if err := tr.Prove(origin, proof); err != nil {
		log.Debug("Failed to prove range", "kind", kind, "origin", origin, "err", err)
		return &proofResult{
			keys:     keys,
			vals:     vals,
			diskMore: diskMore,
			proofErr: err,
			tr:       tr,
		}, nil
	}
	if len(keys) > 0 {
		if err := tr.Prove(keys[len(keys)-1], proof); err != nil {
			log.Debug("Failed to prove range", "kind", kind, "last", keys[len(keys)-1], "err", err)
			return &proofResult{
				keys:     keys,
				vals:     vals,
				diskMore: diskMore,
				proofErr: err,
				tr:       tr,
			}, nil
		}
	}
	// Verify the snapshot segment with range prover, ensure that all flat states
	// in this range correspond to merkle trie.
	// 使用范围证明器验证快照段，确保该范围内的所有平面状态与 Merkle trie 对应。
	cont, err := trie.VerifyRangeProof(root, origin, keys, vals, proof)
	return &proofResult{
			keys:     keys,
			vals:     vals,
			diskMore: diskMore,
			trieMore: cont,
			proofErr: err,
			tr:       tr},
		nil
}

// onStateCallback is a function that is called by generateRange, when processing a range of
// accounts or storage slots. For each element, the callback is invoked.
//
// - If 'delete' is true, then this element (and potential slots) needs to be deleted from the snapshot.
// - If 'write' is true, then this element needs to be updated with the 'val'.
// - If 'write' is false, then this element is already correct, and needs no update.
// The 'val' is the canonical encoding of the value (not the slim format for accounts)
//
// However, for accounts, the storage trie of the account needs to be checked. Also,
// dangling storages(storage exists but the corresponding account is missing) need to
// be cleaned up.
// onStateCallback 是 generateRange 在处理账户或存储槽范围时调用的函数。对每个元素都会调用该回调。
// - 如果 'delete' 为 true，则该元素（及其潜在的槽）需要从快照中删除。
// - 如果 'write' 为 true，则该元素需要使用 'val' 更新。
// - 如果 'write' 为 false，则该元素已是正确的，无需更新。
// 'val' 是值的规范编码（对于账户不是 slim 格式）。
// 然而，对于账户，需要检查其存储 trie。此外，需要清理悬空存储（存储存在但对应的账户缺失）。
type onStateCallback func(key []byte, val []byte, write bool, delete bool) error

// generateRange generates the state segment with particular prefix. Generation can
// either verify the correctness of existing state through range-proof and skip
// generation, or iterate trie to regenerate state on demand.
// generateRange 生成具有特定前缀的状态段。生成过程可以通过范围证明验证现有状态的正确性并跳过生成，或者按需迭代 trie 重新生成状态。
func (dl *diskLayer) generateRange(ctx *generatorContext, trieId *trie.ID, prefix []byte, kind string, origin []byte, max int, onState onStateCallback, valueConvertFn func([]byte) ([]byte, error)) (bool, []byte, error) {
	// Use range prover to check the validity of the flat state in the range
	// 使用范围证明器检查范围内平面状态的有效性
	result, err := dl.proveRange(ctx, trieId, prefix, kind, origin, max, valueConvertFn)
	if err != nil {
		return false, nil, err
	}
	last := result.last() // 获取最后一个验证的键

	// Construct contextual logger
	// 构造上下文日志记录器
	logCtx := []interface{}{"kind", kind, "prefix", hexutil.Encode(prefix)}
	if len(origin) > 0 {
		logCtx = append(logCtx, "origin", hexutil.Encode(origin))
	}
	logger := log.New(logCtx...)

	// The range prover says the range is correct, skip trie iteration
	// 范围证明器表示范围是正确的，跳过 trie 迭代
	if result.valid() {
		snapSuccessfulRangeProofMeter.Mark(1)
		logger.Trace("Proved state range", "last", hexutil.Encode(last))

		// The verification is passed, process each state with the given
		// callback function. If this state represents a contract, the
		// corresponding storage check will be performed in the callback
		// 验证通过，使用给定的回调函数处理每个状态。如果该状态表示合约，则在回调中执行相应的存储检查
		if err := result.forEach(func(key []byte, val []byte) error { return onState(key, val, false, false) }); err != nil {
			return false, nil, err
		}
		// Only abort the iteration when both database and trie are exhausted
		// 仅当数据库和 trie 都耗尽时才中止迭代
		return !result.diskMore && !result.trieMore, last, nil
	}
	logger.Trace("Detected outdated state range", "last", hexutil.Encode(last), "err", result.proofErr)
	snapFailedRangeProofMeter.Mark(1)

	// Special case, the entire trie is missing. In the original trie scheme,
	// all the duplicated subtries will be filtered out (only one copy of data
	// will be stored). While in the snapshot model, all the storage tries
	// belong to different contracts will be kept even they are duplicated.
	// Track it to a certain extent remove the noise data used for statistics.
	// 特殊情况，整个 trie 缺失。在原始 trie 方案中，所有重复的子 trie 会被过滤掉（只存储一份数据）。
	// 而在快照模型中，属于不同合约的所有存储 trie 都会保留，即使它们是重复的。
	// 在一定程度上跟踪以移除用于统计的噪声数据。
	if origin == nil && last == nil {
		meter := snapMissallAccountMeter
		if kind == snapStorage {
			meter = snapMissallStorageMeter
		}
		meter.Mark(1)
	}
	// We use the snap data to build up a cache which can be used by the
	// main account trie as a primary lookup when resolving hashes
	// 使用快照数据构建缓存，可作为主账户 trie 在解析哈希时的主要查找
	var resolver trie.NodeResolver
	if len(result.keys) > 0 {
		tr := trie.NewEmpty(nil)
		for i, key := range result.keys {
			tr.Update(key, result.vals[i])
		}
		_, nodes := tr.Commit(false)
		hashSet := nodes.HashSet()
		resolver = func(owner common.Hash, path []byte, hash common.Hash) []byte {
			return hashSet[hash]
		}
	}
	// Construct the trie for state iteration, reuse the trie
	// if it's already opened with some nodes resolved.
	// 构造用于状态迭代的 trie，如果 trie 已打开并解析了一些节点，则重用它。
	tr := result.tr
	if tr == nil {
		tr, err = trie.New(trieId, dl.triedb)
		if err != nil {
			ctx.stats.Log("Trie missing, state snapshotting paused", dl.root, dl.genMarker)
			return false, nil, errMissingTrie
		}
	}
	var (
		trieMore       bool                       // 标记 trie 是否还有更多数据
		kvkeys, kvvals = result.keys, result.vals // 从结果中获取键值对

		// counters
		count     = 0 // number of states delivered by iterator // 迭代器提供的状态数
		created   = 0 // states created from the trie // 从 trie 创建的状态数
		updated   = 0 // states updated from the trie // 从 trie 更新的状态数
		deleted   = 0 // states not in trie, but were in snapshot // 不在 trie 中但在快照中的状态数
		untouched = 0 // states already correct // 已正确的状态数

		// timers
		start    = time.Now()  // 开始时间
		internal time.Duration // 内部处理时间
	)
	// 创建节点迭代器，从起点开始
	nodeIt, err := tr.NodeIterator(origin)
	if err != nil {
		return false, nil, err
	}
	nodeIt.AddResolver(resolver)
	iter := trie.NewIterator(nodeIt)

	// 遍历 trie
	for iter.Next() {
		if last != nil && bytes.Compare(iter.Key, last) > 0 {
			trieMore = true
			break
		}
		count++
		write := true
		created++
		// 处理快照中的键值对
		for len(kvkeys) > 0 {
			if cmp := bytes.Compare(kvkeys[0], iter.Key); cmp < 0 {
				// delete the key
				// 删除键
				istart := time.Now()
				if err := onState(kvkeys[0], nil, false, true); err != nil {
					return false, nil, err
				}
				kvkeys = kvkeys[1:]
				kvvals = kvvals[1:]
				deleted++
				internal += time.Since(istart)
				continue
			} else if cmp == 0 {
				// the snapshot key can be overwritten
				// 快照键可以被覆盖
				created--
				if write = !bytes.Equal(kvvals[0], iter.Value); write {
					updated++
				} else {
					untouched++
				}
				kvkeys = kvkeys[1:]
				kvvals = kvvals[1:]
			}
			break
		}
		istart := time.Now()
		if err := onState(iter.Key, iter.Value, write, false); err != nil {
			return false, nil, err
		}
		internal += time.Since(istart)
	}
	if iter.Err != nil {
		// Trie errors should never happen. Still, in case of a bug, expose the
		// error here, as the outer code will presume errors are interrupts, not
		// some deeper issues.
		// Trie 错误不应该发生。尽管如此，如果出现 bug，这里会暴露错误，
		// 因为外部代码会假定错误是中断，而不是更深层次的问题。
		log.Error("State snapshotter failed to iterate trie", "err", iter.Err)
		return false, nil, iter.Err
	}
	// Delete all stale snapshot states remaining
	// 删除所有剩余的过期快照状态
	istart := time.Now()
	for _, key := range kvkeys {
		if err := onState(key, nil, false, true); err != nil {
			return false, nil, err
		}
		deleted += 1
	}
	internal += time.Since(istart)

	// Update metrics for counting trie iteration
	// 更新计数 trie 迭代的指标
	if kind == snapStorage {
		snapStorageTrieReadCounter.Inc((time.Since(start) - internal).Nanoseconds())
	} else {
		snapAccountTrieReadCounter.Inc((time.Since(start) - internal).Nanoseconds())
	}
	logger.Debug("Regenerated state range", "root", trieId.Root, "last", hexutil.Encode(last),
		"count", count, "created", created, "updated", updated, "untouched", untouched, "deleted", deleted)

	// If there are either more trie items, or there are more snap items
	// (in the next segment), then we need to keep working
	// 如果 trie 或快照中还有更多项（在下一段中），则需要继续工作
	return !trieMore && !result.diskMore, last, nil
}

// checkAndFlush checks if an interruption signal is received or the
// batch size has exceeded the allowance.
// checkAndFlush 检查是否接收到中断信号或批量大小是否超过允许值。
func (dl *diskLayer) checkAndFlush(ctx *generatorContext, current []byte) error {
	var abort chan *generatorStats
	select {
	case abort = <-dl.genAbort: // 检查是否收到中止信号
	default:
	}
	// 如果批量大小超过理想值或收到中止信号
	if ctx.batch.ValueSize() > ethdb.IdealBatchSize || abort != nil {
		// 检查当前标记是否回退
		if bytes.Compare(current, dl.genMarker) < 0 {
			log.Error("Snapshot generator went backwards", "current", fmt.Sprintf("%x", current), "genMarker", fmt.Sprintf("%x", dl.genMarker))
		}
		// Flush out the batch anyway no matter it's empty or not.
		// It's possible that all the states are recovered and the
		// generation indeed makes progress.
		// 无论批量是否为空，都执行刷新
		journalProgress(ctx.batch, current, ctx.stats)

		if err := ctx.batch.Write(); err != nil {
			return err
		}
		ctx.batch.Reset()

		// 更新生成标记
		dl.lock.Lock()
		dl.genMarker = current
		dl.lock.Unlock()

		// 如果收到中止信号，记录并返回错误
		if abort != nil {
			ctx.stats.Log("Aborting state snapshot generation", dl.root, current)
			return newAbortErr(abort) // bubble up an error for interruption
		}
		// Don't hold the iterators too long, release them to let compactor works 释放迭代器，避免长时间占用
		ctx.reopenIterator(snapAccount)
		ctx.reopenIterator(snapStorage)
	}
	// 每隔 8 秒记录一次生成状态
	if time.Since(ctx.logged) > 8*time.Second {
		ctx.stats.Log("Generating state snapshot", dl.root, current)
		ctx.logged = time.Now()
	}
	return nil
}

// generateStorages generates the missing storage slots of the specific contract.
// It's supposed to restart the generation from the given origin position.
// generateStorages 生成特定合约缺失的存储槽。应该从给定的起点位置重新开始生成。
func generateStorages(ctx *generatorContext, dl *diskLayer, stateRoot common.Hash, account common.Hash, storageRoot common.Hash, storeMarker []byte) error {
	// 定义存储处理的回调函数
	onStorage := func(key []byte, val []byte, write bool, delete bool) error {
		defer func(start time.Time) {
			snapStorageWriteCounter.Inc(time.Since(start).Nanoseconds())
		}(time.Now())

		if delete {
			// 删除存储快照
			rawdb.DeleteStorageSnapshot(ctx.batch, account, common.BytesToHash(key))
			snapWipedStorageMeter.Mark(1)
			return nil
		}
		if write {
			// 写入存储快照
			rawdb.WriteStorageSnapshot(ctx.batch, account, common.BytesToHash(key), val)
			snapGeneratedStorageMeter.Mark(1)
		} else {
			snapRecoveredStorageMeter.Mark(1)
		}
		// 更新统计数据
		ctx.stats.storage += common.StorageSize(1 + 2*common.HashLength + len(val))
		ctx.stats.slots++

		// If we've exceeded our batch allowance or termination was requested, flush to disk
		// 检查并刷新批量数据
		if err := dl.checkAndFlush(ctx, append(account[:], key...)); err != nil {
			return err
		}
		return nil
	}
	// Loop for re-generating the missing storage slots.
	// 循环重新生成缺失的存储槽
	var origin = common.CopyBytes(storeMarker)
	for {
		id := trie.StorageTrieID(stateRoot, account, storageRoot)
		exhausted, last, err := dl.generateRange(ctx, id, append(rawdb.SnapshotStoragePrefix, account.Bytes()...), snapStorage, origin, storageCheckRange, onStorage, nil)
		if err != nil {
			return err // The procedure it aborted, either by external signal or internal error.
		}
		// Abort the procedure if the entire contract storage is generated
		// 如果整个合约存储已生成，则退出
		if exhausted {
			break
		}
		if origin = increaseKey(last); origin == nil {
			break // special case, the last is 0xffffffff...fff
		}
	}
	return nil
}

// generateAccounts generates the missing snapshot accounts as well as their
// storage slots in the main trie. It's supposed to restart the generation
// from the given origin position.
// generateAccounts 生成主 trie 中缺失的快照账户及其存储槽。应该从给定的起点位置重新开始生成。
func generateAccounts(ctx *generatorContext, dl *diskLayer, accMarker []byte) error {
	// 定义账户处理的回调函数
	onAccount := func(key []byte, val []byte, write bool, delete bool) error {
		// Make sure to clear all dangling storages before this account
		// 在处理此账户前清理所有悬空存储
		account := common.BytesToHash(key)
		ctx.removeStorageBefore(account)

		start := time.Now()
		if delete {
			// 删除账户快照
			rawdb.DeleteAccountSnapshot(ctx.batch, account)
			snapWipedAccountMeter.Mark(1)
			snapAccountWriteCounter.Inc(time.Since(start).Nanoseconds())
			// 清理该账户的存储
			ctx.removeStorageAt(account)
			return nil
		}
		// Retrieve the current account and flatten it into the internal format
		// 获取当前账户并将其转换为内部格式
		var acc types.StateAccount
		if err := rlp.DecodeBytes(val, &acc); err != nil {
			log.Crit("Invalid account encountered during snapshot creation", "err", err)
		}
		// If the account is not yet in-progress, write it out
		// 如果账户尚未在处理中，写入数据
		if accMarker == nil || !bytes.Equal(account[:], accMarker) {
			dataLen := len(val) // Approximate size, saves us a round of RLP-encoding
			if !write {
				if bytes.Equal(acc.CodeHash, types.EmptyCodeHash[:]) {
					dataLen -= 32
				}
				if acc.Root == types.EmptyRootHash {
					dataLen -= 32
				}
				snapRecoveredAccountMeter.Mark(1)
			} else {
				data := types.SlimAccountRLP(acc)
				dataLen = len(data)
				rawdb.WriteAccountSnapshot(ctx.batch, account, data)
				snapGeneratedAccountMeter.Mark(1)
			}
			// 更新统计数据
			ctx.stats.storage += common.StorageSize(1 + common.HashLength + dataLen)
			ctx.stats.accounts++
		}
		// If the snap generation goes here after interrupted, genMarker may go backward
		// when last genMarker is consisted of accountHash and storageHash
		marker := account[:]
		if accMarker != nil && bytes.Equal(marker, accMarker) && len(dl.genMarker) > common.HashLength {
			marker = dl.genMarker[:]
		}
		// If we've exceeded our batch allowance or termination was requested, flush to disk
		if err := dl.checkAndFlush(ctx, marker); err != nil {
			return err
		}
		snapAccountWriteCounter.Inc(time.Since(start).Nanoseconds()) // let's count flush time as well

		// If the iterated account is the contract, create a further loop to
		// verify or regenerate the contract storage.
		if acc.Root == types.EmptyRootHash {
			ctx.removeStorageAt(account)
		} else {
			var storeMarker []byte
			if accMarker != nil && bytes.Equal(account[:], accMarker) && len(dl.genMarker) > common.HashLength {
				storeMarker = dl.genMarker[common.HashLength:]
			}
			if err := generateStorages(ctx, dl, dl.root, account, acc.Root, storeMarker); err != nil {
				return err
			}
		}
		// Some account processed, unmark the marker
		accMarker = nil
		return nil
	}
	// 循环生成账户
	origin := common.CopyBytes(accMarker)
	for {
		id := trie.StateTrieID(dl.root)
		exhausted, last, err := dl.generateRange(ctx, id, rawdb.SnapshotAccountPrefix, snapAccount, origin, accountCheckRange, onAccount, types.FullAccountRLP)
		if err != nil {
			return err // The procedure it aborted, either by external signal or internal error.
		}
		origin = increaseKey(last)

		// Last step, cleanup the storages after the last account.
		// All the left storages should be treated as dangling.
		if origin == nil || exhausted {
			ctx.removeStorageLeft()
			break
		}
	}
	return nil
}

// generate is a background thread that iterates over the state and storage tries,
// constructing the state snapshot. All the arguments are purely for statistics
// gathering and logging, since the method surfs the blocks as they arrive, often
// being restarted.
// generate 是一个后台线程，迭代状态和存储 trie，构建状态快照。所有参数仅用于统计收集和日志记录，
// 因为该方法会随着区块到达而浏览，通常会频繁重启。
func (dl *diskLayer) generate(stats *generatorStats) {
	var (
		accMarker []byte               // 账户生成标记
		abort     chan *generatorStats // 中止信号通道
	)
	if len(dl.genMarker) > 0 { // []byte{} is the start, use nil for that
		accMarker = dl.genMarker[:common.HashLength]
	}
	stats.Log("Resuming state snapshot generation", dl.root, dl.genMarker)

	// Initialize the global generator context. The snapshot iterators are
	// opened at the interrupted position because the assumption is held
	// that all the snapshot data are generated correctly before the marker.
	// Even if the snapshot data is updated during the interruption (before
	// or at the marker), the assumption is still held.
	// For the account or storage slot at the interruption, they will be
	// processed twice by the generator(they are already processed in the
	// last run) but it's fine.
	ctx := newGeneratorContext(stats, dl.diskdb, accMarker, dl.genMarker)
	defer ctx.close()

	// 生成账户及其存储
	if err := generateAccounts(ctx, dl, accMarker); err != nil {
		// Extract the received interruption signal if exists
		if aerr, ok := err.(*abortErr); ok {
			abort = aerr.abort
		}
		// Aborted by internal error, wait the signal
		if abort == nil {
			abort = <-dl.genAbort
		}
		abort <- stats
		return
	}
	// Snapshot fully generated, set the marker to nil.
	// Note even there is nothing to commit, persist the
	// generator anyway to mark the snapshot is complete.
	journalProgress(ctx.batch, nil, stats)
	if err := ctx.batch.Write(); err != nil {
		log.Error("Failed to flush batch", "err", err)

		abort = <-dl.genAbort
		abort <- stats
		return
	}
	ctx.batch.Reset()

	// 记录生成完成信息
	log.Info("Generated state snapshot", "accounts", stats.accounts, "slots", stats.slots,
		"storage", stats.storage, "dangling", stats.dangling, "elapsed", common.PrettyDuration(time.Since(stats.start)))

	// 更新生成状态
	dl.lock.Lock()
	dl.genMarker = nil
	close(dl.genPending)
	dl.lock.Unlock()

	// Someone will be looking for us, wait it out
	// 等待中止信号
	abort = <-dl.genAbort
	abort <- nil
}

// increaseKey increase the input key by one bit. Return nil if the entire
// addition operation overflows.
// increaseKey 将输入键增加一位。如果整个加法操作溢出，则返回 nil。
func increaseKey(key []byte) []byte {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]++
		if key[i] != 0x0 {
			return key
		}
	}
	return nil
}

// abortErr wraps an interruption signal received to represent the
// generation is aborted by external processes.
// abortErr 包装接收到的中断信号，表示生成被外部进程中止。
type abortErr struct {
	abort chan *generatorStats
}

func newAbortErr(abort chan *generatorStats) error {
	return &abortErr{abort: abort}
}

func (err *abortErr) Error() string {
	return "aborted"
}
