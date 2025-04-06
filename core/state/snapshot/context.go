// Copyright 2022 The go-ethereum Authors
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
	"math"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/log"
)

// 这段代码是 go-ethereum 中关于快照生成 (Snapshot Generation) 的一部分，主要涉及到如何高效地存储和管理以太坊的状态数据。下面我将结合以太坊的原理、黄皮书、EIP 等相关知识进行解释：
//
// 背景：状态爆炸 (State Bloat)
//
// 以太坊的状态是指所有账户的余额、合约代码以及合约的存储数据。随着时间的推移，以太坊区块链上的交易越来越多，导致状态数据急剧增长，这就是所谓的“状态爆炸”。庞大的状态数据给以太坊节点的存储、同步和查询带来了巨大的压力。
//
// 快照 (Snapshotting) 的作用
//
// 为了解决状态爆炸的问题，go-ethereum 实现了状态快照机制。快照是指在某个特定的区块高度，将当前以太坊的状态数据以一种优化的方式存储下来。这样做的好处包括：
//
// 更快的节点同步： 新节点可以从最近的快照开始同步，而不是从创世区块开始，大大缩短了同步时间。
// 更低的存储需求： 快照通常会采用一些压缩和优化的技术，减少存储空间的占用。
// 更快的状态查询： 通过快照可以更快地查询历史状态。

// 以太坊黄皮书 (Ethereum Yellow Paper): 黄皮书中详细定义了以太坊的状态转换函数和数据结构。快照机制是对状态数据存储和管理的一种优化实现，其目标是更高效地维护和访问符合黄皮书规范的状态数据。
// Merkle-Patricia Tree: 快照的生成和验证依赖于 Merkle-Patricia 树的原理。通过存储状态树的根哈希，可以验证快照数据的完整性和一致性。
// EIP (Ethereum Improvement Proposals): 虽然我无法直接指出与这段代码相关的特定 EIP，但有一些 EIP 旨在改进以太坊的状态管理和同步，例如 EIP-1764 (State rent) 和 EIP-2935 (Save historical state root in beacon chain). 这些提案都关注于如何更有效地处理不断增长的状态数据，而快照机制是 go-ethereum 实现这些目标的一种方式。

const (
	snapAccount = "account" // Identifier of account snapshot generation
	// snapAccount 是账户快照生成的标识符
	snapStorage = "storage" // Identifier of storage snapshot generation
	// snapStorage 是存储快照生成的标识符
)

// generatorStats is a collection of statistics gathered by the snapshot generator
// for logging purposes.
// generatorStats 是快照生成器收集的用于日志记录的统计信息集合。
type generatorStats struct {
	origin uint64 // Origin prefix where generation started
	// origin 是生成开始的原始前缀
	start time.Time // Timestamp when generation started
	// start 是生成开始的时间戳
	accounts uint64 // Number of accounts indexed(generated or recovered)
	// accounts 是已索引的账户数量（生成或恢复）
	slots uint64 // Number of storage slots indexed(generated or recovered)
	// slots 是已索引的存储槽数量（生成或恢复）
	dangling uint64 // Number of dangling storage slots
	// dangling 是悬挂存储槽的数量
	storage common.StorageSize // Total account and storage slot size(generation or recovery)
	// storage 是账户和存储槽的总大小（生成或恢复）
}

// Log creates a contextual log with the given message and the context pulled
// from the internally maintained statistics.
// Log 使用给定的消息和从内部维护的统计信息中提取的上下文创建一个上下文日志。
func (gs *generatorStats) Log(msg string, root common.Hash, marker []byte) {
	var ctx []interface{}
	if root != (common.Hash{}) {
		// 如果 root 不是零哈希，则将其添加到上下文信息中
		ctx = append(ctx, []interface{}{"root", root}...)
	}
	// Figure out whether we're after or within an account
	// 判断 marker 是指向一个账户还是账户内的某个存储槽
	switch len(marker) {
	case common.HashLength:
		// 如果 marker 的长度等于哈希长度，则表示指向一个账户
		ctx = append(ctx, []interface{}{"at", common.BytesToHash(marker)}...)
	case 2 * common.HashLength:
		// 如果 marker 的长度是哈希长度的两倍，则表示指向一个账户内的某个存储槽
		ctx = append(ctx, []interface{}{
			"in", common.BytesToHash(marker[:common.HashLength]),
			"at", common.BytesToHash(marker[common.HashLength:]),
		}...)
	}
	// Add the usual measurements
	// 添加常规的度量信息
	ctx = append(ctx, []interface{}{
		"accounts", gs.accounts,
		"slots", gs.slots,
		"storage", gs.storage,
		"dangling", gs.dangling,
		"elapsed", common.PrettyDuration(time.Since(gs.start)),
	}...)
	// Calculate the estimated indexing time based on current stats
	// 根据当前的统计信息计算估计的索引时间
	if len(marker) > 0 {
		if done := binary.BigEndian.Uint64(marker[:8]) - gs.origin; done > 0 {
			// 计算已完成的索引量
			left := math.MaxUint64 - binary.BigEndian.Uint64(marker[:8])
			// 计算剩余的索引量

			speed := done/uint64(time.Since(gs.start)/time.Millisecond+1) + 1 // +1s to avoid division by zero
			// 计算索引速度，加上 1 毫秒和 1 以避免除以零
			ctx = append(ctx, []interface{}{
				"eta", common.PrettyDuration(time.Duration(left/speed) * time.Millisecond),
			}...)
		}
	}
	log.Info(msg, ctx...) // 使用上下文信息记录日志消息
}

// generatorContext carries a few global values to be shared by all generation functions.
// generatorContext 携带一些全局值，供所有生成函数共享。
type generatorContext struct {
	stats *generatorStats // Generation statistic collection
	// stats 是生成统计信息的集合
	db ethdb.KeyValueStore // Key-value store containing the snapshot data
	// db 是包含快照数据的键值存储
	account *holdableIterator // Iterator of account snapshot data
	// account 是账户快照数据的可持有迭代器
	storage *holdableIterator // Iterator of storage snapshot data
	// storage 是存储快照数据的可持有迭代器
	batch ethdb.Batch // Database batch for writing batch data atomically
	// batch 是用于原子写入批量数据的数据库批处理
	logged time.Time // The timestamp when last generation progress was displayed
	// logged 是上次显示生成进度的的时间戳
}

// newGeneratorContext initializes the context for generation.
// newGeneratorContext 初始化生成操作的上下文。
func newGeneratorContext(stats *generatorStats, db ethdb.KeyValueStore, accMarker []byte, storageMarker []byte) *generatorContext {
	ctx := &generatorContext{
		stats:  stats,
		db:     db,
		batch:  db.NewBatch(),
		logged: time.Now(),
	}
	ctx.openIterator(snapAccount, accMarker)     // 打开账户快照迭代器
	ctx.openIterator(snapStorage, storageMarker) // 打开存储快照迭代器
	return ctx
}

// openIterator constructs global account and storage snapshot iterators
// at the interrupted position. These iterators should be reopened from time
// to time to avoid blocking leveldb compaction for a long time.
// openIterator 在中断的位置构建全局账户和存储快照迭代器。这些迭代器应该不时地重新打开，以避免长时间阻塞 leveldb 的压缩。
func (ctx *generatorContext) openIterator(kind string, start []byte) {
	if kind == snapAccount {
		// 如果是账户快照，则创建账户迭代器
		iter := ctx.db.NewIterator(rawdb.SnapshotAccountPrefix, start)
		// 创建一个新的迭代器，该迭代器遍历以 rawdb.SnapshotAccountPrefix 为前缀的数据库条目，并从指定的 start 位置开始。
		// rawdb.SnapshotAccountPrefix 可能定义了账户快照数据在数据库中存储的前缀。
		// start 参数指定了迭代器应该从哪个键开始。这在恢复中断的快照生成过程时非常有用。
		ctx.account = newHoldableIterator(rawdb.NewKeyLengthIterator(iter, 1+common.HashLength))
		// 使用 rawdb.NewKeyLengthIterator 包装原始迭代器 iter。
		// rawdb.NewKeyLengthIterator 可能是用于处理具有特定长度键的迭代器的工具。
		// 在这里，键的长度被指定为 1 + common.HashLength，这可能表示键包含一个类型标识符（长度为 1）和一个账户哈希（长度为 common.HashLength）。
		// 然后，这个带有长度限制的迭代器被传递给 newHoldableIterator，创建一个可持有（holdable）的迭代器。
		// holdableIterator 可能是自定义的迭代器类型，它允许在迭代过程中暂停（hold）当前位置，并在稍后恢复。这在快照生成过程中可能用于优化数据库操作。
		return
	}
	// 如果不是账户快照，则是存储快照
	iter := ctx.db.NewIterator(rawdb.SnapshotStoragePrefix, start)
	// 创建一个新的迭代器，该迭代器遍历以 rawdb.SnapshotStoragePrefix 为前缀的数据库条目，并从指定的 start 位置开始。
	// rawdb.SnapshotStoragePrefix 可能定义了存储快照数据在数据库中存储的前缀。
	ctx.storage = newHoldableIterator(rawdb.NewKeyLengthIterator(iter, 1+2*common.HashLength))
	// 类似地，创建一个用于存储快照数据的可持有迭代器。
	// 键的长度被指定为 1 + 2 * common.HashLength，这可能表示键包含一个类型标识符、一个账户哈希和一个存储槽哈希。
}

// reopenIterator releases the specified snapshot iterator and re-open it
// in the next position. It's aimed for not blocking leveldb compaction.
// reopenIterator 释放指定的快照迭代器，并在下一个位置重新打开它。目的是为了不阻塞 leveldb 的压缩。
func (ctx *generatorContext) reopenIterator(kind string) {
	// Shift iterator one more step, so that we can reopen
	// the iterator at the right position.
	// 将迭代器向前移动一步，以便我们可以在正确的位置重新打开迭代器。
	var iter = ctx.account
	if kind == snapStorage {
		iter = ctx.storage
	}
	hasNext := iter.Next() // 将迭代器移动到下一个位置
	if !hasNext {
		// Iterator exhausted, release forever and create an already exhausted virtual iterator
		// 迭代器已耗尽，永久释放并创建一个已耗尽的虚拟迭代器
		iter.Release()
		if kind == snapAccount {
			ctx.account = newHoldableIterator(memorydb.New().NewIterator(nil, nil))
			return
		}
		ctx.storage = newHoldableIterator(memorydb.New().NewIterator(nil, nil))
		return
	}
	next := iter.Key()               // 获取当前迭代器的键
	iter.Release()                   // 释放当前的迭代器
	ctx.openIterator(kind, next[1:]) // 在下一个位置重新打开迭代器，跳过键的第一个字节（可能是类型标识符）
}

// close releases all the held resources.
// close 释放所有持有的资源。
func (ctx *generatorContext) close() {
	ctx.account.Release() // 释放账户迭代器
	ctx.storage.Release() // 释放存储迭代器
}

// iterator returns the corresponding iterator specified by the kind.
// iterator 返回由 kind 指定的相应迭代器。
func (ctx *generatorContext) iterator(kind string) *holdableIterator {
	if kind == snapAccount {
		return ctx.account
	}
	return ctx.storage
}

// removeStorageBefore deletes all storage entries which are located before
// the specified account. When the iterator touches the storage entry which
// is located in or outside the given account, it stops and holds the current
// iterated element locally.
// removeStorageBefore 删除所有位于指定账户之前的存储条目。当迭代器遇到位于给定账户内或之外的存储条目时，它会停止并将当前迭代的元素本地持有。
func (ctx *generatorContext) removeStorageBefore(account common.Hash) {
	var (
		count uint64
		start = time.Now()
		iter  = ctx.storage
	)
	for iter.Next() { // 遍历存储迭代器中的下一个元素
		key := iter.Key() // 获取当前元素的键
		// 存储快照的键结构可能是 [prefix][account_hash][storage_slot_hash]。
		// 这里比较 key 中账户哈希部分（从索引 1 开始，长度为 common.HashLength）与给定的 account 哈希。
		if bytes.Compare(key[1:1+common.HashLength], account.Bytes()) >= 0 {
			// 如果当前存储条目的账户哈希大于或等于给定的账户哈希，则停止迭代并持有当前元素。
			iter.Hold()
			break
		}
		count++               // 增加删除计数器
		ctx.batch.Delete(key) // 从批处理中删除当前的键
		if ctx.batch.ValueSize() > ethdb.IdealBatchSize {
			// 如果批处理的大小超过了理想大小，则写入批处理并重置。
			ctx.batch.Write()
			ctx.batch.Reset()
		}
	}
	ctx.stats.dangling += count                                  // 将删除的存储条目数添加到悬挂计数器中
	snapStorageCleanCounter.Inc(time.Since(start).Nanoseconds()) // 记录清理存储所花费的时间
}

// removeStorageAt deletes all storage entries which are located in the specified
// account. When the iterator touches the storage entry which is outside the given
// account, it stops and holds the current iterated element locally. An error will
// be returned if the initial position of iterator is not in the given account.
// removeStorageAt 删除所有位于指定账户内的存储条目。当迭代器遇到位于给定账户之外的存储条目时，它会停止并将当前迭代的元素本地持有。如果迭代器的初始位置不在给定的账户内，则会返回错误。
func (ctx *generatorContext) removeStorageAt(account common.Hash) error {
	var (
		count int64
		start = time.Now()
		iter  = ctx.storage
	)
	for iter.Next() { // 遍历存储迭代器中的下一个元素
		key := iter.Key() // 获取当前元素的键
		cmp := bytes.Compare(key[1:1+common.HashLength], account.Bytes())
		// 比较当前存储条目的账户哈希与给定的账户哈希。
		if cmp < 0 {
			// 如果当前存储条目的账户哈希小于给定的账户哈希，说明迭代器的起始位置不在正确的账户内，返回错误。
			return errors.New("invalid iterator position")
		}
		if cmp > 0 {
			// 如果当前存储条目的账户哈希大于给定的账户哈希，说明已经遍历完指定账户的存储条目，停止迭代并持有当前元素。
			iter.Hold()
			break
		}
		count++               // 增加删除计数器
		ctx.batch.Delete(key) // 从批处理中删除当前的键
		if ctx.batch.ValueSize() > ethdb.IdealBatchSize {
			// 如果批处理的大小超过了理想大小，则写入批处理并重置。
			ctx.batch.Write()
			ctx.batch.Reset()
		}
	}
	snapWipedStorageMeter.Mark(count)                            // 记录已擦除的存储条目数量
	snapStorageCleanCounter.Inc(time.Since(start).Nanoseconds()) // 记录清理存储所花费的时间
	return nil
}

// removeStorageLeft deletes all storage entries which are located after
// the current iterator position.
// removeStorageLeft 删除所有位于当前迭代器位置之后的存储条目。
func (ctx *generatorContext) removeStorageLeft() {
	var (
		count uint64
		start = time.Now()
		iter  = ctx.storage
	)
	for iter.Next() { // 遍历存储迭代器中的下一个元素
		count++                      // 增加删除计数器
		ctx.batch.Delete(iter.Key()) // 从批处理中删除当前的键
		if ctx.batch.ValueSize() > ethdb.IdealBatchSize {
			// 如果批处理的大小超过了理想大小，则写入批处理并重置。
			ctx.batch.Write()
			ctx.batch.Reset()
		}
	}
	ctx.stats.dangling += count                                  // 将删除的存储条目数添加到悬挂计数器中
	snapDanglingStorageMeter.Mark(int64(count))                  // 记录悬挂存储条目的数量
	snapStorageCleanCounter.Inc(time.Since(start).Nanoseconds()) // 记录清理存储所花费的时间
}
