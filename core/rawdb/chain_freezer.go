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

package rawdb

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

const (
	// freezerRecheckInterval is the frequency to check the key-value database for
	// chain progression that might permit new blocks to be frozen into immutable
	// storage.
	// freezerRecheckInterval 是检查键值数据库的频率，目的是检测链的进展，
	// 可能允许新的区块被冻结到不可变的存储中。
	freezerRecheckInterval = time.Minute

	// freezerBatchLimit is the maximum number of blocks to freeze in one batch
	// before doing an fsync and deleting it from the key-value store.
	// freezerBatchLimit 是一次冻结操作中最大块的数量，
	// 冻结后需执行 fsync 并从键值存储中删除。
	freezerBatchLimit = 30000
)

// chainFreezer is a wrapper of chain ancient store with additional chain freezing
// feature. The background thread will keep moving ancient chain segments from
// key-value database to flat files for saving space on live database.
// chainFreezer 是链古老存储的一个包装，具有额外的链冻结功能。
// 后台线程将不断将古老链段从键值数据库移动到平面文件中，以节省活动数据库的空间。
type chainFreezer struct {
	ethdb.AncientStore // Ancient store for storing cold chain segment 用于存储冷链段的古老存储

	quit    chan struct{} // 结束信号
	wg      sync.WaitGroup
	trigger chan chan struct{} // Manual blocking freeze trigger, test determinism  手动阻塞冻结触发器，以便测试确定性
}

// newChainFreezer initializes the freezer for ancient chain segment.
//
//   - if the empty directory is given, initializes the pure in-memory
//     state freezer (e.g. dev mode).
//   - if non-empty directory is given, initializes the regular file-based
//     state freezer.
//
// newChainFreezer 初始化古老链段的冷冻存储。
//
//   - if the empty directory is given, initializes the pure in-memory
//     state freezer (e.g. dev mode).
//   - if non-empty directory is given, initializes the regular file-based
//     state freezer.
func newChainFreezer(datadir string, namespace string, readonly bool) (*chainFreezer, error) {
	var (
		err     error
		freezer ethdb.AncientStore
	)
	if datadir == "" {
		// 如果提供的是空目录，则初始化为纯内存冷冻存储（例如，开发模式）。
		freezer = NewMemoryFreezer(readonly, chainFreezerNoSnappy)
	} else {
		// 如果提供的是非空目录，则初始化为基于文件的常规冷冻存储。
		freezer, err = NewFreezer(datadir, namespace, readonly, freezerTableSize, chainFreezerNoSnappy)
	}
	if err != nil {
		return nil, err
	}
	return &chainFreezer{
		AncientStore: freezer,
		quit:         make(chan struct{}),
		trigger:      make(chan chan struct{}),
	}, nil
}

// Close closes the chain freezer instance and terminates the background thread.
// Close 关闭链冷冻存储实例并终止后台线程。
func (f *chainFreezer) Close() error {
	select {
	case <-f.quit:
	default:
		close(f.quit)
	}
	f.wg.Wait()
	return f.AncientStore.Close()
}

// readHeadNumber returns the number of chain head block. 0 is returned if the
// block is unknown or not available yet.
// readHeadNumber 返回链头区块的编号。若未找到或不可用则返回 0。
func (f *chainFreezer) readHeadNumber(db ethdb.KeyValueReader) uint64 {
	hash := ReadHeadBlockHash(db) // 读取链头区块的哈希值
	if hash == (common.Hash{}) {
		log.Error("Head block is not reachable")
		return 0
	}
	number := ReadHeaderNumber(db, hash) // 通过哈希读取区块编号
	if number == nil {
		log.Error("Number of head block is missing")
		return 0
	}
	return *number
}

// readFinalizedNumber returns the number of finalized block. 0 is returned
// if the block is unknown or not available yet.
// readFinalizedNumber 返回已最终确定的区块编号。若未找到或不可用则返回 0。
func (f *chainFreezer) readFinalizedNumber(db ethdb.KeyValueReader) uint64 {
	hash := ReadFinalizedBlockHash(db) // 读取已最终确定的区块的哈希值
	if hash == (common.Hash{}) {
		return 0
	}
	number := ReadHeaderNumber(db, hash) // 通过哈希读取区块编号
	if number == nil {
		log.Error("Number of finalized block is missing")
		return 0
	}
	return *number
}

// freezeThreshold returns the threshold for chain freezing. It's determined
// by formula: max(finality, HEAD-params.FullImmutabilityThreshold).
//
// freezeThreshold 返回链冻结的阈值。由该公式确定：max(finality, HEAD-params.FullImmutabilityThreshold)。
func (f *chainFreezer) freezeThreshold(db ethdb.KeyValueReader) (uint64, error) {
	var (
		head      = f.readHeadNumber(db)      // 获取链头编号
		final     = f.readFinalizedNumber(db) // 获取已最终确定的区块编号
		headLimit uint64
	)
	if head > params.FullImmutabilityThreshold {
		headLimit = head - params.FullImmutabilityThreshold // 计算头部限制
	}
	if final == 0 && headLimit == 0 {
		return 0, errors.New("freezing threshold is not available")
	}
	if final > headLimit {
		return final, nil // 返回最终确定的编号
	}
	return headLimit, nil // 返回头部限制
}

// freeze is a background thread that periodically checks the blockchain for any
// import progress and moves ancient data from the fast database into the freezer.
//
// This functionality is deliberately broken off from block importing to avoid
// incurring additional data shuffling delays on block propagation.
//
// freeze 是一个后台线程，定期检查区块链的导入进展，
// 并将古老数据从快速数据库移动到冷冻存储中。
//
// 此功能故意与区块导入分开，以避免在区块传输时引入额外的数据移动延迟
func (f *chainFreezer) freeze(db ethdb.KeyValueStore) {
	var (
		backoff   bool
		triggered chan struct{} // Used in tests 在测试中使用
		nfdb      = &nofreezedb{KeyValueStore: db}
	)
	timer := time.NewTimer(freezerRecheckInterval) // 创建一个新的定时器
	defer timer.Stop()

	for {
		select {
		case <-f.quit: // 检测是否需要关闭
			log.Info("Freezer shutting down")
			return
		default:
		}
		if backoff {
			// If we were doing a manual trigger, notify it
			if triggered != nil {
				triggered <- struct{}{}
				triggered = nil
			}
			select {
			case <-timer.C:
				backoff = false
				timer.Reset(freezerRecheckInterval)
			case triggered = <-f.trigger: // 手动触发
				backoff = false
			case <-f.quit: // 检测是否需要关闭
				return
			}
		}
		threshold, err := f.freezeThreshold(nfdb) // 计算冻结的阈值
		if err != nil {
			backoff = true
			log.Debug("Current full block not old enough to freeze", "err", err)
			continue
		}
		frozen, _ := f.Ancients() // no error will occur, safe to ignore // 获取已经冻结的区块数

		// Short circuit if the blocks below threshold are already frozen.
		// 如果低于阈值的区块已经冻结，则直接跳过。
		if frozen != 0 && frozen-1 >= threshold {
			backoff = true
			log.Debug("Ancient blocks frozen already", "threshold", threshold, "frozen", frozen)
			continue
		}
		// Seems we have data ready to be frozen, process in usable batches
		// 看起来是时候冻结数据了，按可用批处理进行处理
		var (
			start = time.Now()
			first = frozen    // the first block to freeze  第一个要冻结的区块
			last  = threshold // the last block to freeze  最后一个要冻结的区块
		)
		if last-first+1 > freezerBatchLimit { // 检查是否超出批处理限制
			last = freezerBatchLimit + first - 1 // 设置最后一个区块为批处理限制
		}
		ancients, err := f.freezeRange(nfdb, first, last) // 冻结指定区块范围
		if err != nil {
			log.Error("Error in block freeze operation", "err", err)
			backoff = true
			continue
		}
		// Batch of blocks have been frozen, flush them before wiping from key-value store
		// 已冻结的区块批量写入数据库，清除前需要刷新
		if err := f.Sync(); err != nil {
			log.Crit("Failed to flush frozen tables", "err", err)
		}
		// Wipe out all data from the active database
		batch := db.NewBatch() // 创建一个新的写入批次
		for i := 0; i < len(ancients); i++ {
			// Always keep the genesis block in active database
			if first+uint64(i) != 0 {
				DeleteBlockWithoutNumber(batch, ancients[i], first+uint64(i)) // 从批次中删除区块
				DeleteCanonicalHash(batch, first+uint64(i))                   // 从批次中删除标准哈希
			}
		}
		if err := batch.Write(); err != nil {
			log.Crit("Failed to delete frozen canonical blocks", "err", err)
		}
		batch.Reset()

		// Wipe out side chains also and track dangling side chains
		// 清除旁支链并跟踪悬挂的旁支链
		var dangling []common.Hash
		frozen, _ = f.Ancients() // Needs reload after during freezeRange // 需要在 freezeRange 后重新加载
		for number := first; number < frozen; number++ {
			// Always keep the genesis block in active database
			if number != 0 {
				dangling = ReadAllHashes(db, number) // 读取指定编号的所有哈希值
				for _, hash := range dangling {
					log.Trace("Deleting side chain", "number", number, "hash", hash)
					DeleteBlock(batch, hash, number) // 删除旁支链的区块
				}
			}
		}
		if err := batch.Write(); err != nil {
			log.Crit("Failed to delete frozen side blocks", "err", err)
		}
		batch.Reset()

		// Step into the future and delete any dangling side chains
		// 清理未来的悬挂旁支链
		if frozen > 0 {
			tip := frozen
			for len(dangling) > 0 {
				drop := make(map[common.Hash]struct{})
				for _, hash := range dangling {
					log.Debug("Dangling parent from Freezer", "number", tip-1, "hash", hash)
					drop[hash] = struct{}{}
				}
				children := ReadAllHashes(db, tip)
				for i := 0; i < len(children); i++ {
					// Dig up the child and ensure it's dangling
					// 检查子链是否是悬挂的
					child := ReadHeader(nfdb, children[i], tip)
					if child == nil {
						log.Error("Missing dangling header", "number", tip, "hash", children[i])
						continue
					}
					if _, ok := drop[child.ParentHash]; !ok { // 不是悬挂的
						children = append(children[:i], children[i+1:]...)
						i--
						continue
					}
					// Delete all block data associated with the child
					// 删除与该子链相关的所有区块数据
					log.Debug("Deleting dangling block", "number", tip, "hash", children[i], "parent", child.ParentHash)
					DeleteBlock(batch, children[i], tip)
				}
				dangling = children // 更新悬挂链
				tip++
			}
			if err := batch.Write(); err != nil {
				log.Crit("Failed to delete dangling side blocks", "err", err)
			}
		}

		// Log something friendly for the user
		// 为用户记录友好的信息
		context := []interface{}{
			"blocks", frozen - first, "elapsed", common.PrettyDuration(time.Since(start)), "number", frozen - 1,
		}
		if n := len(ancients); n > 0 {
			context = append(context, []interface{}{"hash", ancients[n-1]}...)
		}
		log.Debug("Deep froze chain segment", context...)

		// Avoid database thrashing with tiny writes
		// 通过控制小写入来避免数据库抖动
		if frozen-first < freezerBatchLimit {
			backoff = true
		}
	}
}

// freezeRange moves a batch of chain segments from the fast database to the freezer.
// The parameters (number, limit) specify the relevant block range, both of which
// are included.
//
// freezeRange 将一批链段从快速数据库移动到冷冻存储。
// 参数 (number, limit) 指定相关的区块范围，二者均被包含。
func (f *chainFreezer) freezeRange(nfdb *nofreezedb, number, limit uint64) (hashes []common.Hash, err error) {
	hashes = make([]common.Hash, 0, limit-number+1) // 初始化哈希数组

	_, err = f.ModifyAncients(func(op ethdb.AncientWriteOp) error {
		for ; number <= limit; number++ {
			// Retrieve all the components of the canonical block.
			// 检索标准区块的所有部分。
			hash := ReadCanonicalHash(nfdb, number)
			if hash == (common.Hash{}) {
				return fmt.Errorf("canonical hash missing, can't freeze block %d", number)
			}
			header := ReadHeaderRLP(nfdb, hash, number)
			if len(header) == 0 {
				return fmt.Errorf("block header missing, can't freeze block %d", number)
			}
			body := ReadBodyRLP(nfdb, hash, number)
			if len(body) == 0 {
				return fmt.Errorf("block body missing, can't freeze block %d", number)
			}
			receipts := ReadReceiptsRLP(nfdb, hash, number)
			if len(receipts) == 0 {
				return fmt.Errorf("block receipts missing, can't freeze block %d", number)
			}
			td := ReadTdRLP(nfdb, hash, number)
			if len(td) == 0 {
				return fmt.Errorf("total difficulty missing, can't freeze block %d", number)
			}

			// Write to the batch.
			if err := op.AppendRaw(ChainFreezerHashTable, number, hash[:]); err != nil {
				return fmt.Errorf("can't write hash to Freezer: %v", err)
			}
			if err := op.AppendRaw(ChainFreezerHeaderTable, number, header); err != nil {
				return fmt.Errorf("can't write header to Freezer: %v", err)
			}
			if err := op.AppendRaw(ChainFreezerBodiesTable, number, body); err != nil {
				return fmt.Errorf("can't write body to Freezer: %v", err)
			}
			if err := op.AppendRaw(ChainFreezerReceiptTable, number, receipts); err != nil {
				return fmt.Errorf("can't write receipts to Freezer: %v", err)
			}
			if err := op.AppendRaw(ChainFreezerDifficultyTable, number, td); err != nil {
				return fmt.Errorf("can't write td to Freezer: %v", err)
			}
			hashes = append(hashes, hash) // 将哈希添加到数组
		}
		return nil
	})
	return hashes, err
}
