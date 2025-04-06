// Copyright 2021 The go-ethereum Authors
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

package pruner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

// 状态 Trie (State Trie): 以太坊使用 Merkle Patricia Trie 来存储当前的账户状态（包括余额、nonce、存储和代码哈希）。状态修剪的目标是删除不再属于最新状态历史的 trie 节点。
// 快照 (Snapshots): 快照是状态 trie 的更轻量级和高效的表示，用于加速状态同步和修剪。它们通过存储状态差异（diff layers）来实现。
// 布隆过滤器 (Bloom Filter): 布隆过滤器是一种概率数据结构，用于快速判断一个元素是否可能在一个集合中。在这里，状态布隆过滤器用于快速判断一个状态 trie 节点或合约代码是否属于当前的活动状态，从而避免删除活动状态的数据。布隆过滤器可能会有假阳性，但假阴性的概率很低。
// 创世状态 (Genesis State): 这是以太坊区块链的初始状态。在状态修剪过程中，必须保留创世状态的数据。
// 数据库压缩 (Database Compaction): LevelDB 等底层数据库在执行删除操作时，通常只是标记数据为删除，并不会立即回收磁盘空间。数据库压缩是一个清理这些标记为删除的数据并回收磁盘空间的过程。
// 离线工具 (Offline Tool): 状态修剪通常是一个耗时的操作，需要在以太坊节点停止运行的情况下进行，因此被称为离线工具。

const (
	// stateBloomFilePrefix is the filename prefix of state bloom filter.
	// stateBloomFilePrefix 是状态布隆过滤器的文件名前缀。
	stateBloomFilePrefix = "statebloom"

	// stateBloomFilePrefix is the filename suffix of state bloom filter.
	// stateBloomFileSuffix 是状态布隆过滤器的文件名后缀。
	stateBloomFileSuffix = "bf.gz"

	// stateBloomFileTempSuffix is the filename suffix of state bloom filter
	// while it is being written out to detect write aborts.
	// stateBloomFileTempSuffix 是状态布隆过滤器在写入时使用的临时文件名后缀，用于检测写入中断。
	stateBloomFileTempSuffix = ".tmp"

	// rangeCompactionThreshold is the minimal deleted entry number for
	// triggering range compaction. It's a quite arbitrary number but just
	// to avoid triggering range compaction because of small deletion.
	// rangeCompactionThreshold 是触发范围压缩的最小删除条目数。这是一个相当随意的数字，只是为了避免因少量删除而触发范围压缩。
	rangeCompactionThreshold = 100000
)

// Config includes all the configurations for pruning.
// Config 包含修剪的所有配置。
type Config struct {
	Datadir string // The directory of the state database
	// Datadir 是状态数据库的目录。
	BloomSize uint64 // The Megabytes of memory allocated to bloom-filter
	// BloomSize 是分配给布隆过滤器的内存大小，单位为兆字节。
}

// Pruner is an offline tool to prune the stale state with the
// help of the snapshot. The workflow of pruner is very simple:
// Pruner 是一个离线工具，用于借助快照修剪过时的状态。修剪器的工作流程非常简单：
//
//   - iterate the snapshot, reconstruct the relevant state
//     遍历快照，重建相关状态
//   - iterate the database, delete all other state entries which
//     遍历数据库，删除所有不属于目标状态和创世状态的其他状态条目
//     don't belong to the target state and the genesis state
//
// It can take several hours(around 2 hours for mainnet) to finish
// the whole pruning work. It's recommended to run this offline tool
// periodically in order to release the disk usage and improve the
// disk read performance to some extent.
// 完成整个修剪工作可能需要几个小时（主网大约 2 小时）。建议定期运行此离线工具，以释放磁盘空间并在一定程度上提高磁盘读取性能。
type Pruner struct {
	config      Config
	chainHeader *types.Header
	db          ethdb.Database
	stateBloom  *stateBloom
	snaptree    *snapshot.Tree
}

// NewPruner creates the pruner instance.
// NewPruner 创建 Pruner 实例。
func NewPruner(db ethdb.Database, config Config) (*Pruner, error) {
	headBlock := rawdb.ReadHeadBlock(db)
	if headBlock == nil {
		return nil, errors.New("failed to load head block")
	}
	// Offline pruning is only supported in legacy hash based scheme.
	// 离线修剪仅在旧的基于哈希的方案中受支持。
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)

	snapconfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   false,
		NoBuild:    true,
		AsyncBuild: false,
	}
	snaptree, err := snapshot.New(snapconfig, db, triedb, headBlock.Root())
	if err != nil {
		return nil, err // The relevant snapshot(s) might not exist
		// 相关的快照可能不存在
	}
	// Sanitize the bloom filter size if it's too small.
	// 如果布隆过滤器大小太小，则进行清理。
	if config.BloomSize < 256 {
		log.Warn("Sanitizing bloomfilter size", "provided(MB)", config.BloomSize, "updated(MB)", 256)
		config.BloomSize = 256
	}
	stateBloom, err := newStateBloomWithSize(config.BloomSize)
	if err != nil {
		return nil, err
	}
	return &Pruner{
		config:      config,
		chainHeader: headBlock.Header(),
		db:          db,
		stateBloom:  stateBloom,
		snaptree:    snaptree,
	}, nil
}

func prune(snaptree *snapshot.Tree, root common.Hash, maindb ethdb.Database, stateBloom *stateBloom, bloomPath string, middleStateRoots map[common.Hash]struct{}, start time.Time) error {
	// Delete all stale trie nodes in the disk. With the help of state bloom
	// the trie nodes(and codes) belong to the active state will be filtered
	// out. A very small part of stale tries will also be filtered because of
	// the false-positive rate of bloom filter. But the assumption is held here
	// that the false-positive is low enough(~0.05%). The probability of the
	// dangling node is the state root is super low. So the dangling nodes in
	// theory will never ever be visited again.
	// 删除磁盘中所有过时的 trie 节点。借助状态布隆过滤器，属于活动状态的 trie 节点（和代码）将被过滤掉。由于布隆过滤器的假阳性率，一小部分过时的 tries 也将被过滤掉。但这里的假设是假阳性率足够低（~0.05%）。状态根是悬挂节点的概率非常低。因此，理论上永远不会再次访问悬挂节点。
	var (
		skipped, count int
		size           common.StorageSize
		pstart         = time.Now()
		logged         = time.Now()
		batch          = maindb.NewBatch()
		iter           = maindb.NewIterator(nil, nil)
	)
	for iter.Next() {
		key := iter.Key()

		// All state entries don't belong to specific state and genesis are deleted here
		// - trie node
		// - legacy contract code
		// - new-scheme contract code
		// 所有不属于特定状态和创世状态的状态条目都在此处删除
		// - trie 节点
		// - 旧合约代码
		// - 新方案合约代码
		isCode, codeKey := rawdb.IsCodeKey(key)
		if len(key) == common.HashLength || isCode {
			checkKey := key
			if isCode {
				checkKey = codeKey
			}
			if _, exist := middleStateRoots[common.BytesToHash(checkKey)]; exist {
				log.Debug("Forcibly delete the middle state roots", "hash", common.BytesToHash(checkKey))
			} else {
				if stateBloom.Contain(checkKey) {
					skipped += 1
					continue
				}
			}
			count += 1
			size += common.StorageSize(len(key) + len(iter.Value()))
			batch.Delete(key)

			var eta time.Duration // Realistically will never remain uninited
			// 实际上永远不会保持未初始化
			if done := binary.BigEndian.Uint64(key[:8]); done > 0 {
				var (
					left  = math.MaxUint64 - binary.BigEndian.Uint64(key[:8])
					speed = done/uint64(time.Since(pstart)/time.Millisecond+1) + 1 // +1s to avoid division by zero
					// +1 秒以避免除以零
				)
				eta = time.Duration(left/speed) * time.Millisecond
			}
			if time.Since(logged) > 8*time.Second {
				log.Info("Pruning state data", "nodes", count, "skipped", skipped, "size", size,
					"elapsed", common.PrettyDuration(time.Since(pstart)), "eta", common.PrettyDuration(eta))
				logged = time.Now()
			}
			// Recreate the iterator after every batch commit in order
			// to allow the underlying compactor to delete the entries.
			// 在每次批量提交后重新创建迭代器，以便允许底层压缩器删除条目。
			if batch.ValueSize() >= ethdb.IdealBatchSize {
				batch.Write()
				batch.Reset()

				iter.Release()
				iter = maindb.NewIterator(nil, key)
			}
		}
	}
	if batch.ValueSize() > 0 {
		batch.Write()
		batch.Reset()
	}
	iter.Release()
	log.Info("Pruned state data", "nodes", count, "size", size, "elapsed", common.PrettyDuration(time.Since(pstart)))

	// Pruning is done, now drop the "useless" layers from the snapshot.
	// Firstly, flushing the target layer into the disk. After that all
	// diff layers below the target will all be merged into the disk.
	// 修剪完成，现在从快照中删除“无用”的层。首先，将目标层刷新到磁盘。之后，目标层以下的所有差异层都将合并到磁盘中。
	if err := snaptree.Cap(root, 0); err != nil {
		return err
	}
	// Secondly, flushing the snapshot journal into the disk. All diff
	// layers upon are dropped silently. Eventually the entire snapshot
	// tree is converted into a single disk layer with the pruning target
	// as the root.
	// 其次，将快照日志刷新到磁盘。其上的所有差异层都将被静默删除。最终，整个快照树将转换为以修剪目标为根的单个磁盘层。
	if _, err := snaptree.Journal(root); err != nil {
		return err
	}
	// Delete the state bloom, it marks the entire pruning procedure is
	// finished. If any crashes or manual exit happens before this,
	// `RecoverPruning` will pick it up in the next restarts to redo all
	// the things.
	// 删除状态布隆过滤器，它标志着整个修剪过程已完成。如果在此之前发生任何崩溃或手动退出，`RecoverPruning` 将在下次重新启动时拾取它以重新执行所有操作。
	os.RemoveAll(bloomPath)

	// Start compactions, will remove the deleted data from the disk immediately.
	// Note for small pruning, the compaction is skipped.
	// 开始压缩，将立即从磁盘中删除已删除的数据。请注意，对于小规模修剪，将跳过压缩。
	if count >= rangeCompactionThreshold {
		cstart := time.Now()
		for b := 0x00; b <= 0xf0; b += 0x10 {
			var (
				start = []byte{byte(b)}
				end   = []byte{byte(b + 0x10)}
			)
			if b == 0xf0 {
				end = nil
			}
			log.Info("Compacting database", "range", fmt.Sprintf("%#x-%#x", start, end), "elapsed", common.PrettyDuration(time.Since(cstart)))
			if err := maindb.Compact(start, end); err != nil {
				log.Error("Database compaction failed", "error", err)
				return err
			}
		}
		log.Info("Database compaction finished", "elapsed", common.PrettyDuration(time.Since(cstart)))
	}
	log.Info("State pruning successful", "pruned", size, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}

// Prune deletes all historical state nodes except the nodes belong to the
// specified state version. If user doesn't specify the state version, use
// the bottom-most snapshot diff layer as the target.
// Prune 删除所有历史状态节点，除了属于指定状态版本的节点。如果用户未指定状态版本，则使用最底层的快照差异层作为目标。
func (p *Pruner) Prune(root common.Hash) error {
	// If the state bloom filter is already committed previously,
	// reuse it for pruning instead of generating a new one. It's
	// mandatory because a part of state may already be deleted,
	// the recovery procedure is necessary.
	// 如果状态布隆过滤器之前已经提交，则重用它进行修剪，而不是生成新的。这是强制性的，因为可能已经删除了一部分状态，因此需要恢复过程。
	_, stateBloomRoot, err := findBloomFilter(p.config.Datadir)
	if err != nil {
		return err
	}
	if stateBloomRoot != (common.Hash{}) {
		return RecoverPruning(p.config.Datadir, p.db)
	}
	// If the target state root is not specified, use the HEAD-127 as the
	// target. The reason for picking it is:
	// - in most of the normal cases, the related state is available
	// - the probability of this layer being reorg is very low
	// 如果未指定目标状态根，则使用 HEAD-127 作为目标。选择它的原因是：
	// - 在大多数正常情况下，相关状态可用
	// - 此层发生重组的可能性非常低
	var layers []snapshot.Snapshot
	if root == (common.Hash{}) {
		// Retrieve all snapshot layers from the current HEAD.
		// In theory there are 128 difflayers + 1 disk layer present,
		// so 128 diff layers are expected to be returned.
		// 从当前的 HEAD 中检索所有快照层。理论上存在 128 个差异层 + 1 个磁盘层，因此预计返回 128 个差异层。
		layers = p.snaptree.Snapshots(p.chainHeader.Root, 128, true)
		if len(layers) != 128 {
			// Reject if the accumulated diff layers are less than 128. It
			// means in most of normal cases, there is no associated state
			// with bottom-most diff layer.
			// 如果累积的差异层少于 128，则拒绝。这意味着在大多数正常情况下，最底层的差异层没有关联的状态。
			return fmt.Errorf("snapshot not old enough yet: need %d more blocks", 128-len(layers))
		}
		// Use the bottom-most diff layer as the target
		// 使用最底层的差异层作为目标
		root = layers[len(layers)-1].Root()
	}
	// Ensure the root is really present. The weak assumption
	// is the presence of root can indicate the presence of the
	// entire trie.
	// 确保根确实存在。一个弱假设是根的存在可以表明整个 trie 的存在。
	if !rawdb.HasLegacyTrieNode(p.db, root) {
		// The special case is for clique based networks, it's possible
		// that two consecutive blocks will have same root. In this case
		// snapshot difflayer won't be created. So HEAD-127 may not paired
		// with head-127 layer. Instead the paired layer is higher than the
		// bottom-most diff layer. Try to find the bottom-most snapshot
		// layer with state available.
		//
		// Note HEAD and HEAD-1 is ignored. Usually there is the associated
		// state available, but we don't want to use the topmost state
		// as the pruning target.
		// 特殊情况是对于基于 Clique 的网络，两个连续的区块可能具有相同的根。在这种情况下，不会创建快照差异层。因此，HEAD-127 可能不会与 head-127 层配对。相反，配对的层高于最底层的差异层。尝试查找具有可用状态的最底层的快照层。
		//
		// 注意：HEAD 和 HEAD-1 被忽略。通常有相关的状态可用，但我们不想使用最顶层的状态作为修剪目标。
		var found bool
		for i := len(layers) - 2; i >= 2; i-- {
			if rawdb.HasLegacyTrieNode(p.db, layers[i].Root()) {
				root = layers[i].Root()
				found = true
				log.Info("Selecting middle-layer as the pruning target", "root", root, "depth", i)
				break
			}
		}
		if !found {
			if len(layers) > 0 {
				return errors.New("no snapshot paired state")
			}
			return fmt.Errorf("associated state[%x] is not present", root)
		}
	} else {
		if len(layers) > 0 {
			log.Info("Selecting bottom-most difflayer as the pruning target", "root", root, "height", p.chainHeader.Number.Uint64()-127)
		} else {
			log.Info("Selecting user-specified state as the pruning target", "root", root)
		}
	}
	// All the state roots of the middle layer should be forcibly pruned,
	// otherwise the dangling state will be left.
	// 中间层的所有状态根都应该被强制修剪，否则会留下悬挂状态。
	middleRoots := make(map[common.Hash]struct{})
	for _, layer := range layers {
		if layer.Root() == root {
			break
		}
		middleRoots[layer.Root()] = struct{}{}
	}
	// Traverse the target state, re-construct the whole state trie and
	// commit to the given bloom filter.
	// 遍历目标状态，重建整个状态 trie 并提交到给定的布隆过滤器。
	start := time.Now()
	if err := snapshot.GenerateTrie(p.snaptree, root, p.db, p.stateBloom); err != nil {
		return err
	}
	// Traverse the genesis, put all genesis state entries into the
	// bloom filter too.
	// 遍历创世状态，并将所有创世状态条目也放入布隆过滤器中。
	if err := extractGenesis(p.db, p.stateBloom); err != nil {
		return err
	}
	filterName := bloomFilterName(p.config.Datadir, root)

	log.Info("Writing state bloom to disk", "name", filterName)
	if err := p.stateBloom.Commit(filterName, filterName+stateBloomFileTempSuffix); err != nil {
		return err
	}
	log.Info("State bloom filter committed", "name", filterName)
	return prune(p.snaptree, root, p.db, p.stateBloom, filterName, middleRoots, start)
}

// RecoverPruning will resume the pruning procedure during the system restart.
// This function is used in this case: user tries to prune state data, but the
// system was interrupted midway because of crash or manual-kill. In this case
// if the bloom filter for filtering active state is already constructed, the
// pruning can be resumed. What's more if the bloom filter is constructed, the
// pruning **has to be resumed**. Otherwise a lot of dangling nodes may be left
// in the disk.
// RecoverPruning 将在系统重新启动期间恢复修剪过程。此函数用于以下情况：用户尝试修剪状态数据，但由于崩溃或手动终止导致系统在中间中断。在这种情况下，如果用于过滤活动状态的布隆过滤器已经构建，则可以恢复修剪。更重要的是，如果布隆过滤器已构建，则**必须**恢复修剪。否则，磁盘中可能会留下许多悬挂节点。
func RecoverPruning(datadir string, db ethdb.Database) error {
	stateBloomPath, stateBloomRoot, err := findBloomFilter(datadir)
	if err != nil {
		return err
	}
	if stateBloomPath == "" {
		return nil // nothing to recover
		// 无需恢复
	}
	headBlock := rawdb.ReadHeadBlock(db)
	if headBlock == nil {
		return errors.New("failed to load head block")
	}
	// Initialize the snapshot tree in recovery mode to handle this special case:
	// - Users run the `prune-state` command multiple times
	// - Neither these `prune-state` running is finished(e.g. interrupted manually)
	// - The state bloom filter is already generated, a part of state is deleted,
	//   so that resuming the pruning here is mandatory
	// - The state HEAD is rewound already because of multiple incomplete `prune-state`
	// In this case, even the state HEAD is not exactly matched with snapshot, it
	// still feasible to recover the pruning correctly.
	// 在恢复模式下初始化快照树以处理此特殊情况：
	// - 用户多次运行 `prune-state` 命令
	// - 这些 `prune-state` 运行都没有完成（例如，手动中断）
	// - 状态布隆过滤器已经生成，一部分状态已被删除，因此必须在此处恢复修剪
	// - 由于多次不完整的 `prune-state` 操作，状态 HEAD 已经回滚
	// 在这种情况下，即使状态 HEAD 与快照不完全匹配，仍然可以正确地恢复修剪。
	snapconfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   true,
		NoBuild:    true,
		AsyncBuild: false,
	}
	// Offline pruning is only supported in legacy hash based scheme.
	// 离线修剪仅在旧的基于哈希的方案中受支持。
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)
	snaptree, err := snapshot.New(snapconfig, db, triedb, headBlock.Root())
	if err != nil {
		return err // The relevant snapshot(s) might not exist
		// 相关的快照可能不存在
	}
	stateBloom, err := NewStateBloomFromDisk(stateBloomPath)
	if err != nil {
		return err
	}
	log.Info("Loaded state bloom filter", "path", stateBloomPath)

	// All the state roots of the middle layers should be forcibly pruned,
	// otherwise the dangling state will be left.
	// 中间层的所有状态根都应该被强制修剪，否则会留下悬挂状态。
	var (
		found       bool
		layers      = snaptree.Snapshots(headBlock.Root(), 128, true)
		middleRoots = make(map[common.Hash]struct{})
	)
	for _, layer := range layers {
		if layer.Root() == stateBloomRoot {
			found = true
			break
		}
		middleRoots[layer.Root()] = struct{}{}
	}
	if !found {
		log.Error("Pruning target state is not existent")
		return errors.New("non-existent target state")
	}
	return prune(snaptree, stateBloomRoot, db, stateBloom, stateBloomPath, middleRoots, time.Now())
}

// extractGenesis loads the genesis state and commits all the state entries
// into the given bloomfilter.
// extractGenesis 加载创世状态并将所有状态条目提交到给定的布隆过滤器。
func extractGenesis(db ethdb.Database, stateBloom *stateBloom) error {
	genesisHash := rawdb.ReadCanonicalHash(db, 0)
	if genesisHash == (common.Hash{}) {
		return errors.New("missing genesis hash")
	}
	genesis := rawdb.ReadBlock(db, genesisHash, 0)
	if genesis == nil {
		return errors.New("missing genesis block")
	}
	t, err := trie.NewStateTrie(trie.StateTrieID(genesis.Root()), triedb.NewDatabase(db, triedb.HashDefaults))
	if err != nil {
		return err
	}
	accIter, err := t.NodeIterator(nil)
	if err != nil {
		return err
	}
	for accIter.Next(true) {
		hash := accIter.Hash()

		// Embedded nodes don't have hash.
		// 嵌入式节点没有哈希。
		if hash != (common.Hash{}) {
			stateBloom.Put(hash.Bytes(), nil)
		}
		// If it's a leaf node, yes we are touching an account,
		// dig into the storage trie further.
		// 如果它是叶子节点，是的，我们正在访问一个账户，进一步深入到存储 trie 中。
		if accIter.Leaf() {
			var acc types.StateAccount
			if err := rlp.DecodeBytes(accIter.LeafBlob(), &acc); err != nil {
				return err
			}
			if acc.Root != types.EmptyRootHash {
				id := trie.StorageTrieID(genesis.Root(), common.BytesToHash(accIter.LeafKey()), acc.Root)
				storageTrie, err := trie.NewStateTrie(id, triedb.NewDatabase(db, triedb.HashDefaults))
				if err != nil {
					return err
				}
				storageIter, err := storageTrie.NodeIterator(nil)
				if err != nil {
					return err
				}
				for storageIter.Next(true) {
					hash := storageIter.Hash()
					if hash != (common.Hash{}) {
						stateBloom.Put(hash.Bytes(), nil)
					}
				}
				if storageIter.Error() != nil {
					return storageIter.Error()
				}
			}
			if !bytes.Equal(acc.CodeHash, types.EmptyCodeHash.Bytes()) {
				stateBloom.Put(acc.CodeHash, nil)
			}
		}
	}
	return accIter.Error()
}

func bloomFilterName(datadir string, hash common.Hash) string {
	return filepath.Join(datadir, fmt.Sprintf("%s.%s.%s", stateBloomFilePrefix, hash.Hex(), stateBloomFileSuffix))
}

func isBloomFilter(filename string) (bool, common.Hash) {
	filename = filepath.Base(filename)
	if strings.HasPrefix(filename, stateBloomFilePrefix) && strings.HasSuffix(filename, stateBloomFileSuffix) {
		return true, common.HexToHash(filename[len(stateBloomFilePrefix)+1 : len(filename)-len(stateBloomFileSuffix)-1])
	}
	return false, common.Hash{}
}

func findBloomFilter(datadir string) (string, common.Hash, error) {
	var (
		stateBloomPath string
		stateBloomRoot common.Hash
	)
	if err := filepath.Walk(datadir, func(path string, info os.FileInfo, err error) error {
		if info != nil && !info.IsDir() {
			ok, root := isBloomFilter(path)
			if ok {
				stateBloomPath = path
				stateBloomRoot = root
			}
		}
		return nil
	}); err != nil {
		return "", common.Hash{}, err
	}
	return stateBloomPath, stateBloomRoot, nil
}
