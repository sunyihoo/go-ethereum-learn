// Copyright 2018 The go-ethereum Authors
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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/olekukonko/tablewriter"
)

// freezerdb is a database wrapper that enables ancient chain segment freezing.
// freezerdb 是一个数据库包装器，支持将古老的链段冻结。
type freezerdb struct {
	ethdb.KeyValueStore
	*chainFreezer

	readOnly    bool
	ancientRoot string
}

// AncientDatadir returns the path of root ancient directory.
// AncientDatadir 返回根祖先目录的路径。
func (frdb *freezerdb) AncientDatadir() (string, error) {
	return frdb.ancientRoot, nil
}

// Close implements io.Closer, closing both the fast key-value store as well as
// the slow ancient tables.
// Close 实现了 io.Closer，关闭快速键值存储和慢速古董表。
func (frdb *freezerdb) Close() error {
	var errs []error
	if err := frdb.chainFreezer.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := frdb.KeyValueStore.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) != 0 {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

// Freeze is a helper method used for external testing to trigger and block until
// a freeze cycle completes, without having to sleep for a minute to trigger the
// automatic background run.
// Freeze 是一个辅助方法，用于外部测试以触发并阻塞直到冻结周期完成，而不需要睡眠一分钟来触发自动后台运行。
func (frdb *freezerdb) Freeze() error {
	if frdb.readOnly {
		return errReadOnly
	}
	// Trigger a freeze cycle and block until it's done
	// 触发冻结周期并阻塞直到完成
	trigger := make(chan struct{}, 1)
	frdb.chainFreezer.trigger <- trigger
	<-trigger
	return nil
}

// nofreezedb is a database wrapper that disables freezer data retrievals.
// nofreezedb 是一个数据库包装器，禁用冻结数据检索。
type nofreezedb struct {
	ethdb.KeyValueStore
}

// HasAncient returns an error as we don't have a backing chain freezer.
// HasAncient 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) HasAncient(kind string, number uint64) (bool, error) {
	return false, errNotSupported
}

// Ancient returns an error as we don't have a backing chain freezer.
// Ancient 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) Ancient(kind string, number uint64) ([]byte, error) {
	return nil, errNotSupported
}

// AncientRange returns an error as we don't have a backing chain freezer.
// AncientRange 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) AncientRange(kind string, start, max, maxByteSize uint64) ([][]byte, error) {
	return nil, errNotSupported
}

// Ancients returns an error as we don't have a backing chain freezer.
// Ancients 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) Ancients() (uint64, error) {
	return 0, errNotSupported
}

// Tail returns an error as we don't have a backing chain freezer.
// Tail 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) Tail() (uint64, error) {
	return 0, errNotSupported
}

// AncientSize returns an error as we don't have a backing chain freezer.
// AncientSize 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) AncientSize(kind string) (uint64, error) {
	return 0, errNotSupported
}

// ModifyAncients is not supported.
// ModifyAncients 不支持。
func (db *nofreezedb) ModifyAncients(func(ethdb.AncientWriteOp) error) (int64, error) {
	return 0, errNotSupported
}

// TruncateHead returns an error as we don't have a backing chain freezer.
// TruncateHead 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) TruncateHead(items uint64) (uint64, error) {
	return 0, errNotSupported
}

// TruncateTail returns an error as we don't have a backing chain freezer.
// TruncateTail 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) TruncateTail(items uint64) (uint64, error) {
	return 0, errNotSupported
}

// Sync returns an error as we don't have a backing chain freezer.
// Sync 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) Sync() error {
	return errNotSupported
}

func (db *nofreezedb) ReadAncients(fn func(reader ethdb.AncientReaderOp) error) (err error) {
	// Unlike other ancient-related methods, this method does not return
	// errNotSupported when invoked.
	// The reason for this is that the caller might want to do several things:
	// 1. Check if something is in the freezer,
	// 2. If not, check leveldb.
	//
	// This will work, since the ancient-checks inside 'fn' will return errors,
	// and the leveldb work will continue.
	//
	// If we instead were to return errNotSupported here, then the caller would
	// have to explicitly check for that, having an extra clause to do the
	// non-ancient operations.
	//
	// ReadAncients 不像其他与古董相关的方法，此方法在调用时不返回 errNotSupported。
	// 原因是调用者可能想做几件事：
	// 1. 检查某些内容是否在冻结器中，
	// 2. 如果不在，则检查 leveldb。
	//
	// 这将有效，因为 'fn' 内部的古董检查将返回错误，而 leveldb 的工作将继续。
	//
	// 如果我们在这里返回 errNotSupported，则调用者必须显式检查该错误，增加额外的非古董操作子句。
	return fn(db)
}

// AncientDatadir returns an error as we don't have a backing chain freezer.
// AncientDatadir 返回一个错误，因为我们没有支持链冻结器。
func (db *nofreezedb) AncientDatadir() (string, error) {
	return "", errNotSupported
}

// NewDatabase creates a high level database on top of a given key-value data
// store without a freezer moving immutable chain segments into cold storage.
// NewDatabase 在给定的键值数据存储上创建一个高级数据库，而不使用冻结器将不可变的链段移动到冷存储。
func NewDatabase(db ethdb.KeyValueStore) ethdb.Database {
	return &nofreezedb{KeyValueStore: db}
}

// resolveChainFreezerDir is a helper function which resolves the absolute path
// of chain freezer by considering backward compatibility.
// resolveChainFreezerDir 是一个辅助函数，通过考虑向后兼容性来解析链冻结器的绝对路径。
func resolveChainFreezerDir(ancient string) string {
	// Check if the chain freezer is already present in the specified
	// sub folder, if not then two possibilities:
	// - chain freezer is not initialized
	// - chain freezer exists in legacy location (root ancient folder)
	// 检查链冻结器是否已存在于指定的子文件夹中，如果不存在则有两种可能：
	// - 链冻结器未初始化
	// - 链冻结器存在于旧位置（根古董文件夹）
	freezer := filepath.Join(ancient, ChainFreezerName)
	if !common.FileExist(freezer) {
		if !common.FileExist(ancient) {
			// The entire ancient store is not initialized, still use the sub
			// folder for initialization.
			// 整个古董存储未初始化，仍然使用子文件夹进行初始化。
		} else {
			// Ancient root is already initialized, then we hold the assumption
			// that chain freezer is also initialized and located in root folder.
			// In this case fallback to legacy location.
			// 古董根目录已初始化，我们假设链冻结器也已初始化并位于根文件夹中。
			// 在这种情况下回退到旧位置。
			freezer = ancient
			log.Info("Found legacy ancient chain path", "location", ancient)
		}
	}
	return freezer
}

// NewDatabaseWithFreezer creates a high level database on top of a given key-
// value data store with a freezer moving immutable chain segments into cold
// storage. The passed ancient indicates the path of root ancient directory
// where the chain freezer can be opened.
// NewDatabaseWithFreezer 在给定的键值数据存储上创建一个高级数据库，并使用冻结器将不可变的链段移动到冷存储。传递的 ancient 指示链冻结器可以打开的根古董目录的路径。
func NewDatabaseWithFreezer(db ethdb.KeyValueStore, ancient string, namespace string, readonly bool) (ethdb.Database, error) {
	// Create the idle freezer instance. If the given ancient directory is empty,
	// in-memory chain freezer is used (e.g. dev mode); otherwise the regular
	// file-based freezer is created.
	// 创建空闲冻结器实例。如果给定的古董目录为空，则使用内存中的链冻结器（例如开发模式）；否则创建常规的文件基础冻结器。
	chainFreezerDir := ancient
	if chainFreezerDir != "" {
		chainFreezerDir = resolveChainFreezerDir(chainFreezerDir)
	}
	frdb, err := newChainFreezer(chainFreezerDir, namespace, readonly)
	if err != nil {
		printChainMetadata(db)
		return nil, err
	}
	// Since the freezer can be stored separately from the user's key-value database,
	// there's a fairly high probability that the user requests invalid combinations
	// of the freezer and database. Ensure that we don't shoot ourselves in the foot
	// by serving up conflicting data, leading to both datastores getting corrupted.
	//
	//   - If both the freezer and key-value store are empty (no genesis), we just
	//     initialized a new empty freezer, so everything's fine.
	//   - If the key-value store is empty, but the freezer is not, we need to make
	//     sure the user's genesis matches the freezer. That will be checked in the
	//     blockchain, since we don't have the genesis block here (nor should we at
	//     this point care, the key-value/freezer combo is valid).
	//   - If neither the key-value store nor the freezer is empty, cross validate
	//     the genesis hashes to make sure they are compatible. If they are, also
	//     ensure that there's no gap between the freezer and subsequently leveldb.
	//   - If the key-value store is not empty, but the freezer is, we might just be
	//     upgrading to the freezer release, or we might have had a small chain and
	//     not frozen anything yet. Ensure that no blocks are missing yet from the
	//     key-value store, since that would mean we already had an old freezer.
	// 由于冻结器可以与用户的键值数据库分开存储，用户请求冻结器和数据库的无效组合的可能性相当高。
	// 确保我们不会因为提供冲突数据而自找麻烦，导致两个数据存储都被损坏。
	//
	//   - 如果冻结器和键值存储都为空（没有创世块），我们刚初始化了一个新的空冻结器，一切正常。
	//   - 如果键值存储为空，但冻结器不为空，我们需要确保用户的创世块与冻结器匹配。这将在区块链中检查，
	//     因为我们这里没有创世块（此时也不应该关心，键值/冻结器组合是有效的）。
	//   - 如果键值存储和冻结器都不为空，交叉验证创世块哈希以确保它们兼容。如果兼容，还要确保冻结器和后续的 leveldb 之间没有间隙。
	//   - 如果键值存储不为空，但冻结器为空，我们可能正在升级到冻结器版本，或者我们有一个小的链且尚未冻结任何东西。
	//     确保键值存储中尚未缺少任何块，否则这意味着我们已经有一个旧的冻结器。

	// If the genesis hash is empty, we have a new key-value store, so nothing to
	// validate in this method. If, however, the genesis hash is not nil, compare
	// it to the freezer content.
	// 如果创世块哈希为空，我们有一个新的键值存储，因此此方法无需验证。
	// 然而，如果创世块哈希不为空，则将其与冻结器内容进行比较。
	if kvgenesis, _ := db.Get(headerHashKey(0)); len(kvgenesis) > 0 {
		if frozen, _ := frdb.Ancients(); frozen > 0 {
			// If the freezer already contains something, ensure that the genesis blocks
			// match, otherwise we might mix up freezers across chains and destroy both
			// the freezer and the key-value store.
			// 如果冻结器已包含某些内容，确保创世块匹配，否则我们可能会混淆不同链的冻结器并毁坏冻结器和键值存储。
			frgenesis, err := frdb.Ancient(ChainFreezerHashTable, 0)
			if err != nil {
				printChainMetadata(db)
				return nil, fmt.Errorf("failed to retrieve genesis from ancient %v", err)
			} else if !bytes.Equal(kvgenesis, frgenesis) {
				printChainMetadata(db)
				return nil, fmt.Errorf("genesis mismatch: %#x (leveldb) != %#x (ancients)", kvgenesis, frgenesis)
			}
			// Key-value store and freezer belong to the same network. Ensure that they
			// are contiguous, otherwise we might end up with a non-functional freezer.
			// 键值存储和冻结器属于同一网络。确保它们是连续的，否则我们可能会得到一个无法使用的冻结器。
			if kvhash, _ := db.Get(headerHashKey(frozen)); len(kvhash) == 0 {
				// Subsequent header after the freezer limit is missing from the database.
				// Reject startup if the database has a more recent head.
				// 冻结器限制后的后续头部在数据库中缺失。
				// 如果数据库有更新的头部，则拒绝启动。
				if head := *ReadHeaderNumber(db, ReadHeadHeaderHash(db)); head > frozen-1 {
					// Find the smallest block stored in the key-value store
					// in range of [frozen, head]
					// 在 [frozen, head] 范围内找到键值存储中存储的最小块
					var number uint64
					for number = frozen; number <= head; number++ {
						if present, _ := db.Has(headerHashKey(number)); present {
							break
						}
					}
					// We are about to exit on error. Print database metadata before exiting
					// 我们即将因错误退出。在退出前打印数据库元数据
					printChainMetadata(db)
					return nil, fmt.Errorf("gap in the chain between ancients [0 - #%d] and leveldb [#%d - #%d] ",
						frozen-1, number, head)
				}
				// Database contains only older data than the freezer, this happens if the
				// state was wiped and reinited from an existing freezer.
				// 数据库仅包含比冻结器更旧的数据，如果状态被擦除并从现有冻结器重新初始化，则会发生这种情况。
			}
			// Otherwise, key-value store continues where the freezer left off, all is fine.
			// We might have duplicate blocks (crash after freezer write but before key-value
			// store deletion, but that's fine).
			// 否则，键值存储从冻结器停止的地方继续，一切正常。
			// 我们可能有重复的块（冻结器写入后但键值存储删除前崩溃，但这没问题）。
		} else {
			// If the freezer is empty, ensure nothing was moved yet from the key-value
			// store, otherwise we'll end up missing data. We check block #1 to decide
			// if we froze anything previously or not, but do take care of databases with
			// only the genesis block.
			// 如果冻结器为空，确保尚未从键值存储中移动任何内容，否则我们会丢失数据。
			// 我们检查第 1 块以决定之前是否冻结了任何东西，但要注意只有创世块的数据库。
			if ReadHeadHeaderHash(db) != common.BytesToHash(kvgenesis) {
				// Key-value store contains more data than the genesis block, make sure we
				// didn't freeze anything yet.
				// 键值存储包含比创世块更多的数据，确保我们尚未冻结任何东西。
				if kvblob, _ := db.Get(headerHashKey(1)); len(kvblob) == 0 {
					printChainMetadata(db)
					return nil, errors.New("ancient chain segments already extracted, please set --datadir.ancient to the correct path")
				}
				// Block #1 is still in the database, we're allowed to init a new freezer
				// 第 1 块仍在数据库中，我们可以初始化一个新的冻结器
			}
			// Otherwise, the head header is still the genesis, we're allowed to init a new
			// freezer.
			// 否则，头部仍是创世块，我们可以初始化一个新的冻结器。
		}
	}
	// Freezer is consistent with the key-value database, permit combining the two
	// 冻结器与键值数据库一致，允许组合两者
	if !readonly {
		frdb.wg.Add(1)
		go func() {
			frdb.freeze(db)
			frdb.wg.Done()
		}()
	}
	return &freezerdb{
		ancientRoot:   ancient,
		KeyValueStore: db,
		chainFreezer:  frdb,
	}, nil
}

// NewMemoryDatabase creates an ephemeral in-memory key-value database without a
// freezer moving immutable chain segments into cold storage.
// NewMemoryDatabase 创建一个临时的内存键值数据库，而不使用冻结器将不可变的链段移动到冷存储。
func NewMemoryDatabase() ethdb.Database {
	return NewDatabase(memorydb.New())
}

const (
	DBPebble  = "pebble"
	DBLeveldb = "leveldb"
)

// PreexistingDatabase checks the given data directory whether a database is already
// instantiated at that location, and if so, returns the type of database (or the
// empty string).
// PreexistingDatabase 检查给定的数据目录是否已经存在数据库实例，如果存在，则返回数据库的类型（否则返回空字符串）。
func PreexistingDatabase(path string) string {
	if _, err := os.Stat(filepath.Join(path, "CURRENT")); err != nil {
		return "" // No pre-existing db  没有预先存在的数据库
	}
	if matches, err := filepath.Glob(filepath.Join(path, "OPTIONS*")); len(matches) > 0 || err != nil {
		if err != nil {
			panic(err) // only possible if the pattern is malformed 仅在模式格式错误时可能发生
		}
		return DBPebble
	}
	return DBLeveldb
}

type counter uint64

func (c counter) String() string {
	return fmt.Sprintf("%d", c)
}

func (c counter) Percentage(current uint64) string {
	return fmt.Sprintf("%d", current*100/uint64(c))
}

// stat stores sizes and count for a parameter
type stat struct {
	size  common.StorageSize
	count counter
}

// Add size to the stat and increase the counter by 1
func (s *stat) Add(size common.StorageSize) {
	s.size += size
	s.count++
}

func (s *stat) Size() string {
	return s.size.String()
}

func (s *stat) Count() string {
	return s.count.String()
}

// InspectDatabase traverses the entire database and checks the size
// of all different categories of data.
// InspectDatabase 遍历整个数据库并检查所有不同类别数据的大小。
func InspectDatabase(db ethdb.Database, keyPrefix, keyStart []byte) error {
	it := db.NewIterator(keyPrefix, keyStart)
	defer it.Release()

	var (
		count  int64
		start  = time.Now()
		logged = time.Now()

		// Key-value store statistics 键值存储统计
		headers         stat
		bodies          stat
		receipts        stat
		tds             stat
		numHashPairings stat
		hashNumPairings stat
		legacyTries     stat
		stateLookups    stat
		accountTries    stat
		storageTries    stat
		codes           stat
		txLookups       stat
		accountSnaps    stat
		storageSnaps    stat
		preimages       stat
		bloomBits       stat
		beaconHeaders   stat
		cliqueSnaps     stat

		// 其他统计变量

		// Verkle statistics
		verkleTries        stat
		verkleStateLookups stat

		// Les statistic
		chtTrieNodes   stat
		bloomTrieNodes stat

		// Meta- and unaccounted data
		metadata    stat
		unaccounted stat

		// Totals
		total common.StorageSize
	)
	// Inspect key-value database first. 首先检查键值数据库。
	for it.Next() {
		var (
			key  = it.Key()
			size = common.StorageSize(len(key) + len(it.Value()))
		)
		total += size
		switch {
		case bytes.HasPrefix(key, headerPrefix) && len(key) == (len(headerPrefix)+8+common.HashLength):
			headers.Add(size)
		case bytes.HasPrefix(key, blockBodyPrefix) && len(key) == (len(blockBodyPrefix)+8+common.HashLength):
			bodies.Add(size)
		case bytes.HasPrefix(key, blockReceiptsPrefix) && len(key) == (len(blockReceiptsPrefix)+8+common.HashLength):
			receipts.Add(size)
		case bytes.HasPrefix(key, headerPrefix) && bytes.HasSuffix(key, headerTDSuffix):
			tds.Add(size)
		case bytes.HasPrefix(key, headerPrefix) && bytes.HasSuffix(key, headerHashSuffix):
			numHashPairings.Add(size)
		case bytes.HasPrefix(key, headerNumberPrefix) && len(key) == (len(headerNumberPrefix)+common.HashLength):
			hashNumPairings.Add(size)
		case IsLegacyTrieNode(key, it.Value()):
			legacyTries.Add(size)
		case bytes.HasPrefix(key, stateIDPrefix) && len(key) == len(stateIDPrefix)+common.HashLength:
			stateLookups.Add(size)
		case IsAccountTrieNode(key):
			accountTries.Add(size)
		case IsStorageTrieNode(key):
			storageTries.Add(size)
		case bytes.HasPrefix(key, CodePrefix) && len(key) == len(CodePrefix)+common.HashLength:
			codes.Add(size)
		case bytes.HasPrefix(key, txLookupPrefix) && len(key) == (len(txLookupPrefix)+common.HashLength):
			txLookups.Add(size)
		case bytes.HasPrefix(key, SnapshotAccountPrefix) && len(key) == (len(SnapshotAccountPrefix)+common.HashLength):
			accountSnaps.Add(size)
		case bytes.HasPrefix(key, SnapshotStoragePrefix) && len(key) == (len(SnapshotStoragePrefix)+2*common.HashLength):
			storageSnaps.Add(size)
		case bytes.HasPrefix(key, PreimagePrefix) && len(key) == (len(PreimagePrefix)+common.HashLength):
			preimages.Add(size)
		case bytes.HasPrefix(key, configPrefix) && len(key) == (len(configPrefix)+common.HashLength):
			metadata.Add(size)
		case bytes.HasPrefix(key, genesisPrefix) && len(key) == (len(genesisPrefix)+common.HashLength):
			metadata.Add(size)
		case bytes.HasPrefix(key, bloomBitsPrefix) && len(key) == (len(bloomBitsPrefix)+10+common.HashLength):
			bloomBits.Add(size)
		case bytes.HasPrefix(key, BloomBitsIndexPrefix):
			bloomBits.Add(size)
		case bytes.HasPrefix(key, skeletonHeaderPrefix) && len(key) == (len(skeletonHeaderPrefix)+8):
			beaconHeaders.Add(size)
		case bytes.HasPrefix(key, CliqueSnapshotPrefix) && len(key) == 7+common.HashLength:
			cliqueSnaps.Add(size)
		case bytes.HasPrefix(key, ChtTablePrefix) ||
			bytes.HasPrefix(key, ChtIndexTablePrefix) ||
			bytes.HasPrefix(key, ChtPrefix): // Canonical hash trie
			chtTrieNodes.Add(size)
		case bytes.HasPrefix(key, BloomTrieTablePrefix) ||
			bytes.HasPrefix(key, BloomTrieIndexPrefix) ||
			bytes.HasPrefix(key, BloomTriePrefix): // Bloomtrie sub
			bloomTrieNodes.Add(size)

		// Verkle trie data is detected, determine the sub-category
		case bytes.HasPrefix(key, VerklePrefix):
			remain := key[len(VerklePrefix):]
			switch {
			case IsAccountTrieNode(remain):
				verkleTries.Add(size)
			case bytes.HasPrefix(remain, stateIDPrefix) && len(remain) == len(stateIDPrefix)+common.HashLength:
				verkleStateLookups.Add(size)
			case bytes.Equal(remain, persistentStateIDKey):
				metadata.Add(size)
			case bytes.Equal(remain, trieJournalKey):
				metadata.Add(size)
			case bytes.Equal(remain, snapSyncStatusFlagKey):
				metadata.Add(size)
			default:
				unaccounted.Add(size)
			}
		default:
			var accounted bool
			for _, meta := range [][]byte{
				databaseVersionKey, headHeaderKey, headBlockKey, headFastBlockKey, headFinalizedBlockKey,
				lastPivotKey, fastTrieProgressKey, snapshotDisabledKey, SnapshotRootKey, snapshotJournalKey,
				snapshotGeneratorKey, snapshotRecoveryKey, txIndexTailKey, fastTxLookupLimitKey,
				uncleanShutdownKey, badBlockKey, transitionStatusKey, skeletonSyncStatusKey,
				persistentStateIDKey, trieJournalKey, snapshotSyncStatusKey, snapSyncStatusFlagKey,
			} {
				if bytes.Equal(key, meta) {
					metadata.Add(size)
					accounted = true
					break
				}
			}
			if !accounted {
				unaccounted.Add(size)
			}
		}
		count++
		if count%1000 == 0 && time.Since(logged) > 8*time.Second {
			log.Info("Inspecting database", "count", count, "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	// Display the database statistic of key-value store.
	stats := [][]string{
		{"Key-Value store", "Headers", headers.Size(), headers.Count()},
		{"Key-Value store", "Bodies", bodies.Size(), bodies.Count()},
		{"Key-Value store", "Receipt lists", receipts.Size(), receipts.Count()},
		{"Key-Value store", "Difficulties", tds.Size(), tds.Count()},
		{"Key-Value store", "Block number->hash", numHashPairings.Size(), numHashPairings.Count()},
		{"Key-Value store", "Block hash->number", hashNumPairings.Size(), hashNumPairings.Count()},
		{"Key-Value store", "Transaction index", txLookups.Size(), txLookups.Count()},
		{"Key-Value store", "Bloombit index", bloomBits.Size(), bloomBits.Count()},
		{"Key-Value store", "Contract codes", codes.Size(), codes.Count()},
		{"Key-Value store", "Hash trie nodes", legacyTries.Size(), legacyTries.Count()},
		{"Key-Value store", "Path trie state lookups", stateLookups.Size(), stateLookups.Count()},
		{"Key-Value store", "Path trie account nodes", accountTries.Size(), accountTries.Count()},
		{"Key-Value store", "Path trie storage nodes", storageTries.Size(), storageTries.Count()},
		{"Key-Value store", "Verkle trie nodes", verkleTries.Size(), verkleTries.Count()},
		{"Key-Value store", "Verkle trie state lookups", verkleStateLookups.Size(), verkleStateLookups.Count()},
		{"Key-Value store", "Trie preimages", preimages.Size(), preimages.Count()},
		{"Key-Value store", "Account snapshot", accountSnaps.Size(), accountSnaps.Count()},
		{"Key-Value store", "Storage snapshot", storageSnaps.Size(), storageSnaps.Count()},
		{"Key-Value store", "Beacon sync headers", beaconHeaders.Size(), beaconHeaders.Count()},
		{"Key-Value store", "Clique snapshots", cliqueSnaps.Size(), cliqueSnaps.Count()},
		{"Key-Value store", "Singleton metadata", metadata.Size(), metadata.Count()},
		{"Light client", "CHT trie nodes", chtTrieNodes.Size(), chtTrieNodes.Count()},
		{"Light client", "Bloom trie nodes", bloomTrieNodes.Size(), bloomTrieNodes.Count()},
	}
	// Inspect all registered append-only file store then.
	ancients, err := inspectFreezers(db)
	if err != nil {
		return err
	}
	for _, ancient := range ancients {
		for _, table := range ancient.sizes {
			stats = append(stats, []string{
				fmt.Sprintf("Ancient store (%s)", strings.Title(ancient.name)),
				strings.Title(table.name),
				table.size.String(),
				fmt.Sprintf("%d", ancient.count()),
			})
		}
		total += ancient.size()
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Database", "Category", "Size", "Items"})
	table.SetFooter([]string{"", "Total", total.String(), " "})
	table.AppendBulk(stats)
	table.Render()

	if unaccounted.size > 0 {
		log.Error("Database contains unaccounted data", "size", unaccounted.size, "count", unaccounted.count)
	}
	return nil
}

// printChainMetadata prints out chain metadata to stderr.
// printChainMetadata 将链元数据打印到标准错误。
func printChainMetadata(db ethdb.KeyValueStore) {
	fmt.Fprintf(os.Stderr, "Chain metadata\n")
	for _, v := range ReadChainMetadata(db) {
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Join(v, ": "))
	}
	fmt.Fprintf(os.Stderr, "\n\n")
}

// ReadChainMetadata returns a set of key/value pairs that contains information
// about the database chain status. This can be used for diagnostic purposes
// when investigating the state of the node.
// ReadChainMetadata 返回一组键/值对，包含有关数据库链状态的信息。这可用于诊断目的，调查节点的状态。
func ReadChainMetadata(db ethdb.KeyValueStore) [][]string {
	pp := func(val *uint64) string {
		if val == nil {
			return "<nil>"
		}
		return fmt.Sprintf("%d (%#x)", *val, *val)
	}
	data := [][]string{
		{"databaseVersion", pp(ReadDatabaseVersion(db))},
		{"headBlockHash", fmt.Sprintf("%v", ReadHeadBlockHash(db))},
		{"headFastBlockHash", fmt.Sprintf("%v", ReadHeadFastBlockHash(db))},
		{"headHeaderHash", fmt.Sprintf("%v", ReadHeadHeaderHash(db))},
		{"lastPivotNumber", pp(ReadLastPivotNumber(db))},
		{"len(snapshotSyncStatus)", fmt.Sprintf("%d bytes", len(ReadSnapshotSyncStatus(db)))},
		{"snapshotDisabled", fmt.Sprintf("%v", ReadSnapshotDisabled(db))},
		{"snapshotJournal", fmt.Sprintf("%d bytes", len(ReadSnapshotJournal(db)))},
		{"snapshotRecoveryNumber", pp(ReadSnapshotRecoveryNumber(db))},
		{"snapshotRoot", fmt.Sprintf("%v", ReadSnapshotRoot(db))},
		{"txIndexTail", pp(ReadTxIndexTail(db))},
	}
	if b := ReadSkeletonSyncStatus(db); b != nil {
		data = append(data, []string{"SkeletonSyncStatus", string(b)})
	}
	return data
}
