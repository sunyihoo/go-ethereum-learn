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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/triedb"
)

const (
	// stateBloomFilePrefix is the filename prefix of state bloom filter.
	stateBloomFilePrefix = "statebloom"

	// stateBloomFilePrefix is the filename suffix of state bloom filter.
	stateBloomFileSuffix = "bf.gz"

	// stateBloomFileTempSuffix is the filename suffix of state bloom filter
	// while it is being written out to detect write aborts.
	stateBloomFileTempSuffix = ".tmp"

	// rangeCompactionThreshold is the minimal deleted entry number for
	// triggering range compaction. It's a quite arbitrary number but just
	// to avoid triggering range compaction because of small deletion.
	rangeCompactionThreshold = 100000
)

// RecoverPruning will resume the pruning procedure during the system restart.
// This function is used in this case: user tries to prune state data, but the
// system was interrupted midway because of crash or manual-kill. In this case
// if the bloom filter for filtering active state is already constructed, the
// pruning can be resumed. What's more if the bloom filter is constructed, the
// pruning **has to be resumed**. Otherwise a lot of dangling nodes may be left
// in the disk.

func RecoverPruning(datadir string, db ethdb.Database) error {
	stateBloomPath, stateBloomRoot, err := findBloomFilter(datadir)
	if err != nil {
		return err
	}
	if stateBloomPath == "" {
		return nil // nothing to recover
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
	snapconfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   true,
		NoBuild:    true,
		AsyncBuild: false,
	}
	// Offline pruning is only supported in legacy hash based scheme.
	triedb := triedb.NewDatabase(db, triedb.HashDefaults)
	snaptree, err := snapshot.New(snapconfig, db, triedb, headBlock.Root())
	if err != nil {
		return err // The relevant snapshot(s) might not exist
	}
	stateBloom, err := NewStateBloomFromDisk(stateBloomPath)
	if err != nil {
		return err
	}
	log.Info("Loaded state bloom filter", "path", stateBloomPath)

	// All the state roots of the middle layers should be forcibly pruned,
	// otherwise the dangling state will be left.
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
