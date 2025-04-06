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
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// 状态存储 (State Storage): 以太坊的状态（包括账户和存储）是区块链的核心组成部分。维护状态数据的完整性和一致性至关重要。悬挂存储是一种可能破坏这种完整性的情况。
// 快照机制 (Snapshotting): 快照是为了更高效地存储和同步以太坊状态而引入的。检查悬挂存储是确保快照数据质量的重要步骤。
// 数据完整性 (Data Integrity): 以太坊作为一个去中心化的账本，数据的完整性至关重要。检查悬挂存储有助于确保快照数据没有损坏或不一致。

// CheckDanglingStorage iterates the snap storage data, and verifies that all
// storage also has corresponding account data.
// CheckDanglingStorage 迭代快照存储数据，并验证所有存储是否都有对应的账户数据。
func CheckDanglingStorage(chaindb ethdb.KeyValueStore) error {
	if err := checkDanglingDiskStorage(chaindb); err != nil {
		log.Error("Database check error", "err", err)
		// 如果检查磁盘存储时发生错误，则记录错误。
	}
	return checkDanglingMemStorage(chaindb)
	// 检查内存中的悬挂存储。
}

// checkDanglingDiskStorage checks if there is any 'dangling' storage data in the
// disk-backed snapshot layer.
// checkDanglingDiskStorage 检查在磁盘支持的快照层中是否存在任何“悬挂”存储数据。
func checkDanglingDiskStorage(chaindb ethdb.KeyValueStore) error {
	var (
		lastReport = time.Now()
		start      = time.Now()
		lastKey    []byte
		it         = rawdb.NewKeyLengthIterator(chaindb.NewIterator(rawdb.SnapshotStoragePrefix, nil), 1+2*common.HashLength)
		// 创建一个新的迭代器，遍历以 rawdb.SnapshotStoragePrefix 为前缀的数据库条目，键的长度为 1 + 2 * common.HashLength。
	)
	log.Info("Checking dangling snapshot disk storage")
	// 记录开始检查磁盘快照中悬挂存储的日志。

	defer it.Release() // 确保在函数返回时释放迭代器资源。
	for it.Next() {
		k := it.Key()     // 获取当前迭代到的键。
		accKey := k[1:33] // 从键中提取账户相关的部分（跳过第一个字节，取 32 字节的哈希）。
		if bytes.Equal(accKey, lastKey) {
			// No need to look up for every slot
			// 如果当前存储槽属于与上一个存储槽相同的账户，则无需再次查找账户数据。
			continue
		}
		lastKey = common.CopyBytes(accKey) // 更新 lastKey 为当前的账户键。
		if time.Since(lastReport) > time.Second*8 {
			log.Info("Iterating snap storage", "at", fmt.Sprintf("%#x", accKey), "elapsed", common.PrettyDuration(time.Since(start)))
			// 定期记录迭代进度。
			lastReport = time.Now() // 更新上次报告时间。
		}
		if data := rawdb.ReadAccountSnapshot(chaindb, common.BytesToHash(accKey)); len(data) == 0 {
			// 尝试读取与当前存储槽关联的账户快照数据。如果读取到的数据长度为 0，则表示存在悬挂存储。
			log.Warn("Dangling storage - missing account", "account", fmt.Sprintf("%#x", accKey), "storagekey", fmt.Sprintf("%#x", k))
			// 记录警告信息，指出存在悬挂存储，并打印相关的账户哈希和存储键。
			return fmt.Errorf("dangling snapshot storage account %#x", accKey)
			// 返回一个错误，指示发现了悬挂的快照存储账户。
		}
	}
	log.Info("Verified the snapshot disk storage", "time", common.PrettyDuration(time.Since(start)), "err", it.Error())
	// 记录验证磁盘快照存储完成的日志，包括耗时和可能发生的错误。
	return nil
}

// checkDanglingMemStorage checks if there is any 'dangling' storage in the journalled
// snapshot difflayers.
// checkDanglingMemStorage 检查在日志记录的快照差异层中是否存在任何“悬挂”存储。
func checkDanglingMemStorage(db ethdb.KeyValueStore) error {
	start := time.Now()
	log.Info("Checking dangling journalled storage")
	// 记录开始检查日志记录的快照中悬挂存储的日志。
	err := iterateJournal(db, func(pRoot, root common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) error {
		// 遍历快照日志中的每一层。
		for accHash := range storage {
			// 遍历当前层中的所有存储数据对应的账户哈希。
			if _, ok := accounts[accHash]; !ok {
				// 如果在当前层的账户数据中找不到与存储数据对应的账户哈希，则表示存在悬挂存储。
				log.Error("Dangling storage - missing account", "account", fmt.Sprintf("%#x", accHash), "root", root)
				// 记录错误信息，指出存在悬挂存储，并打印相关的账户哈希和当前层的根哈希。
			}
		}
		return nil
	})
	if err != nil {
		log.Info("Failed to resolve snapshot journal", "err", err)
		// 如果遍历快照日志时发生错误，则记录错误信息。
		return err
	}
	log.Info("Verified the snapshot journalled storage", "time", common.PrettyDuration(time.Since(start)))
	// 记录验证日志记录的快照存储完成的日志，包括耗时。
	return nil
}

// CheckJournalAccount shows information about an account, from the disk layer and
// up through the diff layers.
// CheckJournalAccount 显示关于一个账户的信息，从磁盘层到差异层。
func CheckJournalAccount(db ethdb.KeyValueStore, hash common.Hash) error {
	// Look up the disk layer first
	// 首先查找磁盘层。
	baseRoot := rawdb.ReadSnapshotRoot(db)
	fmt.Printf("Disklayer: Root: %x\n", baseRoot)
	if data := rawdb.ReadAccountSnapshot(db, hash); data != nil {
		// 如果在磁盘层找到了账户快照数据。
		account, err := types.FullAccount(data)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\taccount.nonce: %d\n", account.Nonce)
		fmt.Printf("\taccount.balance: %x\n", account.Balance)
		fmt.Printf("\taccount.root: %x\n", account.Root)
		fmt.Printf("\taccount.codehash: %x\n", account.CodeHash)
	}
	// Check storage
	{
		it := rawdb.NewKeyLengthIterator(db.NewIterator(append(rawdb.SnapshotStoragePrefix, hash.Bytes()...), nil), 1+2*common.HashLength)
		// 创建一个新的迭代器，遍历指定账户哈希下的存储快照数据。
		fmt.Printf("\tStorage:\n")
		for it.Next() {
			slot := it.Key()[33:] // 从键中提取存储槽哈希（跳过前缀和账户哈希）。
			fmt.Printf("\t\t%x: %x\n", slot, it.Value())
		}
		it.Release() // 释放迭代器资源。
	}
	var depth = 0

	return iterateJournal(db, func(pRoot, root common.Hash, accounts map[common.Hash][]byte, storage map[common.Hash]map[common.Hash][]byte) error {
		// 遍历快照日志中的每一层。
		_, a := accounts[hash] // 检查当前层中是否存在指定哈希的账户数据。
		_, b := storage[hash]  // 检查当前层中是否存在指定哈希的账户的存储数据。
		depth++
		if !a && !b {
			// 如果在当前层中既没有指定哈希的账户数据也没有其存储数据，则继续下一层。
			return nil
		}
		fmt.Printf("Disklayer+%d: Root: %x, parent %x\n", depth, root, pRoot)
		// 打印当前层的深度、根哈希和父根哈希。
		if data, ok := accounts[hash]; ok {
			// 如果在当前层找到了指定哈希的账户数据。
			account, err := types.FullAccount(data)
			if err != nil {
				panic(err)
			}
			fmt.Printf("\taccount.nonce: %d\n", account.Nonce)
			fmt.Printf("\taccount.balance: %x\n", account.Balance)
			fmt.Printf("\taccount.root: %x\n", account.Root)
			fmt.Printf("\taccount.codehash: %x\n", account.CodeHash)
		}
		if data, ok := storage[hash]; ok {
			// 如果在当前层找到了指定哈希的账户的存储数据。
			fmt.Printf("\tStorage\n")
			for k, v := range data {
				fmt.Printf("\t\t%x: %x\n", k, v)
			}
		}
		return nil
	})
}
