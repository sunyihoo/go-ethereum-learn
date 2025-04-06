// Copyright 2020 The go-ethereum Authors
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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// trieKV represents a trie key-value pair
// trieKV 表示一个 trie 键值对
type trieKV struct {
	key   common.Hash // 键
	value []byte      // 值
}

type (
	// trieGeneratorFn is the interface of trie generation which can
	// be implemented by different trie algorithm.
	// trieGeneratorFn 是 trie 生成的接口，可以由不同的 trie 算法实现。
	trieGeneratorFn func(db ethdb.KeyValueWriter, scheme string, owner common.Hash, in chan (trieKV), out chan (common.Hash))

	// leafCallbackFn is the callback invoked at the leaves of the trie,
	// returns the subtrie root with the specified subtrie identifier.
	// leafCallbackFn 是在 trie 的叶子节点调用的回调，
	// 返回具有指定子 trie 标识符的子 trie 根。
	leafCallbackFn func(db ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, error)
)

// GenerateTrie takes the whole snapshot tree as the input, traverses all the
// accounts as well as the corresponding storages and regenerate the whole state
// (account trie + all storage tries).
// GenerateTrie 以整个快照树作为输入，遍历所有账户及其对应的存储，重新生成整个状态
// （账户 trie + 所有存储 trie）。
func GenerateTrie(snaptree *Tree, root common.Hash, src ethdb.Database, dst ethdb.KeyValueWriter) error {
	// Traverse all state by snapshot, re-generate the whole state trie
	// 通过快照遍历所有状态，重新生成整个状态 trie
	acctIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err // The required snapshot might not exist.
		// 所需的快照可能不存在。
	}
	defer acctIt.Release()

	scheme := snaptree.triedb.Scheme()
	got, err := generateTrieRoot(dst, scheme, acctIt, common.Hash{}, stackTrieGenerate, func(dst ethdb.KeyValueWriter, accountHash, codeHash common.Hash, stat *generateStats) (common.Hash, error) {
		// Migrate the code first, commit the contract code into the tmp db.
		// 首先迁移代码，将合约代码提交到临时数据库。
		if codeHash != types.EmptyCodeHash {
			code := rawdb.ReadCode(src, codeHash)
			if len(code) == 0 {
				return common.Hash{}, errors.New("failed to read contract code")
				// 无法读取合约代码
			}
			rawdb.WriteCode(dst, codeHash, code)
		}
		// Then migrate all storage trie nodes into the tmp db.
		// 然后将所有存储 trie 节点迁移到临时数据库。
		storageIt, err := snaptree.StorageIterator(root, accountHash, common.Hash{})
		if err != nil {
			return common.Hash{}, err
		}
		defer storageIt.Release()

		hash, err := generateTrieRoot(dst, scheme, storageIt, accountHash, stackTrieGenerate, nil, stat, false)
		if err != nil {
			return common.Hash{}, err
		}
		return hash, nil
	}, newGenerateStats(), true)

	if err != nil {
		return err
	}
	if got != root {
		return fmt.Errorf("state root hash mismatch: got %x, want %x", got, root)
		// 状态根哈希不匹配：得到 %x，期望 %x
	}
	return nil
}

// generateStats is a collection of statistics gathered by the trie generator
// for logging purposes.
// generateStats 是 trie 生成器为日志目的收集的统计信息。
type generateStats struct {
	head  common.Hash // 当前账户头
	start time.Time   // 开始时间

	accounts uint64 // Number of accounts done (including those being crawled)
	// 已完成的账户数（包括正在爬取的）
	slots uint64 // Number of storage slots done (including those being crawled)
	// 已完成的存储槽数（包括正在爬取的）

	slotsStart map[common.Hash]time.Time // Start time for account slot crawling
	// 账户槽爬取的开始时间
	slotsHead map[common.Hash]common.Hash // Slot head for accounts being crawled
	// 正在爬取的账户的槽头

	lock sync.RWMutex // 读写锁
}

// newGenerateStats creates a new generator stats.
// newGenerateStats 创建一个新的生成器统计。
func newGenerateStats() *generateStats {
	return &generateStats{
		slotsStart: make(map[common.Hash]time.Time),
		slotsHead:  make(map[common.Hash]common.Hash),
		start:      time.Now(),
	}
}

// progressAccounts updates the generator stats for the account range.
// progressAccounts 更新账户范围的生成器统计。
func (stat *generateStats) progressAccounts(account common.Hash, done uint64) {
	stat.lock.Lock()
	defer stat.lock.Unlock()

	stat.accounts += done
	stat.head = account
}

// finishAccounts updates the generator stats for the finished account range.
// finishAccounts 更新已完成账户范围的生成器统计。
func (stat *generateStats) finishAccounts(done uint64) {
	stat.lock.Lock()
	defer stat.lock.Unlock()

	stat.accounts += done
}

// progressContract updates the generator stats for a specific in-progress contract.
// progressContract 更新特定进行中合约的生成器统计。
func (stat *generateStats) progressContract(account common.Hash, slot common.Hash, done uint64) {
	stat.lock.Lock()
	defer stat.lock.Unlock()

	stat.slots += done
	stat.slotsHead[account] = slot
	if _, ok := stat.slotsStart[account]; !ok {
		stat.slotsStart[account] = time.Now()
	}
}

// finishContract updates the generator stats for a specific just-finished contract.
// finishContract 更新特定刚完成合约的生成器统计。
func (stat *generateStats) finishContract(account common.Hash, done uint64) {
	stat.lock.Lock()
	defer stat.lock.Unlock()

	stat.slots += done
	delete(stat.slotsHead, account)
	delete(stat.slotsStart, account)
}

// report prints the cumulative progress statistic smartly.
// report 智能地打印累积进度统计。
func (stat *generateStats) report() {
	stat.lock.RLock()
	defer stat.lock.RUnlock()

	ctx := []interface{}{
		"accounts", stat.accounts,
		"slots", stat.slots,
		"elapsed", common.PrettyDuration(time.Since(stat.start)),
	}
	if stat.accounts > 0 {
		// If there's progress on the account trie, estimate the time to finish crawling it
		// 如果账户 trie 有进展，估计完成爬取的时间
		if done := binary.BigEndian.Uint64(stat.head[:8]) / stat.accounts; done > 0 {
			var (
				left  = (math.MaxUint64 - binary.BigEndian.Uint64(stat.head[:8])) / stat.accounts
				speed = done/uint64(time.Since(stat.start)/time.Millisecond+1) + 1 // +1s to avoid division by zero
				// +1s 以避免除以零
				eta = time.Duration(left/speed) * time.Millisecond
			)
			// If there are large contract crawls in progress, estimate their finish time
			// 如果有大型合约爬取在进行中，估计它们的完成时间
			for acc, head := range stat.slotsHead {
				start := stat.slotsStart[acc]
				if done := binary.BigEndian.Uint64(head[:8]); done > 0 {
					var (
						left  = math.MaxUint64 - binary.BigEndian.Uint64(head[:8])
						speed = done/uint64(time.Since(start)/time.Millisecond+1) + 1 // +1s to avoid division by zero
						// +1s 以避免除以零
					)
					// Override the ETA if larger than the largest until now
					// 如果槽 ETA 大于迄今为止的最大值，则覆盖 ETA
					if slotETA := time.Duration(left/speed) * time.Millisecond; eta < slotETA {
						eta = slotETA
					}
				}
			}
			ctx = append(ctx, []interface{}{
				"eta", common.PrettyDuration(eta),
			}...)
		}
	}
	log.Info("Iterating state snapshot", ctx...)
	// 迭代状态快照
}

// reportDone prints the last log when the whole generation is finished.
// reportDone 在整个生成完成后打印最后日志。
func (stat *generateStats) reportDone() {
	stat.lock.RLock()
	defer stat.lock.RUnlock()

	var ctx []interface{}
	ctx = append(ctx, []interface{}{"accounts", stat.accounts}...)
	if stat.slots != 0 {
		ctx = append(ctx, []interface{}{"slots", stat.slots}...)
	}
	ctx = append(ctx, []interface{}{"elapsed", common.PrettyDuration(time.Since(stat.start))}...)
	log.Info("Iterated snapshot", ctx...)
	// 已迭代快照
}

// runReport periodically prints the progress information.
// runReport 定期打印进度信息。
func runReport(stats *generateStats, stop chan bool) {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			stats.report()
			timer.Reset(time.Second * 8)
		case success := <-stop:
			if success {
				stats.reportDone()
			}
			return
		}
	}
}

// generateTrieRoot generates the trie hash based on the snapshot iterator.
// It can be used for generating account trie, storage trie or even the
// whole state which connects the accounts and the corresponding storages.
// generateTrieRoot 基于快照迭代器生成 trie 哈希。
// 它可用于生成账户 trie、存储 trie 甚至连接账户及其对应存储的整个状态。
func generateTrieRoot(db ethdb.KeyValueWriter, scheme string, it Iterator, account common.Hash, generatorFn trieGeneratorFn, leafCallback leafCallbackFn, stats *generateStats, report bool) (common.Hash, error) {
	var (
		in = make(chan trieKV) // chan to pass leaves
		// 用于传递叶子的通道
		out = make(chan common.Hash, 1) // chan to collect result
		// 用于收集结果的通道
		stoplog = make(chan bool, 1) // 1-size buffer, works when logging is not enabled
		// 1 大小的缓冲区，在未启用日志时工作
		wg sync.WaitGroup // 等待组
	)
	// Spin up a go-routine for trie hash re-generation
	// 启动一个 goroutine 用于 trie 哈希重新生成
	wg.Add(1)
	go func() {
		defer wg.Done()
		generatorFn(db, scheme, account, in, out)
	}()
	// Spin up a go-routine for progress logging
	// 启动一个 goroutine 用于进度日志
	if report && stats != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runReport(stats, stoplog)
		}()
	}
	// Create a semaphore to assign tasks and collect results through. We'll pre-
	// fill it with nils, thus using the same channel for both limiting concurrent
	// processing and gathering results.
	// 创建一个信号量来分配任务并收集结果。我们将预填充 nil，
	// 从而使用同一通道来限制并发处理和收集结果。
	threads := runtime.NumCPU()
	results := make(chan error, threads)
	for i := 0; i < threads; i++ {
		results <- nil // fill the semaphore
		// 填充信号量
	}
	// stop is a helper function to shutdown the background threads
	// and return the re-generated trie hash.
	// stop 是一个辅助函数，用于关闭后台线程并返回重新生成的 trie 哈希。
	stop := func(fail error) (common.Hash, error) {
		close(in)
		result := <-out
		for i := 0; i < threads; i++ {
			if err := <-results; err != nil && fail == nil {
				fail = err
			}
		}
		stoplog <- fail == nil

		wg.Wait()
		return result, fail
	}
	var (
		logged    = time.Now()
		processed = uint64(0)
		leaf      trieKV
	)
	// Start to feed leaves
	// 开始喂送叶子
	for it.Next() {
		if account == (common.Hash{}) {
			var (
				err      error
				fullData []byte
			)
			if leafCallback == nil {
				fullData, err = types.FullAccountRLP(it.(AccountIterator).Account())
				if err != nil {
					return stop(err)
				}
			} else {
				// Wait until the semaphore allows us to continue, aborting if
				// a sub-task failed
				// 等待信号量允许我们继续，如果子任务失败则中止
				if err := <-results; err != nil {
					results <- nil // stop will drain the results, add a noop back for this error we just consumed
					// stop 将耗尽结果，为我们刚消耗的错误添加一个空操作
					return stop(err)
				}
				// Fetch the next account and process it concurrently
				// 获取下一个账户并并发处理它
				account, err := types.FullAccount(it.(AccountIterator).Account())
				if err != nil {
					return stop(err)
				}
				go func(hash common.Hash) {
					subroot, err := leafCallback(db, hash, common.BytesToHash(account.CodeHash), stats)
					if err != nil {
						results <- err
						return
					}
					if account.Root != subroot {
						results <- fmt.Errorf("invalid subroot(path %x), want %x, have %x", hash, account.Root, subroot)
						// 无效的子根（路径 %x），期望 %x，得到 %x
					}
					results <- nil
				}(it.Hash())
				fullData, err = rlp.EncodeToBytes(account)
				if err != nil {
					return stop(err)
				}
			}
			leaf = trieKV{it.Hash(), fullData}
		} else {
			leaf = trieKV{it.Hash(), common.CopyBytes(it.(StorageIterator).Slot())}
		}
		in <- leaf

		// Accumulate the generation statistic if it's required.
		// 如果需要，累积生成统计信息。
		processed++
		if time.Since(logged) > 3*time.Second && stats != nil {
			if account == (common.Hash{}) {
				stats.progressAccounts(it.Hash(), processed)
			} else {
				stats.progressContract(account, it.Hash(), processed)
			}
			logged, processed = time.Now(), 0
		}
	}
	// Commit the last part statistic.
	// 提交最后一部分统计信息。
	if processed > 0 && stats != nil {
		if account == (common.Hash{}) {
			stats.finishAccounts(processed)
		} else {
			stats.finishContract(account, processed)
		}
	}
	return stop(nil)
}

func stackTrieGenerate(db ethdb.KeyValueWriter, scheme string, owner common.Hash, in chan trieKV, out chan common.Hash) {
	var onTrieNode trie.OnTrieNode
	if db != nil {
		onTrieNode = func(path []byte, hash common.Hash, blob []byte) {
			rawdb.WriteTrieNode(db, owner, path, hash, blob, scheme)
		}
	}
	t := trie.NewStackTrie(onTrieNode)
	for leaf := range in {
		t.Update(leaf.key[:], leaf.value)
	}
	out <- t.Hash()
}
