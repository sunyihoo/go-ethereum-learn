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
	"encoding/binary"
	"errors"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/log"
	bloomfilter "github.com/holiman/bloomfilter/v2"
)

// 布隆过滤器参数: m（位数）和 k（哈希函数数）影响假阳性率。
// 布隆过滤器 (Bloom Filter): 一种概率数据结构，用于快速成员检查。
// 假阳性: 可能误报存在，但不会漏报不存在。
// 状态树 (State Trie): 以太坊存储账户状态的 Merkle Patricia Trie。
// 快照同步: 从快照生成状态的优化方式。
// 快速同步 (Fast Sync): 下载区块头和状态的同步模式。

// stateBloomHash is used to convert a trie hash or contract code hash into a 64 bit mini hash.
// stateBloomHash 用于将 trie 哈希或合约代码哈希转换为 64 位迷你哈希
func stateBloomHash(f []byte) uint64 {
	return binary.BigEndian.Uint64(f)
}

// stateBloom is a bloom filter used during the state conversion(snapshot->state).
// The keys of all generated entries will be recorded here so that in the pruning
// stage the entries belong to the specific version can be avoided for deletion.
//
// The false-positive is allowed here. The "false-positive" entries means they
// actually don't belong to the specific version but they are not deleted in the
// pruning. The downside of the false-positive allowance is we may leave some "dangling"
// nodes in the disk. But in practice the it's very unlike the dangling node is
// state root. So in theory this pruned state shouldn't be visited anymore. Another
// potential issue is for fast sync. If we do another fast sync upon the pruned
// database, it's problematic which will stop the expansion during the syncing.
// TODO address it @rjl493456442 @holiman @karalabe.
//
// After the entire state is generated, the bloom filter should be persisted into
// the disk. It indicates the whole generation procedure is finished.
// stateBloom 是一个在状态转换（快照到状态）期间使用的布隆过滤器。
// 所有生成的条目的键将记录在此，以便在修剪阶段避免删除属于特定版本的条目。
//
// 这里允许假阳性。“假阳性”条目意味着它们实际上不属于特定版本，但在修剪中未被删除。
// 允许假阳性的缺点是我们可能会在磁盘上留下一些“悬空”节点。
// 但在实践中，悬空节点很不可能是状态根。因此理论上修剪后的状态不应该再次被访问。
// 另一个潜在问题是快速同步。如果我们在修剪后的数据库上再次进行快速同步，
// 会出现问题，这将停止同步期间的扩展。
// TODO 解决此问题 @rjl493456442 @holiman @karalabe。
//
// 在整个状态生成完成后，布隆过滤器应持久化到磁盘中。这表示整个生成过程已完成。
type stateBloom struct {
	bloom *bloomfilter.Filter // 底层布隆过滤器
}

// newStateBloomWithSize creates a brand new state bloom for state generation.
// The bloom filter will be created by the passing bloom filter size. According
// to the https://hur.st/bloomfilter/?n=600000000&p=&m=2048MB&k=4, the parameters
// are picked so that the false-positive rate for mainnet is low enough.
// newStateBloomWithSize 为状态生成创建一个全新的状态布隆过滤器。
// 布隆过滤器将根据传入的布隆过滤器大小创建。根据 https://hur.st/bloomfilter/?n=600000000&p=&m=2048MB&k=4，
// 参数的选择使得主网的假阳性率足够低。
func newStateBloomWithSize(size uint64) (*stateBloom, error) {
	bloom, err := bloomfilter.New(size*1024*1024*8, 4)
	if err != nil {
		return nil, err
	}
	log.Info("Initialized state bloom", "size", common.StorageSize(float64(bloom.M()/8)))
	return &stateBloom{bloom: bloom}, nil
}

// NewStateBloomFromDisk loads the state bloom from the given file.
// In this case the assumption is held the bloom filter is complete.
// NewStateBloomFromDisk 从给定文件加载状态布隆过滤器。
// 在这种情况下，假设布隆过滤器是完整的。
func NewStateBloomFromDisk(filename string) (*stateBloom, error) {
	bloom, _, err := bloomfilter.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &stateBloom{bloom: bloom}, nil
}

// Commit flushes the bloom filter content into the disk and marks the bloom
// as complete.
// Commit 将布隆过滤器内容刷新到磁盘并标记布隆过滤器为完成。
func (bloom *stateBloom) Commit(filename, tempname string) error {
	// Write the bloom out into a temporary file
	// 将布隆过滤器写入临时文件
	_, err := bloom.bloom.WriteFile(tempname)
	if err != nil {
		return err
	}
	// Ensure the file is synced to disk
	// 确保文件同步到磁盘
	f, err := os.OpenFile(tempname, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Move the temporary file into it's final location
	// 将临时文件移动到最终位置
	return os.Rename(tempname, filename)
}

// Put implements the KeyValueWriter interface. But here only the key is needed.
// Put 实现了 KeyValueWriter 接口。但这里只需要键。
func (bloom *stateBloom) Put(key []byte, value []byte) error {
	// If the key length is not 32bytes, ensure it's contract code
	// entry with new scheme.
	// 如果键长度不是 32 字节，确保它是新方案的合约代码条目。
	if len(key) != common.HashLength {
		isCode, codeKey := rawdb.IsCodeKey(key)
		if !isCode {
			return errors.New("invalid entry")
		}
		bloom.bloom.AddHash(stateBloomHash(codeKey))
		return nil
	}
	bloom.bloom.AddHash(stateBloomHash(key))
	return nil
}

// Delete removes the key from the key-value data store.
// Delete 从键值数据存储中移除键
func (bloom *stateBloom) Delete(key []byte) error { panic("not supported") }

// Contain is the wrapper of the underlying contains function which
// reports whether the key is contained.
// - If it says yes, the key may be contained
// - If it says no, the key is definitely not contained.
// Contain 是底层 contains 函数的包装器，报告键是否包含在内。
// - 如果返回是，键可能包含在内
// - 如果返回否，键肯定不包含在内。
func (bloom *stateBloom) Contain(key []byte) bool {
	return bloom.bloom.ContainsHash(stateBloomHash(key))
}
