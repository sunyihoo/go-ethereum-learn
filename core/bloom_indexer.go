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

package core

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// Bloom 过滤器: 以太坊区块头包含一个 Bloom 过滤器，用于快速检查该区块中是否可能包含与特定事件相关的日志。Bloom 过滤器是一种概率数据结构，可以高效地判断某个元素是否可能在一个集合中。
// 日志过滤: 以太坊的事件日志是智能合约与外部世界通信的重要方式。用户和应用程序经常需要查询特定合约或特定事件的日志。直接扫描整个区块链来查找这些日志是非常低效的。
// Bloom bits 索引: BloomIndexer 通过构建一个旋转的 Bloom bits 索引来解决这个问题。它将每个区块头的 Bloom 过滤器分解成多个位集，并按位进行聚合。这样，当需要查询包含特定事件的区块时，可以首先查询 Bloom bits 索引，快速排除掉那些不可能包含该事件的区块，从而大大提高查询效率。
// 段 (Section): BloomIndexer 将区块链分成多个段进行处理。每个段包含固定数量的区块（由 size 参数指定）。这样做可能是为了更好地管理索引数据，例如分批写入数据库或进行错误恢复。
// 节流 (Throttling): bloomThrottling 常量的引入是为了在执行索引操作（特别是链升级期间可能需要重新索引大量数据）时，限制对磁盘的访问频率，避免因 I/O 过载而导致节点性能下降。

const (
	// bloomThrottling is the time to wait between processing two consecutive index
	// sections. It's useful during chain upgrades to prevent disk overload.
	// bloomThrottling 是处理两个连续索引部分之间等待的时间。
	// 在链升级期间，这对于防止磁盘过载非常有用。
	bloomThrottling = 100 * time.Millisecond
)

// BloomIndexer implements a core.ChainIndexer, building up a rotated bloom bits index
// for the Ethereum header bloom filters, permitting blazing fast filtering.
// BloomIndexer 实现了 core.ChainIndexer 接口，为以太坊头部 bloom 过滤器构建一个旋转的 bloom 位索引，
// 从而实现极快的过滤。
type BloomIndexer struct {
	size uint64 // section size to generate bloombits for
	// size 生成 bloombits 的段大小。
	db ethdb.Database // database instance to write index data and metadata into
	// db 用于写入索引数据和元数据的数据库实例。
	gen *bloombits.Generator // generator to rotate the bloom bits crating the bloom index
	// gen 用于旋转 bloom bits 以创建 bloom 索引的生成器。
	section uint64 // Section is the section number being processed currently
	// section 当前正在处理的段号。
	head common.Hash // Head is the hash of the last header processed
	// head 上一个已处理的头部的哈希值。
}

// NewBloomIndexer returns a chain indexer that generates bloom bits data for the
// canonical chain for fast logs filtering.
// NewBloomIndexer 返回一个链索引器，它为规范链生成 bloom bits 数据，以实现快速的日志过滤。
func NewBloomIndexer(db ethdb.Database, size, confirms uint64) *ChainIndexer {
	backend := &BloomIndexer{
		db:   db,
		size: size,
	}
	table := rawdb.NewTable(db, string(rawdb.BloomBitsIndexPrefix))

	return NewChainIndexer(db, table, backend, size, confirms, bloomThrottling, "bloombits")
}

// Reset implements core.ChainIndexerBackend, starting a new bloombits index
// section.
// Reset 实现了 core.ChainIndexerBackend 接口，启动一个新的 bloombits 索引段。
func (b *BloomIndexer) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	gen, err := bloombits.NewGenerator(uint(b.size))
	b.gen, b.section, b.head = gen, section, common.Hash{}
	return err
}

// Process implements core.ChainIndexerBackend, adding a new header's bloom into
// the index.
// Process 实现了 core.ChainIndexerBackend 接口，将新头部的 bloom 添加到索引中。
func (b *BloomIndexer) Process(ctx context.Context, header *types.Header) error {
	b.gen.AddBloom(uint(header.Number.Uint64()-b.section*b.size), header.Bloom)
	b.head = header.Hash()
	return nil
}

// Commit implements core.ChainIndexerBackend, finalizing the bloom section and
// writing it out into the database.
// Commit 实现了 core.ChainIndexerBackend 接口，完成 bloom 段并将它写入数据库。
func (b *BloomIndexer) Commit() error {
	batch := b.db.NewBatchWithSize((int(b.size) / 8) * types.BloomBitLength)
	for i := 0; i < types.BloomBitLength; i++ {
		bits, err := b.gen.Bitset(uint(i))
		if err != nil {
			return err
		}
		rawdb.WriteBloomBits(batch, uint(i), b.section, b.head, bitutil.CompressBytes(bits))
	}
	return batch.Write()
}

// Prune returns an empty error since we don't support pruning here.
// Prune 返回一个空错误，因为我们在此不支持修剪。
func (b *BloomIndexer) Prune(threshold uint64) error {
	return nil
}
