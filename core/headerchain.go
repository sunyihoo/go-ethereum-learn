// Copyright 2015 The go-ethereum Authors
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
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// 1. HeaderChain 的作用与以太坊白皮书
// HeaderChain 是 go-ethereum 中核心模块之一，负责管理区块头部的链结构。以太坊白皮书（Vitalik Buterin, 2013）中提到，区块链的核心是一个由区块头组成的链，每个区块头包含前一区块的哈希、时间戳、难度等信息。HeaderChain 正是实现这一概念的结构，它不存储完整的区块数据（包括交易和状态），而只维护头部信息，用于快速验证和同步链的状态。这与白皮书中“轻客户端”验证的理念一致，轻客户端只需下载头部链即可验证交易，而无需完整区块数据。
//
// 2. 总难度（Total Difficulty）与黄皮书
// HeaderChain 中维护了 tdCache 和 GetTd 方法，用于管理总难度（Total Difficulty, TD）。根据以太坊黄皮书（Ethereum Yellow Paper），总难度是衡量链工作量的重要指标，计算公式为：
//
// TD(block) = TD(parent) + block.Difficulty
// 其中 block.Difficulty 是当前区块的难度，由共识算法（如 Ethash 或未来的 PoS）根据网络情况动态调整。WriteHeaders 方法中通过 newTD.Add(newTD, header.Difficulty) 累加总难度，体现了黄皮书中定义的链增长逻辑。总难度在分叉选择中至关重要，go-ethereum 使用它来决定哪条链是“最重”的规范链。
//
// 3. 重组（Reorg）与 EIP-1559
// Reorg 方法处理链的重组，当新导入的头部链比当前链更优时，会切换头部。以太坊引入 EIP-1559（2021 年伦敦升级）后，区块的 Gas 费用机制改变，但重组逻辑依然基于总难度和规范性。Reorg 的两种情况——扩展链和切换头部——反映了以太坊网络中常见的“叔块”（Uncle Blocks）和分叉处理。白皮书中提到叔块机制允许短分叉被部分承认，而 Reorg 确保最终一致性，符合以太坊的 GHOST 协议（Greedy Heaviest Observed SubTree）。
//
// 4. 缓存机制与性能优化
// headerCache、tdCache 和 numberCache 使用 LRU（Least Recently Used）缓存算法，这是 go-ethereum 的性能优化手段。以太坊网络需要处理大量头部查询（如同步、验证），直接访问数据库（chainDb）会显著降低性能。缓存机制减少了磁盘 I/O，符合黄皮书中对高效节点实现的要求。headerCacheLimit 等常量定义了缓存大小，平衡了内存使用和查询速度。
//
// 5. 共识引擎（Engine）与 PoW/PoS 过渡
// HeaderChain 中的 engine 字段引用 consensus.Engine 接口，支持不同的共识算法。以太坊最初使用 PoW（Ethash），通过 ValidateHeaderChain 调用 engine.VerifyHeaders 验证头部有效性（如工作量证明）。随着 EIP-3675（2022 年合并），以太坊过渡到 PoS（Proof of Stake），engine 可切换为 Beacon Chain 的实现。代码的模块化设计支持这种过渡，体现了以太坊的可扩展性。
//
// 6. 关键函数与以太坊特性
// InsertHeaderChain：实现头部链的插入和重组，是同步协议（如 Fast Sync）的核心。白皮书中提到节点需快速同步到最新状态，InsertHeaderChain 通过批量写入和验证优化了这一过程。
// SetHead：支持链回滚，用于处理分叉或错误状态。黄皮书中定义了状态回滚的必要性，SetHead 提供了实现。
// GetAncestor：查找祖先头部，用于分叉分析和历史查询，与以太坊的链式结构一致。

const (
	headerCacheLimit = 512  // 头部缓存限制
	tdCacheLimit     = 1024 // 总难度缓存限制
	numberCacheLimit = 2048 // 区块号缓存限制
)

// HeaderChain implements the basic block header chain logic. It is not usable
// in itself, but rather an internal structure of core.Blockchain.
// HeaderChain 实现了基本的区块头部链逻辑。它本身不可单独使用，而是 core.Blockchain 的内部结构。
//
// HeaderChain is responsible for maintaining the header chain including the
// header query and updating.
// HeaderChain 负责维护头部链，包括头部查询和更新。
//
// The data components maintained by HeaderChain include:
// HeaderChain 维护的数据组件包括：
//
// - total difficulty
// - 总难度
// - header
// - 头部
// - block hash -> number mapping
// - 区块哈希到区块号的映射
// - canonical number -> hash mapping
// - 规范区块号到哈希的映射
// - head header flag.
// - 头部标志。
//
// It is not thread safe, the encapsulating chain structures should do the
// necessary mutex locking/unlocking.
// 它不是线程安全的，封装的链结构应负责必要的互斥锁加锁/解锁。
type HeaderChain struct {
	config        *params.ChainConfig // 链配置
	chainDb       ethdb.Database      // 链数据库
	genesisHeader *types.Header       // 创世区块头部

	currentHeader atomic.Pointer[types.Header] // Current head of the header chain (maybe above the block chain!)
	// 当前头部链的头部（可能高于区块链！）
	currentHeaderHash common.Hash // Hash of the current head of the header chain (prevent recomputing all the time)
	// 当前头部链的头部哈希（避免反复计算）

	headerCache *lru.Cache[common.Hash, *types.Header] // 头部缓存
	tdCache     *lru.Cache[common.Hash, *big.Int]      // most recent total difficulties 最近的总难度缓存
	numberCache *lru.Cache[common.Hash, uint64]        // most recent block numbers 最近的区块号缓存

	procInterrupt func() bool      // 处理中断函数
	engine        consensus.Engine // 共识引擎
}

// NewHeaderChain creates a new HeaderChain structure. ProcInterrupt points
// to the parent's interrupt semaphore.
// NewHeaderChain 创建一个新的 HeaderChain 结构。ProcInterrupt 指向父级的中断信号量。
func NewHeaderChain(chainDb ethdb.Database, config *params.ChainConfig, engine consensus.Engine, procInterrupt func() bool) (*HeaderChain, error) {
	hc := &HeaderChain{
		config:        config,
		chainDb:       chainDb,
		headerCache:   lru.NewCache[common.Hash, *types.Header](headerCacheLimit),
		tdCache:       lru.NewCache[common.Hash, *big.Int](tdCacheLimit),
		numberCache:   lru.NewCache[common.Hash, uint64](numberCacheLimit),
		procInterrupt: procInterrupt,
		engine:        engine,
	}
	hc.genesisHeader = hc.GetHeaderByNumber(0) // 获取创世区块头部
	if hc.genesisHeader == nil {
		return nil, ErrNoGenesis // 如果创世区块不存在，返回错误
	}
	hc.currentHeader.Store(hc.genesisHeader) // 将创世区块头部设置为当前头部
	if head := rawdb.ReadHeadBlockHash(chainDb); head != (common.Hash{}) {
		if chead := hc.GetHeaderByHash(head); chead != nil {
			hc.currentHeader.Store(chead) // 如果数据库中有头部区块哈希，则更新当前头部
		}
	}
	hc.currentHeaderHash = hc.CurrentHeader().Hash()          // 设置当前头部哈希
	headHeaderGauge.Update(hc.CurrentHeader().Number.Int64()) // 更新头部高度仪表
	return hc, nil
}

// 代码逻辑注解：
// 1. 初始化 HeaderChain 结构体，设置配置、数据库、缓存等。
// 2. 获取创世区块头部，若失败则返回错误。
// 3. 将创世区块头部设为当前头部，并检查数据库中是否有更新的头部区块，若有则更新。
// 4. 设置当前头部哈希并更新仪表。

// GetBlockNumber retrieves the block number belonging to the given hash
// from the cache or database
// GetBlockNumber 从缓存或数据库中检索给定哈希对应的区块号
func (hc *HeaderChain) GetBlockNumber(hash common.Hash) *uint64 {
	if cached, ok := hc.numberCache.Get(hash); ok {
		return &cached // 如果缓存中存在，直接返回
	}
	number := rawdb.ReadHeaderNumber(hc.chainDb, hash) // 从数据库读取区块号
	if number != nil {
		hc.numberCache.Add(hash, *number)
	}
	return number
}

// 代码逻辑注解：
// 1. 优先检查缓存，若存在则返回缓存中的区块号。
// 2. 若缓存中不存在，从数据库读取并加入缓存后返回。

// 中文注解：定义头部写入结果结构体
type headerWriteResult struct {
	status     WriteStatus   // 写入状态
	ignored    int           // 被忽略的头部数量
	imported   int           // 已导入的头部数量
	lastHash   common.Hash   // 最后一个头部的哈希
	lastHeader *types.Header // 最后一个头部
}

// Reorg reorgs the local canonical chain into the specified chain. The reorg
// can be classified into two cases: (a) extend the local chain (b) switch the
// head to the given header.
// Reorg 将本地规范链重新组织为指定的链。重组可分为两种情况：(a) 扩展本地链 (b) 将头部切换到给定的头部。
func (hc *HeaderChain) Reorg(headers []*types.Header) error {
	// Short circuit if nothing to reorg.
	// 如果没有需要重组的内容，直接返回。
	if len(headers) == 0 {
		return nil
	}
	// If the parent of the (first) block is already the canon header,
	// we don't have to go backwards to delete canon blocks, but simply
	// pile them onto the existing chain. Otherwise, do the necessary
	// reorgs.
	// 如果（第一个）区块的父区块已经是规范头部，我们无需回退删除规范区块，只需将它们堆叠到现有链上。否则，执行必要的重组。
	var (
		first = headers[0]              // 第一个头部
		last  = headers[len(headers)-1] // 最后一个头部
		batch = hc.chainDb.NewBatch()   // 创建数据库批处理
	)
	if first.ParentHash != hc.currentHeaderHash {
		// Delete any canonical number assignments above the new head
		// 删除新头部以上的任何规范编号分配
		for i := last.Number.Uint64() + 1; ; i++ {
			hash := rawdb.ReadCanonicalHash(hc.chainDb, i)
			if hash == (common.Hash{}) {
				break // 如果哈希为空，退出循环
			}
			rawdb.DeleteCanonicalHash(batch, i) // 删除规范哈希
		}
		// Overwrite any stale canonical number assignments, going
		// backwards from the first header in this import until the
		// cross link between two chains.
		// 覆盖任何过时的规范编号分配，从本次导入的第一个头部向后回溯，直到两条链的交叉点。
		var (
			header     = first                  // 当前处理的头部
			headNumber = header.Number.Uint64() // 当前头部编号
			headHash   = header.Hash()          // 当前头部哈希
		)
		for rawdb.ReadCanonicalHash(hc.chainDb, headNumber) != headHash {
			rawdb.WriteCanonicalHash(batch, headHash, headNumber) // 写入新的规范哈希
			if headNumber == 0 {
				break // It shouldn't be reached 不应到达此点，退出循环
			}
			headHash, headNumber = header.ParentHash, header.Number.Uint64()-1 // 更新为父哈希和编号
			header = hc.GetHeader(headHash, headNumber)                        // 获取父头部
			if header == nil {
				return fmt.Errorf("missing parent %d %x", headNumber, headHash) // 如果父头部缺失，返回错误
			}
		}
	}
	// Extend the canonical chain with the new headers
	// 用新头部扩展规范链
	for i := 0; i < len(headers)-1; i++ {
		hash := headers[i+1].ParentHash // Save some extra hashing
		// 保存一些额外的哈希计算
		num := headers[i].Number.Uint64()
		rawdb.WriteCanonicalHash(batch, hash, num) // 写入规范哈希
		rawdb.WriteHeadHeaderHash(batch, hash)     // 写入头部哈希
	}
	// Write the last header
	// 写入最后一个头部
	hash := headers[len(headers)-1].Hash()
	num := headers[len(headers)-1].Number.Uint64()
	rawdb.WriteCanonicalHash(batch, hash, num) // 写入最后一个规范哈希
	rawdb.WriteHeadHeaderHash(batch, hash)     // 写入最后一个头部哈希

	if err := batch.Write(); err != nil {
		return err // 如果批处理写入失败，返回错误
	}
	// Last step update all in-memory head header markers
	// 最后一步更新内存中的头部标记
	hc.currentHeaderHash = last.Hash()
	hc.currentHeader.Store(types.CopyHeader(last))
	headHeaderGauge.Update(last.Number.Int64())
	return nil
}

// 代码逻辑注解：
// 1. 如果传入的头部为空，直接返回。
// 2. 检查第一个头部的父哈希是否为当前头部哈希，若不是则需要删除旧的规范链数据并重新写入。
// 3. 从最后一个头部编号向上删除多余的规范哈希。
// 4. 从第一个头部向后回溯，覆盖旧的规范哈希直到与现有链交叉。
// 5. 将新头部逐个写入规范链，最后更新内存中的当前头部信息。

// WriteHeaders writes a chain of headers into the local chain, given that the
// parents are already known. The chain head header won't be updated in this
// function, the additional SetCanonical is expected in order to finish the entire
// procedure.
// WriteHeaders 将一组头部写入本地链，前提是父区块已知。此函数不会更新链头部，需额外调用 SetCanonical 以完成整个过程。
func (hc *HeaderChain) WriteHeaders(headers []*types.Header) (int, error) {
	if len(headers) == 0 {
		return 0, nil // 如果头部为空，返回 0 和 nil
	}
	ptd := hc.GetTd(headers[0].ParentHash, headers[0].Number.Uint64()-1) // 获取父区块的总难度
	if ptd == nil {
		return 0, consensus.ErrUnknownAncestor // 如果父区块未知，返回错误
	}
	var (
		newTD = new(big.Int).Set(ptd) // Total difficulty of inserted chain
		// 插入链的总难度
		inserted []rawdb.NumberHash // Ephemeral lookup of number/hash for the chain
		// 链的临时编号/哈希查找表
		parentKnown = true // Set to true to force hc.HasHeader check the first iteration
		// 设置为 true 以强制第一次迭代检查 hc.HasHeader
		batch = hc.chainDb.NewBatch() // 创建数据库批处理
	)
	for i, header := range headers {
		var hash common.Hash
		// The headers have already been validated at this point, so we already
		// know that it's a contiguous chain, where
		// headers[i].Hash() == headers[i+1].ParentHash
		// 此时头部已通过验证，因此我们知道这是一个连续的链，其中
		// headers[i].Hash() == headers[i+1].ParentHash
		if i < len(headers)-1 {
			hash = headers[i+1].ParentHash // 获取下一个头部的父哈希
		} else {
			hash = header.Hash() // 获取当前头部的哈希
		}
		number := header.Number.Uint64()
		newTD.Add(newTD, header.Difficulty) // 累加总难度

		// If the parent was not present, store it
		// If the header is already known, skip it, otherwise store
		// 如果父区块不存在，则存储它
		// 如果头部已知，则跳过，否则存储
		alreadyKnown := parentKnown && hc.HasHeader(hash, number) // 检查头部是否已知
		if !alreadyKnown {
			// Irrelevant of the canonical status, write the TD and header to the database.
			// 无论规范状态如何，将总难度和头部写入数据库。
			rawdb.WriteTd(batch, hash, number, newTD)     // 写入总难度
			hc.tdCache.Add(hash, new(big.Int).Set(newTD)) // 更新总难度缓存

			rawdb.WriteHeader(batch, header)                                          // 写入头部
			inserted = append(inserted, rawdb.NumberHash{Number: number, Hash: hash}) // 添加到插入列表
			hc.headerCache.Add(hash, header)                                          // 更新头部缓存
			hc.numberCache.Add(hash, number)                                          // 更新区块号缓存
		}
		parentKnown = alreadyKnown // 更新父区块已知状态
	}
	// Skip the slow disk write of all headers if interrupted.
	// 如果被中断，跳过所有头部的慢速磁盘写入。
	if hc.procInterrupt() {
		log.Debug("Premature abort during headers import")
		return 0, errors.New("aborted") // 如果中断，返回错误
	}
	// Commit to disk!
	// 提交到磁盘！
	if err := batch.Write(); err != nil {
		log.Crit("Failed to write headers", "error", err) // 如果写入失败，记录严重错误
	}
	return len(inserted), nil // 返回插入的头部数量
}

// 代码逻辑注解：
// 1. 检查头部列表是否为空，若为空则返回。
// 2. 获取第一个头部的父区块总难度，若未知则返回错误。
// 3. 遍历头部列表，计算总难度并检查每个头部是否已知。
// 4. 对未知头部，写入总难度和头部数据到数据库，并更新缓存。
// 5. 如果中断，提前退出；否则提交批处理并返回插入数量。

// writeHeadersAndSetHead writes a batch of block headers and applies the last
// header as the chain head if the fork choicer says it's ok to update the chain.
// Note: This method is not concurrent-safe with inserting blocks simultaneously
// into the chain, as side effects caused by reorganisations cannot be emulated
// without the real blocks. Hence, writing headers directly should only be done
// in two scenarios: pure-header mode of operation (light clients), or properly
// separated header/block phases (non-archive clients).
// writeHeadersAndSetHead 写入一批区块头部，并将最后一个头部应用为链头部，前提是分叉选择器允许更新链。
// 注意：此方法与同时插入区块到链中不是并发安全的，因为没有真实区块无法模拟重组的副作用。因此，直接写入头部只应在两种场景下进行：纯头部操作模式（轻客户端），或适当分离的头部/区块阶段（非归档客户端）。
func (hc *HeaderChain) writeHeadersAndSetHead(headers []*types.Header) (*headerWriteResult, error) {
	inserted, err := hc.WriteHeaders(headers) // 写入头部
	if err != nil {
		return nil, err // 如果写入失败，返回错误
	}
	var (
		lastHeader = headers[len(headers)-1]        // 最后一个头部
		lastHash   = headers[len(headers)-1].Hash() // 最后一个头部的哈希
		result     = &headerWriteResult{
			status:     NonStatTy,               // 默认非规范状态
			ignored:    len(headers) - inserted, // 计算忽略的头部数量
			imported:   inserted,                // 已导入的头部数量
			lastHash:   lastHash,
			lastHeader: lastHeader,
		}
	)
	// Special case, all the inserted headers are already on the canonical
	// header chain, skip the reorg operation.
	// 特殊情况，所有插入的头部已在规范头部链上，跳过重组操作。
	if hc.GetCanonicalHash(lastHeader.Number.Uint64()) == lastHash && lastHeader.Number.Uint64() <= hc.CurrentHeader().Number.Uint64() {
		return result, nil // 如果最后一个头部已在规范链上，直接返回
	}
	// Apply the reorg operation
	// 应用重组操作
	if err := hc.Reorg(headers); err != nil {
		return nil, err // 如果重组失败，返回错误
	}
	result.status = CanonStatTy // 更新为规范状态
	return result, nil
}

// 代码逻辑注解：
// 1. 调用 WriteHeaders 写入头部，若失败则返回错误。
// 2. 创建结果结构体，记录状态、忽略数量、导入数量等。
// 3. 检查最后一个头部是否已在规范链上，若是则无需重组。
//4. 否则调用 Reorg 进行重组，并更新状态为规范状态。

// 中文注解：验证头部链的函数
func (hc *HeaderChain) ValidateHeaderChain(chain []*types.Header) (int, error) {
	// Do a sanity check that the provided chain is actually ordered and linked
	// 对提供的链进行健全性检查，确保其有序且链接正确
	for i := 1; i < len(chain); i++ {
		if chain[i].Number.Uint64() != chain[i-1].Number.Uint64()+1 {
			hash := chain[i].Hash()
			parentHash := chain[i-1].Hash()
			// Chain broke ancestry, log a message (programming error) and skip insertion
			// 链的祖先关系断裂，记录消息（编程错误）并跳过插入
			log.Error("Non contiguous header insert", "number", chain[i].Number, "hash", hash,
				"parent", chain[i].ParentHash, "prevnumber", chain[i-1].Number, "prevhash", parentHash)

			return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x..], item %d is #%d [%x..] (parent [%x..])", i-1, chain[i-1].Number,
				parentHash.Bytes()[:4], i, chain[i].Number, hash.Bytes()[:4], chain[i].ParentHash[:4])
		}
	}
	// Start the parallel verifier
	// 启动并行验证器
	abort, results := hc.engine.VerifyHeaders(hc, chain)
	defer close(abort)

	// Iterate over the headers and ensure they all check out
	// 遍历头部并确保它们都通过检查
	for i := range chain {
		// If the chain is terminating, stop processing blocks
		// 如果链正在终止，停止处理区块
		if hc.procInterrupt() {
			log.Debug("Premature abort during headers verification")
			return 0, errors.New("aborted")
		}
		// Otherwise wait for headers checks and ensure they pass
		// 否则等待头部检查并确保通过
		if err := <-results; err != nil {
			return i, err // 如果验证失败，返回失败的索引和错误
		}
	}

	return 0, nil // 验证成功，返回 0 和 nil
}

// 代码逻辑注解：
// 1. 检查头部链是否连续，若不连续则记录错误并返回。
// 2. 使用共识引擎启动并行验证。
// 3. 遍历头部，检查中断状态并等待验证结果，若失败则返回错误。

// InsertHeaderChain inserts the given headers and does the reorganisations.
//
// The validity of the headers is NOT CHECKED by this method, i.e. they need to be
// validated by ValidateHeaderChain before calling InsertHeaderChain.
//
// This insert is all-or-nothing. If this returns an error, no headers were written,
// otherwise they were all processed successfully.
//
// The returned 'write status' says if the inserted headers are part of the canonical chain
// or a side chain.
// InsertHeaderChain 插入给定的头部并执行重组。
//
// 此方法不对头部的有效性进行检查，即在调用 InsertHeaderChain 前需通过 ValidateHeaderChain 验证。
//
// 插入是全或无的。如果返回错误，则没有头部被写入，否则所有头部都被成功处理。
//
// 返回的“写入状态”表示插入的头部是规范链的一部分还是侧链。
func (hc *HeaderChain) InsertHeaderChain(chain []*types.Header, start time.Time) (WriteStatus, error) {
	if hc.procInterrupt() {
		return 0, errors.New("aborted") // 如果中断，返回错误
	}
	res, err := hc.writeHeadersAndSetHead(chain) // 写入头部并设置头部
	if err != nil {
		return 0, err // 如果失败，返回错误
	}
	// Report some public statistics so the user has a clue what's going on
	// 报告一些公共统计信息，以便用户了解正在发生的事情
	context := []interface{}{
		"count", res.imported,
		"elapsed", common.PrettyDuration(time.Since(start)),
	}
	if last := res.lastHeader; last != nil {
		context = append(context, "number", last.Number, "hash", res.lastHash)
		if timestamp := time.Unix(int64(last.Time), 0); time.Since(timestamp) > time.Minute {
			context = append(context, []interface{}{"age", common.PrettyAge(timestamp)}...)
		}
	}
	if res.ignored > 0 {
		context = append(context, []interface{}{"ignored", res.ignored}...)
	}
	log.Debug("Imported new block headers", context...)
	return res.status, err
}

// 代码逻辑注解：
// 1. 检查中断状态，若中断则返回错误。
// 2. 调用 writeHeadersAndSetHead 写入头部并设置头部。
// 3. 记录导入统计信息，包括数量、耗时、最后一个头部的编号和哈希等。

// GetAncestor retrieves the Nth ancestor of a given block. It assumes that either the given block or
// a close ancestor of it is canonical. maxNonCanonical points to a downwards counter limiting the
// number of blocks to be individually checked before we reach the canonical chain.
//
// Note: ancestor == 0 returns the same block, 1 returns its parent and so on.
// GetAncestor 检索给定区块的第 N 个祖先。假设给定的区块或其近亲祖先是规范的。maxNonCanonical 指向一个向下计数器，限制在到达规范链之前单独检查的区块数量。
//
// 注意：ancestor == 0 返回同一区块，1 返回其父区块，依此类推。
func (hc *HeaderChain) GetAncestor(hash common.Hash, number, ancestor uint64, maxNonCanonical *uint64) (common.Hash, uint64) {
	if ancestor > number {
		return common.Hash{}, 0 // 如果祖先编号大于当前编号，返回空值
	}
	if ancestor == 1 {
		// in this case it is cheaper to just read the header
		// 在这种情况下，直接读取头部更便宜
		if header := hc.GetHeader(hash, number); header != nil {
			return header.ParentHash, number - 1 // 返回父哈希和编号
		}
		return common.Hash{}, 0
	}
	for ancestor != 0 {
		if rawdb.ReadCanonicalHash(hc.chainDb, number) == hash {
			ancestorHash := rawdb.ReadCanonicalHash(hc.chainDb, number-ancestor)
			if rawdb.ReadCanonicalHash(hc.chainDb, number) == hash {
				number -= ancestor
				return ancestorHash, number // 如果找到规范祖先，返回其哈希和编号
			}
		}
		if *maxNonCanonical == 0 {
			return common.Hash{}, 0 // 如果非规范计数器耗尽，返回空值
		}
		*maxNonCanonical--
		ancestor--
		header := hc.GetHeader(hash, number)
		if header == nil {
			return common.Hash{}, 0 // 如果头部不存在，返回空值
		}
		hash = header.ParentHash
		number--
	}
	return hash, number
}

// 代码逻辑注解：
// 1. 检查祖先编号是否有效，若无效则返回空值。
// 2. 如果只需找父区块，直接读取头部并返回。
// 3. 否则循环回溯，检查规范链并在非规范计数器允许范围内查找祖先。

// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number, caching it if found.
// GetTd 从数据库中按哈希和编号检索规范链中区块的总难度，如果找到则缓存。
func (hc *HeaderChain) GetTd(hash common.Hash, number uint64) *big.Int {
	// Short circuit if the td's already in the cache, retrieve otherwise
	// 如果总难度已在缓存中，直接返回，否则检索
	if cached, ok := hc.tdCache.Get(hash); ok {
		return cached
	}
	td := rawdb.ReadTd(hc.chainDb, hash, number)
	if td == nil {
		return nil // 如果未找到，返回 nil
	}
	// Cache the found body for next time and return
	// 缓存找到的主体以供下次使用并返回
	hc.tdCache.Add(hash, td)
	return td
}

// GetHeader retrieves a block header from the database by hash and number,
// caching it if found.
// GetHeader 从数据库中按哈希和编号检索区块头部，如果找到则缓存。
func (hc *HeaderChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	// Short circuit if the header's already in the cache, retrieve otherwise
	// 如果头部已在缓存中，直接返回，否则检索
	if header, ok := hc.headerCache.Get(hash); ok {
		return header
	}
	header := rawdb.ReadHeader(hc.chainDb, hash, number)
	if header == nil {
		return nil // 如果未找到，返回 nil
	}
	// Cache the found header for next time and return
	// 缓存找到的头部以供下次使用并返回
	hc.headerCache.Add(hash, header)
	return header
}

// GetHeaderByHash retrieves a block header from the database by hash, caching it if
// found.
// GetHeaderByHash 从数据库中按哈希检索区块头部，如果找到则缓存。
func (hc *HeaderChain) GetHeaderByHash(hash common.Hash) *types.Header {
	number := hc.GetBlockNumber(hash) // 获取区块号
	if number == nil {
		return nil // 如果未找到，返回 nil
	}
	return hc.GetHeader(hash, *number) // 根据哈希和编号获取头部
}

// HasHeader checks if a block header is present in the database or not.
// In theory, if header is present in the database, all relative components
// like td and hash->number should be present too.
// HasHeader 检查区块头部是否在数据库中存在。
// 理论上，如果头部存在于数据库中，所有相关组件（如总难度和哈希到编号的映射）也应存在。
func (hc *HeaderChain) HasHeader(hash common.Hash, number uint64) bool {
	if hc.numberCache.Contains(hash) || hc.headerCache.Contains(hash) {
		return true // 如果缓存中存在，返回 true
	}
	return rawdb.HasHeader(hc.chainDb, hash, number) // 检查数据库中是否存在
}

// GetHeaderByNumber retrieves a block header from the database by number,
// caching it (associated with its hash) if found.
// GetHeaderByNumber 从数据库中按编号检索区块头部，如果找到则缓存（与其哈希关联）。
func (hc *HeaderChain) GetHeaderByNumber(number uint64) *types.Header {
	hash := rawdb.ReadCanonicalHash(hc.chainDb, number) // 获取规范哈希
	if hash == (common.Hash{}) {
		return nil // 如果未找到，返回 nil
	}
	return hc.GetHeader(hash, number) // 根据哈希和编号获取头部
}

// GetHeadersFrom returns a contiguous segment of headers, in rlp-form, going
// backwards from the given number.
// If the 'number' is higher than the highest local header, this method will
// return a best-effort response, containing the headers that we do have.
// GetHeadersFrom 返回从给定编号向后的一段连续头部，以 RLP 形式。
// 如果“编号”高于本地最高头部，此方法将尽力返回我们拥有的头部。
func (hc *HeaderChain) GetHeadersFrom(number, count uint64) []rlp.RawValue {
	// If the request is for future headers, we still return the portion of
	// headers that we are able to serve
	// 如果请求的是未来头部，我们仍返回我们能够提供的头部部分
	if current := hc.CurrentHeader().Number.Uint64(); current < number {
		if count > number-current {
			count -= number - current
			number = current // 调整编号和计数以适应当前头部
		} else {
			return nil // 如果无法提供，返回 nil
		}
	}
	var headers []rlp.RawValue
	// If we have some of the headers in cache already, use that before going to db.
	// 如果缓存中已有一些头部，先使用它们再访问数据库。
	hash := rawdb.ReadCanonicalHash(hc.chainDb, number)
	if hash == (common.Hash{}) {
		return nil // 如果未找到规范哈希，返回 nil
	}
	for count > 0 {
		header, ok := hc.headerCache.Get(hash)
		if !ok {
			break // 如果缓存中不存在，退出循环
		}
		rlpData, _ := rlp.EncodeToBytes(header) // 将头部编码为 RLP 格式
		headers = append(headers, rlpData)
		hash = header.ParentHash
		count--
		number--
	}
	// Read remaining from db
	// 从数据库读取剩余部分
	if count > 0 {
		headers = append(headers, rawdb.ReadHeaderRange(hc.chainDb, number, count)...) // 读取剩余头部
	}
	return headers
}

// 中文注解：获取指定编号的规范哈希
func (hc *HeaderChain) GetCanonicalHash(number uint64) common.Hash {
	return rawdb.ReadCanonicalHash(hc.chainDb, number)
}

// CurrentHeader retrieves the current head header of the canonical chain. The
// header is retrieved from the HeaderChain's internal cache.
// CurrentHeader 检索规范链的当前头部。从 HeaderChain 的内部缓存中检索头部。
func (hc *HeaderChain) CurrentHeader() *types.Header {
	return hc.currentHeader.Load() // 从原子指针加载当前头部
}

// SetCurrentHeader sets the in-memory head header marker of the canonical chan
// as the given header.
// SetCurrentHeader 将规范链的内存头部标记设置为给定的头部。
func (hc *HeaderChain) SetCurrentHeader(head *types.Header) {
	hc.currentHeader.Store(head)                // 存储新头部
	hc.currentHeaderHash = head.Hash()          // 更新头部哈希
	headHeaderGauge.Update(head.Number.Int64()) // 更新仪表
}

// 中文注解：定义更新头部区块的回调函数类型
type (
	// UpdateHeadBlocksCallback is a callback function that is called by SetHead
	// before head header is updated. The method will return the actual block it
	// updated the head to (missing state) and a flag if setHead should continue
	// rewinding till that forcefully (exceeded ancient limits)
	// UpdateHeadBlocksCallback 是 SetHead 在更新头部之前调用的回调函数。该方法返回实际更新到的头部区块（可能缺少状态）和一个标志，指示是否应强制继续回退（超出古老限制）。
	UpdateHeadBlocksCallback func(ethdb.KeyValueWriter, *types.Header) (*types.Header, bool)

	// DeleteBlockContentCallback is a callback function that is called by SetHead
	// before each header is deleted.
	// DeleteBlockContentCallback 是 SetHead 在删除每个头部之前调用的回调函数。
	DeleteBlockContentCallback func(ethdb.KeyValueWriter, common.Hash, uint64)
)

// SetHead rewinds the local chain to a new head. Everything above the new head
// will be deleted and the new one set.
// SetHead 将本地链回退到新的头部。新头部以上的所有内容将被删除，并设置新的头部。
func (hc *HeaderChain) SetHead(head uint64, updateFn UpdateHeadBlocksCallback, delFn DeleteBlockContentCallback) {
	hc.setHead(head, 0, updateFn, delFn) // 调用内部 setHead 方法
}

// SetHeadWithTimestamp rewinds the local chain to a new head timestamp. Everything
// above the new head will be deleted and the new one set.
// SetHeadWithTimestamp 将本地链回退到新的头部时间戳。新头部以上的所有内容将被删除，并设置新的头部。
func (hc *HeaderChain) SetHeadWithTimestamp(time uint64, updateFn UpdateHeadBlocksCallback, delFn DeleteBlockContentCallback) {
	hc.setHead(0, time, updateFn, delFn) // 调用内部 setHead 方法
}

// setHead rewinds the local chain to a new head block or a head timestamp.
// Everything above the new head will be deleted and the new one set.
// setHead 将本地链回退到新的头部区块或头部时间戳。新头部以上的所有内容将被删除，并设置新的头部。
func (hc *HeaderChain) setHead(headBlock uint64, headTime uint64, updateFn UpdateHeadBlocksCallback, delFn DeleteBlockContentCallback) {
	// Sanity check that there's no attempt to undo the genesis block. This is
	// a fairly synthetic case where someone enables a timestamp based fork
	// below the genesis timestamp. It's nice to not allow that instead of the
	// entire chain getting deleted.
	// 健全性检查，确保不会尝试撤销创世区块。这是一个相当人为的情况，有人启用了低于创世时间戳的分叉。不允许这样做比删除整个链更好。
	if headTime > 0 && hc.genesisHeader.Time > headTime {
		// Note, a critical error is quite brutal, but we should really not reach
		// this point. Since pre-timestamp based forks it was impossible to have
		// a fork before block 0, the setHead would always work. With timestamp
		// forks it becomes possible to specify below the genesis. That said, the
		// only time we setHead via timestamp is with chain config changes on the
		// startup, so failing hard there is ok.
		// 注意，严重错误相当残酷，但我们确实不应到达这一点。在基于时间戳的分叉之前，不可能在第 0 块之前有分叉，setHead 总是有效的。有了时间戳分叉，就可能指定低于创世块的时间。也就是说，我们唯一通过时间戳设置 setHead 的时候是在启动时的链配置更改，所以那里硬性失败是可以的。
		log.Crit("Rejecting genesis rewind via timestamp", "target", headTime, "genesis", hc.genesisHeader.Time)
	}
	var (
		parentHash common.Hash
		batch      = hc.chainDb.NewBatch() // 创建批处理
		origin     = true                  // 标记是否为第一次迭代
	)
	done := func(header *types.Header) bool {
		if headTime > 0 {
			return header.Time <= headTime // 如果基于时间戳，检查时间是否满足
		}
		return header.Number.Uint64() <= headBlock // 如果基于区块号，检查编号是否满足
	}
	for hdr := hc.CurrentHeader(); hdr != nil && !done(hdr); hdr = hc.CurrentHeader() {
		num := hdr.Number.Uint64()

		// Rewind chain to new head
		// 将链回退到新头部
		parent := hc.GetHeader(hdr.ParentHash, num-1)
		if parent == nil {
			parent = hc.genesisHeader // 如果父区块不存在，使用创世区块
		}
		parentHash = parent.Hash()

		// Notably, since geth has the possibility for setting the head to a low
		// height which is even lower than ancient head.
		// In order to ensure that the head is always no higher than the data in
		// the database (ancient store or active store), we need to update head
		// first then remove the relative data from the database.
		//
		// Update head first(head fast block, head full block) before deleting the data.
		// 值得注意的是，由于 geth 可以将头部设置为低于古老头部的高度。
		// 为了确保头部始终不超过数据库中的数据（古老存储或活动存储），我们需要先更新头部，然后删除相关数据。
		//
		// 先更新头部（快速区块头部、完整区块头部），然后删除数据。
		markerBatch := hc.chainDb.NewBatch()
		if updateFn != nil {
			newHead, force := updateFn(markerBatch, parent) // 调用更新回调
			if force && ((headTime > 0 && newHead.Time < headTime) || (headTime == 0 && newHead.Number.Uint64() < headBlock)) {
				log.Warn("Force rewinding till ancient limit", "head", newHead.Number.Uint64())
				headBlock, headTime = newHead.Number.Uint64(), 0 // Target timestamp passed, continue rewind in block mode (cleaner) 强制回退到古老限制
			}
		}
		// Update head header then.
		// 然后更新头部。
		rawdb.WriteHeadHeaderHash(markerBatch, parentHash)
		if err := markerBatch.Write(); err != nil {
			log.Crit("Failed to update chain markers", "error", err) // 如果更新失败，记录严重错误
		}
		hc.currentHeader.Store(parent)
		hc.currentHeaderHash = parentHash
		headHeaderGauge.Update(parent.Number.Int64())

		// If this is the first iteration, wipe any leftover data upwards too so
		// we don't end up with dangling daps in the database
		// 如果这是第一次迭代，也向上擦除任何剩余数据，以免数据库中出现悬空数据
		var nums []uint64
		if origin {
			for n := num + 1; len(rawdb.ReadAllHashes(hc.chainDb, n)) > 0; n++ {
				nums = append([]uint64{n}, nums...) // suboptimal, but we don't really expect this path 收集需要删除的编号
			}
			origin = false
		}
		nums = append(nums, num)

		// Remove the related data from the database on all sidechains
		// 从所有侧链中删除相关数据
		for _, num := range nums {
			// Gather all the side fork hashes
			// 收集所有侧叉哈希
			hashes := rawdb.ReadAllHashes(hc.chainDb, num)
			if len(hashes) == 0 {
				// No hashes in the database whatsoever, probably frozen already
				// 数据库中完全没有哈希，可能已被冻结
				hashes = append(hashes, hdr.Hash())
			}
			for _, hash := range hashes {
				if delFn != nil {
					delFn(batch, hash, num) // 调用删除回调
				}
				rawdb.DeleteHeader(batch, hash, num) // 删除头部
				rawdb.DeleteTd(batch, hash, num)     // 删除总难度
			}
			rawdb.DeleteCanonicalHash(batch, num) // 删除规范哈希
		}
	}
	// Flush all accumulated deletions.
	// 刷新所有累积的删除操作。
	if err := batch.Write(); err != nil {
		log.Crit("Failed to rewind block", "error", err)
	}
	// Clear out any stale content from the caches
	// 清除缓存中的任何过时内容
	hc.headerCache.Purge()
	hc.tdCache.Purge()
	hc.numberCache.Purge()
}

// 代码逻辑注解：
// 1. 检查是否尝试回退创世区块，若是则记录严重错误。
// 2. 定义完成条件（基于时间戳或区块号）。
// 3. 循环回退当前头部，获取父区块并更新头部标记。
// 4. 删除高于新头部的所有数据，包括侧链数据。
// 5. 提交批处理并清除缓存。

// SetGenesis sets a new genesis block header for the chain
// SetGenesis 为链设置新的创世区块头部
func (hc *HeaderChain) SetGenesis(head *types.Header) {
	hc.genesisHeader = head // 设置创世头部
}

// Config retrieves the header chain's chain configuration.
// Config 检索头部链的链配置。
func (hc *HeaderChain) Config() *params.ChainConfig { return hc.config }

// Engine retrieves the header chain's consensus engine.
// Engine 检索头部链的共识引擎。
func (hc *HeaderChain) Engine() consensus.Engine { return hc.engine }

// GetBlock implements consensus.ChainReader, and returns nil for every input as
// a header chain does not have blocks available for retrieval.
// GetBlock 实现 consensus.ChainReader，对于每个输入返回 nil，因为头部链无法检索区块。
func (hc *HeaderChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return nil
}
