// Copyright 2023 The go-ethereum Authors
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

package blobpool

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/billy"
)

// Blob 交易、重组和最终性
//
// 在以太坊中，交易首先被广播到网络，然后由矿工打包到区块中。由于网络延迟和共识机制，可能会发生短暂的区块链分叉或重组 (reorgs)，即暂时出现多个竞争的链头。最终，其中一条链会成为主链，而其他分叉上的区块和交易会被丢弃。
//
// 对于引入了 Blob 交易的 EIP-4844 来说，这些包含大量数据的交易的处理方式与普通交易有所不同。limbo 结构体的目的是在 Blob 交易被包含到区块后，但在该区块被认为是最终确定 (finalized) 之前，临时存储这些交易的相关信息。这样做是为了在发生小的重组时，能够找回那些原本包含在现在被废弃的区块中的 Blob 交易。
//
// limbo 结构体的作用
//
// limbo 是一个轻量级的、带有索引的数据库，用于临时存储最近包含的 Blob 交易，直到它们所在的区块达到最终性。它使用一个持久性存储 (billy.Database) 来保存数据，并使用内存中的索引来加速查找和管理。

// EIP-4844 (Blob 交易): limbo 的设计是为了处理 EIP-4844 引入的 Blob 交易，这些交易具有较大的数据负载。
// 重组处理: limbo 的主要目的是在发生区块链重组时，临时保存最近包含的 Blob 交易，以便在重组后能够恢复这些交易，避免数据丢失或需要重新广播。
// 最终性: 区块链的最终性是指一旦某个区块被确认，就很难再被撤销。limbo 会存储 Blob 交易直到它们所在的区块达到一定的最终性，之后就可以安全地从 limbo 中移除。
// 临时存储: limbo 提供了一个临时的存储层，介于交易池和永久的区块链存储之间，专门用于处理 Blob 交易在最终确定之前的状态。
// 持久性存储: 使用 billy.Database 作为底层存储意味着即使节点重启，limbo 中的数据也可以被保留，直到达到最终性条件。

// limboBlob is a wrapper around an opaque blobset that also contains the tx hash
// to which it belongs as well as the block number in which it was included for
// finality eviction.
// limboBlob 是一个围绕不透明 blobset 的包装器，它还包含其所属的交易哈希以及包含它的区块号，用于最终性驱逐。
type limboBlob struct {
	TxHash common.Hash // Owner transaction's hash to support resurrecting reorged txs
	// TxHash 所有者交易的哈希，用于支持恢复重组的交易。
	Block uint64 // Block in which the blob transaction was included
	// Block 包含 blob 交易的区块号。
	Tx *types.Transaction
	// Tx 包含的完整交易对象。
}

// limbo is a light, indexed database to temporarily store recently included
// blobs until they are finalized. The purpose is to support small reorgs, which
// would require pulling back up old blobs (which aren't part of the chain).
// limbo 是一个轻量级的索引数据库，用于临时存储最近包含的 blob，直到它们最终确定。
// 目的是支持小的重组，这需要拉回旧的 blob（这些 blob 不属于链的一部分）。
//
// TODO(karalabe): Currently updating the inclusion block of a blob needs a full db rewrite. Can we do without?
// TODO(karalabe): 目前更新 blob 的包含区块需要完全重写数据库。我们能避免吗？
type limbo struct {
	store billy.Database // Persistent data store for limboed blobs
	// store 用于存储在 limbo 中的 blob 的持久性数据存储。

	index map[common.Hash]uint64 // Mappings from tx hashes to datastore ids
	// index 从交易哈希到数据存储 ID 的映射。
	groups map[uint64]map[uint64]common.Hash // Set of txs included in past blocks
	// groups 包含在过去区块中的交易集合，按区块号和数据存储 ID 索引。
}

// newLimbo opens and indexes a set of limboed blob transactions.
// newLimbo 打开并索引一组在 limbo 中的 blob 交易。
func newLimbo(datadir string) (*limbo, error) {
	// newLimbo 函数创建一个新的 limbo 实例，并从给定的数据目录加载和索引现有的 blob。
	l := &limbo{
		index:  make(map[common.Hash]uint64),
		groups: make(map[uint64]map[uint64]common.Hash),
	}
	// Index all limboed blobs on disk and delete anything unprocessable
	// 索引磁盘上所有在 limbo 中的 blob，并删除任何无法处理的内容。
	var fails []uint64
	index := func(id uint64, size uint32, data []byte) {
		if l.parseBlob(id, data) != nil {
			fails = append(fails, id)
		}
	}
	store, err := billy.Open(billy.Options{Path: datadir, Repair: true}, newSlotter(), index)
	if err != nil {
		return nil, err
	}
	l.store = store

	if len(fails) > 0 {
		log.Warn("Dropping invalidated limboed blobs", "ids", fails)
		for _, id := range fails {
			if err := l.store.Delete(id); err != nil {
				l.Close()
				return nil, err
			}
		}
	}
	return l, nil
}

// Close closes down the underlying persistent store.
// Close 关闭底层的持久性存储。
func (l *limbo) Close() error {
	// Close 方法关闭 limbo 使用的持久性数据存储。
	return l.store.Close()
}

// parseBlob is a callback method on limbo creation that gets called for each
// limboed blob on disk to create the in-memory metadata index.
// parseBlob 是 limbo 创建时的回调方法，对于磁盘上的每个 limbo 中的 blob 都会调用它，以创建内存中的元数据索引。
func (l *limbo) parseBlob(id uint64, data []byte) error {
	// parseBlob 函数解析从磁盘加载的单个 blob 数据项，并将其添加到内存索引中。
	item := new(limboBlob)
	if err := rlp.DecodeBytes(data, item); err != nil {
		// This path is impossible unless the disk data representation changes
		// across restarts. For that ever improbable case, recover gracefully
		// by ignoring this data entry.
		// 除非跨重启磁盘数据表示发生更改，否则此路径不可能发生。
		// 对于这种极不可能的情况，通过忽略此数据条目来优雅地恢复。
		log.Error("Failed to decode blob limbo entry", "id", id, "err", err)
		return err
	}
	if _, ok := l.index[item.TxHash]; ok {
		// This path is impossible, unless due to a programming error a blob gets
		// inserted into the limbo which was already part of if. Recover gracefully
		// by ignoring this data entry.
		// 除非由于编程错误导致已在 limbo 中的 blob 再次插入，否则此路径不可能发生。
		// 通过忽略此数据条目来优雅地恢复。
		log.Error("Dropping duplicate blob limbo entry", "owner", item.TxHash, "id", id)
		return errors.New("duplicate blob")
	}
	l.index[item.TxHash] = id

	if _, ok := l.groups[item.Block]; !ok {
		l.groups[item.Block] = make(map[uint64]common.Hash)
	}
	l.groups[item.Block][id] = item.TxHash

	return nil
}

// finalize evicts all blobs belonging to a recently finalized block or older.
// finalize 驱逐所有属于最近最终确定的区块或更早区块的 blob。
func (l *limbo) finalize(final *types.Header) {
	// finalize 方法根据最近最终确定的区块头，从 limbo 中删除过时的 blob。
	// Just in case there's no final block yet (network not yet merged, weird
	// restart, sethead, etc), fail gracefully.
	// 以防还没有最终确定的区块（网络尚未合并，奇怪的重启，sethead 等），优雅地失败。
	if final == nil {
		log.Error("Nil finalized block cannot evict old blobs")
		return
	}
	for block, ids := range l.groups {
		if block > final.Number.Uint64() {
			continue
		}
		for id, owner := range ids {
			if err := l.store.Delete(id); err != nil {
				log.Error("Failed to drop finalized blob", "block", block, "id", id, "err", err)
			}
			delete(l.index, owner)
		}
		delete(l.groups, block)
	}
}

// push stores a new blob transaction into the limbo, waiting until finality for
// it to be automatically evicted.
// push 将一个新的 blob 交易存储到 limbo 中，等待最终确定后自动驱逐。
func (l *limbo) push(tx *types.Transaction, block uint64) error {
	// push 方法将一个新的 blob 交易添加到 limbo 中。
	// If the blobs are already tracked by the limbo, consider it a programming
	// error. There's not much to do against it, but be loud.
	// 如果 blob 已经被 limbo 跟踪，则认为是编程错误。对此没有太多可做的，但要发出警告。
	if _, ok := l.index[tx.Hash()]; ok {
		log.Error("Limbo cannot push already tracked blobs", "tx", tx)
		return errors.New("already tracked blob transaction")
	}
	if err := l.setAndIndex(tx, block); err != nil {
		log.Error("Failed to set and index limboed blobs", "tx", tx, "err", err)
		return err
	}
	return nil
}

// pull retrieves a previously pushed set of blobs back from the limbo, removing
// it at the same time. This method should be used when a previously included blob
// transaction gets reorged out.
// pull 从 limbo 中检索先前推送的一组 blob，同时将其删除。
// 当先前包含的 blob 交易被重组时，应使用此方法。
func (l *limbo) pull(tx common.Hash) (*types.Transaction, error) {
	// pull 方法从 limbo 中检索并删除一个 blob 交易，通常在发生重组时使用。
	// If the blobs are not tracked by the limbo, there's not much to do. This
	// can happen for example if a blob transaction is mined without pushing it
	// into the network first.
	// 如果 blob 没有被 limbo 跟踪，则无需执行任何操作。
	// 例如，如果在没有先将其推送到网络的情况下挖掘了 blob 交易，则可能会发生这种情况。
	id, ok := l.index[tx]
	if !ok {
		log.Trace("Limbo cannot pull non-tracked blobs", "tx", tx)
		return nil, errors.New("unseen blob transaction")
	}
	item, err := l.getAndDrop(id)
	if err != nil {
		log.Error("Failed to get and drop limboed blobs", "tx", tx, "id", id, "err", err)
		return nil, err
	}
	return item.Tx, nil
}

// update changes the block number under which a blob transaction is tracked. This
// method should be used when a reorg changes a transaction's inclusion block.
// update 更改跟踪 blob 交易的区块号。当重组更改交易的包含区块时，应使用此方法。
//
// The method may log errors for various unexpected scenarios but will not return
// any of it since there's no clear error case. Some errors may be due to coding
// issues, others caused by signers mining MEV stuff or swapping transactions. In
// all cases, the pool needs to continue operating.
// 该方法可能会记录各种意外情况的错误，但不会返回任何错误，因为没有明确的错误情况。
// 某些错误可能是由于编码问题，其他错误可能是由于签名者挖掘 MEV 或交换交易造成的。
// 在所有情况下，池需要继续运行。
func (l *limbo) update(txhash common.Hash, block uint64) {
	// update 方法更新 limbo 中 blob 交易的包含区块号。
	// If the blobs are not tracked by the limbo, there's not much to do. This
	// can happen for example if a blob transaction is mined without pushing it
	// into the network first.
	// 如果 blob 没有被 limbo 跟踪，则无需执行任何操作。
	// 例如，如果在没有先将其推送到网络的情况下挖掘了 blob 交易，则可能会发生这种情况。
	id, ok := l.index[txhash]
	if !ok {
		log.Trace("Limbo cannot update non-tracked blobs", "tx", txhash)
		return
	}
	// If there was no change in the blob's inclusion block, don't mess around
	// with heavy database operations.
	// 如果 blob 的包含区块没有变化，则不要进行繁重的数据库操作。
	if _, ok := l.groups[block][id]; ok {
		log.Trace("Blob transaction unchanged in limbo", "tx", txhash, "block", block)
		return
	}
	// Retrieve the old blobs from the data store and write them back with a new
	// block number. IF anything fails, there's not much to do, go on.
	// 从数据存储中检索旧的 blob，并使用新的区块号将其写回。如果任何操作失败，则无需执行任何操作，继续。
	item, err := l.getAndDrop(id)
	if err != nil {
		log.Error("Failed to get and drop limboed blobs", "tx", txhash, "id", id, "err", err)
		return
	}
	if err := l.setAndIndex(item.Tx, block); err != nil {
		log.Error("Failed to set and index limboed blobs", "tx", txhash, "err", err)
		return
	}
	log.Trace("Blob transaction updated in limbo", "tx", txhash, "old-block", item.Block, "new-block", block)
}

// getAndDrop retrieves a blob item from the limbo store and deletes it both from
// the store and indices.
// getAndDrop 从 limbo 存储中检索一个 blob 项，并将其从存储和索引中删除。
func (l *limbo) getAndDrop(id uint64) (*limboBlob, error) {
	// getAndDrop 函数从持久性存储中检索一个 blob 项，并将其从存储和内存索引中删除。
	data, err := l.store.Get(id)
	if err != nil {
		return nil, err
	}
	item := new(limboBlob)
	if err = rlp.DecodeBytes(data, item); err != nil {
		return nil, err
	}
	delete(l.index, item.TxHash)
	delete(l.groups[item.Block], id)
	if len(l.groups[item.Block]) == 0 {
		delete(l.groups, item.Block)
	}
	if err := l.store.Delete(id); err != nil {
		return nil, err
	}
	return item, nil
}

// setAndIndex assembles a limbo blob database entry and stores it, also updating
// the in-memory indices.
// setAndIndex 组装一个 limbo blob 数据库条目并存储它，同时更新内存索引。
func (l *limbo) setAndIndex(tx *types.Transaction, block uint64) error {
	// setAndIndex 函数创建一个 limboBlob 对象，将其序列化并存储到持久性存储中，同时更新内存索引。
	txhash := tx.Hash()
	item := &limboBlob{
		TxHash: txhash,
		Block:  block,
		Tx:     tx,
	}
	data, err := rlp.EncodeToBytes(item)
	if err != nil {
		panic(err) // cannot happen runtime, dev error
	}
	id, err := l.store.Put(data)
	if err != nil {
		return err
	}
	l.index[txhash] = id
	if _, ok := l.groups[block]; !ok {
		l.groups[block] = make(map[uint64]common.Hash)
	}
	l.groups[block][id] = txhash
	return nil
}
