// Copyright 2014 The go-ethereum Authors
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

// Package ethdb defines the interfaces for an Ethereum data store.
// 包 ethdb 定义了以太坊数据存储的接口。
package ethdb

import "io"

// 以太坊节点需要存储多种数据，包括状态树（账户余额、合约状态）、交易、区块头和日志。这些数据通常存储在键/值数据库中。
// ethdb 包定义了访问这些数据的接口，使上层逻辑（如状态处理）无需关心底层存储细节。

// KeyValueReader wraps the Has and Get method of a backing data store.
// KeyValueReader 封装了后端数据存储的 Has 和 Get 方法。
//
// 在以太坊中， KeyValueReader 是 ethdb 包的一部分，用于访问底层数据库（如 LevelDB），读取状态、交易或日志数据。
// 键通常是字节数组（[]byte），值可以是任意数据（如账户余额、合约存储）。
// 该接口专注于读取，不包括写入或删除操作，适合需要只读访问的场景（如状态查询）。
type KeyValueReader interface {
	// Has retrieves if a key is present in the key-value data store.
	// Has 检查键是否存在于键/值数据存储中。
	Has(key []byte) (bool, error)

	// Get retrieves the given key if it's present in the key-value data store.
	// Get 如果给定的键存在于键/值数据存储中，则检索该键。
	Get(key []byte) ([]byte, error)
}

// KeyValueWriter wraps the Put method of a backing data store.
// KeyValueWriter 封装了后端数据存储的 Put 方法。
//
// 封装了键/值数据存储的写入操作，提供了插入和删除键/值对的功能。
// KeyValueWriter 用于操作底层数据库（如 LevelDB），更新状态、交易或存储数据
type KeyValueWriter interface {
	// Put inserts the given value into the key-value data store.
	// Put 将给定的值插入键/值数据存储中。
	Put(key []byte, value []byte) error

	// Delete removes the key from the key-value data store.
	// Delete 从键/值数据存储中删除指定的键。
	Delete(key []byte) error
}

// KeyValueRangeDeleter wraps the DeleteRange method of a backing data store.
// KeyValueRangeDeleter 封装了后端数据存储的 DeleteRange 方法。
//
// 封装了键/值数据存储的范围删除操作，允许一次性删除某个键范围内的所有数据。
// 操作底层数据库（如 LevelDB），清理特定范围的状态或存储数据。
type KeyValueRangeDeleter interface {
	// DeleteRange deletes all of the keys (and values) in the range [start,end)
	// (inclusive on start, exclusive on end).
	// DeleteRange 删除范围 [start, end) 中的所有键（及其值）
	// （包含 start，不包含 end）。
	DeleteRange(start, end []byte) error
}

// KeyValueStater wraps the Stat method of a backing data store.
// KeyValueStater 封装了后端数据存储的 Stat 方法。
//
// 封装了键/值数据存储的统计操作，提供获取数据库统计信息的功能。
// 用于操作底层数据库（如 LevelDB），获取运行时统计数据。
type KeyValueStater interface {
	// Stat returns the statistic data of the database.
	// Stat 返回数据库的统计数据。
	Stat() (string, error)
}

// Compacter wraps the Compact method of a backing data store.
// Compacter 封装了后端数据存储的 Compact 方法。
//
// 封装了键/值数据存储的压缩操作，用于优化存储结构和性能。
// 以太坊的状态数据库会因状态更新或删除积累大量历史版本，Compact 清理这些冗余数据，提升查询效率。
type Compacter interface {
	// Compact flattens the underlying data store for the given key range. In essence,
	// deleted and overwritten versions are discarded, and the data is rearranged to
	// reduce the cost of operations needed to access them.
	//
	// A nil start is treated as a key before all keys in the data store; a nil limit
	// is treated as a key after all keys in the data store. If both is nil then it
	// will compact entire data store.
	//
	// Compact 压缩给定键范围内的底层数据存储。本质上，删除和覆盖的版本将被丢弃，
	// 数据将被重新排列，以减少访问它们所需的操作成本。
	//
	// 如果 start 为 nil，则视为数据存储中所有键之前的一个键；如果 limit 为 nil，
	// 则视为数据存储中所有键之后的一个键。如果两者都为 nil，则压缩整个数据存储。
	Compact(start []byte, limit []byte) error
}

// KeyValueStore contains all the methods required to allow handling different
// key-value data stores backing the high level database.
// KeyValueStore 包含处理支持高级数据库的不同键值数据存储所需的所有方法。
type KeyValueStore interface {
	KeyValueReader
	KeyValueWriter
	KeyValueStater
	KeyValueRangeDeleter
	Batcher
	Iteratee
	Compacter
	io.Closer
}

// AncientReaderOp contains the methods required to read from immutable ancient data.
// AncientReaderOp 包含从不可变的古老数据中读取所需的方法。
//
// 用于从以太坊的不可变古老数据存储中读取数据。
// 提供访问以太坊“冻结”数据的接口，这些数据存储在仅追加的不可变文件中。
// 支持检查、单个读取、范围读取和统计功能。
//
// 古老数据不可修改，只能追加，AncientReaderOp 提供只读访问。
//
//	在以太坊中，古老数据是指较旧的区块数据（如区块体、收据），为了节省活跃数据库（如 LevelDB）的空间，被移到单独的仅追加存储（通常是文件系统上的 freezer）。
//	kind 表示数据类型（如 "headers"、"bodies"、"receipts"）。
//	number 是区块编号，标识具体数据。
type AncientReaderOp interface {
	// HasAncient returns an indicator whether the specified data exists in the
	// ancient store.
	// HasAncient 返回一个指示器，表明指定数据是否存在于古老存储中。
	HasAncient(kind string, number uint64) (bool, error)

	// Ancient retrieves an ancient binary blob from the append-only immutable files.
	// Ancient 从仅追加的不可变文件中检索古老的二进制数据。
	Ancient(kind string, number uint64) ([]byte, error)

	// AncientRange retrieves multiple items in sequence, starting from the index 'start'.
	// It will return
	//   - at most 'count' items,
	//   - if maxBytes is specified: at least 1 item (even if exceeding the maxByteSize),
	//     but will otherwise return as many items as fit into maxByteSize.
	//   - if maxBytes is not specified, 'count' items will be returned if they are present
	//
	// AncientRange 按顺序检索多个项目，从索引 'start' 开始。
	// 它将返回：
	//   - 最多 'count' 个项目，
	//   - 如果指定了 maxBytes：至少 1 个项目（即使超过 maxByteSize），
	//     否则返回适合 maxByteSize 的尽可能多的项目。
	//   - 如果未指定 maxBytes，则返回 'count' 个项目（如果存在）。
	AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error)

	// Ancients returns the ancient item numbers in the ancient store.
	// Ancients 返回古老存储中的古老项目数量。
	Ancients() (uint64, error)

	// Tail returns the number of first stored item in the ancient store.
	// This number can also be interpreted as the total deleted items.
	//
	// Tail 返回古老存储中第一个存储项目的编号。
	// 这个数字也可以解释为总删除项目的数量。
	Tail() (uint64, error) // Tail 表示已删除的项数，反映修剪策略（pruning）的影响。

	// AncientSize returns the ancient size of the specified category.
	// AncientSize 返回指定类别的古老数据大小。
	AncientSize(kind string) (uint64, error)
}

// AncientReader is the extended ancient reader interface including 'batched' or 'atomic' reading.
// AncientReader 是扩展的古老读取器接口，包括“批处理”或“原子”读取。
type AncientReader interface {
	AncientReaderOp

	// ReadAncients runs the given read operation while ensuring that no writes take place
	// on the underlying ancient store.
	// ReadAncients 执行给定的读取操作，同时确保底层古老存储上不会发生写入。
	// ReadAncients 确保读取操作是原子的，防止在读取多个数据时被并发的写入操作（如修剪）干扰。
	ReadAncients(fn func(AncientReaderOp) error) (err error)
}

// AncientWriter contains the methods required to write to immutable ancient data.
// AncientWriter 包含写入不可变古老数据所需的方法。
type AncientWriter interface {
	// ModifyAncients runs a write operation on the ancient store.
	// If the function returns an error, any changes to the underlying store are reverted.
	// The integer return value is the total size of the written data.
	//
	// ModifyAncients 在古老存储上执行写操作。
	// 如果函数返回错误，底层存储的任何更改都将被回滚。
	// 返回的整数值是写入数据的总大小。
	ModifyAncients(func(AncientWriteOp) error) (int64, error)

	// TruncateHead discards all but the first n ancient data from the ancient store.
	// After the truncation, the latest item can be accessed it item_n-1(start from 0).
	//
	// TruncateHead 丢弃古老存储中除前 n 个数据之外的所有数据。
	// 截断后，最新的项可以通过 item_n-1 访问（从 0 开始计数）。
	TruncateHead(n uint64) (uint64, error)

	// TruncateTail discards the first n ancient data from the ancient store. The already
	// deleted items are ignored. After the truncation, the earliest item can be accessed
	// is item_n(start from 0). The deleted items may not be removed from the ancient store
	// immediately, but only when the accumulated deleted data reach the threshold then
	// will be removed all together.
	//
	// TruncateTail 丢弃古老存储中最前面的 n 个数据。已删除的项将被忽略。
	// 截断后，最早的项可以通过 item_n 访问（从 0 开始计数）。被删除的项可能不会立即从古老存储中移除，
	// 而是当累积的删除数据达到阈值时，才会一起被移除。
	TruncateTail(n uint64) (uint64, error)

	// Sync flushes all in-memory ancient store data to disk.
	// Sync 将内存中的所有古老存储数据刷新到磁盘。
	Sync() error
}

// AncientWriteOp is given to the function argument of ModifyAncients.
// AncientWriteOp 被提供给 ModifyAncients 的函数参数。
//
// 用于在古老存储（ancient store）中执行具体的写操作。
// 在以太坊中，古老存储通常用于保存不可变的历史数据，例如区块头（headers）、区块体（bodies）、交易收据（receipts）等。
// 这些数据通常通过 RLP（Recursive Length Prefix，一种以太坊使用的序列化格式）编码后存储。
type AncientWriteOp interface {
	// Append adds an RLP-encoded item.
	// Append 添加一个 RLP 编码的项。
	Append(kind string, number uint64, item interface{}) error

	// AppendRaw adds an item without RLP-encoding it.
	// AppendRaw 添加一个未经过 RLP 编码的项。
	AppendRaw(kind string, number uint64, item []byte) error
}

// AncientStater wraps the Stat method of a backing ancient store.
// AncientStater 封装了底层古老存储的 Stat 方法。
type AncientStater interface {
	// AncientDatadir returns the path of the ancient store directory.
	//
	// If the ancient store is not activated, an error is returned.
	// If an ephemeral ancient store is used, an empty path is returned.
	//
	// The path returned by AncientDatadir can be used as the root path
	// of the ancient store to construct paths for other sub ancient stores.
	//
	// AncientDatadir 返回古老存储目录的路径。
	//
	// 如果古老存储未激活，则返回错误。
	// 如果使用的是临时古老存储，则返回空路径。
	//
	// AncientDatadir 返回的路径可以用作古老存储的根路径，
	// 以构建其他子古老存储的路径。
	AncientDatadir() (string, error)
}

// Reader contains the methods required to read data from both key-value as well as
// immutable ancient data.
// Reader 包含从键值存储和不可变古老数据中读取数据所需的方法。
type Reader interface {
	KeyValueReader
	AncientReader
}

// 键值存储（如 LevelDB）用于快速读写当前状态，键是哈希（如状态根），值是编码数据。
// 古老存储（如 freezer）按顺序存储历史数据，键是类型和编号（如 "headers" 和区块高度）。

// AncientStore contains all the methods required to allow handling different
// ancient data stores backing immutable data store.
// AncientStore 包含处理支持不可变数据存储的不同古老数据存储所需的所有方法。
type AncientStore interface {
	AncientReader
	AncientWriter
	AncientStater
	io.Closer
}

// ResettableAncientStore extends the AncientStore interface by adding a Reset method.
// ResettableAncientStore 通过添加 Reset 方法扩展了 AncientStore 接口。
type ResettableAncientStore interface {
	AncientStore

	// Reset is designed to reset the entire ancient store to its default state.
	// Reset 旨在将整个古老存储重置为其默认状态。
	Reset() error
}

// 键值存储（KeyValueStore）：通常基于 LevelDB，用于存储当前区块链状态（如账户余额、合约状态）和其他动态数据。
// 古老存储（AncientStore）：基于 freezer，用于存储不可变的历史数据（如区块头、交易、收据）。
// 这种设计反映了以太坊客户端对数据管理的分层需求：快速访问最新状态（键值存储）和高效存储历史数据（古老存储）。
//
// 键值存储（LevelDB）：
//  - 用于存储动态数据，如状态树（state trie）、交易索引。
//  - 数据以键值对形式保存，键通常是哈希（如状态根），值是 RLP 编码的内容。
// 古老存储（Freezer）：
//  - 用于存储不可变数据，按类型（如 "headers"、"bodies"）和区块高度组织。
//  - 数据文件是只追加的，优化了顺序写入和读取。
// 数据分离：
//  - 以太坊将动态数据和历史数据分开存储，减少主数据库的负担，提升性能。这种设计与 EIP-2464（状态修剪）和 EIP-4444（分布式历史访问）的优化目标一致。

// Database contains all the methods required by the high level database to not
// only access the key-value data store but also the ancient chain store.
//
// Database 包含高级数据库所需的所有方法，不仅用于访问键值数据存储，还包括古老链存储。
type Database interface {
	KeyValueStore
	AncientStore
}
