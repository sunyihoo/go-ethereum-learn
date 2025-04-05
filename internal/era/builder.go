// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http//www.gnu.org/licenses/>.

package era

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/era/e2store"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

// Builder is used to create Era1 archives of block data.
//
// Era1 files are themselves e2store files. For more information on this format,
// see https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md.
//
// The overall structure of an Era1 file follows closely the structure of an Era file
// which contains consensus Layer data (and as a byproduct, EL data after the merge).
//
// The structure can be summarized through this definition:
//
//	era1 := Version | block-tuple* | other-entries* | Accumulator | BlockIndex
//	block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts | TotalDifficulty
//
// Each basic element is its own entry:
//
//	Version            = { type: [0x65, 0x32], data: nil }
//	CompressedHeader   = { type: [0x03, 0x00], data: snappyFramed(rlp(header)) }
//	CompressedBody     = { type: [0x04, 0x00], data: snappyFramed(rlp(body)) }
//	CompressedReceipts = { type: [0x05, 0x00], data: snappyFramed(rlp(receipts)) }
//	TotalDifficulty    = { type: [0x06, 0x00], data: uint256(header.total_difficulty) }
//	AccumulatorRoot    = { type: [0x07, 0x00], data: accumulator-root }
//	BlockIndex         = { type: [0x32, 0x66], data: block-index }
//
// Accumulator is computed by constructing an SSZ list of header-records of length at most
// 8192 and then calculating the hash_tree_root of that list.
//
//	header-record := { block-hash: Bytes32, total-difficulty: Uint256 }
//	accumulator   := hash_tree_root([]header-record, 8192)
//
// BlockIndex stores relative offsets to each compressed block entry. The
// format is:
//
//	block-index := starting-number | index | index | index ... | count
//
// starting-number is the first block number in the archive. Every index is a
// defined relative to beginning of the record. The total number of block
// entries in the file is recorded with count.
//
// Due to the accumulator size limit of 8192, the maximum number of blocks in
// an Era1 batch is also 8192.
// Builder 用于创建区块数据的 Era1 归档文件。
//
// Era1 文件本身就是 e2store 文件。有关此格式的更多信息，请参阅 https://github.com/status-im/nimbus-eth2/blob/stable/docs/e2store.md。
//
// Era1 文件的整体结构与 Era 文件（包含共识层数据，以及合并后的执行层数据）的结构非常相似。
//
// 该结构可以通过以下定义进行总结：
//
//	era1 := Version | block-tuple* | other-entries* | Accumulator | BlockIndex
//	block-tuple :=  CompressedHeader | CompressedBody | CompressedReceipts | TotalDifficulty
//
// 每个基本元素都是一个独立的条目：
//
//	Version            = { type: [0x65, 0x32], data: nil }
//	CompressedHeader   = { type: [0x03, 0x00], data: snappyFramed(rlp(header)) }
//	CompressedBody     = { type: [0x04, 0x00], data: snappyFramed(rlp(body)) }
//	CompressedReceipts = { type: [0x05, 0x00], data: snappyFramed(rlp(receipts)) }
//	TotalDifficulty    = { type: [0x06, 0x00], data: uint256(header.total_difficulty) }
//	AccumulatorRoot    = { type: [0x07, 0x00], data: accumulator-root }
//	BlockIndex         = { type: [0x32, 0x66], data: block-index }
//
// 累加器通过构建一个最多包含 8192 个 header-record 的 SSZ 列表，然后计算该列表的 hash_tree_root 来计算。
//
//	header-record := { block-hash: Bytes32, total-difficulty: Uint256 }
//	accumulator   := hash_tree_root([]header-record, 8192)
//
// BlockIndex 存储每个压缩区块条目的相对偏移量。格式如下：
//
//	block-index := starting-number | index | index | index ... | count
//
// starting-number 是归档文件中的第一个区块号。每个索引都相对于记录的开头定义。文件中区块条目的总数记录在 count 中。
//
// 由于累加器大小限制为 8192，因此 Era1 批处理中的最大区块数也为 8192。
type Builder struct {
	w *e2store.Writer
	// w 是用于写入底层 e2store 文件的写入器。
	startNum *uint64
	// startNum 是归档文件中的起始区块号。
	startTd *big.Int
	// startTd 是起始区块的总难度。
	indexes []uint64
	// indexes 存储每个区块数据条目在文件中的起始偏移量。
	hashes []common.Hash
	// hashes 存储每个区块的哈希值，用于计算累加器。
	tds []*big.Int
	// tds 存储每个区块的总难度值，用于计算累加器。
	written int
	// written 记录已写入文件的总字节数。

	buf *bytes.Buffer
	// buf 是用于 snappy 压缩的临时缓冲区。
	snappy *snappy.Writer
	// snappy 是用于 snappy 压缩的写入器。
}

// NewBuilder returns a new Builder instance.
// NewBuilder 返回一个新的 Builder 实例。
func NewBuilder(w io.Writer) *Builder {
	buf := bytes.NewBuffer(nil)
	return &Builder{
		w:      e2store.NewWriter(w),
		buf:    buf,
		snappy: snappy.NewBufferedWriter(buf),
	}
}

// Add writes a compressed block entry and compressed receipts entry to the
// underlying e2store file.
// Add 将压缩的区块条目和压缩的回执条目写入底层的 e2store 文件。
func (b *Builder) Add(block *types.Block, receipts types.Receipts, td *big.Int) error {
	eh, err := rlp.EncodeToBytes(block.Header())
	if err != nil {
		return err
	}
	eb, err := rlp.EncodeToBytes(block.Body())
	if err != nil {
		return err
	}
	er, err := rlp.EncodeToBytes(receipts)
	if err != nil {
		return err
	}
	return b.AddRLP(eh, eb, er, block.NumberU64(), block.Hash(), td, block.Difficulty())
}

// AddRLP writes a compressed block entry and compressed receipts entry to the
// underlying e2store file.
// AddRLP 将压缩的区块条目和压缩的回执条目写入底层的 e2store 文件。
func (b *Builder) AddRLP(header, body, receipts []byte, number uint64, hash common.Hash, td, difficulty *big.Int) error {
	// Write Era1 version entry before first block.
	// 在写入第一个区块之前，写入 Era1 版本条目。
	if b.startNum == nil {
		n, err := b.w.Write(TypeVersion, nil)
		if err != nil {
			return err
		}
		startNum := number
		b.startNum = &startNum
		b.startTd = new(big.Int).Sub(td, difficulty)
		b.written += n
	}
	if len(b.indexes) >= MaxEra1Size {
		return fmt.Errorf("exceeds maximum batch size of %d", MaxEra1Size)
	}

	b.indexes = append(b.indexes, uint64(b.written))
	b.hashes = append(b.hashes, hash)
	b.tds = append(b.tds, td)

	// Write block data.
	// 写入区块数据。
	if err := b.snappyWrite(TypeCompressedHeader, header); err != nil {
		return err
	}
	if err := b.snappyWrite(TypeCompressedBody, body); err != nil {
		return err
	}
	if err := b.snappyWrite(TypeCompressedReceipts, receipts); err != nil {
		return err
	}

	// Also write total difficulty, but don't snappy encode.
	// 同时写入总难度，但不进行 snappy 编码。
	btd := bigToBytes32(td)
	n, err := b.w.Write(TypeTotalDifficulty, btd[:])
	b.written += n
	if err != nil {
		return err
	}

	return nil
}

// Finalize computes the accumulator and block index values, then writes the
// corresponding e2store entries.
// Finalize 计算累加器和区块索引值，然后写入相应的 e2store 条目。
func (b *Builder) Finalize() (common.Hash, error) {
	if b.startNum == nil {
		return common.Hash{}, errors.New("finalize called on empty builder")
	}
	// Compute accumulator root and write entry.
	// 计算累加器根并写入条目。
	root, err := ComputeAccumulator(b.hashes, b.tds)
	if err != nil {
		return common.Hash{}, fmt.Errorf("error calculating accumulator root: %w", err)
	}
	n, err := b.w.Write(TypeAccumulator, root[:])
	b.written += n
	if err != nil {
		return common.Hash{}, fmt.Errorf("error writing accumulator: %w", err)
	}
	// Get beginning of index entry to calculate block relative offset.
	// 获取索引条目的起始位置，以计算区块的相对偏移量。
	base := int64(b.written)

	// Construct block index. Detailed format described in Builder
	// documentation, but it is essentially encoded as:
	// "start | index | index | ... | count"
	// 构建区块索引。详细格式在 Builder 文档中描述，但本质上编码为：
	// "start | index | index | ... | count"
	var (
		count = len(b.indexes)
		index = make([]byte, 16+count*8)
	)
	binary.LittleEndian.PutUint64(index, *b.startNum)
	// Each offset is relative from the position it is encoded in the
	// index. This means that even if the same block was to be included in
	// the index twice (this would be invalid anyways), the relative offset
	// would be different. The idea with this is that after reading a
	// relative offset, the corresponding block can be quickly read by
	// performing a seek relative to the current position.
	// 每个偏移量都相对于它在索引中编码的位置。这意味着即使同一个区块在索引中包含两次（无论如何这都是无效的），相对偏移量也会不同。
	// 这样做的目的是，在读取一个相对偏移量后，可以通过相对于当前位置进行查找来快速读取相应的区块。
	for i, offset := range b.indexes {
		relative := int64(offset) - base
		binary.LittleEndian.PutUint64(index[8+i*8:], uint64(relative))
	}
	binary.LittleEndian.PutUint64(index[8+count*8:], uint64(count))

	// Finally, write the block index entry.
	// 最后，写入区块索引条目。
	if _, err := b.w.Write(TypeBlockIndex, index); err != nil {
		return common.Hash{}, fmt.Errorf("unable to write block index: %w", err)
	}

	return root, nil
}

// snappyWrite is a small helper to take care snappy encoding and writing an e2store entry.
// snappyWrite 是一个小助手函数，用于处理 snappy 编码和写入 e2store 条目。
func (b *Builder) snappyWrite(typ uint16, in []byte) error {
	var (
		buf = b.buf
		s   = b.snappy
	)
	buf.Reset()
	s.Reset(buf)
	if _, err := b.snappy.Write(in); err != nil {
		return fmt.Errorf("error snappy encoding: %w", err)
	}
	if err := s.Flush(); err != nil {
		return fmt.Errorf("error flushing snappy encoding: %w", err)
	}
	n, err := b.w.Write(typ, b.buf.Bytes())
	b.written += n
	if err != nil {
		return fmt.Errorf("error writing e2store entry: %w", err)
	}
	return nil
}
