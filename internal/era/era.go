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
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package era

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/era/e2store"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

var (
	// TypeVersion represents the version of the Era1 file format.
	// TypeVersion 代表 Era1 文件格式的版本。
	TypeVersion uint16 = 0x3265
	// TypeCompressedHeader represents the compressed block header type in Era1.
	// TypeCompressedHeader 代表 Era1 中压缩的区块头类型。
	TypeCompressedHeader uint16 = 0x03
	// TypeCompressedBody represents the compressed block body type in Era1.
	// TypeCompressedBody 代表 Era1 中压缩的区块主体类型。
	TypeCompressedBody uint16 = 0x04
	// TypeCompressedReceipts represents the compressed transaction receipts type in Era1.
	// TypeCompressedReceipts 代表 Era1 中压缩的交易回执类型。
	TypeCompressedReceipts uint16 = 0x05
	// TypeTotalDifficulty represents the total difficulty type in Era1.
	// TypeTotalDifficulty 代表 Era1 中的总难度类型。
	TypeTotalDifficulty uint16 = 0x06
	// TypeAccumulator represents the accumulator type in Era1.
	// TypeAccumulator 代表 Era1 中的累加器类型。
	TypeAccumulator uint16 = 0x07
	// TypeBlockIndex represents the block index type in Era1.
	// TypeBlockIndex 代表 Era1 中的区块索引类型。
	TypeBlockIndex uint16 = 0x3266

	// MaxEra1Size defines the maximum allowed size for an Era1 file.
	// MaxEra1Size 定义了 Era1 文件允许的最大大小。
	MaxEra1Size = 8192
)

// Filename returns a recognizable Era1-formatted file name for the specified
// epoch and network.
// Filename 返回指定纪元和网络的 Era1 格式的可识别文件名。
func Filename(network string, epoch int, root common.Hash) string {
	return fmt.Sprintf("%s-%05d-%s.era1", network, epoch, root.Hex()[2:10])
}

// ReadDir reads all the era1 files in a directory for a given network.
// Format: <network>-<epoch>-<hexroot>.era1
// ReadDir 读取给定网络目录下所有的 era1 文件。
// 格式: <网络>-<纪元>-<十六进制根>.era1
func ReadDir(dir, network string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory %s: %w", dir, err)
	}
	var (
		next = uint64(0)
		eras []string
	)
	for _, entry := range entries {
		if path.Ext(entry.Name()) != ".era1" {
			continue
		}
		parts := strings.Split(entry.Name(), "-")
		if len(parts) != 3 || parts[0] != network {
			// invalid era1 filename, skip
			// 无效的 era1 文件名，跳过
			continue
		}
		if epoch, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
			return nil, fmt.Errorf("malformed era1 filename: %s", entry.Name())
		} else if epoch != next {
			return nil, fmt.Errorf("missing epoch %d", next)
		}
		next += 1
		eras = append(eras, entry.Name())
	}
	return eras, nil
}

// ReadAtSeekCloser is an interface that combines io.ReaderAt, io.Seeker, and io.Closer.
// ReadAtSeekCloser 是一个接口，它组合了 io.ReaderAt、io.Seeker 和 io.Closer。
type ReadAtSeekCloser interface {
	io.ReaderAt
	io.Seeker
	io.Closer
}

// Era reads and Era1 file.
// Era 读取一个 Era1 文件。
type Era struct {
	f   ReadAtSeekCloser // backing era1 file
	s   *e2store.Reader  // e2store reader over f
	m   metadata         // start, count, length info
	mu  *sync.Mutex      // lock for buf
	buf [8]byte          // buffer reading entry offsets
}

// From returns an Era backed by f.
// From 返回一个由 f 支持的 Era。
func From(f ReadAtSeekCloser) (*Era, error) {
	m, err := readMetadata(f)
	if err != nil {
		return nil, err
	}
	return &Era{
		f:  f,
		s:  e2store.NewReader(f),
		m:  m,
		mu: new(sync.Mutex),
	}, nil
}

// Open returns an Era backed by the given filename.
// Open 返回一个由给定文件名支持的 Era。
func Open(filename string) (*Era, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	return From(f)
}

// Close closes the underlying Era1 file.
// Close 关闭底层的 Era1 文件。
func (e *Era) Close() error {
	return e.f.Close()
}

// GetBlockByNumber retrieves a specific block from the Era1 file by its number.
// GetBlockByNumber 根据区块号从 Era1 文件中检索特定的区块。
func (e *Era) GetBlockByNumber(num uint64) (*types.Block, error) {
	if e.m.start > num || e.m.start+e.m.count <= num {
		return nil, errors.New("out-of-bounds")
	}
	off, err := e.readOffset(num)
	if err != nil {
		return nil, err
	}
	// Reads the compressed header data from the e2store at the calculated offset.
	// It uses the TypeCompressedHeader identifier to specify the type of data being read.
	r, n, err := newSnappyReader(e.s, TypeCompressedHeader, off)
	if err != nil {
		return nil, err
	}
	var header types.Header
	// Decodes the compressed header data (read from the snappy reader) into a types.Header struct using RLP.
	if err := rlp.Decode(r, &header); err != nil {
		return nil, err
	}
	off += n
	// Reads the compressed body data similarly to the header.
	r, _, err = newSnappyReader(e.s, TypeCompressedBody, off)
	if err != nil {
		return nil, err
	}
	var body types.Body
	// Decodes the compressed body data into a types.Body struct using RLP.
	if err := rlp.Decode(r, &body); err != nil {
		return nil, err
	}
	// Creates a new types.Block using the decoded header and body.
	return types.NewBlockWithHeader(&header).WithBody(body), nil
}

// Accumulator reads the accumulator entry in the Era1 file.
// Accumulator 读取 Era1 文件中的累加器条目。
func (e *Era) Accumulator() (common.Hash, error) {
	entry, err := e.s.Find(TypeAccumulator)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(entry.Value), nil
}

// InitialTD returns initial total difficulty before the difficulty of the
// first block of the Era1 is applied.
// InitialTD 返回应用 Era1 第一个区块的难度之前的初始总难度。
func (e *Era) InitialTD() (*big.Int, error) {
	var (
		r      io.Reader
		header types.Header
		rawTd  []byte
		n      int64
		off    int64
		err    error
	)

	// Read first header.
	// 读取第一个区块头。
	if off, err = e.readOffset(e.m.start); err != nil {
		return nil, err
	}
	if r, n, err = newSnappyReader(e.s, TypeCompressedHeader, off); err != nil {
		return nil, err
	}
	if err := rlp.Decode(r, &header); err != nil {
		return nil, err
	}
	off += n

	// Skip over next two records.
	// 跳过接下来的两个记录。
	for i := 0; i < 2; i++ {
		length, err := e.s.LengthAt(off)
		if err != nil {
			return nil, err
		}
		off += length
	}

	// Read total difficulty after first block.
	// 读取第一个区块后的总难度。
	if r, _, err = e.s.ReaderAt(TypeTotalDifficulty, off); err != nil {
		return nil, err
	}
	rawTd, err = io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	td := new(big.Int).SetBytes(reverseOrder(rawTd))
	// Subtract the first block's difficulty from the total difficulty after the first block
	// to get the initial total difficulty.
	// 从第一个区块后的总难度中减去第一个区块的难度，得到初始总难度。
	return td.Sub(td, header.Difficulty), nil
}

// Start returns the listed start block number of the Era1.
// Start 返回 Era1 列出的起始区块号。
func (e *Era) Start() uint64 {
	return e.m.start
}

// Count returns the total number of blocks in the Era1.
// Count 返回 Era1 中的区块总数。
func (e *Era) Count() uint64 {
	return e.m.count
}

// readOffset reads a specific block's offset from the block index. The value n
// is the absolute block number desired.
// readOffset 从区块索引中读取特定区块的偏移量。值 n 是所需的绝对区块号。
func (e *Era) readOffset(n uint64) (int64, error) {
	var (
		// Calculates the offset of the block index record. It subtracts the size of the start block number,
		// the count of blocks, the header (likely 16 bytes), and the size of all index entries (count * 8 bytes)
		// from the total length of the Era1 file.
		blockIndexRecordOffset = e.m.length - 24 - int64(e.m.count)*8 // skips start, count, and header
		// Calculates the offset of the first index entry after the header and start block number.
		firstIndex = blockIndexRecordOffset + 16 // first index after header / start-num
		// Calculates the offset of the desired block's index entry within the block index record.
		indexOffset = int64(n-e.m.start) * 8 // desired index * size of indexes
		// Calculates the absolute offset of the block's offset within the Era1 file.
		offOffset = firstIndex + indexOffset // offset of block offset
	)
	// Acquires a lock to protect the shared buffer e.buf.
	e.mu.Lock()
	// Releases the lock when the function returns.
	defer e.mu.Unlock()
	// Clears the buffer before reading.
	clear(e.buf[:])
	// Reads 8 bytes (the size of a uint64 offset) from the Era1 file at the calculated offset.
	if _, err := e.f.ReadAt(e.buf[:], offOffset); err != nil {
		return 0, err
	}
	// Since the block offset is relative from the start of the block index record
	// we need to add the record offset to it's offset to get the block's absolute
	// offset.
	return blockIndexRecordOffset + int64(binary.LittleEndian.Uint64(e.buf[:])), nil
}

// newSnappyReader returns a snappy.Reader for the e2store entry value at off.
// newSnappyReader 返回一个用于给定偏移量处 e2store 条目值的 snappy.Reader。
func newSnappyReader(e *e2store.Reader, expectedType uint16, off int64) (io.Reader, int64, error) {
	// Reads the raw data for the expected type at the given offset from the e2store.
	r, n, err := e.ReaderAt(expectedType, off)
	if err != nil {
		return nil, 0, err
	}
	// Creates a new snappy.Reader that will decompress the data read from the e2store on the fly.
	return snappy.NewReader(r), int64(n), err
}

// metadata wraps the metadata in the block index.
// metadata 封装了区块索引中的元数据。
type metadata struct {
	start  uint64
	count  uint64
	length int64
}

// readMetadata reads the metadata stored in an Era1 file's block index.
// readMetadata 读取存储在 Era1 文件区块索引中的元数据。
func readMetadata(f ReadAtSeekCloser) (m metadata, err error) {
	// Determine length of reader.
	// 确定读取器的长度。
	if m.length, err = f.Seek(0, io.SeekEnd); err != nil {
		return
	}
	b := make([]byte, 16)
	// Read count. It's the last 8 bytes of the file.
	// 读取区块数量。它是文件的最后 8 个字节。
	if _, err = f.ReadAt(b[:8], m.length-8); err != nil {
		return
	}
	// Interprets the last 8 bytes as a little-endian unsigned 64-bit integer, which represents the block count.
	m.count = binary.LittleEndian.Uint64(b)
	// Read start. It's at the offset -sizeof(m.count) -
	// count*sizeof(indexEntry) - sizeof(m.start)
	// 读取起始区块号。它的偏移量是文件长度减去 count 的大小、所有索引条目的大小以及 start 的大小。
	if _, err = f.ReadAt(b[8:], m.length-16-int64(m.count*8)); err != nil {
		return
	}
	// Interprets the 8 bytes before the last 8 bytes as the starting block number.
	m.start = binary.LittleEndian.Uint64(b[8:])
	return
}
