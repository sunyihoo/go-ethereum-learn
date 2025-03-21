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

package types

import (
	"bytes"
	"fmt"
	"math"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// hasherPool holds LegacyKeccak256 hashers for rlpHash.
// hasherPool 保存用于 rlpHash 的 LegacyKeccak256 哈希器。
var hasherPool = sync.Pool{
	// Legacy区分于新的 Keccak256 实现，保持与以太坊早期版本兼容。
	New: func() interface{} { return sha3.NewLegacyKeccak256() },
}

// encodeBufferPool holds temporary encoder buffers for DeriveSha and TX encoding.
// encodeBufferPool 保存用于 DeriveSha 和交易编码的临时编码缓冲区。
// 缓存 bytes.Buffer 对象，用于 DeriveSha 和交易（TX）编码的临时缓冲。
var encodeBufferPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

// getPooledBuffer retrieves a buffer from the pool and creates a byte slice of the
// requested size from it.
//
// The caller should return the *bytes.Buffer object back into encodeBufferPool after use!
// The returned byte slice must not be used after returning the buffer.
// getPooledBuffer 从池中检索一个缓冲区，并从中创建指定大小的字节切片。
//
// 调用者应在使用后将 *bytes.Buffer 对象归还到 encodeBufferPool！
// 返回的字节切片在缓冲区归还后不得使用。
func getPooledBuffer(size uint64) ([]byte, *bytes.Buffer, error) {
	if size > math.MaxInt {
		return nil, nil, fmt.Errorf("can't get buffer of size %d", size)
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(int(size))
	b := buf.Bytes()[:int(size)]
	return b, buf, nil
}

// rlpHash encodes x and hashes the encoded bytes.
// rlpHash 对 x 进行编码并对编码后的字节进行哈希。
func rlpHash(x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}

// prefixedRlpHash writes the prefix into the hasher before rlp-encoding x.
// It's used for typed transactions.
// prefixedRlpHash 在 RLP 编码 x 之前将前缀写入哈希器。
// 它用于类型化交易。
func prefixedRlpHash(prefix byte, x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	sha.Write([]byte{prefix})
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}

// TrieHasher is the tool used to calculate the hash of derivable list.
// This is internal, do not use.
//
// TrieHasher 是用于计算可派生列表哈希值的工具。
// 这是内部接口，请勿使用。
type TrieHasher interface {
	Reset()                      // 重置哈希器的内部状态。
	Update([]byte, []byte) error // 更新哈希器的状态，添加新的数据。
	Hash() common.Hash           // 计算并返回最终的哈希值。
}

// DerivableList is the input to DeriveSha.
// It is implemented by the 'Transactions' and 'Receipts' types.
// This is internal, do not use these methods.
//
// DerivableList 是 DeriveSha 的输入。
// 它由 'Transactions' 和 'Receipts' 类型实现。
// 这是内部接口，请勿使用这些方法。
type DerivableList interface {
	Len() int
	EncodeIndex(int, *bytes.Buffer)
}

func encodeForDerive(list DerivableList, i int, buf *bytes.Buffer) []byte {
	buf.Reset()
	list.EncodeIndex(i, buf)
	// It's really unfortunate that we need to perform this copy.
	// StackTrie holds onto the values until Hash is called, so the values
	// written to it must not alias.
	// 不得不进行这次复制实在令人遗憾。
	// StackTrie 会持有这些值直到调用 Hash，因此写入其中的值不得存在别名。
	return common.CopyBytes(buf.Bytes())
}

// DeriveSha creates the tree hashes of transactions, receipts, and withdrawals in a block header.
// DeriveSha 创建区块头中交易、收据和提款的树哈希。
// 为 DerivableList（如交易或收据）计算 Trie 根哈希，存入区块头（如 TxHash）
// 按特定顺序（1-127, 0, 128+）编码并更新每个元素
func DeriveSha(list DerivableList, hasher TrieHasher) common.Hash {
	hasher.Reset()

	valueBuf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(valueBuf)

	// StackTrie requires values to be inserted in increasing hash order, which is not the
	// order that `list` provides hashes in. This insertion sequence ensures that the
	// order is correct.
	//
	// The error returned by hasher is omitted because hasher will produce an incorrect
	// hash in case any error occurs.
	//
	// StackTrie 要求按哈希值递增的顺序插入值，而 `list` 提供的哈希顺序并非如此。
	// 这种插入顺序确保顺序正确。
	//
	// hasher 返回的错误被省略，因为如果发生任何错误，hasher 将生成错误的哈希。
	//
	//定义一个缓冲区，用于存储索引的 RLP 编码。
	var indexBuf []byte
	// 第一阶段 处理索引 1 到 127
	for i := 1; i < list.Len() && i <= 0x7f; i++ {
		// 将索引 i 编码为 RLP 格式，写入 indexBuf
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		// 将索引 i 处的元素编码为 RLP，返回字节副本
		value := encodeForDerive(list, i, valueBuf)
		// 将索引（键）和值更新到哈希器
		hasher.Update(indexBuf, value)
	}
	// 第二阶段 处理索引 0（特殊处理）
	if list.Len() > 0 {
		indexBuf = rlp.AppendUint64(indexBuf[:0], 0)
		value := encodeForDerive(list, 0, valueBuf)
		hasher.Update(indexBuf, value)
	}
	// 第三阶段 处理索引 128 及以上。
	for i := 0x80; i < list.Len(); i++ {
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		value := encodeForDerive(list, i, valueBuf)
		hasher.Update(indexBuf, value)
	}
	// 计算并返回最终的 Trie 根哈希。
	return hasher.Hash()
}
