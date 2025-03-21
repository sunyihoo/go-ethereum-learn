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

// Package types contains data types related to Ethereum consensus.
package types

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-verkle"
)

// A BlockNonce is a 64-bit hash which proves (combined with the
// mix-hash) that a sufficient amount of computation has been carried
// out on a block.
// BlockNonce 是一个64位哈希值，它证明（结合 mix-hash）已经对一个区块执行了足够的计算工作。
// BlockNonce 表示以太坊区块头中的 nonce 字段。nonce是一个64位值，在工作量证明（Proof of Work, PoW）共识机制中用于挖矿。
// mix-hash 是挖矿过程中生成的中间结果，与 nonce 一起用于验证PoW的有效性。两者结合后，通过哈希函数（在以太坊中是Ethash算法）生成最终的区块哈希。
// “sufficient amount of computation”: 指的是PoW的难度要求。矿工需要找到一个 nonce，使得区块哈希低于当前网络的难度目标。
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
// EncodeNonce 将给定的整数转换为区块nonce。
// 使用大端字节序是因为以太坊协议中约定 nonce 值的存储和传输遵循大端序，这与网络协议和跨平台兼容性有关。
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i) // 将输入的 uint64 值 i 按照大端字节序（Big Endian）写入 n 的字节数组中。
	return n
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return hexutil.Bytes(n[:]).MarshalText()
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("BlockNonce", input, n[:])
}

// ExecutionWitness represents the witness + proof used in a verkle context,
// to provide the ability to execute a block statelessly.
// ExecutionWitness 表示在 Verkle 上下文中所使用的见证和证明，
// 以提供无状态执行区块的能力。
// 它的目的是支持“无状态执行”（stateless execution），即客户端无需维护完整的状态树即可验证和执行区块。
type ExecutionWitness struct {
	StateDiff   verkle.StateDiff    `json:"stateDiff"`   // 存储执行区块时涉及的状态变化（例如账户余额、存储槽等的更新）。它描述了从旧状态到新状态的差异。
	VerkleProof *verkle.VerkleProof `json:"verkleProof"` // 提供 Verkle 树的加密证明，用于验证状态差异的正确性。它可能是路径证明（path proof）或 Merkle 风格的证明，具体取决于 Verkle 树的实现。
}

//go:generate go run github.com/fjl/gencodec -type Header -field-override headerMarshaling -out gen_header_json.go
//go:generate go run ../../rlp/rlpgen -type Header -out gen_header_rlp.go

// Header represents a block header in the Ethereum blockchain.
// Header 表示以太坊区块链中的区块头。
type Header struct {
	ParentHash  common.Hash    `json:"parentHash"       gencodec:"required"` // 前一区块的哈希值，用于链接区块链。父哈希
	UncleHash   common.Hash    `json:"sha3Uncles"       gencodec:"required"` // 叔块（uncle blocks）的哈希值，通过 SHA3 计算。
	Coinbase    common.Address `json:"miner"`                                // 矿工的地址，接收区块奖励。
	Root        common.Hash    `json:"stateRoot"        gencodec:"required"` // 状态树的根哈希（state root），反映区块执行后的账户状态。
	TxHash      common.Hash    `json:"transactionsRoot" gencodec:"required"` // 交易树的根哈希（transactions root）。
	ReceiptHash common.Hash    `json:"receiptsRoot"     gencodec:"required"` // 收据树的根哈希（receipts root），存储交易执行结果。
	Bloom       Bloom          `json:"logsBloom"        gencodec:"required"` // Bloom过滤器，用于快速查询日志。
	Difficulty  *big.Int       `json:"difficulty"       gencodec:"required"` // 挖矿难度，PoW机制的核心参数。 以太坊难度值通常远小于 2⁸⁰，限制其大小防止异常。
	Number      *big.Int       `json:"number"           gencodec:"required"` // 区块高度（从0开始）。
	GasLimit    uint64         `json:"gasLimit"         gencodec:"required"` // 区块的燃气上限。
	GasUsed     uint64         `json:"gasUsed"          gencodec:"required"` // 区块中交易实际使用的燃气量。
	Time        uint64         `json:"timestamp"        gencodec:"required"` // 区块时间戳（Unix时间，秒为单位）。
	Extra       []byte         `json:"extraData"        gencodec:"required"` // 额外数据字段，矿工可自定义（有长度限制-通常 32 字节以内，最大100KB）。
	MixDigest   common.Hash    `json:"mixHash"`                              // 挖矿过程中的中间哈希值，与nonce一起验证PoW。
	Nonce       BlockNonce     `json:"nonce"`                                // 挖矿nonce值，用于PoW计算。

	// BaseFee was added by EIP-1559 and is ignored in legacy headers.
	// BaseFee 由 EIP-1559 添加，在旧版区块头中被忽略。
	BaseFee *big.Int `json:"baseFeePerGas" rlp:"optional"` // 基础费用（base fee），由EIP-1559（伦敦升级）引入，用于动态调整燃气价格。

	// WithdrawalsHash was added by EIP-4895 and is ignored in legacy headers.
	// WithdrawalsHash 由 EIP-4895 添加，在旧版区块头中被忽略。
	WithdrawalsHash *common.Hash `json:"withdrawalsRoot" rlp:"optional"` // 提款树的根哈希，由EIP-4895（上海升级）引入，支持PoS下的提款。

	// BlobGasUsed was added by EIP-4844 and is ignored in legacy headers.
	// BlobGasUsed 由 EIP-4844 添加，在旧版区块头中被忽略。
	BlobGasUsed *uint64 `json:"blobGasUsed" rlp:"optional"` // Blob燃气使用量，由EIP-4844（Cancun升级）引入，支持数据分片（blobs）。

	// ExcessBlobGas was added by EIP-4844 and is ignored in legacy headers.
	// ExcessBlobGas 由 EIP-4844 添加，在旧版区块头中被忽略。
	ExcessBlobGas *uint64 `json:"excessBlobGas" rlp:"optional"` // 超额Blob燃气，由EIP-4844引入，用于Blob燃气价格调节。

	// ParentBeaconRoot was added by EIP-4788 and is ignored in legacy headers.
	// ParentBeaconRoot 由 EIP-4788 添加，在旧版区块头中被忽略。
	ParentBeaconRoot *common.Hash `json:"parentBeaconBlockRoot" rlp:"optional"` // 父信标链区块的根哈希，由EIP-4788引入，支持PoS与信标链交互。

	// RequestsHash was added by EIP-7685 and is ignored in legacy headers.
	// RequestsHash 由 EIP-7685 添加，在旧版区块头中被忽略。
	RequestsHash *common.Hash `json:"requestsHash" rlp:"optional"` // 请求树的根哈希，由EIP-7685引入，用于通用请求机制。
}

// field type overrides for gencodec
type headerMarshaling struct {
	Difficulty    *hexutil.Big
	Number        *hexutil.Big
	GasLimit      hexutil.Uint64
	GasUsed       hexutil.Uint64
	Time          hexutil.Uint64
	Extra         hexutil.Bytes
	BaseFee       *hexutil.Big
	Hash          common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
	BlobGasUsed   *hexutil.Uint64
	ExcessBlobGas *hexutil.Uint64
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
// Hash 返回区块头的区块哈希值，它仅仅是其 RLP 编码的 keccak256 哈希。
func (h *Header) Hash() common.Hash {
	return rlpHash(h)
}

// 计算 Header 结构体实例在内存中的字节大小
var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
// Size 返回所有内部内容所使用的大约内存量。它用于近似估计并限制各种缓存的内存消耗。
// 是内存占用估计，包括动态数据。
func (h *Header) Size() common.StorageSize {
	var baseFeeBits int
	if h.BaseFee != nil {
		baseFeeBits = h.BaseFee.BitLen()
	}
	return headerSize + common.StorageSize(len(h.Extra)+(h.Difficulty.BitLen()+h.Number.BitLen()+baseFeeBits)/8)
}

// SanityCheck checks a few basic things -- these checks are way beyond what
// any 'sane' production values should hold, and can mainly be used to prevent
// that the unbounded fields are stuffed with junk data to add processing
// overhead
// SanityCheck 检查一些基本事项 -- 这些检查远远超出了任何“合理”的生产环境中应该出现的值，
// 主要用于防止无界字段被填充垃圾数据以增加处理开销。
// 防止恶意构造的区块头（如填充超大数据）增加处理开销或引发崩溃。
// 这些限制远超生产环境中的“合理”值，属于防御性编程。
func (h *Header) SanityCheck() error {
	if h.Number != nil && !h.Number.IsUint64() { // 区块号不应该超过 64 位，因为实际区块链高度远低于此值。
		return fmt.Errorf("too large block number: bitlen %d", h.Number.BitLen())
	}
	if h.Difficulty != nil {
		if diffLen := h.Difficulty.BitLen(); diffLen > 80 {
			return fmt.Errorf("too large block difficulty: bitlen %d", diffLen)
		}
	}
	if eLen := len(h.Extra); eLen > 100*1024 {
		return fmt.Errorf("too large block extradata: size %d", eLen)
	}
	if h.BaseFee != nil {
		if bfLen := h.BaseFee.BitLen(); bfLen > 256 {
			return fmt.Errorf("too large base fee: bitlen %d", bfLen)
		}
	}
	return nil
}

// EmptyBody returns true if there is no additional 'body' to complete the header
// that is: no transactions, no uncles and no withdrawals.
// EmptyBody 如果没有额外的“区块体”来补充区块头，则返回 true，
// 也就是说：没有交易、没有叔块和没有提款。
func (h *Header) EmptyBody() bool {
	var (
		emptyWithdrawals = h.WithdrawalsHash == nil || *h.WithdrawalsHash == EmptyWithdrawalsHash
	)
	return h.TxHash == EmptyTxsHash && h.UncleHash == EmptyUncleHash && emptyWithdrawals
}

// EmptyReceipts returns true if there are no receipts for this header/block.
func (h *Header) EmptyReceipts() bool {
	return h.ReceiptHash == EmptyReceiptsHash
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
// Body 是一个简单的（可变的、非线程安全的）数据容器，用于存储和移动
// 区块的数据内容（交易和叔块）。
// 在区块生成、验证或同步过程中，存储和传递非头部的区块数据。
type Body struct {
	Transactions []*Transaction // Header.TxHash 是 Body.Transactions 的 Merkle 根哈希。
	Uncles       []*Header
	Withdrawals  []*Withdrawal `rlp:"optional"` // rlp:"optional" 在 RLP 编码中是可选字段，表示旧区块（不支持提款）可以省略此字段。
}

// Block represents an Ethereum block.
//
// Note the Block type tries to be 'immutable', and contains certain caches that rely
// on that. The rules around block immutability are as follows:
//
//   - We copy all data when the block is constructed. This makes references held inside
//     the block independent of whatever value was passed in.
//
//   - We copy all header data on access. This is because any change to the header would mess
//     up the cached hash and size values in the block. Calling code is expected to take
//     advantage of this to avoid over-allocating!
//
//   - When new body data is attached to the block, a shallow copy of the block is returned.
//     This ensures block modifications are race-free.
//
//   - We do not copy body data on access because it does not affect the caches, and also
//     because it would be too expensive.
//
// Block 表示以太坊中的一个区块。
//
// 请注意，Block 类型尽量保持“不可变”，并包含一些依赖此特性的缓存。关于区块不可变性的规则如下：
//
//   - 在构造区块时，我们会复制所有数据。这使得区块内部持有的引用独立于传入的任何值。
//
//   - 在访问时，我们会复制所有头部数据。这是因为头部数据的任何更改都会干扰区块中缓存的哈希值和大小值。调用代码应利用这一点以避免过度分配！
//
//   - 当新的区块体数据附加到区块时，会返回区块的一个浅拷贝。这确保区块修改是无竞争的。
//
//   - 在访问时，我们不复制区块体数据，因为它不会影响缓存，而且这样做成本太高。
//
// 获取 uncles, transactions, withdrawals 时，直接返回原始引用。
// 因为这些数据不影响缓存，且复制成本高。
type Block struct {
	header       *Header      // 区块头
	uncles       []*Header    // 叔块列表
	transactions Transactions // 交易列表 存储区块中的交易数据。
	withdrawals  Withdrawals  // 提款列表 存储区块中的提款数据（EIP-4895 引入）。

	// witness is not an encoded part of the block body.
	// It is held in Block in order for easy relaying to the places
	// that process it.
	// 不是区块体的编码部分，存储在 Block 中以便于传递到处理它的地方。
	witness *ExecutionWitness // 执行见证 用于无状态执行（Verkle 树相关），不参与区块的 RLP 编码。

	// caches
	hash atomic.Pointer[common.Hash] // 区块哈希的缓存 提供线程安全的哈希值访问，避免重复计算
	size atomic.Uint64               // 区块大小的缓存 提供线程安全的大小访问，记录近似内存占用。

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time   // 区块接收时间
	ReceivedFrom interface{} // 区块来源
}

// "external" block encoding. used for eth protocol, etc.
// “外部”区块编码。用于 ETH 协议等。 用于表示区块的外部序列化形式。
// 包含区块的所有核心数据，适合在节点间传输或存储
// 主要用于以太坊的 P2P 协议（ETH 协议），在节点间交换区块数据。
// 提供一种简洁的结构体，将区块的所有数据（头和体）打包为一个整体。
// 专为序列化（如 RLP 编码）设计，用于网络传输或存储。
type extblock struct {
	Header      *Header
	Txs         []*Transaction
	Uncles      []*Header
	Withdrawals []*Withdrawal `rlp:"optional"`
}

// NewBlock creates a new block. The input data is copied, changes to header and to the
// field values will not affect the block.
//
// The body elements and the receipts are used to recompute and overwrite the
// relevant portions of the header.
// NewBlock 创建一个新的区块。输入数据会被复制，对头部和字段值的更改不会影响该区块。
//
// 区块体元素和收据用于重新计算并覆盖头部中的相关部分。
func NewBlock(header *Header, body *Body, receipts []*Receipt, hasher TrieHasher) *Block {
	if body == nil {
		body = &Body{}
	}
	var (
		b           = NewBlockWithHeader(header)
		txs         = body.Transactions
		uncles      = body.Uncles
		withdrawals = body.Withdrawals
	)

	if len(txs) == 0 {
		b.header.TxHash = EmptyTxsHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs), hasher) // 计算交易的 Merkle 根哈希
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyReceiptsHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts), hasher) // 计算收据的 Merkle 根哈希
		b.header.Bloom = CreateBloom(receipts)                       // 生成 Bloom 过滤器
	}

	if len(uncles) == 0 {
		b.header.UncleHash = EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles) // 计算叔块哈希
		b.uncles = make([]*Header, len(uncles))
		for i := range uncles {
			b.uncles[i] = CopyHeader(uncles[i])
		}
	}

	if withdrawals == nil {
		b.header.WithdrawalsHash = nil
	} else if len(withdrawals) == 0 {
		b.header.WithdrawalsHash = &EmptyWithdrawalsHash
		b.withdrawals = Withdrawals{}
	} else {
		hash := DeriveSha(Withdrawals(withdrawals), hasher) // 计算提款的 Merkle 根哈希
		b.header.WithdrawalsHash = &hash
		b.withdrawals = slices.Clone(withdrawals)
	}

	return b
}

// CopyHeader creates a deep copy of a block header.
// CopyHeader 创建区块头的深拷贝。
func CopyHeader(h *Header) *Header {
	// 浅拷贝直接复制字段值，对于基本类型（如 uint64）是独立的，但对于指针类型（如 *big.Int）和切片（如 []byte），只是复制引用。
	cpy := *h
	if cpy.Difficulty = new(big.Int); h.Difficulty != nil {
		cpy.Difficulty.Set(h.Difficulty)
	}
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if h.BaseFee != nil {
		cpy.BaseFee = new(big.Int).Set(h.BaseFee)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	if h.WithdrawalsHash != nil {
		cpy.WithdrawalsHash = new(common.Hash)
		*cpy.WithdrawalsHash = *h.WithdrawalsHash
	}
	if h.ExcessBlobGas != nil {
		cpy.ExcessBlobGas = new(uint64)
		*cpy.ExcessBlobGas = *h.ExcessBlobGas
	}
	if h.BlobGasUsed != nil {
		cpy.BlobGasUsed = new(uint64)
		*cpy.BlobGasUsed = *h.BlobGasUsed
	}
	if h.ParentBeaconRoot != nil {
		cpy.ParentBeaconRoot = new(common.Hash)
		*cpy.ParentBeaconRoot = *h.ParentBeaconRoot
	}
	if h.RequestsHash != nil {
		cpy.RequestsHash = new(common.Hash)
		*cpy.RequestsHash = *h.RequestsHash
	}
	return &cpy
}

// DecodeRLP decodes a block from RLP.
// DecodeRLP 从 RLP 中解码一个区块。
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock        // 用于临时存储解码后的数据。
	_, size, _ := s.Kind() // 获取 RLP 数据的类型和大小信息。size 数据的大小（字节数）。size 表示整个 RLP 列表的编码长度，用于后续缓存。
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.withdrawals = eb.Header, eb.Uncles, eb.Txs, eb.Withdrawals
	b.size.Store(rlp.ListSize(size)) // 记录了区块的编码大小，用于缓存。 rlp.ListSize(size) 将原始大小转换为 RLP 列表的总字节数。
	return nil
}

// EncodeRLP serializes a block as RLP.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &extblock{
		Header:      b.header,
		Txs:         b.transactions,
		Uncles:      b.uncles,
		Withdrawals: b.withdrawals,
	})
}

// Body returns the non-header content of the block.
// Note the returned data is not an independent copy.
// Body 返回区块的非头部内容。
// 请注意，返回的数据不是独立的副本。
// non-header content 表示返回的数据是区块体，不包括 header 和其他元数据（如 witness, hash, size）。
// 用于访问区块的交易、叔块和提款数据，例如在验证或处理过程中。
func (b *Block) Body() *Body {
	return &Body{b.transactions, b.uncles, b.withdrawals}
}

// Accessors for body data. These do not return a copy because the content
// of the body slices does not affect the cached hash/size in block.
// 区块体数据的访问方法。这些方法不返回副本，
// 因为body切片的内容不会影响区块中缓存的哈希值或大小。block.hash block.size

func (b *Block) Uncles() []*Header          { return b.uncles }
func (b *Block) Transactions() Transactions { return b.transactions }
func (b *Block) Withdrawals() Withdrawals   { return b.withdrawals }

// Transaction 根据交易哈希查找并返回对应的交易。
func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

// Header returns the block header (as a copy).
// Header 返回区块头（作为副本）。
func (b *Block) Header() *Header {
	return CopyHeader(b.header)
}

// Header value accessors. These do copy!
// 区块头值的访问方法。这些方法会进行复制！

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }     // 返回区块号的副本。
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }                     // 返回燃气上限。
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }                      // 返回已用燃气量。
func (b *Block) Difficulty() *big.Int { return new(big.Int).Set(b.header.Difficulty) } // 返回挖矿难度的副本。
func (b *Block) Time() uint64         { return b.header.Time }                         // 返回时间戳。

func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }                   // 返回区块号的 uint64 表示。
func (b *Block) MixDigest() common.Hash   { return b.header.MixDigest }                         // 返回混合摘要。
func (b *Block) Nonce() uint64            { return binary.BigEndian.Uint64(b.header.Nonce[:]) } // 返回 PoW nonce 的 uint64 表示。
func (b *Block) Bloom() Bloom             { return b.header.Bloom }                             // 返回 Bloom 过滤器。
func (b *Block) Coinbase() common.Address { return b.header.Coinbase }                          // 返回矿工地址。
func (b *Block) Root() common.Hash        { return b.header.Root }                              // 返回状态树根哈希。
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }                        // 返回父区块哈希。
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }                            // 返回交易树根哈希。
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }                       // 返回收据树根哈希。
func (b *Block) UncleHash() common.Hash   { return b.header.UncleHash }                         // 返回叔块树根哈希。
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }           // 返回额外数据的副本。

func (b *Block) BaseFee() *big.Int {
	if b.header.BaseFee == nil {
		return nil
	}
	return new(big.Int).Set(b.header.BaseFee)
}

func (b *Block) BeaconRoot() *common.Hash   { return b.header.ParentBeaconRoot }
func (b *Block) RequestsHash() *common.Hash { return b.header.RequestsHash }

func (b *Block) ExcessBlobGas() *uint64 {
	var excessBlobGas *uint64
	if b.header.ExcessBlobGas != nil {
		excessBlobGas = new(uint64)
		*excessBlobGas = *b.header.ExcessBlobGas
	}
	return excessBlobGas
}

func (b *Block) BlobGasUsed() *uint64 {
	var blobGasUsed *uint64
	if b.header.BlobGasUsed != nil {
		blobGasUsed = new(uint64)
		*blobGasUsed = *b.header.BlobGasUsed
	}
	return blobGasUsed
}

// ExecutionWitness returns the verkle execution witneess + proof for a block
// ExecutionWitness 返回区块的 Verkle 执行见证和证明。
func (b *Block) ExecutionWitness() *ExecutionWitness { return b.witness }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previously cached value.
// Size 返回区块的真实 RLP 编码存储大小，可以通过编码并返回结果，或者返回之前缓存的值。
func (b *Block) Size() uint64 {
	if size := b.size.Load(); size > 0 {
		return size
	}
	c := writeCounter(0) // 创建一个 writeCounter 对象，用于统计编码后的字节数。
	rlp.Encode(&c, b)
	b.size.Store(uint64(c))
	return uint64(c)
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
// SanityCheck 可用于防止无界字段被填充垃圾数据以增加处理开销。
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

type writeCounter uint64

// 实现了 io.Writer，通过累加写入字节数统计大小。
func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// CalcUncleHash 计算叔父块头的哈希
func CalcUncleHash(uncles []*Header) common.Hash {
	if len(uncles) == 0 {
		return EmptyUncleHash
	}
	return rlpHash(uncles)
}

// CalcRequestsHash creates the block requestsHash value for a list of requests.
func CalcRequestsHash(requests [][]byte) common.Hash {
	h1, h2 := sha256.New(), sha256.New() // 双层哈希: 使用两个 SHA-256 实例，先哈希单个请求，再汇总。
	var buf common.Hash
	for _, item := range requests {
		if len(item) > 1 { // skip items with only requestType and no data. 跳过只有请求类型而无数据的项
			h1.Reset() // 重置 h1，确保每次计算从干净状态开始。
			h1.Write(item)
			h2.Write(h1.Sum(buf[:0])) // h1.Sum(buf[:0])计算 item 的 SHA-256 哈希，写入 buf（不追加，直接覆盖）；h2.Write 将该哈希写入 h2，累积到最终结果。
		}
	}
	h2.Sum(buf[:0])
	return buf
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
// NewBlockWithHeader 使用给定的头部数据创建一个区块。
// 头部数据会被复制，对头部及其字段值的更改不会影响该区块。
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
//
// WithSeal 返回一个新区块，使用 b 的数据，但头部替换为已密封的头部。
//
// “已密封”（sealed）通常意味着头部已完成计算（如 PoW 的 nonce 已填入，或 PoS 的签名已添加），不可再修改。
// 在区块密封过程（如挖矿完成或共识达成）后，更新头部并生成新区块。
//
// “密封”的含义:
//   - 在 PoW 中，可能指 nonce 和 mixDigest 已计算完成。
//   - 在 PoS 中，可能指签名或其他共识字段已填充。
func (b *Block) WithSeal(header *Header) *Block {
	return &Block{
		header:       CopyHeader(header),
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
		witness:      b.witness,
	}
}

// WithBody returns a new block with the original header and a deep copy of the
// provided body.
// WithBody 返回一个新区块，包含原始头部和提供的区块体的深拷贝。
// 用于更新区块体数据，例如在同步或验证过程中替换交易、叔块或提款。
func (b *Block) WithBody(body Body) *Block {
	block := &Block{
		header:       b.header,
		transactions: slices.Clone(body.Transactions),
		uncles:       make([]*Header, len(body.Uncles)),
		withdrawals:  slices.Clone(body.Withdrawals),
		witness:      b.witness,
	}
	for i := range body.Uncles {
		block.uncles[i] = CopyHeader(body.Uncles[i])
	}
	return block
}

// WithWitness 返回一个新区块，使用 b 的原始数据，但将见证替换为提供的见证。
// 在无状态执行场景中，更新 Block 的执行见证数据，例如同步或验证时添加证明。
func (b *Block) WithWitness(witness *ExecutionWitness) *Block {
	return &Block{
		header:       b.header,
		transactions: b.transactions,
		uncles:       b.uncles,
		withdrawals:  b.withdrawals,
		witness:      witness,
	}
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
// Hash 返回 b 的头部 Keccak256 哈希值。
// 哈希值在第一次调用时计算，此后缓存。
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return *hash
	}
	h := b.header.Hash()
	b.hash.Store(&h)
	return h
}

type Blocks []*Block

// HeaderParentHashFromRLP returns the parentHash of an RLP-encoded
// header. If 'header' is invalid, the zero hash is returned.
//
// HeaderParentHashFromRLP 返回 RLP 编码的区块头的 parentHash。
// 如果 'header' 无效，则返回零哈希。
//
// header 表示 RLP 编码的区块头数据
func HeaderParentHashFromRLP(header []byte) common.Hash {
	// parentHash is the first list element.
	// 将 RLP 编码的头部数据解析为列表，并提取列表内容。
	// listContent 列表内容的字节数据（不含列表前缀）
	listContent, _, err := rlp.SplitList(header)
	if err != nil {
		return common.Hash{}
	}
	//从列表内容中提取第一个字符串元素，即 ParentHash。
	parentHash, _, err := rlp.SplitString(listContent)
	if err != nil {
		return common.Hash{}
	}
	if len(parentHash) != 32 {
		return common.Hash{}
	}
	return common.BytesToHash(parentHash)
}
