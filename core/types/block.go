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
type Body struct {
	Transactions []*Transaction
	Uncles       []*Header
	Withdrawals  []*Withdrawal `rlp:"optional"`
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
type Block struct {
	header       *Header
	uncles       []*Header
	transactions Transactions
	withdrawals  Withdrawals

	// witness is not an encoded part of the block body.
	// It is held in Block in order for easy relaying to the places
	// that process it.
	witness *ExecutionWitness

	// caches
	hash atomic.Pointer[common.Hash]
	size atomic.Uint64

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

// "external" block encoding. used for eth protocol, etc.
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
		b.header.TxHash = DeriveSha(Transactions(txs), hasher)
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyReceiptsHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts), hasher)
		b.header.Bloom = CreateBloom(receipts)
	}

	if len(uncles) == 0 {
		b.header.UncleHash = EmptyUncleHash
	} else {
		b.header.UncleHash = CalcUncleHash(uncles)
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
		hash := DeriveSha(Withdrawals(withdrawals), hasher)
		b.header.WithdrawalsHash = &hash
		b.withdrawals = slices.Clone(withdrawals)
	}

	return b
}

// CopyHeader creates a deep copy of a block header.
func CopyHeader(h *Header) *Header {
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
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.uncles, b.transactions, b.withdrawals = eb.Header, eb.Uncles, eb.Txs, eb.Withdrawals
	b.size.Store(rlp.ListSize(size))
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
func (b *Block) Body() *Body {
	return &Body{b.transactions, b.uncles, b.withdrawals}
}

// Accessors for body data. These do not return a copy because the content
// of the body slices does not affect the cached hash/size in block.

func (b *Block) Uncles() []*Header          { return b.uncles }
func (b *Block) Transactions() Transactions { return b.transactions }
func (b *Block) Withdrawals() Withdrawals   { return b.withdrawals }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

// Header returns the block header (as a copy).
func (b *Block) Header() *Header {
	return CopyHeader(b.header)
}

// Header value accessors. These do copy!

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }
func (b *Block) Difficulty() *big.Int { return new(big.Int).Set(b.header.Difficulty) }
func (b *Block) Time() uint64         { return b.header.Time }

func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }
func (b *Block) MixDigest() common.Hash   { return b.header.MixDigest }
func (b *Block) Nonce() uint64            { return binary.BigEndian.Uint64(b.header.Nonce[:]) }
func (b *Block) Bloom() Bloom             { return b.header.Bloom }
func (b *Block) Coinbase() common.Address { return b.header.Coinbase }
func (b *Block) Root() common.Hash        { return b.header.Root }
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }
func (b *Block) UncleHash() common.Hash   { return b.header.UncleHash }
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }

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
func (b *Block) ExecutionWitness() *ExecutionWitness { return b.witness }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previously cached value.
func (b *Block) Size() uint64 {
	if size := b.size.Load(); size > 0 {
		return size
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(uint64(c))
	return uint64(c)
}

// SanityCheck can be used to prevent that unbounded fields are
// stuffed with junk data to add processing overhead
func (b *Block) SanityCheck() error {
	return b.header.SanityCheck()
}

type writeCounter uint64

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

func CalcUncleHash(uncles []*Header) common.Hash {
	if len(uncles) == 0 {
		return EmptyUncleHash
	}
	return rlpHash(uncles)
}

// CalcRequestsHash creates the block requestsHash value for a list of requests.
func CalcRequestsHash(requests [][]byte) common.Hash {
	h1, h2 := sha256.New(), sha256.New()
	var buf common.Hash
	for _, item := range requests {
		if len(item) > 1 { // skip items with only requestType and no data.
			h1.Reset()
			h1.Write(item)
			h2.Write(h1.Sum(buf[:0]))
		}
	}
	h2.Sum(buf[:0])
	return buf
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
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
func HeaderParentHashFromRLP(header []byte) common.Hash {
	// parentHash is the first list element.
	listContent, _, err := rlp.SplitList(header)
	if err != nil {
		return common.Hash{}
	}
	parentHash, _, err := rlp.SplitString(listContent)
	if err != nil {
		return common.Hash{}
	}
	if len(parentHash) != 32 {
		return common.Hash{}
	}
	return common.BytesToHash(parentHash)
}
