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

package types

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec -type Receipt -field-override receiptMarshaling -out gen_receipt_json.go

var (
	// 表示交易执行失败时的状态在 RLP（Recursive Length Prefix，以太坊序列化格式）编码下的表示。
	receiptStatusFailedRLP = []byte{}
	// 表示交易执行成功时的状态在 RLP 编码下的表示。
	receiptStatusSuccessfulRLP = []byte{0x01}
)

// 当类型化收据（typed receipt）数据长度不足时返回的错误。
var errShortTypedReceipt = errors.New("typed receipt too short")

const (
	// ReceiptStatusFailed is the status code of a transaction if execution failed.
	// ReceiptStatusFailed 是交易执行失败时的状态码。在以太坊中，状态码 0 表示交易未成功执行。
	ReceiptStatusFailed = uint64(0)

	// ReceiptStatusSuccessful is the status code of a transaction if execution succeeded.
	// ReceiptStatusSuccessful 是交易执行成功时的状态码。状态码 1 表示交易已成功执行。
	ReceiptStatusSuccessful = uint64(1)
)

// 当节点处理完一笔交易后，会生成一个 Receipt 对象，记录执行结果和相关元数据。
// 客户端可以通过 RPC 接口（如 eth_getTransactionReceipt）获取此数据，用于分析交易状态、Gas 消耗或合约事件。

// Receipt represents the results of a transaction.
// Receipt 表示交易的结果。
//
// 表示以太坊中交易执行的结果（即交易收据）。
// 分为三类：共识字段（由以太坊黄皮书定义）、实现字段（由 geth 添加）和包含信息字段（描述交易在区块中的位置）。
type Receipt struct {
	// Consensus fields: These fields are defined by the Yellow Paper
	// 共识字段：由以太坊黄皮书（Yellow Paper）定义，是以太坊协议的核心部分
	Type              uint8  `json:"type,omitempty"`                        // 交易的类型（如 0x0 表示遗留交易，0x1 表示 EIP-2930 交易，0x2 表示 EIP-1559 交易）。自 EIP-2718 引入类型化交易后，交易类型成为收据的一部分。
	PostState         []byte `json:"root"`                                  // 交易执行后的状态根（state root），表示世界状态的哈希。在早期的以太坊版本中，收据包含状态根；在新版本中（如引入 Status 后），此字段可能为空或不使用。
	Status            uint64 `json:"status"`                                // 交易执行的状态码，0 表示失败，1 表示成功（与前面提到的 ReceiptStatusFailed 和 ReceiptStatusSuccessful 对应）。自 EIP-658 引入后，状态码取代了 PostState 来表示交易结果。
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed" gencodec:"required"` // 区块中截至此交易的累计 Gas 消耗量。用于追踪区块中所有交易的 Gas 使用情况。
	Bloom             Bloom  `json:"logsBloom"         gencodec:"required"` // 布隆过滤器（Bloom Filter），用于快速检测日志中是否包含特定的事件或地址。以太坊使用布隆过滤器优化日志查询。
	Logs              []*Log `json:"logs"              gencodec:"required"` // 交易产生的日志列表（事件记录），每个日志是一个 *Log 类型。记录智能合约发出的事件，供外部查询。

	// Implementation fields: These fields are added by geth when processing a transaction.
	// 实现字段: 由 geth（Go Ethereum 客户端）在处理交易时添加，不属于黄皮书的核心定义。
	TxHash            common.Hash    `json:"transactionHash" gencodec:"required"` // 交易的哈希值，用于唯一标识该交易。便于追踪收据对应的交易。
	ContractAddress   common.Address `json:"contractAddress"`                     // 如果交易创建了合约，则记录新合约的地址；否则为空。仅在合约创建交易中有效。
	GasUsed           uint64         `json:"gasUsed" gencodec:"required"`         // 此交易单独消耗的 Gas 量。与 CumulativeGasUsed 不同，这是单个交易的 Gas 消耗。
	EffectiveGasPrice *big.Int       `json:"effectiveGasPrice"`                   // 交易的实际 Gas 价格（单位：wei），支持 EIP-1559 后的动态定价。在 EIP-1559 之前，此字段可能为空；之后为必须字段。
	BlobGasUsed       uint64         `json:"blobGasUsed,omitempty"`               // 交易使用的 Blob Gas（EIP-4844 引入，用于分片数据）。仅在支持 Blob 交易的网络中有效。
	BlobGasPrice      *big.Int       `json:"blobGasPrice,omitempty"`              // Blob Gas 的价格（单位：wei）。与 BlobGasUsed 配套使用。

	// Inclusion information: These fields provide information about the inclusion of the
	// transaction corresponding to this receipt.
	// 包含信息字段： 这些字段提供与此收据对应的交易的包含信息。
	BlockHash        common.Hash `json:"blockHash,omitempty"`   // 包含此交易的区块的哈希值。用于定位交易所属的区块。
	BlockNumber      *big.Int    `json:"blockNumber,omitempty"` // 包含此交易的区块高度。与 BlockHash 一起标识区块。
	TransactionIndex uint        `json:"transactionIndex"`      // 交易在区块中的索引位置（从 0 开始）。表示交易在区块交易列表中的顺序。
}

type receiptMarshaling struct {
	Type              hexutil.Uint64
	PostState         hexutil.Bytes
	Status            hexutil.Uint64
	CumulativeGasUsed hexutil.Uint64
	GasUsed           hexutil.Uint64
	EffectiveGasPrice *hexutil.Big
	BlobGasUsed       hexutil.Uint64
	BlobGasPrice      *hexutil.Big
	BlockNumber       *hexutil.Big
	TransactionIndex  hexutil.Uint
}

// receiptRLP is the consensus encoding of a receipt.
// receiptRLP 是收据的共识编码。
//
// 用于共识编码（consensus encoding），即以太坊协议中节点间共享的收据格式。
//
// 定义了交易收据在以太坊网络中传输和验证时使用的 RLP（Recursive Length Prefix）编码格式。这是节点之间达成共识的标准化表示。
//
// receiptRLP 是以太坊黄皮书定义的收据格式，用于在网络中序列化（RLP 编码）并传输交易收据。
type receiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Bloom             Bloom
	Logs              []*Log
}

// 以太坊的交易收据需要同时满足共识需求（网络传输和验证）和存储需求（本地高效保存）。
// receiptRLP 是协议层面的标准格式，确保所有节点对收据数据达成一致。
// storedReceiptRLP 是 geth 的实现优化，通过省略可动态生成的字段（如 Bloom）来减少存储空间。

// storedReceiptRLP is the storage encoding of a receipt.
// storedReceiptRLP 是收据的存储编码。
//
// storedReceiptRLP 是 geth 在本地存储交易收据时的格式。
//
// 当需要完整收据（如 RPC 调用 eth_getTransactionReceipt）时，geth 会从 storedReceiptRLP 重建 receiptRLP，并根据 Logs 计算 Bloom。
type storedReceiptRLP struct {
	PostStateOrStatus []byte
	CumulativeGasUsed uint64
	Logs              []*Log // Bloom（布隆过滤器）可以从 Logs 动态生成，而无需额外存储。
}

// NewReceipt creates a barebone transaction receipt, copying the init fields.
// Deprecated: create receipts using a struct literal instead.
func NewReceipt(root []byte, failed bool, cumulativeGasUsed uint64) *Receipt {
	r := &Receipt{
		Type:              LegacyTxType,
		PostState:         common.CopyBytes(root),
		CumulativeGasUsed: cumulativeGasUsed,
	}
	if failed {
		r.Status = ReceiptStatusFailed
	} else {
		r.Status = ReceiptStatusSuccessful
	}
	return r
}

// EncodeRLP implements rlp.Encoder, and flattens the consensus fields of a receipt
// into an RLP stream. If no post state is present, byzantium fork is assumed.
// EncodeRLP 实现了 rlp.Encoder 接口，将收据的共识字段扁平化为 RLP 流。
// 如果没有状态后数据（post state），则假定为拜占庭分叉（Byzantium fork）。
func (r *Receipt) EncodeRLP(w io.Writer) error {
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType { // 遗留交易的收据编码格式较简单，不需要额外的类型前缀。
		return rlp.Encode(w, data)
	}
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := r.encodeTyped(data, buf); err != nil {
		return err
	}
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed receipt to w.
// encodeTyped 将类型化收据的规范编码写入 w。
func (r *Receipt) encodeTyped(data *receiptRLP, w *bytes.Buffer) error {
	// 类型化交易（如 EIP-2930 或 EIP-1559）的收据在 RLP 编码时，需要在开头添加一个字节表示交易类型。
	w.WriteByte(r.Type)
	return rlp.Encode(w, data)
}

// MarshalBinary returns the consensus encoding of the receipt.
// MarshalBinary 返回收据的共识编码。
func (r *Receipt) MarshalBinary() ([]byte, error) {
	if r.Type == LegacyTxType {
		return rlp.EncodeToBytes(r)
	}
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	var buf bytes.Buffer
	err := r.encodeTyped(data, &buf)
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder, and loads the consensus fields of a receipt
// from an RLP stream.
// DecodeRLP 实现了 rlp.Decoder，并从 RLP 流中加载收据的共识字段。
func (r *Receipt) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind() // 检查流的类型（kind）和大小（size）。
	switch {
	case err != nil:
		return err
	case kind == rlp.List: // 表示一个 RLP 列表（传统收据）
		// It's a legacy receipt.
		var dec receiptRLP
		if err := s.Decode(&dec); err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(dec)
	case kind == rlp.Byte: // 返回错误 errShortTypedReceipt，因为类型化收据至少需要类型字节和数据
		return errShortTypedReceipt
	default:
		// It's an EIP-2718 typed tx receipt.
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		return r.decodeTyped(b)
	}
}

// UnmarshalBinary decodes the consensus encoding of receipts.
// It supports legacy RLP receipts and EIP-2718 typed receipts.
// UnmarshalBinary 解码收据的共识编码。它支持传统 RLP 收据和 EIP-2718 类型化收据。
func (r *Receipt) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f { // b[0] > 0x7f：RLP 编码中，0x80 以上表示列表或长字节串，传统收据以列表形式编码。
		// It's a legacy receipt decode the RLP
		var data receiptRLP
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		r.Type = LegacyTxType
		return r.setFromRLP(data)
	}
	// 如果首字节 <= 0x7f， EIP-2718 类型化收据（类型字节通常是 0x00-0x7f）。
	// It's an EIP2718 typed transaction envelope.
	return r.decodeTyped(b)
}

// decodeTyped decodes a typed receipt from the canonical format.
// decodeTyped 从规范格式解码类型化收据。 解码类型化收据（EIP-2718 格式）。
func (r *Receipt) decodeTyped(b []byte) error {
	if len(b) <= 1 { // 至少需要类型字节和数据
		return errShortTypedReceipt
	}
	switch b[0] {
	case DynamicFeeTxType, AccessListTxType, BlobTxType, SetCodeTxType:
		var data receiptRLP
		err := rlp.DecodeBytes(b[1:], &data)
		if err != nil {
			return err
		}
		r.Type = b[0]
		return r.setFromRLP(data)
	default:
		return ErrTxTypeNotSupported
	}
}

// 将解码后的 receiptRLP 数据填充到 Receipt 结构体。
func (r *Receipt) setFromRLP(data receiptRLP) error {
	r.CumulativeGasUsed, r.Bloom, r.Logs = data.CumulativeGasUsed, data.Bloom, data.Logs
	return r.setStatus(data.PostStateOrStatus)
}

// 根据 postStateOrStatus 设置收据的状态。
func (r *Receipt) setStatus(postStateOrStatus []byte) error {
	switch {
	case bytes.Equal(postStateOrStatus, receiptStatusSuccessfulRLP):
		r.Status = ReceiptStatusSuccessful
	case bytes.Equal(postStateOrStatus, receiptStatusFailedRLP):
		r.Status = ReceiptStatusFailed
	case len(postStateOrStatus) == len(common.Hash{}): // 如果长度等于哈希长度（32 字节），设置为 r.PostState（旧分叉如拜占庭之前）
		r.PostState = postStateOrStatus
	default:
		return fmt.Errorf("invalid receipt status %x", postStateOrStatus)
	}
	return nil
}

func (r *Receipt) statusEncoding() []byte {
	if len(r.PostState) == 0 { // 如果 PostState 为空（长度为 0），说明收据没有提供状态根数据。这种情况通常发生在拜占庭分叉（Byzantium Fork）之后，因为从那时起，以太坊开始使用 Status 字段（一个简单的成功/失败标志）代替完整的状态根。
		if r.Status == ReceiptStatusFailed {
			return receiptStatusFailedRLP
		}
		return receiptStatusSuccessfulRLP
	}
	return r.PostState
}

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
// Size 返回所有内部内容使用的大约内存大小。它用于近似计算并限制各种缓存的内存消耗。
func (r *Receipt) Size() common.StorageSize {
	size := common.StorageSize(unsafe.Sizeof(*r)) + common.StorageSize(len(r.PostState))
	size += common.StorageSize(len(r.Logs)) * common.StorageSize(unsafe.Sizeof(Log{}))
	for _, log := range r.Logs {
		size += common.StorageSize(len(log.Topics)*common.HashLength + len(log.Data))
	}
	return size
}

// ReceiptForStorage is a wrapper around a Receipt with RLP serialization
// that omits the Bloom field and deserialization that re-computes it.
//
// ReceiptForStorage 是 Receipt 的包装器，其 RLP 序列化省略了 Bloom 字段，
// 反序列化时重新计算它。
type ReceiptForStorage Receipt

// EncodeRLP implements rlp.Encoder, and flattens all content fields of a receipt
// into an RLP stream.
//
// EncodeRLP 实现了 rlp.Encoder，将收据的所有内容字段展平到 RLP 流中。
func (r *ReceiptForStorage) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	outerList := w.List()                        // 开始外层 RLP 列表。
	w.WriteBytes((*Receipt)(r).statusEncoding()) // 写入状态字段（PostState 或 Status）
	w.WriteUint64(r.CumulativeGasUsed)           // 写入累计燃气使用量。
	logList := w.List()                          // 开始日志列表。
	for _, log := range r.Logs {
		//fmt.Println(log)
		if err := log.EncodeRLP(w); err != nil {
			return err
		}
	}
	w.ListEnd(logList)   // 结束日志列表。
	w.ListEnd(outerList) // 结束外层列表。
	return w.Flush()     // 刷新缓冲区，完成写入。
}

// DecodeRLP implements rlp.Decoder, and loads both consensus and implementation
// fields of a receipt from an RLP stream.
//
// DecodeRLP 实现了 rlp.Decoder，从 RLP 流中加载收据的共识字段和实现字段。
//
// 从 RLP 流反序列化 ReceiptForStorage，并重新计算 Bloom。
func (r *ReceiptForStorage) DecodeRLP(s *rlp.Stream) error {
	var stored storedReceiptRLP
	if err := s.Decode(&stored); err != nil {
		return err
	}
	if err := (*Receipt)(r).setStatus(stored.PostStateOrStatus); err != nil {
		return err
	}
	r.CumulativeGasUsed = stored.CumulativeGasUsed // 设置燃气使用量。
	r.Logs = stored.Logs                           // 设置日志列表。
	r.Bloom = CreateBloom(Receipts{(*Receipt)(r)}) // 调用 CreateBloom，根据日志重新计算 Bloom。

	return nil
}

// Receipts implements DerivableList for receipts.
// Receipts 为收据实现了 DerivableList 接口。
type Receipts []*Receipt

// Len returns the number of receipts in this list.
// Len 返回此列表中的收据数量。
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex encodes the i'th receipt to w.
// EncodeIndex 将第 i 个收据编码到 w 中。
func (rs Receipts) EncodeIndex(i int, w *bytes.Buffer) {
	r := rs[i]
	data := &receiptRLP{r.statusEncoding(), r.CumulativeGasUsed, r.Bloom, r.Logs}
	if r.Type == LegacyTxType {
		rlp.Encode(w, data)
		return
	}
	w.WriteByte(r.Type)
	switch r.Type {
	case AccessListTxType, DynamicFeeTxType, BlobTxType, SetCodeTxType:
		rlp.Encode(w, data)
	default:
		// For unsupported types, write nothing. Since this is for
		// DeriveSha, the error will be caught matching the derived hash
		// to the block.
		// 对于不支持的类型，不写入任何内容。由于这是为了 DeriveSha，
		// 错误将在匹配派生的哈希与区块时被捕获。
	}
}

// DeriveFields fills the receipts with their computed fields based on consensus
// data and contextual infos like containing block and transactions.
//
// DeriveFields 根据共识数据和上下文信息（如包含的区块和交易）填充收据的计算字段。
func (rs Receipts) DeriveFields(config *params.ChainConfig, hash common.Hash, number uint64, time uint64, baseFee *big.Int, blobGasPrice *big.Int, txs []*Transaction) error {
	// 创建签名者
	// 检查交易和收据数量是否匹配。
	signer := MakeSigner(config, new(big.Int).SetUint64(number), time)

	logIndex := uint(0)
	if len(txs) != len(rs) {
		return errors.New("transaction and receipt count mismatch")
	}
	for i := 0; i < len(rs); i++ {
		// The transaction type and hash can be retrieved from the transaction itself
		// 交易类型和哈希可以从交易本身检索。
		rs[i].Type = txs[i].Type()
		rs[i].TxHash = txs[i].Hash()
		rs[i].EffectiveGasPrice = txs[i].inner.effectiveGasPrice(new(big.Int), baseFee)

		// EIP-4844 blob transaction fields
		// EIP-4844 blob 交易字段
		if txs[i].Type() == BlobTxType {
			rs[i].BlobGasUsed = txs[i].BlobGas()
			rs[i].BlobGasPrice = blobGasPrice
		}

		// block location fields
		// 区块字段
		rs[i].BlockHash = hash
		rs[i].BlockNumber = new(big.Int).SetUint64(number)
		rs[i].TransactionIndex = uint(i)

		// The contract address can be derived from the transaction itself
		// 合约地址可以从交易本身派生
		if txs[i].To() == nil { // 如果 To 为空，从签名者和 Nonce 派生。
			// Deriving the signer is expensive, only do if it's actually needed
			// 派生签名者代价高昂，仅在实际需要时执行
			from, _ := Sender(signer, txs[i])
			rs[i].ContractAddress = crypto.CreateAddress(from, txs[i].Nonce())
		} else {
			rs[i].ContractAddress = common.Address{}
		}

		// The used gas can be calculated based on previous r
		// 已使用的燃气可以根据前一个收据计算
		if i == 0 {
			rs[i].GasUsed = rs[i].CumulativeGasUsed
		} else {
			rs[i].GasUsed = rs[i].CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}

		// The derived log fields can simply be set from the block and transaction
		// 派生的日志字段可以简单地从区块和交易中设置
		for j := 0; j < len(rs[i].Logs); j++ {
			rs[i].Logs[j].BlockNumber = number
			rs[i].Logs[j].BlockHash = hash
			rs[i].Logs[j].TxHash = rs[i].TxHash
			rs[i].Logs[j].TxIndex = uint(i)
			rs[i].Logs[j].Index = logIndex
			logIndex++
		}
	}
	return nil
}
