// Copyright 2022 The go-ethereum Authors
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

package engine

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

//这些结构是引擎 API（Engine API）的一部分，用于在以太坊合并后协调共识层（如 Beacon Chain）和执行层（如 Geth）之间的通信。

// BaseFeePerGas（EIP-1559）是伦敦升级引入的基础费用机制，动态调整交易成本。
// BlobGasUsed 和 ExcessBlobGas（EIP-4844）支持数据分片（Proto-Danksharding），降低 Rollup 的数据存储成本。
// ExecutionWitness 是无状态执行的支持字段，提供验证所需的状态证明。

// PayloadVersion denotes the version of PayloadAttributes used to request the
// building of the payload to commence.
// PayloadVersion 表示用于请求开始构建负载的 PayloadAttributes 的版本。
type PayloadVersion byte

var (
	PayloadV1 PayloadVersion = 0x1 // 第一代负载版本。
	PayloadV2 PayloadVersion = 0x2 // 第二代负载版本。
	PayloadV3 PayloadVersion = 0x3 // 第三代负载版本。
)

//go:generate go run github.com/fjl/gencodec -type PayloadAttributes -field-override payloadAttributesMarshaling -out gen_blockparams.go

// PayloadAttributes describes the environment context in which a block should
// be built.
// PayloadAttributes 描述了构建区块时所需的环境上下文。
type PayloadAttributes struct {
	Timestamp             uint64              `json:"timestamp"             gencodec:"required"` // 区块时间戳。
	Random                common.Hash         `json:"prevRandao"            gencodec:"required"` // 前一个随机值（PrevRandao）。
	SuggestedFeeRecipient common.Address      `json:"suggestedFeeRecipient" gencodec:"required"` // 建议的费用接收者地址。
	Withdrawals           []*types.Withdrawal `json:"withdrawals"`                               // 提款列表。
	BeaconRoot            *common.Hash        `json:"parentBeaconBlockRoot"`                     // 父信标链区块根哈希。
}

// JSON type overrides for PayloadAttributes.
// PayloadAttributes 的 JSON 类型覆盖。
type payloadAttributesMarshaling struct {
	Timestamp hexutil.Uint64 // 时间戳以十六进制格式表示。
}

//go:generate go run github.com/fjl/gencodec -type ExecutableData -field-override executableDataMarshaling -out gen_ed.go

// ExecutableData is the data necessary to execute an EL payload.
// ExecutableData 是执行执行层 (EL) 负载所需的数据。
type ExecutableData struct {
	ParentHash       common.Hash             `json:"parentHash"    gencodec:"required"` // 父区块哈希。
	FeeRecipient     common.Address          `json:"feeRecipient"  gencodec:"required"` // 费用接收者地址。
	StateRoot        common.Hash             `json:"stateRoot"     gencodec:"required"` // 状态根哈希。
	ReceiptsRoot     common.Hash             `json:"receiptsRoot"  gencodec:"required"` // 收据根哈希。
	LogsBloom        []byte                  `json:"logsBloom"     gencodec:"required"` // 日志布隆过滤器。
	Random           common.Hash             `json:"prevRandao"    gencodec:"required"` // 前一个随机值（PrevRandao）。
	Number           uint64                  `json:"blockNumber"   gencodec:"required"` // 区块高度。
	GasLimit         uint64                  `json:"gasLimit"      gencodec:"required"` // Gas 限制。
	GasUsed          uint64                  `json:"gasUsed"       gencodec:"required"` // 已使用的 Gas。
	Timestamp        uint64                  `json:"timestamp"     gencodec:"required"` // 时间戳。
	ExtraData        []byte                  `json:"extraData"     gencodec:"required"` // 额外数据。
	BaseFeePerGas    *big.Int                `json:"baseFeePerGas" gencodec:"required"` // 每单位 Gas 的基础费用。
	BlockHash        common.Hash             `json:"blockHash"     gencodec:"required"` // 区块哈希。
	Transactions     [][]byte                `json:"transactions"  gencodec:"required"` // 交易列表。
	Withdrawals      []*types.Withdrawal     `json:"withdrawals"`                       // 提款列表。
	BlobGasUsed      *uint64                 `json:"blobGasUsed"`                       // 已使用的 Blob Gas。
	ExcessBlobGas    *uint64                 `json:"excessBlobGas"`                     // 超额 Blob Gas。
	ExecutionWitness *types.ExecutionWitness `json:"executionWitness,omitempty"`        // 执行见证数据（可选）。
}

// JSON type overrides for executableData.
// ExecutableData 的 JSON 类型覆盖。
type executableDataMarshaling struct {
	Number        hexutil.Uint64  // 区块高度以十六进制格式表示。
	GasLimit      hexutil.Uint64  // Gas 限制以十六进制格式表示。
	GasUsed       hexutil.Uint64  // 已使用的 Gas 以十六进制格式表示。
	Timestamp     hexutil.Uint64  // 时间戳以十六进制格式表示。
	BaseFeePerGas *hexutil.Big    // 基础费用以十六进制大整数表示。
	ExtraData     hexutil.Bytes   // 额外数据以十六进制字节表示。
	LogsBloom     hexutil.Bytes   // 日志布隆过滤器以十六进制字节表示。
	Transactions  []hexutil.Bytes // 交易列表以十六进制字节表示。
	BlobGasUsed   *hexutil.Uint64 // 已使用的 Blob Gas 以十六进制表示。
	ExcessBlobGas *hexutil.Uint64 // 超额 Blob Gas 以十六进制表示。
}

// StatelessPayloadStatusV1 is the result of a stateless payload execution.
// StatelessPayloadStatusV1 是无状态负载执行的结果。
type StatelessPayloadStatusV1 struct {
	Status          string      `json:"status"`          // 执行状态。
	StateRoot       common.Hash `json:"stateRoot"`       // 状态根哈希。
	ReceiptsRoot    common.Hash `json:"receiptsRoot"`    // 收据根哈希。
	ValidationError *string     `json:"validationError"` // 验证错误（可选）。
}

//go:generate go run github.com/fjl/gencodec -type ExecutionPayloadEnvelope -field-override executionPayloadEnvelopeMarshaling -out gen_epe.go

type ExecutionPayloadEnvelope struct {
	ExecutionPayload *ExecutableData `json:"executionPayload"  gencodec:"required"` // 执行负载数据。
	BlockValue       *big.Int        `json:"blockValue"  gencodec:"required"`       // 区块价值。
	BlobsBundle      *BlobsBundleV1  `json:"blobsBundle"`                           // Blob 数据包。
	Requests         [][]byte        `json:"executionRequests"`                     // 执行请求。
	Override         bool            `json:"shouldOverrideBuilder"`                 // 是否覆盖构建者。
	Witness          *hexutil.Bytes  `json:"witness,omitempty"`                     // 见证数据（可选）。
}

type BlobsBundleV1 struct {
	Commitments []hexutil.Bytes `json:"commitments"` // Blob 承诺列表。
	Proofs      []hexutil.Bytes `json:"proofs"`      // Blob 证明列表。
	Blobs       []hexutil.Bytes `json:"blobs"`       // Blob 数据列表。
}

type BlobAndProofV1 struct {
	Blob  hexutil.Bytes `json:"blob"`  // Blob 数据。
	Proof hexutil.Bytes `json:"proof"` // Blob 证明。
}

// JSON type overrides for ExecutionPayloadEnvelope.
// ExecutionPayloadEnvelope 的 JSON 类型覆盖。
type executionPayloadEnvelopeMarshaling struct {
	BlockValue *hexutil.Big    // 区块价值以十六进制大整数表示。
	Requests   []hexutil.Bytes // 执行请求以十六进制字节表示。
}

type PayloadStatusV1 struct {
	Status          string         `json:"status"`          // 负载状态。
	Witness         *hexutil.Bytes `json:"witness"`         // 见证数据（可选）。
	LatestValidHash *common.Hash   `json:"latestValidHash"` // 最新有效哈希（可选）。
	ValidationError *string        `json:"validationError"` // 验证错误（可选）。
}

type TransitionConfigurationV1 struct {
	TerminalTotalDifficulty *hexutil.Big   `json:"terminalTotalDifficulty"` // 终端总难度。
	TerminalBlockHash       common.Hash    `json:"terminalBlockHash"`       // 终端区块哈希。
	TerminalBlockNumber     hexutil.Uint64 `json:"terminalBlockNumber"`     // 终端区块高度。
}

// PayloadID is an identifier of the payload build process
// PayloadID 是负载构建过程的标识符。
type PayloadID [8]byte

// Version returns the payload version associated with the identifier.
// Version 返回与标识符关联的负载版本。
func (b PayloadID) Version() PayloadVersion {
	return PayloadVersion(b[0])
}

// Is returns whether the identifier matches any of provided payload versions.
// Is 返回标识符是否匹配提供的任意负载版本。
func (b PayloadID) Is(versions ...PayloadVersion) bool {
	return slices.Contains(versions, b.Version())
}

func (b PayloadID) String() string {
	return hexutil.Encode(b[:]) // 将 PayloadID 转换为十六进制字符串。
}

func (b PayloadID) MarshalText() ([]byte, error) {
	return hexutil.Bytes(b[:]).MarshalText() // 将 PayloadID 序列化为文本。
}

func (b *PayloadID) UnmarshalText(input []byte) error {
	err := hexutil.UnmarshalFixedText("PayloadID", input, b[:])
	if err != nil {
		return fmt.Errorf("invalid payload id %q: %w", input, err) // 如果反序列化失败，返回错误。
	}
	return nil
}

type ForkChoiceResponse struct {
	PayloadStatus PayloadStatusV1 `json:"payloadStatus"` // 负载状态。
	PayloadID     *PayloadID      `json:"payloadId"`     // 负载 ID（可选）。
}

type ForkchoiceStateV1 struct {
	HeadBlockHash      common.Hash `json:"headBlockHash"`      // 头部区块哈希。
	SafeBlockHash      common.Hash `json:"safeBlockHash"`      // 安全区块哈希。
	FinalizedBlockHash common.Hash `json:"finalizedBlockHash"` // 最终化区块哈希。
}

func encodeTransactions(txs []*types.Transaction) [][]byte {
	var enc = make([][]byte, len(txs))
	for i, tx := range txs {
		enc[i], _ = tx.MarshalBinary() // 将交易序列化为字节数组。
	}
	return enc
}

func decodeTransactions(enc [][]byte) ([]*types.Transaction, error) {
	var txs = make([]*types.Transaction, len(enc))
	for i, encTx := range enc {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, fmt.Errorf("invalid transaction %d: %v", i, err) // 如果交易反序列化失败，返回错误。
		}
		txs[i] = &tx
	}
	return txs, nil
}

// ExecutableDataToBlock constructs a block from executable data.
// It verifies that the following fields:
//
//		len(extraData) <= 32
//		uncleHash = emptyUncleHash
//		difficulty = 0
//	 	if versionedHashes != nil, versionedHashes match to blob transactions
//
// and that the blockhash of the constructed block matches the parameters. Nil
// Withdrawals value will propagate through the returned block. Empty
// Withdrawals value must be passed via non-nil, length 0 value in data.
// ExecutableDataToBlock 从可执行数据构造一个区块。
// 它验证以下字段：
//
//	extraData 长度 <= 32
//	uncleHash = emptyUncleHash
//	difficulty = 0
//	如果 versionedHashes 不为空，则 versionedHashes 与 blob 交易匹配
//
// 并验证构造的区块哈希与参数匹配。空的 Withdrawals 值必须通过非空、长度为 0 的值传递。
func ExecutableDataToBlock(data ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash, requests [][]byte) (*types.Block, error) {
	block, err := ExecutableDataToBlockNoHash(data, versionedHashes, beaconRoot, requests)
	if err != nil {
		return nil, err
	}
	if block.Hash() != data.BlockHash {
		return nil, fmt.Errorf("blockhash mismatch, want %x, got %x", data.BlockHash, block.Hash()) // 如果区块哈希不匹配，返回错误。
	}
	return block, nil
}

// ExecutableDataToBlockNoHash is analogous to ExecutableDataToBlock, but is used
// for stateless execution, so it skips checking if the executable data hashes to
// the requested hash (stateless has to *compute* the root hash, it's not given).
// ExecutableDataToBlockNoHash 与 ExecutableDataToBlock 类似，但用于无状态执行，因此跳过检查可执行数据是否哈希到请求的哈希（无状态需要计算根哈希，而不是给定）。
func ExecutableDataToBlockNoHash(data ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash, requests [][]byte) (*types.Block, error) {
	txs, err := decodeTransactions(data.Transactions)
	if err != nil {
		return nil, err
	}
	if len(data.ExtraData) > int(params.MaximumExtraDataSize) {
		return nil, fmt.Errorf("invalid extradata length: %v", len(data.ExtraData)) // 如果额外数据长度超过限制，返回错误。
	}
	if len(data.LogsBloom) != 256 {
		return nil, fmt.Errorf("invalid logsBloom length: %v", len(data.LogsBloom)) // 如果日志布隆过滤器长度不正确，返回错误。
	}
	// Check that baseFeePerGas is not negative or too big
	// 检查 baseFeePerGas 不为负数且不过大。
	if data.BaseFeePerGas != nil && (data.BaseFeePerGas.Sign() == -1 || data.BaseFeePerGas.BitLen() > 256) {
		return nil, fmt.Errorf("invalid baseFeePerGas: %v", data.BaseFeePerGas) // 如果基础费用无效，返回错误。
	}
	var blobHashes = make([]common.Hash, 0, len(txs))
	for _, tx := range txs {
		blobHashes = append(blobHashes, tx.BlobHashes()...) // 收集所有 Blob 交易的哈希。
	}
	if len(blobHashes) != len(versionedHashes) {
		return nil, fmt.Errorf("invalid number of versionedHashes: %v blobHashes: %v", versionedHashes, blobHashes) // 如果 Blob 哈希数量不匹配，返回错误。
	}
	for i := 0; i < len(blobHashes); i++ {
		if blobHashes[i] != versionedHashes[i] {
			return nil, fmt.Errorf("invalid versionedHash at %v: %v blobHashes: %v", i, versionedHashes, blobHashes) // 如果 Blob 哈希值不匹配，返回错误。
		}
	}
	// Only set withdrawalsRoot if it is non-nil. This allows CLs to use
	// ExecutableData before withdrawals are enabled by marshaling
	// Withdrawals as the json null value.
	// 仅当 Withdrawals 不为空时设置 withdrawalsRoot。这允许共识层在提款启用前使用 ExecutableData，通过将 Withdrawals 序列化为 JSON null 值。
	var withdrawalsRoot *common.Hash
	if data.Withdrawals != nil {
		h := types.DeriveSha(types.Withdrawals(data.Withdrawals), trie.NewStackTrie(nil))
		withdrawalsRoot = &h
	}

	var requestsHash *common.Hash
	if requests != nil {
		h := types.CalcRequestsHash(requests)
		requestsHash = &h
	}

	header := &types.Header{
		ParentHash:       data.ParentHash,
		UncleHash:        types.EmptyUncleHash,
		Coinbase:         data.FeeRecipient,
		Root:             data.StateRoot,
		TxHash:           types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
		ReceiptHash:      data.ReceiptsRoot,
		Bloom:            types.BytesToBloom(data.LogsBloom),
		Difficulty:       common.Big0,
		Number:           new(big.Int).SetUint64(data.Number),
		GasLimit:         data.GasLimit,
		GasUsed:          data.GasUsed,
		Time:             data.Timestamp,
		BaseFee:          data.BaseFeePerGas,
		Extra:            data.ExtraData,
		MixDigest:        data.Random,
		WithdrawalsHash:  withdrawalsRoot,
		ExcessBlobGas:    data.ExcessBlobGas,
		BlobGasUsed:      data.BlobGasUsed,
		ParentBeaconRoot: beaconRoot,
		RequestsHash:     requestsHash,
	}
	return types.NewBlockWithHeader(header).
			WithBody(types.Body{Transactions: txs, Uncles: nil, Withdrawals: data.Withdrawals}).
			WithWitness(data.ExecutionWitness),
		nil
}

// BlockToExecutableData constructs the ExecutableData structure by filling the
// fields from the given block. It assumes the given block is post-merge block.
// BlockToExecutableData 通过从给定区块填充字段来构造 ExecutableData 结构。假设给定的区块是合并后的区块。
func BlockToExecutableData(block *types.Block, fees *big.Int, sidecars []*types.BlobTxSidecar, requests [][]byte) *ExecutionPayloadEnvelope {
	data := &ExecutableData{
		BlockHash:        block.Hash(),
		ParentHash:       block.ParentHash(),
		FeeRecipient:     block.Coinbase(),
		StateRoot:        block.Root(),
		Number:           block.NumberU64(),
		GasLimit:         block.GasLimit(),
		GasUsed:          block.GasUsed(),
		BaseFeePerGas:    block.BaseFee(),
		Timestamp:        block.Time(),
		ReceiptsRoot:     block.ReceiptHash(),
		LogsBloom:        block.Bloom().Bytes(),
		Transactions:     encodeTransactions(block.Transactions()),
		Random:           block.MixDigest(),
		ExtraData:        block.Extra(),
		Withdrawals:      block.Withdrawals(),
		BlobGasUsed:      block.BlobGasUsed(),
		ExcessBlobGas:    block.ExcessBlobGas(),
		ExecutionWitness: block.ExecutionWitness(),
	}

	// Add blobs.
	// 添加 Blob 数据。
	bundle := BlobsBundleV1{
		Commitments: make([]hexutil.Bytes, 0),
		Blobs:       make([]hexutil.Bytes, 0),
		Proofs:      make([]hexutil.Bytes, 0),
	}
	for _, sidecar := range sidecars {
		for j := range sidecar.Blobs {
			bundle.Blobs = append(bundle.Blobs, hexutil.Bytes(sidecar.Blobs[j][:]))
			bundle.Commitments = append(bundle.Commitments, hexutil.Bytes(sidecar.Commitments[j][:]))
			bundle.Proofs = append(bundle.Proofs, hexutil.Bytes(sidecar.Proofs[j][:]))
		}
	}

	return &ExecutionPayloadEnvelope{
		ExecutionPayload: data,
		BlockValue:       fees,
		BlobsBundle:      &bundle,
		Requests:         requests,
		Override:         false,
	}
}

// ExecutionPayloadBody is used in the response to GetPayloadBodiesByHash and GetPayloadBodiesByRange
// ExecutionPayloadBody 用于 GetPayloadBodiesByHash 和 GetPayloadBodiesByRange 的响应。
type ExecutionPayloadBody struct {
	TransactionData []hexutil.Bytes     `json:"transactions"` // 交易数据。
	Withdrawals     []*types.Withdrawal `json:"withdrawals"`  // 提款列表。
}

// Client identifiers to support ClientVersionV1.
// 支持 ClientVersionV1 的客户端标识符。
const (
	ClientCode = "GE"          // 客户端代码。
	ClientName = "go-ethereum" // 客户端名称。
)

// ClientVersionV1 contains information which identifies a client implementation.
// ClientVersionV1 包含标识客户端实现的信息。
type ClientVersionV1 struct {
	Code    string `json:"code"`    // 客户端代码。
	Name    string `json:"name"`    // 客户端名称。
	Version string `json:"version"` // 版本号。
	Commit  string `json:"commit"`  // 提交哈希。
}

func (v *ClientVersionV1) String() string {
	return fmt.Sprintf("%s-%s-%s-%s", v.Code, v.Name, v.Version, v.Commit) // 将客户端版本信息格式化为字符串。
}
