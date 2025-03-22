// Copyright 2018 The go-ethereum Authors
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

package apitypes

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/holiman/uint256"
)

// 定义一个正则表达式，用于验证类型化数据的引用类型
var typedDataReferenceTypeRegexp = regexp.MustCompile(`^[A-Za-z](\w*)(\[\d*\])*$`)

// ValidationInfo 表示单个验证消息。
//
// 用于记录交易或数据验证中的问题或状态。
type ValidationInfo struct {
	Typ     string `json:"type"`
	Message string `json:"message"`
}

// ValidationMessages 表示多个验证消息的集合。
type ValidationMessages struct {
	Messages []ValidationInfo
}

const (
	WARN = "WARNING"
	CRIT = "CRITICAL"
	INFO = "Info"
)

func (vs *ValidationMessages) Crit(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{CRIT, msg})
}
func (vs *ValidationMessages) Warn(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{WARN, msg})
}
func (vs *ValidationMessages) Info(msg string) {
	vs.Messages = append(vs.Messages, ValidationInfo{INFO, msg})
}

// GetWarnings returns an error with all messages of type WARN of above, or nil if no warnings were present
func (vs *ValidationMessages) GetWarnings() error {
	var messages []string
	for _, msg := range vs.Messages {
		if msg.Typ == WARN || msg.Typ == CRIT {
			messages = append(messages, msg.Message)
		}
	}
	if len(messages) > 0 {
		return fmt.Errorf("validation failed: %s", strings.Join(messages, ","))
	}
	return nil
}

// SendTxArgs represents the arguments to submit a transaction
// This struct is identical to ethapi.TransactionArgs, except for the usage of
// common.MixedcaseAddress in From and To
//
// SendTxArgs 表示提交交易的参数
// 此结构体与 ethapi.TransactionArgs 相同，除了 From 和 To 使用了 common.MixedcaseAddress
//
// 表示交易提交的完整参数，支持传统、EIP-1559 和 Blob 交易。
type SendTxArgs struct {
	From                 common.MixedcaseAddress  `json:"from"`                 // 发送者地址（支持大小写混合校验）。
	To                   *common.MixedcaseAddress `json:"to"`                   // 接收者地址（指针，可选，nil 表示创建合约）。
	Gas                  hexutil.Uint64           `json:"gas"`                  // 燃气限制。
	GasPrice             *hexutil.Big             `json:"gasPrice"`             // 传统交易的燃气价格（可选）。
	MaxFeePerGas         *hexutil.Big             `json:"maxFeePerGas"`         // EIP-1559 的每单位燃气最大费用（可选）。
	MaxPriorityFeePerGas *hexutil.Big             `json:"maxPriorityFeePerGas"` // EIP-1559 的每单位燃气优先费（可选）。
	Value                hexutil.Big              `json:"value"`                // 转账金额（以 Wei 为单位）。
	Nonce                hexutil.Uint64           `json:"nonce"`                // 发送者账户的交易计数。

	// We accept "data" and "input" for backwards-compatibility reasons.
	// "input" is the newer name and should be preferred by clients.
	// Issue detail: https://github.com/ethereum/go-ethereum/issues/15628
	// 我们接受 "data" 和 "input" 是为了向后兼容。
	// "input" 是较新的名称，客户端应优先使用。
	// 问题详情：https://github.com/ethereum/go-ethereum/issues/15628
	Data  *hexutil.Bytes `json:"data,omitempty"`  // 交易数据（旧名称，可选）。
	Input *hexutil.Bytes `json:"input,omitempty"` // 交易数据（新名称，可选，优先使用）。

	// For non-legacy transactions
	AccessList *types.AccessList `json:"accessList,omitempty"` // EIP-2930 访问列表（可选）。
	ChainID    *hexutil.Big      `json:"chainId,omitempty"`    // 链 ID（可选，用于 EIP-155）。

	// For BlobTxType
	BlobFeeCap *hexutil.Big  `json:"maxFeePerBlobGas,omitempty"`    // Blob 燃气的最大费用（可选）。
	BlobHashes []common.Hash `json:"blobVersionedHashes,omitempty"` // Blob 的版本化哈希（可选）。

	// For BlobTxType transactions with blob sidecar
	Blobs       []kzg4844.Blob       `json:"blobs,omitempty"`       // Blob 的版本化哈希（可选）。
	Commitments []kzg4844.Commitment `json:"commitments,omitempty"` // Blob 的 KZG 承诺（可选）。
	Proofs      []kzg4844.Proof      `json:"proofs,omitempty"`      // Blob 的 KZG 证明（可选）。
}

func (args SendTxArgs) String() string {
	s, err := json.Marshal(args)
	if err == nil {
		return string(s)
	}
	return err.Error()
}

// data retrieves the transaction calldata. Input field is preferred.
// data 获取交易的调用数据，优先使用 Input 字段。
func (args *SendTxArgs) data() []byte {
	if args.Input != nil {
		return *args.Input
	}
	if args.Data != nil {
		return *args.Data
	}
	return nil
}

// ToTransaction converts the arguments to a transaction.
// ToTransaction 将参数转换为交易。
func (args *SendTxArgs) ToTransaction() (*types.Transaction, error) {
	// Add the To-field, if specified
	var to *common.Address
	if args.To != nil {
		dstAddr := args.To.Address()
		to = &dstAddr
	}
	// 验证 Blob 侧车
	if err := args.validateTxSidecar(); err != nil {
		return nil, err
	}
	var data types.TxData
	switch {
	case args.BlobHashes != nil: // Blob 交易 (EIP-4844)
		al := types.AccessList{}
		if args.AccessList != nil {
			al = *args.AccessList
		}
		data = &types.BlobTx{
			To:         *to,
			ChainID:    uint256.MustFromBig((*big.Int)(args.ChainID)),
			Nonce:      uint64(args.Nonce),
			Gas:        uint64(args.Gas),
			GasFeeCap:  uint256.MustFromBig((*big.Int)(args.MaxFeePerGas)),
			GasTipCap:  uint256.MustFromBig((*big.Int)(args.MaxPriorityFeePerGas)),
			Value:      uint256.MustFromBig((*big.Int)(&args.Value)),
			Data:       args.data(),
			AccessList: al,
			BlobHashes: args.BlobHashes,
			BlobFeeCap: uint256.MustFromBig((*big.Int)(args.BlobFeeCap)),
		}
		if args.Blobs != nil {
			data.(*types.BlobTx).Sidecar = &types.BlobTxSidecar{
				Blobs:       args.Blobs,
				Commitments: args.Commitments,
				Proofs:      args.Proofs,
			}
		}

	case args.MaxFeePerGas != nil: // 动态费用交易 (EIP-1559)
		al := types.AccessList{}
		if args.AccessList != nil {
			al = *args.AccessList
		}
		data = &types.DynamicFeeTx{
			To:         to,
			ChainID:    (*big.Int)(args.ChainID),
			Nonce:      uint64(args.Nonce),
			Gas:        uint64(args.Gas),
			GasFeeCap:  (*big.Int)(args.MaxFeePerGas),
			GasTipCap:  (*big.Int)(args.MaxPriorityFeePerGas),
			Value:      (*big.Int)(&args.Value),
			Data:       args.data(),
			AccessList: al,
		}
	case args.AccessList != nil: // 访问列表交易 (EIP-2930)。
		data = &types.AccessListTx{
			To:         to,
			ChainID:    (*big.Int)(args.ChainID),
			Nonce:      uint64(args.Nonce),
			Gas:        uint64(args.Gas),
			GasPrice:   (*big.Int)(args.GasPrice),
			Value:      (*big.Int)(&args.Value),
			Data:       args.data(),
			AccessList: *args.AccessList,
		}
	default: // 传统交易
		data = &types.LegacyTx{
			To:       to,
			Nonce:    uint64(args.Nonce),
			Gas:      uint64(args.Gas),
			GasPrice: (*big.Int)(args.GasPrice),
			Value:    (*big.Int)(&args.Value),
			Data:     args.data(),
		}
	}

	return types.NewTx(data), nil
}

// validateTxSidecar validates blob data, if present
// validateTxSidecar 验证存在的 Blob 数据。
// 验证和补全 Blob 交易的侧车数据
func (args *SendTxArgs) validateTxSidecar() error {
	// No blobs, we're done.
	if args.Blobs == nil {
		return nil
	}

	n := len(args.Blobs)
	// Assume user provides either only blobs (w/o hashes), or
	// blobs together with commitments and proofs.
	if args.Commitments == nil && args.Proofs != nil {
		return errors.New(`blob proofs provided while commitments were not`)
	} else if args.Commitments != nil && args.Proofs == nil {
		return errors.New(`blob commitments provided while proofs were not`)
	}

	// len(blobs) == len(commitments) == len(proofs) == len(hashes)
	// 验证 Blobs, Commitments, Proofs, BlobHashes 的长度是否一致
	if args.Commitments != nil && len(args.Commitments) != n {
		return fmt.Errorf("number of blobs and commitments mismatch (have=%d, want=%d)", len(args.Commitments), n)
	}
	if args.Proofs != nil && len(args.Proofs) != n {
		return fmt.Errorf("number of blobs and proofs mismatch (have=%d, want=%d)", len(args.Proofs), n)
	}
	if args.BlobHashes != nil && len(args.BlobHashes) != n {
		return fmt.Errorf("number of blobs and hashes mismatch (have=%d, want=%d)", len(args.BlobHashes), n)
	}

	if args.Commitments == nil {
		// Generate commitment and proof.
		// 为每个 Blob 生成 Commitment 和 Proof（使用 KZG-4844）
		commitments := make([]kzg4844.Commitment, n)
		proofs := make([]kzg4844.Proof, n)
		for i, b := range args.Blobs {
			c, err := kzg4844.BlobToCommitment(&b)
			if err != nil {
				return fmt.Errorf("blobs[%d]: error computing commitment: %v", i, err)
			}
			commitments[i] = c
			p, err := kzg4844.ComputeBlobProof(&b, c)
			if err != nil {
				return fmt.Errorf("blobs[%d]: error computing proof: %v", i, err)
			}
			proofs[i] = p
		}
		args.Commitments = commitments
		args.Proofs = proofs
	} else { // 验证每个 Blob 的证明。
		for i, b := range args.Blobs {
			if err := kzg4844.VerifyBlobProof(&b, args.Commitments[i], args.Proofs[i]); err != nil {
				return fmt.Errorf("failed to verify blob proof: %v", err)
			}
		}
	}

	hashes := make([]common.Hash, n)
	hasher := sha256.New()
	for i, c := range args.Commitments { // 从 Commitments 计算 BlobHashes
		hashes[i] = kzg4844.CalcBlobHashV1(hasher, &c)
	}
	if args.BlobHashes != nil { // 如果 args.BlobHashes 非空，验证匹配；否则赋值
		for i, h := range hashes {
			if h != args.BlobHashes[i] {
				return fmt.Errorf("blob hash verification failed (have=%s, want=%s)", args.BlobHashes[i], h)
			}
		}
	} else {
		args.BlobHashes = hashes
	}
	return nil
}

// SigFormat 表示签名数据的格式
type SigFormat struct {
	Mime        string // MIME 类型，用于标识数据的类型或用途。
	ByteVersion byte   // 单字节版本号，可能用于区分格式的版本或类型。
}

var (
	IntendedValidator = SigFormat{
		accounts.MimetypeDataWithValidator,
		0x00,
	}
	DataTyped = SigFormat{
		accounts.MimetypeTypedData,
		0x01,
	}
	ApplicationClique = SigFormat{
		accounts.MimetypeClique,
		0x02,
	}
	TextPlain = SigFormat{
		accounts.MimetypeTextPlain,
		0x45,
	}
)

type ValidatorData struct {
	Address common.Address
	Message hexutil.Bytes
}

// TypedData is a type to encapsulate EIP-712 typed messages
// TypedData 是一个封装 EIP-712 类型化消息的类型
//
//	封装 EIP-712 的所有组成部分，用于签名和验证
type TypedData struct {
	Types       Types            `json:"types"`       // 定义所有类型
	PrimaryType string           `json:"primaryType"` // 主类型名称，指定消息的根类型。
	Domain      TypedDataDomain  `json:"domain"`      // 域分隔符，用于区分不同应用或链
	Message     TypedDataMessage `json:"message"`     // 实际消息内容
}

// Type is the inner type of an EIP-712 message
// Type 是 EIP-712 消息的内部类型
type Type struct {
	Name string `json:"name"` // 字段名称
	Type string `json:"type"` // 字段类型（如 string, uint256, address[]）
}

// isArray returns true if the type is a fixed or variable sized array.
// This method may return false positives, in case the Type is not a valid
// expression, e.g. "fooo[[[[".
// isArray 如果类型是固定大小或可变大小的数组，则返回 true。
// 如果 Type 不是有效的表达式（例如 "fooo[[[["），此方法可能返回误报。
func (t *Type) isArray() bool {
	return strings.IndexByte(t.Type, '[') > 0
}

// typeName returns the canonical name of the type. If the type is 'Person[]' or 'Person[2]', then
// this method returns 'Person'
// typeName 返回类型的规范名称。如果类型是 'Person[]' 或 'Person[2]'，则此方法返回 'Person'。
func (t *Type) typeName() string {
	return strings.Split(t.Type, "[")[0]
}

type Types map[string][]Type

type TypePriority struct {
	Type  string
	Value uint
}

type TypedDataMessage = map[string]interface{}

// EIP-712 背景：提供结构化数据的签名标准，使签名对用户更直观。
// 哈希公式 hash = keccak256("\x19\x01" || domainHash || messageHash)

// TypedDataDomain represents the domain part of an EIP-712 message.
// TypedDataDomain 表示 EIP-712 消息的域部分。
//
//	表示 EIP-712 的域分隔符，确保签名特定于应用和链。
//	防止签名跨应用或链重放
type TypedDataDomain struct {
	Name              string                `json:"name"`              // 应用名称
	Version           string                `json:"version"`           // 应用版本
	ChainId           *math.HexOrDecimal256 `json:"chainId"`           // 链 ID（支持 16 进制或十进制）。
	VerifyingContract string                `json:"verifyingContract"` // 验证合约地址
	Salt              string                `json:"salt"`              // 可选的盐值（额外唯一性）
}

// TypedDataAndHash is a helper function that calculates a hash for typed data conforming to EIP-712.
// This hash can then be safely used to calculate a signature.
//
// See https://eips.ethereum.org/EIPS/eip-712 for the full specification.
//
// This gives context to the signed typed data and prevents signing of transactions.
//
// TypedDataAndHash 是一个辅助函数，用于计算符合 EIP-712 标准的类型化数据的哈希值。
// 此哈希值随后可安全用于计算签名。
//
// 完整规范请参见 https://eips.ethereum.org/EIPS/eip-712。
//
// 这为签名的类型化数据提供了上下文，并防止对交易的签名。
// hash = keccak256("\x19\x01" || domainSeparator || structHash)
// \x19\x01: 前缀，表示 EIP-712 签名，防止与交易签名混淆。 前缀 \x19\x01 防止重放攻击。
// domainSeparator: 域分隔符的哈希。
// structHash: 主类型数据的哈希。
func TypedDataAndHash(typedData TypedData) ([]byte, string, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, "", err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, "", err
	}
	rawData := fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash))
	return crypto.Keccak256([]byte(rawData)), rawData, nil
}

// HashStruct generates a keccak256 hash of the encoding of the provided data
// HashStruct 生成所提供数据的编码的 keccak256 哈希
func (typedData *TypedData) HashStruct(primaryType string, data TypedDataMessage) (hexutil.Bytes, error) {
	encodedData, err := typedData.EncodeData(primaryType, data, 1) // 调用 EncodeData 编码数据。
	if err != nil {
		return nil, err
	}
	return crypto.Keccak256(encodedData), nil // 对编码结果计算哈希。
}

// Dependencies returns an array of custom types ordered by their hierarchical reference tree
// Dependencies 返回按层次引用树排序的自定义类型数组
// 返回 primaryType 的依赖类型列表（按层次顺序）。
//
//	 流程:
//		- 去掉数组标记（[n] 或 []）。
//		- 如果已找到或类型不存在，返回当前列表。
//		- 添加当前类型，递归查找字段的依赖。
func (typedData *TypedData) Dependencies(primaryType string, found []string) []string {
	primaryType = strings.Split(primaryType, "[")[0]

	if slices.Contains(found, primaryType) {
		return found
	}
	if typedData.Types[primaryType] == nil {
		return found
	}
	found = append(found, primaryType)
	for _, field := range typedData.Types[primaryType] {
		for _, dep := range typedData.Dependencies(field.Type, found) {
			if !slices.Contains(found, dep) {
				found = append(found, dep)
			}
		}
	}
	return found
}

// EncodeType generates the following encoding:
// `name ‖ "(" ‖ member₁ ‖ "," ‖ member₂ ‖ "," ‖ … ‖ memberₙ ")"`
//
// each member is written as `type ‖ " " ‖ name` encodings cascade down and are sorted by name
//
// EncodeType 生成以下编码：
// `name ‖ "(" ‖ member₁ ‖ "," ‖ member₂ ‖ "," ‖ … ‖ memberₙ ")"`
//
// 每个成员写作 `type ‖ " " ‖ name`，编码按名称排序并级联向下
//
// 生成类型的字符串编码 eg: TypeName(type1 name1,type2 name2,...)
func (typedData *TypedData) EncodeType(primaryType string) hexutil.Bytes {
	// Get dependencies primary first, then alphabetical
	deps := typedData.Dependencies(primaryType, []string{})
	if len(deps) > 0 {
		slicedDeps := deps[1:]
		sort.Strings(slicedDeps)
		deps = append([]string{primaryType}, slicedDeps...)
	}

	// Format as a string with fields
	var buffer bytes.Buffer
	for _, dep := range deps {
		buffer.WriteString(dep)
		buffer.WriteString("(")
		for _, obj := range typedData.Types[dep] {
			buffer.WriteString(obj.Type)
			buffer.WriteString(" ")
			buffer.WriteString(obj.Name)
			buffer.WriteString(",")
		}
		buffer.Truncate(buffer.Len() - 1)
		buffer.WriteString(")")
	}
	return buffer.Bytes()
}

// TypeHash creates the keccak256 hash  of the data
// TypeHash 创建数据的 keccak256 哈希
func (typedData *TypedData) TypeHash(primaryType string) hexutil.Bytes {
	return crypto.Keccak256(typedData.EncodeType(primaryType))
}

// EncodeData generates the following encoding:
// `enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ)`
//
// each encoded member is 32-byte long
//
// EncodeData 生成以下编码：
// `enc(value₁) ‖ enc(value₂) ‖ … ‖ enc(valueₙ)`
//
// 每个编码成员长度为 32 字节
func (typedData *TypedData) EncodeData(primaryType string, data map[string]interface{}, depth int) (hexutil.Bytes, error) {
	if err := typedData.validate(); err != nil {
		return nil, err
	}

	buffer := bytes.Buffer{}

	// Verify extra data
	if exp, got := len(typedData.Types[primaryType]), len(data); exp < got {
		return nil, fmt.Errorf("there is extra data provided in the message (%d < %d)", exp, got)
	}

	// Add typehash
	buffer.Write(typedData.TypeHash(primaryType))

	// Add field contents. Structs and arrays have special handlers.
	for _, field := range typedData.Types[primaryType] {
		encType := field.Type
		encValue := data[field.Name]
		if encType[len(encType)-1:] == "]" {
			encodedData, err := typedData.encodeArrayValue(encValue, encType, depth)
			if err != nil {
				return nil, err
			}
			buffer.Write(encodedData)
		} else if typedData.Types[field.Type] != nil {
			mapValue, ok := encValue.(map[string]interface{})
			if !ok {
				return nil, dataMismatchError(encType, encValue)
			}
			encodedData, err := typedData.EncodeData(field.Type, mapValue, depth+1)
			if err != nil {
				return nil, err
			}
			buffer.Write(crypto.Keccak256(encodedData))
		} else {
			byteValue, err := typedData.EncodePrimitiveValue(encType, encValue, depth)
			if err != nil {
				return nil, err
			}
			buffer.Write(byteValue)
		}
	}
	return buffer.Bytes(), nil
}

func (typedData *TypedData) encodeArrayValue(encValue interface{}, encType string, depth int) (hexutil.Bytes, error) {
	arrayValue, err := convertDataToSlice(encValue)
	if err != nil {
		return nil, dataMismatchError(encType, encValue)
	}

	arrayBuffer := new(bytes.Buffer)
	parsedType := strings.Split(encType, "[")[0]
	for _, item := range arrayValue {
		if reflect.TypeOf(item).Kind() == reflect.Slice ||
			reflect.TypeOf(item).Kind() == reflect.Array {
			encodedData, err := typedData.encodeArrayValue(item, parsedType, depth+1)
			if err != nil {
				return nil, err
			}
			arrayBuffer.Write(encodedData)
		} else {
			if typedData.Types[parsedType] != nil {
				mapValue, ok := item.(map[string]interface{})
				if !ok {
					return nil, dataMismatchError(parsedType, item)
				}
				encodedData, err := typedData.EncodeData(parsedType, mapValue, depth+1)
				if err != nil {
					return nil, err
				}
				digest := crypto.Keccak256(encodedData)
				arrayBuffer.Write(digest)
			} else {
				bytesValue, err := typedData.EncodePrimitiveValue(parsedType, item, depth)
				if err != nil {
					return nil, err
				}
				arrayBuffer.Write(bytesValue)
			}
		}
	}
	return crypto.Keccak256(arrayBuffer.Bytes()), nil
}

// Attempt to parse bytes in different formats: byte array, hex string, hexutil.Bytes.
// 尝试以不同格式解析字节：字节数组、十六进制字符串、hexutil.Bytes。
func parseBytes(encType interface{}) ([]byte, bool) {
	// Handle array types.
	val := reflect.ValueOf(encType)
	if val.Kind() == reflect.Array && val.Type().Elem().Kind() == reflect.Uint8 { // 检查 val 是否为数组类型（reflect.Array），并且数组的元素类型是 uint8（即字节类型）。
		v := reflect.MakeSlice(reflect.TypeOf([]byte{}), val.Len(), val.Len())
		reflect.Copy(v, val)
		return v.Bytes(), true
	}

	switch v := encType.(type) {
	case []byte: // 如果输入已经是字节切片，直接返回并标记成功（true）
		return v, true
	case hexutil.Bytes: // 如果输入是 hexutil.Bytes 类型（这是 go-ethereum 中定义的十六进制字节类型），直接返回其值并标记成功。
		return v, true
	case string: // 如果输入是字符串，假设它是十六进制编码格式，调用 hexutil.Decode 解码为字节数组。如果解码成功，返回字节数组和 true；如果失败，返回 nil 和 false。
		bytes, err := hexutil.Decode(v)
		if err != nil {
			return nil, false
		}
		return bytes, true
	default:
		return nil, false
	}
}

func parseInteger(encType string, encValue interface{}) (*big.Int, error) {
	var (
		length int                                 // 整数的位长度
		signed = strings.HasPrefix(encType, "int") // 通过检查 encType 是否以 "int" 开头，判断是否为有符号整数
		b      *big.Int
	)
	if encType == "int" || encType == "uint" {
		length = 256
	} else { // 从 encType 中提取长度部分（例如 "uint64" 提取 "64"），使用 strconv.Atoi 将其转换为整数。如果转换失败，返回错误。
		lengthStr := ""
		if strings.HasPrefix(encType, "uint") {
			lengthStr = strings.TrimPrefix(encType, "uint")
		} else {
			lengthStr = strings.TrimPrefix(encType, "int")
		}
		atoiSize, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, fmt.Errorf("invalid size on integer: %v", lengthStr)
		}
		length = atoiSize
	}
	switch v := encValue.(type) {
	case *math.HexOrDecimal256:
		b = (*big.Int)(v)
	case *big.Int:
		b = v
	case string:
		var hexIntValue math.HexOrDecimal256
		if err := hexIntValue.UnmarshalText([]byte(v)); err != nil {
			return nil, err
		}
		b = (*big.Int)(&hexIntValue)
	case float64:
		// JSON parses non-strings as float64. Fail if we cannot
		// convert it losslessly
		// JSON 解析非字符串时可能返回 float64。检查是否可以无损转换为 int64（即小数部分为 0）
		if float64(int64(v)) == v {
			b = big.NewInt(int64(v))
		} else {
			return nil, fmt.Errorf("invalid float value %v for type %v", v, encType)
		}
	}
	if b == nil {
		return nil, fmt.Errorf("invalid integer value %v/%v for type %v", encValue, reflect.TypeOf(encValue), encType)
	}
	if b.BitLen() > length { // 检查 b 的位长度（BitLen()）是否超过指定的 length，如果超过，返回错误
		return nil, fmt.Errorf("integer larger than '%v'", encType)
	}
	if !signed && b.Sign() == -1 { // 如果是无符号类型（!signed）但值为负数（b.Sign() == -1），返回错误
		return nil, fmt.Errorf("invalid negative value for unsigned type %v", encType)
	}
	return b, nil
}

// EncodePrimitiveValue deals with the primitive values found
// while searching through the typed data
// EncodePrimitiveValue 处理在类型化数据中搜索时发现的原始值
func (typedData *TypedData) EncodePrimitiveValue(encType string, encValue interface{}, depth int) ([]byte, error) {
	switch encType {
	case "address":
		retval := make([]byte, 32)
		switch val := encValue.(type) {
		case string:
			if common.IsHexAddress(val) {
				copy(retval[12:], common.HexToAddress(val).Bytes())
				return retval, nil
			}
		case []byte:
			if len(val) == 20 {
				copy(retval[12:], val)
				return retval, nil
			}
		case [20]byte:
			copy(retval[12:], val[:])
			return retval, nil
		}
		return nil, dataMismatchError(encType, encValue)
	case "bool":
		boolValue, ok := encValue.(bool)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		if boolValue {
			return math.PaddedBigBytes(common.Big1, 32), nil
		}
		return math.PaddedBigBytes(common.Big0, 32), nil
	case "string":
		strVal, ok := encValue.(string)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		return crypto.Keccak256([]byte(strVal)), nil
	case "bytes":
		bytesValue, ok := parseBytes(encValue)
		if !ok {
			return nil, dataMismatchError(encType, encValue)
		}
		return crypto.Keccak256(bytesValue), nil
	}
	if strings.HasPrefix(encType, "bytes") {
		lengthStr := strings.TrimPrefix(encType, "bytes")
		length, err := strconv.Atoi(lengthStr)
		if err != nil {
			return nil, fmt.Errorf("invalid size on bytes: %v", lengthStr)
		}
		if length < 0 || length > 32 {
			return nil, fmt.Errorf("invalid size on bytes: %d", length)
		}
		if byteValue, ok := parseBytes(encValue); !ok || len(byteValue) != length {
			return nil, dataMismatchError(encType, encValue)
		} else {
			// Right-pad the bits
			dst := make([]byte, 32)
			copy(dst, byteValue)
			return dst, nil
		}
	}
	if strings.HasPrefix(encType, "int") || strings.HasPrefix(encType, "uint") {
		b, err := parseInteger(encType, encValue)
		if err != nil {
			return nil, err
		}
		return math.U256Bytes(new(big.Int).Set(b)), nil
	}
	return nil, fmt.Errorf("unrecognized type '%s'", encType)
}

// dataMismatchError generates an error for a mismatch between
// the provided type and data
func dataMismatchError(encType string, encValue interface{}) error {
	return fmt.Errorf("provided data '%v' doesn't match type '%s'", encValue, encType)
}

func convertDataToSlice(encValue interface{}) ([]interface{}, error) {
	var outEncValue []interface{}
	rv := reflect.ValueOf(encValue)
	if rv.Kind() == reflect.Slice {
		for i := 0; i < rv.Len(); i++ {
			outEncValue = append(outEncValue, rv.Index(i).Interface())
		}
	} else {
		return outEncValue, fmt.Errorf("provided data '%v' is not slice", encValue)
	}
	return outEncValue, nil
}

// validate makes sure the types are sound
func (typedData *TypedData) validate() error {
	if err := typedData.Types.validate(); err != nil {
		return err
	}
	if err := typedData.Domain.validate(); err != nil {
		return err
	}
	return nil
}

// Map generates a map version of the typed data
func (typedData *TypedData) Map() map[string]interface{} {
	dataMap := map[string]interface{}{
		"types":       typedData.Types,
		"domain":      typedData.Domain.Map(),
		"primaryType": typedData.PrimaryType,
		"message":     typedData.Message,
	}
	return dataMap
}

// Format returns a representation of typedData, which can be easily displayed by a user-interface
// without in-depth knowledge about 712 rules
func (typedData *TypedData) Format() ([]*NameValueType, error) {
	domain, err := typedData.formatData("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, err
	}
	ptype, err := typedData.formatData(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, err
	}
	var nvts []*NameValueType
	nvts = append(nvts, &NameValueType{
		Name:  "EIP712Domain",
		Value: domain,
		Typ:   "domain",
	})
	nvts = append(nvts, &NameValueType{
		Name:  typedData.PrimaryType,
		Value: ptype,
		Typ:   "primary type",
	})
	return nvts, nil
}

func (typedData *TypedData) formatData(primaryType string, data map[string]interface{}) ([]*NameValueType, error) {
	var output []*NameValueType

	// Add field contents. Structs and arrays have special handlers.
	for _, field := range typedData.Types[primaryType] {
		encName := field.Name
		encValue := data[encName]
		item := &NameValueType{
			Name: encName,
			Typ:  field.Type,
		}
		if field.isArray() {
			arrayValue, _ := convertDataToSlice(encValue)
			parsedType := field.typeName()
			for _, v := range arrayValue {
				if typedData.Types[parsedType] != nil {
					mapValue, _ := v.(map[string]interface{})
					mapOutput, err := typedData.formatData(parsedType, mapValue)
					if err != nil {
						return nil, err
					}
					item.Value = mapOutput
				} else {
					primitiveOutput, err := formatPrimitiveValue(field.Type, encValue)
					if err != nil {
						return nil, err
					}
					item.Value = primitiveOutput
				}
			}
		} else if typedData.Types[field.Type] != nil {
			if mapValue, ok := encValue.(map[string]interface{}); ok {
				mapOutput, err := typedData.formatData(field.Type, mapValue)
				if err != nil {
					return nil, err
				}
				item.Value = mapOutput
			} else {
				item.Value = "<nil>"
			}
		} else {
			primitiveOutput, err := formatPrimitiveValue(field.Type, encValue)
			if err != nil {
				return nil, err
			}
			item.Value = primitiveOutput
		}
		output = append(output, item)
	}
	return output, nil
}

func formatPrimitiveValue(encType string, encValue interface{}) (string, error) {
	switch encType {
	case "address":
		if stringValue, ok := encValue.(string); !ok {
			return "", fmt.Errorf("could not format value %v as address", encValue)
		} else {
			return common.HexToAddress(stringValue).String(), nil
		}
	case "bool":
		if boolValue, ok := encValue.(bool); !ok {
			return "", fmt.Errorf("could not format value %v as bool", encValue)
		} else {
			return fmt.Sprintf("%t", boolValue), nil
		}
	case "bytes", "string":
		return fmt.Sprintf("%s", encValue), nil
	}
	if strings.HasPrefix(encType, "bytes") {
		return fmt.Sprintf("%s", encValue), nil
	}
	if strings.HasPrefix(encType, "uint") || strings.HasPrefix(encType, "int") {
		if b, err := parseInteger(encType, encValue); err != nil {
			return "", err
		} else {
			return fmt.Sprintf("%d (%#x)", b, b), nil
		}
	}
	return "", fmt.Errorf("unhandled type %v", encType)
}

// validate checks if the types object is conformant to the specs
func (t Types) validate() error {
	for typeKey, typeArr := range t {
		if len(typeKey) == 0 {
			return errors.New("empty type key")
		}
		for i, typeObj := range typeArr {
			if len(typeObj.Type) == 0 {
				return fmt.Errorf("type %q:%d: empty Type", typeKey, i)
			}
			if len(typeObj.Name) == 0 {
				return fmt.Errorf("type %q:%d: empty Name", typeKey, i)
			}
			if typeKey == typeObj.Type {
				return fmt.Errorf("type %q cannot reference itself", typeObj.Type)
			}
			if isPrimitiveTypeValid(typeObj.Type) {
				continue
			}
			// Must be reference type
			if _, exist := t[typeObj.typeName()]; !exist {
				return fmt.Errorf("reference type %q is undefined", typeObj.Type)
			}
			if !typedDataReferenceTypeRegexp.MatchString(typeObj.Type) {
				return fmt.Errorf("unknown reference type %q", typeObj.Type)
			}
		}
	}
	return nil
}

var validPrimitiveTypes = map[string]struct{}{}

// build the set of valid primitive types
func init() {
	// Types those are trivially valid
	for _, t := range []string{
		"address", "address[]", "bool", "bool[]", "string", "string[]",
		"bytes", "bytes[]", "int", "int[]", "uint", "uint[]",
	} {
		validPrimitiveTypes[t] = struct{}{}
	}
	// For 'bytesN', 'bytesN[]', we allow N from 1 to 32
	for n := 1; n <= 32; n++ {
		validPrimitiveTypes[fmt.Sprintf("bytes%d", n)] = struct{}{}
		validPrimitiveTypes[fmt.Sprintf("bytes%d[]", n)] = struct{}{}
	}
	// For 'intN','intN[]' and 'uintN','uintN[]' we allow N in increments of 8, from 8 up to 256
	for n := 8; n <= 256; n += 8 {
		validPrimitiveTypes[fmt.Sprintf("int%d", n)] = struct{}{}
		validPrimitiveTypes[fmt.Sprintf("int%d[]", n)] = struct{}{}
		validPrimitiveTypes[fmt.Sprintf("uint%d", n)] = struct{}{}
		validPrimitiveTypes[fmt.Sprintf("uint%d[]", n)] = struct{}{}
	}
}

// Checks if the primitive value is valid
func isPrimitiveTypeValid(primitiveType string) bool {
	input := strings.Split(primitiveType, "[")[0]
	_, ok := validPrimitiveTypes[input]
	return ok
}

// validate checks if the given domain is valid, i.e. contains at least
// the minimum viable keys and values
func (domain *TypedDataDomain) validate() error {
	if domain.ChainId == nil && len(domain.Name) == 0 && len(domain.Version) == 0 && len(domain.VerifyingContract) == 0 && len(domain.Salt) == 0 {
		return errors.New("domain is undefined")
	}

	return nil
}

// Map is a helper function to generate a map version of the domain
func (domain *TypedDataDomain) Map() map[string]interface{} {
	dataMap := map[string]interface{}{}

	if domain.ChainId != nil {
		dataMap["chainId"] = domain.ChainId
	}

	if len(domain.Name) > 0 {
		dataMap["name"] = domain.Name
	}

	if len(domain.Version) > 0 {
		dataMap["version"] = domain.Version
	}

	if len(domain.VerifyingContract) > 0 {
		dataMap["verifyingContract"] = domain.VerifyingContract
	}

	if len(domain.Salt) > 0 {
		dataMap["salt"] = domain.Salt
	}
	return dataMap
}

// NameValueType is a very simple struct with Name, Value and Type. It's meant for simple
// json structures used to communicate signing-info about typed data with the UI
type NameValueType struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	Typ   string      `json:"type"`
}

// Pprint returns a pretty-printed version of nvt
func (nvt *NameValueType) Pprint(depth int) string {
	output := bytes.Buffer{}
	output.WriteString(strings.Repeat("\u00a0", depth*2))
	output.WriteString(fmt.Sprintf("%s [%s]: ", nvt.Name, nvt.Typ))
	if nvts, ok := nvt.Value.([]*NameValueType); ok {
		output.WriteString("\n")
		for _, next := range nvts {
			sublevel := next.Pprint(depth + 1)
			output.WriteString(sublevel)
		}
	} else {
		if nvt.Value != nil {
			output.WriteString(fmt.Sprintf("%q\n", nvt.Value))
		} else {
			output.WriteString("\n")
		}
	}
	return output.String()
}
