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

package types

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// BlobTx 结构体定义了 EIP-4844 Blob 交易的格式，交易类型为 0x03，是坎昆硬分叉（ 2024 年）引入的新交易类型。
// 它扩展了 EIP-1559 的动态费用机制，增加了 Blob 数据存储功能，用于支持分片和 Rollup 数据的高效处理。
// BlobTxSidecar 是 Blob 交易的附属结构，包含实际的 Blob 数据及其验证信息。
// 通过 Sidecar 携带实际 Blob 数据及其验证信息。它支持 EIP-4844 的分片目标，降低 Rollup 等二层方案的数据成本。

// BlobTx represents an EIP-4844 transaction.
// BlobTx 表示 EIP-4844 交易。
type BlobTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	GasTipCap  *uint256.Int // a.k.a. maxPriorityFeePerGas 又称 maxPriorityFeePerGas，最大优先费每单位 Gas
	GasFeeCap  *uint256.Int // a.k.a. maxFeePerGas 又称 maxFeePerGas，最大费用每单位 Gas
	Gas        uint64
	To         common.Address // 不再是 *common.Address，强制非空。
	Value      *uint256.Int
	Data       []byte
	AccessList AccessList
	BlobFeeCap *uint256.Int  // a.k.a. maxFeePerBlobGas 又称 maxFeePerBlobGas，最大 Blob Gas 费用。EIP-4844 引入，限制 Blob 数据存储的费用。
	BlobHashes []common.Hash // Blob 数据的哈希值。每个 Blob 的 32 字节哈希，用于验证和索引。

	// A blob transaction can optionally contain blobs. This field must be set when BlobTx
	// is used to create a transaction for signing.
	// Blob 交易可以选择包含 Blobs。此字段在创建用于签名的交易时必须设置。 Blob 数据及其验证信息。仅用于签名或本地处理
	Sidecar *BlobTxSidecar `rlp:"-"`

	// Signature values
	// 签名值
	V *uint256.Int // V 为 0 或 1，与 EIP-1559 一致。
	R *uint256.Int
	S *uint256.Int
}

// BlobTxSidecar contains the blobs of a blob transaction.
// BlobTxSidecar 包含 Blob 交易的 Blobs 数据。
type BlobTxSidecar struct {
	Blobs       []kzg4844.Blob       // Blobs needed by the blob pool; Blob 池所需的 Blobs。实际的 Blob 数据。每个 Blob 是固定大小（约 128 KB）的二进制数据，用于存储 Rollup 数据。
	Commitments []kzg4844.Commitment // Commitments needed by the blob pool; Blob 池所需的承诺。Blob 的 KZG 承诺。基于 KZG 多项式承诺，用于验证 Blob 数据。
	Proofs      []kzg4844.Proof      // Proofs needed by the blob pool; Blob 池所需的证明。Blob 的 KZG 证明。用于验证 Blob 数据与承诺的一致性。
}

// BlobHashes computes the blob hashes of the given blobs.
// BlobHashes 计算给定 Blobs 的 Blob 哈希值。
//
// 计算 BlobTxSidecar 中 Blob 数据对应的哈希值，用于验证 Blob 数据与交易中的 BlobHashes 一致。
func (sc *BlobTxSidecar) BlobHashes() []common.Hash {
	hasher := sha256.New()
	h := make([]common.Hash, len(sc.Commitments))
	for i := range sc.Blobs {
		// 计算每个 Blob 的哈希值
		h[i] = kzg4844.CalcBlobHashV1(hasher, &sc.Commitments[i])
	}
	return h
}

// encodedSize computes the RLP size of the sidecar elements. This does NOT return the
// encoded size of the BlobTxSidecar, it's just a helper for tx.Size().
//
// encodedSize 计算 Sidecar 元素的 RLP 大小。此方法不返回 BlobTxSidecar 的编码大小，
// 仅作为 tx.Size() 的辅助函数。
//
// 计算 BlobTxSidecar 中元素的 RLP 编码大小，作为交易大小计算的辅助函数，支持 EIP-4844 Blob 交易的内存和序列化处理。
func (sc *BlobTxSidecar) encodedSize() uint64 {
	// 定义变量存储 Blobs、Commitments 和 Proofs 的 RLP 大小
	var blobs, commitments, proofs uint64
	for i := range sc.Blobs {
		// 计算每个 Blob 的 RLP 字节大小
		blobs += rlp.BytesSize(sc.Blobs[i][:])
	}
	for i := range sc.Commitments {
		// 计算每个 Commitment 的 RLP 字节大小
		commitments += rlp.BytesSize(sc.Commitments[i][:])
	}
	for i := range sc.Proofs {
		// 计算每个 Proof 的 RLP 字节大小
		proofs += rlp.BytesSize(sc.Proofs[i][:])
	}
	// 返回列表的总 RLP 大小
	return rlp.ListSize(blobs) + rlp.ListSize(commitments) + rlp.ListSize(proofs)
}

// blobTxWithBlobs 是一个辅助结构体，用于在 EIP-4844 Blob 交易（BlobTx）包含 Blobs 数据时进行 RLP 编码。
//它将 BlobTx 的核心字段与 Sidecar 中的 Blobs、Commitments 和 Proofs 组合成一个单一结构，以便在网络传输中编码完整的交易数据。

// blobTxWithBlobs is used for encoding of transactions when blobs are present.
// blobTxWithBlobs 用于在存在 Blobs 时编码交易。
type blobTxWithBlobs struct {
	BlobTx      *BlobTx              // Blob 交易
	Blobs       []kzg4844.Blob       // Blobs 数据
	Commitments []kzg4844.Commitment // 承诺
	Proofs      []kzg4844.Proof      // 证明
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *BlobTx) copy() TxData {
	cpy := &BlobTx{
		Nonce: tx.Nonce,
		To:    tx.To,
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		BlobHashes: make([]common.Hash, len(tx.BlobHashes)),
		Value:      new(uint256.Int),
		ChainID:    new(uint256.Int),
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		BlobFeeCap: new(uint256.Int),
		V:          new(uint256.Int),
		R:          new(uint256.Int),
		S:          new(uint256.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	copy(cpy.BlobHashes, tx.BlobHashes)

	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.BlobFeeCap != nil {
		cpy.BlobFeeCap.Set(tx.BlobFeeCap)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	if tx.Sidecar != nil {
		cpy.Sidecar = &BlobTxSidecar{
			Blobs:       append([]kzg4844.Blob(nil), tx.Sidecar.Blobs...),
			Commitments: append([]kzg4844.Commitment(nil), tx.Sidecar.Commitments...),
			Proofs:      append([]kzg4844.Proof(nil), tx.Sidecar.Proofs...),
		}
	}
	return cpy
}

// accessors for innerTx.
func (tx *BlobTx) txType() byte           { return BlobTxType }
func (tx *BlobTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *BlobTx) accessList() AccessList { return tx.AccessList }
func (tx *BlobTx) data() []byte           { return tx.Data }
func (tx *BlobTx) gas() uint64            { return tx.Gas }
func (tx *BlobTx) gasFeeCap() *big.Int    { return tx.GasFeeCap.ToBig() }
func (tx *BlobTx) gasTipCap() *big.Int    { return tx.GasTipCap.ToBig() }
func (tx *BlobTx) gasPrice() *big.Int     { return tx.GasFeeCap.ToBig() }
func (tx *BlobTx) value() *big.Int        { return tx.Value.ToBig() }
func (tx *BlobTx) nonce() uint64          { return tx.Nonce }
func (tx *BlobTx) to() *common.Address    { tmp := tx.To; return &tmp }

// blobGas 方法为 BlobTx（EIP-4844 Blob 交易）计算 Blob Gas 的总用量。
// Blob Gas 是 EIP-4844 引入的一种新资源计量单位，用于衡量交易中 Blob 数据存储的成本，与传统 Gas（计算资源）分开计费。
// blobGas 方法通过简单的乘法计算 Blob 交易的 Blob Gas 用量：BlobGas = BlobGasPerBlob * Blob数量。
// 它是 EIP-4844 交易成本计算的关键部分，与执行层 Gas（tx.Gas）并行存在，用于评估 Blob 数据存储的资源消耗。
func (tx *BlobTx) blobGas() uint64 { return params.BlobTxBlobGasPerBlob * uint64(len(tx.BlobHashes)) }

func (tx *BlobTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

func (tx *BlobTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V.ToBig(), tx.R.ToBig(), tx.S.ToBig()
}

func (tx *BlobTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID.SetFromBig(chainID)
	tx.V.SetFromBig(v)
	tx.R.SetFromBig(r)
	tx.S.SetFromBig(s)
}

// withoutSidecar 返回一个不含 Sidecar 的 BlobTx 副本。不含 Blob 数据（用于网络传输）
func (tx *BlobTx) withoutSidecar() *BlobTx {
	cpy := *tx
	cpy.Sidecar = nil
	return &cpy
}

// withSidecar 返回一个带有指定 Sidecar 的 BlobTx 副本。含 Blob 数据（用于签名或验证）。
func (tx *BlobTx) withSidecar(sideCar *BlobTxSidecar) *BlobTx {
	cpy := *tx
	cpy.Sidecar = sideCar
	return &cpy
}

// encode 将 BlobTx 编码到缓冲区。
func (tx *BlobTx) encode(b *bytes.Buffer) error {
	if tx.Sidecar == nil {
		return rlp.Encode(b, tx)
	}
	inner := &blobTxWithBlobs{
		BlobTx:      tx,
		Blobs:       tx.Sidecar.Blobs,
		Commitments: tx.Sidecar.Commitments,
		Proofs:      tx.Sidecar.Proofs,
	}
	return rlp.Encode(b, inner)
}

// decode 从输入字节解码 BlobTx。
func (tx *BlobTx) decode(input []byte) error {
	// Here we need to support two formats: the network protocol encoding of the tx (with
	// blobs) or the canonical encoding without blobs.
	//
	// The two encodings can be distinguished by checking whether the first element of the
	// input list is itself a list.
	// 这里需要支持两种格式：网络协议编码（含 Blobs）和不含 Blobs 的规范编码。
	// 两种编码可以通过检查输入列表的第一个元素是否为列表来区分。

	// 提取外部列表
	// 以太坊知识点：RLP 编码的交易是一个列表。
	// 区分编码格式通过第一个元素类型：规范编码为单一结构，网络编码为嵌套列表。
	outerList, _, err := rlp.SplitList(input)
	if err != nil {
		return err
	}
	// 检查第一个元素的类型
	firstElemKind, _, _, err := rlp.Split(outerList)
	if err != nil {
		return err
	}

	if firstElemKind != rlp.List {
		// 如果不是列表，直接解码为 BlobTx（不含 Blobs）
		return rlp.DecodeBytes(input, tx)
	}
	// It's a tx with blobs.
	// 处理含 Blobs 的交易
	var inner blobTxWithBlobs
	if err := rlp.DecodeBytes(input, &inner); err != nil {
		return err
	}
	// 将 BlobTx 数据复制到 tx
	*tx = *inner.BlobTx
	// 设置 Sidecar
	tx.Sidecar = &BlobTxSidecar{
		Blobs:       inner.Blobs,
		Commitments: inner.Commitments,
		Proofs:      inner.Proofs,
	}
	return nil
}
