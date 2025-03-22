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
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	ErrInvalidSig           = errors.New("invalid transaction v, r, s values")                               // 交易签名中的 v, r, s 值无效（可能是格式错误或无法恢复签名者）
	ErrUnexpectedProtection = errors.New("transaction type does not supported EIP-155 protected signatures") // 交易类型不支持 EIP-155 保护签名（EIP-155 添加了链 ID 防止重放攻击）
	ErrInvalidTxType        = errors.New("transaction type not valid in this context")                       // 交易类型在当前上下文无效（例如区块不支持该类型）。
	ErrTxTypeNotSupported   = errors.New("transaction type not supported")                                   // 交易类型完全不受支持（例如新类型未实现）。
	ErrGasFeeCapTooLow      = errors.New("fee cap less than base fee")                                       // 动态费用交易的燃气费用上限低于基础费用（EIP-1559 相关）。
	errShortTypedTx         = errors.New("typed transaction too short")                                      // 类型化交易的数据长度不足（可能是编码错误）。
	errInvalidYParity       = errors.New("'yParity' field must be 0 or 1")                                   // 类型化交易的 yParity 字段（签名奇偶性）必须是 0 或 1。
	errVYParityMismatch     = errors.New("'v' and 'yParity' fields do not match")                            // 传统 v 值与类型化交易的 yParity 不一致。
	errVYParityMissing      = errors.New("missing 'yParity' or 'v' field in transaction")                    // 交易缺少 yParity 或 v 字段。
)

// Transaction types.
// 交易类型。
const (
	LegacyTxType     = 0x00 // 传统交易类型（EIP-2718）
	AccessListTxType = 0x01 // 访问列表交易（EIP-2930）
	DynamicFeeTxType = 0x02 // 动态费用交易（EIP-1559）
	BlobTxType       = 0x03 // Blob 交易（EIP-4844，用于分片数据）
	SetCodeTxType    = 0x04 // 设置代码交易（可能是自定义或未来扩展）
)

// Transaction is an Ethereum transaction.
// Transaction 是以太坊交易。
//
// 表示以太坊交易，包含共识数据和本地缓存。
type Transaction struct {
	inner TxData    // Consensus contents of a transaction 交易的共识内容
	time  time.Time // Time first seen locally (spam avoidance) 本地首次看到的时间（避免垃圾交易）

	// caches
	hash atomic.Pointer[common.Hash] // 交易哈希的缓存
	size atomic.Uint64               // 交易编码后的大小（字节）
	from atomic.Pointer[sigCache]    // 签名者地址的缓存
}

// NewTx creates a new transaction.
// NewTx 创建一个新的交易。
func NewTx(inner TxData) *Transaction {
	tx := new(Transaction)
	tx.setDecoded(inner.copy(), 0)
	return tx
}

// TxData is the underlying data of a transaction.
//
// This is implemented by DynamicFeeTx, LegacyTx and AccessListTx.
//
// TxData 是交易的底层数据。
//
// 它由 DynamicFeeTx LegacyTx 和 AccessListTx 实现。 DynamicFeeTx（EIP-1559 动态费用交易） LegacyTx（传统交易） AccessListTx（EIP-2930 访问列表交易）。
//
// 定义交易数据的通用接口，抽象不同交易类型（如传统交易、动态费用交易等）的行为。
type TxData interface {
	txType() byte // returns the type ID  返回类型 ID
	copy() TxData // creates a deep copy and initializes all fields 创建一个深拷贝并初始化所有字段

	chainID() *big.Int      // 链 ID（EIP-155）
	accessList() AccessList // 访问列表（EIP-2930）
	data() []byte           // 交易数据（调用数据或合约代码）
	gas() uint64            // 燃气限制
	gasPrice() *big.Int     // 燃气价格（传统交易）
	gasTipCap() *big.Int    // 小费上限（EIP-1559）
	gasFeeCap() *big.Int    // 费用上限（EIP-1559）
	value() *big.Int        // 转账金额
	nonce() uint64          // 账户交易计数器
	to() *common.Address    // 目标地址（nil 表示创建合约）

	rawSignatureValues() (v, r, s *big.Int)       // 返回原始签名值
	setSignatureValues(chainID, v, r, s *big.Int) // 设置签名值

	// effectiveGasPrice computes the gas price paid by the transaction, given
	// the inclusion block baseFee.
	//
	// Unlike other TxData methods, the returned *big.Int should be an independent
	// copy of the computed value, i.e. callers are allowed to mutate the result.
	// Method implementations can use 'dst' to store the result.
	//
	// effectiveGasPrice 计算交易支付的燃气价格，给定包含区块的基础费用。
	//
	// 与其他 TxData 方法不同，返回的 *big.Int 应是计算值的独立副本，即调用者可以修改结果。
	// 方法实现可以使用 'dst' 来存储结果。
	effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int

	encode(*bytes.Buffer) error
	decode([]byte) error
}

// EncodeRLP implements rlp.Encoder
//
// EncodeRLP 实现了 rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	if tx.Type() == LegacyTxType {
		return rlp.Encode(w, tx.inner)
	}
	// It's an EIP-2718 typed TX envelope.
	buf := encodeBufferPool.Get().(*bytes.Buffer)
	defer encodeBufferPool.Put(buf)
	buf.Reset()
	if err := tx.encodeTyped(buf); err != nil {
		return err
	} // 使用 encodeTyped 写入类型和负载，再编码为 RLP
	return rlp.Encode(w, buf.Bytes())
}

// encodeTyped writes the canonical encoding of a typed transaction to w.
// encodeTyped 将类型化交易的规范编码写入 w。
func (tx *Transaction) encodeTyped(w *bytes.Buffer) error {
	w.WriteByte(tx.Type())
	return tx.inner.encode(w)
}

// MarshalBinary returns the canonical encoding of the transaction.
// For legacy transactions, it returns the RLP encoding. For EIP-2718 typed
// transactions, it returns the type and payload.
//
// MarshalBinary 返回交易的规范编码。
// 对于传统交易，返回 RLP 编码。对于 EIP-2718 类型化交易，返回类型和负载（不包裹 RLP）。
//
// 返回交易的二进制编码。
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	if tx.Type() == LegacyTxType {
		return rlp.EncodeToBytes(tx.inner)
	}
	var buf bytes.Buffer
	err := tx.encodeTyped(&buf)
	return buf.Bytes(), err
}

// DecodeRLP implements rlp.Decoder
// DecodeRLP 实现了 rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	kind, size, err := s.Kind()
	switch {
	case err != nil:
		return err
	case kind == rlp.List:
		// It's a legacy transaction. 这是一个传统交易。
		var inner LegacyTx
		err := s.Decode(&inner)
		if err == nil {
			tx.setDecoded(&inner, rlp.ListSize(size))
		}
		return err
	case kind == rlp.Byte:
		return errShortTypedTx
	default:
		// It's an EIP-2718 typed TX envelope.
		// 这是一个 EIP-2718 类型化交易包。
		// First read the tx payload bytes into a temporary buffer.
		b, buf, err := getPooledBuffer(size)
		if err != nil {
			return err
		}
		defer encodeBufferPool.Put(buf)
		if err := s.ReadBytes(b); err != nil {
			return err
		}
		// Now decode the inner transaction.
		inner, err := tx.decodeTyped(b)
		if err == nil {
			tx.setDecoded(inner, size)
		}
		return err
	}
}

// UnmarshalBinary decodes the canonical encoding of transactions.
// It supports legacy RLP transactions and EIP-2718 typed transactions.
//
// UnmarshalBinary 解码交易的规范编码。
// 它支持传统 RLP 交易和 EIP-2718 类型化交易。
func (tx *Transaction) UnmarshalBinary(b []byte) error {
	if len(b) > 0 && b[0] > 0x7f { // 如果首字节 > 0x7f（RLP 列表标志）：传统交易，解码为 LegacyTx
		// It's a legacy transaction.
		var data LegacyTx
		err := rlp.DecodeBytes(b, &data)
		if err != nil {
			return err
		}
		tx.setDecoded(&data, uint64(len(b)))
		return nil
	}
	// It's an EIP-2718 typed transaction envelope.
	inner, err := tx.decodeTyped(b)
	if err != nil {
		return err
	}
	tx.setDecoded(inner, uint64(len(b)))
	return nil
}

// decodeTyped decodes a typed transaction from the canonical format.
// decodeTyped 从规范格式解码类型化交易。
func (tx *Transaction) decodeTyped(b []byte) (TxData, error) {
	if len(b) <= 1 {
		return nil, errShortTypedTx
	}
	var inner TxData
	switch b[0] {
	case AccessListTxType:
		inner = new(AccessListTx)
	case DynamicFeeTxType:
		inner = new(DynamicFeeTx)
	case BlobTxType:
		inner = new(BlobTx)
	case SetCodeTxType:
		inner = new(SetCodeTx)
	default:
		return nil, ErrTxTypeNotSupported
	}
	err := inner.decode(b[1:])
	return inner, err
}

// setDecoded sets the inner transaction and size after decoding.
// setDecoded 在解码后设置内部交易和大小。
func (tx *Transaction) setDecoded(inner TxData, size uint64) {
	tx.inner = inner     // 设置交易的共识数据
	tx.time = time.Now() // 记录当前时间，表示首次看到交易
	if size > 0 {        // 如果提供了有效大小（>0），使用原子操作存储
		tx.size.Store(size)
	}
}

// 检查交易签名 (v, r, s) 的有效性
//
// maybeProtected bool（是否允许 EIP-155 保护）
func sanityCheckSignature(v *big.Int, r *big.Int, s *big.Int, maybeProtected bool) error {
	// 如果 v 是受保护的（EIP-155），但上下文不允许，返回 ErrUnexpectedProtection。
	if isProtectedV(v) && !maybeProtected {
		return ErrUnexpectedProtection
	}

	var plainV byte
	if isProtectedV(v) {
		chainID := deriveChainId(v).Uint64()
		plainV = byte(v.Uint64() - 35 - 2*chainID) // 提取原始恢复 ID（0 或 1）。 根据 EIP-155，v = 35 + 2 * chainID + plainV
	} else if maybeProtected {
		// 假设 v 是 27 或 28（传统签名），减去 27  plainV得到 0 或 1。
		//
		// Only EIP-155 signatures can be optionally protected. Since
		// we determined this v value is not protected, it must be a
		// raw 27 or 28.
		// 只有 EIP-155 签名可以选择性地受保护。由于我们确定这个 v 值未受保护，
		// 它必须是原始的 27 或 28。
		plainV = byte(v.Uint64() - 27)
	} else {
		// If the signature is not optionally protected, we assume it
		// must already be equal to the recovery id.
		// 如果签名未选择性地受保护，我们假设它必须已经等于恢复 ID。
		plainV = byte(v.Uint64()) // 假设 v 已是最小值（0 或 1）
	}
	if !crypto.ValidateSignatureValues(plainV, r, s, false) {
		return ErrInvalidSig
	}

	return nil
}

// 判断 v 是否受 EIP-155 保护。
func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 { // 如果 v 小于等于 8 位（即小于 256）
		v := V.Uint64()
		return v != 27 && v != 28 && v != 1 && v != 0 // 传统签名 v 为 27 或 28（加链 ID 前）类型化交易 v 为 0 或 1（yParity），其他值表示 EIP-155 保护。
	}
	// 大于 8 位（超出 255），视为受保护。
	// anything not 27 or 28 is considered protected
	// 任何不是 27 或 28 的值都被视为受保护
	return true
}

// Protected says whether the transaction is replay-protected.
func (tx *Transaction) Protected() bool {
	switch tx := tx.inner.(type) {
	case *LegacyTx:
		return tx.V != nil && isProtectedV(tx.V)
	default:
		return true
	}
}

// Type returns the transaction type.
// Type 返回交易类型。
func (tx *Transaction) Type() uint8 {
	return tx.inner.txType()
}

// ChainId returns the EIP155 chain ID of the transaction. The return value will always be
// non-nil. For legacy transactions which are not replay-protected, the return value is
// zero.
//
// ChainId 返回交易的 EIP-155 链 ID。返回值始终非 nil。
// 对于不受重放保护的传统交易，返回值为零。
func (tx *Transaction) ChainId() *big.Int {
	return tx.inner.chainID()
}

// Data returns the input data of the transaction.
// Data 返回交易的输入数据。
func (tx *Transaction) Data() []byte { return tx.inner.data() }

// AccessList returns the access list of the transaction.
// AccessList 返回交易的访问列表。
//
// 返回访问列表（EIP-2930），传统交易通常返回空。
func (tx *Transaction) AccessList() AccessList { return tx.inner.accessList() }

// Gas returns the gas limit of the transaction.
// Gas 返回交易的燃气限制。
func (tx *Transaction) Gas() uint64 { return tx.inner.gas() }

// GasPrice returns the gas price of the transaction.
// GasPrice 返回交易的燃气价格。
//
// 返回燃气价格（传统交易使用，EIP-1559 交易可能为 nil）
func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.inner.gasPrice()) }

// GasTipCap returns the gasTipCap per gas of the transaction.
// GasTipCap 返回交易的每单位燃气的燃气小费上限。
// 返回每单位燃气的小费上限（EIP-1559）
func (tx *Transaction) GasTipCap() *big.Int { return new(big.Int).Set(tx.inner.gasTipCap()) }

// GasFeeCap returns the fee cap per gas of the transaction.
// GasFeeCap 返回交易的每单位燃气的费用上限。
// 返回每单位燃气的费用上限（EIP-1559）。
func (tx *Transaction) GasFeeCap() *big.Int { return new(big.Int).Set(tx.inner.gasFeeCap()) }

// Value returns the ether amount of the transaction.
// Value 返回交易的以太金额。
func (tx *Transaction) Value() *big.Int { return new(big.Int).Set(tx.inner.value()) }

// Nonce returns the sender account nonce of the transaction.
// Nonce 返回交易的发送者账户 nonce。
func (tx *Transaction) Nonce() uint64 { return tx.inner.nonce() }

// To returns the recipient address of the transaction.
// For contract-creation transactions, To returns nil.
//
// To 返回交易的接收者地址。
// 对于合约创建交易，To 返回 nil。
func (tx *Transaction) To() *common.Address {
	return copyAddressPtr(tx.inner.to())
}

// Cost returns (gas * gasPrice) + (blobGas * blobGasPrice) + value.
// Cost 返回 (gas * gasPrice) + (blobGas * blobGasPrice) + value。
//
// 计算总成本：(gas * gasPrice) + (blobGas * blobGasPrice) + value。
// Blob 交易（EIP-4844）额外考虑 Blob 费用。
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(tx.Gas()))
	if tx.Type() == BlobTxType {
		total.Add(total, new(big.Int).Mul(tx.BlobGasFeeCap(), new(big.Int).SetUint64(tx.BlobGas())))
	}
	total.Add(total, tx.Value())
	return total
}

// RawSignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
// The return values may be nil or zero, if the transaction is unsigned.
//
// RawSignatureValues 返回交易的 V、R、S 签名值。
// 调用者不应修改返回值。
// 如果交易未签名，返回值可能为 nil 或零。
func (tx *Transaction) RawSignatureValues() (v, r, s *big.Int) {
	return tx.inner.rawSignatureValues()
}

// GasFeeCapCmp compares the fee cap of two transactions.
// 比较两个交易的燃气参数。
func (tx *Transaction) GasFeeCapCmp(other *Transaction) int {
	return tx.inner.gasFeeCap().Cmp(other.inner.gasFeeCap())
}

// GasFeeCapIntCmp compares the fee cap of the transaction against the given fee cap.
// 比较交易参数与给定值。
func (tx *Transaction) GasFeeCapIntCmp(other *big.Int) int {
	return tx.inner.gasFeeCap().Cmp(other)
}

// GasTipCapCmp compares the gasTipCap of two transactions.
func (tx *Transaction) GasTipCapCmp(other *Transaction) int {
	return tx.inner.gasTipCap().Cmp(other.inner.gasTipCap())
}

// GasTipCapIntCmp compares the gasTipCap of the transaction against the given gasTipCap.
func (tx *Transaction) GasTipCapIntCmp(other *big.Int) int {
	return tx.inner.gasTipCap().Cmp(other)
}

// EffectiveGasTip returns the effective miner gasTipCap for the given base fee.
// Note: if the effective gasTipCap is negative, this method returns both error
// the actual negative value, _and_ ErrGasFeeCapTooLow
//
// EffectiveGasTip 返回给定基础费用的有效矿工 gasTipCap。
// 注意：如果有效 gasTipCap 为负，此方法返回错误和实际负值，以及 ErrGasFeeCapTooLow。
//
// 计算交易支付给矿工的实际小费（effective gas tip），基于 EIP-1559 的规则
//
//	baseFee 区块基础费用
//	有效小费 = min(gasTipCap, gasFeeCap - baseFee)
//
// EIP-1559 机制:
//
//	gasFeeCap 是用户愿意支付的最大费用。
//	baseFee 是网络决定的基础费用。
//	gasTipCap 是矿工小费上限。
//	实际小费是 min(gasTipCap, gasFeeCap - baseFee)。
func (tx *Transaction) EffectiveGasTip(baseFee *big.Int) (*big.Int, error) {
	if baseFee == nil { // 这适用于传统交易或无基础费用的场景。
		return tx.GasTipCap(), nil
	}
	var err error
	gasFeeCap := tx.GasFeeCap()     // 获取交易的燃气费用上限
	if gasFeeCap.Cmp(baseFee) < 0 { // 表示费用上限不足以支付基础费用。
		err = ErrGasFeeCapTooLow
	}
	gasFeeCap = gasFeeCap.Sub(gasFeeCap, baseFee) // 计算 gasFeeCap - baseFee，表示基础费用之外的可用费用

	gasTipCap := tx.GasTipCap()       // 获取交易的小费上限（gasTipCap）。
	if gasTipCap.Cmp(gasFeeCap) < 0 { // 表示小费上限是限制因素。
		return gasTipCap, err
	}
	return gasFeeCap, err
}

// EffectiveGasTipValue is identical to EffectiveGasTip, but does not return an
// error in case the effective gasTipCap is negative
func (tx *Transaction) EffectiveGasTipValue(baseFee *big.Int) *big.Int {
	effectiveTip, _ := tx.EffectiveGasTip(baseFee)
	return effectiveTip
}

// EffectiveGasTipCmp compares the effective gasTipCap of two transactions assuming the given base fee.
func (tx *Transaction) EffectiveGasTipCmp(other *Transaction, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other.EffectiveGasTipValue(baseFee))
}

// EffectiveGasTipIntCmp compares the effective gasTipCap of a transaction to the given gasTipCap.
func (tx *Transaction) EffectiveGasTipIntCmp(other *big.Int, baseFee *big.Int) int {
	if baseFee == nil {
		return tx.GasTipCapIntCmp(other)
	}
	return tx.EffectiveGasTipValue(baseFee).Cmp(other)
}

// BlobGas returns the blob gas limit of the transaction for blob transactions, 0 otherwise.
//
// BlobGas 返回 Blob 交易的 Blob 燃气限制，否则返回 0。
func (tx *Transaction) BlobGas() uint64 {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.blobGas()
	}
	return 0
}

// BlobGasFeeCap returns the blob gas fee cap per blob gas of the transaction for blob transactions, nil otherwise.
//
// BlobGasFeeCap 返回 Blob 交易的每 Blob 燃气的 Blob 燃气费用上限，否则返回 nil。
func (tx *Transaction) BlobGasFeeCap() *big.Int {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.BlobFeeCap.ToBig()
	}
	return nil
}

// BlobHashes returns the hashes of the blob commitments for blob transactions, nil otherwise.
//
// BlobHashes 返回 Blob 交易的 Blob 承诺哈希，否则返回 nil。
func (tx *Transaction) BlobHashes() []common.Hash {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.BlobHashes
	}
	return nil
}

// BlobTxSidecar returns the sidecar of a blob transaction, nil otherwise.
//
// BlobTxSidecar 返回 Blob 交易的sidecar数据，否则返回 nil。
func (tx *Transaction) BlobTxSidecar() *BlobTxSidecar {
	if blobtx, ok := tx.inner.(*BlobTx); ok {
		return blobtx.Sidecar
	}
	return nil
}

// BlobGasFeeCapCmp compares the blob fee cap of two transactions.
func (tx *Transaction) BlobGasFeeCapCmp(other *Transaction) int {
	return tx.BlobGasFeeCap().Cmp(other.BlobGasFeeCap())
}

// BlobGasFeeCapIntCmp compares the blob fee cap of the transaction against the given blob fee cap.
func (tx *Transaction) BlobGasFeeCapIntCmp(other *big.Int) int {
	return tx.BlobGasFeeCap().Cmp(other)
}

// WithoutBlobTxSidecar returns a copy of tx with the blob sidecar removed.
func (tx *Transaction) WithoutBlobTxSidecar() *Transaction {
	blobtx, ok := tx.inner.(*BlobTx)
	if !ok {
		return tx
	}
	cpy := &Transaction{
		inner: blobtx.withoutSidecar(),
		time:  tx.time,
	}
	// Note: tx.size cache not carried over because the sidecar is included in size!
	if h := tx.hash.Load(); h != nil {
		cpy.hash.Store(h)
	}
	if f := tx.from.Load(); f != nil {
		cpy.from.Store(f)
	}
	return cpy
}

// WithBlobTxSidecar returns a copy of tx with the blob sidecar added.
func (tx *Transaction) WithBlobTxSidecar(sideCar *BlobTxSidecar) *Transaction {
	blobtx, ok := tx.inner.(*BlobTx)
	if !ok {
		return tx
	}
	cpy := &Transaction{
		inner: blobtx.withSidecar(sideCar),
		time:  tx.time,
	}
	// Note: tx.size cache not carried over because the sidecar is included in size!
	if h := tx.hash.Load(); h != nil {
		cpy.hash.Store(h)
	}
	if f := tx.from.Load(); f != nil {
		cpy.from.Store(f)
	}
	return cpy
}

// SetCodeAuthorizations returns the authorizations list of the transaction.
func (tx *Transaction) SetCodeAuthorizations() []SetCodeAuthorization {
	setcodetx, ok := tx.inner.(*SetCodeTx)
	if !ok {
		return nil
	}
	return setcodetx.AuthList
}

// SetTime sets the decoding time of a transaction. This is used by tests to set
// arbitrary times and by persistent transaction pools when loading old txs from
// disk.
//
// SetTime 设置交易的解码时间。此方法用于测试中设置任意时间，以及在持久化交易池中从磁盘加载旧交易时使用。
func (tx *Transaction) SetTime(t time.Time) {
	tx.time = t
}

// Time returns the time when the transaction was first seen on the network. It
// is a heuristic to prefer mining older txs vs new all other things equal.
//
// Time 返回交易首次在网络上被看到的时间。这是一个启发式方法，用于在其他条件相同的情况下优先挖掘较旧的交易。
func (tx *Transaction) Time() time.Time {
	return tx.time
}

// Hash returns the transaction hash.
// Hash 返回交易的哈希值。
func (tx *Transaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return *hash
	}

	var h common.Hash
	if tx.Type() == LegacyTxType {
		h = rlpHash(tx.inner)
	} else {
		h = prefixedRlpHash(tx.Type(), tx.inner)
	}
	tx.hash.Store(&h)
	return h
}

// Size returns the true encoded storage size of the transaction, either by encoding
// and returning it, or returning a previously cached value.
// Size 返回交易的真实编码存储大小，可以通过编码计算并返回，或者返回之前缓存的值。
func (tx *Transaction) Size() uint64 {
	if size := tx.size.Load(); size > 0 {
		return size
	}

	// Cache miss, encode and cache.
	// Note we rely on the assumption that all tx.inner values are RLP-encoded!
	// 缓存未命中，编码并缓存。
	// 注意：我们依赖于所有 tx.inner 值都是 RLP 编码的假设！
	c := writeCounter(0)
	rlp.Encode(&c, &tx.inner)
	size := uint64(c)

	// For blob transactions, add the size of the blob content and the outer list of the
	// tx + sidecar encoding.
	// 对于 Blob 交易，添加 Blob 内容的大小以及交易和侧车编码的外部列表大小。
	if sc := tx.BlobTxSidecar(); sc != nil {
		size += rlp.ListSize(sc.encodedSize())
	}

	// For typed transactions, the encoding also includes the leading type byte.
	if tx.Type() != LegacyTxType {
		size += 1
	}

	tx.size.Store(size)
	return size
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be in the [R || S || V] format where V is 0 or 1.
//
// WithSignature 返回一个带有给定签名的新交易。
// 该签名需要采用 [R || S || V] 格式，其中 V 为 0 或 1。
//
// 为交易添加签名，生成新的签名交易实例。
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	if r == nil || s == nil || v == nil {
		return nil, fmt.Errorf("%w: r: %s, s: %s, v: %s", ErrInvalidSig, r, s, v)
	}
	cpy := tx.inner.copy()
	cpy.setSignatureValues(signer.ChainID(), v, r, s)
	return &Transaction{inner: cpy, time: tx.time}, nil
}

// Transactions implements DerivableList for transactions.
// Transactions 为交易实现了 DerivableList 接口。
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// EncodeIndex encodes the i'th transaction to w. Note that this does not check for errors
// because we assume that *Transaction will only ever contain valid txs that were either
// constructed by decoding or via public API in this package.
//
// EncodeIndex 将第 i 个交易编码到 w 中。注意，此方法不检查错误，
// 因为我们假设 *Transaction 只包含通过解码或此包的公共 API 构造的有效交易。
func (s Transactions) EncodeIndex(i int, w *bytes.Buffer) {
	tx := s[i]
	if tx.Type() == LegacyTxType {
		rlp.Encode(w, tx.inner)
	} else {
		tx.encodeTyped(w)
	}
}

// TxDifference returns a new set of transactions that are present in a but not in b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{}, b.Len())
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}

// HashDifference returns a new set of hashes that are present in a but not in b.
func HashDifference(a, b []common.Hash) []common.Hash {
	keep := make([]common.Hash, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, hash := range b {
		remove[hash] = struct{}{}
	}

	for _, hash := range a {
		if _, ok := remove[hash]; !ok {
			keep = append(keep, hash)
		}
	}

	return keep
}

// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
//
// TxByNonce 实现了 sort 接口，以允许按交易的 nonce 排序交易列表。
// 这通常只对来自单个账户的交易排序有用，否则 nonce 比较没有太大意义。
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Nonce() < s[j].Nonce() }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// copyAddressPtr copies an address.
// copyAddressPtr 复制一个地址。
func copyAddressPtr(a *common.Address) *common.Address {
	if a == nil {
		return nil
	}
	cpy := *a
	return &cpy
}
