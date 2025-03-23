// Copyright 2016 The go-ethereum Authors
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
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var ErrInvalidChainId = errors.New("invalid chain id for signer")

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
//
// sigCache 用于缓存派生的发送者，并包含用于派生的签名者。
type sigCache struct {
	signer Signer         // 签名者接口，用于从交易签名中派生发送者地址。
	from   common.Address // 缓存的发送者地址（以太坊账户地址）。 发送者地址通过公钥哈希（Keccak-256）生成，是交易的核心元数据，用于验证和记账。
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *params.ChainConfig, blockNumber *big.Int, blockTime uint64) Signer {
	var signer Signer
	switch {
	case config.IsPrague(blockNumber, blockTime):
		signer = NewPragueSigner(config.ChainID)
	case config.IsCancun(blockNumber, blockTime):
		signer = NewCancunSigner(config.ChainID)
	case config.IsLondon(blockNumber):
		signer = NewLondonSigner(config.ChainID)
	case config.IsBerlin(blockNumber):
		signer = NewEIP2930Signer(config.ChainID)
	case config.IsEIP155(blockNumber):
		signer = NewEIP155Signer(config.ChainID)
	case config.IsHomestead(blockNumber):
		signer = HomesteadSigner{}
	default:
		signer = FrontierSigner{}
	}
	return signer
}

// LatestSigner returns the 'most permissive' Signer available for the given chain
// configuration. Specifically, this enables support of all types of transactions
// when their respective forks are scheduled to occur at any block number (or time)
// in the chain config.
//
// Use this in transaction-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestSigner(config *params.ChainConfig) Signer {
	var signer Signer
	if config.ChainID != nil {
		switch {
		case config.PragueTime != nil:
			signer = NewPragueSigner(config.ChainID)
		case config.CancunTime != nil:
			signer = NewCancunSigner(config.ChainID)
		case config.LondonBlock != nil:
			signer = NewLondonSigner(config.ChainID)
		case config.BerlinBlock != nil:
			signer = NewEIP2930Signer(config.ChainID)
		case config.EIP155Block != nil:
			signer = NewEIP155Signer(config.ChainID)
		default:
			signer = HomesteadSigner{}
		}
	} else {
		signer = HomesteadSigner{}
	}
	return signer
}

// LatestSignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for EIP-155 replay protection and all implemented EIP-2718
// transaction types if chainID is non-nil.
//
// Use this in transaction-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestSignerForChainID(chainID *big.Int) Signer {
	var signer Signer
	if chainID != nil {
		signer = NewPragueSigner(chainID)
	} else {
		signer = HomesteadSigner{}
	}
	return signer
}

// SignTx signs the transaction using the given signer and private key.
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

// SignNewTx creates a transaction and signs it.
func SignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) (*Transaction, error) {
	return SignTx(NewTx(txdata), s, prv)
}

// MustSignNewTx creates a transaction and signs it.
// This panics if the transaction cannot be signed.
func MustSignNewTx(prv *ecdsa.PrivateKey, s Signer, txdata TxData) *Transaction {
	tx, err := SignNewTx(prv, s, txdata)
	if err != nil {
		panic(err)
	}
	return tx
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sigCache := tx.from.Load(); sigCache != nil {
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(&sigCache{signer: signer, from: addr})
	return addr, nil
}

// Signer encapsulates transaction signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
//
// Signer 封装了交易签名处理。这个类型的名称有些误导，因为 Signer 实际上并不签名，
// 它们仅用于验证和处理签名。
//
// 请注意，此接口不是稳定的 API，可能会随时更改以适应新的协议规则。
type Signer interface {
	// Sender returns the sender address of the transaction.
	// 返回交易的发送者地址
	// 通过交易的签名和哈希，使用椭圆曲线数字签名算法（ECDSA）恢复公钥，再从公钥推导出以太坊地址。
	// 以太坊地址是从公钥的 Keccak-256 哈希取后 20 字节生成的。签名验证基于 EIP-155（引入 ChainID 以防止跨链重放攻击）。
	Sender(tx *Transaction) (common.Address, error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	// 返回给定签名对应的原始 R、S、V 值
	// 以太坊签名通常是 65 字节（R: 32 字节，S: 32 字节，V: 1 字节）。此方法将字节数组解码为大整数。
	// R 和 S 是 ECDSA 签名的核心参数，V 是恢复标识符，用于确定公钥的正确恢复路径。EIP-155 调整了 V 的计算方式，加入了 ChainID。
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	ChainID() *big.Int // ChainID 是 EIP-155 引入的概念，用于区分不同以太坊网络（如主网 ChainID=1，Ropsten ChainID=3），防止交易在不同链上重放。

	// Hash returns 'signature hash', i.e. the transaction hash that is signed by the
	// private key. This hash does not uniquely identify the transaction.
	// 返回“签名哈希”，即由私钥签名的交易哈希。此哈希并不能唯一标识交易
	// 对交易数据进行编码（通常使用 RLP 编码），然后计算 Keccak-256 哈希。
	// 签名哈希是私钥签名的目标值，但它不包括 nonce 等字段，因此不唯一标识交易。
	Hash(tx *Transaction) common.Hash

	// Equal returns true if the given signer is the same as the receiver.
	// 如果给定的 signer 与接收者相同，则返回 true
	// 比较两个 Signer 是否相同。通常比较 ChainID 或其他实现细节。
	Equal(Signer) bool
}

// pragueSigner 是 Signer 接口的一个实现，支持 EIP-7702 设置代码交易（Set Code Transactions），
// 同时通过嵌入 cancunSigner 兼容 EIP-4844、EIP-1559、EIP-2930、EIP-155 和 Homestead 交易。
// 它是为布拉格硬分叉设计的最新签名者。
//
//	EIP-7702（布拉格硬分叉提案）引入设置代码交易，交易类型为 0x04，允许动态修改账户代码。
//	EIP-7702：V 为 0 或 1，不嵌入 ChainID，与后续交易类型一致。
//	EIP-7702：引入 SetCodeAuthorizations，允许授权修改账户代码。
//	布拉格硬分叉提案，交易类型为 0x04，允许通过交易设置账户代码，支持账户抽象和 EOA 升级。
type pragueSigner struct{ cancunSigner }

// NewPragueSigner returns a signer that accepts
// - EIP-7702 set code transactions
// - EIP-4844 blob transactions
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
//
// NewPragueSigner 返回一个签名者，支持以下交易类型：
// - EIP-7702 设置代码交易
// - EIP-4844 Blob 交易
// - EIP-1559 动态费用交易
// - EIP-2930 访问列表交易
// - EIP-155 重放保护交易
// - 传统的 Homestead 交易
func NewPragueSigner(chainId *big.Int) Signer {
	// 创建并返回支持布拉格规则的签名者，基于 cancunSigner
	signer, _ := NewCancunSigner(chainId).(cancunSigner)
	return pragueSigner{signer}
}

func (s pragueSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != SetCodeTxType {
		// 如果不是设置代码交易，交给 cancunSigner 处理
		return s.cancunSigner.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()

	// Set code txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	// 设置代码交易的 V 为 0 或 1，加 27 以匹配未保护的 Homestead 签名格式
	V = new(big.Int).Add(V, big.NewInt(27))
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func (s pragueSigner) Equal(s2 Signer) bool {
	x, ok := s2.(pragueSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s pragueSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*SetCodeTx)
	if !ok {
		// 如果不是设置代码交易，交给 cancunSigner 处理
		return s.cancunSigner.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	// 检查交易的 ChainID 是否匹配签名者的 ChainID，允许 ChainID 为 nil（未指定）
	if txdata.ChainID != nil && txdata.ChainID.CmpBig(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
	}
	// 解析签名数据，提取 R、S
	R, S, _ = decodeSignature(sig)
	V = big.NewInt(int64(sig[64]))
	// 直接从签名末字节取 V（0 或 1）
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
//
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (s pragueSigner) Hash(tx *Transaction) common.Hash {
	if tx.Type() != SetCodeTxType {
		// 如果不是设置代码交易，交给 cancunSigner 处理
		return s.cancunSigner.Hash(tx)
	}
	// 计算设置代码交易的签名哈希
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
			tx.SetCodeAuthorizations(),
		})
}

// cancunSigner 是 Signer 接口的一个实现，支持 EIP-4844 Blob 交易（坎昆硬分叉引入），
// 同时通过嵌入 londonSigner 兼容 EIP-1559、EIP-2930、EIP-155 和 Homestead 交易。
// 它是坎昆硬分叉（预计 2024 年）后以太坊交易处理的最新实现。
//
//	EIP-4844（分片 Blob 交易）引入 Blob 数据存储，交易类型为 0x03
//	EIP-4844：V 为 0 或 1，不嵌入 ChainID，与 EIP-1559 和 EIP-2930 类似。
//	EIP-4844：引入 Blob Gas 费用和 Blob 数据哈希，用于分片数据存储。
type cancunSigner struct{ londonSigner }

// NewCancunSigner returns a signer that accepts
// - EIP-4844 blob transactions
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
//
// NewCancunSigner 返回一个签名者，支持以下交易类型：
// - EIP-4844 Blob 交易
// - EIP-1559 动态费用交易
// - EIP-2930 访问列表交易
// - EIP-155 重放保护交易
// - 传统的 Homestead 交易
func NewCancunSigner(chainId *big.Int) Signer {
	// 创建并返回支持坎昆规则的签名者，基于 londonSigner、eip2930Signer 和 EIP155Signer
	return cancunSigner{londonSigner{eip2930Signer{NewEIP155Signer(chainId)}}}
}

func (s cancunSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != BlobTxType {
		// 如果不是 Blob 交易，交给 londonSigner 处理
		return s.londonSigner.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()
	// Blob txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	// Blob 交易的 V 为 0 或 1，加 27 以匹配未保护的 Homestead 签名格式
	V = new(big.Int).Add(V, big.NewInt(27))
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func (s cancunSigner) Equal(s2 Signer) bool {
	x, ok := s2.(cancunSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s cancunSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*BlobTx)
	if !ok {
		// 如果不是 Blob 交易，交给 londonSigner 处理
		return s.londonSigner.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	// 检查交易的 ChainID 是否匹配签名者的 ChainID，允许 ChainID 为 0（未指定）
	if txdata.ChainID.Sign() != 0 && txdata.ChainID.ToBig().Cmp(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
	}
	// 解析签名数据，提取 R、S
	R, S, _ = decodeSignature(sig)
	// 直接从签名末字节取 V（0 或 1）
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (s cancunSigner) Hash(tx *Transaction) common.Hash {
	if tx.Type() != BlobTxType {
		// 如果不是 Blob 交易，交给 londonSigner 处理
		return s.londonSigner.Hash(tx)
	}
	// 计算 Blob 交易的签名哈希
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
			tx.BlobGasFeeCap(),
			tx.BlobHashes(),
		})
}

// londonSigner 是 Signer 接口的一个实现，支持 EIP-1559 动态费用交易（Dynamic Fee Transactions），
// 同时通过嵌入 eip2930Signer 兼容 EIP-2930、EIP-155 和 Homestead 交易。
// 它是伦敦硬分叉（2021 年）后以太坊交易处理的完整实现。
//
//	EIP-1559（伦敦硬分叉）引入动态费用机制，交易类型为 0x02。
//	EIP-1559 签名格式与 EIP-2930 一致，V 未嵌入 ChainID
//	EIP-1559 引入基础费用和优先费，哈希计算需包含新字段。
type londonSigner struct{ eip2930Signer }

// NewLondonSigner returns a signer that accepts
// - EIP-1559 dynamic fee transactions
// - EIP-2930 access list transactions,
// - EIP-155 replay protected transactions, and
// - legacy Homestead transactions.
//
// NewLondonSigner 返回一个签名者，支持以下交易类型：
// - EIP-1559 动态费用交易
// - EIP-2930 访问列表交易
// - EIP-155 重放保护交易
// - 传统的 Homestead 交易
func NewLondonSigner(chainId *big.Int) Signer {
	// 创建并返回支持伦敦规则的签名者，基于 eip2930Signer 和 EIP155Signer
	return londonSigner{eip2930Signer{NewEIP155Signer(chainId)}}
}

func (s londonSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != DynamicFeeTxType {
		// 如果不是动态费用交易，交给 eip2930Signer 处理
		return s.eip2930Signer.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()
	// DynamicFee txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	// 动态费用交易的 V 为 0 或 1，加 27 以匹配未保护的 Homestead 签名格式
	V = new(big.Int).Add(V, big.NewInt(27))
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func (s londonSigner) Equal(s2 Signer) bool {
	x, ok := s2.(londonSigner)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s londonSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	txdata, ok := tx.inner.(*DynamicFeeTx)
	if !ok {
		// 如果不是动态费用交易，交给 eip2930Signer 处理
		return s.eip2930Signer.SignatureValues(tx, sig)
	}
	// Check that chain ID of tx matches the signer. We also accept ID zero here,
	// because it indicates that the chain ID was not specified in the tx.
	// 检查交易的 ChainID 是否匹配签名者的 ChainID，允许 ChainID 为 0（未指定）
	if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
	}
	// 解析签名数据，提取 R、S
	R, S, _ = decodeSignature(sig)
	// 直接从签名末字节取 V（0 或 1）
	V = big.NewInt(int64(sig[64]))
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (s londonSigner) Hash(tx *Transaction) common.Hash {
	if tx.Type() != DynamicFeeTxType {
		// 如果不是动态费用交易，交给 eip2930Signer 处理
		return s.eip2930Signer.Hash(tx)
	}
	// 计算动态费用交易的签名哈希
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.Nonce(),
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
			tx.AccessList(),
		})
}

// EIP-2930（柏林硬分叉，2021 年）引入了访问列表交易，优化 Gas 计算。
type eip2930Signer struct{ EIP155Signer }

// NewEIP2930Signer returns a signer that accepts EIP-2930 access list transactions,
// EIP-155 replay protected transactions, and legacy Homestead transactions.
// NewEIP2930Signer 返回一个签名者，支持 EIP-2930 访问列表交易、EIP-155 重放保护交易以及传统的 Homestead 交易。
func NewEIP2930Signer(chainId *big.Int) Signer {
	// 创建并返回支持 EIP-2930 的签名者，基于 EIP155Signer
	return eip2930Signer{NewEIP155Signer(chainId)}
}

func (s eip2930Signer) ChainID() *big.Int {
	return s.chainId
}

func (s eip2930Signer) Equal(s2 Signer) bool {
	x, ok := s2.(eip2930Signer)
	return ok && x.chainId.Cmp(s.chainId) == 0
}

func (s eip2930Signer) Sender(tx *Transaction) (common.Address, error) {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case LegacyTxType:
		// 处理传统交易，调用 EIP155Signer 的 Sender 方法
		return s.EIP155Signer.Sender(tx)
	case AccessListTxType:
		// AL txs are defined to use 0 and 1 as their recovery
		// id, add 27 to become equivalent to unprotected Homestead signatures.
		//
		// 访问列表交易的 V 为 0 或 1，加 27 以匹配未保护的 Homestead 签名格式
		// EIP-2930：V 为 0 或 1，不包含 ChainID，需手动调整。
		V = new(big.Int).Add(V, big.NewInt(27))
	default:
		// 不支持的交易类型，返回错误
		return common.Address{}, ErrTxTypeNotSupported
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	// 使用签名哈希和 R、S、V 恢复发送者地址
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func (s eip2930Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	switch txdata := tx.inner.(type) {
	case *LegacyTx:
		// 处理传统交易，调用 EIP155Signer 的 SignatureValues 方法
		return s.EIP155Signer.SignatureValues(tx, sig)
	case *AccessListTx:
		// Check that chain ID of tx matches the signer. We also accept ID zero here,
		// because it indicates that the chain ID was not specified in the tx.
		// 检查交易的 ChainID 是否匹配签名者的 ChainID，允许 ChainID 为 0（未指定）
		if txdata.ChainID.Sign() != 0 && txdata.ChainID.Cmp(s.chainId) != 0 {
			return nil, nil, nil, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, txdata.ChainID, s.chainId)
		}
		// 解析签名数据，提取 R、S
		R, S, _ = decodeSignature(sig)
		// 直接从签名末字节取 V（0 或 1）
		V = big.NewInt(int64(sig[64]))
	default:
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (s eip2930Signer) Hash(tx *Transaction) common.Hash {
	switch tx.Type() {
	case LegacyTxType:
		// 处理传统交易，调用 EIP155Signer 的 Hash 方法
		return s.EIP155Signer.Hash(tx)
	case AccessListTxType:
		// 计算 EIP-2930 访问列表交易的签名哈希
		return prefixedRlpHash(
			tx.Type(),
			[]interface{}{
				s.chainId,
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(), // EIP-2930 引入访问列表字段，哈希计算需包含此字段。
			})
	default:
		// This _should_ not happen, but in case someone sends in a bad
		// json struct via RPC, it's probably more prudent to return an
		// empty hash instead of killing the node with a panic
		//panic("Unsupported transaction type: %d", tx.typ)
		return common.Hash{}
	}
}

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
// EIP155Signer 使用 EIP-155 规则实现了 Signer 接口。它接受受重放保护的交易以及不受保护的 Homestead 交易。
type EIP155Signer struct {
	chainId, chainIdMul *big.Int
}

// NewEIP155Signer EIP-155 定义了签名中 V 的计算方式：V = ChainID * 2 + 35 或 36。
func NewEIP155Signer(chainId *big.Int) EIP155Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155Signer{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155Signer) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155Signer) Equal(s2 Signer) bool {
	eip155, ok := s2.(EIP155Signer)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

// Sender 从交易中恢复发送者地址。
func (s EIP155Signer) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType { // 检查交易类型，仅支持 LegacyTxType
		return common.Address{}, ErrTxTypeNotSupported
	}
	if !tx.Protected() {
		// 如果交易不受保护，则使用 HomesteadSigner 处理
		return HomesteadSigner{}.Sender(tx)
	}
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Sub(V, s.chainIdMul)
	V.Sub(V, big8) // 从 V 中减去 8 以恢复原始值
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
// SignatureValues 返回签名值。此签名需要采用 [R || S || V] 格式，其中 V 为 0 或 1。
func (s EIP155Signer) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	R, S, V = decodeSignature(sig) // 使用 decodeSignature 解析 65 字节签名。
	if s.chainId.Sign() != 0 {     // 若 ChainID 非 0，按 EIP-155 规则调整 V（sig[64] + 35 + chainIdMul）。
		// 根据 EIP-155 规则调整 V 值
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (s EIP155Signer) Hash(tx *Transaction) common.Hash {
	// 对交易字段（包括 ChainID 和占位符 0、0）进行 RLP 编码，再计算 Keccak-256 哈希。
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		s.chainId, uint(0), uint(0),
	})
}

// HomesteadSigner implements Signer interface using the
// homestead rules.
//
// HomesteadSigner 使用 Homestead 规则实现了 Signer 接口。
type HomesteadSigner struct{ FrontierSigner }

func (hs HomesteadSigner) ChainID() *big.Int {
	return nil
}

func (hs HomesteadSigner) Equal(s2 Signer) bool {
	_, ok := s2.(HomesteadSigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
// SignatureValues 返回签名值。此签名需要采用 [R || S || V] 格式，其中 V 为 0 或 1。
func (hs HomesteadSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	// Homestead 和 Frontier 的签名解析逻辑相同，V 仍为 0 或 1（加 27 后为 27 或 28）。
	return hs.FrontierSigner.SignatureValues(tx, sig)
}

func (hs HomesteadSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	return recoverPlain(hs.Hash(tx), r, s, v, true)
}

// FrontierSigner implements Signer interface using the
// frontier rules.
// FrontierSigner 使用 Frontier 规则实现了 Signer 接口。
// 基于以太坊最初的 Frontier 阶段规则。它处理最原始的交易签名格式，不包含 ChainID 或重放保护机制，适用于以太坊早期版本的交易验证。
// Frontier 是以太坊 2015 年上线的第一个版本，交易签名不包含网络标识。
type FrontierSigner struct{}

func (fs FrontierSigner) ChainID() *big.Int {
	return nil
}

func (fs FrontierSigner) Equal(s2 Signer) bool {
	_, ok := s2.(FrontierSigner)
	return ok
}

func (fs FrontierSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != LegacyTxType {
		return common.Address{}, ErrTxTypeNotSupported
	}
	v, r, s := tx.RawSignatureValues()
	// 使用 recoverPlain 通过签名哈希和 R、S、V 恢复地址，homestead=false 表示使用 Frontier 规则。
	// V 值：在 Frontier 中，V 仅为 27 或 28（无 ChainID 调整）。
	return recoverPlain(fs.Hash(tx), r, s, v, false)
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
// SignatureValues 返回签名值。此签名需要采用 [R || S || V] 格式，其中 V 为 0 或 1。
func (fs FrontierSigner) SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if tx.Type() != LegacyTxType {
		return nil, nil, nil, ErrTxTypeNotSupported
	}
	r, s, v = decodeSignature(sig)
	return r, s, v, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
// Hash 返回发送者需要签名的哈希值。
// 它并不能唯一标识交易。
func (fs FrontierSigner) Hash(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
	})
}

func decodeSignature(sig []byte) (r, s, v *big.Int) {
	// 如果签名长度错误，则抛出异常 以太坊标准签名长度65字节 以太坊签名固定为 65 字节，其中 R（32 字节）、S（32 字节）、V（1 字节）
	if len(sig) != crypto.SignatureLength {
		panic(fmt.Sprintf("wrong size for signature: got %d, want %d", len(sig), crypto.SignatureLength))
	}
	// 从前 32 字节提取 R 值
	r = new(big.Int).SetBytes(sig[:32])
	// 从 32-64 字节提取 S 值
	s = new(big.Int).SetBytes(sig[32:64])
	// 从第 64 字节提取 V 值并加 27
	// sig[64] 是原始 V 值（通常为 0 或 1）,加 27 调整为以太坊早期格式的 27 或 28。
	// V 是恢复标识符，用于确定 ECDSA 公钥恢复的正确路径。
	// 在 Frontier 和 Homestead 阶段，V 为 27 或 28；EIP-155 后，V 被扩展为包含 ChainID。
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v
}

// recoverPlain 函数通过签名哈希（sighash）和签名值（R、S、V）恢复以太坊交易的发送者地址。
// 它是基于 ECDSA 签名验证的核心工具，适用于早期以太坊交易格式（如 Frontier 和 Homestead）。
func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	// V 在早期以太坊中通常为 27 或 28（对应 0 或 1 加 27），不应超过 255
	if Vb.BitLen() > 8 {
		// 如果 V 的位长度超过 8，则签名无效
		return common.Address{}, ErrInvalidSig
	}
	// 将 Vb 转换为字节并减去 27
	// 早期以太坊签名中，V 被加 27 以适配 ECDSA 标准，此处逆向调整
	V := byte(Vb.Uint64() - 27)
	// Frontier：V 为 0 或 1，R 和 S 有范围限制。
	// Homestead：增加了签名值约束（如 S 的上限）。
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.Address{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	// 以未压缩格式编码签名
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	// 从签名中恢复公钥
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	// 公钥应为 65 字节未压缩格式，前缀为 0x04
	// 以太坊公钥为 64 字节（X、Y 坐标），加上 1 字节前缀
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	// 从公钥计算地址，取 Keccak256 哈希的后 20 字节
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// deriveChainId derives the chain id from the given v parameter
// deriveChainId 从给定的 v 参数中推导出链 ID
func deriveChainId(v *big.Int) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 { // 如果 v 为 27 或 28，则返回 0，表示无链 ID
			return new(big.Int)
		}
		// 根据 EIP-155 规则计算链 ID: (v - 35) / 2
		return new(big.Int).SetUint64((v - 35) / 2)
	}
	// 早期 V 值较小（27 或 28），EIP-155 后可能包含 ChainID，值会变大
	// 对于大整数 v，减去 35
	vCopy := new(big.Int).Sub(v, big.NewInt(35))
	// 右移 1 位，相当于除以 2
	return vCopy.Rsh(vCopy, 1)
}
