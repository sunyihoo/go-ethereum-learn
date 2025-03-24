// Copyright 2017 The go-ethereum Authors
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

//go:build nacl || js || !cgo || gofuzz
// +build nacl js !cgo gofuzz

package crypto

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decred_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Ecrecover returns the uncompressed public key that created the given signature.
// Ecrecover 返回创建给定签名的未压缩公钥。
func Ecrecover(hash, sig []byte) ([]byte, error) {
	pub, err := sigToPub(hash, sig)
	if err != nil {
		return nil, err
	}
	// 将公钥序列化为未压缩格式字节数组
	bytes := pub.SerializeUncompressed()
	return bytes, err
}

// sigToPub 从签名和哈希恢复 secp256k1 公钥。
func sigToPub(hash, sig []byte) (*secp256k1.PublicKey, error) {
	// 检查签名长度
	if len(sig) != SignatureLength {
		return nil, errors.New("invalid signature")
	}
	// Convert to secp256k1 input format with 'recovery id' v at the beginning.
	// 转换为 secp256k1 输入格式，v 在开头
	btcsig := make([]byte, SignatureLength)
	// 以太坊签名 V 在末尾（偏移 64），早期为 0/1，后调整为 27/28（EIP-155 后包含链 ID）。
	// decred_ecdsa 期望 V 在开头，需转换。
	btcsig[0] = sig[RecoveryIDOffset] + 27
	copy(btcsig[1:], sig)

	// 使用 decred_ecdsa 恢复公钥
	pub, _, err := decred_ecdsa.RecoverCompact(btcsig, hash)
	return pub, err
}

// SigToPub returns the public key that created the given signature.
// SigToPub 返回创建给定签名的公钥。
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	pub, err := sigToPub(hash, sig)
	if err != nil {
		return nil, err
	}
	// We need to explicitly set the curve here, because we're wrapping
	// the original curve to add (un-)marshalling
	// 转换为 ecdsa.PublicKey 并设置曲线
	return &ecdsa.PublicKey{
		Curve: S256(),
		X:     pub.X(),
		Y:     pub.Y(),
	}, nil
}

// Sign calculates an ECDSA signature.
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given hash cannot be chosen by an adversary. Common
// solution is to hash any input before calculating the signature.
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
//
// Sign 计算 ECDSA 签名。
// 此函数易受选择明文攻击，可能泄露私钥信息。调用者需确保哈希不可由攻击者选择。
// 生成的签名格式为 [R || S || V]，V 为 0 或 1。
func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	// 检查私钥曲线
	if prv.Curve != S256() {
		return nil, errors.New("private key curve is not secp256k1")
	}
	// ecdsa.PrivateKey -> secp256k1.PrivateKey
	// 将 ecdsa.PrivateKey 转换为 secp256k1.PrivateKey
	var priv secp256k1.PrivateKey
	if overflow := priv.Key.SetByteSlice(prv.D.Bytes()); overflow || priv.Key.IsZero() {
		return nil, errors.New("invalid private key")
	}
	// 清零私钥
	defer priv.Zero()
	// 生成签名
	sig := decred_ecdsa.SignCompact(&priv, hash, false) // ref uncompressed pubkey
	// Convert to Ethereum signature format with 'recovery id' v at the end.
	// 转换为以太坊格式，V 在末尾
	// 调整为以太坊格式（R || S || V），V 从 27/28 转为 0/1。
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[RecoveryIDOffset] = v
	return sig, nil
}

// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
//
// VerifySignature 检查公钥是否创建了针对哈希的签名。
// 公钥应为压缩（33 字节）或未压缩（65 字节）格式。
// 签名应为 64 字节 [R || S] 格式。
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	// 将签名拆分为 R 和 S
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(signature[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	sig := decred_ecdsa.NewSignature(&r, &s)
	// 解析公钥
	key, err := secp256k1.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but decred doesn't.
	// 拒绝可塑签名
	if s.IsOverHalfOrder() {
		return false
	}
	// 验证签名
	return sig.Verify(hash, key)
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// DecompressPubkey 解析 33 字节压缩格式的公钥。
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, errors.New("invalid compressed public key length")
	}
	key, err := secp256k1.ParsePubKey(pubkey)
	if err != nil {
		return nil, err
	}
	// We need to explicitly set the curve here, because we're wrapping
	// the original curve to add (un-)marshalling
	// 转换为 ecdsa.PublicKey
	return &ecdsa.PublicKey{
		Curve: S256(),
		X:     key.X(),
		Y:     key.Y(),
	}, nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format. The
// provided PublicKey must be valid. Namely, the coordinates must not be larger
// than 32 bytes each, they must be less than the field prime, and it must be a
// point on the secp256k1 curve. This is the case for a PublicKey constructed by
// elliptic.Unmarshal (see UnmarshalPubkey), or by ToECDSA and ecdsa.GenerateKey
// when constructing a PrivateKey.
//
// CompressPubkey 将公钥编码为 33 字节压缩格式。
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	// NOTE: the coordinates may be validated with
	// secp256k1.ParsePubKey(FromECDSAPub(pubkey))
	var x, y secp256k1.FieldVal
	x.SetByteSlice(pubkey.X.Bytes())
	y.SetByteSlice(pubkey.Y.Bytes())
	return secp256k1.NewPublicKey(&x, &y).SerializeCompressed()
}

// S256 returns an instance of the secp256k1 curve.
// S256 返回 secp256k1 曲线的一个实例。
func S256() EllipticCurve {
	return btCurve{secp256k1.S256()}
}

// btCurve 是一个包装了 secp256k1.KoblitzCurve 的结构体。
type btCurve struct {
	*secp256k1.KoblitzCurve
}

// Marshal converts a point given as (x, y) into a byte slice.
// Marshal 将给定的 (x, y) 点转换为字节切片。
func (curve btCurve) Marshal(x, y *big.Int) []byte {
	// 计算每个坐标的字节长度
	byteLen := (curve.Params().BitSize + 7) / 8

	// 创建未压缩格式的字节数组：1 字节前缀 + 2 * byteLen
	ret := make([]byte, 1+2*byteLen)
	// 设置前缀为 4，表示未压缩点
	ret[0] = 4 // uncompressed point

	// 将 x 填充到字节数组的前半部分
	x.FillBytes(ret[1 : 1+byteLen])
	// 将 y 填充到字节数组的后半部分
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
// Unmarshal 将由 Marshal 序列化的点转换为 x, y 对。如果出错，x = nil。
func (curve btCurve) Unmarshal(data []byte) (x, y *big.Int) {
	// 计算每个坐标的字节长度
	byteLen := (curve.Params().BitSize + 7) / 8
	// 检查数据长度是否符合未压缩格式
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	// 检查前缀是否为 4（未压缩格式）
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	// 从字节数组提取 x 坐标
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	// 从字节数组提取 y 坐标
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return
}
