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

//go:build !nacl && !js && cgo && !gofuzz
// +build !nacl,!js,cgo,!gofuzz

package crypto

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// Ecrecover returns the uncompressed public key that created the given signature.
// Ecrecover 返回创建给定签名的未压缩公钥。
//
// hash：被签名的消息哈希。
// sig：签名，格式为 [r (32字节), s (32字节), v (1字节)]，共 65 字节。
//
// 返回的公钥是 65 字节未压缩格式：0x04 前缀 + 32 字节 X 坐标 + 32 字节 Y 坐标。以太坊地址可通过对公钥进行 Keccak-256 哈希并取后 20 字节生成。
// 输入签名需包含以太坊特定的消息前缀（\x19Ethereum Signed Message:\n）和长度。
func Ecrecover(hash, sig []byte) ([]byte, error) {
	// 使用 secp256k1 恢复未压缩公钥
	return secp256k1.RecoverPubkey(hash, sig)
}

// SigToPub returns the public key that created the given signature.
// SigToPub 返回创建给定签名的公钥。
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	// 从签名和哈希恢复未压缩公钥字节
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}
	// 将未压缩公钥字节解析为 ECDSA 公钥结构体
	return UnmarshalPubkey(s)
}

// Sign calculates an ECDSA signature.
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given digest cannot be chosen by an adversary. Common
// solution is to hash any input before calculating the signature.
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
//
// Sign 计算 ECDSA 签名。
//
// 此函数容易受到选择明文攻击，可能泄露用于签名的私钥信息。调用者必须确保给定的摘要不能由攻击者选择。
// 常见的解决方案是在计算签名之前对任何输入进行哈希处理。
//
// 生成的签名格式为 [R || S || V]，其中 V 为 0 或 1。
//
// digestHash []byte：消息的哈希，通常是 32 字节的 Keccak-256 哈希。
func Sign(digestHash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	// 如果哈希长度不等于预期长度，返回错误
	if len(digestHash) != DigestLength {
		return nil, fmt.Errorf("hash is required to be exactly %d bytes (%d)", DigestLength, len(digestHash))
	}
	// 将私钥 D 转换为固定长度的字节数组
	seckey := math.PaddedBigBytes(prv.D, prv.Params().BitSize/8)
	// 在函数退出时清零私钥字节数组
	defer zeroBytes(seckey)
	// 使用 secp256k1 计算签名
	return secp256k1.Sign(digestHash, seckey)
}

// VerifySignature checks that the given public key created signature over digest.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
//
// VerifySignature 检查给定的公钥是否创建了针对摘要的签名。
// 公钥应为压缩格式（33 字节）或未压缩格式（65 字节）。
// 签名应为 64 字节的 [R || S] 格式。
//
// pubkey []byte：公钥，可以是压缩格式（33 字节）或未压缩格式（65 字节）。
// digestHash []byte：消息的哈希，通常是 32 字节的 Keccak-256 哈希。
// signature []byte：签名，64 字节，格式为 [R || S]。
func VerifySignature(pubkey, digestHash, signature []byte) bool {
	// 使用 secp256k1 验证公钥是否匹配签名和摘要
	return secp256k1.VerifySignature(pubkey, digestHash, signature)
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// DecompressPubkey 解析 33 字节压缩格式的公钥。
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	// 从压缩格式公钥中解压出 X 和 Y 坐标
	// 前缀 0x02 表示 Y 为偶数，0x03 表示 Y 为奇数。
	// 后 32 字节是 X 坐标。
	// 该函数使用 secp256k1 曲线方程 y² = x³ + 7 计算 Y 值，返回 x, y（均为 *big.Int）
	x, y := secp256k1.DecompressPubkey(pubkey)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	// 构造并返回 ECDSA 公钥结构体
	return &ecdsa.PublicKey{X: x, Y: y, Curve: S256()}, nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
// CompressPubkey 将公钥编码为 33 字节的压缩格式。
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	// 将公钥的 X 和 Y 坐标压缩为 33 字节格式
	return secp256k1.CompressPubkey(pubkey.X, pubkey.Y)
}

// S256 returns an instance of the secp256k1 curve.
// S256 返回 secp256k1 曲线的一个实例。
func S256() EllipticCurve {
	// 返回 secp256k1 曲线的实例
	return secp256k1.S256()
}
