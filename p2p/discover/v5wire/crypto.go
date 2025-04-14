// Copyright 2020 The go-ethereum Authors
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

package v5wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"hash"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"golang.org/x/crypto/hkdf"
)

const (
	// Encryption/authentication parameters.
	// 加密/认证参数
	aesKeySize   = 16 // (AES密钥大小，单位字节)
	gcmNonceSize = 12 // (GCM随机数大小，单位字节)
)

// Nonce represents a nonce used for AES/GCM.
// Nonce表示用于AES/GCM的随机数
type Nonce [gcmNonceSize]byte

// EncodePubkey encodes a public key.
// EncodePubkey 对公钥进行编码
func EncodePubkey(key *ecdsa.PublicKey) []byte {
	switch key.Curve {
	case crypto.S256(): // 检查曲线是否为secp256k1
		return crypto.CompressPubkey(key) // 压缩公钥
	default:
		panic("unsupported curve " + key.Curve.Params().Name + " in EncodePubkey")
	}
}

// DecodePubkey decodes a public key in compressed format.
// DecodePubkey 解码压缩格式的公钥
func DecodePubkey(curve elliptic.Curve, e []byte) (*ecdsa.PublicKey, error) {
	switch curve {
	case crypto.S256():
		if len(e) != 33 {
			return nil, errors.New("wrong size public key data")
		}
		return crypto.DecompressPubkey(e)
	default:
		return nil, fmt.Errorf("unsupported curve %s in DecodePubkey", curve.Params().Name)
	}
}

// idNonceHash computes the ID signature hash used in the handshake.
// idNonceHash 计算用于握手的ID签名哈希
func idNonceHash(h hash.Hash, challenge, ephkey []byte, destID enode.ID) []byte {
	h.Reset()                                      // 重置哈希状态
	h.Write([]byte("discovery v5 identity proof")) // 写入静态前缀
	h.Write(challenge)                             // 写入挑战数据
	h.Write(ephkey)                                // 写入临时密钥
	h.Write(destID[:])                             // 写入目标节点ID
	return h.Sum(nil)                              // 计算并返回哈希
}

// 这是以太坊 devp2p 协议的一部分（具体为 Discovery v5），用于节点间身份验证。
// challenge 和 ephkey（临时密钥）确保每次握手唯一，防止重放攻击。
// destID 是目标节点的唯一标识符（基于公钥的哈希）。

// makeIDSignature creates the ID nonce signature.
// makeIDSignature 创建ID随机数签名
func makeIDSignature(hash hash.Hash, key *ecdsa.PrivateKey, challenge, ephkey []byte, destID enode.ID) ([]byte, error) {
	input := idNonceHash(hash, challenge, ephkey, destID) // 计算哈希输入
	switch key.Curve {
	case crypto.S256(): // 检查曲线是否为secp256k1
		idsig, err := crypto.Sign(input, key) // 用私钥签名哈希
		if err != nil {
			return nil, err
		}
		return idsig[:len(idsig)-1], nil // remove recovery ID 移除恢复ID并返回
	default:
		return nil, fmt.Errorf("unsupported curve %s", key.Curve.Params().Name)
	}
}

// s256raw is an unparsed secp256k1 public key ENR entry.
// s256raw 是未解析的secp256k1公钥ENR条目
type s256raw []byte

func (s256raw) ENRKey() string { return "secp256k1" } // 返回ENR键类型

// ENR（Ethereum Node Records）是以太坊节点发现协议的一部分，存储节点的公钥等信息。
// s256raw 表示未解析的 secp256k1 公钥。验证过程使用 ECDSA 签名验证。

// verifyIDSignature checks that signature over idnonce was made by the given node.
// verifyIDSignature 检查ID随机数上的签名是否由给定节点生成
func verifyIDSignature(hash hash.Hash, sig []byte, n *enode.Node, challenge, ephkey []byte, destID enode.ID) error {
	switch idscheme := n.Record().IdentityScheme(); idscheme { // 检查节点的身份方案
	case "v4": // Discovery v4方案
		var pubkey s256raw          // 定义原始公钥
		if n.Load(&pubkey) != nil { // 从节点记录加载公钥
			return errors.New("no secp256k1 public key in record")
		}
		input := idNonceHash(hash, challenge, ephkey, destID) // 计算哈希输入
		if !crypto.VerifySignature(pubkey, input, sig) {      // 验证签名
			return errInvalidNonceSig
		}
		return nil
	default:
		return fmt.Errorf("can't verify ID nonce signature against scheme %q", idscheme)
	}
}

type hashFn func() hash.Hash // 哈希函数类型

// deriveKeys creates the session keys.
// deriveKeys 创建会话密钥
func deriveKeys(hash hashFn, priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, n1, n2 enode.ID, challenge []byte) *session {
	const text = "discovery v5 key agreement"             // KDF的静态文本
	var info = make([]byte, 0, len(text)+len(n1)+len(n2)) // 初始化信息缓冲区
	info = append(info, text...)                          // 追加静态文本
	info = append(info, n1[:]...)                         // 追加节点1的ID
	info = append(info, n2[:]...)                         // 追加节点2的ID

	eph := ecdh(priv, pub) // 通过ECDH计算共享密钥
	if eph == nil {
		return nil
	}
	kdf := hkdf.New(hash, eph, challenge, info)                                           // (初始化HKDF)
	sec := session{writeKey: make([]byte, aesKeySize), readKey: make([]byte, aesKeySize)} // (创建会话密钥)
	kdf.Read(sec.writeKey)                                                                // 派生写入密钥
	kdf.Read(sec.readKey)                                                                 // 派生读取密钥
	clear(eph)                                                                            // 清除共享密钥
	return &sec
}

// deriveKeys 使用 ECDH（椭圆曲线 Diffie-Hellman）和 HKDF（HMAC-based Key Derivation Function）生成会话密钥，ecdh 计算共享密钥。
// 以太坊知识点：ECDH 是以太坊节点通信中常用的密钥交换方法，HKDF 用于从共享密钥派生对称加密密钥（这里是 AES 密钥）。
// 这是 Discovery v5 中建立安全通信的关键步骤。

// ecdh creates a shared secret.
// ecdh 创建共享密钥
func ecdh(privkey *ecdsa.PrivateKey, pubkey *ecdsa.PublicKey) []byte {
	secX, secY := pubkey.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes()) // (执行ECDH乘法)
	if secX == nil {
		return nil
	}
	sec := make([]byte, 33)           // (分配33字节给压缩密钥)
	sec[0] = 0x02 | byte(secY.Bit(0)) // (根据Y奇偶性设置前缀) 0010 | 0000 = 0010 或者 0010 | 0001 = 0011
	math.ReadBits(secX, sec[1:])      // (编码X坐标)
	return sec
}

// 使用 AES-GCM（Galois/Counter Mode）对数据加密和解密，提供机密性和完整性。
// 以太坊知识点：AES-GCM 是以太坊节点通信中常用的对称加密算法，结合了加密和认证（通过认证标签）。
// nonce 确保每次加密唯一，防止重放攻击。

// encryptGCM encrypts pt using AES-GCM with the given key and nonce. The ciphertext is
// appended to dest, which must not overlap with plaintext. The resulting ciphertext is 16
// bytes longer than plaintext because it contains an authentication tag.
//
// encryptGCM 使用AES-GCM加密明文，密文附加到dest中，dest不能与明文重叠。密文比明文长16字节，因为包含认证标签
func encryptGCM(dest, key, nonce, plaintext, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) // (创建AES加密器)
	if err != nil {
		panic(fmt.Errorf("can't create block cipher: %v", err))
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize) // (创建GCM模式)
	if err != nil {
		panic(fmt.Errorf("can't create GCM: %v", err))
	}
	return aesgcm.Seal(dest, nonce, plaintext, authData), nil // (加密并返回密文)
}

// decryptGCM decrypts ct using AES-GCM with the given key and nonce.
// decryptGCM 使用AES-GCM解密密文
func decryptGCM(key, nonce, ct, authData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key) // (创建AES加密器)
	if err != nil {
		return nil, fmt.Errorf("can't create block cipher: %v", err)
	}
	if len(nonce) != gcmNonceSize { // (检查随机数大小)
		return nil, fmt.Errorf("invalid GCM nonce size: %d", len(nonce))
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize) // (创建GCM模式)
	if err != nil {
		return nil, fmt.Errorf("can't create GCM: %v", err)
	}
	pt := make([]byte, 0, len(ct))              // (分配明文缓冲区)
	return aesgcm.Open(pt, nonce, ct, authData) // (解密并返回明文)
}
