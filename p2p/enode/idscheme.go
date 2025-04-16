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

package enode

import (
	"crypto/ecdsa"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// ENR (EIP-778): ENR 是以太坊节点发现协议的扩展，定义了一种可扩展的记录格式，包含节点 ID、公钥、IP、端口等信息。V4ID 方案是其标准实现。
//
// secp256k1: 以太坊使用的椭圆曲线，用于签名和地址生成。ENR 中的公钥以此格式存储。
//
// Kademlia DHT: 节点 ID（Keccak256 哈希）用于节点发现中的距离计算，优化 P2P 网络效率。

// ValidSchemes is a List of known secure identity schemes.
// ValidSchemes 是已知的安全身份方案列表。
var ValidSchemes = enr.SchemeMap{
	"v4": V4ID{}, // "v4" 方案，使用签名验证
}

// ValidSchemesForTesting is a List of identity schemes for testing.
// ValidSchemesForTesting 是用于测试的身份方案列表。
var ValidSchemesForTesting = enr.SchemeMap{
	"v4":   V4ID{},   // "v4" 方案，用于正式环境和测试
	"null": NullID{}, // "null" 方案，无签名，用于测试
}

// V4ID is the "v4" identity scheme.
// V4ID 是 "v4" 身份方案。
type V4ID struct{}

// SignV4 signs a record using the v4 scheme.
// SignV4 使用 v4 方案对记录进行签名。
func SignV4(r *enr.Record, privkey *ecdsa.PrivateKey) error {
	// Copy r to avoid modifying it if signing fails.
	// 复制 r，以避免签名失败时修改原始记录。
	cpy := *r
	cpy.Set(enr.ID("v4"))                 // 设置身份方案为 "v4"
	cpy.Set(Secp256k1(privkey.PublicKey)) // 设置公钥字段

	h := sha3.NewLegacyKeccak256()               // 创建 Keccak256 哈希对象
	rlp.Encode(h, cpy.AppendElements(nil))       // 对记录的 RLP 编码进行哈希
	sig, err := crypto.Sign(h.Sum(nil), privkey) // 使用私钥对哈希签名
	if err != nil {
		return err
	}
	sig = sig[:len(sig)-1]                         // remove v (移除恢复标识符 v)
	if err = cpy.SetSig(V4ID{}, sig); err == nil { // 设置签名并检查
		*r = cpy // 成功则更新原始记录
	}
	return err
}

// Verify verifies the signature of a record using the v4 scheme.
// Verify 使用 v4 方案验证记录的签名。
func (V4ID) Verify(r *enr.Record, sig []byte) error {
	var entry s256raw
	if err := r.Load(&entry); err != nil { // 加载公钥字段
		return err
	} else if len(entry) != 33 { // 检查公钥长度是否为压缩格式（33字节）
		return errors.New("invalid public key")
	}

	h := sha3.NewLegacyKeccak256()                       // 创建 Keccak256 哈希对象
	rlp.Encode(h, r.AppendElements(nil))                 // 对记录的 RLP 编码进行哈希
	if !crypto.VerifySignature(entry, h.Sum(nil), sig) { // 验证签名
		return enr.ErrInvalidSig
	}
	return nil
}

// NodeAddr returns the node address (ID) derived from the public key in the record.
//
// NodeAddr 返回从记录中的公钥派生的节点地址（ID）。
func (V4ID) NodeAddr(r *enr.Record) []byte {
	var pubkey Secp256k1
	err := r.Load(&pubkey) // 加载公钥
	if err != nil {
		return nil
	}
	buf := make([]byte, 64)           // 创建 64 字节缓冲区存储未压缩公钥
	math.ReadBits(pubkey.X, buf[:32]) // 将 X 坐标写入前 32 字节
	math.ReadBits(pubkey.Y, buf[32:]) // 将 Y 坐标写入后 32 字节
	return crypto.Keccak256(buf)      // 对未压缩公钥计算 Keccak256 哈希作为节点 ID
}

// Secp256k1 is the "secp256k1" key, which holds a public key.
// Secp256k1 是 "secp256k1" 键，保存公钥。
type Secp256k1 ecdsa.PublicKey

func (v Secp256k1) ENRKey() string { return "secp256k1" } // 返回 ENR 键名

// EncodeRLP implements rlp.Encoder.
// EncodeRLP 实现 rlp.Encoder 接口。
func (v Secp256k1) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, crypto.CompressPubkey((*ecdsa.PublicKey)(&v))) // 将公钥压缩并编码为 RLP
}

// DecodeRLP implements rlp.Decoder.
// DecodeRLP 实现 rlp.Decoder 接口。
func (v *Secp256k1) DecodeRLP(s *rlp.Stream) error {
	buf, err := s.Bytes() // 从流中读取字节
	if err != nil {
		return err
	}
	pk, err := crypto.DecompressPubkey(buf) // 解压公钥
	if err != nil {
		return err
	}
	*v = (Secp256k1)(*pk) // 将解压后的公钥赋值
	return nil
}

// s256raw is an unparsed secp256k1 public key entry.
// s256raw 是未解析的 secp256k1 公钥条目。
type s256raw []byte

func (s256raw) ENRKey() string { return "secp256k1" } // 返回 ENR 键名

// v4CompatID is a weaker and insecure version of the "v4" scheme which only checks for the
// presence of a secp256k1 public key, but doesn't verify the signature.
//
// v4CompatID 是 "v4" 方案的较弱且不安全版本，仅检查 secp256k1 公钥的存在，不验证签名。
type v4CompatID struct {
	V4ID
}

func (v4CompatID) Verify(r *enr.Record, sig []byte) error {
	var pubkey Secp256k1
	return r.Load(&pubkey) // 仅检查公钥是否存在
}

func signV4Compat(r *enr.Record, pubkey *ecdsa.PublicKey) {
	r.Set((*Secp256k1)(pubkey))                              // 设置公钥
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil { // 设置空签名
		panic(err)
	}
}

// NullID is the "null" ENR identity scheme. This scheme stores the node
// ID in the record without any signature.
//
// NullID 是 "null" ENR 身份方案，此方案在记录中存储节点 ID，无需签名。
type NullID struct{}

func (NullID) Verify(r *enr.Record, sig []byte) error {
	return nil // 无需验证签名
}

func (NullID) NodeAddr(r *enr.Record) []byte {
	var id ID
	r.Load(enr.WithEntry("nulladdr", &id)) // 从记录中加载节点 ID
	return id[:]                           // 返回节点 ID
}

func SignNull(r *enr.Record, id ID) *Node {
	r.Set(enr.ID("null"))                                // 设置身份方案为 "null"
	r.Set(enr.WithEntry("nulladdr", id))                 // 设置节点 ID
	if err := r.SetSig(NullID{}, []byte{}); err != nil { // 设置空签名
		panic(err)
	}
	return newNodeWithID(r, id) // 创建并返回节点
}
