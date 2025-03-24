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

package crypto

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// 以太坊使用 ECDSA（基于 secp256k1 曲线）来签署交易或消息，
// 以太坊使用 secp256k1 椭圆曲线进行签名，这是一种高效的加密算法。
// 签名由两部分组成：r（签名中的随机点坐标）和 s（证明签名有效性的值），各占 32 字节。
// 恢复ID 是额外的元数据，用于公钥恢复。

// SignatureLength indicates the byte length required to carry a signature with recovery id.
// SignatureLength 表示携带恢复ID的签名所需的字节长度。
//
// 定义签名的总长度为 65 字节，其中 64 字节是 ECDSA 签名的核心部分（由 r 和 s 两部分组成，每部分 32 字节），1 字节是恢复ID（recovery id）。恢复ID 用于从签名中推导出公钥。
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id  64字节ECDSA签名 + 1字节恢复ID

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
// RecoveryIDOffset 指向签名中包含恢复ID的字节偏移量。
//
// 指定恢复ID 在签名字节数组中的位置（第 64 个字节，索引从 0 开始）。这表明签名数据结构中，前 64 字节是 r 和 s，最后 1 字节是恢复ID。
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
// DigestLength 设置签名摘要的确切长度
//
// 定义签名摘要（digest）的长度为 32 字节。在以太坊中，摘要通常是通过 Keccak-256 哈希算法对消息或交易数据进行哈希后的结果，长度固定为 32 字节。
// 以太坊交易签名（如 EIP-155）或消息签名（如 personal_sign）的标准。
const DigestLength = 32

// ECDSA 签名规范化：在 ECDSA 中，签名由 (r, s) 组成，其中 s 必须满足 s ≤ N/2。如果 s > N/2，需要将其转换为 N - s，以确保签名符合规范。secp256k1halfN 正是用于这个判断。

var (
	secp256k1N     = S256().Params().N                           // secp256k1 曲线的阶（N） 即有限域中椭圆曲线的基点 G 的阶。N: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2)) // secp256k1 曲线阶的一半 用于签名验证或规范化过程中。 用于确保签名参数 s 的值在曲线的“低半部分”（即 s ≤ N/2），这是签名验证的标准要求。
)

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

// 在以太坊中，公钥通常以两种形式序列化：
// - 未压缩格式：04 || x || y（65 字节，前缀 04 加 x、y 各 32 字节）。
// - 压缩格式：02 或 03 || x（33 字节，根据 y 的奇偶性选择前缀）。

// EllipticCurve contains curve operations.
// EllipticCurve 包含曲线操作。
type EllipticCurve interface {
	elliptic.Curve

	// Point marshaling/unmarshaing.
	// 点序列化/反序列化。
	Marshal(x, y *big.Int) []byte          // 将椭圆曲线上的点 (x, y) 序列化为字节数组。 将公钥序列化为字节形式，以便存储或传输。
	Unmarshal(data []byte) (x, y *big.Int) // 从字节数组反序列化出椭圆曲线上的点 (x, y)。从 65 字节未压缩公钥中提取 x 和 y，或者从 33 字节压缩公钥中推导 y。
}

// Keccak-256
// - 以太坊使用 Keccak-256（SHA-3 家族的一种变体）作为主要哈希算法，而非 SHA-256。它生成 32 字节的哈希值，用于：
// - 从公钥生成以太坊地址（取 Keccak-256 哈希的后 20 字节）。
// - 计算交易的哈希（Transaction Hash）。
// - 在智能合约中计算函数选择器或事件签名。

// 状态操作
// Keccak 算法基于“海绵函数”（sponge construction），通过吸收（absorb）和挤出（squeeze）阶段处理数据。
// Read 方法利用了挤出阶段，允许从状态中提取任意长度的数据，而 Sum 通常只返回固定长度的输出。

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
//
// KeccakState 封装了 sha3.state。除了通常的哈希方法外，它还支持 Read 方法，
// 以从哈希状态中获取可变数量的数据。Read 比 Sum 更快，因为它不复制内部状态，但也会修改内部状态。
type KeccakState interface {
	hash.Hash
	// Read 从哈希状态中获取可变数量的数据。Read 比 Sum 更快，因为它不复制内部状态，但也会修改内部状态。
	Read([]byte) (int, error)
}

// NewKeccakState creates a new KeccakState
// NewKeccakState 创建一个新的 KeccakState
func NewKeccakState() KeccakState {
	// NewLegacyKeccak256 表示使用“遗留”版本的 Keccak-256，与以太坊使用的原始 Keccak-256 实现保持一致。
	return sha3.NewLegacyKeccak256().(KeccakState)
}

// HashData hashes the provided data using the KeccakState and returns a 32 byte hash
// 使用 KeccakState 对提供的输入数据进行哈希计算，并返回一个 32 字节的哈希值
func HashData(kh KeccakState, data []byte) (h common.Hash) {
	kh.Reset()     // 重置哈希状态
	kh.Write(data) // 将输入数据写入哈希状态 在 Keccak-256 中，这对应于“吸收”（absorb）阶段，将数据分块处理并更新内部状态。
	kh.Read(h[:])  // 从哈希状态读取 32 字节哈希值到 h Read 方法（KeccakState 的扩展方法）直接从状态中挤出（squeeze）数据，比 Sum 更快，但会修改内部状态。
	return h       // 返回哈希值
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
// 计算并返回输入数据的 Keccak256 哈希值
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
// 计算输入数据的 Keccak256 哈希值，并将其转换为内部的 Hash 数据结构返回
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
// Keccak512 计算并返回输入数据的 Keccak512 哈希值。
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512() // 创建一个新的 Keccak-512 哈希实例
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil) // 返回 64 字节的哈希值
}

// CreateAddress creates an ethereum address given the bytes and the nonce
// 根据给定的字节和 nonce 创建一个以太坊地址
//
// CreateAddress 函数根据给定的调用者地址（b）和交易 nonce（nonce）生成一个新的以太坊地址。
// 这是以太坊中通过交易创建合约地址的标准方法。
//
// 以太坊中，通过 CREATE 操作码创建合约时，新地址由调用者地址和 nonce 决定。公式为：
// address = Keccak256(RLP([callerAddress, nonce]))[12:]
// nonce 从 0 开始递增，每次创建合约时使用当前的 nonce。
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce}) // 将地址和 nonce 编码为 RLP 格式
	return common.BytesToAddress(Keccak256(data)[12:])    // 计算 Keccak256 哈希，取后 20 字节转换为地址
}

// CreateAddress2 creates an ethereum address given the address bytes, initial
// contract code hash and a salt.
// 根据地址字节、初始合约代码哈希和盐值创建以太坊地址
//
// CreateAddress2 函数根据调用者地址（b）、盐值（salt）和初始合约代码哈希（inithash）生成一个新的以太坊地址。
// 这是以太坊中通过 CREATE2 操作码创建合约地址的方法，引入了盐值以增加灵活性。
// []byte{0xff}：固定前缀，表示 CREATE2
// 总输入长度：1 + 20 + 32 + 32 = 85 字节。
// 输出 32 字节哈希，取 [12:] 得到后 20 字节。
//
//	CREATE2 是以太坊在君士坦丁堡硬分叉中引入的操作码（EIP-1014），允许通过盐值和代码哈希确定合约地址。公式为：
//	address = Keccak256(0xff || callerAddress || salt || Keccak256(initCode))[12:]
//
// 依赖盐值和代码哈希，地址可预测且独立于 nonce。
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak256([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:]) // 拼接 0xff、地址、盐值和初始哈希，计算 Keccak256，取后 20 字节转换为地址
}

// ToECDSA creates a private key with the given D value.
// ToECDSA 使用给定的 D 值创建私钥。
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
// ToECDSAUnsafe 盲目地将二进制数据转换为私钥。
// 除非你确定输入有效且希望避免因不良原始编码（去掉 0 前缀）导致的错误，否则几乎不应使用。
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := toECDSA(d, false)
	return priv
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
// toECDSA 使用给定的 D 值创建私钥。strict 参数控制是否强制要求密钥长度与曲线大小一致，或者是否接受遗留编码（带 0 前缀）。
//
// toECDSA 函数的目的是从给定的字节数组（d）构造一个 ECDSA 私钥对象（*ecdsa.PrivateKey），
// 并确保其符合以太坊使用的 secp256k1 曲线的约束。
// strict 参数控制是否强制私钥长度为 32 字节（256 位）。
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)                    // 创建一个新的 ECDSA 私钥对象
	priv.PublicKey.Curve = S256()                    // 设置曲线为 secp256k1
	if strict && 8*len(d) != priv.Params().BitSize { // 如果严格模式且字节长度不匹配曲线位数，返回错误
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d) // 将字节数组 d 转换为大整数并赋值给私钥 D

	// N 是曲线的有限域大小，私钥必须满足 0 < D < N。
	// The priv.D must < N
	// 私钥 D 必须小于 N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, errors.New("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	// 私钥 D 不能为零或负数
	if priv.D.Sign() <= 0 {
		return nil, errors.New("invalid private key, zero or negative")
	}

	// 使用标量乘法计算公钥：PublicKey = D * G，其中 G 是 secp256k1 的基点。
	priv.PublicKey.X, priv.PublicKey.Y = S256().ScalarBaseMult(d) // 通过标量乘法计算公钥
	if priv.PublicKey.X == nil {                                  // 如果公钥 X 为 nil，表示私钥无效
		return nil, errors.New("invalid private key")
	}
	return priv, nil // 返回私钥对象
}

// FromECDSA exports a private key into a binary dump.
// FromECDSA 将私钥导出为二进制格式。
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	// 将私钥的 D 值（大整数）填充并转换为字节数组，长度为 BitSize/8
	// priv.Params().BitSize 获取椭圆曲线的位长度。在以太坊中，使用的是 secp256k1 曲线，BitSize 为 256 位。
	// BitSize/8 转换为字节长度，即 256/8 = 32 字节。
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// UnmarshalPubkey converts bytes to a secp256k1 public key.
// UnmarshalPubkey 将字节数组转换为 secp256k1 公钥。
//
// 一个字节数组，通常是以太坊公钥的序列化形式。以太坊中，公钥可以是：
// 未压缩格式（65 字节）：0x04 前缀 + 32 字节 X 坐标 + 32 字节 Y 坐标。
// 压缩格式（33 字节）：0x02 或 0x03 前缀（取决于 Y 的奇偶性）+ 32 字节 X 坐标。
func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := S256().Unmarshal(pub)
	if x == nil {
		return nil, errInvalidPubkey
	}
	// 返回构造的 ECDSA 公钥结构体
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return S256().Marshal(pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
// HexToECDSA 解析一个 secp256k1 私钥。
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if byteErr, ok := err.(hex.InvalidByteError); ok {
		return nil, fmt.Errorf("invalid hex character %q in private key", byte(byteErr))
	} else if err != nil {
		return nil, errors.New("invalid hex data for private key")
	}
	return ToECDSA(b)
}

// LoadECDSA loads a secp256k1 private key from the given file.
// LoadECDSA 从指定文件中加载 secp256k1 私钥。
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	// 创建 64 字节缓冲区，用于存储十六进制私钥
	buf := make([]byte, 64)
	// 从文件中读取 ASCII 字符到缓冲区
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) { // 如果读取的字节数不足 64，返回错误
		return nil, errors.New("key file too short, want 64 hex characters")
	}
	// 检查文件是否有多余内容
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	// 将缓冲区内容转换为 ECDSA 私钥
	return HexToECDSA(string(buf))
}

// readASCII reads into 'buf', stopping when the buffer is full or
// when a non-printable control character is encountered.
//
// readASCII 读取数据到 'buf' 中，当缓冲区满或遇到不可打印的控制字符时停止。
//
// 以太坊私钥的十六进制表示是 64 个 ASCII 字符（0-9, a-f），对应 32 字节。readASCII 确保只读取有效的可打印字符，停止于控制字符（如换行符）
func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	// 循环读取直到缓冲区满
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		// 如果遇到文件末尾或字符小于 '!'，返回已读取的字节数
		case err == io.EOF || buf[n] < '!':
			return n, nil
		// 如果读取出错，返回错误和已读取的字节数
		case err != nil:
			return n, err
		}
	}
	// 如果缓冲区满，返回读取的字节数
	return n, nil
}

// checkKeyFileEnd skips over additional newlines at the end of a key file.
// readASCII 读取数据到 'buf' 中，当缓冲区满或遇到不可打印的控制字符时停止。
// checkKeyFileEnd 的功能是检查文件在读取 64 个字符后是否只包含换行符（\n 或 \r），若有其他字符或换行符过多则报错。
// 这是 LoadECDSA 的辅助函数，确保密钥文件格式严格。
func checkKeyFileEnd(r *bufio.Reader) error {
	// 无限循环读取字节
	for i := 0; ; i++ {
		// 读取一个字节
		b, err := r.ReadByte()
		switch {
		// 如果到达文件末尾，返回 nil 表示成功
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		// 如果遇到非换行符（\n 或 \r）的字符，返回错误
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		// 如果换行符超过 2 个，返回错误
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
//
// SaveECDSA 将 secp256k1 私钥保存到指定文件中，并设置严格的权限。密钥数据以十六进制编码保存。
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	// 以太坊私钥是 256 位（32 字节）随机数，保存时通常以 64 个十六进制字符的字符串形式存储，方便导入和阅读。
	// 将私钥转换为十六进制字符串
	k := hex.EncodeToString(FromECDSA(key))
	// 将字符串写入文件，权限设置为 0600（仅用户可读写）
	return os.WriteFile(file, []byte(k), 0600)
}

// GenerateKey generates a new private key.
// GenerateKey 生成一个新的私钥。
func GenerateKey() (*ecdsa.PrivateKey, error) {
	// 使用 secp256k1 曲线和随机源生成私钥
	// rand.Reader 是 crypto/rand 包提供的加密安全随机数生成器，确保私钥的随机性和安全性。
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
//
// ValidateSignatureValues 验证签名值是否符合给定的链规则。假设 v 值为 0 或 1。
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	// 如果 r 或 s 小于 1，返回 false
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	//
	// 在 Homestead 规则下，拒绝 s 值超过 secp256k1 曲线阶一半的情况（ECDSA 可塑性问题）
	// 参见 secp256k1/libsecp256k1/include/secp256k1.h 中的讨论
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}

	// Homestead 硬分叉
	//  - 引入于 2016 年（区块高度 1,150,000），包括 EIP-2，限制 s 值范围。
	// Frontier 阶段
	//  - 以太坊早期阶段，允许 s 在整个 N 范围内（s < N）。

	// Frontier: allow s to be in full N range
	// Frontier 规则：允许 s 在整个 N 范围内
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	clear(bytes)
}
