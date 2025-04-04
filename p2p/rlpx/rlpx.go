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

// Package rlpx implements the RLPx transport protocol.
package rlpx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	mrand "math/rand"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
	"golang.org/x/crypto/sha3"
)

// 代码背景：RLPx 协议与以太坊
// RLPx 是以太坊 DevP2P 网络协议栈的传输层，基于 TCP 提供加密和认证功能，用于节点间安全通信。它是 Go-Ethereum（Geth）实现以太坊 P2P 网络的关键组件。
//
// 以太坊相关知识点：
// DevP2P：以太坊的点对点网络协议，RLPx 是其基础传输层。
// EIP-8：以太坊改进提案第 8 号，定义了 RLPx v4 握手格式，增加了前向兼容性。
// ECIES：椭圆曲线集成加密方案，用于握手消息的加密，结合 ECDH 和 AES。

// Conn is an RLPx network connection. It wraps a low-level network connection. The
// underlying connection should not be used for other activity when it is wrapped by Conn.
//
// Before sending messages, a handshake must be performed by calling the Handshake method.
// This type is not generally safe for concurrent use, but reading and writing of messages
// may happen concurrently after the handshake.
// Conn 是一个 RLPx 网络连接。它包装了一个低级网络连接。当连接被 Conn 包装时，
// 底层的连接不应该用于其他活动。
//
// 在发送消息之前，必须通过调用 Handshake 方法执行握手。
// 此类型通常不安全用于并发使用，但在握手后消息的读写可以并发进行。
type Conn struct {
	dialDest *ecdsa.PublicKey // 拨号目标的公钥 / Public key of the dial destination
	conn     net.Conn         // 底层网络连接 / Underlying network connection
	session  *sessionState    // 会话状态 / Session state

	// These are the buffers for snappy compression.
	// Compression is enabled if they are non-nil.
	// 这些是用于 snappy 压缩的缓冲区。
	// 如果它们非 nil，则启用压缩。
	snappyReadBuffer  []byte // 读取缓冲区 / Read buffer for snappy
	snappyWriteBuffer []byte // 写入缓冲区 / Write buffer for snappy
}

// sessionState contains the session keys.
// sessionState 包含会话密钥。
type sessionState struct {
	enc cipher.Stream // 加密流 / Encryption stream
	dec cipher.Stream // 解密流 / Decryption stream

	egressMAC  hashMAC     // 出口 MAC / Egress MAC
	ingressMAC hashMAC     // 入口 MAC / Ingress MAC
	rbuf       readBuffer  // 读取缓冲区 / Read buffer
	wbuf       writeBuffer // 写入缓冲区 / Write buffer
}

// hashMAC holds the state of the RLPx v4 MAC contraption.
// hashMAC 持有 RLPx v4 MAC 机制的状态。
type hashMAC struct {
	cipher     cipher.Block // 密码块 / Cipher block
	hash       hash.Hash    // 哈希 / Hash
	aesBuffer  [16]byte     // AES 缓冲区 / AES buffer
	hashBuffer [32]byte     // 哈希缓冲区 / Hash buffer
	seedBuffer [32]byte     // 种子缓冲区 / Seed buffer
}

func newHashMAC(cipher cipher.Block, h hash.Hash) hashMAC {
	// 创建一个新的 hashMAC 实例 / Create a new hashMAC instance
	m := hashMAC{cipher: cipher, hash: h}
	if cipher.BlockSize() != len(m.aesBuffer) {
		panic(fmt.Errorf("invalid MAC cipher block size %d", cipher.BlockSize()))
		// 如果密码块大小不匹配，抛出异常 / Panic if cipher block size does not match
	}
	if h.Size() != len(m.hashBuffer) {
		panic(fmt.Errorf("invalid MAC digest size %d", h.Size()))
		// 如果哈希大小不匹配，抛出异常 / Panic if hash size does not match
	}
	return m
}

// NewConn wraps the given network connection. If dialDest is non-nil, the connection
// behaves as the initiator during the handshake.
// NewConn 包装给定的网络连接。如果 dialDest 非 nil，则连接在握手期间作为发起者。
func NewConn(conn net.Conn, dialDest *ecdsa.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest, // 设置拨号目标公钥 / Set dial destination public key
		conn:     conn,     // 设置底层连接 / Set underlying connection
	}
}

// SetSnappy enables or disables snappy compression of messages. This is usually called
// after the devp2p Hello message exchange when the negotiated version indicates that
// compression is available on both ends of the connection.
// SetSnappy 启用或禁用消息的 snappy 压缩。通常在 devp2p Hello 消息交换后调用，
// 当协商的版本指示连接两端都支持压缩时。
func (c *Conn) SetSnappy(snappy bool) {
	if snappy {
		c.snappyReadBuffer = []byte{}  // 启用压缩时初始化读取缓冲区 / Initialize read buffer when enabling compression
		c.snappyWriteBuffer = []byte{} // 启用压缩时初始化写入缓冲区 / Initialize write buffer when enabling compression
	} else {
		c.snappyReadBuffer = nil  // 禁用压缩时置空读取缓冲区 / Set read buffer to nil when disabling compression
		c.snappyWriteBuffer = nil // 禁用压缩时置空写入缓冲区 / Set write buffer to nil when disabling compression
	}
}

// SetReadDeadline sets the deadline for all future read operations.
// SetReadDeadline 为所有未来的读取操作设置截止时间。
func (c *Conn) SetReadDeadline(time time.Time) error {
	return c.conn.SetReadDeadline(time) // 调用底层连接设置读取截止时间 / Call underlying connection to set read deadline
}

// SetWriteDeadline sets the deadline for all future write operations.
// SetWriteDeadline 为所有未来的写入操作设置截止时间。
func (c *Conn) SetWriteDeadline(time time.Time) error {
	return c.conn.SetWriteDeadline(time) // 调用底层连接设置写入截止时间
}

// SetDeadline sets the deadline for all future read and write operations.
// SetDeadline 为所有未来的读写操作设置截止时间。
func (c *Conn) SetDeadline(time time.Time) error {
	return c.conn.SetDeadline(time) // 调用底层连接设置读写截止时间 / Call underlying connection to set read/write deadline
}

// Read reads a message from the connection.
// The returned data buffer is valid until the next call to Read.
// Read 从连接中读取消息。
// 返回的数据缓冲区在下次调用 Read 之前有效。
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	if c.session == nil {
		panic("can't ReadMsg before handshake")
		// 在握手之前不能读取消息 / Cannot read message before handshake
	}

	frame, err := c.session.readFrame(c.conn) // 读取帧 / Read frame
	if err != nil {
		return 0, nil, 0, err
	}
	code, data, err = rlp.SplitUint64(frame) // 分割 RLP 编码的帧 / Split RLP-encoded frame
	if err != nil {
		return 0, nil, 0, fmt.Errorf("invalid message code: %v", err)
		// 无效的消息代码 / Invalid message code
	}
	wireSize = len(data) // 记录原始数据大小 / Record original data size

	// If snappy is enabled, verify and decompress message.
	// 如果启用了 snappy，验证并解压缩消息。
	if c.snappyReadBuffer != nil {
		var actualSize int
		actualSize, err = snappy.DecodedLen(data) // 获取解压后的大小 / Get decompressed size
		if err != nil {
			return code, nil, 0, err
		}
		if actualSize > maxUint24 {
			return code, nil, 0, errPlainMessageTooLarge // 消息过大 / Message too large
		}
		c.snappyReadBuffer = growslice(c.snappyReadBuffer, actualSize) // 扩展缓冲区 / Expand buffer
		data, err = snappy.Decode(c.snappyReadBuffer, data)            // 解压缩 / Decompress
	}
	return code, data, wireSize, err
}

func (h *sessionState) readFrame(conn io.Reader) ([]byte, error) {
	h.rbuf.reset() // 重置读取缓冲区 / Reset read buffer

	// Read the frame header.
	// 读取帧头。
	header, err := h.rbuf.read(conn, 32) // 读取 32 字节的帧头 / Read 32-byte frame header
	if err != nil {
		return nil, err
	}

	// Verify header MAC.
	// 验证帧头 MAC。
	wantHeaderMAC := h.ingressMAC.computeHeader(header[:16]) // 计算预期的帧头 MAC / Compute expected header MAC
	if !hmac.Equal(wantHeaderMAC, header[16:]) {
		return nil, errors.New("bad header MAC") // MAC 不匹配 / MAC mismatch
	}

	// Decrypt the frame header to get the frame size.
	// 解密帧头以获取帧大小。
	h.dec.XORKeyStream(header[:16], header[:16]) // 解密前 16 字节 / Decrypt first 16 bytes
	fsize := readUint24(header[:16])             // 读取帧大小 / Read frame size
	// Frame size rounded up to 16 byte boundary for padding.
	// 帧大小向上取整到 16 字节边界以便填充。
	rsize := fsize
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding // 计算填充后的帧大小 / Calculate padded frame size
	}

	// Read the frame content.
	// 读取帧内容。
	frame, err := h.rbuf.read(conn, int(rsize)) // 读取帧数据 / Read frame data
	if err != nil {
		return nil, err
	}

	// Validate frame MAC.
	// 验证帧 MAC。
	frameMAC, err := h.rbuf.read(conn, 16) // 读取 16 字节的帧 MAC / Read 16-byte frame MAC
	if err != nil {
		return nil, err
	}
	wantFrameMAC := h.ingressMAC.computeFrame(frame) // 计算预期的帧 MAC / Compute expected frame MAC
	if !hmac.Equal(wantFrameMAC, frameMAC) {
		return nil, errors.New("bad frame MAC") // MAC 不匹配 / MAC mismatch
	}

	// Decrypt the frame data.
	// 解密帧数据。
	h.dec.XORKeyStream(frame, frame) // 解密帧 / Decrypt frame
	return frame[:fsize], nil        // 返回解密后的帧数据 / Return decrypted frame data
}

// Write writes a message to the connection.
//
// Write returns the written size of the message data. This may be less than or equal to
// len(data) depending on whether snappy compression is enabled.
// Write 向连接写入消息。
//
// Write 返回写入的消息数据大小。根据是否启用 snappy 压缩，这可能小于或等于 len(data)。
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	if c.session == nil {
		panic("can't WriteMsg before handshake")
		// 在握手之前不能写入消息 / Cannot write message before handshake
	}
	if len(data) > maxUint24 {
		return 0, errPlainMessageTooLarge // 消息过大 / Message too large
	}
	if c.snappyWriteBuffer != nil {
		// Ensure the buffer has sufficient size.
		// Package snappy will allocate its own buffer if the provided
		// one is smaller than MaxEncodedLen.
		// 确保缓冲区有足够的大小。
		// 如果提供的缓冲区小于 MaxEncodedLen，snappy 包会分配自己的缓冲区。
		c.snappyWriteBuffer = growslice(c.snappyWriteBuffer, snappy.MaxEncodedLen(len(data))) // 扩展缓冲区 / Expand buffer
		data = snappy.Encode(c.snappyWriteBuffer, data)                                       // 压缩数据 / Compress data
	}

	wireSize := uint32(len(data))                   // 记录原始数据大小 / Record original data size
	err := c.session.writeFrame(c.conn, code, data) // 写入帧 / Write frame
	return wireSize, err
}

func (h *sessionState) writeFrame(conn io.Writer, code uint64, data []byte) error {
	h.wbuf.reset() // 重置写入缓冲区 / Reset write buffer

	// Write header.
	// 写入帧头。
	fsize := rlp.IntSize(code) + len(data) // 计算帧大小 / Calculate frame size
	if fsize > maxUint24 {
		return errPlainMessageTooLarge // 帧过大 / Frame too large
	}
	header := h.wbuf.appendZero(16)    // 添加 16 字节的帧头 / Append 16-byte header
	putUint24(uint32(fsize), header)   // 写入帧大小 / Write frame size
	copy(header[3:], zeroHeader)       // 复制零头 / Copy zero header
	h.enc.XORKeyStream(header, header) // 加密帧头 / Encrypt header

	// Write header MAC.
	// 写入帧头 MAC。
	h.wbuf.Write(h.egressMAC.computeHeader(header)) // 写入计算的帧头 MAC / Write computed header MAC

	// Encode and encrypt the frame data.
	// 编码并加密帧数据。
	offset := len(h.wbuf.data)
	h.wbuf.data = rlp.AppendUint64(h.wbuf.data, code) // 追加消息代码 / Append message code
	h.wbuf.Write(data)                                // 写入数据 / Write data
	if padding := fsize % 16; padding > 0 {
		h.wbuf.appendZero(16 - padding) // 添加填充 / Add padding
	}
	framedata := h.wbuf.data[offset:]        // 获取帧数据 / Get frame data
	h.enc.XORKeyStream(framedata, framedata) // 加密帧数据 / Encrypt frame data

	// Write frame MAC.
	// 写入帧 MAC。
	h.wbuf.Write(h.egressMAC.computeFrame(framedata)) // 写入计算的帧 MAC / Write computed frame MAC

	_, err := conn.Write(h.wbuf.data) // 写入所有数据 / Write all data
	return err
}

// computeHeader computes the MAC of a frame header.
// computeHeader 计算帧头的 MAC。
func (m *hashMAC) computeHeader(header []byte) []byte {
	sum1 := m.hash.Sum(m.hashBuffer[:0]) // 获取当前哈希状态 / Get current hash state
	return m.compute(sum1, header)       // 计算 MAC / Compute MAC
}

// computeFrame computes the MAC of framedata.
// computeFrame 计算帧数据的 MAC。
func (m *hashMAC) computeFrame(framedata []byte) []byte {
	m.hash.Write(framedata)              // 更新哈希 / Update hash
	seed := m.hash.Sum(m.seedBuffer[:0]) // 获取哈希值 / Get hash value
	return m.compute(seed, seed[:16])    // 计算 MAC / Compute MAC
}

// compute computes the MAC of a 16-byte 'seed'.
//
// To do this, it encrypts the current value of the hash state, then XORs the ciphertext
// with seed. The obtained value is written back into the hash state and hash output is
// taken again. The first 16 bytes of the resulting sum are the MAC value.
//
// This MAC construction is a horrible, legacy thing.
// compute 计算 16 字节 'seed' 的 MAC。
//
// 它加密哈希状态的当前值，然后将密文与 seed 异或。
// 得到的值写回哈希状态并再次获取哈希输出。
// 结果的前 16 字节是 MAC 值。
//
// 这种 MAC 构造是一种糟糕的、遗留的东西。
func (m *hashMAC) compute(sum1, seed []byte) []byte {
	if len(seed) != len(m.aesBuffer) {
		panic("invalid MAC seed")
		// 无效的 MAC 种子 / Invalid MAC seed
	}

	m.cipher.Encrypt(m.aesBuffer[:], sum1) // 加密 sum1 / Encrypt sum1
	for i := range m.aesBuffer {
		m.aesBuffer[i] ^= seed[i] // 异或 seed / XOR with seed
	}
	m.hash.Write(m.aesBuffer[:])         // 更新哈希 / Update hash
	sum2 := m.hash.Sum(m.hashBuffer[:0]) // 获取哈希值 / Get hash value
	return sum2[:16]                     // 返回前 16 字节 / Return first 16 bytes
}

// Handshake performs the handshake. This must be called before any data is written
// or read from the connection.
// Handshake 执行握手。在连接上写入或读取任何数据之前必须调用此方法。
func (c *Conn) Handshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	var (
		sec Secrets        // 会话秘密 / Session secrets
		err error          // 错误 / Error
		h   handshakeState // 握手状态 / Handshake state
	)
	if c.dialDest != nil {
		sec, err = h.runInitiator(c.conn, prv, c.dialDest) // 作为发起者执行握手 / Run handshake as initiator
	} else {
		sec, err = h.runRecipient(c.conn, prv) // 作为接收者执行握手 / Run handshake as recipient
	}
	if err != nil {
		return nil, err
	}
	c.InitWithSecrets(sec)  // 初始化会话 / Initialize session
	c.session.rbuf = h.rbuf // 设置读取缓冲区 / Set read buffer
	c.session.wbuf = h.wbuf // 设置写入缓冲区 / Set write buffer
	return sec.remote, err  // 返回远程公钥和错误 / Return remote public key and error
}

// InitWithSecrets injects connection secrets as if a handshake had
// been performed. This cannot be called after the handshake.
// InitWithSecrets 注入连接秘密，就像已经执行了握手一样。握手后不能调用此方法。
func (c *Conn) InitWithSecrets(sec Secrets) {
	if c.session != nil {
		panic("can't handshake twice")
		// 不能两次握手 / Cannot handshake twice
	}
	macc, err := aes.NewCipher(sec.MAC) // 创建 MAC 密码 / Create MAC cipher
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
		// 无效的 MAC 秘密 / Invalid MAC secret
	}
	encc, err := aes.NewCipher(sec.AES) // 创建 AES 密码 / Create AES cipher
	if err != nil {
		panic("invalid AES secret: " + err.Error())
		// 无效的 AES 秘密 / Invalid AES secret
	}
	// we use an all-zeroes IV for AES because the key used
	// for encryption is ephemeral.
	// 我们使用全零 IV 进行 AES 加密，因为用于加密的密钥是临时的。
	iv := make([]byte, encc.BlockSize()) // 创建全零初始向量 / Create all-zero initialization vector
	c.session = &sessionState{
		enc:        cipher.NewCTR(encc, iv),          // 创建 CTR 加密流 / Create CTR encryption stream
		dec:        cipher.NewCTR(encc, iv),          // 创建 CTR 解密流 / Create CTR decryption stream
		egressMAC:  newHashMAC(macc, sec.EgressMAC),  // 创建出口 MAC / Create egress MAC
		ingressMAC: newHashMAC(macc, sec.IngressMAC), // 创建入口 MAC / Create ingress MAC
	}
}

// Close closes the underlying network connection.
// Close 关闭底层的网络连接。
func (c *Conn) Close() error {
	return c.conn.Close() // 关闭底层连接 / Close underlying connection
}

// Constants for the handshake.
// 握手常量。
const (
	sskLen = 16                     // ecies.MaxSharedKeyLength(pubKey) / 2 / 共享密钥长度 / Shared key length
	sigLen = crypto.SignatureLength // elliptic S256 / 签名长度 / Signature length
	pubLen = 64                     // 512 bit pubkey in uncompressed representation without format byte / 公钥长度 / Public key length
	shaLen = 32                     // hash length (for nonce etc) / 哈希长度（用于 nonce 等） / Hash length (for nonce, etc.)

	eciesOverhead = 65 /* pubkey */ + 16 /* IV */ + 32 /* MAC */ // ECIES 开销 / ECIES overhead
)

var (
	// this is used in place of actual frame header data.
	// TODO: replace this when Msg contains the protocol type code.
	// 这是用于替代实际帧头数据的。
	// TODO: 当 Msg 包含协议类型代码时替换此项。
	zeroHeader = []byte{0xC2, 0x80, 0x80}

	// errPlainMessageTooLarge is returned if a decompressed message length exceeds
	// the allowed 24 bits (i.e. length >= 16MB).
	// errPlainMessageTooLarge 在解压后的消息长度超过允许的 24 位（即长度 >= 16MB）时返回。
	errPlainMessageTooLarge = errors.New("message length >= 16MB")
)

// Secrets represents the connection secrets which are negotiated during the handshake.
// Secrets 表示在握手期间协商的连接秘密。
type Secrets struct {
	AES, MAC              []byte           // AES 和 MAC 密钥 / AES and MAC keys
	EgressMAC, IngressMAC hash.Hash        // 出口和入口 MAC 哈希 / Egress and ingress MAC hashes
	remote                *ecdsa.PublicKey // 远程公钥 / Remote public key
}

// handshakeState contains the state of the encryption handshake.
// handshakeState 包含加密握手的状态。
type handshakeState struct {
	initiator            bool              // 是否为发起者 / Whether it is the initiator
	remote               *ecies.PublicKey  // 远程公钥 / Remote public key
	initNonce, respNonce []byte            // 发起者和响应者的 nonce / Initiator and responder nonces
	randomPrivKey        *ecies.PrivateKey // 随机私钥 / Random private key
	remoteRandomPub      *ecies.PublicKey  // 远程随机公钥 / Remote random public key

	rbuf readBuffer  // 读取缓冲区 / Read buffer
	wbuf writeBuffer // 写入缓冲区 / Write buffer
}

// RLPx v4 handshake auth (defined in EIP-8).
// RLPx v4 握手认证（在 EIP-8 中定义）。
type authMsgV4 struct {
	Signature       [sigLen]byte // 签名 / Signature
	InitiatorPubkey [pubLen]byte // 发起者公钥 / Initiator public key
	Nonce           [shaLen]byte // Nonce
	Version         uint         // 版本 / Version

	// Ignore additional fields (forward-compatibility)
	// 忽略额外字段（前向兼容性）
	Rest []rlp.RawValue `rlp:"tail"`
}

// RLPx v4 handshake response (defined in EIP-8).
// RLPx v4 握手响应（在 EIP-8 中定义）。
type authRespV4 struct {
	RandomPubkey [pubLen]byte // 随机公钥 / Random public key
	Nonce        [shaLen]byte // Nonce
	Version      uint         // 版本 / Version

	// Ignore additional fields (forward-compatibility)
	// 忽略额外字段（前向兼容性）
	Rest []rlp.RawValue `rlp:"tail"`
}

// runRecipient negotiates a session token on conn.
// it should be called on the listening side of the connection.
//
// prv is the local client's private key.
// runRecipient 在 conn 上协商会话令牌。
// 它应该在连接的监听端调用。
//
// prv 是本地客户端的私钥。
func (h *handshakeState) runRecipient(conn io.ReadWriter, prv *ecdsa.PrivateKey) (s Secrets, err error) {
	authMsg := new(authMsgV4)
	authPacket, err := h.readMsg(authMsg, prv, conn) // 读取认证消息 / Read authentication message
	if err != nil {
		return s, err
	}
	if err := h.handleAuthMsg(authMsg, prv); err != nil { // 处理认证消息 / Handle authentication message
		return s, err
	}

	authRespMsg, err := h.makeAuthResp() // 创建认证响应 / Create authentication response
	if err != nil {
		return s, err
	}
	authRespPacket, err := h.sealEIP8(authRespMsg) // 密封认证响应 / Seal authentication response
	if err != nil {
		return s, err
	}
	if _, err = conn.Write(authRespPacket); err != nil { // 写入认证响应 / Write authentication response
		return s, err
	}

	return h.secrets(authPacket, authRespPacket) // 生成秘密 / Generate secrets
}

func (h *handshakeState) handleAuthMsg(msg *authMsgV4, prv *ecdsa.PrivateKey) error {
	// Import the remote identity.
	// 导入远程身份。
	rpub, err := importPublicKey(msg.InitiatorPubkey[:]) // 导入公钥 / Import public key
	if err != nil {
		return err
	}
	h.initNonce = msg.Nonce[:] // 设置发起者 nonce / Set initiator nonce
	h.remote = rpub            // 设置远程公钥 / Set remote public key

	// Generate random keypair for ECDH.
	// If a private key is already set, use it instead of generating one (for testing).
	// 生成用于 ECDH 的随机密钥对。
	// 如果已设置私钥，则使用它而不是生成一个（用于测试）。
	if h.randomPrivKey == nil {
		h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil) // 生成随机私钥 / Generate random private key
		if err != nil {
			return err
		}
	}

	// Check the signature.
	// 检查签名。
	token, err := h.staticSharedSecret(prv) // 计算静态共享秘密 / Compute static shared secret
	if err != nil {
		return err
	}
	signedMsg := xor(token, h.initNonce)                                  // 计算签名消息 / Compute signed message
	remoteRandomPub, err := crypto.Ecrecover(signedMsg, msg.Signature[:]) // 恢复公钥 / Recover public key
	if err != nil {
		return err
	}
	h.remoteRandomPub, _ = importPublicKey(remoteRandomPub) // 导入远程随机公钥 / Import remote random public key
	return nil
}

// secrets is called after the handshake is completed.
// It extracts the connection secrets from the handshake values.
// secrets 在握手完成后调用。
// 它从握手值中提取连接秘密。
func (h *handshakeState) secrets(auth, authResp []byte) (Secrets, error) {
	ecdheSecret, err := h.randomPrivKey.GenerateShared(h.remoteRandomPub, sskLen, sskLen) // 生成 ECDHE 秘密 / Generate ECDHE secret
	if err != nil {
		return Secrets{}, err
	}

	// derive base secrets from ephemeral key agreement
	// 从临时密钥协商中派生基本秘密
	sharedSecret := crypto.Keccak256(ecdheSecret, crypto.Keccak256(h.respNonce, h.initNonce)) // 计算共享秘密 / Compute shared secret
	aesSecret := crypto.Keccak256(ecdheSecret, sharedSecret)                                  // 计算 AES 秘密 / Compute AES secret
	s := Secrets{
		remote: h.remote.ExportECDSA(),                   // 导出远程公钥 / Export remote public key
		AES:    aesSecret,                                // 设置 AES 密钥 / Set AES key
		MAC:    crypto.Keccak256(ecdheSecret, aesSecret), // 设置 MAC 密钥 / Set MAC key
	}

	// setup sha3 instances for the MACs
	// 为 MAC 设置 sha3 实例
	mac1 := sha3.NewLegacyKeccak256()
	mac1.Write(xor(s.MAC, h.respNonce)) // 写入 MAC 密钥和响应者 nonce 的异或 / Write XOR of MAC key and responder nonce
	mac1.Write(auth)                    // 写入认证消息 / Write authentication message
	mac2 := sha3.NewLegacyKeccak256()
	mac2.Write(xor(s.MAC, h.initNonce)) // 写入 MAC 密钥和发起者 nonce 的异或 / Write XOR of MAC key and initiator nonce
	mac2.Write(authResp)                // 写入认证响应 / Write authentication response
	if h.initiator {
		s.EgressMAC, s.IngressMAC = mac1, mac2 // 如果是发起者，设置出口和入口 MAC / Set egress and ingress MAC for initiator
	} else {
		s.EgressMAC, s.IngressMAC = mac2, mac1 // 如果是接收者，设置出口和入口 MAC / Set egress and ingress MAC for recipient
	}

	return s, nil
}

// staticSharedSecret returns the static shared secret, the result
// of key agreement between the local and remote static node key.
// staticSharedSecret 返回静态共享秘密，即本地和远程静态节点密钥之间的密钥协商结果。
func (h *handshakeState) staticSharedSecret(prv *ecdsa.PrivateKey) ([]byte, error) {
	return ecies.ImportECDSA(prv).GenerateShared(h.remote, sskLen, sskLen) // 生成共享秘密 / Generate shared secret
}

// runInitiator negotiates a session token on conn.
// it should be called on the dialing side of the connection.
//
// prv is the local client's private key.
// runInitiator 在 conn 上协商会话令牌。
// 它应该在连接的拨号端调用。
//
// prv 是本地客户端的私钥。
func (h *handshakeState) runInitiator(conn io.ReadWriter, prv *ecdsa.PrivateKey, remote *ecdsa.PublicKey) (s Secrets, err error) {
	h.initiator = true                         // 设置为发起者 / Set as initiator
	h.remote = ecies.ImportECDSAPublic(remote) // 导入远程公钥 / Import remote public key

	authMsg, err := h.makeAuthMsg(prv) // 创建认证消息 / Create authentication message
	if err != nil {
		return s, err
	}
	authPacket, err := h.sealEIP8(authMsg) // 密封认证消息 / Seal authentication message
	if err != nil {
		return s, err
	}

	if _, err = conn.Write(authPacket); err != nil { // 写入认证消息 / Write authentication message
		return s, err
	}

	authRespMsg := new(authRespV4)
	authRespPacket, err := h.readMsg(authRespMsg, prv, conn) // 读取认证响应 / Read authentication response
	if err != nil {
		return s, err
	}
	if err := h.handleAuthResp(authRespMsg); err != nil { // 处理认证响应 / Handle authentication response
		return s, err
	}

	return h.secrets(authPacket, authRespPacket) // 生成秘密 / Generate secrets
}

// makeAuthMsg creates the initiator handshake message.
// makeAuthMsg 创建发起者握手消息。
func (h *handshakeState) makeAuthMsg(prv *ecdsa.PrivateKey) (*authMsgV4, error) {
	// Generate random initiator nonce.
	// 生成随机发起者 nonce。
	h.initNonce = make([]byte, shaLen)
	_, err := rand.Read(h.initNonce)
	if err != nil {
		return nil, err
	}
	// Generate random keypair to for ECDH.
	// 生成用于 ECDH 的随机密钥对。
	h.randomPrivKey, err = ecies.GenerateKey(rand.Reader, crypto.S256(), nil)
	if err != nil {
		return nil, err
	}

	// Sign known message: static-shared-secret ^ nonce
	// 签名已知消息：静态共享秘密 ^ nonce
	token, err := h.staticSharedSecret(prv) // 计算静态共享秘密 / Compute static shared secret
	if err != nil {
		return nil, err
	}
	signed := xor(token, h.initNonce)                                    // 计算签名消息 / Compute signed message
	signature, err := crypto.Sign(signed, h.randomPrivKey.ExportECDSA()) // 签名 / Sign
	if err != nil {
		return nil, err
	}

	msg := new(authMsgV4)
	copy(msg.Signature[:], signature)                                     // 设置签名 / Set signature
	copy(msg.InitiatorPubkey[:], crypto.FromECDSAPub(&prv.PublicKey)[1:]) // 设置发起者公钥 / Set initiator public key
	copy(msg.Nonce[:], h.initNonce)                                       // 设置 nonce / Set nonce
	msg.Version = 4                                                       // 设置版本 / Set version
	return msg, nil
}

func (h *handshakeState) handleAuthResp(msg *authRespV4) (err error) {
	h.respNonce = msg.Nonce[:]                                    // 设置响应者 nonce / Set responder nonce
	h.remoteRandomPub, err = importPublicKey(msg.RandomPubkey[:]) // 导入远程随机公钥 / Import remote random public key
	return err
}

func (h *handshakeState) makeAuthResp() (msg *authRespV4, err error) {
	// Generate random nonce.
	// 生成随机 nonce。
	h.respNonce = make([]byte, shaLen)
	if _, err = rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	msg = new(authRespV4)
	copy(msg.Nonce[:], h.respNonce)                                     // 设置 nonce / Set nonce
	copy(msg.RandomPubkey[:], exportPubkey(&h.randomPrivKey.PublicKey)) // 设置随机公钥 / Set random public key
	msg.Version = 4                                                     // 设置版本 / Set version
	return msg, nil
}

// readMsg reads an encrypted handshake message, decoding it into msg.
// readMsg 读取加密的握手消息，并将其解码到 msg 中。
func (h *handshakeState) readMsg(msg interface{}, prv *ecdsa.PrivateKey, r io.Reader) ([]byte, error) {
	h.rbuf.reset()   // 重置读取缓冲区 / Reset read buffer
	h.rbuf.grow(512) // 扩展缓冲区 / Grow buffer

	// Read the size prefix.
	// 读取大小前缀。
	prefix, err := h.rbuf.read(r, 2) // 读取 2 字节前缀 / Read 2-byte prefix
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(prefix) // 解析大小 / Parse size

	// baseProtocolMaxMsgSize = 2 * 1024
	if size > 2048 {
		return nil, errors.New("message too big")
		// 消息过大 / Message too big
	}

	// Read the handshake packet.
	// 读取握手包。
	packet, err := h.rbuf.read(r, int(size)) // 读取包 / Read packet
	if err != nil {
		return nil, err
	}
	dec, err := ecies.ImportECDSA(prv).Decrypt(packet, nil, prefix) // 解密包 / Decrypt packet
	if err != nil {
		return nil, err
	}
	// Can't use rlp.DecodeBytes here because it rejects
	// trailing data (forward-compatibility).
	// 不能在这里使用 rlp.DecodeBytes，因为它拒绝尾部数据（前向兼容性）。
	s := rlp.NewStream(bytes.NewReader(dec), 0)
	err = s.Decode(msg)                               // 解码消息 / Decode message
	return h.rbuf.data[:len(prefix)+len(packet)], err // 返回读取的数据 / Return read data
}

// sealEIP8 encrypts a handshake message.
// sealEIP8 加密握手消息。
func (h *handshakeState) sealEIP8(msg interface{}) ([]byte, error) {
	h.wbuf.reset() // 重置写入缓冲区 / Reset write buffer

	// Write the message plaintext.
	// 写入消息明文。
	if err := rlp.Encode(&h.wbuf, msg); err != nil {
		return nil, err
	}
	// Pad with random amount of data. the amount needs to be at least 100 bytes to make
	// the message distinguishable from pre-EIP-8 handshakes.
	// 用随机数量的数据填充。填充量至少为 100 字节，以使消息与 pre-EIP-8 握手区分开来。
	h.wbuf.appendZero(mrand.Intn(100) + 100) // 添加随机填充 / Add random padding

	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(h.wbuf.data)+eciesOverhead)) // 设置前缀 / Set prefix

	enc, err := ecies.Encrypt(rand.Reader, h.remote, h.wbuf.data, nil, prefix) // 加密 / Encrypt
	return append(prefix, enc...), err                                         // 返回前缀和加密数据 / Return prefix and encrypted data
}

// importPublicKey unmarshals 512 bit public keys.
// importPublicKey 反序列化 512 位公钥。
func importPublicKey(pubKey []byte) (*ecies.PublicKey, error) {
	var pubKey65 []byte
	switch len(pubKey) {
	case 64:
		// add 'uncompressed key' flag
		// 添加 '未压缩密钥' 标志
		pubKey65 = append([]byte{0x04}, pubKey...)
	case 65:
		pubKey65 = pubKey
	default:
		return nil, fmt.Errorf("invalid public key length %v (expect 64/65)", len(pubKey))
		// 无效的公钥长度 / Invalid public key length
	}
	// TODO: fewer pointless conversions
	// TODO: 减少无意义的转换
	pub, err := crypto.UnmarshalPubkey(pubKey65) // 反序列化公钥 / Unmarshal public key
	if err != nil {
		return nil, err
	}
	return ecies.ImportECDSAPublic(pub), nil // 导入 ECIES 公钥 / Import ECIES public key
}

func exportPubkey(pub *ecies.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
		// 公钥为 nil / Public key is nil
	}
	if curve, ok := pub.Curve.(crypto.EllipticCurve); ok {
		return curve.Marshal(pub.X, pub.Y)[1:] // 导出公钥 / Export public key
	}
	return []byte{}
}

func xor(one, other []byte) (xor []byte) {
	xor = make([]byte, len(one))
	for i := 0; i < len(one); i++ {
		xor[i] = one[i] ^ other[i] // 异或操作 / XOR operation
	}
	return xor
}
