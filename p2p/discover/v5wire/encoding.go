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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
)

//Discovery v5：以太坊的节点发现协议，改进自 v4，增加了加密和隐私保护（EIP-1459）。
//ENR：节点记录格式，包含公钥、IP 等信息，通过序列号（Seq）跟踪更新。
//Secp256k1：以太坊使用的椭圆曲线，用于签名和密钥交换。
// TODO concurrent WHOAREYOU tie-breaker
// TODO rehandshake after X packets
// TODO 并发 WHOAREYOU 冲突解决
// TODO 在 X 个数据包后重新握手

// Header represents a packet header.
// Header 表示数据包头部。
type Header struct {
	IV           [sizeofMaskingIV]byte // 初始化向量，用于掩码加密 初始化向量（16 字节），用于 AES-CTR 模式加密头部数据的掩码过程，确保头部数据在传输中不被轻易识别。
	StaticHeader                       // 静态头部字段 包含固定的头部字段，如协议 ID（"discv5"）、版本号、标志位（表示数据包类型）、Nonce（随机数）和认证数据大小。
	AuthData     []byte                // 认证数据，内容根据数据包类型变化 可变长字段，根据数据包类型（Flag）存储不同的认证信息，例如 WHOAREYOU 的 ID Nonce 或握手的签名和公钥。

	src enode.ID // used by decoder // 源节点 ID，由解码器使用 解码时填充的源节点 ID，便于追踪数据包来源。
}

// StaticHeader contains the static fields of a packet header.
// StaticHeader 包含数据包头部的静态字段。
type StaticHeader struct {
	ProtocolID [6]byte // 协议标识符，例如 "discv5"
	Version    uint16  // 协议版本
	Flag       byte    // 数据包类型标志（消息、WHOAREYOU、握手）
	Nonce      Nonce   // 随机数，用于加密和验证
	AuthSize   uint16  // 认证数据的大小
}

// Authdata layouts.
// 认证数据布局。
type (
	whoareyouAuthData struct {
		IDNonce   [16]byte // ID 证明数据，用于身份验证
		RecordSeq uint64   // 请求者已知的最高 ENR 序列号
	}

	handshakeAuthData struct {
		h struct {
			SrcID      enode.ID // 源节点 ID
			SigSize    byte     // 签名数据大小
			PubkeySize byte     // 公钥数据偏移量
		}
		// Trailing variable-size data.
		// 尾随的可变大小数据。
		signature, pubkey, record []byte // 签名、公钥、ENR 记录
	}

	messageAuthData struct {
		SrcID enode.ID // 源节点 ID
	}
)

// Packet header flag values.
// 数据包头部标志值。
const (
	flagMessage   = iota // 普通消息
	flagWhoareyou        // WHOAREYOU 请求
	flagHandshake        // 握手消息
)

// Protocol constants.
// 协议常量。
const (
	version         = 1  // 当前协议版本
	minVersion      = 1  // 最低支持版本
	sizeofMaskingIV = 16 // 掩码初始化向量大小

	// The minimum size of any Discovery v5 packet is 63 bytes.
	// Should reject packets smaller than minPacketSize.
	// 任何 Discovery v5 数据包的最小大小为 63 字节。
	// 应拒绝小于 minPacketSize 的数据包。
	minPacketSize = 63

	maxPacketSize = 1280 // 最大数据包大小

	minMessageSize      = 48 // this refers to data after static headers // 静态头部后的最小消息大小
	randomPacketMsgSize = 20 // 随机数据包消息大小
)

var DefaultProtocolID = [6]byte{'d', 'i', 's', 'c', 'v', '5'} // 默认协议 ID "discv5"

// Errors.
// 错误定义。
var (
	errTooShort            = errors.New("packet too short")                            // 数据包太短
	errInvalidHeader       = errors.New("invalid packet header")                       // 无效数据包头部
	errInvalidFlag         = errors.New("invalid flag value in header")                // 头部标志值无效
	errMinVersion          = errors.New("version of packet header below minimum")      // 头部版本低于最低要求
	errMsgTooShort         = errors.New("message/handshake packet below minimum size") // 消息/握手数据包小于最小大小
	errAuthSize            = errors.New("declared auth size is beyond packet length")  // 声明的认证大小超出数据包长度
	errUnexpectedHandshake = errors.New("unexpected auth response, not in handshake")  // 未在握手中收到意外的认证响应
	errInvalidAuthKey      = errors.New("invalid ephemeral pubkey")                    // 无效的临时公钥
	errNoRecord            = errors.New("expected ENR in handshake but none sent")     // 握手中预期 ENR 但未发送
	errInvalidNonceSig     = errors.New("invalid ID nonce signature")                  // 无效的 ID nonce 签名
	errMessageTooShort     = errors.New("message contains no data")                    // 消息不包含数据
	errMessageDecrypt      = errors.New("cannot decrypt message")                      // 无法解密消息
)

// Public errors.
// 公共错误。
var (
	// ErrInvalidReqID represents error when the ID is invalid.
	// ErrInvalidReqID 表示 ID 无效时的错误。
	ErrInvalidReqID = errors.New("request ID larger than 8 bytes")
)

// IsInvalidHeader reports whether 'err' is related to an invalid packet header. When it
// returns false, it is pretty certain that the packet causing the error does not belong
// to discv5.
// IsInvalidHeader 报告“err”是否与无效数据包头部相关。如果返回 false，几乎可以确定导致10分钟前触发错误的数据包不属于 discv5。
func IsInvalidHeader(err error) bool {
	return err == errTooShort || err == errInvalidHeader || err == errMsgTooShort
}

// Packet sizes.
// 数据包大小。
var (
	sizeofStaticHeader      = binary.Size(StaticHeader{})          // 静态头部大小
	sizeofWhoareyouAuthData = binary.Size(whoareyouAuthData{})     // WHOAREYOU 认证数据大小
	sizeofHandshakeAuthData = binary.Size(handshakeAuthData{}.h)   // 握手认证数据大小（固定部分）
	sizeofMessageAuthData   = binary.Size(messageAuthData{})       // 消息认证数据大小
	sizeofStaticPacketData  = sizeofMaskingIV + sizeofStaticHeader // 静态数据包大小
)

// Codec encodes and decodes Discovery v5 packets.
// This type is not safe for concurrent use.
// Codec 编码和解码 Discovery v5 数据包。
// 此类型对并发使用不安全。
type Codec struct {
	sha256     hash.Hash         // SHA256 哈希函数，用于签名验证
	localnode  *enode.LocalNode  // 本地节点信息
	privkey    *ecdsa.PrivateKey // 本地节点的私钥
	sc         *SessionCache     // 会话缓存
	protocolID [6]byte           // 协议 ID

	// encoder buffers
	// 编码器缓冲区
	buf      bytes.Buffer // 整个数据包
	headbuf  bytes.Buffer // 数据包头部
	msgbuf   bytes.Buffer // 消息 RLP 明文
	msgctbuf []byte       // 消息密文

	// decoder buffer
	// 解码器缓冲区
	decbuf []byte
	reader bytes.Reader
}

// NewCodec creates a wire codec.
// NewCodec 创建一个有线编解码器。
func NewCodec(ln *enode.LocalNode, key *ecdsa.PrivateKey, clock mclock.Clock, protocolID *[6]byte) *Codec {
	c := &Codec{
		sha256:     sha256.New(),                 // 初始化 SHA256
		localnode:  ln,                           // 设置本地节点
		privkey:    key,                          // 设置私钥
		sc:         NewSessionCache(1024, clock), // 初始化会话缓存
		protocolID: DefaultProtocolID,            // 默认协议 ID
		decbuf:     make([]byte, maxPacketSize),  // 分配解码缓冲区
	}
	if protocolID != nil {
		c.protocolID = *protocolID // 如果提供了协议 ID，则使用它
	}
	return c
}

// Discovery v5 使用了基于 ECDH（椭圆曲线 Diffie-Hellman）的密钥交换来建立会话密钥，确保通信加密。
// encodeRandom 是协议的特性，当没有会话时发送随机数据，迫使对方发起 WHOAREYOU 挑战，从而启动握手。

// Encode encodes a packet to a node. 'id' and 'addr' specify the destination node. The
// 'challenge' parameter should be the most recently received WHOAREYOU packet from that
// node.
// Encode 将数据包编码到目标节点。'id' 和 'addr' 指定目标节点。
// 'challenge' 参数应为从该节点最近收到的 WHOAREYOU 数据包。
func (c *Codec) Encode(id enode.ID, addr string, packet Packet, challenge *Whoareyou) ([]byte, Nonce, error) {
	// Create the packet header.
	// 创建数据包头部。
	var (
		head    Header
		session *session
		msgData []byte
		err     error
	)
	switch {
	case packet.Kind() == WhoareyouPacket:
		head, err = c.encodeWhoareyou(id, packet.(*Whoareyou)) // 编码 WHOAREYOU 数据包
	case challenge != nil:
		// We have an unanswered challenge, send handshake.
		// 我们有一个未回答的挑战，发送握手。
		head, session, err = c.encodeHandshakeHeader(id, addr, challenge)
	default:
		session = c.sc.session(id, addr) // 获取会话
		if session != nil {
			// There is a session, use it.
			// 存在会话，使用它。
			head, err = c.encodeMessageHeader(id, session)
		} else {
			// No keys, send random data to kick off the handshake.
			// 没有密钥，发送随机数据以启动握手。
			head, msgData, err = c.encodeRandom(id)
		}
	}
	if err != nil {
		return nil, Nonce{}, err
	}

	// Generate masking IV.
	// 生成掩码初始化向量。
	if err := c.sc.maskingIVGen(head.IV[:]); err != nil {
		return nil, Nonce{}, fmt.Errorf("can't generate masking IV: %v", err)
	}

	// Encode header data.
	// 编码头部数据。
	c.writeHeaders(&head)

	// Store sent WHOAREYOU challenges.
	// 存储发送的 WHOAREYOU 挑战。
	if challenge, ok := packet.(*Whoareyou); ok {
		challenge.ChallengeData = bytesCopy(&c.buf)
		c.sc.storeSentHandshake(id, addr, challenge)
	} else if msgData == nil {
		headerData := c.buf.Bytes()
		msgData, err = c.encryptMessage(session, packet, &head, headerData)
		if err != nil {
			return nil, Nonce{}, err
		}
	}

	enc, err := c.EncodeRaw(id, head, msgData)
	return enc, head.Nonce, err
}

// EncodeRaw encodes a packet with the given header.
// EncodeRaw 使用给定的头部编码数据包。
func (c *Codec) EncodeRaw(id enode.ID, head Header, msgdata []byte) ([]byte, error) {
	c.writeHeaders(&head)

	// Apply masking.
	// 应用掩码。
	masked := c.buf.Bytes()[sizeofMaskingIV:]
	mask := head.mask(id)
	mask.XORKeyStream(masked[:], masked[:])

	// Write message data.
	// 写入消息数据。
	c.buf.Write(msgdata)
	return c.buf.Bytes(), nil
}

func (c *Codec) writeHeaders(head *Header) {
	c.buf.Reset()
	c.buf.Write(head.IV[:])
	binary.Write(&c.buf, binary.BigEndian, &head.StaticHeader)
	c.buf.Write(head.AuthData)
}

// makeHeader creates a packet header.
// makeHeader 创建数据包头部。
func (c *Codec) makeHeader(toID enode.ID, flag byte, authsizeExtra int) Header {
	var authsize int
	switch flag {
	case flagMessage:
		authsize = sizeofMessageAuthData
	case flagWhoareyou:
		authsize = sizeofWhoareyouAuthData
	case flagHandshake:
		authsize = sizeofHandshakeAuthData
	default:
		panic(fmt.Errorf("BUG: invalid packet header flag %x", flag))
	}
	authsize += authsizeExtra
	if authsize > int(^uint16(0)) {
		panic(fmt.Errorf("BUG: auth size %d overflows uint16", authsize))
	}
	return Header{
		StaticHeader: StaticHeader{
			ProtocolID: c.protocolID,
			Version:    version,
			Flag:       flag,
			AuthSize:   uint16(authsize),
		},
	}
}

// encodeRandom encodes a packet with random content.
// encodeRandom 编码一个包含随机内容的数据包。
func (c *Codec) encodeRandom(toID enode.ID) (Header, []byte, error) {
	head := c.makeHeader(toID, flagMessage, 0)

	// Encode auth data.
	// 编码认证数据。
	auth := messageAuthData{SrcID: c.localnode.ID()}
	if _, err := crand.Read(head.Nonce[:]); err != nil {
		return head, nil, fmt.Errorf("can't get random data: %v", err)
	}
	c.headbuf.Reset()
	binary.Write(&c.headbuf, binary.BigEndian, auth)
	head.AuthData = c.headbuf.Bytes()

	// Fill message ciphertext buffer with random bytes.
	// 用随机字节填充消息密文缓冲区。
	c.msgctbuf = append(c.msgctbuf[:0], make([]byte, randomPacketMsgSize)...)
	crand.Read(c.msgctbuf)
	return head, c.msgctbuf, nil
}

// encodeWhoareyou encodes a WHOAREYOU packet.
// encodeWhoareyou 编码一个 WHOAREYOU 数据包。
func (c *Codec) encodeWhoareyou(toID enode.ID, packet *Whoareyou) (Header, error) {
	// Sanity check node field to catch misbehaving callers.
	// 检查节点字段的合理性，以捕获行为不当的调用者。
	if packet.RecordSeq > 0 && packet.Node == nil {
		panic("BUG: missing node in whoareyou with non-zero seq")
	}

	// Create header.
	// 创建头部。
	head := c.makeHeader(toID, flagWhoareyou, 0)
	head.AuthData = bytesCopy(&c.buf)
	head.Nonce = packet.Nonce

	// Encode auth data.
	// 编码认证数据。
	auth := &whoareyouAuthData{
		IDNonce:   packet.IDNonce,
		RecordSeq: packet.RecordSeq,
	}
	c.headbuf.Reset()
	binary.Write(&c.headbuf, binary.BigEndian, auth)
	head.AuthData = c.headbuf.Bytes()
	return head, nil
}

// encodeHandshakeHeader encodes the handshake message packet header.
// encodeHandshakeHeader 编码握手消息数据包头部。
func (c *Codec) encodeHandshakeHeader(toID enode.ID, addr string, challenge *Whoareyou) (Header, *session, error) {
	// Ensure calling code sets challenge.node.
	// 确保调用代码设置了 challenge.Node。
	if challenge.Node == nil {
		panic("BUG: missing challenge.Node in encode")
	}

	// Generate new secrets.
	// 生成新的密钥。
	auth, session, err := c.makeHandshakeAuth(toID, addr, challenge)
	if err != nil {
		return Header{}, nil, err
	}

	// Generate nonce for message.
	// 为消息生成 nonce。
	nonce, err := c.sc.nextNonce(session)
	if err != nil {
		return Header{}, nil, fmt.Errorf("can't generate nonce: %v", err)
	}

	// TODO: this should happen when the first authenticated message is received
	// TODO: 这应该在收到第一个经过认证的消息时发生
	c.sc.storeNewSession(toID, addr, session)

	// Encode the auth header.
	// 编码认证头部。
	var (
		authsizeExtra = len(auth.pubkey) + len(auth.signature) + len(auth.record)
		head          = c.makeHeader(toID, flagHandshake, authsizeExtra)
	)
	c.headbuf.Reset()
	binary.Write(&c.headbuf, binary.BigEndian, &auth.h)
	c.headbuf.Write(auth.signature)
	c.headbuf.Write(auth.pubkey)
	c.headbuf.Write(auth.record)
	head.AuthData = c.headbuf.Bytes()
	head.Nonce = nonce
	return head, session, err
}

// ECDH 密钥交换：基于 Secp256k1 曲线（以太坊标准曲线），用于生成会话密钥。
// ENR（Ethereum Node Records）：EIP-778 定义的节点记录格式，用于存储节点元数据（如 IP、端口）。
// ID Nonce 签名：防止中间人攻击，确保握手中的身份真实性。

// makeHandshakeAuth creates the auth header on a request packet following WHOAREYOU.
// makeHandshakeAuth 在 WHOAREYOU 后的请求数据包上创建认证头部。
func (c *Codec) makeHandshakeAuth(toID enode.ID, addr string, challenge *Whoareyou) (*handshakeAuthData, *session, error) {
	auth := new(handshakeAuthData)
	auth.h.SrcID = c.localnode.ID()

	// Create the ephemeral key. This needs to be first because the
	// key is part of the ID nonce signature.
	// 创建临时密钥。这需要首先完成，因为该密钥是 ID nonce 签名的一部分。
	var remotePubkey = new(ecdsa.PublicKey)
	if err := challenge.Node.Load((*enode.Secp256k1)(remotePubkey)); err != nil {
		return nil, nil, errors.New("can't find secp256k1 key for recipient")
	}
	ephkey, err := c.sc.ephemeralKeyGen()
	if err != nil {
		return nil, nil, errors.New("can't generate ephemeral key")
	}
	ephpubkey := EncodePubkey(&ephkey.PublicKey)
	auth.pubkey = ephpubkey[:]
	auth.h.PubkeySize = byte(len(auth.pubkey))

	// Add ID nonce signature to response.
	// 将 ID nonce 签名添加到响应中。
	cdata := challenge.ChallengeData
	idsig, err := makeIDSignature(c.sha256, c.privkey, cdata, ephpubkey[:], toID)
	if err != nil {
		return nil, nil, fmt.Errorf("can't sign: %v", err)
	}
	auth.signature = idsig
	auth.h.SigSize = byte(len(auth.signature))

	// Add our record to response if it's newer than what remote side has.
	// 如果我们的记录比远程端拥有的更新，则将其添加到响应中。
	ln := c.localnode.Node()
	if challenge.RecordSeq < ln.Seq() {
		auth.record, _ = rlp.EncodeToBytes(ln.Record())
	}

	// Create session keys.
	// 创建会话密钥。
	sec := deriveKeys(sha256.New, ephkey, remotePubkey, c.localnode.ID(), challenge.Node.ID(), cdata)
	if sec == nil {
		return nil, nil, errors.New("key derivation failed")
	}
	return auth, sec, err
}

// encodeMessageHeader encodes an encrypted message packet.
// encodeMessageHeader 编码一个加密消息数据包。
func (c *Codec) encodeMessageHeader(toID enode.ID, s *session) (Header, error) {
	head := c.makeHeader(toID, flagMessage, 0)

	// Create the header.
	// 创建头部。
	nonce, err := c.sc.nextNonce(s)
	if err != nil {
		return Header{}, fmt.Errorf("can't generate nonce: %v", err)
	}
	auth := messageAuthData{SrcID: c.localnode.ID()}
	c.buf.Reset()
	binary.Write(&c.buf, binary.BigEndian, &auth)
	head.AuthData = bytesCopy(&c.buf)
	head.Nonce = nonce
	return head, err
}

func (c *Codec) encryptMessage(s *session, p Packet, head *Header, headerData []byte) ([]byte, error) {
	// Encode message plaintext.
	// 编码消息明文。
	c.msgbuf.Reset()
	c.msgbuf.WriteByte(p.Kind())
	if err := rlp.Encode(&c.msgbuf, p); err != nil {
		return nil, err
	}
	messagePT := c.msgbuf.Bytes()

	// Encrypt into message ciphertext buffer.
	// 加密到消息密文缓冲区。
	messageCT, err := encryptGCM(c.msgctbuf[:0], s.writeKey, head.Nonce[:], messagePT, headerData)
	if err == nil {
		c.msgctbuf = messageCT
	}
	return messageCT, err
}

// Decode decodes a discovery packet.
// Decode 解码一个发现数据包。
func (c *Codec) Decode(inputData []byte, addr string) (src enode.ID, n *enode.Node, p Packet, err error) {
	if len(inputData) < minPacketSize {
		return enode.ID{}, nil, nil, errTooShort
	}
	// Copy the packet to a tmp buffer to avoid modifying it.
	// 将数据包复制到临时缓冲区以避免修改它。
	c.decbuf = append(c.decbuf[:0], inputData...)
	input := c.decbuf
	// Unmask the static header.
	// 解掩静态头部。
	var head Header
	copy(head.IV[:], input[:sizeofMaskingIV])
	mask := head.mask(c.localnode.ID())
	staticHeader := input[sizeofMaskingIV:sizeofStaticPacketData]
	mask.XORKeyStream(staticHeader, staticHeader)

	// Decode and verify the static header.
	// 解码并验证静态头部。
	c.reader.Reset(staticHeader)
	binary.Read(&c.reader, binary.BigEndian, &head.StaticHeader)
	remainingInput := len(input) - sizeofStaticPacketData
	if err := head.checkValid(remainingInput, c.protocolID); err != nil {
		return enode.ID{}, nil, nil, err
	}

	// Unmask auth data.
	// 解掩认证数据。
	authDataEnd := sizeofStaticPacketData + int(head.AuthSize)
	authData := input[sizeofStaticPacketData:authDataEnd]
	mask.XORKeyStream(authData, authData)
	head.AuthData = authData

	// Delete timed-out handshakes. This must happen before decoding to avoid
	// processing the same handshake twice.
	// 删除超时的握手。这必须在解码之前发生，以避免重复处理相同的握手。
	c.sc.handshakeGC()

	// Decode auth part and message.
	// 解码认证部分和消息。
	headerData := input[:authDataEnd]
	msgData := input[authDataEnd:]
	switch head.Flag {
	case flagWhoareyou:
		p, err = c.decodeWhoareyou(&head, headerData)
	case flagHandshake:
		n, p, err = c.decodeHandshakeMessage(addr, &head, headerData, msgData)
	case flagMessage:
		p, err = c.decodeMessage(addr, &head, headerData, msgData)
	default:
		err = errInvalidFlag
	}
	return head.src, n, p, err
}

// decodeWhoareyou reads packet data after the header as a WHOAREYOU packet.
// decodeWhoareyou 将头部后的数据包数据读取为 WHOAREYOU 数据包。
func (c *Codec) decodeWhoareyou(head *Header, headerData []byte) (Packet, error) {
	if len(head.AuthData) != sizeofWhoareyouAuthData {
		return nil, fmt.Errorf("invalid auth size %d for WHOAREYOU", len(head.AuthData))
	}
	var auth whoareyouAuthData
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth)
	p := &Whoareyou{
		Nonce:         head.Nonce,
		IDNonce:       auth.IDNonce,
		RecordSeq:     auth.RecordSeq,
		ChallengeData: make([]byte, len(headerData)),
	}
	copy(p.ChallengeData, headerData)
	return p, nil
}

func (c *Codec) decodeHandshakeMessage(fromAddr string, head *Header, headerData, msgData []byte) (n *enode.Node, p Packet, err error) {
	node, auth, session, err := c.decodeHandshake(fromAddr, head)
	if err != nil {
		c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
		return nil, nil, err
	}

	// Decrypt the message using the new session keys.
	// 使用新的会话密钥解密消息。
	msg, err := c.decryptMessage(msgData, head.Nonce[:], headerData, session.readKey)
	if err != nil {
		c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
		return node, msg, err
	}

	// Handshake OK, drop the challenge and store the new session keys.
	// 握手成功，丢弃挑战并存储新的会话密钥。
	c.sc.storeNewSession(auth.h.SrcID, fromAddr, session)
	c.sc.deleteHandshake(auth.h.SrcID, fromAddr)
	return node, msg, nil
}

func (c *Codec) decodeHandshake(fromAddr string, head *Header) (n *enode.Node, auth handshakeAuthData, s *session, err error) {
	if auth, err = c.decodeHandshakeAuthData(head); err != nil {
		return nil, auth, nil, err
	}

	// Verify against our last WHOAREYOU.
	// 针对我们最后的 WHOAREYOU 进行验证。
	challenge := c.sc.getHandshake(auth.h.SrcID, fromAddr)
	if challenge == nil {
		return nil, auth, nil, errUnexpectedHandshake
	}
	// Get node record.
	// 获取节点记录。
	n, err = c.decodeHandshakeRecord(challenge.Node, auth.h.SrcID, auth.record)
	if err != nil {
		return nil, auth, nil, err
	}
	// Verify ID nonce signature.
	// 验证 ID nonce 签名。
	sig := auth.signature
	cdata := challenge.ChallengeData
	err = verifyIDSignature(c.sha256, sig, n, cdata, auth.pubkey, c.localnode.ID())
	if err != nil {
		return nil, auth, nil, err
	}
	// Verify ephemeral key is on curve.
	// 验证临时密钥在曲线上。
	ephkey, err := DecodePubkey(c.privkey.Curve, auth.pubkey)
	if err != nil {
		return nil, auth, nil, errInvalidAuthKey
	}
	// Derive session keys.
	// 派生会话密钥。
	session := deriveKeys(sha256.New, c.privkey, ephkey, auth.h.SrcID, c.localnode.ID(), cdata)
	session = session.keysFlipped()
	return n, auth, session, nil
}

// decodeHandshakeAuthData reads the authdata section of a handshake packet.
// decodeHandshakeAuthData 读取握手数据包的认证数据部分。
func (c *Codec) decodeHandshakeAuthData(head *Header) (auth handshakeAuthData, err error) {
	// Decode fixed size part.
	// 解码固定大小部分。
	if len(head.AuthData) < sizeofHandshakeAuthData {
		return auth, fmt.Errorf("header authsize %d too low for handshake", head.AuthSize)
	}
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth.h)
	head.src = auth.h.SrcID

	// Decode variable-size part.
	// 解码可变大小部分。
	var (
		vardata       = head.AuthData[sizeofHandshakeAuthData:]
		sigAndKeySize = int(auth.h.SigSize) + int(auth.h.PubkeySize)
		keyOffset     = int(auth.h.SigSize)
		recOffset     = keyOffset + int(auth.h.PubkeySize)
	)
	if len(vardata) < sigAndKeySize {
		return auth, errTooShort
	}
	auth.signature = vardata[:keyOffset]
	auth.pubkey = vardata[keyOffset:recOffset]
	auth.record = vardata[recOffset:]
	return auth, nil
}

// decodeHandshakeRecord verifies the node record contained in a handshake packet. The
// remote node should include the record if we don't have one or if ours is older than the
// latest sequence number.
// decodeHandshakeRecord 验证握手数据包中包含的节点记录。
// 如果我们没有记录或我们的记录比最新的序列号旧，远程节点应包含该记录。
func (c *Codec) decodeHandshakeRecord(local *enode.Node, wantID enode.ID, remote []byte) (*enode.Node, error) {
	node := local
	if len(remote) > 0 {
		var record enr.Record
		if err := rlp.DecodeBytes(remote, &record); err != nil {
			return nil, err
		}
		if local == nil || local.Seq() < record.Seq() {
			n, err := enode.New(enode.ValidSchemes, &record)
			if err != nil {
				return nil, fmt.Errorf("invalid node record: %v", err)
			}
			if n.ID() != wantID {
				return nil, fmt.Errorf("record in handshake has wrong ID: %v", n.ID())
			}
			node = n
		}
	}
	if node == nil {
		return nil, errNoRecord
	}
	return node, nil
}

// decodeMessage reads packet data following the header as an ordinary message packet.
// decodeMessage 将头部后的数据包数据读取为普通消息数据包。
func (c *Codec) decodeMessage(fromAddr string, head *Header, headerData, msgData []byte) (Packet, error) {
	if len(head.AuthData) != sizeofMessageAuthData {
		return nil, fmt.Errorf("invalid auth size %d for message packet", len(head.AuthData))
	}
	var auth messageAuthData
	c.reader.Reset(head.AuthData)
	binary.Read(&c.reader, binary.BigEndian, &auth)
	head.src = auth.SrcID

	// Try decrypting the message.
	// 尝试解密消息。
	key := c.sc.readKey(auth.SrcID, fromAddr)
	msg, err := c.decryptMessage(msgData, head.Nonce[:], headerData, key)
	if errors.Is(err, errMessageDecrypt) {
		// It didn't work. Start the handshake since this is an ordinary message packet.
		// 解密失败。由于这是一个普通消息数据包，启动握手。
		return &Unknown{Nonce: head.Nonce}, nil
	}
	return msg, err
}

func (c *Codec) decryptMessage(input, nonce, headerData, readKey []byte) (Packet, error) {
	msgdata, err := decryptGCM(readKey, nonce, input, headerData)
	if err != nil {
		return nil, errMessageDecrypt
	}
	if len(msgdata) == 0 {
		return nil, errMessageTooShort
	}
	return DecodeMessage(msgdata[0], msgdata[1:])
}

// checkValid performs some basic validity checks on the header.
// The packetLen here is the length remaining after the static header.
// checkValid 对头部执行一些基本的有效性检查。
// 此处的 packetLen 是静态头部后的剩余长度。
func (h *StaticHeader) checkValid(packetLen int, protocolID [6]byte) error {
	if h.ProtocolID != protocolID {
		return errInvalidHeader
	}
	if h.Version < minVersion {
		return errMinVersion
	}
	if h.Flag != flagWhoareyou && packetLen < minMessageSize {
		return errMsgTooShort
	}
	if int(h.AuthSize) > packetLen {
		return errAuthSize
	}
	return nil
}

// mask returns a cipher for 'masking' / 'unmasking' packet headers.
// mask 返回用于“掩码”/“解掩”数据包头部的加密器。
func (h *Header) mask(destID enode.ID) cipher.Stream {
	block, err := aes.NewCipher(destID[:16])
	if err != nil {
		panic("can't create cipher")
	}
	return cipher.NewCTR(block, h.IV[:])
}

func bytesCopy(r *bytes.Buffer) []byte {
	b := make([]byte, r.Len())
	copy(b, r.Bytes())
	return b
}
