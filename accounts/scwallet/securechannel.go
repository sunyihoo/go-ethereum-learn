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

package scwallet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	pcsc "github.com/gballet/go-libpcsclite"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

const (
	maxPayloadSize  = 223 // 最大有效载荷大小
	pairP1FirstStep = 0   // 配对的第一步 P1 值
	pairP1LastStep  = 1   // 配对的最后一步 P1 值

	scSecretLength = 32 // 安全通道密钥长度
	scBlockSize    = 16 // 安全通道块大小

	insOpenSecureChannel    = 0x10 // 打开安全通道的指令
	insMutuallyAuthenticate = 0x11 // 相互认证的指令
	insPair                 = 0x12 // 配对的指令
	insUnpair               = 0x13 // 取消配对的指令

	pairingSalt = "Keycard Pairing Password Salt" // 配对密码的盐值
)

// SecureChannelSession enables secure communication with a hardware wallet.
// SecureChannelSession 启用与硬件钱包的安全通信。
type SecureChannelSession struct {
	card *pcsc.Card // A handle to the smartcard for communication
	// 用于通信的智能卡句柄
	secret []byte // A shared secret generated from our ECDSA keys
	// 从我们的 ECDSA 密钥生成的共享秘密
	publicKey []byte // Our own ephemeral public key
	// 我们自己的临时公钥
	PairingKey []byte // A permanent shared secret for a pairing, if present
	// 如果存在，用于配对的永久共享秘密
	sessionEncKey []byte // The current session encryption key
	// 当前会话加密密钥
	sessionMacKey []byte // The current session MAC key
	// 当前会话 MAC 密钥
	iv []byte // The current IV
	// 当前初始化向量 (IV)
	PairingIndex uint8 // The pairing index
	// 配对索引
}

// NewSecureChannelSession creates a new secure channel for the given card and public key.
// NewSecureChannelSession 为给定的卡和公钥创建新的安全通道。
func NewSecureChannelSession(card *pcsc.Card, keyData []byte) (*SecureChannelSession, error) {
	// Generate an ECDSA keypair for ourselves
	// 为我们自己生成一个 ECDSA 密钥对
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	cardPublic, err := crypto.UnmarshalPubkey(keyData)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal public key from card: %v", err)
		// 无法从卡中解析公钥：%v
	}
	secret, _ := crypto.S256().ScalarMult(cardPublic.X, cardPublic.Y, key.D.Bytes())
	return &SecureChannelSession{
		card:      card,
		secret:    secret.Bytes(),
		publicKey: crypto.FromECDSAPub(&key.PublicKey),
	}, nil
}

// Pair establishes a new pairing with the smartcard.
// Pair 与智能卡建立新的配对。
func (s *SecureChannelSession) Pair(pairingPassword []byte) error {
	secretHash := pbkdf2.Key(norm.NFKD.Bytes(pairingPassword), norm.NFKD.Bytes([]byte(pairingSalt)), 50000, 32, sha256.New)

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}

	response, err := s.pair(pairP1FirstStep, challenge)
	if err != nil {
		return err
	}

	md := sha256.New()
	md.Write(secretHash[:])
	md.Write(challenge)

	expectedCryptogram := md.Sum(nil)
	cardCryptogram := response.Data[:32]
	cardChallenge := response.Data[32:64]

	if !bytes.Equal(expectedCryptogram, cardCryptogram) {
		return fmt.Errorf("invalid card cryptogram %v != %v", expectedCryptogram, cardCryptogram)
		// 无效的卡密码 %v != %v
	}

	md.Reset()
	md.Write(secretHash[:])
	md.Write(cardChallenge)
	response, err = s.pair(pairP1LastStep, md.Sum(nil))
	if err != nil {
		return err
	}

	md.Reset()
	md.Write(secretHash[:])
	md.Write(response.Data[1:])
	s.PairingKey = md.Sum(nil)
	s.PairingIndex = response.Data[0]

	return nil
}

// Unpair disestablishes an existing pairing.
// Unpair 取消现有的配对。
func (s *SecureChannelSession) Unpair() error {
	if s.PairingKey == nil {
		return errors.New("cannot unpair: not paired")
		// 无法取消配对：未配对
	}

	_, err := s.transmitEncrypted(claSCWallet, insUnpair, s.PairingIndex, 0, []byte{})
	if err != nil {
		return err
	}
	s.PairingKey = nil
	// Close channel
	// 关闭通道
	s.iv = nil
	return nil
}

// Open initializes the secure channel.
// Open 初始化安全通道。
func (s *SecureChannelSession) Open() error {
	if s.iv != nil {
		return errors.New("session already opened")
		// 会话已打开
	}

	response, err := s.open()
	if err != nil {
		return err
	}

	// Generate the encryption/mac key by hashing our shared secret,
	// pairing key, and the first bytes returned from the Open APDU.
	// 通过对我们的共享秘密、配对密钥和从 Open APDU 返回的前几个字节进行哈希，生成加密/MAC 密钥。
	md := sha512.New()
	md.Write(s.secret)
	md.Write(s.PairingKey)
	md.Write(response.Data[:scSecretLength])
	keyData := md.Sum(nil)
	s.sessionEncKey = keyData[:scSecretLength]
	s.sessionMacKey = keyData[scSecretLength : scSecretLength*2]

	// The IV is the last bytes returned from the Open APDU.
	// IV 是从 Open APDU 返回的最后几个字节。
	s.iv = response.Data[scSecretLength:]

	return s.mutuallyAuthenticate()
}

// mutuallyAuthenticate is an internal method to authenticate both ends of the
// connection.
// mutuallyAuthenticate 是用于认证连接两端的内部方法。
func (s *SecureChannelSession) mutuallyAuthenticate() error {
	data := make([]byte, scSecretLength)
	if _, err := rand.Read(data); err != nil {
		return err
	}

	response, err := s.transmitEncrypted(claSCWallet, insMutuallyAuthenticate, 0, 0, data)
	if err != nil {
		return err
	}
	if response.Sw1 != 0x90 || response.Sw2 != 0x00 {
		return fmt.Errorf("got unexpected response from MUTUALLY_AUTHENTICATE: %#x%x", response.Sw1, response.Sw2)
		// 从 MUTUALLY_AUTHENTICATE 收到意外响应：%#x%x
	}

	if len(response.Data) != scSecretLength {
		return fmt.Errorf("response from MUTUALLY_AUTHENTICATE was %d bytes, expected %d", len(response.Data), scSecretLength)
		// MUTUALLY_AUTHENTICATE 的响应是 %d 字节，预期为 %d
	}

	return nil
}

// open is an internal method that sends an open APDU.
// open 是发送打开 APDU 的内部方法。
func (s *SecureChannelSession) open() (*responseAPDU, error) {
	return transmit(s.card, &commandAPDU{
		Cla:  claSCWallet,
		Ins:  insOpenSecureChannel,
		P1:   s.PairingIndex,
		P2:   0,
		Data: s.publicKey,
		Le:   0,
	})
}

// pair is an internal method that sends a pair APDU.
// pair 是发送配对 APDU 的内部方法。
func (s *SecureChannelSession) pair(p1 uint8, data []byte) (*responseAPDU, error) {
	return transmit(s.card, &commandAPDU{
		Cla:  claSCWallet,
		Ins:  insPair,
		P1:   p1,
		P2:   0,
		Data: data,
		Le:   0,
	})
}

// transmitEncrypted sends an encrypted message, and decrypts and returns the response.
// transmitEncrypted 发送加密消息，并解密并返回响应。
func (s *SecureChannelSession) transmitEncrypted(cla, ins, p1, p2 byte, data []byte) (*responseAPDU, error) {
	if s.iv == nil {
		return nil, errors.New("channel not open")
		// 通道未打开
	}

	data, err := s.encryptAPDU(data)
	if err != nil {
		return nil, err
	}
	meta := [16]byte{cla, ins, p1, p2, byte(len(data) + scBlockSize)}
	if err = s.updateIV(meta[:], data); err != nil {
		return nil, err
	}

	fulldata := make([]byte, len(s.iv)+len(data))
	copy(fulldata, s.iv)
	copy(fulldata[len(s.iv):], data)

	response, err := transmit(s.card, &commandAPDU{
		Cla:  cla,
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: fulldata,
	})
	if err != nil {
		return nil, err
	}

	rmeta := [16]byte{byte(len(response.Data))}
	rmac := response.Data[:len(s.iv)]
	rdata := response.Data[len(s.iv):]
	plainData, err := s.decryptAPDU(rdata)
	if err != nil {
		return nil, err
	}

	if err = s.updateIV(rmeta[:], rdata); err != nil {
		return nil, err
	}
	if !bytes.Equal(s.iv, rmac) {
		return nil, errors.New("invalid MAC in response")
		// 响应中的 MAC 无效
	}

	rapdu := &responseAPDU{}
	rapdu.deserialize(plainData)

	if rapdu.Sw1 != sw1Ok {
		return nil, fmt.Errorf("unexpected response status Cla=%#x, Ins=%#x, Sw=%#x%x", cla, ins, rapdu.Sw1, rapdu.Sw2)
		// 意外的响应状态 Cla=%#x, Ins=%#x, Sw=%#x%x
	}

	return rapdu, nil
}

// encryptAPDU is an internal method that serializes and encrypts an APDU.
// encryptAPDU 是序列化和加密 APDU 的内部方法。
func (s *SecureChannelSession) encryptAPDU(data []byte) ([]byte, error) {
	if len(data) > maxPayloadSize {
		return nil, fmt.Errorf("payload of %d bytes exceeds maximum of %d", len(data), maxPayloadSize)
		// 有效载荷 %d 字节超过最大值 %d
	}
	data = pad(data, 0x80)

	ret := make([]byte, len(data))

	a, err := aes.NewCipher(s.sessionEncKey)
	if err != nil {
		return nil, err
	}
	crypter := cipher.NewCBCEncrypter(a, s.iv)
	crypter.CryptBlocks(ret, data)
	return ret, nil
}

// pad applies message padding to a 16 byte boundary.
// pad 将消息填充应用到 16 字节边界。
func pad(data []byte, terminator byte) []byte {
	padded := make([]byte, (len(data)/16+1)*16)
	copy(padded, data)
	padded[len(data)] = terminator
	return padded
}

// decryptAPDU is an internal method that decrypts and deserializes an APDU.
// decryptAPDU 是解密和反序列化 APDU 的内部方法。
func (s *SecureChannelSession) decryptAPDU(data []byte) ([]byte, error) {
	a, err := aes.NewCipher(s.sessionEncKey)
	if err != nil {
		return nil, err
	}

	ret := make([]byte, len(data))

	crypter := cipher.NewCBCDecrypter(a, s.iv)
	crypter.CryptBlocks(ret, data)
	return unpad(ret, 0x80)
}

// unpad strips padding from a message.
// unpad 从消息中剥离填充。
func unpad(data []byte, terminator byte) ([]byte, error) {
	for i := 1; i <= 16; i++ {
		switch data[len(data)-i] {
		case 0:
			continue
		case terminator:
			return data[:len(data)-i], nil
		default:
			return nil, fmt.Errorf("expected end of padding, got %d", data[len(data)-i])
			// 预期填充结束，得到 %d
		}
	}
	return nil, errors.New("expected end of padding, got 0")
	// 预期填充结束，得到 0
}

// updateIV is an internal method that updates the initialization vector after
// each message exchanged.
// updateIV 是每次消息交换后更新初始化向量的内部方法。
func (s *SecureChannelSession) updateIV(meta, data []byte) error {
	data = pad(data, 0)
	a, err := aes.NewCipher(s.sessionMacKey)
	if err != nil {
		return err
	}
	crypter := cipher.NewCBCEncrypter(a, make([]byte, 16))
	crypter.CryptBlocks(meta, meta)
	crypter.CryptBlocks(data, data)
	// The first 16 bytes of the last block is the MAC
	// 最后一块的前 16 个字节是 MAC
	s.iv = data[len(data)-32 : len(data)-16]
	return nil
}
