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
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"time"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// 节点发现：以太坊网络中的节点通过 Discovery 协议找到彼此，v5 版本引入了更强的加密和身份验证机制。
// ECDSA：代码中使用了 ecdsa.PrivateKey，这是以太坊常用的椭圆曲线数字签名算法，用于身份验证和密钥协商。
// Nonce：在加密通信中，nonce（一次性随机数）用于防止重放攻击，这在以太坊 P2P 通信中尤为重要。

const handshakeTimeout = time.Second

// The SessionCache keeps negotiated encryption keys and
// state for in-progress handshakes in the Discovery v5 wire protocol.
//
// SessionCache 存储协商后的加密密钥以及 Discovery v5 协议中正在进行握手的状态。
type SessionCache struct {
	sessions   lru.BasicLRU[sessionID, *session] // LRU cache for storing established sessions / 用于存储已建立会话的 LRU 缓存
	handshakes map[sessionID]*Whoareyou          // Map for tracking in-progress handshakes / 用于跟踪进行中握手的映射
	clock      mclock.Clock                      // Clock interface for time operations / 用于时间操作的时钟接口

	// hooks for overriding randomness.
	// 用于覆盖随机性的钩子。
	nonceGen        func(uint32) (Nonce, error)       // Function to generate nonces / 生成 nonce 的函数
	maskingIVGen    func([]byte) error                // Function to generate masking IVs / 生成掩码 IV 的函数
	ephemeralKeyGen func() (*ecdsa.PrivateKey, error) // Function to generate ephemeral ECDSA keys / 生成临时 ECDSA 密钥的函数
}

// sessionID identifies a session or handshake.
// sessionID 用于标识一个会话或握手。
type sessionID struct {
	id   enode.ID // Node ID (public key) / 节点 ID（公钥）
	addr string   // Network address of the node / 节点的网络地址
}

// session contains session information
// session 包含会话信息
type session struct {
	writeKey     []byte // Encryption key for outbound messages / 用于发送消息的加密密钥
	readKey      []byte // Decryption key for inbound messages / 用于接收消息的解密密钥
	nonceCounter uint32 // Counter for nonce generation / 用于 nonce 生成的计数器
}

// keysFlipped returns a copy of s with the read and write keys flipped.
// keysFlipped 返回一个 s 的副本，其中读写密钥对调。
func (s *session) keysFlipped() *session {
	return &session{s.readKey, s.writeKey, s.nonceCounter}
}

func NewSessionCache(maxItems int, clock mclock.Clock) *SessionCache {
	return &SessionCache{
		sessions:        lru.NewBasicLRU[sessionID, *session](maxItems), // Initialize LRU cache with max size / 初始化具有最大容量的 LRU 缓存
		handshakes:      make(map[sessionID]*Whoareyou),                 // Initialize handshake map / 初始化握手映射
		clock:           clock,                                          // Set clock / 设置时钟
		nonceGen:        generateNonce,                                  // Default nonce generator / 默认 nonce 生成器
		maskingIVGen:    generateMaskingIV,                              // Default masking IV generator / 默认掩码 IV 生成器
		ephemeralKeyGen: crypto.GenerateKey,                             // Default ephemeral key generator / 默认临时密钥生成器
	}
}

// 防止重放攻击：nonce 的递增和随机性结合是区块链网络中常见的安全措施。
// 性能与安全平衡：计数器提供顺序，随机字节增加不可预测性。

func generateNonce(counter uint32) (n Nonce, err error) {
	binary.BigEndian.PutUint32(n[:4], counter) // Store counter in first 4 bytes / 将计数器存储在前 4 个字节
	_, err = crand.Read(n[4:])                 // Fill rest with random bytes / 其余部分填充随机字节
	return n, err
}

func generateMaskingIV(buf []byte) error {
	_, err := crand.Read(buf) // Fill buffer with random bytes / 用随机字节填充缓冲区
	return err
}

// nextNonce creates a nonce for encrypting a message to the given session.
// nextNonce 为加密发送给指定会话的消息创建 nonce。
func (sc *SessionCache) nextNonce(s *session) (Nonce, error) {
	s.nonceCounter++                   // Increment nonce counter / 增加 nonce 计数器
	return sc.nonceGen(s.nonceCounter) // Generate nonce with updated counter / 使用更新后的计数器生成 nonce
}

// session returns the current session for the given node, if any.
// session 返回指定节点的当前会话（如果存在）。
func (sc *SessionCache) session(id enode.ID, addr string) *session {
	item, _ := sc.sessions.Get(sessionID{id, addr}) // Retrieve session from LRU cache / 从 LRU 缓存中检索会话
	return item
}

// readKey returns the current read key for the given node.
// readKey 返回指定节点的当前读取密钥。
func (sc *SessionCache) readKey(id enode.ID, addr string) []byte {
	if s := sc.session(id, addr); s != nil { // Check if session exists / 检查会话是否存在
		return s.readKey // Return read key / 返回读取密钥
	}
	return nil // Return nil if no session / 如果没有会话则返回 nil
}

// storeNewSession stores new encryption keys in the cache.
// storeNewSession 将新的加密密钥存储到缓存中。
func (sc *SessionCache) storeNewSession(id enode.ID, addr string, s *session) {
	sc.sessions.Add(sessionID{id, addr}, s) // Add session to LRU cache / 将会话添加到 LRU 缓存
}

// getHandshake gets the handshake challenge we previously sent to the given remote node.
// getHandshake 获取之前发送给指定远程节点的握手挑战。
func (sc *SessionCache) getHandshake(id enode.ID, addr string) *Whoareyou {
	return sc.handshakes[sessionID{id, addr}] // Retrieve handshake from map / 从映射中检索握手
}

// storeSentHandshake stores the handshake challenge sent to the given remote node.
// storeSentHandshake 存储发送给指定远程节点的握手挑战。
func (sc *SessionCache) storeSentHandshake(id enode.ID, addr string, challenge *Whoareyou) {
	challenge.sent = sc.clock.Now()                // Record send time / 记录发送时间
	sc.handshakes[sessionID{id, addr}] = challenge // Store in handshake map / 存储到握手映射中
}

// deleteHandshake deletes handshake data for the given node.
// deleteHandshake 删除指定节点的握手数据。
func (sc *SessionCache) deleteHandshake(id enode.ID, addr string) {
	delete(sc.handshakes, sessionID{id, addr}) // Remove from handshake map / 从握手映射中移除
}

// handshakeGC deletes timed-out handshakes.
// handshakeGC 删除超时的握手。
func (sc *SessionCache) handshakeGC() {
	deadline := sc.clock.Now().Add(-handshakeTimeout) // Calculate deadline (1 second ago) / 计算截止时间（1秒前）
	for key, challenge := range sc.handshakes {       // Iterate over handshakes / 遍历握手
		if challenge.sent < deadline { // Check if timed out / 检查是否超时
			delete(sc.handshakes, key) // Delete if expired / 如果过期则删除
		}
	}
}
