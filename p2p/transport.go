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

package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p/rlpx"
	"github.com/ethereum/go-ethereum/rlp"
)

// 以太坊 RLPx 传输层
// rlpxTransport 是 Go-Ethereum 中用于实际网络连接的传输层实现，基于 RLPx 协议（以太坊 DevP2P 的传输层）。它负责加密握手、协议握手和消息传输，是节点间安全通信的关键组件。
//
// 以太坊相关知识点：
//  RLPx 协议：基于 TCP 的加密传输协议，使用 ECDH 密钥交换和 AES 加密。
//  DevP2P：以太坊的 P2P 网络协议栈，rlpxTransport 是其底层实现。
//  EIP-8：定义了握手格式，doProtoHandshake 遵循此标准。

const (
	// total timeout for encryption handshake and protocol
	// handshake in both directions.
	// 加密握手和协议握手的总超时时间，双向。
	handshakeTimeout = 5 * time.Second

	// This is the timeout for sending the disconnect reason.
	// This is shorter than the usual timeout because we don't want
	// to wait if the connection is known to be bad anyway.
	// 发送断开原因的超时时间。
	// 这个时间比通常的超时时间短，因为如果连接已知有问题，我们不想等待。
	discWriteTimeout = 1 * time.Second
)

// rlpxTransport is the transport used by actual (non-test) connections.
// It wraps an RLPx connection with locks and read/write deadlines.
// rlpxTransport 是实际（非测试）连接使用的传输层。
// 它包装了一个 RLPx 连接，并添加了锁和读写截止时间。
type rlpxTransport struct {
	rmu, wmu sync.Mutex   // 读写互斥锁 / Read and write mutexes
	wbuf     bytes.Buffer // 写入缓冲区 / Write buffer
	conn     *rlpx.Conn   // RLPx 连接 / RLPx connection
}

func newRLPX(conn net.Conn, dialDest *ecdsa.PublicKey) transport {
	return &rlpxTransport{conn: rlpx.NewConn(conn, dialDest)}
	// 创建新的 RLPx 传输实例 / Create a new RLPx transport instance
}

func (t *rlpxTransport) ReadMsg() (Msg, error) {
	t.rmu.Lock()         // 加读锁 / Lock for reading
	defer t.rmu.Unlock() // 延迟解锁 / Defer unlock

	var msg Msg
	t.conn.SetReadDeadline(time.Now().Add(frameReadTimeout)) // 设置读取截止时间 / Set read deadline
	code, data, wireSize, err := t.conn.Read()               // 读取消息 / Read message
	if err == nil {
		// Protocol messages are dispatched to subprotocol handlers asynchronously,
		// but package rlpx may reuse the returned 'data' buffer on the next call
		// to Read. Copy the message data to avoid this being an issue.
		// 协议消息异步分派到子协议处理程序，
		// 但 rlpx 包可能在下次调用 Read 时重用返回的 'data' 缓冲区。
		// 复制消息数据以避免这个问题。
		data = common.CopyBytes(data) // 复制数据 / Copy data
		msg = Msg{
			ReceivedAt: time.Now(),            // 设置接收时间 / Set received time
			Code:       code,                  // 设置消息代码 / Set message code
			Size:       uint32(len(data)),     // 设置消息大小 / Set message size
			meterSize:  uint32(wireSize),      // 设置传输大小 / Set wire size
			Payload:    bytes.NewReader(data), // 创建 payload 读取器 / Create payload reader
		}
	}
	return msg, err
}

func (t *rlpxTransport) WriteMsg(msg Msg) error {
	t.wmu.Lock()         // 加写锁 / Lock for writing
	defer t.wmu.Unlock() // 延迟解锁 / Defer unlock

	// Copy message data to write buffer.
	// 将消息数据复制到写入缓冲区。
	t.wbuf.Reset() // 重置缓冲区 / Reset buffer
	if _, err := io.CopyN(&t.wbuf, msg.Payload, int64(msg.Size)); err != nil {
		return err // 复制失败返回错误 / Return error if copy fails
	}

	// Write the message.
	// 写入消息。
	t.conn.SetWriteDeadline(time.Now().Add(frameWriteTimeout)) // 设置写入截止时间 / Set write deadline
	size, err := t.conn.Write(msg.Code, t.wbuf.Bytes())        // 写入消息 / Write message
	if err != nil {
		return err // 写入失败返回错误 / Return error if write fails
	}

	// Set metrics.
	// 设置指标。
	msg.meterSize = size
	if metrics.Enabled() && msg.meterCap.Name != "" { // don't meter non-subprotocol messages
		// 如果指标启用且消息属于子协议，则记录 / Record if metrics enabled and message is subprotocol
		m := fmt.Sprintf("%s/%s/%d/%#02x", egressMeterName, msg.meterCap.Name, msg.meterCap.Version, msg.meterCode)
		metrics.GetOrRegisterMeter(m, nil).Mark(int64(msg.meterSize)) // 记录数据量 / Record data size
		metrics.GetOrRegisterMeter(m+"/packets", nil).Mark(1)         // 记录数据包计数 / Record packet count
	}
	return nil
}

func (t *rlpxTransport) close(err error) {
	t.wmu.Lock()         // 加写锁 / Lock for writing
	defer t.wmu.Unlock() // 延迟解锁 / Defer unlock

	// Tell the remote end why we're disconnecting if possible.
	// We only bother doing this if the underlying connection supports
	// setting a timeout tough.
	// 如果可能，告诉远程端我们断开的原因。
	// 只有在底层连接支持设置超时的情况下才这样做。
	if reason, ok := err.(DiscReason); ok && reason != DiscNetworkError {
		// 我们不使用 WriteMsg 函数，因为我们想要自定义截止时间
		// We do not use the WriteMsg func since we want a custom deadline
		deadline := time.Now().Add(discWriteTimeout) // 设置断开写入截止时间 / Set disconnect write deadline
		if err := t.conn.SetWriteDeadline(deadline); err == nil {
			// Connection supports write deadline.
			// 连接支持写入截止时间。
			t.wbuf.Reset()                        // 重置缓冲区 / Reset buffer
			rlp.Encode(&t.wbuf, []any{reason})    // 编码断开原因 / Encode disconnect reason
			t.conn.Write(discMsg, t.wbuf.Bytes()) // 写入断开消息 / Write disconnect message
		}
	}
	t.conn.Close() // 关闭连接 / Close connection
}

func (t *rlpxTransport) doEncHandshake(prv *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	t.conn.SetDeadline(time.Now().Add(handshakeTimeout)) // 设置握手截止时间 / Set handshake deadline
	return t.conn.Handshake(prv)                         // 执行加密握手 / Perform encryption handshake
}

func (t *rlpxTransport) doProtoHandshake(our *protoHandshake) (their *protoHandshake, err error) {
	// Writing our handshake happens concurrently, we prefer
	// returning the handshake read error. If the remote side
	// disconnects us early with a valid reason, we should return it
	// as the error so it can be tracked elsewhere.
	// 我们的握手写入是并发进行的，我们优先返回读取错误。
	// 如果远程端提前断开并提供有效原因，我们应将其作为错误返回，以便在其他地方跟踪。
	werr := make(chan error, 1)
	go func() { werr <- Send(t, handshakeMsg, our) }() // 并发发送我们的握手 / Concurrently send our handshake
	if their, err = readProtocolHandshake(t); err != nil {
		<-werr // make sure the write terminates too
		// 确保写入也终止 / Ensure write terminates
		return nil, err
	}
	if err := <-werr; err != nil {
		return nil, fmt.Errorf("write error: %v", err) // 返回写入错误 / Return write error
	}
	// If the protocol version supports Snappy encoding, upgrade immediately
	// 如果协议版本支持 Snappy 编码，立即升级
	t.conn.SetSnappy(their.Version >= snappyProtocolVersion)

	return their, nil
}

func readProtocolHandshake(rw MsgReader) (*protoHandshake, error) {
	msg, err := rw.ReadMsg() // 读取消息 / Read message
	if err != nil {
		return nil, err
	}
	if msg.Size > baseProtocolMaxMsgSize { // 检查消息大小 / Check message size
		return nil, errors.New("message too big")
		// 消息过大 / Message too big
	}
	if msg.Code == discMsg { // 检查是否为断开消息 / Check if disconnect message
		// Disconnect before protocol handshake is valid according to the
		// spec and we send it ourself if the post-handshake checks fail.
		// 在协议握手之前断开是有效的，根据规范，
		// 如果握手后检查失败，我们会自己发送它。
		r := decodeDisconnectMessage(msg.Payload) // 解码断开原因 / Decode disconnect reason
		return nil, r
	}
	if msg.Code != handshakeMsg { // 检查是否为握手消息 / Check if handshake message
		return nil, fmt.Errorf("expected handshake, got %x", msg.Code)
		// 预期握手消息，收到其他 / Expected handshake, got other
	}
	var hs protoHandshake
	if err := msg.Decode(&hs); err != nil { // 解码握手消息 / Decode handshake message
		return nil, err
	}
	if len(hs.ID) != 64 || !bitutil.TestBytes(hs.ID) { // 验证 ID / Validate ID
		return nil, DiscInvalidIdentity
		// 无效身份 / Invalid identity
	}
	return &hs, nil
}
