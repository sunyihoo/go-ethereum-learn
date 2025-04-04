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

package p2p

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// DevP2P 协议：定义了消息格式和通信规则，Msg 结构对应其消息单元。
// RLP 编码：以太坊标准序列化格式，用于消息 payload。
// P2P 管道：MsgPipe 模拟节点间通信，便于测试和调试。

// Msg defines the structure of a p2p message.
//
// Note that a Msg can only be sent once since the Payload reader is
// consumed during sending. It is not possible to create a Msg and
// send it any number of times. If you want to reuse an encoded
// structure, encode the payload into a byte array and create a
// separate Msg with a bytes.Reader as Payload for each send.
// Msg 定义了 P2P 消息的结构。
//
// 注意，Msg 只能发送一次，因为在发送过程中 Payload 读取器会被消耗。
// 无法创建 Msg 并多次发送。如果想重用编码结构，请将 payload 编码为字节数组，
// 并为每次发送创建一个带有 bytes.Reader 作为 Payload 的单独 Msg。
type Msg struct {
	Code       uint64    // 消息代码 / Message code
	Size       uint32    // 原始 payload 大小 / Size of the raw payload
	Payload    io.Reader // payload 读取器 / Payload reader
	ReceivedAt time.Time // 接收时间 / Received time

	meterCap  Cap    // 用于出口计量的协议名称和版本 / Protocol name and version for egress metering
	meterCode uint64 // 用于出口计量的协议内的消息代码 / Message within protocol for egress metering
	meterSize uint32 // 用于入口计量的压缩消息大小 / Compressed message size for ingress metering
}

// Decode parses the RLP content of a message into
// the given value, which must be a pointer.
//
// For the decoding rules, please see package rlp.
// Decode 将消息的 RLP 内容解析到给定的值中，该值必须是指针。
//
// 有关解码规则，请参见 rlp 包。
func (msg Msg) Decode(val interface{}) error {
	s := rlp.NewStream(msg.Payload, uint64(msg.Size)) // 创建 RLP 流 / Create RLP stream
	if err := s.Decode(val); err != nil {             // 解码 payload / Decode payload
		return newPeerError(errInvalidMsg, "(code %x) (size %d) %v", msg.Code, msg.Size, err)
		// 返回无效消息错误 / Return invalid message error
	}
	return nil
}

func (msg Msg) String() string {
	return fmt.Sprintf("msg #%v (%v bytes)", msg.Code, msg.Size)
	// 返回消息的字符串表示 / Return string representation of the message
}

// Discard reads any remaining payload data into a black hole.
// Discard 将任何剩余的 payload 数据读取到黑洞中。
func (msg Msg) Discard() error {
	_, err := io.Copy(io.Discard, msg.Payload) // 丢弃 payload / Discard payload
	return err
}

func (msg Msg) Time() time.Time {
	return msg.ReceivedAt // 返回接收时间 / Return received time
}

type MsgReader interface {
	ReadMsg() (Msg, error) // 读取消息 / Read message
}

type MsgWriter interface {
	// WriteMsg sends a message. It will block until the message's
	// Payload has been consumed by the other end.
	//
	// Note that messages can be sent only once because their
	// payload reader is drained.
	// WriteMsg 发送消息。它将阻塞，直到消息的 Payload 被另一端消耗。
	//
	// 注意，消息只能发送一次，因为它们的 payload 读取器会被耗尽。
	WriteMsg(Msg) error
}

// MsgReadWriter provides reading and writing of encoded messages.
// Implementations should ensure that ReadMsg and WriteMsg can be
// called simultaneously from multiple goroutines.
// MsgReadWriter 提供编码消息的读写。
// 实现应确保 ReadMsg 和 WriteMsg 可以从多个 goroutine 同时调用。
type MsgReadWriter interface {
	MsgReader
	MsgWriter
}

// Send writes an RLP-encoded message with the given code.
// data should encode as an RLP list.
// Send 写入带有给定代码的 RLP 编码消息。
// data 应编码为 RLP 列表。
func Send(w MsgWriter, msgcode uint64, data interface{}) error {
	size, r, err := rlp.EncodeToReader(data) // 将数据编码为 RLP / Encode data to RLP
	if err != nil {
		return err
	}
	return w.WriteMsg(Msg{Code: msgcode, Size: uint32(size), Payload: r}) // 发送消息 / Send message
}

// SendItems writes an RLP with the given code and data elements.
// For a call such as:
//
//	SendItems(w, code, e1, e2, e3)
//
// the message payload will be an RLP list containing the items:
//
//	[e1, e2, e3]
//
// SendItems 写入带有给定代码和数据元素的 RLP。
// 对于如下调用：
//
//	SendItems(w, code, e1, e2, e3)
//
// 消息 payload 将是一个包含以下项的 RLP 列表：
//
//	[e1, e2, e3]
func SendItems(w MsgWriter, msgcode uint64, elems ...interface{}) error {
	return Send(w, msgcode, elems) // 发送包含多个元素的 RLP 列表 / Send RLP list with multiple elements
}

// eofSignal wraps a reader with eof signaling. the eof channel is
// closed when the wrapped reader returns an error or when count bytes
// have been read.
// eofSignal 用 eof 信号包装读取器。当被包装的读取器返回错误或读取了 count 字节时，
// eof 通道将被关闭。
type eofSignal struct {
	wrapped io.Reader       // 被包装的读取器 / Wrapped reader
	count   uint32          // 剩余字节数 / Number of bytes left
	eof     chan<- struct{} // EOF 信号通道 / EOF signal channel
}

// note: when using eofSignal to detect whether a message payload
// has been read, Read might not be called for zero sized messages.
// 注意：当使用 eofSignal 检测消息 payload 是否被读取时，
// 对于零大小的消息可能不会调用 Read。
func (r *eofSignal) Read(buf []byte) (int, error) {
	if r.count == 0 { // 如果剩余字节数为 0 / If remaining bytes are 0
		if r.eof != nil {
			r.eof <- struct{}{} // 发送 EOF 信号 / Send EOF signal
			r.eof = nil
		}
		return 0, io.EOF // 返回 EOF / Return EOF
	}

	max := len(buf)
	if int(r.count) < len(buf) {
		max = int(r.count) // 调整最大读取字节数 / Adjust max read bytes
	}
	n, err := r.wrapped.Read(buf[:max]) // 读取数据 / Read data
	r.count -= uint32(n)                // 更新剩余字节数 / Update remaining bytes
	if (err != nil || r.count == 0) && r.eof != nil {
		r.eof <- struct{}{} // 发送 EOF 信号 / Send EOF signal
		r.eof = nil
	}
	return n, err
}

// MsgPipe creates a message pipe. Reads on one end are matched
// with writes on the other. The pipe is full-duplex, both ends
// implement MsgReadWriter.
// MsgPipe 创建一个消息管道。一端的读取与另一端的写入匹配。
// 该管道是全双工的，两端都实现了 MsgReadWriter。
func MsgPipe() (*MsgPipeRW, *MsgPipeRW) {
	var (
		c1, c2  = make(chan Msg), make(chan Msg)      // 创建两个消息通道 / Create two message channels
		closing = make(chan struct{})                 // 关闭信号通道 / Closing signal channel
		closed  = new(atomic.Bool)                    // 关闭状态 / Closed state
		rw1     = &MsgPipeRW{c1, c2, closing, closed} // 管道一端 / One end of the pipe
		rw2     = &MsgPipeRW{c2, c1, closing, closed} // 管道另一端 / Other end of the pipe
	)
	return rw1, rw2
}

// ErrPipeClosed is returned from pipe operations after the
// pipe has been closed.
// ErrPipeClosed 在管道关闭后从管道操作返回。
var ErrPipeClosed = errors.New("p2p: read or write on closed message pipe")

// MsgPipeRW is an endpoint of a MsgReadWriter pipe.
// MsgPipeRW 是 MsgReadWriter 管道的一个端点。
type MsgPipeRW struct {
	w       chan<- Msg    // 写入通道 / Write channel
	r       <-chan Msg    // 读取通道 / Read channel
	closing chan struct{} // 关闭信号 / Closing signal
	closed  *atomic.Bool  // 关闭标志 / Closed flag
}

// WriteMsg sends a message on the pipe.
// It blocks until the receiver has consumed the message payload.
// WriteMsg 在管道上发送消息。
// 它将阻塞，直到接收者消耗了消息 payload。
func (p *MsgPipeRW) WriteMsg(msg Msg) error {
	if !p.closed.Load() { // 如果管道未关闭 / If pipe is not closed
		consumed := make(chan struct{}, 1)                        // 创建消耗信号通道 / Create consumed signal channel
		msg.Payload = &eofSignal{msg.Payload, msg.Size, consumed} // 包装 payload / Wrap payload
		select {
		case p.w <- msg: // 发送消息 / Send message
			if msg.Size > 0 { // 如果 payload 非空 / If payload is not empty
				// wait for payload read or discard
				// 等待 payload 被读取或丢弃
				select {
				case <-consumed: // payload 被消耗 / Payload consumed
				case <-p.closing: // 管道关闭 / Pipe closed
				}
			}
			return nil
		case <-p.closing: // 管道已关闭 / Pipe already closed
		}
	}
	return ErrPipeClosed // 返回管道关闭错误 / Return pipe closed error
}

// ReadMsg returns a message sent on the other end of the pipe.
// ReadMsg 返回管道另一端发送的消息。
func (p *MsgPipeRW) ReadMsg() (Msg, error) {
	if !p.closed.Load() { // 如果管道未关闭 / If pipe is not closed
		select {
		case msg := <-p.r: // 读取消息 / Read message
			return msg, nil
		case <-p.closing: // 管道关闭 / Pipe closed
		}
	}
	return Msg{}, ErrPipeClosed // 返回空消息和管道关闭错误 / Return empty message and pipe closed error
}

// Close unblocks any pending ReadMsg and WriteMsg calls on both ends
// of the pipe. They will return ErrPipeClosed. Close also
// interrupts any reads from a message payload.
// Close 解锁管道两端任何挂起的 ReadMsg 和 WriteMsg 调用。
// 它们将返回 ErrPipeClosed。Close 还会中断从消息 payload 的任何读取。
func (p *MsgPipeRW) Close() error {
	if p.closed.Swap(true) { // 如果已关闭 / If already closed
		// someone else is already closing
		// 其他人已在关闭
		return nil
	}
	close(p.closing) // 关闭信号通道 / Close signal channel
	return nil
}

// ExpectMsg reads a message from r and verifies that its
// code and encoded RLP content match the provided values.
// If content is nil, the payload is discarded and not verified.
// ExpectMsg 从 r 读取消息，并验证其代码和编码的 RLP 内容与提供的值匹配。
// 如果 content 为 nil，则丢弃 payload 且不验证。
func ExpectMsg(r MsgReader, code uint64, content interface{}) error {
	msg, err := r.ReadMsg() // 读取消息 / Read message
	if err != nil {
		return err
	}
	if msg.Code != code { // 检查消息代码 / Check message code
		return fmt.Errorf("message code mismatch: got %d, expected %d", msg.Code, code)
		// 消息代码不匹配 / Message code mismatch
	}
	if content == nil { // 如果内容为空 / If content is nil
		return msg.Discard() // 丢弃 payload / Discard payload
	}
	contentEnc, err := rlp.EncodeToBytes(content) // 编码预期内容 / Encode expected content
	if err != nil {
		panic("content encode error: " + err.Error())
		// 内容编码错误 / Content encode error
	}
	if int(msg.Size) != len(contentEnc) { // 检查大小 / Check size
		return fmt.Errorf("message size mismatch: got %d, want %d", msg.Size, len(contentEnc))
		// 消息大小不匹配 / Message size mismatch
	}
	actualContent, err := io.ReadAll(msg.Payload) // 读取实际内容 / Read actual content
	if err != nil {
		return err
	}
	if !bytes.Equal(actualContent, contentEnc) { // 比较内容 / Compare content
		return fmt.Errorf("message payload mismatch:\ngot:  %x\nwant: %x", actualContent, contentEnc)
		// 消息 payload 不匹配 / Message payload mismatch
	}
	return nil
}

// msgEventer wraps a MsgReadWriter and sends events whenever a message is sent
// or received
// msgEventer 包装 MsgReadWriter，并在消息发送或接收时发送事件。
type msgEventer struct {
	MsgReadWriter // 嵌入 MsgReadWriter / Embedded MsgReadWriter

	feed          *event.Feed // 事件订阅 / Event feed
	peerID        enode.ID    // 对等节点 ID / Peer ID
	Protocol      string      // 协议名称 / Protocol name
	localAddress  string      // 本地地址 / Local address
	remoteAddress string      // 远程地址 / Remote address
}

// newMsgEventer returns a msgEventer which sends message events to the given
// feed
// newMsgEventer 返回一个 msgEventer，它将消息事件发送到给定的事件订阅。
func newMsgEventer(rw MsgReadWriter, feed *event.Feed, peerID enode.ID, proto, remote, local string) *msgEventer {
	return &msgEventer{
		MsgReadWriter: rw,     // 设置 MsgReadWriter / Set MsgReadWriter
		feed:          feed,   // 设置事件订阅 / Set event feed
		peerID:        peerID, // 设置对等节点 ID / Set peer ID
		Protocol:      proto,  // 设置协议 / Set protocol
		remoteAddress: remote, // 设置远程地址 / Set remote address
		localAddress:  local,  // 设置本地地址 / Set local address
	}
}

// ReadMsg reads a message from the underlying MsgReadWriter and emits a
// "message received" event
// ReadMsg 从底层的 MsgReadWriter 读取消息并发出“消息接收”事件。
func (ev *msgEventer) ReadMsg() (Msg, error) {
	msg, err := ev.MsgReadWriter.ReadMsg() // 读取消息 / Read message
	if err != nil {
		return msg, err
	}
	ev.feed.Send(&PeerEvent{ // 发送事件 / Send event
		Type:          PeerEventTypeMsgRecv, // 事件类型 / Event type
		Peer:          ev.peerID,            // 对等节点 / Peer
		Protocol:      ev.Protocol,          // 协议 / Protocol
		MsgCode:       &msg.Code,            // 消息代码 / Message code
		MsgSize:       &msg.Size,            // 消息大小 / Message size
		LocalAddress:  ev.localAddress,      // 本地地址 / Local address
		RemoteAddress: ev.remoteAddress,     // 远程地址 / Remote address
	})
	return msg, nil
}

// WriteMsg writes a message to the underlying MsgReadWriter and emits a
// "message sent" event
// WriteMsg 向底层的 MsgReadWriter 写入消息并发出“消息发送”事件。
func (ev *msgEventer) WriteMsg(msg Msg) error {
	err := ev.MsgReadWriter.WriteMsg(msg) // 写入消息 / Write message
	if err != nil {
		return err
	}
	ev.feed.Send(&PeerEvent{ // 发送事件 / Send event
		Type:          PeerEventTypeMsgSend, // 事件类型 / Event type
		Peer:          ev.peerID,            // 对等节点 / Peer
		Protocol:      ev.Protocol,          // 协议 / Protocol
		MsgCode:       &msg.Code,            // 消息代码 / Message code
		MsgSize:       &msg.Size,            // 消息大小 / Message size
		LocalAddress:  ev.localAddress,      // 本地地址 / Local address
		RemoteAddress: ev.remoteAddress,     // 远程地址 / Remote address
	})
	return nil
}

// Close closes the underlying MsgReadWriter if it implements the io.Closer
// interface
// Close 关闭底层的 MsgReadWriter，如果它实现了 io.Closer 接口。
func (ev *msgEventer) Close() error {
	if v, ok := ev.MsgReadWriter.(io.Closer); ok { // 检查是否实现 io.Closer / Check if io.Closer is implemented
		return v.Close() // 关闭 / Close
	}
	return nil
}
