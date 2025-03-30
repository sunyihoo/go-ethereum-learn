// Copyright 2015 The go-ethereum Authors
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

package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"
)

// 用于统一 RPC 服务的方法命名规则和默认超时设置。
const (
	vsn                      = "2.0"           // 表示协议版本号。通常用于 JSON-RPC，表明遵循版本 2.0 规范。
	serviceMethodSeparator   = "_"             // 服务方法名的分隔符。
	subscribeMethodSuffix    = "_subscribe"    // 订阅方法的后缀。表示订阅某个事件或数据流，例如 eth_subscribe。
	unsubscribeMethodSuffix  = "_unsubscribe"  // 取消订阅方法的后缀。表示取消订阅，例如 eth_unsubscribe。
	notificationMethodSuffix = "_subscription" // 通知方法的后缀。表示订阅的通知回调，例如 eth_subscription。

	defaultWriteTimeout = 10 * time.Second // used if context has no deadline 如果上下文没有截止时间，则使用此值。默认写超时时间。如果上下文未指定截止时间，写操作将在 10 秒后超时。
)

var null = json.RawMessage("null") // 表示 JSON 中的 null 值。"null" 是 JSON 中的空值，直接以字节形式存储。

// 表示订阅通知中的参数部分（未编码结果）。
// 用于存储订阅返回的原始 JSON 数据，避免立即解析。
type subscriptionResult struct {
	ID     string          `json:"subscription"`     // 订阅的唯一标识符。
	Result json.RawMessage `json:"result,omitempty"` // 订阅的结果数据，未解析的 JSON。
}

// 表示订阅通知中的参数部分（已编码结果）。
// 用于在需要解析结果时存储具体类型的值。
type subscriptionResultEnc struct {
	ID     string `json:"subscription"` // 订阅的唯一标识符。
	Result any    `json:"result"`       // 订阅的结果数据，使用 any（等价于 interface{}）表示任意类型。与 subscriptionResult 的区别在于这里允许解析后的值。
}

// 表示完整的 JSON-RPC 订阅通知消息。
//
// eg:
//
//	{
//	 "jsonrpc": "2.0",
//	 "method": "eth_subscription",
//	 "params": {
//	   "subscription": "0x123",
//	   "result": {"number": "0x1b4"}
//	 }
//	}
type jsonrpcSubscriptionNotification struct {
	Version string                `json:"jsonrpc"` // JSON-RPC 协议版本，例如 "2.0"。
	Method  string                `json:"method"`  // 通知的方法名，例如 "eth_subscription"。
	Params  subscriptionResultEnc `json:"params"`  // 通知的参数，嵌套 subscriptionResultEnc 结构体。
}

// 消息类型的判断
//
// 请求: 包含 jsonrpc, id, method, params。
// 示例: {"jsonrpc":"2.0","id":1,"method":"eth_call","params":["0x..."]}
//
// 通知: 包含 jsonrpc, method, params，无 id。
// 示例: {"jsonrpc":"2.0","method":"eth_subscription","params":{"subscription":"0x123"}}
//
// 成功响应: 包含 jsonrpc, id, result。
// 示例: {"jsonrpc":"2.0","id":1,"result":"0x456"}
//
// 错误响应: 包含 jsonrpc, id, error。
// 示例: {"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}

// A value of this type can a JSON-RPC request, notification, successful response or
// error response. Which one it is depends on the fields.
//
// 此类型的值可以是 JSON-RPC 请求、通知、成功响应或错误响应。具体是哪种类型取决于字段。
// 表示 JSON-RPC 2.0 协议中的通用消息格式，能够涵盖请求、通知、成功响应和错误响应。
type jsonrpcMessage struct {
	Version string          `json:"jsonrpc,omitempty"` // JSON-RPC 协议版本，通常为 "2.0"。在所有消息类型中都应存在。
	ID      json.RawMessage `json:"id,omitempty"`      // 请求的唯一标识符，可以是数字、字符串或 null。用于匹配请求和响应，在通知中不存在。
	Method  string          `json:"method,omitempty"`  // 请求或通知的方法名，例如 "eth_call"。在请求和通知中存在，响应中不存在。
	Params  json.RawMessage `json:"params,omitempty"`  // 请求或通知的参数，未解析的 JSON 数据。在请求和通知中存在，响应中不存在。
	Error   *jsonError      `json:"error,omitempty"`   // 错误对象。在错误响应中存在，其他情况不存在。
	Result  json.RawMessage `json:"result,omitempty"`  // 成功响应的结果，未解析的 JSON 数据。在成功响应中存在，其他情况不存在。
}

// 判断消息是否为 JSON-RPC 通知。
// 识别无响应的订阅通知，例如 {"jsonrpc":"2.0","method":"eth_subscription","params":{...}}。
func (msg *jsonrpcMessage) isNotification() bool {
	// 版本必须为 "2.0"（vsn），通知没有 id 字段，必须有方法名。
	return msg.hasValidVersion() && msg.ID == nil && msg.Method != ""
}

// 判断消息是否为 JSON-RPC 请求（调用）。
// 识别需要响应的请求，例如 {"jsonrpc":"2.0","id":1,"method":"eth_call","params":["0x..."]}。
func (msg *jsonrpcMessage) isCall() bool {
	return msg.hasValidVersion() && msg.hasValidID() && msg.Method != ""
}

// 判断消息是否为 JSON-RPC 响应。
// 识别成功或错误响应，例如 {"jsonrpc":"2.0","id":1,"result":"0x456"}。
func (msg *jsonrpcMessage) isResponse() bool {
	// 版本必须为 "2.0"。必须有有效 id。响应没有方法名。响应没有参数。必须有结果或错误。
	return msg.hasValidVersion() && msg.hasValidID() && msg.Method == "" && msg.Params == nil && (msg.Result != nil || msg.Error != nil)
}

// 检查 id 是否有效。
func (msg *jsonrpcMessage) hasValidID() bool {
	// 不能是对象 {} 或数组 []（JSON-RPC 2.0 要求 id 为字符串、数字或 null）。
	return len(msg.ID) > 0 && msg.ID[0] != '{' && msg.ID[0] != '['
}

// 检查版本是否有效。确保消息遵循 JSON-RPC 2.0。
func (msg *jsonrpcMessage) hasValidVersion() bool {
	return msg.Version == vsn
}

// 判断是否为订阅请求。识别订阅方法，例如 "eth_subscribe"。
func (msg *jsonrpcMessage) isSubscribe() bool {
	return strings.HasSuffix(msg.Method, subscribeMethodSuffix)
}

// 判断是否为取消订阅请求。识别取消订阅方法，例如 "eth_unsubscribe"。
func (msg *jsonrpcMessage) isUnsubscribe() bool {
	return strings.HasSuffix(msg.Method, unsubscribeMethodSuffix)
}

// 提取方法名中的命名空间。分离服务名和方法名。
// 示例: "ui_approveTx" 返回 "ui"。
func (msg *jsonrpcMessage) namespace() string {
	before, _, _ := strings.Cut(msg.Method, serviceMethodSeparator)
	return before
}

// 将消息序列化为 JSON 字符串。
func (msg *jsonrpcMessage) String() string {
	b, _ := json.Marshal(msg)
	return string(b)
}

func (msg *jsonrpcMessage) errorResponse(err error) *jsonrpcMessage {
	resp := errorMessage(err)
	resp.ID = msg.ID
	return resp
}

func (msg *jsonrpcMessage) response(result interface{}) *jsonrpcMessage {
	enc, err := json.Marshal(result)
	if err != nil {
		return msg.errorResponse(&internalServerError{errcodeMarshalError, err.Error()})
	}
	return &jsonrpcMessage{Version: vsn, ID: msg.ID, Result: enc}
}

func errorMessage(err error) *jsonrpcMessage {
	msg := &jsonrpcMessage{Version: vsn, ID: null, Error: &jsonError{
		Code:    errcodeDefault,
		Message: err.Error(),
	}}
	ec, ok := err.(Error)
	if ok {
		msg.Error.Code = ec.ErrorCode()
	}
	de, ok := err.(DataError)
	if ok {
		msg.Error.Data = de.ErrorData()
	}
	return msg
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (err *jsonError) Error() string {
	if err.Message == "" {
		return fmt.Sprintf("json-rpc error %d", err.Code)
	}
	return err.Message
}

func (err *jsonError) ErrorCode() int {
	return err.Code
}

func (err *jsonError) ErrorData() interface{} {
	return err.Data
}

// Conn is a subset of the methods of net.Conn which are sufficient for ServerCodec.
type Conn interface {
	io.ReadWriteCloser
	SetWriteDeadline(time.Time) error
}

type deadlineCloser interface {
	io.Closer
	SetWriteDeadline(time.Time) error
}

// ConnRemoteAddr wraps the RemoteAddr operation, which returns a description
// of the peer address of a connection. If a Conn also implements ConnRemoteAddr, this
// description is used in log messages.
//
// ConnRemoteAddr 封装了 RemoteAddr 操作，该操作返回连接的对等地址的描述。
// 如果一个 Conn 也实现了 ConnRemoteAddr，则此描述将用于日志消息中。
type ConnRemoteAddr interface {
	RemoteAddr() string // RemoteAddr 返回连接的对等地址的字符串描述。
}

// jsonCodec reads and writes JSON-RPC messages to the underlying connection. It also has
// support for parsing arguments and serializing (result) objects.
// jsonCodec 读取和写入 JSON-RPC 消息到下层连接。它还支持
// 解析参数和序列化（结果）对象。
type jsonCodec struct {
	remote  string           // 存储连接的远程地址（如果可用）。
	closer  sync.Once        // close closed channel once  closeCh 只关闭一次
	closeCh chan interface{} // closed on Close            在 Close 时关闭
	decode  decodeFunc       // decoder to allow multiple transports 解码器，允许使用多种传输方式
	encMu   sync.Mutex       // guards the encoder          保护编码器
	encode  encodeFunc       // encoder to allow multiple transports 编码器，允许使用多种传输方式
	conn    deadlineCloser
}

type encodeFunc = func(v interface{}, isErrorResponse bool) error

type decodeFunc = func(v interface{}) error

// NewFuncCodec creates a codec which uses the given functions to read and write. If conn
// implements ConnRemoteAddr, log messages will use it to include the remote address of
// the connection.
//
// NewFuncCodec 创建一个使用给定函数进行读写的编解码器。如果 conn
// 实现了 ConnRemoteAddr，日志消息将使用它来包含连接的远程地址。
func NewFuncCodec(conn deadlineCloser, encode encodeFunc, decode decodeFunc) ServerCodec {
	codec := &jsonCodec{
		closeCh: make(chan interface{}),
		encode:  encode,
		decode:  decode,
		conn:    conn,
	}
	if ra, ok := conn.(ConnRemoteAddr); ok {
		codec.remote = ra.RemoteAddr()
	}
	return codec
}

// NewCodec creates a codec on the given connection. If conn implements ConnRemoteAddr, log
// messages will use it to include the remote address of the connection.
//
// NewCodec 在给定的连接上创建一个编解码器。如果 conn 实现了 ConnRemoteAddr，日志
// 消息将使用它来包含连接的远程地址。
func NewCodec(conn Conn) ServerCodec {
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	dec.UseNumber()

	encode := func(v interface{}, isErrorResponse bool) error {
		return enc.Encode(v)
	}
	return NewFuncCodec(conn, encode, dec.Decode)
}

func (c *jsonCodec) peerInfo() PeerInfo {
	// This returns "ipc" because all other built-in transports have a separate codec type.
	// 这里返回 "ipc" 是因为所有其他内置的传输方式都有单独的编解码器类型。
	return PeerInfo{Transport: "ipc", RemoteAddr: c.remote}
}

func (c *jsonCodec) remoteAddr() string {
	return c.remote
}

func (c *jsonCodec) readBatch() (messages []*jsonrpcMessage, batch bool, err error) {
	// Decode the next JSON object in the input stream.
	// This verifies basic syntax, etc.
	// 解码输入流中的下一个 JSON 对象。
	// 这会验证基本语法等。
	var rawmsg json.RawMessage
	if err := c.decode(&rawmsg); err != nil {
		return nil, false, err
	}
	messages, batch = parseMessage(rawmsg)
	for i, msg := range messages {
		if msg == nil {
			// Message is JSON 'null'. Replace with zero value so it
			// will be treated like any other invalid message.
			// 消息是 JSON 'null'。替换为零值，以便像任何其他无效消息一样处理。
			messages[i] = new(jsonrpcMessage)
		}
	}
	return messages, batch, nil
}

func (c *jsonCodec) writeJSON(ctx context.Context, v interface{}, isErrorResponse bool) error {
	c.encMu.Lock()
	defer c.encMu.Unlock()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(defaultWriteTimeout)
	}
	c.conn.SetWriteDeadline(deadline)
	return c.encode(v, isErrorResponse)
}

func (c *jsonCodec) close() {
	c.closer.Do(func() {
		close(c.closeCh)
		c.conn.Close()
	})
}

// closed returns a channel which will be closed when Close is called
// closed 返回一个通道，该通道在 Close 被调用时关闭
func (c *jsonCodec) closed() <-chan interface{} {
	return c.closeCh
}

// parseMessage parses raw bytes as a (batch of) JSON-RPC message(s). There are no error
// checks in this function because the raw message has already been syntax-checked when it
// is called. Any non-JSON-RPC messages in the input return the zero value of
// jsonrpcMessage.
//
// parseMessage 解析原始字节作为一个（批量）JSON-RPC 消息。此函数中没有错误检查，因为原始消息在调用时已经进行了语法检查。
// 输入中的任何非 JSON-RPC 消息将返回 jsonrpcMessage 的零值。
func parseMessage(raw json.RawMessage) ([]*jsonrpcMessage, bool) {
	if !isBatch(raw) {
		msgs := []*jsonrpcMessage{{}}
		json.Unmarshal(raw, &msgs[0])
		return msgs, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.Token() // skip '['
	var msgs []*jsonrpcMessage
	// TODO: More examples
	for dec.More() { // dec.More() 用于检查是否有更多的 JSON 数据来解析。
		msgs = append(msgs, new(jsonrpcMessage))
		dec.Decode(&msgs[len(msgs)-1])
	}
	return msgs, true
}

// isBatch returns true when the first non-whitespace characters is '['
//
// isBatch 当第一个非空格字符是 '[' 时返回 true
// 该函数用于判断一个 JSON-RPC 消息是否是批量请求格式。批量请求是指一次性包含多个请求的 JSON 数据（通常是一个数组）。
//
// 在以太坊中，批量请求通常用于同时发送多个请求，以提高效率。JSON-RPC 批量请求允许客户端一次发送多个请求，并一次性接收多个响应。
func isBatch(raw json.RawMessage) bool {
	for _, c := range raw {
		// skip insignificant whitespace (http://www.ietf.org/rfc/rfc4627.txt)
		// 跳过无意义的空白字符 (http://www.ietf.org/rfc/rfc4627.txt)
		if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
			continue
		}
		return c == '['
	}
	return false
}

// parsePositionalArguments tries to parse the given args to an array of values with the
// given types. It returns the parsed values or an error when the args could not be
// parsed. Missing optional arguments are returned as reflect.Zero values.
//
// parsePositionalArguments 尝试将给定的参数解析为具有给定类型的值数组。
// 它返回解析后的值，或者在参数无法解析时返回错误。
// 缺失的可选参数将返回 reflect.Zero 值。
func parsePositionalArguments(rawArgs json.RawMessage, types []reflect.Type) ([]reflect.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(rawArgs))
	var args []reflect.Value
	tok, err := dec.Token()
	switch {
	case err == io.EOF || tok == nil && err == nil:
		// "params" is optional and may be empty. Also allow "params":null even though it's
		// not in the spec because our own client used to send it.
		// "params" 是可选的，可以为空。也允许 "params":null，尽管这在规范中没有定义，
		// 但是我们自己的客户端以前曾发送过这个。
	case err != nil:
		return nil, err
	case tok == json.Delim('['):
		// Read argument array.
		// 读取参数数组。
		if args, err = parseArgumentArray(dec, types); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("non-array args")
	}
	// Set any missing args to nil.
	// 将缺失的参数设置为 nil。
	for i := len(args); i < len(types); i++ {
		if types[i].Kind() != reflect.Ptr {
			return nil, fmt.Errorf("missing value for required argument %d", i)
		}
		args = append(args, reflect.Zero(types[i]))
	}
	return args, nil
}

func parseArgumentArray(dec *json.Decoder, types []reflect.Type) ([]reflect.Value, error) {
	args := make([]reflect.Value, 0, len(types))
	for i := 0; dec.More(); i++ {
		if i >= len(types) {
			return args, fmt.Errorf("too many arguments, want at most %d", len(types))
		}
		argval := reflect.New(types[i])
		if err := dec.Decode(argval.Interface()); err != nil {
			return args, fmt.Errorf("invalid argument %d: %v", i, err)
		}
		if argval.IsNil() && types[i].Kind() != reflect.Ptr {
			return args, fmt.Errorf("missing value for required argument %d", i)
		}
		args = append(args, argval.Elem())
	}
	// Read end of args array.
	// 读取参数数组的结束标记。
	_, err := dec.Token()
	return args, err
}

// parseSubscriptionName extracts the subscription name from an encoded argument array.
// parseSubscriptionName 从编码的参数数组中提取订阅名称。
func parseSubscriptionName(rawArgs json.RawMessage) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(rawArgs))
	// 第一个 token 应该是 JSON 数组的开始标记 [。json.Delim('[') 表示这个开始标记。如果读取到的 token 不是这个开始标记，说明 rawArgs 不是一个 JSON 数组，函数会返回一个错误。
	if tok, _ := dec.Token(); tok != json.Delim('[') {
		return "", errors.New("non-array args")
	}
	v, _ := dec.Token() // 读取数组中的第一个元素
	method, ok := v.(string)
	if !ok {
		return "", errors.New("expected subscription name as first argument")
	}
	return method, nil
}
