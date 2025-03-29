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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// API describes the set of methods offered over the RPC interface
// API 描述了通过 RPC 接口提供的方法集合
type API struct {
	Namespace     string      // namespace under which the rpc methods of Service are exposed              Service 的 RPC 方法暴露在其下的命名空间。命名空间有助于组织和区分不同的功能模块提供的 RPC 方法。例如，在以太坊的 JSON-RPC API 中，就存在 eth、net、web3 等不同的命名空间。
	Version       string      // deprecated - this field is no longer used, but retained for compatibility 已弃用 - 该字段不再使用，但为了兼容性而保留。
	Service       interface{} // receiver instance which holds the methods                                 包含这些方法的接收者实例。
	Public        bool        // deprecated - this field is no longer used, but retained for compatibility 已弃用 - 该字段不再使用，但为了兼容性而保留。
	Authenticated bool        // whether the api should only be available behind authentication.           指示该 API 是否应该仅在通过身份验证后可用。
}

// ServerCodec implements reading, parsing and writing RPC messages for the server side of
// an RPC session. Implementations must be go-routine safe since the codec can be called in
// multiple go-routines concurrently.
//
// ServerCodec 实现了 RPC 会话服务器端的 RPC 消息的读取、解析和写入。
// 实现必须是 goroutine 安全的，因为 codec 可以被多个 goroutine 并发调用。
//
// 定义了 RPC 会话服务器端读取、解析和写入消息所需的全部方法。
type ServerCodec interface {
	peerInfo() PeerInfo                                           // 返回关于连接的对等方的信息。
	readBatch() (msgs []*jsonrpcMessage, isBatch bool, err error) // 从连接中读取一批 RPC 消息。JSON-RPC 协议支持批量请求。
	close()                                                       //  关闭底层的连接。

	jsonWriter
}

// jsonWriter can write JSON messages to its underlying connection.
// Implementations must be safe for concurrent use.
//
// jsonWriter 可以将 JSON 消息写入其底层连接。
// 实现必须是并发安全的。
type jsonWriter interface {
	// writeJSON writes a message to the connection.
	// writeJSON 将消息写入连接。
	// 将给定的消息 msg 编码为 JSON 格式，并通过底层连接发送出去。
	writeJSON(ctx context.Context, msg interface{}, isError bool) error

	// Closed returns a channel which is closed when the connection is closed.
	// Closed 返回一个通道，该通道在连接关闭时关闭。
	// 返回一个只读的通道。当底层的连接关闭时，该通道会被关闭。这允许其他部分的代码监听连接的关闭事件。
	closed() <-chan interface{}
	// RemoteAddr returns the peer address of the connection.
	// RemoteAddr 返回连接的对等地址。
	// 返回与当前连接的远程对等方的网络地址（例如 IP 地址和端口号）。
	remoteAddr() string
}

//  在以太坊区块链中，每个区块都有一个唯一的编号，称为区块高度。通常，我们用非负整数来表示具体的区块高度。

type BlockNumber int64

const (
	SafeBlockNumber      = BlockNumber(-4) // 安全的区块号    在以太坊中，由于区块链可能发生重组（reorg），最新的几个区块可能不稳定。一个“安全”的区块通常是指已经经过足够多的确认，不太可能被回滚的区块。具体的确认数可能因实现和配置而异。
	FinalizedBlockNumber = BlockNumber(-3) // 已完成的区块号  已经达到最终确定性的区块。在以太坊的权益证明（PoS）共识机制下，最终确定性是一个更强的保证，表示该区块及其之前的所有区块都不会被撤销。
	LatestBlockNumber    = BlockNumber(-2) // 最新的区块号    这个常量指区块链上最新的、刚刚被矿工挖出的区块。
	PendingBlockNumber   = BlockNumber(-1) // 待处理的区块号  指当前正在被矿工处理、尚未被添加到区块链中的区块。查询这个状态可以获取最新的交易信息，但这些信息尚未最终确认。
	EarliestBlockNumber  = BlockNumber(0)  // 最早的区块号    指区块链上的第一个区块，也称为创世区块（genesis block）。它的区块高度为 0。
)

// JSON-RPC 中的区块号表示： 在与以太坊节点进行 JSON-RPC 通信时，区块号可以有多种表示方式。除了具体的区块高度（通常编码为十六进制字符串），还可以使用特定的标签来引用区块链的不同状态。
// 特殊区块号标签： "latest"、"earliest" 和 "pending" 是 JSON-RPC 标准中常用的标签。而 "safe" 和 "finalized" 是在以太坊升级后引入的，用于表示更稳定的区块状态。

// UnmarshalJSON parses the given JSON fragment into a BlockNumber. It supports:
// - "safe", "finalized", "latest", "earliest" or "pending" as string arguments
// - the block number
// Returned errors:
// - an invalid block number error when the given argument isn't a known strings
// - an out of range error when the given block number is either too little or too large
//
// UnmarshalJSON 将给定的 JSON 片段解析为一个 BlockNumber。它支持：
// - "safe", "finalized", "latest", "earliest" 或 "pending" 作为字符串参数
// - 区块号
// 返回的错误：
// - 当给定的参数不是已知的字符串时，返回一个无效的区块号错误
// - 当给定的区块号过小或过大时，返回一个超出范围的错误
func (bn *BlockNumber) UnmarshalJSON(data []byte) error {
	input := strings.TrimSpace(string(data))                              // 去除输入字符串两端的空白
	if len(input) >= 2 && input[0] == '"' && input[len(input)-1] == '"' { // 如果输入是带引号的字符串
		input = input[1 : len(input)-1] // 移除引号
	}

	switch input {
	case "earliest":
		*bn = EarliestBlockNumber
		return nil
	case "latest":
		*bn = LatestBlockNumber
		return nil
	case "pending":
		*bn = PendingBlockNumber
		return nil
	case "finalized":
		*bn = FinalizedBlockNumber
		return nil
	case "safe":
		*bn = SafeBlockNumber
		return nil
	}

	// 如果输入字符串不是特殊字符串，则尝试使用 hexutil.DecodeUint64 函数将其解析为一个无符号 64 位整数。
	blckNum, err := hexutil.DecodeUint64(input) // 尝试将输入解析为十六进制的 uint64
	if err != nil {
		return err
	}
	if blckNum > math.MaxInt64 { // 检查区块号是否超出 int64 的最大值
		return errors.New("block number larger than int64")
	}
	*bn = BlockNumber(blckNum) // 将解析出的 uint64 转换为 BlockNumber 并赋值给接收者
	return nil
}

// Int64 returns the block number as int64.
// Int64 返回区块号的 int64 表示。
func (bn BlockNumber) Int64() int64 {
	return (int64)(bn)
}

// MarshalText implements encoding.TextMarshaler. It marshals:
// - "safe", "finalized", "latest", "earliest" or "pending" as strings
// - other numbers as hex
//
// MarshalText 实现了 encoding.TextMarshaler 接口。它将以下内容序列化为文本：
// - "safe", "finalized", "latest", "earliest" 或 "pending" 作为字符串
// - 其他数字作为十六进制
func (bn BlockNumber) MarshalText() ([]byte, error) {
	return []byte(bn.String()), nil
}

func (bn BlockNumber) String() string {
	switch bn {
	case EarliestBlockNumber:
		return "earliest"
	case LatestBlockNumber:
		return "latest"
	case PendingBlockNumber:
		return "pending"
	case FinalizedBlockNumber:
		return "finalized"
	case SafeBlockNumber:
		return "safe"
	default:
		if bn < 0 {
			return fmt.Sprintf("<invalid %d>", bn)
		}
		return hexutil.Uint64(bn).String()
	}
}

type BlockNumberOrHash struct {
	BlockNumber      *BlockNumber `json:"blockNumber,omitempty"`      // 区块号（可选）
	BlockHash        *common.Hash `json:"blockHash,omitempty"`        // 区块哈希（可选）
	RequireCanonical bool         `json:"requireCanonical,omitempty"` // 是否要求是规范链上的区块（可选）
}

func (bnh *BlockNumberOrHash) UnmarshalJSON(data []byte) error {
	type erased BlockNumberOrHash // 创建一个别名，用于避免在 UnmarshalJSON 中无限递归
	e := erased{}
	err := json.Unmarshal(data, &e) // 尝试将 JSON 数据解析为 BlockNumberOrHash 结构体
	if err == nil {
		if e.BlockNumber != nil && e.BlockHash != nil {
			return errors.New("cannot specify both BlockHash and BlockNumber, choose one or the other")
		}
		bnh.BlockNumber = e.BlockNumber
		bnh.BlockHash = e.BlockHash
		bnh.RequireCanonical = e.RequireCanonical
		return nil
	}
	var input string
	err = json.Unmarshal(data, &input)
	if err != nil {
		return err
	}
	switch input {
	case "earliest":
		bn := EarliestBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "latest":
		bn := LatestBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "pending":
		bn := PendingBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "finalized":
		bn := FinalizedBlockNumber
		bnh.BlockNumber = &bn
		return nil
	case "safe":
		bn := SafeBlockNumber
		bnh.BlockNumber = &bn
		return nil
	default:
		if len(input) == 66 { // 检查字符串长度是否为 66，这通常是包含 "0x" 前缀的区块哈希的长度
			hash := common.Hash{}
			err := hash.UnmarshalText([]byte(input)) // 尝试将字符串解析为区块哈希
			if err != nil {
				return err
			}
			bnh.BlockHash = &hash
			return nil
		} else {
			blckNum, err := hexutil.DecodeUint64(input) // 尝试将字符串解析为十六进制的区块号
			if err != nil {
				return err
			}
			if blckNum > math.MaxInt64 {
				return errors.New("blocknumber too high")
			}
			bn := BlockNumber(blckNum)
			bnh.BlockNumber = &bn
			return nil
		}
	}
}

func (bnh *BlockNumberOrHash) Number() (BlockNumber, bool) {
	if bnh.BlockNumber != nil {
		return *bnh.BlockNumber, true
	}
	return BlockNumber(0), false
}

func (bnh *BlockNumberOrHash) String() string {
	if bnh.BlockNumber != nil {
		return bnh.BlockNumber.String()
	}
	if bnh.BlockHash != nil {
		return bnh.BlockHash.String()
	}
	return "nil"
}

func (bnh *BlockNumberOrHash) Hash() (common.Hash, bool) {
	if bnh.BlockHash != nil {
		return *bnh.BlockHash, true
	}
	return common.Hash{}, false
}

func BlockNumberOrHashWithNumber(blockNr BlockNumber) BlockNumberOrHash {
	return BlockNumberOrHash{
		BlockNumber:      &blockNr,
		BlockHash:        nil,
		RequireCanonical: false,
	}
}

func BlockNumberOrHashWithHash(hash common.Hash, canonical bool) BlockNumberOrHash {
	return BlockNumberOrHash{
		BlockNumber:      nil,
		BlockHash:        &hash,
		RequireCanonical: canonical,
	}
}
