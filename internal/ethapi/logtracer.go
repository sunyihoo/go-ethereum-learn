// Copyright 2023 The go-ethereum Authors
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

package ethapi

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

var (
	// keccak256("Transfer(address,address,uint256)")
	transferTopic = common.HexToHash("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
	// 转账事件的签名哈希，用于标识 ERC-20 的 Transfer 事件。

	// ERC-7528
	transferAddress = common.HexToAddress("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
	// 特殊地址，表示以太币（Ether）转账。在 ERC-7528 中，该地址用于模拟原生 Ether 的 Transfer 事件。
)

// tracer is a simple tracer that records all logs and
// ether transfers. Transfers are recorded as if they
// were logs. Transfer events include:
// - tx value
// - call value
// - self destructs
//
// The log format for a transfer is:
// - address: 0x0000000000000000000000000000000000000000
// - data: Value
// - topics:
//   - Transfer(address,address,uint256)
//   - Sender address
//   - Recipient address
//
// tracer 是一个简单的追踪器，记录所有日志和以太币转账。转账被记录为日志格式，包含以下信息：
// - 交易值（tx value）
// - 调用值（call value）
// - 自毁操作（self destructs）
type tracer struct {
	// logs keeps logs for all open call frames.
	// This lets us clear logs for failed calls.
	logs           [][]*types.Log // 记录所有调用帧的日志，允许清除失败调用的日志。
	count          int            // 记录日志的计数器。
	traceTransfers bool           // 是否追踪转账。
	blockNumber    uint64         // 当前区块编号。
	blockHash      common.Hash    // 当前区块哈希。
	txHash         common.Hash    // 当前交易哈希。
	txIdx          uint           // 当前交易索引。
}

func newTracer(traceTransfers bool, blockNumber uint64, blockHash, txHash common.Hash, txIndex uint) *tracer {
	return &tracer{
		traceTransfers: traceTransfers,
		blockNumber:    blockNumber,
		blockHash:      blockHash,
		txHash:         txHash,
		txIdx:          txIndex,
	}
}

func (t *tracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnEnter: t.onEnter, // 在进入调用时触发。
		OnExit:  t.onExit,  // 在退出调用时触发。
		OnLog:   t.onLog,   // 在生成日志时触发。
	}
}

func (t *tracer) onEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	t.logs = append(t.logs, make([]*types.Log, 0)) // 为新的调用帧创建日志列表。
	if vm.OpCode(typ) != vm.DELEGATECALL && value != nil && value.Cmp(common.Big0) > 0 {
		t.captureTransfer(from, to, value) // 如果是普通调用且有转账金额，则捕获转账事件。
	}
}

func (t *tracer) onExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		t.onEnd(reverted) // 如果是最外层调用结束，处理最终结果。
		return
	}
	size := len(t.logs)
	if size <= 1 {
		return
	}
	// pop call
	call := t.logs[size-1]
	t.logs = t.logs[:size-1]
	size--

	// Clear logs if call failed.
	if !reverted {
		t.logs[size-1] = append(t.logs[size-1], call...) // 如果调用成功，将子调用的日志合并到父调用中。
	}
}

func (t *tracer) onEnd(reverted bool) {
	if reverted {
		t.logs[0] = nil // 如果交易回滚，清空所有日志。
	}
}

func (t *tracer) onLog(log *types.Log) {
	t.captureLog(log.Address, log.Topics, log.Data) // 捕获日志并存储。
}

func (t *tracer) captureLog(address common.Address, topics []common.Hash, data []byte) {
	t.logs[len(t.logs)-1] = append(t.logs[len(t.logs)-1], &types.Log{
		Address:     address,       // 日志来源地址。
		Topics:      topics,        // 日志主题。
		Data:        data,          // 日志数据。
		BlockNumber: t.blockNumber, // 区块编号。
		BlockHash:   t.blockHash,   // 区块哈希。
		TxHash:      t.txHash,      // 交易哈希。
		TxIndex:     t.txIdx,       // 交易索引。
		Index:       uint(t.count), // 日志索引。
	})
	t.count++ // 增加日志计数器。
}

func (t *tracer) captureTransfer(from, to common.Address, value *big.Int) {
	if !t.traceTransfers {
		return // 如果未启用转账追踪，则直接返回。
	}
	topics := []common.Hash{
		transferTopic,                    // 转账事件主题。
		common.BytesToHash(from.Bytes()), // 发送者地址。
		common.BytesToHash(to.Bytes()),   // 接收者地址。
	}
	t.captureLog(transferAddress, topics, common.BigToHash(value).Bytes()) // 将转账记录为日志。
}

// reset prepares the tracer for the next transaction.
// 重置追踪器以准备处理下一个交易。
func (t *tracer) reset(txHash common.Hash, txIdx uint) {
	t.logs = nil      // 清空日志。
	t.txHash = txHash // 更新交易哈希。
	t.txIdx = txIdx   // 更新交易索引。
}

func (t *tracer) Logs() []*types.Log {
	return t.logs[0] // 返回最外层调用的日志。
}
