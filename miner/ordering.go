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

package miner

import (
	"container/heap"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

// txWithMinerFee wraps a transaction with its gas price or effective miner gasTipCap
// txWithMinerFee 将交易与其 Gas 价格或有效的矿工 GasTipCap 封装在一起。
type txWithMinerFee struct {
	tx   *txpool.LazyTransaction // 延迟加载的交易对象
	from common.Address          // 发送方地址
	fees *uint256.Int            // 矿工可获得的有效费用（GasTipCap）
}

// newTxWithMinerFee creates a wrapped transaction, calculating the effective
// miner gasTipCap if a base fee is provided.
// Returns error in case of a negative effective miner gasTipCap.
// newTxWithMinerFee 创建一个封装的交易，计算有效矿工 GasTipCap（如果提供了基础费用）。
// 如果有效矿工 GasTipCap 为负值，则返回错误。
func newTxWithMinerFee(tx *txpool.LazyTransaction, from common.Address, baseFee *uint256.Int) (*txWithMinerFee, error) {
	tip := new(uint256.Int).Set(tx.GasTipCap)
	if baseFee != nil {
		if tx.GasFeeCap.Cmp(baseFee) < 0 {
			return nil, types.ErrGasFeeCapTooLow // 如果 GasFeeCap 小于基础费用，返回错误
		}
		tip = new(uint256.Int).Sub(tx.GasFeeCap, baseFee) // 计算有效矿工 GasTipCap
		if tip.Gt(tx.GasTipCap) {
			tip = tx.GasTipCap // 确保有效费用不超过 GasTipCap
		}
	}
	return &txWithMinerFee{
		tx:   tx,
		from: from,
		fees: tip,
	}, nil
}

// txByPriceAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
// txByPriceAndTime 实现了排序和堆接口，适用于一次性排序以及单独添加和移除元素。
type txByPriceAndTime []*txWithMinerFee

func (s txByPriceAndTime) Len() int { return len(s) } // 返回堆中元素的数量
func (s txByPriceAndTime) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	// 如果费用相等，则使用交易首次被看到的时间进行确定性排序。
	cmp := s[i].fees.Cmp(s[j].fees)
	if cmp == 0 {
		return s[i].tx.Time.Before(s[j].tx.Time)
	}
	return cmp > 0 // 按费用降序排序
}
func (s txByPriceAndTime) Swap(i, j int) { s[i], s[j] = s[j], s[i] } // 交换两个元素

func (s *txByPriceAndTime) Push(x interface{}) {
	*s = append(*s, x.(*txWithMinerFee)) // 向堆中添加新元素
}

func (s *txByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*s = old[0 : n-1] // 移除堆顶元素
	return x
}

// transactionsByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
// transactionsByPriceAndNonce 表示一组交易，能够以利润最大化的方式返回排序后的交易，
// 同时支持移除不可执行账户的所有交易批次。
type transactionsByPriceAndNonce struct {
	txs     map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions 每个账户按 Nonce 排序的交易列表
	heads   txByPriceAndTime                             // Next transaction for each unique account (price heap) 每个唯一账户的下一个交易（价格堆）
	signer  types.Signer                                 // Signer for the set of transactions 用于签名的交易集合
	baseFee *uint256.Int                                 // Current base fee 当前基础费用
}

// newTransactionsByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
// newTransactionsByPriceAndNonce 创建一个交易集合，能够以遵循 Nonce 的方式检索按价格排序的交易。
// 注意，输入映射会被重新拥有，调用者在提供给构造函数后不应再与其交互。
func newTransactionsByPriceAndNonce(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, baseFee *big.Int) *transactionsByPriceAndNonce {
	// Convert the basefee from header format to uint256 format
	// 将基础费用从 Header 格式转换为 uint256 格式。
	var baseFeeUint *uint256.Int
	if baseFee != nil {
		baseFeeUint = uint256.MustFromBig(baseFee)
	}
	// Initialize a price and received time based heap with the head transactions
	// 使用头部交易初始化基于价格和接收时间的堆。
	heads := make(txByPriceAndTime, 0, len(txs))
	for from, accTxs := range txs {
		wrapped, err := newTxWithMinerFee(accTxs[0], from, baseFeeUint)
		if err != nil {
			delete(txs, from) // 如果交易无效，删除该账户的交易
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:] // 更新剩余交易
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	// 组装并返回交易集合。
	return &transactionsByPriceAndNonce{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFeeUint,
	}
}

// Peek returns the next transaction by price.
// Peek 返回下一个按价格排序的交易。
func (t *transactionsByPriceAndNonce) Peek() (*txpool.LazyTransaction, *uint256.Int) {
	if len(t.heads) == 0 {
		return nil, nil
	}
	return t.heads[0].tx, t.heads[0].fees
}

// Shift replaces the current best head with the next one from the same account.
// Shift 将当前最佳头部替换为同一账户的下一个交易。
func (t *transactionsByPriceAndNonce) Shift() {
	acc := t.heads[0].from
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.heads[0], t.txs[acc] = wrapped, txs[1:]
			heap.Fix(&t.heads, 0) // 修复堆结构
			return
		}
	}
	heap.Pop(&t.heads) // 如果没有更多交易，移除堆顶元素
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
// Pop 移除最佳交易，且不将其替换为同一账户的下一个交易。
// 当交易无法执行时应使用此方法，因此应丢弃同一账户的所有后续交易。
func (t *transactionsByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// Empty returns if the price heap is empty. It can be used to check it simpler
// than calling peek and checking for nil return.
// Empty 返回价格堆是否为空。相比调用 Peek 并检查 nil 返回值，这种方式更简单。
func (t *transactionsByPriceAndNonce) Empty() bool {
	return len(t.heads) == 0
}

// Clear removes the entire content of the heap.
// Clear 移除堆中的所有内容。
func (t *transactionsByPriceAndNonce) Clear() {
	t.heads, t.txs = nil, nil
}
