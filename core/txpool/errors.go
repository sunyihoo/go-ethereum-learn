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

package txpool

import "errors"

var (
	// ErrAlreadyKnown is returned if the transactions is already contained
	// within the pool.
	// ErrAlreadyKnown 如果交易已包含在池中，则返回此错误。
	ErrAlreadyKnown = errors.New("already known")

	// ErrInvalidSender is returned if the transaction contains an invalid signature.
	// ErrInvalidSender 如果交易包含无效签名，则返回此错误。
	ErrInvalidSender = errors.New("invalid sender")

	// ErrUnderpriced is returned if a transaction's gas price is below the minimum
	// configured for the transaction pool.
	// ErrUnderpriced 如果交易的 Gas 价格低于交易池配置的最低价格，则返回此错误。
	ErrUnderpriced = errors.New("transaction underpriced")

	// ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
	// with a different one without the required price bump.
	// ErrReplaceUnderpriced 如果尝试用不同的交易替换现有交易，但没有达到要求的价格涨幅，则返回此错误。
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")

	// ErrAccountLimitExceeded is returned if a transaction would exceed the number
	// allowed by a pool for a single account.
	// ErrAccountLimitExceeded 如果一个交易将超过池中单个账户允许的交易数量，则返回此错误。
	ErrAccountLimitExceeded = errors.New("account limit exceeded")

	// ErrGasLimit is returned if a transaction's requested gas limit exceeds the
	// maximum allowance of the current block.
	// ErrGasLimit 如果交易请求的 Gas 限制超过当前区块的最大允许值，则返回此错误。
	ErrGasLimit = errors.New("exceeds block gas limit")

	// ErrNegativeValue is a sanity error to ensure no one is able to specify a
	// transaction with a negative value.
	// ErrNegativeValue 是一个健全性检查错误，确保没有人能够指定一个负值的交易。
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	// ErrOversizedData 如果交易的输入数据大于用户可能使用的某个有意义的限制，则返回此错误。
	// 这不是一个导致交易无效的共识错误，而是一种拒绝服务 (DOS) 保护。
	ErrOversizedData = errors.New("oversized data")

	// ErrFutureReplacePending is returned if a future transaction replaces a pending
	// one. Future transactions should only be able to replace other future transactions.
	// ErrFutureReplacePending 如果一个未来的交易替换了一个待处理的交易，则返回此错误。
	// 未来的交易应该只能替换其他未来的交易。
	ErrFutureReplacePending = errors.New("future transaction tries to replace pending")

	// ErrAlreadyReserved is returned if the sender address has a pending transaction
	// in a different subpool. For example, this error is returned in response to any
	// input transaction of non-blob type when a blob transaction from this sender
	// remains pending (and vice-versa).
	// ErrAlreadyReserved 如果发送者地址在不同的子池中有一个待处理的交易，则返回此错误。
	// 例如，当来自该发送者的 Blob 交易仍然待处理时（反之亦然），针对任何非 Blob 类型的输入交易，都会返回此错误。
	ErrAlreadyReserved = errors.New("address already reserved")
)
