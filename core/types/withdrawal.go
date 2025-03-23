// Copyright 2022 The go-ethereum Authors
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

package types

import (
	"bytes"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

//go:generate go run github.com/fjl/gencodec -type Withdrawal -field-override withdrawalMarshaling -out gen_withdrawal_json.go
//go:generate go run ../../rlp/rlpgen -type Withdrawal -out gen_withdrawal_rlp.go

// The Merge：2022 年 9 月，以太坊从 PoW（工作量证明）过渡到 PoS，引入 Beacon Chain 和验证者机制。
// 验证者提款：EIP-4895（上海/卡佩拉升级，2023 年）启用了验证者提款功能，分为部分提款（奖励）和完全提款（本金+奖励）。
// Gwei：1 Gwei = 10⁹ Wei，1 ETH = 10⁹ Gwei，方便计算小额费用或奖励。

// Withdrawal 结构体封装了验证者从共识层提取资金所需的核心信息。
// 它是 Beacon Chain 和执行层（Execution Layer，原 Ethereum 1.0）交互的一部分，通常在合并（The Merge）后用于处理验证者资金流动。

// Withdrawal represents a validator withdrawal from the consensus layer.
// Withdrawal 表示共识层中验证者的提款。
// 用于表示以太坊共识层（Beacon Chain）中验证者的提款操作。它记录了提款的标识、验证者信息、目标地址和金额，通常用于以太坊 PoS（权益证明）机制下的资金提取流程。
type Withdrawal struct {
	// 在 Beacon Chain 中，提款操作被记录为事件，Index 用于追踪和管理。
	// 由共识层生成，单调递增，确保每笔提款有唯一编号。
	Index uint64 `json:"index"` // monotonically increasing identifier issued by consensus layer 共识层发出的单调递增标识符
	// 验证者索引是 Beacon Chain 分配给每个验证者的唯一编号。
	// 一个验证者通过质押 32 ETH 参与 PoS，提款通常涉及质押资金的解锁或奖励提取。
	// 标识哪个验证者发起了提款请求。
	Validator uint64 `json:"validatorIndex"` // index of validator associated with withdrawal 与提款关联的验证者索引
	// 指定以太币（ETH）将转入的账户，通常是 EOA（外部拥有账户）。
	// 提款地址可以由验证者设置，用于接收解锁的 ETH。
	Address common.Address `json:"address"` // target address for withdrawn ether 提款以太币的目标地址
	// 表示提取的以太币数量，以 Gwei（1 ETH = 10⁹ Gwei）为单位。
	// 提款金额可能包括验证者的质押本金（部分或全部）或累积的奖励。
	Amount uint64 `json:"amount"` // value of withdrawal in Gwei 提款金额，单位为 Gwei
}

// field type overrides for gencodec
type withdrawalMarshaling struct {
	Index     hexutil.Uint64
	Validator hexutil.Uint64
	Amount    hexutil.Uint64
}

// 它实现了 DerivableList 接口，用于处理一组验证者提款数据，通常在以太坊共识层（如 Beacon Chain）或执行层（如上海升级后的提款处理）中使用。
// DerivableList 接口常用于 SSZ（Simple Serialize）或 RLP（Recursive Length Prefix）编码场景。

// Withdrawals implements DerivableList for withdrawals.
// Withdrawals 为提款实现了 DerivableList 接口。
type Withdrawals []*Withdrawal

// Len returns the length of s.
// Len 返回 s 的长度。
func (s Withdrawals) Len() int { return len(s) }

// Withdrawal 包含 uint64（8 字节）×3 + common.Address（20 字节），总计 44 字节。
var withdrawalSize = int(reflect.TypeOf(Withdrawal{}).Size())

func (s Withdrawals) Size() int {
	// 返回所有提款的总字节大小
	return withdrawalSize * len(s)
}

// EncodeIndex encodes the i'th withdrawal to w. Note that this does not check for errors
// because we assume that *Withdrawal will only ever contain valid withdrawals that were either
// constructed by decoding or via public API in this package.
//
// EncodeIndex 将第 i 个提款编码到 w 中。注意，此方法不检查错误，
// 因为我们假设 *Withdrawal 只包含通过解码或此包中公共 API 构造的有效提款。
func (s Withdrawals) EncodeIndex(i int, w *bytes.Buffer) {
	// 将第 i 个提款使用 RLP 编码写入缓冲区
	rlp.Encode(w, s[i])
}
