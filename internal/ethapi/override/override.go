// Copyright 2024 The go-ethereum Authors
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

package override

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// 预编译合约是以太坊虚拟机（EVM）中的一组特殊合约，用于高效实现某些复杂功能（如加密算法）。通过 MovePrecompileTo，可以动态调整预编译合约的位置。

// OverrideAccount indicates the overriding fields of account during the execution
// of a message call.
// Note, state and stateDiff can't be specified at the same time. If state is
// set, message execution will only use the data in the given state. Otherwise
// if stateDiff is set, all diff will be applied first and then execute the call
// message.
// OverrideAccount 表示在消息调用执行期间覆盖的账户字段。
// 注意，state 和 stateDiff 不能同时指定。如果设置了 state，
// 消息执行将仅使用给定状态中的数据。否则，如果设置了 stateDiff，
// 将先应用所有差异，然后执行调用消息。
type OverrideAccount struct {
	Nonce            *hexutil.Uint64             `json:"nonce"`                   // 覆盖账户的随机数。
	Code             *hexutil.Bytes              `json:"code"`                    // 覆盖账户的合约代码。
	Balance          *hexutil.Big                `json:"balance"`                 // 覆盖账户的余额。
	State            map[common.Hash]common.Hash `json:"state"`                   // 完全替换账户的存储状态。
	StateDiff        map[common.Hash]common.Hash `json:"stateDiff"`               // 对账户的存储状态进行部分修改。
	MovePrecompileTo *common.Address             `json:"movePrecompileToAddress"` // 将预编译合约移动到的目标地址。
}

// StateOverride is the collection of overridden accounts.
// StateOverride 是被覆盖账户的集合。
type StateOverride map[common.Address]OverrideAccount

func (diff *StateOverride) has(address common.Address) bool {
	_, ok := (*diff)[address]
	return ok
}

// Apply overrides the fields of specified accounts into the given state.
// Apply 将指定账户的字段覆盖到给定的状态中。
func (diff *StateOverride) Apply(statedb *state.StateDB, precompiles vm.PrecompiledContracts) error {
	if diff == nil {
		return nil
	}
	// Tracks destinations of precompiles that were moved.
	// 跟踪被移动的预编译合约的目标地址。
	dirtyAddrs := make(map[common.Address]struct{})
	for addr, account := range *diff {
		// If a precompile was moved to this address already, it can't be overridden.
		// 如果一个预编译合约已经被移动到该地址，则不能被覆盖。
		if _, ok := dirtyAddrs[addr]; ok {
			return fmt.Errorf("account %s has already been overridden by a precompile", addr.Hex())
		}
		p, isPrecompile := precompiles[addr]
		// The MoveTo feature makes it possible to move a precompile
		// code to another address. If the target address is another precompile
		// the code for the latter is lost for this session.
		// Note the destination account is not cleared upon move.
		// MoveTo 功能允许将预编译合约的代码移动到另一个地址。如果目标地址是另一个预编译合约，
		// 则后者的代码在本次会话中将丢失。注意，移动时目标账户不会被清空。
		if account.MovePrecompileTo != nil {
			if !isPrecompile {
				return fmt.Errorf("account %s is not a precompile", addr.Hex())
			}
			// Refuse to move a precompile to an address that has been
			// or will be overridden.
			// 拒绝将预编译合约移动到已被或即将被覆盖的地址。
			if diff.has(*account.MovePrecompileTo) {
				return fmt.Errorf("account %s is already overridden", account.MovePrecompileTo.Hex())
			}
			precompiles[*account.MovePrecompileTo] = p
			dirtyAddrs[*account.MovePrecompileTo] = struct{}{}
		}
		if isPrecompile {
			delete(precompiles, addr)
		}
		// Override account nonce.
		// 覆盖账户的随机数。
		if account.Nonce != nil {
			statedb.SetNonce(addr, uint64(*account.Nonce))
		}
		// Override account(contract) code.
		// 覆盖账户（合约）的代码。
		if account.Code != nil {
			statedb.SetCode(addr, *account.Code)
		}
		// Override account balance.
		// 覆盖账户的余额。
		if account.Balance != nil {
			u256Balance, _ := uint256.FromBig((*big.Int)(account.Balance))
			statedb.SetBalance(addr, u256Balance, tracing.BalanceChangeUnspecified)
		}
		if account.State != nil && account.StateDiff != nil {
			return fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		// 如果调用者要求，替换整个状态。
		if account.State != nil {
			statedb.SetStorage(addr, account.State)
		}
		// Apply state diff into specified accounts.
		// 将状态差异应用到指定账户。
		if account.StateDiff != nil {
			for key, value := range account.StateDiff {
				statedb.SetState(addr, key, value)
			}
		}
	}
	// Now finalize the changes. Finalize is normally performed between transactions.
	// By using finalize, the overrides are semantically behaving as
	// if they were created in a transaction just before the tracing occur.
	// 现在提交更改。Finalize 通常在交易之间执行。
	// 通过使用 Finalize，覆盖操作在语义上表现得就像它们是在跟踪发生前的一笔交易中创建的一样。
	statedb.Finalise(false)
	return nil
}

// BlockOverrides is a set of header fields to override.
// BlockOverrides 是一组需要覆盖的区块头字段。
type BlockOverrides struct {
	Number        *hexutil.Big    // 覆盖区块号。
	Difficulty    *hexutil.Big    // 覆盖难度值（在合并后调用模拟时无效）。
	Time          *hexutil.Uint64 // 覆盖时间戳。
	GasLimit      *hexutil.Uint64 // 覆盖 Gas 上限。
	FeeRecipient  *common.Address // 覆盖费用接收者（矿工地址）。
	PrevRandao    *common.Hash    // 覆盖 PrevRandao 值。
	BaseFeePerGas *hexutil.Big    // 覆盖每单位 Gas 的基础费用。
	BlobBaseFee   *hexutil.Big    // 覆盖 Blob 交易的基础费用。
}

// Apply overrides the given header fields into the given block context.
// Apply 将给定的区块头字段覆盖到给定的区块上下文中。
func (o *BlockOverrides) Apply(blockCtx *vm.BlockContext) {
	if o == nil {
		return
	}
	if o.Number != nil {
		blockCtx.BlockNumber = o.Number.ToInt()
	}
	if o.Difficulty != nil {
		blockCtx.Difficulty = o.Difficulty.ToInt()
	}
	if o.Time != nil {
		blockCtx.Time = uint64(*o.Time)
	}
	if o.GasLimit != nil {
		blockCtx.GasLimit = uint64(*o.GasLimit)
	}
	if o.FeeRecipient != nil {
		blockCtx.Coinbase = *o.FeeRecipient
	}
	if o.PrevRandao != nil {
		blockCtx.Random = o.PrevRandao
	}
	if o.BaseFeePerGas != nil {
		blockCtx.BaseFee = o.BaseFeePerGas.ToInt()
	}
	if o.BlobBaseFee != nil {
		blockCtx.BlobBaseFee = o.BlobBaseFee.ToInt()
	}
}

// MakeHeader returns a new header object with the overridden
// fields.
// Note: MakeHeader ignores BlobBaseFee if set. That's because
// header has no such field.
// MakeHeader 返回一个新的区块头对象，并应用覆盖的字段。
// 注意：MakeHeader 忽略 BlobBaseFee 字段（如果设置）。这是因为区块头中没有该字段。
func (o *BlockOverrides) MakeHeader(header *types.Header) *types.Header {
	if o == nil {
		return header
	}
	h := types.CopyHeader(header)
	if o.Number != nil {
		h.Number = o.Number.ToInt()
	}
	if o.Difficulty != nil {
		h.Difficulty = o.Difficulty.ToInt()
	}
	if o.Time != nil {
		h.Time = uint64(*o.Time)
	}
	if o.GasLimit != nil {
		h.GasLimit = uint64(*o.GasLimit)
	}
	if o.FeeRecipient != nil {
		h.Coinbase = *o.FeeRecipient
	}
	if o.PrevRandao != nil {
		h.MixDigest = *o.PrevRandao
	}
	if o.BaseFeePerGas != nil {
		h.BaseFee = o.BaseFeePerGas.ToInt()
	}
	return h
}
