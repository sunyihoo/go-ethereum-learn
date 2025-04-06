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

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/holiman/uint256"
)

// ContractRef is a reference to the contract's backing object
// ContractRef 是对合约底层对象的引用
type ContractRef interface {
	Address() common.Address
}

// AccountRef implements ContractRef.
//
// Account references are used during EVM initialisation and
// its primary use is to fetch addresses. Removing this object
// proves difficult because of the cached jump destinations which
// are fetched from the parent contract (i.e. the caller), which
// is a ContractRef.
// AccountRef 实现了 ContractRef 接口。
//
// 账户引用在 EVM 初始化期间使用，其主要用途是获取地址。移除这个对象
// 很困难，因为缓存的跳转目标是从父合约（即调用者）中获取的，而父合约
// 是一个 ContractRef。
type AccountRef common.Address

// Address casts AccountRef to an Address
// Address 将 AccountRef 转换为一个地址
func (ar AccountRef) Address() common.Address { return (common.Address)(ar) }

// Contract represents an ethereum contract in the state database. It contains
// the contract code, calling arguments. Contract implements ContractRef
// Contract 表示状态数据库中的以太坊合约。它包含合约代码和调用参数。
// Contract 实现了 ContractRef 接口
type Contract struct {
	// CallerAddress is the result of the caller which initialised this
	// contract. However when the "call method" is delegated this value
	// needs to be initialised to that of the caller's caller.
	// CallerAddress 是初始化此合约的调用者的地址。然而，当“调用方法”被
	// 委托时，此值需要初始化为调用者的调用者的地址。
	CallerAddress common.Address
	caller        ContractRef
	self          ContractRef

	jumpdests map[common.Hash]bitvec // Aggregated result of JUMPDEST analysis.
	// jumpdests 是 JUMPDEST 分析的聚合结果
	analysis bitvec // Locally cached result of JUMPDEST analysis
	// analysis 是本地缓存的 JUMPDEST 分析结果

	Code     []byte
	CodeHash common.Hash
	CodeAddr *common.Address
	Input    []byte

	// is the execution frame represented by this object a contract deployment
	// 此对象表示的执行框架是否为合约部署
	IsDeployment bool

	Gas   uint64
	value *uint256.Int
}

// NewContract returns a new contract environment for the execution of EVM.
// NewContract 返回一个新的合约环境，用于 EVM 的执行。
func NewContract(caller ContractRef, object ContractRef, value *uint256.Int, gas uint64) *Contract {
	c := &Contract{CallerAddress: caller.Address(), caller: caller, self: object}

	if parent, ok := caller.(*Contract); ok {
		// Reuse JUMPDEST analysis from parent context if available.
		// 如果可用，则重用父上下文中的 JUMPDEST 分析。
		c.jumpdests = parent.jumpdests
	} else {
		c.jumpdests = make(map[common.Hash]bitvec)
	}

	// Gas should be a pointer so it can safely be reduced through the run
	// This pointer will be off the state transition
	// Gas 应该是一个指针，以便在运行过程中可以安全地减少
	// 这个指针将脱离状态转换
	c.Gas = gas
	// ensures a value is set
	// 确保设置了一个值
	c.value = value

	return c
}

func (c *Contract) validJumpdest(dest *uint256.Int) bool {
	udest, overflow := dest.Uint64WithOverflow()
	// PC cannot go beyond len(code) and certainly can't be bigger than 63bits.
	// Don't bother checking for JUMPDEST in that case.
	// PC 不能超过代码长度，并且肯定不能大于 63 位。
	// 在这种情况下不必检查 JUMPDEST。
	if overflow || udest >= uint64(len(c.Code)) {
		return false
	}
	// Only JUMPDESTs allowed for destinations
	// 目标只允许是 JUMPDEST
	// 关键步骤：检查目标位置是否为 JUMPDEST 操作码
	if OpCode(c.Code[udest]) != JUMPDEST {
		return false
	}
	return c.isCode(udest)
}

// isCode returns true if the provided PC location is an actual opcode, as
// opposed to a data-segment following a PUSHN operation.
// isCode 如果提供的 PC 位置是实际的操作码而不是 PUSHN 操作后的数据段，则返回 true。
func (c *Contract) isCode(udest uint64) bool {
	// Do we already have an analysis laying around?
	// 我们是否已经有了现成的分析结果？
	if c.analysis != nil {
		return c.analysis.codeSegment(udest)
	}
	// Do we have a contract hash already?
	// If we do have a hash, that means it's a 'regular' contract. For regular
	// contracts ( not temporary initcode), we store the analysis in a map
	// 我们是否已经有了合约哈希？
	// 如果有了哈希，说明这是一个“常规”合约。对于常规合约（不是临时的初始化代码），
	// 我们将分析结果存储在一个映射中
	if c.CodeHash != (common.Hash{}) {
		// Does parent context have the analysis?
		// 父上下文是否有分析结果？
		analysis, exist := c.jumpdests[c.CodeHash]
		if !exist {
			// Do the analysis and save in parent context
			// We do not need to store it in c.analysis
			// 进行分析并保存在父上下文中
			// 我们不需要将其存储在 c.analysis 中
			analysis = codeBitmap(c.Code)
			c.jumpdests[c.CodeHash] = analysis
		}
		// Also stash it in current contract for faster access
		// 同时将其存储在当前合约中以便更快访问
		c.analysis = analysis
		return analysis.codeSegment(udest)
	}
	// We don't have the code hash, most likely a piece of initcode not already
	// in state trie. In that case, we do an analysis, and save it locally, so
	// we don't have to recalculate it for every JUMP instruction in the execution
	// However, we don't save it within the parent context
	// 我们没有代码哈希，很可能是一段尚未在状态树中的初始化代码。在这种情况下，
	// 我们进行分析并在本地保存，这样就不必为执行中的每个 JUMP 指令重新计算
	// 然而，我们不会将其保存在父上下文中
	if c.analysis == nil {
		c.analysis = codeBitmap(c.Code)
	}
	return c.analysis.codeSegment(udest)
}

// AsDelegate sets the contract to be a delegate call and returns the current
// contract (for chaining calls)
// AsDelegate 将合约设置为委托调用并返回当前合约（以便链式调用）
func (c *Contract) AsDelegate() *Contract {
	// NOTE: caller must, at all times be a contract. It should never happen
	// that caller is something other than a Contract.
	// 注意：调用者必须始终是合约。不应发生调用者不是 Contract 的情况。
	parent := c.caller.(*Contract)
	c.CallerAddress = parent.CallerAddress
	c.value = parent.value

	return c
}

// GetOp returns the n'th element in the contract's byte array
// GetOp 返回合约字节数组中的第 n 个元素
func (c *Contract) GetOp(n uint64) OpCode {
	if n < uint64(len(c.Code)) {
		return OpCode(c.Code[n])
	}

	return STOP
}

// Caller returns the caller of the contract.
//
// Caller will recursively call caller when the contract is a delegate
// call, including that of caller's caller.
// Caller 返回合约的调用者。
//
// 当合约是委托调用时，Caller 将递归调用调用者，包括调用者的调用者。
func (c *Contract) Caller() common.Address {
	return c.CallerAddress
}

// UseGas attempts the use gas and subtracts it and returns true on success
// UseGas 尝试使用 gas 并减去它，成功时返回 true
func (c *Contract) UseGas(gas uint64, logger *tracing.Hooks, reason tracing.GasChangeReason) (ok bool) {
	if c.Gas < gas {
		return false
	}
	if logger != nil && logger.OnGasChange != nil && reason != tracing.GasChangeIgnored {
		logger.OnGasChange(c.Gas, c.Gas-gas, reason)
	}
	c.Gas -= gas
	return true
}

// RefundGas refunds gas to the contract
// RefundGas 将 gas 退还给合约
func (c *Contract) RefundGas(gas uint64, logger *tracing.Hooks, reason tracing.GasChangeReason) {
	if gas == 0 {
		return
	}
	if logger != nil && logger.OnGasChange != nil && reason != tracing.GasChangeIgnored {
		logger.OnGasChange(c.Gas, c.Gas+gas, reason)
	}
	c.Gas += gas
}

// Address returns the contracts address
// Address 返回合约的地址
func (c *Contract) Address() common.Address {
	return c.self.Address()
}

// Value returns the contract's value (sent to it from it's caller)
// Value 返回合约的值（由其调用者发送给它）
func (c *Contract) Value() *uint256.Int {
	return c.value
}

// SetCallCode sets the code of the contract and address of the backing data
// object
// SetCallCode 设置合约的代码和底层数据对象的地址
func (c *Contract) SetCallCode(addr *common.Address, hash common.Hash, code []byte) {
	c.Code = code
	c.CodeHash = hash
	c.CodeAddr = addr
}

// SetCodeOptionalHash can be used to provide code, but it's optional to provide hash.
// In case hash is not provided, the jumpdest analysis will not be saved to the parent context
// SetCodeOptionalHash 可用于提供代码，但提供哈希是可选的。
// 如果未提供哈希，则跳转目标分析不会保存到父上下文中
func (c *Contract) SetCodeOptionalHash(addr *common.Address, codeAndHash *codeAndHash) {
	c.Code = codeAndHash.code
	c.CodeHash = codeAndHash.hash
	c.CodeAddr = addr
}
