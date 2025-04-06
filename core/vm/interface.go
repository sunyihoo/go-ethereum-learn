// Copyright 2016 The go-ethereum Authors
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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// StateDB is an EVM database for full state querying.
// StateDB 是用于完整状态查询的EVM数据库。
type StateDB interface {
	CreateAccount(common.Address) // 创建账户
	// 创建一个新账户

	CreateContract(common.Address) // 创建合约
	// 创建一个新合约账户

	SubBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int // 减少余额
	// 从指定地址减去余额，返回新余额

	AddBalance(common.Address, *uint256.Int, tracing.BalanceChangeReason) uint256.Int // 增加余额
	// 向指定地址添加余额，返回新余额

	GetBalance(common.Address) *uint256.Int // 获取余额
	// 获取指定地址的余额

	GetNonce(common.Address) uint64 // 获取Nonce
	// 获取指定地址的Nonce（交易计数器）

	SetNonce(common.Address, uint64) // 设置Nonce
	// 设置指定地址的Nonce

	GetCodeHash(common.Address) common.Hash // 获取代码哈希
	// 获取指定地址的代码哈希

	GetCode(common.Address) []byte // 获取代码
	// 获取指定地址的代码

	// SetCode sets the new code for the address, and returns the previous code, if any.
	// SetCode 为地址设置新代码，并返回之前的代码（如果有）。
	SetCode(common.Address, []byte) []byte // 设置代码
	// 设置指定地址的代码并返回旧代码

	GetCodeSize(common.Address) int // 获取代码大小
	// 获取指定地址的代码大小

	AddRefund(uint64) // 增加退款
	// 增加Gas退款量

	SubRefund(uint64) // 减少退款
	// 减少Gas退款量

	GetRefund() uint64 // 获取退款
	// 获取当前的Gas退款量

	GetCommittedState(common.Address, common.Hash) common.Hash // 获取已提交状态
	// 获取指定地址的已提交状态值

	GetState(common.Address, common.Hash) common.Hash // 获取状态
	// 获取指定地址的当前状态值

	SetState(common.Address, common.Hash, common.Hash) common.Hash // 设置状态
	// 设置指定地址的状态值并返回旧值

	GetStorageRoot(addr common.Address) common.Hash // 获取存储根
	// 获取指定地址的存储根哈希

	GetTransientState(addr common.Address, key common.Hash) common.Hash // 获取瞬态状态
	// 获取指定地址的瞬态状态值

	SetTransientState(addr common.Address, key, value common.Hash) // 设置瞬态状态
	// 设置指定地址的瞬态状态值

	SelfDestruct(common.Address) uint256.Int // 自毁
	// 执行账户自毁，返回余额

	HasSelfDestructed(common.Address) bool // 检查是否已自毁
	// 检查指定地址是否已标记为自毁

	// SelfDestruct6780 is post-EIP6780 selfdestruct, which means that it's a
	// send-all-to-beneficiary, unless the contract was created in this same
	// transaction, in which case it will be destructed.
	// This method returns the prior balance, along with a boolean which is
	// true iff the object was indeed destructed.
	// SelfDestruct6780 是EIP-6780后的自毁，表示将所有余额发送给受益人，
	// 除非合约在同一交易中创建，此时将被销毁。
	// 此方法返回之前的余额，以及一个布尔值，仅当对象确实被销毁时为true。
	SelfDestruct6780(common.Address) (uint256.Int, bool) // EIP-6780自毁
	// 执行EIP-6780自毁，返回余额和是否销毁的标志

	// Exist reports whether the given account exists in state.
	// Notably this should also return true for self-destructed accounts.
	// Exist 报告给定账户在状态中是否存在。
	// 值得注意的是，对于已自毁的账户也应返回true。
	Exist(common.Address) bool // 检查账户是否存在
	// 检查指定地址是否存在于状态中

	// Empty returns whether the given account is empty. Empty
	// is defined according to EIP161 (balance = nonce = code = 0).
	// Empty 返回给定账户是否为空。
	// 根据EIP-161定义，空账户为(balance = nonce = code = 0)。
	Empty(common.Address) bool // 检查账户是否为空
	// 检查指定地址是否为空账户

	AddressInAccessList(addr common.Address) bool // 检查地址是否在访问列表中
	// 检查指定地址是否在访问列表中

	SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool) // 检查槽是否在访问列表中
	// 检查指定地址和存储槽是否在访问列表中，返回地址和槽的状态

	// AddAddressToAccessList adds the given address to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	// AddAddressToAccessList 将给定地址添加到访问列表。即使功能/分叉尚未激活，此操作也是安全的。
	AddAddressToAccessList(addr common.Address) // 添加地址到访问列表
	// 将指定地址添加到访问列表

	// AddSlotToAccessList adds the given (address,slot) to the access list. This operation is safe to perform
	// even if the feature/fork is not active yet
	// AddSlotToAccessList 将给定的(地址,槽)添加到访问列表。即使功能/分叉尚未激活，此操作也是安全的。
	AddSlotToAccessList(addr common.Address, slot common.Hash) // 添加槽到访问列表
	// 将指定地址和存储槽添加到访问列表

	// PointCache returns the point cache used in computations
	// PointCache 返回计算中使用的点缓存
	PointCache() *utils.PointCache // 获取点缓存
	// 返回用于计算的点缓存对象

	Prepare(rules params.Rules, sender, coinbase common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList) // 准备状态
	// 根据规则、发送者、矿工、目标地址、预编译合约和交易访问列表准备状态数据库

	RevertToSnapshot(int) // 回滚到快照
	// 回滚状态到指定快照

	Snapshot() int // 创建快照
	// 创建当前状态的快照并返回快照ID

	AddLog(*types.Log) // 添加日志
	// 添加交易日志

	AddPreimage(common.Hash, []byte) // 添加前映像
	// 添加SHA3前映像记录

	Witness() *stateless.Witness // 获取见证数据
	// 返回无状态执行的见证数据

	// Finalise must be invoked at the end of a transaction
	// Finalise 必须在交易结束时调用
	Finalise(bool) // 完成状态
	// 完成状态更新并提交更改
}

// CallContext provides a basic interface for the EVM calling conventions. The EVM
// depends on this context being implemented for doing subcalls and initialising new EVM contracts.
// CallContext 提供了EVM调用约定的基本接口。EVM
// 依赖此上下文的实现来进行子调用和初始化新的EVM合约。
type CallContext interface {
	// Call calls another contract.
	// Call 调用另一个合约。
	Call(env *EVM, me ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error) // 调用合约
	// 调用指定地址的合约

	// CallCode takes another contracts code and execute within our own context
	// CallCode 获取另一个合约的代码并在我们的上下文中执行
	CallCode(env *EVM, me ContractRef, addr common.Address, data []byte, gas, value *big.Int) ([]byte, error) // 调用代码
	// 在当前上下文中执行另一个合约的代码

	// DelegateCall is same as CallCode except sender and value is propagated from parent to child scope
	// DelegateCall 与CallCode相同，但发送者和价值从父作用域传播到子作用域
	DelegateCall(env *EVM, me ContractRef, addr common.Address, data []byte, gas *big.Int) ([]byte, error) // 委托调用
	// 在当前上下文中委托调用另一个合约，传播发送者和价值

	// Create creates a new contract
	// Create 创建一个新合约
	Create(env *EVM, me ContractRef, data []byte, gas, value *big.Int) ([]byte, common.Address, error) // 创建合约
	// 创建并部署一个新合约，返回代码和地址
}
