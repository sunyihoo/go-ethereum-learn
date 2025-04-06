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

package state

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// 状态跟踪 (State Tracing) 的重要性
//
// 在以太坊中，状态是区块链的核心组成部分，它记录了所有账户的余额、合约代码、存储等信息。理解交易执行过程中状态的变化对于以下场景至关重要：
//
// 智能合约调试 (Smart Contract Debugging)：开发者可以使用状态跟踪来了解合约执行的每一步对状态产生了哪些影响，例如变量的修改、事件的触发等。
// 性能分析 (Performance Analysis)：通过跟踪状态的读写操作，可以分析交易执行的性能瓶颈。
// 安全审计 (Security Auditing)：审计员可以利用状态跟踪来检查智能合约是否存在安全漏洞，例如未经授权的状态修改。
// 协议开发 (Protocol Development)：以太坊协议的开发者可以使用状态跟踪来验证新的协议变更是否按预期工作。

// hookedStateDB represents a statedb which emits calls to tracing-hooks
// on state operations.
// hookedStateDB 代表一个状态数据库，它在状态操作时发出对跟踪钩子的调用。
type hookedStateDB struct {
	inner *StateDB // The underlying StateDB instance.
	// inner 底层的 StateDB 实例。
	hooks *tracing.Hooks // Hooks to be called on state operations.
	// hooks 在状态操作时调用的钩子。
}

// NewHookedState wraps the given stateDb with the given hooks
// NewHookedState 使用给定的钩子包装给定的 stateDb。
func NewHookedState(stateDb *StateDB, hooks *tracing.Hooks) *hookedStateDB {
	s := &hookedStateDB{stateDb, hooks}
	if s.hooks == nil {
		s.hooks = new(tracing.Hooks) // Initialize hooks if not provided.
		// 如果没有提供钩子，则初始化。
	}
	return s
}

func (s *hookedStateDB) CreateAccount(addr common.Address) {
	s.inner.CreateAccount(addr) // Call the inner StateDB's CreateAccount method.
	// 调用内部 StateDB 的 CreateAccount 方法。
}

func (s *hookedStateDB) CreateContract(addr common.Address) {
	s.inner.CreateContract(addr) // Call the inner StateDB's CreateContract method.
	// 调用内部 StateDB 的 CreateContract 方法。
}

func (s *hookedStateDB) GetBalance(addr common.Address) *uint256.Int {
	return s.inner.GetBalance(addr) // Call the inner StateDB's GetBalance method.
	// 调用内部 StateDB 的 GetBalance 方法。
}

func (s *hookedStateDB) GetNonce(addr common.Address) uint64 {
	return s.inner.GetNonce(addr) // Call the inner StateDB's GetNonce method.
	// 调用内部 StateDB 的 GetNonce 方法。
}

func (s *hookedStateDB) GetCodeHash(addr common.Address) common.Hash {
	return s.inner.GetCodeHash(addr) // Call the inner StateDB's GetCodeHash method.
	// 调用内部 StateDB 的 GetCodeHash 方法。
}

func (s *hookedStateDB) GetCode(addr common.Address) []byte {
	return s.inner.GetCode(addr) // Call the inner StateDB's GetCode method.
	// 调用内部 StateDB 的 GetCode 方法。
}

func (s *hookedStateDB) GetCodeSize(addr common.Address) int {
	return s.inner.GetCodeSize(addr) // Call the inner StateDB's GetCodeSize method.
	// 调用内部 StateDB 的 GetCodeSize 方法。
}

func (s *hookedStateDB) AddRefund(u uint64) {
	s.inner.AddRefund(u) // Call the inner StateDB's AddRefund method.
	// 调用内部 StateDB 的 AddRefund 方法。
}

func (s *hookedStateDB) SubRefund(u uint64) {
	s.inner.SubRefund(u) // Call the inner StateDB's SubRefund method.
	// 调用内部 StateDB 的 SubRefund 方法。
}

func (s *hookedStateDB) GetRefund() uint64 {
	return s.inner.GetRefund() // Call the inner StateDB's GetRefund method.
	// 调用内部 StateDB 的 GetRefund 方法。
}

func (s *hookedStateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	return s.inner.GetCommittedState(addr, hash) // Call the inner StateDB's GetCommittedState method.
	// 调用内部 StateDB 的 GetCommittedState 方法。
}

func (s *hookedStateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	return s.inner.GetState(addr, hash) // Call the inner StateDB's GetState method.
	// 调用内部 StateDB 的 GetState 方法。
}

func (s *hookedStateDB) GetStorageRoot(addr common.Address) common.Hash {
	return s.inner.GetStorageRoot(addr) // Call the inner StateDB's GetStorageRoot method.
	// 调用内部 StateDB 的 GetStorageRoot 方法。
}

func (s *hookedStateDB) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	return s.inner.GetTransientState(addr, key) // Call the inner StateDB's GetTransientState method.
	// 调用内部 StateDB 的 GetTransientState 方法。
}

func (s *hookedStateDB) SetTransientState(addr common.Address, key, value common.Hash) {
	s.inner.SetTransientState(addr, key, value) // Call the inner StateDB's SetTransientState method.
	// 调用内部 StateDB 的 SetTransientState 方法。
}

func (s *hookedStateDB) HasSelfDestructed(addr common.Address) bool {
	return s.inner.HasSelfDestructed(addr) // Call the inner StateDB's HasSelfDestructed method.
	// 调用内部 StateDB 的 HasSelfDestructed 方法。
}

func (s *hookedStateDB) Exist(addr common.Address) bool {
	return s.inner.Exist(addr) // Call the inner StateDB's Exist method.
	// 调用内部 StateDB 的 Exist 方法。
}

func (s *hookedStateDB) Empty(addr common.Address) bool {
	return s.inner.Empty(addr) // Call the inner StateDB's Empty method.
	// 调用内部 StateDB 的 Empty 方法。
}

func (s *hookedStateDB) AddressInAccessList(addr common.Address) bool {
	return s.inner.AddressInAccessList(addr) // Call the inner StateDB's AddressInAccessList method.
	// 调用内部 StateDB 的 AddressInAccessList 方法。
}

func (s *hookedStateDB) SlotInAccessList(addr common.Address, slot common.Hash) (addressOk bool, slotOk bool) {
	return s.inner.SlotInAccessList(addr, slot) // Call the inner StateDB's SlotInAccessList method.
	// 调用内部 StateDB 的 SlotInAccessList 方法。
}

func (s *hookedStateDB) AddAddressToAccessList(addr common.Address) {
	s.inner.AddAddressToAccessList(addr) // Call the inner StateDB's AddAddressToAccessList method.
	// 调用内部 StateDB 的 AddAddressToAccessList 方法。
}

func (s *hookedStateDB) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	s.inner.AddSlotToAccessList(addr, slot) // Call the inner StateDB's AddSlotToAccessList method.
	// 调用内部 StateDB 的 AddSlotToAccessList 方法。
}

func (s *hookedStateDB) PointCache() *utils.PointCache {
	return s.inner.PointCache() // Call the inner StateDB's PointCache method.
	// 调用内部 StateDB 的 PointCache 方法。
}

func (s *hookedStateDB) Prepare(rules params.Rules, sender, coinbase common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList) {
	s.inner.Prepare(rules, sender, coinbase, dest, precompiles, txAccesses) // Call the inner StateDB's Prepare method.
	// 调用内部 StateDB 的 Prepare 方法。
}

func (s *hookedStateDB) RevertToSnapshot(i int) {
	s.inner.RevertToSnapshot(i) // Call the inner StateDB's RevertToSnapshot method.
	// 调用内部 StateDB 的 RevertToSnapshot 方法。
}

func (s *hookedStateDB) Snapshot() int {
	return s.inner.Snapshot() // Call the inner StateDB's Snapshot method.
	// 调用内部 StateDB 的 Snapshot 方法。
}

func (s *hookedStateDB) AddPreimage(hash common.Hash, bytes []byte) {
	s.inner.AddPreimage(hash, bytes) // Call the inner StateDB's AddPreimage method.
	// 调用内部 StateDB 的 AddPreimage 方法。
}

func (s *hookedStateDB) Witness() *stateless.Witness {
	return s.inner.Witness() // Call the inner StateDB's Witness method.
	// 调用内部 StateDB 的 Witness 方法。
}

func (s *hookedStateDB) SubBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	prev := s.inner.SubBalance(addr, amount, reason) // Call the inner StateDB's SubBalance method.
	// 调用内部 StateDB 的 SubBalance 方法。
	if s.hooks.OnBalanceChange != nil && !amount.IsZero() {
		// If a balance change hook is registered and the amount is not zero.
		// 如果注册了余额变更钩子且金额不为零。
		newBalance := new(uint256.Int).Sub(&prev, amount) // Calculate the new balance.
		// 计算新的余额。
		s.hooks.OnBalanceChange(addr, prev.ToBig(), newBalance.ToBig(), reason) // Call the balance change hook.
		// 调用余额变更钩子。
	}
	return prev
}

func (s *hookedStateDB) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	prev := s.inner.AddBalance(addr, amount, reason) // Call the inner StateDB's AddBalance method.
	// 调用内部 StateDB 的 AddBalance 方法。
	if s.hooks.OnBalanceChange != nil && !amount.IsZero() {
		// If a balance change hook is registered and the amount is not zero.
		// 如果注册了余额变更钩子且金额不为零。
		newBalance := new(uint256.Int).Add(&prev, amount) // Calculate the new balance.
		// 计算新的余额。
		s.hooks.OnBalanceChange(addr, prev.ToBig(), newBalance.ToBig(), reason) // Call the balance change hook.
		// 调用余额变更钩子。
	}
	return prev
}

func (s *hookedStateDB) SetNonce(address common.Address, nonce uint64) {
	s.inner.SetNonce(address, nonce) // Call the inner StateDB's SetNonce method.
	// 调用内部 StateDB 的 SetNonce 方法。
	if s.hooks.OnNonceChange != nil {
		// If a nonce change hook is registered.
		// 如果注册了 nonce 变更钩子。
		s.hooks.OnNonceChange(address, nonce-1, nonce) // Call the nonce change hook.
		// 调用 nonce 变更钩子。
	}
}

func (s *hookedStateDB) SetCode(address common.Address, code []byte) []byte {
	prev := s.inner.SetCode(address, code) // Call the inner StateDB's SetCode method.
	// 调用内部 StateDB 的 SetCode 方法。
	if s.hooks.OnCodeChange != nil {
		// If a code change hook is registered.
		// 如果注册了代码变更钩子。
		prevHash := types.EmptyCodeHash
		if len(prev) != 0 {
			prevHash = crypto.Keccak256Hash(prev) // Calculate the hash of the previous code.
			// 计算先前代码的哈希。
		}
		s.hooks.OnCodeChange(address, prevHash, prev, crypto.Keccak256Hash(code), code) // Call the code change hook.
		// 调用代码变更钩子。
	}
	return prev
}

func (s *hookedStateDB) SetState(address common.Address, key common.Hash, value common.Hash) common.Hash {
	prev := s.inner.SetState(address, key, value) // Call the inner StateDB's SetState method.
	// 调用内部 StateDB 的 SetState 方法。
	if s.hooks.OnStorageChange != nil && prev != value {
		// If a storage change hook is registered and the value has changed.
		// 如果注册了存储变更钩子且值已更改。
		s.hooks.OnStorageChange(address, key, prev, value) // Call the storage change hook.
		// 调用存储变更钩子。
	}
	return prev
}

func (s *hookedStateDB) SelfDestruct(address common.Address) uint256.Int {
	var prevCode []byte
	var prevCodeHash common.Hash

	if s.hooks.OnCodeChange != nil {
		// If a code change hook is registered.
		// 如果注册了代码变更钩子。
		prevCode = s.inner.GetCode(address) // Get the previous code.
		// 获取先前的代码。
		prevCodeHash = s.inner.GetCodeHash(address) // Get the hash of the previous code.
		// 获取先前代码的哈希。
	}

	prev := s.inner.SelfDestruct(address) // Call the inner StateDB's SelfDestruct method.
	// 调用内部 StateDB 的 SelfDestruct 方法。

	if s.hooks.OnBalanceChange != nil && !prev.IsZero() {
		// If a balance change hook is registered and the balance is not zero.
		// 如果注册了余额变更钩子且余额不为零。
		s.hooks.OnBalanceChange(address, prev.ToBig(), new(big.Int), tracing.BalanceDecreaseSelfdestruct) // Call the balance change hook for self-destruct.
		// 调用余额变更钩子，表示自毁导致的余额减少。
	}

	if s.hooks.OnCodeChange != nil && len(prevCode) > 0 {
		// If a code change hook is registered and there was previous code.
		// 如果注册了代码变更钩子且存在先前的代码。
		s.hooks.OnCodeChange(address, prevCodeHash, prevCode, types.EmptyCodeHash, nil) // Call the code change hook for self-destruct.
		// 调用代码变更钩子，表示自毁导致的代码清除。
	}

	return prev
}

func (s *hookedStateDB) SelfDestruct6780(address common.Address) (uint256.Int, bool) {
	var prevCode []byte
	var prevCodeHash common.Hash

	if s.hooks.OnCodeChange != nil {
		prevCodeHash = s.inner.GetCodeHash(address)
		prevCode = s.inner.GetCode(address)
	}

	prev, changed := s.inner.SelfDestruct6780(address)

	if s.hooks.OnBalanceChange != nil && changed && !prev.IsZero() {
		s.hooks.OnBalanceChange(address, prev.ToBig(), new(big.Int), tracing.BalanceDecreaseSelfdestruct)
	}

	if s.hooks.OnCodeChange != nil && changed && len(prevCode) > 0 {
		s.hooks.OnCodeChange(address, prevCodeHash, prevCode, types.EmptyCodeHash, nil)
	}

	return prev, changed
}

func (s *hookedStateDB) AddLog(log *types.Log) {
	// The inner will modify the log (add fields), so invoke that first
	// 内部会修改日志（添加字段），所以首先调用内部的方法。
	s.inner.AddLog(log) // Call the inner StateDB's AddLog method.
	// 调用内部 StateDB 的 AddLog 方法。
	if s.hooks.OnLog != nil {
		// If a log hook is registered.
		// 如果注册了日志钩子。
		s.hooks.OnLog(log) // Call the log hook.
		// 调用日志钩子。
	}
}

func (s *hookedStateDB) Finalise(deleteEmptyObjects bool) {
	defer s.inner.Finalise(deleteEmptyObjects) // Call the inner StateDB's Finalise method at the end.
	// 在结束时调用内部 StateDB 的 Finalise 方法。
	if s.hooks.OnBalanceChange == nil {
		return
	}
	for addr := range s.inner.journal.dirties {
		obj := s.inner.stateObjects[addr]
		if obj != nil && obj.selfDestructed {
			// If ether was sent to account post-selfdestruct it is burnt.
			// 如果在自毁后向账户发送了以太币，则会销毁。
			if bal := obj.Balance(); bal.Sign() != 0 {
				s.hooks.OnBalanceChange(addr, bal.ToBig(), new(big.Int), tracing.BalanceDecreaseSelfdestructBurn) // Call the balance change hook for self-destruct burn.
				// 调用余额变更钩子，表示自毁导致的余额销毁。
			}
		}
	}
}
