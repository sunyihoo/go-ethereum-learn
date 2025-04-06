// Copyright 2021 The go-ethereum Authors
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
	"maps"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// 背景：冷访问 (Cold Access) 与热访问 (Warm Access)
//
// 在以太坊中，执行交易需要访问状态数据（例如，账户余额、合约代码、存储）。为了更准确地衡量和收取执行交易所需的计算资源（Gas），以太坊引入了冷访问和热访问的概念。
//
// 冷访问 (Cold Access)：指交易首次访问某个状态数据。由于该数据可能不在内存中，节点需要从磁盘或其他较慢的存储介质中读取，因此成本较高。
// 热访问 (Warm Access)：指交易已经访问过某个状态数据，或者该数据在同一交易中被多次访问。由于数据很可能已经加载到内存中，因此访问成本较低。

// EIP-2930：可选访问列表
//
// EIP-2930 引入了交易的可选访问列表。交易发送者可以在交易中指定该交易将要访问的账户和存储槽。这样做的好处是：
//
// 降低 Gas 成本： 如果交易提前声明了其需要访问的状态，那么首次访问这些状态时将被视为“热访问”，从而降低 Gas 费用。
// 提高交易执行的可预测性： 节点可以提前知道交易需要访问哪些状态，从而进行更好的优化。

// EIP-2930 (Optional access lists): AccessEvents 是实现 EIP-2930 的关键组成部分。它允许交易执行引擎跟踪哪些账户和存储槽被访问，以便根据访问列表中的声明来降低 Gas 成本。
// EIP-1559 (Fee market change for ETH 1.0): 虽然 EIP-1559 的主要目的是改变交易费用的计算方式，但它也引入了“基本费用”的概念，而访问状态的 Gas 成本是影响交易能否被包含在区块中的重要因素。AccessEvents 用于准确计算这些 Gas 成本。
// Gas 计量 (Gas Metering): 以太坊黄皮书中详细定义了每种操作码和状态访问操作的 Gas 成本。AccessEvents 的方法用于根据访问的类型和频率（冷/热）来计算 Gas 费用。
// 状态树 (State Tree): 以太坊的状态存储在一个 Merkle-Patricia 树中。AccessEvents 通过跟踪对树中分支 (branches) 和叶子节点 (chunks) 的访问，来确定哪些状态数据被触及。

// mode specifies how a tree location has been accessed
// for the byte value:
// * the first bit is set if the branch has been read
// * the second bit is set if the branch has been edited
// mode 指定了树形结构中的一个位置是如何被访问的
// 对于字节值：
// * 如果该分支已被读取，则设置第一个比特位
// * 如果该分支已被编辑，则设置第二个比特位
type mode byte

const (
	AccessWitnessReadFlag = mode(1) // Flag indicating the tree location has been read.
	// AccessWitnessReadFlag 标志表示树形结构中的位置已被读取。
	AccessWitnessWriteFlag = mode(2) // Flag indicating the tree location has been written to.
	// AccessWitnessWriteFlag 标志表示树形结构中的位置已被写入。
)

var zeroTreeIndex uint256.Int // Represents the zero value for a tree index.
// zeroTreeIndex 代表树形索引的零值。

// AccessEvents lists the locations of the state that are being accessed
// during the production of a block.
// AccessEvents 列出了在区块生产期间正在被访问的状态的位置。
type AccessEvents struct {
	branches map[branchAccessKey]mode // Map to track access mode for each branch.
	// branches 是一个映射，用于跟踪每个分支的访问模式。
	chunks map[chunkAccessKey]mode // Map to track access mode for each chunk (leaf).
	// chunks 是一个映射，用于跟踪每个块（叶子节点）的访问模式。

	pointCache *utils.PointCache // Cache for tree points to optimize key derivation.
	// pointCache 是一个树形节点的缓存，用于优化键的推导。
}

// NewAccessEvents creates a new AccessEvents instance.
// NewAccessEvents 创建一个新的 AccessEvents 实例。
func NewAccessEvents(pointCache *utils.PointCache) *AccessEvents {
	return &AccessEvents{
		branches:   make(map[branchAccessKey]mode),
		chunks:     make(map[chunkAccessKey]mode),
		pointCache: pointCache,
	}
}

// Merge is used to merge the access events that were generated during the
// execution of a tx, with the accumulation of all access events that were
// generated during the execution of all txs preceding this one in a block.
// Merge 用于合并在执行一个交易期间生成的访问事件，以及在一个区块中该交易之前所有交易执行期间生成的所有访问事件的累积。
func (ae *AccessEvents) Merge(other *AccessEvents) {
	for k := range other.branches {
		ae.branches[k] |= other.branches[k] // Merge branch access modes.
		// 合并分支的访问模式。
	}
	for k, chunk := range other.chunks {
		ae.chunks[k] |= chunk // Merge chunk access modes.
		// 合并块的访问模式。
	}
}

// Keys returns, predictably, the list of keys that were touched during the
// buildup of the access witness.
// Keys 方法返回在构建访问见证期间被触及的键的列表。
func (ae *AccessEvents) Keys() [][]byte {
	// TODO: consider if parallelizing this is worth it, probably depending on len(ae.chunks).
	// TODO: 考虑是否值得并行化此操作，可能取决于 len(ae.chunks) 的大小。
	keys := make([][]byte, 0, len(ae.chunks))
	for chunk := range ae.chunks {
		basePoint := ae.pointCache.Get(chunk.addr[:])
		key := utils.GetTreeKeyWithEvaluatedAddress(basePoint, &chunk.treeIndex, chunk.leafKey)
		keys = append(keys, key)
	}
	return keys
}

func (ae *AccessEvents) Copy() *AccessEvents {
	cpy := &AccessEvents{
		branches:   maps.Clone(ae.branches),
		chunks:     maps.Clone(ae.chunks),
		pointCache: ae.pointCache,
	}
	return cpy
}

// AddAccount returns the gas to be charged for each of the currently cold
// member fields of an account.
// AddAccount 方法返回需要为账户当前冷成员字段收取的 gas 费用。
func (ae *AccessEvents) AddAccount(addr common.Address, isWrite bool) uint64 {
	var gas uint64
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, isWrite)
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, isWrite)
	return gas
}

// MessageCallGas returns the gas to be charged for each of the currently
// cold member fields of an account, that need to be touched when making a message
// call to that account.
// MessageCallGas 方法返回在向该账户发起消息调用时，需要为账户当前冷成员字段收取的 gas 费用。
func (ae *AccessEvents) MessageCallGas(destination common.Address) uint64 {
	var gas uint64
	gas += ae.touchAddressAndChargeGas(destination, zeroTreeIndex, utils.BasicDataLeafKey, false)
	return gas
}

// ValueTransferGas returns the gas to be charged for each of the currently
// cold balance member fields of the caller and the callee accounts.
// ValueTransferGas 方法返回需要为调用者和被调用者账户当前冷的余额成员字段收取的 gas 费用。
func (ae *AccessEvents) ValueTransferGas(callerAddr, targetAddr common.Address) uint64 {
	var gas uint64
	gas += ae.touchAddressAndChargeGas(callerAddr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	gas += ae.touchAddressAndChargeGas(targetAddr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	return gas
}

// ContractCreatePreCheckGas charges access costs before
// a contract creation is initiated. It is just reads, because the
// address collision is done before the transfer, and so no write
// are guaranteed to happen at this point.
// ContractCreatePreCheckGas 在合约创建启动之前收取访问成本。这只是读取操作，因为地址冲突在转账之前完成，
// 因此此时不能保证会发生任何写入操作。
func (ae *AccessEvents) ContractCreatePreCheckGas(addr common.Address) uint64 {
	var gas uint64
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, false)
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, false)
	return gas
}

// ContractCreateInitGas returns the access gas costs for the initialization of
// a contract creation.
// ContractCreateInitGas 方法返回合约创建初始化的访问 gas 成本。
func (ae *AccessEvents) ContractCreateInitGas(addr common.Address) uint64 {
	var gas uint64
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	gas += ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, true)
	return gas
}

// AddTxOrigin adds the member fields of the sender account to the access event list,
// so that cold accesses are not charged, since they are covered by the 21000 gas.
// AddTxOrigin 方法将发送者账户的成员字段添加到访问事件列表中，这样就不会收取冷访问的 gas 费用，
// 因为它们已被 21000 gas 所覆盖。
func (ae *AccessEvents) AddTxOrigin(originAddr common.Address) {
	ae.touchAddressAndChargeGas(originAddr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	ae.touchAddressAndChargeGas(originAddr, zeroTreeIndex, utils.CodeHashLeafKey, false)
}

// AddTxDestination adds the member fields of the sender account to the access event list,
// so that cold accesses are not charged, since they are covered by the 21000 gas.
// AddTxDestination 方法将发送者账户的成员字段添加到访问事件列表中，这样就不会收取冷访问的 gas 费用，
// 因为它们已被 21000 gas 所覆盖。
func (ae *AccessEvents) AddTxDestination(addr common.Address, sendsValue bool) {
	ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, sendsValue)
	ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, false)
}

// SlotGas returns the amount of gas to be charged for a cold storage access.
// SlotGas 方法返回需要为冷存储访问收取的 gas 量。
func (ae *AccessEvents) SlotGas(addr common.Address, slot common.Hash, isWrite bool) uint64 {
	treeIndex, subIndex := utils.StorageIndex(slot.Bytes())
	return ae.touchAddressAndChargeGas(addr, *treeIndex, subIndex, isWrite)
}

// touchAddressAndChargeGas adds any missing access event to the access event list, and returns the cold
// access cost to be charged, if need be.
// touchAddressAndChargeGas 方法将任何缺失的访问事件添加到访问事件列表中，并返回需要收取的冷访问成本（如果需要）。
func (ae *AccessEvents) touchAddressAndChargeGas(addr common.Address, treeIndex uint256.Int, subIndex byte, isWrite bool) uint64 {
	stemRead, selectorRead, stemWrite, selectorWrite, selectorFill := ae.touchAddress(addr, treeIndex, subIndex, isWrite)

	var gas uint64
	if stemRead {
		gas += params.WitnessBranchReadCost
	}
	if selectorRead {
		gas += params.WitnessChunkReadCost
	}
	if stemWrite {
		gas += params.WitnessBranchWriteCost
	}
	if selectorWrite {
		gas += params.WitnessChunkWriteCost
	}
	if selectorFill {
		gas += params.WitnessChunkFillCost
	}
	return gas
}

// touchAddress adds any missing access event to the access event list.
// touchAddress 方法将任何缺失的访问事件添加到访问事件列表中。
func (ae *AccessEvents) touchAddress(addr common.Address, treeIndex uint256.Int, subIndex byte, isWrite bool) (bool, bool, bool, bool, bool) {
	branchKey := newBranchAccessKey(addr, treeIndex)
	chunkKey := newChunkAccessKey(branchKey, subIndex)

	// Read access.
	var branchRead, chunkRead bool
	if _, hasStem := ae.branches[branchKey]; !hasStem {
		branchRead = true
		ae.branches[branchKey] = AccessWitnessReadFlag
	}
	if _, hasSelector := ae.chunks[chunkKey]; !hasSelector {
		chunkRead = true
		ae.chunks[chunkKey] = AccessWitnessReadFlag
	}

	// Write access.
	var branchWrite, chunkWrite, chunkFill bool
	if isWrite {
		if (ae.branches[branchKey] & AccessWitnessWriteFlag) == 0 {
			branchWrite = true
			ae.branches[branchKey] |= AccessWitnessWriteFlag
		}

		chunkValue := ae.chunks[chunkKey]
		if (chunkValue & AccessWitnessWriteFlag) == 0 {
			chunkWrite = true
			ae.chunks[chunkKey] |= AccessWitnessWriteFlag
		}
		// TODO: charge chunk filling costs if the leaf was previously empty in the state
		// TODO: 如果叶子节点在状态中之前为空，则收取块填充成本。
	}
	return branchRead, chunkRead, branchWrite, chunkWrite, chunkFill
}

type branchAccessKey struct {
	addr      common.Address
	treeIndex uint256.Int
}

func newBranchAccessKey(addr common.Address, treeIndex uint256.Int) branchAccessKey {
	var sk branchAccessKey
	sk.addr = addr
	sk.treeIndex = treeIndex
	return sk
}

type chunkAccessKey struct {
	branchAccessKey
	leafKey byte
}

func newChunkAccessKey(branchKey branchAccessKey, leafKey byte) chunkAccessKey {
	var lk chunkAccessKey
	lk.branchAccessKey = branchKey
	lk.leafKey = leafKey
	return lk
}

// CodeChunksRangeGas is a helper function to touch every chunk in a code range and charge witness gas costs
// CodeChunksRangeGas 是一个辅助函数，用于触及代码范围内的每个块并收取见证 gas 成本。
func (ae *AccessEvents) CodeChunksRangeGas(contractAddr common.Address, startPC, size uint64, codeLen uint64, isWrite bool) uint64 {
	// note that in the case where the copied code is outside the range of the
	// contract code but touches the last leaf with contract code in it,
	// we don't include the last leaf of code in the AccessWitness.  The
	// reason that we do not need the last leaf is the account's code size
	// is already in the AccessWitness so a stateless verifier can see that
	// the code from the last leaf is not needed.
	// 请注意，在复制的代码超出合约代码范围但触及包含合约代码的最后一个叶子节点的情况下，
	// 我们不会在 AccessWitness 中包含代码的最后一个叶子节点。我们不需要最后一个叶子节点的原因是，
	// 账户的代码大小已经存在于 AccessWitness 中，因此无状态验证器可以看到不需要来自最后一个叶子节点的代码。
	if (codeLen == 0 && size == 0) || startPC > codeLen {
		return 0
	}

	endPC := startPC + size
	if endPC > codeLen {
		endPC = codeLen
	}
	if endPC > 0 {
		endPC -= 1 // endPC is the last bytecode that will be touched.
		// endPC 是将被触及的最后一个字节码。
	}

	var statelessGasCharged uint64
	for chunkNumber := startPC / 31; chunkNumber <= endPC/31; chunkNumber++ {
		treeIndex := *uint256.NewInt((chunkNumber + 128) / 256)
		subIndex := byte((chunkNumber + 128) % 256)
		gas := ae.touchAddressAndChargeGas(contractAddr, treeIndex, subIndex, isWrite)
		var overflow bool
		statelessGasCharged, overflow = math.SafeAdd(statelessGasCharged, gas)
		if overflow {
			panic("overflow when adding gas")
		}
	}
	return statelessGasCharged
}

// BasicDataGas adds the account's basic data to the accessed data, and returns the
// amount of gas that it costs.
// Note that an access in write mode implies an access in read mode, whereas an
// access in read mode does not imply an access in write mode.
// BasicDataGas 方法将账户的基本数据添加到访问的数据中，并返回其成本的 gas 量。
// 请注意，写入模式的访问意味着读取模式的访问，而读取模式的访问并不意味着写入模式的访问。
func (ae *AccessEvents) BasicDataGas(addr common.Address, isWrite bool) uint64 {
	return ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, isWrite)
}

// CodeHashGas adds the account's code hash to the accessed data, and returns the
// amount of gas that it costs.
// in write mode. If false, the charged gas corresponds to an access in read mode.
// Note that an access in write mode implies an access in read mode, whereas an access in
// read mode does not imply an access in write mode.
// CodeHashGas 方法将账户的代码哈希添加到访问的数据中，并返回其成本的 gas 量。
// 在写入模式下。如果为 false，则收取的 gas 对应于读取模式下的访问。
// 请注意，写入模式的访问意味着读取模式的访问，而读取模式的访问并不意味着写入模式的访问。
func (ae *AccessEvents) CodeHashGas(addr common.Address, isWrite bool) uint64 {
	return ae.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, isWrite)
}
