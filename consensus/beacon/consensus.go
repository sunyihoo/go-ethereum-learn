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

package beacon

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// Proof-of-stake protocol constants.
// 权益证明协议的常量。
var (
	beaconDifficulty = common.Big0 // The default block difficulty in the beacon consensus
	// beaconDifficulty 是信标共识中的默认区块难度，设置为 0。在 PoS 阶段，区块的产生不再依赖于工作量证明，因此难度为 0。
	beaconNonce = types.EncodeNonce(0) // The default block nonce in the beacon consensus
	// beaconNonce 是信标共识中的默认区块 nonce，设置为 0。Nonce 在 PoW 中用于寻找满足难度目标的哈希，但在 PoS 中其作用不同或不再使用，因此设置为 0。
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
// 用于标记区块无效的各种错误消息。这些错误消息应该是私有的，以防止引擎特定的错误在代码库的其他部分被引用，如果在引擎被替换时会导致不兼容。请将通用的错误类型放在 consensus 包中。
var (
	errTooManyUncles = errors.New("too many uncles")
	// errTooManyUncles 表示区块中包含过多的叔块。在 PoS 阶段，叔块的概念被移除。
	errInvalidNonce = errors.New("invalid nonce")
	// errInvalidNonce 表示区块的 nonce 无效。在 PoS 阶段，nonce 的验证规则与 PoW 不同。
	errInvalidUncleHash = errors.New("invalid uncle hash")
	// errInvalidUncleHash 表示区块的叔块哈希无效。在 PoS 阶段，叔块哈希应为特定的空值。
	errInvalidTimestamp = errors.New("invalid timestamp")
	// errInvalidTimestamp 表示区块的时间戳无效。PoS 阶段对时间戳的验证有新的规则。
)

// Beacon is a consensus engine that combines the eth1 consensus and proof-of-stake
// algorithm. There is a special flag inside to decide whether to use legacy consensus
// rules or new rules. The transition rule is described in the eth1/2 merge spec.
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3675.md
//
// The beacon here is a half-functional consensus engine with partial functions which
// is only used for necessary consensus checks. The legacy consensus engine can be any
// engine implements the consensus interface (except the beacon itself).
// Beacon 是一种结合了 eth1 共识和权益证明算法的共识引擎。内部有一个特殊的标志来决定是使用旧的共识规则还是新的规则。过渡规则在 eth1/2 合并规范（EIP-3675）中描述。
//
// 这里的 Beacon 是一个半功能的共识引擎，只有部分功能，仅用于必要的共识检查。旧的共识引擎可以是任何实现 consensus 接口的引擎（除了 Beacon 本身）。
type Beacon struct {
	ethone consensus.Engine // Original consensus engine used in eth1, e.g. ethash or clique
	// ethone 是在 eth1 阶段使用的原始共识引擎，例如 ethash（用于 PoW）或 clique（用于 PoA）。
}

// New creates a consensus engine with the given embedded eth1 engine.
// New 函数使用给定的嵌入式 eth1 引擎创建一个新的共识引擎。
func New(ethone consensus.Engine) *Beacon {
	if _, ok := ethone.(*Beacon); ok {
		panic("nested consensus engine")
	}
	return &Beacon{ethone: ethone}
}

// Author implements consensus.Engine, returning the verified author of the block.
// Author 实现了 consensus.Engine 接口，返回区块的已验证作者。
func (beacon *Beacon) Author(header *types.Header) (common.Address, error) {
	if !beacon.IsPoSHeader(header) {
		return beacon.ethone.Author(header)
	}
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum consensus engine.
// VerifyHeader 检查区块头是否符合标准以太坊共识引擎的规则。
func (beacon *Beacon) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	reached, err := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	// IsTTDReached 函数用于检查是否已经达到终端总难度（Terminal Total Difficulty, TTD），TTD 是以太坊从 PoW 过渡到 PoS 的触发点。
	if err != nil {
		return err
	}
	if !reached {
		return beacon.ethone.VerifyHeader(chain, header)
		// 如果尚未达到 TTD，则使用嵌入的 eth1 引擎（例如 ethash）的规则来验证区块头。
	}
	// Short circuit if the parent is not known
	// 如果父区块未知，则快速返回错误。
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	// 基本检查通过，进行更细致的验证。
	return beacon.verifyHeader(chain, header, parent)
	// 如果已经达到 TTD，则使用 Beacon 共识引擎自身的 verifyHeader 方法来验证区块头，该方法会应用 PoS 阶段的规则。
}

// errOut constructs an error channel with prefilled errors inside.
// errOut 函数创建一个预先填充了错误的错误通道。
func errOut(n int, err error) chan error {
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		errs <- err
	}
	return errs
}

// splitHeaders splits the provided header batch into two parts according to
// the configured ttd. It requires the parent of header batch along with its
// td are stored correctly in chain. If ttd is not configured yet, all headers
// will be treated legacy PoW headers.
// Note, this function will not verify the header validity but just split them.
// splitHeaders 函数根据配置的 TTD 将提供的区块头批处理分割成两部分。它要求链中正确存储了区块头批处理的父区块及其总难度。如果 TTD 尚未配置，则所有区块头都将被视为旧的 PoW 区块头。
// 注意，此函数不会验证区块头的有效性，只会分割它们。
func (beacon *Beacon) splitHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) ([]*types.Header, []*types.Header, error) {
	// TTD is not defined yet, all headers should be in legacy format.
	// 如果 TTD 尚未定义，则所有区块头都应采用旧格式。
	ttd := chain.Config().TerminalTotalDifficulty
	ptd := chain.GetTd(headers[0].ParentHash, headers[0].Number.Uint64()-1)
	if ptd == nil {
		return nil, nil, consensus.ErrUnknownAncestor
	}
	// The entire header batch already crosses the transition.
	// 整个区块头批处理已经跨越了过渡点。
	if ptd.Cmp(ttd) >= 0 {
		return nil, headers, nil
	}
	var (
		preHeaders  = headers
		postHeaders []*types.Header
		td          = new(big.Int).Set(ptd)
		tdPassed    bool
	)
	for i, header := range headers {
		if tdPassed {
			preHeaders = headers[:i]
			postHeaders = headers[i:]
			break
		}
		td = td.Add(td, header.Difficulty)
		if td.Cmp(ttd) >= 0 {
			// This is the last PoW header, it still belongs to
			// the preHeaders, so we cannot split+break yet.
			// 这是最后一个 PoW 区块头，它仍然属于 preHeaders，所以我们不能立即分割并跳出循环。
			tdPassed = true
		}
	}
	return preHeaders, postHeaders, nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
// VerifyHeaders expect the headers to be ordered and continuous.
// VerifyHeaders 与 VerifyHeader 类似，但并发地验证一批区块头。该方法返回一个退出通道以中止操作，并返回一个结果通道以检索异步验证结果。
// VerifyHeaders 期望区块头是有序且连续的。
func (beacon *Beacon) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	preHeaders, postHeaders, err := beacon.splitHeaders(chain, headers)
	if err != nil {
		return make(chan struct{}), errOut(len(headers), err)
	}
	if len(postHeaders) == 0 {
		return beacon.ethone.VerifyHeaders(chain, headers)
		// 如果没有 PoS 阶段的区块头，则使用 eth1 引擎验证所有区块头。
	}
	if len(preHeaders) == 0 {
		return beacon.verifyHeaders(chain, headers, nil)
		// 如果所有区块头都属于 PoS 阶段，则使用 Beacon 引擎验证。
	}
	// The transition point exists in the middle, separate the headers
	// into two batches and apply different verification rules for them.
	// 过渡点存在于中间，将区块头分成两批，并对它们应用不同的验证规则。
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		var (
			old, new, out      = 0, len(preHeaders), 0
			errors             = make([]error, len(headers))
			done               = make([]bool, len(headers))
			oldDone, oldResult = beacon.ethone.VerifyHeaders(chain, preHeaders)
			// 使用 eth1 引擎并发验证 PoW 阶段的区块头。
			newDone, newResult = beacon.verifyHeaders(chain, postHeaders, preHeaders[len(preHeaders)-1])
			// 使用 Beacon 引擎并发验证 PoS 阶段的区块头，并将最后一个 PoW 区块头作为祖先传递。
		)
		// Collect the results
		// 收集验证结果。
		for {
			for ; done[out]; out++ {
				results <- errors[out]
				if out == len(headers)-1 {
					return
				}
			}
			select {
			case err := <-oldResult:
				if !done[old] { // skip TTD-verified failures
					errors[old], done[old] = err, true
				}
				old++
			case err := <-newResult:
				errors[new], done[new] = err, true
				new++
			case <-abort:
				close(oldDone)
				close(newDone)
				return
			}
		}
	}()
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the Ethereum consensus engine.
// VerifyUncles 验证给定区块的叔块是否符合以太坊共识引擎的规则。
func (beacon *Beacon) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.VerifyUncles(chain, block)
	}
	// Verify that there is no uncle block. It's explicitly disabled in the beacon
	// 验证区块中没有叔块。在信标共识中，叔块被显式禁用。
	if len(block.Uncles()) > 0 {
		return errTooManyUncles
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum consensus engine. The difference between the beacon and classic is
// (a) The following fields are expected to be constants:
//   - difficulty is expected to be 0
//   - nonce is expected to be 0
//   - unclehash is expected to be Hash(emptyHeader)
//     to be the desired constants
//
// (b) we don't verify if a block is in the future anymore
// (c) the extradata is limited to 32 bytes
// verifyHeader 检查区块头是否符合标准以太坊共识引擎的规则。Beacon 共识引擎与经典共识引擎的区别在于：
// (a) 以下字段预计为常量：
//   - difficulty 预计为 0
//   - nonce 预计为 0
//   - unclehash 预计为 Hash(emptyHeader)，即 `types.EmptyUncleHash`
//     这些是期望的常量值。
//
// (b) 我们不再验证区块是否在未来生成（PoW 阶段有时间戳限制，PoS 阶段有所放宽）
// (c) extradata 的大小限制为 32 字节
func (beacon *Beacon) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header) error {
	// Ensure that the header's extra-data section is of a reasonable size
	// 确保区块头的 extra-data 部分大小合理。
	if len(header.Extra) > int(params.MaximumExtraDataSize) {
		return fmt.Errorf("extra-data longer than 32 bytes (%d)", len(header.Extra))
	}
	// Verify the seal parts. Ensure the nonce and uncle hash are the expected value.
	// 验证区块头的密封部分。确保 nonce 和 uncle hash 是期望的值。
	if header.Nonce != beaconNonce {
		return errInvalidNonce
	}
	if header.UncleHash != types.EmptyUncleHash {
		return errInvalidUncleHash
	}
	// Verify the timestamp
	// 验证时间戳。PoS 阶段对时间戳的要求通常是大于父区块的时间戳，并且在一定允许的偏差范围内。
	if header.Time <= parent.Time {
		return errInvalidTimestamp
	}
	// Verify the block's difficulty to ensure it's the default constant
	// 验证区块的难度，确保它是默认的常量（0）。
	if beaconDifficulty.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, beaconDifficulty)
	}
	// Verify that the gas limit is <= 2^63-1
	// 验证 gas limit 是否小于等于 2^63-1。这是以太坊的共识规则。
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	// 验证 gasUsed 是否小于等于 gasLimit。这也是以太坊的共识规则。
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify that the block number is parent's +1
	// 验证区块号是否为父区块号加 1。这是区块链的基本规则。
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(common.Big1) != 0 {
		return consensus.ErrInvalidNumber
	}
	// Verify the header's EIP-1559 attributes.
	// 验证区块头的 EIP-1559 属性。EIP-1559 引入了基础费用和矿工小费的交易费用机制。
	if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		return err
	}
	// Verify existence / non-existence of withdrawalsHash.
	// 验证 withdrawalsHash 是否存在/不存在。提款功能是在上海升级中引入的，允许信标链验证者提取他们的质押 ETH。
	shanghai := chain.Config().IsShanghai(header.Number, header.Time)
	if shanghai && header.WithdrawalsHash == nil {
		return errors.New("missing withdrawalsHash")
	}
	if !shanghai && header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}
	// Verify the existence / non-existence of cancun-specific header fields
	// 验证 Cancun 升级特定的区块头字段是否存在/不存在。Cancun 升级引入了 EIP-4844，增加了 blob 交易。
	cancun := chain.Config().IsCancun(header.Number, header.Time)
	if !cancun {
		switch {
		case header.ExcessBlobGas != nil:
			return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", header.ExcessBlobGas)
		case header.BlobGasUsed != nil:
			return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", header.BlobGasUsed)
		case header.ParentBeaconRoot != nil:
			return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", header.ParentBeaconRoot)
		}
	} else {
		if header.ParentBeaconRoot == nil {
			return errors.New("header is missing beaconRoot")
		}
		if err := eip4844.VerifyEIP4844Header(parent, header); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeaders is similar to verifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications. An additional parent
// header will be passed if the relevant header is not in the database yet.
// verifyHeaders 与 verifyHeader 类似，但并发地验证一批区块头。该方法返回一个退出通道以中止操作，并返回一个结果通道以检索异步验证结果。如果相关的父区块头尚未在数据库中，则会传递一个额外的父区块头。
func (beacon *Beacon) verifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, ancestor *types.Header) (chan<- struct{}, <-chan error) {
	var (
		abort   = make(chan struct{})
		results = make(chan error, len(headers))
	)
	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				if ancestor != nil {
					parent = ancestor
				} else {
					parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
				}
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}
			if parent == nil {
				select {
				case <-abort:
					return
				case results <- consensus.ErrUnknownAncestor:
				}
				continue
			}
			err := beacon.verifyHeader(chain, header, parent)
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the beacon protocol. The changes are done inline.
// Prepare 实现了 consensus.Engine 接口，初始化区块头的 difficulty 字段以符合信标协议。这些更改是就地进行的。
func (beacon *Beacon) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Transition isn't triggered yet, use the legacy rules for preparation.
	// 如果尚未触发过渡，则使用旧的规则进行准备。
	reached, err := IsTTDReached(chain, header.ParentHash, header.Number.Uint64()-1)
	if err != nil {
		return err
	}
	if !reached {
		return beacon.ethone.Prepare(chain, header)
		// 在 PoW 阶段，区块头的准备工作由嵌入的 eth1 引擎处理。
	}
	header.Difficulty = beaconDifficulty
	// 一旦达到 TTD，新的区块的 difficulty 应该设置为信标共识的默认值，即 0。
	return nil
}

// Finalize implements consensus.Engine and processes withdrawals on top.
// Finalize 实现了 consensus.Engine 接口，并在其基础上处理提款。
func (beacon *Beacon) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body) {
	if !beacon.IsPoSHeader(header) {
		beacon.ethone.Finalize(chain, header, state, body)
		return
		// 在 PoW 阶段，区块的最终确定工作由嵌入的 eth1 引擎处理。
	}
	// Withdrawals processing.
	// 处理提款。
	for _, w := range body.Withdrawals {
		// Convert amount from gwei to wei.
		// 将提款金额从 gwei 转换为 wei。以太坊内部通常使用 wei 作为最小单位。
		amount := new(uint256.Int).SetUint64(w.Amount)
		amount = amount.Mul(amount, uint256.NewInt(params.GWei))
		state.AddBalance(w.Address, amount, tracing.BalanceIncreaseWithdrawal)
		// 将提款金额添加到指定地址的余额中。
	}
	// No block reward which is issued by consensus layer instead.
	// PoS 阶段没有由执行层发放的区块奖励，区块奖励由共识层（信标链）负责。
}

// FinalizeAndAssemble implements consensus.Engine, setting the final state and
// assembling the block.
// FinalizeAndAssemble 实现了 consensus.Engine 接口，设置最终状态并组装区块。
func (beacon *Beacon) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	if !beacon.IsPoSHeader(header) {
		return beacon.ethone.FinalizeAndAssemble(chain, header, state, body, receipts)
		// 在 PoW 阶段，区块的最终确定和组装工作由嵌入的 eth1 引擎处理。
	}
	shanghai := chain.Config().IsShanghai(header.Number, header.Time)
	if shanghai {
		// All blocks after Shanghai must include a withdrawals root.
		// 上海升级后的所有区块都必须包含提款根哈希（withdrawals root）。
		if body.Withdrawals == nil {
			body.Withdrawals = make([]*types.Withdrawal, 0)
		}
	} else {
		if len(body.Withdrawals) > 0 {
			return nil, errors.New("withdrawals set before Shanghai activation")
		}
	}
	// Finalize and assemble the block.
	// 最终确定并组装区块。
	beacon.Finalize(chain, header, state, body)

	// Assign the final state root to header.
	// 将最终的状态根哈希（state root）赋值给区块头。状态根哈希是对执行完区块中所有交易后状态树的 Merkle 根的表示。
	header.Root = state.IntermediateRoot(true)

	// Assemble the final block.
	// 组装最终的区块。
	block := types.NewBlock(header, body, receipts, trie.NewStackTrie(nil))
	// 使用区块头、交易体、交易回执和叔块（在 PoS 阶段叔块为空）创建一个新的区块。

	// Create the block witness and attach to block.
	// This step needs to happen as late as possible to catch all access events.
	// 创建区块见证（witness）并将其附加到区块。
	// 此步骤需要尽可能晚地发生，以捕获所有访问事件。这部分代码与 Verkle 树有关，Verkle 树是一种更高效的状态树结构，旨在替代 Merkle Patricia 树。
	if chain.Config().IsVerkle(header.Number, header.Time) {
		keys := state.AccessEvents().Keys()

		// Open the pre-tree to prove the pre-state against
		// 打开前一个状态树，用于证明状态的改变。
		parent := chain.GetHeaderByNumber(header.Number.Uint64() - 1)
		if parent == nil {
			return nil, fmt.Errorf("nil parent header for block %d", header.Number)
		}
		preTrie, err := state.Database().OpenTrie(parent.Root)
		if err != nil {
			return nil, fmt.Errorf("error opening pre-state tree root: %w", err)
		}
		vktPreTrie, okpre := preTrie.(*trie.VerkleTrie)
		vktPostTrie, okpost := state.GetTrie().(*trie.VerkleTrie)

		// The witness is only attached iff both parent and current block are
		// using verkle tree.
		// 只有当父区块和当前区块都使用 Verkle 树时，才附加见证。
		if okpre && okpost {
			if len(keys) > 0 {
				verkleProof, stateDiff, err := vktPreTrie.Proof(vktPostTrie, keys)
				if err != nil {
					return nil, fmt.Errorf("error generating verkle proof for block %d: %w", header.Number, err)
				}
				block = block.WithWitness(&types.ExecutionWitness{
					StateDiff:   stateDiff,
					VerkleProof: verkleProof,
				})
			}
		}
	}

	return block, nil
}

// Seal generates a new sealing request for the given input block and pushes
// the result into the given channel.
//
// Note, the method returns immediately and will send the result async. More
// than one result may also be returned depending on the consensus algorithm.
// Seal 为给定的输入区块生成一个新的密封请求，并将结果推送到给定的通道中。
//
// 注意，该方法会立即返回，并异步发送结果。根据共识算法的不同，也可能返回多个结果。
func (beacon *Beacon) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	if !beacon.IsPoSHeader(block.Header()) {
		return beacon.ethone.Seal(chain, block, results, stop)
		// 在 PoW 阶段，区块的密封工作由嵌入的 eth1 引擎处理（例如，ethash 引擎会尝试找到满足难度目标的 nonce）。
	}
	// The seal verification is done by the external consensus engine,
	// return directly without pushing any block back. In another word
	// beacon won't return any result by `results` channel which may
	// blocks the receiver logic forever.
	// 在 PoS 阶段，区块的密封验证由外部的共识引擎（信标链）完成，这里直接返回，不向结果通道推送任何区块。换句话说，Beacon 共识引擎不会通过 `results` 通道返回任何结果，这可能会导致接收逻辑永远阻塞。这是因为在 PoS 中，区块的提议和证明是由信标链上的验证者完成的，而不是由执行层（即这里的 Beacon 引擎）直接完成。
	return nil
}

// SealHash returns the hash of a block prior to it being sealed.
// SealHash 返回区块在被密封之前的哈希值。
func (beacon *Beacon) SealHash(header *types.Header) common.Hash {
	return beacon.ethone.SealHash(header)
	// 在 PoS 阶段，SealHash 的计算可能仍然沿用 eth1 的规则，用于标识需要被签名的内容。
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
// CalcDifficulty 是难度调整算法。它返回在给定时间创建新区块时应具有的难度，该难度取决于父区块的时间和难度。
func (beacon *Beacon) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	// Transition isn't triggered yet, use the legacy rules for calculation
	// 如果尚未触发过渡，则使用旧的规则进行计算难度。
	if reached, _ := IsTTDReached(chain, parent.Hash(), parent.Number.Uint64()); !reached {
		return beacon.ethone.CalcDifficulty(chain, time, parent)
		// 在 PoW 阶段，区块的难度调整由嵌入的 eth1 引擎处理。
	}
	return beaconDifficulty
	// 一旦达到 TTD，新的区块的难度应该设置为信标共识的默认值，即 0。PoS 阶段不再有动态难度调整。
}

// APIs implements consensus.Engine, returning the user facing RPC APIs.
// APIs 实现了 consensus.Engine 接口，返回面向用户的 RPC API。
func (beacon *Beacon) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return beacon.ethone.APIs(chain)
	// Beacon 共识引擎通常不暴露额外的 RPC API，而是沿用 eth1 引擎的 API。
}

// Close shutdowns the consensus engine
// Close 关闭共识引擎。
func (beacon *Beacon) Close() error {
	return beacon.ethone.Close()
	// 关闭 Beacon 共识引擎时，也会关闭其嵌入的 eth1 引擎。
}

// IsPoSHeader reports the header belongs to the PoS-stage with some special fields.
// This function is not suitable for a part of APIs like Prepare or CalcDifficulty
// because the header difficulty is not set yet.
// IsPoSHeader 报告区块头是否属于具有某些特殊字段的 PoS 阶段。
// 此函数不适用于 Prepare 或 CalcDifficulty 等 API 的一部分，因为区块头的 difficulty 尚未设置。
func (beacon *Beacon) IsPoSHeader(header *types.Header) bool {
	if header.Difficulty == nil {
		panic("IsPoSHeader called with invalid difficulty")
	}
	return header.Difficulty.Cmp(beaconDifficulty) == 0
	// 通过检查区块头的 difficulty 是否等于 beaconDifficulty（即 0）来判断该区块是否属于 PoS 阶段。
}

// InnerEngine returns the embedded eth1 consensus engine.
// InnerEngine 返回嵌入的 eth1 共识引擎。
func (beacon *Beacon) InnerEngine() consensus.Engine {
	return beacon.ethone
}

// SetThreads updates the mining threads. Delegate the call
// to the eth1 engine if it's threaded.
// SetThreads 更新挖矿线程数。如果 eth1 引擎是基于线程的，则将调用委托给它。
func (beacon *Beacon) SetThreads(threads int) {
	type threaded interface {
		SetThreads(threads int)
	}
	if th, ok := beacon.ethone.(threaded); ok {
		th.SetThreads(threads)
	}
}

// IsTTDReached checks if the TotalTerminalDifficulty has been surpassed on the `parentHash` block.
// It depends on the parentHash already being stored in the database.
// If the parentHash is not stored in the database a UnknownAncestor error is returned.
// IsTTDReached 检查在 `parentHash` 的区块上是否已经超过了终端总难度（TotalTerminalDifficulty）。
// 这取决于 `parentHash` 是否已经存储在数据库中。
// 如果 `parentHash` 未存储在数据库中，则返回 UnknownAncestor 错误。
func IsTTDReached(chain consensus.ChainHeaderReader, parentHash common.Hash, parentNumber uint64) (bool, error) {
	td := chain.GetTd(parentHash, parentNumber)
	if td == nil {
		return false, consensus.ErrUnknownAncestor
	}
	return td.Cmp(chain.Config().TerminalTotalDifficulty) >= 0, nil
	// 通过比较父区块的总难度（Total Difficulty, TD）与配置的终端总难度（Terminal Total Difficulty, TTD）来判断是否已经达到合并的触发点。
}
