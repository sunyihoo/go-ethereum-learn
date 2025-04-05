// Copyright 2017 The go-ethereum Authors
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

package ethash

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

// 工作量证明 (PoW): Ethash 是一种 PoW 算法，矿工需要通过解决一个计算难题（找到满足难度目标的哈希值）来创建新的区块。代码中的难度调整机制确保了出块时间的稳定。
// 难度调整和难度炸弹: 代码中定义了多个难度调整算法，这些算法会根据历史出块时间动态调整网络的挖矿难度。难度炸弹是协议中内置的一个机制，旨在随着时间的推移逐渐增加挖矿难度，最终使得 PoW 变得不可行，从而推动协议向新的共识机制（如权益证明）的过渡。
// 叔块 (Uncle Blocks): 叔块是 Ethash PoW 的一个特性，用于奖励那些几乎同时挖出区块但其区块未被包含在主链上的矿工，有助于减少 PoW 挖矿的中心化风险。
// 硬分叉 (Hard Forks): 代码中多次提到了不同的硬分叉（Frontier, Byzantium, Constantinople 等），这些是以太坊协议升级的关键节点，会引入新的特性、修改共识规则或调整参数（如区块奖励、难度调整算法）。
// 共识接口 (consensus.Engine): 这段代码实现了 consensus.Engine 接口，定义了 Ethash 共识引擎需要实现的方法，例如区块头的验证、难度计算、奖励分配等。

// Ethash proof-of-work protocol constants.
// Ethash 工作量证明协议的常量。
var (
	FrontierBlockReward = uint256.NewInt(5e+18) // Block reward in wei for successfully mining a block
	// FrontierBlockReward 是成功挖出一个区块的奖励，单位为 wei (以太坊最小单位)。这是 Frontier 时代的奖励。
	ByzantiumBlockReward = uint256.NewInt(3e+18) // Block reward in wei for successfully mining a block upward from Byzantium
	// ByzantiumBlockReward 是拜占庭 (Byzantium) 硬分叉之后成功挖出一个区块的奖励。
	ConstantinopleBlockReward = uint256.NewInt(2e+18) // Block reward in wei for successfully mining a block upward from Constantinople
	// ConstantinopleBlockReward 是君士坦丁堡 (Constantinople) 硬分叉之后成功挖出一个区块的奖励。
	maxUncles = 2 // Maximum number of uncles allowed in a single block
	// maxUncles 是单个区块中允许包含的最大叔块 (uncle block) 数量。
	allowedFutureBlockTimeSeconds = int64(15) // Max seconds from current time allowed for blocks, before they're considered future blocks
	// allowedFutureBlockTimeSeconds 是区块的时间戳与当前时间的允许最大偏差秒数。超过这个偏差的区块被认为是未来的区块。

	// calcDifficultyEip5133 is the difficulty adjustment algorithm as specified by EIP 5133.
	// It offsets the bomb a total of 11.4M blocks.
	// Specification EIP-5133: https://eips.ethereum.org/EIPS/eip-5133
	// calcDifficultyEip5133 是由 EIP-5133 规定的难度调整算法。它将难度炸弹推迟了总共 1140 万个区块。
	calcDifficultyEip5133 = makeDifficultyCalculator(big.NewInt(11_400_000))

	// calcDifficultyEip4345 is the difficulty adjustment algorithm as specified by EIP 4345.
	// It offsets the bomb a total of 10.7M blocks.
	// Specification EIP-4345: https://eips.ethereum.org/EIPS/eip-4345
	// calcDifficultyEip4345 是由 EIP-4345 规定的难度调整算法。它将难度炸弹推迟了总共 1070 万个区块。
	calcDifficultyEip4345 = makeDifficultyCalculator(big.NewInt(10_700_000))

	// calcDifficultyEip3554 is the difficulty adjustment algorithm as specified by EIP 3554.
	// It offsets the bomb a total of 9.7M blocks.
	// Specification EIP-3554: https://eips.ethereum.org/EIPS/eip-3554
	// calcDifficultyEip3554 是由 EIP-3554 规定的难度调整算法。它将难度炸弹推迟了总共 970 万个区块。
	calcDifficultyEip3554 = makeDifficultyCalculator(big.NewInt(9700000))

	// calcDifficultyEip2384 is the difficulty adjustment algorithm as specified by EIP 2384.
	// It offsets the bomb 4M blocks from Constantinople, so in total 9M blocks.
	// Specification EIP-2384: https://eips.ethereum.org/EIPS/eip-2384
	// calcDifficultyEip2384 是由 EIP-2384 规定的难度调整算法。它在君士坦丁堡硬分叉后将难度炸弹推迟了 400 万个区块，总共推迟了 900 万个区块。
	calcDifficultyEip2384 = makeDifficultyCalculator(big.NewInt(9000000))

	// calcDifficultyConstantinople is the difficulty adjustment algorithm for Constantinople.
	// It returns the difficulty that a new block should have when created at time given the
	// parent block's time and difficulty. The calculation uses the Byzantium rules, but with
	// bomb offset 5M.
	// Specification EIP-1234: https://eips.ethereum.org/EIPS/eip-1234
	// calcDifficultyConstantinople 是君士坦丁堡硬分叉的难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。计算使用拜占庭规则，但难度炸弹偏移量为 500 万。
	calcDifficultyConstantinople = makeDifficultyCalculator(big.NewInt(5000000))

	// calcDifficultyByzantium is the difficulty adjustment algorithm. It returns
	// the difficulty that a new block should have when created at time given the
	// parent block's time and difficulty. The calculation uses the Byzantium rules.
	// Specification EIP-649: https://eips.ethereum.org/EIPS/eip-649
	// calcDifficultyByzantium 是拜占庭硬分叉的难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。计算使用拜占庭规则。
	calcDifficultyByzantium = makeDifficultyCalculator(big.NewInt(3000000))
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
// 用于标记区块无效的各种错误消息。这些应该是私有的，以防止引擎特定的错误在代码库的其他部分被引用，如果引擎被替换，则会自然地中断。请将常见的错误类型放入 consensus 包中。
var (
	errOlderBlockTime = errors.New("timestamp older than parent")
	// errOlderBlockTime 表示区块的时间戳早于父区块的时间戳。
	errTooManyUncles = errors.New("too many uncles")
	// errTooManyUncles 表示区块中包含的叔块数量超过了最大允许数量。
	errDuplicateUncle = errors.New("duplicate uncle")
	// errDuplicateUncle 表示区块中包含了重复的叔块。
	errUncleIsAncestor = errors.New("uncle is ancestor")
	// errUncleIsAncestor 表示叔块是当前区块的祖先区块。
	errDanglingUncle = errors.New("uncle's parent is not ancestor")
	// errDanglingUncle 表示叔块的父区块不是当前区块的祖先区块。
)

// Author implements consensus.Engine, returning the header's coinbase as the
// proof-of-work verified author of the block.
// Author 实现了 consensus.Engine 接口，返回区块头的 coinbase 作为经过工作量证明验证的区块作者。
func (ethash *Ethash) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
// VerifyHeader 检查一个区块头是否符合标准以太坊 Ethash 引擎的共识规则。
func (ethash *Ethash) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	// Short circuit if the header is known, or its parent not
	// 如果区块头已知，或者其父区块未知，则直接返回。
	number := header.Number.Uint64()
	if chain.GetHeader(header.Hash(), number) != nil {
		return nil
	}
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	// Sanity checks passed, do a proper verification
	// 通过初步检查，进行更细致的验证。
	return ethash.verifyHeader(chain, header, parent, false, time.Now().Unix())
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications.
// VerifyHeaders 类似于 VerifyHeader，但并发地验证一批区块头。该方法返回一个退出通道以中止操作，并返回一个结果通道以检索异步验证结果。
func (ethash *Ethash) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	// If we're running a full engine faking, accept any input as valid
	// 如果我们正在运行一个完整的引擎模拟，则接受任何输入为有效。
	if ethash.fakeFull || len(headers) == 0 {
		abort, results := make(chan struct{}), make(chan error, len(headers))
		for i := 0; i < len(headers); i++ {
			results <- nil
		}
		return abort, results
	}
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	unixNow := time.Now().Unix()

	go func() {
		for i, header := range headers {
			var parent *types.Header
			if i == 0 {
				parent = chain.GetHeader(headers[0].ParentHash, headers[0].Number.Uint64()-1)
			} else if headers[i-1].Hash() == headers[i].ParentHash {
				parent = headers[i-1]
			}
			var err error
			if parent == nil {
				err = consensus.ErrUnknownAncestor
			} else {
				err = ethash.verifyHeader(chain, header, parent, false, unixNow)
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifyUncles verifies that the given block's uncles conform to the consensus
// rules of the stock Ethereum ethash engine.
// VerifyUncles 验证给定区块的叔块是否符合标准以太坊 Ethash 引擎的共识规则。
func (ethash *Ethash) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	// If we're running a full engine faking, accept any input as valid
	// 如果我们正在运行一个完整的引擎模拟，则接受任何输入为有效。
	if ethash.fakeFull {
		return nil
	}
	// Verify that there are at most 2 uncles included in this block
	// 验证此区块中包含的叔块数量是否最多为 2 个。
	if len(block.Uncles()) > maxUncles {
		return errTooManyUncles
	}
	if len(block.Uncles()) == 0 {
		return nil
	}
	// Gather the set of past uncles and ancestors
	// 收集过去的叔块和祖先区块的集合。
	uncles, ancestors := mapset.NewSet[common.Hash](), make(map[common.Hash]*types.Header)

	number, parent := block.NumberU64()-1, block.ParentHash()
	for i := 0; i < 7; i++ {
		ancestorHeader := chain.GetHeader(parent, number)
		if ancestorHeader == nil {
			break
		}
		ancestors[parent] = ancestorHeader
		// If the ancestor doesn't have any uncles, we don't have to iterate them
		// 如果祖先区块没有任何叔块，我们就不必迭代它们。
		if ancestorHeader.UncleHash != types.EmptyUncleHash {
			// Need to add those uncles to the banned list too
			// 也需要将这些叔块添加到禁止列表中。
			ancestor := chain.GetBlock(parent, number)
			if ancestor == nil {
				break
			}
			for _, uncle := range ancestor.Uncles() {
				uncles.Add(uncle.Hash())
			}
		}
		parent, number = ancestorHeader.ParentHash, number-1
	}
	ancestors[block.Hash()] = block.Header()
	uncles.Add(block.Hash())

	// Verify each of the uncles that it's recent, but not an ancestor
	// 验证每个叔块是否是最近的，但不是祖先区块。
	for _, uncle := range block.Uncles() {
		// Make sure every uncle is rewarded only once
		// 确保每个叔块只被奖励一次。
		hash := uncle.Hash()
		if uncles.Contains(hash) {
			return errDuplicateUncle
		}
		uncles.Add(hash)

		// Make sure the uncle has a valid ancestry
		// 确保叔块具有有效的祖先关系。
		if ancestors[hash] != nil {
			return errUncleIsAncestor
		}
		if ancestors[uncle.ParentHash] == nil || uncle.ParentHash == block.ParentHash() {
			return errDanglingUncle
		}
		if err := ethash.verifyHeader(chain, uncle, ancestors[uncle.ParentHash], true, time.Now().Unix()); err != nil {
			return err
		}
	}
	return nil
}

// verifyHeader checks whether a header conforms to the consensus rules of the
// stock Ethereum ethash engine.
// See YP section 4.3.4. "Block Header Validity"
// verifyHeader 检查一个区块头是否符合标准以太坊 Ethash 引擎的共识规则。
// 参见黄皮书 (Yellow Paper) 第 4.3.4 节 “区块头有效性”。
func (ethash *Ethash) verifyHeader(chain consensus.ChainHeaderReader, header, parent *types.Header, uncle bool, unixNow int64) error {
	// Ensure that the header's extra-data section is of a reasonable size
	// 确保区块头的 extra-data 部分的大小在合理范围内。
	if uint64(len(header.Extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra-data too long: %d > %d", len(header.Extra), params.MaximumExtraDataSize)
	}
	// Verify the header's timestamp
	// 验证区块头的时间戳。
	if !uncle {
		if header.Time > uint64(unixNow+allowedFutureBlockTimeSeconds) {
			return consensus.ErrFutureBlock
		}
	}
	if header.Time <= parent.Time {
		return errOlderBlockTime
	}
	// Verify the block's difficulty based on its timestamp and parent's difficulty
	// 根据区块的时间戳和父区块的难度验证区块的难度。
	expected := ethash.CalcDifficulty(chain, header.Time, parent)

	if expected.Cmp(header.Difficulty) != 0 {
		return fmt.Errorf("invalid difficulty: have %v, want %v", header.Difficulty, expected)
	}
	// Verify that the gas limit is <= 2^63-1
	// 验证 gas limit 是否小于等于 2^63 - 1。
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	// Verify that the gasUsed is <= gasLimit
	// 验证 gasUsed 是否小于等于 gasLimit。
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Verify the block's gas usage and (if applicable) verify the base fee.
	// 验证区块的 gas 使用情况，并在适用时验证基础费用 (base fee)。
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		// 在 EIP-1559 分叉之前，验证 BaseFee 是否不存在。
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, expected 'nil'", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		// 验证区块头的 EIP-1559 属性。
		return err
	}
	// Verify that the block number is parent's +1
	// 验证区块号是否为父区块号加 1。
	if diff := new(big.Int).Sub(header.Number, parent.Number); diff.Cmp(big.NewInt(1)) != 0 {
		return consensus.ErrInvalidNumber
	}
	if chain.Config().IsShanghai(header.Number, header.Time) {
		return errors.New("ethash does not support shanghai fork")
	}
	// Verify the non-existence of withdrawalsHash.
	if header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}
	if chain.Config().IsCancun(header.Number, header.Time) {
		return errors.New("ethash does not support cancun fork")
	}
	// Verify the non-existence of cancun-specific header fields
	switch {
	case header.ExcessBlobGas != nil:
		return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", header.ExcessBlobGas)
	case header.BlobGasUsed != nil:
		return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", header.BlobGasUsed)
	case header.ParentBeaconRoot != nil:
		return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", header.ParentBeaconRoot)
	}
	// Add some fake checks for tests
	// 为测试添加一些虚假的检查。
	if ethash.fakeDelay != nil {
		time.Sleep(*ethash.fakeDelay)
	}
	if ethash.fakeFail != nil && *ethash.fakeFail == header.Number.Uint64() {
		return errors.New("invalid tester pow")
	}
	// If all checks passed, validate any special fields for hard forks
	// 如果所有检查都通过，则验证硬分叉的任何特殊字段。
	if err := misc.VerifyDAOHeaderExtraData(chain.Config(), header); err != nil {
		return err
	}
	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
// CalcDifficulty 是难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。
func (ethash *Ethash) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	return CalcDifficulty(chain.Config(), time, parent)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time
// given the parent block's time and difficulty.
// CalcDifficulty 是难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。
func CalcDifficulty(config *params.ChainConfig, time uint64, parent *types.Header) *big.Int {
	next := new(big.Int).Add(parent.Number, big1)
	switch {
	case config.IsGrayGlacier(next):
		return calcDifficultyEip5133(time, parent)
	case config.IsArrowGlacier(next):
		return calcDifficultyEip4345(time, parent)
	case config.IsLondon(next):
		return calcDifficultyEip3554(time, parent)
	case config.IsMuirGlacier(next):
		return calcDifficultyEip2384(time, parent)
	case config.IsConstantinople(next):
		return calcDifficultyConstantinople(time, parent)
	case config.IsByzantium(next):
		return calcDifficultyByzantium(time, parent)
	case config.IsHomestead(next):
		return calcDifficultyHomestead(time, parent)
	default:
		return calcDifficultyFrontier(time, parent)
	}
}

// Some weird constants to avoid constant memory allocs for them.
// 一些奇怪的常量，以避免为它们分配常量内存。
var (
	expDiffPeriod = big.NewInt(100000)
	// expDiffPeriod 是难度调整中指数增长部分的周期，通常称为“难度炸弹”的周期。
	big1       = big.NewInt(1)
	big2       = big.NewInt(2)
	big9       = big.NewInt(9)
	big10      = big.NewInt(10)
	bigMinus99 = big.NewInt(-99)
)

// makeDifficultyCalculator creates a difficultyCalculator with the given bomb-delay.
// the difficulty is calculated with Byzantium rules, which differs from Homestead in
// how uncles affect the calculation
// makeDifficultyCalculator 使用给定的难度炸弹延迟创建一个难度计算器。
// 难度计算使用拜占庭规则，这与家园规则在叔块如何影响计算方面有所不同。
func makeDifficultyCalculator(bombDelay *big.Int) func(time uint64, parent *types.Header) *big.Int {
	// Note, the calculations below looks at the parent number, which is 1 below
	// the block number. Thus we remove one from the delay given
	// 注意，下面的计算查看的是父区块号，它比当前区块号小 1。因此，我们从给定的延迟中减去 1。
	bombDelayFromParent := new(big.Int).Sub(bombDelay, big1)
	return func(time uint64, parent *types.Header) *big.Int {
		// https://github.com/ethereum/EIPs/issues/100.
		// algorithm:
		// diff = (parent_diff +
		//         (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
		//        ) + 2^(periodCount - 2)

		bigTime := new(big.Int).SetUint64(time)
		bigParentTime := new(big.Int).SetUint64(parent.Time)

		// holds intermediate values to make the algo easier to read & audit
		// 保存中间值，使算法更易于阅读和审计。
		x := new(big.Int)
		y := new(big.Int)

		// (2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9
		x.Sub(bigTime, bigParentTime)
		x.Div(x, big9)
		if parent.UncleHash == types.EmptyUncleHash {
			x.Sub(big1, x)
		} else {
			x.Sub(big2, x)
		}
		// max((2 if len(parent_uncles) else 1) - (block_timestamp - parent_timestamp) // 9, -99)
		if x.Cmp(bigMinus99) < 0 {
			x.Set(bigMinus99)
		}
		// parent_diff + (parent_diff / 2048 * max((2 if len(parent.uncles) else 1) - ((timestamp - parent.timestamp) // 9), -99))
		y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
		x.Mul(y, x)
		x.Add(parent.Difficulty, x)

		// minimum difficulty can ever be (before exponential factor)
		// 难度在指数因子之前的最小值。
		if x.Cmp(params.MinimumDifficulty) < 0 {
			x.Set(params.MinimumDifficulty)
		}
		// calculate a fake block number for the ice-age delay
		// Specification: https://eips.ethereum.org/EIPS/eip-1234
		// 计算冰河期延迟的虚假区块号。
		fakeBlockNumber := new(big.Int)
		if parent.Number.Cmp(bombDelayFromParent) >= 0 {
			fakeBlockNumber = fakeBlockNumber.Sub(parent.Number, bombDelayFromParent)
		}
		// for the exponential factor
		// 用于指数因子。
		periodCount := fakeBlockNumber
		periodCount.Div(periodCount, expDiffPeriod)

		// the exponential factor, commonly referred to as "the bomb"
		// diff = diff + 2^(periodCount - 2)
		// 指数因子，通常被称为“难度炸弹”。
		if periodCount.Cmp(big1) > 0 {
			y.Sub(periodCount, big2)
			y.Exp(big2, y, nil)
			x.Add(x, y)
		}
		return x
	}
}

// calcDifficultyHomestead is the difficulty adjustment algorithm. It returns
// the difficulty that a new block should have when created at time given the
// parent block's time and difficulty. The calculation uses the Homestead rules.
// calcDifficultyHomestead 是家园 (Homestead) 硬分叉的难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。计算使用家园规则。
func calcDifficultyHomestead(time uint64, parent *types.Header) *big.Int {
	// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md
	// algorithm:
	// diff = (parent_diff +
	//         (parent_diff / 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	//        ) + 2^(periodCount - 2)

	bigTime := new(big.Int).SetUint64(time)
	bigParentTime := new(big.Int).SetUint64(parent.Time)

	// holds intermediate values to make the algo easier to read & audit
	// 保存中间值，使算法更易于阅读和审计。
	x := new(big.Int)
	y := new(big.Int)

	// 1 - (block_timestamp - parent_timestamp) // 10
	x.Sub(bigTime, bigParentTime)
	x.Div(x, big10)
	x.Sub(big1, x)

	// max(1 - (block_timestamp - parent_timestamp) // 10, -99)
	if x.Cmp(bigMinus99) < 0 {
		x.Set(bigMinus99)
	}
	// (parent_diff + parent_diff // 2048 * max(1 - (block_timestamp - parent_timestamp) // 10, -99))
	y.Div(parent.Difficulty, params.DifficultyBoundDivisor)
	x.Mul(y, x)
	x.Add(parent.Difficulty, x)

	// minimum difficulty can ever be (before exponential factor)
	// 难度在指数因子之前的最小值。
	if x.Cmp(params.MinimumDifficulty) < 0 {
		x.Set(params.MinimumDifficulty)
	}
	// for the exponential factor
	// 用于指数因子。
	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)

	// the exponential factor, commonly referred to as "the bomb"
	// diff = diff + 2^(periodCount - 2)
	// 指数因子，通常被称为“难度炸弹”。
	if periodCount.Cmp(big1) > 0 {
		y.Sub(periodCount, big2)
		y.Exp(big2, y, nil)
		x.Add(x, y)
	}
	return x
}

// calcDifficultyFrontier is the difficulty adjustment algorithm. It returns the
// difficulty that a new block should have when created at time given the parent
// block's time and difficulty. The calculation uses the Frontier rules.
// calcDifficultyFrontier 是前沿 (Frontier) 时代的难度调整算法。它根据父区块的时间和难度计算新区块应该具有的难度。计算使用前沿规则。
func calcDifficultyFrontier(time uint64, parent *types.Header) *big.Int {
	diff := new(big.Int)
	adjust := new(big.Int).Div(parent.Difficulty, params.DifficultyBoundDivisor)
	bigTime := new(big.Int)
	bigParentTime := new(big.Int)

	bigTime.SetUint64(time)
	bigParentTime.SetUint64(parent.Time)

	if bigTime.Sub(bigTime, bigParentTime).Cmp(params.DurationLimit) < 0 {
		diff.Add(parent.Difficulty, adjust)
	} else {
		diff.Sub(parent.Difficulty, adjust)
	}
	if diff.Cmp(params.MinimumDifficulty) < 0 {
		diff.Set(params.MinimumDifficulty)
	}

	periodCount := new(big.Int).Add(parent.Number, big1)
	periodCount.Div(periodCount, expDiffPeriod)
	if periodCount.Cmp(big1) > 0 {
		// diff = diff + 2^(periodCount - 2)
		expDiff := periodCount.Sub(periodCount, big2)
		expDiff.Exp(big2, expDiff, nil)
		diff.Add(diff, expDiff)
		if diff.Cmp(params.MinimumDifficulty) < 0 {
			diff = params.MinimumDifficulty
		}
	}
	return diff
}

// Exported for fuzzing
// 为模糊测试导出。
var FrontierDifficultyCalculator = calcDifficultyFrontier
var HomesteadDifficultyCalculator = calcDifficultyHomestead
var DynamicDifficultyCalculator = makeDifficultyCalculator

// Prepare implements consensus.Engine, initializing the difficulty field of a
// header to conform to the ethash protocol. The changes are done inline.
// Prepare 实现了 consensus.Engine 接口，用于初始化区块头的难度字段，使其符合 Ethash 协议。这些更改是直接在原地进行的。
func (ethash *Ethash) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = ethash.CalcDifficulty(chain, header.Time, parent)
	return nil
}

// Finalize implements consensus.Engine, accumulating the block and uncle rewards.
// Finalize 实现了 consensus.Engine 接口，用于累积区块和叔块的奖励。
func (ethash *Ethash) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body) {
	// Accumulate any block and uncle rewards
	// 累积任何区块和叔块的奖励。
	accumulateRewards(chain.Config(), state, header, body.Uncles)
}

// FinalizeAndAssemble implements consensus.Engine, accumulating the block and
// uncle rewards, setting the final state and assembling the block.
// FinalizeAndAssemble 实现了 consensus.Engine 接口，用于累积区块和叔块的奖励，设置最终状态并组装区块。
func (ethash *Ethash) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	if len(body.Withdrawals) > 0 {
		return nil, errors.New("ethash does not support withdrawals")
	}
	// Finalize block
	// 完成区块的最终处理。
	ethash.Finalize(chain, header, state, body)

	// Assign the final state root to header.
	// 将最终的状态根 (state root) 赋值给区块头。
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Header seems complete, assemble into a block and return
	// 区块头似乎已完成，将其组装成一个区块并返回。
	return types.NewBlock(header, &types.Body{Transactions: body.Transactions, Uncles: body.Uncles}, receipts, trie.NewStackTrie(nil)), nil
}

// SealHash returns the hash of a block prior to it being sealed.
// SealHash 返回在区块被密封之前（即挖矿完成之前）的哈希值。
func (ethash *Ethash) SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()

	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("withdrawal hash set on ethash")
	}
	if header.ExcessBlobGas != nil {
		panic("excess blob gas set on ethash")
	}
	if header.BlobGasUsed != nil {
		panic("blob gas used set on ethash")
	}
	if header.ParentBeaconRoot != nil {
		panic("parent beacon root set on ethash")
	}
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}

// accumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
// accumulateRewards 将给定区块的 coinbase 记入挖矿奖励。总奖励包括静态区块奖励和包含的叔块奖励。每个叔块的 coinbase 也会得到奖励。
func accumulateRewards(config *params.ChainConfig, stateDB vm.StateDB, header *types.Header, uncles []*types.Header) {
	// Select the correct block reward based on chain progression
	// 根据链的进展选择正确的区块奖励。
	blockReward := FrontierBlockReward
	if config.IsByzantium(header.Number) {
		blockReward = ByzantiumBlockReward
	}
	if config.IsConstantinople(header.Number) {
		blockReward = ConstantinopleBlockReward
	}
	// Accumulate the rewards for the miner and any included uncles
	// 累积矿工和任何包含的叔块的奖励。
	reward := new(uint256.Int).Set(blockReward)
	r := new(uint256.Int)
	hNum, _ := uint256.FromBig(header.Number)
	for _, uncle := range uncles {
		uNum, _ := uint256.FromBig(uncle.Number)
		r.AddUint64(uNum, 8)
		r.Sub(r, hNum)
		r.Mul(r, blockReward)
		r.Rsh(r, 3)
		stateDB.AddBalance(uncle.Coinbase, r, tracing.BalanceIncreaseRewardMineUncle)

		r.Rsh(blockReward, 5)
		reward.Add(reward, r)
	}
	stateDB.AddBalance(header.Coinbase, reward, tracing.BalanceIncreaseRewardMineBlock)
}
