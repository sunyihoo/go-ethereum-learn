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

// Package clique implements the proof-of-authority consensus engine.
package clique

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/crypto/sha3"
)

// Clique 是一种典型的 PoA 共识算法，它依赖于一组预先授权的签名者来维护区块链的安全。其关键特点包括：
//
// 授权签名者: 只有被授权的节点才能创建新的区块。签名者列表可以通过投票机制进行更新。
// 投票机制: 通过在区块的 nonce 字段中使用特定的值 (nonceAuthVote 和 nonceDropVote)，签名者可以投票添加或删除其他签名者。
// Epoch 和检查点: epochLength 定义了投票结果生效的周期。在每个 epoch 的开始（检查点），会强制更新签名者列表。
// 轮流出块: 虽然代码中通过难度值 (diffInTurn 和 diffNoTurn) 来区分是否轮到某个签名者出块，但 PoA 并不强制轮流机制，这取决于具体的实现逻辑。
// 区块结构: Clique 对区块头的 Extra 字段有特定的格式要求，用于存储签名者的 vanity、签名以及在检查点区块中存储签名者列表。
// 不支持 PoW 特性: 由于是 PoA 共识，Clique 不支持叔块，并且 MixDigest 字段通常为零。
// 对新升级的限制: 从代码中可以看出，当前的 Clique 实现不支持 Shanghai 和 Cancun 升级引入的新特性（如提款和 blob 交易）。

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	// checkpointInterval 是指在多少个区块之后将投票快照保存到数据库。这里设置为 1024 个区块。
	inmemorySnapshots = 128 // Number of recent vote snapshots to keep in memory
	// inmemorySnapshots 是指在内存中保留的最近投票快照的数量。这里设置为 128 个。
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory
	// inmemorySignatures 是指在内存中保留的最近区块签名的数量。这里设置为 4096 个。
)

// Clique proof-of-authority protocol constants.
// Clique 权益权威证明协议的常量。
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes
	// epochLength 是指在多少个区块之后进行检查点操作并重置待处理的投票。这里设置为 30000 个区块。在 Clique 中，epoch 用于定期更新授权的签名者列表。

	extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	// extraVanity 是指在区块头的 extra-data 字段中，用于存储签名者自定义信息的固定字节数。这里设置为 32 字节。
	extraSeal = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal
	// extraSeal 是指在区块头的 extra-data 字段中，用于存储签名者签名的固定字节数。这里使用 `crypto.SignatureLength`，通常是 65 字节（对于 secp256k1 签名）。

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	// nonceAuthVote 是一个特殊的 nonce 值，用于投票添加一个新的签名者。
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.
	// nonceDropVote 是一个特殊的 nonce 值，用于投票移除一个签名者。

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
	// uncleHash 是叔块哈希，在 PoA 共识中，叔块没有意义，因此始终是空叔块列表的哈希值。

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	// diffInTurn 是指轮到某个授权签名者签署区块时，区块的难度值。这里设置为 2。
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
	// diffNoTurn 是指未轮到某个授权签名者签署区块时，区块的难度值。这里设置为 1。Clique 使用难度值来帮助区分是否是轮到某个签名者出块。
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
// 用于标记区块无效的各种错误消息。这些错误消息应该是私有的，以防止引擎特定的错误在代码库的其他部分被引用，如果在引擎被替换时会导致不兼容。请将通用的错误类型放在 consensus 包中。
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errUnknownBlock 当请求一个不在本地区块链中的区块的签名者列表时返回。

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")
	// errInvalidCheckpointBeneficiary 如果一个检查点/epoch 过渡区块的受益人地址不为零时返回。在 Clique 中，检查点区块的受益人通常应为零地址。

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")
	// errInvalidVote 如果区块头的 nonce 值不是用于投票的两个常量值（`nonceAuthVote` 或 `nonceDropVote`）时返回。

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")
	// errInvalidCheckpointVote 如果一个检查点/epoch 过渡区块的投票 nonce 不为零时返回。

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")
	// errMissingVanity 如果区块头的 extra-data 部分长度小于 32 字节（用于存储签名者的自定义信息）时返回。

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")
	// errMissingSignature 如果区块头的 extra-data 部分末尾没有 65 字节的 secp256k1 签名时返回。

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")
	// errExtraSigners 如果非检查点区块在其 extra-data 字段中包含签名者列表数据时返回。签名者列表只应出现在检查点区块中。

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")
	// errInvalidCheckpointSigners 如果一个检查点区块包含无效的签名者列表（例如，长度不能被 20 字节整除，因为每个地址是 20 字节）时返回。

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")
	// errMismatchingCheckpointSigners 如果一个检查点区块包含的签名者列表与本地节点计算出的列表不匹配时返回。

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")
	// errInvalidMixDigest 如果区块头的 mix digest 不为零时返回。在 PoA 中，mix digest 通常为零。

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")
	// errInvalidUncleHash 如果区块包含非空的叔块列表时返回。在 PoA 中，叔块通常不被允许。

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")
	// errInvalidDifficulty 如果区块的难度值既不是 1 也不是 2 时返回。

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")
	// errWrongDifficulty 如果区块的难度值与签署者的轮次不匹配时返回。

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")
	// errInvalidTimestamp 如果区块的时间戳小于前一个区块的时间戳加上最小区块间隔时返回。

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")
	// errInvalidVotingChain 如果尝试通过超出范围或不连续的区块头来修改授权列表时返回。

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")
	// errUnauthorizedSigner 如果区块头由未经授权的实体签名时返回。

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")
	// errRecentlySigned 如果一个授权实体最近已经签署过一个区块头，因此暂时不允许再次签署时返回。Clique 通常有这种机制来防止单个签名者过于频繁地出块。
)

// ecrecover extracts the Ethereum account address from a signed header.
// ecrecover 函数从已签名的区块头中提取以太坊账户地址。
func ecrecover(header *types.Header, sigcache *sigLRU) (common.Address, error) {
	// If the signature's already cached, return that
	// 如果签名已经缓存，则直接返回缓存的地址。
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address, nil
	}
	// Retrieve the signature from the header extra-data
	// 从区块头的 extra-data 中检索签名。
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	// 恢复公钥和以太坊地址。
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// Clique is the proof-of-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
// Clique 是一种提议用于在 Ropsten 攻击后支持以太坊测试网络的权益权威证明共识引擎。
type Clique struct {
	config *params.CliqueConfig // Consensus engine configuration parameters
	// config 存储 Clique 共识引擎的配置参数。
	db ethdb.Database // Database to store and retrieve snapshot checkpoints
	// db 是用于存储和检索快照检查点的数据库。

	recents *lru.Cache[common.Hash, *Snapshot] // Snapshots for recent block to speed up reorgs
	// recents 是一个 LRU 缓存，用于存储最近区块的快照，以加速链重组。
	signatures *sigLRU // Signatures of recent blocks to speed up mining
	// signatures 是一个 LRU 缓存，用于存储最近区块的签名，以加速挖矿（尽管在 PoA 中通常不叫挖矿）。

	proposals map[common.Address]bool // Current list of proposals we are pushing
	// proposals 是当前我们正在推动的提案列表，用于添加或删除授权签名者。键是提议的地址，值表示是授权（true）还是撤销授权（false）。

	signer common.Address // Ethereum address of the signing key
	// signer 是当前节点的签名密钥对应的以太坊地址。
	lock sync.RWMutex // Protects the signer and proposals fields
	// lock 用于保护 `signer` 和 `proposals` 字段的并发访问。

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
	// fakeDiff 是一个仅用于测试的标志，用于跳过难度验证。
}

// New creates a Clique proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
// New 函数创建一个新的 Clique 权益权威证明共识引擎，其初始签名者列表由用户提供。
func New(config *params.CliqueConfig, db ethdb.Database) *Clique {
	// Set any missing consensus parameters to their defaults
	// 将任何缺失的共识参数设置为默认值。
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	// Allocate the snapshot caches and create the engine
	// 分配快照缓存并创建引擎。
	recents := lru.NewCache[common.Hash, *Snapshot](inmemorySnapshots)
	signatures := lru.NewCache[common.Hash, common.Address](inmemorySignatures)

	return &Clique{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
	}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
// Author 实现了 consensus.Engine 接口，返回从区块头 extra-data 部分的签名中恢复出的以太坊地址。
func (c *Clique) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
// VerifyHeader 检查区块头是否符合共识规则。
func (c *Clique) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
// VerifyHeaders 与 VerifyHeader 类似，但用于验证一批区块头。该方法返回一个退出通道以中止操作，并返回一个结果通道以检索异步验证结果（顺序与输入切片一致）。
func (c *Clique) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
// verifyHeader 检查区块头是否符合共识规则。调用者可以选择性地传入一个父区块头批处理（升序），以避免从数据库中查找。这对于并发验证一批新的区块头很有用。
func (c *Clique) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	// 不要浪费时间检查来自未来的区块。
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	// Checkpoint blocks need to enforce zero beneficiary
	// 检查点区块需要强制受益人为零地址。
	checkpoint := (number % c.config.Epoch) == 0
	if checkpoint && header.Coinbase != (common.Address{}) {
		return errInvalidCheckpointBeneficiary
	}
	// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
	// Nonce 必须是 0x00..0 或 0xff..f，检查点强制为零。
	if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidVote
	}
	if checkpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
		return errInvalidCheckpointVote
	}
	// Check that the extra-data contains both the vanity and signature
	// 检查 extra-data 是否包含 vanity 和签名。
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
	// 确保 extra-data 在检查点包含签名者列表，否则不包含。
	signersBytes := len(header.Extra) - extraVanity - extraSeal
	if !checkpoint && signersBytes != 0 {
		return errExtraSigners
	}
	if checkpoint && signersBytes%common.AddressLength != 0 {
		return errInvalidCheckpointSigners
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	// 确保 mix digest 为零，因为目前没有分叉保护。
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	// 确保区块不包含任何在 PoA 中没有意义的叔块。
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	// 确保区块的难度是有意义的（此时可能不正确）。
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidDifficulty
		}
	}
	// Verify that the gas limit is <= 2^63-1
	// 验证 gas limit 是否小于等于 2^63-1。
	if header.GasLimit > params.MaxGasLimit {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, params.MaxGasLimit)
	}
	if chain.Config().IsShanghai(header.Number, header.Time) {
		return errors.New("clique does not support shanghai fork")
		// Clique 共识引擎不支持上海升级。
	}
	// Verify the non-existence of withdrawalsHash.
	// 验证 withdrawalsHash 不存在。
	if header.WithdrawalsHash != nil {
		return fmt.Errorf("invalid withdrawalsHash: have %x, expected nil", header.WithdrawalsHash)
	}
	if chain.Config().IsCancun(header.Number, header.Time) {
		return errors.New("clique does not support cancun fork")
		// Clique 共识引擎不支持 Cancun 升级。
	}
	// Verify the non-existence of cancun-specific header fields
	// 验证 Cancun 升级特定的区块头字段不存在。
	switch {
	case header.ExcessBlobGas != nil:
		return fmt.Errorf("invalid excessBlobGas: have %d, expected nil", header.ExcessBlobGas)
	case header.BlobGasUsed != nil:
		return fmt.Errorf("invalid blobGasUsed: have %d, expected nil", header.BlobGasUsed)
	case header.ParentBeaconRoot != nil:
		return fmt.Errorf("invalid parentBeaconRoot, have %#x, expected nil", header.ParentBeaconRoot)
	}
	// All basic checks passed, verify cascading fields
	// 所有基本检查通过，验证级联字段。
	return c.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
// verifyCascadingFields 验证所有非独立的区块头字段，而是依赖于一批先前的区块头。调用者可以选择性地传入一个父区块头批处理（升序），以避免从数据库中查找。这对于并发验证一批新的区块头很有用。
func (c *Clique) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	// 创世区块始终是有效的终点。
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to its parent
	// 确保区块的时间戳不会离其父区块太近。
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+c.config.Period > header.Time {
		return errInvalidTimestamp
	}
	// Verify that the gasUsed is <= gasLimit
	// 验证 gasUsed 是否小于等于 gasLimit。
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	if !chain.Config().IsLondon(header.Number) {
		// Verify BaseFee not present before EIP-1559 fork.
		// 在 EIP-1559 分叉之前验证 BaseFee 不存在。
		if header.BaseFee != nil {
			return fmt.Errorf("invalid baseFee before fork: have %d, want <nil>", header.BaseFee)
		}
		if err := misc.VerifyGaslimit(parent.GasLimit, header.GasLimit); err != nil {
			return err
		}
	} else if err := eip1559.VerifyEIP1559Header(chain.Config(), parent, header); err != nil {
		// Verify the header's EIP-1559 attributes.
		// 验证区块头的 EIP-1559 属性。
		return err
	}
	// Retrieve the snapshot needed to verify this header and cache it
	// 检索验证此区块头所需的快照并缓存它。
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the signer list
	// 如果区块是检查点区块，则验证签名者列表。
	if number%c.config.Epoch == 0 {
		signers := make([]byte, len(snap.Signers)*common.AddressLength)
		for i, signer := range snap.signers() {
			copy(signers[i*common.AddressLength:], signer[:])
		}
		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], signers) {
			return errMismatchingCheckpointSigners
		}
	}
	// All basic checks passed, verify the seal and return
	// 所有基本检查通过，验证签名并返回。
	return c.verifySeal(snap, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
// snapshot 函数检索给定时间点的授权快照。
func (c *Clique) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	// 在内存或磁盘中搜索检查点的快照。
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		// 如果找到了内存中的快照，则使用它。
		if s, ok := c.recents.Get(hash); ok {
			snap = s
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		// 如果找到了磁盘上的检查点快照，则使用它。
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		// 如果我们处于创世区块，则快照初始状态。或者，如果在没有父区块的检查点区块（轻客户端 CHT），或者我们积累了超过允许重组的区块头数量（从冷存储重新初始化链），则认为该检查点是可信的并进行快照。
		if number == 0 || (number%c.config.Epoch == 0 && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				signers := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(signers); i++ {
					copy(signers[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				snap = newSnapshot(c.config, c.signatures, number, hash, signers)
				if err := snap.store(c.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		// 此区块头没有快照，收集区块头并向后移动。
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			// 如果我们有明确的父区块，则从中选择（强制执行）。
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			// 没有明确的父区块（或没有剩余的），从数据库中获取。
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	// 找到先前的快照，在其基础上应用任何待处理的区块头。
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	// 如果我们生成了一个新的检查点快照，则保存到磁盘。
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
// VerifyUncles 实现了 consensus.Engine 接口，由于此共识机制不允许叔块，因此对于任何叔块都始终返回错误。
func (c *Clique) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
// verifySeal 检查区块头中包含的签名是否满足共识协议的要求。该方法接受一个可选的父区块头列表，这些区块头尚未成为本地区块链的一部分，用于生成快照。
func (c *Clique) verifySeal(snap *Snapshot, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	// 不支持验证创世区块。
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Resolve the authorization key and check against signers
	// 解析授权密钥并对照签名者列表进行检查。
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	for seen, recent := range snap.Recents {
		if recent == signer {
			// Signer is among recents, only fail if the current block doesn't shift it out
			// 签名者在最近签名者列表中，只有当当前区块没有将其移出时才失败。Clique 通常会限制签名者连续出块的次数。
			if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	// 确保难度与签名者的轮次相对应。
	if !c.fakeDiff {
		inturn := snap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
// Prepare 实现了 consensus.Engine 接口，准备区块头的所有共识字段，以便在其上运行交易。
func (c *Clique) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	// 如果该区块不是检查点，则投一个随机票（目前足够）。
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	// Assemble the voting snapshot to check which votes make sense
	// 组装投票快照以检查哪些投票是合理的。
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	c.lock.RLock()
	if number%c.config.Epoch != 0 {
		// Gather all the proposals that make sense voting on
		// 收集所有有意义的投票提案。
		addresses := make([]common.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		// 如果有待处理的提案，则对其进行投票。
		if len(addresses) > 0 {
			header.Coinbase = addresses[rand.Intn(len(addresses))]
			if c.proposals[header.Coinbase] {
				copy(header.Nonce[:], nonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}
	}

	// Copy signer protected by mutex to avoid race condition
	// 复制受互斥锁保护的签名者，以避免竞争条件。
	signer := c.signer
	c.lock.RUnlock()

	// Set the correct difficulty
	// 设置正确的难度。
	header.Difficulty = calcDifficulty(snap, signer)

	// Ensure the extra data has all its components
	// 确保 extra data 包含所有组件。
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	if number%c.config.Epoch == 0 {
		for _, signer := range snap.signers() {
			header.Extra = append(header.Extra, signer[:]...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	// Mix digest 目前保留，设置为空。
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	// 确保时间戳具有正确的延迟。Clique 共识通常要求区块的时间戳比父区块的时间戳至少晚一个固定的时间间隔。
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + c.config.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine. There is no post-transaction
// consensus rules in clique, do nothing here.
// Finalize 实现了 consensus.Engine 接口。Clique 中没有交易后共识规则，因此这里不执行任何操作。
func (c *Clique) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state vm.StateDB, body *types.Body) {
	// No block rewards in PoA, so the state remains as is
	// PoA 中没有区块奖励，因此状态保持不变。
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
// FinalizeAndAssemble 实现了 consensus.Engine 接口，确保没有设置叔块，也没有给予区块奖励，并返回最终的区块。
func (c *Clique) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, body *types.Body, receipts []*types.Receipt) (*types.Block, error) {
	if len(body.Withdrawals) > 0 {
		return nil, errors.New("clique does not support withdrawals")
		// Clique 共识引擎不支持提款功能。
	}
	// Finalize block
	// 最终确定区块。
	c.Finalize(chain, header, state, body)

	// Assign the final state root to header.
	// 将最终的状态根哈希赋值给区块头。
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))

	// Assemble and return the final block for sealing.
	// 组装并返回用于签名的最终区块。
	return types.NewBlock(header, &types.Body{Transactions: body.Transactions}, receipts, trie.NewStackTrie(nil)), nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
// Authorize 函数将一个私钥注入到共识引擎中，用于签署新的区块。
func (c *Clique) Authorize(signer common.Address) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
// Seal 实现了 consensus.Engine 接口，尝试使用本地签名凭据创建一个已签名的区块。
func (c *Clique) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	panic("clique (poa) sealing not supported any more")
	// 目前不再支持 Clique (PoA) 的密封操作。这可能是因为密封逻辑被移动到了其他地方，或者在当前的实现中不直接支持。
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX
// CalcDifficulty 是难度调整算法。它返回新区块应具有的难度：
// * 如果 BLOCK_NUMBER % SIGNER_COUNT != SIGNER_INDEX，则为 DIFF_NOTURN (2)
// * 如果 BLOCK_NUMBER % SIGNER_COUNT == SIGNER_INDEX，则为 DIFF_INTURN (1)
func (c *Clique) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := c.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	c.lock.RLock()
	signer := c.signer
	c.lock.RUnlock()
	return calcDifficulty(snap, signer)
}

func calcDifficulty(snap *Snapshot, signer common.Address) *big.Int {
	if snap.inturn(snap.Number+1, signer) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
// SealHash 返回区块在被签名之前的哈希值。
func (c *Clique) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
// Close 实现了 consensus.Engine 接口。对于 Clique 来说，这是一个空操作，因为没有后台线程。
func (c *Clique) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
// APIs 实现了 consensus.Engine 接口，返回面向用户的 RPC API，以允许控制签名者的投票。
func (c *Clique) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "clique",
		Service:   &API{chain: chain, clique: c},
	}}
}

// SealHash returns the hash of a block prior to it being sealed.
// SealHash 返回区块在被签名之前的哈希值。
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// CliqueRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
// CliqueRLP 返回用于权益权威证明签名的 RLP 编码字节。要签名的 RLP 包括整个区块头，但不包括 extra data 末尾的 65 字节签名。
//
// 注意，该方法要求 extra data 至少为 65 字节，否则会 panic。这样做是为了避免意外地使用两种形式（存在签名或不存在签名），这可能会被滥用来为同一个区块头生成不同的哈希值。
func CliqueRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header) {
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
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("unexpected withdrawal hash value in clique")
	}
	if header.ExcessBlobGas != nil {
		panic("unexpected excess blob gas value in clique")
	}
	if header.BlobGasUsed != nil {
		panic("unexpected blob gas used value in clique")
	}
	if header.ParentBeaconRoot != nil {
		panic("unexpected parent beacon root value in clique")
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}
