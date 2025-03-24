// Copyright 2019 The go-ethereum Authors
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

// Package forkid implements EIP-2124 (https://eips.ethereum.org/EIPS/eip-2124).
package forkid

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// 分叉（Fork）: 以太坊网络中的分叉分为软分叉（soft fork）和硬分叉（hard fork）。硬分叉通常涉及协议升级（例如 EIP-1559），会导致链分裂为两条不兼容的链（如以太坊和以太经典 ETC）。
// EIP 标准: 以太坊改进提案（Ethereum Improvement Proposals）定义了分叉规则。例如，EIP-1559 引入了新的交易费用机制，并通过硬分叉在特定区块高度激活。客户端需要校验这些规则是否一致。
// 区块链同步: 以太坊节点通过 P2P 网络同步数据，分叉校验和是确保节点在同一链上的重要机制。如果校验和不匹配，节点可能需要切换链或更新软件版本。

// 这两个错误变量用于在Geth的分叉验证逻辑中，处理远程节点与本地节点在区块链分叉校验时的异常情况。
var (
	// ErrRemoteStale is returned by the validator if a remote fork checksum is a
	// subset of our already applied forks, but the announced next fork block is
	// not on our already passed chain.
	// 如果远程分叉校验和是我们已经应用的分叉的子集，但所宣布的下一个分叉块不在我们已经通过的链上，则验证器返回 ErrRemoteStale。
	//
	// 表示远程节点的分叉数据已经过时（stale）。
	//
	// 本地节点维护了一组已经应用的分叉规则（fork rules），这些规则通常以校验和（checksum）的形式存储。
	// 远程节点发送其分叉校验和，表明它当前支持的分叉规则。
	// 如果远程校验和是本地已应用分叉的子集（即远程节点支持的分叉少于本地），且远程节点声称的下一个分叉块（fork block）不在本地链上，则认为远程节点需要更新。
	ErrRemoteStale = errors.New("remote needs update")

	// ErrLocalIncompatibleOrStale is returned by the validator if a remote fork
	// checksum does not match any local checksum variation, signalling that the
	// two chains have diverged in the past at some point (possibly at genesis).
	// 如果远程分叉校验和与任何本地校验和变体都不匹配，表明两条链在过去某个时间点（可能是创世块）发生了分歧，则验证器返回 ErrLocalIncompatibleOrStale。
	//
	// 远程节点发送的分叉校验和与本地存储的所有校验和变体（variations）进行比较。
	// 如果没有任何匹配，说明两条链的历史记录在某个点（可能是创世块）发生了分歧。
	// 这种情况下，本地节点可能不兼容，或者需要更新以同步到正确的链。
	//
	// 分歧点（divergence point）：两条链分叉的起点，可能由不同的创世块或硬分叉规则引起。
	ErrLocalIncompatibleOrStale = errors.New("local incompatible or needs update")
)

// 在以太坊的演进中，分叉规则从基于区块高度（例如伦敦分叉在特定区块激活）逐渐过渡到基于时间戳（例如某些测试网或未来的升级）。
// EIP-2124（Fork Identifier）提出了分叉标识的概念，帮助节点检测是否在同一链上运行。
// 区块分叉: 传统硬分叉通过区块高度触发，例如 EIP-1559 在区块 12,965,000 激活。
// 时间分叉: 较新的分叉规则可能基于时间戳触发，例如某些测试网（如 Goerli）使用时间戳来规划升级。这种方式更灵活，但需要客户端调整验证逻辑。

// Fork ID: 在以太坊 P2P 协议中，forkid 是一个标识符，用于确保节点在相同的分叉规则下运行。
// 它通常包含当前分叉的校验和（checksum）以及下一个分叉点（next）。
// timestampThreshold 是对 forkid.next 的临时（hacky）解析方案。

// timestampThreshold is the Ethereum mainnet genesis timestamp. It is used to
// differentiate if a forkid.next field is a block number or a timestamp. Whilst
// very hacky, something's needed to split the validation during the transition
// period (block forks -> time forks).
//
// timestampThreshold 是以太坊主网的创世时间戳。
// 它用于区分 forkid.next 字段是区块号还是时间戳。
// 虽然这种方法非常临时，但在过渡期（从区块分叉转向时间分叉）需要某种方式来分割验证逻辑。
//
// 对应以太坊主网的创世时间戳（Unix 时间戳，单位为秒，表示 2015-07-30 15:26:13 UTC）。
const timestampThreshold = 1438269973

// Blockchain defines all necessary method to build a forkID.
// Blockchain 定义了构建 forkID 所需的所有必要方法。
type Blockchain interface {
	// Config retrieves the chain's fork configuration.
	// Config 获取链的分叉配置。
	Config() *params.ChainConfig

	// Genesis retrieves the chain's genesis block.
	// Genesis 获取链的创世块。
	Genesis() *types.Block

	// CurrentHeader retrieves the current head header of the canonical chain.
	// CurrentHeader 获取规范链的当前头部区块头。
	// 规范链（Canonical Chain）: 以太坊通过工作量证明（PoW，过去）或权益证明（PoS，现在）确定主链。
	// CurrentHeader 确保返回的是主链的最新状态，而不是临时分叉或叔块（uncle block）。
	CurrentHeader() *types.Header
}

// EIP-2124 定义了一种标准，用于在以太坊 P2P 协议中标识节点的链状态。
// forkID 的格式为 [Hash, Next]，其中：
//  - Hash 是历史分叉的校验和，用于区分不同的链（如以太坊主网和以太经典）。
//  - Next 是下一个分叉的触发点，用于提前通知节点即将到来的协议变更。
// 目的是防止节点连接到不兼容的链，提高网络同步效率。

// ID is a fork identifier as defined by EIP-2124.
// ID 是由 EIP-2124 定义的分叉标识符。
type ID struct {
	Hash [4]byte // CRC32 checksum of the genesis block and passed fork block numbers  创世块和已通过的分叉区块号的 CRC32 校验和
	Next uint64  // Block number of the next upcoming fork, or 0 if no forks are known 下一个即将发生的分叉的区块号，如果没有已知的分叉则为 0
}

// 在以太坊的 P2P 网络中，节点会通过协议（如 eth 协议）广播自己的分叉标识（forkID），以告知其他节点其当前的链状态。

// Filter is a fork id filter to validate a remotely advertised ID.
// Filter 是一个分叉 ID 过滤器，用于验证远程广播的分叉 ID。
type Filter func(id ID) error

// NewID calculates the Ethereum fork ID from the chain config, genesis hash, head and time.
// NewID 根据链配置、创世块哈希、当前头部区块高度和时间计算以太坊分叉 ID。
func NewID(config *params.ChainConfig, genesis *types.Block, head, time uint64) ID {
	// Calculate the starting checksum from the genesis hash
	// 从创世块哈希计算初始校验和
	hash := crc32.ChecksumIEEE(genesis.Hash().Bytes())

	// Calculate the current fork checksum and the next fork block
	// 计算当前分叉校验和和下一个分叉区块
	forksByBlock, forksByTime := gatherForks(config, genesis.Time())
	// 处理基于区块的分叉
	for _, fork := range forksByBlock {
		if fork <= head { // 分叉已发生，调用 checksumUpdate(hash, fork) 更新校验和，将当前 hash 和分叉区块号纳入计算。
			// Fork already passed, checksum the previous hash and the fork number
			// 分叉已通过，校验前一个哈希和分叉号
			hash = checksumUpdate(hash, fork)
			continue
		}
		// 分叉尚未发生，返回当前 hash（转为 4 字节数组）和 fork 作为 Next。
		return ID{Hash: checksumToBytes(hash), Next: fork}
	}
	// 处理基于时间的分叉
	for _, fork := range forksByTime {
		if fork <= time { // 分叉已发生，调用 checksumUpdate(hash, fork) 更新校验和。
			// Fork already passed, checksum the previous hash and fork timestamp
			// 分叉已通过，校验前一个哈希和分叉时间戳
			hash = checksumUpdate(hash, fork)
			continue
		}
		// 分叉尚未发生，返回当前 hash 和 fork 作为 Next。
		return ID{Hash: checksumToBytes(hash), Next: fork}
	}
	// 如果所有分叉都已处理完（即没有未到达的分叉），返回 ID{Hash: checksumToBytes(hash), Next: 0}。Next: 0 表示没有已知的未来分叉。
	return ID{Hash: checksumToBytes(hash), Next: 0}
}

// NewIDWithChain calculates the Ethereum fork ID from an existing chain instance.
// NewIDWithChain 从现有的链实例中计算以太坊分叉 ID。
func NewIDWithChain(chain Blockchain) ID {
	head := chain.CurrentHeader()

	return NewID(
		chain.Config(),
		chain.Genesis(),
		head.Number.Uint64(),
		head.Time,
	)
}

// NewFilter creates a filter that returns if a fork ID should be rejected or not
// based on the local chain's status.
// NewFilter 创建一个过滤器，根据本地链的状态返回是否应拒绝某个分叉 ID。
//
// 使用动态头部信息（CurrentHeader），反映链的实时状态（如当前高度 18,000,000 或时间戳）。
func NewFilter(chain Blockchain) Filter {
	return newFilter(
		chain.Config(),
		chain.Genesis(),
		func() (uint64, uint64) {
			head := chain.CurrentHeader()
			return head.Number.Uint64(), head.Time
		},
	)
}

// NewStaticFilter creates a filter at block zero.
// NewStaticFilter 在区块零处创建一个过滤器。
func NewStaticFilter(config *params.ChainConfig, genesis *types.Block) Filter {
	head := func() (uint64, uint64) { return 0, 0 }
	return newFilter(config, genesis, head)
}

// newFilter is the internal version of NewFilter, taking closures as its arguments
// instead of a chain. The reason is to allow testing it without having to simulate
// an entire blockchain.
//
// newFilter 是 NewFilter 的内部版本，使用闭包作为参数而不是链实例。原因是允许在不模拟整个区块链的情况下测试它。
func newFilter(config *params.ChainConfig, genesis *types.Block, headfn func() (uint64, uint64)) Filter {
	// Calculate the all the valid fork hash and fork next combos
	// 计算所有有效的分叉哈希和下一个分叉组合
	var (
		forksByBlock, forksByTime = gatherForks(config, genesis.Time())
		forks                     = append(append([]uint64{}, forksByBlock...), forksByTime...)
		sums                      = make([][4]byte, len(forks)+1) // 0th is the genesis 第0个是创世块  创建校验和数组，第 0 项为创世块校验和。
	)
	// 计算初始校验和并逐步更新：从创世块哈希开始
	hash := crc32.ChecksumIEEE(genesis.Hash().Bytes())
	sums[0] = checksumToBytes(hash)
	// 遍历 forks，每次用 checksumUpdate 更新 hash，存储到 sums 中。
	for i, fork := range forks {
		hash = checksumUpdate(hash, fork)
		sums[i+1] = checksumToBytes(hash)
	}
	// Add two sentries to simplify the fork checks and don't require special
	// casing the last one.
	// 添加两个哨兵以简化分叉检查，不需要对最后一个进行特殊处理。
	// 添加最大值哨兵，确保循环始终有终止条件。
	forks = append(forks, math.MaxUint64) // Last fork will never be passed 最后一个分叉永远不会被通过
	if len(forksByTime) == 0 {            // 如果没有时间分叉，forksByBlock 也添加哨兵，避免溢出到时间戳范围。
		// In purely block based forks, avoid the sentry spilling into timestapt territory
		// 在纯基于区块的分叉中，避免哨兵溢出到时间戳领域
		forksByBlock = append(forksByBlock, math.MaxUint64) // Last fork will never be passed 最后一个分叉永远不会被通过
	}
	// Create a validator that will filter out incompatible chains
	// 创建一个验证器，用于过滤不兼容的链
	return func(id ID) error {
		// Run the fork checksum validation ruleset:
		//   1. If local and remote FORK_CSUM matches, compare local head to FORK_NEXT.
		//        The two nodes are in the same fork state currently. They might know
		//        of differing future forks, but that's not relevant until the fork
		//        triggers (might be postponed, nodes might be updated to match).
		//      1a. A remotely announced but remotely not passed block is already passed
		//          locally, disconnect, since the chains are incompatible.
		//      1b. No remotely announced fork; or not yet passed locally, connect.
		//   2. If the remote FORK_CSUM is a subset of the local past forks and the
		//      remote FORK_NEXT matches with the locally following fork block number,
		//      connect.
		//        Remote node is currently syncing. It might eventually diverge from
		//        us, but at this current point in time we don't have enough information.
		//   3. If the remote FORK_CSUM is a superset of the local past forks and can
		//      be completed with locally known future forks, connect.
		//        Local node is currently syncing. It might eventually diverge from
		//        the remote, but at this current point in time we don't have enough
		//        information.
		//   4. Reject in all other cases.
		//
		// 运行分叉校验和验证规则集：
		//   1. 如果本地和远程的 FORK_CSUM 匹配，比较本地头部与 FORK_NEXT。
		//        两个节点当前处于相同的分叉状态。它们可能知道不同的未来分叉，
		//        但在分叉触发之前这无关紧要（可能推迟，节点可能更新以匹配）。
		//      1a. 远程宣布但未通过的区块已在本地通过，断开连接，因为链不兼容。
		//      1b. 没有远程宣布的分叉；或本地尚未通过，连接。
		//   2. 如果远程 FORK_CSUM 是本地过去分叉的子集，并且远程 FORK_NEXT
		//      与本地接下来的分叉区块号匹配，连接。
		//        远程节点当前正在同步。它最终可能与我们分歧，但当前我们没有足够信息。
		//   3. 如果远程 FORK_CSUM 是本地过去分叉的超集，并且可以用本地已知的未来分叉补全，连接。
		//        本地节点当前正在同步。它最终可能与远程分歧，但当前我们没有足够信息。
		//   4. 在所有其他情况下拒绝。
		block, time := headfn()
		for i, fork := range forks {
			// Pick the head comparison based on fork progression
			// 根据分叉进度选择头部比较
			head := block
			if i >= len(forksByBlock) {
				head = time
			}
			// If our head is beyond this fork, continue to the next (we have a dummy
			// fork of maxuint64 as the last item to always fail this check eventually).
			// 如果我们的头部超出此分叉，继续到下一个（我们有一个最大值哨兵作为最后一项，始终会失败）。
			if head >= fork {
				continue
			}
			// Found the first unpassed fork block, check if our current state matches
			// the remote checksum (rule #1).
			// 找到第一个未通过的分叉块，检查当前状态是否与远程校验和匹配（规则 #1）。
			if sums[i] == id.Hash {
				// Fork checksum matched, check if a remote future fork block already passed
				// locally without the local node being aware of it (rule #1a).
				// 分叉校验和匹配，检查远程未来分叉块是否已在本地通过而本地节点不知道（规则 #1a）。
				if id.Next > 0 && (head >= id.Next || (id.Next > timestampThreshold && time >= id.Next)) {
					return ErrLocalIncompatibleOrStale
				}
				// Haven't passed locally a remote-only fork, accept the connection (rule #1b).
				// 本地未通过远程独有的分叉，接受连接（规则 #1b）。
				return nil
			}
			// The local and remote nodes are in different forks currently, check if the
			// remote checksum is a subset of our local forks (rule #2).
			// 本地和远程节点当前处于不同分叉，检查远程校验和是否是本地分叉的子集（规则 #2）。
			for j := 0; j < i; j++ {
				if sums[j] == id.Hash {
					// Remote checksum is a subset, validate based on the announced next fork
					// 远程校验和是子集，根据宣布的下一个分叉验证
					if forks[j] != id.Next {
						return ErrRemoteStale
					}
					return nil
				}
			}
			// Remote chain is not a subset of our local one, check if it's a superset by
			// any chance, signalling that we're simply out of sync (rule #3).
			// 远程链不是本地链的子集，检查它是否可能是超集，表明我们只是不同步（规则 #3）。
			for j := i + 1; j < len(sums); j++ {
				if sums[j] == id.Hash {
					// Yay, remote checksum is a superset, ignore upcoming forks
					// 远程校验和是超集，忽略即将到来的分叉
					return nil
				}
			}
			// No exact, subset or superset match. We are on differing chains, reject.
			// 没有精确匹配、子集或超集。我们处于不同链，拒绝。
			return ErrLocalIncompatibleOrStale
		}
		log.Error("Impossible fork ID validation", "id", id)
		return nil // Something's very wrong, accept rather than reject  出现严重错误，接受而不是拒绝
	}
}

// 以太坊协议中，字节序通常采用大端（big-endian），即高位字节在前。这在 binary.BigEndian 中体现，确保跨平台一致性。

// checksumUpdate calculates the next IEEE CRC32 checksum based on the previous
// one and a fork block number (equivalent to CRC32(original-blob || fork)).
//
// checksumUpdate 根据前一个校验和和分叉区块号计算下一个 IEEE CRC32 校验和（等价于 CRC32(原始数据 || 分叉号)）。
//
// 根据前一个 CRC32 校验和（hash）和新的分叉点（fork），计算更新后的校验和，用于分叉标识的 Hash 计算。
// 等价于对原始数据和 fork 拼接后的单次 CRC32 计算（CRC32(original-blob || fork)）
func checksumUpdate(hash uint32, fork uint64) uint32 {
	var blob [8]byte                                    // 创建一个 8 字节数组，用于存储 fork 的字节表示。
	binary.BigEndian.PutUint64(blob[:], fork)           // 将 fork（64 位）按大端字节序写入 blob，确保字节顺序一致。
	return crc32.Update(hash, crc32.IEEETable, blob[:]) // 使用 CRC32 算法更新校验和：
}

// checksumToBytes converts a uint32 checksum into a [4]byte array.
//
// checksumToBytes 将 uint32 校验和转换为 [4]byte 数组。
func checksumToBytes(hash uint32) [4]byte {
	var blob [4]byte
	binary.BigEndian.PutUint32(blob[:], hash) // 将 hash（32 位）按大端字节序写入 blob。
	return blob
}

// gatherForks gathers all the known forks and creates two sorted lists out of
// them, one for the block number based forks and the second for the timestamps.
//
// gatherForks 收集所有已知的分叉，并从中创建两个排序列表，一个用于基于区块号的分叉，另一个用于时间戳。
func gatherForks(config *params.ChainConfig, genesis uint64) ([]uint64, []uint64) {
	// Gather all the fork block numbers via reflection
	// 通过反射收集所有分叉区块号
	kind := reflect.TypeOf(params.ChainConfig{})
	conf := reflect.ValueOf(config).Elem()
	x := uint64(0)
	var (
		forksByBlock []uint64
		forksByTime  []uint64
	)
	for i := 0; i < kind.NumField(); i++ {
		// Fetch the next field and skip non-fork rules
		// 获取下一个字段并跳过非分叉规则
		field := kind.Field(i) // 获取第 i 个字段的元数据。

		time := strings.HasSuffix(field.Name, "Time")         // 查字段名是否以 "Time" 结尾（时间分叉）。
		if !time && !strings.HasSuffix(field.Name, "Block") { // 如果字段名不以 "Time" 或 "Block" 结尾，跳过（非分叉规则）。
			continue
		}

		// Extract the fork rule block number or timestamp and aggregate it
		// 提取分叉规则的区块号或时间戳并聚合
		if field.Type == reflect.TypeOf(&x) { // 如果是 *uint64 类型（时间戳分叉），如 MergeForkTime。
			if rule := conf.Field(i).Interface().(*uint64); rule != nil {
				forksByTime = append(forksByTime, *rule)
			}
		}
		if field.Type == reflect.TypeOf(new(big.Int)) { // 如果是 *big.Int 类型（区块分叉），如 LondonBlock。
			if rule := conf.Field(i).Interface().(*big.Int); rule != nil {
				forksByBlock = append(forksByBlock, rule.Uint64())
			}
		}
	}
	slices.Sort(forksByBlock)
	slices.Sort(forksByTime)

	// Deduplicate fork identifiers applying multiple forks
	// 去重分叉标识符，处理多个分叉的情况
	// 去重确保每个分叉点只出现一次，避免重复计算校验和。
	for i := 1; i < len(forksByBlock); i++ {
		if forksByBlock[i] == forksByBlock[i-1] {
			forksByBlock = append(forksByBlock[:i], forksByBlock[i+1:]...)
			i--
		}
	}
	for i := 1; i < len(forksByTime); i++ {
		if forksByTime[i] == forksByTime[i-1] {
			forksByTime = append(forksByTime[:i], forksByTime[i+1:]...)
			i--
		}
	}
	// Skip any forks in block 0, that's the genesis ruleset
	// 跳过区块 0 的任何分叉，那是创世规则集
	// 如果区块分叉包含 0（创世块），移除，因为创世规则不视为独立分叉。
	if len(forksByBlock) > 0 && forksByBlock[0] == 0 {
		forksByBlock = forksByBlock[1:]
	}
	// Skip any forks before genesis.
	// 跳过创世时间之前的任何分叉
	// 移除早于或等于创世时间的时间分叉，因为这些分叉无效（链尚未开始）。
	for len(forksByTime) > 0 && forksByTime[0] <= genesis {
		forksByTime = forksByTime[1:]
	}
	return forksByBlock, forksByTime
}
