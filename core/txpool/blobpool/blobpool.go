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

// Package blobpool implements the EIP-4844 blob transaction pool.
package blobpool

import (
	"container/heap"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/billy"
	"github.com/holiman/uint256"
)

const (
	// blobSize is the protocol constrained byte size of a single blob in a
	// transaction. There can be multiple of these embedded into a single tx.
	// blobSize 是一个交易中单个 blob 的协议约束字节大小。单个交易中可以嵌入多个 blob。
	blobSize = params.BlobTxFieldElementsPerBlob * params.BlobTxBytesPerFieldElement

	// maxBlobsPerTransaction is the maximum number of blobs a single transaction
	// is allowed to contain. Whilst the spec states it's unlimited, the block
	// data slots are protocol bound, which implicitly also limit this.
	// maxBlobsPerTransaction 是单个交易允许包含的最大 blob 数量。尽管规范中说它是无限制的，但区块数据槽位受协议限制，这也隐式地限制了这个值。
	maxBlobsPerTransaction = params.MaxBlobGasPerBlock / params.BlobTxBlobGasPerBlob

	// txAvgSize is an approximate byte size of a transaction metadata to avoid
	// tiny overflows causing all txs to move a shelf higher, wasting disk space.
	// txAvgSize 是交易元数据的近似字节大小，用于避免微小溢出导致所有交易移动到更高的槽位，浪费磁盘空间。
	txAvgSize = 4 * 1024

	// txMaxSize is the maximum size a single transaction can have, outside
	// the included blobs. Since blob transactions are pulled instead of pushed,
	// and only a small metadata is kept in ram, the rest is on disk, there is
	// no critical limit that should be enforced. Still, capping it to some sane
	// limit can never hurt.
	// txMaxSize 是单个交易可以拥有的最大大小，不包括包含的 blob。由于 blob 交易是被拉取的，而不是推送的，并且只有少量元数据保存在内存中，其余部分在磁盘上，因此没有需要强制执行的严格限制。尽管如此，将其限制在某个合理的范围内总是有益的。
	txMaxSize = 1024 * 1024

	// maxTxsPerAccount is the maximum number of blob transactions admitted from
	// a single account. The limit is enforced to minimize the DoS potential of
	// a private tx cancelling publicly propagated blobs.
	//
	// Note, transactions resurrected by a reorg are also subject to this limit,
	// so pushing it down too aggressively might make resurrections non-functional.
	// maxTxsPerAccount 是从单个账户允许的 blob 交易的最大数量。执行此限制以最小化私下交易取消公开传播的 blob 的 DoS 潜力。
	//
	// 注意，通过 reorg 恢复的交易也受此限制，因此过于激进地降低此限制可能会使恢复功能失效。
	maxTxsPerAccount = 16

	// pendingTransactionStore is the subfolder containing the currently queued
	// blob transactions.
	// pendingTransactionStore 是包含当前排队的 blob 交易的子文件夹。
	pendingTransactionStore = "queue"

	// limboedTransactionStore is the subfolder containing the currently included
	// but not yet finalized transaction blobs.
	// limboedTransactionStore 是包含当前已包含但尚未最终确定的交易 blob 的子文件夹。
	limboedTransactionStore = "limbo"
)

// blobTxMeta is the minimal subset of types.BlobTx necessary to validate and
// schedule the blob transactions into the following blocks. Only ever add the
// bare minimum needed fields to keep the size down (and thus number of entries
// larger with the same memory consumption).
// blobTxMeta 是 types.BlobTx 的最小子集，用于验证和调度 blob 交易到后续区块。只添加保持大小最小所需的字段（从而在相同内存消耗下允许更多条目）。
type blobTxMeta struct {
	hash common.Hash // Transaction hash to maintain the lookup table
	// 交易哈希，用于维护查找表
	vhashes []common.Hash // Blob versioned hashes to maintain the lookup table
	// blob 版本化哈希，用于维护查找表

	id uint64 // Storage ID in the pool's persistent store
	// 池的持久存储中的存储 ID
	size uint32 // Byte size in the pool's persistent store
	// 池的持久存储中的字节大小

	nonce uint64 // Needed to prioritize inclusion order within an account
	// nonce，用于在账户内优先考虑包含顺序
	costCap *uint256.Int // Needed to validate cumulative balance sufficiency
	// costCap，用于验证累积余额是否充足
	execTipCap *uint256.Int // Needed to prioritize inclusion order across accounts and validate replacement price bump
	// execTipCap，用于跨账户优先考虑包含顺序并验证替换价格提升
	execFeeCap *uint256.Int // Needed to validate replacement price bump
	// execFeeCap，用于验证替换价格提升
	blobFeeCap *uint256.Int // Needed to validate replacement price bump
	// blobFeeCap，用于验证替换价格提升
	execGas uint64 // Needed to check inclusion validity before reading the blob
	// execGas，用于在读取 blob 之前检查包含有效性
	blobGas uint64 // Needed to check inclusion validity before reading the blob
	// blobGas，用于在读取 blob 之前检查包含有效性

	basefeeJumps float64 // Absolute number of 1559 fee adjustments needed to reach the tx's fee cap
	// basefeeJumps，达到交易费用上限所需的 1559 费用调整的绝对次数
	blobfeeJumps float64 // Absolute number of 4844 fee adjustments needed to reach the tx's blob fee cap
	// blobfeeJumps，达到交易 blob 费用上限所需的 4844 费用调整的绝对次数

	evictionExecTip *uint256.Int // Worst gas tip across all previous nonces
	// evictionExecTip，所有先前 nonce 中最差的 gas tip
	evictionExecFeeJumps float64 // Worst base fee (converted to fee jumps) across all previous nonces
	// evictionExecFeeJumps，所有先前 nonce 中最差的 base fee（转换为费用跳跃）
	evictionBlobFeeJumps float64 // Worse blob fee (converted to fee jumps) across all previous nonces
	// evictionBlobFeeJumps，所有先前 nonce 中最差的 blob fee（转换为费用跳跃）
}

// newBlobTxMeta retrieves the indexed metadata fields from a blob transaction
// and assembles a helper struct to track in memory.
// newBlobTxMeta 从 blob 交易中检索索引的元数据字段，并组装一个助手结构体以在内存中跟踪。
func newBlobTxMeta(id uint64, size uint32, tx *types.Transaction) *blobTxMeta {
	// 创建 blobTxMeta 结构体实例，用于存储交易的元数据
	meta := &blobTxMeta{
		hash:       tx.Hash(),                               // 获取交易哈希
		vhashes:    tx.BlobHashes(),                         // 获取 blob 版本化哈希列表
		id:         id,                                      // 设置存储 ID
		size:       size,                                    // 设置存储字节大小
		nonce:      tx.Nonce(),                              // 获取交易 nonce
		costCap:    uint256.MustFromBig(tx.Cost()),          // 将交易成本转换为 uint256 类型
		execTipCap: uint256.MustFromBig(tx.GasTipCap()),     // 将 gas tip 上限转换为 uint256 类型
		execFeeCap: uint256.MustFromBig(tx.GasFeeCap()),     // 将 gas 费用上限转换为 uint256 类型
		blobFeeCap: uint256.MustFromBig(tx.BlobGasFeeCap()), // 将 blob gas 费用上限转换为 uint256 类型
		execGas:    tx.Gas(),                                // 获取执行 gas
		blobGas:    tx.BlobGas(),                            // 获取 blob gas
	}
	// 计算达到交易费用上限所需的 1559 费用调整次数
	meta.basefeeJumps = dynamicFeeJumps(meta.execFeeCap)
	// 计算达到交易 blob 费用上限所需的 4844 费用调整次数
	meta.blobfeeJumps = dynamicFeeJumps(meta.blobFeeCap)

	return meta // 返回构造好的元数据结构体
}

// BlobPool is the transaction pool dedicated to EIP-4844 blob transactions.
// BlobPool 是专用于 EIP-4844 blob 交易的交易池。
//
// Blob transactions are special snowflakes that are designed for a very specific
// purpose (rollups) and are expected to adhere to that specific use case. These
// behavioural expectations allow us to design a transaction pool that is more robust
// (i.e. resending issues) and more resilient to DoS attacks (e.g. replace-flush
// attacks) than the generic tx pool. These improvements will also mean, however,
// that we enforce a significantly more aggressive strategy on entering and exiting
// the pool:
// blob 交易是专为非常特定的目的（rollups）设计的特殊交易，预计会遵守该特定用例。这些行为预期使我们能够设计一个比通用交易池更健壮（即重发问题）和更能抵御 DoS 攻击（例如替换刷新攻击）的交易池。然而，这些改进也意味着我们在进入和退出池时执行更激进的策略：
//
//   - Blob transactions are large. With the initial design aiming for 128KB blobs,
//     we must ensure that these only traverse the network the absolute minimum
//     number of times. Broadcasting to sqrt(peers) is out of the question, rather
//     these should only ever be announced and the remote side should request it if
//     it wants to.
//
//   - blob 交易很大。初始设计目标是 128KB 的 blob，我们必须确保这些交易只在网络中传输绝对最少的次数。广播到 sqrt(peers) 是不可能的，相反，这些交易应该只被宣布，远程方如果想要应该请求。
//
//   - Block blob-space is limited. With blocks being capped to a few blob txs, we
//     can make use of the very low expected churn rate within the pool. Notably,
//     we should be able to use a persistent disk backend for the pool, solving
//     the tx resend issue that plagues the generic tx pool, as long as there's no
//     artificial churn (i.e. pool wars).
//
//   - 区块 blob 空间有限。由于区块被限制为几个 blob 交易，我们可以利用池内非常低的预期 churn 率。值得注意的是，我们应该能够为池使用持久磁盘后端，解决困扰通用交易池的交易重发问题，只要没有人为的 churn（即池战争）。
//
//   - Purpose of blobs are layer-2s. Layer-2s are meant to use blob transactions to
//     commit to their own current state, which is independent of Ethereum mainnet
//     (state, txs). This means that there's no reason for blob tx cancellation or
//     replacement, apart from a potential basefee / miner tip adjustment.
//
//   - blob 的目的是 layer-2s。layer-2s 旨在使用 blob 交易来提交它们自己的当前状态，这独立于以太坊主网（状态、交易）。这意味着除了潜在的 basefee / miner tip 调整外，没有理由取消或替换 blob 交易。
//
//   - Replacements are expensive. Given their size, propagating a replacement
//     blob transaction to an existing one should be aggressively discouraged.
//     Whilst generic transactions can start at 1 Wei gas cost and require a 10%
//     fee bump to replace, we suggest requiring a higher min cost (e.g. 1 gwei)
//     and a more aggressive bump (100%).
//
//   - 替换是昂贵的。鉴于它们的大小，应该极力阻止传播替换 blob 交易到现有的 blob 交易。虽然通用交易可以以 1 Wei 的 gas 成本开始，并需要 10% 的费用提升来进行替换，我们建议要求更高的最小成本（例如 1 gwei）和更激进的提升（100%）。
//
//   - Cancellation is prohibitive. Evicting an already propagated blob tx is a huge
//     DoS vector. As such, a) replacement (higher-fee) blob txs mustn't invalidate
//     already propagated (future) blob txs (cumulative fee); b) nonce-gapped blob
//     txs are disallowed; c) the presence of blob transactions exclude non-blob
//     transactions.
//
//   - 取消是禁止的。驱逐已传播的 blob 交易是一个巨大的 DoS 向量。因此，a) 替换（更高费用）的 blob 交易不得使已传播的（未来）blob 交易（累积费用）无效；b) 不允许 nonce 间隙的 blob 交易；c) blob 交易的存在排除了非 blob 交易。
//
//   - Malicious cancellations are possible. Although the pool might prevent txs
//     that cancel blobs, blocks might contain such transaction (malicious miner
//     or flashbotter). The pool should cap the total number of blob transactions
//     per account as to prevent propagating too much data before cancelling it
//     via a normal transaction. It should nonetheless be high enough to support
//     resurrecting reorged transactions. Perhaps 4-16.
//
//   - 恶意取消是可能的。虽然池可能会阻止取消 blob 的交易，但区块可能包含此类交易（恶意矿工或 flashbotter）。池应该限制每个账户的 blob 交易总数，以防止在通过正常交易取消之前传播过多数据。然而，它应该足够高以支持恢复 reorged 交易。可能是 4-16。
//
//   - Local txs are meaningless. Mining pools historically used local transactions
//     for payouts or for backdoor deals. With 1559 in place, the basefee usually
//     dominates the final price, so 0 or non-0 tip doesn't change much. Blob txs
//     retain the 1559 2D gas pricing (and introduce on top a dynamic blob gas fee),
//     so locality is moot. With a disk backed blob pool avoiding the resend issue,
//     there's also no need to save own transactions for later.
//
//   - 本地交易是无意义的。历史上，矿池使用本地交易进行支付或后门交易。随着 1559 的实施，basefee 通常主导最终价格，因此 0 或非 0 tip 变化不大。blob 交易保留了 1559 的 2D gas 定价（并在顶部引入了动态 blob gas 费用），因此本地性是无意义的。有了磁盘支持的 blob 池避免了重发问题，也没有必要保存自己的交易以备后用。
//
//   - No-blob blob-txs are bad. Theoretically there's no strong reason to disallow
//     blob txs containing 0 blobs. In practice, admitting such txs into the pool
//     breaks the low-churn invariant as blob constraints don't apply anymore. Even
//     though we could accept blocks containing such txs, a reorg would require moving
//     them back into the blob pool, which can break invariants.
//
//   - 无 blob 的 blob-tx 是不好的。理论上没有充分理由禁止包含 0 个 blob 的 blob 交易。实际上，允许这样的交易进入池会破坏低 churn 不变性，因为 blob 约束不再适用。即使我们可以接受包含此类交易的区块，reorg 将要求将它们移回 blob 池，这可能会破坏不变性。
//
//   - Dropping blobs needs delay. When normal transactions are included, they
//     are immediately evicted from the pool since they are contained in the
//     including block. Blobs however are not included in the execution chain,
//     so a mini reorg cannot re-pool "lost" blob transactions. To support reorgs,
//     blobs are retained on disk until they are finalised.
//
//   - 丢弃 blob 需要延迟。当正常交易被包含时，它们会立即从池中驱逐，因为它们包含在包含区块中。然而，blob 不包含在执行链中，因此 mini reorg 无法重新池化“丢失”的 blob 交易。为了支持 reorg，blob 被保留在磁盘上直到它们被最终确定。
//
//   - Blobs can arrive via flashbots. Blocks might contain blob transactions we
//     have never seen on the network. Since we cannot recover them from blocks
//     either, the engine_newPayload needs to give them to us, and we cache them
//     until finality to support reorgs without tx losses.
//
//   - blob 可以通过 flashbots 到达。区块可能包含我们在网络上从未见过的 blob 交易。由于我们也无法从区块中恢复它们，engine_newPayload 需要将它们提供给我们，我们将它们缓存直到最终确定以支持没有交易丢失的 reorg。
//
// Whilst some constraints above might sound overly aggressive, the general idea is
// that the blob pool should work robustly for its intended use case and whilst
// anyone is free to use blob transactions for arbitrary non-rollup use cases,
// they should not be allowed to run amok the network.
// 虽然上述一些约束可能听起来过于激进，但总体思路是 blob 池应该为其预期用例稳健工作，虽然任何人都可以自由地将 blob 交易用于任意非 rollup 用例，但不应允许它们在网络上肆意妄为。
//
// Implementation wise there are a few interesting design choices:
// 在实现方面，有一些有趣的设计选择：
//
//   - Adding a transaction to the pool blocks until persisted to disk. This is
//     viable because TPS is low (2-4 blobs per block initially, maybe 8-16 at
//     peak), so natural churn is a couple MB per block. Replacements doing O(n)
//     updates are forbidden and transaction propagation is pull based (i.e. no
//     pileup of pending data).
//
//   - 将交易添加到池中会阻塞，直到持久化到磁盘。这是可行的，因为 TPS 很低（最初每个区块 2-4 个 blob，峰值时可能 8-16 个），所以自然 churn 每个区块只有几 MB。禁止进行 O(n) 更新的替换，交易传播是基于拉取的（即没有待处理数据的堆积）。
//
//   - When transactions are chosen for inclusion, the primary criteria is the
//     signer tip (and having a basefee/data fee high enough of course). However,
//     same-tip transactions will be split by their basefee/datafee, preferring
//     those that are closer to the current network limits. The idea being that
//     very relaxed ones can be included even if the fees go up, when the closer
//     ones could already be invalid.
//
//   - 当交易被选择包含时，主要标准是签名者 tip（当然还有足够高的 basefee/data fee）。然而，相同 tip 的交易将根据它们的 basefee/datafee 进行分割，优先选择接近当前网络限制的交易。这样做的想法是，即使费用上涨，宽松的交易也能被包含，而接近的交易可能已经无效。
//
// When the pool eventually reaches saturation, some old transactions - that may
// never execute - will need to be evicted in favor of newer ones. The eviction
// strategy is quite complex:
// 当池最终达到饱和时，一些旧交易 - 可能永远不会执行 - 将需要被驱逐以支持更新的交易。驱逐策略相当复杂：
//
//   - Exceeding capacity evicts the highest-nonce of the account with the lowest
//     paying blob transaction anywhere in the pooled nonce-sequence, as that tx
//     would be executed the furthest in the future and is thus blocking anything
//     after it. The smallest is deliberately not evicted to avoid a nonce-gap.
//
//   - 超出容量时，驱逐池中 nonce 序列中支付最低的 blob 交易的账户的最高 nonce 交易，因为该交易将在最远的未来执行，因此会阻塞其后的任何交易。故意不驱逐最小的交易以避免 nonce 间隙。
//
//   - Analogously, if the pool is full, the consideration price of a new tx for
//     evicting an old one is the smallest price in the entire nonce-sequence of
//     the account. This avoids malicious users DoSing the pool with seemingly
//     high paying transactions hidden behind a low-paying blocked one.
//
//   - 类似地，如果池已满，新交易驱逐旧交易的考虑价格是账户整个 nonce 序列中的最小价格。这避免了恶意用户用看似高支付但隐藏在低支付阻塞交易后面的交易对池进行 DoS 攻击。
//
//   - Since blob transactions have 3 price parameters: execution tip, execution
//     fee cap and data fee cap, there's no singular parameter to create a total
//     price ordering on. What's more, since the base fee and blob fee can move
//     independently of one another, there's no pre-defined way to combine them
//     into a stable order either. This leads to a multi-dimensional problem to
//     solve after every block.
//
//   - 由于 blob 交易有 3 个价格参数：execution tip、execution fee cap 和 data fee cap，没有单个参数可以创建总价格排序。更重要的是，由于 base fee 和 blob fee 可以独立移动，也没有预定义的方式将它们组合成稳定的顺序。这导致在每个区块后需要解决一个多维问题。
//
//   - The first observation is that comparing 1559 base fees or 4844 blob fees
//     needs to happen in the context of their dynamism. Since these fees jump
//     up or down in ~1.125 multipliers (at max) across blocks, comparing fees
//     in two transactions should be based on log1.125(fee) to eliminate noise.
//
//   - 第一个观察是，比较 1559 base fees 或 4844 blob fees 需要在其动态性上下文中进行。由于这些费用在区块间以 ~1.125 倍数（最大）跳跃，比较两个交易中的费用应该基于 log1.125(fee) 以消除噪声。
//
//   - The second observation is that the basefee and blobfee move independently,
//     so there's no way to split mixed txs on their own (A has higher base fee,
//     B has higher blob fee). Rather than look at the absolute fees, the useful
//     metric is the max time it can take to exceed the transaction's fee caps.
//     Specifically, we're interested in the number of jumps needed to go from
//     the current fee to the transaction's cap:
//
//   - 第二个观察是，basefee 和 blobfee 独立移动，因此无法单独分割混合交易（A 有更高的 base fee，B 有更高的 blob fee）。与其查看绝对费用，不如关注可能超过交易费用上限的最大时间。具体来说，我们感兴趣的是从当前费用到交易上限所需的跳跃次数：
//
//     jumps = log1.125(txfee) - log1.125(basefee)
//     jumps = log1.125(txfee) - log1.125(basefee)
//
//   - The third observation is that the base fee tends to hover around rather
//     than swing wildly. The number of jumps needed from the current fee starts
//     to get less relevant the higher it is. To remove the noise here too, the
//     pool will use log(jumps) as the delta for comparing transactions.
//
//   - 第三个观察是，base fee 倾向于徘徊而不是剧烈波动。从当前费用开始所需的跳跃次数越高，其相关性就越低。为了也消除这里的噪声，池将使用 log(jumps) 作为比较交易的 delta。
//
//     delta = sign(jumps) * log(abs(jumps))
//     delta = sign(jumps) * log(abs(jumps))
//
//   - To establish a total order, we need to reduce the dimensionality of the
//     two base fees (log jumps) to a single value. The interesting aspect from
//     the pool's perspective is how fast will a tx get executable (fees going
//     down, crossing the smaller negative jump counter) or non-executable (fees
//     going up, crossing the smaller positive jump counter). As such, the pool
//     cares only about the min of the two delta values for eviction priority.
//
//   - 为了建立一个总顺序，我们需要将两个 base fees（log jumps）的维度降低为单个值。从池的角度来看，有趣的是交易多快会变得可执行（费用下降，跨越较小的负跳跃计数器）或不可执行（费用上升，跨越较小的正跳跃计数器）。因此，池只关心两个 delta 值中的最小值作为驱逐优先级。
//
//     priority = min(deltaBasefee, deltaBlobfee)
//     priority = min(deltaBasefee, deltaBlobfee)
//
//   - The above very aggressive dimensionality and noise reduction should result
//     in transaction being grouped into a small number of buckets, the further
//     the fees the larger the buckets. This is good because it allows us to use
//     the miner tip meaningfully as a splitter.
//
//   - 上述非常激进的维度和噪声降低应该会导致交易被分组到少量桶中，费用越远，桶越大。这是好的，因为它允许我们有意义地使用 miner tip 作为分割器。
//
//   - For the scenario where the pool does not contain non-executable blob txs
//     anymore, it does not make sense to grant a later eviction priority to txs
//     with high fee caps since it could enable pool wars. As such, any positive
//     priority will be grouped together.
//
//   - 对于池不再包含不可执行 blob 交易的情况，给予具有高费用上限的交易较晚的驱逐优先级是没有意义的，因为这可能启用池战争。因此，任何正优先级将被分组在一起。
//
//     priority = min(deltaBasefee, deltaBlobfee, 0)
//     priority = min(deltaBasefee, deltaBlobfee, 0)
//
// Optimisation tradeoffs:
// 优化权衡：
//
//   - Eviction relies on 3 fee minimums per account (exec tip, exec cap and blob
//     cap). Maintaining these values across all transactions from the account is
//     problematic as each transaction replacement or inclusion would require a
//     rescan of all other transactions to recalculate the minimum. Instead, the
//     pool maintains a rolling minimum across the nonce range. Updating all the
//     minimums will need to be done only starting at the swapped in/out nonce
//     and leading up to the first no-change.
//   - 驱逐依赖于每个账户的 3 个费用最小值（exec tip、exec cap 和 blob cap）。在账户的所有交易中维护这些值是有问题的，因为每次交易替换或包含都需要重新扫描所有其他交易以重新计算最小值。相反，池在 nonce 范围内维护一个滚动最小值。更新所有最小值只需要从交换进/出的 nonce 开始，直到第一个没有变化的 nonce。
type BlobPool struct {
	config Config // Pool configuration
	// 池配置
	reserve txpool.AddressReserver // Address reserver to ensure exclusivity across subpools
	// 地址保留器，以确保跨子池的独占性

	store billy.Database // Persistent data store for the tx metadata and blobs
	// 交易元数据和 blob 的持久数据存储
	stored uint64 // Useful data size of all transactions on disk
	// 磁盘上所有交易的有用数据大小
	limbo *limbo // Persistent data store for the non-finalized blobs
	// 未最终确定 blob 的持久数据存储

	signer types.Signer // Transaction signer to use for sender recovery
	// 交易签名者，用于恢复发送者
	chain BlockChain // Chain object to access the state through
	// 链对象，用于通过状态访问

	head *types.Header // Current head of the chain
	// 链的当前头部
	state *state.StateDB // Current state at the head of the chain
	// 链头部处的当前状态
	gasTip *uint256.Int // Currently accepted minimum gas tip
	// 当前接受的最小 gas tip

	lookup *lookup // Lookup table mapping blobs to txs and txs to billy entries
	// 查找表，将 blob 映射到交易，交易映射到 billy 条目
	index map[common.Address][]*blobTxMeta // Blob transactions grouped by accounts, sorted by nonce
	// 按账户分组的 blob 交易，按 nonce 排序
	spent map[common.Address]*uint256.Int // Expenditure tracking for individual accounts
	// 单个账户的支出跟踪
	evict *evictHeap // Heap of cheapest accounts for eviction when full
	// 满时用于驱逐的最便宜账户的堆

	discoverFeed event.Feed // Event feed to send out new tx events on pool discovery (reorg excluded)
	// 事件馈送，用于在池发现时发送新交易事件（不包括 reorg）
	insertFeed event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)
	// 事件馈送，用于在池包含时发送新交易事件（包括 reorg）

	// txValidationFn defaults to txpool.ValidateTransaction, but can be
	// overridden for testing purposes.
	// txValidationFn 默认为 txpool.ValidateTransaction，但可以为测试目的而覆盖。
	txValidationFn txpool.ValidationFunction

	lock sync.RWMutex // Mutex protecting the pool during reorg handling
	// 在 reorg 处理期间保护池的互斥锁
}

// New creates a new blob transaction pool to gather, sort and filter inbound
// blob transactions from the network.
// New 创建一个新的 blob 交易池，以收集、排序和过滤来自网络的入站 blob 交易。
func New(config Config, chain BlockChain) *BlobPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	// 清理输入以确保没有设置易受攻击的 gas 价格
	config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	// 使用其初始设置创建交易池
	pool := &BlobPool{
		config:         config,                                 // 设置池配置
		signer:         types.LatestSigner(chain.Config()),     // 使用链配置创建最新的签名者
		chain:          chain,                                  // 设置区块链对象
		lookup:         newLookup(),                            // 初始化查找表
		index:          make(map[common.Address][]*blobTxMeta), // 初始化按账户分组的交易索引
		spent:          make(map[common.Address]*uint256.Int),  // 初始化账户支出跟踪
		txValidationFn: txpool.ValidateTransaction,             // 设置默认交易验证函数
	}
	return pool // 返回新创建的 blob 交易池
}

// Filter returns whether the given transaction can be consumed by the blob pool.
// Filter 返回给定的交易是否可以被 blob 池消费。
func (p *BlobPool) Filter(tx *types.Transaction) bool {
	// 检查交易类型是否为 blob 交易类型
	return tx.Type() == types.BlobTxType
}

// Init sets the gas price needed to keep a transaction in the pool and the chain
// head to allow balance / nonce checks. The transaction journal will be loaded
// from disk and filtered based on the provided starting settings.
// Init 设置保持交易在池中所需的 gas 价格和链头部，以允许余额 / nonce 检查。交易日志将从磁盘加载并根据提供的起始设置进行过滤。
func (p *BlobPool) Init(gasTip uint64, head *types.Header, reserve txpool.AddressReserver) error {
	// 设置地址保留器
	p.reserve = reserve

	// 定义存储路径变量
	var (
		queuedir string // 队列交易存储路径
		limbodir string // 未最终确定交易存储路径
	)
	// 如果配置中指定了数据目录，创建相应的子目录
	if p.config.Datadir != "" {
		queuedir = filepath.Join(p.config.Datadir, pendingTransactionStore)
		if err := os.MkdirAll(queuedir, 0700); err != nil {
			return err // 创建目录失败则返回错误
		}
		limbodir = filepath.Join(p.config.Datadir, limboedTransactionStore)
		if err := os.MkdirAll(limbodir, 0700); err != nil {
			return err // 创建目录失败则返回错误
		}
	}
	// Initialize the state with head block, or fallback to empty one in
	// case the head state is not available (might occur when node is not
	// fully synced).
	// 使用头部区块初始化状态，或者在头部状态不可用时回退到空状态（可能在节点未完全同步时发生）。
	state, err := p.chain.StateAt(head.Root) // 获取链头部的状态
	if err != nil {
		state, err = p.chain.StateAt(types.EmptyRootHash) // 如果失败，回退到空根状态
	}
	if err != nil {
		return err // 获取状态失败则返回错误
	}
	p.head, p.state = head, state // 设置链头部和状态

	// Index all transactions on disk and delete anything unprocessable
	// 索引磁盘上的所有交易并删除任何无法处理的交易
	var fails []uint64 // 记录无法处理的交易 ID
	// 定义索引函数，遍历磁盘上的交易数据
	index := func(id uint64, size uint32, blob []byte) {
		if p.parseTransaction(id, size, blob) != nil {
			fails = append(fails, id) // 如果解析失败，记录 ID
		}
	}
	// 打开持久化存储
	store, err := billy.Open(billy.Options{Path: queuedir, Repair: true}, newSlotter(), index)
	if err != nil {
		return err // 打开存储失败则返回错误
	}
	p.store = store // 设置存储对象

	// 如果有无法处理的交易，删除它们
	if len(fails) > 0 {
		log.Warn("Dropping invalidated blob transactions", "ids", fails)
		dropInvalidMeter.Mark(int64(len(fails)))

		for _, id := range fails {
			if err := p.store.Delete(id); err != nil {
				p.Close() // 删除失败则关闭池并返回错误
				return err
			}
		}
	}
	// Sort the indexed transactions by nonce and delete anything gapped, create
	// the eviction heap of anyone still standing
	// 按 nonce 对索引的交易进行排序并删除任何有间隙的交易，创建仍然存在的任何人的驱逐堆
	for addr := range p.index {
		p.recheck(addr, nil) // 重新检查每个账户的交易
	}
	// 计算当前的基础费用和 blob 费用
	var (
		basefee = uint256.MustFromBig(eip1559.CalcBaseFee(p.chain.Config(), p.head))
		blobfee = uint256.NewInt(params.BlobTxMinBlobGasprice)
	)
	if p.head.ExcessBlobGas != nil {
		blobfee = uint256.MustFromBig(eip4844.CalcBlobFee(*p.head.ExcessBlobGas))
	}
	p.evict = newPriceHeap(basefee, blobfee, p.index) // 创建驱逐堆

	// Pool initialized, attach the blob limbo to it to track blobs included
	// recently but not yet finalized
	// 池已初始化，将 blob limbo 附加到它以跟踪最近包含但尚未最终确定的 blob
	p.limbo, err = newLimbo(limbodir) // 初始化 limbo 存储
	if err != nil {
		p.Close() // 初始化失败则关闭池并返回错误
		return err
	}
	// Set the configured gas tip, triggering a filtering of anything just loaded
	// 设置配置的 gas tip，触发对刚刚加载的任何内容的过滤
	basefeeGauge.Update(int64(basefee.Uint64()))
	blobfeeGauge.Update(int64(blobfee.Uint64()))

	p.SetGasTip(new(big.Int).SetUint64(gasTip)) // 设置 gas tip

	// Since the user might have modified their pool's capacity, evict anything
	// above the current allowance
	// 由于用户可能修改了他们的池容量，驱逐超出当前允许的任何内容
	for p.stored > p.config.Datacap {
		p.drop() // 如果存储超出容量，执行驱逐
	}
	// Update the metrics and return the constructed pool
	// 更新指标并返回构建的池
	datacapGauge.Update(int64(p.config.Datacap))
	p.updateStorageMetrics() // 更新存储指标
	return nil               // 初始化成功，返回 nil
}

// Close closes down the underlying persistent store.
// Close 关闭底层持久存储。
func (p *BlobPool) Close() error {
	var errs []error // 收集关闭过程中的错误
	// 如果 limbo 已初始化，尝试关闭
	if p.limbo != nil { // Close might be invoked due to error in constructor, before p.limbo is set
		if err := p.limbo.Close(); err != nil {
			errs = append(errs, err) // 关闭失败则记录错误
		}
	}
	// 关闭主存储
	if err := p.store.Close(); err != nil {
		errs = append(errs, err) // 关闭失败则记录错误
	}
	// 根据错误数量返回结果
	switch {
	case errs == nil:
		return nil // 无错误，返回 nil
	case len(errs) == 1:
		return errs[0] // 单个错误，返回该错误
	default:
		return fmt.Errorf("%v", errs) // 多个错误，返回错误列表
	}
}

// parseTransaction is a callback method on pool creation that gets called for
// each transaction on disk to create the in-memory metadata index.
// parseTransaction 是池创建时的回调方法，对磁盘上的每个交易调用以创建内存中的元数据索引。
func (p *BlobPool) parseTransaction(id uint64, size uint32, blob []byte) error {
	tx := new(types.Transaction) // 创建新的交易对象
	// 解码磁盘上的 blob 数据到交易对象
	if err := rlp.DecodeBytes(blob, tx); err != nil {
		// This path is impossible unless the disk data representation changes
		// across restarts. For that ever improbable case, recover gracefully
		// by ignoring this data entry.
		// 除非磁盘数据表示在重启间发生变化，否则此路径不可能。对于这种极不可能的情况，通过忽略此数据条目优雅地恢复。
		log.Error("Failed to decode blob pool entry", "id", id, "err", err)
		return err // 解码失败，返回错误
	}
	// 检查交易是否包含 blob sidecar
	if tx.BlobTxSidecar() == nil {
		log.Error("Missing sidecar in blob pool entry", "id", id, "hash", tx.Hash())
		return errors.New("missing blob sidecar") // 无 sidecar，返回错误
	}

	// 创建交易元数据
	meta := newBlobTxMeta(id, size, tx)
	// 检查是否已存在相同的交易哈希
	if p.lookup.exists(meta.hash) {
		// This path is only possible after a crash, where deleted items are not
		// removed via the normal shutdown-startup procedure and thus may get
		// partially resurrected.
		// 仅在崩溃后可能出现此路径，其中删除的项目未通过正常的关机-启动程序删除，因此可能会部分复活。
		log.Error("Rejecting duplicate blob pool entry", "id", id, "hash", tx.Hash())
		return errors.New("duplicate blob entry") // 重复交易，返回错误
	}
	// 获取交易发送者
	sender, err := types.Sender(p.signer, tx)
	if err != nil {
		// This path is impossible unless the signature validity changes across
		// restarts. For that ever improbable case, recover gracefully by ignoring
		// this data entry.
		// 除非签名有效性在重启间发生变化，否则此路径不可能。对于这种极不可能的情况，通过忽略此数据条目优雅地恢复。
		log.Error("Failed to recover blob tx sender", "id", id, "hash", tx.Hash(), "err", err)
		return err // 恢复发送者失败，返回错误
	}
	// 如果发送者不在索引中，初始化其数据结构
	if _, ok := p.index[sender]; !ok {
		if err := p.reserve(sender, true); err != nil {
			return err // 保留地址失败，返回错误
		}
		p.index[sender] = []*blobTxMeta{}  // 初始化交易列表
		p.spent[sender] = new(uint256.Int) // 初始化支出跟踪
	}
	// 将元数据添加到索引
	p.index[sender] = append(p.index[sender], meta)
	p.spent[sender] = new(uint256.Int).Add(p.spent[sender], meta.costCap) // 更新账户支出

	p.lookup.track(meta)          // 跟踪元数据
	p.stored += uint64(meta.size) // 更新存储大小
	return nil                    // 解析成功，返回 nil
}

// recheck verifies the pool's content for a specific account and drops anything
// that does not fit anymore (dangling or filled nonce, overdraft).
// recheck 验证特定账户的池内容并丢弃不再适合的任何内容（悬空或已填充的 nonce，透支）。
func (p *BlobPool) recheck(addr common.Address, inclusions map[common.Hash]uint64) {
	// Sort the transactions belonging to the account so reinjects can be simpler
	// 对属于账户的交易进行排序，以便 reinjects 更简单
	txs := p.index[addr]                 // 获取账户的交易列表
	if inclusions != nil && txs == nil { // during reorgs, we might find new accounts
		// 在 reorg 期间，如果账户没有交易，直接返回
		return
	}
	// 按 nonce 排序交易
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].nonce < txs[j].nonce
	})
	// If there is a gap between the chain state and the blob pool, drop
	// all the transactions as they are non-executable. Similarly, if the
	// entire tx range was included, drop all.
	// 如果链状态和 blob 池之间存在间隙，丢弃所有交易，因为它们是不可执行的。类似地，如果整个 tx 范围已被包含，丢弃所有。
	var (
		next   = p.state.GetNonce(addr)       // 获取账户的下一个 nonce
		gapped = txs[0].nonce > next          // 检查是否存在 nonce 间隙
		filled = txs[len(txs)-1].nonce < next // 检查是否所有交易已被包含
	)
	if gapped || filled {
		var (
			ids    []uint64 // 待删除的交易 ID 列表
			nonces []uint64 // 待删除的交易 nonce 列表
		)
		// 遍历交易，收集需要删除的信息
		for i := 0; i < len(txs); i++ {
			ids = append(ids, txs[i].id)
			nonces = append(nonces, txs[i].nonce)

			p.stored -= uint64(txs[i].size) // 减少存储大小
			p.lookup.untrack(txs[i])        // 取消跟踪

			// Included transactions blobs need to be moved to the limbo
			// 包含的交易 blob 需要移动到 limbo
			if filled && inclusions != nil {
				p.offload(addr, txs[i].nonce, txs[i].id, inclusions) // 移动到 limbo
			}
		}
		// 删除账户相关数据
		delete(p.index, addr)
		delete(p.spent, addr)
		if inclusions != nil { // only during reorgs will the heap be initialized
			heap.Remove(p.evict, p.evict.index[addr]) // 从驱逐堆中移除
		}
		p.reserve(addr, false) // 释放地址保留

		// 记录日志并更新指标
		if gapped {
			log.Warn("Dropping dangling blob transactions", "from", addr, "missing", next, "drop", nonces, "ids", ids)
			dropDanglingMeter.Mark(int64(len(ids)))
		} else {
			log.Trace("Dropping filled blob transactions", "from", addr, "filled", nonces, "ids", ids)
			dropFilledMeter.Mark(int64(len(ids)))
		}
		// 从存储中删除交易
		for _, id := range ids {
			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
		}
		return // 处理完毕，返回
	}
	// If there is overlap between the chain state and the blob pool, drop
	// anything below the current state
	// 如果链状态和 blob 池之间存在重叠，丢弃低于当前状态的任何内容
	if txs[0].nonce < next {
		var (
			ids    []uint64 // 待删除的交易 ID 列表
			nonces []uint64 // 待删除的交易 nonce 列表
		)
		// 删除低于当前 nonce 的交易
		for len(txs) > 0 && txs[0].nonce < next {
			ids = append(ids, txs[0].id)
			nonces = append(nonces, txs[0].nonce)

			p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], txs[0].costCap) // 更新支出
			p.stored -= uint64(txs[0].size)                                     // 减少存储大小
			p.lookup.untrack(txs[0])                                            // 取消跟踪

			// Included transactions blobs need to be moved to the limbo
			// 包含的交易 blob 需要移动到 limbo
			if inclusions != nil {
				p.offload(addr, txs[0].nonce, txs[0].id, inclusions) // 移动到 limbo
			}
			txs = txs[1:] // 移除已处理交易
		}
		log.Trace("Dropping overlapped blob transactions", "from", addr, "overlapped", nonces, "ids", ids, "left", len(txs))
		dropOverlappedMeter.Mark(int64(len(ids)))

		// 从存储中删除交易
		for _, id := range ids {
			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
		}
		p.index[addr] = txs // 更新交易索引
	}
	// Iterate over the transactions to initialize their eviction thresholds
	// and to detect any nonce gaps
	// 遍历交易以初始化它们的驱逐阈值并检测任何 nonce 间隙
	txs[0].evictionExecTip = txs[0].execTipCap        // 初始化第一个交易的驱逐 gas tip
	txs[0].evictionExecFeeJumps = txs[0].basefeeJumps // 初始化第一个交易的驱逐 basefee 跳跃
	txs[0].evictionBlobFeeJumps = txs[0].blobfeeJumps // 初始化第一个交易的驱逐 blobfee 跳跃

	// 遍历剩余交易
	for i := 1; i < len(txs); i++ {
		// If there's no nonce gap, initialize the eviction thresholds as the
		// minimum between the cumulative thresholds and the current tx fees
		// 如果没有 nonce 间隙，将驱逐阈值初始化为累积阈值和当前交易费用之间的最小值
		if txs[i].nonce == txs[i-1].nonce+1 {
			txs[i].evictionExecTip = txs[i-1].evictionExecTip // 继承前一交易的 gas tip
			if txs[i].evictionExecTip.Cmp(txs[i].execTipCap) > 0 {
				txs[i].evictionExecTip = txs[i].execTipCap // 更新为当前交易的最小值
			}
			txs[i].evictionExecFeeJumps = txs[i-1].evictionExecFeeJumps // 继承前一交易的 basefee 跳跃
			if txs[i].evictionExecFeeJumps > txs[i].basefeeJumps {
				txs[i].evictionExecFeeJumps = txs[i].basefeeJumps // 更新为当前交易的最小值
			}
			txs[i].evictionBlobFeeJumps = txs[i-1].evictionBlobFeeJumps // 继承前一交易的 blobfee 跳跃
			if txs[i].evictionBlobFeeJumps > txs[i].blobfeeJumps {
				txs[i].evictionBlobFeeJumps = txs[i].blobfeeJumps // 更新为当前交易的最小值
			}
			continue // 继续处理下一交易
		}
		// Sanity check that there's no double nonce. This case would generally
		// be a coding error, so better know about it.
		//
		// Also, Billy behind the blobpool does not journal deletes. A process
		// crash would result in previously deleted entities being resurrected.
		// That could potentially cause a duplicate nonce to appear.
		// 健全性检查，确保没有重复的 nonce。这种情况通常是编码错误，所以最好知道。
		//
		// 此外，blobpool 背后的 Billy 不记录删除。进程崩溃会导致之前删除的实体复活。这可能导致出现重复的 nonce。
		if txs[i].nonce == txs[i-1].nonce {
			id, _ := p.lookup.storeidOfTx(txs[i].hash) // 获取重复交易的存储 ID

			log.Error("Dropping repeat nonce blob transaction", "from", addr, "nonce", txs[i].nonce, "id", id)
			dropRepeatedMeter.Mark(1)

			p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], txs[i].costCap) // 更新支出
			p.stored -= uint64(txs[i].size)                                     // 减少存储大小
			p.lookup.untrack(txs[i])                                            // 取消跟踪

			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
			txs = append(txs[:i], txs[i+1:]...) // 从列表中移除重复交易
			p.index[addr] = txs                 // 更新索引

			i-- // 调整索引以重新检查当前位置
			continue
		}
		// Otherwise if there's a nonce gap evict all later transactions
		// 否则，如果有 nonce 间隙，驱逐所有后续交易
		var (
			ids    []uint64 // 待删除的交易 ID 列表
			nonces []uint64 // 待删除的交易 nonce 列表
		)
		for j := i; j < len(txs); j++ {
			ids = append(ids, txs[j].id)
			nonces = append(nonces, txs[j].nonce)

			p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], txs[j].costCap) // 更新支出
			p.stored -= uint64(txs[j].size)                                     // 减少存储大小
			p.lookup.untrack(txs[j])                                            // 取消跟踪
		}
		txs = txs[:i] // 截断交易列表

		log.Error("Dropping gapped blob transactions", "from", addr, "missing", txs[i-1].nonce+1, "drop", nonces, "ids", ids)
		dropGappedMeter.Mark(int64(len(ids)))

		// 从存储中删除交易
		for _, id := range ids {
			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
		}
		p.index[addr] = txs // 更新索引
		break               // 发现间隙后终止循环
	}
	// Ensure that there's no over-draft, this is expected to happen when some
	// transactions get included without publishing on the network
	// 确保没有透支，这在某些交易未在网络上发布时被包含时预计会发生
	var (
		balance = p.state.GetBalance(addr) // 获取账户余额
		spent   = p.spent[addr]            // 获取账户支出
	)
	if spent.Cmp(balance) > 0 {
		// Evict the highest nonce transactions until the pending set falls under
		// the account's available balance
		// 驱逐最高 nonce 的交易，直到待处理集低于账户的可用余额
		var (
			ids    []uint64 // 待删除的交易 ID 列表
			nonces []uint64 // 待删除的交易 nonce 列表
		)
		for p.spent[addr].Cmp(balance) > 0 {
			last := txs[len(txs)-1] // 获取最后一个交易
			txs[len(txs)-1] = nil   // 清空最后一个交易
			txs = txs[:len(txs)-1]  // 截断交易列表

			ids = append(ids, last.id)
			nonces = append(nonces, last.nonce)

			p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], last.costCap) // 更新支出
			p.stored -= uint64(last.size)                                     // 减少存储大小
			p.lookup.untrack(last)                                            // 取消跟踪
		}
		// 如果交易列表为空，删除账户相关数据
		if len(txs) == 0 {
			delete(p.index, addr)
			delete(p.spent, addr)
			if inclusions != nil { // only during reorgs will the heap be initialized
				heap.Remove(p.evict, p.evict.index[addr]) // 从驱逐堆中移除
			}
			p.reserve(addr, false) // 释放地址保留
		} else {
			p.index[addr] = txs // 更新索引
		}
		log.Warn("Dropping overdrafted blob transactions", "from", addr, "balance", balance, "spent", spent, "drop", nonces, "ids", ids)
		dropOverdraftedMeter.Mark(int64(len(ids)))

		// 从存储中删除交易
		for _, id := range ids {
			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
		}
	}
	// Sanity check that no account can have more queued transactions than the
	// DoS protection threshold.
	// 健全性检查，确保没有账户可以有超过 DoS 保护阈值的排队交易。
	if len(txs) > maxTxsPerAccount {
		// Evict the highest nonce transactions until the pending set falls under
		// the account's transaction cap
		// 驱逐最高 nonce 的交易，直到待处理集低于账户的交易上限
		var (
			ids    []uint64 // 待删除的交易 ID 列表
			nonces []uint64 // 待删除的交易 nonce 列表
		)
		for len(txs) > maxTxsPerAccount {
			last := txs[len(txs)-1] // 获取最后一个交易
			txs[len(txs)-1] = nil   // 清空最后一个交易
			txs = txs[:len(txs)-1]  // 截断交易列表

			ids = append(ids, last.id)
			nonces = append(nonces, last.nonce)

			p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], last.costCap) // 更新支出
			p.stored -= uint64(last.size)                                     // 减少存储大小
			p.lookup.untrack(last)                                            // 取消跟踪
		}
		p.index[addr] = txs // 更新索引

		log.Warn("Dropping overcapped blob transactions", "from", addr, "kept", len(txs), "drop", nonces, "ids", ids)
		dropOvercappedMeter.Mark(int64(len(ids)))

		// 从存储中删除交易
		for _, id := range ids {
			if err := p.store.Delete(id); err != nil {
				log.Error("Failed to delete blob transaction", "from", addr, "id", id, "err", err)
			}
		}
	}
	// Included cheap transactions might have left the remaining ones better from
	// an eviction point, fix any potential issues in the heap.
	// 包含的廉价交易可能使剩余交易在驱逐点上更好，修复堆中的任何潜在问题。
	if _, ok := p.index[addr]; ok && inclusions != nil {
		heap.Fix(p.evict, p.evict.index[addr]) // 修复驱逐堆
	}
}

// offload removes a tracked blob transaction from the pool and moves it into the
// limbo for tracking until finality.
// offload 从池中删除一个跟踪的 blob 交易并将其移动到 limbo 以跟踪直到最终确定。
//
// The method may log errors for various unexpected scenarios but will not return
// any of it since there's no clear error case. Some errors may be due to coding
// issues, others caused by signers mining MEV stuff or swapping transactions. In
// all cases, the pool needs to continue operating.
// 该方法可能会记录各种意外场景的错误，但不会返回任何错误，因为没有明确的错误情况。一些错误可能是由于编码问题引起的，其他可能是由于签名者挖掘 MEV 或交换交易引起的。在所有情况下，池都需要继续运行。
func (p *BlobPool) offload(addr common.Address, nonce uint64, id uint64, inclusions map[common.Hash]uint64) {
	// 从存储中获取交易数据
	data, err := p.store.Get(id)
	if err != nil {
		log.Error("Blobs missing for included transaction", "from", addr, "nonce", nonce, "id", id, "err", err)
		return // 数据缺失，记录错误并返回
	}
	var tx types.Transaction // 创建交易对象
	// 解码交易数据
	if err = rlp.DecodeBytes(data, &tx); err != nil {
		log.Error("Blobs corrupted for included transaction", "from", addr, "nonce", nonce, "id", id, "err", err)
		return // 数据损坏，记录错误并返回
	}
	// 检查交易是否在 inclusions 中
	block, ok := inclusions[tx.Hash()]
	if !ok {
		log.Warn("Blob transaction swapped out by signer", "from", addr, "nonce", nonce, "id", id)
		return // 交易被替换，记录警告并返回
	}
	// 将交易推入 limbo
	if err := p.limbo.push(&tx, block); err != nil {
		log.Warn("Failed to offload blob tx into limbo", "err", err)
		return // 推入失败，记录警告并返回
	}
}

// Reset implements txpool.SubPool, allowing the blob pool's internal state to be
// kept in sync with the main transaction pool's internal state.
// Reset 实现 txpool.SubPool，允许 blob 池的内部状态与主交易池的内部状态保持同步。
func (p *BlobPool) Reset(oldHead, newHead *types.Header) {
	// 记录等待锁的时间
	waitStart := time.Now()
	p.lock.Lock()
	resetwaitHist.Update(time.Since(waitStart).Nanoseconds())
	defer p.lock.Unlock()

	// 记录重置操作的总时间
	defer func(start time.Time) {
		resettimeHist.Update(time.Since(start).Nanoseconds())
	}(time.Now())

	// 获取新头部的状态
	statedb, err := p.chain.StateAt(newHead.Root)
	if err != nil {
		log.Error("Failed to reset blobpool state", "err", err)
		return // 获取状态失败，记录错误并返回
	}
	p.head = newHead  // 更新链头部
	p.state = statedb // 更新状态

	// Run the reorg between the old and new head and figure out which accounts
	// need to be rechecked and which transactions need to be readded
	// 在旧头部和新头部之间运行 reorg，并找出哪些账户需要重新检查，哪些交易需要重新添加
	if reinject, inclusions := p.reorg(oldHead, newHead); reinject != nil {
		var adds []*types.Transaction // 记录需要添加的交易
		for addr, txs := range reinject {
			// Blindly push all the lost transactions back into the pool
			// 盲目地将所有丢失的交易推回池中
			for _, tx := range txs {
				if err := p.reinject(addr, tx.Hash()); err == nil {
					adds = append(adds, tx.WithoutBlobTxSidecar()) // 添加成功则记录
				}
			}
			// Recheck the account's pooled transactions to drop included and
			// invalidated ones
			// 重新检查账户的池化交易以丢弃包含的和无效的交易
			p.recheck(addr, inclusions) // 重新检查账户交易
		}
		// 如果有新添加的交易，发送事件
		if len(adds) > 0 {
			p.insertFeed.Send(core.NewTxsEvent{Txs: adds})
		}
	}
	// Flush out any blobs from limbo that are older than the latest finality
	// 从 limbo 中刷新出比最新最终性更旧的 blob
	if p.chain.Config().IsCancun(p.head.Number, p.head.Time) {
		p.limbo.finalize(p.chain.CurrentFinalBlock()) // 最终化 limbo 中的交易
	}
	// Reset the price heap for the new set of basefee/blobfee pairs
	// 为新的 basefee/blobfee 对重置价格堆
	var (
		basefee = uint256.MustFromBig(eip1559.CalcBaseFee(p.chain.Config(), newHead))
		blobfee = uint256.MustFromBig(big.NewInt(params.BlobTxMinBlobGasprice))
	)
	if newHead.ExcessBlobGas != nil {
		blobfee = uint256.MustFromBig(eip4844.CalcBlobFee(*newHead.ExcessBlobGas))
	}
	p.evict.reinit(basefee, blobfee, false) // 重置驱逐堆

	// 更新费用指标
	basefeeGauge.Update(int64(basefee.Uint64()))
	blobfeeGauge.Update(int64(blobfee.Uint64()))
	p.updateStorageMetrics() // 更新存储指标
}

// reorg assembles all the transactors and missing transactions between an old
// and new head to figure out which account's tx set needs to be rechecked and
// which transactions need to be requeued.
// reorg 组装旧头部和新头部之间的所有交易者和缺失交易，以找出哪些账户的交易集需要重新检查，哪些交易需要重新排队。
//
// The transactionblock inclusion infos are also returned to allow tracking any
// just-included blocks by block number in the limbo.
// 还返回交易块包含信息，以允许在 limbo 中按块号跟踪任何刚刚包含的块。
func (p *BlobPool) reorg(oldHead, newHead *types.Header) (map[common.Address][]*types.Transaction, map[common.Hash]uint64) {
	// If the pool was not yet initialized, don't do anything
	// 如果池尚未初始化，不执行任何操作
	if oldHead == nil {
		return nil, nil // 未初始化，返回空值
	}
	// If the reorg is too deep, avoid doing it (will happen during snap sync)
	// 如果 reorg 太深，避免执行（在 snap sync 期间会发生）
	oldNum := oldHead.Number.Uint64()
	newNum := newHead.Number.Uint64()

	if depth := uint64(math.Abs(float64(oldNum) - float64(newNum))); depth > 64 {
		return nil, nil // reorg 深度超过 64，跳过处理
	}
	// Reorg seems shallow enough to pull in all transactions into memory
	// reorg 似乎足够浅，可以将所有交易拉入内存
	var (
		transactors = make(map[common.Address]struct{})             // 交易者集合
		discarded   = make(map[common.Address][]*types.Transaction) // 被丢弃的交易
		included    = make(map[common.Address][]*types.Transaction) // 已包含的交易
		inclusions  = make(map[common.Hash]uint64)                  // 交易包含信息

		rem = p.chain.GetBlock(oldHead.Hash(), oldHead.Number.Uint64()) // 旧头部块
		add = p.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64()) // 新头部块
	)
	if add == nil {
		// if the new head is nil, it means that something happened between
		// the firing of newhead-event and _now_: most likely a
		// reorg caused by sync-reversion or explicit sethead back to an
		// earlier block.
		// 如果新头部为 nil，意味着在 newhead-event 触发和现在之间发生了某些事情：很可能是由 sync-reversion 或显式 sethead 回退到早期块引起的 reorg。
		log.Warn("Blobpool reset with missing new head", "number", newHead.Number, "hash", newHead.Hash())
		return nil, nil // 新头部缺失，返回空值
	}
	if rem == nil {
		// This can happen if a setHead is performed, where we simply discard
		// the old head from the chain. If that is the case, we don't have the
		// lost transactions anymore, and there's nothing to add.
		// 如果执行 setHead，我们简单地从链中丢弃旧头部。在这种情况下，我们不再有丢失的交易，也没有东西可以添加。
		if newNum >= oldNum {
			// If we reorged to a same or higher number, then it's not a case
			// of setHead
			// 如果我们 reorg 到相同或更高的编号，那么这不是 setHead 的情况
			log.Warn("Blobpool reset with missing old head",
				"old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
			return nil, nil // 旧头部缺失且新高度不低于旧高度，返回空值
		}
		// If the reorg ended up on a lower number, it's indicative of setHead
		// being the cause
		// 如果 reorg 结束在较低的编号上，这表明 setHead 是原因
		log.Debug("Skipping blobpool reset caused by setHead",
			"old", oldHead.Hash(), "oldnum", oldNum, "new", newHead.Hash(), "newnum", newNum)
		return nil, nil // setHead 导致的 reorg，跳过处理
	}
	// Both old and new blocks exist, traverse through the progression chain
	// and accumulate the transactors and transactions
	// 旧块和新块都存在，遍历进度链并累积交易者和交易
	for rem.NumberU64() > add.NumberU64() {
		for _, tx := range rem.Transactions() {
			from, _ := types.Sender(p.signer, tx) // 获取交易发送者

			discarded[from] = append(discarded[from], tx) // 记录被丢弃的交易
			transactors[from] = struct{}{}                // 添加交易者
		}
		// 获取父块
		if rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
			log.Error("Unrooted old chain seen by blobpool", "block", oldHead.Number, "hash", oldHead.Hash())
			return nil, nil // 旧链断裂，返回空值
		}
	}
	for add.NumberU64() > rem.NumberU64() {
		for _, tx := range add.Transactions() {
			from, _ := types.Sender(p.signer, tx) // 获取交易发送者

			included[from] = append(included[from], tx) // 记录已包含的交易
			inclusions[tx.Hash()] = add.NumberU64()     // 记录包含块号
			transactors[from] = struct{}{}              // 添加交易者
		}
		// 获取父块
		if add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
			log.Error("Unrooted new chain seen by blobpool", "block", newHead.Number, "hash", newHead.Hash())
			return nil, nil // 新链断裂，返回空值
		}
	}
	for rem.Hash() != add.Hash() {
		for _, tx := range rem.Transactions() {
			from, _ := types.Sender(p.signer, tx) // 获取交易发送者

			discarded[from] = append(discarded[from], tx) // 记录被丢弃的交易
			transactors[from] = struct{}{}                // 添加交易者
		}
		// 获取父块
		if rem = p.chain.GetBlock(rem.ParentHash(), rem.NumberU64()-1); rem == nil {
			log.Error("Unrooted old chain seen by blobpool", "block", oldHead.Number, "hash", oldHead.Hash())
			return nil, nil // 旧链断裂，返回空值
		}
		for _, tx := range add.Transactions() {
			from, _ := types.Sender(p.signer, tx) // 获取交易发送者

			included[from] = append(included[from], tx) // 记录已包含的交易
			inclusions[tx.Hash()] = add.NumberU64()     // 记录包含块号
			transactors[from] = struct{}{}              // 添加交易者
		}
		// 获取父块
		if add = p.chain.GetBlock(add.ParentHash(), add.NumberU64()-1); add == nil {
			log.Error("Unrooted new chain seen by blobpool", "block", newHead.Number, "hash", newHead.Hash())
			return nil, nil // 新链断裂，返回空值
		}
	}
	// Generate the set of transactions per address to pull back into the pool,
	// also updating the rest along the way
	// 为每个地址生成要拉回池的交易集，同时更新其余部分
	reinject := make(map[common.Address][]*types.Transaction, len(transactors))
	for addr := range transactors {
		// Generate the set that was lost to reinject into the pool
		// 生成丢失的集以 reinject 到池中
		lost := make([]*types.Transaction, 0, len(discarded[addr]))
		for _, tx := range types.TxDifference(discarded[addr], included[addr]) {
			if p.Filter(tx) {
				lost = append(lost, tx) // 添加符合条件的丢失交易
			}
		}
		reinject[addr] = lost // 设置需要重新注入的交易

		// Update the set that was already reincluded to track the blocks in limbo
		// 更新已经 reincluded 的集以在 limbo 中跟踪块
		for _, tx := range types.TxDifference(included[addr], discarded[addr]) {
			if p.Filter(tx) {
				p.limbo.update(tx.Hash(), inclusions[tx.Hash()]) // 更新 limbo 中的块信息
			}
		}
	}
	return reinject, inclusions // 返回需要重新注入的交易和包含信息
}

// reinject blindly pushes a transaction previously included in the chain - and
// just reorged out - into the pool. The transaction is assumed valid (having
// been in the chain), thus the only validation needed is nonce sorting and over-
// draft checks after injection.
// reinject 盲目地将先前包含在链中 - 刚刚 reorg 出的交易推入池中。交易被假定为有效（曾经在链中），因此唯一需要的验证是 nonce 排序和注入后的透支检查。
//
// Note, the method will not initialize the eviction cache values as those will
// be done once for all transactions belonging to an account after all individual
// transactions are injected back into the pool.
// 注意，该方法不会初始化驱逐缓存值，因为这些值将在所有单个交易被注入回池后为属于账户的所有交易一次性完成。
func (p *BlobPool) reinject(addr common.Address, txhash common.Hash) error {
	// Retrieve the associated blob from the limbo. Without the blobs, we cannot
	// add the transaction back into the pool as it is not mineable.
	// 从 limbo 检索关联的 blob。没有 blob，我们无法将交易添加回池中，因为它不可挖掘。
	tx, err := p.limbo.pull(txhash) // 从 limbo 中拉取交易
	if err != nil {
		log.Error("Blobs unavailable, dropping reorged tx", "err", err)
		return err // 拉取失败，返回错误
	}
	// TODO: seems like an easy optimization here would be getting the serialized tx
	// from limbo instead of re-serializing it here.
	// TODO: 这里的简单优化是从 limbo 获取序列化的 tx，而不是在这里重新序列化。

	// Serialize the transaction back into the primary datastore.
	// 将交易序列化回主数据存储。
	blob, err := rlp.EncodeToBytes(tx) // 序列化交易
	if err != nil {
		log.Error("Failed to encode transaction for storage", "hash", tx.Hash(), "err", err)
		return err // 序列化失败，返回错误
	}
	id, err := p.store.Put(blob) // 存储序列化数据
	if err != nil {
		log.Error("Failed to write transaction into storage", "hash", tx.Hash(), "err", err)
		return err // 存储失败，返回错误
	}

	// Update the indices and metrics
	// 更新索引和指标
	meta := newBlobTxMeta(id, p.store.Size(id), tx) // 创建交易元数据
	// 如果账户不在索引中，初始化其数据结构
	if _, ok := p.index[addr]; !ok {
		if err := p.reserve(addr, true); err != nil {
			log.Warn("Failed to reserve account for blob pool", "tx", tx.Hash(), "from", addr, "err", err)
			return err // 保留地址失败，返回错误
		}
		p.index[addr] = []*blobTxMeta{meta} // 初始化交易列表
		p.spent[addr] = meta.costCap        // 设置支出
		p.evict.Push(addr)                  // 添加到驱逐堆
	} else {
		p.index[addr] = append(p.index[addr], meta)                       // 添加到现有交易列表
		p.spent[addr] = new(uint256.Int).Add(p.spent[addr], meta.costCap) // 更新支出
	}
	p.lookup.track(meta)          // 跟踪元数据
	p.stored += uint64(meta.size) // 更新存储大小
	return nil                    // 注入成功，返回 nil
}

// SetGasTip implements txpool.SubPool, allowing the blob pool's gas requirements
// to be kept in sync with the main transaction pool's gas requirements.
// SetGasTip 实现 txpool.SubPool，允许 blob 池的 gas 要求与主交易池的 gas 要求保持同步。
func (p *BlobPool) SetGasTip(tip *big.Int) {
	p.lock.Lock() // 加锁保护池状态
	defer p.lock.Unlock()

	// Store the new minimum gas tip
	// 存储新的最小 gas tip
	old := p.gasTip                     // 保存旧的 gas tip
	p.gasTip = uint256.MustFromBig(tip) // 设置新的 gas tip

	// If the min miner fee increased, remove transactions below the new threshold
	// 如果 min miner fee 增加，移除低于新阈值的交易
	if old == nil || p.gasTip.Cmp(old) > 0 {
		for addr, txs := range p.index {
			for i, tx := range txs {
				if tx.execTipCap.Cmp(p.gasTip) < 0 {
					// Drop the offending transaction
					// 丢弃违规交易
					var (
						ids    = []uint64{tx.id}    // 待删除的交易 ID
						nonces = []uint64{tx.nonce} // 待删除的交易 nonce
					)
					p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], txs[i].costCap) // 更新支出
					p.stored -= uint64(tx.size)                                         // 减少存储大小
					p.lookup.untrack(tx)                                                // 取消跟踪
					txs[i] = nil                                                        // 清空交易

					// Drop everything afterwards, no gaps allowed
					// 丢弃其后的所有内容，不允许间隙
					for j, tx := range txs[i+1:] {
						ids = append(ids, tx.id)
						nonces = append(nonces, tx.nonce)

						p.spent[addr] = new(uint256.Int).Sub(p.spent[addr], tx.costCap) // 更新支出
						p.stored -= uint64(tx.size)                                     // 减少存储大小
						p.lookup.untrack(tx)                                            // 取消跟踪
						txs[i+1+j] = nil                                                // 清空交易
					}
					// Clear out the dropped transactions from the index
					// 从索引中清除丢弃的交易
					if i > 0 {
						p.index[addr] = txs[:i]                // 更新索引
						heap.Fix(p.evict, p.evict.index[addr]) // 修复驱逐堆
					} else {
						delete(p.index, addr) // 删除账户索引
						delete(p.spent, addr) // 删除账户支出

						heap.Remove(p.evict, p.evict.index[addr]) // 从驱逐堆中移除
						p.reserve(addr, false)                    // 释放地址保留
					}
					// Clear out the transactions from the data store
					// 从数据存储中清除交易
					log.Warn("Dropping underpriced blob transaction", "from", addr, "rejected", tx.nonce, "tip", tx.execTipCap, "want", tip, "drop", nonces, "ids", ids)
					dropUnderpricedMeter.Mark(int64(len(ids)))

					for _, id := range ids {
						if err := p.store.Delete(id); err != nil {
							log.Error("Failed to delete dropped transaction", "id", id, "err", err)
						}
					}
					break // 处理完当前账户，跳出循环
				}
			}
		}
	}
	log.Debug("Blobpool tip threshold updated", "tip", tip)
	pooltipGauge.Update(tip.Int64())
	p.updateStorageMetrics() // 更新存储指标
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
// validateTx 根据共识规则检查交易是否有效，并遵守本地节点的一些启发式限制（价格和大小）。
func (p *BlobPool) validateTx(tx *types.Transaction) error {
	// Ensure the transaction adheres to basic pool filters (type, size, tip) and
	// consensus rules
	// 确保交易遵守基本的池过滤器（类型、大小、tip）和共识规则
	baseOpts := &txpool.ValidationOptions{
		Config:  p.chain.Config(),      // 区块链配置
		Accept:  1 << types.BlobTxType, // 只接受 blob 交易类型
		MaxSize: txMaxSize,             // 最大交易大小
		MinTip:  p.gasTip.ToBig(),      // 最小 gas tip
	}

	// 验证交易的基本规则
	if err := p.txValidationFn(tx, p.head, p.signer, baseOpts); err != nil {
		return err // 验证失败，返回错误
	}
	// Ensure the transaction adheres to the stateful pool filters (nonce, balance)
	// 确保交易遵守有状态的池过滤器（nonce，余额）
	stateOpts := &txpool.ValidationOptionsWithState{
		State: p.state, // 当前状态

		// 定义第一个 nonce 间隙
		FirstNonceGap: func(addr common.Address) uint64 {
			// Nonce gaps are not permitted in the blob pool, the first gap will
			// be the next nonce shifted by however many transactions we already
			// have pooled.
			// blob 池中不允许 nonce 间隙，第一个间隙将是下一个 nonce 加上我们已经池化的交易数量。
			return p.state.GetNonce(addr) + uint64(len(p.index[addr]))
		},
		// 返回已使用和剩余的交易槽位
		UsedAndLeftSlots: func(addr common.Address) (int, int) {
			have := len(p.index[addr]) // 已有的交易数
			if have >= maxTxsPerAccount {
				return have, 0 // 已达上限，无剩余槽位
			}
			return have, maxTxsPerAccount - have // 返回已用和剩余槽位
		},
		// 返回账户现有支出
		ExistingExpenditure: func(addr common.Address) *big.Int {
			if spent := p.spent[addr]; spent != nil {
				return spent.ToBig() // 返回现有支出
			}
			return new(big.Int) // 无支出返回 0
		},
		// 返回指定 nonce 的交易成本
		ExistingCost: func(addr common.Address, nonce uint64) *big.Int {
			next := p.state.GetNonce(addr)
			if uint64(len(p.index[addr])) > nonce-next {
				return p.index[addr][int(nonce-next)].costCap.ToBig() // 返回交易成本
			}
			return nil // 无对应交易返回 nil
		},
	}
	// 验证交易的状态规则
	if err := txpool.ValidateTransactionWithState(tx, p.signer, stateOpts); err != nil {
		return err // 验证失败，返回错误
	}
	// If the transaction replaces an existing one, ensure that price bumps are
	// adhered to.
	// 如果交易替换现有的交易，确保遵守价格提升。
	var (
		from, _ = types.Sender(p.signer, tx) // 获取发送者，已在上方验证
		next    = p.state.GetNonce(from)     // 获取下一个 nonce
	)
	if uint64(len(p.index[from])) > tx.Nonce()-next {
		prev := p.index[from][int(tx.Nonce()-next)] // 获取被替换的交易
		// Ensure the transaction is different than the one tracked locally
		// 确保交易与本地跟踪的交易不同
		if prev.hash == tx.Hash() {
			return txpool.ErrAlreadyKnown // 交易已知，返回错误
		}
		// Account can support the replacement, but the price bump must also be met
		// 账户可以支持替换，但价格提升也必须满足
		switch {
		case tx.GasFeeCapIntCmp(prev.execFeeCap.ToBig()) <= 0:
			return fmt.Errorf("%w: new tx gas fee cap %v <= %v queued", txpool.ErrReplaceUnderpriced, tx.GasFeeCap(), prev.execFeeCap)
		case tx.GasTipCapIntCmp(prev.execTipCap.ToBig()) <= 0:
			return fmt.Errorf("%w: new tx gas tip cap %v <= %v queued", txpool.ErrReplaceUnderpriced, tx.GasTipCap(), prev.execTipCap)
		case tx.BlobGasFeeCapIntCmp(prev.blobFeeCap.ToBig()) <= 0:
			return fmt.Errorf("%w: new tx blob gas fee cap %v <= %v queued", txpool.ErrReplaceUnderpriced, tx.BlobGasFeeCap(), prev.blobFeeCap)
		}
		// 计算替换所需的最小费用提升
		var (
			multiplier = uint256.NewInt(100 + p.config.PriceBump) // 提升倍数
			onehundred = uint256.NewInt(100)                      // 100，用于计算百分比

			minGasFeeCap     = new(uint256.Int).Div(new(uint256.Int).Mul(multiplier, prev.execFeeCap), onehundred)
			minGasTipCap     = new(uint256.Int).Div(new(uint256.Int).Mul(multiplier, prev.execTipCap), onehundred)
			minBlobGasFeeCap = new(uint256.Int).Div(new(uint256.Int).Mul(multiplier, prev.blobFeeCap), onehundred)
		)
		// 检查是否满足最小费用提升要求
		switch {
		case tx.GasFeeCapIntCmp(minGasFeeCap.ToBig()) < 0:
			return fmt.Errorf("%w: new tx gas fee cap %v < %v queued + %d%% replacement penalty", txpool.ErrReplaceUnderpriced, tx.GasFeeCap(), prev.execFeeCap, p.config.PriceBump)
		case tx.GasTipCapIntCmp(minGasTipCap.ToBig()) < 0:
			return fmt.Errorf("%w: new tx gas tip cap %v < %v queued + %d%% replacement penalty", txpool.ErrReplaceUnderpriced, tx.GasTipCap(), prev.execTipCap, p.config.PriceBump)
		case tx.BlobGasFeeCapIntCmp(minBlobGasFeeCap.ToBig()) < 0:
			return fmt.Errorf("%w: new tx blob gas fee cap %v < %v queued + %d%% replacement penalty", txpool.ErrReplaceUnderpriced, tx.BlobGasFeeCap(), prev.blobFeeCap, p.config.PriceBump)
		}
	}
	return nil // 验证通过，返回 nil
}

// Has returns an indicator whether subpool has a transaction cached with the
// given hash.
// Has 返回一个指示，子池是否缓存了具有给定哈希的交易。
func (p *BlobPool) Has(hash common.Hash) bool {
	p.lock.RLock() // 加读锁
	defer p.lock.RUnlock()

	return p.lookup.exists(hash) // 检查交易是否存在于查找表中
}

// Get returns a transaction if it is contained in the pool, or nil otherwise.
// Get 如果池中包含交易，则返回交易，否则返回 nil。
func (p *BlobPool) Get(hash common.Hash) *types.Transaction {
	// Track the amount of time waiting to retrieve a fully resolved blob tx from
	// the pool and the amount of time actually spent on pulling the data from disk.
	// 跟踪从池中检索完全解析的 blob tx 的等待时间和实际从磁盘拉取数据的时间。
	getStart := time.Now()
	p.lock.RLock()
	getwaitHist.Update(time.Since(getStart).Nanoseconds())
	defer p.lock.RUnlock()

	// 记录获取操作的总时间
	defer func(start time.Time) {
		gettimeHist.Update(time.Since(start).Nanoseconds())
	}(time.Now())

	// Pull the blob from disk and return an assembled response
	// 从磁盘拉取 blob 并返回组装的响应
	id, ok := p.lookup.storeidOfTx(hash) // 获取交易存储 ID
	if !ok {
		return nil // 未找到交易，返回 nil
	}
	data, err := p.store.Get(id) // 从存储中获取数据
	if err != nil {
		log.Error("Tracked blob transaction missing from store", "hash", hash, "id", id, "err", err)
		return nil // 数据缺失，返回 nil
	}
	item := new(types.Transaction) // 创建交易对象
	if err = rlp.DecodeBytes(data, item); err != nil {
		log.Error("Blobs corrupted for traced transaction", "hash", hash, "id", id, "err", err)
		return nil // 数据损坏，返回 nil
	}
	return item // 返回解析后的交易
}

// GetBlobs returns a number of blobs are proofs for the given versioned hashes.
// This is a utility method for the engine API, enabling consensus clients to
// retrieve blobs from the pools directly instead of the network.
// GetBlobs 返回给定版本化哈希的 blob 和证明。这是一个用于 engine API 的实用方法，使共识客户端能够直接从池中检索 blob，而不是从网络中。
func (p *BlobPool) GetBlobs(vhashes []common.Hash) ([]*kzg4844.Blob, []*kzg4844.Proof) {
	// Create a map of the blob hash to indices for faster fills
	// 创建 blob 哈希到索引的映射以更快地填充
	var (
		blobs  = make([]*kzg4844.Blob, len(vhashes))  // 初始化 blob 数组
		proofs = make([]*kzg4844.Proof, len(vhashes)) // 初始化证明数组
	)
	index := make(map[common.Hash]int) // 创建哈希到索引的映射
	for i, vhash := range vhashes {
		index[vhash] = i // 填充映射
	}
	// Iterate over the blob hashes, pulling transactions that fill it. Take care
	// to also fill anything else the transaction might include (probably will).
	// 遍历 blob 哈希，拉取填充它的交易。注意也要填充交易可能包含的任何其他内容（可能会有）。
	for i, vhash := range vhashes {
		// If already filled by a previous fetch, skip
		// 如果已经被先前的获取填充，跳过
		if blobs[i] != nil {
			continue
		}
		// Unfilled, retrieve the datastore item (in a short lock)
		// 未填充，检索数据存储项（在短锁中）
		p.lock.RLock()
		id, exists := p.lookup.storeidOfBlob(vhash) // 获取 blob 存储 ID
		if !exists {
			p.lock.RUnlock()
			continue // 未找到 blob，继续下一个
		}
		data, err := p.store.Get(id) // 从存储中获取数据
		p.lock.RUnlock()

		// After releasing the lock, try to fill any blobs requested
		// 释放锁后，尝试填充任何请求的 blob
		if err != nil {
			log.Error("Tracked blob transaction missing from store", "id", id, "err", err)
			continue // 数据缺失，继续下一个
		}
		item := new(types.Transaction) // 创建交易对象
		if err = rlp.DecodeBytes(data, item); err != nil {
			log.Error("Blobs corrupted for traced transaction", "id", id, "err", err)
			continue // 数据损坏，继续下一个
		}
		// Fill anything requested, not just the current versioned hash
		// 填充任何请求的内容，而不仅仅是当前版本化哈希
		sidecar := item.BlobTxSidecar() // 获取交易 sidecar
		for j, blobhash := range item.BlobHashes() {
			if idx, ok := index[blobhash]; ok {
				blobs[idx] = &sidecar.Blobs[j]   // 填充 blob
				proofs[idx] = &sidecar.Proofs[j] // 填充证明
			}
		}
	}
	return blobs, proofs // 返回填充好的 blob 和证明
}

// Add inserts a set of blob transactions into the pool if they pass validation (both
// consensus validity and pool restrictions).
// Add 如果一组 blob 交易通过验证（共识有效性和池限制），则将它们插入池中。
func (p *BlobPool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	var (
		adds = make([]*types.Transaction, 0, len(txs)) // 记录成功添加的交易
		errs = make([]error, len(txs))                 // 记录每个交易的错误
	)
	// 遍历交易并尝试添加
	for i, tx := range txs {
		errs[i] = p.add(tx) // 添加交易
		if errs[i] == nil {
			adds = append(adds, tx.WithoutBlobTxSidecar()) // 添加成功则记录
		}
	}
	// 如果有成功添加的交易，发送事件
	if len(adds) > 0 {
		p.discoverFeed.Send(core.NewTxsEvent{Txs: adds})
		p.insertFeed.Send(core.NewTxsEvent{Txs: adds})
	}
	return errs // 返回错误列表
}

// add inserts a new blob transaction into the pool if it passes validation (both
// consensus validity and pool restrictions).
// add 如果新的 blob 交易通过验证（共识有效性和池限制），则将它插入池中。
func (p *BlobPool) add(tx *types.Transaction) (err error) {
	// The blob pool blocks on adding a transaction. This is because blob txs are
	// only even pulled from the network, so this method will act as the overload
	// protection for fetches.
	// blob 池在添加交易时阻塞。这是因为 blob 交易只是从网络中拉取的，因此此方法将作为获取的过载保护。
	waitStart := time.Now()
	p.lock.Lock()
	addwaitHist.Update(time.Since(waitStart).Nanoseconds())
	defer p.lock.Unlock()

	// 记录添加操作的总时间
	defer func(start time.Time) {
		addtimeHist.Update(time.Since(start).Nanoseconds())
	}(time.Now())

	// Ensure the transaction is valid from all perspectives
	// 确保交易从所有角度都是有效的
	if err := p.validateTx(tx); err != nil {
		log.Trace("Transaction validation failed", "hash", tx.Hash(), "err", err)
		// 根据错误类型更新指标
		switch {
		case errors.Is(err, txpool.ErrUnderpriced):
			addUnderpricedMeter.Mark(1)
		case errors.Is(err, core.ErrNonceTooLow):
			addStaleMeter.Mark(1)
		case errors.Is(err, core.ErrNonceTooHigh):
			addGappedMeter.Mark(1)
		case errors.Is(err, core.ErrInsufficientFunds):
			addOverdraftedMeter.Mark(1)
		case errors.Is(err, txpool.ErrAccountLimitExceeded):
			addOvercappedMeter.Mark(1)
		case errors.Is(err, txpool.ErrReplaceUnderpriced):
			addNoreplaceMeter.Mark(1)
		default:
			addInvalidMeter.Mark(1)
		}
		return err // 验证失败，返回错误
	}
	// If the address is not yet known, request exclusivity to track the account
	// only by this subpool until all transactions are evicted
	// 如果地址尚不知晓，请求独占性以仅由此子池跟踪账户，直到所有交易被驱逐
	from, _ := types.Sender(p.signer, tx) //  already validated above 获取发送者，已在上方验证
	if _, ok := p.index[from]; !ok {
		if err := p.reserve(from, true); err != nil {
			addNonExclusiveMeter.Mark(1)
			return err // 保留地址失败，返回错误
		}
		// 如果添加失败，释放地址保留
		defer func() {
			// If the transaction is rejected by some post-validation check, remove
			// the lock on the reservation set.
			//
			// Note, `err` here is the named error return, which will be initialized
			// by a return statement before running deferred methods. Take care with
			// removing or subscoping err as it will break this clause.
			// 如果交易被某些后验证检查拒绝，移除保留集上的锁。
			//
			// 注意，这里的 `err` 是命名的错误返回，它将在运行延迟方法之前由 return 语句初始化。注意不要移除或子作用域 err，因为这会破坏此子句。
			if err != nil {
				p.reserve(from, false)
			}
		}()
	}
	// Transaction permitted into the pool from a nonce and cost perspective,
	// insert it into the database and update the indices
	// 从 nonce 和成本角度允许交易进入池，将其插入数据库并更新索引
	blob, err := rlp.EncodeToBytes(tx) // 序列化交易
	if err != nil {
		log.Error("Failed to encode transaction for storage", "hash", tx.Hash(), "err", err)
		return err // 序列化失败，返回错误
	}
	id, err := p.store.Put(blob) // 存储序列化数据
	if err != nil {
		return err // 存储失败，返回错误
	}
	meta := newBlobTxMeta(id, p.store.Size(id), tx) // 创建交易元数据

	var (
		next   = p.state.GetNonce(from) // 获取下一个 nonce
		offset = int(tx.Nonce() - next) // 计算交易偏移
		newacc = false                  // 是否为新账户
	)
	var oldEvictionExecFeeJumps, oldEvictionBlobFeeJumps float64 // 保存旧的驱逐跳跃值
	if txs, ok := p.index[from]; ok {
		oldEvictionExecFeeJumps = txs[len(txs)-1].evictionExecFeeJumps
		oldEvictionBlobFeeJumps = txs[len(txs)-1].evictionBlobFeeJumps
	}
	if len(p.index[from]) > offset {
		// Transaction replaces a previously queued one
		// 交易替换先前排队的交易
		dropReplacedMeter.Mark(1)

		prev := p.index[from][offset] // 获取被替换的交易
		if err := p.store.Delete(prev.id); err != nil {
			// Shitty situation, but try to recover gracefully instead of going boom
			// 糟糕的情况，但尝试优雅地恢复而不是崩溃
			log.Error("Failed to delete replaced transaction", "id", prev.id, "err", err)
		}
		// Update the transaction index
		// 更新交易索引
		p.index[from][offset] = meta                                      // 替换交易
		p.spent[from] = new(uint256.Int).Sub(p.spent[from], prev.costCap) // 减去旧成本
		p.spent[from] = new(uint256.Int).Add(p.spent[from], meta.costCap) // 加上新成本

		p.lookup.untrack(prev)                            // 取消跟踪旧交易
		p.lookup.track(meta)                              // 跟踪新交易
		p.stored += uint64(meta.size) - uint64(prev.size) // 更新存储大小
	} else {
		// Transaction extends previously scheduled ones
		// 交易扩展先前计划的交易
		p.index[from] = append(p.index[from], meta) // 添加新交易
		if _, ok := p.spent[from]; !ok {
			p.spent[from] = new(uint256.Int) // 初始化支出
			newacc = true                    // 标记为新账户
		}
		p.spent[from] = new(uint256.Int).Add(p.spent[from], meta.costCap) // 更新支出
		p.lookup.track(meta)                                              // 跟踪新交易
		p.stored += uint64(meta.size)                                     // 更新存储大小
	}
	// Recompute the rolling eviction fields. In case of a replacement, this will
	// recompute all subsequent fields. In case of an append, this will only do
	// the fresh calculation.
	// 重新计算滚动驱逐字段。在替换的情况下，这将重新计算所有后续字段。在追加的情况下，这只会进行新的计算。
	txs := p.index[from] // 获取账户交易列表

	for i := offset; i < len(txs); i++ {
		// The first transaction will always use itself
		// 第一个交易将始终使用自身
		if i == 0 {
			txs[0].evictionExecTip = txs[0].execTipCap        // 设置驱逐 gas tip
			txs[0].evictionExecFeeJumps = txs[0].basefeeJumps // 设置驱逐 basefee 跳跃
			txs[0].evictionBlobFeeJumps = txs[0].blobfeeJumps // 设置驱逐 blobfee 跳跃

			continue
		}
		// Subsequent transactions will use a rolling calculation
		// 后续交易将使用滚动计算
		txs[i].evictionExecTip = txs[i-1].evictionExecTip // 继承前一交易的 gas tip
		if txs[i].evictionExecTip.Cmp(txs[i].execTipCap) > 0 {
			txs[i].evictionExecTip = txs[i].execTipCap // 更新为当前交易的最小值
		}
		txs[i].evictionExecFeeJumps = txs[i-1].evictionExecFeeJumps // 继承前一交易的 basefee 跳跃
		if txs[i].evictionExecFeeJumps > txs[i].basefeeJumps {
			txs[i].evictionExecFeeJumps = txs[i].basefeeJumps // 更新为当前交易的最小值
		}
		txs[i].evictionBlobFeeJumps = txs[i-1].evictionBlobFeeJumps // 继承前一交易的 blobfee 跳跃
		if txs[i].evictionBlobFeeJumps > txs[i].blobfeeJumps {
			txs[i].evictionBlobFeeJumps = txs[i].blobfeeJumps // 更新为当前交易的最小值
		}
	}
	// Update the eviction heap with the new information:
	//   - If the transaction is from a new account, add it to the heap
	//   - If the account had a singleton tx replaced, update the heap (new price caps)
	//   - If the account has a transaction replaced or appended, update the heap if significantly changed
	// 使用新信息更新驱逐堆：
	//   - 如果交易来自新账户，将其添加到堆中
	//   - 如果账户的单例交易被替换，更新堆（新价格上限）
	//   - 如果账户的交易被替换或追加，如果有显著变化，更新堆
	switch {
	case newacc:
		heap.Push(p.evict, from) // 新账户，添加到堆

	case len(txs) == 1: // 1 tx and not a new acc, must be replacement
		heap.Fix(p.evict, p.evict.index[from]) // 单交易替换，修复堆

	default: // replacement or new append
		// 计算驱逐跳跃的差异
		evictionExecFeeDiff := oldEvictionExecFeeJumps - txs[len(txs)-1].evictionExecFeeJumps
		evictionBlobFeeDiff := oldEvictionBlobFeeJumps - txs[len(txs)-1].evictionBlobFeeJumps

		if math.Abs(evictionExecFeeDiff) > 0.001 || math.Abs(evictionBlobFeeDiff) > 0.001 { // need math.Abs, can go up and down
			heap.Fix(p.evict, p.evict.index[from]) // 如果差异显著，修复堆
		}
	}
	// If the pool went over the allowed data limit, evict transactions until
	// we're again below the threshold
	// 如果池超出了允许的数据限制，驱逐交易直到我们再次低于阈值
	for p.stored > p.config.Datacap {
		p.drop() // 执行驱逐
	}
	p.updateStorageMetrics() // 更新存储指标

	addValidMeter.Mark(1)
	return nil // 添加成功，返回 nil
}

// drop removes the worst transaction from the pool. It is primarily used when a
// freshly added transaction overflows the pool and needs to evict something. The
// method is also called on startup if the user resizes their storage, might be an
// expensive run but it should be fine-ish.
// drop 从池中移除最差的交易。主要在新添加的交易溢出池并需要驱逐某些内容时使用。如果用户调整存储大小，该方法也将在启动时调用，可能是昂贵的运行，但应该没问题。
func (p *BlobPool) drop() {
	// Peek at the account with the worse transaction set to evict from (Go's heap
	// stores the minimum at index zero of the heap slice) and retrieve it's last
	// transaction.
	// 查看具有最差交易集的账户以驱逐（Go 的堆将最小值存储在堆切片的索引 0 处），并检索其最后一个交易。
	var (
		from = p.evict.addrs[0] // cannot call drop on empty pool
		// 获取最差账户地址

		txs  = p.index[from]   // 获取账户交易列表
		drop = txs[len(txs)-1] // 获取最后一个交易作为待驱逐交易
		last = len(txs) == 1   // 检查是否为账户最后一个交易
	)
	// Remove the transaction from the pool's index
	// 从池的索引中移除交易
	if last {
		delete(p.index, from)  // 删除账户索引
		delete(p.spent, from)  // 删除账户支出
		p.reserve(from, false) // 释放地址保留
	} else {
		txs[len(txs)-1] = nil  // 清空最后一个交易
		txs = txs[:len(txs)-1] // 截断交易列表

		p.index[from] = txs                                               // 更新索引
		p.spent[from] = new(uint256.Int).Sub(p.spent[from], drop.costCap) // 更新支出
	}
	p.stored -= uint64(drop.size) // 减少存储大小
	p.lookup.untrack(drop)        // 取消跟踪

	// Remove the transaction from the pool's eviction heap:
	//   - If the entire account was dropped, pop off the address
	//   - Otherwise, if the new tail has better eviction caps, fix the heap
	// 从池的驱逐堆中移除交易：
	//   - 如果整个账户被丢弃，弹出地址
	//   - 否则，如果新的尾部有更好的驱逐上限，修复堆
	if last {
		heap.Pop(p.evict) // 账户被完全移除，弹出堆顶
	} else {
		tail := txs[len(txs)-1] // 获取新的尾部交易，必定存在

		// 计算驱逐跳跃的差异
		evictionExecFeeDiff := tail.evictionExecFeeJumps - drop.evictionExecFeeJumps
		evictionBlobFeeDiff := tail.evictionBlobFeeJumps - drop.evictionBlobFeeJumps

		if evictionExecFeeDiff > 0.001 || evictionBlobFeeDiff > 0.001 { // no need for math.Abs, monotonic decreasing
			heap.Fix(p.evict, 0) // 如果差异显著，修复堆
		}
	}
	// Remove the transaction from the data store
	// 从数据存储中移除交易
	log.Debug("Evicting overflown blob transaction", "from", from, "evicted", drop.nonce, "id", drop.id)
	dropOverflownMeter.Mark(1)

	if err := p.store.Delete(drop.id); err != nil {
		log.Error("Failed to drop evicted transaction", "id", drop.id, "err", err)
	}
}

// Pending retrieves all currently processable transactions, grouped by origin
// account and sorted by nonce.
// Pending 检索所有当前可处理的交易，按原始账户分组并按 nonce 排序。
//
// The transactions can also be pre-filtered by the dynamic fee components to
// reduce allocations and load on downstream subsystems.
// 交易也可以通过动态费用组件预过滤，以减少分配和下游子系统的负载。
func (p *BlobPool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	// If only plain transactions are requested, this pool is unsuitable as it
	// contains none, don't even bother.
	// 如果只请求普通交易，此池不适合，因为它不包含任何普通交易，甚至不需要费心。
	if filter.OnlyPlainTxs {
		return nil // 只请求普通交易，返回 nil
	}
	// Track the amount of time waiting to retrieve the list of pending blob txs
	// from the pool and the amount of time actually spent on assembling the data.
	// The latter will be pretty much moot, but we've kept it to have symmetric
	// across all user operations.
	// 跟踪从池中检索待处理 blob tx 列表的等待时间和实际用于组装数据的时间。后者几乎是无意义的，但我们保留它以在所有用户操作中保持对称。
	pendStart := time.Now()
	p.lock.RLock()
	pendwaitHist.Update(time.Since(pendStart).Nanoseconds())
	defer p.lock.RUnlock()

	execStart := time.Now()
	defer func() {
		pendtimeHist.Update(time.Since(execStart).Nanoseconds())
	}()

	pending := make(map[common.Address][]*txpool.LazyTransaction, len(p.index)) // 初始化待处理交易映射
	for addr, txs := range p.index {
		lazies := make([]*txpool.LazyTransaction, 0, len(txs)) // 初始化懒加载交易列表
		for _, tx := range txs {
			// If transaction filtering was requested, discard badly priced ones
			// 如果请求了交易过滤，丢弃定价不良的交易
			if filter.MinTip != nil && filter.BaseFee != nil {
				if tx.execFeeCap.Lt(filter.BaseFee) {
					break // basefee too low, cannot be included, discard rest of txs from the account
				}
				tip := new(uint256.Int).Sub(tx.execFeeCap, filter.BaseFee) // 计算实际 tip
				if tip.Gt(tx.execTipCap) {
					tip = tx.execTipCap // 如果超过上限，使用上限值
				}
				if tip.Lt(filter.MinTip) {
					break // allowed or remaining tip too low, cannot be included, discard rest of txs from the account
				}
			}
			if filter.BlobFee != nil {
				if tx.blobFeeCap.Lt(filter.BlobFee) {
					break // blobfee too low, cannot be included, discard rest of txs from the account
				}
			}
			// Transaction was accepted according to the filter, append to the pending list
			// 根据过滤器接受交易，追加到待处理列表
			lazies = append(lazies, &txpool.LazyTransaction{
				Pool:      p,             // 设置交易池
				Hash:      tx.hash,       // 设置交易哈希
				Time:      execStart,     // TODO(karalabe): Maybe save these and use that? 设置时间戳（TODO: 可能需要保存并使用实际时间）
				GasFeeCap: tx.execFeeCap, // 设置 gas 费用上限
				GasTipCap: tx.execTipCap, // 设置 gas tip 上限
				Gas:       tx.execGas,    // 设置执行 gas
				BlobGas:   tx.blobGas,    // 设置 blob gas
			})
		}
		if len(lazies) > 0 {
			pending[addr] = lazies // 添加非空交易列表到结果
		}
	}
	return pending // 返回待处理交易
}

// updateStorageMetrics retrieves a bunch of stats from the data store and pushes
// them out as metrics.
// updateStorageMetrics 从数据存储中检索一系列统计信息，并将它们作为指标推送出去。
func (p *BlobPool) updateStorageMetrics() {
	stats := p.store.Infos()

	var (
		dataused uint64
		datareal uint64
		slotused uint64

		oversizedDataused uint64
		oversizedDatagaps uint64
		oversizedSlotused uint64
		oversizedSlotgaps uint64
	)
	for _, shelf := range stats.Shelves {
		slotDataused := shelf.FilledSlots * uint64(shelf.SlotSize)
		slotDatagaps := shelf.GappedSlots * uint64(shelf.SlotSize)

		dataused += slotDataused
		datareal += slotDataused + slotDatagaps
		slotused += shelf.FilledSlots

		metrics.GetOrRegisterGauge(fmt.Sprintf(shelfDatausedGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(slotDataused))
		metrics.GetOrRegisterGauge(fmt.Sprintf(shelfDatagapsGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(slotDatagaps))
		metrics.GetOrRegisterGauge(fmt.Sprintf(shelfSlotusedGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(shelf.FilledSlots))
		metrics.GetOrRegisterGauge(fmt.Sprintf(shelfSlotgapsGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(shelf.GappedSlots))

		if shelf.SlotSize/blobSize > maxBlobsPerTransaction {
			oversizedDataused += slotDataused
			oversizedDatagaps += slotDatagaps
			oversizedSlotused += shelf.FilledSlots
			oversizedSlotgaps += shelf.GappedSlots
		}
	}
	datausedGauge.Update(int64(dataused))
	datarealGauge.Update(int64(datareal))
	slotusedGauge.Update(int64(slotused))

	oversizedDatausedGauge.Update(int64(oversizedDataused))
	oversizedDatagapsGauge.Update(int64(oversizedDatagaps))
	oversizedSlotusedGauge.Update(int64(oversizedSlotused))
	oversizedSlotgapsGauge.Update(int64(oversizedSlotgaps))

	p.updateLimboMetrics()
}

// updateLimboMetrics retrieves a bunch of stats from the limbo store and pushes
// them out as metrics.
// updateLimboMetrics 从临时存储中检索一系列统计信息，并将它们作为指标推送出去。
func (p *BlobPool) updateLimboMetrics() {
	stats := p.limbo.store.Infos()

	var (
		dataused uint64
		datareal uint64
		slotused uint64
	)
	for _, shelf := range stats.Shelves {
		slotDataused := shelf.FilledSlots * uint64(shelf.SlotSize)
		slotDatagaps := shelf.GappedSlots * uint64(shelf.SlotSize)

		dataused += slotDataused
		datareal += slotDataused + slotDatagaps
		slotused += shelf.FilledSlots

		metrics.GetOrRegisterGauge(fmt.Sprintf(limboShelfDatausedGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(slotDataused))
		metrics.GetOrRegisterGauge(fmt.Sprintf(limboShelfDatagapsGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(slotDatagaps))
		metrics.GetOrRegisterGauge(fmt.Sprintf(limboShelfSlotusedGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(shelf.FilledSlots))
		metrics.GetOrRegisterGauge(fmt.Sprintf(limboShelfSlotgapsGaugeName, shelf.SlotSize/blobSize), nil).Update(int64(shelf.GappedSlots))
	}
	limboDatausedGauge.Update(int64(dataused))
	limboDatarealGauge.Update(int64(datareal))
	limboSlotusedGauge.Update(int64(slotused))
}

// SubscribeTransactions registers a subscription for new transaction events,
// supporting feeding only newly seen or also resurrected transactions.
// SubscribeTransactions 注册一个新交易事件的订阅，支持仅提供新看到的或也包括重新出现的交易。
func (p *BlobPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	if reorgs {
		return p.insertFeed.Subscribe(ch)
	} else {
		return p.discoverFeed.Subscribe(ch)
	}
}

// Nonce returns the next nonce of an account, with all transactions executable
// by the pool already applied on top.
// Nonce 返回账户的下一个 nonce，池中所有可执行的交易都已应用。
func (p *BlobPool) Nonce(addr common.Address) uint64 {
	// We need a write lock here, since state.GetNonce might write the cache.
	// 这里需要写锁，因为 state.GetNonce 可能会写入缓存。
	p.lock.Lock()
	defer p.lock.Unlock()

	if txs, ok := p.index[addr]; ok {
		return txs[len(txs)-1].nonce + 1
	}
	return p.state.GetNonce(addr)
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
// Stats 检索当前的池统计信息，即挂起（pending）和排队（queued，不可执行）的交易数量。
func (p *BlobPool) Stats() (int, int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	var pending int
	for _, txs := range p.index {
		pending += len(txs)
	}
	return pending, 0 // No non-executable txs in the blob pool
	// Blob 池中没有不可执行的交易。
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
//
// For the blob pool, this method will return nothing for now.
// TODO(karalabe): Abstract out the returned metadata.
// Content 检索交易池的数据内容，返回所有挂起和排队的交易，按账户分组并按 nonce 排序。
//
// 对于 blob 池，此方法目前将不返回任何内容。
// TODO(karalabe): 抽象出返回的元数据。
func (p *BlobPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return make(map[common.Address][]*types.Transaction), make(map[common.Address][]*types.Transaction)
}

// ContentFrom retrieves the data content of the transaction pool, returning the
// pending as well as queued transactions of this address, grouped by nonce.
//
// For the blob pool, this method will return nothing for now.
// TODO(karalabe): Abstract out the returned metadata.
// ContentFrom 检索交易池的数据内容，返回此地址的挂起和排队的交易，按 nonce 分组。
//
// 对于 blob 池，此方法目前将不返回任何内容。
// TODO(karalabe): 抽象出返回的元数据。
func (p *BlobPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return []*types.Transaction{}, []*types.Transaction{}
}

// Locals retrieves the accounts currently considered local by the pool.
//
// There is no notion of local accounts in the blob pool.
// Locals 检索池中当前被认为是本地的账户。
//
// 在 blob 池中没有本地账户的概念。
func (p *BlobPool) Locals() []common.Address {
	return []common.Address{}
}

// Status returns the known status (unknown/pending/queued) of a transaction
// identified by their hashes.
// Status 返回由其哈希标识的交易的已知状态（未知/挂起/排队）。
func (p *BlobPool) Status(hash common.Hash) txpool.TxStatus {
	if p.Has(hash) {
		return txpool.TxStatusPending
	}
	return txpool.TxStatusUnknown
}

// Clear implements txpool.SubPool, removing all tracked transactions
// from the blob pool and persistent store.
// Clear 实现 txpool.SubPool 接口，从 blob 池和持久化存储中删除所有跟踪的交易。
func (p *BlobPool) Clear() {
	p.lock.Lock()
	defer p.lock.Unlock()

	// manually iterating and deleting every entry is super sub-optimal
	// However, Clear is not currently used in production so
	// performance is not critical at the moment.
	// 手动迭代和删除每个条目是非常次优的。
	// 然而，Clear 目前在生产中未使用，因此性能目前并不关键。
	for hash := range p.lookup.txIndex {
		id, _ := p.lookup.storeidOfTx(hash)
		if err := p.store.Delete(id); err != nil {
			log.Warn("failed to delete blob tx from backing store", "err", err)
		}
	}
	for hash := range p.lookup.blobIndex {
		id, _ := p.lookup.storeidOfBlob(hash)
		if err := p.store.Delete(id); err != nil {
			log.Warn("failed to delete blob from backing store", "err", err)
		}
	}

	// unreserve each tracked account.  Ideally, we could just clear the
	// reservation map in the parent txpool context.  However, if we clear in
	// parent context, to avoid exposing the subpool lock, we have to lock the
	// reservations and then lock each subpool.
	//
	// This creates the potential for a deadlock situation:
	//
	// * TxPool.Clear locks the reservations
	// * a new transaction is received which locks the subpool mutex
	// * TxPool.Clear attempts to lock subpool mutex
	//
	// The transaction addition may attempt to reserve the sender addr which
	// can't happen until Clear releases the reservation lock.  Clear cannot
	// acquire the subpool lock until the transaction addition is completed.
	// 取消预留每个跟踪的账户。理想情况下，我们可以直接清除父 txpool 上下文中的预留映射。
	// 然而，如果我们在父上下文中清除，为了避免暴露子池锁，我们必须锁定预留，然后锁定每个子池。
	//
	// 这会产生死锁的可能性：
	//
	// * TxPool.Clear 锁定预留
	// * 接收到一个新的交易，它锁定子池互斥锁
	// * TxPool.Clear 尝试锁定子池互斥锁
	//
	// 交易添加可能会尝试预留发送者地址，这在 Clear 释放预留锁之前无法发生。
	// Clear 在交易添加完成之前无法获取子池锁。
	for acct := range p.index {
		p.reserve(acct, false)
	}
	p.lookup = newLookup()
	p.index = make(map[common.Address][]*blobTxMeta)
	p.spent = make(map[common.Address]*uint256.Int)

	var (
		basefee = uint256.MustFromBig(eip1559.CalcBaseFee(p.chain.Config(), p.head))
		blobfee = uint256.NewInt(params.BlobTxMinBlobGasprice)
	)
	p.evict = newPriceHeap(basefee, blobfee, p.index)
}
