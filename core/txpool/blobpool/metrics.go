// Copyright 2023 The go-ethereum Authors
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

package blobpool

import "github.com/ethereum/go-ethereum/metrics"

var (
	// datacapGauge tracks the user's configured capacity for the blob pool. It
	// is mostly a way to expose/debug issues.
	// datacapGauge 跟踪用户为 blob 池配置的容量。这主要是暴露/调试问题的一种方式。
	datacapGauge = metrics.NewRegisteredGauge("blobpool/datacap", nil)

	// The below metrics track the per-datastore metrics for the primary blob
	// store and the temporary limbo store.
	// 下面的指标跟踪主 blob 存储和临时 limbo 存储的每个数据存储的指标。
	datausedGauge = metrics.NewRegisteredGauge("blobpool/dataused", nil) // Tracks the used data size of the main blob store.
	// datausedGauge 跟踪主 blob 存储的已用数据大小。
	datarealGauge = metrics.NewRegisteredGauge("blobpool/datareal", nil) // Tracks the actual allocated data size of the main blob store.
	// datarealGauge 跟踪主 blob 存储的实际分配数据大小。
	slotusedGauge = metrics.NewRegisteredGauge("blobpool/slotused", nil) // Tracks the number of used slots in the main blob store.
	// slotusedGauge 跟踪主 blob 存储中已用槽位的数量。

	limboDatausedGauge = metrics.NewRegisteredGauge("blobpool/limbo/dataused", nil) // Tracks the used data size of the limbo blob store.
	// limboDatausedGauge 跟踪 limbo blob 存储的已用数据大小。
	limboDatarealGauge = metrics.NewRegisteredGauge("blobpool/limbo/datareal", nil) // Tracks the actual allocated data size of the limbo blob store.
	// limboDatarealGauge 跟踪 limbo blob 存储的实际分配数据大小。
	limboSlotusedGauge = metrics.NewRegisteredGauge("blobpool/limbo/slotused", nil) // Tracks the number of used slots in the limbo blob store.
	// limboSlotusedGauge 跟踪 limbo blob 存储中已用槽位的数量。

	// The below metrics track the per-shelf metrics for the primary blob store
	// and the temporary limbo store.
	// 下面的指标跟踪主 blob 存储和临时 limbo 存储的每个 shelf 的指标。
	shelfDatausedGaugeName = "blobpool/shelf_%d/dataused" // Name format for data used by a specific shelf in the main blob store.
	// shelfDatausedGaugeName 主 blob 存储中特定 shelf 已用数据的指标名称格式。
	shelfDatagapsGaugeName = "blobpool/shelf_%d/datagaps" // Name format for data gaps in a specific shelf in the main blob store.
	// shelfDatagapsGaugeName 主 blob 存储中特定 shelf 数据间隙的指标名称格式。
	shelfSlotusedGaugeName = "blobpool/shelf_%d/slotused" // Name format for used slots in a specific shelf in the main blob store.
	// shelfSlotusedGaugeName 主 blob 存储中特定 shelf 已用槽位的指标名称格式。
	shelfSlotgapsGaugeName = "blobpool/shelf_%d/slotgaps" // Name format for slot gaps in a specific shelf in the main blob store.
	// shelfSlotgapsGaugeName 主 blob 存储中特定 shelf 槽位间隙的指标名称格式。

	limboShelfDatausedGaugeName = "blobpool/limbo/shelf_%d/dataused" // Name format for data used by a specific shelf in the limbo blob store.
	// limboShelfDatausedGaugeName limbo blob 存储中特定 shelf 已用数据的指标名称格式。
	limboShelfDatagapsGaugeName = "blobpool/limbo/shelf_%d/datagaps" // Name format for data gaps in a specific shelf in the limbo blob store.
	// limboShelfDatagapsGaugeName limbo blob 存储中特定 shelf 数据间隙的指标名称格式。
	limboShelfSlotusedGaugeName = "blobpool/limbo/shelf_%d/slotused" // Name format for used slots in a specific shelf in the limbo blob store.
	// limboShelfSlotusedGaugeName limbo blob 存储中特定 shelf 已用槽位的指标名称格式。
	limboShelfSlotgapsGaugeName = "blobpool/limbo/shelf_%d/slotgaps" // Name format for slot gaps in a specific shelf in the limbo blob store.
	// limboShelfSlotgapsGaugeName limbo blob 存储中特定 shelf 槽位间隙的指标名称格式。

	// The oversized metrics aggregate the shelf stats above the max blob count
	// limits to track transactions that are just huge, but don't contain blobs.
	// 超大指标聚合了超过最大 blob 计数限制的 shelf 统计信息，以跟踪那些非常大但不包含 blob 的交易。
	//
	// There are no oversized data in the limbo, it only contains blobs and some
	// constant metadata.
	// limbo 中没有超大数据，它只包含 blob 和一些常量元数据。
	oversizedDatausedGauge = metrics.NewRegisteredGauge("blobpool/oversized/dataused", nil) // Tracks the used data size of oversized transactions.
	// oversizedDatausedGauge 跟踪超大交易的已用数据大小。
	oversizedDatagapsGauge = metrics.NewRegisteredGauge("blobpool/oversized/datagaps", nil) // Tracks the data gaps of oversized transactions.
	// oversizedDatagapsGauge 跟踪超大交易的数据间隙。
	oversizedSlotusedGauge = metrics.NewRegisteredGauge("blobpool/oversized/slotused", nil) // Tracks the number of used slots for oversized transactions.
	// oversizedSlotusedGauge 跟踪超大交易的已用槽位数量。
	oversizedSlotgapsGauge = metrics.NewRegisteredGauge("blobpool/oversized/slotgaps", nil) // Tracks the slot gaps for oversized transactions.
	// oversizedSlotgapsGauge 跟踪超大交易的槽位间隙。

	// basefeeGauge and blobfeeGauge track the current network 1559 base fee and
	// 4844 blob fee respectively.
	// basefeeGauge 和 blobfeeGauge 分别跟踪当前网络的 1559 基础费用和 4844 blob 费用。
	basefeeGauge = metrics.NewRegisteredGauge("blobpool/basefee", nil) // Tracks the current base fee of the network.
	// basefeeGauge 跟踪当前网络的基礎費用。
	blobfeeGauge = metrics.NewRegisteredGauge("blobpool/blobfee", nil) // Tracks the current blob fee of the network.
	// blobfeeGauge 跟踪当前网络的 blob 費用。

	// pooltipGauge is the configurable miner tip to permit a transaction into
	// the pool.
	// pooltipGauge 是可配置的矿工小费，用于允许交易进入池中。
	pooltipGauge = metrics.NewRegisteredGauge("blobpool/pooltip", nil) // Tracks the configured miner tip for the blob pool.
	// pooltipGauge 跟踪为 blob 池配置的矿工小费。

	// addwait/time, resetwait/time and getwait/time track the rough health of
	// the pool and whether it's capable of keeping up with the load from the
	// network.
	// addwait/time、resetwait/time 和 getwait/time 跟踪池的大致健康状况以及它是否能够跟上网络的负载。
	addwaitHist = metrics.NewRegisteredHistogram("blobpool/addwait", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent waiting to add a transaction.
	// addwaitHist 添加交易等待时间的直方图。
	addtimeHist = metrics.NewRegisteredHistogram("blobpool/addtime", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent actually adding a transaction.
	// addtimeHist 实际添加交易花费时间的直方图。
	getwaitHist = metrics.NewRegisteredHistogram("blobpool/getwait", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent waiting to get a transaction.
	// getwaitHist 获取交易等待时间的直方图。
	gettimeHist = metrics.NewRegisteredHistogram("blobpool/gettime", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent actually getting a transaction.
	// gettimeHist 实际获取交易花费时间的直方图。
	pendwaitHist = metrics.NewRegisteredHistogram("blobpool/pendwait", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent waiting for pending transactions.
	// pendwaitHist 等待挂起交易花费时间的直方图。
	pendtimeHist = metrics.NewRegisteredHistogram("blobpool/pendtime", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent processing pending transactions.
	// pendtimeHist 处理挂起交易花费时间的直方图。
	resetwaitHist = metrics.NewRegisteredHistogram("blobpool/resetwait", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent waiting to reset the pool.
	// resetwaitHist 等待重置池花费时间的直方图。
	resettimeHist = metrics.NewRegisteredHistogram("blobpool/resettime", nil, metrics.NewExpDecaySample(1028, 0.015)) // Histogram of time spent actually resetting the pool.
	// resettimeHist 实际重置池花费时间的直方图。

	// The below metrics track various cases where transactions are dropped out
	// of the pool. Most are exceptional, some are chain progression and some
	// threshold cappings.
	// 下面的指标跟踪交易从池中删除的各种情况。大多数是异常情况，一些是链进展，一些是阈值上限。
	dropInvalidMeter = metrics.NewRegisteredMeter("blobpool/drop/invalid", nil) // Invalid transaction, consensus change or bugfix, neutral-ish
	// dropInvalidMeter 无效交易，共识更改或错误修复导致的丢弃计数器，中性。
	dropDanglingMeter = metrics.NewRegisteredMeter("blobpool/drop/dangling", nil) // First nonce gapped, bad
	// dropDanglingMeter 第一个 nonce 出现间隙导致的丢弃计数器，不良。
	dropFilledMeter = metrics.NewRegisteredMeter("blobpool/drop/filled", nil) // State full-overlap, chain progress, ok
	// dropFilledMeter 状态完全重叠，链进展导致的丢弃计数器，正常。
	dropOverlappedMeter = metrics.NewRegisteredMeter("blobpool/drop/overlapped", nil) // State partial-overlap, chain progress, ok
	// dropOverlappedMeter 状态部分重叠，链进展导致的丢弃计数器，正常。
	dropRepeatedMeter = metrics.NewRegisteredMeter("blobpool/drop/repeated", nil) // Repeated nonce, bad
	// dropRepeatedMeter 重复 nonce 导致的丢弃计数器，不良。
	dropGappedMeter = metrics.NewRegisteredMeter("blobpool/drop/gapped", nil) // Non-first nonce gapped, bad
	// dropGappedMeter 非第一个 nonce 出现间隙导致的丢弃计数器，不良。
	dropOverdraftedMeter = metrics.NewRegisteredMeter("blobpool/drop/overdrafted", nil) // Balance exceeded, bad
	// dropOverdraftedMeter 余额不足导致的丢弃计数器，不良。
	dropOvercappedMeter = metrics.NewRegisteredMeter("blobpool/drop/overcapped", nil) // Per-account cap exceeded, bad
	// dropOvercappedMeter 超出每个账户的上限导致的丢弃计数器，不良。
	dropOverflownMeter = metrics.NewRegisteredMeter("blobpool/drop/overflown", nil) // Global disk cap exceeded, neutral-ish
	// dropOverflownMeter 超出全局磁盘上限导致的丢弃计数器，中性。
	dropUnderpricedMeter = metrics.NewRegisteredMeter("blobpool/drop/underpriced", nil) // Gas tip changed, neutral
	// dropUnderpricedMeter Gas 小费变化导致的丢弃计数器，中性。
	dropReplacedMeter = metrics.NewRegisteredMeter("blobpool/drop/replaced", nil) // Transaction replaced, neutral
	// dropReplacedMeter 交易被替换导致的丢弃计数器，中性。

	// The below metrics track various outcomes of transactions being added to
	// the pool.
	// 下面的指标跟踪交易添加到池中的各种结果。
	addInvalidMeter = metrics.NewRegisteredMeter("blobpool/add/invalid", nil) // Invalid transaction, reject, neutral
	// addInvalidMeter 无效交易，拒绝计数器，中性。
	addUnderpricedMeter = metrics.NewRegisteredMeter("blobpool/add/underpriced", nil) // Gas tip too low, neutral
	// addUnderpricedMeter Gas 小费过低，中性。
	addStaleMeter = metrics.NewRegisteredMeter("blobpool/add/stale", nil) // Nonce already filled, reject, bad-ish
	// addStaleMeter Nonce 已被填充，拒绝计数器，不良。
	addGappedMeter = metrics.NewRegisteredMeter("blobpool/add/gapped", nil) // Nonce gapped, reject, bad-ish
	// addGappedMeter Nonce 出现间隙，拒绝计数器，不良。
	addOverdraftedMeter = metrics.NewRegisteredMeter("blobpool/add/overdrafted", nil) // Balance exceeded, reject, neutral
	// addOverdraftedMeter 余额不足，拒绝计数器，中性。
	addOvercappedMeter = metrics.NewRegisteredMeter("blobpool/add/overcapped", nil) // Per-account cap exceeded, reject, neutral
	// addOvercappedMeter 超出每个账户的上限，拒绝计数器，中性。
	addNoreplaceMeter = metrics.NewRegisteredMeter("blobpool/add/noreplace", nil) // Replacement fees or tips too low, neutral
	// addNoreplaceMeter 替换费用或小费过低，中性。
	addNonExclusiveMeter = metrics.NewRegisteredMeter("blobpool/add/nonexclusive", nil) // Plain transaction from same account exists, reject, neutral
	// addNonExclusiveMeter 同一账户已存在普通交易，拒绝计数器，中性。
	addValidMeter = metrics.NewRegisteredMeter("blobpool/add/valid", nil) // Valid transaction, add, neutral
	// addValidMeter 有效交易，添加计数器，中性。
)
