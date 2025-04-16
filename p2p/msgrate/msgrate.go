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

// Package msgrate allows estimating the throughput of peers for more balanced syncs.
package msgrate

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// 在以太坊 P2P 网络中（如 eth 或 snap 协议），容量表示如区块头或账户范围的传输能力，与带宽和延迟密切相关。

// measurementImpact is the impact a single measurement has on a peer's final
// capacity value. A value closer to 0 reacts slower to sudden network changes,
// but it is also more stable against temporary hiccups. 0.1 worked well for
// most of Ethereum's existence, so might as well go with it.
//
// measurementImpact 是单次测量对对等节点最终容量值的影响。
// 接近 0 的值对突发网络变化反应较慢，但对临时小故障更稳定。
// 0.1 在以太坊的大部分时间里表现良好，因此可以继续使用。
const measurementImpact = 0.1

// capacityOverestimation is the ratio of items to over-estimate when retrieving
// a peer's capacity to avoid locking into a lower value due to never attempting
// to fetch more than some local stable value.
//
// capacityOverestimation 是检索对等节点容量时过度估计的项目比率，
// 以避免因从未尝试获取超出本地稳定值的内容而锁定在较低值。
const capacityOverestimation = 1.01

// rttMinEstimate is the minimal round trip time to target requests for. Since
// every request entails a 2 way latency + bandwidth + serving database lookups,
// it should be generous enough to permit meaningful work to be done on top of
// the transmission costs.
//
// rttMinEstimate 是请求目标的最小往返时间。
// 由于每个请求涉及双向延迟 + 带宽 + 服务数据库查询，
// 它应足够宽松，以允许在传输成本之上完成有意义的工作。
const rttMinEstimate = 2 * time.Second

// rttMaxEstimate is the maximal round trip time to target requests for. Although
// the expectation is that a well connected node will never reach this, certain
// special connectivity ones might experience significant delays (e.g. satellite
// uplink with 3s RTT). This value should be low enough to forbid stalling the
// pipeline too long, but large enough to cover the worst of the worst links.
//
// rttMaxEstimate 是请求目标的最大往返时间。
// 虽然期望良好连接的节点不会达到此值，但某些特殊连接（例如卫星上行链路，3秒 RTT）可能会出现显著延迟。
// 此值应足够低以避免管道长时间停滞，但足够大以覆盖最差的链接。
const rttMaxEstimate = 20 * time.Second

// rttPushdownFactor is a multiplier to attempt forcing quicker requests than
// what the message rate tracker estimates. The reason is that message rate
// tracking adapts queries to the RTT, but multiple RTT values can be perfectly
// valid, they just result in higher packet sizes. Since smaller packets almost
// always result in stabler download streams, this factor hones in on the lowest
// RTT from all the functional ones.
//
// rttPushdownFactor 是一个乘数，尝试强制执行比消息速率跟踪器估计更快的请求。
// 原因是消息速率跟踪根据 RTT 调整查询，但多个 RTT 值可能完全有效，只是导致更大的数据包。
// 由于较小的数据包几乎总是带来更稳定的下载流，此因子专注于所有功能性 RTT 中的最低值。
const rttPushdownFactor = 0.9

// rttMinConfidence is the minimum value the roundtrip confidence factor may drop
// to. Since the target timeouts are based on how confident the tracker is in the
// true roundtrip, it's important to not allow too huge fluctuations.
//
// rttMinConfidence 是往返置信因子可能下降到的最小值。
// 由于目标超时基于跟踪器对真实往返时间的置信度，重要的是不允许过大波动。
const rttMinConfidence = 0.1

// ttlScaling is the multiplier that converts the estimated roundtrip time to a
// timeout cap for network requests. The expectation is that peers' response time
// will fluctuate around the estimated roundtrip, but depending in their load at
// request time, it might be higher than anticipated. This scaling factor ensures
// that we allow remote connections some slack but at the same time do enforce a
// behavior similar to our median peers.
//
// ttlScaling 是将估计的往返时间转换为网络请求超时上限的乘数。
// 期望对等节点的响应时间会在估计的往返时间附近波动，但根据请求时的负载，可能会高于预期。
// 此缩放因子确保我们为远程连接留出一些余地，同时强制执行与中位数对等节点相似的行为。
const ttlScaling = 3

// ttlLimit is the maximum timeout allowance to prevent reaching crazy numbers
// if some unforeseen network events happen. As much as we try to hone in on
// the most optimal values, it doesn't make any sense to go above a threshold,
// even if everything is slow and screwy.
//
// ttlLimit 是最大超时允许值，以防止在发生不可预见的网络事件时达到疯狂的数字。
// 尽管我们尽力优化最优值，但超过阈值没有意义，即使一切都很慢且混乱。
const ttlLimit = time.Minute

// tuningConfidenceCap is the number of active peers above which to stop detuning
// the confidence number. The idea here is that once we hone in on the capacity
// of a meaningful number of peers, adding one more should ot have a significant
// impact on things, so just ron with the originals.
//
// tuningConfidenceCap 是活动对等节点数量的上限，超过此值时停止降低置信度。
// 这里的想法是，一旦我们确定了足够数量的对等节点容量，再添加一个不应对事情产生重大影响，因此继续使用原始值。
const tuningConfidenceCap = 10

// tuningImpact is the influence that a new tuning target has on the previously
// cached value. This number is mostly just an out-of-the-blue heuristic that
// prevents the estimates from jumping around. There's no particular reason for
// the current value.
//
// tuningImpact 是新调优目标对之前缓存值的影响。
// 这个数字主要是一个凭空得出的启发式值，防止估计值跳跃。目前的值没有特别的理由。
const tuningImpact = 0.25

// Tracker estimates the throughput capacity of a peer with regard to each data
// type it can deliver. The goal is to dynamically adjust request sizes to max
// out network throughput without overloading either the peer or the local node.
//
// By tracking in real time the latencies and bandwidths peers exhibit for each
// packet type, it's possible to prevent overloading by detecting a slowdown on
// one type when another type is pushed too hard.
//
// Similarly, real time measurements also help avoid overloading the local net
// connection if our peers would otherwise be capable to deliver more, but the
// local link is saturated. In that case, the live measurements will force us
// to reduce request sizes until the throughput gets stable.
//
// Lastly, message rate measurements allows us to detect if a peer is unusually
// slow compared to other peers, in which case we can decide to keep it around
// or free up the slot so someone closer.
//
// Since throughput tracking and estimation adapts dynamically to live network
// conditions, it's fine to have multiple trackers locally track the same peer
// in different subsystem. The throughput will simply be distributed across the
// two trackers if both are highly active.
//
// Tracker 估计对等节点针对其可传递的每种数据类型的吞吐量容量。
// 目标是动态调整请求大小，以最大化网络吞吐量，同时不超载对等节点或本地节点。
//
// 通过实时跟踪对等节点对每种数据包类型展示的延迟和带宽，可以通过检测一种类型在另一种类型被过度推送时的减速来防止超载。
//
// 同样，实时测量还有助于避免本地网络连接超载，如果我们的对等节点原本能够提供更多，但本地链接已饱和。
// 在这种情况下，实时测量将迫使我们减小请求大小，直到吞吐量稳定。
//
// 最后，消息速率测量允许我们检测对等节点是否比其他节点异常慢，在这种情况下，我们可以决定保留它或释放槽位给更近的节点。
//
// 由于吞吐量跟踪和估计动态适应实时网络条件，因此在本地有多个跟踪器在不同子系统中跟踪同一对等节点是没问题的。
// 如果两个跟踪器都高度活跃，吞吐量将简单地在两者之间分配。
type Tracker struct {
	// capacity is the number of items retrievable per second of a given type.
	// It is analogous to bandwidth, but we deliberately avoided using bytes
	// as the unit, since serving nodes also spend a lot of time loading data
	// from disk, which is linear in the number of items, but mostly constant
	// in their sizes.
	//
	// Callers of course are free to use the item counter as a byte counter if
	// or when their protocol of choice if capped by bytes instead of items.
	// (eg. eth.getHeaders vs snap.getAccountRange).
	//
	// capacity 是每秒可检索的给定类型的项目数。
	// 它类似于带宽，但我们故意避免使用字节作为单位，因为服务节点还花费大量时间从磁盘加载数据，
	// 这与项目数量成线性关系，但大小大多是恒定的。
	//
	// 调用者当然可以自由将项目计数器用作字节计数器，如果他们选择的协议受字节而非项目限制。
	// （例如 eth.getHeaders 与 snap.getAccountRange）。
	capacity map[uint64]float64

	// roundtrip is the latency a peer in general responds to data requests.
	// This number is not used inside the tracker, but is exposed to compare
	// peers to each other and filter out slow ones. Note however, it only
	// makes sense to compare RTTs if the caller caters request sizes for
	// each peer to target the same RTT. There's no need to make this number
	// the real networking RTT, we just need a number to compare peers with.
	//
	// roundtrip 是对等节点通常响应数据请求的延迟。
	// 这个数字不在跟踪器内部使用，而是暴露出来以比较对等节点并过滤慢速节点。
	// 但需要注意的是，只有在调用者为每个对等节点调整请求大小以目标相同 RTT 时比较 RTT 才有意义。
	// 无需使此数字成为真实的网络 RTT，我们只需要一个用于比较对等节点的数字。
	roundtrip time.Duration

	lock sync.RWMutex // 读写锁 // Read-write mutex
}

// NewTracker creates a new message rate tracker for a specific peer. An initial
// RTT is needed to avoid a peer getting marked as an outlier compared to others
// right after joining. It's suggested to use the median rtt across all peers to
// init a new peer tracker.
//
// NewTracker 为特定对等节点创建一个新的消息速率跟踪器。
// 需要一个初始 RTT，以避免新加入的对等节点与其他节点相比立即被标记为异常值。
// 建议使用所有对等节点的中位 RTT 来初始化新对等节点跟踪器。
func NewTracker(caps map[uint64]float64, rtt time.Duration) *Tracker {
	if caps == nil { // 如果容量为空 // If capacity is nil
		caps = make(map[uint64]float64) // 初始化容量映射 // Initialize capacity map
	}
	return &Tracker{
		capacity:  caps, // 设置初始容量
		roundtrip: rtt,  // 设置初始往返时间
	}
}

// Capacity calculates the number of items the peer is estimated to be able to
// retrieve within the allotted time slot. The method will round up any division
// errors and will add an additional overestimation ratio on top. The reason for
// overshooting the capacity is because certain message types might not increase
// the load proportionally to the requested items, so fetching a bit more might
// still take the same RTT. By forcefully overshooting by a small amount, we can
// avoid locking into a lower-that-real capacity.
//
// Capacity 计算对等节点在分配的时间段内估计能够检索的项目数。
// 该方法将向上取整任何除法误差，并额外添加一个过度估计比率。
// 过度估计容量的原因是某些消息类型可能不会按请求项目比例增加负载，因此多获取一些可能仍需相同 RTT。
// 通过强制少量过度估计，我们可以避免锁定在低于真实容量的值。
func (t *Tracker) Capacity(kind uint64, targetRTT time.Duration) int {
	t.lock.RLock()         // 读锁
	defer t.lock.RUnlock() // 延迟解锁

	// Calculate the actual measured throughput
	// 计算实际测量的吞吐量
	throughput := t.capacity[kind] * float64(targetRTT) / float64(time.Second)

	// Return an overestimation to force the peer out of a stuck minima, adding
	// +1 in case the item count is too low for the overestimator to dent
	//
	// 返回过度估计值以强制对等节点脱离局部最小值，添加 +1 以防项目数太低而过度估计不起作用
	return roundCapacity(1 + capacityOverestimation*throughput)
}

// roundCapacity gives the integer value of a capacity.
// The result fits int32, and is guaranteed to be positive.
//
// roundCapacity 给出容量的整数值。
// 结果适合 int32，并保证为正数。
func roundCapacity(cap float64) int {
	const maxInt32 = float64(1<<31 - 1)                         // 最大 int32 值
	return int(math.Min(maxInt32, math.Max(1, math.Ceil(cap)))) // 返回取整后的容量
}

// Update modifies the peer's capacity values for a specific data type with a new
// measurement. If the delivery is zero, the peer is assumed to have either timed
// out or to not have the requested data, resulting in a slash to 0 capacity. This
// avoids assigning the peer retrievals that it won't be able to honour.
//
// Update 使用新测量值修改对等节点特定数据类型的容量值。
// 如果交付为零，则假设对等节点超时或没有请求的数据，导致容量降为 0。
// 这避免为对等节点分配其无法完成的检索任务。
func (t *Tracker) Update(kind uint64, elapsed time.Duration, items int) {
	t.lock.Lock()         // 写锁
	defer t.lock.Unlock() // 延迟解锁

	// If nothing was delivered (timeout / unavailable data), reduce throughput
	// to minimum
	// 如果没有交付任何内容（超时/数据不可用），将吞吐量降至最低
	if items == 0 {
		t.capacity[kind] = 0 // 设置容量为 0
		return
	}
	// Otherwise update the throughput with a new measurement
	// 否则使用新测量值更新吞吐量
	if elapsed <= 0 { // 如果经过时间为 0 或负值
		elapsed = 1 // 设置为 1 纳秒以确保非零除数
	}
	measured := float64(items) / (float64(elapsed) / float64(time.Second)) // 计算测量吞吐量

	t.capacity[kind] = (1-measurementImpact)*(t.capacity[kind]) + measurementImpact*measured                     // 更新容量
	t.roundtrip = time.Duration((1-measurementImpact)*float64(t.roundtrip) + measurementImpact*float64(elapsed)) // 更新往返时间
}

// Trackers is a set of message rate trackers across a number of peers with the
// goal of aggregating certain measurements across the entire set for outlier
// filtering and newly joining initialization.
//
// Trackers 是一组跨多个对等节点的消息速率跟踪器，
// 目标是聚合整个集合的某些测量值，用于异常值过滤和新加入节点的初始化。
type Trackers struct {
	trackers map[string]*Tracker // 对等节点跟踪器映射

	// roundtrip is the current best guess as to what is a stable round trip time
	// across the entire collection of connected peers. This is derived from the
	// various trackers added, but is used as a cache to avoid recomputing on each
	// network request. The value is updated once every RTT to avoid fluctuations
	// caused by hiccups or peer events.
	//
	// roundtrip 是当前对所有连接对等节点的稳定往返时间的最佳猜测。
	// 它从添加的各种跟踪器中派生，但用作缓存以避免在每次网络请求时重新计算。
	// 该值每 RTT 更新一次，以避免因小故障或对等节点事件引起的波动。
	roundtrip time.Duration

	// confidence represents the probability that the estimated roundtrip value
	// is the real one across all our peers. The confidence value is used as an
	// impact factor of new measurements on old estimates. As our connectivity
	// stabilizes, this value gravitates towards 1, new measurements having
	// almost no impact. If there's a large peer churn and few peers, then new
	// measurements will impact it more. The confidence is increased with every
	// packet and dropped with every new connection.
	//
	// confidence 表示估计的往返时间值是我们所有对等节点的真实值的概率。
	// 置信值用作新测量对旧估计的影响因子。
	// 随着连接稳定，此值趋向于 1，新测量几乎没有影响。
	// 如果对等节点变动大且数量少，则新测量影响更大。
	// 置信度随每个数据包增加，随每个新连接下降。
	confidence float64

	// tuned is the time instance the tracker recalculated its cached roundtrip
	// value and confidence values. A cleaner way would be to have a heartbeat
	// goroutine do it regularly, but that requires a lot of maintenance to just
	// run every now and again.
	//
	// tuned 是跟踪器重新计算其缓存往返时间值和置信值的时间实例。
	// 更干净的方法是让心跳 goroutine 定期执行，但这需要大量维护才能偶尔运行。
	tuned time.Time

	// The fields below can be used to override certain default values. Their
	// purpose is to allow quicker tests. Don't use them in production.
	//
	// 以下字段可用于覆盖某些默认值。
	// 它们的目的是允许更快的测试。不要在生产中使用。
	OverrideTTLLimit time.Duration

	log  log.Logger   // 日志记录器
	lock sync.RWMutex // 读写锁
}

// NewTrackers creates an empty set of trackers to be filled with peers.
// NewTrackers 创建一个空的跟踪器集，以填充对等节点。
func NewTrackers(log log.Logger) *Trackers {
	return &Trackers{
		trackers:         make(map[string]*Tracker), // 初始化跟踪器映射 // Initialize tracker map
		roundtrip:        rttMaxEstimate,            // 设置初始往返时间为最大估计 // Set initial roundtrip to max estimate
		confidence:       1,                         // 设置初始置信度为 1 // Set initial confidence to 1
		tuned:            time.Now(),                // 设置初始调优时间 // Set initial tuning time
		OverrideTTLLimit: ttlLimit,                  // 设置超时限制 // Set timeout limit
		log:              log,                       // 设置日志记录器 // Set logger
	}
}

// Track inserts a new tracker into the set.
// Track 将新跟踪器插入集合中。
func (t *Trackers) Track(id string, tracker *Tracker) error {
	t.lock.Lock()         // 写锁 // Write lock
	defer t.lock.Unlock() // 延迟解锁 // Deferred unlock

	if _, ok := t.trackers[id]; ok { // 如果已存在 // If already exists
		return errors.New("already tracking") // 返回错误 // Return error
	}
	t.trackers[id] = tracker // 添加跟踪器 // Add tracker
	t.detune()               // 降低置信度 // Detune confidence

	return nil
}

// Untrack stops tracking a previously added peer.
// Untrack 停止跟踪之前添加的对等节点。
func (t *Trackers) Untrack(id string) error {
	t.lock.Lock()         // 写锁 // Write lock
	defer t.lock.Unlock() // 延迟解锁 // Deferred unlock

	if _, ok := t.trackers[id]; !ok { // 如果不存在 // If not exists
		return errors.New("not tracking") // 返回错误 // Return error
	}
	delete(t.trackers, id) // 删除跟踪器 // Delete tracker
	return nil
}

// MedianRoundTrip returns the median RTT across all known trackers. The purpose
// of the median RTT is to initialize a new peer with sane statistics that it will
// hopefully outperform. If it seriously underperforms, there's a risk of dropping
// the peer, but that is ok as we're aiming for a strong median.
// MedianRoundTrip 返回所有已知跟踪器的中位 RTT。
// 中位 RTT 的目的是为新对等节点初始化合理的统计数据，希望它能超越此值。
// 如果表现严重不足，可能有丢弃对等节点的风险，但这是可以接受的，因为我们目标是强劲的中位数。
func (t *Trackers) MedianRoundTrip() time.Duration {
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	return t.medianRoundTrip() // 返回中位 RTT // Return median RTT
}

// medianRoundTrip is the internal lockless version of MedianRoundTrip to be used
// by the QoS tuner.
// medianRoundTrip 是 MedianRoundTrip 的内部无锁版本，供 QoS 调优器使用。
func (t *Trackers) medianRoundTrip() time.Duration {
	// Gather all the currently measured round trip times
	// 收集所有当前测量的往返时间
	rtts := make([]float64, 0, len(t.trackers))
	for _, tt := range t.trackers {
		tt.lock.RLock()                            // 读锁 // Read lock
		rtts = append(rtts, float64(tt.roundtrip)) // 添加 RTT // Add RTT
		tt.lock.RUnlock()                          // 解锁 // Unlock
	}
	sort.Float64s(rtts) // 排序 // Sort

	var median time.Duration
	switch len(rtts) {
	case 0: // 如果没有 RTT // If no RTTs
		median = rttMaxEstimate // 使用最大估计 // Use max estimate
	case 1: // 如果只有一个 RTT // If only one RTT
		median = time.Duration(rtts[0]) // 使用该值 // Use that value
	default: // 如果有多个 RTT // If multiple RTTs
		idx := int(math.Sqrt(float64(len(rtts)))) // 计算中位索引 // Calculate median index
		median = time.Duration(rtts[idx])         // 使用中位值 // Use median value
	}
	// Restrict the RTT into some QoS defaults, irrelevant of true RTT
	// 将 RTT 限制在某些 QoS 默认值内，与真实 RTT 无关
	if median < rttMinEstimate { // 如果低于最小估计 // If below min estimate
		median = rttMinEstimate // 使用最小估计 // Use min estimate
	}
	if median > rttMaxEstimate { // 如果高于最大估计 // If above max estimate
		median = rttMaxEstimate // 使用最大估计 // Use max estimate
	}
	return median
}

// MeanCapacities returns the capacities averaged across all the added trackers.
// The purpose of the mean capacities are to initialize a new peer with some sane
// starting values that it will hopefully outperform. If the mean overshoots, the
// peer will be cut back to minimal capacity and given another chance.
// MeanCapacities 返回所有添加跟踪器的平均容量。
// 平均容量的目的是为新对等节点初始化一些合理的起始值，希望它能超越此值。
// 如果平均值过高，对等节点将被削减到最小容量并给予另一次机会。
func (t *Trackers) MeanCapacities() map[uint64]float64 {
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	return t.meanCapacities() // 返回平均容量 // Return mean capacities
}

// meanCapacities is the internal lockless version of MeanCapacities used for
// debug logging.
// meanCapacities 是 MeanCapacities 的内部无锁版本，用于调试日志。
func (t *Trackers) meanCapacities() map[uint64]float64 {
	capacities := make(map[uint64]float64, len(t.trackers)) // 初始化容量映射 // Initialize capacity map
	for _, tt := range t.trackers {
		tt.lock.RLock()                     // 读锁 // Read lock
		for key, val := range tt.capacity { // 累加容量 // Accumulate capacity
			capacities[key] += val
		}
		tt.lock.RUnlock() // 解锁 // Unlock
	}
	for key, val := range capacities { // 计算平均值 // Calculate average
		capacities[key] = val / float64(len(t.trackers))
	}
	return capacities
}

// TargetRoundTrip returns the current target round trip time for a request to
// complete in.The returned RTT is slightly under the estimated RTT. The reason
// is that message rate estimation is a 2 dimensional problem which is solvable
// for any RTT. The goal is to gravitate towards smaller RTTs instead of large
// messages, to result in a stabler download stream.
// TargetRoundTrip 返回请求完成的当前目标往返时间。
// 返回的 RTT 略低于估计的 RTT。
// 原因是消息速率估计是一个二维问题，对任何 RTT 都可解。
// 目标是趋向于较小的 RTT 而不是大消息，以获得更稳定的下载流。
func (t *Trackers) TargetRoundTrip() time.Duration {
	// Recalculate the internal caches if it's been a while
	// 如果一段时间未更新，重新计算内部缓存
	t.tune()

	// Caches surely recent, return target roundtrip
	// 缓存肯定是最新的，返回目标往返时间
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	return time.Duration(float64(t.roundtrip) * rttPushdownFactor) // 返回调整后的 RTT // Return adjusted RTT
}

// TargetTimeout returns the timeout allowance for a single request to finish
// under. The timeout is proportional to the roundtrip, but also takes into
// consideration the tracker's confidence in said roundtrip and scales it
// accordingly. The final value is capped to avoid runaway requests.
// TargetTimeout 返回单个请求完成所需的超时允许值。
// 超时与往返时间成正比，但还考虑了跟踪器对该往返时间的置信度并相应缩放。
// 最终值被限制以避免失控请求。
func (t *Trackers) TargetTimeout() time.Duration {
	// Recalculate the internal caches if it's been a while
	// 如果一段时间未更新，重新计算内部缓存
	t.tune()

	// Caches surely recent, return target timeout
	// 缓存肯定是最新的，返回目标超时
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	return t.targetTimeout() // 返回目标超时 // Return target timeout
}

// targetTimeout is the internal lockless version of TargetTimeout to be used
// during QoS tuning.
// targetTimeout 是 TargetTimeout 的内部无锁版本，供 QoS 调优期间使用。
func (t *Trackers) targetTimeout() time.Duration {
	timeout := time.Duration(ttlScaling * float64(t.roundtrip) / t.confidence) // 计算超时 // Calculate timeout
	if timeout > t.OverrideTTLLimit {                                          // 如果超过限制 // If exceeds limit
		timeout = t.OverrideTTLLimit // 使用限制值 // Use limit value
	}
	return timeout
}

// tune gathers the individual tracker statistics and updates the estimated
// request round trip time.
// tune 收集各个跟踪器的统计数据并更新估计的请求往返时间。
func (t *Trackers) tune() {
	// Tune may be called concurrently all over the place, but we only want to
	// periodically update and even then only once. First check if it was updated
	// recently and abort if so.
	// tune 可能在各处并发调用，但我们只想定期更新，甚至只更新一次。
	// 首先检查是否最近更新过，如果是则中止。
	t.lock.RLock()                             // 读锁 // Read lock
	dirty := time.Since(t.tuned) > t.roundtrip // 检查是否需要更新 // Check if update is needed
	t.lock.RUnlock()                           // 解锁 // Unlock
	if !dirty {
		return
	}
	// If an update is needed, obtain a write lock but make sure we don't update
	// it on all concurrent threads one by one.
	// 如果需要更新，获取写锁，但确保不会在所有并发线程上逐一更新。
	t.lock.Lock()         // 写锁 // Write lock
	defer t.lock.Unlock() // 延迟解锁 // Deferred unlock

	if dirty := time.Since(t.tuned) > t.roundtrip; !dirty { // 再次检查 // Double check
		return // 并发请求已完成调优 // Concurrent request beat us to tuning
	}
	// First thread reaching the tuning point, update the estimates and return
	// 第一个到达调优点程，更新估计并返回
	t.roundtrip = time.Duration((1-tuningImpact)*float64(t.roundtrip) + tuningImpact*float64(t.medianRoundTrip())) // 更新 RTT // Update RTT
	t.confidence = t.confidence + (1-t.confidence)/2                                                               // 更新置信度 // Update confidence

	t.tuned = time.Now()                                                                                                                                       // 更新调优时间 // Update tuning time
	t.log.Debug("Recalculated msgrate QoS values", "rtt", t.roundtrip, "confidence", t.confidence, "ttl", t.targetTimeout(), "next", t.tuned.Add(t.roundtrip)) // 记录日志 // Log
	if t.log.Enabled(context.Background(), log.LevelTrace) {                                                                                                   // 如果跟踪日志启用 // If trace logging enabled
		t.log.Trace("Debug dump of mean capacities", "caps", t.meanCapacities()) // 记录平均容量 // Log mean capacities
	}
}

// detune reduces the tracker's confidence in order to make fresh measurements
// have a larger impact on the estimates. It is meant to be used during new peer
// connections so they can have a proper impact on the estimates.
// detune 降低跟踪器的置信度，以使新测量对估计产生更大影响。
// 它旨在在新对等节点连接时使用，以便它们对估计产生适当影响。
func (t *Trackers) detune() {
	// If we have a single peer, confidence is always 1
	// 如果只有一个对等节点，置信度始终为 1
	if len(t.trackers) == 1 {
		t.confidence = 1
		return
	}
	// If we have a ton of peers, don't drop the confidence since there's enough
	// remaining to retain the same throughput
	// 如果对等节点数量很多，不降低置信度，因为剩余的足够维持相同吞吐量
	if len(t.trackers) >= tuningConfidenceCap {
		return
	}
	// Otherwise drop the confidence factor
	// 否则降低置信因子
	peers := float64(len(t.trackers))

	t.confidence = t.confidence * (peers - 1) / peers // 降低置信度 // Reduce confidence
	if t.confidence < rttMinConfidence {              // 如果低于最小值 // If below minimum
		t.confidence = rttMinConfidence // 设置为最小值 // Set to minimum
	}
	t.log.Debug("Relaxed msgrate QoS values", "rtt", t.roundtrip, "confidence", t.confidence, "ttl", t.targetTimeout()) // 记录日志 // Log
}

// Capacity is a helper function to access a specific tracker without having to
// track it explicitly outside.
// Capacity 是一个辅助函数，用于访问特定跟踪器而无需在外部显式跟踪。
func (t *Trackers) Capacity(id string, kind uint64, targetRTT time.Duration) int {
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	tracker := t.trackers[id] // 获取跟踪器 // Get tracker
	if tracker == nil {       // 如果不存在 // If not exists
		return 1 // 返回 1，避免危险的 0 值 // Return 1 to avoid dangerous 0
	}
	return tracker.Capacity(kind, targetRTT) // 返回容量 // Return capacity
}

// Update is a helper function to access a specific tracker without having to
// track it explicitly outside.
// Update 是一个辅助函数，用于访问特定跟踪器而无需在外部显式跟踪。
func (t *Trackers) Update(id string, kind uint64, elapsed time.Duration, items int) {
	t.lock.RLock()         // 读锁 // Read lock
	defer t.lock.RUnlock() // 延迟解锁 // Deferred unlock

	if tracker := t.trackers[id]; tracker != nil { // 如果跟踪器存在 // If tracker exists
		tracker.Update(kind, elapsed, items) // 更新跟踪器 // Update tracker
	}
}
