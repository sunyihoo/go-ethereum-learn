// Hook go-metrics into expvar
// 将 go-metrics 挂钩到 expvar
// on any /debug/metrics request, load all vars from the registry into expvar, and execute regular expvar handler
// 对于任何 /debug/metrics 请求，将所有变量从注册表加载到 expvar 中，并执行常规的 expvar 处理程序

package exp

import (
	"expvar" // Go 标准库，用于导出变量以供 HTTP 监控
	"fmt"
	"net/http" // Go 标准库，用于 HTTP 客户端和服务器实现
	"sync"     // Go 标准库，提供基本的同步原语，如互斥锁

	"github.com/ethereum/go-ethereum/log"                // Go-ethereum 的日志库
	"github.com/ethereum/go-ethereum/metrics"            // Go-ethereum 的核心指标库
	"github.com/ethereum/go-ethereum/metrics/prometheus" // Go-ethereum 指标库与 Prometheus 的集成
)

// exp struct holds the necessary components for exposing metrics via expvar.
// exp 结构体持有通过 expvar 暴露指标所需的必要组件。
type exp struct {
	// expvarLock sync.Mutex // expvar panics if you try to register the same var twice, so we must probe it safely
	// expvarLock sync.Mutex // 如果你尝试注册同一个变量两次，expvar 会发生 panic，所以我们必须安全地探测它
	// 用于保护对 expvar 注册表的并发访问，防止重复注册变量导致的 panic。
	expvarLock sync.Mutex

	// registry metrics.Registry
	// registry metrics.Registry // 指标注册表，存储所有由 go-ethereum/metrics 管理的指标。
	registry metrics.Registry
}

// expHandler is the HTTP handler function that serves metrics in expvar format.
// expHandler 是以 expvar 格式提供指标的 HTTP 处理函数。
func (exp *exp) expHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Synchronize metrics from the registry to expvar.
	// 1. 将指标从注册表同步到 expvar。
	// load our variables into expvar
	// 将我们的变量加载到 expvar 中
	exp.syncToExpvar()

	// 2. Execute the standard expvar handler logic (copied inline).
	// 2. 执行标准的 expvar 处理程序逻辑（内联复制）。
	// now just run the official expvar handler code (which is not publicly callable, so pasted inline)
	// 现在只需运行官方的 expvar 处理程序代码（该代码不是公开可调用的，因此内联粘贴）
	w.Header().Set("Content-Type", "application/json; charset=utf-8") // 设置响应头为 JSON
	fmt.Fprintf(w, "{\n")                                             // 开始 JSON 对象
	first := true
	// 3. Iterate through all variables registered with expvar.
	// 3. 遍历所有在 expvar 中注册的变量。
	expvar.Do(func(kv expvar.KeyValue) {
		if !first {
			fmt.Fprintf(w, ",\n") // 在变量之间添加逗号
		}
		first = false
		// 4. Format each key-value pair as JSON.
		// 4. 将每个键值对格式化为 JSON。
		fmt.Fprintf(w, "%q: %s", kv.Key, kv.Value) // 写入键（带引号）和值
	})
	fmt.Fprintf(w, "\n}\n") // 结束 JSON 对象
}

// Exp registers an expvar-powered metrics handler with http.DefaultServeMux on "/debug/metrics".
// Exp 使用 http.DefaultServeMux 在 "/debug/metrics" 路径上注册一个由 expvar 驱动的指标处理程序。
// It also registers a Prometheus handler at "/debug/metrics/prometheus".
// 它同时在 "/debug/metrics/prometheus" 路径上注册一个 Prometheus 处理程序。
func Exp(r metrics.Registry) {
	// Create the expvar handler using the provided registry.
	// 使用提供的注册表创建 expvar 处理程序。
	h := ExpHandler(r)
	// this would cause a panic:
	// 这会导致 panic：
	// panic: http: multiple registrations for /debug/vars
	// panic: http: /debug/vars 的多次注册
	// http.HandleFunc("/debug/vars", e.expHandler)
	// haven't found an elegant way, so just use a different endpoint
	// 还没有找到优雅的方法，所以就使用一个不同的端点
	// Register the expvar handler on a custom path to avoid conflict with the default "/debug/vars".
	// 在自定义路径上注册 expvar 处理程序，以避免与默认的 "/debug/vars" 冲突。
	http.Handle("/debug/metrics", h)
	// Register the Prometheus handler on its specific path.
	// 在其特定路径上注册 Prometheus 处理程序。
	http.Handle("/debug/metrics/prometheus", prometheus.Handler(r))
}

// ExpHandler creates and returns an expvar-powered metrics handler using the given registry.
// ExpHandler 使用给定的注册表创建并返回一个由 expvar 驱动的指标处理程序。
func ExpHandler(r metrics.Registry) http.Handler {
	// Initialize the exp struct with a mutex and the registry.
	// 使用互斥锁和注册表初始化 exp 结构体。
	e := exp{sync.Mutex{}, r}
	// Return an http.HandlerFunc that wraps the expHandler method.
	// 返回一个包装了 expHandler 方法的 http.HandlerFunc。
	return http.HandlerFunc(e.expHandler)
}

// Setup starts a dedicated HTTP server for metrics on the specified address.
// Setup 在指定的地址上启动一个专用的 HTTP 服务器用于提供指标。
// This allows separating metrics reporting from other HTTP services like pprof.
// 这允许将指标报告与其他 HTTP 服务（如 pprof）分开。
func Setup(address string) {
	// Create a new HTTP ServeMux to avoid interfering with the DefaultServeMux.
	// 创建一个新的 HTTP ServeMux 以避免干扰 DefaultServeMux。
	m := http.NewServeMux()
	// Register the expvar handler using the default metrics registry.
	// 使用默认的指标注册表注册 expvar 处理程序。
	m.Handle("/debug/metrics", ExpHandler(metrics.DefaultRegistry))
	// Register the Prometheus handler using the default metrics registry.
	// 使用默认的指标注册表注册 Prometheus 处理程序。
	m.Handle("/debug/metrics/prometheus", prometheus.Handler(metrics.DefaultRegistry))
	// Log the address where the metrics server is starting.
	// 记录指标服务器启动的地址。
	log.Info("Starting metrics server", "addr", fmt.Sprintf("http://%s/debug/metrics", address))
	// Start the HTTP server in a new goroutine.
	// 在一个新的 goroutine 中启动 HTTP 服务器。
	go func() {
		// ListenAndServe blocks until the server fails.
		// ListenAndServe 会阻塞直到服务器失败。
		if err := http.ListenAndServe(address, m); err != nil {
			// Log any error encountered while running the metrics server.
			// 记录运行指标服务器时遇到的任何错误。
			log.Error("Failure in running metrics server", "err", err)
		}
	}()
}

// getInt safely retrieves or creates an expvar.Int variable.
// getInt 安全地检索或创建一个 expvar.Int 变量。
// It uses expvarLock to prevent race conditions during access and registration.
// 它使用 expvarLock 来防止访问和注册过程中的竞态条件。
func (exp *exp) getInt(name string) *expvar.Int {
	var v *expvar.Int
	exp.expvarLock.Lock()         // Acquire lock
	defer exp.expvarLock.Unlock() // Ensure lock is released

	p := expvar.Get(name) // Try to get existing variable
	if p != nil {
		// If exists, assert its type to *expvar.Int
		// 如果存在，将其类型断言为 *expvar.Int
		v = p.(*expvar.Int)
	} else {
		// If not exists, create a new *expvar.Int
		// 如果不存在，创建一个新的 *expvar.Int
		v = new(expvar.Int)
		// Publish the new variable under the given name
		// 以给定名称发布新变量
		expvar.Publish(name, v)
	}
	return v
}

// getFloat safely retrieves or creates an expvar.Float variable.
// getFloat 安全地检索或创建一个 expvar.Float 变量。
// It uses expvarLock to prevent race conditions.
// 它使用 expvarLock 来防止竞态条件。
func (exp *exp) getFloat(name string) *expvar.Float {
	var v *expvar.Float
	exp.expvarLock.Lock()         // Acquire lock
	defer exp.expvarLock.Unlock() // Ensure lock is released

	p := expvar.Get(name) // Try to get existing variable
	if p != nil {
		// If exists, assert its type to *expvar.Float
		// 如果存在，将其类型断言为 *expvar.Float
		v = p.(*expvar.Float)
	} else {
		// If not exists, create a new *expvar.Float
		// 如果不存在，创建一个新的 *expvar.Float
		v = new(expvar.Float)
		// Publish the new variable
		// 发布新变量
		expvar.Publish(name, v)
	}
	return v
}

// getInfo safely retrieves or creates an expvar.String variable (used for GaugeInfo).
// getInfo 安全地检索或创建一个 expvar.String 变量（用于 GaugeInfo）。
// It uses expvarLock to prevent race conditions.
// 它使用 expvarLock 来防止竞态条件。
func (exp *exp) getInfo(name string) *expvar.String {
	var v *expvar.String
	exp.expvarLock.Lock()         // Acquire lock
	defer exp.expvarLock.Unlock() // Ensure lock is released

	p := expvar.Get(name) // Try to get existing variable
	if p != nil {
		// If exists, assert its type to *expvar.String
		// 如果存在，将其类型断言为 *expvar.String
		v = p.(*expvar.String)
	} else {
		// If not exists, create a new *expvar.String
		// 如果不存在，创建一个新的 *expvar.String
		v = new(expvar.String)
		// Publish the new variable
		// 发布新变量
		expvar.Publish(name, v)
	}
	return v
}

// publishCounter publishes a Counter metric snapshot to expvar as an Int.
// publishCounter 将 Counter 指标快照作为 Int 发布到 expvar。
func (exp *exp) publishCounter(name string, metric metrics.CounterSnapshot) {
	// Get or create the expvar.Int variable.
	// 获取或创建 expvar.Int 变量。
	v := exp.getInt(name)
	// Set its value to the counter's current count.
	// 将其值设置为计数器的当前计数值。
	v.Set(metric.Count())
}

// publishCounterFloat64 publishes a CounterFloat64 metric snapshot to expvar as a Float.
// publishCounterFloat64 将 CounterFloat64 指标快照作为 Float 发布到 expvar。
func (exp *exp) publishCounterFloat64(name string, metric metrics.CounterFloat64Snapshot) {
	// Get or create the expvar.Float variable.
	// 获取或创建 expvar.Float 变量。
	v := exp.getFloat(name)
	// Set its value to the counter's current float count.
	// 将其值设置为计数器的当前浮点计数值。
	v.Set(metric.Count())
}

// publishGauge publishes a Gauge metric snapshot to expvar as an Int.
// publishGauge 将 Gauge 指标快照作为 Int 发布到 expvar。
func (exp *exp) publishGauge(name string, metric metrics.GaugeSnapshot) {
	// Get or create the expvar.Int variable.
	// 获取或创建 expvar.Int 变量。
	v := exp.getInt(name)
	// Set its value to the gauge's current value.
	// 将其值设置为仪表盘的当前值。
	v.Set(metric.Value())
}

// publishGaugeFloat64 publishes a GaugeFloat64 metric snapshot to expvar as a Float.
// publishGaugeFloat64 将 GaugeFloat64 指标快照作为 Float 发布到 expvar。
func (exp *exp) publishGaugeFloat64(name string, metric metrics.GaugeFloat64Snapshot) {
	// Get or create the expvar.Float variable and set its value.
	// 获取或创建 expvar.Float 变量并设置其值。
	exp.getFloat(name).Set(metric.Value())
}

// publishGaugeInfo publishes a GaugeInfo metric snapshot to expvar as a String.
// publishGaugeInfo 将 GaugeInfo 指标快照作为 String 发布到 expvar。
func (exp *exp) publishGaugeInfo(name string, metric metrics.GaugeInfoSnapshot) {
	// Get or create the expvar.String variable and set its value to the string representation of the info.
	// 获取或创建 expvar.String 变量，并将其值设置为信息的字符串表示形式。
	exp.getInfo(name).Set(metric.Value().String())
}

// publishHistogram publishes a Histogram metric snapshot to expvar by creating multiple expvar variables.
// publishHistogram 通过创建多个 expvar 变量将 Histogram 指标快照发布到 expvar。
// It exports count, min, max, mean, standard deviation, and percentiles (50th, 75th, 95th, 99th, 99.9th).
// 它导出计数值、最小值、最大值、平均值、标准差和百分位数（50、75、95、99、99.9）。
func (exp *exp) publishHistogram(name string, metric metrics.Histogram) {
	// Get a snapshot of the histogram's current state.
	// 获取直方图当前状态的快照。
	h := metric.Snapshot()
	// Calculate specific percentiles.
	// 计算特定的百分位数。
	ps := h.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
	// Publish each statistic as a separate expvar variable with a descriptive suffix.
	// 将每个统计数据作为带有描述性后缀的独立 expvar 变量发布。
	exp.getInt(name + ".count").Set(h.Count())
	exp.getFloat(name + ".min").Set(float64(h.Min()))
	exp.getFloat(name + ".max").Set(float64(h.Max()))
	exp.getFloat(name + ".mean").Set(h.Mean())
	exp.getFloat(name + ".std-dev").Set(h.StdDev())
	exp.getFloat(name + ".50-percentile").Set(ps[0]) // Median 中位数
	exp.getFloat(name + ".75-percentile").Set(ps[1])
	exp.getFloat(name + ".95-percentile").Set(ps[2])
	exp.getFloat(name + ".99-percentile").Set(ps[3])
	exp.getFloat(name + ".999-percentile").Set(ps[4])
}

// publishMeter publishes a Meter metric snapshot to expvar by creating multiple expvar variables.
// publishMeter 通过创建多个 expvar 变量将 Meter 指标快照发布到 expvar。
// It exports the total count and the 1-, 5-, and 15-minute exponentially-weighted moving average rates, plus the mean rate.
// 它导出总计数以及 1 分钟、5 分钟和 15 分钟指数加权移动平均速率，以及平均速率。
func (exp *exp) publishMeter(name string, metric *metrics.Meter) {
	// Get a snapshot of the meter's current state.
	// 获取速率计当前状态的快照。
	m := metric.Snapshot()
	// Publish each statistic as a separate expvar variable.
	// 将每个统计数据作为独立的 expvar 变量发布。
	exp.getInt(name + ".count").Set(m.Count())
	exp.getFloat(name + ".one-minute").Set(m.Rate1())      // 1分钟速率
	exp.getFloat(name + ".five-minute").Set(m.Rate5())     // 5分钟速率
	exp.getFloat(name + ".fifteen-minute").Set(m.Rate15()) // 15分钟速率
	exp.getFloat(name + ".mean").Set(m.RateMean())         // 平均速率
}

// publishTimer publishes a Timer metric snapshot to expvar by creating multiple expvar variables.
// publishTimer 通过创建多个 expvar 变量将 Timer 指标快照发布到 expvar。
// It combines Histogram statistics (count, min, max, mean, stddev, percentiles) and Meter statistics (rates).
// 它结合了 Histogram 的统计数据（计数、最小、最大、平均、标准差、百分位数）和 Meter 的统计数据（速率）。
func (exp *exp) publishTimer(name string, metric *metrics.Timer) {
	// Get a snapshot of the timer's current state.
	// 获取计时器当前状态的快照。
	t := metric.Snapshot()
	// Calculate specific percentiles.
	// 计算特定的百分位数。
	ps := t.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999})
	// Publish histogram-like statistics.
	// 发布类似直方图的统计数据。
	exp.getInt(name + ".count").Set(t.Count())
	exp.getFloat(name + ".min").Set(float64(t.Min()))
	exp.getFloat(name + ".max").Set(float64(t.Max()))
	exp.getFloat(name + ".mean").Set(t.Mean())
	exp.getFloat(name + ".std-dev").Set(t.StdDev())
	exp.getFloat(name + ".50-percentile").Set(ps[0])
	exp.getFloat(name + ".75-percentile").Set(ps[1])
	exp.getFloat(name + ".95-percentile").Set(ps[2])
	exp.getFloat(name + ".99-percentile").Set(ps[3])
	exp.getFloat(name + ".999-percentile").Set(ps[4])
	// Publish meter-like rate statistics.
	// 发布类似速率计的速率统计数据。
	exp.getFloat(name + ".one-minute").Set(t.Rate1())
	exp.getFloat(name + ".five-minute").Set(t.Rate5())
	exp.getFloat(name + ".fifteen-minute").Set(t.Rate15())
	exp.getFloat(name + ".mean-rate").Set(t.RateMean())
}

// publishResettingTimer publishes a ResettingTimer metric snapshot to expvar.
// publishResettingTimer 将 ResettingTimer 指标快照发布到 expvar。
// It exports count, mean, and specific percentiles (50th, 75th, 95th, 99th).
// 它导出计数值、平均值和特定的百分位数（50、75、95、99）。
// ResettingTimers capture values within non-overlapping windows.
// ResettingTimers 在非重叠的时间窗口内捕获值。
func (exp *exp) publishResettingTimer(name string, metric *metrics.ResettingTimer) {
	// Get a snapshot of the resetting timer's current state.
	// 获取重置计时器当前状态的快照。
	t := metric.Snapshot()
	// Calculate specific percentiles.
	// 计算特定的百分位数。
	ps := t.Percentiles([]float64{0.50, 0.75, 0.95, 0.99})
	// Publish the statistics as separate expvar variables.
	// 将统计数据作为独立的 expvar 变量发布。
	exp.getInt(name + ".count").Set(int64(t.Count()))
	exp.getFloat(name + ".mean").Set(t.Mean())
	exp.getFloat(name + ".50-percentile").Set(ps[0])
	exp.getFloat(name + ".75-percentile").Set(ps[1])
	exp.getFloat(name + ".95-percentile").Set(ps[2])
	exp.getFloat(name + ".99-percentile").Set(ps[3])
}

// syncToExpvar iterates through the metrics registry and publishes each metric to expvar
// syncToExpvar 遍历指标注册表并将每个指标发布到 expvar
// using the appropriate publish function based on the metric type.
// 根据指标类型使用适当的发布函数。
func (exp *exp) syncToExpvar() {
	// Iterate over each metric (name and interface value i) in the registry.
	// 遍历注册表中的每个指标（名称和接口值 i）。
	exp.registry.Each(func(name string, i interface{}) {
		// Use a type switch to determine the actual type of the metric.
		// 使用类型断言 (type switch) 来确定指标的实际类型。
		switch i := i.(type) {
		case *metrics.Counter:
			// If it's a Counter, publish its snapshot.
			// 如果是 Counter，发布其快照。
			exp.publishCounter(name, i.Snapshot())
		case *metrics.CounterFloat64:
			// If it's a CounterFloat64, publish its snapshot.
			// 如果是 CounterFloat64，发布其快照。
			exp.publishCounterFloat64(name, i.Snapshot())
		case *metrics.Gauge:
			// If it's a Gauge, publish its snapshot.
			// 如果是 Gauge，发布其快照。
			exp.publishGauge(name, i.Snapshot())
		case *metrics.GaugeFloat64:
			// If it's a GaugeFloat64, publish its snapshot.
			// 如果是 GaugeFloat64，发布其快照。
			exp.publishGaugeFloat64(name, i.Snapshot())
		case *metrics.GaugeInfo:
			// If it's a GaugeInfo, publish its snapshot.
			// 如果是 GaugeInfo，发布其快照。
			exp.publishGaugeInfo(name, i.Snapshot())
		case metrics.Histogram: // Note: Histogram is an interface type
			// If it's a Histogram, publish its statistics.
			// 如果是 Histogram，发布其统计信息。
			exp.publishHistogram(name, i)
		case *metrics.Meter:
			// If it's a Meter, publish its snapshot.
			// 如果是 Meter，发布其快照。
			exp.publishMeter(name, i)
		case *metrics.Timer:
			// If it's a Timer, publish its snapshot.
			// 如果是 Timer，发布其快照。
			exp.publishTimer(name, i)
		case *metrics.ResettingTimer:
			// If it's a ResettingTimer, publish its snapshot.
			// 如果是 ResettingTimer，发布其快照。
			exp.publishResettingTimer(name, i)
		default:
			// If an unsupported metric type is encountered, panic.
			// 如果遇到不支持的指标类型，则发生 panic。
			// This helps catch errors if new metric types are added without updating this code.
			// 如果添加了新的指标类型而没有更新此代码，这有助于捕获错误。
			panic(fmt.Sprintf("unsupported type for '%s': %T", name, i))
		}
	})
}
