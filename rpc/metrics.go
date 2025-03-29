// Copyright 2020 The go-ethereum Authors
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

package rpc

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/metrics"
)

var (
	rpcRequestGauge        = metrics.NewRegisteredGauge("rpc/requests", nil) // RPC 请求计数器
	successfulRequestGauge = metrics.NewRegisteredGauge("rpc/success", nil)  // 成功 RPC 请求计数器
	failedRequestGauge     = metrics.NewRegisteredGauge("rpc/failure", nil)  // 失败 RPC 请求计数器

	// serveTimeHistName is the prefix of the per-request serving time histograms.
	// serveTimeHistName 是每个请求服务时间直方图的前缀。
	serveTimeHistName = "rpc/duration"

	rpcServingTimer = metrics.NewRegisteredTimer("rpc/duration/all", nil) // 所有 RPC 请求的服务时间计时器
)

// updateServeTimeHistogram tracks the serving time of a remote RPC call.
// updateServeTimeHistogram 跟踪远程 RPC 调用的服务时间。
func updateServeTimeHistogram(method string, success bool, elapsed time.Duration) {
	note := "success"
	if !success {
		note = "failure"
	}
	h := fmt.Sprintf("%s/%s/%s", serveTimeHistName, method, note)
	sampler := func() metrics.Sample {
		return metrics.ResettingSample(
			metrics.NewExpDecaySample(1028, 0.015), // 使用指数衰减采样器
		)
	}
	metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(elapsed.Nanoseconds()) // 获取或注册直方图并更新服务时间
}
