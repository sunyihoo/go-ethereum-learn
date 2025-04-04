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

package node

import (
	"net"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

// StartHTTPEndpoint starts the HTTP RPC endpoint.
// StartHTTPEndpoint 启动 HTTP RPC 端点。
func StartHTTPEndpoint(endpoint string, timeouts rpc.HTTPTimeouts, handler http.Handler) (*http.Server, net.Addr, error) {
	// start the HTTP listener
	// 启动 HTTP 监听器
	var (
		listener net.Listener // 网络监听器
		err      error        // 错误变量
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil { // 监听指定的 TCP 端点
		return nil, nil, err // 如果监听失败，返回错误
	}
	// make sure timeout values are meaningful
	// 确保超时值是合理的
	CheckTimeouts(&timeouts) // 检查并修正超时配置
	// Bundle and start the HTTP server
	// 打包并启动 HTTP 服务器
	httpSrv := &http.Server{
		Handler:           handler,                    // 设置请求处理程序
		ReadTimeout:       timeouts.ReadTimeout,       // 设置读取超时
		ReadHeaderTimeout: timeouts.ReadHeaderTimeout, // 设置读取头部超时
		WriteTimeout:      timeouts.WriteTimeout,      // 设置写入超时
		IdleTimeout:       timeouts.IdleTimeout,       // 设置空闲超时
	}
	go httpSrv.Serve(listener)           // 异步启动 HTTP 服务器，监听请求
	return httpSrv, listener.Addr(), err // 返回服务器实例、监听地址和错误（若有）
}

// checkModuleAvailability checks that all names given in modules are actually
// available API services. It assumes that the MetadataApi module ("rpc") is always available;
// the registration of this "rpc" module happens in NewServer() and is thus common to all endpoints.
// checkModuleAvailability 检查用户请求的模块名称是否确实对应于可用的 API 服务。
// 它假定 MetadataApi 模块（"rpc"）始终可用；该 "rpc" 模块的注册在 NewServer() 中完成，因此对所有端点通用。
// 验证用户请求的 API 模块是否确实存在于以太坊节点中。它会遍历用户指定的模块名称列表（modules），
// 确保每个名称对应的 API 服务已注册。此外，它会确保 "rpc" 模块（元数据 API）始终被包含，因为该模块是 RPC 服务的基础，必须存在。
func checkModuleAvailability(modules []string, apis []rpc.API) (bad, available []string) {
	availableSet := make(map[string]struct{}) // 创建可用模块的集合
	for _, api := range apis {                // 遍历所有注册的 API
		if _, ok := availableSet[api.Namespace]; !ok { // 如果该命名空间尚未记录
			availableSet[api.Namespace] = struct{}{}     // 添加到集合
			available = append(available, api.Namespace) // 添加到可用列表
		}
	}
	for _, name := range modules { // 遍历用户请求的模块
		if _, ok := availableSet[name]; !ok { // 如果模块不在可用集合中
			if name != rpc.MetadataApi && name != rpc.EngineApi { // 排除 "rpc" 和 "engine" 模块
				bad = append(bad, name) // 添加到不可用列表
			}
		}
	}
	return bad, available // 返回不可用和可用模块列表
}

// CheckTimeouts ensures that timeout values are meaningful
// CheckTimeouts 确保超时值是合理的
func CheckTimeouts(timeouts *rpc.HTTPTimeouts) {
	if timeouts.ReadTimeout < time.Second { // 如果读取超时小于 1 秒
		log.Warn("Sanitizing invalid HTTP read timeout", "provided", timeouts.ReadTimeout, "updated", rpc.DefaultHTTPTimeouts.ReadTimeout)
		// 记录警告：修正无效的 HTTP 读取超时，显示提供的和更新后的值
		timeouts.ReadTimeout = rpc.DefaultHTTPTimeouts.ReadTimeout // 设置为默认值
	}
	if timeouts.ReadHeaderTimeout < time.Second { // 如果读取头部超时小于 1 秒
		log.Warn("Sanitizing invalid HTTP read header timeout", "provided", timeouts.ReadHeaderTimeout, "updated", rpc.DefaultHTTPTimeouts.ReadHeaderTimeout)
		// 记录警告：修正无效的 HTTP 读取头部超时，显示提供的和更新后的值
		timeouts.ReadHeaderTimeout = rpc.DefaultHTTPTimeouts.ReadHeaderTimeout // 设置为默认值
	}
	if timeouts.WriteTimeout < time.Second { // 如果写入超时小于 1 秒
		log.Warn("Sanitizing invalid HTTP write timeout", "provided", timeouts.WriteTimeout, "updated", rpc.DefaultHTTPTimeouts.WriteTimeout)
		// 记录警告：修正无效的 HTTP 写入超时，显示提供的和更新后的值
		timeouts.WriteTimeout = rpc.DefaultHTTPTimeouts.WriteTimeout // 设置为默认值
	}
	if timeouts.IdleTimeout < time.Second { // 如果空闲超时小于 1 秒
		log.Warn("Sanitizing invalid HTTP idle timeout", "provided", timeouts.IdleTimeout, "updated", rpc.DefaultHTTPTimeouts.IdleTimeout)
		// 记录警告：修正无效的 HTTP 空闲超时，显示提供的和更新后的值
		timeouts.IdleTimeout = rpc.DefaultHTTPTimeouts.IdleTimeout // 设置为默认值
	}
}
