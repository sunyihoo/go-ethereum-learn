// Copyright 2016 The go-ethereum Authors
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
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/rpc"
)

// Engine API
// 背景：Engine API 是以太坊合并（The Merge）后引入的，用于执行客户端（EL）和共识客户端（CL）之间的通信，基于 JSON-RPC。
// 关联：engineAPIBatchItemLimit 等常量限制了 Engine API 的请求和响应，确保高效性和安全性。
// RPC 服务
// 背景：以太坊节点通过 HTTP（8545）和 WebSocket（8546）提供 RPC 接口，认证 API（8551）用于敏感操作。
// 关联：默认端口和模块（如 eth, engine）支持标准以太坊功能。
// P2P 网络
// 背景：以太坊使用端口 30303 进行 P2P 通信，默认支持最多 50 个节点连接。
// 关联：P2P 配置中的 ListenAddr 和 MaxPeers 反映了这一标准。
// 数据库引擎
// 背景：以太坊节点支持多种数据库引擎（如 LevelDB、Pebble），Pebble 是较新的默认选项。
// 关联：DBEngine 为空时动态选择，优先使用 Pebble。

const (
	DefaultHTTPHost = "localhost" // Default host interface for the HTTP RPC server
	// HTTP RPC 服务器的默认主机接口
	DefaultHTTPPort = 8545 // Default TCP port for the HTTP RPC server
	// HTTP RPC 服务器的默认 TCP 端口
	DefaultWSHost = "localhost" // Default host interface for the websocket RPC server
	// WebSocket RPC 服务器的默认主机接口
	DefaultWSPort = 8546 // Default TCP port for the websocket RPC server
	// WebSocket RPC 服务器的默认 TCP 端口
	DefaultAuthHost = "localhost" // Default host interface for the authenticated apis
	// 认证 API 的默认主机接口
	DefaultAuthPort = 8551 // Default port for the authenticated apis
	// 认证 API 的默认端口
)

// 这段代码定义了 Engine API 的批处理限制常量，包括批处理项数、批处理响应大小和请求体大小的最大值。
// 这些限制确保了共识客户端和执行客户端之间的通信是高效且安全的，同时也防止了资源耗尽问题。
// 这些值是固定且不可配置的，以确保系统的稳定性和一致性。
const (
	// Engine API batch limits: these are not configurable by users, and should cover the
	// needs of all CLs.
	// 定义了 Engine API 的批处理限制常量，这些常量不可由用户配置，其目的是确保 CLs（共识客户端）的需求得到满足。
	engineAPIBatchItemLimit         = 2000              // 限制单次批处理请求中可包含的最大项数，防止处理过大的批处理请求。
	engineAPIBatchResponseSizeLimit = 250 * 1000 * 1000 // 250 MB 限制批处理响应的总大小，防止发送或接收过大的响应。
	engineAPIBodyLimit              = 128 * 1024 * 1024 // 128 MB 限制单次请求体的大小，防止处理过大的请求。
)

// 这段代码定义了与认证 API 相关的默认配置变量，用于设置跨域资源共享（CORS）、虚拟主机（Vhosts）、来源（Origins）、API 前缀以及模块的默认值。
var (
	DefaultAuthCors = []string{"localhost"} // Default cors domain for the authenticated apis
	// 认证 API 的默认跨域资源共享（CORS）域
	DefaultAuthVhosts = []string{"localhost"} // Default virtual hosts for the authenticated apis
	// 认证 API 的默认虚拟主机（Vhosts）
	DefaultAuthOrigins = []string{"localhost"} // Default origins for the authenticated apis
	// 认证 API 的默认来源（Origins）
	DefaultAuthPrefix = "" // Default prefix for the authenticated apis
	// 认证 API 的默认前缀
	DefaultAuthModules = []string{"eth", "engine"} // Default modules for the authenticated apis
	// 认证 API 的默认模块列表
)

// DefaultConfig contains reasonable default settings.
// DefaultConfig 包含合理的默认设置。
var DefaultConfig = Config{
	DataDir:              DefaultDataDir(),
	HTTPPort:             DefaultHTTPPort,
	AuthAddr:             DefaultAuthHost,
	AuthPort:             DefaultAuthPort,
	AuthVirtualHosts:     DefaultAuthVhosts,
	HTTPModules:          []string{"net", "web3"},
	HTTPVirtualHosts:     []string{"localhost"},
	HTTPTimeouts:         rpc.DefaultHTTPTimeouts,
	WSPort:               DefaultWSPort,
	WSModules:            []string{"net", "web3"},
	BatchRequestLimit:    1000,
	BatchResponseMaxSize: 25 * 1000 * 1000,
	GraphQLVirtualHosts:  []string{"localhost"},
	P2P: p2p.Config{
		ListenAddr: ":30303",
		MaxPeers:   50,
		NAT:        nat.Any(),
	},
	DBEngine: "", // Use whatever exists, will default to Pebble if non-existent and supported
	// 使用已有的数据库引擎，如果不存在且支持则默认使用 Pebble
}

// DefaultDataDir is the default data directory to use for the databases and other
// persistence requirements.
// DefaultDataDir 是用于数据库和其他持久性需求的默认数据目录。
func DefaultDataDir() string {
	// Try to place the data folder in the user's home dir
	// 尝试将数据文件夹放置在用户的家目录中
	home := homeDir()
	if home != "" {
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Ethereum")
		case "windows":
			// We used to put everything in %HOME%\AppData\Roaming, but this caused
			// problems with non-typical setups. If this fallback location exists and
			// is non-empty, use it, otherwise DTRT and check %LOCALAPPDATA%.
			// 我们过去将所有内容放在 %HOME%\AppData\Roaming 中，但这在非典型设置中会导致问题。
			// 如果这个回退位置存在且非空，则使用它，否则检查 %LOCALAPPDATA%。
			fallback := filepath.Join(home, "AppData", "Roaming", "Ethereum")
			appdata := windowsAppData()
			if appdata == "" || isNonEmptyDir(fallback) {
				return fallback
			}
			return filepath.Join(appdata, "Ethereum")
		default:
			return filepath.Join(home, ".ethereum")
		}
	}
	// As we cannot guess a stable location, return empty and handle later
	// 由于无法猜测稳定的位置，返回空字符串并稍后处理
	return ""
}

func windowsAppData() string {
	v := os.Getenv("LOCALAPPDATA")
	if v == "" {
		// Windows XP and below don't have LocalAppData. Crash here because
		// we don't support Windows XP and undefining the variable will cause
		// other issues.
		// Windows XP 及以下版本没有 LocalAppData。在此崩溃，因为我们不支持 Windows XP，
		// 且未定义该变量会导致其他问题。
		panic("environment variable LocalAppData is undefined")
	}
	return v
}

func isNonEmptyDir(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	names, _ := f.Readdir(1)
	f.Close()
	return len(names) > 0
}

func homeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}
