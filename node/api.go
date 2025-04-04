// Copyright 2015 The go-ethereum Authors
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
	"context"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rpc"
)

// devp2p 协议
// 背景：devp2p 是以太坊的 P2P 网络协议，基于 Kademlia 算法实现节点发现和通信。
// 关联：AddPeer 和 AddTrustedPeer 使用 enode URL（如 enode://id@host:port）标识节点，这是 devp2p 的标准格式。
// Keccak-256 哈希
// 背景：Keccak-256 是以太坊使用的 SHA-3 变种哈希算法，用于签名、地址生成等。
// 关联：Sha3 方法实现了这一算法，与以太坊的 web3.sha3 接口一致。
// RPC 接口
// 背景：以太坊节点通过 RPC（如 HTTP、WebSocket）暴露 API，遵循 JSON-RPC 2.0 标准。
// 关联：StartHTTP 和 StartWS 配置并启动 RPC 服务，支持外部客户端交互。
// 节点发现
// 背景：以太坊使用 UDP 协议（Discovery v4/v5）发现网络中的节点。
// 关联：DiscoveryV4Table 返回节点发现表的桶结构，便于调试 Kademlia 路由表。

// apis returns the collection of built-in RPC APIs.
// apis 返回内置 RPC API 的集合。
func (n *Node) apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "admin",
			Service:   &adminAPI{n},
		}, {
			Namespace: "debug",
			Service:   debug.Handler,
		}, {
			Namespace: "debug",
			Service:   &p2pDebugAPI{n},
		}, {
			Namespace: "web3",
			Service:   &web3API{n},
		},
	}
}

// adminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
// adminAPI 是通过安全和普通 RPC 信道暴露的一组管理 API 方法。
type adminAPI struct {
	node *Node // Node interfaced by this API
	// 此 API 接口的节点
}

// AddPeer requests connecting to a remote node, and also maintaining the new
// connection at all times, even reconnecting if it is lost.
// AddPeer 请求连接到一个远程节点，并始终维持新的连接，即使连接丢失也会重新连接。
func (api *adminAPI) AddPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	// 确保服务器正在运行，否则失败
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to add the url as a static peer and return
	// 尝试将 URL 添加为静态节点并返回
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.AddPeer(node)
	return true, nil
}

// RemovePeer disconnects from a remote node if the connection exists
// RemovePeer 如果连接存在，则断开与远程节点的连接
func (api *adminAPI) RemovePeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	// 确保服务器正在运行，否则失败
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to remove the url as a static peer and return
	// 尝试将 URL 作为静态节点移除并返回
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.RemovePeer(node)
	return true, nil
}

// AddTrustedPeer allows a remote node to always connect, even if slots are full
// AddTrustedPeer 允许远程节点始终连接，即使连接槽已满
func (api *adminAPI) AddTrustedPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	// 确保服务器正在运行，否则失败
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.AddTrustedPeer(node)
	return true, nil
}

// RemoveTrustedPeer removes a remote node from the trusted peer set, but it
// does not disconnect it automatically.
// RemoveTrustedPeer 从受信任节点集中移除远程节点，但不会自动断开连接。
func (api *adminAPI) RemoveTrustedPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	// 确保服务器正在运行，否则失败
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	node, err := enode.Parse(enode.ValidSchemes, url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.RemoveTrustedPeer(node)
	return true, nil
}

// PeerEvents creates an RPC subscription which receives peer events from the
// node's p2p.Server
// PeerEvents 创建一个 RPC 订阅，从节点的 p2p.Server 接收节点事件
func (api *adminAPI) PeerEvents(ctx context.Context) (*rpc.Subscription, error) {
	// Make sure the server is running, fail otherwise
	// 确保服务器正在运行，否则失败
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}

	// Create the subscription
	// 创建订阅
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return nil, rpc.ErrNotificationsUnsupported
	}
	rpcSub := notifier.CreateSubscription()

	go func() {
		events := make(chan *p2p.PeerEvent)
		sub := server.SubscribeEvents(events)
		defer sub.Unsubscribe()

		for {
			select {
			case event := <-events:
				notifier.Notify(rpcSub.ID, event)
			case <-sub.Err():
				return
			case <-rpcSub.Err():
				return
			}
		}
	}()

	return rpcSub, nil
}

// StartHTTP starts the HTTP RPC API server.
// StartHTTP 启动 HTTP RPC API 服务器。
func (api *adminAPI) StartHTTP(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	// Determine host and port.
	// 确定主机和端口。
	if host == nil {
		h := DefaultHTTPHost
		if api.node.config.HTTPHost != "" {
			h = api.node.config.HTTPHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.HTTPPort
	}

	// Determine config.
	// 确定配置。
	config := httpConfig{
		CorsAllowedOrigins: api.node.config.HTTPCors,
		Vhosts:             api.node.config.HTTPVirtualHosts,
		Modules:            api.node.config.HTTPModules,
		rpcEndpointConfig: rpcEndpointConfig{
			batchItemLimit:         api.node.config.BatchRequestLimit,
			batchResponseSizeLimit: api.node.config.BatchResponseMaxSize,
		},
	}
	if cors != nil {
		config.CorsAllowedOrigins = nil
		for _, origin := range strings.Split(*cors, ",") {
			config.CorsAllowedOrigins = append(config.CorsAllowedOrigins, strings.TrimSpace(origin))
		}
	}
	if vhosts != nil {
		config.Vhosts = nil
		for _, vhost := range strings.Split(*host, ",") {
			config.Vhosts = append(config.Vhosts, strings.TrimSpace(vhost))
		}
	}
	if apis != nil {
		config.Modules = nil
		for _, m := range strings.Split(*apis, ",") {
			config.Modules = append(config.Modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.http.setListenAddr(*host, *port); err != nil {
		return false, err
	}
	if err := api.node.http.enableRPC(api.node.rpcAPIs, config); err != nil {
		return false, err
	}
	if err := api.node.http.start(); err != nil {
		return false, err
	}
	return true, nil
}

// StartRPC starts the HTTP RPC API server.
// Deprecated: use StartHTTP instead.
// StartRPC 启动 HTTP RPC API 服务器。
// 已弃用：请使用 StartHTTP 代替。
func (api *adminAPI) StartRPC(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	log.Warn("Deprecation warning", "method", "admin.StartRPC", "use-instead", "admin.StartHTTP")
	return api.StartHTTP(host, port, cors, apis, vhosts)
}

// StopHTTP shuts down the HTTP server.
// StopHTTP 关闭 HTTP 服务器。
func (api *adminAPI) StopHTTP() (bool, error) {
	api.node.http.stop()
	return true, nil
}

// StopRPC shuts down the HTTP server.
// Deprecated: use StopHTTP instead.
// StopRPC 关闭 HTTP 服务器。
// 已弃用：请使用 StopHTTP 代替。
func (api *adminAPI) StopRPC() (bool, error) {
	log.Warn("Deprecation warning", "method", "admin.StopRPC", "use-instead", "admin.StopHTTP")
	return api.StopHTTP()
}

// StartWS starts the websocket RPC API server.
// StartWS 启动 WebSocket RPC API 服务器。
func (api *adminAPI) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	// Determine host and port.
	// 确定主机和端口。
	if host == nil {
		h := DefaultWSHost
		if api.node.config.WSHost != "" {
			h = api.node.config.WSHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.WSPort
	}

	// Determine config.
	// 确定配置。
	config := wsConfig{
		Modules: api.node.config.WSModules,
		Origins: api.node.config.WSOrigins,
		// ExposeAll: api.node.config.WSExposeAll,
		rpcEndpointConfig: rpcEndpointConfig{
			batchItemLimit:         api.node.config.BatchRequestLimit,
			batchResponseSizeLimit: api.node.config.BatchResponseMaxSize,
		},
	}
	if apis != nil {
		config.Modules = nil
		for _, m := range strings.Split(*apis, ",") {
			config.Modules = append(config.Modules, strings.TrimSpace(m))
		}
	}
	if allowedOrigins != nil {
		config.Origins = nil
		for _, origin := range strings.Split(*allowedOrigins, ",") {
			config.Origins = append(config.Origins, strings.TrimSpace(origin))
		}
	}

	// Enable WebSocket on the server.
	// 在服务器上启用 WebSocket。
	server := api.node.wsServerForPort(*port, false)
	if err := server.setListenAddr(*host, *port); err != nil {
		return false, err
	}
	openApis, _ := api.node.getAPIs()
	if err := server.enableWS(openApis, config); err != nil {
		return false, err
	}
	if err := server.start(); err != nil {
		return false, err
	}
	api.node.http.log.Info("WebSocket endpoint opened", "url", api.node.WSEndpoint())
	return true, nil
}

// StopWS terminates all WebSocket servers.
// StopWS 终止所有 WebSocket 服务器。
func (api *adminAPI) StopWS() (bool, error) {
	api.node.http.stopWS()
	api.node.ws.stop()
	return true, nil
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
// Peers 检索我们所知道的每个单独节点在协议粒度上的所有信息。
func (api *adminAPI) Peers() ([]*p2p.PeerInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
// NodeInfo 检索我们所知道的主节点在协议粒度上的所有信息。
func (api *adminAPI) NodeInfo() (*p2p.NodeInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.NodeInfo(), nil
}

// Datadir retrieves the current data directory the node is using.
// Datadir 检索节点当前使用的数据目录。
func (api *adminAPI) Datadir() string {
	return api.node.DataDir()
}

// web3API offers helper utils
// web3API 提供辅助工具
type web3API struct {
	stack *Node
}

// ClientVersion returns the node name
// ClientVersion 返回节点名称
func (s *web3API) ClientVersion() string {
	return s.stack.Server().Name
}

// Sha3 applies the ethereum sha3 implementation on the input.
// It assumes the input is hex encoded.
// Sha3 对输入应用以太坊 sha3 实现。
// 假设输入是十六进制编码的。
func (s *web3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}

// p2pDebugAPI provides access to p2p internals for debugging.
// p2pDebugAPI 提供对 P2P 内部的访问以进行调试。
type p2pDebugAPI struct {
	stack *Node
}

func (s *p2pDebugAPI) DiscoveryV4Table() [][]discover.BucketNode {
	disc := s.stack.server.DiscoveryV4()
	if disc != nil {
		return disc.TableBuckets()
	}
	return nil
}
