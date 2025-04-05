// Copyright 2024 The go-ethereum Authors
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

package blsync

import (
	"github.com/ethereum/go-ethereum/beacon/light"
	"github.com/ethereum/go-ethereum/beacon/light/api"
	"github.com/ethereum/go-ethereum/beacon/light/request"
	"github.com/ethereum/go-ethereum/beacon/light/sync"
	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client represents a client that interacts with the beacon chain and execution layer.
// Client 表示一个与信标链和执行层交互的客户端。
type Client struct {
	urls         []string             // Beacon API 的 URL 列表
	customHeader map[string]string    // 自定义 HTTP 请求头
	config       *params.ClientConfig // 客户端配置
	scheduler    *request.Scheduler   // 请求调度器
	blockSync    *beaconBlockSync     // 信标区块同步模块
	engineRPC    *rpc.Client          // 执行层 RPC 客户端

	chainHeadSub event.Subscription // 链头部事件订阅
	engineClient *engineClient      // 执行层客户端
}

// NewClient creates a new Client instance.
// NewClient 创建一个新的 Client 实例。
func NewClient(config params.ClientConfig) *Client {
	// create data structures
	// 创建数据结构
	var (
		db             = memorydb.New() // 内存数据库，用于存储委员会链数据
		committeeChain = light.NewCommitteeChain(db, &config.ChainConfig, config.Threshold, !config.NoFilter)
		// 委员会链，用于跟踪验证者委员会的状态
		headTracker = light.NewHeadTracker(committeeChain, config.Threshold)
		// 头部跟踪器，用于跟踪最新的信标链头部信息
	)
	headSync := sync.NewHeadSync(headTracker, committeeChain)
	// 头部同步模块，用于同步最新的信标链头部

	// set up scheduler and sync modules
	// 设置调度器和同步模块
	scheduler := request.NewScheduler()
	checkpointInit := sync.NewCheckpointInit(committeeChain, config.Checkpoint)
	// 检查点初始化模块，用于从检查点恢复状态
	forwardSync := sync.NewForwardUpdateSync(committeeChain)
	// 前向同步模块，用于处理增量更新
	beaconBlockSync := newBeaconBlockSync(headTracker)
	// 信标区块同步模块，用于同步信标区块
	scheduler.RegisterTarget(headTracker)
	scheduler.RegisterTarget(committeeChain)
	scheduler.RegisterModule(checkpointInit, "checkpointInit")
	scheduler.RegisterModule(forwardSync, "forwardSync")
	scheduler.RegisterModule(headSync, "headSync")
	scheduler.RegisterModule(beaconBlockSync, "beaconBlockSync")

	return &Client{
		scheduler:    scheduler,
		urls:         config.Apis,
		customHeader: config.CustomHeader,
		config:       &config,
		blockSync:    beaconBlockSync,
	}
}

// SetEngineRPC sets the engine RPC client for the client.
// SetEngineRPC 设置客户端的执行层 RPC 客户端。
func (c *Client) SetEngineRPC(engine *rpc.Client) {
	c.engineRPC = engine
}

// Start starts the client and its associated components.
// Start 启动客户端及其相关组件。
func (c *Client) Start() error {
	headCh := make(chan types.ChainHeadEvent, 16)
	// 创建一个通道，用于接收链头部事件
	c.chainHeadSub = c.blockSync.SubscribeChainHead(headCh)
	// 订阅链头部事件
	c.engineClient = startEngineClient(c.config, c.engineRPC, headCh)
	// 启动执行层客户端

	c.scheduler.Start()
	// 启动请求调度器
	for _, url := range c.urls {
		beaconApi := api.NewBeaconLightApi(url, c.customHeader)
		// 创建 Beacon API 客户端
		c.scheduler.RegisterServer(request.NewServer(api.NewApiServer(beaconApi), &mclock.System{}))
		// 注册服务器到调度器
	}
	return nil
}

// Stop stops the client and its associated components.
// Stop 停止客户端及其相关组件。
func (c *Client) Stop() error {
	c.engineClient.stop()
	// 停止执行层客户端
	c.chainHeadSub.Unsubscribe()
	// 取消链头部事件订阅
	c.scheduler.Stop()
	// 停止请求调度器
	return nil
}
