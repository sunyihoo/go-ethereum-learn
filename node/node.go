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
	crand "crypto/rand"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gofrs/flock"
)

// P2P 网络
// 以太坊使用基于 Kademlia 的 P2P 网络实现节点发现和数据同步。p2p.Server 负责管理连接、协议协商和数据传输。
// RPC 服务
// 节点通过 RPC 接口（如 HTTP、WebSocket、IPC）与外部应用交互，提供区块链数据查询和交易提交功能。
// 数据库管理
// 以太坊节点使用 LevelDB 或 Pebble 存储区块链状态，OpenDatabase 支持持久化和内存数据库，OpenDatabaseWithFreezer 引入 freezer 机制，将古老数据存为只追加文件。
// JWT 认证
// obtainJWTSecret 方法生成或加载 JWT，用于认证敏感 API（如引擎 API），符合 EIP-1559 和合并后的安全性要求。
// 生命周期管理
// Lifecycle 接口允许服务（如区块同步、交易池）在节点启动和停止时执行自定义逻辑。

// Node is a container on which services can be registered.
// Node 是一个容器，可以在其上注册服务。
type Node struct {
	eventmux      *event.TypeMux    // 事件多路复用器，用于网络服务的事件处理
	config        *Config           // 节点配置，包含数据目录、P2P 配置等
	accman        *accounts.Manager // 账户管理器，管理以太坊账户
	log           log.Logger        // 日志记录器
	keyDir        string            // key store directory // 密钥存储目录
	keyDirTemp    bool              // If true, key directory will be removed by Stop // 如果为 true，Stop 时将删除密钥目录
	dirLock       *flock.Flock      // prevents concurrent use of instance directory // 防止实例目录的并发使用
	stop          chan struct{}     // Channel to wait for termination notifications // 等待终止通知的通道
	server        *p2p.Server       // Currently running P2P networking layer // 当前运行的 P2P 网络层
	startStopLock sync.Mutex        // Start/Stop are protected by an additional lock // Start/Stop 由额外的锁保护
	state         int               // Tracks state of node lifecycle // 跟踪节点生命周期的状态

	lock          sync.Mutex  // 保护节点状态的锁
	lifecycles    []Lifecycle // All registered backends, services, and auxiliary services that have a lifecycle // 所有注册的具有生命周期的后端、服务和辅助服务
	rpcAPIs       []rpc.API   // List of APIs currently provided by the node // 节点当前提供的 API 列表
	http          *httpServer // HTTP 服务器
	ws            *httpServer // WebSocket 服务器
	httpAuth      *httpServer // 认证 HTTP 服务器
	wsAuth        *httpServer // 认证 WebSocket 服务器
	ipc           *ipcServer  // Stores information about the ipc http server // 存储有关 IPC HTTP 服务器的信息
	inprocHandler *rpc.Server // In-process RPC request handler to process the API requests // 处理 API 请求的进程内 RPC 请求处理程序

	databases map[*closeTrackingDB]struct{} // All open databases // 所有打开的数据库
}

const (
	initializingState = iota // 初始化状态
	runningState             // 运行状态
	closedState              // 关闭状态
)

// New creates a new P2P node, ready for protocol registration.
// New 创建一个新的 P2P 节点，准备进行协议注册。
func New(conf *Config) (*Node, error) {
	// Copy config and resolve the datadir so future changes to the current
	// working directory don't affect the node.
	// 复制配置并解析 datadir，以免当前工作目录的未来更改影响节点。
	confCopy := *conf
	conf = &confCopy
	if conf.DataDir != "" {
		absdatadir, err := filepath.Abs(conf.DataDir)
		if err != nil {
			return nil, err
		}
		conf.DataDir = absdatadir
	}
	if conf.Logger == nil {
		conf.Logger = log.New()
	}

	// Ensure that the instance name doesn't cause weird conflicts with
	// other files in the data directory.
	// 确保实例名称不会与数据目录中的其他文件产生奇怪的冲突。
	if strings.ContainsAny(conf.Name, `/\`) {
		return nil, errors.New(`Config.Name must not contain '/' or '\'`)
	}
	if conf.Name == datadirDefaultKeyStore {
		return nil, errors.New(`Config.Name cannot be "` + datadirDefaultKeyStore + `"`)
	}
	if strings.HasSuffix(conf.Name, ".ipc") {
		return nil, errors.New(`Config.Name cannot end in ".ipc"`)
	}
	server := rpc.NewServer()
	server.SetBatchLimits(conf.BatchRequestLimit, conf.BatchResponseMaxSize)
	node := &Node{
		config:        conf,
		inprocHandler: server,
		eventmux:      new(event.TypeMux),
		log:           conf.Logger,
		stop:          make(chan struct{}),
		server:        &p2p.Server{Config: conf.P2P},
		databases:     make(map[*closeTrackingDB]struct{}),
	}

	// Register built-in APIs.
	// 注册内置 API。
	node.rpcAPIs = append(node.rpcAPIs, node.apis()...)

	// Acquire the instance directory lock.
	// 获取实例目录锁。
	if err := node.openDataDir(); err != nil {
		return nil, err
	}
	keyDir, isEphem, err := conf.GetKeyStoreDir()
	if err != nil {
		return nil, err
	}
	node.keyDir = keyDir
	node.keyDirTemp = isEphem
	// Creates an empty AccountManager with no backends. Callers (e.g. cmd/geth)
	// are required to add the backends later on.
	// 创建一个空的 AccountManager 实例。
	node.accman = accounts.NewManager(nil)

	// Initialize the p2p server. This creates the node key and discovery databases.
	// 初始化 P2P 服务器。这将创建节点密钥和发现数据库。
	node.server.Config.PrivateKey = node.config.NodeKey()
	node.server.Config.Name = node.config.NodeName()
	node.server.Config.Logger = node.log
	node.config.checkLegacyFiles()
	if node.server.Config.NodeDatabase == "" {
		node.server.Config.NodeDatabase = node.config.NodeDB()
	}

	// Check HTTP/WS prefixes are valid.
	// 检查 HTTP/WS 前缀是否有效。
	if err := validatePrefix("HTTP", conf.HTTPPathPrefix); err != nil {
		return nil, err
	}
	if err := validatePrefix("WebSocket", conf.WSPathPrefix); err != nil {
		return nil, err
	}

	// Configure RPC servers.
	// 配置 RPC 服务器。
	node.http = newHTTPServer(node.log, conf.HTTPTimeouts)
	node.httpAuth = newHTTPServer(node.log, conf.HTTPTimeouts)
	node.ws = newHTTPServer(node.log, rpc.DefaultHTTPTimeouts)
	node.wsAuth = newHTTPServer(node.log, rpc.DefaultHTTPTimeouts)
	node.ipc = newIPCServer(node.log, conf.IPCEndpoint())

	return node, nil
}

// Start starts all registered lifecycles, RPC services and p2p networking.
// Node can only be started once.
// Start 启动所有注册的生命周期、RPC 服务和 P2P 网络。节点只能启动一次。
func (n *Node) Start() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()

	n.lock.Lock()
	switch n.state {
	case runningState:
		n.lock.Unlock()
		return ErrNodeRunning
	case closedState:
		n.lock.Unlock()
		return ErrNodeStopped
	}
	n.state = runningState
	// open networking and RPC endpoints
	// 打开网络和 RPC 端点
	err := n.openEndpoints()
	lifecycles := make([]Lifecycle, len(n.lifecycles))
	copy(lifecycles, n.lifecycles)
	n.lock.Unlock()

	// Check if endpoint startup failed.
	// 检查端点启动是否失败。
	if err != nil {
		n.doClose(nil)
		return err
	}
	// Start all registered lifecycles.
	// 启动所有注册的生命周期。
	var started []Lifecycle
	for _, lifecycle := range lifecycles {
		if err = lifecycle.Start(); err != nil {
			break
		}
		started = append(started, lifecycle)
	}
	// Check if any lifecycle failed to start.
	// 检查是否有生命周期启动失败。
	if err != nil {
		n.stopServices(started)
		n.doClose(nil)
	}
	return err
}

// Close stops the Node and releases resources acquired in
// Node constructor New.
// Close 停止节点并释放 Node 构造函数 New 中获取的资源。
func (n *Node) Close() error {
	n.startStopLock.Lock()
	defer n.startStopLock.Unlock()

	n.lock.Lock()
	state := n.state
	n.lock.Unlock()
	switch state {
	case initializingState:
		// The node was never started.
		// 节点从未启动。
		return n.doClose(nil)
	case runningState:
		// The node was started, release resources acquired by Start().
		// 节点已启动，释放 Start() 获取的资源。
		var errs []error
		if err := n.stopServices(n.lifecycles); err != nil {
			errs = append(errs, err)
		}
		return n.doClose(errs)
	case closedState:
		return ErrNodeStopped
	default:
		panic(fmt.Sprintf("node is in unknown state %d", state))
	}
}

// doClose releases resources acquired by New(), collecting errors.
// doClose 释放 New() 获取的资源，收集错误。
func (n *Node) doClose(errs []error) error {
	// Close databases. This needs the lock because it needs to
	// synchronize with OpenDatabase*.
	// 关闭数据库。这需要锁，因为它需要与 OpenDatabase* 同步。
	n.lock.Lock()
	n.state = closedState
	errs = append(errs, n.closeDatabases()...)
	n.lock.Unlock()

	if err := n.accman.Close(); err != nil {
		errs = append(errs, err)
	}
	if n.keyDirTemp {
		if err := os.RemoveAll(n.keyDir); err != nil {
			errs = append(errs, err)
		}
	}

	// Release instance directory lock.
	// 释放实例目录锁。
	n.closeDataDir()

	// Unblock n.Wait.
	// 解除 n.Wait 的阻塞。
	close(n.stop)

	// Report any errors that might have occurred.
	// 报告可能发生的任何错误。
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return fmt.Errorf("%v", errs)
	}
}

// openEndpoints starts all network and RPC endpoints.
// openEndpoints 启动所有网络和 RPC 端点。
func (n *Node) openEndpoints() error {
	// start networking endpoints
	// 启动网络端点
	n.log.Info("Starting peer-to-peer node", "instance", n.server.Name)
	if err := n.server.Start(); err != nil {
		return convertFileLockError(err)
	}
	// start RPC endpoints
	// 启动 RPC 端点
	err := n.startRPC()
	if err != nil {
		n.stopRPC()
		n.server.Stop()
	}
	return err
}

// stopServices terminates running services, RPC and p2p networking.
// It is the inverse of Start.
// stopServices 终止运行的服务、RPC 和 P2P 网络。它是 Start 的逆操作。
func (n *Node) stopServices(running []Lifecycle) error {
	n.stopRPC()

	// Stop running lifecycles in reverse order.
	// 按逆序停止运行的生命周期。
	failure := &StopError{Services: make(map[reflect.Type]error)}
	for i := len(running) - 1; i >= 0; i-- {
		if err := running[i].Stop(); err != nil {
			failure.Services[reflect.TypeOf(running[i])] = err
		}
	}

	// Stop p2p networking.
	// 停止 P2P 网络。
	n.server.Stop()

	if len(failure.Services) > 0 {
		return failure
	}
	return nil
}

func (n *Node) openDataDir() error {
	if n.config.DataDir == "" {
		return nil // ephemeral // 临时
	}

	instdir := filepath.Join(n.config.DataDir, n.config.name())
	if err := os.MkdirAll(instdir, 0700); err != nil {
		return err
	}
	// Lock the instance directory to prevent concurrent use by another instance as well as
	// accidental use of the instance directory as a database.
	// 锁定实例目录以防止其他实例并发使用，以及意外将实例目录用作数据库。
	n.dirLock = flock.New(filepath.Join(instdir, "LOCK"))

	if locked, err := n.dirLock.TryLock(); err != nil {
		return err
	} else if !locked {
		return ErrDatadirUsed
	}
	return nil
}

func (n *Node) closeDataDir() {
	// Release instance directory lock.
	// 释放实例目录锁。
	if n.dirLock != nil && n.dirLock.Locked() {
		n.dirLock.Unlock()
		n.dirLock = nil
	}
}

// ObtainJWTSecret loads the jwt-secret from the provided config. If the file is not
// present, it generates a new secret and stores to the given location.
// ObtainJWTSecret 从提供的配置中加载 jwt-secret。如果文件不存在，则生成一个新的 secret 并存储到给定位置。
func ObtainJWTSecret(fileName string) ([]byte, error) {
	// try reading from file
	// 尝试从文件读取
	if data, err := os.ReadFile(fileName); err == nil {
		jwtSecret := common.FromHex(strings.TrimSpace(string(data)))
		if len(jwtSecret) == 32 {
			log.Info("Loaded JWT secret file", "path", fileName, "crc32", fmt.Sprintf("%#x", crc32.ChecksumIEEE(jwtSecret)))
			return jwtSecret, nil
		}
		log.Error("Invalid JWT secret", "path", fileName, "length", len(jwtSecret))
		return nil, errors.New("invalid JWT secret")
	}
	// Need to generate one
	// 需要生成一个
	jwtSecret := make([]byte, 32)
	crand.Read(jwtSecret)
	// if we're in --dev mode, don't bother saving, just show it
	// 如果在 --dev 模式下，不保存，只显示
	if fileName == "" {
		log.Info("Generated ephemeral JWT secret", "secret", hexutil.Encode(jwtSecret))
		return jwtSecret, nil
	}
	if err := os.WriteFile(fileName, []byte(hexutil.Encode(jwtSecret)), 0600); err != nil {
		return nil, err
	}
	log.Info("Generated JWT secret", "path", fileName)
	return jwtSecret, nil
}

// obtainJWTSecret loads the jwt-secret, either from the provided config,
// or from the default location. If neither of those are present, it generates
// a new secret and stores to the default location.
// obtainJWTSecret 加载 jwt-secret，要么从提供的配置中，要么从默认位置。如果两者都不存在，则生成一个新的 secret 并存储到默认位置。
func (n *Node) obtainJWTSecret(cliParam string) ([]byte, error) {
	fileName := cliParam
	if len(fileName) == 0 {
		// no path provided, use default
		// 没有提供路径，使用默认
		fileName = n.ResolvePath(datadirJWTKey)
	}
	return ObtainJWTSecret(fileName)
}

// startRPC is a helper method to configure all the various RPC endpoints during node
// startup. It's not meant to be called at any time afterwards as it makes certain
// assumptions about the state of the node.
// startRPC 是一个辅助方法，用于在节点启动期间配置各种 RPC 端点。它不打算在之后任何时间调用，因为它对节点的状态有某些假设。
func (n *Node) startRPC() error {
	if err := n.startInProc(n.rpcAPIs); err != nil {
		return err
	}

	// Configure IPC.
	// 配置 IPC。
	if n.ipc.endpoint != "" {
		if err := n.ipc.start(n.rpcAPIs); err != nil {
			return err
		}
	}
	var (
		servers           []*httpServer
		openAPIs, allAPIs = n.getAPIs()
	)

	rpcConfig := rpcEndpointConfig{
		batchItemLimit:         n.config.BatchRequestLimit,
		batchResponseSizeLimit: n.config.BatchResponseMaxSize,
	}

	initHttp := func(server *httpServer, port int) error {
		if err := server.setListenAddr(n.config.HTTPHost, port); err != nil {
			return err
		}
		if err := server.enableRPC(openAPIs, httpConfig{
			CorsAllowedOrigins: n.config.HTTPCors,
			Vhosts:             n.config.HTTPVirtualHosts,
			Modules:            n.config.HTTPModules,
			prefix:             n.config.HTTPPathPrefix,
			rpcEndpointConfig:  rpcConfig,
		}); err != nil {
			return err
		}
		servers = append(servers, server)
		return nil
	}

	initWS := func(port int) error {
		server := n.wsServerForPort(port, false)
		if err := server.setListenAddr(n.config.WSHost, port); err != nil {
			return err
		}
		if err := server.enableWS(openAPIs, wsConfig{
			Modules:           n.config.WSModules,
			Origins:           n.config.WSOrigins,
			prefix:            n.config.WSPathPrefix,
			rpcEndpointConfig: rpcConfig,
		}); err != nil {
			return err
		}
		servers = append(servers, server)
		return nil
	}

	initAuth := func(port int, secret []byte) error {
		// Enable auth via HTTP
		// 通过 HTTP 启用认证
		server := n.httpAuth
		if err := server.setListenAddr(n.config.AuthAddr, port); err != nil {
			return err
		}
		sharedConfig := rpcEndpointConfig{
			jwtSecret:              secret,
			batchItemLimit:         engineAPIBatchItemLimit,
			batchResponseSizeLimit: engineAPIBatchResponseSizeLimit,
			httpBodyLimit:          engineAPIBodyLimit,
		}
		err := server.enableRPC(allAPIs, httpConfig{
			CorsAllowedOrigins: DefaultAuthCors,
			Vhosts:             n.config.AuthVirtualHosts,
			Modules:            DefaultAuthModules,
			prefix:             DefaultAuthPrefix,
			rpcEndpointConfig:  sharedConfig,
		})
		if err != nil {
			return err
		}
		servers = append(servers, server)

		// Enable auth via WS
		// 通过 WS 启用认证
		server = n.wsServerForPort(port, true)
		if err := server.setListenAddr(n.config.AuthAddr, port); err != nil {
			return err
		}
		if err := server.enableWS(allAPIs, wsConfig{
			Modules:           DefaultAuthModules,
			Origins:           DefaultAuthOrigins,
			prefix:            DefaultAuthPrefix,
			rpcEndpointConfig: sharedConfig,
		}); err != nil {
			return err
		}
		servers = append(servers, server)
		return nil
	}

	// Set up HTTP.
	// 设置 HTTP。
	if n.config.HTTPHost != "" {
		// Configure legacy unauthenticated HTTP.
		// 配置传统的未认证 HTTP。
		if err := initHttp(n.http, n.config.HTTPPort); err != nil {
			return err
		}
	}
	// Configure WebSocket.
	// 配置 WebSocket。
	if n.config.WSHost != "" {
		// legacy unauthenticated
		// 传统的未认证
		if err := initWS(n.config.WSPort); err != nil {
			return err
		}
	}
	// Configure authenticated API
	// 配置认证 API
	if len(openAPIs) != len(allAPIs) {
		jwtSecret, err := n.obtainJWTSecret(n.config.JWTSecret)
		if err != nil {
			return err
		}
		if err := initAuth(n.config.AuthPort, jwtSecret); err != nil {
			return err
		}
	}
	// Start the servers
	// 启动服务器
	for _, server := range servers {
		if err := server.start(); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) wsServerForPort(port int, authenticated bool) *httpServer {
	httpServer, wsServer := n.http, n.ws
	if authenticated {
		httpServer, wsServer = n.httpAuth, n.wsAuth
	}
	if n.config.HTTPHost == "" || httpServer.port == port {
		return httpServer
	}
	return wsServer
}

func (n *Node) stopRPC() {
	n.http.stop()
	n.ws.stop()
	n.httpAuth.stop()
	n.wsAuth.stop()
	n.ipc.stop()
	n.stopInProc()
}

// startInProc registers all RPC APIs on the inproc server.
// startInProc 在 inproc 服务器上注册所有 RPC API。
func (n *Node) startInProc(apis []rpc.API) error {
	for _, api := range apis {
		if err := n.inprocHandler.RegisterName(api.Namespace, api.Service); err != nil {
			return err
		}
	}
	return nil
}

// stopInProc terminates the in-process RPC endpoint.
// stopInProc 终止进程内 RPC 端点。
func (n *Node) stopInProc() {
	n.inprocHandler.Stop()
}

// Wait blocks until the node is closed.
// Wait 阻塞直到节点关闭。
func (n *Node) Wait() {
	<-n.stop
}

// RegisterLifecycle registers the given Lifecycle on the node.
// RegisterLifecycle 在节点上注册给定的 Lifecycle。
func (n *Node) RegisterLifecycle(lifecycle Lifecycle) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register lifecycle on running/stopped node")
	}
	if slices.Contains(n.lifecycles, lifecycle) {
		panic(fmt.Sprintf("attempt to register lifecycle %T more than once", lifecycle))
	}
	n.lifecycles = append(n.lifecycles, lifecycle)
}

// RegisterProtocols adds backend's protocols to the node's p2p server.
// RegisterProtocols 将后端的协议添加到节点的 P2P 服务器。
func (n *Node) RegisterProtocols(protocols []p2p.Protocol) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register protocols on running/stopped node")
	}
	n.server.Protocols = append(n.server.Protocols, protocols...)
}

// RegisterAPIs registers the APIs a service provides on the node.
// RegisterAPIs 注册服务在节点上提供的 API。
func (n *Node) RegisterAPIs(apis []rpc.API) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register APIs on running/stopped node")
	}
	n.rpcAPIs = append(n.rpcAPIs, apis...)
}

// getAPIs return two sets of APIs, both the ones that do not require
// authentication, and the complete set
// getAPIs 返回两组 API，一组是不需要认证的，另一组是完整的
func (n *Node) getAPIs() (unauthenticated, all []rpc.API) {
	for _, api := range n.rpcAPIs {
		if !api.Authenticated {
			unauthenticated = append(unauthenticated, api)
		}
	}
	return unauthenticated, n.rpcAPIs
}

// RegisterHandler mounts a handler on the given path on the canonical HTTP server.
// RegisterHandler 在规范的 HTTP 服务器上的给定路径上挂载一个处理程序。
func (n *Node) RegisterHandler(name, path string, handler http.Handler) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state != initializingState {
		panic("can't register HTTP handler on running/stopped node")
	}

	n.http.mux.Handle(path, handler)
	n.http.handlerNames[path] = name
}

// Attach creates an RPC client attached to an in-process API handler.
// Attach 创建一个附加到进程内 API 处理程序的 RPC 客户端。
func (n *Node) Attach() *rpc.Client {
	return rpc.DialInProc(n.inprocHandler)
}

// RPCHandler returns the in-process RPC request handler.
// RPCHandler 返回进程内 RPC 请求处理程序。
func (n *Node) RPCHandler() (*rpc.Server, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.state == closedState {
		return nil, ErrNodeStopped
	}
	return n.inprocHandler, nil
}

// Config returns the configuration of node.
// Config 返回节点的配置。
func (n *Node) Config() *Config {
	return n.config
}

// Server retrieves the currently running P2P network layer. This method is meant
// only to inspect fields of the currently running server. Callers should not
// start or stop the returned server.
// Server 检索当前运行的 P2P 网络层。此方法仅用于检查当前运行服务器的字段。调用者不应启动或停止返回的服务器。
func (n *Node) Server() *p2p.Server {
	n.lock.Lock()
	defer n.lock.Unlock()

	return n.server
}

// DataDir retrieves the current datadir used by the protocol stack.
// Deprecated: No files should be stored in this directory, use InstanceDir instead.
// DataDir 检索协议栈使用的当前 datadir。已弃用：不应在此目录中存储文件，请改用 InstanceDir。
func (n *Node) DataDir() string {
	return n.config.DataDir
}

// InstanceDir retrieves the instance directory used by the protocol stack.
// InstanceDir 检索协议栈使用的实例目录。
func (n *Node) InstanceDir() string {
	return n.config.instanceDir()
}

// KeyStoreDir retrieves the key directory
// KeyStoreDir 检索密钥目录
func (n *Node) KeyStoreDir() string {
	return n.keyDir
}

// AccountManager retrieves the account manager used by the protocol stack.
// AccountManager 检索协议栈使用的账户管理器。
func (n *Node) AccountManager() *accounts.Manager {
	return n.accman
}

// IPCEndpoint retrieves the current IPC endpoint used by the protocol stack.
// IPCEndpoint 检索协议栈使用的当前 IPC 端点。
func (n *Node) IPCEndpoint() string {
	return n.ipc.endpoint
}

// HTTPEndpoint returns the URL of the HTTP server. Note that this URL does not
// contain the JSON-RPC path prefix set by HTTPPathPrefix.
// HTTPEndpoint 返回 HTTP 服务器的 URL。请注意，此 URL 不包含由 HTTPPathPrefix 设置的 JSON-RPC 路径前缀。
func (n *Node) HTTPEndpoint() string {
	return "http://" + n.http.listenAddr()
}

// WSEndpoint returns the current JSON-RPC over WebSocket endpoint.
// WSEndpoint 返回当前的 JSON-RPC over WebSocket 端点。
func (n *Node) WSEndpoint() string {
	if n.http.wsAllowed() {
		return "ws://" + n.http.listenAddr() + n.http.wsConfig.prefix
	}
	return "ws://" + n.ws.listenAddr() + n.ws.wsConfig.prefix
}

// HTTPAuthEndpoint returns the URL of the authenticated HTTP server.
// HTTPAuthEndpoint 返回认证 HTTP 服务器的 URL。
func (n *Node) HTTPAuthEndpoint() string {
	return "http://" + n.httpAuth.listenAddr()
}

// WSAuthEndpoint returns the current authenticated JSON-RPC over WebSocket endpoint.
// WSAuthEndpoint 返回当前的认证 JSON-RPC over WebSocket 端点。
func (n *Node) WSAuthEndpoint() string {
	if n.httpAuth.wsAllowed() {
		return "ws://" + n.httpAuth.listenAddr() + n.httpAuth.wsConfig.prefix
	}
	return "ws://" + n.wsAuth.listenAddr() + n.wsAuth.wsConfig.prefix
}

// EventMux retrieves the event multiplexer used by all the network services in
// the current protocol stack.
// EventMux 检索当前协议栈中所有网络服务使用的事件多路复用器。
func (n *Node) EventMux() *event.TypeMux {
	return n.eventmux
}

// OpenDatabase opens an existing database with the given name (or creates one if no
// previous can be found) from within the node's instance directory. If the node is
// ephemeral, a memory database is returned.
// OpenDatabase 从节点的实例目录中打开一个现有的数据库（如果找不到则创建一个）。如果节点是临时的，则返回内存数据库。
func (n *Node) OpenDatabase(name string, cache, handles int, namespace string, readonly bool) (ethdb.Database, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.state == closedState {
		return nil, ErrNodeStopped
	}

	var db ethdb.Database
	var err error
	if n.config.DataDir == "" {
		db = rawdb.NewMemoryDatabase()
	} else {
		db, err = openDatabase(openOptions{
			Type:      n.config.DBEngine,
			Directory: n.ResolvePath(name),
			Namespace: namespace,
			Cache:     cache,
			Handles:   handles,
			ReadOnly:  readonly,
		})
	}
	if err == nil {
		db = n.wrapDatabase(db)
	}
	return db, err
}

// OpenDatabaseWithFreezer opens an existing database with the given name (or
// creates one if no previous can be found) from within the node's data directory,
// also attaching a chain freezer to it that moves ancient chain data from the
// database to immutable append-only files. If the node is an ephemeral one, a
// memory database is returned.
// OpenDatabaseWithFreezer 从节点的数据目录中打开一个现有的数据库（如果找不到则创建一个），同时附加一个链 freezer，将古老的链数据从数据库移动到不可变的仅追加文件。如果节点是临时的，则返回内存数据库。
func (n *Node) OpenDatabaseWithFreezer(name string, cache, handles int, ancient string, namespace string, readonly bool) (ethdb.Database, error) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.state == closedState {
		return nil, ErrNodeStopped
	}
	var db ethdb.Database
	var err error
	if n.config.DataDir == "" {
		db, err = rawdb.NewDatabaseWithFreezer(memorydb.New(), "", namespace, readonly)
	} else {
		db, err = openDatabase(openOptions{
			Type:              n.config.DBEngine,
			Directory:         n.ResolvePath(name),
			AncientsDirectory: n.ResolveAncient(name, ancient),
			Namespace:         namespace,
			Cache:             cache,
			Handles:           handles,
			ReadOnly:          readonly,
		})
	}
	if err == nil {
		db = n.wrapDatabase(db)
	}
	return db, err
}

// ResolvePath returns the absolute path of a resource in the instance directory.
// ResolvePath 返回实例目录中资源的绝对路径。
func (n *Node) ResolvePath(x string) string {
	return n.config.ResolvePath(x)
}

// ResolveAncient returns the absolute path of the root ancient directory.
// ResolveAncient 返回根 ancient 目录的绝对路径。
func (n *Node) ResolveAncient(name string, ancient string) string {
	switch {
	case ancient == "":
		ancient = filepath.Join(n.ResolvePath(name), "ancient")
	case !filepath.IsAbs(ancient):
		ancient = n.ResolvePath(ancient)
	}
	return ancient
}

// closeTrackingDB wraps the Close method of a database. When the database is closed by the
// service, the wrapper removes it from the node's database map. This ensures that Node
// won't auto-close the database if it is closed by the service that opened it.
// closeTrackingDB 包装数据库的 Close 方法。当服务关闭数据库时，包装器将其从节点的数据库映射中移除。这确保了如果数据库被打开它的服务关闭，Node 不会自动关闭数据库。
type closeTrackingDB struct {
	ethdb.Database
	n *Node
}

func (db *closeTrackingDB) Close() error {
	db.n.lock.Lock()
	delete(db.n.databases, db)
	db.n.lock.Unlock()
	return db.Database.Close()
}

// wrapDatabase ensures the database will be auto-closed when Node is closed.
// wrapDatabase 确保数据库在 Node 关闭时自动关闭。
func (n *Node) wrapDatabase(db ethdb.Database) ethdb.Database {
	wrapper := &closeTrackingDB{db, n}
	n.databases[wrapper] = struct{}{}
	return wrapper
}

// closeDatabases closes all open databases.
// closeDatabases 关闭所有打开的数据库。
func (n *Node) closeDatabases() (errors []error) {
	for db := range n.databases {
		delete(n.databases, db)
		if err := db.Database.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	return errors
}
