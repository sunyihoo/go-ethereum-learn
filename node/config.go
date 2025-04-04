// Copyright 2014 The go-ethereum Authors
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
	"crypto/ecdsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
)

// devp2p 协议
// 背景：devp2p 是以太坊的点对点网络协议，用于节点发现和数据交换。
// 关联：NodeName 方法生成的节点标识符（如 Geth/v1.10.0/linux-amd64/go1.16）在 devp2p 中用于唯一标识节点。
// EIP-155
// 背景：EIP-155（Ethereum Improvement Proposal 155）引入了链 ID 到交易签名中，防止跨链重放攻击。
// 关联：AllowUnprotectedTxs 允许发送未受 EIP-155 保护的交易，可能用于测试或兼容旧系统，但安全性较低。
// JWT 认证
// 背景：JWT（JSON Web Token）在以太坊合并后用于引擎 API 的认证，确保节点与执行客户端之间的安全通信。
// 关联：JWTSecret 指定 JWT 秘密的路径，用于生成认证令牌。
// CORS 和 DNS 重绑定防护
// 背景：CORS（跨源资源共享）是浏览器安全机制，而 DNS 重绑定是一种绕过 SOP（同源策略）的攻击方式。
// 关联：HTTPCors 和 HTTPVirtualHosts 用于限制请求来源，防止恶意访问。
// 临时节点
// 背景：临时节点不持久化数据，适合开发和测试场景。
// 关联：当 DataDir 为空时，节点以临时模式运行，数据存储在内存中。

const (
	datadirPrivateKey = "nodekey" // Path within the datadir to the node's private key
	// 数据目录中节点私钥的路径
	datadirJWTKey = "jwtsecret" // Path within the datadir to the node's jwt secret
	// 数据目录中节点 JWT 秘密的路径
	datadirDefaultKeyStore = "keystore" // Path within the datadir to the keystore
	// 数据目录中密钥存储的路径
	datadirStaticNodes = "static-nodes.json" // Path within the datadir to the static node list
	// 数据目录中静态节点列表的路径
	datadirTrustedNodes = "trusted-nodes.json" // Path within the datadir to the trusted node list
	// 数据目录中受信任节点列表的路径
	datadirNodeDatabase = "nodes" // Path within the datadir to store the node infos
	// 数据目录中存储节点信息的路径
)

// Config represents a small collection of configuration values to fine tune the
// P2P network layer of a protocol stack. These values can be further extended by
// all registered services.
// Config 表示一小部分配置值，用于微调协议栈的 P2P 网络层。
// 这些值可以被所有注册的服务进一步扩展。
type Config struct {
	// 节点身份相关

	// Name sets the instance name of the node. It must not contain the / character and is
	// used in the devp2p node identifier. The instance name of geth is "geth". If no
	// value is specified, the basename of the current executable is used.
	// 节点的实例名称，用于 devp2p 节点标识符。默认为当前可执行文件的名称。
	// Name 设置节点的实例名称。该名称不能包含 `/` 字符，
	// 并用于 devp2p 节点标识符。Geth 的实例名称为 "geth"。
	// 如果未指定值，则使用当前可执行文件的名称。
	Name string `toml:"-"`

	// UserIdent, if set, is used as an additional component in the devp2p node identifier.
	// 用户自定义标识符，作为 devp2p 节点标识符的附加组件。
	UserIdent string `toml:",omitempty"`

	// Version should be set to the version number of the program. It is used
	// in the devp2p node identifier.
	// 程序版本号，用于 devp2p 节点标识符。
	Version string `toml:"-"`

	// DataDir is the file system folder the node should use for any data storage
	// requirements. The configured data directory will not be directly shared with
	// registered services, instead those can use utility methods to create/access
	// databases or flat files. This enables ephemeral nodes which can fully reside
	// in memory.
	// 节点用于数据存储的文件系统目录。注册的服务可以通过工具方法访问或创建数据库或文件。
	DataDir string

	// Configuration of peer-to-peer networking.
	// P2P 网络的配置。
	P2P p2p.Config

	// KeyStoreDir is the file system folder that contains private keys. The directory can
	// be specified as a relative path, in which case it is resolved relative to the
	// current directory.
	//
	// If KeyStoreDir is empty, the default location is the "keystore" subdirectory of
	// DataDir. If DataDir is unspecified and KeyStoreDir is empty, an ephemeral directory
	// is created by New and destroyed when the node is stopped.
	// 存储私钥的文件系统目录。如果未指定，则默认为 DataDir 下的 keystore 子目录。
	KeyStoreDir string `toml:",omitempty"`

	// ExternalSigner specifies an external URI for a clef-type signer.
	// 外部签名器（如 Clef）的 URI。
	ExternalSigner string `toml:",omitempty"`

	// UseLightweightKDF lowers the memory and CPU requirements of the key store
	// scrypt KDF at the expense of security.
	// 降低密钥存储的安全级别以减少内存和 CPU 使用。
	UseLightweightKDF bool `toml:",omitempty"`

	// InsecureUnlockAllowed is a deprecated option to allow users to accounts in unsafe http environment.
	// 允许在不安全的 HTTP 环境中解锁账户（已弃用）。
	InsecureUnlockAllowed bool `toml:",omitempty"`

	// NoUSB disables hardware wallet monitoring and connectivity.
	// Deprecated: USB monitoring is disabled by default and must be enabled explicitly.
	// 禁用硬件钱包监控和连接（已弃用）。
	NoUSB bool `toml:",omitempty"`

	// USB enables hardware wallet monitoring and connectivity.
	// 启用硬件钱包监控和连接。
	USB bool `toml:",omitempty"`

	// SmartCardDaemonPath is the path to the smartcard daemon's socket.
	// 智能卡守护程序的套接字路径。
	SmartCardDaemonPath string `toml:",omitempty"`

	// IPCPath is the requested location to place the IPC endpoint. If the path is
	// a simple file name, it is placed inside the data directory (or on the root
	// pipe path on Windows), whereas if it's a resolvable path name (absolute or
	// relative), then that specific path is enforced. An empty path disables IPC.
	// IPC 端点的路径。如果为空，则禁用 IPC。
	IPCPath string

	// HTTPHost is the host interface on which to start the HTTP RPC server. If this
	// field is empty, no HTTP API endpoint will be started.
	// HTTPHost 是启动 HTTP RPC 服务器的主机接口。如果此字段为空，则不会启动 HTTP API 端点。
	HTTPHost string

	// HTTPPort is the TCP port number on which to start the HTTP RPC server. The
	// default zero value is valid and will pick a port number randomly (useful
	// for ephemeral nodes).
	// HTTPPort 是启动 HTTP RPC 服务器的 TCP 端口号。默认的零值是有效的，并将随机选择一个端口号（对临时节点有用）。
	HTTPPort int `toml:",omitempty"`

	// HTTPCors is the Cross-Origin Resource Sharing header to send to requesting
	// clients. Please be aware that CORS is a browser enforced security, it's fully
	// useless for custom HTTP clients.
	// HTTPCors 是发送给请求客户端的跨源资源共享头。请注意，CORS 是浏览器强制执行的安全性，对于自定义 HTTP 客户端完全无用。
	HTTPCors []string `toml:",omitempty"`

	// HTTPVirtualHosts is the list of virtual hostnames which are allowed on incoming requests.
	// This is by default {'localhost'}. Using this prevents attacks like
	// DNS rebinding, which bypasses SOP by simply masquerading as being within the same
	// origin. These attacks do not utilize CORS, since they are not cross-domain.
	// By explicitly checking the Host-header, the server will not allow requests
	// made against the server with a malicious host domain.
	// Requests using ip address directly are not affected
	// HTTPVirtualHosts 是允许在传入请求中的虚拟主机名列表。默认情况下为 {'localhost'}。
	// 使用此功能可防止像 DNS 重绑定这样的攻击，这些攻击通过简单地伪装成在同一来源内来绕过 SOP。
	HTTPVirtualHosts []string `toml:",omitempty"`

	// HTTPModules is a list of API modules to expose via the HTTP RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	// HTTPModules 是通过 HTTP RPC 接口公开的 API 模块列表。
	// 如果模块列表为空，则将公开所有指定为公共的 RPC API 端点。
	HTTPModules []string

	// HTTPTimeouts allows for customization of the timeout values used by the HTTP RPC
	// interface.
	// HTTPTimeouts 允许自定义 HTTP RPC 接口使用的超时值。
	HTTPTimeouts rpc.HTTPTimeouts

	// HTTPPathPrefix specifies a path prefix on which http-rpc is to be served.
	// HTTPPathPrefix 指定 http-rpc 服务的路径前缀。
	HTTPPathPrefix string `toml:",omitempty"`

	// AuthAddr is the listening address on which authenticated APIs are provided.
	// AuthAddr 是提供认证 API 的监听地址。
	AuthAddr string `toml:",omitempty"`

	// AuthPort is the port number on which authenticated APIs are provided.
	// AuthPort 是提供认证 API 的端口号。
	AuthPort int `toml:",omitempty"`

	// AuthVirtualHosts is the list of virtual hostnames which are allowed on incoming requests
	// for the authenticated api. This is by default {'localhost'}.
	// AuthVirtualHosts 是允许在认证 API 的传入请求中的虚拟主机名列表。默认情况下为 {'localhost'}。
	AuthVirtualHosts []string `toml:",omitempty"`

	// WSHost is the host interface on which to start the websocket RPC server. If
	// this field is empty, no websocket API endpoint will be started.
	// WSHost 是启动 websocket RPC 服务器的主机接口。如果此字段为空，则不会启动 websocket API 端点。
	WSHost string

	// WSPort is the TCP port number on which to start the websocket RPC server. The
	// default zero value is valid and will pick a port number randomly (useful for
	// ephemeral nodes).
	// WSPort 是启动 websocket RPC 服务器的 TCP 端口号。默认的零值是有效的，并将随机选择一个端口号（对临时节点有用）。
	WSPort int `toml:",omitempty"`

	// WSPathPrefix specifies a path prefix on which ws-rpc is to be served.
	// WSPathPrefix 指定 ws-rpc 服务的路径前缀。
	WSPathPrefix string `toml:",omitempty"`

	// WSOrigins is the list of domain to accept websocket requests from. Please be
	// aware that the server can only act upon the HTTP request the client sends and
	// cannot verify the validity of the request header.
	// WSOrigins 是接受 websocket 请求的域列表。请注意，服务器只能根据客户端发送的 HTTP 请求采取行动，
	// 无法验证请求头的有效性。
	WSOrigins []string `toml:",omitempty"`

	// WSModules is a list of API modules to expose via the websocket RPC interface.
	// If the module list is empty, all RPC API endpoints designated public will be
	// exposed.
	// WSModules 是通过 websocket RPC 接口公开的 API 模块列表。
	// 如果模块列表为空，则将公开所有指定为公共的 RPC API 端点。
	WSModules []string

	// WSExposeAll exposes all API modules via the WebSocket RPC interface rather
	// than just the public ones.
	//
	// *WARNING* Only set this if the node is running in a trusted network, exposing
	// private APIs to untrusted users is a major security risk.
	// WSExposeAll 通过 WebSocket RPC 接口公开所有 API 模块，而不仅仅是公共的。
	// *警告* 仅在节点在受信任的网络中运行时设置此项，向不受信任的用户公开私有 API 是重大的安全风险。
	WSExposeAll bool `toml:",omitempty"`

	// GraphQLCors is the Cross-Origin Resource Sharing header to send to requesting
	// clients. Please be aware that CORS is a browser enforced security, it's fully
	// useless for custom HTTP clients.
	// GraphQLCors 是发送给请求客户端的跨源资源共享头。请注意，CORS 是浏览器强制执行的安全性，对于自定义 HTTP 客户端完全无用。
	GraphQLCors []string `toml:",omitempty"`

	// GraphQLVirtualHosts is the list of virtual hostnames which are allowed on incoming requests.
	// This is by default {'localhost'}. Using this prevents attacks like
	// DNS rebinding, which bypasses SOP by simply masquerading as being within the same
	// origin. These attacks do not utilize CORS, since they are not cross-domain.
	// By explicitly checking the Host-header, the server will not allow requests
	// made against the server with a malicious host domain.
	// Requests using ip address directly are not affected
	// GraphQLVirtualHosts 是允许在传入请求中的虚拟主机名列表。默认情况下为 {'localhost'}。
	// 使用此功能可防止像 DNS 重绑定这样的攻击，这些攻击通过简单地伪装成在同一来源内来绕过 SOP。
	GraphQLVirtualHosts []string `toml:",omitempty"`

	// Logger is a custom logger to use with the p2p.Server.
	// Logger 是与 p2p.Server 一起使用的自定义日志记录器。
	Logger log.Logger `toml:",omitempty"`

	oldGethResourceWarning bool

	// AllowUnprotectedTxs allows non EIP-155 protected transactions to be send over RPC.
	// AllowUnprotectedTxs 允许通过 RPC 发送未受 EIP-155 保护的交易。
	AllowUnprotectedTxs bool `toml:",omitempty"`

	// BatchRequestLimit is the maximum number of requests in a batch.
	// BatchRequestLimit 是批处理中的最大请求数。
	BatchRequestLimit int `toml:",omitempty"`

	// BatchResponseMaxSize is the maximum number of bytes returned from a batched rpc call.
	// BatchResponseMaxSize 是从批处理 RPC 调用返回的最大字节数。
	BatchResponseMaxSize int `toml:",omitempty"`

	// JWTSecret is the path to the hex-encoded jwt secret.
	// JWTSecret 是十六进制编码的 JWT 秘密的路径。
	JWTSecret string `toml:",omitempty"`

	// EnablePersonal enables the deprecated personal namespace.
	// EnablePersonal 启用已弃用的 personal 命名空间。
	EnablePersonal bool `toml:"-"`

	DBEngine string `toml:",omitempty"`
}

// IPCEndpoint resolves an IPC endpoint based on a configured value, taking into
// account the set data folders as well as the designated platform we're currently
// running on.
// IPCEndpoint 根据配置的值解析 IPC 端点，
// 同时考虑到设置的数据目录以及当前运行的平台。
// IPC（Inter-Process Communication，进程间通信）是一种允许不同进程之间进行数据交换的机制。
// 在以太坊节点中，IPC 通常用于本地客户端（如 geth）与其他程序（如钱包或 DApp）之间的通信。
func (c *Config) IPCEndpoint() string {
	// Short circuit if IPC has not been enabled
	if c.IPCPath == "" {
		return ""
	}
	// On windows we can only use plain top-level pipes
	if runtime.GOOS == "windows" {
		if strings.HasPrefix(c.IPCPath, `\\.\pipe\`) {
			return c.IPCPath
		}
		return `\\.\pipe\` + c.IPCPath
	}
	// Resolve names into the data directory full paths otherwise
	if filepath.Base(c.IPCPath) == c.IPCPath {
		if c.DataDir == "" {
			return filepath.Join(os.TempDir(), c.IPCPath)
		}
		return filepath.Join(c.DataDir, c.IPCPath)
	}
	return c.IPCPath
}

// NodeDB returns the path to the discovery node database.
// NodeDB 返回发现节点数据库的路径。
func (c *Config) NodeDB() string {
	if c.DataDir == "" {
		return "" // ephemeral
	}
	return c.ResolvePath(datadirNodeDatabase)
}

// DefaultIPCEndpoint returns the IPC path used by default.
// DefaultIPCEndpoint 返回默认使用的 IPC 路径。
func DefaultIPCEndpoint(clientIdentifier string) string {
	if clientIdentifier == "" {
		clientIdentifier = strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
		if clientIdentifier == "" {
			panic("empty executable name")
		}
	}
	config := &Config{DataDir: DefaultDataDir(), IPCPath: clientIdentifier + ".ipc"}
	return config.IPCEndpoint()
}

// HTTPEndpoint resolves an HTTP endpoint based on the configured host interface
// and port parameters.
// HTTPEndpoint 根据配置的主机接口和端口参数解析 HTTP 端点。
func (c *Config) HTTPEndpoint() string {
	if c.HTTPHost == "" {
		return ""
	}
	return net.JoinHostPort(c.HTTPHost, fmt.Sprintf("%d", c.HTTPPort))
}

// DefaultHTTPEndpoint returns the HTTP endpoint used by default.
// DefaultHTTPEndpoint 返回默认使用的 HTTP 端点。
func DefaultHTTPEndpoint() string {
	config := &Config{HTTPHost: DefaultHTTPHost, HTTPPort: DefaultHTTPPort, AuthPort: DefaultAuthPort}
	return config.HTTPEndpoint()
}

// WSEndpoint resolves a websocket endpoint based on the configured host interface
// and port parameters.
// WSEndpoint 根据配置的主机接口和端口参数解析 WebSocket 端点。
func (c *Config) WSEndpoint() string {
	if c.WSHost == "" {
		return ""
	}
	return net.JoinHostPort(c.WSHost, fmt.Sprintf("%d", c.WSPort))
}

// DefaultWSEndpoint returns the websocket endpoint used by default.
// DefaultWSEndpoint 返回默认使用的 WebSocket 端点。
func DefaultWSEndpoint() string {
	config := &Config{WSHost: DefaultWSHost, WSPort: DefaultWSPort}
	return config.WSEndpoint()
}

// ExtRPCEnabled returns the indicator whether node enables the external
// RPC(http, ws or graphql).
// ExtRPCEnabled 返回节点是否启用外部 RPC（HTTP、WS 或 GraphQL）的指示器。
func (c *Config) ExtRPCEnabled() bool {
	return c.HTTPHost != "" || c.WSHost != ""
}

// NodeName returns the devp2p node identifier.
// NodeName 返回 devp2p 节点标识符。
func (c *Config) NodeName() string {
	name := c.name()
	// Backwards compatibility: previous versions used title-cased "Geth", keep that.
	// 向后兼容：以前的版本使用标题大小写的 "Geth"，保持不变。
	if name == "geth" || name == "geth-testnet" {
		name = "Geth"
	}
	if c.UserIdent != "" {
		name += "/" + c.UserIdent
	}
	if c.Version != "" {
		name += "/v" + c.Version
	}
	name += "/" + runtime.GOOS + "-" + runtime.GOARCH
	name += "/" + runtime.Version()
	return name
}

func (c *Config) name() string {
	if c.Name == "" {
		progname := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
		if progname == "" {
			panic("empty executable name, set Config.Name")
		}
		return progname
	}
	return c.Name
}

// These resources are resolved differently for "geth" instances.
// 这些资源在 "geth" 实例中以不同方式解析。
var isOldGethResource = map[string]bool{
	"chaindata":          true,
	"nodes":              true,
	"nodekey":            true,
	"static-nodes.json":  false, // no warning for these because they have their
	"trusted-nodes.json": false, // own separate warning.
	// 不对这些文件发出警告，因为它们有单独的警告机制。
}

// ResolvePath resolves path in the instance directory.
// ResolvePath 解析实例目录中的路径。
func (c *Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if c.DataDir == "" {
		return ""
	}
	// Backwards-compatibility: ensure that data directory files created
	// by geth 1.4 are used if they exist.
	// 向后兼容：确保如果存在 geth 1.4 创建的数据目录文件，则使用它们。
	if warn, isOld := isOldGethResource[path]; isOld {
		oldpath := ""
		if c.name() == "geth" {
			oldpath = filepath.Join(c.DataDir, path)
		}
		if oldpath != "" && common.FileExist(oldpath) {
			if warn && !c.oldGethResourceWarning {
				c.oldGethResourceWarning = true
				log.Warn("Using deprecated resource file, please move this file to the 'geth' subdirectory of datadir.", "file", oldpath)
			}
			return oldpath
		}
	}
	return filepath.Join(c.instanceDir(), path)
}

func (c *Config) instanceDir() string {
	if c.DataDir == "" {
		return ""
	}
	return filepath.Join(c.DataDir, c.name())
}

// NodeKey retrieves the currently configured private key of the node, checking
// first any manually set key, falling back to the one found in the configured
// data folder. If no key can be found, a new one is generated.
// NodeKey 获取当前配置的节点私钥，
// 首先检查是否存在手动设置的密钥，如果未找到则回退到配置的数据目录中的密钥。
// 如果仍未找到，则生成一个新的密钥。
func (c *Config) NodeKey() *ecdsa.PrivateKey {
	// Use any specifically configured key.
	// 使用任何手动设置的密钥。
	if c.P2P.PrivateKey != nil {
		return c.P2P.PrivateKey
	}
	// Generate ephemeral key if no datadir is being used.
	// 如果未使用数据目录，则生成临时密钥。
	if c.DataDir == "" {
		key, err := crypto.GenerateKey()
		if err != nil {
			log.Crit(fmt.Sprintf("Failed to generate ephemeral node key: %v", err))
		}
		return key
	}

	keyfile := c.ResolvePath(datadirPrivateKey)
	if key, err := crypto.LoadECDSA(keyfile); err == nil {
		return key
	}
	// No persistent key found, generate and store a new one.
	// 未找到持久化的密钥，生成并存储一个新的密钥。
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate node key: %v", err))
	}
	instanceDir := filepath.Join(c.DataDir, c.name())
	if err := os.MkdirAll(instanceDir, 0700); err != nil {
		log.Error(fmt.Sprintf("Failed to persist node key: %v", err))
		return key
	}
	keyfile = filepath.Join(instanceDir, datadirPrivateKey)
	if err := crypto.SaveECDSA(keyfile, key); err != nil {
		log.Error(fmt.Sprintf("Failed to persist node key: %v", err))
	}
	return key
}

// checkLegacyFiles inspects the datadir for signs of legacy static-nodes
// and trusted-nodes files. If they exist it raises an error.
// checkLegacyFiles 检查数据目录中是否存在遗留的 static-nodes 和 trusted-nodes 文件。
// 如果存在，则引发错误。
func (c *Config) checkLegacyFiles() {
	c.checkLegacyFile(c.ResolvePath(datadirStaticNodes))
	c.checkLegacyFile(c.ResolvePath(datadirTrustedNodes))
}

// checkLegacyFile will only raise an error if a file at the given path exists.
// checkLegacyFile 仅在给定路径的文件存在时引发错误。
func (c *Config) checkLegacyFile(path string) {
	// Short circuit if no node config is present
	// 如果没有节点配置，直接返回
	if c.DataDir == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	logger := c.Logger
	if logger == nil {
		logger = log.Root()
	}
	switch fname := filepath.Base(path); fname {
	case "static-nodes.json":
		logger.Error("The static-nodes.json file is deprecated and ignored. Use P2P.StaticNodes in config.toml instead.")
		// static-nodes.json 文件已弃用并被忽略。请在 config.toml 中使用 P2P.StaticNodes 代替。
	case "trusted-nodes.json":
		logger.Error("The trusted-nodes.json file is deprecated and ignored. Use P2P.TrustedNodes in config.toml instead.")
		// trusted-nodes.json 文件已弃用并被忽略。请在 config.toml 中使用 P2P.TrustedNodes 代替。
	default:
		// We shouldn't wind up here, but better print something just in case.
		// 我们不应该到达这里，但以防万一还是打印一些信息。
		logger.Error("Ignoring deprecated file.", "file", path)
	}
}

// KeyDirConfig determines the settings for keydirectory
// KeyDirConfig 确定密钥目录的设置
func (c *Config) KeyDirConfig() (string, error) {
	var (
		keydir string
		err    error
	)
	switch {
	case filepath.IsAbs(c.KeyStoreDir):
		keydir = c.KeyStoreDir
	case c.DataDir != "":
		if c.KeyStoreDir == "" {
			keydir = filepath.Join(c.DataDir, datadirDefaultKeyStore)
		} else {
			keydir, err = filepath.Abs(c.KeyStoreDir)
		}
	case c.KeyStoreDir != "":
		keydir, err = filepath.Abs(c.KeyStoreDir)
	}
	return keydir, err
}

// GetKeyStoreDir retrieves the key directory and will create
// and ephemeral one if necessary.
// GetKeyStoreDir 检索密钥目录，并在必要时创建临时目录。
func (c *Config) GetKeyStoreDir() (string, bool, error) {
	keydir, err := c.KeyDirConfig()
	if err != nil {
		return "", false, err
	}
	isEphemeral := false
	if keydir == "" {
		// There is no datadir.
		// 没有数据目录。
		keydir, err = os.MkdirTemp("", "go-ethereum-keystore")
		isEphemeral = true
	}

	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(keydir, 0700); err != nil {
		return "", false, err
	}

	return keydir, isEphemeral, nil
}
