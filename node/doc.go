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

/*
Package node sets up multi-protocol Ethereum nodes.

In the model exposed by this package, a node is a collection of services which use shared
resources to provide RPC APIs. Services can also offer devp2p protocols, which are wired
up to the devp2p network when the node instance is started.

# Node Lifecycle

The Node object has a lifecycle consisting of three basic states, INITIALIZING, RUNNING
and CLOSED.

	●───────┐
	     New()
	        │
	        ▼
	  INITIALIZING ────Start()─┐
	        │                  │
	        │                  ▼
	    Close()             RUNNING
	        │                  │
	        ▼                  │
	     CLOSED ◀──────Close()─┘

Creating a Node allocates basic resources such as the data directory and returns the node
in its INITIALIZING state. Lifecycle objects, RPC APIs and peer-to-peer networking
protocols can be registered in this state. Basic operations such as opening a key-value
database are permitted while initializing.

Once everything is registered, the node can be started, which moves it into the RUNNING
state. Starting the node starts all registered Lifecycle objects and enables RPC and
peer-to-peer networking. Note that no additional Lifecycles, APIs or p2p protocols can be
registered while the node is running.

Closing the node releases all held resources. The actions performed by Close depend on the
state it was in. When closing a node in INITIALIZING state, resources related to the data
directory are released. If the node was RUNNING, closing it also stops all Lifecycle
objects and shuts down RPC and peer-to-peer networking.

You must always call Close on Node, even if the node was not started.

# Resources Managed By Node

All file-system resources used by a node instance are located in a directory called the
data directory. The location of each resource can be overridden through additional node
configuration. The data directory is optional. If it is not set and the location of a
resource is otherwise unspecified, package node will create the resource in memory.

To access to the devp2p network, Node configures and starts p2p.Server. Each host on the
devp2p network has a unique identifier, the node key. The Node instance persists this key
across restarts. Node also loads static and trusted node lists and ensures that knowledge
about other hosts is persisted.

JSON-RPC servers which run HTTP, WebSocket or IPC can be started on a Node. RPC modules
offered by registered services will be offered on those endpoints. Users can restrict any
endpoint to a subset of RPC modules. Node itself offers the "debug", "admin" and "web3"
modules.

Service implementations can open LevelDB databases through the service context. Package
node chooses the file system location of each database. If the node is configured to run
without a data directory, databases are opened in memory instead.

Node also creates the shared store of encrypted Ethereum account keys. Services can access
the account manager through the service context.

# Sharing Data Directory Among Instances

Multiple node instances can share a single data directory if they have distinct instance
names (set through the Name config option). Sharing behaviour depends on the type of
resource.

devp2p-related resources (node key, static/trusted node lists, known hosts database) are
stored in a directory with the same name as the instance. Thus, multiple node instances
using the same data directory will store this information in different subdirectories of
the data directory.

LevelDB databases are also stored within the instance subdirectory. If multiple node
instances use the same data directory, opening the databases with identical names will
create one database for each instance.

The account key store is shared among all node instances using the same data directory
unless its location is changed through the KeyStoreDir configuration option.

# Data Directory Sharing Example

In this example, two node instances named A and B are started with the same data
directory. Node instance A opens the database "db", node instance B opens the databases
"db" and "db-2". The following files will be created in the data directory:

	data-directory/
		A/
			nodekey            -- devp2p node key of instance A
			nodes/             -- devp2p discovery knowledge database of instance A
			db/                -- LevelDB content for "db"
		A.ipc                  -- JSON-RPC UNIX domain socket endpoint of instance A
		B/
			nodekey            -- devp2p node key of node B
			nodes/             -- devp2p discovery knowledge database of instance B
			static-nodes.json  -- devp2p static node list of instance B
			db/                -- LevelDB content for "db"
			db-2/              -- LevelDB content for "db-2"
		B.ipc                  -- JSON-RPC UNIX domain socket endpoint of instance B
		keystore/              -- account key store, used by both instances
*/
package node

// node 包用于创建和管理多协议的以太坊节点。
// 节点是 服务（Services） 的集合，这些服务共享资源以提供 RPC API。
// 服务还可以提供 devp2p 协议，当节点启动时，这些协议会自动连接到 devp2p 网络。
//
// 生命周期：
// 节点（Node 对象）有三个基本状态：INITIALIZING（初始化）、RUNNING（运行）和 CLOSED（关闭）。
// 初始化（INITIALIZING）：通过调用 New() 创建节点，分配资源（如数据目录）。
// 运行 （RUNNING）：通过调用 Start() 启动节点，启用 RPC 和 P2P 网络。
// 关闭 （CLOSED）：通过调用 Close() 释放所有资源，无论节点是否启动过。
//
// 节点管理的资源
// 数据目录（Data Directory）:
// - 节点使用的所有文件系统资源都位于数据目录中。数据目录是可选的，如果未设置，资源将存储在内存中。
//
// P2P 网络（P2P Network）：
// - 节点配置并启动 p2p.Server，用于连接 devp2p 网络。
// - 每个节点有一个唯一的标识符（节点密钥），该密钥会在重启时保留。
// - 节点还会加载静态节点列表和受信任节点列表。
//
// RPC 服务（RPC Services）：
// - 可以启动 HTTP、WebSocket 或 IPC 的 JSON-RPC 服务器。
// - 注册的服务提供的 RPC 模块会暴露在这些端点上。
//
// LevelDB 数据库：
// - 服务可以通过服务上下文打开 LevelDB 数据库。
// - 数据目录未配置时，数据库将存储在内存中。
//
// 以太坊账户密钥存储（Account Key Store）：
// - 节点创建加密的以太坊账户密钥存储，服务可以通过服务上下文访问账户管理器。
//
// 共享数据目录
//
// 共享行为：
// - 多个节点实例可以共享同一个数据目录，但需要使用不同的实例名称（通过 Name 配置选项设置）。
// - devp2p 相关资源（如节点密钥、节点列表）存储在以实例名命名的子目录中。
// - LevelDB 数据库也存储在实例子目录中，相同名称的数据库会为每个实例创建单独的实例。
// - 账户密钥存储默认在数据目录的 keystore 目录中共享，除非通过 KeyStoreDir 配置选项更改位置。
//
// 数据目录共享示例
// 两个节点实例 A 和 B 共享同一个数据目录。
// 实例 A 打开数据库 db，实例 B 打开数据库 db 和 db-2。
//  data-directory/
// 		A/
//			nodekey            -- 实例 A 的节点密钥
//			nodes/             -- 实例 A 的发现数据库
//			db/                -- 实例 A 的 LevelDB 数据库
//		A.ipc                -- 实例 A 的 JSON-RPC IPC 端点
//			B/
//			nodekey            -- 实例 B 的节点密钥
//			nodes/             -- 实例 B 的发现数据库
//			static-nodes.json  -- 实例 B 的静态节点列表
//			db/                -- 实例 B 的 LevelDB 数据库
//			db-2/              -- 实例 B 的 LevelDB 数据库
//		B.ipc                -- 实例 B 的 JSON-RPC IPC 端点
//		keystore/            -- 账户密钥存储，由两个实例共享

// node 包是以太坊节点的核心管理模块，提供了创建、启动、关闭节点的功能，
// 同时管理节点的资源（如数据目录、P2P 网络、RPC 服务、LevelDB 数据库和账户密钥存储）。
// 通过该包，开发者可以灵活地配置和启动以太坊节点，支持多协议和共享资源。
