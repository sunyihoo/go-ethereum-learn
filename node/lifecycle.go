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

// 服务的生命周期管理 ：
//  在以太坊节点中，服务（如 P2P 网络服务、共识引擎、RPC 服务等）是模块化的，每个服务都有自己的生命周期。Lifecycle 接口定义了两个核心方法：
//   Start ：启动服务，通常用于初始化资源（如启动 goroutine、建立网络连接等）。
//   Stop ：停止服务，释放资源并确保所有 goroutine 正常退出。
// 节点与服务的解耦 ：
//  节点负责管理服务的生命周期（如按顺序启动或停止服务），但具体的实现细节由服务自身提供。这种设计符合单一职责原则，增强了代码的可维护性和扩展性。

// Lifecycle encompasses the behavior of services that can be started and stopped
// on the node. Lifecycle management is delegated to the node, but it is the
// responsibility of the service-specific package to configure and register the
// service on the node using the `RegisterLifecycle` method.
// Lifecycle 接口定义了节点上可启动和停止的服务的生命周期行为。
// 生命周期管理权归节点所管辖，但服务需要通过 `RegisterLifecycle` 方法将自己的实现注册到节点上，
// 由服务的所属包完成具体配置和注册。
type Lifecycle interface {
	// Start is called after all services have been constructed and the networking
	// layer was also initialized to spawn any goroutines required by the service.
	// Start 方法在所有服务被构造完成且网络层初始化完成后调用，
	// 用于启动服务所需的任何 goroutine。
	Start() error

	// Stop terminates all goroutines belonging to the service, blocking until they
	// are all terminated.
	// Stop 方法终止属于该服务的所有 goroutine，并阻塞直到它们全部停止。
	Stop() error
}
