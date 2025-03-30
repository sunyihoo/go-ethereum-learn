// Copyright 2018 The go-ethereum Authors
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
	"net"
	"strings"

	"github.com/ethereum/go-ethereum/log"
)

// StartIPCEndpoint starts an IPC endpoint.
// StartIPCEndpoint 启动一个 IPC 端点。
func StartIPCEndpoint(ipcEndpoint string, apis []API) (net.Listener, *Server, error) {
	// Register all the APIs exposed by the services.
	// 注册服务暴露的所有 API。
	var (
		handler    = NewServer()
		regMap     = make(map[string]struct{}) // 跟踪已注册的 API 命名空间，避免重复记录。
		registered []string
	)
	for _, api := range apis {
		if err := handler.RegisterName(api.Namespace, api.Service); err != nil {
			log.Info("IPC registration failed", "namespace", api.Namespace, "error", err)
			return nil, nil, err
		}
		if _, ok := regMap[api.Namespace]; !ok {
			registered = append(registered, api.Namespace)
			regMap[api.Namespace] = struct{}{}
		}
	}
	log.Debug("IPCs registered", "namespaces", strings.Join(registered, ","))
	// All APIs registered, start the IPC listener.
	// 所有 API 已注册，启动 IPC 监听器。
	listener, err := ipcListen(ipcEndpoint)
	if err != nil {
		return nil, nil, err
	}
	go handler.ServeListener(listener)
	return listener, handler, nil
}
