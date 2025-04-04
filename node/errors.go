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
	"errors"
	"fmt"
	"reflect"
	"syscall"
)

var (
	ErrDatadirUsed    = errors.New("datadir already used by another process") // 数据目录已被其他进程使用
	ErrNodeStopped    = errors.New("node not started")                        // 节点未启动
	ErrNodeRunning    = errors.New("node already running")                    // 节点已在运行
	ErrServiceUnknown = errors.New("unknown service")                         // 未知服务

	datadirInUseErrnos = map[uint]bool{11: true, 32: true, 35: true} // 定义可能的错误码映射表，用于检测数据目录是否被占用
)

func convertFileLockError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && datadirInUseErrnos[uint(errno)] {
		return ErrDatadirUsed // 如果错误码匹配，则返回数据目录被占用的错误
	}
	return err // 否则返回原始错误
}

// StopError is returned if a Node fails to stop either any of its registered
// services or itself.
// StopError 是在节点无法停止其注册的服务或自身时返回的错误。
type StopError struct {
	Server   error                  // 节点本身的停止错误
	Services map[reflect.Type]error // 每个服务的停止错误，按服务类型分类
}

// Error generates a textual representation of the stop error.
// Error 方法生成停止错误的文本表示。
func (e *StopError) Error() string {
	return fmt.Sprintf("server: %v, services: %v", e.Server, e.Services) // 格式化输出节点和服务的错误信息
}
