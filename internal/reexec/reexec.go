// This file originates from Docker/Moby,
// https://github.com/moby/moby/blob/master/pkg/reexec/reexec.go
// Licensed under Apache License 2.0: https://github.com/moby/moby/blob/master/LICENSE
// Copyright 2013-2018 Docker, Inc.
//
// Package reexec facilitates the busybox style reexec of the docker binary that
// we require because of the forking limitations of using Go.  Handlers can be
// registered with a name and the argv 0 of the exec of the binary will be used
// to find and execute custom init paths.

package reexec

import (
	"fmt"
	"os"
)

// reexec 的概念 ：
// 在以太坊中，reexec 是一种机制，允许程序在运行时重新执行某些初始化逻辑。
// 这种机制通常用于实现多阶段初始化或动态加载模块。

var registeredInitializers = make(map[string]func())

// Register adds an initialization func under the specified name
// Register 在指定名称下注册一个初始化函数。
func Register(name string, initializer func()) {
	if _, exists := registeredInitializers[name]; exists {
		panic(fmt.Sprintf("reexec func already registered under name %q", name)) // 如果名称已存在，抛出 panic 错误。
	}
	registeredInitializers[name] = initializer // 将初始化函数注册到 map 中。
}

// Init is called as the first part of the exec process and returns true if an
// initialization function was called.
// Init 是 exec 过程的第一部分调用，如果调用了初始化函数，则返回 true。
func Init() bool {
	if initializer, ok := registeredInitializers[os.Args[0]]; ok {
		initializer() // 调用与当前程序名称匹配的初始化函数。
		return true   // 返回 true 表示初始化函数已被调用。
	}
	return false // 如果未找到匹配的初始化函数，则返回 false。
}
