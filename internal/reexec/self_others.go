// This file originates from Docker/Moby,
// https://github.com/moby/moby/blob/master/pkg/reexec/
// Licensed under Apache License 2.0: https://github.com/moby/moby/blob/master/LICENSE
// Copyright 2013-2018 Docker, Inc.

//go:build !linux

package reexec

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Self returns the path to the current process's binary.
// Uses os.Args[0].
// Self 返回当前进程二进制文件的路径。
// 使用 os.Args[0]。
func Self() string {
	name := os.Args[0] // 获取程序名称或路径。
	if filepath.Base(name) == name {
		// 如果 name 是一个不带路径的可执行文件名（如 "myapp"），尝试查找其完整路径。
		if lp, err := exec.LookPath(name); err == nil {
			return lp // 返回通过 LookPath 查找到的完整路径。
		}
	}
	// handle conversion of relative paths to absolute
	// 处理相对路径到绝对路径的转换。
	if absName, err := filepath.Abs(name); err == nil {
		return absName // 如果成功转换为绝对路径，返回绝对路径。
	}
	// if we couldn't get absolute name, return original
	// 如果无法获取绝对路径，返回原始值。
	// (NOTE: Go only errors on Abs() if os.Getwd fails)
	// 注意：Abs() 只有在 os.Getwd 失败时才会报错。
	return name
}
