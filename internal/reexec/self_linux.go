// This file originates from Docker/Moby,
// https://github.com/moby/moby/blob/master/pkg/reexec/
// Licensed under Apache License 2.0: https://github.com/moby/moby/blob/master/LICENSE
// Copyright 2013-2018 Docker, Inc.

//go:build linux

package reexec

// Self returns the path to the current process's binary.
// Returns "/proc/self/exe".
// Self 返回当前进程二进制文件的路径。
// 返回值为 "/proc/self/exe"。
func Self() string {
	return "/proc/self/exe" // 在类 Unix 系统中，"/proc/self/exe" 是一个指向当前进程可执行文件的符号链接。
}
