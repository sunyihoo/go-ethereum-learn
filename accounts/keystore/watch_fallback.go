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

//go:build (darwin && !cgo) || ios || (linux && arm64) || windows || (!darwin && !freebsd && !linux && !netbsd && !solaris)
// +build darwin,!cgo ios linux,arm64 windows !darwin,!freebsd,!linux,!netbsd,!solaris

// This is the fallback implementation of directory watching.
// It is used on unsupported platforms.

package keystore

// 密钥库目录监视 (Keystore Directory Watching): 在许多现代操作系统中，应用程序可以注册监听文件系统中的特定目录，以便在目录中的文件或子目录发生变化（例如，创建、删除、修改）时收到通知。在以太坊客户端中，监视密钥库目录可以使得客户端能够自动检测到用户何时添加或删除了新的账户密钥文件，从而动态更新其管理的账户列表，而无需用户手动触发刷新或重新加载操作。
// 平台兼容性 (Platform Compatibility): 不同的操作系统提供了不同的 API 来实现文件系统事件的通知。例如，Linux 使用 inotify，macOS 使用 FSEvents 或 kqueue，Windows 使用 ReadDirectoryChangesW。为了在所有支持的平台上提供统一的目录监视功能，go-ethereum 通常会针对不同的平台实现特定的监视器。
// 回退实现 (Fallback Implementation): 当 go-ethereum 运行在某个操作系统上，但该操作系统没有受到支持的本地目录监视机制时，或者在实现本地监视器时遇到问题，就会使用这种回退实现。回退实现通常会提供一个最基本的功能（甚至是不提供任何实际功能），以确保程序在所有平台上都能运行，尽管某些高级特性可能无法使用。

type watcher struct {
	running  bool
	runEnded bool
}

// newWatcher creates a new watcher instance. Since this is the fallback
// implementation, it doesn't actually start any watching process.
// newWatcher 创建一个新的 watcher 实例。由于这是回退实现，它实际上并不启动任何监视进程。
func newWatcher(*accountCache) *watcher { return new(watcher) }

// start does nothing in the fallback implementation.
// start 在回退实现中不做任何事情。
func (*watcher) start() {}

// close does nothing in the fallback implementation.
// close 在回退实现中不做任何事情。
func (*watcher) close() {}

// enabled returns false on systems not supported.
// enabled 在不支持的系统上返回 false。
func (*watcher) enabled() bool { return false }
