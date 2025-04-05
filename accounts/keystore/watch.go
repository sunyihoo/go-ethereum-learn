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

//go:build (darwin && !ios && cgo) || freebsd || (linux && !arm64) || netbsd || solaris
// +build darwin,!ios,cgo freebsd linux,!arm64 netbsd solaris

package keystore

import (
	"os"
	"time"

	"github.com/ethereum/go-ethereum/log"
	"github.com/fsnotify/fsnotify"
)

type watcher struct {
	ac      *accountCache // 关联的账户缓存
	running bool          // 当运行循环开始时设置为 true
	// 当运行循环开始时设置为 true
	runEnded bool // 当运行循环结束时设置为 true
	// 当运行循环结束时设置为 true
	starting bool // 在运行循环启动前设置为 true
	// 在运行循环启动前设置为 true
	quit chan struct{} // 用于退出信号的通道
	// 用于退出信号的通道
}

func newWatcher(ac *accountCache) *watcher {
	return &watcher{
		ac:   ac,
		quit: make(chan struct{}),
	}
}

// enabled returns false on systems not supported.
// enabled 在不支持的系统上返回 false。
func (*watcher) enabled() bool { return true }

// starts the watcher loop in the background.
// Start a watcher in the background if that's not already in progress.
// The caller must hold w.ac.mu.
// 在后台启动观察者循环。
// 如果观察者尚未在进行中，则在后台启动一个观察者。
// 调用者必须持有 w.ac.mu。
func (w *watcher) start() {
	if w.starting || w.running {
		return
	}
	w.starting = true
	go w.loop()
}

func (w *watcher) close() {
	close(w.quit)
}

func (w *watcher) loop() {
	defer func() {
		w.ac.mu.Lock()
		w.running = false
		w.starting = false
		w.runEnded = true
		w.ac.mu.Unlock()
	}()
	logger := log.New("path", w.ac.keydir)

	// Create new watcher.
	// 创建新的观察者。
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("Failed to start filesystem watcher", "err", err)
		// 无法启动文件系统观察者
		return
	}
	defer watcher.Close()
	if err := watcher.Add(w.ac.keydir); err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("Failed to watch keystore folder", "err", err)
			// 无法观察密钥存储文件夹
		}
		return
	}

	logger.Trace("Started watching keystore folder", "folder", w.ac.keydir)
	// 开始观察密钥存储文件夹
	defer logger.Trace("Stopped watching keystore folder")
	// 停止观察密钥存储文件夹

	w.ac.mu.Lock()
	w.running = true
	w.ac.mu.Unlock()

	// Wait for file system events and reload.
	// When an event occurs, the reload call is delayed a bit so that
	// multiple events arriving quickly only cause a single reload.
	// 等待文件系统事件并重新加载。
	// 当事件发生时，重新加载调用会延迟一点，以便快速到达的多个事件只触发一次重新加载。
	var (
		debounceDuration = 500 * time.Millisecond // 防抖动持续时间
		rescanTriggered  = false                  // 是否已触发重新扫描
		debounce         = time.NewTimer(0)       // 防抖动定时器
	)
	// Ignore initial trigger
	// 忽略初始触发
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()
	for {
		select {
		case <-w.quit:
			return
		case _, ok := <-watcher.Events:
			if !ok {
				return
			}
			// Trigger the scan (with delay), if not already triggered
			// 如果尚未触发，则触发扫描（带延迟）
			if !rescanTriggered {
				debounce.Reset(debounceDuration)
				rescanTriggered = true
			}
			// The fsnotify library does provide more granular event-info, it
			// would be possible to refresh individual affected files instead
			// of scheduling a full rescan. For most cases though, the
			// full rescan is quick and obviously simplest.
			// fsnotify 库确实提供了更细粒度的事件信息，
			// 可以刷新单个受影响的文件，而不是安排完全重新扫描。
			// 但在大多数情况下，完全重新扫描很快且显然是最简单的。
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Info("Filesystem watcher error", "err", err)
			// 文件系统观察者错误
		case <-debounce.C:
			w.ac.scanAccounts()
			rescanTriggered = false
		}
	}
}
