// Copyright 2021 The go-ethereum Authors
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

package shutdowncheck

import (
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// ShutdownTracker is a service that reports previous unclean shutdowns
// upon start. It needs to be started after a successful start-up and stopped
// after a successful shutdown, just before the db is closed.
// ShutdownTracker 是一个服务，用于在节点启动时报告之前的非正常关机。
// 它需要在成功启动后启动，并在成功关闭之前（数据库关闭前）停止。
type ShutdownTracker struct {
	db     ethdb.Database // 数据库实例，用于存储和检索非正常关机标记。
	stopCh chan struct{}  // 用于停止更新循环的信号通道。
}

// NewShutdownTracker creates a new ShutdownTracker instance and has
// no other side-effect.
// NewShutdownTracker 创建一个新的 ShutdownTracker 实例，没有其他副作用。
func NewShutdownTracker(db ethdb.Database) *ShutdownTracker {
	return &ShutdownTracker{
		db:     db,                  // 初始化数据库实例。
		stopCh: make(chan struct{}), // 初始化停止信号通道。
	}
}

// MarkStartup is to be called in the beginning when the node starts. It will:
// - Push a new startup marker to the db
// - Report previous unclean shutdowns
// MarkStartup 在节点启动时调用。它将：
// - 向数据库推送一个新的启动标记。
// - 报告之前的非正常关机。
func (t *ShutdownTracker) MarkStartup() {
	if uncleanShutdowns, discards, err := rawdb.PushUncleanShutdownMarker(t.db); err != nil {
		log.Error("Could not update unclean-shutdown-marker list", "error", err) // 如果更新失败，记录错误日志。
	} else {
		if discards > 0 {
			log.Warn("Old unclean shutdowns found", "count", discards) // 如果有旧的非正常关机标记被丢弃，记录警告日志。
		}
		for _, tstamp := range uncleanShutdowns {
			t := time.Unix(int64(tstamp), 0) // 将时间戳转换为时间对象。
			log.Warn("Unclean shutdown detected", "booted", t,
				"age", common.PrettyAge(t)) // 记录每个非正常关机的时间和持续时间。
		}
	}
}

// Start runs an event loop that updates the current marker's timestamp every 5 minutes.
// Start 运行一个事件循环，每 5 分钟更新当前标记的时间戳。
func (t *ShutdownTracker) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // 创建一个每 5 分钟触发一次的定时器。
		defer ticker.Stop()                       // 确保在退出时停止定时器。
		for {
			select {
			case <-ticker.C:
				rawdb.UpdateUncleanShutdownMarker(t.db) // 每隔 5 分钟更新非正常关机标记的时间戳。
			case <-t.stopCh:
				return // 如果收到停止信号，则退出循环。
			}
		}
	}()
}

// Stop will stop the update loop and clear the current marker.
// Stop 将停止更新循环并清除当前标记。
func (t *ShutdownTracker) Stop() {
	// Stop update loop.
	t.stopCh <- struct{}{} // 发送停止信号以终止更新循环。
	// Clear last marker.
	rawdb.PopUncleanShutdownMarker(t.db) // 清除最后一个非正常关机标记。
}
