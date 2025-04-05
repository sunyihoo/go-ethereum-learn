// Copyright 2022 The go-ethereum Authors
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

package version

import (
	"runtime/debug"
	"time"
)

// In go 1.18 and beyond, the go tool embeds VCS information into the build.
// 在 Go 1.18 及以上版本中，go 工具会在构建时嵌入 VCS 信息。
const (
	govcsTimeLayout = "2006-01-02T15:04:05Z" // Go VCS 时间格式，遵循 ISO 8601。
	ourTimeLayout   = "20060102"             // 自定义时间格式，简化为 YYYYMMDD。
)

// These variables are set at build-time by the linker when the build is
// done by build/ci.go.
// 这些变量在构建时由链接器设置，通常通过 build/ci.go 完成。
var gitCommit, gitDate string

// VCSInfo represents the git repository state.
// VCSInfo 表示 git 仓库的状态。
type VCSInfo struct {
	Commit string // head commit hash 头部提交哈希。
	Date   string // commit time in YYYYMMDD format 提交时间，格式为 YYYYMMDD。
	Dirty  bool   // 是否有未提交的更改。
}

// VCS returns version control information of the current executable.
// VCS 返回当前可执行文件的版本控制信息。
func VCS() (VCSInfo, bool) {
	if gitCommit != "" {
		// Use information set by the build script if present.
		// 如果存在构建脚本设置的信息，则使用它。
		return VCSInfo{Commit: gitCommit, Date: gitDate}, true
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		if buildInfo.Main.Path == ourPath {
			return buildInfoVCS(buildInfo)
		}
	}
	return VCSInfo{}, false
}

// buildInfoVCS returns VCS information of the build.
// buildInfoVCS 返回构建的 VCS 信息。
func buildInfoVCS(info *debug.BuildInfo) (s VCSInfo, ok bool) {
	for _, v := range info.Settings {
		switch v.Key {
		case "vcs.revision":
			s.Commit = v.Value // 设置提交哈希。
		case "vcs.modified":
			if v.Value == "true" {
				s.Dirty = true // 如果值为 "true"，表示仓库有未提交的更改。
			}
		case "vcs.time":
			t, err := time.Parse(govcsTimeLayout, v.Value)
			if err == nil {
				s.Date = t.Format(ourTimeLayout) // 将 VCS 时间转换为自定义格式。
			}
		}
	}
	if s.Commit != "" && s.Date != "" {
		ok = true // 如果提交哈希和日期都存在，则返回成功。
	}
	return
}
