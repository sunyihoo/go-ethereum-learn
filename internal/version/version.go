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

// Package version implements reading of build version information.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/ethereum/go-ethereum/version"
)

const ourPath = "github.com/ethereum/go-ethereum" // Path to our module
// 定义我们模块的路径，即 go-ethereum 的 GitHub 地址。

// Family holds the textual version string for major.minor
// Family 保存主版本号和小版本号的文本版本字符串。
var Family = fmt.Sprintf("%d.%d", version.Major, version.Minor)

// Semantic holds the textual version string for major.minor.patch.
// Semantic 保存主版本号、小版本号和补丁号的文本版本字符串。
var Semantic = fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)

// WithMeta holds the textual version string including the metadata.
// WithMeta 保存包含元数据的文本版本字符串。
var WithMeta = func() string {
	v := Semantic
	if version.Meta != "" {
		v += "-" + version.Meta
	}
	return v
}()

func WithCommit(gitCommit, gitDate string) string {
	// WithCommit 返回包含 git 提交哈希和日期的版本字符串。
	vsn := WithMeta
	if len(gitCommit) >= 8 {
		vsn += "-" + gitCommit[:8]
	}
	if (version.Meta != "stable") && (gitDate != "") {
		vsn += "-" + gitDate
	}
	return vsn
}

// Archive holds the textual version string used for Geth archives. e.g.
// "1.8.11-dea1ce05" for stable releases, or "1.8.13-unstable-21c059b6" for unstable
// releases.
// Archive 保存用于 Geth 存档的文本版本字符串。例如，稳定版本为 "1.8.11-dea1ce05"，不稳定版本为 "1.8.13-unstable-21c059b6"。
func Archive(gitCommit string) string {
	vsn := Semantic
	if version.Meta != "stable" {
		vsn += "-" + version.Meta
	}
	if len(gitCommit) >= 8 {
		vsn += "-" + gitCommit[:8]
	}
	return vsn
}

// ClientName creates a software name/version identifier according to common
// conventions in the Ethereum p2p network.
// ClientName 根据以太坊 P2P 网络的常见惯例创建软件名称/版本标识符。
func ClientName(clientIdentifier string) string {
	git, _ := VCS()
	return fmt.Sprintf("%s/v%v/%v-%v/%v",
		strings.Title(clientIdentifier),
		WithCommit(git.Commit, git.Date),
		runtime.GOOS, runtime.GOARCH,
		runtime.Version(),
	)
}

// Info returns build and platform information about the current binary.
//
// If the package that is currently executing is a prefixed by our go-ethereum
// module path, it will print out commit and date VCS information. Otherwise,
// it will assume it's imported by a third-party and will return the imported
// version and whether it was replaced by another module.
// Info 返回当前二进制文件的构建和平台信息。
// 如果当前执行的包以 go-ethereum 模块路径为前缀，它将输出提交和日期的 VCS 信息。否则，它将假设被第三方导入，并返回导入的版本以及是否被另一个模块替换。
func Info() (version, vcs string) {
	version = WithMeta
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		return version, ""
	}
	version = versionInfo(buildInfo)
	if status, ok := VCS(); ok {
		modified := ""
		if status.Dirty {
			modified = " (dirty)"
		}
		commit := status.Commit
		if len(commit) > 8 {
			commit = commit[:8]
		}
		vcs = commit + "-" + status.Date + modified
	}
	return version, vcs
}

// versionInfo returns version information for the currently executing
// implementation.
//
// Depending on how the code is instantiated, it returns different amounts of
// information. If it is unable to determine which module is related to our
// package it falls back to the hardcoded values in the params package.
// versionInfo 返回当前执行实现的版本信息。
// 根据代码的实例化方式，它返回不同数量的信息。如果无法确定与我们包相关的模块，它将回退到 params 包中的硬编码值。
func versionInfo(info *debug.BuildInfo) string {
	// If the main package is from our repo, prefix version with "geth".
	// 如果主包来自我们的仓库，则版本前缀为 "geth"。
	if strings.HasPrefix(info.Path, ourPath) {
		return fmt.Sprintf("geth %s", info.Main.Version)
	}
	// Not our main package, so explicitly print out the module path and
	// version.
	// 不是我们的主包，因此明确打印出模块路径和版本。
	var version string
	if info.Main.Path != "" && info.Main.Version != "" {
		// These can be empty when invoked with "go run".
		// 当使用 "go run" 调用时，这些可能为空。
		version = fmt.Sprintf("%s@%s ", info.Main.Path, info.Main.Version)
	}
	mod := findModule(info, ourPath)
	if mod == nil {
		// If our module path wasn't imported, it's unclear which
		// version of our code they are running. Fallback to hardcoded
		// version.
		// 如果我们的模块路径未被导入，则不清楚他们运行的是哪个版本的代码。回退到硬编码版本。
		return version + fmt.Sprintf("geth %s", WithMeta)
	}
	// Our package is a dependency for the main module. Return path and
	// version data for both.
	// 我们的包是主模块的依赖项。返回两者的路径和版本数据。
	version += fmt.Sprintf("%s@%s", mod.Path, mod.Version)
	if mod.Replace != nil {
		// If our package was replaced by something else, also note that.
		// 如果我们的包被其他东西替换，也记录下来。
		version += fmt.Sprintf(" (replaced by %s@%s)", mod.Replace.Path, mod.Replace.Version)
	}
	return version
}

// findModule returns the module at path.
// findModule 返回指定路径的模块。
func findModule(info *debug.BuildInfo, path string) *debug.Module {
	if info.Path == ourPath {
		return &info.Main
	}
	for _, mod := range info.Deps {
		if mod.Path == path {
			return mod
		}
	}
	return nil
}
