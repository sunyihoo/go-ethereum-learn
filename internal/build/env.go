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

package build

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// These flags override values in build env.
	// 这些标志覆盖构建环境中的值。
	GitCommitFlag = flag.String("git-commit", "", `Overrides git commit hash embedded into executables`)
	// 覆盖嵌入到可执行文件中的 git 提交哈希
	GitBranchFlag = flag.String("git-branch", "", `Overrides git branch being built`)
	// 覆盖正在构建的 git 分支
	GitTagFlag = flag.String("git-tag", "", `Overrides git tag being built`)
	// 覆盖正在构建的 git 标签
	BuildnumFlag = flag.String("buildnum", "", `Overrides CI build number`)
	// 覆盖 CI 构建编号
	PullRequestFlag = flag.Bool("pull-request", false, `Overrides pull request status of the build`)
	// 覆盖构建的拉取请求状态
	CronJobFlag = flag.Bool("cron-job", false, `Overrides cron job status of the build`)
	// 覆盖构建的定时任务状态
	UbuntuVersionFlag = flag.String("ubuntu", "", `Sets the ubuntu version being built for`)
	// 设置正在构建的 Ubuntu 版本
)

// Environment contains metadata provided by the build environment.
// Environment 包含构建环境提供的元数据。
type Environment struct {
	CI   bool
	Name string // name of the environment
	// 环境名称
	Repo string // name of GitHub repo
	// GitHub 仓库名称
	Commit, Date, Branch, Tag string // Git info
	// Git 信息（提交哈希、日期、分支、标签）
	Buildnum string
	// 构建编号
	UbuntuVersion string // Ubuntu version being built for
	// 正在构建的 Ubuntu 版本
	IsPullRequest bool
	// 是否为拉取请求
	IsCronJob bool
	// 是否为定时任务
}

func (env Environment) String() string {
	return fmt.Sprintf("%s env (commit:%s date:%s branch:%s tag:%s buildnum:%s pr:%t)",
		env.Name, env.Commit, env.Date, env.Branch, env.Tag, env.Buildnum, env.IsPullRequest)
}

// Env returns metadata about the current CI environment, falling back to LocalEnv
// if not running on CI.
// Env 返回当前 CI 环境的元数据，如果未运行在 CI 上，则回退到 LocalEnv。
func Env() Environment {
	switch {
	case os.Getenv("CI") == "true" && os.Getenv("TRAVIS") == "true":
		commit := os.Getenv("TRAVIS_PULL_REQUEST_SHA")
		if commit == "" {
			commit = os.Getenv("TRAVIS_COMMIT")
		}
		return Environment{
			CI:            true,
			Name:          "travis",
			Repo:          os.Getenv("TRAVIS_REPO_SLUG"),
			Commit:        commit,
			Date:          getDate(commit),
			Branch:        os.Getenv("TRAVIS_BRANCH"),
			Tag:           os.Getenv("TRAVIS_TAG"),
			Buildnum:      os.Getenv("TRAVIS_BUILD_NUMBER"),
			IsPullRequest: os.Getenv("TRAVIS_PULL_REQUEST") != "false",
			IsCronJob:     os.Getenv("TRAVIS_EVENT_TYPE") == "cron",
		}
	case os.Getenv("CI") == "True" && os.Getenv("APPVEYOR") == "True":
		commit := os.Getenv("APPVEYOR_PULL_REQUEST_HEAD_COMMIT")
		if commit == "" {
			commit = os.Getenv("APPVEYOR_REPO_COMMIT")
		}
		return Environment{
			CI:            true,
			Name:          "appveyor",
			Repo:          os.Getenv("APPVEYOR_REPO_NAME"),
			Commit:        commit,
			Date:          getDate(commit),
			Branch:        os.Getenv("APPVEYOR_REPO_BRANCH"),
			Tag:           os.Getenv("APPVEYOR_REPO_TAG_NAME"),
			Buildnum:      os.Getenv("APPVEYOR_BUILD_NUMBER"),
			IsPullRequest: os.Getenv("APPVEYOR_PULL_REQUEST_NUMBER") != "",
			IsCronJob:     os.Getenv("APPVEYOR_SCHEDULED_BUILD") == "True",
		}
	default:
		return LocalEnv()
	}
}

// LocalEnv returns build environment metadata gathered from git.
// LocalEnv 返回从 git 收集的构建环境元数据。
func LocalEnv() Environment {
	env := applyEnvFlags(Environment{Name: "local", Repo: "ethereum/go-ethereum"})

	head := readGitFile("HEAD")
	if fields := strings.Fields(head); len(fields) == 2 {
		head = fields[1]
	} else {
		// In this case we are in "detached head" state
		// see: https://git-scm.com/docs/git-checkout#_detached_head
		// 在这种情况下，我们处于“分离头指针”状态
		// 参见：https://git-scm.com/docs/git-checkout#_detached_head
		// Additional check required to verify, that file contains commit hash
		// 需要额外检查以验证文件是否包含提交哈希
		commitRe, _ := regexp.Compile("^([0-9a-f]{40})$")
		if commit := commitRe.FindString(head); commit != "" && env.Commit == "" {
			env.Commit = commit
			env.Date = getDate(env.Commit)
		}
		return env
	}
	if env.Commit == "" {
		env.Commit = readGitFile(head)
	}
	env.Date = getDate(env.Commit)
	if env.Branch == "" {
		if head != "HEAD" {
			env.Branch = strings.TrimPrefix(head, "refs/heads/")
		}
	}
	if info, err := os.Stat(".git/objects"); err == nil && info.IsDir() && env.Tag == "" {
		env.Tag = firstLine(RunGit("tag", "-l", "--points-at", "HEAD"))
	}
	return env
}

func firstLine(s string) string {
	return strings.Split(s, "\n")[0]
}

func getDate(commit string) string {
	if commit == "" {
		return ""
	}
	out := RunGit("show", "-s", "--format=%ct", commit)
	if out == "" {
		return ""
	}
	date, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse git commit date: %v", err))
	}
	return time.Unix(date, 0).Format("20060102")
}

func applyEnvFlags(env Environment) Environment {
	if !flag.Parsed() {
		panic("you need to call flag.Parse before Env or LocalEnv")
	}
	if *GitCommitFlag != "" {
		env.Commit = *GitCommitFlag
	}
	if *GitBranchFlag != "" {
		env.Branch = *GitBranchFlag
	}
	if *GitTagFlag != "" {
		env.Tag = *GitTagFlag
	}
	if *BuildnumFlag != "" {
		env.Buildnum = *BuildnumFlag
	}
	if *PullRequestFlag {
		env.IsPullRequest = true
	}
	if *CronJobFlag {
		env.IsCronJob = true
	}
	if *UbuntuVersionFlag != "" {
		env.UbuntuVersion = *UbuntuVersionFlag
	}
	return env
}
