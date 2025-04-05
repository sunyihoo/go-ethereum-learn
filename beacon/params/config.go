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

package params

import (
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/beacon/merkle"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"gopkg.in/yaml.v3"
)

// 分叉机制 ：以太坊信标链通过分叉机制实现协议升级（如 Altair、Bellatrix 和 Capella），每个分叉都有独立的版本号和激活纪元。
// 签名域隔离 ：通过签名域的隔离，避免不同分叉之间的签名冲突，确保网络的安全性和稳定性。
// syncCommitteeDomain specifies the signatures specific use to avoid clashes
// across signing different data structures.
// syncCommitteeDomain 指定签名的具体用途，以避免在签署不同数据结构时发生冲突。
const syncCommitteeDomain = 7

var knownForks = []string{"GENESIS", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB"}

// ClientConfig contains beacon light client configuration.
// ClientConfig 包含信标轻客户端的配置。
type ClientConfig struct {
	ChainConfig
	Apis         []string          // Beacon API 的 URL 列表
	CustomHeader map[string]string // 自定义 HTTP 请求头
	Threshold    int               // 验证阈值
	NoFilter     bool              // 是否禁用过滤
}

// ChainConfig contains the beacon chain configuration.
// ChainConfig 包含信标链的配置。
type ChainConfig struct {
	GenesisTime           uint64      //  Unix timestamp of slot 0 第 0 个槽位的时间戳（Unix 时间戳）
	GenesisValidatorsRoot common.Hash // Root hash of the genesis validator set, used for signature domain calculation 创世验证者集合的根哈希，用于签名域计算
	Forks                 Forks       // 分叉列表
	Checkpoint            common.Hash // 检查点哈希
}

// ForkAtEpoch returns the latest active fork at the given epoch.
// ForkAtEpoch 返回给定纪元中最新的活跃分叉。
func (c *ChainConfig) ForkAtEpoch(epoch uint64) Fork {
	for i := len(c.Forks) - 1; i >= 0; i-- {
		if c.Forks[i].Epoch <= epoch {
			return *c.Forks[i]
		}
	}
	return Fork{}
}

// AddFork adds a new item to the list of forks.
// AddFork 向分叉列表中添加一个新的分叉。
func (c *ChainConfig) AddFork(name string, epoch uint64, version []byte) *ChainConfig {
	knownIndex := slices.Index(knownForks, name)
	if knownIndex == -1 {
		knownIndex = math.MaxInt // assume that the unknown fork happens after the known ones 假设未知分叉发生在已知分叉之后
		if epoch != math.MaxUint64 {
			log.Warn("Unknown fork in config.yaml", "fork name", name, "known forks", knownForks)
		}
	}
	fork := &Fork{
		Name:       name,
		Epoch:      epoch,
		Version:    version,
		knownIndex: knownIndex,
	}
	fork.computeDomain(c.GenesisValidatorsRoot)
	c.Forks = append(c.Forks, fork)
	sort.Sort(c.Forks)
	return c
}

// LoadForks parses the beacon chain configuration file (config.yaml) and extracts
// the list of forks.
// LoadForks 解析信标链配置文件（config.yaml）并提取分叉列表。
func (c *ChainConfig) LoadForks(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read beacon chain config file: %v", err)
	}
	config := make(map[string]string)
	if err := yaml.Unmarshal(file, &config); err != nil {
		return fmt.Errorf("failed to parse beacon chain config file: %v", err)
	}
	var (
		versions = make(map[string][]byte)
		epochs   = make(map[string]uint64)
	)
	epochs["GENESIS"] = 0

	for key, value := range config {
		if strings.HasSuffix(key, "_FORK_VERSION") {
			name := key[:len(key)-len("_FORK_VERSION")]
			if v, err := hexutil.Decode(value); err == nil {
				versions[name] = v
			} else {
				return fmt.Errorf("failed to decode hex fork id %q in beacon chain config file: %v", value, err)
			}
		}
		if strings.HasSuffix(key, "_FORK_EPOCH") {
			name := key[:len(key)-len("_FORK_EPOCH")]
			if v, err := strconv.ParseUint(value, 10, 64); err == nil {
				epochs[name] = v
			} else {
				return fmt.Errorf("failed to parse epoch number %q in beacon chain config file: %v", value, err)
			}
		}
	}
	for name, epoch := range epochs {
		if version, ok := versions[name]; ok {
			delete(versions, name)
			c.AddFork(name, epoch, version)
		} else {
			return fmt.Errorf("fork id missing for %q in beacon chain config file", name)
		}
	}
	for name := range versions {
		return fmt.Errorf("epoch number missing for fork %q in beacon chain config file", name)
	}
	return nil
}

// Fork describes a single beacon chain fork and also stores the calculated
// signature domain used after this fork.
// Fork 描述了一个信标链分叉，并存储该分叉后的签名域。
type Fork struct {
	// Name of the fork in the chain config (config.yaml) file
	// 分叉名称（在 config.yaml 文件中）
	Name string

	// Epoch when given fork version is activated
	// 激活该分叉版本的纪元
	Epoch uint64

	// Fork version, see https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#custom-types
	// 分叉版本
	Version []byte

	// index in list of known forks or MaxInt if unknown
	// 已知分叉列表中的索引，或为 MaxInt（如果未知）
	knownIndex int

	// calculated by computeDomain, based on fork version and genesis validators root
	// 根据分叉版本和创世验证者根哈希计算的签名域
	domain merkle.Value
}

// computeDomain returns the signature domain based on the given fork version
// and genesis validator set root.
// computeDomain 根据给定的分叉版本和创世验证者集合根哈希返回签名域。
func (f *Fork) computeDomain(genesisValidatorsRoot common.Hash) {
	var (
		hasher        = sha256.New()
		forkVersion32 merkle.Value
		forkDataRoot  merkle.Value
	)
	copy(forkVersion32[:], f.Version)
	hasher.Write(forkVersion32[:])
	hasher.Write(genesisValidatorsRoot[:])
	hasher.Sum(forkDataRoot[:0])

	f.domain[0] = syncCommitteeDomain
	copy(f.domain[4:], forkDataRoot[:28])
}

// Forks is the list of all beacon chain forks in the chain configuration.
// Forks 是信标链配置中所有分叉的列表。
type Forks []*Fork

// domain returns the signature domain for the given epoch (assumes that domains
// have already been calculated).
// domain 返回给定纪元的签名域（假设签名域已经计算过）。
func (f Forks) domain(epoch uint64) (merkle.Value, error) {
	for i := len(f) - 1; i >= 0; i-- {
		if epoch >= f[i].Epoch {
			return f[i].domain, nil
		}
	}
	return merkle.Value{}, fmt.Errorf("unknown fork for epoch %d", epoch)
}

// SigningRoot calculates the signing root of the given header.
// SigningRoot 计算给定头部的签名根。
func (f Forks) SigningRoot(epoch uint64, root common.Hash) (common.Hash, error) {
	domain, err := f.domain(epoch)
	if err != nil {
		return common.Hash{}, err
	}
	var (
		signingRoot common.Hash
		hasher      = sha256.New()
	)
	hasher.Write(root[:])
	hasher.Write(domain[:])
	hasher.Sum(signingRoot[:0])

	return signingRoot, nil
}

func (f Forks) Len() int      { return len(f) }
func (f Forks) Swap(i, j int) { f[i], f[j] = f[j], f[i] }
func (f Forks) Less(i, j int) bool {
	if f[i].Epoch != f[j].Epoch {
		return f[i].Epoch < f[j].Epoch
	}
	return f[i].knownIndex < f[j].knownIndex
}
