// Copyright 2017 The go-ethereum Authors
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

package clique

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

// PoA 的核心概念: 代码中体现了 PoA 的核心思想，即由一组预先信任的权威节点来维护区块链。授权签名者的管理是通过链上的投票机制实现的。
// 链上治理: Clique 通过特殊的 nonce 值和投票机制，实现了基本的链上治理功能，允许授权签名者动态地添加或删除其他签名者。
// 防止垃圾签名: Recents 字段和相关的逻辑用于限制单个签名者连续出块，提高了网络的稳定性和抗攻击性。
// 快照机制: 使用快照来记录不同区块高度的授权状态，这对于链的同步和重组至关重要。快照可以存储在内存中以提高性能，也可以持久化到数据库中。
// 与区块头结构的关联: 代码中可以看到投票信息是通过区块头的特定字段（如 Nonce 和 Coinbase）来传递的，这与之前分析的区块头结构定义相符。

// Vote represents a single vote that an authorized signer made to modify the
// list of authorizations.
// Vote 表示授权签名者为修改授权列表而投出的一票。
type Vote struct {
	Signer    common.Address `json:"signer"`    // Authorized signer that cast this vote 投票的授权签名者地址
	Block     uint64         `json:"block"`     // Block number the vote was cast in (expire old votes) 投票所在的区块号（用于过期旧投票）
	Address   common.Address `json:"address"`   // Account being voted on to change its authorization 被投票更改授权状态的账户地址
	Authorize bool           `json:"authorize"` // Whether to authorize or deauthorize the voted account 是否授权或取消授权该账户
}

// Tally is a simple vote tally to keep the current score of votes. Votes that
// go against the proposal aren't counted since it's equivalent to not voting.
// Tally 是一个简单的投票计数器，用于记录当前的投票分数。反对提案的投票不计入统计，因为等同于未投票。
type Tally struct {
	Authorize bool `json:"authorize"` // Whether the vote is about authorizing or kicking someone 投票是否关于授权或移除某个签名者
	Votes     int  `json:"votes"`     // Number of votes until now wanting to pass the proposal 当前支持提案的投票数量
}

type sigLRU = lru.Cache[common.Hash, common.Address]

// Snapshot is the state of the authorization voting at a given point in time.
// Snapshot 是某一时间点授权投票的状态快照。
type Snapshot struct {
	config   *params.CliqueConfig // Consensus engine parameters to fine tune behavior 共识引擎参数，用于微调行为
	sigcache *sigLRU              // Cache of recent block signatures to speed up ecrecover 最近区块签名的缓存，用于加速 ecrecover

	Number  uint64                      `json:"number"`  // Block number where the snapshot was created 创建快照时的区块号
	Hash    common.Hash                 `json:"hash"`    // Block hash where the snapshot was created 创建快照时的区块哈希
	Signers map[common.Address]struct{} `json:"signers"` // Set of authorized signers at this moment 当前授权签名者的集合
	Recents map[uint64]common.Address   `json:"recents"` // Set of recent signers for spam protections 最近签名者的集合，用于防止垃圾信息攻击
	Votes   []*Vote                     `json:"votes"`   // List of votes cast in chronological order 按时间顺序排列的投票列表
	Tally   map[common.Address]Tally    `json:"tally"`   // Current vote tally to avoid recalculating 当前投票计数器，避免重新计算
}

// newSnapshot creates a new snapshot with the specified startup parameters. This
// method does not initialize the set of recent signers, so only ever use it for
// the genesis block.
// newSnapshot 使用指定的启动参数创建一个新的快照。此方法不会初始化最近签名者的集合，因此仅适用于创世区块。
func newSnapshot(config *params.CliqueConfig, sigcache *sigLRU, number uint64, hash common.Hash, signers []common.Address) *Snapshot {
	snap := &Snapshot{
		config:   config,
		sigcache: sigcache,
		Number:   number,
		Hash:     hash,
		Signers:  make(map[common.Address]struct{}),
		Recents:  make(map[uint64]common.Address),
		Tally:    make(map[common.Address]Tally),
	}
	for _, signer := range signers {
		snap.Signers[signer] = struct{}{} // 初始化签名者集合
	}
	return snap
}

// loadSnapshot loads an existing snapshot from the database.
// loadSnapshot 从数据库中加载现有的快照。
func loadSnapshot(config *params.CliqueConfig, sigcache *sigLRU, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append(rawdb.CliqueSnapshotPrefix, hash[:]...)) // 从数据库中获取快照数据
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil { // 反序列化为 Snapshot 对象
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache

	return snap, nil
}

// store inserts the snapshot into the database.
// store 将快照存储到数据库中。
func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s) // 序列化快照对象
	if err != nil {
		return err
	}
	return db.Put(append(rawdb.CliqueSnapshotPrefix, s.Hash[:]...), blob) // 存储到数据库
}

// copy creates a deep copy of the snapshot, though not the individual votes.
// copy 创建快照的深拷贝，但不包括单个投票。
func (s *Snapshot) copy() *Snapshot {
	return &Snapshot{
		config:   s.config,
		sigcache: s.sigcache,
		Number:   s.Number,
		Hash:     s.Hash,
		Signers:  maps.Clone(s.Signers), // 深拷贝签名者集合
		Recents:  maps.Clone(s.Recents), // 深拷贝最近签名者集合
		Votes:    slices.Clone(s.Votes), // 深拷贝投票列表
		Tally:    maps.Clone(s.Tally),   // 深拷贝投票计数器
	}
}

// validVote returns whether it makes sense to cast the specified vote in the
// given snapshot context (e.g. don't try to add an already authorized signer).
// validVote 返回在给定快照上下文中投出指定投票是否有意义（例如，不要尝试添加已授权的签名者）。
func (s *Snapshot) validVote(address common.Address, authorize bool) bool {
	_, signer := s.Signers[address]
	return (signer && !authorize) || (!signer && authorize) // 如果是取消已有签名者或授权新签名者，则有效
}

// cast adds a new vote into the tally.
// cast 将新的投票加入计数器。
func (s *Snapshot) cast(address common.Address, authorize bool) bool {
	// Ensure the vote is meaningful
	// 确保投票有意义
	if !s.validVote(address, authorize) {
		return false
	}
	// Cast the vote into an existing or new tally
	// 将投票加入现有的或新的计数器
	if old, ok := s.Tally[address]; ok {
		old.Votes++
		s.Tally[address] = old
	} else {
		s.Tally[address] = Tally{Authorize: authorize, Votes: 1} // 新建计数器
	}
	return true
}

// uncast removes a previously cast vote from the tally.
// uncast 从计数器中移除之前投出的投票。
func (s *Snapshot) uncast(address common.Address, authorize bool) bool {
	// If there's no tally, it's a dangling vote, just drop
	// 如果没有计数器，说明是无效投票，直接丢弃
	tally, ok := s.Tally[address]
	if !ok {
		return false
	}
	// Ensure we only revert counted votes
	// 确保只撤销已统计的投票
	if tally.Authorize != authorize {
		return false
	}
	// Otherwise revert the vote
	// 否则撤销投票
	if tally.Votes > 1 {
		tally.Votes--
		s.Tally[address] = tally
	} else {
		delete(s.Tally, address) // 如果投票数为 0，则删除计数器
	}
	return true
}

// apply creates a new authorization snapshot by applying the given headers to
// the original one.
// apply 通过将给定的区块头部应用到原始快照上，创建一个新的授权快照。
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	// Allow passing in no headers for cleaner code
	// 允许传入空头部以简化代码逻辑
	if len(headers) == 0 {
		return s, nil
	}
	// Sanity check that the headers can be applied
	// 检查头部是否可以正确应用
	for i := 0; i < len(headers)-1; i++ {
		if headers[i+1].Number.Uint64() != headers[i].Number.Uint64()+1 {
			return nil, errInvalidVotingChain // 区块号不连续，返回错误
		}
	}
	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain // 第一个区块号与快照不匹配，返回错误
	}
	// Iterate through the headers and create a new snapshot
	// 遍历头部并创建新的快照
	snap := s.copy()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for i, header := range headers {
		// Remove any votes on checkpoint blocks
		// 在检查点区块移除所有投票
		number := header.Number.Uint64()
		if number%s.config.Epoch == 0 {
			snap.Votes = nil
			snap.Tally = make(map[common.Address]Tally)
		}
		// Delete the oldest signer from the recent list to allow it signing again
		// 从最近签名者列表中删除最旧的签名者，允许其再次签名
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}
		// Resolve the authorization key and check against signers
		// 解析授权密钥并检查签名者
		signer, err := ecrecover(header, s.sigcache) // 从区块头部恢复签名者
		if err != nil {
			return nil, err
		}
		if _, ok := snap.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner // 签名者未经授权，返回错误
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				return nil, errRecentlySigned // 签名者刚刚签名过，返回错误
			}
		}
		snap.Recents[number] = signer

		// Header authorized, discard any previous votes from the signer
		// 区块头部已授权，移除签名者之前的投票
		for i, vote := range snap.Votes {
			if vote.Signer == signer && vote.Address == header.Coinbase {
				// Uncast the vote from the cached tally
				// 从计数器中撤销投票
				snap.uncast(vote.Address, vote.Authorize)

				// Uncast the vote from the chronological list
				// 从时间顺序列表中移除投票
				snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
				break // 每个签名者只能投一票
			}
		}
		// Tally up the new vote from the signer
		// 统计签名者的新投票
		var authorize bool
		switch {
		case bytes.Equal(header.Nonce[:], nonceAuthVote): // 授权投票
			authorize = true
		case bytes.Equal(header.Nonce[:], nonceDropVote): // 取消授权投票
			authorize = false
		default:
			return nil, errInvalidVote // 无效投票，返回错误
		}
		if snap.cast(header.Coinbase, authorize) {
			snap.Votes = append(snap.Votes, &Vote{
				Signer:    signer,
				Block:     number,
				Address:   header.Coinbase,
				Authorize: authorize,
			})
		}
		// If the vote passed, update the list of signers
		// 如果投票通过，更新签名者列表
		if tally := snap.Tally[header.Coinbase]; tally.Votes > len(snap.Signers)/2 {
			if tally.Authorize {
				snap.Signers[header.Coinbase] = struct{}{} // 添加新签名者
			} else {
				delete(snap.Signers, header.Coinbase) // 移除签名者

				// Signer list shrunk, delete any leftover recent caches
				// 签名者列表缩小，删除多余的最近签名者缓存
				if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
					delete(snap.Recents, number-limit)
				}
				// Discard any previous votes the deauthorized signer cast
				// 移除被取消授权签名者投出的所有投票
				for i := 0; i < len(snap.Votes); i++ {
					if snap.Votes[i].Signer == header.Coinbase {
						// Uncast the vote from the cached tally
						// 从计数器中撤销投票
						snap.uncast(snap.Votes[i].Address, snap.Votes[i].Authorize)

						// Uncast the vote from the chronological list
						// 从时间顺序列表中移除投票
						snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)

						i--
					}
				}
			}
			// Discard any previous votes around the just changed account
			// 移除与刚更改账户相关的所有先前投票
			for i := 0; i < len(snap.Votes); i++ {
				if snap.Votes[i].Address == header.Coinbase {
					snap.Votes = append(snap.Votes[:i], snap.Votes[i+1:]...)
					i--
				}
			}
			delete(snap.Tally, header.Coinbase) // 删除计数器中的相关条目
		}
		// If we're taking too much time (ecrecover), notify the user once a while
		// 如果处理时间过长（ecrecover），定期通知用户
		if time.Since(logged) > 8*time.Second {
			log.Info("Reconstructing voting history", "processed", i, "total", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if time.Since(start) > 8*time.Second {
		log.Info("Reconstructed voting history", "processed", len(headers), "elapsed", common.PrettyDuration(time.Since(start)))
	}
	snap.Number += uint64(len(headers))        // 更新快照的区块号
	snap.Hash = headers[len(headers)-1].Hash() // 更新快照的区块哈希

	return snap, nil
}

// signers retrieves the list of authorized signers in ascending order.
// signers 按升序检索授权签名者的列表。
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	slices.SortFunc(sigs, common.Address.Cmp) // 按地址排序
	return sigs
}

// inturn returns if a signer at a given block height is in-turn or not.
// inturn 返回在给定区块高度的签名者是否轮次内签名者。
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers, offset := s.signers(), 0
	for offset < len(signers) && signers[offset] != signer {
		offset++
	}
	return (number % uint64(len(signers))) == uint64(offset) // 判断签名者是否在当前轮次
}
