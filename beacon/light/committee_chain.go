// Copyright 2023 The go-ethereum Authors
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

package light

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/params"
	"github.com/ethereum/go-ethereum/beacon/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/common/mclock"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
)

// 轻客户端验证信标链头部，确保数据可信。

var (
	ErrNeedCommittee      = errors.New("sync committee required")       // 需要同步委员会
	ErrInvalidUpdate      = errors.New("invalid committee update")      // 无效的委员会更新
	ErrInvalidPeriod      = errors.New("invalid update period")         // 无效的更新周期
	ErrWrongCommitteeRoot = errors.New("wrong committee root")          // 错误的委员会根
	ErrCannotReorg        = errors.New("can not reorg committee chain") // 无法重组委员会链
)

// CommitteeChain is a passive data structure that can validate, hold and update
// a chain of beacon light sync committees and updates. It requires at least one
// externally set fixed committee root at the beginning of the chain which can
// be set either based on a BootstrapData or a trusted source (a local beacon
// full node). This makes the structure useful for both light client and light
// server setups.
//
// It always maintains the following consistency constraints:
//   - a committee can only be present if its root hash matches an existing fixed
//     root or if it is proven by an update at the previous period
//   - an update can only be present if a committee is present at the same period
//     and the update signature is valid and has enough participants.
//     The committee at the next period (proven by the update) should also be
//     present (note that this means they can only be added together if neither
//     is present yet). If a fixed root is present at the next period then the
//     update can only be present if it proves the same committee root.
//
// Once synced to the current sync period, CommitteeChain can also validate
// signed beacon headers.
// CommitteeChain 是一个被动数据结构，可以验证、持有和更新信标轻客户端同步委员会和更新的链。
// 它要求链的开始处至少有一个外部设置的固定委员会根，可以基于 BootstrapData 或可信来源（本地信标全节点）设置。
// 这使得该结构适用于轻客户端和轻服务器设置。
//
// 它始终保持以下一致性约束：
//   - 只有当委员会的根哈希与现有的固定根匹配或由前一周期的更新证明时，委员会才能存在
//   - 只有当同一周期存在委员会且更新签名有效且参与者足够时，更新才能存在。
//     下一周期的委员会（由更新证明）也应存在（注意，这意味着如果两者都不存在，则只能一起添加）。
//     如果下一周期存在固定根，则更新只能在证明相同委员会根的情况下存在。
//
// 一旦同步到当前同步周期，CommitteeChain 还可以验证签名信标头部。
type CommitteeChain struct {
	// chainmu guards against concurrent access to the canonicalStore structures
	// (updates, committees, fixedCommitteeRoots) and ensures that they stay consistent
	// with each other and with committeeCache.
	// chainmu 防止对 canonicalStore 结构（updates、committees、fixedCommitteeRoots）的并发访问，
	// 并确保它们彼此以及与 committeeCache 保持一致。
	chainmu             sync.RWMutex
	db                  ethdb.KeyValueStore
	updates             *canonicalStore[*types.LightClientUpdate]       // 更新存储
	committees          *canonicalStore[*types.SerializedSyncCommittee] // 委员会存储
	fixedCommitteeRoots *canonicalStore[common.Hash]                    // 固定委员会根存储
	committeeCache      *lru.Cache[uint64, syncCommittee]               // cache deserialized committees 缓存反序列化的委员会
	changeCounter       uint64                                          // 变更计数器

	clock       mclock.Clock         // monotonic clock (simulated clock in tests) 单调时钟（测试中为模拟时钟）
	unixNano    func() int64         // system clock (simulated clock in tests) 系统时钟（测试中为模拟时钟）
	sigVerifier committeeSigVerifier // BLS sig verifier (dummy verifier in tests) 签名验证器（测试中为虚拟验证器）

	config             *params.ChainConfig
	minimumUpdateScore types.UpdateScore // 最小更新分数
	enforceTime        bool              // enforceTime specifies whether the age of a signed header should be checked 指定是否检查签名头部的年龄
}

// NewCommitteeChain creates a new CommitteeChain.
// NewCommitteeChain 创建一个新的 CommitteeChain。
func NewCommitteeChain(db ethdb.KeyValueStore, config *params.ChainConfig, signerThreshold int, enforceTime bool) *CommitteeChain {
	return newCommitteeChain(db, config, signerThreshold, enforceTime, blsVerifier{}, &mclock.System{}, func() int64 { return time.Now().UnixNano() })
}

// NewTestCommitteeChain creates a new CommitteeChain for testing.
// NewTestCommitteeChain 为测试创建一个新的 CommitteeChain。
func NewTestCommitteeChain(db ethdb.KeyValueStore, config *params.ChainConfig, signerThreshold int, enforceTime bool, clock *mclock.Simulated) *CommitteeChain {
	return newCommitteeChain(db, config, signerThreshold, enforceTime, dummyVerifier{}, clock, func() int64 { return int64(clock.Now()) })
}

// newCommitteeChain creates a new CommitteeChain with the option of replacing the
// clock source and signature verification for testing purposes.
// newCommitteeChain 创建一个新的 CommitteeChain，可以选择替换时钟源和签名验证以用于测试。
func newCommitteeChain(db ethdb.KeyValueStore, config *params.ChainConfig, signerThreshold int, enforceTime bool, sigVerifier committeeSigVerifier, clock mclock.Clock, unixNano func() int64) *CommitteeChain {
	s := &CommitteeChain{
		committeeCache: lru.NewCache[uint64, syncCommittee](10), // LRU 缓存容量为 10
		db:             db,
		sigVerifier:    sigVerifier,
		clock:          clock,
		unixNano:       unixNano,
		config:         config,
		enforceTime:    enforceTime,
		minimumUpdateScore: types.UpdateScore{
			SignerCount:    uint32(signerThreshold),      // 签名者阈值
			SubPeriodIndex: params.SyncPeriodLength / 16, // 子周期索引
		},
	}

	var err1, err2, err3 error
	if s.fixedCommitteeRoots, err1 = newCanonicalStore[common.Hash](db, rawdb.FixedCommitteeRootKey); err1 != nil {
		log.Error("Error creating fixed committee root store", "error", err1)
		// 创建固定委员会根存储时出错
	}
	if s.committees, err2 = newCanonicalStore[*types.SerializedSyncCommittee](db, rawdb.SyncCommitteeKey); err2 != nil {
		log.Error("Error creating committee store", "error", err2)
		// 创建委员会存储时出错
	}
	if s.updates, err3 = newCanonicalStore[*types.LightClientUpdate](db, rawdb.BestUpdateKey); err3 != nil {
		log.Error("Error creating update store", "error", err3)
		// 创建更新存储时出错
	}
	if err1 != nil || err2 != nil || err3 != nil || !s.checkConstraints() {
		log.Info("Resetting invalid committee chain")
		// 重置无效的委员会链
		s.Reset()
	}
	// roll back invalid updates (might be necessary if forks have been changed since last time)
	// 回滚无效更新（如果自上次以来分叉已更改，可能需要这样做）
	for !s.updates.periods.isEmpty() {
		update, ok := s.updates.get(s.db, s.updates.periods.End-1)
		if !ok {
			log.Error("Sync committee update missing", "period", s.updates.periods.End-1)
			// 同步委员会更新缺失
			s.Reset()
			break
		}
		if valid, err := s.verifyUpdate(update); err != nil {
			log.Error("Error validating update", "period", s.updates.periods.End-1, "error", err)
			// 验证更新时出错
		} else if valid {
			break
		}
		if err := s.rollback(s.updates.periods.End); err != nil {
			log.Error("Error writing batch into chain database", "error", err)
			// 将批次写入链数据库时出错
		}
	}
	if !s.committees.periods.isEmpty() {
		log.Trace("Sync committee chain loaded", "first period", s.committees.periods.Start, "last period", s.committees.periods.End-1)
		// 同步委员会链已加载
	}
	return s
}

// checkConstraints checks committee chain validity constraints
// checkConstraints 检查委员会链的有效性约束
func (s *CommitteeChain) checkConstraints() bool {
	isNotInFixedCommitteeRootRange := func(r periodRange) bool {
		return s.fixedCommitteeRoots.periods.isEmpty() ||
			r.Start < s.fixedCommitteeRoots.periods.Start ||
			r.Start >= s.fixedCommitteeRoots.periods.End
	}

	valid := true
	if !s.updates.periods.isEmpty() {
		if isNotInFixedCommitteeRootRange(s.updates.periods) {
			log.Error("Start update is not in the fixed roots range")
			// 起始更新不在固定根范围内
			valid = false
		}
		if s.committees.periods.Start > s.updates.periods.Start || s.committees.periods.End <= s.updates.periods.End {
			log.Error("Missing committees in update range")
			// 更新范围内缺少委员会
			valid = false
		}
	}
	if !s.committees.periods.isEmpty() {
		if isNotInFixedCommitteeRootRange(s.committees.periods) {
			log.Error("Start committee is not in the fixed roots range")
			// 起始委员会不在固定根范围内
			valid = false
		}
		if s.committees.periods.End > s.fixedCommitteeRoots.periods.End && s.committees.periods.End > s.updates.periods.End+1 {
			log.Error("Last committee is neither in the fixed roots range nor proven by updates")
			// 最后一个委员会既不在固定根范围内，也未由更新证明
			valid = false
		}
	}
	return valid
}

// Reset resets the committee chain.
// Reset 重置委员会链。
func (s *CommitteeChain) Reset() {
	s.chainmu.Lock()
	defer s.chainmu.Unlock()

	if err := s.rollback(0); err != nil {
		log.Error("Error writing batch into chain database", "error", err)
		// 将批次写入链数据库时出错
	}
	s.changeCounter++
}

// CheckpointInit initializes a CommitteeChain based on a checkpoint.
// Note: if the chain is already initialized and the committees proven by the
// checkpoint do match the existing chain then the chain is retained and the
// new checkpoint becomes fixed.
// CheckpointInit 基于检查点初始化 CommitteeChain。
// 注意：如果链已初始化且检查点证明的委员会与现有链匹配，则保留该链，新检查点将成为固定点。
func (s *CommitteeChain) CheckpointInit(bootstrap types.BootstrapData) error {
	s.chainmu.Lock()
	defer s.chainmu.Unlock()

	if err := bootstrap.Validate(); err != nil {
		return err
	}
	period := bootstrap.Header.SyncPeriod()
	if err := s.deleteFixedCommitteeRootsFrom(period + 2); err != nil {
		s.Reset()
		return err
	}
	if s.addFixedCommitteeRoot(period, bootstrap.CommitteeRoot) != nil {
		s.Reset()
		if err := s.addFixedCommitteeRoot(period, bootstrap.CommitteeRoot); err != nil {
			s.Reset()
			return err
		}
	}
	if err := s.addFixedCommitteeRoot(period+1, common.Hash(bootstrap.CommitteeBranch[0])); err != nil {
		s.Reset()
		return err
	}
	if err := s.addCommittee(period, bootstrap.Committee); err != nil {
		s.Reset()
		return err
	}
	s.changeCounter++
	return nil
}

// addFixedCommitteeRoot sets a fixed committee root at the given period.
// Note that the period where the first committee is added has to have a fixed
// root which can either come from a BootstrapData or a trusted source.
// addFixedCommitteeRoot 在给定周期设置固定委员会根。
// 注意：添加第一个委员会的周期必须有一个固定根，可以来自 BootstrapData 或可信来源。
func (s *CommitteeChain) addFixedCommitteeRoot(period uint64, root common.Hash) error {
	if root == (common.Hash{}) {
		return ErrWrongCommitteeRoot
	}

	batch := s.db.NewBatch()
	oldRoot := s.getCommitteeRoot(period)
	if !s.fixedCommitteeRoots.periods.canExpand(period) {
		// Note: the fixed committee root range should always be continuous and
		// therefore the expected syncing method is to forward sync and optionally
		// backward sync periods one by one, starting from a checkpoint. The only
		// case when a root that is not adjacent to the already fixed ones can be
		// fixed is when the same root has already been proven by an update chain.
		// In this case the all roots in between can and should be fixed.
		// This scenario makes sense when a new trusted checkpoint is added to an
		// existing chain, ensuring that it will not be rolled back (might be
		// important in case of low signer participation rate).
		// 注意：固定委员会根范围应始终是连续的，因此预期的同步方法是从检查点开始逐个周期向前同步，
		// 并可选地向后同步。只有当同一根已被更新链证明时，才能固定不与已固定的根相邻的根。
		// 在这种情况下，中间的所有根都可以且应该被固定。
		// 当向现有链添加新的可信检查点时，这种情况是有意义的，确保不会回滚（在签名者参与率低的情况下可能很重要）。
		if root != oldRoot {
			return ErrInvalidPeriod
		}
		// if the old root exists and matches the new one then it is guaranteed
		// that the given period is after the existing fixed range and the roots
		// in between can also be fixed.
		// 如果旧根存在且与新根匹配，则保证给定周期在现有固定范围之后，中间的根也可以被固定。
		for p := s.fixedCommitteeRoots.periods.End; p < period; p++ {
			if err := s.fixedCommitteeRoots.add(batch, p, s.getCommitteeRoot(p)); err != nil {
				return err
			}
		}
	}
	if oldRoot != (common.Hash{}) && (oldRoot != root) {
		// existing old root was different, we have to reorg the chain
		// 现有旧根不同，我们必须重组链
		if err := s.rollback(period); err != nil {
			return err
		}
	}
	if err := s.fixedCommitteeRoots.add(batch, period, root); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		log.Error("Error writing batch into chain database", "error", err)
		// 将批次写入链数据库时出错
		return err
	}
	return nil
}

// deleteFixedCommitteeRootsFrom deletes fixed roots starting from the given period.
// It also maintains chain consistency, meaning that it also deletes updates and
// committees if they are no longer supported by a valid update chain.
// deleteFixedCommitteeRootsFrom 从给定周期开始删除固定根。
// 它还保持链的一致性，即如果更新链不再有效支持，则同时删除更新和委员会。
func (s *CommitteeChain) deleteFixedCommitteeRootsFrom(period uint64) error {
	if period >= s.fixedCommitteeRoots.periods.End {
		return nil
	}
	batch := s.db.NewBatch()
	s.fixedCommitteeRoots.deleteFrom(batch, period)
	if s.updates.periods.isEmpty() || period <= s.updates.periods.Start {
		// Note: the first period of the update chain should always be fixed so if
		// the fixed root at the first update is removed then the entire update chain
		// and the proven committees have to be removed. Earlier committees in the
		// remaining fixed root range can stay.
		// 注意：更新链的第一个周期应始终是固定的，因此如果第一个更新的固定根被移除，
		// 则整个更新链和证明的委员会必须被移除。剩余固定根范围内的早期委员会可以保留。
		s.updates.deleteFrom(batch, period)
		s.deleteCommitteesFrom(batch, period)
	} else {
		// The update chain stays intact, some previously fixed committee roots might
		// get unfixed but are still proven by the update chain. If there were
		// committees present after the range proven by updates, those should be
		// removed if the belonging fixed roots are also removed.
		// 更新链保持完整，一些先前固定的委员会根可能变为非固定，但仍由更新链证明。
		// 如果更新证明的范围之后存在委员会，且所属固定根也被移除，则应移除这些委员会。
		fromPeriod := s.updates.periods.End + 1 // not proven by updates 未被更新证明的周期
		if period > fromPeriod {
			fromPeriod = period //  also not justified by fixed roots 也不由固定根证明的周期
		}
		s.deleteCommitteesFrom(batch, fromPeriod)
	}
	if err := batch.Write(); err != nil {
		log.Error("Error writing batch into chain database", "error", err)
		// 将批次写入链数据库时出错
		return err
	}
	return nil
}

// deleteCommitteesFrom deletes committees starting from the given period.
// deleteCommitteesFrom 从给定周期开始删除委员会。
func (s *CommitteeChain) deleteCommitteesFrom(batch ethdb.Batch, period uint64) {
	deleted := s.committees.deleteFrom(batch, period)
	for period := deleted.Start; period < deleted.End; period++ {
		s.committeeCache.Remove(period)
	}
}

// addCommittee adds a committee at the given period if possible.
// addCommittee 在可能的情况下在给定周期添加委员会。
func (s *CommitteeChain) addCommittee(period uint64, committee *types.SerializedSyncCommittee) error {
	if !s.committees.periods.canExpand(period) {
		return ErrInvalidPeriod
	}
	root := s.getCommitteeRoot(period)
	if root == (common.Hash{}) {
		return ErrInvalidPeriod
	}
	if root != committee.Root() {
		return ErrWrongCommitteeRoot
	}
	if !s.committees.periods.contains(period) {
		if err := s.committees.add(s.db, period, committee); err != nil {
			return err
		}
		s.committeeCache.Remove(period)
	}
	return nil
}

// InsertUpdate adds a new update if possible.
// InsertUpdate 在可能的情况下添加新更新。
func (s *CommitteeChain) InsertUpdate(update *types.LightClientUpdate, nextCommittee *types.SerializedSyncCommittee) error {
	s.chainmu.Lock()
	defer s.chainmu.Unlock()

	period := update.AttestedHeader.Header.SyncPeriod()
	if !s.updates.periods.canExpand(period) || !s.committees.periods.contains(period) {
		return ErrInvalidPeriod
	}
	if s.minimumUpdateScore.BetterThan(update.Score()) {
		return ErrInvalidUpdate
	}
	oldRoot := s.getCommitteeRoot(period + 1)
	reorg := oldRoot != (common.Hash{}) && oldRoot != update.NextSyncCommitteeRoot
	if oldUpdate, ok := s.updates.get(s.db, period); ok && !update.Score().BetterThan(oldUpdate.Score()) {
		// a better or equal update already exists; no changes, only fail if new one tried to reorg
		// 已存在更好或相等的更新；不做更改，仅在新更新尝试重组时失败
		if reorg {
			return ErrCannotReorg
		}
		return nil
	}
	if s.fixedCommitteeRoots.periods.contains(period+1) && reorg {
		return ErrCannotReorg
	}
	if ok, err := s.verifyUpdate(update); err != nil {
		return err
	} else if !ok {
		return ErrInvalidUpdate
	}
	addCommittee := !s.committees.periods.contains(period+1) || reorg
	if addCommittee {
		if nextCommittee == nil {
			return ErrNeedCommittee
		}
		if nextCommittee.Root() != update.NextSyncCommitteeRoot {
			return ErrWrongCommitteeRoot
		}
	}
	s.changeCounter++
	if reorg {
		if err := s.rollback(period + 1); err != nil {
			return err
		}
	}
	batch := s.db.NewBatch()
	if addCommittee {
		if err := s.committees.add(batch, period+1, nextCommittee); err != nil {
			return err
		}
		s.committeeCache.Remove(period + 1)
	}
	if err := s.updates.add(batch, period, update); err != nil {
		return err
	}
	if err := batch.Write(); err != nil {
		log.Error("Error writing batch into chain database", "error", err)
		// 将批次写入链数据库时出错
		return err
	}
	log.Info("Inserted new committee update", "period", period, "next committee root", update.NextSyncCommitteeRoot)
	// 插入新的委员会更新
	return nil
}

// NextSyncPeriod returns the next period where an update can be added and also
// whether the chain is initialized at all.
// NextSyncPeriod 返回可以添加更新的下一个周期，以及链是否已初始化。
func (s *CommitteeChain) NextSyncPeriod() (uint64, bool) {
	s.chainmu.RLock()
	defer s.chainmu.RUnlock()

	if s.committees.periods.isEmpty() {
		return 0, false
	}
	if !s.updates.periods.isEmpty() {
		return s.updates.periods.End, true
	}
	return s.committees.periods.End - 1, true
}

func (s *CommitteeChain) ChangeCounter() uint64 {
	s.chainmu.RLock()
	defer s.chainmu.RUnlock()

	return s.changeCounter
}

// rollback removes all committees and fixed roots from the given period and updates
// starting from the previous period.
// rollback 从给定周期移除所有委员会和固定根，并从前一周期开始移除更新。
func (s *CommitteeChain) rollback(period uint64) error {
	max := s.updates.periods.End + 1
	if s.committees.periods.End > max {
		max = s.committees.periods.End
	}
	if s.fixedCommitteeRoots.periods.End > max {
		max = s.fixedCommitteeRoots.periods.End
	}
	for max > period {
		max--
		batch := s.db.NewBatch()
		s.deleteCommitteesFrom(batch, max)
		s.fixedCommitteeRoots.deleteFrom(batch, max)
		if max > 0 {
			s.updates.deleteFrom(batch, max-1)
		}
		if err := batch.Write(); err != nil {
			log.Error("Error writing batch into chain database", "error", err)
			// 将批次写入链数据库时出错
			return err
		}
	}
	return nil
}

// getCommitteeRoot returns the committee root at the given period, either fixed,
// proven by a previous update or both. It returns an empty hash if the committee
// root is unknown.
// getCommitteeRoot 返回给定周期的委员会根，可以是固定的、由前一更新证明的或两者兼有。如果委员会根未知，则返回空哈希。
func (s *CommitteeChain) getCommitteeRoot(period uint64) common.Hash {
	if root, ok := s.fixedCommitteeRoots.get(s.db, period); ok || period == 0 {
		return root
	}
	if update, ok := s.updates.get(s.db, period-1); ok {
		return update.NextSyncCommitteeRoot
	}
	return common.Hash{}
}

// getSyncCommittee returns the deserialized sync committee at the given period.
// getSyncCommittee 返回给定周期的反序列化同步委员会。
func (s *CommitteeChain) getSyncCommittee(period uint64) (syncCommittee, error) {
	if c, ok := s.committeeCache.Get(period); ok {
		return c, nil
	}
	if sc, ok := s.committees.get(s.db, period); ok {
		c, err := s.sigVerifier.deserializeSyncCommittee(sc)
		if err != nil {
			return nil, fmt.Errorf("sync committee #%d deserialization error: %v", period, err)
			// 同步委员会 #%d 反序列化错误
		}
		s.committeeCache.Add(period, c)
		return c, nil
	}
	return nil, fmt.Errorf("missing serialized sync committee #%d", period)
	// 缺少序列化的同步委员会 #%d
}

// VerifySignedHeader returns true if the given signed header has a valid signature
// according to the local committee chain. The caller should ensure that the
// committees advertised by the same source where the signed header came from are
// synced before verifying the signature.
// The age of the header is also returned (the time elapsed since the beginning
// of the given slot, according to the local system clock). If enforceTime is
// true then negative age (future) headers are rejected.
// VerifySignedHeader 如果给定签名头部根据本地委员会链具有有效签名，则返回 true。
// 调用者应确保在验证签名之前，与签名头部来自同一来源的委员会已同步。
// 还返回头部的年龄（根据本地系统时钟，自给定槽开始以来经过的时间）。
// 如果 enforceTime 为 true，则拒绝负年龄（未来的）头部。
func (s *CommitteeChain) VerifySignedHeader(head types.SignedHeader) (bool, time.Duration, error) {
	s.chainmu.RLock()
	defer s.chainmu.RUnlock()

	return s.verifySignedHeader(head)
}

func (s *CommitteeChain) verifySignedHeader(head types.SignedHeader) (bool, time.Duration, error) {
	var age time.Duration
	now := s.unixNano()
	if head.Header.Slot < (uint64(now-math.MinInt64)/uint64(time.Second)-s.config.GenesisTime)/12 {
		age = time.Duration(now - int64(time.Second)*int64(s.config.GenesisTime+head.Header.Slot*12))
	} else {
		age = time.Duration(math.MinInt64)
	}
	if s.enforceTime && age < 0 {
		return false, age, nil
	}
	committee, err := s.getSyncCommittee(types.SyncPeriod(head.SignatureSlot))
	if err != nil {
		return false, 0, err
	}
	if committee == nil {
		return false, age, nil
	}
	if signingRoot, err := s.config.Forks.SigningRoot(head.Header.Epoch(), head.Header.Hash()); err == nil {
		return s.sigVerifier.verifySignature(committee, signingRoot, &head.Signature), age, nil
	}
	return false, age, nil
}

// verifyUpdate checks whether the header signature is correct and the update
// fits into the specified constraints (assumes that the update has been
// successfully validated previously)
// verifyUpdate 检查头部签名是否正确以及更新是否符合指定约束（假定更新之前已成功验证）。
func (s *CommitteeChain) verifyUpdate(update *types.LightClientUpdate) (bool, error) {
	// Note: SignatureSlot determines the sync period of the committee used for signature
	// verification. Though in reality SignatureSlot is always bigger than update.Header.Slot,
	// setting them as equal here enforces the rule that they have to be in the same sync
	// period in order for the light client update proof to be meaningful.
	// 注意：SignatureSlot 确定用于签名验证的委员会的同步周期。
	// 虽然实际上 SignatureSlot 总是大于 update.Header.Slot，但在这里将它们设置为相等，
	// 以强制执行它们必须在同一同步周期内的规则，以便轻客户端更新证明有意义。
	ok, age, err := s.verifySignedHeader(update.AttestedHeader)
	if age < 0 {
		log.Warn("Future committee update received", "age", age)
		// 收到未来的委员会更新
	}
	return ok, err
}
