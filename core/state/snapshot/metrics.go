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

package snapshot

import "github.com/ethereum/go-ethereum/metrics"

// Metrics in generation
// 生成过程中的指标
var (
	snapGeneratedAccountMeter = metrics.NewRegisteredMeter("state/snapshot/generation/account/generated", nil) // Number of accounts generated in the snapshot
	// snapGeneratedAccountMeter 是快照中生成的账户数量的度量器。
	snapRecoveredAccountMeter = metrics.NewRegisteredMeter("state/snapshot/generation/account/recovered", nil) // Number of accounts recovered from previous snapshots
	// snapRecoveredAccountMeter 是从先前快照恢复的账户数量的度量器。
	snapWipedAccountMeter = metrics.NewRegisteredMeter("state/snapshot/generation/account/wiped", nil) // Number of accounts wiped out during generation
	// snapWipedAccountMeter 是在生成过程中被清除的账户数量的度量器。
	snapMissallAccountMeter = metrics.NewRegisteredMeter("state/snapshot/generation/account/missall", nil) // Number of accounts missing in all previous snapshots
	// snapMissallAccountMeter 是在所有先前快照中都缺失的账户数量的度量器。
	snapGeneratedStorageMeter = metrics.NewRegisteredMeter("state/snapshot/generation/storage/generated", nil) // Number of storage slots generated in the snapshot
	// snapGeneratedStorageMeter 是快照中生成的存储槽数量的度量器。
	snapRecoveredStorageMeter = metrics.NewRegisteredMeter("state/snapshot/generation/storage/recovered", nil) // Number of storage slots recovered from previous snapshots
	// snapRecoveredStorageMeter 是从先前快照恢复的存储槽数量的度量器。
	snapWipedStorageMeter = metrics.NewRegisteredMeter("state/snapshot/generation/storage/wiped", nil) // Number of storage slots wiped out during generation
	// snapWipedStorageMeter 是在生成过程中被清除的存储槽数量的度量器。
	snapMissallStorageMeter = metrics.NewRegisteredMeter("state/snapshot/generation/storage/missall", nil) // Number of storage slots missing in all previous snapshots
	// snapMissallStorageMeter 是在所有先前快照中都缺失的存储槽数量的度量器。
	snapDanglingStorageMeter = metrics.NewRegisteredMeter("state/snapshot/generation/storage/dangling", nil) // Number of storage slots found without a corresponding account
	// snapDanglingStorageMeter 是找到的没有对应账户的存储槽数量的度量器。
	snapSuccessfulRangeProofMeter = metrics.NewRegisteredMeter("state/snapshot/generation/proof/success", nil) // Number of successful range proofs during generation
	// snapSuccessfulRangeProofMeter 是生成过程中成功的范围证明数量的度量器。
	snapFailedRangeProofMeter = metrics.NewRegisteredMeter("state/snapshot/generation/proof/failure", nil) // Number of failed range proofs during generation
	// snapFailedRangeProofMeter 是生成过程中失败的范围证明数量的度量器。

	// snapAccountProveCounter measures time spent on the account proving
	// snapAccountProveCounter 衡量花费在账户证明上的时间。
	snapAccountProveCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/account/prove", nil)
	// snapAccountTrieReadCounter measures time spent on the account trie iteration
	// snapAccountTrieReadCounter 衡量花费在账户 Trie 迭代上的时间。
	snapAccountTrieReadCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/account/trieread", nil)
	// snapAccountSnapReadCounter measures time spent on the snapshot account iteration
	// snapAccountSnapReadCounter 衡量花费在快照账户迭代上的时间。
	snapAccountSnapReadCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/account/snapread", nil)
	// snapAccountWriteCounter measures time spent on writing/updating/deleting accounts
	// snapAccountWriteCounter 衡量花费在写入/更新/删除账户上的时间。
	snapAccountWriteCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/account/write", nil)
	// snapStorageProveCounter measures time spent on storage proving
	// snapStorageProveCounter 衡量花费在存储证明上的时间。
	snapStorageProveCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/storage/prove", nil)
	// snapStorageTrieReadCounter measures time spent on the storage trie iteration
	// snapStorageTrieReadCounter 衡量花费在存储 Trie 迭代上的时间。
	snapStorageTrieReadCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/storage/trieread", nil)
	// snapStorageSnapReadCounter measures time spent on the snapshot storage iteration
	// snapStorageSnapReadCounter 衡量花费在快照存储迭代上的时间。
	snapStorageSnapReadCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/storage/snapread", nil)
	// snapStorageWriteCounter measures time spent on writing/updating storages
	// snapStorageWriteCounter 衡量花费在写入/更新存储上的时间。
	snapStorageWriteCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/storage/write", nil)
	// snapStorageCleanCounter measures time spent on deleting storages
	// snapStorageCleanCounter 衡量花费在删除存储上的时间。
	snapStorageCleanCounter = metrics.NewRegisteredCounter("state/snapshot/generation/duration/storage/clean", nil)
)
