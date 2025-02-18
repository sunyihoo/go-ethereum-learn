// Copyright 2019 The go-ethereum Authors
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

package rawdb

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
)

// ReadSnapshotDisabled retrieves if the snapshot maintenance is disabled.
func ReadSnapshotDisabled(db ethdb.KeyValueReader) bool {
	disabled, _ := db.Has(snapshotDisabledKey)
	return disabled
}

// ReadSnapshotRoot retrieves the root of the block whose state is contained in
// the persisted snapshot.
func ReadSnapshotRoot(db ethdb.KeyValueReader) common.Hash {
	data, _ := db.Get(SnapshotRootKey)
	if len(data) != common.HashLength {
		return common.Hash{}
	}
	return common.BytesToHash(data)
}

// ReadSnapshotJournal retrieves the serialized in-memory diff layers saved at
// the last shutdown. The blob is expected to be max a few 10s of megabytes.
func ReadSnapshotJournal(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(snapshotJournalKey)
	return data
}

// ReadSnapshotRecoveryNumber retrieves the block number of the last persisted
// snapshot layer.
func ReadSnapshotRecoveryNumber(db ethdb.KeyValueReader) *uint64 {
	data, _ := db.Get(snapshotRecoveryKey)
	if len(data) == 0 {
		return nil
	}
	if len(data) != 8 {
		return nil
	}
	number := binary.BigEndian.Uint64(data)
	return &number
}

// ReadSnapshotSyncStatus retrieves the serialized sync status saved at shutdown.
func ReadSnapshotSyncStatus(db ethdb.KeyValueReader) []byte {
	data, _ := db.Get(snapshotSyncStatusKey)
	return data
}
