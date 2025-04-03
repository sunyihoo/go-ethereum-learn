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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package pathdb

import "errors"

var (
	// errDatabaseReadOnly is returned if the database is opened in read only mode
	// to prevent any mutation.
	// errDatabaseReadOnly：如果数据库以只读模式打开，为了防止任何修改而返回此错误。
	//
	// 在以太坊节点中，有时可能需要以只读模式打开数据库，例如在进行某些分析或查询操作时，以防止意外修改区块链数据。
	errDatabaseReadOnly = errors.New("read only")

	// errDatabaseWaitSync is returned if the initial state sync is not completed
	// yet and database is disabled to prevent accessing state.
	// errDatabaseWaitSync：如果初始状态同步尚未完成，并且数据库已禁用以防止访问状态，则返回此错误。
	//
	// 当一个新的以太坊节点加入网络时，它需要从其他节点下载并验证整个区块链的状态。这个过程称为状态同步。在同步完成之前，节点的状态数据是不完整的，因此可能会阻止某些操作。
	errDatabaseWaitSync = errors.New("waiting for sync")

	// errSnapshotStale is returned from data accessors if the underlying layer
	// had been invalidated due to the chain progressing forward far enough
	// to not maintain the layer's original state.
	// errSnapshotStale：如果由于链向前推进得足够远，以至于无法维护该层原始状态，导致底层 layer 无效，则数据访问器会返回此错误。
	//
	// 为了节省存储空间和提高性能，以太坊节点可能会对历史状态进行修剪（pruning）。当请求访问一个已经被修剪掉的历史状态时，相关的状态层就会变得陈旧（stale）。
	errSnapshotStale = errors.New("layer stale")

	// errUnexpectedHistory is returned if an unmatched state history is applied
	// to the database for state rollback.
	// errUnexpectedHistory：如果将不匹配的状态历史应用于数据库以进行状态回滚，则返回此错误。
	//
	// 以太坊支持状态回滚，这在处理区块链重组（reorganization）等情况时非常有用。节点会保存一定的历史状态信息，以便在需要时回滚到之前的状态。但是，回滚操作需要使用正确的历史记录。
	errUnexpectedHistory = errors.New("unexpected state history")

	// errStateUnrecoverable is returned if state is required to be reverted to
	// a destination without associated state history available.
	// errStateUnrecoverable：如果需要将状态恢复到没有相关状态历史记录的目标，则返回此错误。
	// 虽然以太坊支持状态回滚，但是保存所有的历史状态会消耗大量的存储空间。因此，节点通常只会保留最近一段时间的历史状态。如果需要回滚到的状态超出了保留范围，则状态将无法恢复。
	errStateUnrecoverable = errors.New("state is unrecoverable")
)
