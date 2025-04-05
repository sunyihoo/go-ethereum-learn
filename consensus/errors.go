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

package consensus

import "errors"

var (
	// ErrUnknownAncestor is returned when validating a block requires an ancestor
	// that is unknown.
	// 当验证一个区块需要一个未知的祖先区块时返回 ErrUnknownAncestor。
	ErrUnknownAncestor = errors.New("unknown ancestor")

	// ErrPrunedAncestor is returned when validating a block requires an ancestor
	// that is known, but the state of which is not available.
	// 当验证一个区块需要一个已知但状态不可用的祖先区块时返回 ErrPrunedAncestor。
	ErrPrunedAncestor = errors.New("pruned ancestor")

	// ErrFutureBlock is returned when a block's timestamp is in the future according
	// to the current node.
	// 当一个区块的时间戳相对于当前节点处于未来时返回 ErrFutureBlock。
	ErrFutureBlock = errors.New("block in the future")

	// ErrInvalidNumber is returned if a block's number doesn't equal its parent's
	// plus one.
	// 如果一个区块的编号不等于其父区块编号加一时返回 ErrInvalidNumber。
	ErrInvalidNumber = errors.New("invalid block number")

	// ErrInvalidTerminalBlock is returned if a block is invalid wrt. the terminal
	// total difficulty.
	// 如果一个区块相对于终端总难度无效时返回 ErrInvalidTerminalBlock。
	ErrInvalidTerminalBlock = errors.New("invalid terminal block")
)
