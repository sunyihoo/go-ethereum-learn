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

package misc

import (
	"bytes"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

var (
	// ErrBadProDAOExtra is returned if a header doesn't support the DAO fork on a
	// pro-fork client.
	// 如果区块头在支持 DAO 分叉的客户端上未提供正确的分叉特定 extra-data，则返回此错误。
	ErrBadProDAOExtra = errors.New("bad DAO pro-fork extra-data")

	// ErrBadNoDAOExtra is returned if a header does support the DAO fork on a no-
	// fork client.
	// 如果区块头在不支持 DAO 分叉的客户端上提供了分叉特定 extra-data，则返回此错误。
	ErrBadNoDAOExtra = errors.New("bad DAO no-fork extra-data")
)

// VerifyDAOHeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to DAO hard-fork rules.
//
// DAO hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
//   - 如果节点是 no-fork（不支持分叉），则拒绝 [fork, fork+10) 范围内包含分叉特定 extra-data 的区块。
//   - 如果节点是 pro-fork（支持分叉），则要求该范围内的区块必须包含分叉特定 extra-data。
func VerifyDAOHeaderExtraData(config *params.ChainConfig, header *types.Header) error {
	// Short circuit validation if the node doesn't care about the DAO fork
	if config.DAOForkBlock == nil {
		return nil
	}
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(config.DAOForkBlock, params.DAOForkExtraRange)
	if header.Number.Cmp(config.DAOForkBlock) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	// Depending on whether we support or oppose the fork, validate the extra-data contents
	if config.DAOForkSupport {
		// 支持分叉：要求 extra-data 必须匹配分叉特定值。
		if !bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
			return ErrBadProDAOExtra
		}
	} else {
		// 不支持分叉：禁止 extra-data 匹配分叉特定值。
		if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
			return ErrBadNoDAOExtra
		}
	}
	// All ok, header has the same extra-data we expect
	return nil
}

// ApplyDAOHardFork modifies the state database according to the DAO hard-fork
// rules, transferring all balances of a set of DAO accounts to a single refund
// contract.
// ApplyDAOHardFork 根据 DAO 硬分叉规则修改状态数据库，将所有 DAO 账户的余额转移到退款合约中。
func ApplyDAOHardFork(statedb vm.StateDB) {
	// Retrieve the contract to refund balances into
	if !statedb.Exist(params.DAORefundContract) {
		statedb.CreateAccount(params.DAORefundContract)
	}

	// Move every DAO account and extra-balance account funds into the refund contract
	for _, addr := range params.DAODrainList() {
		balance := statedb.GetBalance(addr)
		statedb.AddBalance(params.DAORefundContract, balance, tracing.BalanceIncreaseDaoContract)
		statedb.SubBalance(addr, balance, tracing.BalanceDecreaseDaoAccount)
	}
}
