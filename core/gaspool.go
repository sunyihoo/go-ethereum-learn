// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"fmt"
	"math"
)

// GasPool tracks the amount of gas available during execution of the transactions
// in a block. The zero value is a pool with zero gas available.
// GasPool 跟踪在区块中执行交易期间可用的 gas 量。零值表示 gas 可用量为零的池。
type GasPool uint64

// AddGas makes gas available for execution.
// AddGas 使 gas 可用于执行。
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	if uint64(*gp) > math.MaxUint64-amount {
		panic("gas pool pushed above uint64")
	}
	*(*uint64)(gp) += amount
	return gp
}

// SubGas deducts the given amount from the pool if enough gas is
// available and returns an error otherwise.
// SubGas 从池中扣除给定的量（如果 gas 足够可用），否则返回错误。
func (gp *GasPool) SubGas(amount uint64) error {
	if uint64(*gp) < amount {
		return ErrGasLimitReached
	}
	*(*uint64)(gp) -= amount
	return nil
}

// Gas returns the amount of gas remaining in the pool.
// Gas 返回池中剩余的 gas 量。
func (gp *GasPool) Gas() uint64 {
	return uint64(*gp)
}

// SetGas sets the amount of gas with the provided number.
// SetGas 使用提供的数量设置 gas 量。
func (gp *GasPool) SetGas(gas uint64) {
	*(*uint64)(gp) = gas
}

func (gp *GasPool) String() string {
	return fmt.Sprintf("%d", *gp)
}
