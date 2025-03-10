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

package eth

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/bloombits"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/gasprice"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// TODO NOT Finish the EthAPIBackend

// EthAPIBackend implements ethapi.Backend and tracers.Backend for full nodes
type EthAPIBackend struct {
	extRPCEnabled       bool
	allowUnprotectedTxs bool
	eth                 *Ethereum
	gpo                 *gasprice.Oracle
}

func (e EthAPIBackend) SyncProgress() ethereum.SyncProgress {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, []*big.Int, []float64, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) BlobBaseFee(ctx context.Context) *big.Int {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) AccountManager() *accounts.Manager {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) ExtRPCEnabled() bool {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) RPCEVMTimeout() time.Duration {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) RPCTxFeeCap() float64 {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) UnprotectedAllowed() bool {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SetHead(number uint64) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) CurrentHeader() *types.Header {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) CurrentBlock() *types.Header {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetEVM(ctx context.Context, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockCtx *vm.BlockContext) *vm.EVM {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetPoolTransactions() (types.Transactions, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) Stats() (pending int, queued int) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SubscribeNewTxsEvent(events chan<- core.NewTxsEvent) event.Subscription {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) BloomStatus() (uint64, uint64) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) Pending() (*types.Block, types.Receipts, *state.StateDB) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) RPCGasCap() uint64 {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) ChainConfig() *params.ChainConfig {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) Engine() consensus.Engine {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) ChainDb() ethdb.Database {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, readOnly bool, preferDisk bool) (*state.StateDB, tracers.StateReleaseFunc, error) {
	//TODO implement me
	panic("implement me")
}

func (e EthAPIBackend) StateAtTransaction(ctx context.Context, block *types.Block, txIndex int, reexec uint64) (*types.Transaction, vm.BlockContext, *state.StateDB, tracers.StateReleaseFunc, error) {
	//TODO implement me
	panic("implement me")
}
