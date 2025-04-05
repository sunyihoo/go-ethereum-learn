// Copyright 2024 The go-ethereum Authors
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

package types

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/beacon/merkle"
	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	zrntcommon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
)

// 执行层 (Execution Layer): 在合并之前是以太坊的主网，负责处理交易的执行和状态的更新。合并后，它成为信标链的一个“执行引擎”。
// 信标链 (Beacon Chain): 合并后的以太坊共识层，负责管理验证者、达成共识以及协调执行层。
// 执行负载 (Execution Payload): 信标链区块中包含的数据，它实际上是来自执行层的区块内容，包括交易、状态根等。
// 执行头 (Execution Header): 是执行负载的头部信息，包含了关键的元数据，例如 Payload Root 和 Block Hash。信标链主要通过引用执行头来与执行层进行交互和共识。
// Payload Root: 执行负载的 Merkle 根，用于确保信标链对执行层数据的共识是基于完整且未被篡改的数据。
// Block Hash: 执行层区块的唯一标识符，信标链需要知道这个哈希来引用特定的执行层区块。
// 分叉 (Forks): 以太坊协议的升级可能会影响执行头的数据结构，因此代码中需要根据不同的分叉名称来处理不同版本的执行头。

type headerObject interface {
	HashTreeRoot(hFn tree.HashFn) zrntcommon.Root
}

type ExecutionHeader struct {
	obj headerObject
}

// ExecutionHeaderFromJSON decodes an execution header from JSON data provided by
// the beacon chain API.
// ExecutionHeaderFromJSON 从信标链 API 提供的 JSON 数据中解码一个执行头。
func ExecutionHeaderFromJSON(forkName string, data []byte) (*ExecutionHeader, error) {
	var obj headerObject
	switch forkName {
	case "capella":
		obj = new(capella.ExecutionPayloadHeader)
	case "deneb":
		obj = new(deneb.ExecutionPayloadHeader)
	default:
		return nil, fmt.Errorf("unsupported fork: %s", forkName)
	}
	if err := json.Unmarshal(data, obj); err != nil {
		return nil, err
	}
	return &ExecutionHeader{obj: obj}, nil
}

// NewExecutionHeader creates a new ExecutionHeader from a headerObject.
// NewExecutionHeader 从一个 headerObject 创建一个新的 ExecutionHeader。
func NewExecutionHeader(obj headerObject) *ExecutionHeader {
	switch obj.(type) {
	case *capella.ExecutionPayloadHeader:
	case *deneb.ExecutionPayloadHeader:
	default:
		panic(fmt.Errorf("unsupported ExecutionPayloadHeader type %T", obj))
	}
	return &ExecutionHeader{obj: obj}
}

// PayloadRoot returns the Merkle root of the execution payload.
// PayloadRoot 返回执行负载的 Merkle 根。
func (eh *ExecutionHeader) PayloadRoot() merkle.Value {
	return merkle.Value(eh.obj.HashTreeRoot(tree.GetHashFn()))
}

// BlockHash returns the block hash of the execution layer block.
// BlockHash 返回执行层区块的哈希值。
func (eh *ExecutionHeader) BlockHash() common.Hash {
	switch obj := eh.obj.(type) {
	case *capella.ExecutionPayloadHeader:
		return common.Hash(obj.BlockHash)
	case *deneb.ExecutionPayloadHeader:
		return common.Hash(obj.BlockHash)
	default:
		panic(fmt.Errorf("unsupported ExecutionPayloadHeader type %T", obj))
	}
}
