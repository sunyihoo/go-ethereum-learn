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

package stateless

import (
	"io"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

// 无状态执行 (Stateless Execution)
//
// 传统的以太坊节点需要维护完整的区块链状态（所有账户的余额、合约代码、存储等）才能验证交易的有效性。这导致全节点的资源消耗非常高。无状态执行的目标是允许客户端在不持有完整状态的情况下验证交易，方法是让提议区块的节点提供一个“见证”，其中包含了执行该区块中的交易所需的所有状态片段。
//
// 见证 (Witness)
//
// 见证是执行一个或多个交易所需的状态数据的集合。对于一个给定的交易，见证通常包括：
//
// 区块头 (Headers)：与交易执行相关的区块头信息。
// 合约代码 (Codes)：交易执行过程中调用的所有合约的字节码。
// 状态 trie 节点 (State)：交易执行过程中访问的所有账户和存储槽对应的状态 trie 节点。
// 通过提供见证，无状态客户端可以重放交易的执行过程，并验证结果（例如状态变化、Gas 消耗）是否与区块头中声明的一致，而无需自己存储完整的状态。
//
// 内部表示 (Witness) 和外部表示 (extWitness)
//
// 代码中定义了两种见证的表示形式：
//
// 内部表示 (Witness): 在代码中，w 指向一个 Witness 类型的结构体（其具体定义没有在此代码片段中给出，但可以推测它可能使用 map 来存储 Codes 和 State，以方便查找和去重）。
// 外部表示 (extWitness): extWitness 结构体是用于在不同客户端之间传输的共识格式。它使用切片 ([][]byte) 来存储 Codes 和 State。
// 使用不同的内部和外部表示的原因可能包括：
//
// 内部优化: 使用 map 可以方便地去重和查找合约代码和状态 trie 节点。
// 共识标准: 使用切片作为外部表示可能更符合 RLP 编码的习惯，并且方便在网络上传输。

// toExtWitness converts our internal witness representation to the consensus one.
// toExtWitness 将我们的内部见证表示转换为共识表示。
func (w *Witness) toExtWitness() *extWitness {
	ext := &extWitness{
		Headers: w.Headers, // Copy the headers from the internal witness.
		// 将内部见证中的头部信息复制到外部见证。
	}
	ext.Codes = make([][]byte, 0, len(w.Codes)) // Initialize a slice for contract codes.
	// 初始化一个用于存储合约代码的切片。
	for code := range w.Codes {
		ext.Codes = append(ext.Codes, []byte(code)) // Copy contract codes to the external witness.
		// 将合约代码复制到外部见证。
	}
	ext.State = make([][]byte, 0, len(w.State)) // Initialize a slice for state trie nodes.
	// 初始化一个用于存储状态 trie 节点的切片。
	for node := range w.State {
		ext.State = append(ext.State, []byte(node)) // Copy state trie nodes to the external witness.
		// 将状态 trie 节点复制到外部见证。
	}
	return ext
}

// fromExtWitness converts the consensus witness format into our internal one.
// fromExtWitness 将共识见证格式转换为我们的内部格式。
func (w *Witness) fromExtWitness(ext *extWitness) error {
	w.Headers = ext.Headers // Copy the headers from the external witness.
	// 将外部见证中的头部信息复制到内部见证。

	w.Codes = make(map[string]struct{}, len(ext.Codes)) // Initialize a map for contract codes.
	// 初始化一个用于存储合约代码的 map。
	for _, code := range ext.Codes {
		w.Codes[string(code)] = struct{}{} // Copy contract codes to the internal witness.
		// 将合约代码复制到内部见证。
	}
	w.State = make(map[string]struct{}, len(ext.State)) // Initialize a map for state trie nodes.
	// 初始化一个用于存储状态 trie 节点的 map。
	for _, node := range ext.State {
		w.State[string(node)] = struct{}{} // Copy state trie nodes to the internal witness.
		// 将状态 trie 节点复制到内部见证。
	}
	return nil
}

// EncodeRLP serializes a witness as RLP.
// EncodeRLP 将一个见证序列化为 RLP 格式。
func (w *Witness) EncodeRLP(wr io.Writer) error {
	return rlp.Encode(wr, w.toExtWitness()) // Convert to external format and then RLP encode.
	// 转换为外部格式，然后进行 RLP 编码。
}

// DecodeRLP decodes a witness from RLP.
// DecodeRLP 从 RLP 格式解码一个见证。
func (w *Witness) DecodeRLP(s *rlp.Stream) error {
	var ext extWitness
	if err := s.Decode(&ext); err != nil {
		return err // Decode the RLP data into the external witness format.
		// 将 RLP 数据解码为外部见证格式。
	}
	return w.fromExtWitness(&ext) // Convert the external witness to the internal format.
	// 将外部见证转换为内部格式。
}

// extWitness is a witness RLP encoding for transferring across clients.
// extWitness 是用于跨客户端传输的见证 RLP 编码格式。
type extWitness struct {
	Headers []*types.Header // Block headers relevant to the witness.
	// Headers 与见证相关的区块头部信息。
	Codes [][]byte // Contract codes accessed by the transaction.
	// Codes 交易访问的合约代码。
	State [][]byte // State trie nodes accessed by the transaction.
	// State 交易访问的状态 trie 节点。
}
