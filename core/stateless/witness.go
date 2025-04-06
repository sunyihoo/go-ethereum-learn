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
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// 轻客户端和状态证明
//
// 以太坊全节点存储了完整的区块链数据和当前的世界状态，这使得它们能够验证任何交易和查询任何历史状态。然而，对于资源受限的设备或应用，存储和同步完整节点的数据是不切实际的。轻客户端通过只存储部分区块链数据（通常是区块头）并依赖全节点提供的证明来验证它们感兴趣的数据。
//
// 为了验证某个特定账户的状态（例如余额）或某个存储槽的值，轻客户端需要一个“状态证明”。这个证明通常包括从状态根到目标数据的 Merkle Patricia Trie 的路径。为了验证这个路径，轻客户端还需要相关的区块头（包含状态根的哈希）以及可能涉及到的中间 Trie 节点。
//
// # Witness 结构体的作用
//
// Witness 结构体的目的是收集在验证以太坊交易执行和推导状态/收据根时所需的最少量的状态数据。它可以被看作是一个轻量级的状态快照，包含了验证特定操作所需的相关区块头、合约代码和状态 Trie 节点。

// 轻客户端协议: Witness 结构体是构建轻客户端协议的关键组件。轻客户端可以使用 Witness 中包含的数据来验证从全节点接收到的状态证明和交易执行结果。
// 状态证明验证: 为了验证一个状态证明，轻客户端需要拥有包含状态根的区块头以及证明路径上的所有相关的 Trie 节点。Witness 结构体用于存储这些必要的数据。
// Gas 成本计算: 在模拟交易执行或计算 Gas 消耗时，可能需要访问合约代码。Witness 存储了执行过程中访问过的所有合约代码，以便进行准确的 Gas 计算。
// 区块哈希操作: 以太坊合约可以使用 blockhash 操作码来获取最近的 256 个区块的哈希值。为了验证这些操作，见证需要包含相关的历史区块头。

// HeaderReader is an interface to pull in headers in place of block hashes for
// the witness.
// HeaderReader 是一个接口，用于拉取区块头以替代见证中的区块哈希。
type HeaderReader interface {
	// GetHeader retrieves a block header from the database by hash and number,
	// GetHeader 通过哈希和编号从数据库中检索区块头。
	GetHeader(hash common.Hash, number uint64) *types.Header
}

// Witness encompasses the state required to apply a set of transactions and
// derive a post state/receipt root.
// Witness 包含应用一组交易并推导出后状态/收据根所需的状态。
type Witness struct {
	context *types.Header // Header to which this witness belongs to, with rootHash and receiptHash zeroed out
	// context 此见证所属的区块头，其 rootHash 和 receiptHash 已清零。

	Headers []*types.Header // Past headers in reverse order (0=parent, 1=parent's-parent, etc). First *must* be set.
	// Headers 过去的区块头，按相反顺序排列（0=父区块，1=父区块的父区块，等等）。第一个 *必须* 设置。
	Codes map[string]struct{} // Set of bytecodes ran or accessed
	// Codes 运行或访问的字节码集合。
	State map[string]struct{} // Set of MPT state trie nodes (account and storage together)
	// State MPT 状态 Trie 节点集合（包括账户和存储）。

	chain HeaderReader // Chain reader to convert block hash ops to header proofs
	// chain 区块链读取器，用于将区块哈希操作转换为区块头证明。
	lock sync.Mutex // Lock to allow concurrent state insertions
	// lock 锁，用于允许并发插入状态。
}

// NewWitness creates an empty witness ready for population.
// NewWitness 创建一个准备填充数据的空见证。
func NewWitness(context *types.Header, chain HeaderReader) (*Witness, error) {
	// When building witnesses, retrieve the parent header, which will *always*
	// be included to act as a trustless pre-root hash container
	// 构建见证时，检索父区块头，该区块头将 *始终* 包含在内，作为可信的预根哈希容器。
	var headers []*types.Header
	if chain != nil {
		parent := chain.GetHeader(context.ParentHash, context.Number.Uint64()-1)
		if parent == nil {
			return nil, errors.New("failed to retrieve parent header")
		}
		headers = append(headers, parent)
	}
	// Create the wtness with a reconstructed gutted out block
	// 使用重建的精简区块创建见证。
	return &Witness{
		context: context,
		Headers: headers,
		Codes:   make(map[string]struct{}),
		State:   make(map[string]struct{}),
		chain:   chain,
	}, nil
}

// AddBlockHash adds a "blockhash" to the witness with the designated offset from
// chain head. Under the hood, this method actually pulls in enough headers from
// the chain to cover the block being added.
// AddBlockHash 将一个“区块哈希”添加到见证中，该哈希与链头的偏移量指定。
// 在底层，此方法实际上从链中拉取足够的区块头来覆盖要添加的区块。
func (w *Witness) AddBlockHash(number uint64) {
	// Keep pulling in headers until this hash is populated
	// 继续拉取区块头，直到填充此哈希。
	for int(w.context.Number.Uint64()-number) > len(w.Headers) {
		tail := w.Headers[len(w.Headers)-1]
		w.Headers = append(w.Headers, w.chain.GetHeader(tail.ParentHash, tail.Number.Uint64()-1))
	}
}

// AddCode adds a bytecode blob to the witness.
// AddCode 将一个字节码 blob 添加到见证中。
func (w *Witness) AddCode(code []byte) {
	// AddCode 方法将给定的字节码添加到见证的 Codes 集合中。
	if len(code) == 0 {
		return
	}
	w.Codes[string(code)] = struct{}{}
}

// AddState inserts a batch of MPT trie nodes into the witness.
// AddState 将一批 MPT Trie 节点插入到见证中。
func (w *Witness) AddState(nodes map[string]struct{}) {
	// AddState 方法将给定的 MPT Trie 节点集合合并到见证的 State 集合中。
	if len(nodes) == 0 {
		return
	}
	w.lock.Lock()
	defer w.lock.Unlock()

	maps.Copy(w.State, nodes)
}

// Copy deep-copies the witness object.  Witness.Block isn't deep-copied as it
// is never mutated by Witness
// Copy 深拷贝见证对象。Witness.Block 不进行深拷贝，因为它永远不会被 Witness 修改。
func (w *Witness) Copy() *Witness {
	// Copy 方法创建一个新的 Witness 实例，其内容是当前 Witness 的深拷贝。
	cpy := &Witness{
		Headers: slices.Clone(w.Headers),
		Codes:   maps.Clone(w.Codes),
		State:   maps.Clone(w.State),
		chain:   w.chain,
	}
	if w.context != nil {
		cpy.context = types.CopyHeader(w.context)
	}
	return cpy
}

// Root returns the pre-state root from the first header.
//
// Note, this method will panic in case of a bad witness (but RLP decoding will
// sanitize it and fail before that).
// Root 从第一个区块头返回预状态根。
//
// 注意，如果见证无效，此方法将 panic（但在那之前，RLP 解码会对其进行清理并失败）。
func (w *Witness) Root() common.Hash {
	// Root 方法返回见证中第一个区块头的状态根哈希。
	return w.Headers[0].Root
}
