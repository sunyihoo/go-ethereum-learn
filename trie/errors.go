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

package trie

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// Trie（状态树）：
// 在以太坊中，状态树（如 Merkle Patricia Trie 或 Verkle Trie）存储账户状态（余额、nonce、代码、存储等）。
// “已提交”（committed）通常表示树的状态已被持久化到数据库（如 LevelDB），生成根哈希后不可更改。
// 以太坊相关知识点：go-ethereum 中，Commit 方法将内存中的 trie 写入磁盘，返回根哈希，之后 trie 变为只读。

// ErrCommitted is returned when an already committed trie is requested for usage.
// The potential usages can be `Get`, `Update`, `Delete`, `NodeIterator`, `Prove`
// and so on.
// ErrCommitted 当请求使用一个已提交的 trie 时返回。
// 潜在的使用场景包括 `Get`、`Update`、`Delete`、`NodeIterator`、`Prove` 等。
//
// 用于表示当尝试对一个已经提交（committed）的 trie（树）进行操作时，返回的错误状态。
// 这通常发生在状态树（如 Verkle 树或 Merkle 树）被锁定或持久化后，禁止进一步修改或特定操作。
var ErrCommitted = errors.New("trie is already committed")

// MissingNodeError is returned by the trie functions (Get, Update, Delete)
// in the case where a trie node is not present in the local database. It contains
// information necessary for retrieving the missing node.
//
// MissingNodeError 由 trie 函数（Get、Update、Delete）在本地数据库中缺少 trie 节点时返回。
// 它包含检索缺失节点所需的信息。
//
// 用于表示 trie 操作（如 Get、Update、Delete）因本地数据库缺少节点而失败。它不仅提供错误信息，还包含定位缺失节点的详细信息，便于后续处理（如从网络检索）。
type MissingNodeError struct {
	Owner    common.Hash // owner of the trie if it's 2-layered trie  如果是双层 trie，则为 trie 的所有者，表示 trie 的所有者哈希，仅在双层 trie 结构中有效。如果为空（common.Hash{}），则表示单层 trie。
	NodeHash common.Hash // hash of the missing node				  缺失节点的哈希值，用于唯一标识该节点。
	Path     []byte      // hex-encoded path to the missing node      到缺失节点的十六进制编码路径，在 trie 中，路径通常是从根到节点的键路径（例如存储键的哈希部分）。
	err      error       // concrete error for missing trie node      缺失 trie 节点的底层错误
}

// Unwrap returns the concrete error for missing trie node which
// allows us for further analysis outside.
// Unwrap 返回缺失 trie 节点的底层错误，以便在外部进行进一步分析。
func (err *MissingNodeError) Unwrap() error {
	return err.err
}

func (err *MissingNodeError) Error() string {
	if err.Owner == (common.Hash{}) { // 如果 Owner 为空哈希
		return fmt.Sprintf("missing trie node %x (path %x) %v", err.NodeHash, err.Path, err.err)
	}
	return fmt.Sprintf("missing trie node %x (owner %x) (path %x) %v", err.NodeHash, err.Owner, err.Path, err.err)
}
