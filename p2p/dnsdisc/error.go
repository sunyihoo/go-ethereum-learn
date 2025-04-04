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

package dnsdisc

import (
	"errors"
	"fmt"
)

// ENR（Ethereum Node Records）：以太坊节点元数据的标准格式（EIP-778），包含公钥、IP、端口等信息，用于节点发现和身份验证。
// 树形结构：类似 Merkle Tree 的结构可能用于分布式数据存储或验证（如 Portal Network 或 Swarm），其中包含根节点、链接（link）和 ENR 条目。
// 签名验证：ENR 和树条目通常需要签名以确保数据完整性和来源可信。
// 树类型分离：errENRInLinkTree 和 errLinkInENRTree 表明代码处理两种树（链接树和 ENR 树），可能是以太坊分布式网络（如 Swarm 或 Portal Network）中的设计。

// Entry parse errors.
// 条目解析错误。
var (
	errUnknownEntry = errors.New("unknown entry type")       // Unknown entry type encountered / 遇到未知的条目类型
	errNoPubkey     = errors.New("missing public key")       // Missing public key in entry / 条目中缺少公钥
	errBadPubkey    = errors.New("invalid public key")       // Invalid public key format or value / 公钥格式或值无效
	errInvalidENR   = errors.New("invalid node record")      // Invalid Ethereum Node Record (ENR) / 以太坊节点记录 (ENR) 无效
	errInvalidChild = errors.New("invalid child hash")       // Invalid hash of a child entry / 子条目的哈希无效
	errInvalidSig   = errors.New("invalid base64 signature") // Invalid base64-encoded signature / base64 编码的签名无效
	errSyntax       = errors.New("invalid syntax")           // Syntax error in parsing / 解析中的语法错误
)

// Resolver/sync errors
// 解析器/同步错误
var (
	errNoRoot        = errors.New("no valid root found")       // No valid root entry found / 未找到有效的根条目
	errNoEntry       = errors.New("no valid tree entry found") // No valid entry in the tree / 树中未找到有效条目
	errHashMismatch  = errors.New("hash mismatch")             // Hash does not match expected value / 哈希与预期值不匹配
	errENRInLinkTree = errors.New("enr entry in link tree")    // ENR entry found in link tree / 在链接树中找到 ENR 条目
	errLinkInENRTree = errors.New("link entry in ENR tree")    // Link entry found in ENR tree / 在 ENR 树中找到链接条目
)

type nameError struct {
	name string // Name associated with the error / 与错误关联的名称
	err  error  // Underlying error / 底层错误
}

func (err nameError) Error() string {
	if ee, ok := err.err.(entryError); ok { // If the error is an entryError / 如果错误是 entryError 类型
		return fmt.Sprintf("invalid %s entry at %s: %v", ee.typ, err.name, ee.err) // Format with entry type / 使用条目类型格式化
	}
	return err.name + ": " + err.err.Error() // Default formatting / 默认格式化
}

type entryError struct {
	typ string // Type of the entry causing the error / 引发错误的条目类型
	err error  // Underlying error / 底层错误
}

func (err entryError) Error() string {
	return fmt.Sprintf("invalid %s entry: %v", err.typ, err.err) // Format error with entry type / 使用条目类型格式化错误
}
