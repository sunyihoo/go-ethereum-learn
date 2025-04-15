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

package discover

import (
	"slices"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

// enode.Node 是以太坊节点记录（ENR，EIP-778）的封装，包含节点标识和网络信息。
// tableNode 是 Kademlia DHT 中节点表的核心结构，结合了存活验证和时间戳管理。
// 在以太坊 Discovery v5（EIP-1459）中，节点存活通过 PING/PONG 消息验证。

type BucketNode struct {
	// 节点信息
	Node *enode.Node `json:"node"` // Node information
	// 节点被添加到表的时间
	AddedToTable time.Time `json:"addedToTable"` // Time when the node was added to the table
	// 节点被添加到桶的时间
	AddedToBucket time.Time `json:"addedToBucket"` // Time when the node was added to the bucket
	// 执行的存活检查次数
	Checks int `json:"checks"` // Number of liveness checks performed
	// 节点当前是否被认为存活
	Live bool `json:"live"` // Whether the node is currently considered live
}

// tableNode is an entry in Table.
// tableNode 是表中的一个条目。
type tableNode struct {
	// 嵌入的节点信息
	*enode.Node // Embedded node information
	// 节点的重新验证列表
	revalList *revalidationList // Revalidation list for the node
	// 节点首次被添加到桶或替换列表的时间
	addedToTable time.Time // first time node was added to bucket or replacement list
	// 节点被添加到实际桶的时间
	addedToBucket time.Time // time it was added in the actual bucket
	// 存活分数
	livenessChecks uint // how often liveness was checked
	// 如果节点的存活状态当前被验证为真，则为 true
	isValidatedLive bool // true if existence of node is considered validated right now
}

func unwrapNodes(ns []*tableNode) []*enode.Node {
	result := make([]*enode.Node, len(ns))
	for i, n := range ns {
		// 从 tableNode 中提取 enode.Node
		result[i] = n.Node // Extract the enode.Node from tableNode
	}
	return result
}

func (n *tableNode) String() string {
	// 返回节点的字符串表示
	return n.Node.String() // Return the string representation of the node
}

// enode.DistCmp 使用 XOR 距离度量，是 Kademlia 算法的核心，用于衡量节点间的“接近度”。
// maxElems 通常对应 Kademlia 的桶大小（16），限制结果集以优化查找性能。
// 在以太坊的节点发现中，这种结构用于 FINDNODE 请求的响应排序。

// nodesByDistance is a list of nodes, ordered by distance to target.
// nodesByDistance 是一个按与目标距离排序的节点列表。
type nodesByDistance struct {
	// 节点列表
	entries []*enode.Node // List of nodes
	// 用于距离计算的目标节点 ID
	target enode.ID // Target node ID for distance calculation
}

// push adds the given node to the list, keeping the total size below maxElems.
// push 将给定节点添加到列表中，保持总数低于 maxElems。
func (h *nodesByDistance) push(n *enode.Node, maxElems int) {
	ix := sort.Search(len(h.entries), func(i int) bool {
		return enode.DistCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})

	end := len(h.entries)
	if len(h.entries) < maxElems {
		// 如果列表未满，直接追加
		h.entries = append(h.entries, n) // Append if the list is not full
	}
	if ix < end {
		// Slide existing entries down to make room.
		// This will overwrite the entry we just appended.
		// 将现有条目向下移动以腾出空间。
		// 这将覆盖我们刚追加的条目。
		copy(h.entries[ix+1:], h.entries[ix:])
		// 在正确位置插入新节点
		h.entries[ix] = n // Insert the new node at the correct position
	}
}

type nodeType interface {
	ID() enode.ID // Interface requiring an ID method 定义需要 ID 方法的接口
}

// containsID reports whether ns contains a node with the given ID.
// containsID 报告 ns 是否包含具有给定 ID 的节点。
func containsID[N nodeType](ns []N, id enode.ID) bool {
	for _, n := range ns {
		if n.ID() == id {
			return true
		}
	}
	return false
}

// deleteNode removes a node from the list.
// deleteNode 从列表中移除一个节点。
func deleteNode[N nodeType](list []N, id enode.ID) []N {
	return slices.DeleteFunc(list, func(n N) bool {
		// 删除匹配给定 ID 的节点
		return n.ID() == id // Delete the node matching the given ID
	})
}
