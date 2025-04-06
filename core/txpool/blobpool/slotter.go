// Copyright 2023 The go-ethereum Authors
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

package blobpool

// newSlotter 函数的作用是为 Blob 交易池所使用的名为 "Billy" 的数据存储创建一个辅助机制，用于确定存储不同大小的 Blob 交易所需的“架子 (shelf)”的大小。这里的“架子”很可能指的是数据存储中预先分配的存储空间单元，用于存放具有特定特征（例如，包含特定数量的 Blob）的交易。
//
// “Billy” 数据存储和“架子”的概念
//
// “Billy” 在这段代码中指的是一个数据存储系统，Blob 交易池使用它来持久化存储待处理的 Blob 交易。为了有效地管理存储空间，Billy 可能会使用不同大小的“架子”来存放不同大小的交易。这样做可以减少存储碎片，并优化存储空间的利用率。

// 为什么需要不同的架子大小？
//
// Blob 交易的大小会根据其包含的 Blob 数量而变化。一个不包含 Blob 的交易大小相对较小，而一个包含最大允许数量 Blob 的交易则会大得多。为所有交易分配相同大小的架子可能会导致存储空间的浪费（对于不包含 Blob 的交易）或者无法存储包含大量 Blob 的交易。因此，newSlotter 通过逐步增加架子的大小（每次增加一个 blobSize），为存储包含不同数量 Blob 的交易提供了不同大小的存储空间。

// newSlotter creates a helper method for the Billy datastore that returns the
// individual shelf sizes used to store transactions in.
//
// The slotter will create shelves for each possible blob count + some tx metadata
// wiggle room, up to the max permitted limits.
//
// The slotter also creates a shelf for 0-blob transactions. Whilst those are not
// allowed in the current protocol, having an empty shelf is not a relevant use
// of resources, but it makes stress testing with junk transactions simpler.
// newSlotter 为 Billy 数据存储创建一个辅助方法，该方法返回用于存储交易的各个“架子 (shelf)”的大小。
//
// 该槽位分配器 (slotter) 将为每个可能的 Blob 计数加上一些交易元数据的缓冲空间创建“架子”，直到达到允许的最大限制。
//
// 该槽位分配器还会为 0-Blob 交易创建一个“架子”。尽管当前协议不允许此类交易，但拥有一个空“架子”并非资源的有效利用，
// 但它可以简化使用垃圾交易进行压力测试。
func newSlotter() func() (uint32, bool) {
	slotsize := uint32(txAvgSize) // Initialize the initial slot size with the average transaction size.
	// 使用平均交易大小初始化初始槽位大小。
	slotsize -= uint32(blobSize) // underflows, it's ok, will overflow back in the first return
	// 发生下溢是正常的，它会在第一次返回时溢出回来。

	return func() (size uint32, done bool) {
		slotsize += blobSize // Increment the slot size by the size of one blob on each call.
		// 每次调用时，将槽位大小增加一个 Blob 的大小。
		finished := slotsize > maxBlobsPerTransaction*blobSize+txMaxSize // Check if the slot size has exceeded the maximum allowed size.
		// 检查槽位大小是否已超过允许的最大大小。

		return slotsize, finished
	}
}
