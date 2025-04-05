// Copyright 2018 The go-ethereum Authors
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

package accounts

// 账户和钱包的 URL ：
// 在以太坊生态系统中，每个账户或钱包都有一个唯一的 URL，用于标识其来源（如硬件钱包、软件钱包等）。
// URL 的标准化格式使得排序和比较变得简单且高效。
// 多后端支持 ：
// 不同的后端可能返回不同的账户或钱包列表，通过统一的排序逻辑，可以更好地整合和管理这些资源。

// AccountsByURL implements sort.Interface for []Account based on the URL field.
// AccountsByURL 实现了基于 URL 字段的 []Account 的 sort.Interface 接口。
type AccountsByURL []Account

// Len returns the length of the AccountsByURL slice.
// Len 返回 AccountsByURL 切片的长度。
func (a AccountsByURL) Len() int { return len(a) }

// Swap swaps the elements at indices i and j in the AccountsByURL slice.
// Swap 交换 AccountsByURL 切片中索引为 i 和 j 的元素。
func (a AccountsByURL) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Less compares the URL fields of the elements at indices i and j in the AccountsByURL slice.
// It returns true if the URL of the element at index i is lexicographically smaller than that at index j.
// Less 比较 AccountsByURL 切片中索引为 i 和 j 的元素的 URL 字段。
// 如果索引为 i 的元素的 URL 字典序小于索引为 j 的元素，则返回 true。
func (a AccountsByURL) Less(i, j int) bool { return a[i].URL.Cmp(a[j].URL) < 0 }

// WalletsByURL implements sort.Interface for []Wallet based on the URL field.
// WalletsByURL 实现了基于 URL 字段的 []Wallet 的 sort.Interface 接口。
type WalletsByURL []Wallet

// Len returns the length of the WalletsByURL slice.
// Len 返回 WalletsByURL 切片的长度。
func (w WalletsByURL) Len() int { return len(w) }

// Swap swaps the elements at indices i and j in the WalletsByURL slice.
// Swap 交换 WalletsByURL 切片中索引为 i 和 j 的元素。
func (w WalletsByURL) Swap(i, j int) { w[i], w[j] = w[j], w[i] }

// Less compares the URL fields of the elements at indices i and j in the WalletsByURL slice.
// It returns true if the URL of the element at index i is lexicographically smaller than that at index j.
// Less 比较 WalletsByURL 切片中索引为 i 和 j 的元素的 URL 字段。
// 如果索引为 i 的元素的 URL 字典序小于索引为 j 的元素，则返回 true。
func (w WalletsByURL) Less(i, j int) bool { return w[i].URL().Cmp(w[j].URL()) < 0 }
