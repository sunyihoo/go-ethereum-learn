// Copyright 2022 The go-ethereum Authors
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

package abi

import "fmt"

// ResolveNameConflict returns the next available name for a given thing.
// This helper can be used for lots of purposes:
//
//   - In solidity function overloading is supported, this function can fix
//     the name conflicts of overloaded functions.
//   - In golang binding generation, the parameter(in function, event, error,
//     and struct definition) name will be converted to camelcase style which
//     may eventually lead to name conflicts.
//
// Name conflicts are mostly resolved by adding number suffix. e.g. if the abi contains
// Methods "send" and "send1", ResolveNameConflict would return "send2" for input "send".
// ResolveNameConflict 返回给定事物的下一个可用名称。
// 该辅助函数可用于多种目的：
//
//   - 在 Solidity 中支持函数重载，此函数可以解决重载函数的名称冲突问题。
//   - 在生成 Go 语言绑定时，参数（在函数、事件、错误和结构体定义中）名称会被转换为驼峰命名风格，
//     这可能会导致名称冲突。
//
// 名称冲突通常通过添加数字后缀来解决。例如，如果 ABI 包含方法 "send" 和 "send1"，
// ResolveNameConflict 对于输入 "send" 将返回 "send2"。
func ResolveNameConflict(rawName string, used func(string) bool) string {
	// 初始化名称为原始名称
	name := rawName
	// 检查当前名称是否已被使用
	ok := used(name)
	// 如果名称已被使用，则循环添加数字后缀，直到找到未使用的名称
	for idx := 0; ok; idx++ {
		name = fmt.Sprintf("%s%d", rawName, idx)
		ok = used(name)
	}
	// 返回最终可用的名称
	return name
}
