// Copyright 2016 The go-ethereum Authors
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

package jsre

import (
	"regexp"
	"sort"
	"strings"

	"github.com/dop251/goja"
)

// JS numerical token
// JS 数值型标记
var numerical = regexp.MustCompile(`^(NaN|-?((\d*\.\d+|\d+)([Ee][+-]?\d+)?|Infinity))$`)

// CompleteKeywords returns potential continuations for the given line. Since line is
// evaluated, callers need to make sure that evaluating line does not have side effects.
// CompleteKeywords 返回给定行的潜在补全项。由于该行会被执行，调用者需要确保执行该行不会产生副作用。
func (jsre *JSRE) CompleteKeywords(line string) []string {
	var results []string
	jsre.Do(func(vm *goja.Runtime) {
		results = getCompletions(vm, line)
	})
	return results
}

func getCompletions(vm *goja.Runtime, line string) (results []string) {
	parts := strings.Split(line, ".")
	if len(parts) == 0 {
		return nil
	}

	// Find the right-most fully named object in the line. e.g. if line = "x.y.z"
	// and "x.y" is an object, obj will reference "x.y".
	// 在行中找到最右边的完整命名的对象。例如，如果 line = "x.y.z" 并且 "x.y" 是一个对象，那么 obj 将引用 "x.y"。
	obj := vm.GlobalObject() // Start with the global object. 从全局对象开始。
	for i := 0; i < len(parts)-1; i++ {
		if numerical.MatchString(parts[i]) {
			return nil // Cannot get properties of a number using dot notation in this context. 在此上下文中，不能使用点符号获取数字的属性。
		}
		v := obj.Get(parts[i]) // Get the property with the current part's name. 获取具有当前部分名称的属性。
		if v == nil || goja.IsNull(v) || goja.IsUndefined(v) {
			return nil // No object was found along the path. 路径上没有找到对象。
		}
		obj = v.ToObject(vm) // Convert the value to an object. 将值转换为对象。
	}

	// Go over the keys of the object and retain the keys matching prefix.
	// Example: if line = "x.y.z" and "x.y" exists and has keys "zebu", "zebra"
	// and "platypus", then "x.y.zebu" and "x.y.zebra" will be added to results.
	// 遍历对象的键，并保留与前缀匹配的键。
	// 示例：如果 line = "x.y.z" 并且 "x.y" 存在且具有键 "zebu"、"zebra" 和 "platypus"，
	// 那么 "x.y.zebu" 和 "x.y.zebra" 将被添加到结果中。
	prefix := parts[len(parts)-1]                       // The last part of the line is the prefix for completion. 行的最后一部分是补全的前缀。
	iterOwnAndConstructorKeys(vm, obj, func(k string) { // Iterate over the object's own and constructor keys. 遍历对象自身的和构造函数的键。
		if strings.HasPrefix(k, prefix) { // Check if the key starts with the given prefix. 检查键是否以给定的前缀开头。
			if len(parts) == 1 {
				results = append(results, k) // If it's the first part, just add the key. 如果是第一部分，直接添加键。
			} else {
				results = append(results, strings.Join(parts[:len(parts)-1], ".")+"."+k) // Otherwise, prepend the previous parts and a dot. 否则，加上前面的部分和一个点。
			}
		}
	})

	// Append opening parenthesis (for functions) or dot (for objects)
	// if the line itself is the only completion.
	// 如果该行本身是唯一的补全项，则附加左括号（对于函数）或点（对于对象）。
	if len(results) == 1 && results[0] == line {
		// Accessing the property will cause it to be evaluated.
		// This can cause an error, e.g. in case of web3.eth.protocolVersion
		// which has been dropped from geth. Ignore the error for autocompletion
		// purposes.
		// 访问该属性将导致其被求值。这可能会导致错误，例如 web3.eth.protocolVersion
		// 已从 geth 中删除的情况。为了自动完成的目的，忽略该错误。
		obj := SafeGet(obj, parts[len(parts)-1]) // Safely get the object to avoid panics during evaluation. 安全地获取对象以避免在求值期间发生 panic。
		if obj != nil {
			if _, isfunc := goja.AssertFunction(obj); isfunc { // Check if the object is a function. 检查对象是否为函数。
				results[0] += "(" // Append an opening parenthesis for function call completion. 为函数调用补全附加一个左括号。
			} else {
				results[0] += "." // Append a dot for object property access completion. 为对象属性访问补全附加一个点。
			}
		}
	}

	sort.Strings(results) // Sort the results alphabetically. 按字母顺序对结果进行排序。
	return results
}
