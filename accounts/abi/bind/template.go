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

package bind

import (
	_ "embed"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// tmplData is the data structure required to fill the binding template.
// tmplData 是填充绑定模板所需的数据结构。
type tmplData struct {
	Package string // Name of the package to place the generated file in
	// Package：生成的文件将放置在的包名
	Contracts map[string]*tmplContract // List of contracts to generate into this file
	// Contracts：要生成到此文件中的合约列表，键是合约名称，值是指向 tmplContract 的指针
	Libraries map[string]string // Map the bytecode's link pattern to the library name
	// Libraries：将字节码的链接模式映射到库名称，键是链接模式，值是库名称
	Structs map[string]*tmplStruct // Contract struct type definitions
	// Structs：合约结构体类型定义，键是结构体名称，值是指向 tmplStruct 的指针
}

// tmplContract contains the data needed to generate an individual contract binding.
// tmplContract 包含生成单个合约绑定所需的数据。
type tmplContract struct {
	Type string // Type name of the main contract binding
	// Type：主合约绑定的类型名称
	InputABI string // JSON ABI used as the input to generate the binding from
	// InputABI：用作生成绑定的输入的 JSON ABI
	InputBin string // Optional EVM bytecode used to generate deploy code from
	// InputBin：可选的 EVM 字节码，用于生成部署代码
	FuncSigs map[string]string // Optional map: string signature -> 4-byte signature
	// FuncSigs：可选的映射：字符串签名 -> 4 字节签名，用于快速查找函数签名对应的选择器
	Constructor abi.Method // Contract constructor for deploy parametrization
	// Constructor：合约构造函数，用于部署参数化
	Calls map[string]*tmplMethod // Contract calls that only read state data
	// Calls：合约调用，仅读取状态数据，键是方法名称，值是指向 tmplMethod 的指针
	Transacts map[string]*tmplMethod // Contract calls that write state data
	// Transacts：合约调用，写入状态数据，键是方法名称，值是指向 tmplMethod 的指针
	Fallback *tmplMethod // Additional special fallback function
	// Fallback：额外的特殊回退函数
	Receive *tmplMethod // Additional special receive function
	// Receive：额外的特殊接收函数（用于接收以太币）
	Events map[string]*tmplEvent // Contract events accessors
	// Events：合约事件访问器，键是事件名称，值是指向 tmplEvent 的指针
	Libraries map[string]string // Same as tmplData, but filtered to only keep what the contract needs
	// Libraries：与 tmplData 相同，但仅保留合约所需的部分
	Library bool // Indicator whether the contract is a library
	// Library：指示合约是否为库
}

// tmplMethod is a wrapper around an abi.Method that contains a few preprocessed
// and cached data fields.
// tmplMethod 是 abi.Method 的包装器，包含一些预处理和缓存的数据字段。
type tmplMethod struct {
	Original abi.Method // Original method as parsed by the abi package
	// Original：abi 包解析的原始方法
	Normalized abi.Method // Normalized version of the parsed method (capitalized names, non-anonymous args/returns)
	// Normalized：解析方法的规范化版本（名称首字母大写，非匿名参数/返回值）
	Structured bool // Whether the returns should be accumulated into a struct
	// Structured：指示返回值是否应该累积到一个结构体中
}

// tmplEvent is a wrapper around an abi.Event that contains a few preprocessed
// and cached data fields.
// tmplEvent 是 abi.Event 的包装器，包含一些预处理和缓存的数据字段。
type tmplEvent struct {
	Original abi.Event // Original event as parsed by the abi package
	// Original：abi 包解析的原始事件
	Normalized abi.Event // Normalized version of the parsed fields
	// Normalized：解析字段的规范化版本
}

// tmplField is a wrapper around a struct field with binding language
// struct type definition and relative filed name.
// tmplField 是结构体字段的包装器，包含绑定语言的结构体类型定义和相对字段名称。
type tmplField struct {
	Type string // Field type representation depends on target binding language
	// Type：字段类型表示，取决于目标绑定语言
	Name string // Field name converted from the raw user-defined field name
	// Name：从原始用户定义的字段名称转换而来的字段名称
	SolKind abi.Type // Raw abi type information
	// SolKind：原始 ABI 类型信息
}

// tmplStruct is a wrapper around an abi.tuple and contains an auto-generated
// struct name.
// tmplStruct 是 abi.tuple 的包装器，包含一个自动生成的结构体名称。
type tmplStruct struct {
	Name string // Auto-generated struct name(before solidity v0.5.11) or raw name.
	// Name：自动生成的结构体名称（Solidity v0.5.11 之前）或原始名称
	Fields []*tmplField // Struct fields definition depends on the binding language.
	// Fields：结构体字段定义，取决于绑定语言
}

// tmplSource is language to template mapping containing all the supported
// programming languages the package can generate to.
// tmplSource 是语言到模板的映射，包含该包可以生成的所有受支持的编程语言。
var tmplSource = map[Lang]string{
	LangGo: tmplSourceGo,
}

// tmplSourceGo is the Go source template that the generated Go contract binding
// is based on.
// tmplSourceGo 是生成的 Go 合约绑定所基于的 Go 源代码模板。
//
//go:embed source.go.tpl
var tmplSourceGo string
