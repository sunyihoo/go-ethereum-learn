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

// Package compiler wraps the Solidity and Vyper compiler executables (solc; vyper).
// 它的主要目的是封装 Solidity 和 Vyper 编译器的可执行文件（solc 和 vyper），为上层应用程序提供统一的接口来调用这些编译器。
package compiler

//核心功能
//  封装编译器可执行文件：
//    将 solc（Solidity 编译器）和 vyper（Vyper 编译器）的可执行文件封装到包中。
//    隐藏底层编译器的具体实现细节，提供简单的 API 供调用。
//  统一接口：
//    为 Solidity 和 Vyper 编译器提供一致的调用方式，简化在应用程序中使用不同编译器的复杂性。
//  跨平台支持：
//    通过封装可执行文件，确保在不同操作系统（如 Linux、macOS、Windows）上都能正常工作。

// Contract contains information about a compiled contract, alongside its code and runtime code.
type Contract struct {
	Code        string            `json:"code"`
	RuntimeCode string            `json:"runtime-code"`
	Info        ContractInfo      `json:"info"`
	Hashes      map[string]string `json:"hashes"`
}

// ContractInfo contains information about a compiled contract, including access
// to the ABI definition, source mapping, user and developer docs, and metadata.
//
// Depending on the source, language version, compiler version, and compiler
// options will provide information about how the contract was compiled.
// 用于存储与编译后的合约相关的信息。这些信息包括合约的 ABI 定义、源代码映射、用户文档、开发者文档以及元数据。
type ContractInfo struct {
	Source          string      `json:"source"`
	Language        string      `json:"language"`
	LanguageVersion string      `json:"languageVersion"`
	CompilerVersion string      `json:"compilerVersion"`
	CompilerOptions string      `json:"compilerOptions"`
	SrcMap          interface{} `json:"srcMap"`
	SrcMapRuntime   string      `json:"srcMapRuntime"`
	AbiDefinition   interface{} `json:"abiDefinition"`
	UserDoc         interface{} `json:"userDoc"`
	DeveloperDoc    interface{} `json:"developerDoc"`
	Metadata        string      `json:"metadata"`
}
