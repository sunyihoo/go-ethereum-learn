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

// Package bind generates Ethereum contract Go bindings.
//
// Detailed usage document and tutorial available on the go-ethereum Wiki page:
// https://github.com/ethereum/go-ethereum/wiki/Native-DApps:-Go-bindings-to-Ethereum-contracts
package bind

import (
	"bytes"
	"fmt"
	"go/format"
	"regexp"
	"strings"
	"text/template"
	"unicode"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/log"
)

// Lang is a target programming language selector to generate bindings for.
// Lang 是用于生成绑定的目标编程语言选择器。
type Lang int

const (
	LangGo Lang = iota // Go 语言
)

func isKeyWord(arg string) bool {
	switch arg {
	case "break":
	case "case":
	case "chan":
	case "const":
	case "continue":
	case "default":
	case "defer":
	case "else":
	case "fallthrough":
	case "for":
	case "func":
	case "go":
	case "goto":
	case "if":
	case "import":
	case "interface":
	case "iota":
	case "map":
	case "make":
	case "new":
	case "package":
	case "range":
	case "return":
	case "select":
	case "struct":
	case "switch":
	case "type":
	case "var":
	default:
		return false
	}
	return true
}

// Bind generates a Go wrapper around a contract ABI. This wrapper isn't meant
// to be used as is in client code, but rather as an intermediate struct which
// enforces compile time type safety and naming convention as opposed to having to
// manually maintain hard coded strings that break on runtime.
// Bind 围绕合同 ABI 生成 Go 包装器。此包装器并非旨在客户端代码中直接使用，
// 而是作为一个中间结构，强制执行编译时类型安全和命名约定，而不是手动维护运行时会中断的硬编码字符串。
func Bind(types []string, abis []string, bytecodes []string, fsigs []map[string]string, pkg string, lang Lang, libs map[string]string, aliases map[string]string) (string, error) {
	var (
		// contracts is the map of each individual contract requested binding
		// contracts 是每个单独请求绑定的合同映射
		contracts = make(map[string]*tmplContract)

		// structs is the map of all redeclared structs shared by passed contracts.
		// structs 是所有由传入合同共享的重新声明的结构体的映射。
		structs = make(map[string]*tmplStruct)

		// isLib is the map used to flag each encountered library as such
		// isLib 是用于标记每个遇到的库的映射
		isLib = make(map[string]struct{})
	)
	for i := 0; i < len(types); i++ {
		// Parse the actual ABI to generate the binding for
		// 解析实际的 ABI 以生成绑定
		evmABI, err := abi.JSON(strings.NewReader(abis[i]))
		if err != nil {
			return "", err
		}
		// Strip any whitespace from the JSON ABI
		// 从 JSON ABI 中去除任何空白
		strippedABI := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, abis[i])

		// Extract the call and transact methods; events, struct definitions; and sort them alphabetically
		// 提取调用和交易方法；事件、结构定义；并按字母顺序排序
		var (
			calls     = make(map[string]*tmplMethod)
			transacts = make(map[string]*tmplMethod)
			events    = make(map[string]*tmplEvent)
			fallback  *tmplMethod
			receive   *tmplMethod

			// identifiers are used to detect duplicated identifiers of functions
			// and events. For all calls, transacts and events, abigen will generate
			// corresponding bindings. However we have to ensure there is no
			// identifier collisions in the bindings of these categories.
			// identifiers 用于检测函数和事件的重复标识符。对于所有调用、交易和事件，
			// abigen 将生成相应的绑定。然而，我们必须确保这些类别的绑定中没有标识符冲突。
			callIdentifiers     = make(map[string]bool)
			transactIdentifiers = make(map[string]bool)
			eventIdentifiers    = make(map[string]bool)
		)

		for _, input := range evmABI.Constructor.Inputs {
			if hasStruct(input.Type) {
				bindStructType[lang](input.Type, structs)
			}
		}

		for _, original := range evmABI.Methods {
			// Normalize the method for capital cases and non-anonymous inputs/outputs
			// 规范化方法以处理大写情况和非匿名输入/输出
			normalized := original
			normalizedName := methodNormalizer[lang](alias(aliases, original.Name))
			// Ensure there is no duplicated identifier
			// 确保没有重复的标识符
			var identifiers = callIdentifiers
			if !original.IsConstant() {
				identifiers = transactIdentifiers
			}
			// Name shouldn't start with a digit. It will make the generated code invalid.
			// 名称不应以数字开头。这会使生成的代码无效。
			if len(normalizedName) > 0 && unicode.IsDigit(rune(normalizedName[0])) {
				normalizedName = fmt.Sprintf("M%s", normalizedName)
				normalizedName = abi.ResolveNameConflict(normalizedName, func(name string) bool {
					_, ok := identifiers[name]
					return ok
				})
			}
			if identifiers[normalizedName] {
				return "", fmt.Errorf("duplicated identifier \"%s\"(normalized \"%s\"), use --alias for renaming", original.Name, normalizedName)
			}
			identifiers[normalizedName] = true

			normalized.Name = normalizedName
			normalized.Inputs = make([]abi.Argument, len(original.Inputs))
			copy(normalized.Inputs, original.Inputs)
			for j, input := range normalized.Inputs {
				if input.Name == "" || isKeyWord(input.Name) {
					normalized.Inputs[j].Name = fmt.Sprintf("arg%d", j)
				}
				if hasStruct(input.Type) {
					bindStructType[lang](input.Type, structs)
				}
			}
			normalized.Outputs = make([]abi.Argument, len(original.Outputs))
			copy(normalized.Outputs, original.Outputs)
			for j, output := range normalized.Outputs {
				if output.Name != "" {
					normalized.Outputs[j].Name = capitalise(output.Name)
				}
				if hasStruct(output.Type) {
					bindStructType[lang](output.Type, structs)
				}
			}
			// Append the methods to the call or transact lists
			// 将方法追加到调用或交易列表
			if original.IsConstant() {
				calls[original.Name] = &tmplMethod{Original: original, Normalized: normalized, Structured: structured(original.Outputs)}
			} else {
				transacts[original.Name] = &tmplMethod{Original: original, Normalized: normalized, Structured: structured(original.Outputs)}
			}
		}
		for _, original := range evmABI.Events {
			// Skip anonymous events as they don't support explicit filtering
			// 跳过匿名事件，因为它们不支持显式过滤
			if original.Anonymous {
				continue
			}
			// Normalize the event for capital cases and non-anonymous outputs
			// 规范化事件以处理大写情况和非匿名输出
			normalized := original

			// Ensure there is no duplicated identifier
			// 确保没有重复的标识符
			normalizedName := methodNormalizer[lang](alias(aliases, original.Name))
			// Name shouldn't start with a digit. It will make the generated code invalid.
			// 名称不应以数字开头。这会使生成的代码无效。
			if len(normalizedName) > 0 && unicode.IsDigit(rune(normalizedName[0])) {
				normalizedName = fmt.Sprintf("E%s", normalizedName)
				normalizedName = abi.ResolveNameConflict(normalizedName, func(name string) bool {
					_, ok := eventIdentifiers[name]
					return ok
				})
			}
			if eventIdentifiers[normalizedName] {
				return "", fmt.Errorf("duplicated identifier \"%s\"(normalized \"%s\"), use --alias for renaming", original.Name, normalizedName)
			}
			eventIdentifiers[normalizedName] = true
			normalized.Name = normalizedName

			used := make(map[string]bool)
			normalized.Inputs = make([]abi.Argument, len(original.Inputs))
			copy(normalized.Inputs, original.Inputs)
			for j, input := range normalized.Inputs {
				if input.Name == "" || isKeyWord(input.Name) {
					normalized.Inputs[j].Name = fmt.Sprintf("arg%d", j)
				}
				// Event is a bit special, we need to define event struct in binding,
				// ensure there is no camel-case-style name conflict.
				// 事件有些特殊，我们需要在绑定中定义事件结构，确保没有驼峰式名称冲突。
				for index := 0; ; index++ {
					if !used[capitalise(normalized.Inputs[j].Name)] {
						used[capitalise(normalized.Inputs[j].Name)] = true
						break
					}
					normalized.Inputs[j].Name = fmt.Sprintf("%s%d", normalized.Inputs[j].Name, index)
				}
				if hasStruct(input.Type) {
					bindStructType[lang](input.Type, structs)
				}
			}
			// Append the event to the accumulator list
			// 将事件追加到累加器列表
			events[original.Name] = &tmplEvent{Original: original, Normalized: normalized}
		}
		// Add two special fallback functions if they exist
		// 如果存在，则添加两个特殊的回退函数
		if evmABI.HasFallback() {
			fallback = &tmplMethod{Original: evmABI.Fallback}
		}
		if evmABI.HasReceive() {
			receive = &tmplMethod{Original: evmABI.Receive}
		}
		contracts[types[i]] = &tmplContract{
			Type:        capitalise(types[i]),
			InputABI:    strings.ReplaceAll(strippedABI, "\"", "\\\""),
			InputBin:    strings.TrimPrefix(strings.TrimSpace(bytecodes[i]), "0x"),
			Constructor: evmABI.Constructor,
			Calls:       calls,
			Transacts:   transacts,
			Fallback:    fallback,
			Receive:     receive,
			Events:      events,
			Libraries:   make(map[string]string),
		}
		// Function 4-byte signatures are stored in the same sequence
		// as types, if available.
		// 函数的 4 字节签名按类型顺序存储（如果可用）。
		if len(fsigs) > i {
			contracts[types[i]].FuncSigs = fsigs[i]
		}
		// Parse library references.
		// 解析库引用。
		for pattern, name := range libs {
			matched, err := regexp.MatchString("__\\$"+pattern+"\\$__", contracts[types[i]].InputBin)
			if err != nil {
				log.Error("Could not search for pattern", "pattern", pattern, "contract", contracts[types[i]], "err", err)
				// 无法搜索模式
			}
			if matched {
				contracts[types[i]].Libraries[pattern] = name
				// keep track that this type is a library
				// 跟踪此类型是库
				if _, ok := isLib[name]; !ok {
					isLib[name] = struct{}{}
				}
			}
		}
	}
	// Check if that type has already been identified as a library
	// 检查该类型是否已被识别为库
	for i := 0; i < len(types); i++ {
		_, ok := isLib[types[i]]
		contracts[types[i]].Library = ok
	}
	// Generate the contract template data content and render it
	// 生成合同模板数据内容并渲染
	data := &tmplData{
		Package:   pkg,
		Contracts: contracts,
		Libraries: libs,
		Structs:   structs,
	}
	buffer := new(bytes.Buffer)

	funcs := map[string]interface{}{
		"bindtype":      bindType[lang],
		"bindtopictype": bindTopicType[lang],
		"namedtype":     namedType[lang],
		"capitalise":    capitalise,
		"decapitalise":  decapitalise,
	}
	tmpl := template.Must(template.New("").Funcs(funcs).Parse(tmplSource[lang]))
	if err := tmpl.Execute(buffer, data); err != nil {
		return "", err
	}
	// For Go bindings pass the code through gofmt to clean it up
	// 对于 Go 绑定，通过 gofmt 处理代码以清理
	if lang == LangGo {
		code, err := format.Source(buffer.Bytes())
		if err != nil {
			return "", fmt.Errorf("%v\n%s", err, buffer)
		}
		return string(code), nil
	}
	// For all others just return as is for now
	// 对于所有其他语言，暂时按原样返回
	return buffer.String(), nil
}

// bindType is a set of type binders that convert Solidity types to some supported
// programming language types.
// bindType 是一组类型绑定器，将 Solidity 类型转换为某些支持的编程语言类型。
var bindType = map[Lang]func(kind abi.Type, structs map[string]*tmplStruct) string{
	LangGo: bindTypeGo,
}

// bindBasicTypeGo converts basic solidity types(except array, slice and tuple) to Go ones.
// bindBasicTypeGo 将基本 Solidity 类型（除数组、切片和元组外）转换为 Go 类型。
func bindBasicTypeGo(kind abi.Type) string {
	switch kind.T {
	case abi.AddressTy:
		return "common.Address"
	case abi.IntTy, abi.UintTy:
		parts := regexp.MustCompile(`(u)?int([0-9]*)`).FindStringSubmatch(kind.String())
		switch parts[2] {
		case "8", "16", "32", "64":
			return fmt.Sprintf("%sint%s", parts[1], parts[2])
		}
		return "*big.Int"
	case abi.FixedBytesTy:
		return fmt.Sprintf("[%d]byte", kind.Size)
	case abi.BytesTy:
		return "[]byte"
	case abi.FunctionTy:
		return "[24]byte"
	default:
		// string, bool types
		// 字符串、布尔类型
		return kind.String()
	}
}

// bindTypeGo converts solidity types to Go ones. Since there is no clear mapping
// from all Solidity types to Go ones (e.g. uint17), those that cannot be exactly
// mapped will use an upscaled type (e.g. BigDecimal).
// bindTypeGo 将 Solidity 类型转换为 Go 类型。由于并非所有 Solidity 类型都能明确映射到 Go 类型（例如 uint17），
// 无法精确映射的类型将使用放大的类型（例如 BigDecimal）。
func bindTypeGo(kind abi.Type, structs map[string]*tmplStruct) string {
	switch kind.T {
	case abi.TupleTy:
		return structs[kind.TupleRawName+kind.String()].Name
	case abi.ArrayTy:
		return fmt.Sprintf("[%d]", kind.Size) + bindTypeGo(*kind.Elem, structs)
	case abi.SliceTy:
		return "[]" + bindTypeGo(*kind.Elem, structs)
	default:
		return bindBasicTypeGo(kind)
	}
}

// bindTopicType is a set of type binders that convert Solidity types to some
// supported programming language topic types.
// bindTopicType 是一组类型绑定器，将 Solidity 类型转换为某些支持的编程语言主题类型。
var bindTopicType = map[Lang]func(kind abi.Type, structs map[string]*tmplStruct) string{
	LangGo: bindTopicTypeGo,
}

// bindTopicTypeGo converts a Solidity topic type to a Go one. It is almost the same
// functionality as for simple types, but dynamic types get converted to hashes.
// bindTopicTypeGo 将 Solidity 主题类型转换为 Go 类型。其功能几乎与简单类型相同，
// 但动态类型会转换为哈希。
func bindTopicTypeGo(kind abi.Type, structs map[string]*tmplStruct) string {
	bound := bindTypeGo(kind, structs)

	// todo(rjl493456442) according solidity documentation, indexed event
	// parameters that are not value types i.e. arrays and structs are not
	// stored directly but instead a keccak256-hash of an encoding is stored.
	//
	// We only convert strings and bytes to hash, still need to deal with
	// array(both fixed-size and dynamic-size) and struct.
	// todo(rjl493456442) 根据 Solidity 文档，索引事件参数如果不是值类型（即数组和结构体），
	// 不会直接存储，而是存储编码的 keccak256 哈希。
	//
	// 我们仅将字符串和字节转换为哈希，仍然需要处理数组（固定大小和动态大小）和结构体。
	if bound == "string" || bound == "[]byte" {
		bound = "common.Hash"
	}
	return bound
}

// bindStructType is a set of type binders that convert Solidity tuple types to some supported
// programming language struct definition.
// bindStructType 是一组类型绑定器，将 Solidity 元组类型转换为某些支持的编程语言结构体定义。
var bindStructType = map[Lang]func(kind abi.Type, structs map[string]*tmplStruct) string{
	LangGo: bindStructTypeGo,
}

// bindStructTypeGo converts a Solidity tuple type to a Go one and records the mapping
// in the given map.
// Notably, this function will resolve and record nested struct recursively.
// bindStructTypeGo 将 Solidity 元组类型转换为 Go 类型，并在给定映射中记录映射。
// 值得注意的是，此函数将递归解析和记录嵌套结构体。
func bindStructTypeGo(kind abi.Type, structs map[string]*tmplStruct) string {
	switch kind.T {
	case abi.TupleTy:
		// We compose a raw struct name and a canonical parameter expression
		// together here. The reason is before solidity v0.5.11, kind.TupleRawName
		// is empty, so we use canonical parameter expression to distinguish
		// different struct definition. From the consideration of backward
		// compatibility, we concat these two together so that if kind.TupleRawName
		// is not empty, it can have unique id.
		// 我们在这里组合了一个原始结构体名称和一个规范参数表达式。
		// 原因是在 Solidity v0.5.11 之前，kind.TupleRawName 是空的，因此我们使用规范参数表达式来区分不同的结构体定义。
		// 考虑到向后兼容性，我们将这两者拼接在一起，以便如果 kind.TupleRawName 不为空，它可以具有唯一 ID。
		id := kind.TupleRawName + kind.String()
		if s, exist := structs[id]; exist {
			return s.Name
		}
		var (
			names  = make(map[string]bool)
			fields []*tmplField
		)
		for i, elem := range kind.TupleElems {
			name := capitalise(kind.TupleRawNames[i])
			name = abi.ResolveNameConflict(name, func(s string) bool { return names[s] })
			names[name] = true
			fields = append(fields, &tmplField{Type: bindStructTypeGo(*elem, structs), Name: name, SolKind: *elem})
		}
		name := kind.TupleRawName
		if name == "" {
			name = fmt.Sprintf("Struct%d", len(structs))
		}
		name = capitalise(name)

		structs[id] = &tmplStruct{
			Name:   name,
			Fields: fields,
		}
		return name
	case abi.ArrayTy:
		return fmt.Sprintf("[%d]", kind.Size) + bindStructTypeGo(*kind.Elem, structs)
	case abi.SliceTy:
		return "[]" + bindStructTypeGo(*kind.Elem, structs)
	default:
		return bindBasicTypeGo(kind)
	}
}

// namedType is a set of functions that transform language specific types to
// named versions that may be used inside method names.
// namedType 是一组函数，将特定语言类型转换为可在方法名称中使用的命名版本。
var namedType = map[Lang]func(string, abi.Type) string{
	LangGo: func(string, abi.Type) string { panic("this shouldn't be needed") },
}

// alias returns an alias of the given string based on the aliasing rules
// or returns itself if no rule is matched.
// alias 根据别名规则返回给定字符串的别名，如果没有匹配规则则返回自身。
func alias(aliases map[string]string, n string) string {
	if alias, exist := aliases[n]; exist {
		return alias
	}
	return n
}

// methodNormalizer is a name transformer that modifies Solidity method names to
// conform to target language naming conventions.
// methodNormalizer 是一个名称转换器，修改 Solidity 方法名称以符合目标语言命名约定。
var methodNormalizer = map[Lang]func(string) string{
	LangGo: abi.ToCamelCase,
}

// capitalise makes a camel-case string which starts with an upper case character.
// capitalise 生成一个以大写字符开头的驼峰式字符串。
var capitalise = abi.ToCamelCase

// decapitalise makes a camel-case string which starts with a lower case character.
// decapitalise 生成一个以小写字符开头的驼峰式字符串。
func decapitalise(input string) string {
	if len(input) == 0 {
		return input
	}

	goForm := abi.ToCamelCase(input)
	return strings.ToLower(goForm[:1]) + goForm[1:]
}

// structured checks whether a list of ABI data types has enough information to
// operate through a proper Go struct or if flat returns are needed.
// structured 检查 ABI 数据类型列表是否具有足够信息通过适当的 Go 结构体操作，或者是否需要平面返回。
func structured(args abi.Arguments) bool {
	if len(args) < 2 {
		return false
	}
	exists := make(map[string]bool)
	for _, out := range args {
		// If the name is anonymous, we can't organize into a struct
		// 如果名称是匿名的，我们无法组织成结构体
		if out.Name == "" {
			return false
		}
		// If the field name is empty when normalized or collides (var, Var, _var, _Var),
		// we can't organize into a struct
		// 如果规范化后的字段名称为空或发生冲突（var、Var、_var、_Var），我们无法组织成结构体
		field := capitalise(out.Name)
		if field == "" || exists[field] {
			return false
		}
		exists[field] = true
	}
	return true
}

// hasStruct returns an indicator whether the given type is struct, struct slice
// or struct array.
// hasStruct 返回一个指示器，指示给定类型是否是结构体、结构体切片或结构体数组。
func hasStruct(t abi.Type) bool {
	switch t.T {
	case abi.SliceTy:
		return hasStruct(*t.Elem)
	case abi.ArrayTy:
		return hasStruct(*t.Elem)
	case abi.TupleTy:
		return true
	default:
		return false
	}
}
