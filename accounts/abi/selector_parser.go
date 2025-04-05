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

import (
	"errors"
	"fmt"
)

// SelectorMarshaling is a struct that represents the JSON-serializable form of a method selector.
// It includes the method name, type, and input arguments.
// SelectorMarshaling 是一个结构体，表示方法选择器的可 JSON 序列化形式。
// 它包括方法名称、类型和输入参数。
type SelectorMarshaling struct {
	Name   string               `json:"name"`   // 方法名称
	Type   string               `json:"type"`   // 方法类型（如 "function"）
	Inputs []ArgumentMarshaling `json:"inputs"` // 输入参数列表
}

// isDigit checks if the given byte is a digit (0-9).
// isDigit 检查给定字节是否为数字字符（0-9）。
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// isAlpha checks if the given byte is an alphabet character (a-z or A-Z).
// isAlpha 检查给定字节是否为字母字符（a-z 或 A-Z）。
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isIdentifierSymbol checks if the given byte is a valid identifier symbol ($ or _).
// isIdentifierSymbol 检查给定字节是否为有效的标识符符号（$ 或 _）。
func isIdentifierSymbol(c byte) bool {
	return c == '$' || c == '_'
}

// parseToken parses a token from the unescapedSelector string based on whether it's an identifier.
// parseToken 从 unescapedSelector 字符串中解析一个标记，基于它是否是标识符。
func parseToken(unescapedSelector string, isIdent bool) (string, string, error) {
	if len(unescapedSelector) == 0 {
		return "", "", errors.New("empty token")
	}
	firstChar := unescapedSelector[0]
	position := 1
	// 检查第一个字符是否有效
	if !(isAlpha(firstChar) || (isIdent && isIdentifierSymbol(firstChar))) {
		return "", "", fmt.Errorf("invalid token start: %c", firstChar)
	}
	// 继续解析有效字符
	for position < len(unescapedSelector) {
		char := unescapedSelector[position]
		if !(isAlpha(char) || isDigit(char) || (isIdent && isIdentifierSymbol(char))) {
			break
		}
		position++
	}
	return unescapedSelector[:position], unescapedSelector[position:], nil
}

// parseIdentifier parses an identifier from the unescapedSelector string.
// parseIdentifier 从 unescapedSelector 字符串中解析一个标识符。
func parseIdentifier(unescapedSelector string) (string, string, error) {
	return parseToken(unescapedSelector, true)
}

// parseElementaryType parses an elementary type (e.g., uint256, address) from the unescapedSelector string.
// parseElementaryType 从 unescapedSelector 字符串中解析一个基本类型（例如 uint256、address）。
func parseElementaryType(unescapedSelector string) (string, string, error) {
	parsedType, rest, err := parseToken(unescapedSelector, false)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse elementary type: %v", err)
	}
	// handle arrays 处理数组类型
	for len(rest) > 0 && rest[0] == '[' {
		parsedType = parsedType + string(rest[0])
		rest = rest[1:]
		for len(rest) > 0 && isDigit(rest[0]) {
			parsedType = parsedType + string(rest[0])
			rest = rest[1:]
		}
		if len(rest) == 0 || rest[0] != ']' {
			return "", "", fmt.Errorf("failed to parse array: expected ']', got %c", unescapedSelector[0])
		}
		parsedType = parsedType + string(rest[0])
		rest = rest[1:]
	}
	return parsedType, rest, nil
}

// parseCompositeType parses a composite type (e.g., tuple, nested types) from the unescapedSelector string.
// parseCompositeType 从 unescapedSelector 字符串中解析一个复合类型（例如 tuple、嵌套类型）。
func parseCompositeType(unescapedSelector string) ([]interface{}, string, error) {
	if len(unescapedSelector) == 0 || unescapedSelector[0] != '(' {
		return nil, "", fmt.Errorf("expected '(', got %c", unescapedSelector[0])
	}
	parsedType, rest, err := parseType(unescapedSelector[1:])
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse type: %v", err)
	}
	result := []interface{}{parsedType}
	// 解析多个类型
	for len(rest) > 0 && rest[0] != ')' {
		parsedType, rest, err = parseType(rest[1:])
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse type: %v", err)
		}
		result = append(result, parsedType)
	}
	if len(rest) == 0 || rest[0] != ')' {
		return nil, "", fmt.Errorf("expected ')', got '%s'", rest)
	}
	// 处理动态数组
	if len(rest) >= 3 && rest[1] == '[' && rest[2] == ']' {
		return append(result, "[]"), rest[3:], nil
	}
	return result, rest[1:], nil
}

// parseType determines whether the type is elementary or composite and delegates parsing accordingly.
// parseType 判断类型是基本类型还是复合类型，并相应地委派解析。
func parseType(unescapedSelector string) (interface{}, string, error) {
	if len(unescapedSelector) == 0 {
		return nil, "", errors.New("empty type")
	}
	if unescapedSelector[0] == '(' {
		return parseCompositeType(unescapedSelector)
	} else {
		return parseElementaryType(unescapedSelector)
	}
}

// assembleArgs assembles the parsed arguments into a structured format for JSON serialization.
// assembleArgs 将解析的参数组装成用于 JSON 序列化的结构化格式。
func assembleArgs(args []interface{}) ([]ArgumentMarshaling, error) {
	arguments := make([]ArgumentMarshaling, 0)
	for i, arg := range args {
		// generate dummy name to avoid unmarshal issues 生成虚拟名称以避免反序列化问题
		name := fmt.Sprintf("name%d", i)
		if s, ok := arg.(string); ok {
			arguments = append(arguments, ArgumentMarshaling{name, s, s, nil, false})
		} else if components, ok := arg.([]interface{}); ok {
			subArgs, err := assembleArgs(components)
			if err != nil {
				return nil, fmt.Errorf("failed to assemble components: %v", err)
			}
			tupleType := "tuple"
			if len(subArgs) != 0 && subArgs[len(subArgs)-1].Type == "[]" {
				subArgs = subArgs[:len(subArgs)-1]
				tupleType = "tuple[]"
			}
			arguments = append(arguments, ArgumentMarshaling{name, tupleType, tupleType, subArgs, false})
		} else {
			return nil, fmt.Errorf("failed to assemble args: unexpected type %T", arg)
		}
	}
	return arguments, nil
}

// ParseSelector converts a method selector into a struct that can be JSON encoded
// and consumed by other functions in this package.
// Note, although uppercase letters are not part of the ABI spec, this function
// still accepts it as the general format is valid.
// ParseSelector 将方法选择器转换为可以 JSON 编码的结构体，
// 并供此包中的其他函数使用。
// 注意：尽管大写字母不是 ABI 规范的一部分，但此函数仍然接受它们，因为通用格式是有效的。
func ParseSelector(unescapedSelector string) (SelectorMarshaling, error) {
	name, rest, err := parseIdentifier(unescapedSelector)
	if err != nil {
		return SelectorMarshaling{}, fmt.Errorf("failed to parse selector '%s': %v", unescapedSelector, err)
	}
	args := []interface{}{}
	// 检查是否有空参数列表
	if len(rest) >= 2 && rest[0] == '(' && rest[1] == ')' {
		rest = rest[2:]
	} else {
		args, rest, err = parseCompositeType(rest)
		if err != nil {
			return SelectorMarshaling{}, fmt.Errorf("failed to parse selector '%s': %v", unescapedSelector, err)
		}
	}
	// 确保解析完毕后没有剩余字符串
	if len(rest) > 0 {
		return SelectorMarshaling{}, fmt.Errorf("failed to parse selector '%s': unexpected string '%s'", unescapedSelector, rest)
	}

	// Reassemble the fake ABI and construct the JSON 重新组装假的 ABI 并构造 JSON
	fakeArgs, err := assembleArgs(args)
	if err != nil {
		return SelectorMarshaling{}, fmt.Errorf("failed to parse selector: %v", err)
	}

	return SelectorMarshaling{name, "function", fakeArgs}, nil
}
