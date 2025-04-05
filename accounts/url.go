// Copyright 2017 The go-ethereum Authors
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

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// 账户标识 (Account Identification): 在以太坊生态系统中，需要一种标准化的方式来唯一标识不同的账户和管理它们的钱包。go-ethereum 的账户管理系统需要能够处理来自不同来源的账户，例如本地密钥库文件、硬件钱包等。
// URI/URL 约定 (URI/URL Conventions): 虽然以太坊并没有强制使用标准的 URL 格式来标识账户，但使用类似 URL 的结构可以提供一种清晰和可扩展的标识方式。go-ethereum 选择了自定义的 URL 结构，以便更好地控制其行为和特性。
// 可值复制 (Value-Copyable): 指一个对象在赋值或传递时，会创建一个新的独立的副本，而不是共享同一个底层数据。这对于账户信息非常重要，因为避免意外修改原始账户信息是至关重要的。
// URL 编码/解码 (URL Encoding/Decoding): 标准的 URL 规范定义了对特殊字符进行编码以确保 URL 在网络传输中的正确性。go-ethereum 的 URL 类型选择不进行编码/解码，可能是为了简化内部处理并确保 URL 的规范性。

// URL represents the canonical identification URL of a wallet or account.
// URL 代表钱包或账户的规范标识 URL。
//
// It is a simplified version of url.URL, with the important limitations (which
// are considered features here) that it contains value-copyable components only,
// as well as that it doesn't do any URL encoding/decoding of special characters.
// 它是 url.URL 的简化版本，具有重要的限制（在此被认为是特性）：它只包含可值复制的组件，
// 并且不对特殊字符进行任何 URL 编码/解码。
//
// The former is important to allow an account to be copied without leaving live
// references to the original version, whereas the latter is important to ensure
// one single canonical form opposed to many allowed ones by the RFC 3986 spec.
// 前者对于允许复制账户而不留下对原始版本的活动引用非常重要，而后者对于确保单一规范形式而不是 RFC 3986 规范允许的多种形式非常重要。
//
// As such, these URLs should not be used outside of the scope of an Ethereum
// wallet or account.
// 因此，这些 URL 不应在以太坊钱包或账户的范围之外使用。
type URL struct {
	Scheme string // Protocol scheme to identify a capable account backend
	// Scheme：协议方案，用于标识能够处理该账户的后端
	Path string // Path for the backend to identify a unique entity
	// Path：后端用于标识唯一实体的路径
}

// parseURL converts a user supplied URL into the accounts specific structure.
// parseURL 将用户提供的 URL 转换为账户特定的结构。
func parseURL(url string) (URL, error) {
	parts := strings.Split(url, "://")
	if len(parts) != 2 || parts[0] == "" {
		return URL{}, errors.New("protocol scheme missing")
	}
	return URL{
		Scheme: parts[0],
		Path:   parts[1],
	}, nil
}

// String implements the stringer interface.
// String 实现了 stringer 接口，用于返回 URL 的字符串表示。
func (u URL) String() string {
	if u.Scheme != "" {
		return fmt.Sprintf("%s://%s", u.Scheme, u.Path)
	}
	return u.Path
}

// TerminalString implements the log.TerminalStringer interface.
// TerminalString 实现了 log.TerminalStringer 接口，用于返回适合终端输出的 URL 字符串。
func (u URL) TerminalString() string {
	url := u.String()
	if len(url) > 32 {
		return url[:31] + ".."
	}
	return url
}

// MarshalJSON implements the json.Marshaller interface.
// MarshalJSON 实现了 json.Marshaller 接口，用于将 URL 序列化为 JSON。
func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON parses url.
// UnmarshalJSON 解析 URL，用于从 JSON 反序列化 URL。
func (u *URL) UnmarshalJSON(input []byte) error {
	var textURL string
	err := json.Unmarshal(input, &textURL)
	if err != nil {
		return err
	}
	url, err := parseURL(textURL)
	if err != nil {
		return err
	}
	u.Scheme = url.Scheme
	u.Path = url.Path
	return nil
}

// Cmp compares x and y and returns:
// Cmp 比较 x 和 y 并返回：
//
//	-1 if x <  y
//	 0 if x == y
//	+1 if x >  y
func (u URL) Cmp(url URL) int {
	if u.Scheme == url.Scheme {
		return strings.Compare(u.Path, url.Path)
	}
	return strings.Compare(u.Scheme, url.Scheme)
}
