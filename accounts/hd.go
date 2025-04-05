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
	"math"
	"math/big"
	"strings"
)

// 分层确定性钱包 ：
// 分层确定性钱包（HD Wallet）通过种子生成多个私钥，避免了单点故障的风险。
// 派生路径标准化 ：
// BIP-32 和 BIP-44 提供了标准化的派生路径格式，提升了钱包的兼容性和安全性。
// Ledger 特定需求 ：
// Ledger Live 使用不同的派生策略（递增第三个组件），需要特殊的迭代器支持。

// DefaultRootDerivationPath is the root path to which custom derivation endpoints
// are appended. As such, the first account will be at m/44'/60'/0'/0, the second
// at m/44'/60'/0'/1, etc.
// DefaultRootDerivationPath 是自定义派生路径附加到的根路径。
// 因此，第一个账户将位于 m/44'/60'/0'/0，第二个账户位于 m/44'/60'/0'/1，依此类推。
var DefaultRootDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}

// DefaultBaseDerivationPath is the base path from which custom derivation endpoints
// are incremented. As such, the first account will be at m/44'/60'/0'/0/0, the second
// at m/44'/60'/0'/0/1, etc.
// DefaultBaseDerivationPath 是自定义派生路径递增的基础路径。
// 因此，第一个账户将位于 m/44'/60'/0'/0/0，第二个账户位于 m/44'/60'/0'/0/1，依此类推。
var DefaultBaseDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0, 0}

// LegacyLedgerBaseDerivationPath is the legacy base path from which custom derivation
// endpoints are incremented. As such, the first account will be at m/44'/60'/0'/0, the
// second at m/44'/60'/0'/1, etc.
// LegacyLedgerBaseDerivationPath 是旧版 Ledger 的基础路径，用于递增自定义派生路径。
// 因此，第一个账户将位于 m/44'/60'/0'/0，第二个账户位于 m/44'/60'/0'/1，依此类推。
var LegacyLedgerBaseDerivationPath = DerivationPath{0x80000000 + 44, 0x80000000 + 60, 0x80000000 + 0, 0}

// DerivationPath represents the computer friendly version of a hierarchical
// deterministic wallet account derivation path.
//
// The BIP-32 spec https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// defines derivation paths to be of the form:
//
//	m / purpose' / coin_type' / account' / change / address_index
//
// The BIP-44 spec https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
// defines that the `purpose` be 44' (or 0x8000002C) for crypto currencies, and
// SLIP-44 https://github.com/satoshilabs/slips/blob/master/slip-0044.md assigns
// the `coin_type` 60' (or 0x8000003C) to Ethereum.
//
// The root path for Ethereum is m/44'/60'/0'/0 according to the specification
// from https://github.com/ethereum/EIPs/issues/84, albeit it's not set in stone
// yet whether accounts should increment the last component or the children of
// that. We will go with the simpler approach of incrementing the last component.
// DerivationPath 表示分层确定性钱包账户派生路径的计算机友好版本。
//
// BIP-32 规范（https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki）定义了派生路径的形式：
//
//	m / purpose' / coin_type' / account' / change / address_index
//
// BIP-44 规范（https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki）规定加密货币的 `purpose` 为 44'（或 0x8000002C），
// SLIP-44（https://github.com/satoshilabs/slips/blob/master/slip-0044.md）将 `coin_type` 60'（或 0x8000003C）分配给以太坊。
//
// 根据 https://github.com/ethereum/EIPs/issues/84 的规范，以太坊的根路径为 m/44'/60'/0'/0。
// 虽然尚未确定是否应递增最后一个组件或其子组件，但我们将采用更简单的递增最后一个组件的方法。
type DerivationPath []uint32

// ParseDerivationPath converts a user specified derivation path string to the
// internal binary representation.
//
// Full derivation paths need to start with the `m/` prefix, relative derivation
// paths (which will get appended to the default root path) must not have prefixes
// in front of the first element. Whitespace is ignored.
// ParseDerivationPath 将用户指定的派生路径字符串转换为内部二进制表示形式。
//
// 完整的派生路径需要以 `m/` 前缀开头，相对派生路径（将附加到默认根路径）不得在第一个元素前有前缀。空格将被忽略。
func ParseDerivationPath(path string) (DerivationPath, error) {
	var result DerivationPath

	// Handle absolute or relative paths
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return nil, errors.New("empty derivation path")

	case strings.TrimSpace(components[0]) == "":
		return nil, errors.New("ambiguous path: use 'm/' prefix for absolute paths, or no leading '/' for relative ones")

	case strings.TrimSpace(components[0]) == "m":
		components = components[1:]

	default:
		result = append(result, DefaultRootDerivationPath...)
	}
	// All remaining components are relative, append one by one
	if len(components) == 0 {
		return nil, errors.New("empty derivation path") // Empty relative paths
	}
	for _, component := range components {
		// Ignore any user added whitespace
		component = strings.TrimSpace(component)
		var value uint32

		// Handle hardened paths
		if strings.HasSuffix(component, "'") {
			value = 0x80000000
			component = strings.TrimSpace(strings.TrimSuffix(component, "'"))
		}
		// Handle the non hardened component
		bigval, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32 - value
		if bigval.Sign() < 0 || bigval.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("component %v out of allowed range [0, %d]", bigval, max)
			}
			return nil, fmt.Errorf("component %v out of allowed hardened range [0, %d]", bigval, max)
		}
		value += uint32(bigval.Uint64())

		// Append and repeat
		result = append(result, value)
	}
	return result, nil
}

// String implements the stringer interface, converting a binary derivation path
// to its canonical representation.
// String 实现了 stringer 接口，将二进制派生路径转换为其规范表示形式。
func (path DerivationPath) String() string {
	result := "m"
	for _, component := range path {
		var hardened bool
		if component >= 0x80000000 {
			component -= 0x80000000
			hardened = true
		}
		result = fmt.Sprintf("%s/%d", result, component)
		if hardened {
			result += "'"
		}
	}
	return result
}

// MarshalJSON turns a derivation path into its json-serialized string
// MarshalJSON 将派生路径转换为 JSON 序列化的字符串。
func (path DerivationPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(path.String())
}

// UnmarshalJSON a json-serialized string back into a derivation path
// UnmarshalJSON 将 JSON 序列化的字符串反序列化为派生路径。
func (path *DerivationPath) UnmarshalJSON(b []byte) error {
	var dp string
	var err error
	if err = json.Unmarshal(b, &dp); err != nil {
		return err
	}
	*path, err = ParseDerivationPath(dp)
	return err
}

// DefaultIterator creates a BIP-32 path iterator, which progresses by increasing the last component:
// i.e. m/44'/60'/0'/0/0, m/44'/60'/0'/0/1, m/44'/60'/0'/0/2, ... m/44'/60'/0'/0/N.
// DefaultIterator 创建一个 BIP-32 路径迭代器，通过递增最后一个组件来推进：
// 即 m/44'/60'/0'/0/0, m/44'/60'/0'/0/1, m/44'/60'/0'/0/2, ... m/44'/60'/0'/0/N。
func DefaultIterator(base DerivationPath) func() DerivationPath {
	path := make(DerivationPath, len(base))
	copy(path[:], base[:])
	// Set it back by one, so the first call gives the first result
	path[len(path)-1]--
	return func() DerivationPath {
		path[len(path)-1]++
		return path
	}
}

// LedgerLiveIterator creates a bip44 path iterator for Ledger Live.
// Ledger Live increments the third component rather than the fifth component
// i.e. m/44'/60'/0'/0/0, m/44'/60'/1'/0/0, m/44'/60'/2'/0/0, ... m/44'/60'/N'/0/0.
// LedgerLiveIterator 为 Ledger Live 创建一个 BIP-44 路径迭代器。
// Ledger Live 递增第三个组件而不是第五个组件：
// 即 m/44'/60'/0'/0/0, m/44'/60'/1'/0/0, m/44'/60'/2'/0/0, ... m/44'/60'/N'/0/0。
func LedgerLiveIterator(base DerivationPath) func() DerivationPath {
	path := make(DerivationPath, len(base))
	copy(path[:], base[:])
	// Set it back by one, so the first call gives the first result
	path[2]--
	return func() DerivationPath {
		// ledgerLivePathIterator iterates on the third component
		path[2]++
		return path
	}
}
