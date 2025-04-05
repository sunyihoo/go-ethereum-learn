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

package abi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// MakeTopics converts a filter query argument list into a filter topic set.
// MakeTopics 将过滤器查询参数列表转换为过滤器主题集合。
func MakeTopics(query ...[]interface{}) ([][]common.Hash, error) {
	topics := make([][]common.Hash, len(query))
	for i, filter := range query {
		for _, rule := range filter {
			var topic common.Hash

			// Try to generate the topic based on simple types
			// 尝试根据简单类型生成主题
			switch rule := rule.(type) {
			case common.Hash:
				copy(topic[:], rule[:])
			case common.Address:
				copy(topic[common.HashLength-common.AddressLength:], rule[:])
			case *big.Int:
				copy(topic[:], math.U256Bytes(new(big.Int).Set(rule)))
			case bool:
				if rule {
					topic[common.HashLength-1] = 1
				}
			case int8:
				copy(topic[:], genIntType(int64(rule), 1))
			case int16:
				copy(topic[:], genIntType(int64(rule), 2))
			case int32:
				copy(topic[:], genIntType(int64(rule), 4))
			case int64:
				copy(topic[:], genIntType(rule, 8))
			case uint8:
				blob := new(big.Int).SetUint64(uint64(rule)).Bytes()
				copy(topic[common.HashLength-len(blob):], blob)
			case uint16:
				blob := new(big.Int).SetUint64(uint64(rule)).Bytes()
				copy(topic[common.HashLength-len(blob):], blob)
			case uint32:
				blob := new(big.Int).SetUint64(uint64(rule)).Bytes()
				copy(topic[common.HashLength-len(blob):], blob)
			case uint64:
				blob := new(big.Int).SetUint64(rule).Bytes()
				copy(topic[common.HashLength-len(blob):], blob)
			case string:
				hash := crypto.Keccak256Hash([]byte(rule))
				copy(topic[:], hash[:])
			case []byte:
				hash := crypto.Keccak256Hash(rule)
				copy(topic[:], hash[:])

			default:
				// todo(rjl493456442) according to solidity documentation, indexed event
				// parameters that are not value types i.e. arrays and structs are not
				// stored directly but instead a keccak256-hash of an encoding is stored.
				//
				// We only convert stringS and bytes to hash, still need to deal with
				// array(both fixed-size and dynamic-size) and struct.
				//
				// 根据 Solidity 文档，索引事件参数中非值类型（如数组和结构体）不会直接存储，
				// 而是存储其编码的 Keccak256 哈希值。
				//
				// 我们目前仅将字符串和字节数组转换为哈希，仍需处理固定大小和动态大小数组以及结构体。

				// Attempt to generate the topic from funky types
				// 尝试从复杂类型生成主题
				val := reflect.ValueOf(rule)
				switch {
				// static byte array
				// 静态字节数组
				case val.Kind() == reflect.Array && reflect.TypeOf(rule).Elem().Kind() == reflect.Uint8:
					reflect.Copy(reflect.ValueOf(topic[:val.Len()]), val)
				default:
					return nil, fmt.Errorf("unsupported indexed type: %T", rule)
				}
			}
			topics[i] = append(topics[i], topic)
		}
	}
	return topics, nil
}

// genIntType generates the canonical representation of an integer type with the given size.
// genIntType 生成给定大小的整数类型的规范表示形式。
func genIntType(rule int64, size uint) []byte {
	var topic [common.HashLength]byte
	if rule < 0 {
		// if a rule is negative, we need to put it into two's complement.
		// extended to common.HashLength bytes.
		// 如果规则为负数，需要将其转换为补码形式，并扩展到 common.HashLength 字节。
		topic = [common.HashLength]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	}
	for i := uint(0); i < size; i++ {
		topic[common.HashLength-i-1] = byte(rule >> (i * 8))
	}
	return topic[:]
}

// ParseTopics converts the indexed topic fields into actual log field values.
// ParseTopics 将索引主题字段转换为实际的日志字段值。
func ParseTopics(out interface{}, fields Arguments, topics []common.Hash) error {
	return parseTopicWithSetter(fields, topics,
		func(arg Argument, reconstr interface{}) {
			field := reflect.ValueOf(out).Elem().FieldByName(ToCamelCase(arg.Name))
			field.Set(reflect.ValueOf(reconstr))
		})
}

// ParseTopicsIntoMap converts the indexed topic field-value pairs into map key-value pairs.
// ParseTopicsIntoMap 将索引主题字段值对转换为映射键值对。
func ParseTopicsIntoMap(out map[string]interface{}, fields Arguments, topics []common.Hash) error {
	return parseTopicWithSetter(fields, topics,
		func(arg Argument, reconstr interface{}) {
			out[arg.Name] = reconstr
		})
}

// parseTopicWithSetter converts the indexed topic field-value pairs and stores them using the
// provided set function.
//
// Note, dynamic types cannot be reconstructed since they get mapped to Keccak256
// hashes as the topic value!
// parseTopicWithSetter 将索引主题字段值对转换，并使用提供的设置函数存储它们。
//
// 注意：动态类型无法重建，因为它们被映射为主题值的 Keccak256 哈希！
func parseTopicWithSetter(fields Arguments, topics []common.Hash, setter func(Argument, interface{})) error {
	// Sanity check that the fields and topics match up
	// 检查字段和主题是否匹配
	if len(fields) != len(topics) {
		return errors.New("topic/field count mismatch")
	}
	// Iterate over all the fields and reconstruct them from topics
	// 遍历所有字段并从主题中重建它们
	for i, arg := range fields {
		if !arg.Indexed {
			return errors.New("non-indexed field in topic reconstruction")
		}
		var reconstr interface{}
		switch arg.Type.T {
		case TupleTy:
			return errors.New("tuple type in topic reconstruction")
		case StringTy, BytesTy, SliceTy, ArrayTy:
			// Array types (including strings and bytes) have their keccak256 hashes stored in the topic- not a hash
			// whose bytes can be decoded to the actual value- so the best we can do is retrieve that hash
			// 数组类型（包括字符串和字节数组）的主题存储的是其 Keccak256 哈希值，
			// 而不是可以直接解码为实际值的哈希值，因此我们只能检索该哈希值。
			reconstr = topics[i]
		case FunctionTy:
			if garbage := binary.BigEndian.Uint64(topics[i][0:8]); garbage != 0 {
				return fmt.Errorf("bind: got improperly encoded function type, got %v", topics[i].Bytes())
			}
			var tmp [24]byte
			copy(tmp[:], topics[i][8:32])
			reconstr = tmp
		default:
			var err error
			reconstr, err = toGoType(0, arg.Type, topics[i].Bytes())
			if err != nil {
				return err
			}
		}
		// Use the setter function to store the value
		// 使用设置函数存储值
		setter(arg, reconstr)
	}

	return nil
}
