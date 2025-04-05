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

package abi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
)

var (
	// MaxUint256 is the maximum value that can be represented by a uint256.
	// MaxUint256 是 uint256 可以表示的最大值。
	MaxUint256 = new(big.Int).Sub(new(big.Int).Lsh(common.Big1, 256), common.Big1)
	// MaxInt256 is the maximum value that can be represented by a int256.
	// MaxInt256 是 int256 可以表示的最大值。
	MaxInt256 = new(big.Int).Sub(new(big.Int).Lsh(common.Big1, 255), common.Big1)
)

// ReadInteger reads the integer based on its kind and returns the appropriate value.
// ReadInteger 根据整数类型读取整数并返回适当的值。
func ReadInteger(typ Type, b []byte) (interface{}, error) {
	ret := new(big.Int).SetBytes(b)

	if typ.T == UintTy {
		u64, isu64 := ret.Uint64(), ret.IsUint64()
		switch typ.Size {
		case 8:
			if !isu64 || u64 > math.MaxUint8 {
				return nil, errBadUint8
			}
			return byte(u64), nil
		case 16:
			if !isu64 || u64 > math.MaxUint16 {
				return nil, errBadUint16
			}
			return uint16(u64), nil
		case 32:
			if !isu64 || u64 > math.MaxUint32 {
				return nil, errBadUint32
			}
			return uint32(u64), nil
		case 64:
			if !isu64 {
				return nil, errBadUint64
			}
			return u64, nil
		default:
			// the only case left for unsigned integer is uint256.
			// 对于无符号整数，唯一剩下的情况是 uint256。
			return ret, nil
		}
	}

	// big.SetBytes can't tell if a number is negative or positive in itself.
	// On EVM, if the returned number > max int256, it is negative.
	// A number is > max int256 if the bit at position 255 is set.
	// big.SetBytes 本身无法判断数字是正数还是负数。
	// 在 EVM 上，如果返回的数字 > max int256，则为负数。
	// 如果第 255 位被置位，则数字 > max int256。
	if ret.Bit(255) == 1 {
		ret.Add(MaxUint256, new(big.Int).Neg(ret))
		ret.Add(ret, common.Big1)
		ret.Neg(ret)
	}
	i64, isi64 := ret.Int64(), ret.IsInt64()
	switch typ.Size {
	case 8:
		if !isi64 || i64 < math.MinInt8 || i64 > math.MaxInt8 {
			return nil, errBadInt8
		}
		return int8(i64), nil
	case 16:
		if !isi64 || i64 < math.MinInt16 || i64 > math.MaxInt16 {
			return nil, errBadInt16
		}
		return int16(i64), nil
	case 32:
		if !isi64 || i64 < math.MinInt32 || i64 > math.MaxInt32 {
			return nil, errBadInt32
		}
		return int32(i64), nil
	case 64:
		if !isi64 {
			return nil, errBadInt64
		}
		return i64, nil
	default:
		// the only case left for integer is int256
		// 对于整数，唯一剩下的情况是 int256
		return ret, nil
	}
}

// readBool reads a bool.
// readBool 读取布尔值。
func readBool(word []byte) (bool, error) {
	for _, b := range word[:31] {
		if b != 0 {
			return false, errBadBool
		}
	}
	switch word[31] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errBadBool
	}
}

// A function type is simply the address with the function selection signature at the end.
//
// readFunctionType enforces that standard by always presenting it as a 24-array (address + sig = 24 bytes)
// 函数类型仅仅是地址后面跟有函数选择签名。
//
// readFunctionType 通过始终将其表示为 24 字节数组（地址 + 签名 = 24 字节）来强制执行该标准。
func readFunctionType(t Type, word []byte) (funcTy [24]byte, err error) {
	if t.T != FunctionTy {
		return [24]byte{}, errors.New("abi: invalid type in call to make function type byte array")
	}
	if garbage := binary.BigEndian.Uint64(word[24:32]); garbage != 0 {
		err = fmt.Errorf("abi: got improperly encoded function type, got %v", word)
	} else {
		copy(funcTy[:], word[0:24])
	}
	return
}

// ReadFixedBytes uses reflection to create a fixed array to be read from.
// ReadFixedBytes 使用反射创建一个要读取的固定数组。
func ReadFixedBytes(t Type, word []byte) (interface{}, error) {
	if t.T != FixedBytesTy {
		return nil, errors.New("abi: invalid type in call to make fixed byte array")
	}
	// convert
	array := reflect.New(t.GetType()).Elem()

	reflect.Copy(array, reflect.ValueOf(word[0:t.Size]))
	return array.Interface(), nil
}

// forEachUnpack iteratively unpack elements.
// forEachUnpack 迭代解包元素。
func forEachUnpack(t Type, output []byte, start, size int) (interface{}, error) {
	if size < 0 {
		return nil, fmt.Errorf("cannot marshal input to array, size is negative (%d)", size)
	}
	if start+32*size > len(output) {
		return nil, fmt.Errorf("abi: cannot marshal into go array: offset %d would go over slice boundary (len=%d)", len(output), start+32*size)
	}

	// this value will become our slice or our array, depending on the type
	// 这个值将根据类型成为我们的切片或数组
	var refSlice reflect.Value

	switch t.T {
	case SliceTy:
		// declare our slice
		// 声明我们的切片
		refSlice = reflect.MakeSlice(t.GetType(), size, size)
	case ArrayTy:
		// declare our array
		// 声明我们的数组
		refSlice = reflect.New(t.GetType()).Elem()
	default:
		return nil, errors.New("abi: invalid type in array/slice unpacking stage")
	}

	// Arrays have packed elements, resulting in longer unpack steps.
	// Slices have just 32 bytes per element (pointing to the contents).
	// 数组具有打包的元素，导致解包步骤更长。
	// 切片每个元素只有 32 字节（指向内容）。
	elemSize := getTypeSize(*t.Elem)

	for i, j := start, 0; j < size; i, j = i+elemSize, j+1 {
		inter, err := toGoType(i, *t.Elem, output)
		if err != nil {
			return nil, err
		}

		// append the item to our reflect slice
		// 将项追加到我们的反射切片中
		refSlice.Index(j).Set(reflect.ValueOf(inter))
	}

	// return the interface
	// 返回接口
	return refSlice.Interface(), nil
}

func forTupleUnpack(t Type, output []byte) (interface{}, error) {
	retval := reflect.New(t.GetType()).Elem()
	virtualArgs := 0
	for index, elem := range t.TupleElems {
		marshalledValue, err := toGoType((index+virtualArgs)*32, *elem, output)
		if err != nil {
			return nil, err
		}
		if elem.T == ArrayTy && !isDynamicType(*elem) {
			// If we have a static array, like [3]uint256, these are coded as
			// just like uint256,uint256,uint256.
			// This means that we need to add two 'virtual' arguments when
			// we count the index from now on.
			//
			// Array values nested multiple levels deep are also encoded inline:
			// [2][3]uint256: uint256,uint256,uint256,uint256,uint256,uint256
			//
			// Calculate the full array size to get the correct offset for the next argument.
			// Decrement it by 1, as the normal index increment is still applied.
			// 如果我们有一个静态数组，如 [3]uint256，这些被编码为
			// 就像 uint256,uint256,uint256。
			// 这意味着从现在起我们需要添加两个“虚拟”参数来计算索引。
			//
			// 多层嵌套的数组值也被内联编码：
			// [2][3]uint256: uint256,uint256,uint256,uint256,uint256,uint256
			//
			// 计算完整数组大小以获取下一个参数的正确偏移量。
			// 减去 1，因为正常的索引增量仍然适用。
			virtualArgs += getTypeSize(*elem)/32 - 1
		} else if elem.T == TupleTy && !isDynamicType(*elem) {
			// If we have a static tuple, like (uint256, bool, uint256), these are
			// coded as just like uint256,bool,uint256
			// 如果我们有一个静态元组，如 (uint256, bool, uint256)，这些被编码为
			// 就像 uint256,bool,uint256
			virtualArgs += getTypeSize(*elem)/32 - 1
		}
		retval.Field(index).Set(reflect.ValueOf(marshalledValue))
	}
	return retval.Interface(), nil
}

// toGoType parses the output bytes and recursively assigns the value of these bytes
// into a go type with accordance with the ABI spec.
// toGoType 解析输出字节并根据 ABI 规范递归地将这些字节的值分配到 Go 类型中。
func toGoType(index int, t Type, output []byte) (interface{}, error) {
	if index+32 > len(output) {
		return nil, fmt.Errorf("abi: cannot marshal in to go type: length insufficient %d require %d", len(output), index+32)
	}

	var (
		returnOutput  []byte
		begin, length int
		err           error
	)

	// if we require a length prefix, find the beginning word and size returned.
	// 如果我们需要长度前缀，找到返回的起始单词和大小。
	if t.requiresLengthPrefix() {
		begin, length, err = lengthPrefixPointsTo(index, output)
		if err != nil {
			return nil, err
		}
	} else {
		returnOutput = output[index : index+32]
	}

	switch t.T {
	case TupleTy:
		if isDynamicType(t) {
			begin, err := tuplePointsTo(index, output)
			if err != nil {
				return nil, err
			}
			return forTupleUnpack(t, output[begin:])
		}
		return forTupleUnpack(t, output[index:])
	case SliceTy:
		return forEachUnpack(t, output[begin:], 0, length)
	case ArrayTy:
		if isDynamicType(*t.Elem) {
			offset := binary.BigEndian.Uint64(returnOutput[len(returnOutput)-8:])
			if offset > uint64(len(output)) {
				return nil, fmt.Errorf("abi: toGoType offset greater than output length: offset: %d, len(output): %d", offset, len(output))
			}
			return forEachUnpack(t, output[offset:], 0, t.Size)
		}
		return forEachUnpack(t, output[index:], 0, t.Size)
	case StringTy: // variable arrays are written at the end of the return bytes
		// 变量数组被写入返回字节的末尾
		return string(output[begin : begin+length]), nil
	case IntTy, UintTy:
		return ReadInteger(t, returnOutput)
	case BoolTy:
		return readBool(returnOutput)
	case AddressTy:
		return common.BytesToAddress(returnOutput), nil
	case HashTy:
		return common.BytesToHash(returnOutput), nil
	case BytesTy:
		return output[begin : begin+length], nil
	case FixedBytesTy:
		return ReadFixedBytes(t, returnOutput)
	case FunctionTy:
		return readFunctionType(t, returnOutput)
	default:
		return nil, fmt.Errorf("abi: unknown type %v", t.T)
	}
}

// lengthPrefixPointsTo interprets a 32 byte slice as an offset and then determines which indices to look to decode the type.
// lengthPrefixPointsTo 将 32 字节切片解释为偏移量，然后确定要查看哪些索引来解码类型。
func lengthPrefixPointsTo(index int, output []byte) (start int, length int, err error) {
	bigOffsetEnd := new(big.Int).SetBytes(output[index : index+32])
	bigOffsetEnd.Add(bigOffsetEnd, common.Big32)
	outputLength := big.NewInt(int64(len(output)))

	if bigOffsetEnd.Cmp(outputLength) > 0 {
		return 0, 0, fmt.Errorf("abi: cannot marshal in to go slice: offset %v would go over slice boundary (len=%v)", bigOffsetEnd, outputLength)
	}

	if bigOffsetEnd.BitLen() > 63 {
		return 0, 0, fmt.Errorf("abi offset larger than int64: %v", bigOffsetEnd)
	}

	offsetEnd := int(bigOffsetEnd.Uint64())
	lengthBig := new(big.Int).SetBytes(output[offsetEnd-32 : offsetEnd])

	totalSize := new(big.Int).Add(bigOffsetEnd, lengthBig)
	if totalSize.BitLen() > 63 {
		return 0, 0, fmt.Errorf("abi: length larger than int64: %v", totalSize)
	}

	if totalSize.Cmp(outputLength) > 0 {
		return 0, 0, fmt.Errorf("abi: cannot marshal in to go type: length insufficient %v require %v", outputLength, totalSize)
	}
	start = int(bigOffsetEnd.Uint64())
	length = int(lengthBig.Uint64())
	return
}

// tuplePointsTo resolves the location reference for dynamic tuple.
// tuplePointsTo 解析动态元组的位置引用。
func tuplePointsTo(index int, output []byte) (start int, err error) {
	offset := new(big.Int).SetBytes(output[index : index+32])
	outputLen := big.NewInt(int64(len(output)))

	if offset.Cmp(outputLen) > 0 {
		return 0, fmt.Errorf("abi: cannot marshal in to go slice: offset %v would go over slice boundary (len=%v)", offset, outputLen)
	}
	if offset.BitLen() > 63 {
		return 0, fmt.Errorf("abi offset larger than int64: %v", offset)
	}
	return int(offset.Uint64()), nil
}
