// Copyright 2024 The go-ethereum Authors
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

package vm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/params"
)

// EIP-3540：引入 EOF 格式，定义了容器结构和基本验证规则。代码中的 eofMagic 和版本检查即来源于此。
// EIP-3670：规定 EOF 代码的验证规则，确保字节码安全性和一致性，与 ValidateCode 功能对应。

// 什么是 EOF（Ethereum Object Format）？
//  EOF（以太坊对象格式）是以太坊虚拟机（EVM）的一种新格式，旨在改进智能合约的部署和执行。它通过将代码、数据和元数据组织成一个结构化的容器，提供更高的模块化、安全性和效率。代码中的 Container 结构体正是 EOF 容器的实现。
//
// EOF 的结构
//  根据以太坊白皮书、黄皮书和相关 EIP（如 EIP-3540 和 EIP-3670），EOF 容器由以下部分组成：
//
// 头部（Header）：
//  魔术字节（eofMagic）：0xef 0x00，用于标识 EOF 格式。
//  版本号（eof1Version）：当前为 1，表示 EOF v1。
//  部分标识符：如 kindTypes（类型）、kindCode（代码）、kindContainer（容器）、kindData（数据）。
// 类型部分（Types Section）：
//  包含函数的元数据（functionMetadata），如输入项数（inputs）、输出项数（outputs）和最大栈高度（maxStackHeight）。
//  用于验证函数调用时的栈行为，防止栈溢出或下溢。
// 代码部分（Code Sections）：
//  包含 EVM 字节码（codeSections），每个代码段对应一个函数。
//  代码段数量与类型部分中的元数据数量必须匹配。
// 容器部分（Container Sections，可选）：
//  包含子容器（subContainers），支持嵌套结构。
//  允许代码模块化和重用。
// 数据部分（Data Section）：
//  包含与代码相关的数据（data），如初始化数据或常量。

const (
	offsetVersion = 2 // 版本号的偏移量
	// offsetVersion 定义了 EOF 容器中版本号的字节偏移量。
	offsetTypesKind = 3 // 类型部分种类的偏移量
	// offsetTypesKind 定义了 EOF 容器中类型部分种类的字节偏移量。
	offsetCodeKind = 6 // 代码部分种类的偏移量
	// offsetCodeKind 定义了 EOF 容器中代码部分种类的字节偏移量。

	kindTypes = 1 // 类型部分的种类
	// kindTypes 表示类型部分的标识符。
	kindCode = 2 // 代码部分的种类
	// kindCode 表示代码部分的标识符。
	kindContainer = 3 // 容器部分的种类
	// kindContainer 表示容器部分的标识符。
	kindData = 4 // 数据部分的种类
	// kindData 表示数据部分的标识符。

	eofFormatByte = 0xef // EOF 格式字节
	// eofFormatByte 是 EOF 容器的格式标识字节。
	eof1Version = 1 // EOF 版本 1
	// eof1Version 表示 EOF 的版本号 1。

	maxInputItems = 127 // 最大输入项数
	// maxInputItems 定义了函数允许的最大输入项数。
	maxOutputItems = 128 // 最大输出项数
	// maxOutputItems 定义了函数允许的最大输出项数。
	maxStackHeight = 1023 // 最大栈高度
	// maxStackHeight 定义了函数执行时的最大栈高度。
	maxContainerSections = 256 // 最大容器部分数
	// maxContainerSections 定义了 EOF 容器中允许的最大子容器部分数。
)

var eofMagic = []byte{0xef, 0x00} // EOF 魔术字节
// eofMagic 是 EOF 容器的魔术字节，用于标识 EOF 格式。

// HasEOFByte returns true if code starts with 0xEF byte
// HasEOFByte 如果代码以 0xEF 字节开头，则返回 true
func HasEOFByte(code []byte) bool {
	return len(code) != 0 && code[0] == eofFormatByte
}

// hasEOFMagic returns true if code starts with magic defined by EIP-3540
// hasEOFMagic 如果代码以 EIP-3540 定义的魔术字节开头，则返回 true
func hasEOFMagic(code []byte) bool {
	return len(eofMagic) <= len(code) && bytes.Equal(eofMagic, code[0:len(eofMagic)])
}

// isEOFVersion1 returns true if the code's version byte equals eof1Version. It
// does not verify the EOF magic is valid.
// isEOFVersion1 如果代码的版本字节等于 eof1Version，则返回 true。它不验证 EOF 魔术字节是否有效。
func isEOFVersion1(code []byte) bool {
	return 2 < len(code) && code[2] == byte(eof1Version)
}

// Container is an EOF container object.
// Container 是 EOF 容器对象。
type Container struct {
	types             []*functionMetadata // 函数元数据列表
	codeSections      [][]byte            // 代码部分列表
	subContainers     []*Container        // 子容器列表
	subContainerCodes [][]byte            // 子容器代码列表
	data              []byte              // 数据部分
	dataSize          int                 // 数据大小（可能大于 len(data)）
	// dataSize might be more than len(data)
}

// functionMetadata is an EOF function signature.
// functionMetadata 是 EOF 函数签名。
type functionMetadata struct {
	inputs         uint8  // 输入项数
	outputs        uint8  // 输出项数
	maxStackHeight uint16 // 最大栈高度
}

// stackDelta returns the #outputs - #inputs
// stackDelta 返回 #outputs - #inputs
func (meta *functionMetadata) stackDelta() int {
	return int(meta.outputs) - int(meta.inputs)
}

// checkInputs checks the current minimum stack (stackMin) against the required inputs
// of the metadata, and returns an error if the stack is too shallow.
// checkInputs 检查当前最小栈（stackMin）是否满足元数据要求的输入项数，如果栈太浅则返回错误。
func (meta *functionMetadata) checkInputs(stackMin int) error {
	if int(meta.inputs) > stackMin {
		return ErrStackUnderflow{stackLen: stackMin, required: int(meta.inputs)}
	}
	return nil
}

// checkStackMax checks the if current maximum stack combined with the
// function max stack will result in a stack overflow, and if so returns an error.
// checkStackMax 检查当前最大栈与函数最大栈的组合是否会导致栈溢出，如果是则返回错误。
func (meta *functionMetadata) checkStackMax(stackMax int) error {
	newMaxStack := stackMax + int(meta.maxStackHeight) - int(meta.inputs)
	if newMaxStack > int(params.StackLimit) {
		return ErrStackOverflow{stackLen: newMaxStack, limit: int(params.StackLimit)}
	}
	return nil
}

// MarshalBinary encodes an EOF container into binary format.
// MarshalBinary 将 EOF 容器编码为二进制格式。
func (c *Container) MarshalBinary() []byte {
	// Build EOF prefix.
	// 构建 EOF 前缀。
	b := make([]byte, 2)
	copy(b, eofMagic)
	b = append(b, eof1Version)

	// Write section headers.
	// 写入部分头。
	b = append(b, kindTypes)
	b = binary.BigEndian.AppendUint16(b, uint16(len(c.types)*4))
	b = append(b, kindCode)
	b = binary.BigEndian.AppendUint16(b, uint16(len(c.codeSections)))
	for _, codeSection := range c.codeSections {
		b = binary.BigEndian.AppendUint16(b, uint16(len(codeSection)))
	}
	var encodedContainer [][]byte
	if len(c.subContainers) != 0 {
		b = append(b, kindContainer)
		b = binary.BigEndian.AppendUint16(b, uint16(len(c.subContainers)))
		for _, section := range c.subContainers {
			encoded := section.MarshalBinary()
			b = binary.BigEndian.AppendUint16(b, uint16(len(encoded)))
			encodedContainer = append(encodedContainer, encoded)
		}
	}
	b = append(b, kindData)
	b = binary.BigEndian.AppendUint16(b, uint16(c.dataSize))
	b = append(b, 0) // terminator

	// Write section contents.
	// 写入部分内容。
	for _, ty := range c.types {
		b = append(b, []byte{ty.inputs, ty.outputs, byte(ty.maxStackHeight >> 8), byte(ty.maxStackHeight & 0x00ff)}...)
	}
	for _, code := range c.codeSections {
		b = append(b, code...)
	}
	for _, section := range encodedContainer {
		b = append(b, section...)
	}
	b = append(b, c.data...)

	return b
}

// UnmarshalBinary decodes an EOF container.
// UnmarshalBinary 解码 EOF 容器。
func (c *Container) UnmarshalBinary(b []byte, isInitcode bool) error {
	return c.unmarshalContainer(b, isInitcode, true)
}

// UnmarshalSubContainer decodes an EOF container that is inside another container.
// UnmarshalSubContainer 解码另一个容器内的 EOF 容器。
func (c *Container) UnmarshalSubContainer(b []byte, isInitcode bool) error {
	return c.unmarshalContainer(b, isInitcode, false)
}

// unmarshalContainer 解码 EOF 容器。
func (c *Container) unmarshalContainer(b []byte, isInitcode bool, topLevel bool) error {
	if !hasEOFMagic(b) {
		return fmt.Errorf("%w: want %x", errInvalidMagic, eofMagic)
	}
	if len(b) < 14 {
		return io.ErrUnexpectedEOF
	}
	if len(b) > params.MaxInitCodeSize {
		return ErrMaxInitCodeSizeExceeded
	}
	if !isEOFVersion1(b) {
		return fmt.Errorf("%w: have %d, want %d", errInvalidVersion, b[2], eof1Version)
	}

	var (
		kind, typesSize, dataSize int
		codeSizes                 []int
		err                       error
	)

	// Parse type section header.
	// 解析类型部分头。
	// 关键步骤：解析类型部分的种类和大小。
	kind, typesSize, err = parseSection(b, offsetTypesKind)
	if err != nil {
		return err
	}
	if kind != kindTypes {
		return fmt.Errorf("%w: found section kind %x instead", errMissingTypeHeader, kind)
	}
	if typesSize < 4 || typesSize%4 != 0 {
		return fmt.Errorf("%w: type section size must be divisible by 4, have %d", errInvalidTypeSize, typesSize)
	}
	if typesSize/4 > 1024 {
		return fmt.Errorf("%w: type section must not exceed 4*1024, have %d", errInvalidTypeSize, typesSize)
	}

	// Parse code section header.
	// 解析代码部分头。
	// 关键步骤：解析代码部分的种类和各代码段大小。
	kind, codeSizes, err = parseSectionList(b, offsetCodeKind)
	if err != nil {
		return err
	}
	if kind != kindCode {
		return fmt.Errorf("%w: found section kind %x instead", errMissingCodeHeader, kind)
	}
	if len(codeSizes) != typesSize/4 {
		return fmt.Errorf("%w: mismatch of code sections found and type signatures, types %d, code %d", errInvalidCodeSize, typesSize/4, len(codeSizes))
	}

	// Parse (optional) container section header.
	// 解析（可选）容器部分头。
	var containerSizes []int
	offset := offsetCodeKind + 2 + 2*len(codeSizes) + 1
	if offset < len(b) && b[offset] == kindContainer {
		kind, containerSizes, err = parseSectionList(b, offset)
		if err != nil {
			return err
		}
		if kind != kindContainer {
			panic("somethings wrong")
		}
		if len(containerSizes) == 0 {
			return fmt.Errorf("%w: total container count must not be zero", errInvalidContainerSectionSize)
		}
		offset = offset + 2 + 2*len(containerSizes) + 1
	}

	// Parse data section header.
	// 解析数据部分头。
	kind, dataSize, err = parseSection(b, offset)
	if err != nil {
		return err
	}
	if kind != kindData {
		return fmt.Errorf("%w: found section %x instead", errMissingDataHeader, kind)
	}
	c.dataSize = dataSize

	// Check for terminator.
	// 检查终止符。
	offsetTerminator := offset + 3
	if len(b) < offsetTerminator {
		return fmt.Errorf("%w: invalid offset terminator", io.ErrUnexpectedEOF)
	}
	if b[offsetTerminator] != 0 {
		return fmt.Errorf("%w: have %x", errMissingTerminator, b[offsetTerminator])
	}

	// Verify overall container size.
	// 验证整体容器大小。
	// 关键步骤：计算并验证整个容器的预期大小。
	expectedSize := offsetTerminator + typesSize + sum(codeSizes) + dataSize + 1
	if len(containerSizes) != 0 {
		expectedSize += sum(containerSizes)
	}
	if len(b) < expectedSize-dataSize {
		return fmt.Errorf("%w: have %d, want %d", errInvalidContainerSize, len(b), expectedSize)
	}
	// Only check that the expected size is not exceed on non-initcode
	// 仅在非初始化代码上检查预期大小未被超过
	if (!topLevel || !isInitcode) && len(b) > expectedSize {
		return fmt.Errorf("%w: have %d, want %d", errInvalidContainerSize, len(b), expectedSize)
	}

	// Parse types section.
	// 解析类型部分。
	// 关键步骤：解析类型部分内容，生成函数元数据。
	idx := offsetTerminator + 1
	var types = make([]*functionMetadata, 0, typesSize/4)
	for i := 0; i < typesSize/4; i++ {
		sig := &functionMetadata{
			inputs:         b[idx+i*4],
			outputs:        b[idx+i*4+1],
			maxStackHeight: binary.BigEndian.Uint16(b[idx+i*4+2:]),
		}
		if sig.inputs > maxInputItems {
			return fmt.Errorf("%w for section %d: have %d", errTooManyInputs, i, sig.inputs)
		}
		if sig.outputs > maxOutputItems {
			return fmt.Errorf("%w for section %d: have %d", errTooManyOutputs, i, sig.outputs)
		}
		if sig.maxStackHeight > maxStackHeight {
			return fmt.Errorf("%w for section %d: have %d", errTooLargeMaxStackHeight, i, sig.maxStackHeight)
		}
		types = append(types, sig)
	}
	if types[0].inputs != 0 || types[0].outputs != 0x80 {
		return fmt.Errorf("%w: have %d, %d", errInvalidSection0Type, types[0].inputs, types[0].outputs)
	}
	c.types = types

	// Parse code sections.
	// 解析代码部分。
	idx += typesSize
	codeSections := make([][]byte, len(codeSizes))
	for i, size := range codeSizes {
		if size == 0 {
			return fmt.Errorf("%w for section %d: size must not be 0", errInvalidCodeSize, i)
		}
		codeSections[i] = b[idx : idx+size]
		idx += size
	}
	c.codeSections = codeSections
	// Parse the optional container sizes.
	// 解析可选的容器大小。
	if len(containerSizes) != 0 {
		if len(containerSizes) > maxContainerSections {
			return fmt.Errorf("%w number of container section exceed: %v: have %v", errInvalidContainerSectionSize, maxContainerSections, len(containerSizes))
		}
		subContainerCodes := make([][]byte, 0, len(containerSizes))
		subContainers := make([]*Container, 0, len(containerSizes))
		for i, size := range containerSizes {
			if size == 0 || idx+size > len(b) {
				return fmt.Errorf("%w for section %d: size must not be 0", errInvalidContainerSectionSize, i)
			}
			subC := new(Container)
			end := min(idx+size, len(b))
			if err := subC.unmarshalContainer(b[idx:end], isInitcode, false); err != nil {
				if topLevel {
					return fmt.Errorf("%w in sub container %d", err, i)
				}
				return err
			}
			subContainers = append(subContainers, subC)
			subContainerCodes = append(subContainerCodes, b[idx:end])

			idx += size
		}
		c.subContainers = subContainers
		c.subContainerCodes = subContainerCodes
	}

	// Parse data section.
	// 解析数据部分。
	end := len(b)
	if !isInitcode {
		end = min(idx+dataSize, len(b))
	}
	if topLevel && len(b) != idx+dataSize {
		return errTruncatedTopLevelContainer
	}
	c.data = b[idx:end]

	return nil
}

// ValidateCode validates each code section of the container against the EOF v1
// rule set.
// ValidateCode 根据 EOF v1 规则集验证容器的每个代码部分。
func (c *Container) ValidateCode(jt *JumpTable, isInitCode bool) error {
	refBy := notRefByEither
	if isInitCode {
		refBy = refByEOFCreate
	}
	return c.validateSubContainer(jt, refBy)
}

// validateSubContainer 验证子容器。
func (c *Container) validateSubContainer(jt *JumpTable, refBy int) error {
	visited := make(map[int]struct{})
	subContainerVisited := make(map[int]int)
	toVisit := []int{0}
	for len(toVisit) > 0 {
		// TODO check if this can be used as a DOS
		// Theres and edge case here where we mark something as visited that we visit before,
		// This should not trigger a re-visit
		// e.g. 0 -> 1, 2, 3
		// 1 -> 2, 3
		// should not mean 2 and 3 should be visited twice
		// TODO 检查这是否可被用作拒绝服务攻击
		// 这里有一个边缘情况，我们标记了一个之前访问过的部分，
		// 这不应触发重新访问
		// 例如：0 -> 1, 2, 3
		// 1 -> 2, 3
		// 不应意味着 2 和 3 需要被访问两次
		var (
			index = toVisit[0]
			code  = c.codeSections[index]
		)
		if _, ok := visited[index]; !ok {
			res, err := validateCode(code, index, c, jt, refBy == refByEOFCreate)
			if err != nil {
				return err
			}
			visited[index] = struct{}{}
			// Mark all sections that can be visited from here.
			// 标记从此处可以访问的所有部分。
			for idx := range res.visitedCode {
				if _, ok := visited[idx]; !ok {
					toVisit = append(toVisit, idx)
				}
			}
			// Mark all subcontainer that can be visited from here.
			// 标记从此处可以访问的所有子容器。
			for idx, reference := range res.visitedSubContainers {
				// Make sure subcontainers are only ever referenced by either EOFCreate or ReturnContract
				// 确保子容器仅由 EOFCreate 或 ReturnContract 引用
				if ref, ok := subContainerVisited[idx]; ok && ref != reference {
					return errors.New("section referenced by both EOFCreate and ReturnContract")
				}
				subContainerVisited[idx] = reference
			}
			if refBy == refByReturnContract && res.isInitCode {
				return errIncompatibleContainerKind
			}
			if refBy == refByEOFCreate && res.isRuntime {
				return errIncompatibleContainerKind
			}
		}
		toVisit = toVisit[1:]
	}
	// Make sure every code section is visited at least once.
	// 确保每个代码部分至少被访问一次。
	if len(visited) != len(c.codeSections) {
		return errUnreachableCode
	}
	for idx, container := range c.subContainers {
		reference, ok := subContainerVisited[idx]
		if !ok {
			return errOrphanedSubcontainer
		}
		if err := container.validateSubContainer(jt, reference); err != nil {
			return err
		}
	}
	return nil
}

// parseSection decodes a (kind, size) pair from an EOF header.
// parseSection 从 EOF 头中解码 (kind, size) 对。
func parseSection(b []byte, idx int) (kind, size int, err error) {
	if idx+3 >= len(b) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	kind = int(b[idx])
	size = int(binary.BigEndian.Uint16(b[idx+1:]))
	return kind, size, nil
}

// parseSectionList decodes a (kind, len, []codeSize) section list from an EOF
// header.
// parseSectionList 从 EOF 头中解码 (kind, len, []codeSize) 部分列表。
func parseSectionList(b []byte, idx int) (kind int, list []int, err error) {
	if idx >= len(b) {
		return 0, nil, io.ErrUnexpectedEOF
	}
	kind = int(b[idx])
	list, err = parseList(b, idx+1)
	if err != nil {
		return 0, nil, err
	}
	return kind, list, nil
}

// parseList decodes a list of uint16..
// parseList 解码 uint16 列表。
func parseList(b []byte, idx int) ([]int, error) {
	if len(b) < idx+2 {
		return nil, io.ErrUnexpectedEOF
	}
	count := binary.BigEndian.Uint16(b[idx:])
	if len(b) <= idx+2+int(count)*2 {
		return nil, io.ErrUnexpectedEOF
	}
	list := make([]int, count)
	for i := 0; i < int(count); i++ {
		list[i] = int(binary.BigEndian.Uint16(b[idx+2+2*i:]))
	}
	return list, nil
}

// parseUint16 parses a 16 bit unsigned integer.
// parseUint16 解析 16 位无符号整数。
func parseUint16(b []byte) (int, error) {
	if len(b) < 2 {
		return 0, io.ErrUnexpectedEOF
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

// parseInt16 parses a 16 bit signed integer.
// parseInt16 解析 16 位有符号整数。
func parseInt16(b []byte) int {
	return int(int16(b[1]) | int16(b[0])<<8)
}

// sum computes the sum of a slice.
// sum 计算切片的总和。
func sum(list []int) (s int) {
	for _, n := range list {
		s += n
	}
	return
}

// String 返回容器的字符串表示。
func (c *Container) String() string {
	var output = []string{
		"Header",
		fmt.Sprintf("  - EOFMagic: %02x", eofMagic),
		fmt.Sprintf("  - EOFVersion: %02x", eof1Version),
		fmt.Sprintf("  - KindType: %02x", kindTypes),
		fmt.Sprintf("  - TypesSize: %04x", len(c.types)*4),
		fmt.Sprintf("  - KindCode: %02x", kindCode),
		fmt.Sprintf("  - KindData: %02x", kindData),
		fmt.Sprintf("  - DataSize: %04x", len(c.data)),
		fmt.Sprintf("  - Number of code sections: %d", len(c.codeSections)),
	}
	for i, code := range c.codeSections {
		output = append(output, fmt.Sprintf("    - Code section %d length: %04x", i, len(code)))
	}

	output = append(output, fmt.Sprintf("  - Number of subcontainers: %d", len(c.subContainers)))
	if len(c.subContainers) > 0 {
		for i, section := range c.subContainers {
			output = append(output, fmt.Sprintf("    - subcontainer %d length: %04x\n", i, len(section.MarshalBinary())))
		}
	}
	output = append(output, "Body")
	for i, typ := range c.types {
		output = append(output, fmt.Sprintf("  - Type %v: %x", i,
			[]byte{typ.inputs, typ.outputs, byte(typ.maxStackHeight >> 8), byte(typ.maxStackHeight & 0x00ff)}))
	}
	for i, code := range c.codeSections {
		output = append(output, fmt.Sprintf("  - Code section %d: %#x", i, code))
	}
	for i, section := range c.subContainers {
		output = append(output, fmt.Sprintf("  - Subcontainer %d: %x", i, section.MarshalBinary()))
	}
	output = append(output, fmt.Sprintf("  - Data: %#x", c.data))
	return strings.Join(output, "\n")
}
