// Copyright 2014 The go-ethereum Authors
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

package trie

// Trie keys are dealt with in three distinct encodings:
//
// KEYBYTES encoding contains the actual key and nothing else. This encoding is the
// input to most API functions.
//
// HEX encoding contains one byte for each nibble of the key and an optional trailing
// 'terminator' byte of value 0x10 which indicates whether or not the node at the key
// contains a value. Hex key encoding is used for nodes loaded in memory because it's
// convenient to access.
//
// COMPACT encoding is defined by the Ethereum Yellow Paper (it's called "hex prefix
// encoding" there) and contains the bytes of the key and a flag. The high nibble of the
// first byte contains the flag; the lowest bit encoding the oddness of the length and
// the second-lowest encoding whether the node at the key is a value node. The low nibble
// of the first byte is zero in the case of an even number of nibbles and the first nibble
// in the case of an odd number. All remaining nibbles (now an even number) fit properly
// into the remaining bytes. Compact encoding is used for nodes stored on disk.
//
// Trie 键以三种不同的编码方式处理：

// KEYBYTES 编码仅包含实际的键，没有其他内容。这种编码是大多数 API 函数的输入。

// HEX 编码为键的每个半字节（nibble）分配一个字节，并带有一个可选的末尾“终止符”字节，值为 0x10，
// 用于指示该键对应的节点是否包含值。HEX 键编码用于内存中加载的节点，因为它便于访问。

// COMPACT 编码由以太坊黄皮书定义（在那里称为“十六进制前缀编码”），包含键的字节和一个标志。
// 第一个字节的高半字节包含标志；最低位编码键长度的奇偶性，次低位编码该键对应的节点是否为值节点。
// 如果键的半字节数为偶数，则第一个字节的低半字节为零；如果为奇数，则为第一个半字节。
// 剩余的半字节（现在为偶数）适配到后续字节中。COMPACT 编码用于磁盘上存储的节点。
// 描述了以太坊 trie（特别是 Merkle Patricia Trie，MPT）中键的三种编码方式：KEYBYTES、HEX 和 COMPACT。这些编码分别服务于不同的场景（如 API 输入、内存操作、磁盘存储）

// KEYBYTES 编码：
//  定义：仅包含原始键字节，没有额外信息。
//  用途：作为 API 的输入，例如 Get、Update、Delete 等函数。
//  特点：
//   键是未经加工的字节数组，通常为 32 字节（如存储键的 Keccak-256 哈希）。
//   不包含元数据，简单直接。
//  以太坊相关知识点：
//   在 go-ethereum 中，KEYBYTES 是用户传入的原始键，例如账户地址或存储槽哈希。
//   示例：0x1234...（32 字节）。
// HEX 编码：
//  定义：将键的每个半字节（nibble，4 位）扩展为一个字节，可选附加终止符 0x10。
//  用途：用于内存中的节点，便于访问和操作。
//  特点：
//   键的每个字节拆分为两个半字节，例如 0xAB 变为 [0x0A, 0x0B]。
//   终止符 0x10 表示节点是否包含值（value node），无终止符表示分支节点。
//   长度是原始键的两倍加可选 1 字节。
//   示例：
//   原始键：0xABCD
//  HEX 编码：[0x0A, 0x0B, 0x0C, 0x0D]（无值）或 [0x0A, 0x0B, 0x0C, 0x0D, 0x10]（有值）。
//  以太坊相关知识点：
//   HEX 编码便于内存操作，因为 trie 的路径是按半字节解析的（MPT 是 16 进制树，基数为 16）。
//   在 go-ethereum 中，内存中的节点使用 HEX 编码以快速访问子节点。
//  COMPACT 编码（十六进制前缀编码，Hex Prefix Encoding）**：
//   定义：由以太坊黄皮书定义，压缩键字节并附加标志位。
//   用途：用于磁盘存储，节省空间。
//   特点：
//    标志位（第一个字节的高半字节）：
//     最低位（bit 0）：键长度奇偶性（1=奇数，0=偶数）。
//     次低位（bit 1）：是否为值节点（1=是，0=否）。
//     高半字节可能值：
//      0x0（00）：偶数长度的分支节点。
//      0x1（01）：奇数长度的分支节点。
//      0x2（10）：偶数长度的值节点。
//   	0x3（11）：奇数长度的值节点。
//   第一个字节的低半字节：
//    偶数长度：填充为 0。
//    奇数长度：键的第一个半字节。
//   后续字节：剩余的半字节（偶数个）紧凑存储。
//  示例：
//  键：0x123（奇数长度，3 个半字节，有值）：
// 	COMPACT：[0x31, 0x23]（0x3 表示奇数值节点，0x1 是第一个半字节）。
// 	键：0x1234（偶数长度，无值）：
// 	COMPACT：[0x00, 0x12, 0x34]（0x0 表示偶数分支节点）。
// 	以太坊相关知识点：
// 	黄皮书中定义的 COMPACT 编码用于 MPT 的序列化（如 RLP 编码后存储到数据库）。
//  在 Verkle 树中，类似概念可能用于键路径的压缩，但具体实现可能不同。

// 半字节（nibble）：trie 的基本单位。
// 标志位：区分节点类型和长度。
// 编码转换：在内存和磁盘间切换。

// 以太坊使用一种称为 Hex-Prefix Encoding（HP 编码）的紧凑格式，定义在 EIP-55 和 MPT 实现中。
// HP 编码规则：
// 第一字节是标志字节：
//   0x00 或 0x01：无终止符的偶数长度路径。
//   0x20 或 0x21：有终止符的偶数长度路径。
//   0x10 或 0x11：无终止符的奇数长度路径。
//   0x30 或 0x31：有终止符的奇数长度路径。
// 奇数长度时，第一个 nibble 被放入标志字节。

// 终止符：在 MPT 中，叶子节点（存储实际数据）与扩展节点（路径分叉）需要区分，终止符用于标记叶子节点。

// 将十六进制字节切片转换为紧凑格式字节切片
// hex: 输入的十六进制字节数组
// 返回值: 转换后的紧凑格式字节数组
//
// 将一个十六进制编码的字节切片（通常表示 Merkle Patricia Trie 中的键或路径）转换为以太坊中使用的紧凑格式（Compact Encoding）。
// 这种编码方式在以太坊的 Merkle Patricia Trie（MPT）中用于高效存储和传输键数据，减少空间占用。
func hexToCompact(hex []byte) []byte {
	// 定义终止符，默认为0
	terminator := byte(0)
	// 如果有终止符，设置标志为1，并移除最后一个字节
	// 在 MPT 中，终止符表示该键指向一个叶子节点，需在紧凑编码中标记。
	if hasTerm(hex) {
		terminator = 1
		hex = hex[:len(hex)-1]
	}
	// 创建输出缓冲区，长度为输入长度的一半加1（包含标志字节）
	// 额外加 1 是因为需要一个标志字节（flag byte）。
	buf := make([]byte, len(hex)/2+1)
	// 第一字节为标志字节，终止符左移5位
	// 第 5 位（1 << 5）：表示终止符。
	// 第 4 位（1 << 4）：表示奇数标志。
	buf[0] = terminator << 5 // the flag byte 将终止符标志左移 5 位（第 5 位表示是否有终止符）。
	// 如果输入长度为奇数，处理输入长度为奇数的情况，确保第一个 nibble 被正确编码。
	if len(hex)&1 == 1 {
		// 设置奇数标志位
		buf[0] |= 1 << 4 // odd flag
		buf[0] |= hex[0] // first nibble is contained in the first byte 将第一个十六进制字符（nibble）放入标志字节
		// 移除已处理的第一个字节
		hex = hex[1:]
	}
	// 将剩余的十六进制数据解码为紧凑格式，填入缓冲区
	decodeNibbles(hex, buf[1:])
	// 返回紧凑格式的字节数组
	return buf
}

// hexToCompactInPlace places the compact key in input buffer, returning the compacted key.
// 将紧凑键放置在输入缓冲区中，返回紧凑后的键
// hex: 输入的十六进制字节数组
// 返回值: 紧凑格式的字节数组，使用输入缓冲区的前部分存储结果
// 将十六进制编码的字节切片转换为以太坊的紧凑格式（Compact Encoding），并直接在输入缓冲区中进行操作，
// 而不是像之前的 hexToCompact 那样分配新的缓冲区。这种“原地”操作减少了内存分配，提高了性能。
func hexToCompactInPlace(hex []byte) []byte {
	var (
		hexLen    = len(hex) // length of the hex input // 十六进制输入的长度
		firstByte = byte(0)  // 第一个字节，初始值为0
	)
	// Check if we have a terminator there
	// 检查最后一个字节是否为终止符（16）
	if hexLen > 0 && hex[hexLen-1] == 16 {
		// 如果有终止符，将第一字节的第5位设置为1
		firstByte = 1 << 5
		hexLen-- // last part was the terminator, ignore that // 减少长度，忽略终止符部分
	}
	var (
		// 紧凑格式的长度，等于十六进制长度的一半加1
		binLen = hexLen/2 + 1
		ni     = 0 // index in hex 十六进制数组的索引
		bi     = 1 // index in bin (compact) 紧凑格式数组的索引
	)
	// 如果十六进制长度为奇数
	if hexLen&1 == 1 {
		// 设置奇数标志位
		firstByte |= 1 << 4 // odd flag
		// 将第一个nibble放入第一字节
		firstByte |= hex[0] // first nibble is contained in the first byte
		// 十六进制索引向前移动一位
		ni++
	}
	// 循环处理剩余的十六进制数据，每两个nibble压缩为一个字节
	for ; ni < hexLen; bi, ni = bi+1, ni+2 {
		hex[bi] = hex[ni]<<4 | hex[ni+1]
	}
	// 设置第一字节
	hex[0] = firstByte
	// 返回紧凑格式的字节切片
	return hex[:binLen]
}

// HP 编码规则：
// 第一字节（标志字节）：
// 0x00：无终止符，偶数长度。
// 0x10：无终止符，奇数长度。
// 0x20：有终止符，偶数长度。
// 0x30：有终止符，奇数长度。
// 奇数长度时，标志字节低 4 位包含第一个 nibble。

// 将紧凑格式的字节切片转换回十六进制格式
// compact: 输入的紧凑格式字节数组
// 返回值: 转换后的十六进制字节数组
//
// 是将以太坊紧凑格式（Compact Encoding）的字节切片转换回普通的十六进制格式。
// 这通常用于从 Merkle Patricia Trie（MPT）的紧凑键中恢复原始路径数据，与之前的 hexToCompact 和 hexToCompactInPlace 形成互逆操作。
func compactToHex(compact []byte) []byte {
	// 如果输入为空，直接返回
	if len(compact) == 0 {
		return compact
	}
	// 将紧凑格式转换为基础十六进制表示
	base := keybytesToHex(compact)

	// 移除终止符：
	// 检查标志字节 base[0] 是否小于 2（即 0x00 或 0x01），表示没有终止符。
	// 如果是，则移除最后一个字节（通常是终止符 0x10）。
	// 目的：在 MPT 中，终止符表示叶子节点，解码时需移除。

	// delete terminator flag
	// 如果没有终止符标志，移除最后一个字节
	if base[0] < 2 {
		base = base[:len(base)-1]
	}

	// 处理奇数标志：
	//  - base[0] & 1：检查标志字节的最低位（奇数标志）。
	//    - 若 base[0] = 0x00 或 0x20，结果为 0（偶数）。
	//    - 若 base[0] = 0x10 或 0x30，结果为 1（奇数）。
	//  - chop := 2 - base[0]&1：
	//    - 偶数时，chop = 2。
	//	  - 奇数时，chop = 1。
	// 返回 base[chop:]：根据奇数标志跳过标志字节的前缀部分。
	// 目的：奇数长度时，标志字节包含第一个 nibble，需要调整偏移量。

	// apply odd flag
	// 根据奇数标志调整起始位置
	chop := 2 - base[0]&1
	// 返回调整后的十六进制字节数组
	return base[chop:]
}

// HEX 编码：
// 在以太坊的 Merkle Patricia Trie（MPT）中，HEX 编码将键的每个半字节扩展为 1 字节，便于内存操作。
// 终止符 0x10 表示节点包含值（leaf node），无终止符表示分支节点（branch node）。

// keybytesToHex 将字节数组转换为 HEX 编码的半字节数组，并附加终止符。
// keybytesToHex 将原始字节数组（KEYBYTES 编码）转换为 HEX 编码的半字节数组，每个字节拆分为两个半字节，并在末尾附加终止符 0x10。
// 将用户输入的存储键（32 字节哈希）转换为内存中的 HEX 格式，用于 trie 查询或更新。
func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1           // 计算结果长度：每个字节拆分为两个半字节，加 1 个终止符
	var nibbles = make([]byte, l) // 创建目标半字节数组
	for i, b := range str {       // 遍历输入字节数组
		nibbles[i*2] = b / 16   // 高位半字节（除以 16）
		nibbles[i*2+1] = b % 16 // 低位半字节（取余 16）
	}
	nibbles[l-1] = 16 // 在末尾添加终止符 0x10
	return nibbles    // 返回 HEX 编码结果
}

// hexToKeybytes turns hex nibbles into key bytes.
// This can only be used for keys of even length.
// hexToKeybytes 将 HEX 编码的半字节数组转换为键字节数组。
// 此函数只能用于长度为偶数的键。
//
// hexToKeybytes 将 HEX 编码的半字节数组（每个半字节占 1 字节）转换为紧凑的字节数组（KEYBYTES 编码），即从内存格式转为原始键格式。
// 它是对 keybytesToHex 的逆操作，但要求输入长度为偶数（不包括终止符）。
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) { // 如果 HEX 键带有终止符
		hex = hex[:len(hex)-1] // 移除终止符
	}
	// 如果是奇数，抛出异常，因为无法将奇数个半字节合并为字节。
	if len(hex)&1 != 0 { // 如果 HEX 键长度为奇数
		panic("can't convert hex key of odd length")
	}
	key := make([]byte, len(hex)/2) // 创建目标字节数组，长度为 HEX 长度的一半
	decodeNibbles(hex, key)         // 将 HEX 半字节解码为字节
	return key                      // 返回键字节数组
}

// decodeNibbles 将半字节数组解码为字节数组。
// 将 HEX 编码的半字节数组（每个半字节占 1 字节）解码为紧凑的字节数组（每 2 个半字节合成 1 字节）。
// nibbles []byte：HEX 编码的半字节数组（例如 [0x0A, 0x0B, 0x0C, 0x0D]）。
// bytes []byte：目标字节数组，用于存储解码结果。
//
// HEX 编码：在 MPT 中，内存节点使用 HEX 编码（每个半字节 1 字节）。
// decodeNibbles 将其转换为原始字节形式（如 KEYBYTES）。
// 从内存中的 HEX 键转换为磁盘存储的紧凑格式。
func decodeNibbles(nibbles []byte, bytes []byte) {
	// ni：半字节数组索引，每次跳跃 2（处理一对半字节）。
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 { // 遍历半字节数组，每次处理两个半字节
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1] // 将两个半字节合并为一个字节
	}
	// 输入：nibbles = [0x0A, 0x0B, 0x0C, 0x0D]
	// 输出：bytes = [0xAB, 0xCD]
}

// prefixLen returns the length of the common prefix of a and b.
// prefixLen 返回两个字节数组的公共前缀长度。
// Trie 路径：在 MPT 中，键路径是字节序列，公共前缀决定分支点。
// prefixLen 用于判断键的分叉位置。
func prefixLen(a, b []byte) int {
	var i, length = 0, len(a)
	if len(b) < length { // 如果 b 较短，则使用 b 的长度
		length = len(b)
	}
	for ; i < length; i++ { // 逐字节比较
		if a[i] != b[i] { // 遇到不同字节时停止
			break
		}
	}
	return i // 返回公共前缀长度
}

// hasTerm returns whether a hex key has the terminator flag.
// hasTerm 返回 HEX 编码的键是否带有终止符标志。
// hasTerm 检查 HEX 编码的键是否带有终止符（0x10），以判断节点是否为值节点。
// HEX 终止符：在 MPT 中，0x10 表示键对应的节点是值节点（leaf node），而不是分支节点。
func hasTerm(s []byte) bool {
	return len(s) > 0 && s[len(s)-1] == 16 // 检查最后一个字节是否为 0x10
}
