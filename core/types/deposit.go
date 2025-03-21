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

package types

import (
	"fmt"
)

const (
	// 48（公钥）+ 32（提款凭证）+ 8（金额）+ 96（签名）+ 8（索引）= 192。
	depositRequestSize = 192 // 定义存款请求的字节长度（192 字节）
)

// DepositLogToRequest unpacks a serialized DepositEvent.
// DepositLogToRequest 解包序列化的 DepositEvent。
// 序列化的 DepositEvent 数据，预期长度为 576 字节（ABI 编码）
// 从 576 字节的 ABI 编码 DepositEvent 数据解包出 192 字节的存款请求。
// 576 字节的来源: 160 字节（5 个 32 字节偏移）+ 32（长度）+ 64（公钥）+ 64（提款凭证）+ 64（金额）+ 128（签名）+ 64（索引）= 576。
// 在以太坊 2.0（信标链）中处理存款事件，提取关键字段。
func DepositLogToRequest(data []byte) ([]byte, error) {
	if len(data) != 576 {
		return nil, fmt.Errorf("deposit wrong length: want 576, have %d", len(data))
	}

	request := make([]byte, depositRequestSize)
	const (
		pubkeyOffset         = 0                         // 公钥起始位置
		withdrawalCredOffset = pubkeyOffset + 48         // 提款凭证位置（48 字节后）
		amountOffset         = withdrawalCredOffset + 32 // 金额位置（48 + 32）
		signatureOffset      = amountOffset + 8          // 签名位置（80 + 8）
		indexOffset          = signatureOffset + 96      // 索引位置（88 + 96）
	)
	// The ABI encodes the position of dynamic elements first. Since there are 5
	// elements, skip over the positional data. The first 32 bytes of dynamic
	// elements also encode their actual length. Skip over that value too.
	// ABI 首先编码动态元素的位置。由于有 5 个元素，跳过位置数据。
	// 动态元素的第一个 32 字节还编码了它们的实际长度，也要跳过这个值。
	// ABI 编码中，前 32*5 = 160 字节是 5 个动态元素的偏移量 再加 32 字节跳过第一个动态元素的长度字段
	b := 32*5 + 32
	// PublicKey is the first element. ABI encoding pads values to 32 bytes, so
	// despite BLS public keys being length 48, the value length here is 64. Then
	// skip over the next length value.
	// PublicKey 是第一个元素。ABI 编码将值填充到 32 字节，因此尽管 BLS 公钥长度为 48 字节，
	// 这里的值长度为 64 字节。然后跳过下一个长度值。
	// 从 data[192:240] 复制 48 字节公钥。
	copy(request[pubkeyOffset:], data[b:b+48])
	b += 48 + 16 + 32
	// WithdrawalCredentials is 32 bytes. Read that value then skip over next
	// length.
	// WithdrawalCredentials 是 32 字节。读取该值，然后跳过下一个长度值。
	// copy(request[48:], data[288:320]) 复制 32 字节提款凭证。
	copy(request[withdrawalCredOffset:], data[b:b+32])
	b += 32 + 32
	// Amount is 8 bytes, but it is padded to 32. Skip over it and the next
	// length.
	// Amount 是 8 字节，但被填充到 32 字节。跳过它和下一个长度值。
	// copy(request[80:], data[352:360]) 复制 8 字节金额（填充到 32 字节）
	copy(request[amountOffset:], data[b:b+8])
	b += 8 + 24 + 32
	// Signature is 96 bytes. Skip over it and the next length.
	// Signature 是 96 字节。跳过它和下一个长度值。
	// copy(request[88:], data[416:512]) 复制 96 字节签名
	copy(request[signatureOffset:], data[b:b+96])
	b += 96 + 32
	// Index is 8 bytes.
	// copy(request[184:], data[544:552]) 复制 8 字节索引。
	copy(request[indexOffset:], data[b:b+8])
	return request, nil
}
