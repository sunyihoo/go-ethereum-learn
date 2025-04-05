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

package scwallet

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// commandAPDU represents an application data unit sent to a smartcard.
// commandAPDU 表示发送到智能卡的应用数据单元。
type commandAPDU struct {
	Cla, Ins, P1, P2 uint8  // Class, Instruction, Parameter 1, Parameter 2
	Data             []byte // Command data 命令数据
	Le               uint8  // Command data length 命令数据长度
}

// serialize serializes a command APDU.
// serialize 序列化一个命令 APDU。
func (ca commandAPDU) serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// 写入 Class 字段
	if err := binary.Write(buf, binary.BigEndian, ca.Cla); err != nil {
		return nil, err
	}
	// 写入 Instruction 字段
	if err := binary.Write(buf, binary.BigEndian, ca.Ins); err != nil {
		return nil, err
	}
	// 写入 Parameter 1 字段
	if err := binary.Write(buf, binary.BigEndian, ca.P1); err != nil {
		return nil, err
	}
	// 写入 Parameter 2 字段
	if err := binary.Write(buf, binary.BigEndian, ca.P2); err != nil {
		return nil, err
	}
	// 如果存在命令数据，写入数据长度和数据内容
	if len(ca.Data) > 0 {
		if err := binary.Write(buf, binary.BigEndian, uint8(len(ca.Data))); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, ca.Data); err != nil {
			return nil, err
		}
	}
	// 写入命令数据长度字段
	if err := binary.Write(buf, binary.BigEndian, ca.Le); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// responseAPDU represents an application data unit received from a smart card.
// responseAPDU 表示从智能卡接收到的应用数据单元。
type responseAPDU struct {
	Data     []byte // response data 响应数据
	Sw1, Sw2 uint8  // status words 1 and 2 状态字 1 和状态字 2
}

// deserialize deserializes a response APDU.
// deserialize 反序列化一个响应 APDU。
func (ra *responseAPDU) deserialize(data []byte) error {
	// 检查数据长度是否足够
	if len(data) < 2 {
		return fmt.Errorf("can not deserialize data: payload too short (%d < 2)", len(data))
	}

	// 提取响应数据（去掉最后两个字节的状态字）
	ra.Data = make([]byte, len(data)-2)

	buf := bytes.NewReader(data)
	// 读取响应数据
	if err := binary.Read(buf, binary.BigEndian, &ra.Data); err != nil {
		return err
	}
	// 读取状态字 1
	if err := binary.Read(buf, binary.BigEndian, &ra.Sw1); err != nil {
		return err
	}
	// 读取状态字 2
	if err := binary.Read(buf, binary.BigEndian, &ra.Sw2); err != nil {
		return err
	}
	return nil
}
