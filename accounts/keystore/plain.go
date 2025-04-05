// Copyright 2015 The go-ethereum Authors
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

package keystore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
)

// keyStorePlain 是一个简单的密钥存储实现，用于管理未加密的密钥文件。
type keyStorePlain struct {
	keysDirPath string // 密钥文件存储的目录路径
}

// GetKey 从指定的文件中读取密钥，并验证其地址是否匹配。
// 如果文件不存在或内容不匹配，则返回错误。
func (ks keyStorePlain) GetKey(addr common.Address, filename, auth string) (*Key, error) {
	// 打开密钥文件
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	// 解码 JSON 格式的密钥文件
	key := new(Key)
	if err := json.NewDecoder(fd).Decode(key); err != nil {
		return nil, err
	}

	// 验证密钥地址是否匹配
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have address %x, want %x", key.Address, addr)
	}
	return key, nil
}

// StoreKey 将密钥序列化为 JSON 格式并保存到指定文件中。
func (ks keyStorePlain) StoreKey(filename string, key *Key, auth string) error {
	// 将密钥序列化为 JSON 格式
	content, err := json.Marshal(key)
	if err != nil {
		return err
	}
	// 将序列化后的密钥写入文件
	return writeKeyFile(filename, content)
}

// JoinPath 将文件名与密钥存储目录路径拼接，生成完整的文件路径。
func (ks keyStorePlain) JoinPath(filename string) string {
	// 如果文件名已经是绝对路径，则直接返回
	if filepath.IsAbs(filename) {
		return filename
	}
	// 否则将文件名与密钥存储目录路径拼接
	return filepath.Join(ks.keysDirPath, filename)
}
