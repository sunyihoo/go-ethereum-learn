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

package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/log"
)

type storedCredential struct {
	// The iv
	Iv []byte `json:"iv"`
	// The ciphertext
	CipherText []byte `json:"c"`
}

// AESEncryptedStorage is a storage type which is backed by a json-file. The json-file contains
// key-value mappings, where the keys are _not_ encrypted, only the values are.
// AESEncryptedStorage 是一种由 JSON 文件支持的存储类型。该 JSON 文件包含键值映射，
// 其中键未加密，只有值是加密的。
type AESEncryptedStorage struct {
	// File to read/write credentials
	// 用于读写凭证的文件
	filename string
	// Key stored in base64
	// 以 base64 存储的密钥
	key []byte
}

// NewAESEncryptedStorage creates a new encrypted storage backed by the given file/key
// NewAESEncryptedStorage 创建一个新的加密存储，由给定的文件和密钥支持
func NewAESEncryptedStorage(filename string, key []byte) *AESEncryptedStorage {
	return &AESEncryptedStorage{
		filename: filename,
		key:      key,
	}
}

// Put stores a value by key. 0-length keys results in noop.
// Put 通过键存储一个值。键的长度为 0 时不执行任何操作。
func (s *AESEncryptedStorage) Put(key, value string) {
	if len(key) == 0 {
		return
	}
	data, err := s.readEncryptedStorage()
	if err != nil {
		log.Warn("Failed to read encrypted storage", "err", err, "file", s.filename)
		return
	}
	ciphertext, iv, err := encrypt(s.key, []byte(value), []byte(key))
	if err != nil {
		log.Warn("Failed to encrypt entry", "err", err)
		return
	}
	encrypted := storedCredential{Iv: iv, CipherText: ciphertext}
	data[key] = encrypted
	if err = s.writeEncryptedStorage(data); err != nil {
		log.Warn("Failed to write entry", "err", err)
	}
}

// Get returns the previously stored value, or an error if it does not exist or
// key is of 0-length.
func (s *AESEncryptedStorage) Get(key string) (string, error) {
	if len(key) == 0 {
		return "", ErrZeroKey
	}
	data, err := s.readEncryptedStorage()
	if err != nil {
		log.Warn("Failed to read encrypted storage", "err", err, "file", s.filename)
		return "", err
	}
	encrypted, exist := data[key]
	if !exist {
		log.Warn("Key does not exist", "key", key)
		return "", ErrNotFound
	}
	entry, err := decrypt(s.key, encrypted.Iv, encrypted.CipherText, []byte(key))
	if err != nil {
		log.Warn("Failed to decrypt key", "key", key)
		return "", err
	}
	return string(entry), nil
}

// Del removes a key-value pair. If the key doesn't exist, the method is a noop.
func (s *AESEncryptedStorage) Del(key string) {
	data, err := s.readEncryptedStorage()
	if err != nil {
		log.Warn("Failed to read encrypted storage", "err", err, "file", s.filename)
		return
	}
	delete(data, key)
	if err = s.writeEncryptedStorage(data); err != nil {
		log.Warn("Failed to write entry", "err", err)
	}
}

// readEncryptedStorage reads the file with encrypted creds
// readEncryptedStorage 读取包含加密凭证的文件
func (s *AESEncryptedStorage) readEncryptedStorage() (map[string]storedCredential, error) {
	creds := make(map[string]storedCredential)
	raw, err := os.ReadFile(s.filename)

	if err != nil {
		if os.IsNotExist(err) {
			// Doesn't exist yet
			return creds, nil
		}
		log.Warn("Failed to read encrypted storage", "err", err, "file", s.filename)
	}
	if err = json.Unmarshal(raw, &creds); err != nil {
		log.Warn("Failed to unmarshal encrypted storage", "err", err, "file", s.filename)
		return nil, err
	}
	return creds, nil
}

// writeEncryptedStorage write the file with encrypted creds
// writeEncryptedStorage 写入包含加密凭证的文件
func (s *AESEncryptedStorage) writeEncryptedStorage(creds map[string]storedCredential) error {
	raw, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	if err = os.WriteFile(s.filename, raw, 0600); err != nil {
		return err
	}
	return nil
}

// encrypt encrypts plaintext with the given key, with additional data
// The 'additionalData' is used to place the (plaintext) KV-store key into the V,
// to prevent the possibility to alter a K, or swap two entries in the KV store with each other.
//
// encrypt 使用给定的密钥加密明文，并带有附加数据
// 'additionalData' 用于将（明文）键值存储的键放入 V 中，
// 以防止更改键 K 或在键值存储中互换两个条目。
func encrypt(key []byte, plaintext []byte, additionalData []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	//GCM 模式在以太坊中常用于需要完整性验证的场景（如 keystore），比 CTR 模式更安全。
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	// 生成一个随机 nonce（默认 12 字节），从 rand.Reader 读取，确保每次加密唯一。\
	// Nonce 的随机性防止重放攻击，在 Geth 的 keystore 中也有类似机制。
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	// 使用 Seal 方法加密 plaintext，additionalData 不加密但用于认证。
	// additionalData（这里是键）防止键值对互换或篡改，增强存储安全性。
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nonce, nil
}

func decrypt(key []byte, nonce []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
