// Copyright 2019 The go-ethereum Authors
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

// Package fourbyte contains the 4byte database.
package fourbyte

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed 4byte.json
var embeddedJSON []byte

// Database is a 4byte database with the possibility of maintaining an immutable
// set (embedded) into the process and a mutable set (loaded and written to file).
//
// Database 是一个 4byte 数据库，可以维护一个嵌入进程的不可变集合（embedded）
// 和一个可变集合（加载并写入文件）。
type Database struct {
	embedded   map[string]string // 存储不可变的 4 字节签名及其描述（例如方法签名），嵌入到进程中。
	custom     map[string]string // 存储可变的 4 字节签名及其描述，可以从文件加载或写入。 允许用户自定义签名数据库，扩展对非标准合约的支持。
	customPath string            // 可变集合的存储路径，用于持久化 custom 数据。 持久化存储便于在不同会话中重用自定义签名。
}

// newEmpty exists for testing purposes.
// newEmpty 存在用于测试目的。
func newEmpty() *Database {
	return &Database{
		embedded: make(map[string]string),
		custom:   make(map[string]string),
	}
}

// New loads the standard signature database embedded in the package.
// New 加载包中嵌入的标准签名数据库。
func New() (*Database, error) {
	return NewWithFile("")
}

// NewFromFile loads signature database from file, and errors if the file is not
// valid JSON. The constructor does no other validation of contents. This method
// does not load the embedded 4byte database.
//
// The provided path will be used to write new values into if they are submitted
// via the API.
//
// NewFromFile 从文件中加载签名数据库，如果文件不是有效的 JSON 则返回错误。
// 该构造函数不对内容进行其他验证。此方法不会加载嵌入的 4byte 数据库。
//
// 提供的路径将用于写入通过 API 提交的新值。
func NewFromFile(path string) (*Database, error) {
	raw, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	db := newEmpty()
	if err := json.NewDecoder(raw).Decode(&db.embedded); err != nil {
		return nil, err
	}
	return db, nil
}

// NewWithFile loads both the standard signature database (embedded resource
// file) as well as a custom database. The latter will be used to write new
// values into if they are submitted via the API.
//
// NewWithFile 加载标准签名数据库（嵌入的资源文件）以及自定义数据库。
// 后者将用于写入通过 API 提交的新值。
func NewWithFile(path string) (*Database, error) {
	db := &Database{make(map[string]string), make(map[string]string), path}
	db.customPath = path

	if err := json.Unmarshal(embeddedJSON, &db.embedded); err != nil {
		return nil, err
	}
	// Custom file may not exist. Will be created during save, if needed.
	// 自定义文件可能不存在。如果需要，将在保存时创建。
	if _, err := os.Stat(path); err == nil {
		var blob []byte
		if blob, err = os.ReadFile(path); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(blob, &db.custom); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Size returns the number of 4byte entries in the embedded and custom datasets.
// Size 返回嵌入和自定义数据集中 4byte 条目的数量。
func (db *Database) Size() (int, int) {
	return len(db.embedded), len(db.custom)
}

// Selector checks the given 4byte ID against the known ABI methods.
//
// This method does not validate the match, it's assumed the caller will do.
//
// Selector 检查给定的 4byte ID 是否存在于已知的 ABI 方法中。
//
// 此方法不对匹配进行验证，假设调用者会这样做。
func (db *Database) Selector(id []byte) (string, error) {
	if len(id) < 4 {
		return "", fmt.Errorf("expected 4-byte id, got %d", len(id))
	}
	sig := hex.EncodeToString(id[:4])
	if selector, exists := db.embedded[sig]; exists {
		return selector, nil
	}
	if selector, exists := db.custom[sig]; exists {
		return selector, nil
	}
	return "", fmt.Errorf("signature %v not found", sig)
}

// AddSelector inserts a new 4byte entry into the database. If custom database
// saving is enabled, the new dataset is also persisted to disk.
//
// Node, this method does _not_ validate the correctness of the data. It assumes
// the caller has already done so.
//
// AddSelector 将一个新的 4byte 条目插入数据库。如果启用了自定义数据库保存，
// 新数据集也会持久化到磁盘。
//
// 注意，此方法不对数据的正确性进行验证，假设调用者已完成验证。
func (db *Database) AddSelector(selector string, data []byte) error {
	// If the selector is already known, skip duplicating it
	// 如果选择器已知，跳过重复添加
	if len(data) < 4 {
		return nil
	}
	if _, err := db.Selector(data[:4]); err == nil {
		return nil
	}
	// Inject the custom selector into the database and persist if needed
	// 如果启用了自定义数据库保存，新数据集也会持久化到磁盘。
	db.custom[hex.EncodeToString(data[:4])] = selector
	if db.customPath == "" {
		return nil
	}
	blob, err := json.Marshal(db.custom)
	if err != nil {
		return err
	}
	return os.WriteFile(db.customPath, blob, 0600)
}
