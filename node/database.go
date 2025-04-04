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

package node

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/leveldb"
	"github.com/ethereum/go-ethereum/ethdb/pebble"
	"github.com/ethereum/go-ethereum/log"
)

// openOptions contains the options to apply when opening a database.
// OBS: If AncientsDirectory is empty, it indicates that no freezer is to be used.
// openOptions 包含打开数据库时要应用的选项。
// 注意：如果 AncientsDirectory 为空，则表示不使用冷冻存储（freezer）。
type openOptions struct {
	Type              string // "leveldb" | "pebble" // 数据库类型，"leveldb" 或 "pebble"
	Directory         string // the datadir // 数据目录
	AncientsDirectory string // the ancients-dir // 冷冻存储目录
	Namespace         string // the namespace for database relevant metrics // 数据库相关指标的命名空间
	Cache             int    // the capacity(in megabytes) of the data caching // 数据缓存的容量（单位：兆字节）
	Handles           int    // number of files to be open simultaneously // 同时打开的文件数量
	ReadOnly          bool   // 是否只读
}

// openDatabase opens both a disk-based key-value database such as leveldb or pebble, but also
// integrates it with a freezer database -- if the AncientDir option has been
// set on the provided OpenOptions.
// The passed o.AncientDir indicates the path of root ancient directory where
// the chain freezer can be opened.
// openDatabase 打开基于磁盘的键值数据库（如 leveldb 或 pebble），
// 如果在提供的 OpenOptions 中设置了 AncientDir 选项，还会集成冷冻数据库。
// 传递的 o.AncientDir 表示链冷冻存储可以打开的根目录路径。
func openDatabase(o openOptions) (ethdb.Database, error) {
	kvdb, err := openKeyValueDatabase(o)
	if err != nil {
		return nil, err
	}
	if len(o.AncientsDirectory) == 0 {
		return kvdb, nil
	}
	frdb, err := rawdb.NewDatabaseWithFreezer(kvdb, o.AncientsDirectory, o.Namespace, o.ReadOnly)
	if err != nil {
		kvdb.Close()
		return nil, err
	}
	return frdb, nil
}

// openKeyValueDatabase opens a disk-based key-value database, e.g. leveldb or pebble.
//
// openKeyValueDatabase 打开基于磁盘的键值数据库，例如 leveldb 或 pebble。
//
//	                      type == null          type != null
//	                   +----------------------------------------
//	db is non-existent |  pebble default  |  specified type
//	db is existent     |  from db         |  specified type (if compatible)
func openKeyValueDatabase(o openOptions) (ethdb.Database, error) {
	// Reject any unsupported database type
	// 拒绝任何不支持的数据库类型
	if len(o.Type) != 0 && o.Type != rawdb.DBLeveldb && o.Type != rawdb.DBPebble {
		return nil, fmt.Errorf("unknown db.engine %v", o.Type)
	}
	// Retrieve any pre-existing database's type and use that or the requested one
	// as long as there's no conflict between the two types
	// 获取任何预先存在的数据库类型，并使用该类型或请求的类型，只要两者之间没有冲突
	existingDb := rawdb.PreexistingDatabase(o.Directory)
	if len(existingDb) != 0 && len(o.Type) != 0 && o.Type != existingDb {
		return nil, fmt.Errorf("db.engine choice was %v but found pre-existing %v database in specified data directory", o.Type, existingDb)
	}
	if o.Type == rawdb.DBPebble || existingDb == rawdb.DBPebble {
		log.Info("Using pebble as the backing database")
		return newPebbleDBDatabase(o.Directory, o.Cache, o.Handles, o.Namespace, o.ReadOnly)
	}
	if o.Type == rawdb.DBLeveldb || existingDb == rawdb.DBLeveldb {
		log.Info("Using leveldb as the backing database")
		return newLevelDBDatabase(o.Directory, o.Cache, o.Handles, o.Namespace, o.ReadOnly)
	}
	// No pre-existing database, no user-requested one either. Default to Pebble.
	// 没有预先存在的数据库，用户也没有请求特定类型，默认使用 Pebble。
	log.Info("Defaulting to pebble as the backing database")
	return newPebbleDBDatabase(o.Directory, o.Cache, o.Handles, o.Namespace, o.ReadOnly)
}

// newLevelDBDatabase creates a persistent key-value database without a freezer
// moving immutable chain segments into cold storage.
// newLevelDBDatabase 创建一个持久化的键值数据库，不使用冷冻存储将不可变的链段移到冷存储。
func newLevelDBDatabase(file string, cache int, handles int, namespace string, readonly bool) (ethdb.Database, error) {
	db, err := leveldb.New(file, cache, handles, namespace, readonly)
	if err != nil {
		return nil, err
	}
	log.Info("Using LevelDB as the backing database")
	return rawdb.NewDatabase(db), nil
}

// newPebbleDBDatabase creates a persistent key-value database without a freezer
// moving immutable chain segments into cold storage.
// newPebbleDBDatabase 创建一个持久化的键值数据库，不使用冷冻存储将不可变的链段移到冷存储。
func newPebbleDBDatabase(file string, cache int, handles int, namespace string, readonly bool) (ethdb.Database, error) {
	db, err := pebble.New(file, cache, handles, namespace, readonly)
	if err != nil {
		return nil, err
	}
	return rawdb.NewDatabase(db), nil
}
