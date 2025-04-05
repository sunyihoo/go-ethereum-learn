// Copyright 2023 The go-ethereum Authors
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

package light

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// canonicalStore stores instances of the given type in a database and caches
// them in memory, associated with a continuous range of period numbers.
// Note: canonicalStore is not thread safe and it is the caller's responsibility
// to avoid concurrent access.
// canonicalStore 在数据库中存储给定类型的实例，并在内存中缓存它们，与连续的周期范围相关联。
// 注意：canonicalStore 不是线程安全的，调用者需负责避免并发访问。
type canonicalStore[T any] struct {
	keyPrefix []byte                // 数据库键的前缀
	periods   periodRange           // 存储的周期范围
	cache     *lru.Cache[uint64, T] // 缓存，用于加速访问
}

// newCanonicalStore creates a new canonicalStore and loads all keys associated
// with the keyPrefix in order to determine the ranges available in the database.
// newCanonicalStore 创建一个新的 canonicalStore，并加载所有与 keyPrefix 关联的键，
// 以确定数据库中可用的周期范围。
func newCanonicalStore[T any](db ethdb.Iteratee, keyPrefix []byte) (*canonicalStore[T], error) {
	cs := &canonicalStore[T]{
		keyPrefix: keyPrefix,
		cache:     lru.NewCache[uint64, T](100), // 初始化缓存，容量为 100
	}
	var (
		iter  = db.NewIterator(keyPrefix, nil) // 创建迭代器以遍历数据库中的键值对
		kl    = len(keyPrefix)                 // 键前缀长度
		first = true                           // 标志是否是第一个键
	)
	defer iter.Release()

	for iter.Next() {
		if len(iter.Key()) != kl+8 {
			log.Warn("Invalid key length in the canonical chain database", "key", fmt.Sprintf("%#x", iter.Key()))
			continue
		}
		period := binary.BigEndian.Uint64(iter.Key()[kl : kl+8]) // 解码键中的周期号
		if first {
			cs.periods.Start = period // 设置起始周期
		} else if cs.periods.End != period {
			return nil, fmt.Errorf("gap in the canonical chain database between periods %d and %d", cs.periods.End, period-1)
		}
		first = false
		cs.periods.End = period + 1 // 更新结束周期
	}
	return cs, nil
}

// databaseKey returns the database key belonging to the given period.
// databaseKey 返回属于给定周期的数据库键。
func (cs *canonicalStore[T]) databaseKey(period uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte{}, cs.keyPrefix...), period) // 将周期号编码为键
}

// add adds the given item to the database. It also ensures that the range remains
// continuous. Can be used either with a batch or database backend.
// add 将给定的项添加到数据库中。它还确保范围保持连续。可以与批量操作或数据库后端一起使用。
func (cs *canonicalStore[T]) add(backend ethdb.KeyValueWriter, period uint64, value T) error {
	if !cs.periods.canExpand(period) {
		return fmt.Errorf("period expansion is not allowed, first: %d, next: %d, period: %d", cs.periods.Start, cs.periods.End, period)
	}
	enc, err := rlp.EncodeToBytes(value) // 使用 RLP 编码将值序列化为字节数组
	if err != nil {
		return err
	}
	if err := backend.Put(cs.databaseKey(period), enc); err != nil { // 将编码后的值存储到数据库中
		return err
	}
	cs.cache.Add(period, value) // 将值添加到缓存中
	cs.periods.expand(period)   // 扩展周期范围
	return nil
}

// deleteFrom removes items starting from the given period.
// deleteFrom 从给定周期开始删除项。
func (cs *canonicalStore[T]) deleteFrom(db ethdb.KeyValueWriter, fromPeriod uint64) (deleted periodRange) {
	keepRange, deleteRange := cs.periods.split(fromPeriod) // 拆分周期范围
	deleteRange.each(func(period uint64) {
		db.Delete(cs.databaseKey(period)) // 删除数据库中的键值对
		cs.cache.Remove(period)           // 从缓存中移除对应的值
	})
	cs.periods = keepRange // 更新周期范围
	return deleteRange     // 返回被删除的周期范围
}

// get returns the item at the given period or the null value of the given type
// if no item is present.
// get 返回给定周期的项。如果没有该项，则返回该类型的零值。
func (cs *canonicalStore[T]) get(backend ethdb.KeyValueReader, period uint64) (T, bool) {
	var null, value T
	if !cs.periods.contains(period) {
		return null, false // 如果周期不在范围内，返回零值和 false
	}
	if value, ok := cs.cache.Get(period); ok {
		return value, true // 如果缓存命中，直接返回值
	}
	enc, err := backend.Get(cs.databaseKey(period)) // 从数据库中获取编码值
	if err != nil {
		log.Error("Canonical store value not found", "period", period, "start", cs.periods.Start, "end", cs.periods.End)
		return null, false
	}
	if err := rlp.DecodeBytes(enc, &value); err != nil { // 使用 RLP 解码字节数组
		log.Error("Error decoding canonical store value", "error", err)
		return null, false
	}
	cs.cache.Add(period, value) // 将解码后的值添加到缓存中
	return value, true          // 返回值和 true
}
