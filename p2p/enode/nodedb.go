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

package enode

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// Keys in the node database.
// 节点数据库中的键。
const (
	dbVersionKey   = "version" // Version of the database to flush if changes // 数据库版本，如果发生变化则刷新
	dbNodePrefix   = "n:"      // Identifier to prefix node entries with // 用于前缀节点条目的标识符
	dbLocalPrefix  = "local:"  // 前缀本地信息 // Prefix for local information
	dbDiscoverRoot = "v4"      // Discovery v4 根 // Discovery v4 root
	dbDiscv5Root   = "v5"      // Discovery v5 根 // Discovery v5 root

	// These fields are stored per ID and IP, the full key is "n:<ID>:v4:<IP>:findfail".
	// Use nodeItemKey to create those keys.
	// 这些字段按 ID 和 IP 存储，完整键为 "n:<ID>:v4:<IP>:findfail"。
	// 使用 nodeItemKey 创建这些键。
	dbNodeFindFails = "findfail" // 查找失败计数 // Find failure count
	dbNodePing      = "lastping" // 上次 ping 时间 // Last ping time
	dbNodePong      = "lastpong" // 上次 pong 时间 // Last pong time
	dbNodeSeq       = "seq"      // 记录序列号 // Record sequence number

	// Local information is keyed by ID only, the full key is "local:<ID>:seq".
	// Use localItemKey to create those keys.
	// 本地信息仅按 ID 键入，完整键为 "local:<ID>:seq"。
	// 使用 localItemKey 创建这些键。
	dbLocalSeq = "seq" // 本地序列号 // Local sequence number
)

const (
	dbNodeExpiration = 24 * time.Hour // Time after which an unseen node should be dropped. // 未见节点应被删除的时间。
	dbCleanupCycle   = time.Hour      // Time period for running the expiration task. // 执行过期任务的时间周期。
	dbVersion        = 9              // 数据库版本 // Database version
)

var (
	errInvalidIP = errors.New("invalid IP") // 无效 IP 错误 // Invalid IP error
)

var zeroIP = netip.IPv6Unspecified() // 零 IP，表示未指定 // Zero IP, indicates unspecified

// DB is the node database, storing previously seen nodes and any collected metadata about
// them for QoS purposes.
// DB 是节点数据库，存储之前见过的节点及其为 QoS 目的收集的元数据。
type DB struct {
	lvl    *leveldb.DB   // Interface to the database itself // 数据库本身的接口
	runner sync.Once     // Ensures we can start at most one expirer // 确保最多启动一个过期器
	quit   chan struct{} // Channel to signal the expiring thread to stop // 信号通道，用于停止过期线程
}

// OpenDB opens a node database for storing and retrieving infos about known peers in the
// network. If no path is given an in-memory, temporary database is constructed.
// OpenDB 打开一个节点数据库，用于存储和检索网络中已知对等节点的信息。如果未给定路径，则构造内存中的临时数据库。
func OpenDB(path string) (*DB, error) {
	if path == "" { // 如果路径为空 // If path is empty
		return newMemoryDB() // 创建内存数据库 // Create in-memory database
	}
	return newPersistentDB(path) // 创建持久化数据库 // Create persistent database
}

// newMemoryDB creates a new in-memory node database without a persistent backend.
// newMemoryDB 创建一个新的无持久化后端的内存节点数据库。
func newMemoryDB() (*DB, error) {
	db, err := leveldb.Open(storage.NewMemStorage(), nil) // 打开内存存储 // Open in-memory storage
	if err != nil {
		return nil, err
	}
	return &DB{lvl: db, quit: make(chan struct{})}, nil // 返回数据库实例 // Return database instance
}

// newPersistentDB creates/opens a leveldb backed persistent node database,
// also flushing its contents in case of a version mismatch.
// newPersistentDB 创建/打开一个由 leveldb 支持的持久化节点数据库，如果版本不匹配则刷新其内容。
func newPersistentDB(path string) (*DB, error) {
	opts := &opt.Options{OpenFilesCacheCapacity: 5}                // 设置选项 // Set options
	db, err := leveldb.OpenFile(path, opts)                        // 打开文件数据库 // Open file database
	if _, iscorrupted := err.(*errors.ErrCorrupted); iscorrupted { // 如果数据库损坏 // If database is corrupted
		db, err = leveldb.RecoverFile(path, nil) // 尝试恢复 // Attempt recovery
	}
	if err != nil {
		return nil, err
	}
	// The nodes contained in the cache correspond to a certain protocol version.
	// Flush all nodes if the version doesn't match.
	// 缓存中的节点对应于特定协议版本。如果版本不匹配，则刷新所有节点。
	currentVer := make([]byte, binary.MaxVarintLen64)                        // 创建版本字节 // Create version bytes
	currentVer = currentVer[:binary.PutVarint(currentVer, int64(dbVersion))] // 存储当前版本 // Store current version

	blob, err := db.Get([]byte(dbVersionKey), nil) // 获取存储的版本 // Get stored version
	switch err {
	case leveldb.ErrNotFound: // 如果未找到版本 // If version not found
		// Version not found (i.e. empty cache), insert it
		// 未找到版本（即空缓存），插入版本
		if err := db.Put([]byte(dbVersionKey), currentVer, nil); err != nil { // 写入版本 // Write version
			db.Close()
			return nil, err
		}

	case nil: // 如果版本存在 // If version exists
		// Version present, flush if different
		// 版本存在，如果不同则刷新
		if !bytes.Equal(blob, currentVer) { // 如果版本不匹配 // If versions don't match
			db.Close()
			if err = os.RemoveAll(path); err != nil { // 删除数据库文件 // Delete database files
				return nil, err
			}
			return newPersistentDB(path) // 重新创建数据库 // Recreate database
		}
	}
	return &DB{lvl: db, quit: make(chan struct{})}, nil // 返回数据库实例 // Return database instance
}

// nodeKey returns the database key for a node record.
// nodeKey 返回节点记录的数据库键。
func nodeKey(id ID) []byte {
	key := append([]byte(dbNodePrefix), id[:]...) // 添加节点前缀和 ID // Append node prefix and ID
	key = append(key, ':')                        // 添加分隔符 // Append separator
	key = append(key, dbDiscoverRoot...)          // 添加发现根 // Append discovery root
	return key
}

// splitNodeKey returns the node ID of a key created by nodeKey.
// splitNodeKey 返回由 nodeKey 创建的键的节点 ID。
func splitNodeKey(key []byte) (id ID, rest []byte) {
	if !bytes.HasPrefix(key, []byte(dbNodePrefix)) { // 如果没有节点前缀 // If no node prefix
		return ID{}, nil
	}
	item := key[len(dbNodePrefix):] // 提取前缀后的部分 // Extract part after prefix
	copy(id[:], item[:len(id)])     // 复制 ID // Copy ID
	return id, item[len(id)+1:]     // 返回 ID 和剩余部分 // Return ID and remainder
}

// nodeItemKey returns the database key for a node metadata field.
// nodeItemKey 返回节点元数据字段的数据库键。
func nodeItemKey(id ID, ip netip.Addr, field string) []byte {
	if !ip.IsValid() {
		panic("invalid IP")
	}
	ip16 := ip.As16()                                                             // 转换为 16 字节格式 // Convert to 16-byte format
	return bytes.Join([][]byte{nodeKey(id), ip16[:], []byte(field)}, []byte{':'}) // 连接键部分 // Join key parts
}

// splitNodeItemKey returns the components of a key created by nodeItemKey.
// splitNodeItemKey 返回由 nodeItemKey 创建的键的组成部分。
func splitNodeItemKey(key []byte) (id ID, ip netip.Addr, field string) {
	id, key = splitNodeKey(key) // 分离 ID // Split ID
	// Skip discover root.
	// 跳过发现根。
	if string(key) == dbDiscoverRoot {
		return id, netip.Addr{}, ""
	}
	key = key[len(dbDiscoverRoot)+1:] // 移除发现根 // Remove discovery root
	// Split out the IP.
	// 分离 IP。
	ip, _ = netip.AddrFromSlice(key[:16]) // 提取 IP // Extract IP
	key = key[16+1:]                      // 移除 IP 和分隔符 // Remove IP and separator
	// Field is the remainder of key.
	// 字段是键的剩余部分。
	field = string(key)
	return id, ip, field
}

func v5Key(id ID, ip netip.Addr, field string) []byte {
	ip16 := ip.As16() // 转换为 16 字节格式 // Convert to 16-byte format
	return bytes.Join([][]byte{ // 连接键部分 // Join key parts
		[]byte(dbNodePrefix),
		id[:],
		[]byte(dbDiscv5Root),
		ip16[:],
		[]byte(field),
	}, []byte{':'})
}

// localItemKey returns the key of a local node item.
// localItemKey 返回本地节点项的键。
func localItemKey(id ID, field string) []byte {
	key := append([]byte(dbLocalPrefix), id[:]...) // 添加本地前缀和 ID // Append local prefix and ID
	key = append(key, ':')                         // 添加分隔符 // Append separator
	key = append(key, field...)                    // 添加字段 // Append field
	return key
}

// fetchInt64 retrieves an integer associated with a particular key.
// fetchInt64 检索与特定键关联的整数。
func (db *DB) fetchInt64(key []byte) int64 {
	blob, err := db.lvl.Get(key, nil) // 获取值 // Get value
	if err != nil {
		return 0
	}
	val, read := binary.Varint(blob) // 解析变长整数 // Parse varint
	if read <= 0 {
		return 0
	}
	return val
}

// storeInt64 stores an integer in the given key.
// storeInt64 将整数存储在给定键中。
func (db *DB) storeInt64(key []byte, n int64) error {
	blob := make([]byte, binary.MaxVarintLen64) // 创建缓冲区 // Create buffer
	blob = blob[:binary.PutVarint(blob, n)]     // 存储整数 // Store integer
	return db.lvl.Put(key, blob, nil)           // 写入数据库 // Write to database
}

// fetchUint64 retrieves an integer associated with a particular key.
// fetchUint64 检索与特定键关联的无符号整数。
func (db *DB) fetchUint64(key []byte) uint64 {
	blob, err := db.lvl.Get(key, nil) // 获取值 // Get value
	if err != nil {
		return 0
	}
	val, _ := binary.Uvarint(blob) // 解析无符号变长整数 // Parse unsigned varint
	return val
}

// storeUint64 stores an integer in the given key.
// storeUint64 将无符号整数存储在给定键中。
func (db *DB) storeUint64(key []byte, n uint64) error {
	blob := make([]byte, binary.MaxVarintLen64) // 创建缓冲区 // Create buffer
	blob = blob[:binary.PutUvarint(blob, n)]    // 存储无符号整数 // Store unsigned integer
	return db.lvl.Put(key, blob, nil)           // 写入数据库 // Write to database
}

// Node retrieves a node with a given id from the database.
// Node 从数据库中检索具有给定 ID 的节点。
func (db *DB) Node(id ID) *Node {
	blob, err := db.lvl.Get(nodeKey(id), nil) // 获取节点数据 // Get node data
	if err != nil {
		return nil
	}
	return mustDecodeNode(id[:], blob) // 解码并返回节点 // Decode and return node
}

func mustDecodeNode(id, data []byte) *Node {
	var r enr.Record                                  // 创建记录 // Create record
	if err := rlp.DecodeBytes(data, &r); err != nil { // 解码 RLP 数据 // Decode RLP data
		panic(fmt.Errorf("p2p/enode: can't decode node %x in DB: %v", id, err))
	}
	if len(id) != len(ID{}) { // 检查 ID 长度 // Check ID length
		panic(fmt.Errorf("invalid id length %d", len(id)))
	}
	return newNodeWithID(&r, ID(id)) // 创建并返回节点 // Create and return node
}

// UpdateNode inserts - potentially overwriting - a node into the peer database.
// UpdateNode 将节点插入对等数据库，可能会覆盖现有节点。
func (db *DB) UpdateNode(node *Node) error {
	if node.Seq() < db.NodeSeq(node.ID()) { // 如果序列号较低，忽略 // If sequence number is lower, ignore
		return nil
	}
	blob, err := rlp.EncodeToBytes(&node.r) // 编码节点记录 // Encode node record
	if err != nil {
		return err
	}
	if err := db.lvl.Put(nodeKey(node.ID()), blob, nil); err != nil { // 写入节点数据 // Write node data
		return err
	}
	return db.storeUint64(nodeItemKey(node.ID(), zeroIP, dbNodeSeq), node.Seq()) // 存储序列号 // Store sequence number
}

// NodeSeq returns the stored record sequence number of the given node.
// NodeSeq 返回给定节点的存储记录序列号。
func (db *DB) NodeSeq(id ID) uint64 {
	return db.fetchUint64(nodeItemKey(id, zeroIP, dbNodeSeq)) // 获取序列号 // Fetch sequence number
}

// Resolve returns the stored record of the node if it has a larger sequence
// number than n.
// Resolve 如果存储的节点记录序列号大于 n，则返回存储记录。
func (db *DB) Resolve(n *Node) *Node {
	if n.Seq() > db.NodeSeq(n.ID()) { // 如果传入的序列号更高 // If input sequence number is higher
		return n
	}
	return db.Node(n.ID()) // 返回数据库中的节点 // Return node from database
}

// DeleteNode deletes all information associated with a node.
// DeleteNode 删除与节点关联的所有信息。
func (db *DB) DeleteNode(id ID) {
	deleteRange(db.lvl, nodeKey(id)) // 删除节点相关数据 // Delete node-related data
}

func deleteRange(db *leveldb.DB, prefix []byte) {
	it := db.NewIterator(util.BytesPrefix(prefix), nil) // 创建迭代器 // Create iterator
	defer it.Release()
	for it.Next() { // 遍历并删除 // Iterate and delete
		db.Delete(it.Key(), nil)
	}
}

// ensureExpirer is a small helper method ensuring that the data expiration
// mechanism is running. If the expiration goroutine is already running, this
// method simply returns.
//
// The goal is to start the data evacuation only after the network successfully
// bootstrapped itself (to prevent dumping potentially useful seed nodes). Since
// it would require significant overhead to exactly trace the first successful
// convergence, it's simpler to "ensure" the correct state when an appropriate
// condition occurs (i.e. a successful bonding), and discard further events.
// ensureExpirer 是一个小型辅助方法，确保数据过期机制运行。如果过期 goroutine 已在运行，此方法仅返回。
//
// 目标是在网络成功自举后才开始数据清理（以防止丢弃可能有用的种子节点）。
// 由于精确追踪第一次成功汇聚需要大量开销，更简单的方法是在适当条件发生时（即成功绑定）“确保”正确状态，并丢弃后续事件。
func (db *DB) ensureExpirer() {
	db.runner.Do(func() { go db.expirer() }) // 确保只启动一次过期器 // Ensure expirer starts only once
}

// expirer should be started in a go routine, and is responsible for looping ad
// infinitum and dropping stale data from the database.
// expirer 应在 goroutine 中启动，负责无限循环并从数据库中删除过时数据。
func (db *DB) expirer() {
	tick := time.NewTicker(dbCleanupCycle) // 创建定时器 // Create ticker
	defer tick.Stop()
	for {
		select { // 选择操作 // Select operation
		case <-tick.C: // 定时触发 // Timer tick
			db.expireNodes() // 执行过期清理 // Perform expiration cleanup
		case <-db.quit: // 退出信号 // Quit signal
			return
		}
	}
}

// expireNodes iterates over the database and deletes all nodes that have not
// been seen (i.e. received a pong from) for some time.
// expireNodes 遍历数据库并删除一段时间内未见（即未收到 pong）的所有节点。
func (db *DB) expireNodes() {
	it := db.lvl.NewIterator(util.BytesPrefix([]byte(dbNodePrefix)), nil) // 创建迭代器 // Create iterator
	defer it.Release()
	if !it.Next() { // 如果没有数据，返回 // If no data, return
		return
	}

	var (
		threshold    = time.Now().Add(-dbNodeExpiration).Unix() // 过期阈值 // Expiration threshold
		youngestPong int64                                      // 最新的 pong 时间 // Youngest pong time
		atEnd        = false                                    // 是否到达末尾 // Whether at end
	)
	for !atEnd { // 遍历所有节点 // Iterate all nodes
		id, ip, field := splitNodeItemKey(it.Key()) // 分解键 // Split key
		if field == dbNodePong {                    // 如果是 pong 字段 // If pong field
			time, _ := binary.Varint(it.Value()) // 获取时间 // Get time
			if time > youngestPong {             // 更新最新 pong 时间 // Update youngest pong time
				youngestPong = time
			}
			if time < threshold { // 如果时间早于阈值 // If time is before threshold
				// Last pong from this IP older than threshold, remove fields belonging to it.
				// 此 IP 的最后 pong 早于阈值，移除其相关字段。
				deleteRange(db.lvl, nodeItemKey(id, ip, ""))
			}
		}
		atEnd = !it.Next()                  // 检查是否结束 // Check if ended
		nextID, _ := splitNodeKey(it.Key()) // 获取下一个 ID // Get next ID
		if atEnd || nextID != id {          // 如果到达末尾或切换 ID // If at end or ID changes
			// We've moved beyond the last entry of the current ID.
			// Remove everything if there was no recent enough pong.
			// 已超出当前 ID 的最后条目。如果没有足够近的 pong，则移除所有内容。
			if youngestPong > 0 && youngestPong < threshold {
				deleteRange(db.lvl, nodeKey(id))
			}
			youngestPong = 0 // 重置 pong 时间 // Reset pong time
		}
	}
}

// LastPingReceived retrieves the time of the last ping packet received from
// a remote node.
// LastPingReceived 检索从远程节点接收的最后 ping 数据包的时间。
func (db *DB) LastPingReceived(id ID, ip netip.Addr) time.Time {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return time.Time{}
	}
	return time.Unix(db.fetchInt64(nodeItemKey(id, ip, dbNodePing)), 0) // 返回时间 // Return time
}

// UpdateLastPingReceived updates the last time we tried contacting a remote node.
// UpdateLastPingReceived 更新我们尝试联系远程节点的最后时间。
func (db *DB) UpdateLastPingReceived(id ID, ip netip.Addr, instance time.Time) error {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodePing), instance.Unix()) // 存储时间 // Store time
}

// LastPongReceived retrieves the time of the last successful pong from remote node.
// LastPongReceived 检索从远程节点成功接收的最后 pong 的时间。
func (db *DB) LastPongReceived(id ID, ip netip.Addr) time.Time {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return time.Time{}
	}
	// Launch expirer
	// 启动过期器
	db.ensureExpirer()
	return time.Unix(db.fetchInt64(nodeItemKey(id, ip, dbNodePong)), 0) // 返回时间 // Return time
}

// UpdateLastPongReceived updates the last pong time of a node.
// UpdateLastPongReceived 更新节点的最后 pong 时间。
func (db *DB) UpdateLastPongReceived(id ID, ip netip.Addr, instance time.Time) error {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodePong), instance.Unix()) // 存储时间 // Store time
}

// FindFails retrieves the number of findnode failures since bonding.
// FindFails 检索自绑定以来的 findnode 失败次数。
func (db *DB) FindFails(id ID, ip netip.Addr) int {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return 0
	}
	return int(db.fetchInt64(nodeItemKey(id, ip, dbNodeFindFails))) // 返回失败次数 // Return failure count
}

// UpdateFindFails updates the number of findnode failures since bonding.
// UpdateFindFails 更新自绑定以来的 findnode 失败次数。
func (db *DB) UpdateFindFails(id ID, ip netip.Addr, fails int) error {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return errInvalidIP
	}
	return db.storeInt64(nodeItemKey(id, ip, dbNodeFindFails), int64(fails)) // 存储失败次数 // Store failure count
}

// FindFailsV5 retrieves the discv5 findnode failure counter.
// FindFailsV5 检索 discv5 findnode 失败计数器。
func (db *DB) FindFailsV5(id ID, ip netip.Addr) int {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return 0
	}
	return int(db.fetchInt64(v5Key(id, ip, dbNodeFindFails))) // 返回失败次数 // Return failure count
}

// UpdateFindFailsV5 stores the discv5 findnode failure counter.
// UpdateFindFailsV5 存储 discv5 findnode 失败计数器。
func (db *DB) UpdateFindFailsV5(id ID, ip netip.Addr, fails int) error {
	if !ip.IsValid() { // 如果 IP 无效 // If IP is invalid
		return errInvalidIP
	}
	return db.storeInt64(v5Key(id, ip, dbNodeFindFails), int64(fails)) // 存储失败次数 // Store failure count
}

// localSeq retrieves the local record sequence counter, defaulting to the current
// timestamp if no previous exists. This ensures that wiping all data associated
// with a node (apart from its key) will not generate already used sequence nums.
// localSeq 检索本地记录序列计数器，如果之前不存在，则默认为当前时间戳。
// 这确保擦除与节点关联的所有数据（除了其键）不会生成已使用的序列号。
func (db *DB) localSeq(id ID) uint64 {
	if seq := db.fetchUint64(localItemKey(id, dbLocalSeq)); seq > 0 { // 如果存在序列号 // If sequence exists
		return seq
	}
	return nowMilliseconds() // 返回当前毫秒时间戳 // Return current millisecond timestamp
}

// storeLocalSeq stores the local record sequence counter.
// storeLocalSeq 存储本地记录序列计数器。
func (db *DB) storeLocalSeq(id ID, n uint64) {
	db.storeUint64(localItemKey(id, dbLocalSeq), n) // 存储序列号 // Store sequence number
}

// QuerySeeds retrieves random nodes to be used as potential seed nodes
// for bootstrapping.
// QuerySeeds 检索随机节点，用作自举的潜在种子节点。
func (db *DB) QuerySeeds(n int, maxAge time.Duration) []*Node {
	var (
		now   = time.Now()                   // 当前时间 // Current time
		nodes = make([]*Node, 0, n)          // 节点列表 // Node list
		it    = db.lvl.NewIterator(nil, nil) // 创建迭代器 // Create iterator
		id    ID                             // 节点 ID // Node ID
	)
	defer it.Release()

seek:
	for seeks := 0; len(nodes) < n && seeks < n*5; seeks++ { // 循环寻找节点 // Loop to find nodes
		// Seek to a random entry. The first byte is incremented by a
		// random amount each time in order to increase the likelihood
		// of hitting all existing nodes in very small databases.
		// 定位到随机条目。每次第一个字节增加随机量，以增加在小型数据库中命中所有现有节点的可能性 。
		ctr := id[0]
		rand.Read(id[:])       // 生成随机 ID // Generate random ID
		id[0] = ctr + id[0]%16 // 调整第一个字节 // Adjust first byte
		it.Seek(nodeKey(id))   // 定位到键 // Seek to key

		n := nextNode(it) // 获取下一个节点 // Get next node
		if n == nil {     // 如果没有节点 // If no node
			id[0] = 0
			continue seek // 迭代器耗尽，继续寻找 // Iterator exhausted, continue seeking
		}
		if now.Sub(db.LastPongReceived(n.ID(), n.IPAddr())) > maxAge { // 如果节点过旧 // If node is too old
			continue seek
		}
		for i := range nodes { // 检查重复 // Check for duplicates
			if nodes[i].ID() == n.ID() {
				continue seek
			}
		}
		nodes = append(nodes, n) // 添加节点 // Add node
	}
	return nodes
}

// reads the next node record from the iterator, skipping over other
// database entries.
// 从迭代器读取下一个节点记录，跳过其他数据库条目。
func nextNode(it iterator.Iterator) *Node {
	for end := false; !end; end = !it.Next() { // 遍历迭代器 // Iterate iterator
		id, rest := splitNodeKey(it.Key())  // 分离键 // Split key
		if string(rest) != dbDiscoverRoot { // 如果不是发现根 // If not discovery root
			continue
		}
		return mustDecodeNode(id[:], it.Value()) // 解码并返回节点 // Decode and return node
	}
	return nil
}

// Close flushes and closes the database files.
// Close 刷新并关闭数据库文件。
func (db *DB) Close() {
	select {
	case <-db.quit: // already closed // 已关闭
	default:
		close(db.quit) // 关闭退出通道 // Close quit channel
	}
	db.lvl.Close() // 关闭数据库 // Close database
}
