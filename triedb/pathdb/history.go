// Copyright 2022 The go-ethereum Authors
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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package pathdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/exp/maps"
)

// 状态历史的主要目的是：
//
// 支持状态回滚：在区块链发生重组（reorg）时，可以通过应用历史对象（状态反向差异）将当前状态恢复到之前的某个状态。
// 提供历史状态查询：允许访问过去的账户和存储数据，适用于归档节点（archive node）或需要历史数据的应用。
// 管理存储空间：通过修剪（pruning）最旧的历史对象，控制磁盘存储的增长。
// 以太坊的区块链状态是通过状态树（state trie，通常是 Merkle Patricia Trie）维护的，状态树的根哈希（state root）记录在每个区块头中。
// 每次区块执行都会导致状态变化（例如账户余额变更、合约存储更新），这些变化会被记录下来。
// 状态历史机制与以太坊的“分层状态”（layered state）设计相关：
//
// Disk Layer：持久化的状态层，存储在磁盘上。
// Diff Layer：临时状态差异层，表示未提交的变更。 当 diff layer 合并到 disk layer 时，状态历史对象会被写入磁盘（称为 ancient store，一个冷冻存储机制，用于存储不可变的历史数据）。

// State history records the state changes involved in executing a block. The
// state can be reverted to the previous version by applying the associated
// history object (state reverse diff). State history objects are kept to
// guarantee that the system can perform state rollbacks in case of deep reorg.
//
// 状态历史记录了执行区块时涉及的状态变化。通过应用相关的历史对象（状态反向差异），可以将状态恢复到前一个版本。
// 保留状态历史对象以确保系统在发生深度重组（reorg）时能够执行状态回滚。
//
// Each state transition will generate a state history object. Note that not
// every block has a corresponding state history object. If a block performs
// no state changes whatsoever, no state is created for it. Each state history
// will have a sequentially increasing number acting as its unique identifier.
//
// 每个状态转换都会生成一个状态历史对象。注意，并非每个区块都有对应的状态历史对象。
// 如果一个区块完全没有状态变化，则不会为其创建状态历史对象。
// 每个状态历史对象都有一个依次递增的数字作为其唯一标识符。
//
// The state history is written to disk (ancient store) when the corresponding
// diff layer is merged into the disk layer. At the same time, system can prune
// the oldest histories according to config.
//
// 当对应的差异层（diff layer）合并到磁盘层（disk layer）时，状态历史会被写入磁盘（ancient store）。
// 同时，系统可以根据配置修剪最旧的历史对象。
//
//
//                                                        Disk State
//                                                            ^
//                                                            |
//   +------------+     +---------+     +---------+     +---------+
//   | Init State |---->| State 1 |---->|   ...   |---->| State n |
//   +------------+     +---------+     +---------+     +---------+
//
//                     +-----------+      +------+     +-----------+
//                     | History 1 |----> | ...  |---->| History n |
//                     +-----------+      +------+     +-----------+
//
// # Rollback
//
// If the system wants to roll back to a previous state n, it needs to ensure
// all history objects from n+1 up to the current disk layer are existent. The
// history objects are applied to the state in reverse order, starting from the
// current disk layer.
//
// 如果系统想要回滚到前一个状态 n，需要确保从 n+1 到当前磁盘层的所有历史对象都存在。
// 历史对象将从当前磁盘层开始按逆序应用于状态。

const (
	// accountIndexSize 表示编码后的账户索引长度，等于以太坊地址长度（20字节）加上13字节元数据
	accountIndexSize = common.AddressLength + 13 // The length of encoded account index
	// slotIndexSize 表示编码后的存储槽索引长度，等于哈希长度（32字节）加上5字节元数据
	slotIndexSize = common.HashLength + 5 // The length of encoded slot index
	// historyMetaSize 表示编码后的历史元数据长度，9字节加上两个哈希长度（64字节）
	historyMetaSize = 9 + 2*common.HashLength // The length of encoded history meta
	// stateHistoryVersion 表示状态历史结构的初始版本，当前为0
	stateHistoryVersion = uint8(0) // initial version of state history structure.
)

// Each state history entry is consisted of five elements:
// 每个状态历史条目由五个元素组成：
//
// # metadata
//  This object contains a few meta fields, such as the associated state root,
//  block number, version tag and so on. This object may contain an extra
//  accountHash list which means the storage changes belong to these accounts
//  are not complete due to large contract destruction. The incomplete history
//  can not be used for rollback and serving archive state request.
//
//  # 元数据
//  该对象包含一些元字段，例如相关的状态根、区块号、版本标签等。该对象可能包含一个额外的账户哈希列表，表示由于大规模合约销毁，这些账户的存储变化不完整。不完整的历史无法用于回滚或服务归档状态请求。
//
// # account index
//  This object contains some index information of account. For example, offset
//  and length indicate the location of the data belonging to the account. Besides,
//  storageOffset and storageSlots indicate the storage modification location
//  belonging to the account.
//
//  The size of each account index is *fixed*, and all indexes are sorted
//  lexicographically. Thus binary search can be performed to quickly locate a
//  specific account.
//
//  # 账户索引
//  该对象包含账户的一些索引信息。例如，offset 和 length 指示账户数据的位置。此外，storageOffset 和 storageSlots 指示该账户的存储修改位置。
//  每个账户索引的大小是固定的，所有索引按字典序排序。因此可以通过二分搜索快速定位特定账户。
//
// # account data
//  Account data is a concatenated byte stream composed of all account data.
//  The account data can be solved by the offset and length info indicated
//  by corresponding account index.
//
//  # 账户数据
//  账户数据是由所有账户数据组成的串联字节流。账户数据可以通过对应账户索引指示的 offset 和 length 信息解析。
//
//            fixed size
//         ^             ^
//        /               \
//        +-----------------+-----------------+----------------+-----------------+
//        | Account index 1 | Account index 2 |       ...      | Account index N |
//        +-----------------+-----------------+----------------+-----------------+
//        |
//        |     length
// offset |----------------+
//        v                v
//        +----------------+----------------+----------------+----------------+
//        | Account data 1 | Account data 2 |       ...      | Account data N |
//        +----------------+----------------+----------------+----------------+
//
// # storage index
//  This object is similar with account index. It's also fixed size and contains
//  the location info of storage slot data.
//
//  # 存储索引
//  该对象与账户索引类似，也是固定大小，包含存储槽数据的位置信息。
//
// # storage data
//  Storage data is a concatenated byte stream composed of all storage slot data.
//  The storage slot data can be solved by the location info indicated by
//  corresponding account index and storage slot index.
//
//  # 存储数据
//  存储数据是由所有存储槽数据组成的串联字节流。存储槽数据可以通过对应账户索引和存储槽索引指示的位置信息解析。
//
//                    fixed size
//                 ^             ^
//                /               \
//                +-----------------+-----------------+----------------+-----------------+
//                | Account index 1 | Account index 2 |       ...      | Account index N |
//                +-----------------+-----------------+----------------+-----------------+
//                |
//                |                    storage slots
// storage offset |-----------------------------------------------------+
//                v                                                     v
//                +-----------------+-----------------+-----------------+
//                | storage index 1 | storage index 2 | storage index 3 |
//                +-----------------+-----------------+-----------------+
//                |     length
//         offset |-------------+
//                v             v
//                +-------------+
//                | slot data 1 |
//                +-------------+

// accountIndex describes the metadata belonging to an account.
// accountIndex 描述属于账户的元数据。
type accountIndex struct {
	address       common.Address // The address of account 账户的地址
	length        uint8          // The length of account data, size limited by 255 账户数据的长度，限制为255字节
	offset        uint32         // The offset of item in account data table 账户数据表中项目的偏移量
	storageOffset uint32         // The offset of storage index in storage index table 存储索引表中存储索引的偏移量
	storageSlots  uint32         // The number of mutated storage slots belonging to the account 属于该账户的变更存储槽数量
}

// encode packs account index into byte stream.
// encode 将账户索引打包成字节流。
func (i *accountIndex) encode() []byte {
	var buf [accountIndexSize]byte
	copy(buf[:], i.address.Bytes())
	buf[common.AddressLength] = i.length
	binary.BigEndian.PutUint32(buf[common.AddressLength+1:], i.offset)
	binary.BigEndian.PutUint32(buf[common.AddressLength+5:], i.storageOffset)
	binary.BigEndian.PutUint32(buf[common.AddressLength+9:], i.storageSlots)
	return buf[:]
}

// decode unpacks account index from byte stream.
// decode 从字节流中解包账户索引。
func (i *accountIndex) decode(blob []byte) {
	i.address = common.BytesToAddress(blob[:common.AddressLength])
	i.length = blob[common.AddressLength]
	i.offset = binary.BigEndian.Uint32(blob[common.AddressLength+1:])
	i.storageOffset = binary.BigEndian.Uint32(blob[common.AddressLength+5:])
	i.storageSlots = binary.BigEndian.Uint32(blob[common.AddressLength+9:])
}

// slotIndex describes the metadata belonging to a storage slot.
// slotIndex 描述属于存储槽的元数据。
type slotIndex struct {
	hash   common.Hash // The hash of slot key 存储槽键的哈希
	length uint8       // The length of storage slot, up to 32 bytes defined in protocol 存储槽的长度，协议定义最多32字节
	offset uint32      // The offset of item in storage slot data table 存储槽数据表中项目的偏移量
}

// encode packs slot index into byte stream.
// encode 将存储槽索引打包成字节流。
func (i *slotIndex) encode() []byte {
	var buf [slotIndexSize]byte
	copy(buf[:common.HashLength], i.hash.Bytes())
	buf[common.HashLength] = i.length
	binary.BigEndian.PutUint32(buf[common.HashLength+1:], i.offset)
	return buf[:]
}

// decode unpack slot index from the byte stream.
// decode 从字节流中解包存储槽索引。
func (i *slotIndex) decode(blob []byte) {
	i.hash = common.BytesToHash(blob[:common.HashLength])
	i.length = blob[common.HashLength]
	i.offset = binary.BigEndian.Uint32(blob[common.HashLength+1:])
}

// meta describes the meta data of state history object.
// meta 描述状态历史对象的元数据。
type meta struct {
	version uint8       // version tag of history object 历史对象的版本标签
	parent  common.Hash // prev-state root before the state transition 状态转换前的上一个状态根
	root    common.Hash // post-state root after the state transition 状态转换后的当前状态根
	block   uint64      // associated block number 相关的区块号
}

// encode packs the meta object into byte stream.
// encode 将元数据对象打包成字节流。
func (m *meta) encode() []byte {
	buf := make([]byte, historyMetaSize)
	buf[0] = m.version
	copy(buf[1:1+common.HashLength], m.parent.Bytes())
	copy(buf[1+common.HashLength:1+2*common.HashLength], m.root.Bytes())
	binary.BigEndian.PutUint64(buf[1+2*common.HashLength:historyMetaSize], m.block)
	return buf[:]
}

// decode unpacks the meta object from byte stream.
// decode 从字节流中解包元数据对象。
func (m *meta) decode(blob []byte) error {
	if len(blob) < 1 {
		return errors.New("no version tag")
	}
	switch blob[0] {
	case stateHistoryVersion:
		if len(blob) != historyMetaSize {
			return fmt.Errorf("invalid state history meta, len: %d", len(blob))
		}
		m.version = blob[0]
		m.parent = common.BytesToHash(blob[1 : 1+common.HashLength])
		m.root = common.BytesToHash(blob[1+common.HashLength : 1+2*common.HashLength])
		m.block = binary.BigEndian.Uint64(blob[1+2*common.HashLength : historyMetaSize])
		return nil
	default:
		return fmt.Errorf("unknown version %d", blob[0])
	}
}

// history represents a set of state changes belong to a block along with
// the metadata including the state roots involved in the state transition.
// State history objects in disk are linked with each other by a unique id
// (8-bytes integer), the oldest state history object can be pruned on demand
// in order to control the storage size.
//
// history 表示属于一个区块的状态变化集合，以及包含状态转换中涉及的状态根的元数据。
// 磁盘上的状态历史对象通过唯一的ID（8字节整数）相互链接，可以按需修剪最旧的状态历史对象以控制存储大小。
type history struct {
	meta        *meta                                     // Meta data of history 历史对象的元数据
	accounts    map[common.Address][]byte                 // Account data keyed by its address hash 以地址哈希为键的账户数据
	accountList []common.Address                          // Sorted account hash list 已排序的账户哈希列表
	storages    map[common.Address]map[common.Hash][]byte // Storage data keyed by its address hash and slot hash 以地址哈希和槽哈希为键的存储数据
	storageList map[common.Address][]common.Hash          // Sorted slot hash list 已排序的槽哈希列表
}

// newHistory constructs the state history object with provided state change set.
// newHistory 使用提供的状态变化集构造状态历史对象。
func newHistory(root common.Hash, parent common.Hash, block uint64, accounts map[common.Address][]byte, storages map[common.Address]map[common.Hash][]byte) *history {
	var (
		accountList = maps.Keys(accounts)
		storageList = make(map[common.Address][]common.Hash)
	)
	slices.SortFunc(accountList, common.Address.Cmp)

	for addr, slots := range storages {
		slist := maps.Keys(slots)
		slices.SortFunc(slist, common.Hash.Cmp)
		storageList[addr] = slist
	}
	return &history{
		meta: &meta{
			version: stateHistoryVersion,
			parent:  parent,
			root:    root,
			block:   block,
		},
		accounts:    accounts,
		accountList: accountList,
		storages:    storages,
		storageList: storageList,
	}
}

// encode serializes the state history and returns four byte streams represent
// concatenated account/storage data, account/storage indexes respectively.
//
// encode 序列化状态历史并返回四个字节流，分别表示串联的账户/存储数据和账户/存储索引。
func (h *history) encode() ([]byte, []byte, []byte, []byte) {
	var (
		slotNumber     uint32 // the number of processed slots 已处理的槽数量
		accountData    []byte // the buffer for concatenated account data 串联账户数据的缓冲区
		storageData    []byte // the buffer for concatenated storage data 串联存储数据的缓冲区
		accountIndexes []byte // the buffer for concatenated account index 串联账户索引的缓冲区
		storageIndexes []byte // the buffer for concatenated storage index 串联存储索引的缓冲区
	)
	for _, addr := range h.accountList {
		accIndex := accountIndex{
			address: addr,
			length:  uint8(len(h.accounts[addr])),
			offset:  uint32(len(accountData)),
		}
		slots, exist := h.storages[addr]
		if exist {
			// Encode storage slots in order
			// 按顺序编码存储槽
			for _, slotHash := range h.storageList[addr] {
				sIndex := slotIndex{
					hash:   slotHash,
					length: uint8(len(slots[slotHash])),
					offset: uint32(len(storageData)),
				}
				storageData = append(storageData, slots[slotHash]...)
				storageIndexes = append(storageIndexes, sIndex.encode()...)
			}
			// Fill up the storage meta in account index
			// 填充账户索引中的存储元数据
			accIndex.storageOffset = slotNumber
			accIndex.storageSlots = uint32(len(slots))
			slotNumber += uint32(len(slots))
		}
		accountData = append(accountData, h.accounts[addr]...)
		accountIndexes = append(accountIndexes, accIndex.encode()...)
	}
	return accountData, storageData, accountIndexes, storageIndexes
}

// decoder wraps the byte streams for decoding with extra meta fields.
// decoder 封装了解码所需的字节流，并带有额外的元字段。
type decoder struct {
	accountData    []byte // the buffer for concatenated account data 串联账户数据的缓冲区
	storageData    []byte // the buffer for concatenated storage data 串联存储数据的缓冲区
	accountIndexes []byte // the buffer for concatenated account index 串联账户索引的缓冲区
	storageIndexes []byte // the buffer for concatenated storage index 串联存储索引的缓冲区

	lastAccount       *common.Address // the address of last resolved account 最后解析的账户地址
	lastAccountRead   uint32          // the read-cursor position of account data 账户数据的读取游标位置
	lastSlotIndexRead uint32          // the read-cursor position of storage slot index 存储槽索引的读取游标位置
	lastSlotDataRead  uint32          // the read-cursor position of storage slot data 存储槽数据的读取游标位置
}

// verify validates the provided byte streams for decoding state history. A few
// checks will be performed to quickly detect data corruption. The byte stream
// is regarded as corrupted if:
//
// - account indexes buffer is empty(empty state set is invalid)
// - account indexes/storage indexer buffer is not aligned
//
// note, these situations are allowed:
//
// - empty account data: all accounts were not present
// - empty storage set: no slots are modified
//
// verify 验证提供的字节流以解码状态历史。将执行一些检查以快速检测数据损坏。如果以下情况发生，则认为字节流已损坏：
// - 账户索引缓冲区为空（空状态集无效）
// - 账户索引/存储索引缓冲区未对齐
//
// 注意，允许以下情况：
// - 空账户数据：所有账户都不存在
// - 空存储集：没有槽被修改
func (r *decoder) verify() error {
	if len(r.accountIndexes)%accountIndexSize != 0 || len(r.accountIndexes) == 0 {
		return fmt.Errorf("invalid account index, len: %d", len(r.accountIndexes))
	}
	if len(r.storageIndexes)%slotIndexSize != 0 {
		return fmt.Errorf("invalid storage index, len: %d", len(r.storageIndexes))
	}
	return nil
}

// readAccount parses the account from the byte stream with specified position.
// readAccount 从指定位置的字节流中解析账户。
func (r *decoder) readAccount(pos int) (accountIndex, []byte, error) {
	// Decode account index from the index byte stream.
	// 从索引字节流中解码账户索引。
	var index accountIndex
	if (pos+1)*accountIndexSize > len(r.accountIndexes) {
		return accountIndex{}, nil, errors.New("account data buffer is corrupted")
	}
	index.decode(r.accountIndexes[pos*accountIndexSize : (pos+1)*accountIndexSize])

	// Perform validation before parsing account data, ensure
	// - account is sorted in order in byte stream
	// - account data is strictly encoded with no gap inside
	// - account data is not out-of-slice
	//
	// 在解析账户数据之前执行验证，确保：
	// - 账户在字节流中按顺序排序
	// - 账户数据严格编码，内部无间隙
	// - 账户数据未超出切片范围
	if r.lastAccount != nil { // zero address is possible
		if bytes.Compare(r.lastAccount.Bytes(), index.address.Bytes()) >= 0 {
			return accountIndex{}, nil, errors.New("account is not in order")
		}
	}
	if index.offset != r.lastAccountRead {
		return accountIndex{}, nil, errors.New("account data buffer is gaped")
	}
	last := index.offset + uint32(index.length)
	if uint32(len(r.accountData)) < last {
		return accountIndex{}, nil, errors.New("account data buffer is corrupted")
	}
	data := r.accountData[index.offset:last]

	r.lastAccount = &index.address
	r.lastAccountRead = last

	return index, data, nil
}

// readStorage parses the storage slots from the byte stream with specified account.
// readStorage 从指定账户的字节流中解析存储槽。
func (r *decoder) readStorage(accIndex accountIndex) ([]common.Hash, map[common.Hash][]byte, error) {
	var (
		last    common.Hash
		count   = int(accIndex.storageSlots)
		list    = make([]common.Hash, 0, count)
		storage = make(map[common.Hash][]byte, count)
	)
	for j := 0; j < count; j++ {
		var (
			index slotIndex
			start = (accIndex.storageOffset + uint32(j)) * uint32(slotIndexSize)
			end   = (accIndex.storageOffset + uint32(j+1)) * uint32(slotIndexSize)
		)
		// Perform validation before parsing storage slot data, ensure
		// - slot index is not out-of-slice
		// - slot data is not out-of-slice
		// - slot is sorted in order in byte stream
		// - slot indexes is strictly encoded with no gap inside
		// - slot data is strictly encoded with no gap inside
		//
		// 在解析存储槽数据之前执行验证，确保：
		// - 槽索引未超出切片范围
		// - 槽数据未超出切片范围
		// - 槽在字节流中按顺序排序
		// - 槽索引严格编码，内部无间隙
		// - 槽数据严格编码，内部无间隙
		if start != r.lastSlotIndexRead {
			return nil, nil, errors.New("storage index buffer is gapped")
		}
		if uint32(len(r.storageIndexes)) < end {
			return nil, nil, errors.New("storage index buffer is corrupted")
		}
		index.decode(r.storageIndexes[start:end])

		if bytes.Compare(last.Bytes(), index.hash.Bytes()) >= 0 {
			return nil, nil, errors.New("storage slot is not in order")
		}
		if index.offset != r.lastSlotDataRead {
			return nil, nil, errors.New("storage data buffer is gapped")
		}
		sEnd := index.offset + uint32(index.length)
		if uint32(len(r.storageData)) < sEnd {
			return nil, nil, errors.New("storage data buffer is corrupted")
		}
		storage[index.hash] = r.storageData[r.lastSlotDataRead:sEnd]
		list = append(list, index.hash)

		last = index.hash
		r.lastSlotIndexRead = end
		r.lastSlotDataRead = sEnd
	}
	return list, storage, nil
}

// decode deserializes the account and storage data from the provided byte stream.
// decode 从提供的字节流中反序列化账户和存储数据。
func (h *history) decode(accountData, storageData, accountIndexes, storageIndexes []byte) error {
	var (
		count       = len(accountIndexes) / accountIndexSize
		accounts    = make(map[common.Address][]byte, count)
		storages    = make(map[common.Address]map[common.Hash][]byte)
		accountList = make([]common.Address, 0, count)
		storageList = make(map[common.Address][]common.Hash)

		r = &decoder{
			accountData:    accountData,
			storageData:    storageData,
			accountIndexes: accountIndexes,
			storageIndexes: storageIndexes,
		}
	)
	if err := r.verify(); err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		// Resolve account first
		// 首先解析账户
		accIndex, accData, err := r.readAccount(i)
		if err != nil {
			return err
		}
		accounts[accIndex.address] = accData
		accountList = append(accountList, accIndex.address)

		// Resolve storage slots
		// 解析存储槽
		slotList, slotData, err := r.readStorage(accIndex)
		if err != nil {
			return err
		}
		if len(slotList) > 0 {
			storageList[accIndex.address] = slotList
			storages[accIndex.address] = slotData
		}
	}
	h.accounts = accounts
	h.accountList = accountList
	h.storages = storages
	h.storageList = storageList
	return nil
}

// readHistory reads and decodes the state history object by the given id.
// readHistory 根据给定的ID读取并解码状态历史对象。
func readHistory(reader ethdb.AncientReader, id uint64) (*history, error) {
	blob := rawdb.ReadStateHistoryMeta(reader, id)
	if len(blob) == 0 {
		return nil, fmt.Errorf("state history not found %d", id)
	}
	var m meta
	if err := m.decode(blob); err != nil {
		return nil, err
	}
	var (
		dec            = history{meta: &m}
		accountData    = rawdb.ReadStateAccountHistory(reader, id)
		storageData    = rawdb.ReadStateStorageHistory(reader, id)
		accountIndexes = rawdb.ReadStateAccountIndex(reader, id)
		storageIndexes = rawdb.ReadStateStorageIndex(reader, id)
	)
	if err := dec.decode(accountData, storageData, accountIndexes, storageIndexes); err != nil {
		return nil, err
	}
	return &dec, nil
}

// writeHistory persists the state history with the provided state set.
// writeHistory 使用提供的状态集持久化状态历史。
func writeHistory(writer ethdb.AncientWriter, dl *diffLayer) error {
	// Short circuit if state set is not available.
	// 如果状态集不可用，则短路返回。
	if dl.states == nil {
		return errors.New("state change set is not available")
	}
	var (
		start   = time.Now()
		history = newHistory(dl.rootHash(), dl.parentLayer().rootHash(), dl.block, dl.states.accountOrigin, dl.states.storageOrigin)
	)
	accountData, storageData, accountIndex, storageIndex := history.encode()
	dataSize := common.StorageSize(len(accountData) + len(storageData))
	indexSize := common.StorageSize(len(accountIndex) + len(storageIndex))

	// Write history data into five freezer table respectively.
	// 将历史数据分别写入五个冷冻表。
	rawdb.WriteStateHistory(writer, dl.stateID(), history.meta.encode(), accountIndex, storageIndex, accountData, storageData)

	historyDataBytesMeter.Mark(int64(dataSize))
	historyIndexBytesMeter.Mark(int64(indexSize))
	historyBuildTimeMeter.UpdateSince(start)
	log.Debug("Stored state history", "id", dl.stateID(), "block", dl.block, "data", dataSize, "index", indexSize, "elapsed", common.PrettyDuration(time.Since(start)))

	return nil
}

// checkHistories retrieves a batch of meta objects with the specified range
// and performs the callback on each item.
//
// checkHistories 在指定范围内检索一批元数据对象，并对每个项目执行回调。
func checkHistories(reader ethdb.AncientReader, start, count uint64, check func(*meta) error) error {
	for count > 0 {
		number := count
		if number > 10000 {
			number = 10000 // split the big read into small chunks // 将大读取拆分为小块
		}
		blobs, err := rawdb.ReadStateHistoryMetaList(reader, start, number)
		if err != nil {
			return err
		}
		for _, blob := range blobs {
			var dec meta
			if err := dec.decode(blob); err != nil {
				return err
			}
			if err := check(&dec); err != nil {
				return err
			}
		}
		count -= uint64(len(blobs))
		start += uint64(len(blobs))
	}
	return nil
}

// truncateFromHead removes the extra state histories from the head with the given
// parameters. It returns the number of items removed from the head.
//
// truncateFromHead 根据给定的参数从头部移除多余的状态历史，返回从头部移除的项目数量。
func truncateFromHead(db ethdb.Batcher, store ethdb.AncientStore, nhead uint64) (int, error) {
	ohead, err := store.Ancients()
	if err != nil {
		return 0, err
	}
	otail, err := store.Tail()
	if err != nil {
		return 0, err
	}
	// Ensure that the truncation target falls within the specified range.
	// 确保截断目标落在指定范围内。
	if ohead < nhead || nhead < otail {
		return 0, fmt.Errorf("out of range, tail: %d, head: %d, target: %d", otail, ohead, nhead)
	}
	// Short circuit if nothing to truncate.
	// 如果没有需要截断的内容，则短路返回。
	if ohead == nhead {
		return 0, nil
	}
	// Load the meta objects in range [nhead+1, ohead]
	// 加载范围 [nhead+1, ohead] 内的元数据对象
	blobs, err := rawdb.ReadStateHistoryMetaList(store, nhead+1, ohead-nhead)
	if err != nil {
		return 0, err
	}
	batch := db.NewBatch()
	for _, blob := range blobs {
		var m meta
		if err := m.decode(blob); err != nil {
			return 0, err
		}
		rawdb.DeleteStateID(batch, m.root)
	}
	if err := batch.Write(); err != nil {
		return 0, err
	}
	ohead, err = store.TruncateHead(nhead)
	if err != nil {
		return 0, err
	}
	return int(ohead - nhead), nil
}

// truncateFromTail removes the extra state histories from the tail with the given
// parameters. It returns the number of items removed from the tail.
//
// truncateFromTail 根据给定的参数从尾部移除多余的状态历史，返回从尾部移除的项目数量。
func truncateFromTail(db ethdb.Batcher, store ethdb.AncientStore, ntail uint64) (int, error) {
	ohead, err := store.Ancients()
	if err != nil {
		return 0, err
	}
	otail, err := store.Tail()
	if err != nil {
		return 0, err
	}
	// Ensure that the truncation target falls within the specified range.
	// 确保截断目标落在指定范围内。
	if otail > ntail || ntail > ohead {
		return 0, fmt.Errorf("out of range, tail: %d, head: %d, target: %d", otail, ohead, ntail)
	}
	// Short circuit if nothing to truncate.
	// 如果没有需要截断的内容，则短路返回。
	if otail == ntail {
		return 0, nil
	}
	// Load the meta objects in range [otail+1, ntail]
	// 加载范围 [otail+1, ntail] 内的元数据对象
	blobs, err := rawdb.ReadStateHistoryMetaList(store, otail+1, ntail-otail)
	if err != nil {
		return 0, err
	}
	batch := db.NewBatch()
	for _, blob := range blobs {
		var m meta
		if err := m.decode(blob); err != nil {
			return 0, err
		}
		rawdb.DeleteStateID(batch, m.root)
	}
	if err := batch.Write(); err != nil {
		return 0, err
	}
	otail, err = store.TruncateTail(ntail)
	if err != nil {
		return 0, err
	}
	return int(ntail - otail), nil
}
