// Copyright 2023 go-ethereum Authors
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

package utils

import (
	"encoding/binary"
	"sync"

	"github.com/crate-crypto/go-ipa/bandersnatch/fr"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

// Trie 中的叶子节点类型:
//  在以太坊的 Merkle Patricia Trie（MPT）中，叶子节点存储账户状态或合约数据：
//    BasicDataLeafKey 对应账户的基本状态（如版本、nonce、余额等）。
//    CodeHashLeafKey 对应合约代码的哈希，用于引用代码内容。
//  这些常量可能用于区分叶子节点的类型，便于在 Trie 操作中识别和处理。
// 账户状态的结构:
//   以太坊账户状态包括以下字段（通常 RLP 编码后存储在 Trie 中）：
//    Version（版本）：账户数据的版本号，从偏移 0 开始。
//    CodeSize（代码大小）：合约代码的字节数，从偏移 5 开始。
//    Nonce（随机数）：账户的交易计数器，从偏移 8 开始。
//    Balance（余额）：账户的以太币余额，从偏移 16 开始。
//  这些偏移量表明基本数据被序列化为固定长度的字节数组，反映了以太坊中状态编码的紧凑性。

// 用于标识 Trie 叶子节点的类型和基本数据字段的偏移量。
const (
	BasicDataLeafKey = 0 // 基本数据叶子键  表示基本数据叶子节点的键，用于存储账户的基本状态信息。
	CodeHashLeafKey  = 1 // 代码哈希叶子键  表示代码哈希叶子节点的键，用于存储合约代码的哈希。

	// 定义了一个固定长度的字节数组结构：
	// 0-4 字节：版本。
	// 5-7 字节：代码大小。
	// 8-15 字节：随机数。
	// 16+ 字节：余额。

	BasicDataVersionOffset  = 0  // 基本数据版本偏移量     版本字段的偏移量，从字节数组的第 0 个字节开始。
	BasicDataCodeSizeOffset = 5  // 基本数据代码大小偏移量 代码大小字段的偏移量，从第 5 个字节开始。
	BasicDataNonceOffset    = 8  // 基本数据随机数偏移量   随机数（nonce）字段的偏移量，从第 8 个字节开始。
	BasicDataBalanceOffset  = 16 // 基本数据余额偏移量     余额字段的偏移量，从第 16 个字节开始。
)

// 主要用于 Verkle Trie（一种以太坊状态 Trie 的优化变种）的实现。
// Verkle Trie 是以太坊状态 Trie 的升级版本，使用向量承诺（Vector Commitment）替代 Merkle Patricia Trie（MPT）的哈希树，提供更小的证明大小和更高的效率。
// verkleNodeWidth = 256 表示每个节点有 256 个槽位，基于多项式承诺的宽度设计。
var (
	// 零值
	zero = uint256.NewInt(0)
	// Verkle 节点宽度的以 2 为底的对数，值为 8（即 2^8 = 256）
	verkleNodeWidthLog2 = 8
	// 头部存储偏移量，值为 64
	headerStorageOffset = uint256.NewInt(64)
	// 代码偏移量，值为 128
	codeOffset = uint256.NewInt(128)
	// Verkle 节点宽度，值为 256（2^8）
	verkleNodeWidth = uint256.NewInt(256)
	// 代码存储差值，计算 codeOffset - headerStorageOffset（128 - 64 = 64）
	codeStorageDelta = uint256.NewInt(0).Sub(codeOffset, headerStorageOffset)
	// 主存储偏移量左移 Verkle 节点宽度，计算 1 << (248 - 8) = 1 << 240
	mainStorageOffsetLshVerkleNodeWidth = new(uint256.Int).Lsh(uint256.NewInt(1), 248-uint(verkleNodeWidthLog2))

	index0Point *verkle.Point // pre-computed commitment of polynomial [2+256*64] // 多项式 [2+256*64] 的预计算承诺点

	// cacheHitGauge is the metric to track how many cache hit occurred.
	// cacheHitGauge 是用于追踪缓存命中次数的指标。
	cacheHitGauge = metrics.NewRegisteredGauge("trie/verkle/cache/hit", nil)

	// cacheMissGauge is the metric to track how many cache miss occurred.
	// cacheMissGauge 是用于追踪缓存未命中次数的指标。
	cacheMissGauge = metrics.NewRegisteredGauge("trie/verkle/cache/miss", nil)
)

func init() {
	// The byte array is the Marshalled output of the point computed as such:
	//
	// 	var (
	//		config = verkle.GetConfig()
	//		fr     verkle.Fr
	//	)
	//	verkle.FromLEBytes(&fr, []byte{2, 64})
	//	point := config.CommitToPoly([]verkle.Fr{fr}, 1)
	//
	// 字节数组是按如下方式计算的点的序列化输出：
	//
	// 	var (
	//		config = verkle.GetConfig()
	//		fr     verkle.Fr
	//	)
	//	verkle.FromLEBytes(&fr, []byte{2, 64})
	//	point := config.CommitToPoly([]verkle.Fr{fr}, 1)
	index0Point = new(verkle.Point)
	// 用于在程序启动时初始化全局变量 index0Point，它是 Verkle Trie 中一个预计算的承诺点。
	// 字节数组：[34, 25, 109, 242, ...] 是多项式 [2 + 256*64] 承诺点的序列化形式。
	// SetBytes 将 32 字节数组反序列化为 verkle.Point，这是在椭圆曲线上的一个点，符合以太坊加密库（如 bn256 或 bls12-381）的规范。
	err := index0Point.SetBytes([]byte{34, 25, 109, 242, 193, 5, 144, 224, 76, 52, 189, 92, 197, 126, 9, 145, 27, 152, 199, 130, 165, 3, 210, 27, 193, 131, 142, 28, 110, 26, 16, 191})
	if err != nil {
		panic(err)
	}
}

// Verkle Trie 中的承诺点:
//  Verkle Trie 使用多项式承诺（Polynomial Commitment）表示状态，verkle.Point 是椭圆曲线上的点，用于承诺地址或状态数据。
//  PointCache 缓存这些点的计算结果，避免重复计算，提高查询效率。
// 地址承诺（Address Commitment）:
//  在 Verkle Trie 中，每个账户地址可能被映射为一个承诺点，用于生成证明或验证状态。
//  缓存这些点可以加速地址相关的操作，例如状态读取或证明生成。
// LRU 缓存的应用:
//  以太坊客户端（如 Geth）常使用缓存优化性能。PointCache 的 LRU 策略确保最近使用的地址承诺优先保留，适合高频访问场景。

// PointCache is the LRU cache for storing evaluated address commitment.
// PointCache 是用于存储已评估地址承诺的 LRU 缓存。
type PointCache struct {
	lru  lru.BasicLRU[string, *verkle.Point] // LRU 缓存，键为字符串，值为 verkle.Point 指针
	lock sync.RWMutex                        // 读写锁，用于并发保护
}

// NewPointCache returns the cache with specified size.
// NewPointCache 返回具有指定大小的缓存。
func NewPointCache(maxItems int) *PointCache {
	return &PointCache{
		lru: lru.NewBasicLRU[string, *verkle.Point](maxItems), // 初始化指定大小的 LRU 缓存
	}
}

// Verkle 树与承诺：Verkle 树使用承诺（commitment）表示节点，verkle.Point 可能是基于 KZG（Kate-Zaverucha-Goldberg）多项式承诺的坐标点，用于压缩状态数据。
// 状态查询优化：以太坊的状态树（State Trie）存储账户数据，Verkle 树通过缓存和高效证明机制减少查询开销，PointCache 是实现这一优化的关键组件。

// Get returns the cached commitment for the specified address, or computing
// it on the flight.
// Get 返回指定地址的缓存承诺，如果缓存中不存在，则即时计算。
//
// addr []byte：以太坊地址的字节表示，通常为 20 字节（160 位），代表一个账户地址。
// 返回值 *verkle.Point：一个指向 Verkle 点的指针，表示地址在 Verkle 树中的承诺或坐标。
func (c *PointCache) Get(addr []byte) *verkle.Point {
	c.lock.Lock()
	defer c.lock.Unlock()

	p, ok := c.lru.Get(string(addr)) // 从 LRU 缓存中获取地址对应的点
	if ok {
		cacheHitGauge.Inc(1) // 缓存命中计数器加 1
		return p             // 返回缓存中的点
	}
	cacheMissGauge.Inc(1)          // 缓存未命中计数器加 1
	p = evaluateAddressPoint(addr) // 计算地址对应的点
	c.lru.Add(string(addr), p)     // 将计算结果添加到缓存
	return p                       // 返回计算得到的点
}

// 树干（Stem）概念：在 Verkle 树中，树键通常分为“树干”（stem）和“后缀”（suffix）。
// 树干标识账户或存储位置的前缀，后缀区分具体数据项（例如余额、nonce 等）。
// 这里的前 31 字节作为树干，第 32 字节（后缀）被设为 0，表示账户元数据。
// 树索引为 0：以太坊账户状态通常存储在树索引 0 的位置（例如余额、nonce），其他索引可能用于存储映射（Storage Trie）。

// GetStem returns the first 31 bytes of the tree key as the tree stem. It only
// works for the account metadata whose treeIndex is 0.
// GetStem 返回树键的前 31 个字节作为树干。它仅适用于树索引为 0 的账户元数据。
// 基于地址获取其 Verkle 点的字节表示，并从中提取前 31 个字节作为“树干”（stem）。注释表明它仅适用于树索引为 0 的账户元数据，通常是账户的基本信息。
func (c *PointCache) GetStem(addr []byte) []byte {
	p := c.Get(addr)              // 获取地址对应的点
	return pointToHash(p, 0)[:31] // 将点转换为字节数组，取前 31 字节作为树干
}

// Verkle 树键：树键由地址、树索引和子索引组成，用于定位```go 定位 Verkle 树中的节点。GetTreeKey 生成的键通常用于状态查询或证明构造。
// Pedersen 哈希：一种基于椭圆曲线的哈希函数，Verkle 树使用它结合多项式承诺生成节点标识。
// EIP-3102：Verkle 树是以太坊优化提案的一部分，旨在减少状态证明大小，提高效率。
// KZG 承诺：CommitToPoly 可能基于 KZG 方案，使用 bn254 曲线实现高效的多项式承诺。

// GetTreeKey performs both the work of the spec's get_tree_key function, and that
// of pedersen_hash: it builds the polynomial in pedersen_hash without having to
// create a mostly zero-filled buffer and "type cast" it to a 128-long 16-byte
// array. Since at most the first 5 coefficients of the polynomial will be non-zero,
// these 5 coefficients are created directly.
//
// GetTreeKey 同时执行规范中的 get_tree_key 函数和 pedersen_hash 的工作：它直接构建 pedersen_hash 中的多项式，
// 无需创建一个大部分填充为零的缓冲区并将其“类型转换”为长度为 128 的 16 字节数组。由于多项式的至多前 5 个系数为非零，
// 因此直接创建这 5 个系数。
//
// treeIndex *uint256.Int：树索引，表示存储位置（如账户的余额或存储槽），使用 uint256 类型。
// subIndex byte：子索引，后缀字节，用于区分同一地址下的不同数据项。
func GetTreeKey(address []byte, treeIndex *uint256.Int, subIndex byte) []byte {
	if len(address) < 32 {
		var aligned [32]byte
		address = append(aligned[:32-len(address)], address...) // 对齐到 32 字节，前面补零
	}
	// poly = [2+256*64, address_le_low, address_le_high, tree_index_le_low, tree_index_le_high]
	var poly [5]fr.Element // 定义包含 5 个系数的多项式数组

	// 32-byte address, interpreted as two little endian
	// 16-byte numbers.
	// 32 字节地址，被解释为两个小端序的 16 字节数字
	verkle.FromLEBytes(&poly[1], address[:16]) // 将地址前 16 字节转换为小端序并存入 poly[1]
	verkle.FromLEBytes(&poly[2], address[16:]) // 将地址后 16 字节转换为小端序并存入 poly[2]

	// treeIndex must be interpreted as a 32-byte aligned little-endian integer.
	// e.g: if treeIndex is 0xAABBCC, we need the byte representation to be 0xCCBBAA00...00.
	// poly[3] = LE({CC,BB,AA,00...0}) (16 bytes), poly[4]=LE({00,00,...}) (16 bytes).
	//
	// To avoid unnecessary endianness conversions for go-ipa, we do some trick:
	// - poly[3]'s byte representation is the same as the *top* 16 bytes (trieIndexBytes[16:]) of
	//   32-byte aligned big-endian representation (BE({00,...,AA,BB,CC})).
	// - poly[4]'s byte representation is the same as the *low* 16 bytes (trieIndexBytes[:16]) of
	//   the 32-byte aligned big-endian representation (BE({00,00,...}).
	//
	// treeIndex 必须被解释为 32 字节对齐的小端序整数。
	// 例如：如果 treeIndex 是 0xAABBCC，则字节表示应为 0xCCBBAA00...00。
	// poly[3] = LE({CC,BB,AA,00...0}) (16 字节), poly[4]=LE({00,00,...}) (16 字节)。
	//
	// 为了避免对 go-ipa 不必要的端序转换，我们使用了一些技巧：
	// - poly[3] 的字节表示与 32 字节对齐的大端序表示 (BE({00,...,AA,BB,CC})) 的高 16 字节 (trieIndexBytes[16:]) 相同。
	// - poly[4] 的字节表示与 32 字节对齐的大端序表示 (BE({00,00,...})) 的低 16 字节 (trieIndexBytes[:16]) 相同。
	trieIndexBytes := treeIndex.Bytes32()           // 将 treeIndex 转换为 32 字节数组
	verkle.FromBytes(&poly[3], trieIndexBytes[16:]) // 从高 16 字节填充 poly[3]
	verkle.FromBytes(&poly[4], trieIndexBytes[:16]) // 从低 16 字节填充 poly[4]

	cfg := verkle.GetConfig()           // 获取 Verkle 配置
	ret := cfg.CommitToPoly(poly[:], 0) // 将多项式提交为一个点

	// add a constant point corresponding to poly[0]=[2+256*64].
	// 添加对应于 poly[0]=[2+256*64] 的常数点
	ret.Add(ret, index0Point) // 将常数点加到结果上

	return pointToHash(ret, subIndex) // 将结果转换为字节数组并附加子索引
}

// GetTreeKeyWithEvaluatedAddress is basically identical to GetTreeKey, the only
// difference is a part of polynomial is already evaluated.
//
// Specifically, poly = [2+256*64, address_le_low, address_le_high] is already
// evaluated.
//
// GetTreeKeyWithEvaluatedAddress 与 GetTreeKey 基本相同，唯一的区别是多项式的一部分已经预先计算。
// 具体来说，poly = [2+256*64, address_le_low, address_le_high] 已完成计算。
func GetTreeKeyWithEvaluatedAddress(evaluated *verkle.Point, treeIndex *uint256.Int, subIndex byte) []byte {
	var poly [5]fr.Element // 定义包含 5 个系数的多项式数组

	// little-endian, 32-byte aligned treeIndex
	// 小端序，32 字节对齐的 treeIndex
	var index [32]byte
	for i := 0; i < len(treeIndex); i++ { // 将 treeIndex 的每个 64 位部分转为小端序字节。
		binary.LittleEndian.PutUint64(index[i*8:(i+1)*8], treeIndex[i]) // 将 treeIndex 转换为小端序字节数组
	}
	verkle.FromLEBytes(&poly[3], index[:16]) // 将前 16 字节填充到 poly[3]
	verkle.FromLEBytes(&poly[4], index[16:]) // 将后 16 字节填充到 poly[4]

	cfg := verkle.GetConfig()           // 获取 Verkle 配置
	ret := cfg.CommitToPoly(poly[:], 0) // 将多项式提交为一个点

	// add the pre-evaluated address
	// 添加预计算的地址点
	ret.Add(ret, evaluated) // 将预计算的 evaluated 点加到结果上

	return pointToHash(ret, subIndex) // 将结果转换为字节数组并附加子索引
}

// Verkle 树结构：Verkle 树将账户状态拆分为多个叶子节点，每个叶子由唯一的树键标识。treeIndex 表示子树位置（此处为 0），subIndex 区分同一子树内的字段。
// 字段分离：以太坊传统状态树（MPT）将账户数据存储在一个节点中，而 Verkle 树通过键分解提高查询效率和证明压缩性。

// 基本数据字段：在以太坊状态树中，账户的基本数据包括余额（balance）、nonce（交易计数器）、代码哈希（code hash）和存储根（storage root）。
// Verkle 树将这些字段组织为叶子节点，

// BasicDataKey returns the verkle tree key of the basic data field for
// the specified account.
// BasicDataKey 返回指定账户基本数据字段的 Verkle 树键。
func BasicDataKey(address []byte) []byte {
	return GetTreeKey(address, zero, BasicDataLeafKey) // 调用 GetTreeKey 生成基本数据字段的树键
}

// 代码哈希字段：以太坊账户的代码哈希是智能合约字节码的 Keccak-256 哈希值。对于外部账户（EOA），此值为固定空哈希。
// Verkle 树将代码哈希作为单独字段存储，CodeHashLeafKey 用于定位。

// CodeHashKey returns the verkle tree key of the code hash field for
// the specified account.
// CodeHashKey 返回指定账户代码哈希字段的 Verkle 树键。
func CodeHashKey(address []byte) []byte {
	return GetTreeKey(address, zero, CodeHashLeafKey) // 调用 GetTreeKey 生成代码哈希字段的树键
}

// 代码分块：以太坊智能合约代码存储在状态树中，Verkle 树将其分块（chunks）以支持高效查询和证明。
// 每个块可能为 32 字节，与 Keccak-256 哈希长度一致。
// 树索引与子索引：Verkle 树通过 treeIndex 定位子树，subIndex 定位叶子，优化了大数据的存储。
func codeChunkIndex(chunk *uint256.Int) (*uint256.Int, byte) {
	var (
		chunkOffset            = new(uint256.Int).Add(codeOffset, chunk)                                 // 计算代码块偏移量：codeOffset + chunk
		treeIndex, subIndexMod = new(uint256.Int).DivMod(chunkOffset, verkleNodeWidth, new(uint256.Int)) // 将偏移量除以节点宽度，得到树索引和子索引余数
	)
	return treeIndex, byte(subIndexMod.Uint64()) // 返回树索引和子索引（转换为 byte 类型）
}

// 代码存储：以太坊账户的代码哈希指向完整字节码，Verkle 树将其分块存储，CodeChunkKey 用于访问特定块。
// 用途：支持部分代码加载或验证（如执行时按需获取字节码）。

// CodeChunkKey returns the verkle tree key of the code chunk for the
// specified account.
// CodeChunkKey 返回指定账户代码块的 Verkle 树键。
func CodeChunkKey(address []byte, chunk *uint256.Int) []byte {
	treeIndex, subIndex := codeChunkIndex(chunk)    // 获取代码块的树索引和子索引
	return GetTreeKey(address, treeIndex, subIndex) // 调用 GetTreeKey 生成代码块的树键
}

// StorageIndex 根据存储键计算 Verkle 树中的树索引和子索引。
func StorageIndex(storageKey []byte) (*uint256.Int, byte) {
	// If the storage slot is in the header, we need to add the header offset.
	// 如果存储槽在头部，我们需要添加头部偏移量
	var key uint256.Int
	key.SetBytes(storageKey)           // 将存储键字节转换为 uint256 类型
	if key.Cmp(codeStorageDelta) < 0 { // 如果存储键小于 codeStorageDelta
		// This addition is always safe; it can't ever overflow since pos<codeStorageDelta.
		// 此加法始终安全，因为 key < codeStorageDelta，不会溢出
		key.Add(headerStorageOffset, &key) // 将头部偏移量加到存储键上

		// In this branch, the tree-index is zero since we're in the account header,
		// and the sub-index is the LSB of the modified storage key.
		// 在此分支中，树索引为零，因为我们在账户头部，子索引是修改后存储键的最低有效字节
		return zero, byte(key[0] & 0xFF) // 返回树索引 0 和子索引（最低字节）
	}
	// If the storage slot is in the main storage, we need to add the main storage offset.
	// 如果存储槽在主存储中，我们需要添加主存储偏移量

	// The first MAIN_STORAGE_OFFSET group will see its
	// first 64 slots unreachable. This is either a typo in the
	// spec or intended to conserve the 256-u256
	// alignment. If we decide to ever access these 64
	// slots, uncomment this.
	// // Get the new offset since we now know that we are above 64.
	// pos.Sub(&pos, codeStorageDelta)
	// suffix := byte(pos[0] & 0xFF)
	//
	// 主存储偏移量的第一个组将无法访问其前 64 个槽。这可能是规范中的笔误，
	// 或者是故意设计以保持 256-uint256 对齐。如果需要访问这 64 个槽，可取消注释以下代码
	// // 得知 key >= 64 后，重新计算偏移量
	// key.Sub(&key, codeStorageDelta)
	// suffix := byte(key[0] & 0xFF)
	suffix := storageKey[len(storageKey)-1] // 子索引取原始存储键的最后一个字节

	// We first divide by VerkleNodeWidth to create room to avoid an overflow next.
	// 先右移 VerkleNodeWidthLog2 位，为后续加法腾出空间，避免溢出
	key.Rsh(&key, uint(verkleNodeWidthLog2))

	// We add mainStorageOffset/VerkleNodeWidth which can't overflow.
	// 添加 mainStorageOffset / VerkleNodeWidth，此操作不会溢出
	key.Add(&key, mainStorageOffsetLshVerkleNodeWidth)

	// The sub-index is the LSB of the original storage key, since mainStorageOffset
	// doesn't affect this byte, so we can avoid masks or shifts.
	// 子索引是原始存储键的最低有效字节，因为 mainStorageOffset 不影响此字节，无需掩码或移位
	return &key, suffix // 返回树索引和子索引
}

// StorageSlotKey returns the verkle tree key of the storage slot for the
// specified account.
// StorageSlotKey 返回指定账户存储槽的 Verkle 树键。
func StorageSlotKey(address []byte, storageKey []byte) []byte {
	treeIndex, subIndex := StorageIndex(storageKey)
	return GetTreeKey(address, treeIndex, subIndex)
}

// BasicDataKeyWithEvaluatedAddress returns the verkle tree key of the basic data
// field for the specified account. The difference between BasicDataKey is the
// address evaluation is already computed to minimize the computational overhead.
//
// BasicDataKeyWithEvaluatedAddress 返回指定账户基本数据字段的 Verkle 树键。与 BasicDataKey 的区别在于地址评估已预先计算，以减少计算开销。
func BasicDataKeyWithEvaluatedAddress(evaluated *verkle.Point) []byte {
	return GetTreeKeyWithEvaluatedAddress(evaluated, zero, BasicDataLeafKey)
}

// CodeHashKeyWithEvaluatedAddress returns the verkle tree key of the code
// hash for the specified account. The difference between CodeHashKey is the
// address evaluation is already computed to minimize the computational overhead.
//
// CodeHashKeyWithEvaluatedAddress 返回指定账户代码哈希的 Verkle 树键。与 CodeHashKey 的区别在于地址评估已预先计算，以减少计算开销。
func CodeHashKeyWithEvaluatedAddress(evaluated *verkle.Point) []byte {
	return GetTreeKeyWithEvaluatedAddress(evaluated, zero, CodeHashLeafKey)
}

// CodeChunkKeyWithEvaluatedAddress returns the verkle tree key of the code
// chunk for the specified account. The difference between CodeChunkKey is the
// address evaluation is already computed to minimize the computational overhead.
//
// CodeChunkKeyWithEvaluatedAddress 返回指定账户代码块的 Verkle 树键。与 CodeChunkKey 的区别在于地址评估已预先计算，以减少计算开销。
func CodeChunkKeyWithEvaluatedAddress(addressPoint *verkle.Point, chunk *uint256.Int) []byte {
	treeIndex, subIndex := codeChunkIndex(chunk)
	return GetTreeKeyWithEvaluatedAddress(addressPoint, treeIndex, subIndex)
}

// StorageSlotKeyWithEvaluatedAddress returns the verkle tree key of the storage
// slot for the specified account. The difference between StorageSlotKey is the
// address evaluation is already computed to minimize the computational overhead.
//
// StorageSlotKeyWithEvaluatedAddress 返回指定账户存储槽的 Verkle 树键。与 StorageSlotKey 的区别在于地址评估已预先计算，以减少计算开销。
func StorageSlotKeyWithEvaluatedAddress(evaluated *verkle.Point, storageKey []byte) []byte {
	treeIndex, subIndex := StorageIndex(storageKey)
	return GetTreeKeyWithEvaluatedAddress(evaluated, treeIndex, subIndex)
}

// Verkle 树：Verkle 树是以太坊社区提出的优化状态树的方案（参考 EIP-3102 等提案），相比 Merkle 树，它使用向量承诺（Vector Commitment）和多项式承诺来减少证明大小，提高效率。
// verkle.Point 可能是一个基于椭圆曲线或有限域的数学表示，用于定位树中的节点。
// 哈希与后缀：在以太坊中，哈希值（如 Keccak-256）广泛用于标识数据、交易或状态。将后缀附加到哈希的做法常见于需要区分不同类型数据的场景，例如以太坊 RLP 编码中的类型标记。

// 将一个 Verkle 树中的点（verkle.Point 类型）转换为一个字节数组表示，并通过附加一个后缀字节（suffix）来区分不同的用途或标识。这是 Verkle 树实现中常见的一种操作，用于生成节点的哈希值或键值。
func pointToHash(evaluated *verkle.Point, suffix byte) []byte {
	retb := verkle.HashPointToBytes(evaluated) // 调用 HashPointToBytes 将 verkle 点转换为字节数组
	retb[31] = suffix                          // 将字节数组的最后一位替换为指定的后缀字节
	return retb[:]                             // 返回完整的字节数组
}

// Verkle Trie 中的地址承诺:
//   Verkle Trie 使用多项式承诺表示状态，evaluateAddressPoint 将账户地址映射为承诺点。
//   地址被拆分为 [0, addr[0:16], addr[16:32]]，可能对应 Verkle Trie 的某种索引或分片方案。
// 有限域与多项式:
//   fr.Element 是有限域元素（通常基于大素数阶），FromLEBytes 将字节数组解析为有限域值。
//   多项式 [0, a, b] 表示地址的数学表示，CommitToPoly 基于椭圆曲线生成承诺。
// 预计算点 index0Point:
//   index0Point 是 [2 + 256*64] 的承诺点，添加它可能是 Verkle Trie 中地址承诺的标准化步骤，确保一致性。

// 用于将以太坊地址转换为 Verkle Trie 中的承诺点。
func evaluateAddressPoint(address []byte) *verkle.Point {
	// 如果地址长度小于 32 字节，则填充到 32 字节
	if len(address) < 32 {
		var aligned [32]byte
		address = append(aligned[:32-len(address)], address...)
	}
	var poly [3]fr.Element // 定义一个包含 3 个有限域元素的数组

	// 32-byte address, interpreted as two little endian
	// 16-byte numbers.
	// 将 32 字节地址解释为两个小端序的 16 字节数字
	verkle.FromLEBytes(&poly[1], address[:16]) // 将前 16 字节转换为有限域元素，存入 poly[1]
	verkle.FromLEBytes(&poly[2], address[16:]) // 将后 16 字节转换为有限域元素，存入 poly[2]

	// 生成地址对应的向量承诺。
	cfg := verkle.GetConfig()           // 获取 Verkle 配置
	ret := cfg.CommitToPoly(poly[:], 0) // 将多项式 poly 转换为承诺点，阶数为 0

	// add a constant point
	// 添加一个常数点
	ret.Add(ret, index0Point) // 将预计算的 index0Point 加到 ret 上
	return ret
}
