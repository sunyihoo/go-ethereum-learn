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

const (
	BasicDataLeafKey = 0
	CodeHashLeafKey  = 1

	BasicDataVersionOffset  = 0
	BasicDataCodeSizeOffset = 5
	BasicDataNonceOffset    = 8
	BasicDataBalanceOffset  = 16
)

var (
	zero                                = uint256.NewInt(0)
	verkleNodeWidthLog2                 = 8
	headerStorageOffset                 = uint256.NewInt(64)
	codeOffset                          = uint256.NewInt(128)
	verkleNodeWidth                     = uint256.NewInt(256)
	codeStorageDelta                    = uint256.NewInt(0).Sub(codeOffset, headerStorageOffset)
	mainStorageOffsetLshVerkleNodeWidth = new(uint256.Int).Lsh(uint256.NewInt(1), 248-uint(verkleNodeWidthLog2))

	index0Point *verkle.Point // pre-computed commitment of polynomial [2+256*64]

	// cacheHitGauge is the metric to track how many cache hit occurred.
	cacheHitGauge = metrics.NewRegisteredGauge("trie/verkle/cache/hit", nil)

	// cacheMissGauge is the metric to track how many cache miss occurred.
	cacheMissGauge = metrics.NewRegisteredGauge("trie/verkle/cache/miss", nil)
)

// PointCache is the LRU cache for storing evaluated address commitment.
type PointCache struct {
	lru  lru.BasicLRU[string, *verkle.Point]
	lock sync.RWMutex
}

// NewPointCache returns the cache with specified size.
func NewPointCache(maxItems int) *PointCache {
	return &PointCache{
		lru: lru.NewBasicLRU[string, *verkle.Point](maxItems),
	}
}

// Get returns the cached commitment for the specified address, or computing
// it on the flight.
func (c *PointCache) Get(addr []byte) *verkle.Point {
	c.lock.Lock()
	defer c.lock.Unlock()

	p, ok := c.lru.Get(string(addr))
	if ok {
		cacheHitGauge.Inc(1)
		return p
	}
	cacheMissGauge.Inc(1)
	p = evaluateAddressPoint(addr)
	c.lru.Add(string(addr), p)
	return p
}

// GetStem returns the first 31 bytes of the tree key as the tree stem. It only
// works for the account metadata whose treeIndex is 0.
func (c *PointCache) GetStem(addr []byte) []byte {
	p := c.Get(addr)
	return pointToHash(p, 0)[:31]
}

// GetTreeKeyWithEvaluatedAddress is basically identical to GetTreeKey, the only
// difference is a part of polynomial is already evaluated.
//
// Specifically, poly = [2+256*64, address_le_low, address_le_high] is already
// evaluated.
func GetTreeKeyWithEvaluatedAddress(evaluated *verkle.Point, treeIndex *uint256.Int, subIndex byte) []byte {
	var poly [5]fr.Element

	// little-endian, 32-byte aligned treeIndex
	var index [32]byte
	for i := 0; i < len(treeIndex); i++ {
		binary.LittleEndian.PutUint64(index[i*8:(i+1)*8], treeIndex[i])
	}
	verkle.FromLEBytes(&poly[3], index[:16])
	verkle.FromLEBytes(&poly[4], index[16:])

	cfg := verkle.GetConfig()
	ret := cfg.CommitToPoly(poly[:], 0)

	// add the pre-evaluated address
	ret.Add(ret, evaluated)

	return pointToHash(ret, subIndex)
}

func codeChunkIndex(chunk *uint256.Int) (*uint256.Int, byte) {
	var (
		chunkOffset            = new(uint256.Int).Add(codeOffset, chunk)
		treeIndex, subIndexMod = new(uint256.Int).DivMod(chunkOffset, verkleNodeWidth, new(uint256.Int))
	)
	return treeIndex, byte(subIndexMod.Uint64())
}

func StorageIndex(storageKey []byte) (*uint256.Int, byte) {
	// If the storage slot is in the header, we need to add the header offset.
	var key uint256.Int
	key.SetBytes(storageKey)
	if key.Cmp(codeStorageDelta) < 0 {
		// This addition is always safe; it can't ever overflow since pos<codeStorageDelta.
		key.Add(headerStorageOffset, &key)

		// In this branch, the tree-index is zero since we're in the account header,
		// and the sub-index is the LSB of the modified storage key.
		return zero, byte(key[0] & 0xFF)
	}
	// If the storage slot is in the main storage, we need to add the main storage offset.

	// The first MAIN_STORAGE_OFFSET group will see its
	// first 64 slots unreachable. This is either a typo in the
	// spec or intended to conserve the 256-u256
	// alignment. If we decide to ever access these 64
	// slots, uncomment this.
	// // Get the new offset since we now know that we are above 64.
	// pos.Sub(&pos, codeStorageDelta)
	// suffix := byte(pos[0] & 0xFF)
	suffix := storageKey[len(storageKey)-1]

	// We first divide by VerkleNodeWidth to create room to avoid an overflow next.
	key.Rsh(&key, uint(verkleNodeWidthLog2))

	// We add mainStorageOffset/VerkleNodeWidth which can't overflow.
	key.Add(&key, mainStorageOffsetLshVerkleNodeWidth)

	// The sub-index is the LSB of the original storage key, since mainStorageOffset
	// doesn't affect this byte, so we can avoid masks or shifts.
	return &key, suffix
}

// BasicDataKeyWithEvaluatedAddress returns the verkle tree key of the basic data
// field for the specified account. The difference between BasicDataKey is the
// address evaluation is already computed to minimize the computational overhead.
func BasicDataKeyWithEvaluatedAddress(evaluated *verkle.Point) []byte {
	return GetTreeKeyWithEvaluatedAddress(evaluated, zero, BasicDataLeafKey)
}

// CodeChunkKeyWithEvaluatedAddress returns the verkle tree key of the code
// chunk for the specified account. The difference between CodeChunkKey is the
// address evaluation is already computed to minimize the computational overhead.
func CodeChunkKeyWithEvaluatedAddress(addressPoint *verkle.Point, chunk *uint256.Int) []byte {
	treeIndex, subIndex := codeChunkIndex(chunk)
	return GetTreeKeyWithEvaluatedAddress(addressPoint, treeIndex, subIndex)
}

// StorageSlotKeyWithEvaluatedAddress returns the verkle tree key of the storage
// slot for the specified account. The difference between StorageSlotKey is the
// address evaluation is already computed to minimize the computational overhead.
func StorageSlotKeyWithEvaluatedAddress(evaluated *verkle.Point, storageKey []byte) []byte {
	treeIndex, subIndex := StorageIndex(storageKey)
	return GetTreeKeyWithEvaluatedAddress(evaluated, treeIndex, subIndex)
}

func pointToHash(evaluated *verkle.Point, suffix byte) []byte {
	retb := verkle.HashPointToBytes(evaluated)
	retb[31] = suffix
	return retb[:]
}

func evaluateAddressPoint(address []byte) *verkle.Point {
	if len(address) < 32 {
		var aligned [32]byte
		address = append(aligned[:32-len(address)], address...)
	}
	var poly [3]fr.Element

	// 32-byte address, interpreted as two little endian
	// 16-byte numbers.
	verkle.FromLEBytes(&poly[1], address[:16])
	verkle.FromLEBytes(&poly[2], address[16:])

	cfg := verkle.GetConfig()
	ret := cfg.CommitToPoly(poly[:], 0)

	// add a constant point
	ret.Add(ret, index0Point)
	return ret
}
