package utils

import (
	"sync"

	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-verkle"
)

// PointCache is the LRU cache for storing evaluated address commitment.
type PointCache struct {
	lru  lru.BasicLRU[string, *verkle.Point]
	lock sync.RWMutex
}
