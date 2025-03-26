package pebble

import (
	"sync/atomic"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/dbtest"
	"github.com/stretchr/testify/assert"
)

func TestOnCompactionBegin(t *testing.T) {
	// Setup: Initialize a Database instance
	db := &Database{
		activeComp:    0,
		compTime:      atomic.Int64{},
		level0Comp:    atomic.Uint32{},
		nonLevel0Comp: atomic.Uint32{},
	}

	// Test case 1: First compaction (Level 0)
	infoL0 := pebble.CompactionInfo{
		Input: []pebble.LevelInfo{{Level: 0}},
	}
	db.onCompactionBegin(infoL0)
	assert.False(t, db.compStartTime.IsZero(), "compStartTime should be set")
	assert.Equal(t, uint32(1), db.level0Comp.Load(), "level0Comp should be 1")
	assert.Equal(t, uint32(0), db.nonLevel0Comp.Load(), "nonLevel0Comp should be 0")
	assert.Equal(t, 1, db.activeComp, "activeComp should be 1")

	// Test case 2: Second compaction (non-Level 0)
	infoNonL0 := pebble.CompactionInfo{
		Input: []pebble.LevelInfo{{Level: 1}},
	}
	db.onCompactionBegin(infoNonL0)
	assert.Equal(t, uint32(1), db.level0Comp.Load(), "level0Comp should remain 1")
	assert.Equal(t, uint32(1), db.nonLevel0Comp.Load(), "nonLevel0Comp should be 1")
	assert.Equal(t, 2, db.activeComp, "activeComp should be 2")
}

func TestUpperBound(t *testing.T) {
	// Test case 1: Normal prefix
	prefix := []byte{0x01, 0x02}
	limit := upperBound(prefix)
	assert.Equal(t, []byte{0x01, 0x03}, limit, "upper bound should increment last byte")

	// Test case 2: Prefix with 0xff
	prefix = []byte{0x01, 0xff}
	limit = upperBound(prefix)
	assert.Equal(t, []byte{0x02}, limit, "upper bound should increment previous byte")

	// Test case 3: All 0xff prefix
	prefix = []byte{0xff, 0xff}
	limit = upperBound(prefix)
	assert.Nil(t, limit, "upper bound should be nil for all 0xff")

	// Test case 4: Empty prefix
	prefix = []byte{}
	limit = upperBound(prefix)
	assert.Nil(t, limit, "upper bound should be nil for empty prefix")
}

func TestPebbleDB(t *testing.T) {
	t.Run("DatabaseSuite", func(t *testing.T) {
		dbtest.TestDatabaseSuite(t, func() ethdb.KeyValueStore {
			db, err := pebble.Open("", &pebble.Options{
				FS: vfs.NewMem(),
			})
			if err != nil {
				t.Fatal(err)
			}
			return &Database{
				db: db,
			}
		})
	})
}

func BenchmarkPebbleDB(b *testing.B) {
	dbtest.BenchDatabaseSuite(b, func() ethdb.KeyValueStore {
		db, err := pebble.Open("", &pebble.Options{
			FS: vfs.NewMem(),
		})
		if err != nil {
			b.Fatal(err)
		}
		return &Database{
			db: db,
		}
	})
}
