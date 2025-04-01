package trie

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
)

// Prng is a pseudo random number generator seeded by strong randomness.
// The randomness is printed on startup in order to make failures reproducible.
var prng = initRnd()

func initRnd() *mrand.Rand {
	var seed [8]byte
	crand.Read(seed[:])
	rnd := mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(seed[:]))))
	fmt.Printf("Seed: %x\n", seed)
	return rnd
}
func randBytes(n int) []byte {
	r := make([]byte, n)
	prng.Read(r)
	return r
}
