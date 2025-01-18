package common

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the excepted length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20
)

type Hash [HashLength]byte

/////////// Address

type Address [AddressLength]byte

// UnprefixedAddress allows marshaling an Address without 0x prefix.
type UnprefixedAddress Address

// UnmarshalText decodes the address from hex. The 0x prefix is optional.
func (a *UnprefixedAddress) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedAddress", input, a[:])
}

func (a *UnprefixedAddress) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}
