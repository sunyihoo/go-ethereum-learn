package types

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestRlpHash(t *testing.T) {
	header := &Header{
		ParentHash: common.HexToHash("0xd4fe7bc31cedb7bfb8a345f31e668033056b2728"),
		Number:     big.NewInt(100),
		Time:       1698771234,
	}
	hash := rlpHash(header)
	fmt.Printf("Block hash: %x\n", hash)
}
