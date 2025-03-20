package types

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestMISC(t *testing.T) {
	t.Log(headerSize)
}

func TestEncodeNonce(t *testing.T) {
	nonceInt := uint64(123456789)
	nonce := EncodeNonce(nonceInt)
	fmt.Printf("Encoded nonce: %x\n", nonce) // 输出字节数组的十六进制表示
}

func TestHeader(t *testing.T) {
	hex := "0xd4fe7bc31cedb7bfb8a345f31e668033056b2728"
	want := "0x9cff99569141df6fb52c05db2b7a797318701b03365337accfd5a4d13fe69150"
	header := &Header{
		ParentHash: common.HexToHash(hex),
		Number:     big.NewInt(100),
		Time:       1698771234,
	}
	hash := header.Hash()
	fmt.Printf("Block hash: %x\n", hash)
	if hash.String() != want {
		t.Errorf("want %s, got %s\n", want, hash.String())
	}
}

func TestBlock_SanityCheck(t *testing.T) {
	header := &Header{
		Number:     big.NewInt(0).Lsh(big.NewInt(1), 70), // 2⁷⁰，超出 uint64
		Difficulty: big.NewInt(100),
		Extra:      make([]byte, 101*1024), // 101KB
		BaseFee:    big.NewInt(1000),
	}
	if err := header.SanityCheck(); err != nil {
		fmt.Println("Sanity check failed:", err)
	} else {
		fmt.Println("Sanity check passed")
	}
}
