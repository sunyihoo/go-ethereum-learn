package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

func TestFullAccount(t *testing.T) {
	// 创建一个空的 StateAccount 并转换为瘦 RLP
	slimData := SlimAccountRLP(*NewEmptyStateAccount())

	// 测试 FullAccount 函数
	acct, err := FullAccount(slimData)
	if err != nil {
		t.Fatalf("Failed to decode slim RLP: %v", err)
	}
	if acct.Nonce != 0 {
		t.Errorf("Expected Nonce to be 0, got %d", acct.Nonce)
	}
	if !bytes.Equal(acct.Root[:], EmptyRootHash[:]) {
		t.Errorf("Expected Root to be EmptyRootHash, got %x", acct.Root)
	}

	// 测试 FullAccountRLP 函数
	fullData, err := FullAccountRLP(slimData)
	if err != nil {
		t.Fatalf("Failed to convert to full RLP: %v", err)
	}
	var decoded StateAccount
	if err := rlp.DecodeBytes(fullData, &decoded); err != nil {
		t.Fatalf("Failed to decode full RLP: %v", err)
	}
	if decoded.Nonce != 0 {
		t.Errorf("Expected Nonce to be 0 in full RLP, got %d", decoded.Nonce)
	}
}
