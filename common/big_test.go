package common

import (
	"fmt"
	"testing"
	"unsafe"
)

func TestBig(t *testing.T) {
	t.Log(Big0)
	t.Log(Big1)
	t.Log(Big2)
	t.Log(Big3)
	t.Log(Big32)
	t.Log(Big256)
	t.Log(Big257)
	t.Log(U2560)
	value := 0x12345678
	bytes := (*[4]byte)(unsafe.Pointer(&value))[:]
	fmt.Printf("Bytes: %x\n", bytes)
}
