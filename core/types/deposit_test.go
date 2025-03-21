package types

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

var (
	depositABI   = abi.ABI{Methods: map[string]abi.Method{"DepositEvent": depositEvent}}
	bytesT, _    = abi.NewType("bytes", "", nil)
	depositEvent = abi.NewMethod("DepositEvent", "DepositEvent", abi.Function, "", false, false, []abi.Argument{
		{Name: "pubkey", Type: bytesT, Indexed: false},
		{Name: "withdrawal_credentials", Type: bytesT, Indexed: false},
		{Name: "amount", Type: bytesT, Indexed: false},
		{Name: "signature", Type: bytesT, Indexed: false},
		{Name: "index", Type: bytesT, Indexed: false}}, nil,
	)
)

// FuzzUnpackIntoDeposit tries roundtrip packing and unpacking of deposit events.
func FuzzUnpackIntoDeposit(f *testing.F) {
	for _, tt := range []struct {
		pubkey string
		wxCred string
		amount string
		sig    string
		index  string
	}{
		{
			pubkey: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
			wxCred: "2222222222222222222222222222222222222222222222222222222222222222",
			amount: "3333333333333333",
			sig:    "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
			index:  "5555555555555555",
		},
	} {
		f.Add(common.FromHex(tt.pubkey), common.FromHex(tt.wxCred), common.FromHex(tt.amount), common.FromHex(tt.sig), common.FromHex(tt.index))
	}

	f.Fuzz(func(t *testing.T, p []byte, w []byte, a []byte, s []byte, i []byte) {
		var (
			pubkey [48]byte
			wxCred [32]byte
			amount [8]byte
			sig    [96]byte
			index  [8]byte
		)
		copy(pubkey[:], p)
		copy(wxCred[:], w)
		copy(amount[:], a)
		copy(sig[:], s)
		copy(index[:], i)

		var enc []byte
		enc = append(enc, pubkey[:]...)
		enc = append(enc, wxCred[:]...)
		enc = append(enc, amount[:]...)
		enc = append(enc, sig[:]...)
		enc = append(enc, index[:]...)

		out, err := depositABI.Pack("DepositEvent", pubkey[:], wxCred[:], amount[:], sig[:], index[:])
		if err != nil {
			t.Fatalf("error packing deposit: %v", err)
		}
		got, err := DepositLogToRequest(out[4:])
		if err != nil {
			t.Errorf("error unpacking deposit: %v", err)
		}
		if len(got) != depositRequestSize {
			t.Errorf("wrong output size: %d, want %d", len(got), depositRequestSize)
		}
		if !bytes.Equal(enc, got) {
			t.Errorf("roundtrip failed: want %x, got %x", enc, got)
		}
	})
}
