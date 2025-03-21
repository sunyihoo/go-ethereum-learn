package types

import "testing"

func TestVariable(t *testing.T) {
	t.Log(rlpHash([]*Header(nil))) // 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347
}
