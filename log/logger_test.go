package log

import (
	"bytes"
	"testing"
	"time"
)

func TestWriteTimeTermFormat(t *testing.T) {
	b := bytes.NewBufferString("")
	writeTimeTermFormat(b, time.Now())
	t.Log(b.String())
}
