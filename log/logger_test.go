package log

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestWriteTimeTermFormat(t *testing.T) {
	b := bytes.NewBufferString("")
	writeTimeTermFormat(b, time.Now())
	t.Log(b.String())
}

func TestLog(t *testing.T) {

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})
	log := slog.New(handler)
	log.Info("asd")
	fmt.Println("E:/Learn/go-ethereum-learn/node/rpcstack.go:168")
	handlsr := NewTerminalHandler(os.Stderr, false)
	log = slog.New(handlsr)
	log.Info("[ E:/Learn/go-ethereum-learn/log/logger_test.go:26 ]")
	h := NewTerminalHandler(os.Stderr, false)
	l := NewLogger(h)
	l.Info("message")
}
