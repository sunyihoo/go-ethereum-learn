package node

import (
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/log"
)

func TestEnv(t *testing.T) {
	t.Log(os.Getenv("LOCALAPPDATA"))
	log.New().Info("Info")
	t.Log(windowsAppData())
}
