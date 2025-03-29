package rpc

import (
	"encoding/binary"
	"sync"
)

func newTestServer() *Server {
	server := NewServer()
	server.idgen = sequentialIDGenerator()
	if err := server.RegisterName("test", new(testService)); err != nil {
		panic(err)
	}
	if err := server.RegisterName("nftest", new(notificationTestService)); err != nil {
		panic(err)
	}
	return server
}

func sequentialIDGenerator() func() ID {
	var (
		mu      sync.Mutex
		counter uint64
	)
	return func() ID {
		mu.Lock()
		defer mu.Unlock()
		counter++
		id := make([]byte, 8)
		binary.BigEndian.PutUint64(id, counter)
		return encodeID(id)
	}
}

type testService struct{}

type notificationTestService struct {
	unsubscribed            chan string
	gotHangSubscriptionReq  chan struct{}
	unblockHangSubscription chan struct{}
}
