// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
)

// Client represents a connection to an RPC server.
type Client struct {
	idgen    func() ID // for subscriptions
	isHTTP   bool      // connection type: http, ws or ipc
	services *serviceRegistry

	idCounter atomic.Uint32

	// This function, if non-nil, is called when the connection is lost.
	reconnectFunc reconnectFunc

	// config fields
	batchItemLimit       int
	batchResponseMaxSize int

	// writeConn is used for writing to the connection on the caller's goroutine. It should
	// only be accessed outside of dispatch, with the write lock held. The write lock is
	// taken by sending on reqInit and released by sending on reqSent.
	writeConn jsonWriter

	// for dispatch
	close       chan struct{}
	closing     chan struct{}    // closed when client is quitting
	didClose    chan struct{}    // closed when client quits
	reconnected chan ServerCodec // where write/reconnect sends the new connection
	readOp      chan readOp      // read messages
	readErr     chan error       // errors from read
	reqInit     chan *requestOp  // register response IDs, takes write lock
	reqSent     chan error       // signals write completion, releases write lock
	reqTimeout  chan *requestOp  // removes response IDs when call timeout expires
}

type reconnectFunc func(context.Context) (ServerCodec, error)

type readOp struct {
	msgs  []*jsonrpcMessage
	batch bool
}

// requestOp represents a pending request. This is used for both batch and non-batch
// requests.
type requestOp struct {
	ids         []json.RawMessage
	err         error
	resp        chan []*jsonrpcMessage // the response goes here
	sub         *ClientSubscription    // set for Subscribe requests.
	hadResponse bool                   // true when the request was responded to
}

// Dial creates a new client for the given URL.
//
// The currently supported URL schemes are "http", "https", "ws" and "wss". If rawurl is a
// file name with no URL scheme, a local socket connection is established using UNIX
// domain sockets on supported platforms and named pipes on Windows.
//
// If you want to further configure the transport, use DialOptions instead of this
// function.
//
// For websocket connections, the origin is set to the local host name.
//
// The client reconnects automatically when the connection is lost.
func Dial(rawurl string) (*Client, error) {
	return DialOptions(context.Background(), rawurl)
}

// DialOptions creates a new RPC client for the given URL. You can supply any of the
// pre-defined client options to configure the underlying transport.
//
// The context is used to cancel or time out the initial connection establishment. It does
// not affect subsequent interactions with the client.
//
// The client reconnects automatically when the connection is lost.
func DialOptions(ctx context.Context, rawurl string, options ...ClientOption) (*Client, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	cfg := new(clientConfig)
	for _, opt := range options {
		opt.applyOption(cfg)
	}

	var reconnect reconnectFunc
	switch u.Scheme {
	case "http", "https":
		reconnect = newClientTransportHTTP(rawurl, cfg)
	case "ws", "wss":
		rc, err := newClientTransportWS(rawurl, cfg)
		if err != nil {
			return nil, err
		}
		reconnect = rc
	case "stdio":
		reconnect = newClientTransportIO(os.Stdin, os.Stdout)
	case "":
		reconnect = newClientTransportIPC(rawurl)
	default:
		return nil, fmt.Errorf("no known transport for URL scheme %q", u.Scheme)
	}
	return newClient(ctx, cfg, reconnect)
	// todo here to start
	return nil, err
}
