// Copyright 2019 The go-ethereum Authors
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

package external

import (
	"fmt"
	"net/rpc"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
)

type ExternalBackend struct {
	signers []accounts.Wallet
}

func (eb *ExternalBackend) Wallets() []accounts.Wallet {
	return eb.signers
}

func NewExternalBackend(endpoint string) (*ExternalBackend, error) {
	//signer, err := NewExternalSigner(endpoint)
	return &ExternalBackend{signers: make([]accounts.Wallet, 0)}, nil
}

// ExternalSigner provides an API to interact with an external signer (clef)
// It proxies request to the external signer while forwarding relevant
// request headers
type ExternalSigner struct {
	client   *rpc.Client
	endpoint string
	status   string
	cacheMu  sync.RWMutex
	cache    []accounts.Account
}

func NewExternalSigner(endpoint string) (*ExternalSigner, error) {
	client, err := rpc.Dial(endpoint)
	if err != nil {
		return nil, err
	}
	extsigner := &ExternalSigner{
		client:   client,
		endpoint: endpoint,
	}
	// Check if reachable
	version, err := extsigner.pingVersion()
	if err != nil {
		return nil, err
	}
	extsigner.status = fmt.Sprintf("ok [version=%v]", version)
	return extsigner, nil
}
