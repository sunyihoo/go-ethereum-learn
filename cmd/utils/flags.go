// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/urfave/cli/v2"
)

// These are all the command line flags we support.
// If you add to this list, please remember to include the
// flag in the appropriate command definition.
//
// The flags are defined here so their names and help texts
// are the same for all commands.

// TODO no finish
var (
	// General settings
	NetworkIdFlag = &cli.Uint64Flag{
		Name:     "networkid",
		Usage:    "Explictly set network id (integer)(For testnets: use --sepolia, --hokesky instead",
		Value:    ethconfig.Defaults.NetworkId,
		Category: flags.EthCategory,
	}
	MainnetFlag = &cli.BoolFlag{
		Name:     "mainnet",
		Usage:    "Ethereum mainnet",
		Category: flags.EthCategory,
	}
	SepoliaFlag = &cli.BoolFlag{
		Name:     "sepolia",
		Usage:    "Seplia network: pre-configured proof-of-work test network",
		Category: flags.EthCategory,
	}
	HoleskyFlag = &cli.BoolFlag{
		Name:     "holesky",
		Usage:    "Holesky networkL: pre-configured proof-stake test network",
		Category: flags.EthCategory,
	}
	// Dev mode
	DeveloperFlag = &cli.BoolFlag{
		Name:     "dev",
		Usage:    "Ephemeral proof-of-authority network with a pre-funded developer account, mining enabled",
		Category: flags.DevCategory,
	}

	// Performance tuning settings
	CacheFlag = &cli.IntFlag{
		Name:     "cache",
		Usage:    "Megabytes of memory allocated to internal caching (default = 4096 mainnet full node, 128 light mode)",
		Value:    1024,
		Category: flags.PerfCategory,
	}

	// Network Settings

	ListenPortFlag = &cli.IntFlag{
		Name:     "port",
		Usage:    "Network listening port",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}

	NodeKeyFileFlag = &cli.StringFlag{
		Name:     "nodekey",
		Usage:    "P2P node key file",
		Category: flags.NetworkingCategory,
	}
	NodeKeyHexFlag = &cli.StringFlag{
		Name:     "nodekeyhex",
		Usage:    "P2P node key as hex (for testing)",
		Category: flags.NetworkingCategory,
	}
	NATFlag = &cli.StringFlag{
		Name:     "nat",
		Usage:    "NAT port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>",
		Value:    "any",
		Category: flags.NetworkingCategory,
	}
	DiscoveryPortFlag = &cli.IntFlag{
		Name:     "discovery.port",
		Usage:    "Use a custom UDP port for P2P discovery",
		Value:    30303,
		Category: flags.NetworkingCategory,
	}
)

// setNodeKey creates a node key from set command line flags, either loading it
// from a file or as a specified hex value. If neither flags were provided, this
// method returns nil and an ephemeral key is to be generated.
func setNodeKey(ctx *cli.Context, cfg *p2p.Config) {
	var (
		hex  = ctx.String(NodeKeyHexFlag.Name)
		file = ctx.String(NodeKeyFileFlag.Name)
		key  *ecdsa.PrivateKey
		err  error
	)
	switch {
	case file != "" && hex != "":
		Fatalf("Options %q and %q are mutually exclusive", NodeKeyFileFlag.Name, NodeKeyHexFlag.Name)
	case file != "":
		if key, err = crypto.LoadECDSA(file); err != nil {
			Fatalf("Option %q: %v", NodeKeyFileFlag.Name, err)
		}
		cfg.PrivateKey = key
	case hex != "":
		if key, err = crypto.HexToECDSA(hex); err != nil {
			Fatalf("Option %q: %v", NodeKeyHexFlag.Name, err)
		}
		cfg.PrivateKey = key
	}
}

// setListenAddress creates TCP/UDP listening address strings from set command
// line flags
func setListenAddress(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(ListenPortFlag.Name) {
		cfg.ListenAddr = fmt.Sprintf(":%d", ctx.Int(ListenPortFlag.Name))
	}
	if ctx.IsSet(DiscoveryPortFlag.Name) {
		cfg.DiscAddr = fmt.Sprintf(":%d", ctx.Int(DiscoveryPortFlag.Name))
	}
}
func setNAT(ctx *cli.Context, cfg *p2p.Config) {
	if ctx.IsSet(NATFlag.Name) {
		natif, err := nat.Parse(ctx.String(NATFlag.Name))
		if err != nil {
			Fatalf("Option %s: %v", NATFlag.Name, err)
		}
		cfg.NAT = natif
	}
}

func SetP2PConfig(ctx *cli.Context, cfg *p2p.Config) {
	setNodeKey(ctx, cfg)
	setNAT(ctx, cfg)
	setListenAddress(ctx, cfg)
	// todo here again
}

// SetNodeConfig applies node-related command line flags to the config.
func SetNodeConfig(ctx *cli.Context, cfg *node.Config) {

}
