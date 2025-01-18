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
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/urfave/cli/v2"
)

// These are all the command line flags we support.
// If you add to this list, please remember to include the
// flag in the appropriate command definition.
//
// The flags are defined here so their names and help texts
// are the same for all commands.

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
)
