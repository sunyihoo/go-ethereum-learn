// Copyright 2020 The go-ethereum Authors
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

package utils

import (
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/urfave/cli/v2"
)

var (
	// Deprecated May 2020, shown in aliased flags section
	NoUSBFlag = &cli.BoolFlag{
		Name:     "nousb",
		Usage:    "Disables monitoring for and managing USB hardware wallets (deprecated)",
		Category: flags.DeprecatedCategory,
	}
	// Deprecated November 2023
	LogBacktraceAtFlag = &cli.StringFlag{
		Name:     "log.backtrace",
		Usage:    "Request a stack trace at a specific logging statement (deprecated)",
		Value:    "",
		Category: flags.DeprecatedCategory,
	}
	LogDebugFlag = &cli.BoolFlag{
		Name:     "log.debug",
		Usage:    "Prepends log messages with call-site location (deprecated)",
		Category: flags.DeprecatedCategory,
	}
	// Deprecated Oct 2024
	EnablePersonal = &cli.BoolFlag{
		Name:     "rpc.enabledeprecatedpersonal",
		Usage:    "This used to enable the 'personal' namespace.",
		Category: flags.DeprecatedCategory,
	}
	InsecureUnlockAllowedFlag = &cli.BoolFlag{
		Name:     "allow-insecure-unlock",
		Usage:    "Allow insecure account unlocking when account-related RPCs are exposed by http (deprecated)",
		Category: flags.DeprecatedCategory,
	}
)
