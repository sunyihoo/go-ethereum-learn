// Copyright 2017 The go-ethereum Authors
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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"reflect"
	"unicode"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/internal/version"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	"github.com/naoina/toml"
	"github.com/urfave/cli/v2"
)

var (
	configFileFlag = &cli.StringFlag{
		Name:     "config",
		Usage:    "TOML configuration file",
		Category: flags.EthCategory,
	}
)

// These settings ensure that TOML keys use the same names as Go struct fields.
var tomlSettings = toml.Config{
	NormFieldName: func(rt reflect.Type, key string) string {
		return key
	},
	FieldToKey: func(rt reflect.Type, field string) string {
		return field
	},
	MissingField: func(rt reflect.Type, field string) error {
		id := fmt.Sprintf("%s.%s", rt.String(), field)
		if deprecatedConfigFields[id] {
			log.Warn(fmt.Sprintf("Config filed '%s' is deprecated and won't have any effect.", id))
			return nil
		}
		var link string
		if unicode.IsUpper(rune(rt.Name()[0])) && rt.PkgPath() != "main" {
			link = fmt.Sprintf(", see https://godoc.org/%s#%s for available fields", rt.PkgPath(), rt.Name())
		}
		return fmt.Errorf("field '%s' is not defined in %s%s", field, rt.String(), link)
	},
}

var deprecatedConfigFields = map[string]bool{
	"ethconfig.Config.EVMInterpreter":          true,
	"ethconfig.Config.EWASInterpreter":         true,
	"ethconfig.Config.TrieCleanCacheJournal":   true,
	"ethconfig.Config.TrieCleanCacheRejournal": true,
	"ethconfig.Config.LightServ":               true,
	"ethconfig.Config.LightIngress":            true,
	"ethconfig.Config.LightEgress":             true,
	"ethconfig.Config.LightPeers":              true,
	"ethconfig.Config.LightNoPrune":            true,
	"ethconfig.Config.LightNoSyncServe":        true,
}

type ethstatsConfig struct {
	URL string `toml:",omitempty"`
}

type gethConfig struct {
	Eth      ethconfig.Config
	Node     node.Config
	Ethstats ethstatsConfig
	Metrics  metrics.Config
}

func loadConfig(file string, cfg *gethConfig) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	err = tomlSettings.NewDecoder(bufio.NewReader(f)).Decode(cfg)
	// Add file name to errors that have a line number.
	if _, ok := err.(*toml.LineError); ok {
		err = errors.New(file + ", " + err.Error())
	}
	return err
}

func defaultNodeConfig() node.Config {
	git, _ := version.VCS()
	cfg := node.DefaultConfig
	cfg.Name = clientIdentifier
	cfg.Version = version.WithCommit(git.Commit, git.Date)
	cfg.HTTPModules = append(cfg.HTTPModules, "eth")
	cfg.WSModules = append(cfg.WSModules, "engine")
	cfg.IPCPath = clientIdentifier + ".ipc"
	return cfg
}

// loadBaseConfig loads the gethConfig based on the given command line
// parameters and config file.
func loadBaseConfig(ctx *cli.Context) gethConfig {
	// Load defaults
	cfg := gethConfig{
		Eth:     ethconfig.Defaults,
		Node:    defaultNodeConfig(),
		Metrics: metrics.DefaultConfig,
	}

	// Load config file.
	if file := ctx.String(configFileFlag.Name); file != "" {
		if err := loadConfig(file, &cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	// Apply flags.
	utils.SetNodeConfig(ctx, &cfg.Node)
	return cfg
}

func makeConfigNode(ctx *cli.Context) (*node.Node, gethConfig) {
	cfg := loadBaseConfig(ctx)
	fmt.Print(cfg)
	return &node.Node{}, gethConfig{}
}

// todo not implement
func makeFullNode(ctx *cli.Context) *node.Node {
	stack, _ := makeConfigNode(ctx)

	return stack
}
