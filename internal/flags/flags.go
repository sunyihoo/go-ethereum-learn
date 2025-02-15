// Copyright 2015 The go-ethereum Authors
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

package flags

import (
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/urfave/cli/v2"
)

// DirectoryString is custom type which is registered in the flags library which cli uses for
// argument parsing. This allows us to expand Value to an absolute path when
// the argument is parsed
type DirectoryString string

func (s *DirectoryString) String() string {
	return string(*s)
}

func (s *DirectoryString) Set(value string) error {
	*s = DirectoryString(expandPath(value))
	return nil
}

// DirectoryFlag is custom cli.Flag type which expand the received string to an absolute path.
// e.g. ~/.ethereum -> /home/username/.ethereum
type DirectoryFlag struct {
	Name string

	Category    string
	DefaultText string
	Usage       string

	Required   bool
	Hidden     bool
	HasBeenSet bool

	Value DirectoryString

	Aliases []string
	EnvVars []string
}

// For cli.Flag:

func (f *DirectoryFlag) Names() []string { return append([]string{f.Name}, f.Aliases...) }
func (f *DirectoryFlag) IsSet() bool     { return f.HasBeenSet }
func (f *DirectoryFlag) String() string  { return cli.FlagStringer(f) }

// Apply called by cli library, grabs variable from environment (if in env)
// and adds variable to flag set for parsing.
func (f *DirectoryFlag) Apply(set *flag.FlagSet) error {
	for _, envVar := range f.EnvVars {
		envVar = strings.TrimSpace(envVar)
		if value, found := syscall.Getenv(envVar); found {
			f.Value.Set(value)
			f.HasBeenSet = true
			break
		}
	}
	eachName(f, func(name string) {
		set.Var(&f.Value, name, f.Usage)
	})
	return nil
}

// For cli.RequiredFlag:

func (f *DirectoryFlag) IsRequired() bool { return f.Required }

// For cli.VisibleFlag:

func (f *DirectoryFlag) IsVisible() bool { return !f.Hidden }

// For cli.CategorizableFlag:

func (f *DirectoryFlag) GetCategory() string { return f.Category }

// For cli.DocGenerationFlag:

func (f *DirectoryFlag) TakesValue() bool     { return true }
func (f *DirectoryFlag) GetUsage() string     { return f.Usage }
func (f *DirectoryFlag) GetValue() string     { return f.Value.String() }
func (f *DirectoryFlag) GetEnvVars() []string { return f.EnvVars }

func (f *DirectoryFlag) GetDefaultText() string {
	if f.DefaultText != "" {
		return f.DefaultText
	}
	return f.GetValue()
}

//var (
//	_ cli.Flag              = (*BigFlag)(nil)
//	_ cli.RequiredFlag      = (*BigFlag)(nil)
//	_ cli.VisibleFlag       = (*BigFlag)(nil)
//	_ cli.DocGenerationFlag = (*BigFlag)(nil)
//	_ cli.CategorizableFlag = (*BigFlag)(nil)
//)

// Expands a file path
// 1. replace tilde with users home dir
// 2. expands embedded environment variables
// 3. cleans the path, e.g. /a/b/../c -> /a/c
// Note, it has limitations, e.g. ~someuser/tmp will not be expanded
func expandPath(p string) string {
	// Named pipes are not file paths on windows, ignore
	if strings.HasPrefix(p, `\\.\pipe`) {
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home := HomeDir(); home != "" {
			p = home + p[1:]
		}
	}
	return filepath.Clean(os.ExpandEnv(p))
}

func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

func eachName(f cli.Flag, fn func(string)) {
	for _, name := range f.Names() {
		name = strings.Trim(name, " ")
		fn(name)
	}
}
