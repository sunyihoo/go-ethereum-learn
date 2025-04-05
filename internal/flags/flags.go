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
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/urfave/cli/v2"
)

// DirectoryString is custom type which is registered in the flags library which cli uses for
// argument parsing. This allows us to expand Value to an absolute path when
// the argument is parsed.
// DirectoryString 是一个自定义类型，注册在 CLI 的标志库中用于参数解析。
// 它允许在解析参数时将值扩展为绝对路径。
type DirectoryString string

func (s *DirectoryString) String() string {
	return string(*s) // 返回字符串形式的值。
}

func (s *DirectoryString) Set(value string) error {
	*s = DirectoryString(expandPath(value)) // 将输入值扩展为绝对路径并设置。
	return nil
}

var (
	_ cli.Flag              = (*DirectoryFlag)(nil)
	_ cli.RequiredFlag      = (*DirectoryFlag)(nil)
	_ cli.VisibleFlag       = (*DirectoryFlag)(nil)
	_ cli.DocGenerationFlag = (*DirectoryFlag)(nil)
	_ cli.CategorizableFlag = (*DirectoryFlag)(nil)
)

// DirectoryFlag is custom cli.Flag type which expand the received string to an absolute path.
// e.g. ~/.ethereum -> /home/username/.ethereum
// DirectoryFlag 是一个自定义的 CLI 标志类型，将接收到的字符串扩展为绝对路径。
type DirectoryFlag struct {
	Name string

	Category    string // 标志类别。
	DefaultText string // 默认文本。
	Usage       string // 使用说明。

	Required   bool // 是否必填。
	Hidden     bool // 是否隐藏。
	HasBeenSet bool // 是否已设置。

	Value DirectoryString // 值。

	Aliases []string // 别名。
	EnvVars []string // 环境变量。
}

// For cli.Flag:
func (f *DirectoryFlag) Names() []string { return append([]string{f.Name}, f.Aliases...) } // 返回标志名称及其别名。
func (f *DirectoryFlag) IsSet() bool     { return f.HasBeenSet }                           // 检查标志是否已设置。
func (f *DirectoryFlag) String() string  { return cli.FlagStringer(f) }                    // 返回标志的字符串表示。

// Apply called by cli library, grabs variable from environment (if in env)
// and adds variable to flag set for parsing.
// Apply 被 CLI 库调用，从环境变量中获取值（如果存在）并将其添加到标志集中进行解析。
func (f *DirectoryFlag) Apply(set *flag.FlagSet) error {
	for _, envVar := range f.EnvVars {
		envVar = strings.TrimSpace(envVar)
		if value, found := syscall.Getenv(envVar); found {
			f.Value.Set(value)  // 设置值。
			f.HasBeenSet = true // 标记为已设置。
			break
		}
	}
	eachName(f, func(name string) {
		set.Var(&f.Value, name, f.Usage) // 将标志添加到标志集。
	})
	return nil
}

// For cli.RequiredFlag:
func (f *DirectoryFlag) IsRequired() bool { return f.Required } // 检查标志是否为必填。

// For cli.VisibleFlag:
func (f *DirectoryFlag) IsVisible() bool { return !f.Hidden } // 检查标志是否可见。

// For cli.CategorizableFlag:
func (f *DirectoryFlag) GetCategory() string { return f.Category } // 获取标志类别。

// For cli.DocGenerationFlag:
func (f *DirectoryFlag) TakesValue() bool     { return true }             // 标志是否接受值。
func (f *DirectoryFlag) GetUsage() string     { return f.Usage }          // 获取使用说明。
func (f *DirectoryFlag) GetValue() string     { return f.Value.String() } // 获取当前值。
func (f *DirectoryFlag) GetEnvVars() []string { return f.EnvVars }        // 获取环境变量列表。
func (f *DirectoryFlag) GetDefaultText() string {
	if f.DefaultText != "" {
		return f.DefaultText
	}
	return f.GetValue() // 如果未设置默认文本，则返回当前值。
}

var (
	_ cli.Flag              = (*BigFlag)(nil)
	_ cli.RequiredFlag      = (*BigFlag)(nil)
	_ cli.VisibleFlag       = (*BigFlag)(nil)
	_ cli.DocGenerationFlag = (*BigFlag)(nil)
	_ cli.CategorizableFlag = (*BigFlag)(nil)
)

// BigFlag is a command line flag that accepts 256 bit big integers in decimal or
// hexadecimal syntax.
// BigFlag 是一个命令行标志，接受十进制或十六进制语法的 256 位大整数。
type BigFlag struct {
	Name string

	Category    string // 标志类别。
	DefaultText string // 默认文本。
	Usage       string // 使用说明。

	Required   bool // 是否必填。
	Hidden     bool // 是否隐藏。
	HasBeenSet bool // 是否已设置。

	Value        *big.Int // 值。
	defaultValue *big.Int // 默认值。

	Aliases []string // 别名。
	EnvVars []string // 环境变量。
}

// For cli.Flag:

func (f *BigFlag) Names() []string { return append([]string{f.Name}, f.Aliases...) } // 返回标志名称及其别名。
func (f *BigFlag) IsSet() bool     { return f.HasBeenSet }                           // 检查标志是否已设置。
func (f *BigFlag) String() string  { return cli.FlagStringer(f) }                    // 返回标志的字符串表示。

func (f *BigFlag) Apply(set *flag.FlagSet) error {
	// Set default value so that environment wont be able to overwrite it
	// 设置默认值以防止环境变量覆盖。
	if f.Value != nil {
		f.defaultValue = new(big.Int).Set(f.Value)
	}
	for _, envVar := range f.EnvVars {
		envVar = strings.TrimSpace(envVar)
		if value, found := syscall.Getenv(envVar); found {
			if _, ok := f.Value.SetString(value, 10); !ok {
				return fmt.Errorf("could not parse %q from environment variable %q for flag %s", value, envVar, f.Name)
			}
			f.HasBeenSet = true
			break
		}
	}
	eachName(f, func(name string) {
		f.Value = new(big.Int)
		set.Var((*bigValue)(f.Value), name, f.Usage) // 将标志添加到标志集。
	})
	return nil
}

// For cli.RequiredFlag:

func (f *BigFlag) IsRequired() bool { return f.Required } // 检查标志是否为必填。

// For cli.VisibleFlag:

func (f *BigFlag) IsVisible() bool { return !f.Hidden } // 检查标志是否可见。

// For cli.CategorizableFlag:

func (f *BigFlag) GetCategory() string { return f.Category } // 获取标志类别。

// For cli.DocGenerationFlag:

func (f *BigFlag) TakesValue() bool     { return true }             // 标志是否接受值。
func (f *BigFlag) GetUsage() string     { return f.Usage }          // 获取使用说明。
func (f *BigFlag) GetValue() string     { return f.Value.String() } // 获取当前值。
func (f *BigFlag) GetEnvVars() []string { return f.EnvVars }        // 获取环境变量列表。
func (f *BigFlag) GetDefaultText() string {
	if f.DefaultText != "" {
		return f.DefaultText
	}
	return f.defaultValue.String() // 如果未设置默认文本，则返回默认值。
}

// bigValue turns *big.Int into a flag.Value
// bigValue 将 *big.Int 转换为 flag.Value。
type bigValue big.Int

func (b *bigValue) String() string {
	if b == nil {
		return ""
	}
	return (*big.Int)(b).String() // 返回大整数的字符串表示。
}

func (b *bigValue) Set(s string) error {
	intVal, ok := math.ParseBig256(s) // 解析字符串为大整数。
	if !ok {
		return errors.New("invalid integer syntax") // 如果解析失败，返回错误。
	}
	*b = (bigValue)(*intVal) // 设置值。
	return nil
}

// GlobalBig returns the value of a BigFlag from the global flag set.
// GlobalBig 从全局标志集中返回 BigFlag 的值。
func GlobalBig(ctx *cli.Context, name string) *big.Int {
	val := ctx.Generic(name)
	if val == nil {
		return nil
	}
	return (*big.Int)(val.(*bigValue)) // 转换为 *big.Int 并返回。
}

// Expands a file path
// 1. replace tilde with users home dir
// 2. expands embedded environment variables
// 3. cleans the path, e.g. /a/b/../c -> /a/c
// Note, it has limitations, e.g. ~someuser/tmp will not be expanded
// expandPath 扩展文件路径：
// 1. 将波浪号替换为用户的主目录。
// 2. 展开嵌入的环境变量。
// 3. 清理路径，例如 /a/b/../c -> /a/c。
func expandPath(p string) string {
	// Named pipes are not file paths on windows, ignore
	// 在 Windows 上，命名管道不是文件路径，忽略。
	if strings.HasPrefix(p, `\\.\pipe`) {
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		if home := HomeDir(); home != "" {
			p = home + p[1:] // 替换波浪号为主目录。
		}
	}
	return filepath.Clean(os.ExpandEnv(p)) // 展开环境变量并清理路径。
}

func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home // 从环境变量 HOME 中获取主目录。
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir // 从用户信息中获取主目录。
	}
	return ""
}

func eachName(f cli.Flag, fn func(string)) {
	for _, name := range f.Names() {
		name = strings.Trim(name, " ")
		fn(name) // 遍历每个标志名称并执行回调函数。
	}
}
