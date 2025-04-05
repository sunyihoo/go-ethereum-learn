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

package prompt

import (
	"fmt"
	"strings"

	"github.com/peterh/liner"
)

// Stdin holds the stdin line reader (also using stdout for printing prompts).
// Only this reader may be used for input because it keeps an internal buffer.
// Stdin 保存标准输入的行读取器（同时使用标准输出打印提示信息）。
// 只能使用此读取器进行输入，因为它维护了一个内部缓冲区。
var Stdin = newTerminalPrompter()

// UserPrompter defines the methods needed by the console to prompt the user for
// various types of inputs.
// UserPrompter 定义了控制台用于提示用户输入的各种类型的方法。
type UserPrompter interface {
	// PromptInput displays the given prompt to the user and requests some textual
	// data to be entered, returning the input of the user.
	// PromptInput 显示给定的提示信息并请求用户输入文本数据，返回用户的输入。
	PromptInput(prompt string) (string, error)

	// PromptPassword displays the given prompt to the user and requests some textual
	// data to be entered, but one which must not be echoed out into the terminal.
	// The method returns the input provided by the user.
	// PromptPassword 显示给定的提示信息并请求用户输入文本数据，但不会在终端中回显输入内容。
	// 该方法返回用户提供的输入。
	PromptPassword(prompt string) (string, error)

	// PromptConfirm displays the given prompt to the user and requests a boolean
	// choice to be made, returning that choice.
	// PromptConfirm 显示给定的提示信息并请求用户做出布尔选择，返回该选择。
	PromptConfirm(prompt string) (bool, error)

	// SetHistory sets the input scrollback history that the prompter will allow
	// the user to scroll back to.
	// SetHistory 设置提示器允许用户回滚的历史记录。
	SetHistory(history []string)

	// AppendHistory appends an entry to the scrollback history. It should be called
	// if and only if the prompt to append was a valid command.
	// AppendHistory 将条目追加到回滚历史记录中。仅当要追加的提示是有效命令时才应调用。
	AppendHistory(command string)

	// ClearHistory clears the entire history
	// ClearHistory 清除所有历史记录。
	ClearHistory()

	// SetWordCompleter sets the completion function that the prompter will call to
	// fetch completion candidates when the user presses tab.
	// SetWordCompleter 设置提示器在用户按下 Tab 键时调用的补全函数以获取补全候选项。
	SetWordCompleter(completer WordCompleter)
}

// WordCompleter takes the currently edited line with the cursor position and
// returns the completion candidates for the partial word to be completed. If
// the line is "Hello, wo!!!" and the cursor is before the first '!', ("Hello,
// wo!!!", 9) is passed to the completer which may returns ("Hello, ", {"world",
// "Word"}, "!!!") to have "Hello, world!!!".
// WordCompleter 接收当前编辑的行和光标位置，并返回部分单词的补全候选项。
// 如果行是 "Hello, wo!!!" 且光标在第一个 '!' 之前，则传递 ("Hello, wo!!!", 9) 给补全器，
// 补全器可能返回 ("Hello, ", {"world", "Word"}, "!!!") 以生成 "Hello, world!!!"。
type WordCompleter func(line string, pos int) (string, []string, string)

// terminalPrompter is a UserPrompter backed by the liner package. It supports
// prompting the user for various input, among others for non-echoing password
// input.
// terminalPrompter 是一个由 liner 包支持的 UserPrompter 实现。它支持提示用户输入各种类型的数据，
// 包括不回显密码的输入。
type terminalPrompter struct {
	*liner.State                   // liner 的状态管理器，用于处理终端输入。
	warned       bool              // 是否已警告用户终端不受支持。
	supported    bool              // 当前终端是否支持 liner 功能。
	normalMode   liner.ModeApplier // 终端的普通模式（如回显模式）。
	rawMode      liner.ModeApplier // 终端的原始模式（如非回显模式）。
}

// newTerminalPrompter creates a liner based user input prompter working off the
// standard input and output streams.
// newTerminalPrompter 创建一个基于 liner 的用户输入提示器，使用标准输入和输出流。
func newTerminalPrompter() *terminalPrompter {
	p := new(terminalPrompter)
	// Get the original mode before calling NewLiner.
	// This is usually regular "cooked" mode where characters echo.
	// 在调用 NewLiner 之前获取原始模式。
	// 这通常是常规的“cooked”模式，字符会回显。
	normalMode, _ := liner.TerminalMode()
	// Turn on liner. It switches to raw mode.
	// 启用 liner。它会切换到原始模式。
	p.State = liner.NewLiner()
	rawMode, err := liner.TerminalMode()
	if err != nil || !liner.TerminalSupported() {
		p.supported = false // 如果终端不支持 liner 功能，标记为不支持。
	} else {
		p.supported = true
		p.normalMode = normalMode // 保存普通模式。
		p.rawMode = rawMode       // 保存原始模式。
		// Switch back to normal mode while we're not prompting.
		// 在未提示时切换回普通模式。
		normalMode.ApplyMode()
	}
	p.SetCtrlCAborts(true)                   // 设置 Ctrl+C 中断功能。
	p.SetTabCompletionStyle(liner.TabPrints) // 设置 Tab 键补全样式。
	p.SetMultiLineMode(true)                 // 启用多行模式。
	return p
}

// PromptInput displays the given prompt to the user and requests some textual
// data to be entered, returning the input of the user.
// PromptInput 显示给定的提示信息并请求用户输入文本数据，返回用户的输入。
func (p *terminalPrompter) PromptInput(prompt string) (string, error) {
	if p.supported {
		p.rawMode.ApplyMode()          // 切换到原始模式。
		defer p.normalMode.ApplyMode() // 提示完成后切换回普通模式。
	} else {
		// liner tries to be smart about printing the prompt
		// and doesn't print anything if input is redirected.
		// Un-smart it by printing the prompt always.
		// liner 试图智能地处理提示信息的打印，但如果输入被重定向则不会打印任何内容。
		// 强制始终打印提示信息。
		fmt.Print(prompt)
		prompt = ""
		defer fmt.Println()
	}
	return p.State.Prompt(prompt) // 调用 liner 的 Prompt 方法获取用户输入。
}

// PromptPassword displays the given prompt to the user and requests some textual
// data to be entered, but one which must not be echoed out into the terminal.
// The method returns the input provided by the user.
// PromptPassword 显示给定的提示信息并请求用户输入文本数据，但不会在终端中回显输入内容。
// 该方法返回用户提供的输入。
func (p *terminalPrompter) PromptPassword(prompt string) (passwd string, err error) {
	if p.supported {
		p.rawMode.ApplyMode()                 // 切换到原始模式。
		defer p.normalMode.ApplyMode()        // 提示完成后切换回普通模式。
		return p.State.PasswordPrompt(prompt) // 调用 liner 的 PasswordPrompt 方法获取密码输入。
	}
	if !p.warned {
		fmt.Println("!! Unsupported terminal, password will be echoed.") // 警告用户密码将被回显。
		p.warned = true
	}
	// Just as in Prompt, handle printing the prompt here instead of relying on liner.
	// 和 Prompt 方法一样，手动打印提示信息而不是依赖 liner。
	fmt.Print(prompt)
	passwd, err = p.State.Prompt("") // 调用 liner 的 Prompt 方法获取密码输入。
	fmt.Println()
	return passwd, err
}

// PromptConfirm displays the given prompt to the user and requests a boolean
// choice to be made, returning that choice.
// PromptConfirm 显示给定的提示信息并请求用户做出布尔选择，返回该选择。
func (p *terminalPrompter) PromptConfirm(prompt string) (bool, error) {
	input, err := p.Prompt(prompt + " [y/n] ")               // 提示用户输入 [y/n]。
	if len(input) > 0 && strings.EqualFold(input[:1], "y") { // 检查输入是否为 "y" 或 "Y"。
		return true, nil
	}
	return false, err
}

// SetHistory sets the input scrollback history that the prompter will allow
// the user to scroll back to.
// SetHistory 设置提示器允许用户回滚的历史记录。
func (p *terminalPrompter) SetHistory(history []string) {
	p.State.ReadHistory(strings.NewReader(strings.Join(history, "\n"))) // 将历史记录加载到 liner。
}

// AppendHistory appends an entry to the scrollback history.
// AppendHistory 将条目追加到回滚历史记录中。
func (p *terminalPrompter) AppendHistory(command string) {
	p.State.AppendHistory(command) // 将命令追加到 liner 的历史记录中。
}

// ClearHistory clears the entire history
// ClearHistory 清除所有历史记录。
func (p *terminalPrompter) ClearHistory() {
	p.State.ClearHistory() // 清除 liner 的历史记录。
}

// SetWordCompleter sets the completion function that the prompter will call to
// fetch completion candidates when the user presses tab.
// SetWordCompleter 设置提示器在用户按下 Tab 键时调用的补全函数以获取补全候选项。
func (p *terminalPrompter) SetWordCompleter(completer WordCompleter) {
	p.State.SetWordCompleter(liner.WordCompleter(completer)) // 设置 liner 的补全器。
}
