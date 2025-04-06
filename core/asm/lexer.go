// Copyright 2017 The go-ethereum Authors
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

package asm

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// stateFn is used through the lifetime of the
// lexer to parse the different values at the
// current state.
// stateFn 在词法分析器的生命周期中用于解析当前状态下的不同值
type stateFn func(*lexer) stateFn

// token is emitted when the lexer has discovered
// a new parsable token. These are delivered over
// the tokens channels of the lexer
// token 在词法分析器发现新的可解析标记时发出，通过词法分析器的标记通道传递
type token struct {
	typ    tokenType // 标记类型
	lineno int       // 行号
	text   string    // 标记文本
}

// tokenType are the different types the lexer
// is able to parse and return.
// tokenType 是词法分析器能够解析并返回的不同类型
type tokenType int

//go:generate go run golang.org/x/tools/cmd/stringer -type tokenType

const (
	eof              tokenType = iota // end of file 文件结束
	lineStart                         // emitted when a line starts 行开始时发出
	lineEnd                           // emitted when a line ends 行结束时发出
	invalidStatement                  // any invalid statement 任何无效语句
	element                           // any element during element parsing 元素解析中的任何元素
	label                             // label is emitted when a label is found 发现标签时发出
	labelDef                          // label definition is emitted when a new label is found 发现新标签定义时发出
	number                            // number is emitted when a number is found 发现数字时发出
	stringValue                       // stringValue is emitted when a string has been found 发现字符串时发出
)

const (
	decimalNumbers = "1234567890"                                           // characters representing any decimal number 表示任何十进制数字的字符
	hexNumbers     = decimalNumbers + "aAbBcCdDeEfF"                        // characters representing any hexadecimal 表示任何十六进制的字符
	alpha          = "abcdefghijklmnopqrstuwvxyzABCDEFGHIJKLMNOPQRSTUWVXYZ" // characters representing alphanumeric 表示字母数字的字符
)

// lexer is the basic construct for parsing
// source code and turning them in to tokens.
// Tokens are interpreted by the compiler.
// lexer 是解析源代码并将其转换为标记的基本结构。
// 标记由编译器解释。
type lexer struct {
	input string // input contains the source code of the program
	// input 包含程序的源代码

	tokens chan token // tokens is used to deliver tokens to the listener
	// tokens 用于向监听器传递标记
	state stateFn // the current state function
	// 当前状态函数

	lineno int // current line number in the source file
	// 源文件中的当前行号
	start, pos, width int // positions for lexing and returning value
	// 用于词法分析和返回值的定位

	debug bool // flag for triggering debug output
	// 触发调试输出的标志
}

// Lex lexes the program by name with the given source. It returns a
// channel on which the tokens are delivered.
// Lex 使用给定的源代码对程序进行词法分析。它返回一个传递标记的通道。
func Lex(source []byte, debug bool) <-chan token {
	ch := make(chan token)
	l := &lexer{
		input:  string(source),
		tokens: ch,
		state:  lexLine,
		debug:  debug,
	}
	go func() {
		l.emit(lineStart)
		for l.state != nil {
			l.state = l.state(l)
		}
		l.emit(eof)
		close(l.tokens)
	}()

	return ch
}

// next returns the next rune in the program's source.
// next 返回程序源代码中的下一个符文
func (l *lexer) next() (rune rune) {
	if l.pos >= len(l.input) {
		l.width = 0
		return 0
	}
	rune, l.width = utf8.DecodeRuneInString(l.input[l.pos:])
	l.pos += l.width
	return rune
}

// backup backsup the last parsed element (multi-character)
// backup 备份最后解析的元素（多字符）
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek returns the next rune but does not advance the seeker
// peek 返回下一个符文但不推进 seeker
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// ignore advances the seeker and ignores the value
// ignore 推进 seeker 并忽略值
func (l *lexer) ignore() {
	l.start = l.pos
}

// accept checks whether the given input matches the next rune
// accept 检查给定输入是否与下一个符文匹配
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}

	l.backup()

	return false
}

// acceptRun will continue to advance the seeker until valid
// can no longer be met.
// acceptRun 将继续推进 seeker，直到 valid 不再满足为止
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// acceptRunUntil is the inverse of acceptRun and will continue
// to advance the seeker until the rune has been found.
// acceptRunUntil 是 acceptRun 的反向操作，将继续推进 seeker，直到找到符文为止
func (l *lexer) acceptRunUntil(until rune) bool {
	// Continues running until a rune is found
	// 继续运行直到找到符文
	for i := l.next(); !strings.ContainsRune(string(until), i); i = l.next() {
		if i == 0 {
			return false
		}
	}

	return true
}

// blob returns the current value
// blob 返回当前值
func (l *lexer) blob() string {
	return l.input[l.start:l.pos]
}

// Emits a new token on to token channel for processing
// emit 将新标记发射到标记通道进行处理
func (l *lexer) emit(t tokenType) {
	token := token{t, l.lineno, l.blob()}

	if l.debug {
		fmt.Fprintf(os.Stderr, "%04d: (%-20v) %s\n", token.lineno, token.typ, token.text)
	}

	l.tokens <- token
	l.start = l.pos
}

// lexLine is state function for lexing lines
// lexLine 是用于词法分析行的状态函数
func lexLine(l *lexer) stateFn {
	for {
		switch r := l.next(); {
		case r == '\n':
			l.emit(lineEnd)
			l.ignore()
			l.lineno++
			l.emit(lineStart)
		case r == ';' && l.peek() == ';':
			return lexComment
		case isSpace(r):
			l.ignore()
		case isLetter(r) || r == '_':
			return lexElement
		case isNumber(r):
			return lexNumber
		case r == '@':
			l.ignore()
			return lexLabel
		case r == '"':
			return lexInsideString
		default:
			return nil
		}
	}
}

// lexComment parses the current position until the end
// of the line and discards the text.
// lexComment 解析当前位置直到行尾并丢弃文本
func lexComment(l *lexer) stateFn {
	l.acceptRunUntil('\n')
	l.backup()
	l.ignore()

	return lexLine
}

// lexLabel parses the current label, emits and returns
// the lex text state function to advance the parsing
// process.
// lexLabel 解析当前标签，发出并返回 lex 文本状态函数以推进解析过程
func lexLabel(l *lexer) stateFn {
	l.acceptRun(alpha + "_" + decimalNumbers)

	l.emit(label)

	return lexLine
}

// lexInsideString lexes the inside of a string until
// the state function finds the closing quote.
// It returns the lex text state function.
// lexInsideString 解析字符串内部，直到状态函数找到结束引号。
// 它返回 lex 文本状态函数。
func lexInsideString(l *lexer) stateFn {
	if l.acceptRunUntil('"') {
		l.emit(stringValue)
	}

	return lexLine
}

func lexNumber(l *lexer) stateFn {
	acceptance := decimalNumbers
	if l.accept("xX") {
		acceptance = hexNumbers
	}
	l.acceptRun(acceptance)

	l.emit(number)

	return lexLine
}

func lexElement(l *lexer) stateFn {
	l.acceptRun(alpha + "_" + decimalNumbers)

	if l.peek() == ':' {
		l.emit(labelDef)

		l.accept(":")
		l.ignore()
	} else {
		l.emit(element)
	}
	return lexLine
}

func isLetter(t rune) bool {
	return unicode.IsLetter(t)
}

func isSpace(t rune) bool {
	return unicode.IsSpace(t)
}

func isNumber(t rune) bool {
	return unicode.IsNumber(t)
}
