// Copyright 2018 The go-ethereum Authors
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

package core

import (
	"errors"
	"regexp"
)

// 定义匹配可打印 7 位 ASCII 字符的正则表达式
var printable7BitAscii = regexp.MustCompile("^[A-Za-z0-9!\"#$%&'()*+,\\-./:;<=>?@[\\]^_`{|}~ ]+$")

// ValidatePasswordFormat returns an error if the password is too short, or consists of characters
// outside the range of the printable 7bit ascii set
// ValidatePasswordFormat 如果密码太短或包含可打印 7 位 ASCII 集范围外的字符，则返回错误
func ValidatePasswordFormat(password string) error {
	if len(password) < 10 {
		return errors.New("password too short (<10 characters)")
	}
	// 检查密码是否仅包含可打印 7 位 ASCII 字符
	if !printable7BitAscii.MatchString(password) {
		return errors.New("password contains invalid characters - only 7bit printable ascii allowed")
	}
	return nil
}
