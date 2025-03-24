// Copyright 2020 The go-ethereum Authors
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

// signFile reads the contents of an input file and signs it (in armored format)
// with the key provided, placing the signature into the output file.

package signify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	// errInvalidKeyHeader 表示密钥头部不正确。
	errInvalidKeyHeader = errors.New("incorrect key header")
	// errInvalidKeyLength 表示密钥长度无效，不等于 104。
	errInvalidKeyLength = errors.New("invalid, key length != 104")
)

// parsePrivateKey 解析一个 Base64 编码的私钥字符串，返回私钥、头部和密钥编号。
//
// k：ed25519 私钥（64 字节）。
// header：密钥头部（2 字节）。
// keyNum：密钥编号（8 字节）。
//
// ed25519 私钥标准长度为 64 字节（32 字节种子 + 32 字节公钥推导数据）。
func parsePrivateKey(key string) (k ed25519.PrivateKey, header []byte, keyNum []byte, err error) {
	// 解码 Base64 编码的密钥字符串
	keydata, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, nil, nil, err
	}
	// 检查密钥数据长度是否为 104 字节
	if len(keydata) != 104 {
		return nil, nil, nil, errInvalidKeyLength
	}
	// 检查头部是否为 "Ed"
	if string(keydata[:2]) != "Ed" {
		return nil, nil, nil, errInvalidKeyHeader
	}
	// 返回私钥（后 64 字节）、头部（前 2 字节）和密钥编号（第 32 到 39 字节）
	return keydata[40:], keydata[:2], keydata[32:40], nil
}

// SignFile creates a signature of the input file.
//
// This accepts base64 keys in the format created by the 'signify' tool.
// The signature is written to the 'output' file.
//
// SignFile 创建输入文件的签名。
//
// 该函数接受由 'signify' 工具创建的 Base64 格式密钥。
// 签名将被写入 'output' 文件。
func SignFile(input string, output string, key string, untrustedComment string, trustedComment string) error {
	// Pre-check comments and ensure they're set to something.
	// 预检查评论，确保不含换行符并设置默认值
	if strings.IndexByte(untrustedComment, '\n') >= 0 {
		return errors.New("untrusted comment must not contain newline")
	}
	if strings.IndexByte(trustedComment, '\n') >= 0 {
		return errors.New("trusted comment must not contain newline")
	}
	if untrustedComment == "" {
		untrustedComment = "verify with " + input + ".pub"
	}
	if trustedComment == "" {
		trustedComment = fmt.Sprintf("timestamp:%d", time.Now().Unix())
	}

	filedata, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	// 解析 Base64 编码的私钥
	skey, header, keyNum, err := parsePrivateKey(key)
	if err != nil {
		return err
	}

	// Create the main data signature.
	// 创建主数据签名
	rawSig := ed25519.Sign(skey, filedata)
	var dataSig []byte
	dataSig = append(dataSig, header...) // 添加头部
	dataSig = append(dataSig, keyNum...) // 添加密钥编号
	dataSig = append(dataSig, rawSig...) // 添加原始签名

	// Create the comment signature.
	// 创建评论签名
	var commentSigInput []byte
	commentSigInput = append(commentSigInput, rawSig...)                 // 原始签名
	commentSigInput = append(commentSigInput, []byte(trustedComment)...) // 可信评论
	commentSig := ed25519.Sign(skey, commentSigInput)

	// Create the output file.
	// 创建输出文件内容
	var out = new(bytes.Buffer)
	fmt.Fprintln(out, "untrusted comment:", untrustedComment)
	fmt.Fprintln(out, base64.StdEncoding.EncodeToString(dataSig))
	fmt.Fprintln(out, "trusted comment:", trustedComment)
	fmt.Fprintln(out, base64.StdEncoding.EncodeToString(commentSig))
	return os.WriteFile(output, out.Bytes(), 0644)
}
