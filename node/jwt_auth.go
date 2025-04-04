// Copyright 2022 The go-ethereum Authors
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

package node

import (
	"fmt"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/golang-jwt/jwt/v4"
)

// EIP-3675（The Merge） ：该提案将共识机制从 PoW（工作量证明）切换到 PoS（权益证明），引入了共识层与执行层的分离。
// Engine API ：这是合并后新增的 JSON-RPC 接口集合，用于共识层与执行层之间的通信。JWT 身份验证是其核心安全机制之一。

// 1. JWT 身份验证机制
// JWT（JSON Web Token） 是一种开放标准（RFC 7519），用于在网络应用间安全地传递信息。它由三部分组成：
//  Header ：描述签名算法和令牌类型。
//  Payload ：包含声明（claims），例如签发时间（iat）、过期时间（exp）等。
//  Signature ：通过指定的算法（如 HMAC-SHA256）对前两部分进行签名，确保令牌未被篡改。
// 在以太坊的 Engine API 中，JWT 被用作客户端与执行层（Execution Layer）之间的身份验证机制。
// 2. Engine API 身份验证规范
// Engine API 是以太坊合并（The Merge）后引入的核心接口，用于共识层（Consensus Layer，如信标链）与执行层之间的通信。
// 根据 Engine API Authentication Spec ，JWT 的密钥必须是 32 字节（256 位），并使用 HMAC-SHA256 算法进行签名。
// 这种设计确保了通信的安全性和完整性，防止未经授权的访问。

// NewJWTAuth creates an rpc client authentication provider that uses JWT. The
// secret MUST be 32 bytes (256 bits) as defined by the Engine-API authentication spec.
// NewJWTAuth 创建一个使用 JWT 的 RPC 客户端身份验证提供程序。
// 密钥必须为 32 字节（256 位），这是由 Engine-API 身份验证规范定义的。
//
// See https://github.com/ethereum/execution-apis/blob/main/src/engine/authentication.md
// for more details about this authentication scheme.
// 有关此身份验证方案的更多详细信息，请参阅上述链接。
func NewJWTAuth(jwtsecret [32]byte) rpc.HTTPAuth {
	return func(h http.Header) error {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iat": &jwt.NumericDate{Time: time.Now()}, // iat 表示签发时间（Issued At），用于防止重放攻击
		})
		s, err := token.SignedString(jwtsecret[:]) // 使用 HMAC-SHA256 签名方法生成签名后的 JWT 字符串
		if err != nil {
			return fmt.Errorf("failed to create JWT token: %w", err) // 如果生成 JWT 失败，返回错误
		}
		h.Set("Authorization", "Bearer "+s) // 将生成的 JWT 添加到 HTTP 请求头中，格式为 "Bearer <token>"
		return nil
	}
}
