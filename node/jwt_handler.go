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
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Engine API 的安全需求 ：
// Engine API 是以太坊合并后引入的核心接口，用于共识层与执行层之间的通信。由于这些接口涉及区块提议、状态更新等敏感操作，因此需要强大的身份验证机制。
// JWT 的优势 ：
// JWT 是一种轻量级的身份验证机制，适合分布式系统中的无状态通信。通过签名和时间戳校验，JWT 提供了防篡改和防重放的能力。
// EIP-3675（The Merge） ：
// 该提案将共识机制从 PoW 切换到 PoS，引入了共识层与执行层的分离。JWT 身份验证是这一架构中的重要组成部分，确保两层之间的通信安全。

const jwtExpiryTimeout = 60 * time.Second // JWT 过期时间为 60 秒

type jwtHandler struct {
	keyFunc func(token *jwt.Token) (interface{}, error) // 提供密钥的函数
	next    http.Handler                                // 下一个处理程序
}

// newJWTHandler creates a http.Handler with jwt authentication support.
// newJWTHandler 创建一个支持 JWT 身份验证的 HTTP 处理程序。
func newJWTHandler(secret []byte, next http.Handler) http.Handler {
	return &jwtHandler{
		keyFunc: func(token *jwt.Token) (interface{}, error) {
			return secret, nil // 返回用于验证 JWT 的密钥
		},
		next: next,
	}
}

// JWT 验证的关键点
// 签名算法限制 ：
// 通过 jwt.WithValidMethods([]string{"HS256"}) 明确指定只允许使用 HMAC-SHA256 签名算法。这是 Engine API 的规范要求，确保安全性。
// 时间窗口校验 ：
// 通过 time.Since 和 time.Until 检查 iat 时间戳是否在允许的时间窗口内（±60 秒）。这种设计可以容忍轻微的时钟偏差，同时防止重放攻击。
// 声明校验的灵活性 ：
// 使用 jwt.WithoutClaimsValidation() 禁用默认的声明校验（如 exp 和 nbf），以便手动验证 iat 和其他自定义逻辑
// 。
// ServeHTTP implements http.Handler
// ServeHTTP 实现了 http.Handler 接口
func (handler *jwtHandler) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	var (
		strToken string               // 存储从请求头中提取的 JWT 字符串
		claims   jwt.RegisteredClaims // 用于解析 JWT 中的声明（claims）
	)
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		strToken = strings.TrimPrefix(auth, "Bearer ") // 提取 Bearer 后的 JWT 字符串
	}
	if len(strToken) == 0 {
		http.Error(out, "missing token", http.StatusUnauthorized) // 如果没有提供令牌，返回 401 错误
		return
	}
	// We explicitly set only HS256 allowed, and also disables the
	// claim-check: the RegisteredClaims internally requires 'iat' to
	// be no later than 'now', but we allow for a bit of drift.
	// 我们明确指定只允许使用 HS256 算法，并禁用声明校验：
	// RegisteredClaims 内部要求 'iat' 不晚于当前时间，但我们允许一些时间偏差。
	token, err := jwt.ParseWithClaims(strToken, &claims, handler.keyFunc,
		jwt.WithValidMethods([]string{"HS256"}), // 只允许使用 HMAC-SHA256 签名方法
		jwt.WithoutClaimsValidation())           // 禁用默认的声明校验

	switch {
	case err != nil:
		http.Error(out, err.Error(), http.StatusUnauthorized) // 如果解析或验证失败，返回 401 错误
	case !token.Valid:
		http.Error(out, "invalid token", http.StatusUnauthorized) // 如果令牌无效，返回 401 错误
	case !claims.VerifyExpiresAt(time.Now(), false): // optional
		http.Error(out, "token is expired", http.StatusUnauthorized) // 如果令牌已过期，返回 401 错误
	case claims.IssuedAt == nil:
		http.Error(out, "missing issued-at", http.StatusUnauthorized) // 如果缺少签发时间，返回 401 错误
	case time.Since(claims.IssuedAt.Time) > jwtExpiryTimeout:
		http.Error(out, "stale token", http.StatusUnauthorized) // 如果令牌太旧（超过 60 秒），返回 401 错误
	case time.Until(claims.IssuedAt.Time) > jwtExpiryTimeout:
		http.Error(out, "future token", http.StatusUnauthorized) // 如果令牌来自未来（超过 60 秒），返回 401 错误
	default:
		handler.next.ServeHTTP(out, r) // 如果令牌有效，调用下一个处理程序
	}
}
