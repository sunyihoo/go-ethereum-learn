// The MIT License (MIT)
//
// Copyright (c) 2016 Muhammed Thanish
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package graphql

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/ethereum/go-ethereum/graphql/internal/graphiql"
	"github.com/ethereum/go-ethereum/log"
)

// GraphiQL is an in-browser IDE for exploring GraphiQL APIs.
// This handler returns GraphiQL when requested.
//
// For more information, see https://github.com/graphql/graphiql.
// GraphiQL 是一个用于探索 GraphiQL API 的浏览器内 IDE。
// 这个处理程序在请求时返回 GraphiQL。
//
// 更多信息，请参见 https://github.com/graphql/graphiql。
type GraphiQL struct{}

func respOk(w http.ResponseWriter, body []byte, ctype string) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}

// respOk 函数将成功的响应写入 HTTP 响应流，包括内容类型和安全头。

func respErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	errMsg, _ := json.Marshal(struct {
		Error string
	}{Error: msg})
	w.Write(errMsg)
}

// respErr 函数将错误响应写入 HTTP 响应流，以 JSON 格式返回错误信息。

func (h GraphiQL) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respErr(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	// 如果请求方法不是 GET，则返回“仅允许 GET”错误，状态码为 405。

	switch r.URL.Path {
	case "/graphql/ui/graphiql.min.css":
		data, err := graphiql.Assets.ReadFile(filepath.Base(r.URL.Path))
		if err != nil {
			log.Warn("Error loading graphiql asset", "err", err)
			respErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		respOk(w, data, "text/css")
		// 处理 GraphiQL 的 CSS 文件请求，从嵌入资源中读取并返回。
	case "/graphql/ui/graphiql.min.js",
		"/graphql/ui/react.production.min.js",
		"/graphql/ui/react-dom.production.min.js":
		data, err := graphiql.Assets.ReadFile(filepath.Base(r.URL.Path))
		if err != nil {
			log.Warn("Error loading graphiql asset", "err", err)
			respErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		respOk(w, data, "application/javascript; charset=utf-8")
		// 处理 GraphiQL 和 React 的 JS 文件请求，从嵌入资源中读取并返回。
		// 详细解释：
		// 1. `graphiql.Assets.ReadFile` 从嵌入的资源（如 go-bindata 或 embed.FS）中读取文件。
		// 2. 支持多个 JS 文件，包括 GraphiQL 主脚本和 React 库。
		// 3. 设置 MIME 类型为 JavaScript，并指定 UTF-8 编码。
	default:
		data, err := graphiql.Assets.ReadFile("index.html")
		if err != nil {
			log.Warn("Error loading graphiql asset", "err", err)
			respErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		respOk(w, data, "text/html")
		// 默认情况下返回 GraphiQL 的 HTML 主页面。
	}
}
