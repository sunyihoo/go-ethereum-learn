// Copyright 2019 The go-ethereum Authors
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

package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/graph-gophers/graphql-go"
	gqlErrors "github.com/graph-gophers/graphql-go/errors"
)

// 以太坊后端（ethapi.Backend）：
// backend 是以太坊节点的 API 接口，提供对区块链数据的访问，如区块头、交易收据等。
// 这里的 Resolver 使用它来解析 GraphQL 查询。

// GraphQL 是一种查询语言，相比传统的 REST API，它允许客户端灵活指定所需数据结构。在以太坊中，GraphQL 常用于替代 JSON-RPC 接口，提供更高效的数据查询方式。
// 这段代码可能用于以太坊客户端（如 Geth）的扩展功能，通过 GraphQL 暴露区块链数据。

type handler struct {
	Schema *graphql.Schema
}

// ServeHTTP handles GraphQL requests over HTTP.
func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var params struct {
		Query         string                 `json:"query"`
		OperationName string                 `json:"operationName"`
		Variables     map[string]interface{} `json:"variables"`
	}
	// 定义一个结构体用于解析 HTTP 请求体中的 JSON 数据，包含 GraphQL 查询字符串、操作名称和变量。
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var (
		ctx       = r.Context()
		responded sync.Once
		timer     *time.Timer
		cancel    context.CancelFunc
	)
	// 初始化上下文、同步控制变量、定时器和取消函数，用于管理请求的生命周期和超时处理。
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	if timeout, ok := rpc.ContextRequestTimeout(ctx); ok {
		timer = time.AfterFunc(timeout, func() {
			responded.Do(func() {
				// Cancel request handling.
				cancel()

				// Create the timeout response.
				response := &graphql.Response{
					Errors: []*gqlErrors.QueryError{{Message: "request timed out"}},
				}
				responseJSON, err := json.Marshal(response)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				// Setting this disables gzip compression in package node.
				w.Header().Set("Transfer-Encoding", "identity")

				// Flush the response. Since we are writing close to the response timeout,
				// chunked transfer encoding must be disabled by setting content-length.
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Length", strconv.Itoa(len(responseJSON)))
				w.Write(responseJSON)
				if flush, ok := w.(http.Flusher); ok {
					flush.Flush()
				}
			})
		})
		// 如果请求上下文指定了超时时间，则启动一个定时器，在超时后取消请求并返回超时响应。
		// 详细解释：
		// 1. `rpc.ContextRequestTimeout(ctx)` 检查上下文是否设置了超时时间。
		// 2. `time.AfterFunc` 在指定时间后执行匿名函数，调用 `responded.Do` 确保响应只发送一次。
		// 3. 超时后，构造一个带有错误信息的 GraphQL 响应，序列化为 JSON 并写入 HTTP 响应。
		// 4. 设置 `Transfer-Encoding` 和 `Content-Length` 头，确保响应在超时边缘正确传输，避免分块编码问题。
	}

	response := h.Schema.Exec(ctx, params.Query, params.OperationName, params.Variables)
	// 执行 GraphQL 查询，使用传入的查询字符串、操作名称和变量，返回查询结果。
	if timer != nil {
		timer.Stop()
	}
	responded.Do(func() {
		responseJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if len(response.Errors) > 0 {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Write(responseJSON)
	})
	// 将查询结果序列化为 JSON 并写入 HTTP 响应，如果有错误则返回 400 状态码。
}

// New constructs a new GraphQL service instance.
func New(stack *node.Node, backend ethapi.Backend, filterSystem *filters.FilterSystem, cors, vhosts []string) error {
	// 创建一个新的 GraphQL 服务实例，初始化相关组件并返回错误（如果有）。
	_, err := newHandler(stack, backend, filterSystem, cors, vhosts)
	return err
}

// newHandler returns a new `http.Handler` that will answer GraphQL queries.
// It additionally exports an interactive query browser on the / endpoint.
func newHandler(stack *node.Node, backend ethapi.Backend, filterSystem *filters.FilterSystem, cors, vhosts []string) (*handler, error) {
	// 构造一个新的 HTTP 处理程序，用于响应 GraphQL 查询，并支持交互式查询浏览器。
	q := Resolver{backend, filterSystem}

	s, err := graphql.ParseSchema(schema, &q)
	if err != nil {
		return nil, err
	}
	h := handler{Schema: s}
	handler := node.NewHTTPHandlerStack(h, cors, vhosts, nil)

	stack.RegisterHandler("GraphQL UI", "/graphql/ui", GraphiQL{})
	stack.RegisterHandler("GraphQL UI", "/graphql/ui/", GraphiQL{})
	stack.RegisterHandler("GraphQL", "/graphql", handler)
	stack.RegisterHandler("GraphQL", "/graphql/", handler)
	// 注册 GraphQL UI 和查询端点到节点栈中，支持 CORS 和虚拟主机配置。

	return &h, nil
}
