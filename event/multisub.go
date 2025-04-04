// Copyright 2023 The go-ethereum Authors
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

package event

// 在以太坊开发中，我们经常需要管理多个并发的操作或者监听多个不同的事件源。例如：
//
// 订阅多个智能合约的事件: 一个应用可能需要同时监听多个智能合约发出的不同类型的事件。使用 JoinSubscriptions 可以将这些独立的事件订阅合并为一个，方便在不需要这些事件时统一取消监听。
// 监听多个区块链事件: Go-ethereum 客户端提供了订阅不同区块链事件（如新的区块头、日志等）的功能。如果一个模块需要同时监听多种类型的事件，可以使用 JoinSubscriptions 来管理这些订阅。
// 管理与多个节点的连接: 在某些场景下，应用可能需要与多个以太坊节点建立连接并进行订阅。JoinSubscriptions 可以用于统一管理这些连接的生命周期。

// JoinSubscriptions joins multiple subscriptions to be able to track them as
// one entity and collectively cancel them or consume any errors from them.
// JoinSubscriptions 将多个订阅连接在一起，以便能够将它们作为一个实体进行跟踪，并统一取消它们或处理它们的任何错误。
func JoinSubscriptions(subs ...Subscription) Subscription {
	return NewSubscription(func(unsubbed <-chan struct{}) error {
		// Unsubscribe all subscriptions before returning
		// 在返回之前取消所有订阅
		defer func() {
			for _, sub := range subs {
				sub.Unsubscribe()
			}
		}()
		// Wait for an error on any of the subscriptions and propagate up
		// 等待任何一个订阅上的错误，并向上层传递
		errc := make(chan error, len(subs))
		for i := range subs {
			go func(sub Subscription) {
				select {
				case err := <-sub.Err():
					if err != nil {
						errc <- err
					}
				case <-unsubbed:
				}
			}(subs[i])
		}

		select {
		case err := <-errc:
			return err
		case <-unsubbed:
			return nil
		}
	})
}
