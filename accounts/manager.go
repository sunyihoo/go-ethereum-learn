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

package accounts

import (
	"reflect"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
)

// 账户管理器 (Account Manager): 在以太坊客户端中，账户管理器负责管理用户的以太坊账户，包括存储密钥、签署交易和消息等。go-ethereum 的 Manager 实现了这个角色，但它更侧重于管理多个不同的钱包后端。
// 钱包后端 (Wallet Backend): 指的是提供钱包功能的具体实现。例如，可以有管理密钥库文件的后端、与硬件钱包交互的后端等。Manager 的设计允许集成多种不同的后端，并为上层应用提供统一的接口。
// 事件订阅 (Event Subscription): 是一种异步通信机制，允许对象订阅并接收特定事件的通知。在这里，Manager 订阅了来自各个后端关于钱包状态变化的事件。
// 并发控制 (Concurrency Control): 由于 Manager 需要处理来自不同后端的事件，并且可能被多个 Goroutine 同时访问，因此需要使用锁（如 sync.RWMutex）来保护共享资源，防止数据竞争。
// 排序 (Sorting): Manager 维护了一个按钱包 URL 排序的钱包列表。这有助于提高查找特定钱包的效率。

// managerSubBufferSize determines how many incoming wallet events
// the manager will buffer in its channel.
// managerSubBufferSize 决定了管理器在其通道中缓冲多少个传入的钱包事件。
const managerSubBufferSize = 50

// Config is a legacy struct which is not used
// Config 是一个遗留结构体，目前未使用。
type Config struct {
	InsecureUnlockAllowed bool // Unused legacy-parameter
	// InsecureUnlockAllowed：未使用的遗留参数
}

// newBackendEvent lets the manager know it should
// track the given backend for wallet updates.
// newBackendEvent 通知管理器应该跟踪给定的后端以获取钱包更新。
type newBackendEvent struct {
	backend   Backend
	processed chan struct{} // Informs event emitter that backend has been integrated
	// processed：通知事件发送器后端已被集成
}

// Manager is an overarching account manager that can communicate with various
// backends for signing transactions.
// Manager 是一个总体的账户管理器，可以与各种后端通信以进行交易签名。
type Manager struct {
	backends map[reflect.Type][]Backend // Index of backends currently registered
	// backends：当前注册的后端的索引，键是后端类型，值是该类型后端的切片
	updaters []event.Subscription // Wallet update subscriptions for all backends
	// updaters：所有后端的钱包更新订阅列表
	updates chan WalletEvent // Subscription sink for backend wallet changes
	// updates：后端钱包更改的订阅接收通道
	newBackends chan newBackendEvent // Incoming backends to be tracked by the manager
	// newBackends：需要管理器跟踪的新后端通道
	wallets []Wallet // Cache of all wallets from all registered backends
	// wallets：来自所有已注册后端的钱包缓存
	feed event.Feed // Wallet feed notifying of arrivals/departures
	// feed：钱包事件通知，用于通知钱包的到来和离开
	quit chan chan error
	term chan struct{} // Channel is closed upon termination of the update loop
	// term：当更新循环终止时关闭的通道
	lock sync.RWMutex
}

// NewManager creates a generic account manager to sign transaction via various
// supported backends.
// NewManager 创建一个通用的账户管理器，用于通过各种受支持的后端进行交易签名。
func NewManager(config *Config, backends ...Backend) *Manager {
	// Retrieve the initial list of wallets from the backends and sort by URL
	// 从后端检索初始钱包列表并按 URL 排序
	var wallets []Wallet
	for _, backend := range backends {
		wallets = merge(wallets, backend.Wallets()...)
	}
	// Subscribe to wallet notifications from all backends
	// 订阅来自所有后端的钱包通知
	updates := make(chan WalletEvent, managerSubBufferSize)

	subs := make([]event.Subscription, len(backends))
	for i, backend := range backends {
		subs[i] = backend.Subscribe(updates)
	}
	// Assemble the account manager and return
	// 组装账户管理器并返回
	am := &Manager{
		backends:    make(map[reflect.Type][]Backend),
		updaters:    subs,
		updates:     updates,
		newBackends: make(chan newBackendEvent),
		wallets:     wallets,
		quit:        make(chan chan error),
		term:        make(chan struct{}),
	}
	for _, backend := range backends {
		kind := reflect.TypeOf(backend)
		am.backends[kind] = append(am.backends[kind], backend)
	}
	go am.update()

	return am
}

// Close terminates the account manager's internal notification processes.
// Close 终止账户管理器的内部通知进程。
func (am *Manager) Close() error {
	for _, w := range am.wallets {
		w.Close()
	}
	errc := make(chan error)
	am.quit <- errc
	return <-errc
}

// AddBackend starts the tracking of an additional backend for wallet updates.
// cmd/geth assumes once this func returns the backends have been already integrated.
// AddBackend 开始跟踪额外的后端以获取钱包更新。cmd/geth 假设一旦此函数返回，后端就已集成完毕。
func (am *Manager) AddBackend(backend Backend) {
	done := make(chan struct{})
	am.newBackends <- newBackendEvent{backend, done}
	<-done
}

// update is the wallet event loop listening for notifications from the backends
// and updating the cache of wallets.
// update 是钱包事件循环，监听来自后端的通知并更新钱包缓存。
func (am *Manager) update() {
	// Close all subscriptions when the manager terminates
	// 当管理器终止时，关闭所有订阅
	defer func() {
		am.lock.Lock()
		for _, sub := range am.updaters {
			sub.Unsubscribe()
		}
		am.updaters = nil
		am.lock.Unlock()
	}()

	// Loop until termination
	// 循环直到终止
	for {
		select {
		case event := <-am.updates:
			// Wallet event arrived, update local cache
			// 钱包事件到达，更新本地缓存
			am.lock.Lock()
			switch event.Kind {
			case WalletArrived:
				am.wallets = merge(am.wallets, event.Wallet)
			case WalletDropped:
				am.wallets = drop(am.wallets, event.Wallet)
			}
			am.lock.Unlock()

			// Notify any listeners of the event
			// 通知任何监听器该事件
			am.feed.Send(event)
		case event := <-am.newBackends:
			am.lock.Lock()
			// Update caches
			// 更新缓存
			backend := event.backend
			am.wallets = merge(am.wallets, backend.Wallets()...)
			am.updaters = append(am.updaters, backend.Subscribe(am.updates))
			kind := reflect.TypeOf(backend)
			am.backends[kind] = append(am.backends[kind], backend)
			am.lock.Unlock()
			close(event.processed)
		case errc := <-am.quit:
			// Manager terminating, return
			// 管理器正在终止，返回
			errc <- nil
			// Signals event emitters the loop is not receiving values
			// to prevent them from getting stuck.
			// 通知事件发送器循环不再接收值，以防止它们卡住。
			close(am.term)
			return
		}
	}
}

// Backends retrieves the backend(s) with the given type from the account manager.
// Backends 从账户管理器中检索具有给定类型的后端。
func (am *Manager) Backends(kind reflect.Type) []Backend {
	am.lock.RLock()
	defer am.lock.RUnlock()

	return am.backends[kind]
}

// Wallets returns all signer accounts registered under this account manager.
// Wallets 返回在此账户管理器下注册的所有签名账户（钱包）。
func (am *Manager) Wallets() []Wallet {
	am.lock.RLock()
	defer am.lock.RUnlock()

	return am.walletsNoLock()
}

// walletsNoLock returns all registered wallets. Callers must hold am.lock.
// walletsNoLock 返回所有已注册的钱包。调用者必须持有 am.lock。
func (am *Manager) walletsNoLock() []Wallet {
	cpy := make([]Wallet, len(am.wallets))
	copy(cpy, am.wallets)
	return cpy
}

// Wallet retrieves the wallet associated with a particular URL.
// Wallet 检索与特定 URL 关联的钱包。
func (am *Manager) Wallet(url string) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	parsed, err := parseURL(url)
	if err != nil {
		return nil, err
	}
	for _, wallet := range am.walletsNoLock() {
		if wallet.URL() == parsed {
			return wallet, nil
		}
	}
	return nil, ErrUnknownWallet
}

// Accounts returns all account addresses of all wallets within the account manager
// Accounts 返回账户管理器中所有钱包的所有账户地址。
func (am *Manager) Accounts() []common.Address {
	am.lock.RLock()
	defer am.lock.RUnlock()

	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, wallet := range am.wallets {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// Find attempts to locate the wallet corresponding to a specific account. Since
// accounts can be dynamically added to and removed from wallets, this method has
// a linear runtime in the number of wallets.
// Find 尝试查找与特定账户对应的钱包。由于账户可以动态地添加到钱包和从钱包中删除，因此此方法的运行时复杂度与钱包数量成线性关系。
func (am *Manager) Find(account Account) (Wallet, error) {
	am.lock.RLock()
	defer am.lock.RUnlock()

	for _, wallet := range am.wallets {
		if wallet.Contains(account) {
			return wallet, nil
		}
	}
	return nil, ErrUnknownAccount
}

// Subscribe creates an async subscription to receive notifications when the
// manager detects the arrival or departure of a wallet from any of its backends.
// Subscribe 创建一个异步订阅，以便在管理器检测到任何后端中的钱包的到来或离开时接收通知。
func (am *Manager) Subscribe(sink chan<- WalletEvent) event.Subscription {
	return am.feed.Subscribe(sink)
}

// merge is a sorted analogue of append for wallets, where the ordering of the
// origin list is preserved by inserting new wallets at the correct position.
// merge 是钱包的排序追加操作，它通过在正确的位置插入新钱包来保留原始列表的顺序。
//
// The original slice is assumed to be already sorted by URL.
// 假设原始切片已按 URL 排序。
func merge(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			slice = append(slice, wallet)
			continue
		}
		slice = append(slice[:n], append([]Wallet{wallet}, slice[n:]...)...)
	}
	return slice
}

// drop is the counterpart of merge, which looks up wallets from within the sorted
// cache and removes the ones specified.
// drop 是 merge 的对应操作，它在已排序的缓存中查找指定的钱包并将其删除。
func drop(slice []Wallet, wallets ...Wallet) []Wallet {
	for _, wallet := range wallets {
		n := sort.Search(len(slice), func(i int) bool { return slice[i].URL().Cmp(wallet.URL()) >= 0 })
		if n == len(slice) {
			// Wallet not found, may happen during startup
			// 未找到钱包，可能发生在启动期间
			continue
		}
		slice = append(slice[:n], slice[n+1:]...)
	}
	return slice
}
