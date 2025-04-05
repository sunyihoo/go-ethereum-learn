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

// This package implements support for smartcard-based hardware wallets such as
// the one written by Status: https://github.com/status-im/hardware-wallet
//
// This implementation of smartcard wallets have a different interaction process
// to other types of hardware wallet. The process works like this:
//
// 1. (First use with a given client) Establish a pairing between hardware
//    wallet and client. This requires a secret value called a 'pairing password'.
//    You can pair with an unpaired wallet with `personal.openWallet(URI, pairing password)`.
// 2. (First use only) Initialize the wallet, which generates a keypair, stores
//    it on the wallet, and returns it so the user can back it up. You can
//    initialize a wallet with `personal.initializeWallet(URI)`.
// 3. Connect to the wallet using the pairing information established in step 1.
//    You can connect to a paired wallet with `personal.openWallet(URI, PIN)`.
// 4. Interact with the wallet as normal.
//
// This package implements support for smartcard-based hardware wallets such as
// the one written by Status: https://github.com/status-im/hardware-wallet
// 这个包实现了对基于智能卡的硬件钱包的支持，例如由 Status 编写的硬件钱包：https://github.com/status-im/hardware-wallet
//
// This implementation of smartcard wallets have a different interaction process
// to other types of hardware wallet. The process works like this:
// 这种智能卡钱包的实现与其他类型的硬件钱包有不同的交互过程。其过程如下：
//
// 1. (First use with a given client) Establish a pairing between hardware
//    wallet and client. This requires a secret value called a 'pairing password'.
//    You can pair with an unpaired wallet with `personal.openWallet(URI, pairing password)`.
// 1. （首次与给定客户端使用）在硬件钱包和客户端之间建立配对。这需要一个称为“配对密码”的秘密值。
//    您可以通过 `personal.openWallet(URI, 配对密码)` 与未配对的钱包进行配对。
//
// 2. (First use only) Initialize the wallet, which generates a keypair, stores
//    it on the wallet, and returns it so the user can back it up. You can
//    initialize a wallet with `personal.initializeWallet(URI)`.
// 2. （仅首次使用）初始化钱包，这会生成一个密钥对，将其存储在钱包中，并返回给用户以便备份。
//    您可以通过 `personal.initializeWallet(URI)` 初始化钱包。
//
// 3. Connect to the wallet using the pairing information established in step 1.
//    You can connect to a paired wallet with `personal.openWallet(URI, PIN)`.
// 3. 使用第 1 步中建立的配对信息连接到钱包。
//    您可以通过 `personal.openWallet(URI, PIN)` 连接到已配对的钱包。
//
// 4. Interact with the wallet as normal.
// 4. 像平常一样与钱包交互。

package scwallet

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	pcsc "github.com/gballet/go-libpcsclite"
)

// Scheme is the URI prefix for smartcard wallets.
// Scheme 是智能卡钱包的 URI 前缀。
const Scheme = "keycard"

// refreshCycle is the maximum time between wallet refreshes (if USB hotplug
// notifications don't work).
// refreshCycle 是钱包刷新之间的最大时间（如果 USB 热插拔通知不起作用）。
const refreshCycle = time.Second

// refreshThrottling is the minimum time between wallet refreshes to avoid thrashing.
// refreshThrottling 是钱包刷新之间的最小时间，以避免过度刷新。
const refreshThrottling = 500 * time.Millisecond

// smartcardPairing contains information about a smart card we have paired with
// or might pair with the hub.
// smartcardPairing 包含与中心配对或可能配对的智能卡的信息。
type smartcardPairing struct {
	PublicKey    []byte                                     `json:"publicKey"`    // 公钥
	PairingIndex uint8                                      `json:"pairingIndex"` // 配对索引
	PairingKey   []byte                                     `json:"pairingKey"`   // 配对密钥
	Accounts     map[common.Address]accounts.DerivationPath `json:"accounts"`     // 账户地址到派生路径的映射
}

// Hub is a accounts.Backend that can find and handle generic PC/SC hardware wallets.
// Hub 是一个 accounts.Backend，可以发现并处理通用的 PC/SC 硬件钱包。
type Hub struct {
	scheme string // Protocol scheme prefixing account and wallet URLs.
	// 协议方案，用于为账户和钱包 URL 添加前缀。

	context  *pcsc.Client
	datadir  string
	pairings map[string]smartcardPairing

	refreshed time.Time // Time instance when the list of wallets was last refreshed
	// 上次刷新钱包列表的时间实例
	wallets map[string]*Wallet // Mapping from reader names to wallet instances
	// 从读取器名称到钱包实例的映射
	updateFeed event.Feed // Event feed to notify wallet additions/removals
	// 事件馈送，用于通知钱包的添加/移除
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	// 订阅范围，跟踪当前活动监听器
	updating bool // Whether the event notification loop is running
	// 事件通知循环是否正在运行

	quit chan chan error

	stateLock sync.RWMutex // Protects the internals of the hub from racey access
	// 保护中心的内部免受竞争访问
}

func (hub *Hub) readPairings() error {
	hub.pairings = make(map[string]smartcardPairing)
	pairingFile, err := os.Open(filepath.Join(hub.datadir, "smartcards.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer pairingFile.Close()

	pairingData, err := io.ReadAll(pairingFile)
	if err != nil {
		return err
	}
	var pairings []smartcardPairing
	if err := json.Unmarshal(pairingData, &pairings); err != nil {
		return err
	}

	for _, pairing := range pairings {
		hub.pairings[string(pairing.PublicKey)] = pairing
	}
	return nil
}

func (hub *Hub) writePairings() error {
	pairingFile, err := os.OpenFile(filepath.Join(hub.datadir, "smartcards.json"), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer pairingFile.Close()

	pairings := make([]smartcardPairing, 0, len(hub.pairings))
	for _, pairing := range hub.pairings {
		pairings = append(pairings, pairing)
	}

	pairingData, err := json.Marshal(pairings)
	if err != nil {
		return err
	}

	if _, err := pairingFile.Write(pairingData); err != nil {
		return err
	}

	return nil
}

func (hub *Hub) pairing(wallet *Wallet) *smartcardPairing {
	if pairing, ok := hub.pairings[string(wallet.PublicKey)]; ok {
		return &pairing
	}
	return nil
}

func (hub *Hub) setPairing(wallet *Wallet, pairing *smartcardPairing) error {
	if pairing == nil {
		delete(hub.pairings, string(wallet.PublicKey))
	} else {
		hub.pairings[string(wallet.PublicKey)] = *pairing
	}
	return hub.writePairings()
}

// NewHub creates a new hardware wallet manager for smartcards.
// NewHub 为智能卡创建新的硬件钱包管理器。
func NewHub(daemonPath string, scheme string, datadir string) (*Hub, error) {
	context, err := pcsc.EstablishContext(daemonPath, pcsc.ScopeSystem)
	if err != nil {
		return nil, err
	}
	hub := &Hub{
		scheme:  scheme,
		context: context,
		datadir: datadir,
		wallets: make(map[string]*Wallet),
		quit:    make(chan chan error),
	}
	if err := hub.readPairings(); err != nil {
		return nil, err
	}
	hub.refreshWallets()
	return hub, nil
}

// Wallets implements accounts.Backend, returning all the currently tracked smart
// cards that appear to be hardware wallets.
// Wallets 实现了 accounts.Backend，返回当前跟踪的所有看似硬件钱包的智能卡。
func (hub *Hub) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is up to date
	// 确保钱包列表是最新的
	hub.refreshWallets()

	hub.stateLock.RLock()
	defer hub.stateLock.RUnlock()

	cpy := make([]accounts.Wallet, 0, len(hub.wallets))
	for _, wallet := range hub.wallets {
		cpy = append(cpy, wallet)
	}
	sort.Sort(accounts.WalletsByURL(cpy))
	return cpy
}

// refreshWallets scans the devices attached to the machine and updates the
// list of wallets based on the found devices.
// refreshWallets 扫描连接到机器的设备，并根据发现的设备更新钱包列表。
func (hub *Hub) refreshWallets() {
	// Don't scan the USB like crazy it the user fetches wallets in a loop
	// 如果用户在循环中获取钱包，不要疯狂扫描 USB
	hub.stateLock.RLock()
	elapsed := time.Since(hub.refreshed)
	hub.stateLock.RUnlock()

	if elapsed < refreshThrottling {
		return
	}
	// Retrieve all the smart card reader to check for cards
	// 检索所有智能卡读取器以检查卡
	readers, err := hub.context.ListReaders()
	if err != nil {
		// This is a perverted hack, the scard library returns an error if no card
		// readers are present instead of simply returning an empty list. We don't
		// want to fill the user's log with errors, so filter those out.
		// 这是一个变态的 hack，scard 库在没有卡读取器时返回错误，而不是简单返回空列表。
		// 我们不想让用户的日志充满错误，所以过滤掉这些。
		if err.Error() != "scard: Cannot find a smart card reader." {
			log.Error("Failed to enumerate smart card readers", "err", err)
			return
		}
	}
	// Transform the current list of wallets into the new one
	// 将当前钱包列表转换为新的列表
	hub.stateLock.Lock()

	events := []accounts.WalletEvent{}
	seen := make(map[string]struct{})

	for _, reader := range readers {
		// Mark the reader as present
		// 标记读取器为存在
		seen[reader] = struct{}{}

		// If we already know about this card, skip to the next reader, otherwise clean up
		// 如果我们已经知道这张卡，跳到下一个读取器，否则清理
		if wallet, ok := hub.wallets[reader]; ok {
			if err := wallet.ping(); err == nil {
				continue
			}
			wallet.Close()
			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
			delete(hub.wallets, reader)
		}
		// New card detected, try to connect to it
		// 检测到新卡，尝试连接到它
		card, err := hub.context.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)
		if err != nil {
			log.Debug("Failed to open smart card", "reader", reader, "err", err)
			continue
		}
		wallet := NewWallet(hub, card)
		if err = wallet.connect(); err != nil {
			log.Debug("Failed to connect to smart card", "reader", reader, "err", err)
			card.Disconnect(pcsc.LeaveCard)
			continue
		}
		// Card connected, start tracking among the wallets
		// 卡已连接，开始在钱包中跟踪
		hub.wallets[reader] = wallet
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
	}
	// Remove any wallets no longer present
	// 移除不再存在的任何钱包
	for reader, wallet := range hub.wallets {
		if _, ok := seen[reader]; !ok {
			wallet.Close()
			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
			delete(hub.wallets, reader)
		}
	}
	hub.refreshed = time.Now()
	hub.stateLock.Unlock()

	for _, event := range events {
		hub.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of smart card wallets.
// Subscribe 实现了 accounts.Backend，创建异步订阅以接收智能卡钱包添加或移除的通知。
func (hub *Hub) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	// 我们需要互斥锁来可靠地启动/停止更新循环
	hub.stateLock.Lock()
	defer hub.stateLock.Unlock()

	// Subscribe the caller and track the subscriber count
	// 订阅调用者并跟踪订阅者计数
	sub := hub.updateScope.Track(hub.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	// 订阅者需要一个活动通知循环，启动它
	if !hub.updating {
		hub.updating = true
		go hub.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets managed
// by the smart card hub, and for firing wallet addition/removal events.
// updater 负责维护由智能卡中心管理的最新钱包列表，并触发钱包添加/移除事件。
func (hub *Hub) updater() {
	for {
		// TODO: Wait for a USB hotplug event (not supported yet) or a refresh timeout
		// TODO：等待 USB 热插拔事件（尚未支持）或刷新超时
		// <-hub.changes
		time.Sleep(refreshCycle)

		// Run the wallet refresher
		// 运行钱包刷新器
		hub.refreshWallets()

		// If all our subscribers left, stop the updater
		// 如果所有订阅者都离开，停止更新器
		hub.stateLock.Lock()
		if hub.updateScope.Count() == 0 {
			hub.updating = false
			hub.stateLock.Unlock()
			return
		}
		hub.stateLock.Unlock()
	}
}
