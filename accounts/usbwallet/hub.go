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

package usbwallet

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/karalabe/hid"
)

// LedgerScheme is the protocol scheme prefixing account and wallet URLs.
// LedgerScheme 是账户和钱包 URL 前缀的协议方案。
const LedgerScheme = "ledger"

// TrezorScheme is the protocol scheme prefixing account and wallet URLs.
// TrezorScheme 是账户和钱包 URL 前缀的协议方案。
const TrezorScheme = "trezor"

// refreshCycle is the maximum time between wallet refreshes (if USB hotplug
// notifications don't work).
// refreshCycle 是钱包刷新之间的最大时间（如果 USB 热插拔通知不起作用）。
const refreshCycle = time.Second

// refreshThrottling is the minimum time between wallet refreshes to avoid USB
// trashing.
// refreshThrottling 是钱包刷新之间的最小时间，以避免 USB 过度操作。
const refreshThrottling = 500 * time.Millisecond

// Hub is a accounts.Backend that can find and handle generic USB hardware wallets.
// Hub 是一个 accounts.Backend，可以发现并处理通用的 USB 硬件钱包。
type Hub struct {
	scheme string // Protocol scheme prefixing account and wallet URLs.
	// 账户和钱包 URL 前缀的协议方案。
	vendorID uint16 // USB vendor identifier used for device discovery
	// 用于设备发现的 USB 供应商标识符
	productIDs []uint16 // USB product identifiers used for device discovery
	// 用于设备发现的 USB 产品标识符
	usageID uint16 // USB usage page identifier used for macOS device discovery
	// 用于 macOS 设备发现的 USB 使用页面标识符
	endpointID int // USB endpoint identifier used for non-macOS device discovery
	// 用于非 macOS 设备发现的 USB 端点标识符
	makeDriver func(log.Logger) driver // Factory method to construct a vendor specific driver
	// 构造特定于供应商的驱动的工厂方法

	refreshed time.Time // Time instance when the list of wallets was last refreshed
	// 上次刷新钱包列表的时间实例
	wallets []accounts.Wallet // List of USB wallet devices currently tracking
	// 当前跟踪的 USB 钱包设备列表
	updateFeed event.Feed // Event feed to notify wallet additions/removals
	// 通知钱包添加/移除的事件流
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	// 跟踪当前活跃监听者的订阅范围
	updating bool // Whether the event notification loop is running
	// 事件通知循环是否正在运行

	quit chan chan error
	// 用于退出信号的通道

	stateLock sync.RWMutex // Protects the internals of the hub from racey access
	// 保护 hub 内部免受竞争访问

	// TODO(karalabe): remove if hotplug lands on Windows
	// TODO(karalabe): 如果 Windows 支持热插拔，则移除
	commsPend int // Number of operations blocking enumeration
	// 阻止枚举的操作数量
	commsLock sync.Mutex // Lock protecting the pending counter and enumeration
	// 保护待处理计数器和枚举的锁
	enumFails atomic.Uint32 // Number of times enumeration has failed
	// 枚举失败的次数
}

// NewLedgerHub creates a new hardware wallet manager for Ledger devices.
// NewLedgerHub 为 Ledger 设备创建一个新的硬件钱包管理器。
func NewLedgerHub() (*Hub, error) {
	return newHub(LedgerScheme, 0x2c97, []uint16{
		// Device definitions taken from
		// https://github.com/LedgerHQ/ledger-live/blob/38012bc8899e0f07149ea9cfe7e64b2c146bc92b/libs/ledgerjs/packages/devices/src/index.ts
		// 设备定义取自上述链接

		// Original product IDs
		// 原始产品 ID
		0x0000, /* Ledger Blue */
		0x0001, /* Ledger Nano S */
		0x0004, /* Ledger Nano X */
		0x0005, /* Ledger Nano S Plus */
		0x0006, /* Ledger Nano FTS */

		0x0015, /* HID + U2F + WebUSB Ledger Blue */
		0x1015, /* HID + U2F + WebUSB Ledger Nano S */
		0x4015, /* HID + U2F + WebUSB Ledger Nano X */
		0x5015, /* HID + U2F + WebUSB Ledger Nano S Plus */
		0x6015, /* HID + U2F + WebUSB Ledger Nano FTS */

		0x0011, /* HID + WebUSB Ledger Blue */
		0x1011, /* HID + WebUSB Ledger Nano S */
		0x4011, /* HID + WebUSB Ledger Nano X */
		0x5011, /* HID + WebUSB Ledger Nano S Plus */
		0x6011, /* HID + WebUSB Ledger Nano FTS */
	}, 0xffa0, 0, newLedgerDriver)
}

// NewTrezorHubWithHID creates a new hardware wallet manager for Trezor devices.
// NewTrezorHubWithHID 为 Trezor 设备创建一个新的硬件钱包管理器（使用 HID）。
func NewTrezorHubWithHID() (*Hub, error) {
	return newHub(TrezorScheme, 0x534c, []uint16{0x0001 /* Trezor HID */}, 0xff00, 0, newTrezorDriver)
}

// NewTrezorHubWithWebUSB creates a new hardware wallet manager for Trezor devices with
// firmware version > 1.8.0
// NewTrezorHubWithWebUSB 为固件版本 > 1.8.0 的 Trezor 设备创建一个新的硬件钱包管理器（使用 WebUSB）。
func NewTrezorHubWithWebUSB() (*Hub, error) {
	return newHub(TrezorScheme, 0x1209, []uint16{0x53c1 /* Trezor WebUSB */}, 0xffff /* No usage id on webusb, don't match unset (0) */, 0, newTrezorDriver)
}

// newHub creates a new hardware wallet manager for generic USB devices.
// newHub 为通用 USB 设备创建一个新的硬件钱包管理器。
func newHub(scheme string, vendorID uint16, productIDs []uint16, usageID uint16, endpointID int, makeDriver func(log.Logger) driver) (*Hub, error) {
	if !hid.Supported() {
		return nil, errors.New("unsupported platform")
		// 不支持的平台
	}
	hub := &Hub{
		scheme:     scheme,
		vendorID:   vendorID,
		productIDs: productIDs,
		usageID:    usageID,
		endpointID: endpointID,
		makeDriver: makeDriver,
		quit:       make(chan chan error),
	}
	hub.refreshWallets()
	return hub, nil
}

// Wallets implements accounts.Backend, returning all the currently tracked USB
// devices that appear to be hardware wallets.
// Wallets 实现了 accounts.Backend，返回当前跟踪的所有看似硬件钱包的 USB 设备。
func (hub *Hub) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is up to date
	// 确保钱包列表是最新的
	hub.refreshWallets()

	hub.stateLock.RLock()
	defer hub.stateLock.RUnlock()

	cpy := make([]accounts.Wallet, len(hub.wallets))
	copy(cpy, hub.wallets)
	return cpy
}

// refreshWallets scans the USB devices attached to the machine and updates the
// list of wallets based on the found devices.
// refreshWallets 扫描连接到机器的 USB 设备，并根据发现的设备更新钱包列表。
func (hub *Hub) refreshWallets() {
	// Don't scan the USB like crazy it the user fetches wallets in a loop
	// 如果用户在循环中获取钱包，不要疯狂扫描 USB
	hub.stateLock.RLock()
	elapsed := time.Since(hub.refreshed)
	hub.stateLock.RUnlock()

	if elapsed < refreshThrottling {
		return
	}
	// If USB enumeration is continually failing, don't keep trying indefinitely
	// 如果 USB 枚举持续失败，不要无限期地继续尝试
	if hub.enumFails.Load() > 2 {
		return
	}
	// Retrieve the current list of USB wallet devices
	// 检索当前 USB 钱包设备列表
	var devices []hid.DeviceInfo

	if runtime.GOOS == "linux" {
		// hidapi on Linux opens the device during enumeration to retrieve some infos,
		// breaking the Ledger protocol if that is waiting for user confirmation. This
		// is a bug acknowledged at Ledger, but it won't be fixed on old devices so we
		// need to prevent concurrent comms ourselves. The more elegant solution would
		// be to ditch enumeration in favor of hotplug events, but that don't work yet
		// on Windows so if we need to hack it anyway, this is more elegant for now.
		// Linux 上的 hidapi 在枚举期间打开设备以检索一些信息，
		// 如果 Ledger 正在等待用户确认，这会破坏 Ledger 协议。这是 Ledger 承认的一个 bug，
		// 但在旧设备上不会修复，所以我们需要自己防止并发通信。更优雅的解决方案是放弃枚举，
		// 转而使用热插拔事件，但这在 Windows 上尚不可用，所以目前这样处理更优雅。
		hub.commsLock.Lock()
		if hub.commsPend > 0 { // A confirmation is pending, don't refresh
			// 有一个确认待处理，不刷新
			hub.commsLock.Unlock()
			return
		}
	}
	infos, err := hid.Enumerate(hub.vendorID, 0)
	if err != nil {
		failcount := hub.enumFails.Add(1)
		if runtime.GOOS == "linux" {
			// See rationale before the enumeration why this is needed and only on Linux.
			// 查看枚举前的理由，了解为什么需要这样做且仅在 Linux 上。
			hub.commsLock.Unlock()
		}
		log.Error("Failed to enumerate USB devices", "hub", hub.scheme,
			"vendor", hub.vendorID, "failcount", failcount, "err", err)
		// 枚举 USB 设备失败
		return
	}
	hub.enumFails.Store(0)

	for _, info := range infos {
		for _, id := range hub.productIDs {
			// Windows and Macos use UsageID matching, Linux uses Interface matching
			// Windows 和 MacOS 使用 UsageID 匹配，Linux 使用 Interface 匹配
			if info.ProductID == id && (info.UsagePage == hub.usageID || info.Interface == hub.endpointID) {
				devices = append(devices, info)
				break
			}
		}
	}
	if runtime.GOOS == "linux" {
		// See rationale before the enumeration why this is needed and only on Linux.
		// 查看枚举前的理由，了解为什么需要这样做且仅在 Linux 上。
		hub.commsLock.Unlock()
	}
	// Transform the current list of wallets into the new one
	// 将当前钱包列表转换为新的列表
	hub.stateLock.Lock()

	var (
		wallets = make([]accounts.Wallet, 0, len(devices))
		events  []accounts.WalletEvent
	)

	for _, device := range devices {
		url := accounts.URL{Scheme: hub.scheme, Path: device.Path}

		// Drop wallets in front of the next device or those that failed for some reason
		// 删除下一个设备之前的钱包或因某些原因失败的钱包
		for len(hub.wallets) > 0 {
			// Abort if we're past the current device and found an operational one
			// 如果我们超过了当前设备并找到了一个可操作的设备，则中止
			_, failure := hub.wallets[0].Status()
			if hub.wallets[0].URL().Cmp(url) >= 0 || failure == nil {
				break
			}
			// Drop the stale and failed devices
			// 删除过时和失败的设备
			events = append(events, accounts.WalletEvent{Wallet: hub.wallets[0], Kind: accounts.WalletDropped})
			hub.wallets = hub.wallets[1:]
		}
		// If there are no more wallets or the device is before the next, wrap new wallet
		// 如果没有更多钱包或设备在下一个之前，包装新钱包
		if len(hub.wallets) == 0 || hub.wallets[0].URL().Cmp(url) > 0 {
			logger := log.New("url", url)
			wallet := &wallet{hub: hub, driver: hub.makeDriver(logger), url: &url, info: device, log: logger}

			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the device is the same as the first wallet, keep it
		// 如果设备与第一个钱包相同，保留它
		if hub.wallets[0].URL().Cmp(url) == 0 {
			wallets = append(wallets, hub.wallets[0])
			hub.wallets = hub.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	// 删除任何剩余的钱包并设置新批次
	for _, wallet := range hub.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	hub.refreshed = time.Now()
	hub.wallets = wallets
	hub.stateLock.Unlock()

	// Fire all wallet events and return
	// 触发所有钱包事件并返回
	for _, event := range events {
		hub.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of USB wallets.
// Subscribe 实现了 accounts.Backend，创建一个异步订阅以接收 USB 钱包添加或移除的通知。
func (hub *Hub) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	// 我们需要互斥锁来可靠地启动/停止更新循环
	hub.stateLock.Lock()
	defer hub.stateLock.Unlock()

	// Subscribe the caller and track the subscriber count
	// 订阅调用者并跟踪订阅者数量
	sub := hub.updateScope.Track(hub.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	// 订阅者需要一个活跃的通知循环，启动它
	if !hub.updating {
		hub.updating = true
		go hub.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets managed
// by the USB hub, and for firing wallet addition/removal events.
// updater 负责维护由 USB hub 管理的最新钱包列表，并触发钱包添加/移除事件。
func (hub *Hub) updater() {
	for {
		// TODO: Wait for a USB hotplug event (not supported yet) or a refresh timeout
		// TODO: 等待 USB 热插拔事件（尚不支持）或刷新超时
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
