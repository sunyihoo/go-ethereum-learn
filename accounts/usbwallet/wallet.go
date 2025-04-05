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

// Package usbwallet implements support for USB hardware wallets.
package usbwallet

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/karalabe/hid"
)

// Maximum time between wallet health checks to detect USB unplugs.
// 钱包健康检查之间的最大时间，用于检测 USB 拔出。
const heartbeatCycle = time.Second

// Minimum time to wait between self derivation attempts, even it the user is
// requesting accounts like crazy.
// 自我派生尝试之间的最小等待时间，即使用户疯狂请求账户。
const selfDeriveThrottling = time.Second

// driver defines the vendor specific functionality hardware wallets instances
// must implement to allow using them with the wallet lifecycle management.
// driver 定义了硬件钱包实例必须实现的特定于供应商的功能，以允许与钱包生命周期管理一起使用。
type driver interface {
	// Status returns a textual status to aid the user in the current state of the
	// wallet. It also returns an error indicating any failure the wallet might have
	// encountered.
	// Status 返回文本状态，以帮助用户了解钱包的当前状态。它还返回一个错误，指示钱包可能遇到的任何故障。
	Status() (string, error)

	// Open initializes access to a wallet instance. The passphrase parameter may
	// or may not be used by the implementation of a particular wallet instance.
	// Open 初始化对钱包实例的访问。passphrase 参数可能被特定钱包实例的实现使用或不使用。
	Open(device io.ReadWriter, passphrase string) error

	// Close releases any resources held by an open wallet instance.
	// Close 释放打开的钱包实例持有的任何资源。
	Close() error

	// Heartbeat performs a sanity check against the hardware wallet to see if it
	// is still online and healthy.
	// Heartbeat 对硬件钱包执行健康检查，以查看它是否仍然在线且健康。
	Heartbeat() error

	// Derive sends a derivation request to the USB device and returns the Ethereum
	// address located on that path.
	// Derive 将派生请求发送到 USB 设备并返回位于该路径的以太坊地址。
	Derive(path accounts.DerivationPath) (common.Address, error)

	// SignTx sends the transaction to the USB device and waits for the user to confirm
	// or deny the transaction.
	// SignTx 将交易发送到 USB 设备并等待用户确认或拒绝交易。
	SignTx(path accounts.DerivationPath, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error)

	SignTypedMessage(path accounts.DerivationPath, messageHash []byte, domainHash []byte) ([]byte, error)
}

// wallet represents the common functionality shared by all USB hardware
// wallets to prevent reimplementing the same complex maintenance mechanisms
// for different vendors.
// wallet 表示所有 USB 硬件钱包共享的通用功能，以防止为不同供应商重新实现相同的复杂维护机制。
type wallet struct {
	hub *Hub // USB hub scanning
	// USB 中心扫描
	driver driver // Hardware implementation of the low level device operations
	// 低级设备操作的硬件实现
	url *accounts.URL // Textual URL uniquely identifying this wallet
	// 唯一标识此钱包的文本 URL

	info hid.DeviceInfo // Known USB device infos about the wallet
	// 关于钱包的已知 USB 设备信息
	device hid.Device // USB device advertising itself as a hardware wallet
	// 自我宣传为硬件钱包的 USB 设备

	accounts []accounts.Account // List of derive accounts pinned on the hardware wallet
	// 固定在硬件钱包上的派生账户列表
	paths map[common.Address]accounts.DerivationPath // Known derivation paths for signing operations
	// 用于签名操作的已知派生路径

	deriveNextPaths []accounts.DerivationPath // Next derivation paths for account auto-discovery (multiple bases supported)
	// 用于账户自动发现的下一个派生路径（支持多个基础）
	deriveNextAddrs []common.Address // Next derived account addresses for auto-discovery (multiple bases supported)
	// 用于自动发现的下一个派生账户地址（支持多个基础）
	deriveChain ethereum.ChainStateReader // Blockchain state reader to discover used account with
	// 区块链状态读取器，用于发现使用的账户
	deriveReq chan chan struct{} // Channel to request a self-derivation on
	// 请求自我派生的通道
	deriveQuit chan chan error // Channel to terminate the self-deriver with
	// 用于终止自我派生的通道

	healthQuit chan chan error
	// 用于健康检查终止的通道

	// Locking a hardware wallet is a bit special. Since hardware devices are lower
	// performing, any communication with them might take a non negligible amount of
	// time. Worse still, waiting for user confirmation can take arbitrarily long,
	// but exclusive communication must be upheld during. Locking the entire wallet
	// in the mean time however would stall any parts of the system that don't want
	// to communicate, just read some state (e.g. list the accounts).
	//
	// As such, a hardware wallet needs two locks to function correctly. A state
	// lock can be used to protect the wallet's software-side internal state, which
	// must not be held exclusively during hardware communication. A communication
	// lock can be used to achieve exclusive access to the device itself, this one
	// however should allow "skipping" waiting for operations that might want to
	// use the device, but can live without too (e.g. account self-derivation).
	//
	// Since we have two locks, it's important to know how to properly use them:
	//   - Communication requires the `device` to not change, so obtaining the
	//     commsLock should be done after having a stateLock.
	//   - Communication must not disable read access to the wallet state, so it
	//     must only ever hold a *read* lock to stateLock.
	// 锁定硬件钱包有点特殊。由于硬件设备性能较低，与它们的任何通信可能需要不可忽略的时间。
	// 更糟的是，等待用户确认可能需要任意长时间，但在此期间必须保持独占通信。
	// 然而，在此期间锁定整个钱包会使系统中不想通信、只想读取某些状态（例如列出账户）的部分停滞。
	//
	// 因此，硬件钱包需要两个锁才能正常工作。状态锁可用于保护钱包的软件端内部状态，
	// 在硬件通信期间不得独占持有。通信锁可用于实现对设备本身的独占访问，
	// 但这个锁应该允许“跳过”那些可能想使用设备但也可以没有的等待操作（例如账户自我派生）。
	//
	// 由于我们有两个锁，正确使用它们很重要：
	//   - 通信要求 `device` 不变，因此在获得 stateLock 后应获取 commsLock。
	//   - 通信不得禁用对钱包状态的读访问，因此它只能持有 stateLock 的 *读* 锁。
	commsLock chan struct{} // Mutex (buf=1) for the USB comms without keeping the state locked
	// 用于 USB 通信的互斥锁（缓冲=1），不保持状态锁
	stateLock sync.RWMutex // Protects read and write access to the wallet struct fields
	// 保护对钱包结构字段的读写访问

	log log.Logger // Contextual logger to tag the base with its id
	// 上下文记录器，用于标记基础的 ID
}

// URL implements accounts.Wallet, returning the URL of the USB hardware device.
// URL 实现了 accounts.Wallet，返回 USB 硬件设备的 URL。
func (w *wallet) URL() accounts.URL {
	return *w.url // Immutable, no need for a lock
	// 不可变，无需锁
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific hardware wallet implementation.
// Status 实现了 accounts.Wallet，返回底层特定于供应商的硬件钱包实现的自定义状态消息。
func (w *wallet) Status() (string, error) {
	w.stateLock.RLock() // No device communication, state lock is enough
	// 无设备通信，状态锁就足够了
	defer w.stateLock.RUnlock()

	status, failure := w.driver.Status()
	if w.device == nil {
		return "Closed", failure
	}
	return status, failure
}

// Open implements accounts.Wallet, attempting to open a USB connection to the
// hardware wallet.
// Open 实现了 accounts.Wallet，尝试打开到硬件钱包的 USB 连接。
func (w *wallet) Open(passphrase string) error {
	w.stateLock.Lock() // State lock is enough since there's no connection yet at this point
	// 此时尚无连接，状态锁就足够了
	defer w.stateLock.Unlock()

	// If the device was already opened once, refuse to try again
	// 如果设备已经打开过一次，拒绝再次尝试
	if w.paths != nil {
		return accounts.ErrWalletAlreadyOpen
	}
	// Make sure the actual device connection is done only once
	// 确保实际设备连接只进行一次
	if w.device == nil {
		device, err := w.info.Open()
		if err != nil {
			return err
		}
		w.device = device
		w.commsLock = make(chan struct{}, 1)
		w.commsLock <- struct{}{} // Enable lock
		// 启用锁
	}
	// Delegate device initialization to the underlying driver
	// 将设备初始化委托给底层驱动
	if err := w.driver.Open(w.device, passphrase); err != nil {
		return err
	}
	// Connection successful, start life-cycle management
	// 连接成功，开始生命周期管理
	w.paths = make(map[common.Address]accounts.DerivationPath)

	w.deriveReq = make(chan chan struct{})
	w.deriveQuit = make(chan chan error)
	w.healthQuit = make(chan chan error)

	go w.heartbeat()
	go w.selfDerive()

	// Notify anyone listening for wallet events that a new device is accessible
	// 通知监听钱包事件的任何人，新设备可访问
	go w.hub.updateFeed.Send(accounts.WalletEvent{Wallet: w, Kind: accounts.WalletOpened})

	return nil
}

// heartbeat is a health check loop for the USB wallets to periodically verify
// whether they are still present or if they malfunctioned.
// heartbeat 是 USB 钱包的健康检查循环，定期验证它们是否仍然存在或是否出现故障。
func (w *wallet) heartbeat() {
	w.log.Debug("USB wallet health-check started")
	// USB 钱包健康检查已开始
	defer w.log.Debug("USB wallet health-check stopped")
	// USB 钱包健康检查已停止

	// Execute heartbeat checks until termination or error
	// 执行心跳检查，直到终止或出错
	var (
		errc chan error
		err  error
	)
	for errc == nil && err == nil {
		// Wait until termination is requested or the heartbeat cycle arrives
		// 等待终止请求或心跳周期到达
		select {
		case errc = <-w.healthQuit:
			// Termination requested
			// 终止已请求
			continue
		case <-time.After(heartbeatCycle):
			// Heartbeat time
			// 心跳时间
		}
		// Execute a tiny data exchange to see responsiveness
		// 执行一个微小的数据交换以查看响应性
		w.stateLock.RLock()
		if w.device == nil {
			// Terminated while waiting for the lock
			// 在等待锁期间已终止
			w.stateLock.RUnlock()
			continue
		}
		<-w.commsLock // Don't lock state while resolving version
		// 在解析版本时不锁定状态
		err = w.driver.Heartbeat()
		w.commsLock <- struct{}{}
		w.stateLock.RUnlock()

		if err != nil {
			w.stateLock.Lock() // Lock state to tear the wallet down
			// 锁定状态以拆除钱包
			w.close()
			w.stateLock.Unlock()
		}
		// Ignore non hardware related errors
		// 忽略与硬件无关的错误
		err = nil
	}
	// In case of error, wait for termination
	// 如果出错，等待终止
	if err != nil {
		w.log.Debug("USB wallet health-check failed", "err", err)
		// USB 钱包健康检查失败
		errc = <-w.healthQuit
	}
	errc <- err
}

// Close implements accounts.Wallet, closing the USB connection to the device.
// Close 实现了 accounts.Wallet，关闭到设备的 USB 连接。
func (w *wallet) Close() error {
	// Ensure the wallet was opened
	// 确保钱包已打开
	w.stateLock.RLock()
	hQuit, dQuit := w.healthQuit, w.deriveQuit
	w.stateLock.RUnlock()

	// Terminate the health checks
	// 终止健康检查
	var herr error
	if hQuit != nil {
		errc := make(chan error)
		hQuit <- errc
		herr = <-errc // Save for later, we *must* close the USB
		// 保存以备后用，我们 *必须* 关闭 USB
	}
	// Terminate the self-derivations
	// 终止自我派生
	var derr error
	if dQuit != nil {
		errc := make(chan error)
		dQuit <- errc
		derr = <-errc // Save for later, we *must* close the USB
		// 保存以备后用，我们 *必须* 关闭 USB
	}
	// Terminate the device connection
	// 终止设备连接
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	w.healthQuit = nil
	w.deriveQuit = nil
	w.deriveReq = nil

	if err := w.close(); err != nil {
		return err
	}
	if herr != nil {
		return herr
	}
	return derr
}

// close is the internal wallet closer that terminates the USB connection and
// resets all the fields to their defaults.
//
// Note, close assumes the state lock is held!
// close 是内部钱包关闭器，终止 USB 连接并将所有字段重置为默认值。
//
// 注意，close 假定状态锁已被持有！
func (w *wallet) close() error {
	// Allow duplicate closes, especially for health-check failures
	// 允许重复关闭，特别是对于健康检查失败
	if w.device == nil {
		return nil
	}
	// Close the device, clear everything, then return
	// 关闭设备，清除所有内容，然后返回
	w.device.Close()
	w.device = nil

	w.accounts, w.paths = nil, nil
	return w.driver.Close()
}

// Accounts implements accounts.Wallet, returning the list of accounts pinned to
// the USB hardware wallet. If self-derivation was enabled, the account list is
// periodically expanded based on current chain state.
// Accounts 实现了 accounts.Wallet，返回固定在 USB 硬件钱包上的账户列表。
// 如果启用了自我派生，账户列表会根据当前链状态定期扩展。
func (w *wallet) Accounts() []accounts.Account {
	// Attempt self-derivation if it's running
	// 如果自我派生正在运行，尝试自我派生
	reqc := make(chan struct{}, 1)
	select {
	case w.deriveReq <- reqc:
		// Self-derivation request accepted, wait for it
		// 自我派生请求被接受，等待它
		<-reqc
	default:
		// Self-derivation offline, throttled or busy, skip
		// 自我派生离线、受限或忙碌，跳过
	}
	// Return whatever account list we ended up with
	// 返回我们最终得到的任何账户列表
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	cpy := make([]accounts.Account, len(w.accounts))
	copy(cpy, w.accounts)
	return cpy
}

// selfDerive is an account derivation loop that upon request attempts to find
// new non-zero accounts.
// selfDerive 是一个账户派生循环，在请求时尝试找到新的非零账户。
func (w *wallet) selfDerive() {
	w.log.Debug("USB wallet self-derivation started")
	// USB 钱包自我派生已开始
	defer w.log.Debug("USB wallet self-derivation stopped")
	// USB 钱包自我派生已停止

	// Execute self-derivations until termination or error
	// 执行自我派生，直到终止或出错
	var (
		reqc chan struct{}
		errc chan error
		err  error
	)
	for errc == nil && err == nil {
		// Wait until either derivation or termination is requested
		// 等待派生或终止请求
		select {
		case errc = <-w.deriveQuit:
			// Termination requested
			// 终止已请求
			continue
		case reqc = <-w.deriveReq:
			// Account discovery requested
			// 账户发现已请求
		}
		// Derivation needs a chain and device access, skip if either unavailable
		// 派生需要链和设备访问，如果任一不可用则跳过
		w.stateLock.RLock()
		if w.device == nil || w.deriveChain == nil {
			w.stateLock.RUnlock()
			reqc <- struct{}{}
			continue
		}
		select {
		case <-w.commsLock:
		default:
			w.stateLock.RUnlock()
			reqc <- struct{}{}
			continue
		}
		// Device lock obtained, derive the next batch of accounts
		// 获得设备锁，派生下一批账户
		var (
			accs  []accounts.Account
			paths []accounts.DerivationPath

			nextPaths = append([]accounts.DerivationPath{}, w.deriveNextPaths...)
			nextAddrs = append([]common.Address{}, w.deriveNextAddrs...)

			context = context.Background()
		)
		for i := 0; i < len(nextAddrs); i++ {
			for empty := false; !empty; {
				// Retrieve the next derived Ethereum account
				// 检索下一个派生的以太坊账户
				if nextAddrs[i] == (common.Address{}) {
					if nextAddrs[i], err = w.driver.Derive(nextPaths[i]); err != nil {
						w.log.Warn("USB wallet account derivation failed", "err", err)
						// USB 钱包账户派生失败
						break
					}
				}
				// Check the account's status against the current chain state
				// 检查账户状态与当前链状态
				var (
					balance *big.Int
					nonce   uint64
				)
				balance, err = w.deriveChain.BalanceAt(context, nextAddrs[i], nil)
				if err != nil {
					w.log.Warn("USB wallet balance retrieval failed", "err", err)
					// USB 钱包余额检索失败
					break
				}
				nonce, err = w.deriveChain.NonceAt(context, nextAddrs[i], nil)
				if err != nil {
					w.log.Warn("USB wallet nonce retrieval failed", "err", err)
					// USB 钱包 nonce 检索失败
					break
				}
				// We've just self-derived a new account, start tracking it locally
				// unless the account was empty.
				// 我们刚刚自我派生了一个新账户，开始在本地跟踪它，除非账户为空。
				path := make(accounts.DerivationPath, len(nextPaths[i]))
				copy(path[:], nextPaths[i][:])
				if balance.Sign() == 0 && nonce == 0 {
					empty = true
					// If it indeed was empty, make a log output for it anyway. In the case
					// of legacy-ledger, the first account on the legacy-path will
					// be shown to the user, even if we don't actively track it
					// 如果它确实是空的，无论如何为它生成日志输出。在 legacy-ledger 的情况下，
					// 遗留路径上的第一个账户将显示给用户，即使我们不主动跟踪它
					if i < len(nextAddrs)-1 {
						w.log.Info("Skipping tracking first account on legacy path, use personal.deriveAccount(<url>,<path>, false) to track",
							"path", path, "address", nextAddrs[i])
						// 跳过跟踪遗留路径上的第一个账户，使用 personal.deriveAccount(<url>,<path>, false) 进行跟踪
						break
					}
				}
				paths = append(paths, path)
				account := accounts.Account{
					Address: nextAddrs[i],
					URL:     accounts.URL{Scheme: w.url.Scheme, Path: fmt.Sprintf("%s/%s", w.url.Path, path)},
				}
				accs = append(accs, account)

				// Display a log message to the user for new (or previously empty accounts)
				// 为新账户（或之前为空的账户）向用户显示日志消息
				if _, known := w.paths[nextAddrs[i]]; !known || (!empty && nextAddrs[i] == w.deriveNextAddrs[i]) {
					w.log.Info("USB wallet discovered new account", "address", nextAddrs[i], "path", path, "balance", balance, "nonce", nonce)
					// USB 钱包发现新账户
				}
				// Fetch the next potential account
				// 获取下一个潜在账户
				if !empty {
					nextAddrs[i] = common.Address{}
					nextPaths[i][len(nextPaths[i])-1]++
				}
			}
		}
		// Self derivation complete, release device lock
		// 自我派生完成，释放设备锁
		w.commsLock <- struct{}{}
		w.stateLock.RUnlock()

		// Insert any accounts successfully derived
		// 插入成功派生的任何账户
		w.stateLock.Lock()
		for i := 0; i < len(accs); i++ {
			if _, ok := w.paths[accs[i].Address]; !ok {
				w.accounts = append(w.accounts, accs[i])
				w.paths[accs[i].Address] = paths[i]
			}
		}
		// Shift the self-derivation forward
		// 将自我派生向前推进
		// TODO(karalabe): don't overwrite changes from wallet.SelfDerive
		// TODO(karalabe): 不要覆盖来自 wallet.SelfDerive 的更改
		w.deriveNextAddrs = nextAddrs
		w.deriveNextPaths = nextPaths
		w.stateLock.Unlock()

		// Notify the user of termination and loop after a bit of time (to avoid trashing)
		// 通知用户终止并在一段时间后循环（以避免过度操作）
		reqc <- struct{}{}
		if err == nil {
			select {
			case errc = <-w.deriveQuit:
				// Termination requested, abort
				// 终止已请求，中止
			case <-time.After(selfDeriveThrottling):
				// Waited enough, willing to self-derive again
				// 等待足够，愿意再次自我派生
			}
		}
	}
	// In case of error, wait for termination
	// 如果出错，等待终止
	if err != nil {
		w.log.Debug("USB wallet self-derivation failed", "err", err)
		// USB 钱包自我派生失败
		errc = <-w.deriveQuit
	}
	errc <- err
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not pinned into this wallet instance. Although we could attempt to resolve
// unpinned accounts, that would be an non-negligible hardware operation.
// Contains 实现了 accounts.Wallet，返回特定账户是否固定在此钱包实例中。
// 虽然我们可以尝试解析未固定的账户，但那将是一个不可忽略的硬件操作。
func (w *wallet) Contains(account accounts.Account) bool {
	w.stateLock.RLock()
	defer w.stateLock.RUnlock()

	_, exists := w.paths[account.Address]
	return exists
}

// Derive implements accounts.Wallet, deriving a new account at the specific
// derivation path. If pin is set to true, the account will be added to the list
// of tracked accounts.
// Derive 实现了 accounts.Wallet，在特定派生路径上派生新账户。如果 pin 设置为 true，账户将被添加到跟踪账户列表中。
func (w *wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	// Try to derive the actual account and update its URL if successful
	// 尝试派生实际账户并在成功时更新其 URL
	w.stateLock.RLock() // Avoid device disappearing during derivation
	// 避免在派生期间设备消失

	if w.device == nil {
		w.stateLock.RUnlock()
		return accounts.Account{}, accounts.ErrWalletClosed
	}
	<-w.commsLock // Avoid concurrent hardware access
	// 避免并发硬件访问
	address, err := w.driver.Derive(path)
	w.commsLock <- struct{}{}

	w.stateLock.RUnlock()

	// If an error occurred or no pinning was requested, return
	// 如果发生错误或未请求固定，返回
	if err != nil {
		return accounts.Account{}, err
	}
	account := accounts.Account{
		Address: address,
		URL:     accounts.URL{Scheme: w.url.Scheme, Path: fmt.Sprintf("%s/%s", w.url.Path, path)},
	}
	if !pin {
		return account, nil
	}
	// Pinning needs to modify the state
	// 固定需要修改状态
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	if w.device == nil {
		return accounts.Account{}, accounts.ErrWalletClosed
	}

	if _, ok := w.paths[address]; !ok {
		w.accounts = append(w.accounts, account)
		w.paths[address] = make(accounts.DerivationPath, len(path))
		copy(w.paths[address], path)
	}
	return account, nil
}

// SelfDerive sets a base account derivation path from which the wallet attempts
// to discover non zero accounts and automatically add them to list of tracked
// accounts.
//
// Note, self derivation will increment the last component of the specified path
// opposed to descending into a child path to allow discovering accounts starting
// from non zero components.
//
// Some hardware wallets switched derivation paths through their evolution, so
// this method supports providing multiple bases to discover old user accounts
// too. Only the last base will be used to derive the next empty account.
//
// You can disable automatic account discovery by calling SelfDerive with a nil
// chain state reader.
// SelfDerive 设置基础账户派生路径，钱包从中尝试发现非零账户并自动将它们添加到跟踪账户列表中。
//
// 注意，自我派生将增加指定路径的最后一个组件，而不是下降到子路径，以允许从非零组件开始发现账户。
//
// 一些硬件钱包在其演变过程中切换了派生路径，因此此方法支持提供多个基础以发现旧用户账户。
// 只有最后一个基础将用于派生下一个空账户。
//
// 您可以通过使用 nil 链状态读取器调用 SelfDerive 来禁用自动账户发现。
func (w *wallet) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
	w.stateLock.Lock()
	defer w.stateLock.Unlock()

	w.deriveNextPaths = make([]accounts.DerivationPath, len(bases))
	for i, base := range bases {
		w.deriveNextPaths[i] = make(accounts.DerivationPath, len(base))
		copy(w.deriveNextPaths[i][:], base[:])
	}
	w.deriveNextAddrs = make([]common.Address, len(bases))
	w.deriveChain = chain
}

// signHash implements accounts.Wallet, however signing arbitrary data is not
// supported for hardware wallets, so this method will always return an error.
// signHash 实现了 accounts.Wallet，然而硬件钱包不支持签名任意数据，因此此方法将始终返回错误。
func (w *wallet) signHash(account accounts.Account, hash []byte) ([]byte, error) {
	return nil, accounts.ErrNotSupported
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed
// SignData 签名 keccak256(data)。mimetype 参数描述正在签名的数据类型
func (w *wallet) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	// Unless we are doing 712 signing, simply dispatch to signHash
	// 除非我们在进行 712 签名，否则简单分派到 signHash
	if !(mimeType == accounts.MimetypeTypedData && len(data) == 66 && data[0] == 0x19 && data[1] == 0x01) {
		return w.signHash(account, crypto.Keccak256(data))
	}

	// dispatch to 712 signing if the mimetype is TypedData and the format matches
	// 如果 mimetype 是 TypedData 且格式匹配，则分派到 712 签名
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	// 通信有自己的互斥锁，这是为了状态字段
	defer w.stateLock.RUnlock()

	// If the wallet is closed, abort
	// 如果钱包已关闭，中止
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}
	// Make sure the requested account is contained within
	// 确保请求的账户包含在其中
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}
	// All infos gathered and metadata checks out, request signing
	// 所有信息已收集且元数据检查通过，请求签名
	<-w.commsLock
	defer func() { w.commsLock <- struct{}{} }()

	// Ensure the device isn't screwed with while user confirmation is pending
	// 确保在用户确认待处理期间设备不会出现问题
	// TODO(karalabe): remove if hotplug lands on Windows
	// TODO(karalabe): 如果 Windows 支持热插拔，则移除
	w.hub.commsLock.Lock()
	w.hub.commsPend++
	w.hub.commsLock.Unlock()

	defer func() {
		w.hub.commsLock.Lock()
		w.hub.commsPend--
		w.hub.commsLock.Unlock()
	}()
	// Sign the transaction
	// 签名交易
	signature, err := w.driver.SignTypedMessage(path, data[2:34], data[34:66])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// SignDataWithPassphrase implements accounts.Wallet, attempting to sign the given
// data with the given account using passphrase as extra authentication.
// Since USB wallets don't rely on passphrases, these are silently ignored.
// SignDataWithPassphrase 实现了 accounts.Wallet，尝试使用给定的账户和 passphrase 作为额外认证来签名给定数据。
// 由于 USB 钱包不依赖 passphrase，这些被静默忽略。
func (w *wallet) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return w.SignData(account, mimeType, data)
}

func (w *wallet) SignText(account accounts.Account, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

// SignTx implements accounts.Wallet. It sends the transaction over to the Ledger
// wallet to request a confirmation from the user. It returns either the signed
// transaction or a failure if the user denied the transaction.
//
// Note, if the version of the Ethereum application running on the Ledger wallet is
// too old to sign EIP-155 transactions, but such is requested nonetheless, an error
// will be returned opposed to silently signing in Homestead mode.
// SignTx 实现了 accounts.Wallet。它将交易发送到 Ledger 钱包以请求用户确认。
// 它返回签名后的交易或用户拒绝交易时的失败。
//
// 注意，如果运行在 Ledger 钱包上的以太坊应用程序版本太旧而无法签名 EIP-155 交易，
// 但仍然请求这样做，将返回错误，而不是在 Homestead 模式下静默签名。
func (w *wallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	w.stateLock.RLock() // Comms have own mutex, this is for the state fields
	// 通信有自己的互斥锁，这是为了状态字段
	defer w.stateLock.RUnlock()

	// If the wallet is closed, abort
	// 如果钱包已关闭，中止
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}
	// Make sure the requested account is contained within
	// 确保请求的账户包含在其中
	path, ok := w.paths[account.Address]
	if !ok {
		return nil, accounts.ErrUnknownAccount
	}
	// All infos gathered and metadata checks out, request signing
	// 所有信息已收集且元数据检查通过，请求签名
	<-w.commsLock
	defer func() { w.commsLock <- struct{}{} }()

	// Ensure the device isn't screwed with while user confirmation is pending
	// 确保在用户确认待处理期间设备不会出现问题
	// TODO(karalabe): remove if hotplug lands on Windows
	// TODO(karalabe): 如果 Windows 支持热插拔，则移除
	w.hub.commsLock.Lock()
	w.hub.commsPend++
	w.hub.commsLock.Unlock()

	defer func() {
		w.hub.commsLock.Lock()
		w.hub.commsPend--
		w.hub.commsLock.Unlock()
	}()
	// Sign the transaction and verify the sender to avoid hardware fault surprises
	// 签名交易并验证发送者以避免硬件故障意外
	sender, signed, err := w.driver.SignTx(path, tx, chainID)
	if err != nil {
		return nil, err
	}
	if sender != account.Address {
		return nil, fmt.Errorf("signer mismatch: expected %s, got %s", account.Address.Hex(), sender.Hex())
		// 签名者不匹配：预期 %s，得到 %s
	}
	return signed, nil
}

// SignTextWithPassphrase implements accounts.Wallet, however signing arbitrary
// data is not supported for Ledger wallets, so this method will always return
// an error.
// SignTextWithPassphrase 实现了 accounts.Wallet，然而 Ledger 钱包不支持签名任意数据，
// 因此此方法将始终返回错误。
func (w *wallet) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	return w.SignText(account, accounts.TextHash(text))
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
// Since USB wallets don't rely on passphrases, these are silently ignored.
// SignTxWithPassphrase 实现了 accounts.Wallet，尝试使用给定的账户和 passphrase 作为额外认证来签名给定交易。
// 由于 USB 钱包不依赖 passphrase，这些被静默忽略。
func (w *wallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return w.SignTx(account, tx, chainID)
}
