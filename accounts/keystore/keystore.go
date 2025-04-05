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

// Package keystore implements encrypted storage of secp256k1 private keys.
//
// Keys are stored as encrypted JSON files according to the Web3 Secret Storage specification.
// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition for more information.
package keystore

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
)

// 密钥存储: 以太坊使用 JSON 格式的密钥文件（UTC 文件），通过 Scrypt 加密。
// 账户管理: 支持多个账户的存储和签名

var (
	ErrLocked = accounts.NewAuthNeededError("password or unlock")
	// ErrLocked 表示账户被锁定，需要密码或解锁
	ErrNoMatch = errors.New("no key for given address or file")
	// ErrNoMatch 表示给定的地址或文件没有对应的密钥
	ErrDecrypt = errors.New("could not decrypt key with given password")
	// ErrDecrypt 表示无法使用给定密码解密密钥

	// ErrAccountAlreadyExists is returned if an account attempted to import is
	// already present in the keystore.
	// ErrAccountAlreadyExists 表示尝试导入的账户已存在于密钥存储中
	ErrAccountAlreadyExists = errors.New("account already exists")
)

// KeyStoreType is the reflect type of a keystore backend.
// KeyStoreType 是密钥存储后端的反射类型
var KeyStoreType = reflect.TypeOf(&KeyStore{})

// KeyStoreScheme is the protocol scheme prefixing account and wallet URLs.
// KeyStoreScheme 是账户和钱包 URL 的协议方案前缀
const KeyStoreScheme = "keystore"

// Maximum time between wallet refreshes (if filesystem notifications don't work).
// 钱包刷新之间的最大时间（如果文件系统通知不起作用）
const walletRefreshCycle = 3 * time.Second

// KeyStore manages a key storage directory on disk.
// KeyStore 管理磁盘上的密钥存储目录
type KeyStore struct {
	storage keyStore // Storage backend, might be cleartext or encrypted
	// 存储后端，可能是明文或加密的
	cache *accountCache // In-memory account cache over the filesystem storage
	// 文件系统存储上的内存账户缓存
	changes chan struct{} // Channel receiving change notifications from the cache
	// 从缓存接收更改通知的通道
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)
	// 当前解锁的账户（已解密的私钥）

	wallets []accounts.Wallet // Wallet wrappers around the individual key files
	// 围绕各个密钥文件的钱包包装器
	updateFeed event.Feed // Event feed to notify wallet additions/removals
	// 通知钱包添加/删除的事件馈送
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	// 跟踪当前活动监听器的订阅范围
	updating bool // Whether the event notification loop is running
	// 事件通知循环是否正在运行

	mu       sync.RWMutex
	importMu sync.Mutex // Import Mutex locks the import to prevent two insertions from racing
	// 导入互斥锁，防止两个插入操作竞争
}

type unlocked struct {
	*Key
	abort chan struct{}
}

// NewKeyStore creates a keystore for the given directory.
// NewKeyStore 为给定目录创建一个密钥存储
func NewKeyStore(keydir string, scryptN, scryptP int) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{storage: &keyStorePassphrase{keydir, scryptN, scryptP, false}}
	ks.init(keydir)
	return ks
}

func (ks *KeyStore) init(keydir string) {
	// Lock the mutex since the account cache might call back with events
	// 锁定互斥锁，因为账户缓存可能会回调事件
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Initialize the set of unlocked keys and the account cache
	// 初始化解锁密钥集合和账户缓存
	ks.unlocked = make(map[common.Address]*unlocked)
	ks.cache, ks.changes = newAccountCache(keydir)

	// TODO: In order for this finalizer to work, there must be no references
	// to ks. addressCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	// TODO: 为了让此终结器工作，必须没有对 ks 的引用。addressCache 不保留引用，
	// 但解锁的密钥会保留，因此在所有定时解锁过期之前，终结器不会触发。
	runtime.SetFinalizer(ks, func(m *KeyStore) {
		m.cache.close()
	})
	// Create the initial list of wallets from the cache
	// 从缓存创建初始钱包列表
	accs := ks.cache.accounts()
	ks.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		ks.wallets[i] = &keystoreWallet{account: accs[i], keystore: ks}
	}
}

// Wallets implements accounts.Backend, returning all single-key wallets from the
// keystore directory.
// Wallets 实现了 accounts.Backend，返回密钥存储目录中的所有单密钥钱包
func (ks *KeyStore) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	// 确保钱包列表与账户缓存同步
	ks.refreshWallets()

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(ks.wallets))
	copy(cpy, ks.wallets)
	return cpy
}

// refreshWallets retrieves the current account list and based on that does any
// necessary wallet refreshes.
// refreshWallets 检索当前账户列表，并根据此进行必要的钱包刷新
func (ks *KeyStore) refreshWallets() {
	// Retrieve the current list of accounts
	// 检索当前账户列表
	ks.mu.Lock()
	accs := ks.cache.accounts()

	// Transform the current list of wallets into the new one
	// 将当前钱包列表转换为新的列表
	var (
		wallets = make([]accounts.Wallet, 0, len(accs))
		events  []accounts.WalletEvent
	)

	for _, account := range accs {
		// Drop wallets while they were in front of the next account
		// 在下一个账户之前删除钱包
		for len(ks.wallets) > 0 && ks.wallets[0].URL().Cmp(account.URL) < 0 {
			events = append(events, accounts.WalletEvent{Wallet: ks.wallets[0], Kind: accounts.WalletDropped})
			ks.wallets = ks.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		// 如果没有更多钱包或账户在下一个之前，包装新钱包
		if len(ks.wallets) == 0 || ks.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &keystoreWallet{account: account, keystore: ks}

			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the account is the same as the first wallet, keep it
		// 如果账户与第一个钱包相同，保留它
		if ks.wallets[0].Accounts()[0] == account {
			wallets = append(wallets, ks.wallets[0])
			ks.wallets = ks.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	// 删除任何剩余的钱包并设置新批次
	for _, wallet := range ks.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	ks.wallets = wallets
	ks.mu.Unlock()

	// Fire all wallet events and return
	// 触发所有钱包事件并返回
	for _, event := range events {
		ks.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of keystore wallets.
// Subscribe 实现了 accounts.Backend，创建异步订阅以接收密钥存储钱包添加或删除的通知
func (ks *KeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	// 我们需要互斥锁来可靠地启动/停止更新循环
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	// 订阅调用者并跟踪订阅者计数
	sub := ks.updateScope.Track(ks.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	// 订阅者需要一个活动通知循环，启动它
	if !ks.updating {
		ks.updating = true
		go ks.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets stored in
// the keystore, and for firing wallet addition/removal events. It listens for
// account change events from the underlying account cache, and also periodically
// forces a manual refresh (only triggers for systems where the filesystem notifier
// is not running).
// updater 负责维护密钥存储中存储的最新钱包列表，并触发钱包添加/删除事件。
// 它监听底层账户缓存的账户更改事件，并定期强制手动刷新（仅在文件系统通知器未运行的系统上触发）。
func (ks *KeyStore) updater() {
	for {
		// Wait for an account update or a refresh timeout
		// 等待账户更新或刷新超时
		select {
		case <-ks.changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		// 运行钱包刷新器
		ks.refreshWallets()

		// If all our subscribers left, stop the updater
		// 如果所有订阅者都离开，停止更新器
		ks.mu.Lock()
		if ks.updateScope.Count() == 0 {
			ks.updating = false
			ks.mu.Unlock()
			return
		}
		ks.mu.Unlock()
	}
}

// HasAddress reports whether a key with the given address is present.
// HasAddress 报告给定地址的密钥是否存在
func (ks *KeyStore) HasAddress(addr common.Address) bool {
	return ks.cache.hasAddress(addr)
}

// Accounts returns all key files present in the directory.
// Accounts 返回目录中存在的所有密钥文件
func (ks *KeyStore) Accounts() []accounts.Account {
	return ks.cache.accounts()
}

// Delete deletes the key matched by account if the passphrase is correct.
// If the account contains no filename, the address must match a unique key.
// Delete 删除与账户匹配的密钥，如果密码正确。
// 如果账户不包含文件名，地址必须匹配唯一密钥。
func (ks *KeyStore) Delete(a accounts.Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do
	// it anyway to check the password and zero out the key
	// immediately afterwards.
	// 解密密钥并不是必需的，但我们还是这样做以检查密码并立即将密钥清零。
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if key != nil {
		zeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	// The order is crucial here. The key is dropped from the
	// cache after the file is gone so that a reload happening in
	// between won't insert it into the cache again.
	// 这里的顺序至关重要。密钥在文件删除后从缓存中移除，
	// 以便在中间发生的重新加载不会再次将其插入缓存。
	err = os.Remove(a.URL.Path)
	if err == nil {
		ks.cache.delete(a)
		ks.refreshWallets()
	}
	return err
}

// SignHash calculates a ECDSA signature for the given hash. The produced
// signature is in the [R || S || V] format where V is 0 or 1.
// SignHash 为给定的哈希计算 ECDSA 签名。生成的签名格式为 [R || S || V]，其中 V 为 0 或 1。
func (ks *KeyStore) SignHash(a accounts.Account, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	// 查找用于签名的密钥，如果找不到则中止
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	// Sign the hash using plain ECDSA operations
	// 使用纯 ECDSA 操作签署哈希
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignTx signs the given transaction with the requested account.
// SignTx 使用请求的账户签署给定交易
func (ks *KeyStore) SignTx(a accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found
	// 查找用于签名的密钥，如果找不到则中止
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[a.Address]
	if !found {
		return nil, ErrLocked
	}
	// Depending on the presence of the chain ID, sign with 2718 or homestead
	// 根据链 ID 的存在与否，使用 EIP-2718 或 Homestead 签名
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, unlockedKey.PrivateKey)
}

// SignHashWithPassphrase signs hash if the private key matching the given address
// can be decrypted with the given passphrase. The produced signature is in the
// [R || S || V] format where V is 0 or 1.
// SignHashWithPassphrase 如果匹配给定地址的私钥可以使用给定密码解密，则签署哈希。
// 生成的签名格式为 [R || S || V]，其中 V 为 0 或 1。
func (ks *KeyStore) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// SignTxWithPassphrase signs the transaction if the private key matching the
// given address can be decrypted with the given passphrase.
// SignTxWithPassphrase 如果匹配给定地址的私钥可以使用给定密码解密，则签署交易
func (ks *KeyStore) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroKey(key.PrivateKey)
	// Depending on the presence of the chain ID, sign with or without replay protection.
	// 根据链 ID 的存在与否，使用或不使用重放保护进行签名。
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, key.PrivateKey)
}

// Unlock unlocks the given account indefinitely.
// Unlock 无期限地解锁给定账户
func (ks *KeyStore) Unlock(a accounts.Account, passphrase string) error {
	return ks.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
// Lock 从内存中移除给定地址的私钥
func (ks *KeyStore) Lock(addr common.Address) error {
	ks.mu.Lock()
	unl, found := ks.unlocked[addr]
	ks.mu.Unlock()
	if found {
		ks.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	}
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
// TimedUnlock 使用密码解锁给定账户。账户在超时持续时间内保持解锁。
// 超时为 0 表示解锁直到程序退出。账户必须匹配唯一的密钥文件。
//
// 如果账户地址已为某个持续时间解锁，TimedUnlock 会延长或缩短活动解锁超时。
// 如果地址之前是无限期解锁，则不更改超时。
func (ks *KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	u, found := ks.unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			// 地址已无限期解锁，因此使用超时解锁会令人困惑。
			zeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		// 终止过期 goroutine 并在下面替换它。
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go ks.expire(a.Address, u, timeout)
	} else {
		u = &unlocked{Key: key}
	}
	ks.unlocked[a.Address] = u
	return nil
}

// Find resolves the given account into a unique entry in the keystore.
// Find 将给定账户解析为密钥存储中的唯一条目
func (ks *KeyStore) Find(a accounts.Account) (accounts.Account, error) {
	ks.cache.maybeReload()
	ks.cache.mu.Lock()
	a, err := ks.cache.find(a)
	ks.cache.mu.Unlock()
	return a, err
}

func (ks *KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, err := ks.Find(a)
	if err != nil {
		return a, nil, err
	}
	key, err := ks.storage.GetKey(a.Address, a.URL.Path, auth)
	return a, key, err
}

func (ks *KeyStore) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
		// 只是退出
	case <-t.C:
		ks.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		// 仅当它仍是 dropLater 启动时的同一密钥实例时才删除。
		// 我们可以使用指针相等性检查这一点，因为地图在每次解锁密钥时存储一个新指针。
		if ks.unlocked[addr] == u {
			zeroKey(u.PrivateKey)
			delete(ks.unlocked, addr)
		}
		ks.mu.Unlock()
	}
}

// NewAccount generates a new key and stores it into the key directory,
// encrypting it with the passphrase.
// NewAccount 生成一个新密钥并将其存储到密钥目录中，使用密码加密。
func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	// 立即将账户添加到缓存，而不是等待文件系统通知来获取它。
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
// Export 以 JSON 密钥形式导出，使用新密码加密。
func (ks *KeyStore) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	var N, P int
	if store, ok := ks.storage.(*keyStorePassphrase); ok {
		N, P = store.scryptN, store.scryptP
	} else {
		N, P = StandardScryptN, StandardScryptP
	}
	return EncryptKey(key, newPassphrase, N, P)
}

// Import stores the given encrypted JSON key into the key directory.
// Import 将给定的加密 JSON 密钥存储到密钥目录中。
func (ks *KeyStore) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {
	key, err := DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer zeroKey(key.PrivateKey)
	}
	if err != nil {
		return accounts.Account{}, err
	}
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}
	return ks.importKey(key, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
// ImportECDSA 将给定的密钥存储到密钥目录中，使用密码加密。
func (ks *KeyStore) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (accounts.Account, error) {
	ks.importMu.Lock()
	defer ks.importMu.Unlock()

	key := newKeyFromECDSA(priv)
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{
			Address: key.Address,
		}, ErrAccountAlreadyExists
	}
	return ks.importKey(key, passphrase)
}

func (ks *KeyStore) importKey(key *Key, passphrase string) (accounts.Account, error) {
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.storage.JoinPath(keyFileName(key.Address))}}
	if err := ks.storage.StoreKey(a.URL.Path, key, passphrase); err != nil {
		return accounts.Account{}, err
	}
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// Update changes the passphrase of an existing account.
// Update 更改现有账户的密码
func (ks *KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return ks.storage.StoreKey(a.URL.Path, key, newPassphrase)
}

// ImportPreSaleKey decrypts the given Ethereum presale wallet and stores
// a key file in the key directory. The key file is encrypted with the same passphrase.
// ImportPreSaleKey 解密给定的以太坊预售钱包并将密钥文件存储到密钥目录中。
// 密钥文件使用相同的密码加密。
func (ks *KeyStore) ImportPreSaleKey(keyJSON []byte, passphrase string) (accounts.Account, error) {
	a, _, err := importPreSaleKey(ks.storage, keyJSON, passphrase)
	if err != nil {
		return a, err
	}
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// isUpdating returns whether the event notification loop is running.
// This method is mainly meant for tests.
// isUpdating 返回事件通知循环是否正在运行。
// 此方法主要用于测试。
func (ks *KeyStore) isUpdating() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.updating
}

// zeroKey zeroes a private key in memory.
// zeroKey 将内存中的私钥清零
func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	clear(b)
}
