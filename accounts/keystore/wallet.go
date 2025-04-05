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

package keystore

import (
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// keystoreWallet implements the accounts.Wallet interface for the original
// keystore.
// keystoreWallet 为原始密钥存储实现了 accounts.Wallet 接口
type keystoreWallet struct {
	account accounts.Account // Single account contained in this wallet
	// 此钱包中包含的单个账户
	keystore *KeyStore // Keystore where the account originates from
	// 账户来源的密钥存储
}

// URL implements accounts.Wallet, returning the URL of the account within.
// URL 实现了 accounts.Wallet，返回钱包内账户的 URL
func (w *keystoreWallet) URL() accounts.URL {
	return w.account.URL
}

// Status implements accounts.Wallet, returning whether the account held by the
// keystore wallet is unlocked or not.
// Status 实现了 accounts.Wallet，返回密钥存储钱包持有的账户是否已解锁
func (w *keystoreWallet) Status() (string, error) {
	w.keystore.mu.RLock()
	defer w.keystore.mu.RUnlock()

	if _, ok := w.keystore.unlocked[w.account.Address]; ok {
		return "Unlocked", nil
	}
	return "Locked", nil
}

// Open implements accounts.Wallet, but is a noop for plain wallets since there
// is no connection or decryption step necessary to access the list of accounts.
// Open 实现了 accounts.Wallet，但对于普通钱包是空操作，
// 因为访问账户列表无需连接或解密步骤
func (w *keystoreWallet) Open(passphrase string) error { return nil }

// Close implements accounts.Wallet, but is a noop for plain wallets since there
// is no meaningful open operation.
// Close 实现了 accounts.Wallet，但对于普通钱包是空操作，
// 因为没有有意义的打开操作
func (w *keystoreWallet) Close() error { return nil }

// Accounts implements accounts.Wallet, returning an account list consisting of
// a single account that the plain keystore wallet contains.
// Accounts 实现了 accounts.Wallet，返回普通密钥存储钱包包含的单个账户的账户列表
func (w *keystoreWallet) Accounts() []accounts.Account {
	return []accounts.Account{w.account}
}

// Contains implements accounts.Wallet, returning whether a particular account is
// or is not wrapped by this wallet instance.
// Contains 实现了 accounts.Wallet，返回特定账户是否由此钱包实例包装
func (w *keystoreWallet) Contains(account accounts.Account) bool {
	return account.Address == w.account.Address && (account.URL == (accounts.URL{}) || account.URL == w.account.URL)
}

// Derive implements accounts.Wallet, but is a noop for plain wallets since there
// is no notion of hierarchical account derivation for plain keystore accounts.
// Derive 实现了 accounts.Wallet，但对于普通钱包是空操作，
// 因为普通密钥存储账户没有层次账户派生的概念
func (w *keystoreWallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, accounts.ErrNotSupported
}

// SelfDerive implements accounts.Wallet, but is a noop for plain wallets since
// there is no notion of hierarchical account derivation for plain keystore accounts.
// SelfDerive 实现了 accounts.Wallet，但对于普通钱包是空操作，
// 因为普通密钥存储账户没有层次账户派生的概念
func (w *keystoreWallet) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
}

// signHash attempts to sign the given hash with
// the given account. If the wallet does not wrap this particular account, an
// error is returned to avoid account leakage (even though in theory we may be
// able to sign via our shared keystore backend).
// signHash 尝试使用给定账户签署给定的哈希。
// 如果钱包未包装此特定账户，则返回错误以避免账户泄露（尽管理论上我们可能通过共享密钥存储后端签名）。
func (w *keystoreWallet) signHash(account accounts.Account, hash []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的账户包含在此钱包内
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 账户看似有效，请求密钥存储签名
	return w.keystore.SignHash(account, hash)
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed.
// SignData 签署 keccak256(data)。mimetype 参数描述被签名的数据类型。
func (w *keystoreWallet) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	return w.signHash(account, crypto.Keccak256(data))
}

// SignDataWithPassphrase signs keccak256(data). The mimetype parameter describes the type of data being signed.
// SignDataWithPassphrase 签署 keccak256(data)。mimetype 参数描述被签名的数据类型。
func (w *keystoreWallet) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的账户包含在此钱包内
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 账户看似有效，请求密钥存储签名
	return w.keystore.SignHashWithPassphrase(account, passphrase, crypto.Keccak256(data))
}

// SignText implements accounts.Wallet, attempting to sign the hash of
// the given text with the given account.
// SignText 实现了 accounts.Wallet，尝试使用给定账户签署给定文本的哈希
func (w *keystoreWallet) SignText(account accounts.Account, text []byte) ([]byte, error) {
	return w.signHash(account, accounts.TextHash(text))
}

// SignTextWithPassphrase implements accounts.Wallet, attempting to sign the
// hash of the given text with the given account using passphrase as extra authentication.
// SignTextWithPassphrase 实现了 accounts.Wallet，尝试使用给定账户和密码作为额外认证签署给定文本的哈希
func (w *keystoreWallet) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	// Make sure the requested account is contained within
	// 确保请求的账户包含在此钱包内
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 账户看似有效，请求密钥存储签名
	return w.keystore.SignHashWithPassphrase(account, passphrase, accounts.TextHash(text))
}

// SignTx implements accounts.Wallet, attempting to sign the given transaction
// with the given account. If the wallet does not wrap this particular account,
// an error is returned to avoid account leakage (even though in theory we may
// be able to sign via our shared keystore backend).
// SignTx 实现了 accounts.Wallet，尝试使用给定账户签署给定交易。
// 如果钱包未包装此特定账户，则返回错误以避免账户泄露（尽管理论上我们可能通过共享密钥存储后端签名）。
func (w *keystoreWallet) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	// 确保请求的账户包含在此钱包内
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 账户看似有效，请求密钥存储签名
	return w.keystore.SignTx(account, tx, chainID)
}

// SignTxWithPassphrase implements accounts.Wallet, attempting to sign the given
// transaction with the given account using passphrase as extra authentication.
// SignTxWithPassphrase 实现了 accounts.Wallet，尝试使用给定账户和密码作为额外认证签署给定交易
func (w *keystoreWallet) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	// Make sure the requested account is contained within
	// 确保请求的账户包含在此钱包内
	if !w.Contains(account) {
		return nil, accounts.ErrUnknownAccount
	}
	// Account seems valid, request the keystore to sign
	// 账户看似有效，请求密钥存储签名
	return w.keystore.SignTxWithPassphrase(account, passphrase, tx, chainID)
}
