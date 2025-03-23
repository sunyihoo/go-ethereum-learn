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

package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// UIServerAPI implements methods Clef provides for a UI to query, in the bidirectional communication
// channel.
// This API is considered secure, since a request can only
// ever arrive from the UI -- and the UI is capable of approving any action, thus we can consider these
// requests pre-approved.
// NB: It's very important that these methods are not ever exposed on the external service
// registry.
//
// UIServerAPI 实现了 Clef 为 UI 提供的查询方法，在双向通信通道中。
// 这个 API 被认为是安全的，因为请求只能从 UI 发出——而 UI 能够批准任何操作，因此我们可以认为这些请求是预先批准的。
// 注意：非常重要的是，这些方法绝不能暴露在外部服务注册表上。
type UIServerAPI struct {
	extApi *SignerAPI
	am     *accounts.Manager
}

// NewUIServerAPI creates a new UIServerAPI
func NewUIServerAPI(extapi *SignerAPI) *UIServerAPI {
	return &UIServerAPI{extapi, extapi.am}
}

// ListAccounts lists available accounts. As opposed to the external API definition, this method delivers
// the full Account object and not only Address.
// Example call
// {"jsonrpc":"2.0","method":"clef_listAccounts","params":[], "id":4}
//
// ListAccounts 列出可用账户。与外部 API 定义不同，此方法返回完整的 Account 对象，而不仅仅是地址。
// 示例调用
// {"jsonrpc":"2.0","method":"clef_listAccounts","params":[], "id":4}
func (api *UIServerAPI) ListAccounts(ctx context.Context) ([]accounts.Account, error) {
	var accs []accounts.Account
	for _, wallet := range api.am.Wallets() {
		accs = append(accs, wallet.Accounts()...)
	}
	return accs, nil
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
//
// rawWallet 是 accounts.Wallet 接口的 JSON 表示形式，其数据内容被提取到普通字段中。
type rawWallet struct {
	URL      string             `json:"url"`                // 钱包的 URL（通常是密钥文件路径）
	Status   string             `json:"status"`             // 钱包的状态（例如 "Locked" 或 "Unlocked"）
	Failure  string             `json:"failure,omitempty"`  // 可选字段，钱包的错误信息（如果有）
	Accounts []accounts.Account `json:"accounts,omitempty"` // 可选字段，钱包中的账户列表
}

// ListWallets will return a list of wallets that clef manages
// Example call
// {"jsonrpc":"2.0","method":"clef_listWallets","params":[], "id":5}
//
// ListWallets 将返回 Clef 管理的钱包列表
// 示例调用
// {"jsonrpc":"2.0","method":"clef_listWallets","params":[], "id":5}
func (api *UIServerAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty 如果为空，返回 [] 而不是 nil
	for _, wallet := range api.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// DeriveAccount requests a HD wallet to derive a new account, optionally pinning
// it for later reuse.
// Example call
// {"jsonrpc":"2.0","method":"clef_deriveAccount","params":["ledger://","m/44'/60'/0'", false], "id":6}
//
// DeriveAccount 请求 HD 钱包派生一个新账户，可选择将其固定以便后续重用。
// 示例调用
// {"jsonrpc":"2.0","method":"clef_deriveAccount","params":["ledger://","m/44'/60'/0'", false], "id":6}
//
// DeriveAccount 的目的是从指定的 HD 钱包中派生一个新账户，支持软件或硬件钱包，并允许选择是否固定账户以便重用
//
//	HD 钱包（BIP-32/BIP-44）：
//	以太坊使用层次确定性（HD）钱包，通过主私钥和派生路径生成子密钥。m/44'/60'/0' 是以太坊的标准路径，60' 表示以太坊链。
func (api *UIServerAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := api.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// fetchKeystore retrieves the encrypted keystore from the account manager.
// fetchKeystore 从账户管理器中检索加密的 keystore。
func fetchKeystore(am *accounts.Manager) *keystore.KeyStore {
	ks := am.Backends(keystore.KeyStoreType)
	if len(ks) == 0 {
		return nil
	}
	return ks[0].(*keystore.KeyStore)
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
// Example call (should fail on password too short)
// {"jsonrpc":"2.0","method":"clef_importRawKey","params":["1111111111111111111111111111111111111111111111111111111111111111","test"], "id":6}
//
// ImportRawKey 将给定的十六进制编码的 ECDSA 密钥存储到密钥目录中，
// 使用密码对其进行加密。
// 示例调用（因密码太短应失败）
// {"jsonrpc":"2.0","method":"clef_importRawKey","params":["1111111111111111111111111111111111111111111111111111111111111111","test"], "id":6}
func (api *UIServerAPI) ImportRawKey(privkey string, password string) (accounts.Account, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return accounts.Account{}, err
	}
	// 检查密码是否满足要求（例如长度或复杂度）。示例中提到短密码（如 "test"）会导致失败。
	if err := ValidatePasswordFormat(password); err != nil {
		return accounts.Account{}, fmt.Errorf("password requirements not met: %v", err)
	}
	// No error
	return fetchKeystore(api.am).ImportECDSA(key, password)
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
// Example
// {"jsonrpc":"2.0","method":"clef_openWallet","params":["ledger://",""], "id":6}
//
// OpenWallet 启动硬件钱包的打开程序，建立 USB 连接并尝试通过提供的密码进行身份验证。注意，
// 该方法可能会返回一个额外的挑战，要求第二次打开（例如 Trezor 的 PIN 矩阵挑战）。
// 示例
// {"jsonrpc":"2.0","method":"clef_openWallet","params":["ledger://",""], "id":6}
func (api *UIServerAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := api.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// ChainId returns the chainid in use for Eip-155 replay protection
// Example call
// {"jsonrpc":"2.0","method":"clef_chainId","params":[], "id":8}
//
// ChainId 返回用于 EIP-155 重放保护的链 ID
// 示例调用
// {"jsonrpc":"2.0","method":"clef_chainId","params":[], "id":8}
func (api *UIServerAPI) ChainId() math.HexOrDecimal64 {
	return (math.HexOrDecimal64)(api.extApi.chainID.Uint64())
}

// SetChainId sets the chain id to use when signing transactions.
// Example call to set Ropsten:
// {"jsonrpc":"2.0","method":"clef_setChainId","params":["3"], "id":8}
//
// SetChainId 设置签名交易时使用的链 ID。
// 示例调用以设置为 Ropsten：
// {"jsonrpc":"2.0","method":"clef_setChainId","params":["3"], "id":8}
func (api *UIServerAPI) SetChainId(id math.HexOrDecimal64) math.HexOrDecimal64 {
	api.extApi.chainID = new(big.Int).SetUint64(uint64(id))
	return api.ChainId()
}

// Export returns encrypted private key associated with the given address in web3 keystore format.
// Example
// {"jsonrpc":"2.0","method":"clef_export","params":["0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"], "id":4}
//
// Export 返回与给定地址关联的加密私钥，采用 web3 keystore 格式。
// 示例
// {"jsonrpc":"2.0","method":"clef_export","params":["0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"], "id":4}
func (api *UIServerAPI) Export(ctx context.Context, addr common.Address) (json.RawMessage, error) {
	// Look up the wallet containing the requested signer
	// 查找包含请求签名者的钱包
	wallet, err := api.am.Find(accounts.Account{Address: addr})
	if err != nil {
		return nil, err
	}
	if wallet.URL().Scheme != keystore.KeyStoreScheme {
		return nil, errors.New("account is not a keystore-account")
	}
	return os.ReadFile(wallet.URL().Path)
}

// Import tries to import the given keyJSON in the local keystore. The keyJSON data is expected to be
// in web3 keystore format. It will decrypt the keyJSON with the given passphrase and on successful
// decryption it will encrypt the key with the given newPassphrase and store it in the keystore.
// Example (the address in question has privkey `11...11`):
// {"jsonrpc":"2.0","method":"clef_import","params":[{"address":"19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","crypto":{"cipher":"aes-128-ctr","ciphertext":"33e4cd3756091d037862bb7295e9552424a391a6e003272180a455ca2a9fb332","cipherparams":{"iv":"b54b263e8f89c42bb219b6279fba5cce"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"e4ca94644fd30569c1b1afbbc851729953c92637b7fe4bb9840bbb31ffbc64a5"},"mac":"f4092a445c2b21c0ef34f17c9cd0d873702b2869ec5df4439a0c2505823217e7"},"id":"216c7eac-e8c1-49af-a215-fa0036f29141","version":3},"test","yaddayadda"], "id":4}
//
// Import 尝试将给定的 keyJSON 导入本地 keystore。keyJSON 数据应采用 web3 keystore 格式。
// 它将使用给定的密码解密 keyJSON，解密成功后，将使用给定的新密码重新加密密钥并存储到 keystore 中。
// 示例（相关地址的私钥为 `11...11`）：
// {"jsonrpc":"2.0","method":"clef_import","params":[{"address":"19e7e376e7c213b7e7e7e46cc70a5dd086daff2a","crypto":{"cipher":"aes-128-ctr","ciphertext":"33e4cd3756091d037862bb7295e9552424a391a6e003272180a455ca2a9fb332","cipherparams":{"iv":"b54b263e8f89c42bb219b6279fba5cce"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"e4ca94644fd30569c1b1afbbc851729953c92637b7fe4bb9840bbb31ffbc64a5"},"mac":"f4092a445c2b21c0ef34f17c9cd0d873702b2869ec5df4439a0c2505823217e7"},"id":"216c7eac-e8c1-49af-a215-fa0036f29141","version":3},"test","yaddayadda"], "id":4}
//
// Import 解密 keyJSON（验证 oldPassphrase），用 newPassphrase 重新加密，生成新的 keystore 文件。
func (api *UIServerAPI) Import(ctx context.Context, keyJSON json.RawMessage, oldPassphrase, newPassphrase string) (accounts.Account, error) {
	be := api.am.Backends(keystore.KeyStoreType)

	if len(be) == 0 {
		return accounts.Account{}, errors.New("password based accounts not supported")
	}
	if err := ValidatePasswordFormat(newPassphrase); err != nil {
		return accounts.Account{}, fmt.Errorf("password requirements not met: %v", err)
	}
	return be[0].(*keystore.KeyStore).Import(keyJSON, oldPassphrase, newPassphrase)
}

// New creates a new password protected Account. The private key is protected with
// the given password. Users are responsible to backup the private key that is stored
// in the keystore location that was specified when this API was created.
// This method is the same as New on the external API, the difference being that
// this implementation does not ask for confirmation, since it's initiated by
// the user
//
// New 创建一个受密码保护的新账户。私钥使用给定的密码进行保护。
// 用户负责备份存储在创建此 API 时指定的 keystore 位置中的私钥。
// 此方法与外部 API 上的 New 方法相同，不同之处在于此实现不需要确认，
// 因为它是由用户发起的
func (api *UIServerAPI) New(ctx context.Context) (common.Address, error) {
	return api.extApi.newAccount()
}

// Other methods to be added, not yet implemented are:
// - Ruleset interaction: add rules, attest rulefiles
// - Store metadata about accounts, e.g. naming of accounts
