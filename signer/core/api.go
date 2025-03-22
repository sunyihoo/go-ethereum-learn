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

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/accounts/scwallet"
	"github.com/ethereum/go-ethereum/accounts/usbwallet"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/ethereum/go-ethereum/signer/storage"
)

// BIP-44：这是比特币改进提案，用于定义硬件钱包的账户派生路径。
// 以太坊使用路径 m/44'/60'/0'/0/n，其中 60' 是以太坊的币种标识，n 是账户索引。

const (
	// numberOfAccountsToDerive For hardware wallets, the number of accounts to derive
	// numberOfAccountsToDerive 对于硬件钱包，要派生的账户数量 numberOfAccountsToDerive 可用于以太坊钱包（如 Ledger、Trezor）中基于 BIP-44 路径派生多个账户。
	numberOfAccountsToDerive = 10
	// ExternalAPIVersion -- see extapi_changelog.md
	ExternalAPIVersion = "6.1.0"
	// InternalAPIVersion -- see intapi_changelog.md
	InternalAPIVersion = "7.0.1"
)

// ExternalAPI defines the external API through which signing requests are made.
// ExternalAPI 定义了通过其进行签名请求的外部 API。
// 定义一个外部 API 接口，用于以太坊账户管理、交易签名、数据签名及多签支持。
type ExternalAPI interface {
	// List available accounts 列出可用账户 返回当前可用的以太坊账户地址列表。
	List(ctx context.Context) ([]common.Address, error)
	// New request to create a new account 请求创建新账户 生成并返回一个新的以太坊账户地址。
	New(ctx context.Context) (common.Address, error)
	// SignTransaction request to sign the specified transaction 请求签名指定交易；对给定的交易参数进行签名
	SignTransaction(ctx context.Context, args apitypes.SendTxArgs, methodSelector *string) (*ethapi.SignTransactionResult, error)
	// SignData - request to sign the given data (plus prefix) 请求签名给定数据，含前缀；对任意数据签名，通常用于消息验证。
	SignData(ctx context.Context, contentType string, addr common.MixedcaseAddress, data interface{}) (hexutil.Bytes, error)
	// SignTypedData - request to sign the given structured data (plus prefix) 对结构化数据签名，请求签名给定的结构化数据，含前缀，遵循 EIP-712。EIP-712 是以太坊类型化数据签名的标准。
	SignTypedData(ctx context.Context, addr common.MixedcaseAddress, data apitypes.TypedData) (hexutil.Bytes, error)
	// EcRecover - recover public key from given message and signature 从给定消息和签名恢复公钥
	EcRecover(ctx context.Context, data hexutil.Bytes, sig hexutil.Bytes) (common.Address, error)
	// Version info about the APIs API 的版本信息
	Version(ctx context.Context) (string, error)
	// SignGnosisSafeTx signs/confirms a gnosis-safe multisig transaction 签名/确认 Gnosis Safe 多签交易
	SignGnosisSafeTx(ctx context.Context, signerAddress common.MixedcaseAddress, gnosisTx GnosisSafeTx, methodSelector *string) (*GnosisSafeTx, error)
}

// UIClientAPI specifies what method a UI needs to implement to be able to be used as a
// UI for the signer
// UIClientAPI 指定了 UI 需要实现哪些方法，以便能够作为签名器的用户界面
// 定义了签名器（如 Clef）与其用户界面交互所需的方法。
type UIClientAPI interface {
	// ApproveTx prompt the user for confirmation to request to sign Transaction 提示用户确认签名交易请求
	//
	// ApproveTx 提示用户确认签名交易请求，请求用户确认是否签名指定的交易。
	ApproveTx(request *SignTxRequest) (SignTxResponse, error)
	// ApproveSignData prompt the user for confirmation to request to sign data
	//
	// ApproveSignData 提示用户确认签名数据请求 请求用户确认签名任意数据。
	ApproveSignData(request *SignDataRequest) (SignDataResponse, error)
	// ApproveListing prompt the user for confirmation to list accounts
	// the list of accounts to list can be modified by the UI
	//
	// ApproveListing 提示用户确认列出账户要列出的账户列表可以由 UI 修改
	// 请求用户确认并可能调整要列出的账户列表。
	ApproveListing(request *ListRequest) (ListResponse, error)
	// ApproveNewAccount prompt the user for confirmation to create new Account, and reveal to caller
	//
	// ApproveNewAccount 提示用户确认创建新账户，并向调用者展示 请求用户确认创建新账户。
	ApproveNewAccount(request *NewAccountRequest) (NewAccountResponse, error)
	// ShowError displays error message to user
	ShowError(message string)
	// ShowInfo displays info message to user
	ShowInfo(message string)
	// OnApprovedTx notifies the UI about a transaction having been successfully signed.
	// This method can be used by a UI to keep track of e.g. how much has been sent to a particular recipient.
	//
	// OnApprovedTx 通知 UI 交易已成功签名
	// 此方法可用于 UI 跟踪，例如发送给特定接收者的金额
	OnApprovedTx(tx ethapi.SignTransactionResult)
	// OnSignerStartup is invoked when the signer boots, and tells the UI info about external API location and version
	// information
	//
	// OnSignerStartup 在签名器启动时调用，告知 UI 外部 API 位置和版本信息 在签名器启动时提供初始化信息。
	OnSignerStartup(info StartupInfo)
	// OnInputRequired is invoked when clef requires user input, for example master password or
	// pin-code for unlocking hardware wallets
	//
	// OnInputRequired 当 Clef 需要用户输入时调用，例如主密码或解锁硬件钱包的 PIN 码 请求用户输入敏感信息（如密码或 PIN 码）
	OnInputRequired(info UserInputRequest) (UserInputResponse, error)
	// RegisterUIServer tells the UI to use the given UIServerAPI for ui->clef communication
	//
	// RegisterUIServer 告诉 UI 使用给定的 UIServerAPI 进行 UI 到 Clef 的通信 注册 UI 与签名器的通信通道。
	RegisterUIServer(api *UIServerAPI)
}

// Validator defines the methods required to validate a transaction against some
// sanity defaults as well as any underlying 4byte method database.
//
// Use fourbyte.Database as an implementation. It is separated out of this package
// to allow pieces of the signer package to be used without having to load the
// 7MB embedded 4byte dump.
//
// Validator 定义了验证交易所需的方法，以检查一些合理的默认值以及底层的 4byte 方法数据库。
//
// 使用 fourbyte.Database 作为实现。它从这个包中分离出来，以便在不加载 7MB 嵌入式 4byte 数据转储的情况下使用签名者包的部分功能。
type Validator interface {
	// ValidateTransaction does a number of checks on the supplied transaction, and
	// returns either a list of warnings, or an error (indicating that the transaction
	// should be immediately rejected).
	//
	// ValidateTransaction 对提供的交易执行多项检查，并返回警告列表或错误（表示交易应立即被拒绝）。
	ValidateTransaction(selector *string, tx *apitypes.SendTxArgs) (*apitypes.ValidationMessages, error)
}

// SignerAPI defines the actual implementation of ExternalAPI
// SignerAPI 定义了 ExternalAPI 的实际实现
type SignerAPI struct {
	chainID     *big.Int          // 链 ID，用于标识当前区块链网络（例如，以太坊主网为 1）
	am          *accounts.Manager // 账户管理器，负责管理钱包账户、密钥等。
	UI          UIClientAPI       // 用户界面客户端 API
	validator   Validator         // 交易验证器
	rejectMode  bool              // 拒绝模式标志
	credentials storage.Storage   // 凭证存储
}

// Metadata about a request
// 请求的元数据
type Metadata struct {
	Remote    string `json:"remote"`
	Local     string `json:"local"`
	Scheme    string `json:"scheme"`
	UserAgent string `json:"User-Agent"`
	Origin    string `json:"Origin"`
}

// StartClefAccountManager
// ksLocation string: 密钥存储路径。
// nousb bool: 是否禁用 USB 硬件钱包。
// lightKDF bool: 是否使用轻量级 Scrypt 参数。
// scpath string: 智能卡套接字路径。
func StartClefAccountManager(ksLocation string, nousb, lightKDF bool, scpath string) *accounts.Manager {
	var (
		backends []accounts.Backend // 存储所有账户后端。
		n, p     = keystore.StandardScryptN, keystore.StandardScryptP
	)
	if lightKDF { // 使用轻量级参数（LightScryptN, LightScryptP），降低计算成本。
		n, p = keystore.LightScryptN, keystore.LightScryptP
	}
	// support password based accounts
	// 支持基于密码的账户
	if len(ksLocation) > 0 {
		backends = append(backends, keystore.NewKeyStore(ksLocation, n, p))
	}
	if !nousb {
		// Start a USB hub for Ledger hardware wallets
		// 启动 Ledger 硬件钱包的 USB 中心
		if ledgerhub, err := usbwallet.NewLedgerHub(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start Ledger hub, disabling: %v", err))
		} else {
			backends = append(backends, ledgerhub)
			log.Debug("Ledger support enabled")
		}
		// Start a USB hub for Trezor hardware wallets (HID version)
		// 启动 Trezor 硬件钱包的 USB 中心（HID 版本）
		if trezorhub, err := usbwallet.NewTrezorHubWithHID(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start HID Trezor hub, disabling: %v", err))
		} else {
			backends = append(backends, trezorhub)
			log.Debug("Trezor support enabled via HID")
		}
		// Start a USB hub for Trezor hardware wallets (WebUSB version)
		// 启动 Trezor 硬件钱包的 USB 中心（WebUSB 版本）
		if trezorhub, err := usbwallet.NewTrezorHubWithWebUSB(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start WebUSB Trezor hub, disabling: %v", err))
		} else {
			backends = append(backends, trezorhub)
			log.Debug("Trezor support enabled via WebUSB")
		}
	}

	// Start a smart card hub
	// 启动智能卡中心
	if len(scpath) > 0 {
		// Sanity check that the smartcard path is valid
		// 检查智能卡路径是否有效
		fi, err := os.Stat(scpath)
		if err != nil {
			log.Info("Smartcard socket file missing, disabling", "err", err)
		} else {
			if fi.Mode()&os.ModeType != os.ModeSocket {
				log.Error("Invalid smartcard socket file type", "path", scpath, "type", fi.Mode().String())
			} else {
				if schub, err := scwallet.NewHub(scpath, scwallet.Scheme, ksLocation); err != nil {
					log.Warn(fmt.Sprintf("Failed to start smart card hub, disabling: %v", err))
				} else {
					backends = append(backends, schub)
				}
			}
		}
	}
	return accounts.NewManager(nil, backends...)
}

// MetadataFromContext extracts Metadata from a given context.Context
func MetadataFromContext(ctx context.Context) Metadata {
	info := rpc.PeerInfoFromContext(ctx)

	m := Metadata{"NA", "NA", "NA", "", ""} // batman

	if info.Transport != "" {
		if info.Transport == "http" {
			m.Scheme = info.HTTP.Version
		}
		m.Scheme = info.Transport
	}
	if info.RemoteAddr != "" {
		m.Remote = info.RemoteAddr
	}
	if info.HTTP.Host != "" {
		m.Local = info.HTTP.Host
	}
	m.Origin = info.HTTP.Origin
	m.UserAgent = info.HTTP.UserAgent
	return m
}

// String implements Stringer interface
func (m Metadata) String() string {
	s, err := json.Marshal(m)
	if err == nil {
		return string(s)
	}
	return err.Error()
}

// types for the requests/response types between signer and UI
// 签名器与 UI 之间请求和响应类型的定义
type (
	// SignTxRequest contains info about a Transaction to sign
	// SignTxRequest 包含待签名交易的信息
	SignTxRequest struct {
		Transaction apitypes.SendTxArgs       `json:"transaction"` // 交易参数
		Callinfo    []apitypes.ValidationInfo `json:"call_info"`   // 调用验证信息
		Meta        Metadata                  `json:"meta"`        // 元数据
	}
	// SignTxResponse result from SignTxRequest
	// SignTxResponse 是 SignTxRequest 的结果
	SignTxResponse struct {
		//The UI may make changes to the TX
		// UI 可能会对交易进行修改
		Transaction apitypes.SendTxArgs `json:"transaction"` // 修改后的交易参数
		Approved    bool                `json:"approved"`    // 是否批准
	}
	// SignDataRequest 包含待签名数据的信息
	SignDataRequest struct {
		ContentType string                    `json:"content_type"` // 内容类型
		Address     common.MixedcaseAddress   `json:"address"`      // 签名地址
		Rawdata     []byte                    `json:"raw_data"`     // 原始数据
		Messages    []*apitypes.NameValueType `json:"messages"`     // 消息列表
		Callinfo    []apitypes.ValidationInfo `json:"call_info"`    // 调用验证信息
		Hash        hexutil.Bytes             `json:"hash"`         // 数据哈希
		Meta        Metadata                  `json:"meta"`         // 元数据
	}
	// SignDataResponse 是 SignDataRequest 的结果
	SignDataResponse struct {
		Approved bool `json:"approved"` // 是否批准
	}
	// NewAccountRequest 包含创建新账户的请求信息
	NewAccountRequest struct {
		Meta Metadata `json:"meta"`
	}
	// NewAccountResponse 是 NewAccountRequest 的结果
	NewAccountResponse struct {
		Approved bool `json:"approved"`
	}
	// ListRequest 包含列出账户的请求信息
	ListRequest struct {
		Accounts []accounts.Account `json:"accounts"`
		Meta     Metadata           `json:"meta"`
	}
	// ListResponse 是 ListRequest 的结果
	ListResponse struct {
		Accounts []accounts.Account `json:"accounts"`
	}
	// Message 包含消息文本
	Message struct {
		Text string `json:"text"` // 消息内容
	}
	// StartupInfo 包含签名器启动信息
	StartupInfo struct {
		Info map[string]interface{} `json:"info"`
	}
	// UserInputRequest 包含用户输入请求的信息
	UserInputRequest struct {
		Title      string `json:"title"`
		Prompt     string `json:"prompt"`
		IsPassword bool   `json:"isPassword"`
	}
	// UserInputResponse 是 UserInputRequest 的结果
	UserInputResponse struct {
		Text string `json:"text"`
	}
)

var ErrRequestDenied = errors.New("request denied")

// NewSignerAPI creates a new API that can be used for Account management.
// ksLocation specifies the directory where to store the password protected private
// key that is generated when a new Account is created.
// noUSB disables USB support that is required to support hardware devices such as
// ledger and trezor.
func NewSignerAPI(am *accounts.Manager, chainID int64, noUSB bool, ui UIClientAPI, validator Validator, advancedMode bool, credentials storage.Storage) *SignerAPI {
	if advancedMode {
		log.Info("Clef is in advanced mode: will warn instead of reject")
	}
	signer := &SignerAPI{big.NewInt(chainID), am, ui, validator, !advancedMode, credentials}
	if !noUSB {
		signer.startUSBListener()
	}
	return signer
}
func (api *SignerAPI) openTrezor(url accounts.URL) {
	resp, err := api.UI.OnInputRequired(UserInputRequest{
		Prompt: "Pin required to open Trezor wallet\n" +
			"Look at the device for number positions\n\n" +
			"7 | 8 | 9\n" +
			"--+---+--\n" +
			"4 | 5 | 6\n" +
			"--+---+--\n" +
			"1 | 2 | 3\n\n",
		IsPassword: true,
		Title:      "Trezor unlock",
	})
	if err != nil {
		log.Warn("failed getting trezor pin", "err", err)
		return
	}
	// We're using the URL instead of the pointer to the
	// Wallet -- perhaps it is not actually present anymore
	w, err := api.am.Wallet(url.String())
	if err != nil {
		log.Warn("wallet unavailable", "url", url)
		return
	}
	err = w.Open(resp.Text)
	if err != nil {
		log.Warn("failed to open wallet", "wallet", url, "err", err)
		return
	}
}

// startUSBListener starts a listener for USB events, for hardware wallet interaction
func (api *SignerAPI) startUSBListener() {
	eventCh := make(chan accounts.WalletEvent, 16)
	am := api.am
	am.Subscribe(eventCh)
	// Open any wallets already attached
	for _, wallet := range am.Wallets() {
		if err := wallet.Open(""); err != nil {
			log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
			if err == usbwallet.ErrTrezorPINNeeded {
				go api.openTrezor(wallet.URL())
			}
		}
	}
	go api.derivationLoop(eventCh)
}

// derivationLoop listens for wallet events
func (api *SignerAPI) derivationLoop(events chan accounts.WalletEvent) {
	// Listen for wallet event till termination
	for event := range events {
		switch event.Kind {
		case accounts.WalletArrived:
			if err := event.Wallet.Open(""); err != nil {
				log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
				if err == usbwallet.ErrTrezorPINNeeded {
					go api.openTrezor(event.Wallet.URL())
				}
			}
		case accounts.WalletOpened:
			status, _ := event.Wallet.Status()
			log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)
			var derive = func(limit int, next func() accounts.DerivationPath) {
				// Derive first N accounts, hardcoded for now
				for i := 0; i < limit; i++ {
					path := next()
					if acc, err := event.Wallet.Derive(path, true); err != nil {
						log.Warn("Account derivation failed", "error", err)
					} else {
						log.Info("Derived account", "address", acc.Address, "path", path)
					}
				}
			}
			log.Info("Deriving default paths")
			derive(numberOfAccountsToDerive, accounts.DefaultIterator(accounts.DefaultBaseDerivationPath))
			if event.Wallet.URL().Scheme == "ledger" {
				log.Info("Deriving ledger legacy paths")
				derive(numberOfAccountsToDerive, accounts.DefaultIterator(accounts.LegacyLedgerBaseDerivationPath))
				log.Info("Deriving ledger live paths")
				// For ledger live, since it's based off the same (DefaultBaseDerivationPath)
				// as one we've already used, we need to step it forward one step to avoid
				// hitting the same path again
				nextFn := accounts.LedgerLiveIterator(accounts.DefaultBaseDerivationPath)
				nextFn()
				derive(numberOfAccountsToDerive, nextFn)
			}
		case accounts.WalletDropped:
			log.Info("Old wallet dropped", "url", event.Wallet.URL())
			event.Wallet.Close()
		}
	}
}

// List returns the set of wallet this signer manages. Each wallet can contain
// multiple accounts.
//
// List 返回此签名器管理的钱包集合。每个钱包可以包含多个账户。
// 用于返回签名器管理的钱包中的账户地址列表。
func (api *SignerAPI) List(ctx context.Context) ([]common.Address, error) {
	var accs = make([]accounts.Account, 0)
	// accs is initialized as empty list, not nil. We use 'nil' to signal
	// rejection, as opposed to an empty list.
	//
	// accs 初始化为空列表，而不是 nil。我们使用 'nil' 来表示拒绝，而非空列表。
	for _, wallet := range api.am.Wallets() {
		// 遍历签名器的账户管理器（api.am）中的所有钱包，获取每个钱包的账户并追加到 accs
		accs = append(accs, wallet.Accounts()...)
	}
	// 调用 UI 的 ApproveListing 方法，获取用户批准的账户列表
	result, err := api.UI.ApproveListing(&ListRequest{Accounts: accs, Meta: MetadataFromContext(ctx)})
	if err != nil {
		return nil, err
	}
	if result.Accounts == nil {
		// 如果返回的账户列表为 nil，表示用户拒绝请求
		return nil, ErrRequestDenied
	}
	// 将批准的账户地址转换为地址列表
	addresses := make([]common.Address, 0)
	for _, acc := range result.Accounts {
		addresses = append(addresses, acc.Address)
	}
	return addresses, nil
}

// New creates a new password protected Account. The private key is protected with
// the given password. Users are responsible to backup the private key that is stored
// in the keystore location that was specified when this API was created.
//
// New 创建一个新的受密码保护的账户。私钥使用给定的密码进行保护。
// 用户负责备份存储在创建此 API 时指定的 keystore 位置的私钥。
//
// 创建新的受密码保护的以太坊账户，确保用户批准和密码安全。
func (api *SignerAPI) New(ctx context.Context) (common.Address, error) {
	// 检查是否支持基于密码的账户
	if be := api.am.Backends(keystore.KeyStoreType); len(be) == 0 {
		return common.Address{}, errors.New("password based accounts not supported")
	}
	// 请求用户批准创建新账户
	if resp, err := api.UI.ApproveNewAccount(&NewAccountRequest{MetadataFromContext(ctx)}); err != nil {
		return common.Address{}, err
	} else if !resp.Approved { // 如果用户未批准，返回拒绝错误
		return common.Address{}, ErrRequestDenied
	}
	return api.newAccount()
}

// newAccount is the internal method to create a new account. It should be used
// _after_ user-approval has been obtained
//
// newAccount 是创建新账户的内部方法。应在获得用户批准后使用。
func (api *SignerAPI) newAccount() (common.Address, error) {
	// 再次检查是否支持基于密码的账户
	be := api.am.Backends(keystore.KeyStoreType)
	if len(be) == 0 {
		return common.Address{}, errors.New("password based accounts not supported")
	}
	// Three retries to get a valid password
	// 提供三次尝试输入有效密码
	for i := 0; i < 3; i++ {
		// 请求用户输入新账户密码
		resp, err := api.UI.OnInputRequired(UserInputRequest{
			"New account password",
			fmt.Sprintf("Please enter a password for the new account to be created (attempt %d of 3)", i),
			true})
		if err != nil {
			log.Warn("error obtaining password", "attempt", i, "error", err)
			continue
		}
		// 验证密码格式
		if pwErr := ValidatePasswordFormat(resp.Text); pwErr != nil {
			// 如果密码格式无效，显示错误并继续下一次尝试
			api.UI.ShowError(fmt.Sprintf("Account creation attempt #%d failed due to password requirements: %v", i+1, pwErr))
		} else {
			// No error
			// 无错误，创建账户
			acc, err := be[0].(*keystore.KeyStore).NewAccount(resp.Text)
			log.Info("Your new key was generated", "address", acc.Address)
			log.Warn("Please backup your key file!", "path", acc.URL.Path)
			log.Warn("Please remember your password!")
			return acc.Address, err
		}
	}
	// Otherwise fail, with generic error message
	// 三次尝试失败后返回通用错误
	return common.Address{}, errors.New("account creation failed")
}

// logDiff logs the difference between the incoming (original) transaction and the one returned from the signer.
// it also returns 'true' if the transaction was modified, to make it possible to configure the signer not to allow
// UI-modifications to requests
//
// logDiff 记录传入的（原始）交易与签名器返回的交易之间的差异。
// 如果交易被修改，它还会返回 'true'，以便可以配置签名器不允许 UI 修改请求。
func logDiff(original *SignTxRequest, new *SignTxResponse) bool {
	// 定义比较两个 *hexutil.Big 是否不同的辅助函数
	var intPtrModified = func(a, b *hexutil.Big) bool {
		aBig := (*big.Int)(a)
		bBig := (*big.Int)(b)
		if aBig != nil && bBig != nil {
			return aBig.Cmp(bBig) != 0
		}
		// One or both of them are nil
		return a != b
	}

	modified := false
	// 比较发送者地址
	if f0, f1 := original.Transaction.From, new.Transaction.From; !reflect.DeepEqual(f0, f1) {
		log.Info("Sender-account changed by UI", "was", f0, "is", f1)
		modified = true
	}
	// 比较接收者地址
	if t0, t1 := original.Transaction.To, new.Transaction.To; !reflect.DeepEqual(t0, t1) {
		log.Info("Recipient-account changed by UI", "was", t0, "is", t1)
		modified = true
	}
	// 比较 Gas 限制
	if g0, g1 := original.Transaction.Gas, new.Transaction.Gas; g0 != g1 {
		modified = true
		log.Info("Gas changed by UI", "was", g0, "is", g1)
	}
	// 比较 Gas 价格
	if a, b := original.Transaction.GasPrice, new.Transaction.GasPrice; intPtrModified(a, b) {
		log.Info("GasPrice changed by UI", "was", a, "is", b)
		modified = true
	}
	// 比较最大优先费
	if a, b := original.Transaction.MaxPriorityFeePerGas, new.Transaction.MaxPriorityFeePerGas; intPtrModified(a, b) {
		log.Info("maxPriorityFeePerGas changed by UI", "was", a, "is", b)
		modified = true
	}
	// 比较最大费用
	if a, b := original.Transaction.MaxFeePerGas, new.Transaction.MaxFeePerGas; intPtrModified(a, b) {
		log.Info("maxFeePerGas changed by UI", "was", a, "is", b)
		modified = true
	}
	// 比较交易金额
	if v0, v1 := big.Int(original.Transaction.Value), big.Int(new.Transaction.Value); v0.Cmp(&v1) != 0 {
		modified = true
		log.Info("Value changed by UI", "was", v0, "is", v1)
	}
	// 比较交易数据
	if d0, d1 := original.Transaction.Data, new.Transaction.Data; d0 != d1 {
		d0s := ""
		d1s := ""
		if d0 != nil {
			d0s = hexutil.Encode(*d0)
		}
		if d1 != nil {
			d1s = hexutil.Encode(*d1)
		}
		if d1s != d0s {
			modified = true
			log.Info("Data changed by UI", "was", d0s, "is", d1s)
		}
	}
	// 比较 Nonce
	if n0, n1 := original.Transaction.Nonce, new.Transaction.Nonce; n0 != n1 {
		modified = true
		log.Info("Nonce changed by UI", "was", n0, "is", n1)
	}
	return modified
}

// lookupPassword 从存储中查找指定地址的密码。
func (api *SignerAPI) lookupPassword(address common.Address) (string, error) {
	// 从凭证存储中获取密码
	return api.credentials.Get(address.Hex())
}

// lookupOrQueryPassword 查找或请求指定地址的密码。
func (api *SignerAPI) lookupOrQueryPassword(address common.Address, title, prompt string) (string, error) {
	// Look up the password and return if available
	// 首先尝试查找密码
	if pw, err := api.lookupPassword(address); err == nil {
		return pw, nil
	}
	// Password unavailable, request it from the user
	// 如果查找失败，请求用户输入密码
	pwResp, err := api.UI.OnInputRequired(UserInputRequest{title, prompt, true})
	if err != nil {
		// 记录错误，但不直接返回原始错误以避免泄露信息
		log.Warn("error obtaining password", "error", err)
		// We'll not forward the error here, in case the error contains info about the response from the UI,
		// which could leak the password if it was malformed json or something
		// 我们不会在此处转发错误，以防错误包含有关 UI 响应的信息，
		// 如果密码格式不正确，则可能会泄露密码 json 或其他内容
		return "", errors.New("internal error")
	}
	// 返回用户输入的密码
	return pwResp.Text, nil
}

// SignTransaction signs the given Transaction and returns it both as json and rlp-encoded form
// SignTransaction 对给定的交易进行签名，并以 JSON 和 RLP 编码形式返回
//
//	流程：1.验证交易 2.拒绝模式检查 3.链 ID 验证 4.构造签名请求 5.用户批准 6.记录差异 7.查找账户和钱包 8.转换为交易 9.获取密码 10.签名交易 11.编码并返回
func (api *SignerAPI) SignTransaction(ctx context.Context, args apitypes.SendTxArgs, methodSelector *string) (*ethapi.SignTransactionResult, error) {
	var (
		err    error
		result SignTxResponse
	)
	// 验证交易
	msgs, err := api.validator.ValidateTransaction(methodSelector, &args)
	if err != nil {
		return nil, err
	}
	// If we are in 'rejectMode', then reject rather than show the user warnings
	// 如果处于 'rejectMode'，则拒绝而不是向用户显示警告
	if api.rejectMode {
		if err := msgs.GetWarnings(); err != nil {
			log.Info("Signing aborted due to warnings. In order to continue despite warnings, please use the flag '--advanced'.")
			return nil, err
		}
	}
	if args.ChainID != nil {
		requestedChainId := (*big.Int)(args.ChainID)
		if api.chainID.Cmp(requestedChainId) != 0 {
			log.Error("Signing request with wrong chain id", "requested", requestedChainId, "configured", api.chainID)
			return nil, fmt.Errorf("requested chainid %d does not match the configuration of the signer",
				requestedChainId)
		}
	}
	// 构造签名请求
	req := SignTxRequest{
		Transaction: args,
		Meta:        MetadataFromContext(ctx),
		Callinfo:    msgs.Messages,
	}
	// Process approval
	// 处理批准
	result, err = api.UI.ApproveTx(&req)
	if err != nil {
		return nil, err
	}
	if !result.Approved {
		return nil, ErrRequestDenied
	}
	// Log changes made by the UI to the signing-request
	// 记录 UI 对签名请求所做的更改
	logDiff(&req, &result)
	var (
		acc    accounts.Account
		wallet accounts.Wallet
	)
	// 从 result.Transaction.From 获取账户地址。
	acc = accounts.Account{Address: result.Transaction.From.Address()}
	// 使用 api.am.Find 查找对应钱包。
	wallet, err = api.am.Find(acc)
	if err != nil {
		return nil, err
	}
	// Convert fields into a real transaction
	// 将字段转换为真实的交易
	// 调用 ToTransaction 生成未签名交易。
	unsignedTx, err := result.Transaction.ToTransaction()
	if err != nil {
		return nil, err
	}
	// Get the password for the transaction
	// 获取交易的密码
	pw, err := api.lookupOrQueryPassword(acc.Address, "Account password",
		fmt.Sprintf("Please enter the password for account %s", acc.Address.String()))
	if err != nil {
		return nil, err
	}
	// The one to sign is the one that was returned from the UI
	// 要签名的是从 UI 返回的那个
	signedTx, err := wallet.SignTxWithPassphrase(acc, pw, unsignedTx, api.chainID)
	if err != nil {
		api.UI.ShowError(err.Error())
		return nil, err
	}

	data, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	response := ethapi.SignTransactionResult{Raw: data, Tx: signedTx}

	// Finally, send the signed tx to the UI
	// 最后，将签名后的交易发送到 UI
	api.UI.OnApprovedTx(response)
	// ...and to the external caller
	// ...并发送给外部调用者
	return &response, nil
}

// SignGnosisSafeTx 签名 Gnosis Safe 多签交易并返回签名后的交易。
// 它验证交易，计算 safeTxHash，并应用签名。
// 验证并签名 Gnosis Safe 多签交易。
func (api *SignerAPI) SignGnosisSafeTx(ctx context.Context, signerAddress common.MixedcaseAddress, gnosisTx GnosisSafeTx, methodSelector *string) (*GnosisSafeTx, error) {
	// Do the usual validations, but on the last-stage transaction
	// 对最终阶段的交易进行常规验证
	args := gnosisTx.ArgsForValidation()
	msgs, err := api.validator.ValidateTransaction(methodSelector, args)
	if err != nil {
		return nil, err
	}
	// If we are in 'rejectMode', then reject rather than show the user warnings
	// 如果处于 'rejectMode' 模式，则拒绝而不是显示警告
	if api.rejectMode {
		if err := msgs.GetWarnings(); err != nil {
			log.Info("Signing aborted due to warnings. In order to continue despite warnings, please use the flag '--advanced'.")
			return nil, err
		}
	}
	// 将交易转换为类型化数据
	typedData := gnosisTx.ToTypedData()
	// might as well error early.
	// we are expected to sign. If our calculated hash does not match what they want,
	// The gnosis safetx input contains a 'safeTxHash' which is the expected safeTxHash that
	// 尽早检查错误：计算签名哈希并与期望值比较、如果计算的哈希与输入的预期哈希不匹配
	sighash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, err
	}
	// 如果计算的哈希与输入的预期哈希不匹配
	if !bytes.Equal(sighash, gnosisTx.InputExpHash.Bytes()) {
		// It might be the case that the json is missing chain id.
		// 如果缺少链 ID，则尝试补充并重新计算
		if gnosisTx.ChainId == nil {
			gnosisTx.ChainId = (*math.HexOrDecimal256)(api.chainID)
			typedData = gnosisTx.ToTypedData()
			sighash, _, _ = apitypes.TypedDataAndHash(typedData)
			if !bytes.Equal(sighash, gnosisTx.InputExpHash.Bytes()) {
				return nil, fmt.Errorf("mismatched safeTxHash; have %#x want %#x", sighash, gnosisTx.InputExpHash[:])
			}
		}
	}
	// 签名类型化数据
	signature, preimage, err := api.signTypedData(ctx, signerAddress, typedData, msgs)
	if err != nil {
		return nil, err
	}
	// 将签名者地址转换为校验和格式
	checkSummedSender, _ := common.NewMixedcaseAddressFromString(signerAddress.Address().Hex())

	gnosisTx.Signature = signature
	gnosisTx.SafeTxHash = common.BytesToHash(preimage)
	gnosisTx.Sender = *checkSummedSender // Must be checksummed to be accepted by relay 必须是校验和格式以被中继接受

	return &gnosisTx, nil
}

// Version returns the external api version. This method does not require user acceptance. Available methods are
// available via enumeration anyway, and this info does not contain user-specific data
//
// Version 返回外部 API 版本。此方法无需用户同意。可用方法无论如何都可以通过枚举获取，
// 且此信息不包含用户特定数据。
func (api *SignerAPI) Version(ctx context.Context) (string, error) {
	return ExternalAPIVersion, nil
}
