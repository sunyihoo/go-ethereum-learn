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

package external

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// 外部签名器 ：
// 外部签名器（如 Clef）是独立运行的签名服务，用于保护私钥并提供签名功能。
// 交易类型 ：
// 以太坊支持多种交易类型（如传统交易、EIP-1559 动态费用交易、Blob 交易等），每种类型有不同的签名要求。
// RPC 协议 ：
// 通过 JSON-RPC 与外部签名器通信，确保灵活性和跨平台兼容性。

// ExternalBackend is a wallet backend that interacts with external signers (e.g., Clef).
// It provides an interface to manage wallets and accounts.
// ExternalBackend 是一个与外部签名器（如 Clef）交互的钱包后端。
// 它提供了一个管理钱包和账户的接口。
type ExternalBackend struct {
	signers []accounts.Wallet // 存储外部签名器的钱包列表
}

// Wallets returns the list of wallets managed by the backend.
// Wallets 返回后端管理的钱包列表。
func (eb *ExternalBackend) Wallets() []accounts.Wallet {
	return eb.signers
}

// NewExternalBackend creates a new instance of ExternalBackend connected to the given endpoint.
// NewExternalBackend 创建一个新的 ExternalBackend 实例，连接到指定的端点。
func NewExternalBackend(endpoint string) (*ExternalBackend, error) {
	// 初始化外部签名器
	signer, err := NewExternalSigner(endpoint)
	if err != nil {
		return nil, err
	}
	return &ExternalBackend{
		signers: []accounts.Wallet{signer},
	}, nil
}

// Subscribe subscribes to wallet events from the backend.
// Subscribe 订阅来自后端的钱包事件。
func (eb *ExternalBackend) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

// ExternalSigner provides an API to interact with an external signer (clef)
// It proxies request to the external signer while forwarding relevant
// request headers
// ExternalSigner 提供了一个与外部签名器（如 Clef）交互的 API。
// 它将请求代理到外部签名器，同时转发相关的请求头。
type ExternalSigner struct {
	client   *rpc.Client        // RPC 客户端，用于与外部签名器通信
	endpoint string             // 外部签名器的连接端点
	status   string             // 签名器状态信息
	cacheMu  sync.RWMutex       // 用于保护缓存的互斥锁
	cache    []accounts.Account // 缓存的账户列表
}

// NewExternalSigner creates a new instance of ExternalSigner connected to the given endpoint.
// NewExternalSigner 创建一个新的 ExternalSigner 实例，连接到指定的端点。
func NewExternalSigner(endpoint string) (*ExternalSigner, error) {
	// 建立 RPC 连接
	client, err := rpc.Dial(endpoint)
	if err != nil {
		return nil, err
	}
	extsigner := &ExternalSigner{
		client:   client,
		endpoint: endpoint,
	}
	// Check if reachable 检查是否可以访问
	version, err := extsigner.pingVersion()
	if err != nil {
		return nil, err
	}
	extsigner.status = fmt.Sprintf("ok [version=%v]", version)
	return extsigner, nil
}

// URL returns the URL of the external signer.
// URL 返回外部签名器的 URL。
func (api *ExternalSigner) URL() accounts.URL {
	return accounts.URL{
		Scheme: "extapi", // 使用 "extapi" 作为协议方案
		Path:   api.endpoint,
	}
}

// Status returns the status of the external signer.
// Status 返回外部签名器的状态。
func (api *ExternalSigner) Status() (string, error) {
	return api.status, nil
}

// Open is not supported for external signers.
// Open 对于外部签名器不支持。
func (api *ExternalSigner) Open(passphrase string) error {
	return errors.New("operation not supported on external signers")
}

// Close is not supported for external signers.
// Close 对于外部签名器不支持。
func (api *ExternalSigner) Close() error {
	return errors.New("operation not supported on external signers")
}

// Accounts returns the list of accounts managed by the external signer.
// Accounts 返回由外部签名器管理的账户列表。
func (api *ExternalSigner) Accounts() []accounts.Account {
	var accnts []accounts.Account
	res, err := api.listAccounts()
	if err != nil {
		log.Error("account listing failed", "error", err)
		return accnts
	}
	for _, addr := range res {
		accnts = append(accnts, accounts.Account{
			URL: accounts.URL{
				Scheme: "extapi",
				Path:   api.endpoint,
			},
			Address: addr,
		})
	}
	api.cacheMu.Lock()
	api.cache = accnts
	api.cacheMu.Unlock()
	return accnts
}

// Contains checks if the given account is managed by the external signer.
// Contains 检查给定账户是否由外部签名器管理。
func (api *ExternalSigner) Contains(account accounts.Account) bool {
	api.cacheMu.RLock()
	defer api.cacheMu.RUnlock()
	if api.cache == nil {
		// If we haven't already fetched the accounts, it's time to do so now 如果尚未获取账户列表，则现在获取
		api.cacheMu.RUnlock()
		api.Accounts()
		api.cacheMu.RLock()
	}
	for _, a := range api.cache {
		if a.Address == account.Address && (account.URL == (accounts.URL{}) || account.URL == api.URL()) {
			return true
		}
	}
	return false
}

// Derive is not supported for external signers.
// Derive 对于外部签名器不支持。
func (api *ExternalSigner) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
	return accounts.Account{}, errors.New("operation not supported on external signers")
}

// SelfDerive is not supported for external signers.
// SelfDerive 对于外部签名器不支持。
func (api *ExternalSigner) SelfDerive(bases []accounts.DerivationPath, chain ethereum.ChainStateReader) {
	log.Error("operation SelfDerive not supported on external signers")
}

// SignData signs keccak256(data). The mimetype parameter describes the type of data being signed.
// SignData 签名 keccak256(data)。mimetype 参数描述了被签名数据的类型。
func (api *ExternalSigner) SignData(account accounts.Account, mimeType string, data []byte) ([]byte, error) {
	var res hexutil.Bytes
	var signAddress = common.NewMixedcaseAddress(account.Address)
	if err := api.client.Call(&res, "account_signData",
		mimeType,
		&signAddress, // Need to use the pointer here, because of how MarshalJSON is defined 需要使用指针，因为 MarshalJSON 的定义
		hexutil.Encode(data)); err != nil {
		return nil, err
	}
	// If V is on 27/28-form, convert to 0/1 for Clique 如果 V 是 27/28 形式，转换为 Clique 使用的 0/1
	if mimeType == accounts.MimetypeClique && (res[64] == 27 || res[64] == 28) {
		res[64] -= 27 // Transform V from 27/28 to 0/1 for Clique use 将 V 从 27/28 转换为 0/1 以供 Clique 使用
	}
	return res, nil
}

// SignText signs plain text. The text is encoded as UTF-8 before signing.
// SignText 签名纯文本。文本在签名前被编码为 UTF-8。
func (api *ExternalSigner) SignText(account accounts.Account, text []byte) ([]byte, error) {
	var signature hexutil.Bytes
	var signAddress = common.NewMixedcaseAddress(account.Address)
	if err := api.client.Call(&signature, "account_signData",
		accounts.MimetypeTextPlain,
		&signAddress, // Need to use the pointer here, because of how MarshalJSON is defined 需要使用指针，因为 MarshalJSON 的定义
		hexutil.Encode(text)); err != nil {
		return nil, err
	}
	if signature[64] == 27 || signature[64] == 28 {
		// If clef is used as a backend, it may already have transformed
		// the signature to ethereum-type signature.
		// 如果 Clef 作为后端，可能已经将签名转换为以太坊类型的签名
		signature[64] -= 27 // Transform V from Ethereum-legacy to 0/1 将 V 从以太坊旧格式转换为 0/1
	}
	return signature, nil
}

// signTransactionResult represents the signing result returned by clef.
// signTransactionResult 表示由 Clef 返回的签名结果。
type signTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"` // 原始签名交易数据
	Tx  *types.Transaction `json:"tx"`  // 解码后的交易对象
}

// SignTx sends the transaction to the external signer.
// If chainID is nil, or tx.ChainID is zero, the chain ID will be assigned
// by the external signer. For non-legacy transactions, the chain ID of the
// transaction overrides the chainID parameter.
// SignTx 将交易发送到外部签名器进行签名。
// 如果 chainID 为 nil 或 tx.ChainID 为零，链 ID 将由外部签名器分配。
// 对于非传统交易，交易的链 ID 会覆盖 chainID 参数。
func (api *ExternalSigner) SignTx(account accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	data := hexutil.Bytes(tx.Data())
	var to *common.MixedcaseAddress
	if tx.To() != nil {
		t := common.NewMixedcaseAddress(*tx.To())
		to = &t
	}
	args := &apitypes.SendTxArgs{
		Input: &data,
		Nonce: hexutil.Uint64(tx.Nonce()),
		Value: hexutil.Big(*tx.Value()),
		Gas:   hexutil.Uint64(tx.Gas()),
		To:    to,
		From:  common.NewMixedcaseAddress(account.Address),
	}
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType:
		args.GasPrice = (*hexutil.Big)(tx.GasPrice())
	case types.DynamicFeeTxType, types.BlobTxType, types.SetCodeTxType:
		args.MaxFeePerGas = (*hexutil.Big)(tx.GasFeeCap())
		args.MaxPriorityFeePerGas = (*hexutil.Big)(tx.GasTipCap())
	default:
		return nil, fmt.Errorf("unsupported tx type %d", tx.Type())
	}
	// We should request the default chain id that we're operating with
	// (the chain we're executing on)
	// 我们应该请求默认的链 ID（即我们正在运行的链）
	if chainID != nil && chainID.Sign() != 0 {
		args.ChainID = (*hexutil.Big)(chainID)
	}
	if tx.Type() != types.LegacyTxType {
		// However, if the user asked for a particular chain id, then we should
		// use that instead.
		// 然而，如果用户请求特定的链 ID，则应使用它
		if tx.ChainId().Sign() != 0 {
			args.ChainID = (*hexutil.Big)(tx.ChainId())
		}
		accessList := tx.AccessList()
		args.AccessList = &accessList
	}
	if tx.Type() == types.BlobTxType {
		args.BlobHashes = tx.BlobHashes()
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			return nil, errors.New("blobs must be present for signing")
		}
		args.Blobs = sidecar.Blobs
		args.Commitments = sidecar.Commitments
		args.Proofs = sidecar.Proofs
	}

	var res signTransactionResult
	if err := api.client.Call(&res, "account_signTransaction", args); err != nil {
		return nil, err
	}
	return res.Tx, nil
}

// SignTextWithPassphrase is not supported for external signers.
// SignTextWithPassphrase 对于外部签名器不支持。
func (api *ExternalSigner) SignTextWithPassphrase(account accounts.Account, passphrase string, text []byte) ([]byte, error) {
	return []byte{}, errors.New("password-operations not supported on external signers")
}

// SignTxWithPassphrase is not supported for external signers.
// SignTxWithPassphrase 对于外部签名器不支持。
func (api *ExternalSigner) SignTxWithPassphrase(account accounts.Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	return nil, errors.New("password-operations not supported on external signers")
}

// SignDataWithPassphrase is not supported for external signers.
// SignDataWithPassphrase 对于外部签名器不支持。
func (api *ExternalSigner) SignDataWithPassphrase(account accounts.Account, passphrase, mimeType string, data []byte) ([]byte, error) {
	return nil, errors.New("password-operations not supported on external signers")
}

// listAccounts retrieves the list of accounts from the external signer.
// listAccounts 从外部签名器检索账户列表。
func (api *ExternalSigner) listAccounts() ([]common.Address, error) {
	var res []common.Address
	if err := api.client.Call(&res, "account_list"); err != nil {
		return nil, err
	}
	return res, nil
}

// pingVersion checks the version of the external signer.
// pingVersion 检查外部签名器的版本。
func (api *ExternalSigner) pingVersion() (string, error) {
	var v string
	if err := api.client.Call(&v, "account_version"); err != nil {
		return "", err
	}
	return v, nil
}
