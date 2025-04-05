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

// Package accounts implements high level Ethereum account management.
package accounts

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"golang.org/x/crypto/sha3"
)

// Account represents an Ethereum account located at a specific location defined
// by the optional URL field.
// Account 代表一个以太坊账户，其位置由可选的 URL 字段定义。
type Account struct {
	Address common.Address `json:"address"` // Ethereum account address derived from the key
	// Address：以太坊账户地址，从密钥派生而来
	URL URL `json:"url"` // Optional resource locator within a backend
	// URL：可选的资源定位符，用于在后端中定位账户
}

const (
	MimetypeDataWithValidator = "data/validator"
	MimetypeTypedData         = "data/typed"
	MimetypeClique            = "application/x-clique-header"
	MimetypeTextPlain         = "text/plain"
)

// Wallet represents a software or hardware wallet that might contain one or more
// accounts (derived from the same seed).
// Wallet 代表一个软件或硬件钱包，可能包含一个或多个账户（从同一个种子派生而来）。
type Wallet interface {
	// URL retrieves the canonical path under which this wallet is reachable. It is
	// used by upper layers to define a sorting order over all wallets from multiple
	// backends.
	// URL 返回此钱包可访问的规范路径。上层使用它来定义来自多个后端的所有钱包的排序顺序。
	URL() URL

	// Status returns a textual status to aid the user in the current state of the
	// wallet. It also returns an error indicating any failure the wallet might have
	// encountered.
	// Status 返回一个文本状态，以帮助用户了解钱包的当前状态。它还会返回一个错误，指示钱包可能遇到的任何故障。
	Status() (string, error)

	// Open initializes access to a wallet instance. It is not meant to unlock or
	// decrypt account keys, rather simply to establish a connection to hardware
	// wallets and/or to access derivation seeds.
	// Open 初始化对钱包实例的访问。它不是用于解锁或解密账户密钥，而是简单地建立与硬件钱包的连接和/或访问派生种子。
	//
	// The passphrase parameter may or may not be used by the implementation of a
	// particular wallet instance. The reason there is no passwordless open method
	// is to strive towards a uniform wallet handling, oblivious to the different
	// backend providers.
	// passphrase 参数可能被特定钱包实例的实现使用，也可能不被使用。没有无密码打开方法的原因是为了实现统一的钱包处理，
	// 而不考虑不同的后端提供程序。
	//
	// Please note, if you open a wallet, you must close it to release any allocated
	// resources (especially important when working with hardware wallets).
	// 请注意，如果您打开一个钱包，您必须关闭它以释放任何已分配的资源（在使用硬件钱包时尤其重要）。
	Open(passphrase string) error

	// Close releases any resources held by an open wallet instance.
	// Close 释放已打开的钱包实例持有的任何资源。
	Close() error

	// Accounts retrieves the list of signing accounts the wallet is currently aware
	// of. For hierarchical deterministic wallets, the list will not be exhaustive,
	// rather only contain the accounts explicitly pinned during account derivation.
	// Accounts 检索钱包当前知道的签名账户列表。对于分层确定性钱包，该列表不会是详尽的，
	// 而只会包含在账户派生过程中显式固定的账户。
	Accounts() []Account

	// Contains returns whether an account is part of this particular wallet or not.
	// Contains 返回一个账户是否属于此特定钱包。
	Contains(account Account) bool

	// Derive attempts to explicitly derive a hierarchical deterministic account at
	// the specified derivation path. If requested, the derived account will be added
	// to the wallet's tracked account list.
	// Derive 尝试在指定的派生路径上显式派生一个分层确定性账户。如果请求，派生的账户将被添加到钱包的跟踪账户列表中。
	Derive(path DerivationPath, pin bool) (Account, error)

	// SelfDerive sets a base account derivation path from which the wallet attempts
	// to discover non zero accounts and automatically add them to list of tracked
	// accounts.
	// SelfDerive 设置一个基本的账户派生路径，钱包会尝试从该路径发现非零账户，并自动将其添加到跟踪账户列表中。
	//
	// Note, self derivation will increment the last component of the specified path
	// opposed to descending into a child path to allow discovering accounts starting
	// from non zero components.
	// 注意，自派生会增加指定路径的最后一个组件，而不是下降到子路径，以便发现从非零组件开始的账户。
	//
	// Some hardware wallets switched derivation paths through their evolution, so
	// this method supports providing multiple bases to discover old user accounts
	// too. Only the last base will be used to derive the next empty account.
	// 一些硬件钱包在其发展过程中切换了派生路径，因此此方法支持提供多个基础路径来发现旧的用户账户。
	// 只有最后一个基础路径将被用于派生下一个空账户。
	//
	// You can disable automatic account discovery by calling SelfDerive with a nil
	// chain state reader.
	// 您可以通过使用 nil 链状态读取器调用 SelfDerive 来禁用自动账户发现。
	SelfDerive(bases []DerivationPath, chain ethereum.ChainStateReader)

	// SignData requests the wallet to sign the hash of the given data
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	// SignData 请求钱包对给定数据的哈希进行签名。它通过包含的地址单独查找指定的账户，
	// 或者可选地借助嵌入的 URL 字段中的任何位置元数据进行查找。
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code to verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignDataWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	// 如果钱包需要额外的身份验证才能签署请求（例如，解密账户的密码或验证交易的 PIN 码），
	// 将返回一个 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。
	// 用户可以通过 SignDataWithPassphrase 提供所需的详细信息，或通过其他方式（例如，解锁密钥库中的账户）重试。
	SignData(account Account, mimeType string, data []byte) ([]byte, error)

	// SignDataWithPassphrase is identical to SignData, but also takes a password
	// SignDataWithPassphrase 与 SignData 相同，但还接受一个密码。
	// NOTE: there's a chance that an erroneous call might mistake the two strings, and
	// supply password in the mimetype field, or vice versa. Thus, an implementation
	// should never echo the mimetype or return the mimetype in the error-response
	// 注意：错误的调用可能会混淆这两个字符串，并在 mimetype 字段中提供密码，反之亦然。
	// 因此，实现不应回显 mimetype 或在错误响应中返回 mimetype。
	SignDataWithPassphrase(account Account, passphrase, mimeType string, data []byte) ([]byte, error)

	// SignText requests the wallet to sign the hash of a given piece of data, prefixed
	// by the Ethereum prefix scheme
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	// SignText 请求钱包对给定数据的哈希进行签名，并带有以太坊前缀方案的前缀。
	// 它通过包含的地址单独查找指定的账户，或者可选地借助嵌入的 URL 字段中的任何位置元数据进行查找。
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code to verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignTextWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	// 如果钱包需要额外的身份验证才能签署请求（例如，解密账户的密码或验证交易的 PIN 码），
	// 将返回一个 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。
	// 用户可以通过 SignTextWithPassphrase 提供所需的详细信息，或通过其他方式（例如，解锁密钥库中的账户）重试。
	//
	// This method should return the signature in 'canonical' format, with v 0 or 1.
	// 此方法应以“规范”格式返回签名，v 值为 0 或 1。
	SignText(account Account, text []byte) ([]byte, error)

	// SignTextWithPassphrase is identical to Signtext, but also takes a password
	// SignTextWithPassphrase 与 SignText 相同，但还接受一个密码。
	SignTextWithPassphrase(account Account, passphrase string, hash []byte) ([]byte, error)

	// SignTx requests the wallet to sign the given transaction.
	// SignTx 请求钱包对给定的交易进行签名。
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	// 它通过包含的地址单独查找指定的账户，或者可选地借助嵌入的 URL 字段中的任何位置元数据进行查找。
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code to verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignTxWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	// 如果钱包需要额外的身份验证才能签署请求（例如，解密账户的密码或验证交易的 PIN 码），
	// 将返回一个 AuthNeededError 实例，其中包含用户需要哪些字段或操作的信息。
	// 用户可以通过 SignTxWithPassphrase 提供所需的详细信息，或通过其他方式（例如，解锁密钥库中的账户）重试。
	SignTx(account Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	// SignTxWithPassphrase is identical to SignTx, but also takes a password
	// SignTxWithPassphrase 与 SignTx 相同，但还接受一个密码。
	SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

// Backend is a "wallet provider" that may contain a batch of accounts they can
// sign transactions with and upon request, do so.
// Backend 是一个“钱包提供者”，可能包含一批可以用来签署交易的账户，并且在请求时可以执行签名。
type Backend interface {
	// Wallets retrieves the list of wallets the backend is currently aware of.
	// Wallets 检索后端当前知道的钱包列表。
	//
	// The returned wallets are not opened by default. For software HD wallets this
	// means that no base seeds are decrypted, and for hardware wallets that no actual
	// connection is established.
	// 默认情况下，返回的钱包不会被打开。对于软件 HD 钱包，这意味着不会解密任何基本种子；
	// 对于硬件钱包，这意味着不会建立实际连接。
	//
	// The resulting wallet list will be sorted alphabetically based on its internal
	// URL assigned by the backend. Since wallets (especially hardware) may come and
	// go, the same wallet might appear at a different positions in the list during
	// subsequent retrievals.
	// 生成的钱包列表将根据后端分配的内部 URL 按字母顺序排序。
	// 由于钱包（尤其是硬件钱包）可能会出现和消失，因此同一个钱包在后续检索中可能会出现在列表中的不同位置。
	Wallets() []Wallet

	// Subscribe creates an async subscription to receive notifications when the
	// backend detects the arrival or departure of a wallet.
	// Subscribe 创建一个异步订阅，以便在后端检测到钱包的到来或离开时接收通知。
	Subscribe(sink chan<- WalletEvent) event.Subscription
}

// TextHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
// TextHash 是一个辅助函数，用于计算给定消息的哈希值，该哈希值可以安全地用于计算签名。
//
// The hash is calculated as
//
//	keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
// 这为签名消息提供了上下文，并防止签署交易。
func TextHash(data []byte) []byte {
	hash, _ := TextAndHash(data)
	return hash
}

// TextAndHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
// TextAndHash 是一个辅助函数，用于计算给定消息的哈希值，该哈希值可以安全地用于计算签名。
//
// The hash is calculated as
//
//	keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
// 这为签名消息提供了上下文，并防止签署交易。
func TextAndHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	return hasher.Sum(nil), msg
}

// WalletEventType represents the different event types that can be fired by
// the wallet subscription subsystem.
// WalletEventType 代表钱包订阅子系统可以触发的不同事件类型。
type WalletEventType int

const (
	// WalletArrived is fired when a new wallet is detected either via USB or via
	// a filesystem event in the keystore.
	// WalletArrived：当通过 USB 或密钥库中的文件系统事件检测到新钱包时触发。
	WalletArrived WalletEventType = iota

	// WalletOpened is fired when a wallet is successfully opened with the purpose
	// of starting any background processes such as automatic key derivation.
	// WalletOpened：当钱包成功打开并开始任何后台进程（如自动密钥派生）时触发。
	WalletOpened

	// WalletDropped is fired when a wallet is removed or disconnected, either via USB
	// or due to a filesystem event in the keystore. This event indicates that the wallet
	// is no longer available for operations.
	// WalletDropped：当钱包被移除或断开连接时触发，无论是通过 USB 还是由于密钥库中的文件系统事件。
	// 此事件表明该钱包不再可用于操作。
	WalletDropped
)

// WalletEvent is an event fired by an account backend when a wallet arrival or
// departure is detected.
// WalletEvent 是账户后端在检测到钱包的到来或离开时触发的事件。
type WalletEvent struct {
	Wallet Wallet // Wallet instance arrived or departed
	// Wallet：到达或离开的钱包实例
	Kind WalletEventType // Event type that happened in the system
	// Kind：系统中发生的事件类型
}
