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

// This file contains the implementation for interacting with the Ledger hardware
// wallets. The wire protocol spec can be found in the Ledger Blue GitHub repo:
// https://github.com/LedgerHQ/app-ethereum/blob/develop/doc/ethapp.adoc

package usbwallet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)

// ledgerOpcode is an enumeration encoding the supported Ledger opcodes.
// ledgerOpcode 是一个枚举类型，编码了 Ledger 支持的操作码。
type ledgerOpcode byte

// ledgerParam1 is an enumeration encoding the supported Ledger parameters for
// specific opcodes. The same parameter values may be reused between opcodes.
// ledgerParam1 是一个枚举类型，编码了特定操作码支持的 Ledger 参数。同一参数值可在不同操作码间重用。
type ledgerParam1 byte

// ledgerParam2 is an enumeration encoding the supported Ledger parameters for
// specific opcodes. The same parameter values may be reused between opcodes.
// ledgerParam2 是一个枚举类型，编码了特定操作码支持的 Ledger 参数。同一参数值可在不同操作码间重用。
type ledgerParam2 byte

const (
	ledgerOpRetrieveAddress ledgerOpcode = 0x02 // Returns the public key and Ethereum address for a given BIP 32 path
	// 返回给定 BIP 32 路径的公钥和以太坊地址
	ledgerOpSignTransaction ledgerOpcode = 0x04 // Signs an Ethereum transaction after having the user validate the parameters
	// 在用户验证参数后签署以太坊交易
	ledgerOpGetConfiguration ledgerOpcode = 0x06 // Returns specific wallet application configuration
	// 返回特定的钱包应用程序配置
	ledgerOpSignTypedMessage ledgerOpcode = 0x0c // Signs an Ethereum message following the EIP 712 specification
	// 按照 EIP-712 规范签署以太坊消息

	ledgerP1DirectlyFetchAddress ledgerParam1 = 0x00 // Return address directly from the wallet
	// 直接从钱包返回地址
	ledgerP1InitTypedMessageData ledgerParam1 = 0x00 // First chunk of Typed Message data
	// 类型化消息数据的第一个块
	ledgerP1InitTransactionData ledgerParam1 = 0x00 // First transaction data block for signing
	// 用于签名的第一个交易数据块
	ledgerP1ContTransactionData ledgerParam1 = 0x80 // Subsequent transaction data block for signing
	// 用于签名的后续交易数据块
	ledgerP2DiscardAddressChainCode ledgerParam2 = 0x00 // Do not return the chain code along with the address
	// 不随地址返回链码

	ledgerEip155Size int = 3 // Size of the EIP-155 chain_id,r,s in unsigned transactions
	// 未签名交易中 EIP-155 的 chain_id、r、s 的大小
)

// errLedgerReplyInvalidHeader is the error message returned by a Ledger data exchange
// if the device replies with a mismatching header. This usually means the device
// is in browser mode.
// errLedgerReplyInvalidHeader 是 Ledger 数据交换返回的错误消息，
// 如果设备回复的头部不匹配。通常意味着设备处于浏览器模式。
var errLedgerReplyInvalidHeader = errors.New("ledger: invalid reply header")

// errLedgerInvalidVersionReply is the error message returned by a Ledger version retrieval
// when a response does arrive, but it does not contain the expected data.
// errLedgerInvalidVersionReply 是 Ledger 版本检索返回的错误消息，
// 当收到响应但不包含预期数据时返回。
var errLedgerInvalidVersionReply = errors.New("ledger: invalid version reply")

// ledgerDriver implements the communication with a Ledger hardware wallet.
// ledgerDriver 实现了与 Ledger 硬件钱包的通信。
type ledgerDriver struct {
	device io.ReadWriter // USB device connection to communicate through
	// 通过 USB 设备连接进行通信
	version [3]byte // Current version of the Ledger firmware (zero if app is offline)
	// Ledger 固件的当前版本（如果应用程序离线则为零）
	browser bool // Flag whether the Ledger is in browser mode (reply channel mismatch)
	// 标记 Ledger 是否处于浏览器模式（回复通道不匹配）
	failure error // Any failure that would make the device unusable
	// 任何使设备不可用的故障
	log log.Logger // Contextual logger to tag the ledger with its id
	// 带有 ID 标记的上下文日志记录器
}

// newLedgerDriver creates a new instance of a Ledger USB protocol driver.
// newLedgerDriver 创建一个新的 Ledger USB 协议驱动实例。
func newLedgerDriver(logger log.Logger) driver {
	return &ledgerDriver{
		log: logger,
	}
}

// Status implements usbwallet.driver, returning various states the Ledger can
// currently be in.
// Status 实现了 usbwallet.driver，返回 Ledger 当前可能处于的各种状态。
func (w *ledgerDriver) Status() (string, error) {
	if w.failure != nil {
		return fmt.Sprintf("Failed: %v", w.failure), w.failure
	}
	if w.browser {
		return "Ethereum app in browser mode", w.failure
	}
	if w.offline() {
		return "Ethereum app offline", w.failure
	}
	return fmt.Sprintf("Ethereum app v%d.%d.%d online", w.version[0], w.version[1], w.version[2]), w.failure
}

// offline returns whether the wallet and the Ethereum app is offline or not.
//
// The method assumes that the state lock is held!
// offline 返回钱包和以太坊应用程序是否离线。
//
// 该方法假定状态锁已被持有！
func (w *ledgerDriver) offline() bool {
	return w.version == [3]byte{0, 0, 0}
}

// Open implements usbwallet.driver, attempting to initialize the connection to the
// Ledger hardware wallet. The Ledger does not require a user passphrase, so that
// parameter is silently discarded.
// Open 实现了 usbwallet.driver，尝试初始化与 Ledger 硬件钱包的连接。
// Ledger 不需要用户密码，因此该参数被默默丢弃。
func (w *ledgerDriver) Open(device io.ReadWriter, passphrase string) error {
	w.device, w.failure = device, nil

	_, err := w.ledgerDerive(accounts.DefaultBaseDerivationPath)
	if err != nil {
		// Ethereum app is not running or in browser mode, nothing more to do, return
		// 以太坊应用程序未运行或处于浏览器模式，无需进一步操作，返回
		if err == errLedgerReplyInvalidHeader {
			w.browser = true
		}
		return nil
	}
	// Try to resolve the Ethereum app's version, will fail prior to v1.0.2
	// 尝试解析以太坊应用程序的版本，在 v1.0.2 之前会失败
	if w.version, err = w.ledgerVersion(); err != nil {
		w.version = [3]byte{1, 0, 0} // Assume worst case, can't verify if v1.0.0 or v1.0.1
		// 假设最坏情况，无法验证是 v1.0.0 还是 v1.0.1
	}
	return nil
}

// Close implements usbwallet.driver, cleaning up and metadata maintained within
// the Ledger driver.
// Close 实现了 usbwallet.driver，清理 Ledger 驱动程序内维护的元数据。
func (w *ledgerDriver) Close() error {
	w.browser, w.version = false, [3]byte{}
	return nil
}

// Heartbeat implements usbwallet.driver, performing a sanity check against the
// Ledger to see if it's still online.
// Heartbeat 实现了 usbwallet.driver，对 Ledger 执行健康检查以查看其是否仍在线。
func (w *ledgerDriver) Heartbeat() error {
	if _, err := w.ledgerVersion(); err != nil && err != errLedgerInvalidVersionReply {
		w.failure = err
		return err
	}
	return nil
}

// Derive implements usbwallet.driver, sending a derivation request to the Ledger
// and returning the Ethereum address located on that derivation path.
// Derive 实现了 usbwallet.driver，向 Ledger 发送派生请求并返回该派生路径上的以太坊地址。
func (w *ledgerDriver) Derive(path accounts.DerivationPath) (common.Address, error) {
	return w.ledgerDerive(path)
}

// SignTx implements usbwallet.driver, sending the transaction to the Ledger and
// waiting for the user to confirm or deny the transaction.
//
// Note, if the version of the Ethereum application running on the Ledger wallet is
// too old to sign EIP-155 transactions, but such is requested nonetheless, an error
// will be returned opposed to silently signing in Homestead mode.
// SignTx 实现了 usbwallet.driver，将交易发送到 Ledger 并等待用户确认或拒绝交易。
//
// 注意，如果 Ledger 钱包上运行的以太坊应用程序版本太旧，无法签署 EIP-155 交易，
// 但仍然请求这样做，将返回错误，而不是在 Homestead 模式下默默签名。
func (w *ledgerDriver) SignTx(path accounts.DerivationPath, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	// If the Ethereum app doesn't run, abort
	// 如果以太坊应用程序未运行，则中止
	if w.offline() {
		return common.Address{}, nil, accounts.ErrWalletClosed
	}
	// Ensure the wallet is capable of signing the given transaction
	// 确保钱包能够签署给定的交易
	if chainID != nil && w.version[0] <= 1 && w.version[1] <= 0 && w.version[2] <= 2 {
		//lint:ignore ST1005 brand name displayed on the console
		return common.Address{}, nil, fmt.Errorf("Ledger v%d.%d.%d doesn't support signing this transaction, please update to v1.0.3 at least", w.version[0], w.version[1], w.version[2])
	}
	// All infos gathered and metadata checks out, request signing
	// 所有信息已收集且元数据检查通过，请求签名
	return w.ledgerSign(path, tx, chainID)
}

// SignTypedMessage implements usbwallet.driver, sending the message to the Ledger and
// waiting for the user to sign or deny the transaction.
//
// Note: this was introduced in the ledger 1.5.0 firmware
// SignTypedMessage 实现了 usbwallet.driver，将消息发送到 Ledger 并等待用户签名或拒绝交易。
//
// 注意：此功能在 Ledger 1.5.0 固件中引入
func (w *ledgerDriver) SignTypedMessage(path accounts.DerivationPath, domainHash []byte, messageHash []byte) ([]byte, error) {
	// If the Ethereum app doesn't run, abort
	// 如果以太坊应用程序未运行，则中止
	if w.offline() {
		return nil, accounts.ErrWalletClosed
	}
	// Ensure the wallet is capable of signing the given transaction
	// 确保钱包能够签署给定的交易
	if w.version[0] < 1 && w.version[1] < 5 {
		//lint:ignore ST1005 brand name displayed on the console
		return nil, fmt.Errorf("Ledger version >= 1.5.0 required for EIP-712 signing (found version v%d.%d.%d)", w.version[0], w.version[1], w.version[2])
	}
	// All infos gathered and metadata checks out, request signing
	// 所有信息已收集且元数据检查通过，请求签名
	return w.ledgerSignTypedMessage(path, domainHash, messageHash)
}

// ledgerVersion retrieves the current version of the Ethereum wallet app running
// on the Ledger wallet.
//
// The version retrieval protocol is defined as follows:
//
//	CLA | INS | P1 | P2 | Lc | Le
//	----+-----+----+----+----+---
//	 E0 | 06  | 00 | 00 | 00 | 04
//
// With no input data, and the output data being:
//
//	Description                                        | Length
//	---------------------------------------------------+--------
//	Flags 01: arbitrary data signature enabled by user | 1 byte
//	Application major version                          | 1 byte
//	Application minor version                          | 1 byte
//	Application patch version                          | 1 byte
//
// ledgerVersion 检索运行在 Ledger 钱包上的以太坊钱包应用程序的当前版本。
//
// 版本检索协议定义如下：
//
//	CLA | INS | P1 | P2 | Lc | Le
//	----+-----+----+----+----+---
//	 E0 | 06  | 00 | 00 | 00 | 04
//
// 无输入数据，输出数据为：
//
//	描述                                               | 长度
//	---------------------------------------------------+--------
//	标志 01：用户启用的任意数据签名                   | 1 字节
//	应用程序主版本                                    | 1 字节
//	应用程序次版本                                    | 1 字节
//	应用程序补丁版本                                  | 1 字节
func (w *ledgerDriver) ledgerVersion() ([3]byte, error) {
	// Send the request and wait for the response
	// 发送请求并等待响应
	reply, err := w.ledgerExchange(ledgerOpGetConfiguration, 0, 0, nil)
	if err != nil {
		return [3]byte{}, err
	}
	if len(reply) != 4 {
		return [3]byte{}, errLedgerInvalidVersionReply
	}
	// Cache the version for future reference
	// 缓存版本以供将来参考
	var version [3]byte
	copy(version[:], reply[1:])
	return version, nil
}

// ledgerDerive retrieves the currently active Ethereum address from a Ledger
// wallet at the specified derivation path.
//
// The address derivation protocol is defined as follows:
//
//	CLA | INS | P1 | P2 | Lc  | Le
//	----+-----+----+----+-----+---
//	 E0 | 02  | 00 return address
//	            01 display address and confirm before returning
//	               | 00: do not return the chain code
//	               | 01: return the chain code
//	                    | var | 00
//
// Where the input data is:
//
//	Description                                      | Length
//	-------------------------------------------------+--------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	First derivation index (big endian)              | 4 bytes
//	...                                              | 4 bytes
//	Last derivation index (big endian)               | 4 bytes
//
// And the output data is:
//
//	Description             | Length
//	------------------------+-------------------
//	Public Key length       | 1 byte
//	Uncompressed Public Key | arbitrary
//	Ethereum address length | 1 byte
//	Ethereum address        | 40 bytes hex ascii
//	Chain code if requested | 32 bytes
//
// ledgerDerive 从 Ledger 钱包中检索指定派生路径上的当前活跃以太坊地址。
//
// 地址派生协议定义如下：
//
//	CLA | INS | P1 | P2 | Lc  | Le
//	----+-----+----+----+-----+---
//	 E0 | 02  | 00 返回地址
//	            01 显示地址并在返回前确认
//	               | 00：不返回链码
//	               | 01：返回链码
//	                    | 可变 | 00
//
// 输入数据为：
//
//	描述                                             | 长度
//	-------------------------------------------------+--------
//	要执行的 BIP 32 派生次数（最多 10 次）          | 1 字节
//	第一个派生索引（大端序）                        | 4 字节
//	...                                              | 4 字节
//	最后一个派生索引（大端序）                      | 4 字节
//
// 输出数据为：
//
//	描述                    | 长度
//	------------------------+-------------------
//	公钥长度                | 1 字节
//	未压缩公钥              | 可变
//	以太坊地址长度          | 1 字节
//	以太坊地址              | 40 字节十六进制 ASCII
//	请求时的链码            | 32 字节
func (w *ledgerDriver) ledgerDerive(derivationPath []uint32) (common.Address, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径展平为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Send the request and wait for the response
	// 发送请求并等待响应
	reply, err := w.ledgerExchange(ledgerOpRetrieveAddress, ledgerP1DirectlyFetchAddress, ledgerP2DiscardAddressChainCode, path)
	if err != nil {
		return common.Address{}, err
	}
	// Discard the public key, we don't need that for now
	// 丢弃公钥，我们暂时不需要它
	if len(reply) < 1 || len(reply) < 1+int(reply[0]) {
		return common.Address{}, errors.New("reply lacks public key entry")
	}
	reply = reply[1+int(reply[0]):]

	// Extract the Ethereum hex address string
	// 提取以太坊十六进制地址字符串
	if len(reply) < 1 || len(reply) < 1+int(reply[0]) {
		return common.Address{}, errors.New("reply lacks address entry")
	}
	hexstr := reply[1 : 1+int(reply[0])]

	// Decode the hex string into an Ethereum address and return
	// 将十六进制字符串解码为以太坊地址并返回
	var address common.Address
	if _, err = hex.Decode(address[:], hexstr); err != nil {
		return common.Address{}, err
	}
	return address, nil
}

// ledgerSign sends the transaction to the Ledger wallet, and waits for the user
// to confirm or deny the transaction.
//
// The transaction signing protocol is defined as follows:
//
//	CLA | INS | P1 | P2 | Lc  | Le
//	----+-----+----+----+-----+---
//	 E0 | 04  | 00: first transaction data block
//	            80: subsequent transaction data block
//	               | 00 | variable | variable
//
// Where the input for the first transaction block (first 255 bytes) is:
//
//	Description                                      | Length
//	-------------------------------------------------+----------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	First derivation index (big endian)              | 4 bytes
//	...                                              | 4 bytes
//	Last derivation index (big endian)               | 4 bytes
//	RLP transaction chunk                            | arbitrary
//
// And the input for subsequent transaction blocks (first 255 bytes) are:
//
//	Description           | Length
//	----------------------+----------
//	RLP transaction chunk | arbitrary
//
// And the output data is:
//
//	Description | Length
//	------------+---------
//	signature V | 1 byte
//	signature R | 32 bytes
//	signature S | 32 bytes
//
// ledgerSign 将交易发送到 Ledger 钱包，并等待用户确认或拒绝交易。
//
// 交易签名协议定义如下：
//
//	CLA | INS | P1 | P2 | Lc  | Le
//	----+-----+----+----+-----+---
//	 E0 | 04  | 00：第一个交易数据块
//	            80：后续交易数据块
//	               | 00 | 可变 | 可变
//
// 第一个交易块（前 255 字节）的输入为：
//
//	描述                                             | 长度
//	-------------------------------------------------+----------
//	要执行的 BIP 32 派生次数（最多 10 次）          | 1 字节
//	第一个派生索引（大端序）                        | 4 字节
//	...                                              | 4 字节
//	最后一个派生索引（大端序）                      | 4 字节
//	RLP 交易块                                      | 可变
//
// 后续交易块（前 255 字节）的输入为：
//
//	描述                   | 长度
//	----------------------+----------
//	RLP 交易块            | 可变
//
// 输出数据为：
//
//	描述         | 长度
//	------------+---------
//	签名 V       | 1 字节
//	签名 R       | 32 字节
//	签名 S       | 32 字节
func (w *ledgerDriver) ledgerSign(derivationPath []uint32, tx *types.Transaction, chainID *big.Int) (common.Address, *types.Transaction, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径展平为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Create the transaction RLP based on whether legacy or EIP155 signing was requested
	// 根据是否请求传统或 EIP-155 签名创建交易 RLP
	var (
		txrlp []byte
		err   error
	)
	if chainID == nil {
		if txrlp, err = rlp.EncodeToBytes([]interface{}{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data()}); err != nil {
			return common.Address{}, nil, err
		}
	} else {
		if tx.Type() == types.DynamicFeeTxType {
			if txrlp, err = rlp.EncodeToBytes([]interface{}{chainID, tx.Nonce(), tx.GasTipCap(), tx.GasFeeCap(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList()}); err != nil {
				return common.Address{}, nil, err
			}
			// append type to transaction
			// 将类型附加到交易
			txrlp = append([]byte{tx.Type()}, txrlp...)
		} else if tx.Type() == types.AccessListTxType {
			if txrlp, err = rlp.EncodeToBytes([]interface{}{chainID, tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), tx.AccessList()}); err != nil {
				return common.Address{}, nil, err
			}
			// append type to transaction
			// 将类型附加到交易
			txrlp = append([]byte{tx.Type()}, txrlp...)
		} else if tx.Type() == types.LegacyTxType {
			if txrlp, err = rlp.EncodeToBytes([]interface{}{tx.Nonce(), tx.GasPrice(), tx.Gas(), tx.To(), tx.Value(), tx.Data(), chainID, big.NewInt(0), big.NewInt(0)}); err != nil {
				return common.Address{}, nil, err
			}
		}
	}
	payload := append(path, txrlp...)

	// Send the request and wait for the response
	// 发送请求并等待响应
	var (
		op    = ledgerP1InitTransactionData
		reply []byte
	)

	// Chunk size selection to mitigate an underlying RLP deserialization issue on the ledger app.
	// https://github.com/LedgerHQ/app-ethereum/issues/409
	// 选择块大小以缓解 Ledger 应用程序中的底层 RLP 反序列化问题。
	// https://github.com/LedgerHQ/app-ethereum/issues/409
	chunk := 255
	if tx.Type() == types.LegacyTxType {
		for ; len(payload)%chunk <= ledgerEip155Size; chunk-- {
		}
	}

	for len(payload) > 0 {
		// Calculate the size of the next data chunk
		// 计算下一个数据块的大小
		if chunk > len(payload) {
			chunk = len(payload)
		}
		// Send the chunk over, ensuring it's processed correctly
		// 发送数据块，确保正确处理
		reply, err = w.ledgerExchange(ledgerOpSignTransaction, op, 0, payload[:chunk])
		if err != nil {
			return common.Address{}, nil, err
		}
		// Shift the payload and ensure subsequent chunks are marked as such
		// 移动负载并确保后续块被标记为后续块
		payload = payload[chunk:]
		op = ledgerP1ContTransactionData
	}
	// Extract the Ethereum signature and do a sanity validation
	// 提取以太坊签名并进行合理性验证
	if len(reply) != crypto.SignatureLength {
		return common.Address{}, nil, errors.New("reply lacks signature")
	}
	signature := append(reply[1:], reply[0])

	// Create the correct signer and signature transform based on the chain ID
	// 根据链 ID 创建正确的签名者和签名转换
	var signer types.Signer
	if chainID == nil {
		signer = new(types.HomesteadSigner)
	} else {
		signer = types.LatestSignerForChainID(chainID)
		// For non-legacy transactions, V is 0 or 1, no need to subtract here.
		// 对于非传统交易，V 为 0 或 1，此处无需减去。
		if tx.Type() == types.LegacyTxType {
			signature[64] -= byte(chainID.Uint64()*2 + 35)
		}
	}
	signed, err := tx.WithSignature(signer, signature)
	if err != nil {
		return common.Address{}, nil, err
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return common.Address{}, nil, err
	}
	return sender, signed, nil
}

// ledgerSignTypedMessage sends the transaction to the Ledger wallet, and waits for the user
// to confirm or deny the transaction.
//
// The signing protocol is defined as follows:
//
//	CLA | INS | P1 | P2                          | Lc  | Le
//	----+-----+----+-----------------------------+-----+---
//	 E0 | 0C  | 00 | implementation version : 00 | variable | variable
//
// Where the input is:
//
//	Description                                      | Length
//	-------------------------------------------------+----------
//	Number of BIP 32 derivations to perform (max 10) | 1 byte
//	First derivation index (big endian)              | 4 bytes
//	...                                              | 4 bytes
//	Last derivation index (big endian)               | 4 bytes
//	domain hash                                      | 32 bytes
//	message hash                                     | 32 bytes
//
// And the output data is:
//
//	Description | Length
//	------------+---------
//	signature V | 1 byte
//	signature R | 32 bytes
//	signature S | 32 bytes
//
// ledgerSignTypedMessage 将交易发送到 Ledger 钱包，并等待用户确认或拒绝交易。
//
// 签名协议定义如下：
//
//	CLA | INS | P1 | P2                          | Lc  | Le
//	----+-----+----+-----------------------------+-----+---
//	 E0 | 0C  | 00 | 实现版本：00                | 可变 | 可变
//
// 输入为：
//
//	描述                                             | 长度
//	-------------------------------------------------+----------
//	要执行的 BIP 32 派生次数（最多 10 次）          | 1 字节
//	第一个派生索引（大端序）                        | 4 字节
//	...                                              | 4 字节
//	最后一个派生索引（大端序）                      | 4 字节
//	域哈希                                          | 32 字节
//	消息哈希                                        | 32 字节
//
// 输出数据为：
//
//	描述         | 长度
//	------------+---------
//	签名 V       | 1 字节
//	签名 R       | 32 字节
//	签名 S       | 32 字节
func (w *ledgerDriver) ledgerSignTypedMessage(derivationPath []uint32, domainHash []byte, messageHash []byte) ([]byte, error) {
	// Flatten the derivation path into the Ledger request
	// 将派生路径展平为 Ledger 请求
	path := make([]byte, 1+4*len(derivationPath))
	path[0] = byte(len(derivationPath))
	for i, component := range derivationPath {
		binary.BigEndian.PutUint32(path[1+4*i:], component)
	}
	// Create the 712 message
	// 创建 EIP-712 消息
	payload := append(path, domainHash...)
	payload = append(payload, messageHash...)

	// Send the request and wait for the response
	// 发送请求并等待响应
	var (
		op    = ledgerP1InitTypedMessageData
		reply []byte
		err   error
	)

	// Send the message over, ensuring it's processed correctly
	// 发送消息，确保正确处理
	reply, err = w.ledgerExchange(ledgerOpSignTypedMessage, op, 0, payload)

	if err != nil {
		return nil, err
	}

	// Extract the Ethereum signature and do a sanity validation
	// 提取以太坊签名并进行合理性验证
	if len(reply) != crypto.SignatureLength {
		return nil, errors.New("reply lacks signature")
	}
	signature := append(reply[1:], reply[0])
	return signature, nil
}

// ledgerExchange performs a data exchange with the Ledger wallet, sending it a
// message and retrieving the response.
//
// The common transport header is defined as follows:
//
//	Description                           | Length
//	--------------------------------------+----------
//	Communication channel ID (big endian) | 2 bytes
//	Command tag                           | 1 byte
//	Packet sequence index (big endian)    | 2 bytes
//	Payload                               | arbitrary
//
// The Communication channel ID allows commands multiplexing over the same
// physical link. It is not used for the time being, and should be set to 0101
// to avoid compatibility issues with implementations ignoring a leading 00 byte.
//
// The Command tag describes the message content. Use TAG_APDU (0x05) for standard
// APDU payloads, or TAG_PING (0x02) for a simple link test.
//
// The Packet sequence index describes the current sequence for fragmented payloads.
// The first fragment index is 0x00.
//
// APDU Command payloads are encoded as follows:
//
//	Description              | Length
//	-----------------------------------
//	APDU length (big endian) | 2 bytes
//	APDU CLA                 | 1 byte
//	APDU INS                 | 1 byte
//	APDU P1                  | 1 byte
//	APDU P2                  | 1 byte
//	APDU length              | 1 byte
//	Optional APDU data       | arbitrary
//
// ledgerExchange 与 Ledger 钱包执行数据交换，向其发送消息并检索响应。
//
// 通用传输头部定义如下：
//
//	描述                                  | 长度
//	--------------------------------------+----------
//	通信通道 ID（大端序）                | 2 字节
//	命令标签                             | 1 字节
//	数据包序列索引（大端序）             | 2 字节
//	负载                                 | 可变
//
// 通信通道 ID 允许在同一物理链接上多路复用命令。目前未使用，应设置为 0101，
// 以避免与忽略前导 00 字节的实现产生兼容性问题。
//
// 命令标签描述消息内容。使用 TAG_APDU (0x05) 表示标准 APDU 负载，
// 或 TAG_PING (0x02) 表示简单链接测试。
//
// 数据包序列索引描述分段负载的当前序列。第一个分段索引为 0x00。
//
// APDU 命令负载编码如下：
//
//	描述                     | 长度
//	-----------------------------------
//	APDU 长度（大端序）     | 2 字节
//	APDU CLA                | 1 字节
//	APDU INS                | 1 字节
//	APDU P1                 | 1 字节
//	APDU P2                 | 1 字节
//	APDU 长度               | 1 字节
//	可选 APDU 数据          | 可变
func (w *ledgerDriver) ledgerExchange(opcode ledgerOpcode, p1 ledgerParam1, p2 ledgerParam2, data []byte) ([]byte, error) {
	// Construct the message payload, possibly split into multiple chunks
	// 构造消息负载，可能会分成多个块
	apdu := make([]byte, 2, 7+len(data))

	binary.BigEndian.PutUint16(apdu, uint16(5+len(data)))
	apdu = append(apdu, []byte{0xe0, byte(opcode), byte(p1), byte(p2), byte(len(data))}...)
	apdu = append(apdu, data...)

	// Stream all the chunks to the device
	// 将所有块流式传输到设备
	header := []byte{0x01, 0x01, 0x05, 0x00, 0x00} // Channel ID and command tag appended
	// 通道 ID 和命令标签已附加
	chunk := make([]byte, 64)
	space := len(chunk) - len(header)

	for i := 0; len(apdu) > 0; i++ {
		// Construct the new message to stream
		// 构造要流式传输的新消息
		chunk = append(chunk[:0], header...)
		binary.BigEndian.PutUint16(chunk[3:], uint16(i))

		if len(apdu) > space {
			chunk = append(chunk, apdu[:space]...)
			apdu = apdu[space:]
		} else {
			chunk = append(chunk, apdu...)
			apdu = nil
		}
		// Send over to the device
		// 发送到设备
		w.log.Trace("Data chunk sent to the Ledger", "chunk", hexutil.Bytes(chunk))
		if _, err := w.device.Write(chunk); err != nil {
			return nil, err
		}
	}
	// Stream the reply back from the wallet in 64 byte chunks
	// 以 64 字节块从钱包流式传输回复
	var reply []byte
	chunk = chunk[:64] // Yeah, we surely have enough space
	// 是的，我们肯定有足够的空间
	for {
		// Read the next chunk from the Ledger wallet
		// 从 Ledger 钱包读取下一个块
		if _, err := io.ReadFull(w.device, chunk); err != nil {
			return nil, err
		}
		w.log.Trace("Data chunk received from the Ledger", "chunk", hexutil.Bytes(chunk))

		// Make sure the transport header matches
		// 确保传输头部匹配
		if chunk[0] != 0x01 || chunk[1] != 0x01 || chunk[2] != 0x05 {
			return nil, errLedgerReplyInvalidHeader
		}
		// If it's the first chunk, retrieve the total message length
		// 如果是第一个块，检索总消息长度
		var payload []byte

		if chunk[3] == 0x00 && chunk[4] == 0x00 {
			reply = make([]byte, 0, int(binary.BigEndian.Uint16(chunk[5:7])))
			payload = chunk[7:]
		} else {
			payload = chunk[5:]
		}
		// Append to the reply and stop when filled up
		// 追加到回复并在填满时停止
		if left := cap(reply) - len(reply); left > len(payload) {
			reply = append(reply, payload...)
		} else {
			reply = append(reply, payload[:left]...)
			break
		}
	}
	return reply[:len(reply)-2], nil
}
