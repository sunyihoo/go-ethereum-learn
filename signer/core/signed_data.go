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
	"mime"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// sign receives a request and produces a signature
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons, if legacyV==true.
//
// sign 接收一个请求并生成签名
//
// 注意，生成的签名符合 secp256k1 曲线的 R、S 和 V 值，
// 其中如果 legacyV==true，出于历史原因，V 值将为 27 或 28。
func (api *SignerAPI) sign(req *SignDataRequest, legacyV bool) (hexutil.Bytes, error) {
	// We make the request prior to looking up if we actually have the account, to prevent
	// account-enumeration via the API
	// 我们先处理请求，然后再检查是否有对应的账户，以防止通过 API 枚举账户
	// 先调用 UI 批准签名请求
	res, err := api.UI.ApproveSignData(req)
	if err != nil {
		return nil, err
	}
	if !res.Approved {
		return nil, ErrRequestDenied // 如果用户未批准请求，返回拒绝错误
	}
	// Look up the wallet containing the requested signer
	// 查找包含请求签名者的钱包
	account := accounts.Account{Address: req.Address.Address()}
	wallet, err := api.am.Find(account)
	if err != nil {
		return nil, err
	}
	// 获取或查询签名所需的密码
	pw, err := api.lookupOrQueryPassword(account.Address,
		"Password for signing",
		fmt.Sprintf("Please enter password for signing data with account %s", account.Address.Hex()))
	if err != nil {
		return nil, err
	}
	// Sign the data with the wallet
	// 使用钱包和密码对数据进行签名
	// 返回的签名遵循 secp256k1 椭圆曲线标准，包含 R、S、V 值。
	signature, err := wallet.SignDataWithPassphrase(account, pw, req.ContentType, req.Rawdata)
	if err != nil {
		return nil, err
	}
	// 如果使用旧版签名格式，调整 V 值
	if legacyV {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper // 根据黄皮书将 V 从 0/1 转换为 27/28
	}
	return signature, nil
}

// SignData signs the hash of the provided data, but does so differently
// depending on the content-type specified.
//
// Different types of validation occur.
//
// SignData 对提供的哈希数据进行签名，但签名方式因指定的 content-type 而异。
//
// 会进行不同类型的验证。
//
// SignData 函数是一个更高层次的签名接口，旨在根据不同的内容类型（contentType）对数据进行签名。它抽象了底层签名逻辑，提供了灵活性以支持多种签名场景（如交易、消息等）。
func (api *SignerAPI) SignData(ctx context.Context, contentType string, addr common.MixedcaseAddress, data interface{}) (hexutil.Bytes, error) {
	// 确定签名格式并构造签名请求
	// 根据 contentType 处理数据并决定是否需要调整 V 值
	var req, transformV, err = api.determineSignatureFormat(ctx, contentType, addr, data)
	if err != nil {
		return nil, err
	}
	// 调用 sign 方法生成签名
	signature, err := api.sign(req, transformV)
	if err != nil {
		api.UI.ShowError(err.Error())
		return nil, err
	}
	return signature, nil
}

// determineSignatureFormat determines which signature method should be used based upon the mime type
// In the cases where it matters ensure that the charset is handled. The charset
// resides in the 'params' returned as the second returnvalue from mime.ParseMediaType
// charset, ok := params["charset"]
// As it is now, we accept any charset and just treat it as 'raw'.
// This method returns the mimetype for signing along with the request
//
// determineSignatureFormat 根据 MIME 类型确定应使用的签名方法
// 在需要的情况下，确保处理字符集。字符集存在于 mime.ParseMediaType 返回的第二个返回值 'params' 中
// charset, ok := params["charset"]
// 目前，我们接受任何字符集，并将其视为 'raw'。
// 此方法返回用于签名的 MIME 类型以及请求
//
// 根据类型处理数据（EIP-191、Clique、EIP-712 或普通文本）
//
//	EIP-191：定义带版本的签名数据，常用于特定验证者。
//	Clique：以太坊 PoA 共识机制，使用 RLP 编码头部签名。
//	EIP-712：结构化数据签名标准，广泛用于 DApp。
//	TextAndHash：普通消息签名，添加以太坊标准前缀。
func (api *SignerAPI) determineSignatureFormat(ctx context.Context, contentType string, addr common.MixedcaseAddress, data interface{}) (*SignDataRequest, bool, error) {
	var (
		req          *SignDataRequest
		useEthereumV = true // Default to use V = 27 or 28, the legacy Ethereum format  默认使用 V = 27 或 28，旧版以太坊格式
	)
	// 解析 MIME 类型，忽略字符集参数
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, useEthereumV, err
	}

	switch mediaType {
	case apitypes.IntendedValidator.Mime: // 解析验证者数据，计算签名哈希和消息，构造包含元信息的请求。
		// Data with an intended validator
		// 处理特定验证者的数据（EIP-191）
		validatorData, err := UnmarshalValidatorData(data)
		if err != nil {
			return nil, useEthereumV, err
		}
		sighash, msg := SignTextValidator(validatorData) // 计算签名哈希和消息
		messages := []*apitypes.NameValueType{
			{
				Name:  "This is a request to sign data intended for a particular validator (see EIP 191 version 0)",
				Typ:   "description",
				Value: "",
			},
			{
				Name:  "Intended validator address",
				Typ:   "address",
				Value: validatorData.Address.String(),
			},
			{
				Name:  "Application-specific data",
				Typ:   "hexdata",
				Value: validatorData.Message,
			},
			{
				Name:  "Full message for signing",
				Typ:   "hexdata",
				Value: fmt.Sprintf("%#x", msg),
			},
		}
		req = &SignDataRequest{ContentType: mediaType, Rawdata: []byte(msg), Messages: messages, Hash: sighash}
	case apitypes.ApplicationClique.Mime:
		// Clique is the Ethereum PoA standard
		// 处理 Clique（以太坊 PoA 标准）
		cliqueData, err := fromHex(data)
		if err != nil {
			return nil, useEthereumV, err
		}
		header := &types.Header{}
		if err := rlp.DecodeBytes(cliqueData, header); err != nil {
			return nil, useEthereumV, err
		}
		// Add space in the extradata to put the signature
		// 为签名预留空间，扩展 Extra 字段
		newExtra := make([]byte, len(header.Extra)+65)
		copy(newExtra, header.Extra)
		header.Extra = newExtra

		// Get back the rlp data, encoded by us
		// 计算 Clique 头部哈希和 RLP 编码
		sighash, cliqueRlp, err := cliqueHeaderHashAndRlp(header)
		if err != nil {
			return nil, useEthereumV, err
		}
		messages := []*apitypes.NameValueType{
			{
				Name:  "Clique header",
				Typ:   "clique",
				Value: fmt.Sprintf("clique header %d [%#x]", header.Number, header.Hash()),
			},
		}
		// Clique uses V on the form 0 or 1
		// Clique 使用 V = 0 或 1
		useEthereumV = false
		req = &SignDataRequest{ContentType: mediaType, Rawdata: cliqueRlp, Messages: messages, Hash: sighash}
	case apitypes.DataTyped.Mime:
		// EIP-712 conformant typed data
		// 处理 EIP-712 类型的结构化数据
		var err error
		req, err = typedDataRequest(data)
		if err != nil {
			return nil, useEthereumV, err
		}
	default: // also case TextPlain.Mime: // 包括 TextPlain.Mime
		// Calculates an Ethereum ECDSA signature for: 处理普通文本签名，符合以太坊标准
		// hash = keccak256("\x19Ethereum Signed Message:\n${message length}${message}") 计算方式：hash = keccak256("\x19Ethereum Signed Message:\n${message length}${message}")
		// We expect input to be a hex-encoded string
		textData, err := fromHex(data)
		if err != nil {
			return nil, useEthereumV, err
		}
		sighash, msg := accounts.TextAndHash(textData) // 计算哈希和消息
		messages := []*apitypes.NameValueType{
			{
				Name:  "message",
				Typ:   accounts.MimetypeTextPlain,
				Value: msg,
			},
		}
		req = &SignDataRequest{ContentType: mediaType, Rawdata: []byte(msg), Messages: messages, Hash: sighash}
	}
	// 设置请求的地址和元数据
	req.Address = addr
	req.Meta = MetadataFromContext(ctx)
	return req, useEthereumV, nil
}

// SignTextValidator signs the given message which can be further recovered
// with the given validator.
// hash = keccak256("\x19\x00"${address}${data}).
//
// SignTextValidator 签名给定的消息，该消息可以随后通过给定的验证者恢复。
// hash = keccak256("\x19\x00"${address}${data}).
func SignTextValidator(validatorData apitypes.ValidatorData) (hexutil.Bytes, string) {
	// 构造待签名消息，格式为 "\x19\x00" + 验证者地址 + 数据
	// "\x19\x00" 是 EIP-191 的版本前缀
	msg := fmt.Sprintf("\x19\x00%s%s", string(validatorData.Address.Bytes()), string(validatorData.Message))
	// 计算消息的 Keccak256 哈希并返回，同时返回原始消息
	return crypto.Keccak256([]byte(msg)), msg
}

// cliqueHeaderHashAndRlp returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// The method requires the extra data to be at least 65 bytes -- the original implementation
// in clique.go panics if this is the case, thus it's been reimplemented here to avoid the panic
// and simply return an error instead
//
// cliqueHeaderHashAndRlp 返回用于权威证明签名的哈希值。
// 它是除去额外数据末尾 65 字节签名之外的整个头部哈希。
//
// 该方法要求额外数据至少为 65 字节 -- 在 clique.go 中的原始实现会在此情况下发生 panic，
// 因此这里重新实现以避免 panic，而是简单地返回错误。
//
// cliqueHeaderHashAndRlp 的目的是为 Clique（以太坊 PoA 共识机制）生成签名所需的哈希和 RLP 编码，用于区块签名验证。
//
//	Clique：以太坊的权威证明（PoA）共识机制，依赖少数可信验证者签名区块。
//	签名格式：Clique 使用 secp256k1 签名，长度为 65 字节（R: 32, S: 32, V: 1）。
//	SealHash：不含签名的头部哈希，用于验证签名。
//	在 Clique 中，头部 Extra 字段末尾存储签名，前部分可包含额外数据。
func cliqueHeaderHashAndRlp(header *types.Header) (hash, rlp []byte, err error) {
	// 检查额外数据长度是否足够容纳 65 字节签名
	if len(header.Extra) < 65 {
		err = fmt.Errorf("clique header extradata too short, %d < 65", len(header.Extra))
		return
	}
	// 计算 Clique 头部的 RLP 编码
	rlp = clique.CliqueRLP(header)
	// 计算不含签名的头部哈希（SealHash）
	hash = clique.SealHash(header).Bytes()
	return hash, rlp, err
}

// SignTypedData signs EIP-712 conformant typed data
// hash = keccak256("\x19${byteVersion}${domainSeparator}${hashStruct(message)}")
// It returns
// - the signature,
// - and/or any error
//
// SignTypedData 签名符合 EIP-712 的类型化数据
// hash = keccak256("\x19${byteVersion}${domainSeparator}${hashStruct(message)}")
// 它返回
// - 签名，
// - 以及/或者任何错误
func (api *SignerAPI) SignTypedData(ctx context.Context, addr common.MixedcaseAddress, typedData apitypes.TypedData) (hexutil.Bytes, error) {
	// 调用底层方法签名类型化数据
	// 传入上下文、地址、类型化数据和 nil（可能是额外参数）
	signature, _, err := api.signTypedData(ctx, addr, typedData, nil)
	return signature, err
}

// signTypedData is identical to the capitalized version, except that it also returns the hash (preimage)
// - the signature preimage (hash)
//
// signTypedData 与大写版本相同，但它还返回哈希（前像）
// - 签名前像（哈希）
//
// EIP-712：定义了类型化数据的签名标准，通过结构化格式提高签名可读性和安全性。
// byteVersion：通常为 "\x01"，表示 EIP-712 版本。
// domainSeparator：域分隔符哈希，避免不同应用间的签名冲突。
// hashStruct(message)：消息的结构化哈希。
func (api *SignerAPI) signTypedData(ctx context.Context, addr common.MixedcaseAddress,
	typedData apitypes.TypedData, validationMessages *apitypes.ValidationMessages) (hexutil.Bytes, hexutil.Bytes, error) {
	// 构造类型化数据的签名请求
	req, err := typedDataRequest(typedData)
	if err != nil {
		return nil, nil, err
	}
	// 设置请求的地址和元数据
	req.Address = addr
	req.Meta = MetadataFromContext(ctx)
	// 如果提供了验证消息，添加到请求中
	if validationMessages != nil {
		req.Callinfo = validationMessages.Messages
	}
	// 调用 sign 方法生成签名，使用旧版 V 值格式（27/28）
	signature, err := api.sign(req, true)
	if err != nil {
		// 如果签名失败，显示错误信息给用户
		api.UI.ShowError(err.Error())
		return nil, nil, err
	}
	// 返回签名和哈希（前像）
	return signature, req.Hash, nil
}

// fromHex tries to interpret the data as type string, and convert from
// hexadecimal to []byte
//
// fromHex 尝试将数据解释为字符串类型，并从十六进制转换为 []byte
func fromHex(data any) ([]byte, error) {
	if stringData, ok := data.(string); ok {
		binary, err := hexutil.Decode(stringData)
		return binary, err
	}
	return nil, fmt.Errorf("wrong type %T", data)
}

// typedDataRequest tries to convert the data into a SignDataRequest.
// typedDataRequest 尝试将数据转换为 SignDataRequest。
func typedDataRequest(data any) (*SignDataRequest, error) {
	var typedData apitypes.TypedData
	if td, ok := data.(apitypes.TypedData); ok {
		typedData = td
	} else { // Hex-encoded data
		jsonData, err := fromHex(data)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(jsonData, &typedData); err != nil {
			return nil, err
		}
	}
	// 格式化类型化数据为消息列表
	messages, err := typedData.Format()
	if err != nil {
		return nil, err
	}
	// 计算签名哈希和原始数据
	sighash, rawData, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, err
	}
	// 构造并返回签名请求
	return &SignDataRequest{
		ContentType: apitypes.DataTyped.Mime,
		Rawdata:     []byte(rawData),
		Messages:    messages,
		Hash:        sighash}, nil
}

// EcRecover recovers the address associated with the given sig.
// Only compatible with `text/plain`
//
// EcRecover 恢复与给定签名关联的地址。
// 仅兼容 `text/plain`
func (api *SignerAPI) EcRecover(ctx context.Context, data hexutil.Bytes, sig hexutil.Bytes) (common.Address, error) {
	// Returns the address for the Account that was used to create the signature.
	//
	// Note, this function is compatible with eth_sign. As such it recovers
	// the address of:
	// hash = keccak256("\x19Ethereum Signed Message:\n${message length}${message}")
	// addr = ecrecover(hash, signature)
	//
	// Note, the signature must conform to the secp256k1 curve R, S and V values, where
	// the V value must be 27 or 28 for legacy reasons.
	//
	// https://geth.ethereum.org/docs/tools/clef/apis#account-ecrecover
	//
	// 返回用于创建签名的账户地址。
	//
	// 注意，此函数兼容 eth_sign。因此，它恢复的地址是：
	// hash = keccak256("\x19Ethereum Signed Message:\n${消息长度}${消息}")
	// addr = ecrecover(hash, signature)
	//
	// 注意，签名必须符合 secp256k1 曲线的 R、S 和 V 值，其中由于历史原因，V 值必须为 27 或 28。
	//
	// https://geth.ethereum.org/docs/tools/clef/apis#account-ecrecover
	// 检查签名长度是否为 65 字节（secp256k1 标准）
	if len(sig) != 65 {
		return common.Address{}, errors.New("signature must be 65 bytes long")
	}
	// 检查 V 值是否为 27 或 28（旧版以太坊签名要求）
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, errors.New("invalid Ethereum signature (V is not 27 or 28)")
	}
	// 将 V 值从 27/28 转换为 0/1，符合现代签名格式
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1 // 根据黄皮书调整 V 值
	// 计算数据的以太坊签名哈希
	// hash = keccak256("\x19Ethereum Signed Message:\n${message length}${message}")
	hash := accounts.TextHash(data)
	// 从签名和哈希恢复公钥
	rpk, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}, err
	}
	// 将公钥转换为以太坊地址并返回
	return crypto.PubkeyToAddress(*rpk), nil
}

// UnmarshalValidatorData converts the bytes input to typed data
// UnmarshalValidatorData 将字节输入转换为类型化数据
func UnmarshalValidatorData(data interface{}) (apitypes.ValidatorData, error) {
	raw, ok := data.(map[string]interface{})
	if !ok {
		return apitypes.ValidatorData{}, errors.New("validator input is not a map[string]interface{}")
	}
	addrBytes, err := fromHex(raw["address"])
	if err != nil {
		return apitypes.ValidatorData{}, fmt.Errorf("validator address error: %w", err)
	}
	if len(addrBytes) == 0 {
		return apitypes.ValidatorData{}, errors.New("validator address is undefined")
	}
	messageBytes, err := fromHex(raw["message"])
	if err != nil {
		return apitypes.ValidatorData{}, fmt.Errorf("message error: %w", err)
	}
	if len(messageBytes) == 0 {
		return apitypes.ValidatorData{}, errors.New("message is undefined")
	}
	return apitypes.ValidatorData{
		Address: common.BytesToAddress(addrBytes),
		Message: messageBytes,
	}, nil
}
