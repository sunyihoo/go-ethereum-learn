// Copyright 2016 The go-ethereum Authors
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

// 预售 (Pre-Sale): 以太坊在正式发布之前进行的一次公开众筹活动，参与者可以通过购买预售的以太币来支持项目的发展。
// 预售密钥格式: 为了在预售期间安全地分发和管理用户的私钥，以太坊团队设计了一种特定的加密 JSON 格式。
// PBKDF2 (Password-Based Key Derivation Function 2): 一种密钥派生函数，用于从密码生成加密密钥。它通过对密码进行多次迭代的哈希运算，增加了暴力破解的难度。预售密钥的解密过程使用了 PBKDF2-HMAC-SHA256。
// AES-CBC (Advanced Encryption Standard - Cipher Block Chaining): 一种对称加密算法的模式。CBC 模式将每个明文块与前一个密文块进行异或后再加密，增加了密文的随机性。预售密钥的种子数据使用 AES-CBC 进行加密。
// Initialization Vector (IV): 在 CBC 模式中，IV 是一个随机的初始值，用于确保相同的密钥加密相同的明文会产生不同的密文。
// Keccak-256: 以太坊使用的哈希算法。预售密钥的解密过程中，通过对解密后的种子进行 Keccak-256 哈希来得到最终的以太坊私钥。
// PKCS#7 Padding: 一种常用的块密码填充方案，用于确保明文的长度是块大小的整数倍，以便进行块加密。

// creates a Key and stores that in the given KeyStore by decrypting a presale key JSON
// creates a Key (密钥) 并通过解密预售密钥 JSON 将其存储在给定的 KeyStore 中
func importPreSaleKey(keyStore keyStore, keyJSON []byte, password string) (accounts.Account, *Key, error) {
	key, err := decryptPreSaleKey(keyJSON, password)
	if err != nil {
		return accounts.Account{}, nil, err
	}
	key.Id, err = uuid.NewRandom()
	if err != nil {
		return accounts.Account{}, nil, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL: accounts.URL{
			Scheme: KeyStoreScheme,
			Path:   keyStore.JoinPath(keyFileName(key.Address)),
		},
	}
	err = keyStore.StoreKey(a.URL.Path, key, password)
	return a, key, err
}

// decryptPreSaleKey takes a presale key JSON and a password and returns the
// decrypted key.
// decryptPreSaleKey 接收预售密钥 JSON 和密码，并返回解密的密钥。
func decryptPreSaleKey(fileContent []byte, password string) (key *Key, err error) {
	// Define the structure of the presale key JSON
	// 定义预售密钥 JSON 的结构
	preSaleKeyStruct := struct {
		EncSeed string
		EthAddr string
		Email   string
		BtcAddr string
	}{}
	err = json.Unmarshal(fileContent, &preSaleKeyStruct)
	if err != nil {
		return nil, err
	}
	// Decode the hex-encoded encrypted seed
	// 解码十六进制编码的加密种子
	encSeedBytes, err := hex.DecodeString(preSaleKeyStruct.EncSeed)
	if err != nil {
		return nil, errors.New("invalid hex in encSeed")
	}
	if len(encSeedBytes) < 16 {
		return nil, errors.New("invalid encSeed, too short")
	}
	// Extract the initialization vector (IV) and the ciphertext
	// 提取初始化向量 (IV) 和密文
	iv := encSeedBytes[:16]
	cipherText := encSeedBytes[16:]
	/*
		See https://github.com/ethereum/pyethsaletool

		pyethsaletool generates the encryption key from password by
		2000 rounds of PBKDF2 with HMAC-SHA-256 using password as salt (:().
		16 byte key length within PBKDF2 and resulting key is used as AES key
	*/
	// Derive the AES decryption key from the password using PBKDF2
	// 使用 PBKDF2 从密码派生 AES 解密密钥
	passBytes := []byte(password)
	derivedKey := pbkdf2.Key(passBytes, passBytes, 2000, 16, sha256.New)
	// Decrypt the seed using AES-CBC with the derived key and IV
	// 使用派生的密钥和 IV 通过 AES-CBC 解密种子
	plainText, err := aesCBCDecrypt(derivedKey, cipherText, iv)
	if err != nil {
		return nil, err
	}
	// Derive the Ethereum private key by hashing the decrypted seed with Keccak-256
	// 通过使用 Keccak-256 哈希解密的种子来派生以太坊私钥
	ethPriv := crypto.Keccak256(plainText)
	ecKey := crypto.ToECDSAUnsafe(ethPriv)

	// Create a Key struct from the decrypted private key
	// 从解密的私钥创建一个 Key 结构体
	key = &Key{
		Id:         uuid.UUID{}, // ID will be generated later during storage
		Address:    crypto.PubkeyToAddress(ecKey.PublicKey),
		PrivateKey: ecKey,
	}
	// Verify that the derived address matches the address stored in the presale key
	// 验证派生的地址是否与预售密钥中存储的地址匹配
	derivedAddr := hex.EncodeToString(key.Address.Bytes()) // needed because .Hex() gives leading "0x"
	expectedAddr := preSaleKeyStruct.EthAddr
	if derivedAddr != expectedAddr {
		err = fmt.Errorf("decrypted addr '%s' not equal to expected addr '%s'", derivedAddr, expectedAddr)
	}
	return key, err
}

// aesCTRXOR performs XOR encryption/decryption using the AES in counter mode.
// aesCTRXOR 使用计数器模式的 AES 执行 XOR 加密/解密。
func aesCTRXOR(key, inText, iv []byte) ([]byte, error) {
	// AES-128 is selected due to size of encryptKey.
	// 由于 encryptKey 的大小，选择了 AES-128。
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

// aesCBCDecrypt decrypts the given ciphertext using AES in cipher block chaining (CBC) mode.
// aesCBCDecrypt 使用密码块链接 (CBC) 模式的 AES 解密给定的密文。
func aesCBCDecrypt(key, cipherText, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(aesBlock, iv)
	paddedPlaintext := make([]byte, len(cipherText))
	decrypter.CryptBlocks(paddedPlaintext, cipherText)
	plaintext := pkcs7Unpad(paddedPlaintext)
	if plaintext == nil {
		return nil, ErrDecrypt
	}
	return plaintext, err
}

// From https://leanpub.com/gocrypto/read#leanpub-auto-block-cipher-modes
// 摘自 https://leanpub.com/gocrypto/read#leanpub-auto-block-cipher-modes
// pkcs7Unpad removes PKCS#7 padding from the given data.
// pkcs7Unpad 从给定的数据中移除 PKCS#7 填充。
func pkcs7Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}
