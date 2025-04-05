// Copyright 2014 The go-ethereum Authors
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
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

// 私钥 (Private Key): 一个用于控制以太坊账户的秘密数字。拥有私钥的人可以发送交易和控制与该账户相关的资产。
// 公钥 (Public Key): 从私钥派生出来的公开可见的密钥。
// 地址 (Address): 从公钥派生出来的以太坊账户的唯一标识符。
// ECDSA (Elliptic Curve Digital Signature Algorithm): 以太坊使用的签名算法。
// 密钥库 (Keystore): 一种安全存储以太坊私钥的方式。通常，密钥库文件会使用密码对私钥进行加密。
// UUID (Universally Unique Identifier): 一种标准的用于唯一标识信息的 128 位数字。
// ICAP (Inter-Client Address Protocol): 一种用于表示以太坊地址的编码方案。Direct ICAP 规范对地址的格式有特定的要求。
// 原子写入 (Atomic Write): 一种确保文件写入操作要么完全成功，要么完全不发生的技术。这通常通过先写入临时文件，然后将其重命名为目标文件来实现，以避免在写入过程中发生错误导致文件损坏。
// ISO8601: 一种国际标准化的日期和时间表示格式.

const (
	version = 3
)

type Key struct {
	Id uuid.UUID // Version 4 "random" for unique id not derived from key data
	// Id：版本 4 的“随机” UUID，用作唯一 ID，不从密钥数据派生
	// to simplify lookups we also store the address
	// 为了简化查找，我们还存储了地址
	Address common.Address
	// we only store privkey as pubkey/address can be derived from it
	// 我们只存储私钥，因为公钥/地址可以从私钥派生出来
	// privkey in this struct is always in plaintext
	// 此结构体中的私钥始终是明文的
	PrivateKey *ecdsa.PrivateKey
}

type keyStore interface {
	// Loads and decrypts the key from disk.
	// 从磁盘加载并解密密钥。
	GetKey(addr common.Address, filename string, auth string) (*Key, error)
	// Writes and encrypts the key.
	// 写入并加密密钥。
	StoreKey(filename string, k *Key, auth string) error
	// Joins filename with the key directory unless it is already absolute.
	// 将文件名与密钥目录连接，除非文件名已经是绝对路径。
	JoinPath(filename string) string
}

type plainKeyJSON struct {
	Address    string `json:"address"`
	PrivateKey string `json:"privatekey"`
	Id         string `json:"id"`
	Version    int    `json:"version"`
}

type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  CryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type CryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

// MarshalJSON implements the json.Marshaller interface.
// MarshalJSON 实现了 json.Marshaller 接口，用于将 Key 结构体序列化为 JSON。
func (k *Key) MarshalJSON() (j []byte, err error) {
	jStruct := plainKeyJSON{
		hex.EncodeToString(k.Address[:]),
		hex.EncodeToString(crypto.FromECDSA(k.PrivateKey)),
		k.Id.String(),
		version,
	}
	j, err = json.Marshal(jStruct)
	return j, err
}

// UnmarshalJSON parses url.
// UnmarshalJSON 解析 JSON 数据，用于将 JSON 数据反序列化为 Key 结构体。
func (k *Key) UnmarshalJSON(j []byte) (err error) {
	keyJSON := new(plainKeyJSON)
	err = json.Unmarshal(j, &keyJSON)
	if err != nil {
		return err
	}

	u := new(uuid.UUID)
	*u, err = uuid.Parse(keyJSON.Id)
	if err != nil {
		return err
	}
	k.Id = *u
	addr, err := hex.DecodeString(keyJSON.Address)
	if err != nil {
		return err
	}
	privkey, err := crypto.HexToECDSA(keyJSON.PrivateKey)
	if err != nil {
		return err
	}

	k.Address = common.BytesToAddress(addr)
	k.PrivateKey = privkey

	return nil
}

// newKeyFromECDSA creates a new Key struct from an existing ECDSA private key.
// newKeyFromECDSA 从现有的 ECDSA 私钥创建一个新的 Key 结构体。
func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	key := &Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}

// NewKeyForDirectICAP generates a key whose address fits into < 155 bits so it can fit
// into the Direct ICAP spec. for simplicity and easier compatibility with other libs, we
// retry until the first byte is 0.
// NewKeyForDirectICAP 生成一个地址小于 155 位的密钥，以便符合 Direct ICAP 规范。
// 为了简单起见并更容易与其他库兼容，我们会重试直到第一个字节为 0。
func NewKeyForDirectICAP(rand io.Reader) *Key {
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic("key generation: could not read from random source: " + err.Error())
	}
	reader := bytes.NewReader(randBytes)
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), reader)
	if err != nil {
		panic("key generation: ecdsa.GenerateKey failed: " + err.Error())
	}
	key := newKeyFromECDSA(privateKeyECDSA)
	if !strings.HasPrefix(key.Address.Hex(), "0x00") {
		return NewKeyForDirectICAP(rand)
	}
	return key
}

// newKey generates a new random ECDSA private key and wraps it in a Key struct.
// newKey 生成一个新的随机 ECDSA 私钥并将其包装在 Key 结构体中。
func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}

// storeNewKey generates a new key, stores it using the provided keyStore, and
// returns the Key and accounts.Account representation.
// storeNewKey 生成一个新的密钥，使用提供的 keyStore 存储它，并返回 Key 和 accounts.Account 表示。
func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand)
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil {
		zeroKey(key.PrivateKey)
		return nil, a, err
	}
	return key, a, err
}

// writeTemporaryKeyFile writes the given content to a temporary file in the
// same directory as the target file, and returns the name of the temporary file.
// writeTemporaryKeyFile 将给定的内容写入与目标文件相同的目录中的临时文件，并返回临时文件的名称。
func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	// 创建密钥库目录，并设置适当的权限，以防目录尚不存在。
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	// 原子写入：首先创建一个临时的隐藏文件，然后将其移动到目标位置。TempFile 会分配 0600 权限。
	f, err := os.CreateTemp(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

// writeKeyFile atomically writes the given content to the target file.
// writeKeyFile 将给定的内容原子地写入目标文件。
func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
// keyFileName 实现了密钥文件的命名约定：UTC--<创建时间 UTC ISO8601 格式>--<地址十六进制>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

// toISO8601 converts the given time to UTC ISO8601 format with nanosecond precision.
// toISO8601 将给定的时间转换为具有纳秒精度的 UTC ISO8601 格式。
func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
