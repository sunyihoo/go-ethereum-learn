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

// Package enr implements Ethereum Node Records as defined in EIP-778. A node record holds
// arbitrary information about a node on the peer-to-peer network. Node information is
// stored in key/value pairs. To store and retrieve key/values in a record, use the Entry
// interface.
//
// # Signature Handling
//
// Records must be signed before transmitting them to another node.
//
// Decoding a record doesn't check its signature. Code working with records from an
// untrusted source must always verify two things: that the record uses an identity scheme
// deemed secure, and that the signature is valid according to the declared scheme.
//
// When creating a record, set the entries you want and use a signing function provided by
// the identity scheme to add the signature. Modifying a record invalidates the signature.
//
// Package enr supports the "secp256k1-keccak" identity scheme.
// TODO understand the text
package enr

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/ethereum/go-ethereum/rlp"
)

const SizeLimit = 300 // maximum encoded size of a node record in bytes
// 最大编码节点记录大小（字节）

var (
	ErrInvalidSig     = errors.New("invalid signature on node record")             // 节点记录上的签名无效 / Invalid signature on node record
	errNotSorted      = errors.New("record key/value pairs are not sorted by key") // 记录键值对未按键排序 / Record key/value pairs not sorted by key
	errDuplicateKey   = errors.New("record contains duplicate key")                // 记录包含重复键 / Record contains duplicate key
	errIncompletePair = errors.New("record contains incomplete k/v pair")          // 记录包含不完整的键值对 / Record contains incomplete k/v pair
	errIncompleteList = errors.New("record contains less than two list elements")  // 记录包含少于两个列表元素 / Record contains less than two list elements
	errTooBig         = fmt.Errorf("record bigger than %d bytes", SizeLimit)       // 记录超过最大大小 / Record exceeds size limit
	errEncodeUnsigned = errors.New("can't encode unsigned record")                 // 无法编码未签名的记录 / Cannot encode unsigned record
	errNotFound       = errors.New("no such key in record")                        // 记录中无此键 / No such key in record
)

// An IdentityScheme is capable of verifying record signatures and
// deriving node addresses.
// IdentityScheme 能够验证记录签名并推导节点地址。
type IdentityScheme interface {
	Verify(r *Record, sig []byte) error // 验证签名 / Verify signature
	NodeAddr(r *Record) []byte          // 推导节点地址 / Derive node address
}

// SchemeMap is a registry of named identity schemes.
// SchemeMap 是命名身份方案的注册表。
type SchemeMap map[string]IdentityScheme

func (m SchemeMap) Verify(r *Record, sig []byte) error {
	s := m[r.IdentityScheme()] // 获取记录的身份方案 / Get identity scheme from record
	if s == nil {
		return ErrInvalidSig // 如果方案不存在则返回签名无效 / Return invalid signature if scheme not found
	}
	return s.Verify(r, sig) // 调用方案的验证方法 / Call scheme's verify method
}

func (m SchemeMap) NodeAddr(r *Record) []byte {
	s := m[r.IdentityScheme()] // 获取记录的身份方案 / Get identity scheme from record
	if s == nil {
		return nil // 如果方案不存在则返回 nil / Return nil if scheme not found
	}
	return s.NodeAddr(r) // 调用方案的节点地址方法 / Call scheme's node address method
}

// Record represents a node record. The zero value is an empty record.
// Record 表示节点记录。零值是一个空记录。
type Record struct {
	seq       uint64 // sequence number / 序列号
	signature []byte // the signature / 签名
	raw       []byte // RLP encoded record / RLP 编码的记录
	pairs     []pair // sorted list of all key/value pairs / 所有键值对的排序列表
}

// pair is a key/value pair in a record.
// pair 是记录中的键值对。
type pair struct {
	k string       // 键 / Key
	v rlp.RawValue // 值（RLP 原始值） / Value (RLP raw value)
}

// Size returns the encoded size of the record.
// Size 返回记录的编码大小。
func (r *Record) Size() uint64 {
	if r.raw != nil {
		return uint64(len(r.raw)) // 如果有原始数据则返回其长度 / Return length if raw data exists
	}
	return computeSize(r) // 否则计算大小 / Otherwise compute size
}

func computeSize(r *Record) uint64 {
	size := uint64(rlp.IntSize(r.seq)) // 计算序列号大小 / Compute size of sequence number
	size += rlp.BytesSize(r.signature) // 加上签名大小 / Add signature size
	for _, p := range r.pairs {
		size += rlp.StringSize(p.k) // 加上每个键的大小 / Add size of each key
		size += uint64(len(p.v))    // 加上每个值的大小 / Add size of each value
	}
	return rlp.ListSize(size) // 返回列表总大小 / Return total list size
}

// Seq returns the sequence number.
// Seq 返回序列号。
func (r *Record) Seq() uint64 {
	return r.seq // 返回序列号 / Return sequence number
}

// SetSeq updates the record sequence number. This invalidates any signature on the record.
// Calling SetSeq is usually not required because setting any key in a signed record
// increments the sequence number.
// SetSeq 更新记录序列号。这会使记录上的任何签名失效。
// 通常不需要调用 SetSeq，因为在已签名记录中设置任何键会递增序列号。
func (r *Record) SetSeq(s uint64) {
	r.signature = nil // 清除签名 / Clear signature
	r.raw = nil       // 清除原始数据 / Clear raw data
	r.seq = s         // 设置新序列号 / Set new sequence number
}

// Load retrieves the value of a key/value pair. The given Entry must be a pointer and will
// be set to the value of the entry in the record.
//
// Errors returned by Load are wrapped in KeyError. You can distinguish decoding errors
// from missing keys using the IsNotFound function.
// Load 检索键值对的值。给定的 Entry 必须是指针，将被设置为记录中的条目值。
//
// Load 返回的错误被包装在 KeyError 中。可以使用 IsNotFound 函数区分解码错误和键缺失。
func (r *Record) Load(e Entry) error {
	i := sort.Search(len(r.pairs), func(i int) bool { return r.pairs[i].k >= e.ENRKey() }) // 二分查找键 / Binary search for key
	if i < len(r.pairs) && r.pairs[i].k == e.ENRKey() {                                    // 如果找到键 / If key found
		if err := rlp.DecodeBytes(r.pairs[i].v, e); err != nil { // 解码值 / Decode value
			return &KeyError{Key: e.ENRKey(), Err: err} // 如果解码失败则返回错误 / Return error if decode fails
		}
		return nil // 成功则返回 nil / Return nil on success
	}
	return &KeyError{Key: e.ENRKey(), Err: errNotFound} // 如果未找到则返回未找到错误 / Return not found error if key not found
}

// Set adds or updates the given entry in the record. It panics if the value can't be
// encoded. If the record is signed, Set increments the sequence number and invalidates
// the sequence number.
// Set 添加或更新记录中的给定条目。如果值无法编码则会 panic。
// 如果记录已签名，Set 会递增序列号并使序列号失效。
func (r *Record) Set(e Entry) {
	blob, err := rlp.EncodeToBytes(e) // 编码条目 / Encode entry
	if err != nil {
		panic(fmt.Errorf("enr: can't encode %s: %v", e.ENRKey(), err)) // 如果编码失败则 panic / Panic if encoding fails
	}
	r.invalidate() // 使签名和原始数据失效 / Invalidate signature and raw data

	pairs := make([]pair, len(r.pairs))                                                // 创建新键值对切片 / Create new pairs slice
	copy(pairs, r.pairs)                                                               // 复制现有键值对 / Copy existing pairs
	i := sort.Search(len(pairs), func(i int) bool { return pairs[i].k >= e.ENRKey() }) // 二分查找插入位置 / Binary search for insertion point
	switch {
	case i < len(pairs) && pairs[i].k == e.ENRKey(): // 如果键已存在 / If key exists
		pairs[i].v = blob // 更新值 / Update value
	case i < len(r.pairs): // 如果插入在中间 / If insert in middle
		el := pair{e.ENRKey(), blob}  // 创建新键值对 / Create new pair
		pairs = append(pairs, pair{}) // 扩展切片 / Expand slice
		copy(pairs[i+1:], pairs[i:])  // 移动元素 / Shift elements
		pairs[i] = el                 // 插入新键值对 / Insert new pair
	default: // 如果插入在末尾 / If insert at end
		pairs = append(pairs, pair{e.ENRKey(), blob}) // 添加新键值对 / Append new pair
	}
	r.pairs = pairs // 更新键值对 / Update pairs
}

func (r *Record) invalidate() {
	if r.signature != nil {
		r.seq++ // 如果有签名则递增序列号 / Increment sequence number if signed
	}
	r.signature = nil // 清除签名 / Clear signature
	r.raw = nil       // 清除原始数据 / Clear raw data
}

// Signature returns the signature of the record.
// Signature 返回记录的签名。
func (r *Record) Signature() []byte {
	if r.signature == nil {
		return nil // 如果无签名则返回 nil / Return nil if no signature
	}
	cpy := make([]byte, len(r.signature))
	copy(cpy, r.signature) // 返回签名副本 / Return copy of signature
	return cpy
}

// EncodeRLP implements rlp.Encoder. Encoding fails if
// the record is unsigned.
// EncodeRLP 实现 rlp.Encoder。如果记录未签名则编码失败。
func (r Record) EncodeRLP(w io.Writer) error {
	if r.signature == nil {
		return errEncodeUnsigned // 如果无签名则返回错误 / Return error if unsigned
	}
	_, err := w.Write(r.raw) // 写入原始数据 / Write raw data
	return err
}

// DecodeRLP implements rlp.Decoder. Decoding doesn't verify the signature.
// DecodeRLP 实现 rlp.Decoder。解码不验证签名。
func (r *Record) DecodeRLP(s *rlp.Stream) error {
	dec, raw, err := decodeRecord(s) // 解码记录 / Decode record
	if err != nil {
		return err // 如果出错则返回错误 / Return error if failed
	}
	*r = dec    // 更新记录 / Update record
	r.raw = raw // 设置原始数据 / Set raw data
	return nil  // 返回成功 / Return success
}

func decodeRecord(s *rlp.Stream) (dec Record, raw []byte, err error) {
	raw, err = s.Raw() // 获取原始 RLP 数据 / Get raw RLP data
	if err != nil {
		return dec, raw, err // 如果出错则返回 / Return if error
	}
	if len(raw) > SizeLimit {
		return dec, raw, errTooBig // 如果超过大小限制则返回错误 / Return error if exceeds size limit
	}

	// Decode the RLP container.
	// 解码 RLP 容器。
	s = rlp.NewStream(bytes.NewReader(raw), 0)
	if _, err := s.List(); err != nil {
		return dec, raw, err // 如果列表解码失败则返回 / Return if list decoding fails
	}
	if err = s.Decode(&dec.signature); err != nil { // 解码签名 / Decode signature
		if err == rlp.EOL {
			err = errIncompleteList // 如果列表不完整则返回错误 / Return incomplete list error
		}
		return dec, raw, err
	}
	if err = s.Decode(&dec.seq); err != nil { // 解码序列号 / Decode sequence number
		if err == rlp.EOL {
			err = errIncompleteList // 如果列表不完整则返回错误 / Return incomplete list error
		}
		return dec, raw, err
	}
	// The rest of the record contains sorted k/v pairs.
	// 记录的其余部分包含排序的键值对。
	var prevkey string
	for i := 0; ; i++ {
		var kv pair
		if err := s.Decode(&kv.k); err != nil { // 解码键 / Decode key
			if err == rlp.EOL {
				break // 如果到达列表末尾则退出 / Exit if end of list
			}
			return dec, raw, err
		}
		if err := s.Decode(&kv.v); err != nil { // 解码值 / Decode value
			if err == rlp.EOL {
				return dec, raw, errIncompletePair // 如果键值对不完整则返回错误 / Return incomplete pair error
			}
			return dec, raw, err
		}
		if i > 0 {
			if kv.k == prevkey {
				return dec, raw, errDuplicateKey // 如果键重复则返回错误 / Return duplicate key error
			}
			if kv.k < prevkey {
				return dec, raw, errNotSorted // 如果键未排序则返回错误 / Return unsorted error
			}
		}
		dec.pairs = append(dec.pairs, kv) // 添加键值对 / Append key/value pair
		prevkey = kv.k                    // 更新前一个键 / Update previous key
	}
	return dec, raw, s.ListEnd() // 返回解码后的记录 / Return decoded record
}

// IdentityScheme returns the name of the identity scheme in the record.
// IdentityScheme 返回记录中的身份方案名称。
func (r *Record) IdentityScheme() string {
	var id ID
	r.Load(&id)       // 加载身份方案 / Load identity scheme
	return string(id) // 返回身份方案名称 / Return identity scheme name
}

// VerifySignature checks whether the record is signed using the given identity scheme.
// VerifySignature 检查记录是否使用给定的身份方案签名。
func (r *Record) VerifySignature(s IdentityScheme) error {
	return s.Verify(r, r.signature) // 使用方案验证签名 / Verify signature with scheme
}

// SetSig sets the record signature. It returns an error if the encoded record is larger
// than the size limit or if the signature is invalid according to the passed scheme.
//
// You can also use SetSig to remove the signature explicitly by passing a nil scheme
// and signature.
//
// SetSig panics when either the scheme or the signature (but not both) are nil.
// SetSig 设置记录签名。如果编码后的记录超过大小限制或签名根据给定的方案无效，则返回错误。
//
// 您也可以通过传递 nil 方案和签名明确移除签名。
//
// 如果方案或签名（但不是两者都）为 nil，则 SetSig 会 panic。
func (r *Record) SetSig(s IdentityScheme, sig []byte) error {
	switch {
	// Prevent storing invalid data.
	// 防止存储无效数据。
	case s == nil && sig != nil:
		panic("enr: invalid call to SetSig with non-nil signature but nil scheme") // 如果签名非 nil 但方案为 nil 则 panic / Panic if signature non-nil but scheme nil
	case s != nil && sig == nil:
		panic("enr: invalid call to SetSig with nil signature but non-nil scheme") // 如果方案非 nil 但签名为 nil 则 panic / Panic if scheme non-nil but signature nil
	// Verify if we have a scheme.
	// 如果有方案则验证。
	case s != nil:
		if err := s.Verify(r, sig); err != nil { // 验证签名 / Verify signature
			return err // 如果无效则返回错误 / Return error if invalid
		}
		raw, err := r.encode(sig) // 编码记录 / Encode record
		if err != nil {
			return err // 如果编码失败则返回错误 / Return error if encoding fails
		}
		r.signature, r.raw = sig, raw // 更新签名和原始数据 / Update signature and raw data
	// Reset otherwise.
	// 否则重置。
	default:
		r.signature, r.raw = nil, nil // 清除签名和原始数据 / Clear signature and raw data
	}
	return nil // 返回成功 / Return success
}

// AppendElements appends the sequence number and entries to the given slice.
// AppendElements 将序列号和条目追加到给定的切片中。
func (r *Record) AppendElements(list []interface{}) []interface{} {
	list = append(list, r.seq) // 添加序列号 / Append sequence number
	for _, p := range r.pairs {
		list = append(list, p.k, p.v) // 添加键值对 / Append key/value pairs
	}
	return list // 返回更新后的切片 / Return updated slice
}

func (r *Record) encode(sig []byte) (raw []byte, err error) {
	list := make([]interface{}, 1, 2*len(r.pairs)+2)    // 创建编码列表 / Create encoding list
	list[0] = sig                                       // 添加签名 / Add signature
	list = r.AppendElements(list)                       // 添加序列号和键值对 / Append sequence number and pairs
	if raw, err = rlp.EncodeToBytes(list); err != nil { // RLP 编码 / RLP encode
		return nil, err // 如果编码失败则返回错误 / Return error if encoding fails
	}
	if len(raw) > SizeLimit {
		return nil, errTooBig // 如果超过大小限制则返回错误 / Return error if exceeds size limit
	}
	return raw, nil // 返回编码数据 / Return encoded data
}
