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

package dnsdisc

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// Tree is a merkle tree of node records.
// Tree 是一个节点记录的 Merkle 树。
type Tree struct {
	root    *rootEntry       // Root entry of the tree / 树的根条目
	entries map[string]entry // Map of subdomain to entry / 子域到条目的映射
}

// Sign signs the tree with the given private key and sets the sequence number.
// Sign 使用给定的私钥对树进行签名并设置序列号。
func (t *Tree) Sign(key *ecdsa.PrivateKey, domain string) (url string, err error) {
	root := *t.root                              // Copy root / 复制根
	sig, err := crypto.Sign(root.sigHash(), key) // Sign root hash / 签名根哈希
	if err != nil {
		return "", err // Return error on failure / 失败时返回错误
	}
	root.sig = sig                               // Set signature / 设置签名
	t.root = &root                               // Update tree root / 更新树根
	link := newLinkEntry(domain, &key.PublicKey) // Create link entry / 创建链接条目
	return link.String(), nil                    // Return link URL / 返回链接 URL
}

// SetSignature verifies the given signature and assigns it as the tree's current
// signature if valid.
//
// SetSignature 验证给定的签名，如果有效则将其设置为树的当前签名。
func (t *Tree) SetSignature(pubkey *ecdsa.PublicKey, signature string) error {
	sig, err := b64format.DecodeString(signature) // Decode base64 signature / 解码 base64 签名
	if err != nil || len(sig) != crypto.SignatureLength {
		return errInvalidSig // Return error if invalid / 如果无效则返回错误
	}
	root := *t.root                    // Copy root / 复制根
	root.sig = sig                     // Set signature / 设置签名
	if !root.verifySignature(pubkey) { // Verify signature / 验证签名
		return errInvalidSig // Return error if invalid / 如果无效则返回错误
	}
	t.root = &root // Update tree root / 更新树根
	return nil
}

// Seq returns the sequence number of the tree.
// Seq 返回树的序列号。
func (t *Tree) Seq() uint {
	return t.root.seq // Return sequence number / 返回序列号
}

// Signature returns the signature of the tree.
// Signature 返回树的签名。
func (t *Tree) Signature() string {
	return b64format.EncodeToString(t.root.sig) // Return base64-encoded signature / 返回 base64 编码的签名
}

// ToTXT returns all DNS TXT records required for the tree.
// ToTXT 返回树所需的所有 DNS TXT 记录。
func (t *Tree) ToTXT(domain string) map[string]string {
	records := map[string]string{domain: t.root.String()} // Initialize with root / 使用根初始化
	for _, e := range t.entries {                         // Iterate entries / 遍历条目
		sd := subdomain(e) // Get subdomain / 获取子域
		if domain != "" {
			sd = sd + "." + domain // Append domain / 追加域名
		}
		records[sd] = e.String() // Add TXT record / 添加 TXT 记录
	}
	return records // Return records / 返回记录
}

// Links returns all links contained in the tree.
// Links 返回树中包含的所有链接。
func (t *Tree) Links() []string {
	var links []string
	for _, e := range t.entries { // Iterate entries / 遍历条目
		if le, ok := e.(*linkEntry); ok { // Check for link entry / 检查链接条目
			links = append(links, le.String()) // Add link / 添加链接
		}
	}
	return links // Return links / 返回链接
}

// Nodes returns all nodes contained in the tree.
// Nodes 返回树中包含的所有节点。
func (t *Tree) Nodes() []*enode.Node {
	var nodes []*enode.Node
	for _, e := range t.entries { // Iterate entries / 遍历条目
		if ee, ok := e.(*enrEntry); ok { // Check for ENR entry / 检查 ENR 条目
			nodes = append(nodes, ee.node) // Add node / 添加节点
		}
	}
	return nodes // Return nodes / 返回节点
}

/*
We want to keep the UDP size below 512 bytes. The UDP size is roughly:
UDP length = 8 + UDP payload length ( 229 )
UPD Payload length:
  - dns.id 2
  - dns.flags 2
  - dns.count.queries 2
  - dns.count.answers 2
  - dns.count.auth_rr 2
  - dns.count.add_rr 2
  - queries (query-size + 6)
  - answers :
  - dns.resp.name 2
  - dns.resp.type 2
  - dns.resp.class 2
  - dns.resp.ttl 4
  - dns.resp.len 2
  - dns.txt.length 1
  - dns.txt resp_data_size

So the total size is roughly a fixed overhead of `39`, and the size of the query (domain
name) and response. The query size is, for example,
FVY6INQ6LZ33WLCHO3BPR3FH6Y.snap.mainnet.ethdisco.net (52)

We also have some static data in the response, such as `enrtree-branch:`, and potentially
splitting the response up with `" "`, leaving us with a size of roughly `400` that we need
to stay below.

The number `370` is used to have some margin for extra overhead (for example, the dns
query may be larger - more subdomains).
*/
const (
	hashAbbrevSize = 1 + 16*13/8          // Size of an encoded hash (plus comma) / 编码哈希的大小（加逗号）
	maxChildren    = 370 / hashAbbrevSize // 13 children / 13 个子节点
	minHashLength  = 12                   // Minimum hash length / 最小哈希长度
)

// MakeTree creates a tree containing the given nodes and links.
// MakeTree 创建一个包含给定节点和链接的树。
func MakeTree(seq uint, nodes []*enode.Node, links []string) (*Tree, error) {
	// Sort records by ID and ensure all nodes have a valid record.
	// 按 ID 排序记录并确保所有节点具有有效记录。
	records := make([]*enode.Node, len(nodes))
	copy(records, nodes)
	sortByID(records) // Sort by ID / 按 ID 排序
	for _, n := range records {
		if len(n.Record().Signature()) == 0 { // Check for signature / 检查签名
			return nil, fmt.Errorf("can't add node %v: unsigned node record", n.ID()) // Return error if unsigned / 如果未签名则返回错误
		}
	}

	// Create the leaf list.
	// 创建叶子列表。
	enrEntries := make([]entry, len(records))
	for i, r := range records {
		enrEntries[i] = &enrEntry{r} // Create ENR entries / 创建 ENR 条目
	}
	linkEntries := make([]entry, len(links))
	for i, l := range links {
		le, err := parseLink(l) // Parse links / 解析链接
		if err != nil {
			return nil, err // Return error on failure / 失败时返回错误
		}
		linkEntries[i] = le // Add link entry / 添加链接条目
	}

	// Create intermediate nodes.
	// 创建中间节点。
	t := &Tree{entries: make(map[string]entry)}                                     // Initialize tree / 初始化树
	eroot := t.build(enrEntries)                                                    // Build ENR subtree / 构建 ENR 子树
	t.entries[subdomain(eroot)] = eroot                                             // Add ENR root / 添加 ENR 根
	lroot := t.build(linkEntries)                                                   // Build link subtree / 构建链接子树
	t.entries[subdomain(lroot)] = lroot                                             // Add link root / 添加链接根
	t.root = &rootEntry{seq: seq, eroot: subdomain(eroot), lroot: subdomain(lroot)} // Set tree root / 设置树根
	return t, nil                                                                   // Return tree / 返回树
}

func (t *Tree) build(entries []entry) entry {
	if len(entries) == 1 {
		return entries[0] // Return single entry / 返回单个条目
	}
	if len(entries) <= maxChildren { // If within max children / 如果在最大子节点数内
		hashes := make([]string, len(entries))
		for i, e := range entries {
			hashes[i] = subdomain(e) // Get subdomain / 获取子域
			t.entries[hashes[i]] = e // Add to entries / 添加到条目
		}
		return &branchEntry{hashes} // Return branch / 返回分支
	}
	var subtrees []entry
	for len(entries) > 0 { // Build subtrees / 构建子树
		n := maxChildren
		if len(entries) < n {
			n = len(entries) // Adjust size / 调整大小
		}
		sub := t.build(entries[:n])      // Build subtree / 构建子树
		entries = entries[n:]            // Move to next chunk / 移动到下一块
		subtrees = append(subtrees, sub) // Add subtree / 添加子树
		t.entries[subdomain(sub)] = sub  // Add to entries / 添加到条目
	}
	return t.build(subtrees) // Recursively build / 递归构建
}

func sortByID(nodes []*enode.Node) []*enode.Node {
	slices.SortFunc(nodes, func(a, b *enode.Node) int { // Sort by ID / 按 ID 排序
		return bytes.Compare(a.ID().Bytes(), b.ID().Bytes())
	})
	return nodes
}

// Entry Types
// 条目类型
type entry interface {
	fmt.Stringer // Stringer interface / Stringer 接口
}

type (
	rootEntry struct {
		eroot string // ENR subtree root / ENR 子树根
		lroot string // Link subtree root / 链接子树根
		seq   uint   // Sequence number / 序列号
		sig   []byte // Signature / 签名
	}
	branchEntry struct {
		children []string // Child hashes / 子哈希
	}
	enrEntry struct {
		node *enode.Node // ENR node / ENR 节点
	}
	linkEntry struct {
		str    string           // Full string / 完整字符串
		domain string           // Domain name / 域名
		pubkey *ecdsa.PublicKey // Public key / 公钥
	}
)

// Entry Encoding
// 条目编码
var (
	b32format = base32.StdEncoding.WithPadding(base32.NoPadding) // Base32 encoding / Base32 编码
	b64format = base64.RawURLEncoding                            // Base64 encoding / Base64 编码
)

const (
	rootPrefix   = "enrtree-root:v1" // Root prefix / 根前缀
	linkPrefix   = "enrtree://"      // Link prefix / 链接前缀
	branchPrefix = "enrtree-branch:" // Branch prefix / 分支前缀
	enrPrefix    = "enr:"            // ENR prefix / ENR 前缀
)

func subdomain(e entry) string {
	h := sha3.NewLegacyKeccak256()                   // Create Keccak256 hash / 创建 Keccak256 哈希
	io.WriteString(h, e.String())                    // Hash entry string / 哈希条目字符串
	return b32format.EncodeToString(h.Sum(nil)[:16]) // Return base32-encoded hash / 返回 base32 编码的哈希
}

func (e *rootEntry) String() string {
	return fmt.Sprintf(rootPrefix+" e=%s l=%s seq=%d sig=%s", e.eroot, e.lroot, e.seq, b64format.EncodeToString(e.sig)) // Format root / 格式化根
}

func (e *rootEntry) sigHash() []byte {
	h := sha3.NewLegacyKeccak256()                                          // Create Keccak256 hash / 创建 Keccak256 哈希
	fmt.Fprintf(h, rootPrefix+" e=%s l=%s seq=%d", e.eroot, e.lroot, e.seq) // Hash root data / 哈希根数据
	return h.Sum(nil)                                                       // Return hash / 返回哈希
}

func (e *rootEntry) verifySignature(pubkey *ecdsa.PublicKey) bool {
	sig := e.sig[:crypto.RecoveryIDOffset]                  // Remove recovery ID / 移除恢复 ID
	enckey := crypto.FromECDSAPub(pubkey)                   // Encode public key / 编码公钥
	return crypto.VerifySignature(enckey, e.sigHash(), sig) // Verify signature / 验证签名
}

func (e *branchEntry) String() string {
	return branchPrefix + strings.Join(e.children, ",") // Join children with commas / 用逗号连接子节点
}

func (e *enrEntry) String() string {
	return e.node.String() // Return node string / 返回节点字符串
}

func (e *linkEntry) String() string {
	return linkPrefix + e.str // Return link string / 返回链接字符串
}

func newLinkEntry(domain string, pubkey *ecdsa.PublicKey) *linkEntry {
	key := b32format.EncodeToString(crypto.CompressPubkey(pubkey)) // Encode public key / 编码公钥
	str := key + "@" + domain                                      // Create link string / 创建链接字符串
	return &linkEntry{str, domain, pubkey}                         // Return link entry / 返回链接条目
}

// Entry Parsing
// 条目解析
func parseEntry(e string, validSchemes enr.IdentityScheme) (entry, error) {
	switch {
	case strings.HasPrefix(e, linkPrefix):
		return parseLinkEntry(e) // Parse link / 解析链接
	case strings.HasPrefix(e, branchPrefix):
		return parseBranch(e) // Parse branch / 解析分支
	case strings.HasPrefix(e, enrPrefix):
		return parseENR(e, validSchemes) // Parse ENR / 解析 ENR
	default:
		return nil, errUnknownEntry // Unknown entry / 未知条目
	}
}

func parseRoot(e string) (rootEntry, error) {
	var eroot, lroot, sig string
	var seq uint
	if _, err := fmt.Sscanf(e, rootPrefix+" e=%s l=%s seq=%d sig=%s", &eroot, &lroot, &seq, &sig); err != nil { // Parse root / 解析根
		return rootEntry{}, entryError{"root", errSyntax} // Return syntax error / 返回语法错误
	}
	if !isValidHash(eroot) || !isValidHash(lroot) { // Check hashes / 检查哈希
		return rootEntry{}, entryError{"root", errInvalidChild} // Return invalid child error / 返回无效子错误
	}
	sigb, err := b64format.DecodeString(sig) // Decode signature / 解码签名
	if err != nil || len(sigb) != crypto.SignatureLength {
		return rootEntry{}, entryError{"root", errInvalidSig} // Return invalid signature error / 返回无效签名错误
	}
	return rootEntry{eroot, lroot, seq, sigb}, nil // Return root entry / 返回根条目
}

func parseLinkEntry(e string) (entry, error) {
	le, err := parseLink(e) // Parse link / 解析链接
	if err != nil {
		return nil, err // Return error / 返回错误
	}
	return le, nil // Return link entry / 返回链接条目
}

func parseLink(e string) (*linkEntry, error) {
	if !strings.HasPrefix(e, linkPrefix) {
		return nil, errors.New("wrong/missing scheme 'enrtree' in URL") // Check prefix / 检查前缀
	}
	e = e[len(linkPrefix):] // Remove prefix / 移除前缀

	keystring, domain, found := strings.Cut(e, "@") // Split key and domain / 分割密钥和域名
	if !found {
		return nil, entryError{"link", errNoPubkey} // Return no pubkey error / 返回无公钥错误
	}
	keybytes, err := b32format.DecodeString(keystring) // Decode key / 解码密钥
	if err != nil {
		return nil, entryError{"link", errBadPubkey} // Return bad pubkey error / 返回无效公钥错误
	}
	key, err := crypto.DecompressPubkey(keybytes) // Decompress key / 解压密钥
	if err != nil {
		return nil, entryError{"link", errBadPubkey} // Return bad pubkey error / 返回无效公钥错误
	}
	return &linkEntry{e, domain, key}, nil // Return link entry / 返回链接条目
}

func parseBranch(e string) (entry, error) {
	e = e[len(branchPrefix):] // Remove prefix / 移除前缀
	if e == "" {
		return &branchEntry{}, nil // Return empty branch / 返回空分支
	}
	hashes := make([]string, 0, strings.Count(e, ",")) // Initialize hashes / 初始化哈希
	for _, c := range strings.Split(e, ",") {          // Split children / 分割子节点
		if !isValidHash(c) {
			return nil, entryError{"branch", errInvalidChild} // Return invalid child error / 返回无效子错误
		}
		hashes = append(hashes, c) // Add hash / 添加哈希
	}
	return &branchEntry{hashes}, nil // Return branch entry / 返回分支条目
}

func parseENR(e string, validSchemes enr.IdentityScheme) (entry, error) {
	e = e[len(enrPrefix):]                // Remove prefix / 移除前缀
	enc, err := b64format.DecodeString(e) // Decode ENR / 解码 ENR
	if err != nil {
		return nil, entryError{"enr", errInvalidENR} // Return invalid ENR error / 返回无效 ENR 错误
	}
	var rec enr.Record
	if err := rlp.DecodeBytes(enc, &rec); err != nil { // Decode RLP / 解码 RLP
		return nil, entryError{"enr", err} // Return error / 返回错误
	}
	n, err := enode.New(validSchemes, &rec) // Create node / 创建节点
	if err != nil {
		return nil, entryError{"enr", err} // Return error / 返回错误
	}
	return &enrEntry{n}, nil // Return ENR entry / 返回 ENR 条目
}

func isValidHash(s string) bool {
	dlen := b32format.DecodedLen(len(s))
	if dlen < minHashLength || dlen > 32 || strings.ContainsAny(s, "\n\r") { // Check hash length and content / 检查哈希长度和内容
		return false
	}
	buf := make([]byte, 32)
	_, err := b32format.Decode(buf, []byte(s)) // Decode hash / 解码哈希
	return err == nil                          // Return validity / 返回有效性
}

// truncateHash truncates the given base32 hash string to the minimum acceptable length.
// truncateHash 将给定的 base32 哈希字符串截断到最小可接受长度。
func truncateHash(hash string) string {
	maxLen := b32format.EncodedLen(minHashLength)
	if len(hash) < maxLen {
		panic(fmt.Errorf("dnsdisc: hash %q is too short", hash)) // Panic if too short / 如果太短则抛出异常
	}
	return hash[:maxLen] // Return truncated hash / 返回截断的哈希
}

// URL encoding
// URL 编码

// ParseURL parses an enrtree:// URL and returns its components.
// ParseURL 解析 enrtree:// URL 并返回其组件。
func ParseURL(url string) (domain string, pubkey *ecdsa.PublicKey, err error) {
	le, err := parseLink(url) // Parse link / 解析链接
	if err != nil {
		return "", nil, err // Return error / 返回错误
	}
	return le.domain, le.pubkey, nil // Return domain and pubkey / 返回域名和公钥
}
