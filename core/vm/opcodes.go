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

package vm

import (
	"fmt"
)

// Gas 机制：每个操作码有固定和动态 gas 成本（未在此代码中定义，但与 operation 结构体相关），防止无限循环和资源滥用。
// 硬分叉与 EIP：代码中的新操作码（如 PUSH0、BLOBHASH）反映了以太坊通过 EIP 持续改进，例如 EIP-1559（费用市场）、EIP-4844（分片）。
// 合并（The Merge）：从 PoW（工作量证明）转向 PoS（权益证明）后，DIFFICULTY 被 PREVRANDAO 取代，体现了以太坊对信标链的依赖。

// EVM 的栈架构：EVM 使用 256 位字长的栈，最大深度 1024，操作码设计围绕栈操作优化。
// 字节码生成：Solidity 等语言编译为 EVM 字节码，PUSH 操作码常用于加载常量。

// 关键操作码与 EIP 的关系
//  基本操作码（0x00–0x1d）：
//   - 如 ADD、MUL、SHL 等，这些是 EVM 的基础算术和位操作，源自以太坊初版（Frontier）。黄皮书中定义了它们的栈行为，例如 ADD 消耗 2 个栈项（输入），产生 1 个栈项（结果）。
//   - SHL、SHR、SAR（0x1b–0x1d）由 EIP-145（Constantinople 硬分叉）引入，增加了位操作能力，提升了智能合约的计算效率。
//  加密操作（0x20）：
//   - KECCAK256 是 EVM 的核心哈希函数，用于生成唯一标识符（如事件签名）。以太坊采用 Keccak-256（SHA-3 的变种），在白皮书中被定义为智能合约和交易验证的基础。
//  状态访问（0x30–0x3f）：
//   - ADDRESS、BALANCE 等操作码访问执行上下文和区块链状态，体现了以太坊“世界计算机”的设计。黄皮书中定义了这些操作码的 gas 成本，例如 BALANCE 在 EIP-1884 中被重新定价以防止 DoS 攻击。
//   - EXTCODEHASH（EIP-1052，Constantinople）允许获取外部合约的代码哈希，提升了安全性检查能力。
//  区块信息（0x40–0x4a）：
//   - BLOCKHASH、COINBASE 等提供对当前区块的访问，源自以太坊初始设计。
//   - BASEFEE（EIP-3198，London 硬分叉）支持 EIP-1559 的动态 gas 费用机制。
//   - BLOBHASH 和 BLOBBASEFEE（EIP-4844，Cancun 硬分叉）引入了数据分片（sharding）支持，优化了 Rollup 的成本。
//   - PREVRANDAO（0x44）在 Merge（合并）后取代了 DIFFICULTY，提供来自信标链的随机值（EIP-4399）。
//  存储与执行（0x50–0x5f）：
//   - SLOAD 和 SSTORE 访问持久化存储，gas 成本在 EIP-2200（Istanbul）中优化。
//   - TLOAD 和 TSTORE（EIP-1153，Cancun）引入临时存储，仅在交易生命周期内有效，降低成本。
//   - PUSH0（EIP-3855，Shanghai）添加了对 0 的直接推送支持，优化了字节码大小。
//  栈操作（0x60–0x9f）：
//   - PUSH1 到 PUSH32、DUP1 到 DUP16、SWAP1 到 SWAP16 是 EVM 基于栈架构的核心操作，符合黄皮书中描述的栈深度限制（1024 项）。
//  日志（0xa0–0xa4）：
//   - LOG0 到 LOG4 用于事件记录，是以太坊智能合约与外部交互的关键机制，白皮书中定义了其重要性。
//  EOF 操作（0xd0 和 0xe0 范围）：
//   - DATALOAD、RJUMP 等属于 EIP-3540（EOF，Ethereum Object Format）的实验性操作，旨在改进字节码结构化和验证，尚未完全上线。
//  闭合操作（0xf0–0xff）：
//   - CREATE 和 CALL 是以太坊合约创建和调用的基础。
//   - CREATE2（EIP-1014，Constantinople）引入确定性地址生成。
//   - DELEGATECALL（EIP-7，Homestead）支持代理合约模式。
//   - SELFDESTRUCT 在 EIP-6780（Cancun）中被限制，仅在同一交易内有效，减少状态膨胀。
// 代码功能的解释
//  OpCode 类型：定义为单字节（0x00–0xFF），与黄皮书的字节码规范一致。
//  IsPush 方法：检查是否为 PUSH 操作码（带立即数），尽管标记为过时，反映了 EVM 设计的演变。
//  opCodeToString 和 String()：提供调试和反汇编支持，将字节码转换为人类可读的字符串。
//  stringToOp 和 StringToOp()：支持从字符串到操作码的反向映射，便于开发和测试。

// OpCode is an EVM opcode
// OpCode 是一个 EVM 操作码
type OpCode byte

// IsPush specifies if an opcode is a PUSH opcode.
// @deprecated: this method is often used in order to know if there are immediates.
// Please use `vm.Immediates` instead.
// IsPush 指定一个操作码是否为 PUSH 操作码。
// @deprecated: 此方法常用于判断是否存在立即数。
// 请改用 `vm.Immediates`。
func (op OpCode) IsPush() bool {
	// 判断操作码是否在 PUSH0 到 PUSH32 范围内，表示这是一个 PUSH 操作码
	return PUSH0 <= op && op <= PUSH32
}

// 0x0 range - arithmetic ops.
// 0x0 范围 - 算术操作
const (
	STOP       OpCode = 0x0 // 停止执行
	ADD        OpCode = 0x1 // 加法
	MUL        OpCode = 0x2 // 乘法
	SUB        OpCode = 0x3 // 减法
	DIV        OpCode = 0x4 // 除法
	SDIV       OpCode = 0x5 // 有符号除法
	MOD        OpCode = 0x6 // 取模
	SMOD       OpCode = 0x7 // 有符号取模
	ADDMOD     OpCode = 0x8 // 加法后取模
	MULMOD     OpCode = 0x9 // 乘法后取模
	EXP        OpCode = 0xa // 指数运算
	SIGNEXTEND OpCode = 0xb // 符号扩展
)

// 0x10 range - comparison ops.
// 0x10 范围 - 比较操作
const (
	LT     OpCode = 0x10 // 小于
	GT     OpCode = 0x11 // 大于
	SLT    OpCode = 0x12 // 有符号小于
	SGT    OpCode = 0x13 // 有符号大于
	EQ     OpCode = 0x14 // 等于
	ISZERO OpCode = 0x15 // 是否为零
	AND    OpCode = 0x16 // 位与
	OR     OpCode = 0x17 // 位或
	XOR    OpCode = 0x18 // 位异或
	NOT    OpCode = 0x19 // 位非
	BYTE   OpCode = 0x1a // 提取字节
	SHL    OpCode = 0x1b // 左移
	SHR    OpCode = 0x1c // 右移
	SAR    OpCode = 0x1d // 有符号右移
)

// 0x20 range - crypto.
// 0x20 范围 - 加密操作
const (
	KECCAK256 OpCode = 0x20 // 计算 Keccak-256 哈希
)

// 0x30 range - closure state.
// 0x30 范围 - 闭合状态
const (
	ADDRESS        OpCode = 0x30 // 获取当前合约地址
	BALANCE        OpCode = 0x31 // 获取账户余额
	ORIGIN         OpCode = 0x32 // 获取交易发起者地址
	CALLER         OpCode = 0x33 // 获取调用者地址
	CALLVALUE      OpCode = 0x34 // 获取调用附带的以太币值
	CALLDATALOAD   OpCode = 0x35 // 加载调用数据
	CALLDATASIZE   OpCode = 0x36 // 获取调用数据大小
	CALLDATACOPY   OpCode = 0x37 // 复制调用数据
	CODESIZE       OpCode = 0x38 // 获取代码大小
	CODECOPY       OpCode = 0x39 // 复制代码
	GASPRICE       OpCode = 0x3a // 获取当前 gas 价格
	EXTCODESIZE    OpCode = 0x3b // 获取外部代码大小
	EXTCODECOPY    OpCode = 0x3c // 复制外部代码
	RETURNDATASIZE OpCode = 0x3d // 获取返回数据大小
	RETURNDATACOPY OpCode = 0x3e // 复制返回数据
	EXTCODEHASH    OpCode = 0x3f // 获取外部代码哈希
)

// 0x40 range - block operations.
// 0x40 范围 - 区块操作
const (
	BLOCKHASH   OpCode = 0x40 // 获取区块哈希
	COINBASE    OpCode = 0x41 // 获取区块矿工地址
	TIMESTAMP   OpCode = 0x42 // 获取区块时间戳
	NUMBER      OpCode = 0x43 // 获取区块高度
	DIFFICULTY  OpCode = 0x44 // 获取难度（合并后为 PREVRANDAO）
	RANDOM      OpCode = 0x44 // Same as DIFFICULTY // 与 DIFFICULTY 相同
	PREVRANDAO  OpCode = 0x44 // Same as DIFFICULTY // 与 DIFFICULTY 相同 // 获取前一随机值
	GASLIMIT    OpCode = 0x45 // 获取 gas 限制
	CHAINID     OpCode = 0x46 // 获取链 ID
	SELFBALANCE OpCode = 0x47 // 获取自身余额
	BASEFEE     OpCode = 0x48 // 获取基础费用
	BLOBHASH    OpCode = 0x49 // 获取 Blob 哈希
	BLOBBASEFEE OpCode = 0x4a // 获取 Blob 基础费用
)

// 0x50 range - 'storage' and execution.
// 0x50 范围 - “存储”和执行
const (
	POP      OpCode = 0x50 // 弹出栈顶元素
	MLOAD    OpCode = 0x51 // 从内存加载
	MSTORE   OpCode = 0x52 // 存储到内存
	MSTORE8  OpCode = 0x53 // 存储 8 位到内存
	SLOAD    OpCode = 0x54 // 从存储加载
	SSTORE   OpCode = 0x55 // 存储到存储
	JUMP     OpCode = 0x56 // 跳转
	JUMPI    OpCode = 0x57 // 条件跳转
	PC       OpCode = 0x58 // 获取程序计数器
	MSIZE    OpCode = 0x59 // 获取内存大小
	GAS      OpCode = 0x5a // 获取剩余 gas
	JUMPDEST OpCode = 0x5b // 跳转目标
	TLOAD    OpCode = 0x5c // 从临时存储加载
	TSTORE   OpCode = 0x5d // 存储到临时存储
	MCOPY    OpCode = 0x5e // 内存复制
	PUSH0    OpCode = 0x5f // 推送 0 到栈
)

// 0x60 range - pushes.
// 0x60 范围 - 推送操作
const (
	PUSH1  OpCode = 0x60 + iota // 推送 1 字节到栈
	PUSH2                       // 推送 2 字节到栈
	PUSH3                       // 推送 3 字节到栈
	PUSH4                       // 推送 4 字节到栈
	PUSH5                       // 推送 5 字节到栈
	PUSH6                       // 推送 6 字节到栈
	PUSH7                       // 推送 7 字节到栈
	PUSH8                       // 推送 8 字节到栈
	PUSH9                       // 推送 9 字节到栈
	PUSH10                      // 推送 10 字节到栈
	PUSH11                      // 推送 11 字节到栈
	PUSH12                      // 推送 12 字节到栈
	PUSH13                      // 推送 13 字节到栈
	PUSH14                      // 推送 14 字节到栈
	PUSH15                      // 推送 15 字节到栈
	PUSH16                      // 推送 16 字节到栈
	PUSH17                      // 推送 17 字节到栈
	PUSH18                      // 推送 18 字节到栈
	PUSH19                      // 推送 19 字节到栈
	PUSH20                      // 推送 20 字节到栈
	PUSH21                      // 推送 21 字节到栈
	PUSH22                      // 推送 22 字节到栈
	PUSH23                      // 推送 23 字节到栈
	PUSH24                      // 推送 24 字节到栈
	PUSH25                      // 推送 25 字节到栈
	PUSH26                      // 推送 26 字节到栈
	PUSH27                      // 推送 27 字节到栈
	PUSH28                      // 推送 28 字节到栈
	PUSH29                      // 推送 29 字节到栈
	PUSH30                      // 推送 30 字节到栈
	PUSH31                      // 推送 31 字节到栈
	PUSH32                      // 推送 32 字节到栈
)

// 0x80 range - dups.
// 0x80 范围 - 复制操作
const (
	DUP1  OpCode = 0x80 + iota // 复制栈顶第 1 项
	DUP2                       // 复制栈顶第 2 项
	DUP3                       // 复制栈顶第 3 项
	DUP4                       // 复制栈顶第 4 项
	DUP5                       // 复制栈顶第 5 项
	DUP6                       // 复制栈顶第 6 项
	DUP7                       // 复制栈顶第 7 项
	DUP8                       // 复制栈顶第 8 项
	DUP9                       // 复制栈顶第 9 项
	DUP10                      // 复制栈顶第 10 项
	DUP11                      // 复制栈顶第 11 项
	DUP12                      // 复制栈顶第 12 项
	DUP13                      // 复制栈顶第 13 项
	DUP14                      // 复制栈顶第 14 项
	DUP15                      // 复制栈顶第 15 项
	DUP16                      // 复制栈顶第 16 项
)

// 0x90 range - swaps.
// 0x90 范围 - 交换操作
const (
	SWAP1  OpCode = 0x90 + iota // 交换栈顶第 1 和第 2 项
	SWAP2                       // 交换栈顶第 1 和第 3 项
	SWAP3                       // 交换栈顶第 1 和第 4 项
	SWAP4                       // 交换栈顶第 1 和第 5 项
	SWAP5                       // 交换栈顶第 1 和第 6 项
	SWAP6                       // 交换栈顶第 1 和第 7 项
	SWAP7                       // 交换栈顶第 1 和第 8 项
	SWAP8                       // 交换栈顶第 1 和第 9 项
	SWAP9                       // 交换栈顶第 1 和第 10 项
	SWAP10                      // 交换栈顶第 1 和第 11 项
	SWAP11                      // 交换栈顶第 1 和第 12 项
	SWAP12                      // 交换栈顶第 1 和第 13 项
	SWAP13                      // 交换栈顶第 1 和第 14 项
	SWAP14                      // 交换栈顶第 1 和第 15 项
	SWAP15                      // 交换栈顶第 1 和第 16 项
	SWAP16                      // 交换栈顶第 1 和第 17 项
)

// 0xa0 range - logging ops.
// 0xa0 范围 - 日志操作
const (
	LOG0 OpCode = 0xa0 + iota // 记录 0 个主题的日志
	LOG1                      // 记录 1 个主题的日志
	LOG2                      // 记录 2 个主题的日志
	LOG3                      // 记录 3 个主题的日志
	LOG4                      // 记录 4 个主题的日志
)

// 0xd0 range - eof operations.
// 0xd0 范围 - EOF 操作
const (
	DATALOAD  OpCode = 0xd0 // 加载数据段
	DATALOADN OpCode = 0xd1 // 加载带偏移的数据
	DATASIZE  OpCode = 0xd2 // 获取数据大小
	DATACOPY  OpCode = 0xd3 // 复制数据
)

// 0xe0 range - eof operations.
// 0xe0 范围 - EOF 操作
const (
	RJUMP          OpCode = 0xe0 // 相对跳转
	RJUMPI         OpCode = 0xe1 // 相对条件跳转
	RJUMPV         OpCode = 0xe2 // 相对跳转表
	CALLF          OpCode = 0xe3 // 调用函数
	RETF           OpCode = 0xe4 // 从函数返回
	JUMPF          OpCode = 0xe5 // 跳转到函数
	DUPN           OpCode = 0xe6 // 复制第 N 项
	SWAPN          OpCode = 0xe7 // 与第 N 项交换
	EXCHANGE       OpCode = 0xe8 // 交换栈项
	EOFCREATE      OpCode = 0xec // 创建 EOF 合约
	RETURNCONTRACT OpCode = 0xee // 返回 EOF 合约
)

// 0xf0 range - closures.
// 0xf0 范围 - 闭合操作
const (
	CREATE       OpCode = 0xf0 // 创建合约
	CALL         OpCode = 0xf1 // 调用合约
	CALLCODE     OpCode = 0xf2 // 调用代码（旧）
	RETURN       OpCode = 0xf3 // 返回执行
	DELEGATECALL OpCode = 0xf4 // 委托调用
	CREATE2      OpCode = 0xf5 // 使用盐创建合约

	RETURNDATALOAD  OpCode = 0xf7 // 加载返回数据
	EXTCALL         OpCode = 0xf8 // 外部调用（EOF）
	EXTDELEGATECALL OpCode = 0xf9 // 外部委托调用（EOF）

	STATICCALL    OpCode = 0xfa // 静态调用
	EXTSTATICCALL OpCode = 0xfb // 外部静态调用（EOF）
	REVERT        OpCode = 0xfd // 回滚执行
	INVALID       OpCode = 0xfe // 无效操作码
	SELFDESTRUCT  OpCode = 0xff // 自毁合约
)

var opCodeToString = [256]string{
	// 0x0 range - arithmetic ops.
	// 0x0 范围 - 算术操作
	STOP:       "STOP",
	ADD:        "ADD",
	MUL:        "MUL",
	SUB:        "SUB",
	DIV:        "DIV",
	SDIV:       "SDIV",
	MOD:        "MOD",
	SMOD:       "SMOD",
	EXP:        "EXP",
	NOT:        "NOT",
	LT:         "LT",
	GT:         "GT",
	SLT:        "SLT",
	SGT:        "SGT",
	EQ:         "EQ",
	ISZERO:     "ISZERO",
	SIGNEXTEND: "SIGNEXTEND",

	// 0x10 range - bit ops.
	// 0x10 范围 - 位操作
	AND:    "AND",
	OR:     "OR",
	XOR:    "XOR",
	BYTE:   "BYTE",
	SHL:    "SHL",
	SHR:    "SHR",
	SAR:    "SAR",
	ADDMOD: "ADDMOD",
	MULMOD: "MULMOD",

	// 0x20 range - crypto.
	// 0x20 范围 - 加密操作
	KECCAK256: "KECCAK256",

	// 0x30 range - closure state.
	// 0x30 范围 - 闭合状态
	ADDRESS:        "ADDRESS",
	BALANCE:        "BALANCE",
	ORIGIN:         "ORIGIN",
	CALLER:         "CALLER",
	CALLVALUE:      "CALLVALUE",
	CALLDATALOAD:   "CALLDATALOAD",
	CALLDATASIZE:   "CALLDATASIZE",
	CALLDATACOPY:   "CALLDATACOPY",
	CODESIZE:       "CODESIZE",
	CODECOPY:       "CODECOPY",
	GASPRICE:       "GASPRICE",
	EXTCODESIZE:    "EXTCODESIZE",
	EXTCODECOPY:    "EXTCODECOPY",
	RETURNDATASIZE: "RETURNDATASIZE",
	RETURNDATACOPY: "RETURNDATACOPY",
	EXTCODEHASH:    "EXTCODEHASH",

	// 0x40 range - block operations.
	// 0x40 范围 - 区块操作
	BLOCKHASH:   "BLOCKHASH",
	COINBASE:    "COINBASE",
	TIMESTAMP:   "TIMESTAMP",
	NUMBER:      "NUMBER",
	DIFFICULTY:  "DIFFICULTY", // TODO (MariusVanDerWijden) rename to PREVRANDAO post merge
	GASLIMIT:    "GASLIMIT",
	CHAINID:     "CHAINID",
	SELFBALANCE: "SELFBALANCE",
	BASEFEE:     "BASEFEE",
	BLOBHASH:    "BLOBHASH",
	BLOBBASEFEE: "BLOBBASEFEE",

	// 0x50 range - 'storage' and execution.
	// 0x50 范围 - “存储”和执行
	POP:      "POP",
	MLOAD:    "MLOAD",
	MSTORE:   "MSTORE",
	MSTORE8:  "MSTORE8",
	SLOAD:    "SLOAD",
	SSTORE:   "SSTORE",
	JUMP:     "JUMP",
	JUMPI:    "JUMPI",
	PC:       "PC",
	MSIZE:    "MSIZE",
	GAS:      "GAS",
	JUMPDEST: "JUMPDEST",
	TLOAD:    "TLOAD",
	TSTORE:   "TSTORE",
	MCOPY:    "MCOPY",
	PUSH0:    "PUSH0",

	// 0x60 range - pushes.
	// 0x60 范围 - 推送操作
	PUSH1:  "PUSH1",
	PUSH2:  "PUSH2",
	PUSH3:  "PUSH3",
	PUSH4:  "PUSH4",
	PUSH5:  "PUSH5",
	PUSH6:  "PUSH6",
	PUSH7:  "PUSH7",
	PUSH8:  "PUSH8",
	PUSH9:  "PUSH9",
	PUSH10: "PUSH10",
	PUSH11: "PUSH11",
	PUSH12: "PUSH12",
	PUSH13: "PUSH13",
	PUSH14: "PUSH14",
	PUSH15: "PUSH15",
	PUSH16: "PUSH16",
	PUSH17: "PUSH17",
	PUSH18: "PUSH18",
	PUSH19: "PUSH19",
	PUSH20: "PUSH20",
	PUSH21: "PUSH21",
	PUSH22: "PUSH22",
	PUSH23: "PUSH23",
	PUSH24: "PUSH24",
	PUSH25: "PUSH25",
	PUSH26: "PUSH26",
	PUSH27: "PUSH27",
	PUSH28: "PUSH28",
	PUSH29: "PUSH29",
	PUSH30: "PUSH30",
	PUSH31: "PUSH31",
	PUSH32: "PUSH32",

	// 0x80 - dups.
	// 0x80 - 复制操作
	DUP1:  "DUP1",
	DUP2:  "DUP2",
	DUP3:  "DUP3",
	DUP4:  "DUP4",
	DUP5:  "DUP5",
	DUP6:  "DUP6",
	DUP7:  "DUP7",
	DUP8:  "DUP8",
	DUP9:  "DUP9",
	DUP10: "DUP10",
	DUP11: "DUP11",
	DUP12: "DUP12",
	DUP13: "DUP13",
	DUP14: "DUP14",
	DUP15: "DUP15",
	DUP16: "DUP16",

	// 0x90 - swaps.
	// 0x90 - 交换操作
	SWAP1:  "SWAP1",
	SWAP2:  "SWAP2",
	SWAP3:  "SWAP3",
	SWAP4:  "SWAP4",
	SWAP5:  "SWAP5",
	SWAP6:  "SWAP6",
	SWAP7:  "SWAP7",
	SWAP8:  "SWAP8",
	SWAP9:  "SWAP9",
	SWAP10: "SWAP10",
	SWAP11: "SWAP11",
	SWAP12: "SWAP12",
	SWAP13: "SWAP13",
	SWAP14: "SWAP14",
	SWAP15: "SWAP15",
	SWAP16: "SWAP16",

	// 0xa0 range - logging ops.
	// 0xa0 范围 - 日志操作
	LOG0: "LOG0",
	LOG1: "LOG1",
	LOG2: "LOG2",
	LOG3: "LOG3",
	LOG4: "LOG4",

	// 0xd range - eof ops.
	// 0xd 范围 - EOF 操作
	DATALOAD:  "DATALOAD",
	DATALOADN: "DATALOADN",
	DATASIZE:  "DATASIZE",
	DATACOPY:  "DATACOPY",

	// 0xe0 range.
	// 0xe0 范围
	RJUMP:          "RJUMP",
	RJUMPI:         "RJUMPI",
	RJUMPV:         "RJUMPV",
	CALLF:          "CALLF",
	RETF:           "RETF",
	JUMPF:          "JUMPF",
	DUPN:           "DUPN",
	SWAPN:          "SWAPN",
	EXCHANGE:       "EXCHANGE",
	EOFCREATE:      "EOFCREATE",
	RETURNCONTRACT: "RETURNCONTRACT",

	// 0xf0 range - closures.
	// 0xf0 范围 - 闭合操作
	CREATE:       "CREATE",
	CALL:         "CALL",
	RETURN:       "RETURN",
	CALLCODE:     "CALLCODE",
	DELEGATECALL: "DELEGATECALL",
	CREATE2:      "CREATE2",

	RETURNDATALOAD:  "RETURNDATALOAD",
	EXTCALL:         "EXTCALL",
	EXTDELEGATECALL: "EXTDELEGATECALL",

	STATICCALL:    "STATICCALL",
	EXTSTATICCALL: "EXTSTATICCALL",
	REVERT:        "REVERT",
	INVALID:       "INVALID",
	SELFDESTRUCT:  "SELFDESTRUCT",
}

// 将操作码转换为字符串表示
func (op OpCode) String() string {
	// 中文注解步骤 1：检查 opCodeToString 中是否有对应的字符串
	if s := opCodeToString[op]; s != "" {
		// 中文注解步骤 2：如果存在，返回该字符串
		return s
	}
	// 中文注解步骤 3：如果不存在，返回格式化的未定义提示
	return fmt.Sprintf("opcode %#x not defined", int(op))
}

// 定义一个从字符串到操作码的映射
var stringToOp = map[string]OpCode{
	"STOP":            STOP,
	"ADD":             ADD,
	"MUL":             MUL,
	"SUB":             SUB,
	"DIV":             DIV,
	"SDIV":            SDIV,
	"MOD":             MOD,
	"SMOD":            SMOD,
	"EXP":             EXP,
	"NOT":             NOT,
	"LT":              LT,
	"GT":              GT,
	"SLT":             SLT,
	"SGT":             SGT,
	"EQ":              EQ,
	"ISZERO":          ISZERO,
	"SIGNEXTEND":      SIGNEXTEND,
	"AND":             AND,
	"OR":              OR,
	"XOR":             XOR,
	"BYTE":            BYTE,
	"SHL":             SHL,
	"SHR":             SHR,
	"SAR":             SAR,
	"ADDMOD":          ADDMOD,
	"MULMOD":          MULMOD,
	"KECCAK256":       KECCAK256,
	"ADDRESS":         ADDRESS,
	"BALANCE":         BALANCE,
	"ORIGIN":          ORIGIN,
	"CALLER":          CALLER,
	"CALLVALUE":       CALLVALUE,
	"CALLDATALOAD":    CALLDATALOAD,
	"CALLDATASIZE":    CALLDATASIZE,
	"CALLDATACOPY":    CALLDATACOPY,
	"CHAINID":         CHAINID,
	"BASEFEE":         BASEFEE,
	"BLOBHASH":        BLOBHASH,
	"BLOBBASEFEE":     BLOBBASEFEE,
	"DELEGATECALL":    DELEGATECALL,
	"STATICCALL":      STATICCALL,
	"CODESIZE":        CODESIZE,
	"CODECOPY":        CODECOPY,
	"GASPRICE":        GASPRICE,
	"EXTCODESIZE":     EXTCODESIZE,
	"EXTCODECOPY":     EXTCODECOPY,
	"RETURNDATASIZE":  RETURNDATASIZE,
	"RETURNDATACOPY":  RETURNDATACOPY,
	"EXTCODEHASH":     EXTCODEHASH,
	"BLOCKHASH":       BLOCKHASH,
	"COINBASE":        COINBASE,
	"TIMESTAMP":       TIMESTAMP,
	"NUMBER":          NUMBER,
	"DIFFICULTY":      DIFFICULTY,
	"GASLIMIT":        GASLIMIT,
	"SELFBALANCE":     SELFBALANCE,
	"POP":             POP,
	"MLOAD":           MLOAD,
	"MSTORE":          MSTORE,
	"MSTORE8":         MSTORE8,
	"SLOAD":           SLOAD,
	"SSTORE":          SSTORE,
	"JUMP":            JUMP,
	"JUMPI":           JUMPI,
	"PC":              PC,
	"MSIZE":           MSIZE,
	"GAS":             GAS,
	"JUMPDEST":        JUMPDEST,
	"TLOAD":           TLOAD,
	"TSTORE":          TSTORE,
	"MCOPY":           MCOPY,
	"PUSH0":           PUSH0,
	"PUSH1":           PUSH1,
	"PUSH2":           PUSH2,
	"PUSH3":           PUSH3,
	"PUSH4":           PUSH4,
	"PUSH5":           PUSH5,
	"PUSH6":           PUSH6,
	"PUSH7":           PUSH7,
	"PUSH8":           PUSH8,
	"PUSH9":           PUSH9,
	"PUSH10":          PUSH10,
	"PUSH11":          PUSH11,
	"PUSH12":          PUSH12,
	"PUSH13":          PUSH13,
	"PUSH14":          PUSH14,
	"PUSH15":          PUSH15,
	"PUSH16":          PUSH16,
	"PUSH17":          PUSH17,
	"PUSH18":          PUSH18,
	"PUSH19":          PUSH19,
	"PUSH20":          PUSH20,
	"PUSH21":          PUSH21,
	"PUSH22":          PUSH22,
	"PUSH23":          PUSH23,
	"PUSH24":          PUSH24,
	"PUSH25":          PUSH25,
	"PUSH26":          PUSH26,
	"PUSH27":          PUSH27,
	"PUSH28":          PUSH28,
	"PUSH29":          PUSH29,
	"PUSH30":          PUSH30,
	"PUSH31":          PUSH31,
	"PUSH32":          PUSH32,
	"DUP1":            DUP1,
	"DUP2":            DUP2,
	"DUP3":            DUP3,
	"DUP4":            DUP4,
	"DUP5":            DUP5,
	"DUP6":            DUP6,
	"DUP7":            DUP7,
	"DUP8":            DUP8,
	"DUP9":            DUP9,
	"DUP10":           DUP10,
	"DUP11":           DUP11,
	"DUP12":           DUP12,
	"DUP13":           DUP13,
	"DUP14":           DUP14,
	"DUP15":           DUP15,
	"DUP16":           DUP16,
	"SWAP1":           SWAP1,
	"SWAP2":           SWAP2,
	"SWAP3":           SWAP3,
	"SWAP4":           SWAP4,
	"SWAP5":           SWAP5,
	"SWAP6":           SWAP6,
	"SWAP7":           SWAP7,
	"SWAP8":           SWAP8,
	"SWAP9":           SWAP9,
	"SWAP10":          SWAP10,
	"SWAP11":          SWAP11,
	"SWAP12":          SWAP12,
	"SWAP13":          SWAP13,
	"SWAP14":          SWAP14,
	"SWAP15":          SWAP15,
	"SWAP16":          SWAP16,
	"LOG0":            LOG0,
	"LOG1":            LOG1,
	"LOG2":            LOG2,
	"LOG3":            LOG3,
	"LOG4":            LOG4,
	"DATALOAD":        DATALOAD,
	"DATALOADN":       DATALOADN,
	"DATASIZE":        DATASIZE,
	"DATACOPY":        DATACOPY,
	"RJUMP":           RJUMP,
	"RJUMPI":          RJUMPI,
	"RJUMPV":          RJUMPV,
	"CALLF":           CALLF,
	"RETF":            RETF,
	"JUMPF":           JUMPF,
	"DUPN":            DUPN,
	"SWAPN":           SWAPN,
	"EXCHANGE":        EXCHANGE,
	"EOFCREATE":       EOFCREATE,
	"RETURNCONTRACT":  RETURNCONTRACT,
	"CREATE":          CREATE,
	"CREATE2":         CREATE2,
	"RETURNDATALOAD":  RETURNDATALOAD,
	"EXTCALL":         EXTCALL,
	"EXTDELEGATECALL": EXTDELEGATECALL,
	"EXTSTATICCALL":   EXTSTATICCALL,
	"CALL":            CALL,
	"RETURN":          RETURN,
	"CALLCODE":        CALLCODE,
	"REVERT":          REVERT,
	"INVALID":         INVALID,
	"SELFDESTRUCT":    SELFDESTRUCT,
}

// StringToOp finds the opcode whose name is stored in `str`.
// StringToOp 查找存储在 `str` 中的操作码名称对应的操作码。
func StringToOp(str string) OpCode {
	return stringToOp[str]
}
