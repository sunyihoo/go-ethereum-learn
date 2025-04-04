// Copyright 2015 The go-ethereum Authors
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

package params

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Gas 费用标准化：为以太坊虚拟机（EVM）中的各种操作、指令和预编译合约提供标准的 Gas 费用。
// 系统参数：定义区块 Gas 限制、难度调整、代码大小限制等系统参数。
// EIP 实现：支持多个 EIP 的实现，如 EIP-1559、EIP-2935、EIP-4788 等。
// 系统合约：提供系统合约的地址和字节码，用于实现特定的链上功能。

// Gas 费用：Gas 是以太坊中用于支付执行智能合约和交易的资源单位。每个 EVM 操作都有相应的 Gas 费用，以防止滥用和确保网络安全。
// EIP：以太坊改进提案（Ethereum Improvement Proposal）是社区提出的改进以太坊协议的标准文档。代码中引用的 EIP 包括 EIP-1559（Gas 费用市场改革）、EIP-2935（历史区块哈希服务）、EIP-4788（信标链根）等。
// 系统合约：以太坊中的预编译合约或系统合约，提供特定功能，如椭圆曲线运算、哈希函数等，优化了性能和 Gas 效率。

const (
	GasLimitBoundDivisor uint64 = 1024 // The bound divisor of the gas limit, used in update calculations.
	// GasLimitBoundDivisor 是 gas 限制的边界除数，用于更新计算。
	MinGasLimit uint64 = 5000 // Minimum the gas limit may ever be.
	// MinGasLimit 是 gas 限制的最小值。
	MaxGasLimit uint64 = 0x7fffffffffffffff // Maximum the gas limit (2^63-1).
	// MaxGasLimit 是 gas 限制的最大值（2^63-1）。
	GenesisGasLimit uint64 = 4712388 // Gas limit of the Genesis block.
	// GenesisGasLimit 是创世区块的 gas 限制。

	MaximumExtraDataSize uint64 = 32 // Maximum size extra data may be after Genesis.
	// MaximumExtraDataSize 是创世区块后 extra data 的最大大小。
	ExpByteGas uint64 = 10 // Times ceil(log256(exponent)) for the EXP instruction.
	// ExpByteGas 是 EXP 指令中 ceil(log256(exponent)) 的乘数。
	SloadGas uint64 = 50 // Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added.
	// SloadGas 在任何 *COPY 操作中，按复制的 32 字节字数（向上取整）乘以并相加。
	CallValueTransferGas uint64 = 9000 // Paid for CALL when the value transfer is non-zero.
	// CallValueTransferGas 是 CALL 指令在转账值非零时的 gas 费用。
	CallNewAccountGas uint64 = 25000 // Paid for CALL when the destination address didn't exist prior.
	// CallNewAccountGas 是 CALL 指令在目标地址之前不存在时的 gas 费用。
	TxGas uint64 = 21000 // Per transaction not creating a contract. NOTE: Not payable on data of calls between transactions.
	// TxGas 是每个不创建合约的交易的 gas 费用。注意：不支付交易间调用的数据。
	TxGasContractCreation uint64 = 53000 // Per transaction that creates a contract. NOTE: Not payable on data of calls between transactions.
	// TxGasContractCreation 是每个创建合约的交易的 gas 费用。注意：不支付交易间调用的数据。
	TxDataZeroGas uint64 = 4 // Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions.
	// TxDataZeroGas 是交易附加的每个零字节数据的 gas 费用。注意：不支付交易间调用的数据。
	QuadCoeffDiv uint64 = 512 // Divisor for the quadratic particle of the memory cost equation.
	// QuadCoeffDiv 是内存成本方程中二次项的除数。
	LogDataGas uint64 = 8 // Per byte in a LOG* operation's data.
	// LogDataGas 是 LOG* 操作中数据的每个字节的 gas 费用。
	CallStipend uint64 = 2300 // Free gas given at beginning of call.
	// CallStipend 是调用开始时提供的免费 gas。

	Keccak256Gas uint64 = 30 // Once per KECCAK256 operation.
	// Keccak256Gas 是每个 KECCAK256 操作的 gas 费用。
	Keccak256WordGas uint64 = 6 // Once per word of the KECCAK256 operation's data.
	// Keccak256WordGas 是 KECCAK256 操作数据中每个字的 gas 费用。
	InitCodeWordGas uint64 = 2 // Once per word of the init code when creating a contract.
	// InitCodeWordGas 是创建合约时初始化代码中每个字的 gas 费用。

	SstoreSetGas uint64 = 20000 // Once per SSTORE operation.
	// SstoreSetGas 是每个 SSTORE 操作的 gas 费用。
	SstoreResetGas uint64 = 5000 // Once per SSTORE operation if the zeroness changes from zero.
	// SstoreResetGas 是 SSTORE 操作中 zeroness 从零改变时的 gas 费用。
	SstoreClearGas uint64 = 5000 // Once per SSTORE operation if the zeroness doesn't change.
	// SstoreClearGas 是 SSTORE 操作中 zeroness 不改变时的 gas 费用。
	SstoreRefundGas uint64 = 15000 // Once per SSTORE operation if the zeroness changes to zero.
	// SstoreRefundGas 是 SSTORE 操作中 zeroness 变为零时的 gas 退款。

	NetSstoreNoopGas uint64 = 200 // Once per SSTORE operation if the value doesn't change.
	// NetSstoreNoopGas 是 SSTORE 操作中值不改变时的 gas 费用。
	NetSstoreInitGas uint64 = 20000 // Once per SSTORE operation from clean zero.
	// NetSstoreInitGas 是从干净的零开始的 SSTORE 操作的 gas 费用。
	NetSstoreCleanGas uint64 = 5000 // Once per SSTORE operation from clean non-zero.
	// NetSstoreCleanGas 是从干净的非零开始的 SSTORE 操作的 gas 费用。
	NetSstoreDirtyGas uint64 = 200 // Once per SSTORE operation from dirty.
	// NetSstoreDirtyGas 是从脏状态开始的 SSTORE 操作的 gas 费用。

	NetSstoreClearRefund uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot
	// NetSstoreClearRefund 是清除原始存在的存储槽的 SSTORE 操作的 gas 退款。
	NetSstoreResetRefund uint64 = 4800 // Once per SSTORE operation for resetting to the original non-zero value
	// NetSstoreResetRefund 是重置为原始非零值的 SSTORE 操作的 gas 退款。
	NetSstoreResetClearRefund uint64 = 19800 // Once per SSTORE operation for resetting to the original zero value
	// NetSstoreResetClearRefund 是重置为原始零值的 SSTORE 操作的 gas 退款。

	SstoreSentryGasEIP2200 uint64 = 2300 // Minimum gas required to be present for an SSTORE call, not consumed
	// SstoreSentryGasEIP2200 是 SSTORE 调用所需的最小 gas，不消耗。
	SstoreSetGasEIP2200 uint64 = 20000 // Once per SSTORE operation from clean zero to non-zero
	// SstoreSetGasEIP2200 是从干净的零到非零的 SSTORE 操作的 gas 费用。
	SstoreResetGasEIP2200 uint64 = 5000 // Once per SSTORE operation from clean non-zero to something else
	// SstoreResetGasEIP2200 是从干净的非零到其他值的 SSTORE 操作的 gas 费用。
	SstoreClearsScheduleRefundEIP2200 uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot
	// SstoreClearsScheduleRefundEIP2200 是清除原始存在的存储槽的 SSTORE 操作的 gas 退款。

	ColdAccountAccessCostEIP2929 = uint64(2600) // COLD_ACCOUNT_ACCESS_COST
	// ColdAccountAccessCostEIP2929 是 EIP-2929 中的冷账户访问成本。
	ColdSloadCostEIP2929 = uint64(2100) // COLD_SLOAD_COST
	// ColdSloadCostEIP2929 是 EIP-2929 中的冷 SLOAD 成本。
	WarmStorageReadCostEIP2929 = uint64(100) // WARM_STORAGE_READ_COST
	// WarmStorageReadCostEIP2929 是 EIP-2929 中的热存储读取成本。

	// In EIP-2200: SstoreResetGas was 5000.
	// In EIP-2929: SstoreResetGas was changed to '5000 - COLD_SLOAD_COST'.
	// In EIP-3529: SSTORE_CLEARS_SCHEDULE is defined as SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST
	// Which becomes: 5000 - 2100 + 1900 = 4800
	SstoreClearsScheduleRefundEIP3529 uint64 = SstoreResetGasEIP2200 - ColdSloadCostEIP2929 + TxAccessListStorageKeyGas
	// SstoreClearsScheduleRefundEIP3529 是 EIP-3529 中 SSTORE_CLEARS_SCHEDULE 的退款，计算为 SstoreResetGasEIP2200 - ColdSloadCostEIP2929 + TxAccessListStorageKeyGas。

	JumpdestGas uint64 = 1 // Once per JUMPDEST operation.
	// JumpdestGas 是每个 JUMPDEST 操作的 gas 费用。
	EpochDuration uint64 = 30000 // Duration between proof-of-work epochs.
	// EpochDuration 是工作量证明 epoch 之间的持续时间。

	CreateDataGas uint64 = 200 // Gas cost per byte of data in contract creation
	// CreateDataGas 是合约创建中数据的每个字节的 gas 费用。
	CallCreateDepth uint64 = 1024 // Maximum depth of call/create stack.
	// CallCreateDepth 是 call/create 栈的最大深度。
	ExpGas uint64 = 10 // Once per EXP instruction
	// ExpGas 是每个 EXP 指令的 gas 费用。
	LogGas uint64 = 375 // Per LOG* operation.
	// LogGas 是每个 LOG* 操作的 gas 费用。
	CopyGas uint64 = 3 // Gas cost per word for memory copy operations
	// CopyGas 是内存复制操作中每个字的 gas 费用。
	StackLimit uint64 = 1024 // Maximum size of VM stack allowed.
	// StackLimit 是 VM 栈允许的最大大小。
	TierStepGas uint64 = 0 // Once per operation, for a selection of them.
	// TierStepGas 是某些操作的每个操作的 gas 费用。
	LogTopicGas uint64 = 375 // Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas.
	// LogTopicGas 是 LOG* 操作中每个主题的 gas 费用。
	CreateGas uint64 = 32000 // Once per CREATE operation & contract-creation transaction.
	// CreateGas 是每个 CREATE 操作和合约创建交易的 gas 费用。
	Create2Gas uint64 = 32000 // Once per CREATE2 operation
	// Create2Gas 是每个 CREATE2 操作的 gas 费用。
	CreateNGasEip4762 uint64 = 1000 // Once per CREATEn operations post-verkle
	// CreateNGasEip4762 是 post-verkle 后 CREATEn 操作的 gas 费用。
	SelfdestructRefundGas uint64 = 24000 // Refunded following a selfdestruct operation.
	// SelfdestructRefundGas 是 selfdestruct 操作后的 gas 退款。
	MemoryGas uint64 = 3 // Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL.
	// MemoryGas 是内存中（最高引用的字节地址 + 1）的倍数。注意：引用发生在读取、写入和 RETURN、CALL 等指令中。

	TxDataNonZeroGasFrontier uint64 = 68 // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions.
	// TxDataNonZeroGasFrontier 是 Frontier 中交易附加的每个非零字节数据的 gas 费用。
	TxDataNonZeroGasEIP2028 uint64 = 16 // Per byte of non zero data attached to a transaction after EIP 2028 (part in Istanbul)
	// TxDataNonZeroGasEIP2028 是 EIP 2028 后交易附加的每个非零字节数据的 gas 费用。
	TxAccessListAddressGas uint64 = 2400 // Per address specified in EIP 2930 access list
	// TxAccessListAddressGas 是 EIP 2930 访问列表中每个地址的 gas 费用。
	TxAccessListStorageKeyGas uint64 = 1900 // Per storage key specified in EIP 2930 access list
	// TxAccessListStorageKeyGas 是 EIP 2930 访问列表中每个存储键的 gas 费用。
	TxAuthTupleGas uint64 = 12500 // Per auth tuple code specified in EIP-7702
	// TxAuthTupleGas 是 EIP-7702 中每个授权元组代码的 gas 费用。

	// These have been changed during the course of the chain
	CallGasFrontier uint64 = 40 // Once per CALL operation & message call transaction.
	// CallGasFrontier 是 Frontier 中每个 CALL 操作和消息调用交易的 gas 费用。
	CallGasEIP150 uint64 = 700 // Static portion of gas for CALL-derivates after EIP 150 (Tangerine)
	// CallGasEIP150 是 EIP 150 后 CALL 衍生操作的静态 gas 部分。
	BalanceGasFrontier uint64 = 20 // The cost of a BALANCE operation
	// BalanceGasFrontier 是 Frontier 中 BALANCE 操作的 gas 费用。
	BalanceGasEIP150 uint64 = 400 // The cost of a BALANCE operation after Tangerine
	// BalanceGasEIP150 是 Tangerine 后 BALANCE 操作的 gas 费用。
	BalanceGasEIP1884 uint64 = 700 // The cost of a BALANCE operation after EIP 1884 (part of Istanbul)
	// BalanceGasEIP1884 是 EIP 1884 后 BALANCE 操作的 gas 费用。
	ExtcodeSizeGasFrontier uint64 = 20 // Cost of EXTCODESIZE before EIP 150 (Tangerine)
	// ExtcodeSizeGasFrontier 是 EIP 150 前 EXTCODESIZE 的 gas 费用。
	ExtcodeSizeGasEIP150 uint64 = 700 // Cost of EXTCODESIZE after EIP 150 (Tangerine)
	// ExtcodeSizeGasEIP150 是 EIP 150 后 EXTCODESIZE 的 gas 费用。
	SloadGasFrontier uint64 = 50
	// SloadGasFrontier 是 Frontier 中 SLOAD 的 gas 费用。
	SloadGasEIP150 uint64 = 200
	// SloadGasEIP150 是 EIP 150 中 SLOAD 的 gas 费用。
	SloadGasEIP1884 uint64 = 800 // Cost of SLOAD after EIP 1884 (part of Istanbul)
	// SloadGasEIP1884 是 EIP 1884 后 SLOAD 的 gas 费用。
	SloadGasEIP2200 uint64 = 800 // Cost of SLOAD after EIP 2200 (part of Istanbul)
	// SloadGasEIP2200 是 EIP 2200 后 SLOAD 的 gas 费用。
	ExtcodeHashGasConstantinople uint64 = 400 // Cost of EXTCODEHASH (introduced in Constantinople)
	// ExtcodeHashGasConstantinople 是 Constantinople 中 EXTCODEHASH 的 gas 费用。
	ExtcodeHashGasEIP1884 uint64 = 700 // Cost of EXTCODEHASH after EIP 1884 (part in Istanbul)
	// ExtcodeHashGasEIP1884 是 EIP 1884 后 EXTCODEHASH 的 gas 费用。
	SelfdestructGasEIP150 uint64 = 5000 // Cost of SELFDESTRUCT post EIP 150 (Tangerine)
	// SelfdestructGasEIP150 是 EIP 150 后 SELFDESTRUCT 的 gas 费用。

	// EXP has a dynamic portion depending on the size of the exponent
	ExpByteFrontier uint64 = 10 // was set to 10 in Frontier
	// ExpByteFrontier 是 Frontier 中 EXP 指令的字节 gas 费用。
	ExpByteEIP158 uint64 = 50 // was raised to 50 during Eip158 (Spurious Dragon)
	// ExpByteEIP158 是 EIP158 后 EXP 指令的字节 gas 费用。

	// Extcodecopy has a dynamic AND a static cost. This represents only the
	// static portion of the gas. It was changed during EIP 150 (Tangerine)
	ExtcodeCopyBaseFrontier uint64 = 20
	// ExtcodeCopyBaseFrontier 是 Frontier 中 EXTCODECOPY 的基础 gas 费用。
	ExtcodeCopyBaseEIP150 uint64 = 700
	// ExtcodeCopyBaseEIP150 是 EIP 150 后 EXTCODECOPY 的基础 gas 费用。

	// CreateBySelfdestructGas is used when the refunded account is one that does
	// not exist. This logic is similar to call.
	// Introduced in Tangerine Whistle (Eip 150)
	CreateBySelfdestructGas uint64 = 25000
	// CreateBySelfdestructGas 是通过 SELFDESTRUCT 创建账户时的 gas 费用，类似于 call。

	DefaultBaseFeeChangeDenominator = 8 // Bounds the amount the base fee can change between blocks.
	// DefaultBaseFeeChangeDenominator 是基础费用在区块间变化的边界。
	DefaultElasticityMultiplier = 2 // Bounds the maximum gas limit an EIP-1559 block may have.
	// DefaultElasticityMultiplier 是 EIP-1559 区块的最大 gas 限制的边界。
	InitialBaseFee = 1000000000 // Initial base fee for EIP-1559 blocks.
	// InitialBaseFee 是 EIP-1559 区块的初始基础费用。

	MaxCodeSize = 24576 // Maximum bytecode to permit for a contract
	// MaxCodeSize 是合约允许的最大字节码大小。
	MaxInitCodeSize = 2 * MaxCodeSize // Maximum initcode to permit in a creation transaction and create instructions
	// MaxInitCodeSize 是创建交易和 create 指令中允许的最大初始化代码大小。

	// Precompiled contract gas prices

	EcrecoverGas uint64 = 3000 // Elliptic curve sender recovery gas price
	// EcrecoverGas 是椭圆曲线发送者恢复的 gas 价格。
	Sha256BaseGas uint64 = 60 // Base price for a SHA256 operation
	// Sha256BaseGas 是 SHA256 操作的基础 gas 价格。
	Sha256PerWordGas uint64 = 12 // Per-word price for a SHA256 operation
	// Sha256PerWordGas 是 SHA256 操作中每个字的 gas 价格。
	Ripemd160BaseGas uint64 = 600 // Base price for a RIPEMD160 operation
	// Ripemd160BaseGas 是 RIPEMD160 操作的基础 gas 价格。
	Ripemd160PerWordGas uint64 = 120 // Per-word price for a RIPEMD160 operation
	// Ripemd160PerWordGas 是 RIPEMD160 操作中每个字的 gas 价格。
	IdentityBaseGas uint64 = 15 // Base price for a data copy operation
	// IdentityBaseGas 是数据复制操作的基础 gas 价格。
	IdentityPerWordGas uint64 = 3 // Per-work price for a data copy operation
	// IdentityPerWordGas 是数据复制操作中每个字的 gas 价格。

	Bn256AddGasByzantium uint64 = 500 // Byzantium gas needed for an elliptic curve addition
	// Bn256AddGasByzantium 是 Byzantium 中椭圆曲线加法的 gas 费用。
	Bn256AddGasIstanbul uint64 = 150 // Gas needed for an elliptic curve addition
	// Bn256AddGasIstanbul 是 Istanbul 中椭圆曲线加法的 gas 费用。
	Bn256ScalarMulGasByzantium uint64 = 40000 // Byzantium gas needed for an elliptic curve scalar multiplication
	// Bn256ScalarMulGasByzantium 是 Byzantium 中椭圆曲线标量乘法的 gas 费用。
	Bn256ScalarMulGasIstanbul uint64 = 6000 // Gas needed for an elliptic curve scalar multiplication
	// Bn256ScalarMulGasIstanbul 是 Istanbul 中椭圆曲线标量乘法的 gas 费用。
	Bn256PairingBaseGasByzantium uint64 = 100000 // Byzantium base price for an elliptic curve pairing check
	// Bn256PairingBaseGasByzantium 是 Byzantium 中椭圆曲线配对检查的基础 gas 价格。
	Bn256PairingBaseGasIstanbul uint64 = 45000 // Base price for an elliptic curve pairing check
	// Bn256PairingBaseGasIstanbul 是 Istanbul 中椭圆曲线配对检查的基础 gas 价格。
	Bn256PairingPerPointGasByzantium uint64 = 80000 // Byzantium per-point price for an elliptic curve pairing check
	// Bn256PairingPerPointGasByzantium 是 Byzantium 中椭圆曲线配对检查的每点 gas 价格。
	Bn256PairingPerPointGasIstanbul uint64 = 34000 // Per-point price for an elliptic curve pairing check
	// Bn256PairingPerPointGasIstanbul 是 Istanbul 中椭圆曲线配对检查的每点 gas 价格。

	Bls12381G1AddGas uint64 = 500 // Price for BLS12-381 elliptic curve G1 point addition
	// Bls12381G1AddGas 是 BLS12-381 椭圆曲线 G1 点加法的 gas 价格。
	Bls12381G1MulGas uint64 = 12000 // Price for BLS12-381 elliptic curve G1 point scalar multiplication
	// Bls12381G1MulGas 是 BLS12-381 椭圆曲线 G1 点标量乘法的 gas 价格。
	Bls12381G2AddGas uint64 = 800 // Price for BLS12-381 elliptic curve G2 point addition
	// Bls12381G2AddGas 是 BLS12-381 椭圆曲线 G2 点加法的 gas 价格。
	Bls12381G2MulGas uint64 = 45000 // Price for BLS12-381 elliptic curve G2 point scalar multiplication
	// Bls12381G2MulGas 是 BLS12-381 椭圆曲线 G2 点标量乘法的 gas 价格。
	Bls12381PairingBaseGas uint64 = 65000 // Base gas price for BLS12-381 elliptic curve pairing check
	// Bls12381PairingBaseGas 是 BLS12-381 椭圆曲线配对检查的基础 gas 价格。
	Bls12381PairingPerPairGas uint64 = 43000 // Per-point pair gas price for BLS12-381 elliptic curve pairing check
	// Bls12381PairingPerPairGas 是 BLS12-381 椭圆曲线配对检查的每对点 gas 价格。
	Bls12381MapG1Gas uint64 = 5500 // Gas price for BLS12-381 mapping field element to G1 operation
	// Bls12381MapG1Gas 是 BLS12-381 映射字段元素到 G1 操作的 gas 价格。
	Bls12381MapG2Gas uint64 = 75000 // Gas price for BLS12-381 mapping field element to G2 operation
	// Bls12381MapG2Gas 是 BLS12-381 映射字段元素到 G2 操作的 gas 价格。

	// The Refund Quotient is the cap on how much of the used gas can be refunded. Before EIP-3529,
	// up to half the consumed gas could be refunded. Redefined as 1/5th in EIP-3529
	RefundQuotient uint64 = 2
	// RefundQuotient 是 EIP-3529 前可退款 gas 的上限，之前为消耗 gas 的一半。
	RefundQuotientEIP3529 uint64 = 5
	// RefundQuotientEIP3529 是 EIP-3529 中可退款 gas 的上限，改为消耗 gas 的 1/5。

	BlobTxBytesPerFieldElement = 32 // Size in bytes of a field element
	// BlobTxBytesPerFieldElement 是字段元素的字节大小。
	BlobTxFieldElementsPerBlob = 4096 // Number of field elements stored in a single data blob
	// BlobTxFieldElementsPerBlob 是单个数据 blob 中存储的字段元素数量。
	BlobTxBlobGasPerBlob = 1 << 17 // Gas consumption of a single data blob (== blob byte size)
	// BlobTxBlobGasPerBlob 是单个数据 blob 的 gas 消耗（== blob 字节大小）。
	BlobTxMinBlobGasprice = 1 // Minimum gas price for data blobs
	// BlobTxMinBlobGasprice 是数据 blob 的最小 gas 价格。
	BlobTxBlobGaspriceUpdateFraction = 3338477 // Controls the maximum rate of change for blob gas price
	// BlobTxBlobGaspriceUpdateFraction 控制 blob gas 价格的最大变化率。
	BlobTxPointEvaluationPrecompileGas = 50000 // Gas price for the point evaluation precompile.
	// BlobTxPointEvaluationPrecompileGas 是点评估预编译的 gas 价格。

	BlobTxTargetBlobGasPerBlock = 3 * BlobTxBlobGasPerBlob // Target consumable blob gas for data blobs per block (for 1559-like pricing)
	// BlobTxTargetBlobGasPerBlock 是每个区块中数据 blob 的目标可消耗 blob gas（用于 1559 式定价）。
	MaxBlobGasPerBlock = 6 * BlobTxBlobGasPerBlob // Maximum consumable blob gas for data blobs per block
	// MaxBlobGasPerBlock 是每个区块中数据 blob 的最大可消耗 blob gas。

	HistoryServeWindow = 8192 // Number of blocks to serve historical block hashes for, EIP-2935.
	// HistoryServeWindow 是 EIP-2935 中服务历史区块哈希的区块数。
)

// Bls12381MultiExpDiscountTable gas discount table for BLS12-381 G1 and G2 multi exponentiation operations
// Bls12381MultiExpDiscountTable 是 BLS12-381 G1 和 G2 多指数运算的 gas 折扣表。
var Bls12381MultiExpDiscountTable = [128]uint64{1200, 888, 764, 641, 594, 547, 500, 453, 438, 423, 408, 394, 379, 364, 349, 334, 330, 326, 322, 318, 314, 310, 306, 302, 298, 294, 289, 285, 281, 277, 273, 269, 268, 266, 265, 263, 262, 260, 259, 257, 256, 254, 253, 251, 250, 248, 247, 245, 244, 242, 241, 239, 238, 236, 235, 233, 232, 231, 229, 228, 226, 225, 223, 222, 221, 220, 219, 219, 218, 217, 216, 216, 215, 214, 213, 213, 212, 211, 211, 210, 209, 208, 208, 207, 206, 205, 205, 204, 203, 202, 202, 201, 200, 199, 199, 198, 197, 196, 196, 195, 194, 193, 193, 192, 191, 191, 190, 189, 188, 188, 187, 186, 185, 185, 184, 183, 182, 182, 181, 180, 179, 179, 178, 177, 176, 176, 175, 174}

// Difficulty parameters.
// 难度参数。
var (
	DifficultyBoundDivisor = big.NewInt(2048) // The bound divisor of the difficulty, used in the update calculations.
	// DifficultyBoundDivisor 是难度更新计算中的边界除数。
	GenesisDifficulty = big.NewInt(131072) // Difficulty of the Genesis block.
	// GenesisDifficulty 是创世区块的难度。
	MinimumDifficulty = big.NewInt(131072) // The minimum that the difficulty may ever be.
	// MinimumDifficulty 是难度可能的最小值。
	DurationLimit = big.NewInt(13) // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
	// DurationLimit 是区块时间持续时间的决策边界，用于确定难度是否应该上升。
)

// System contracts.
// 系统合约。
var (
	// SystemAddress is where the system-transaction is sent from as per EIP-4788
	// SystemAddress 是 EIP-4788 中系统交易发送的地址。
	SystemAddress = common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe")

	// EIP-4788 - Beacon block root in the EVM
	// EIP-4788 - EVM 中的信标区块根。
	BeaconRootsAddress = common.HexToAddress("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02")
	BeaconRootsCode    = common.FromHex("3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500")

	// EIP-2935 - Serve historical block hashes from state
	// EIP-2935 - 从状态中服务历史区块哈希。
	HistoryStorageAddress = common.HexToAddress("0x0F792be4B0c0cb4DAE440Ef133E90C0eCD48CCCC")
	HistoryStorageCode    = common.FromHex("3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500")

	// EIP-7002 - Execution layer triggerable withdrawals
	// EIP-7002 - 执行层可触发的提款。
	WithdrawalQueueAddress = common.HexToAddress("0x0c15F14308530b7CDB8460094BbB9cC28b9AaaAA")
	WithdrawalQueueCode    = common.FromHex("3373fffffffffffffffffffffffffffffffffffffffe1460cb5760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff146101f457600182026001905f5b5f82111560685781019083028483029004916001019190604d565b909390049250505036603814608857366101f457346101f4575f5260205ff35b34106101f457600154600101600155600354806003026004013381556001015f35815560010160203590553360601b5f5260385f601437604c5fa0600101600355005b6003546002548082038060101160df575060105b5f5b8181146101835782810160030260040181604c02815460601b8152601401816001015481526020019060020154807fffffffffffffffffffffffffffffffff00000000000000000000000000000000168252906010019060401c908160381c81600701538160301c81600601538160281c81600501538160201c81600401538160181c81600301538160101c81600201538160081c81600101535360010160e1565b910180921461019557906002556101a0565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff14156101cd57505f5b6001546002828201116101e25750505f6101e8565b01600290035b5f555f600155604c025ff35b5f5ffd")

	// EIP-7251 - Increase the MAX_EFFECTIVE_BALANCE
	// EIP-7251 - 增加 MAX_EFFECTIVE_BALANCE。
	ConsolidationQueueAddress = common.HexToAddress("0x00431F263cE400f4455c2dCf564e53007Ca4bbBb")
	ConsolidationQueueCode    = common.FromHex("3373fffffffffffffffffffffffffffffffffffffffe1460d35760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f82111560685781019083028483029004916001019190604d565b9093900492505050366060146088573661019a573461019a575f5260205ff35b341061019a57600154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b5f5260605f60143760745fa0600101600355005b6003546002548082038060021160e7575060025b5f5b8181146101295782810160040260040181607402815460601b815260140181600101548152602001816002015481526020019060030154905260010160e9565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b6001546001828201116101885750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd")
)
