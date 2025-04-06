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

package vm

func memoryKeccak256(stack *Stack) (uint64, bool) { // 计算KECCAK256的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(1)) // 使用栈顶第0项（偏移）和第1项（长度）
}

func memoryCallDataCopy(stack *Stack) (uint64, bool) { // 计算CALLDATACOPY的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(2)) // 使用栈顶第0项（目标偏移）和第2项（长度）
}

func memoryReturnDataCopy(stack *Stack) (uint64, bool) { // 计算RETURNDATACOPY的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(2)) // 使用栈顶第0项（目标偏移）和第2项（长度）
}

func memoryCodeCopy(stack *Stack) (uint64, bool) { // 计算CODECOPY的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(2)) // 使用栈顶第0项（目标偏移）和第2项（长度）
}

func memoryExtCodeCopy(stack *Stack) (uint64, bool) { // 计算EXTCODECOPY的内存大小
	return calcMemSize64(stack.Back(1), stack.Back(3)) // 使用栈顶第1项（目标偏移）和第3项（长度）
}

func memoryMLoad(stack *Stack) (uint64, bool) { // 计算MLOAD的内存大小
	return calcMemSize64WithUint(stack.Back(0), 32) // 使用栈顶第0项（偏移）和固定32字节长度
}

func memoryMStore8(stack *Stack) (uint64, bool) { // 计算MSTORE8的内存大小
	return calcMemSize64WithUint(stack.Back(0), 1) // 使用栈顶第0项（偏移）和固定1字节长度
}

func memoryMStore(stack *Stack) (uint64, bool) { // 计算MSTORE的内存大小
	return calcMemSize64WithUint(stack.Back(0), 32) // 使用栈顶第0项（偏移）和固定32字节长度
}

func memoryMcopy(stack *Stack) (uint64, bool) { // 计算MCOPY的内存大小
	mStart := stack.Back(0)       // 栈顶第0项：目标偏移
	if stack.Back(1).Gt(mStart) { // 如果源偏移大于目标偏移
		mStart = stack.Back(1) // 使用栈顶第1项（源偏移）作为起始点
	}
	return calcMemSize64(mStart, stack.Back(2)) // 使用最大起始偏移和栈顶第2项（长度）
}

func memoryCreate(stack *Stack) (uint64, bool) { // 计算CREATE的内存大小
	return calcMemSize64(stack.Back(1), stack.Back(2)) // 使用栈顶第1项（偏移）和第2项（长度）
}

func memoryCreate2(stack *Stack) (uint64, bool) { // 计算CREATE2的内存大小
	return calcMemSize64(stack.Back(1), stack.Back(2)) // 使用栈顶第1项（偏移）和第2项（长度）
}

func memoryCall(stack *Stack) (uint64, bool) { // 计算CALL的内存大小
	x, overflow := calcMemSize64(stack.Back(5), stack.Back(6)) // 计算调用数据的内存（栈顶第5项：偏移，第6项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	y, overflow := calcMemSize64(stack.Back(3), stack.Back(4)) // 计算返回数据的内存（栈顶第3项：偏移，第4项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	if x > y { // 返回两者中的较大值
		return x, false
	}
	return y, false
}

func memoryDelegateCall(stack *Stack) (uint64, bool) { // 计算DELEGATECALL的内存大小
	x, overflow := calcMemSize64(stack.Back(4), stack.Back(5)) // 计算调用数据的内存（栈顶第4项：偏移，第5项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	y, overflow := calcMemSize64(stack.Back(2), stack.Back(3)) // 计算返回数据的内存（栈顶第2项：偏移，第3项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	if x > y { // 返回两者中的较大值
		return x, false
	}
	return y, false
}

func memoryStaticCall(stack *Stack) (uint64, bool) { // 计算STATICCALL的内存大小
	x, overflow := calcMemSize64(stack.Back(4), stack.Back(5)) // 计算调用数据的内存（栈顶第4项：偏移，第5项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	y, overflow := calcMemSize64(stack.Back(2), stack.Back(3)) // 计算返回数据的内存（栈顶第2项：偏移，第3项：长度）
	if overflow {                                              // 如果溢出
		return 0, true // 返回0和溢出标志
	}
	if x > y { // 返回两者中的较大值
		return x, false
	}
	return y, false
}

func memoryReturn(stack *Stack) (uint64, bool) { // 计算RETURN的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(1)) // 使用栈顶第0项（偏移）和第1项（长度）
}

func memoryRevert(stack *Stack) (uint64, bool) { // 计算REVERT的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(1)) // 使用栈顶第0项（偏移）和第1项（长度）
}

func memoryLog(stack *Stack) (uint64, bool) { // 计算LOG的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(1)) // 使用栈顶第0项（偏移）和第1项（长度）
}

func memoryExtCall(stack *Stack) (uint64, bool) { // 计算扩展调用的内存大小
	return calcMemSize64(stack.Back(1), stack.Back(2)) // 使用栈顶第1项（偏移）和第2项（长度）
}

func memoryDataCopy(stack *Stack) (uint64, bool) { // 计算DATACOPY的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(2)) // 使用栈顶第0项（目标偏移）和第2项（长度）
}

func memoryEOFCreate(stack *Stack) (uint64, bool) { // 计算EOFCREATE的内存大小
	return calcMemSize64(stack.Back(2), stack.Back(3)) // 使用栈顶第2项（偏移）和第3项（长度）
}

func memoryReturnContract(stack *Stack) (uint64, bool) { // 计算RETURNCONTRACT的内存大小
	return calcMemSize64(stack.Back(0), stack.Back(1)) // 使用栈顶第0项（偏移）和第1项（长度）
}
