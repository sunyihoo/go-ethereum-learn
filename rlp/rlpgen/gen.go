// Copyright 2022 The go-ethereum Authors
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

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"go/types"
	"sort"

	"github.com/ethereum/go-ethereum/rlp/internal/rlpstruct"
)

// RLP 是以太坊的核心序列化格式，用于编码交易、区块、状态树等。它的特点是紧凑、高效，但不支持复杂的类型（比如浮点数）。
// RLP（EIP-2364）：
// RLP 是以太坊的基础协议之一，定义在黄皮书中。它只支持两种基本类型：字节数组和列表。

// buildContext keeps the data needed for make*Op.
// buildContext 存储了 make*Op 所需的各种数据。
// buildContext 的设计是为了把 Go 的复杂类型（结构体、接口）映射到 RLP 的简单格式。
type buildContext struct {
	topType *types.Named // the type we're creating methods for 我们要为其创建方法的类型

	encoderIface *types.Interface // Encoder 接口类型
	decoderIface *types.Interface // Decoder 接口类型
	rawValueType *types.Named     // RawValue 的类型

	typeToStructCache map[types.Type]*rlpstruct.Type // 类型到 RLP 结构体的缓存映射。RLP 编码中，RawValue 通常表示未经解析的字节流，比如交易的签名数据。
}

// newBuildContext 为给定的 RLP 包创建一个新的构建上下文。
func newBuildContext(packageRLP *types.Package) *buildContext {
	enc := packageRLP.Scope().Lookup("Encoder").Type().Underlying() // 通过 Scope().Lookup()，从包的作用域里捞出 Encoder、Decoder 和 RawValue 的类型定义。
	dec := packageRLP.Scope().Lookup("Decoder").Type().Underlying()
	rawv := packageRLP.Scope().Lookup("RawValue").Type()
	return &buildContext{
		typeToStructCache: make(map[types.Type]*rlpstruct.Type),
		encoderIface:      enc.(*types.Interface),
		decoderIface:      dec.(*types.Interface),
		rawValueType:      rawv.(*types.Named),
	}
}

// types.Implements 是 Go 类型系统的神器，它不仅检查直接实现，还能处理接口嵌套和指针类型（*T 是否实现）。

// isEncoder 检查给定类型是否实现了 Encoder 接口。
func (bctx *buildContext) isEncoder(typ types.Type) bool {
	return types.Implements(typ, bctx.encoderIface)
}

// isDecoder 检查给定类型是否实现了 Decoder 接口。
func (bctx *buildContext) isDecoder(typ types.Type) bool {
	return types.Implements(typ, bctx.decoderIface)
}

// typeToStructType converts typ to rlpstruct.Type.
// typeToStructType 将 typ 转换为 rlpstruct.Type。
func (bctx *buildContext) typeToStructType(typ types.Type) *rlpstruct.Type {
	if prev := bctx.typeToStructCache[typ]; prev != nil {
		return prev // short-circuit for recursive types.对于递归类型直接返回缓存。
	}

	// RLP 不支持 Go 的命名类型，它只认底层数据（字节数组、列表）。
	// 这里保留 name 是为了开发者方便，实际编码时用的是 Kind 和 Elem。

	// Resolve named types to their underlying type, but keep the name.
	// 将命名类型解析为其底层类型，但保留名称。
	name := types.TypeString(typ, nil) // 把类型转成字符串表示（比如 MyStruct），保留命名信息，方便调试或生成代码。
	for {
		utype := typ.Underlying()
		if utype == typ {
			break
		}
		typ = utype
	}

	// Create the type and store it in cache.
	// 创建类型并存储到缓存中。
	t := &rlpstruct.Type{
		Name:      name,
		Kind:      typeReflectKind(typ),
		IsEncoder: bctx.isEncoder(typ),
		IsDecoder: bctx.isDecoder(typ),
	}
	bctx.typeToStructCache[typ] = t

	// RLP 支持嵌套列表（[]T），这里递归解析元素类型，确保嵌套结构也能正确转换。
	// RLP 的列表编码是 [item1, item2, ...]，嵌套列表很常见（比如交易的 [[nonce, gasPrice], ...]）。t.Elem 存元素类型，方便后续递归编码。

	// Assign element type.
	// 分配元素类型。
	switch typ.(type) {
	case *types.Array, *types.Slice, *types.Pointer:
		// interface{ Elem() types.Type } 是类型断言的巧妙用法，统一处理三种类型的 Elem() 方法。
		etype := typ.(interface{ Elem() types.Type }).Elem()
		t.Elem = bctx.typeToStructType(etype) // 调用 Elem() 获取元素类型（比如 []int 的 int），然后递归调用 typeToStructType 处理元素类型，赋值给 t.Elem。
	}
	return t
}

// genContext is passed to the gen* methods of op when generating
// the output code. It tracks packages to be imported by the output
// file and assigns unique names of temporary variables.
// genContext 在生成输出代码时传递给 op 的 gen* 方法。它跟踪输出文件需要导入的包，并为临时变量分配唯一名称。
type genContext struct {
	inPackage   *types.Package      // 当前所在的包
	imports     map[string]struct{} // 需要导入的包集合。键是包的路径（比如 "fmt"、"github.com/ethereum/go-ethereum/rlp"），值是空结构体 struct{}（占位符，不占内存）。它的作用是记录生成代码需要 import 的包，避免重复导入。
	tempCounter int                 // 临时变量计数器 用来生成唯一的临时变量名（比如 _tmp0、_tmp1）
}

// newGenContext 为给定包创建一个新的生成上下文。
func newGenContext(inPackage *types.Package) *genContext {
	return &genContext{
		inPackage: inPackage,
		imports:   make(map[string]struct{}),
	}
}

// temp 生成一个唯一的临时变量名称。
func (ctx *genContext) temp() string {
	v := fmt.Sprintf("_tmp%d", ctx.tempCounter)
	ctx.tempCounter++
	return v
}

// resetTemp 重置临时变量计数器。
func (ctx *genContext) resetTemp() {
	ctx.tempCounter = 0
}

// addImport 如果不是当前包，则将包添加到导入列表。
// 记录生成代码需要的外部包，避免重复导入，同时排除当前包。
func (ctx *genContext) addImport(path string) {
	if path == ctx.inPackage.Path() {
		return // avoid importing the package that we're generating in.避免导入正在生成的包。
	}
	// TODO: renaming?
	ctx.imports[path] = struct{}{}
}

// importsList returns all packages that need to be imported.
// importsList 返回所有需要导入的包。
// 返回一个有序的包路径列表，供生成 import 语句用。
func (ctx *genContext) importsList() []string {
	imp := make([]string, 0, len(ctx.imports))
	for k := range ctx.imports {
		imp = append(imp, k)
	}
	sort.Strings(imp)
	return imp
}

// qualify is the types.Qualifier used for printing types.
// qualify 是用于打印类型的 types.Qualifier。
// 作为 types.Qualifier，决定类型字符串如何打印（比如 rlp.Type 还是 Type）。
//
// 在生成代码时，类型可能是 rlp.Type（外部包）或 MyStruct（当前包）。
// qualify 确保引用正确，同时记录依赖。比如生成 RLP 相关代码时，可能用到 rlpstruct.Type，需要正确导入。
func (ctx *genContext) qualify(pkg *types.Package) string {
	if pkg.Path() == ctx.inPackage.Path() {
		return ""
	}
	ctx.addImport(pkg.Path())
	// TODO: renaming?
	return pkg.Name()
}

// op 定义了用于生成编码和解码操作的接口。
// 为动态生成 RLP 编码和解码函数提供规范，结合 genContext，生成可执行的 Go 代码。
// op 接口是为优化 RLP 处理设计的，生成专用函数比反射更快。
type op interface {
	// genWrite creates the encoder. The generated code should write v,
	// which is any Go expression, to the rlp.EncoderBuffer 'w'.
	// genWrite 创建编码器。生成的代码应将 v（任意 Go 表达式）写入 rlp.EncoderBuffer 'w'。
	genWrite(ctx *genContext, v string) string

	// genDecode creates the decoder. The generated code should read
	// a value from the rlp.Stream 'dec' and store it to dst.
	// genDecode 创建解码器。生成的代码应从 rlp.Stream 'dec' 读取值并存储到 dst。
	genDecode(ctx *genContext) (string, string)
}

// 在以太坊中，RLP 编码只支持字节数组和列表，基本类型是构建复杂结构的基础。basicOp 是 go-ethereum/rlp 的底层实现之一，优化常见类型的处理。
// RLP 对基本类型的处理很直接：bool 编码为 1 字节（0 或 1），uint* 去掉前导零后编码为字节数组，string 直接编码为字节序列。
// RLP 只认字节数组和列表，bool 和 uint* 被编码为紧凑的字节，string 直接用字节表示。
// basicOp 的字段设计完美适配这些规则

// basicOp handles basic types bool, uint*, string.
// basicOp 处理基本类型 bool、uint*、string。
type basicOp struct {
	typ           types.Type // 要处理的类型
	writeMethod   string     // EncoderBuffer writer method name EncoderBuffer 的写入方法名称
	writeArgType  types.Type // parameter type of writeMethod    writeMethod 的参数类型
	decMethod     string     // 解码方法名称
	decResultType types.Type // return type of decMethod         decMethod 的返回类型
	decUseBitSize bool       // if true, result bit size is appended to decMethod  如果为 true，则将结果位大小附加到 decMethod
}

// makeBasicOp 为基本类型创建一个 op。
// RLP 编码中，bool 是 1 字节（0 或 1），uint* 去掉前导零后编码为字节，string 直接用字节表示。
// makeBasicOp 为这些类型映射到 rlp.EncoderBuffer 和 rlp.Stream 的方法。
func (*buildContext) makeBasicOp(typ *types.Basic) (op, error) {
	op := basicOp{typ: typ}
	kind := typ.Kind() // 获取类型种类。
	switch {
	case kind == types.Bool: // 写入 WriteBool，解码 Bool，类型都是 bool。
		op.writeMethod = "WriteBool"
		op.writeArgType = types.Typ[types.Bool]
		op.decMethod = "Bool"
		op.decResultType = types.Typ[types.Bool]
	case kind >= types.Uint8 && kind <= types.Uint64: // 写入 WriteUint64，解码 Uint（带位大小），编码用 uint64，解码保留原类型。
		op.writeMethod = "WriteUint64"
		op.writeArgType = types.Typ[types.Uint64]
		op.decMethod = "Uint"
		op.decResultType = typ
		op.decUseBitSize = true // 表示解码方法会动态调整（比如 DecodeUint64）。
	case kind == types.String: // 写入 WriteString，解码 String，类型都是 string。
		op.writeMethod = "WriteString"
		op.writeArgType = types.Typ[types.String]
		op.decMethod = "String"
		op.decResultType = types.Typ[types.String]
	default:
		return nil, fmt.Errorf("unhandled basic type: %v", typ)
	}
	return op, nil
}

// makeByteSliceOp 为字节切片类型创建一个 op。
// RLP 把 []byte 直接编码为字节数组，长度前缀加内容。
// makeByteSliceOp 专为 []byte 优化，在以太坊中常见于交易签名或哈希值。
func (*buildContext) makeByteSliceOp(typ *types.Slice) op {
	if !isByte(typ.Elem()) { // 检查切片元素是否是 byte（uint8）
		panic("non-byte slice type in makeByteSliceOp")
	}
	bslice := types.NewSlice(types.Typ[types.Uint8]) // 创建标准 []byte 类型。
	return basicOp{
		typ:           typ,
		writeMethod:   "WriteBytes", // 写入方法：WriteBytes。
		writeArgType:  bslice,
		decMethod:     "Bytes", // 解码方法：Bytes。
		decResultType: bslice,
	}
}

// makeRawValueOp 为 RawValue 类型创建一个 op。
//
// RawValue 在 go-ethereum 中常用于表示未解码的 RLP 数据（比如交易的原始字节）。
// makeRawValueOp 让它直接读写字节流，适合处理原始交易或状态数据。
func (bctx *buildContext) makeRawValueOp() op {
	bslice := types.NewSlice(types.Typ[types.Uint8])
	return basicOp{
		typ:           bctx.rawValueType,
		writeMethod:   "Write",
		writeArgType:  bslice,
		decMethod:     "Raw",
		decResultType: bslice,
	}
}

// writeNeedsConversion 检查值在写入前是否需要转换。
//
// 调用 types.AssignableTo 检查 op.typ（实际类型）是否可以直接赋值给 op.writeArgType（写入方法的目标类型）。
// 如果不能，返回 true，表示需要类型转换。
// RLP 编码中，uint* 类型统一用 WriteUint64，小位宽（如 uint8）需要转成 uint64，这里就是为这种场景准备的。
func (op basicOp) writeNeedsConversion() bool {
	return !types.AssignableTo(op.typ, op.writeArgType)
}

// decodeNeedsConversion 检查解码后的值是否需要转换。
//
// 检查 op.decResultType（解码方法返回的类型）是否可以直接赋值给 op.typ（目标类型）。如果不能，返回 true，表示需要转换。
// 判断解码后是否需要调整类型。比如 uint64 解码后赋值给 uint32 需要转换。
func (op basicOp) decodeNeedsConversion() bool {
	return !types.AssignableTo(op.decResultType, op.typ)
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
func (op basicOp) genWrite(ctx *genContext, v string) string {
	// 调用 writeNeedsConversion 检查是否需要转换。
	// 如果需要，用 fmt.Sprintf 把 v 包装成类型转换，比如 uint64(x)。
	// 如果不需要，v 保持不变。
	if op.writeNeedsConversion() {
		v = fmt.Sprintf("%s(%s)", op.writeArgType, v)
	}
	// 用 fmt.Sprintf 生成调用 w（rlp.EncoderBuffer）的代码，比如 w.WriteUint64(x)，加换行符 \n。
	return fmt.Sprintf("w.%s(%s)\n", op.writeMethod, v)
}

// RLP 解码：
// RLP 数据是字节流，Stream 提供精确读取方法（如 DecodeUint32）。
// genDecode 生成专用逻辑，优化性能。

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
func (op basicOp) genDecode(ctx *genContext) (string, string) {
	var (
		resultV = ctx.temp() // 存解码的初始结果。
		result  = resultV
		method  = op.decMethod // 从 op.decMethod 获取解码方法名（比如 Bool、Uint）。
	)
	if op.decUseBitSize { // 如果为 true（比如 uint* 类型），调整解码方法名。
		// Note: For now, this only works for platform-independent integer
		// sizes. makeBasicOp forbids the platform-dependent types.
		// 注意：目前这仅适用于与平台无关的整数大小。makeBasicOp 禁止使用平台相关类型。
		var sizes types.StdSizes
		method = fmt.Sprintf("%s%d", op.decMethod, sizes.Sizeof(op.typ)*8) // 用 types.StdSizes 计算类型大小（字节数），乘以 8 转为位数（比如 uint32 是 4 字节，32 位）。
	}

	// Call the decoder method.
	// 调用解码方法。
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s, err := dec.%s()\n", resultV, method) // 生成调用 dec 的解码方法，比如 _tmp0, err := dec.Uint32()。
	fmt.Fprintf(&b, "if err != nil { return err }\n")         // 添加错误检查 if err != nil { return err }，确保解码失败时退出。
	if op.decodeNeedsConversion() {                           //  检查是否需要转换（比如 uint64 到 uint32）
		conv := ctx.temp()                                                                      // 生成新变量名
		fmt.Fprintf(&b, "%s := %s(%s)\n", conv, types.TypeString(op.typ, ctx.qualify), resultV) // 生成转换代码，比如 _tmp1 := uint32(_tmp0)。
		result = conv                                                                           // 更新 result 为新变量名。
	}
	return result, b.String()
}

// RLP 编码把 [...]byte 当作单一字节序列，加上长度前缀。byteArrayOp 为这种固定长度类型优化。

// byteArrayOp handles [...]byte.
// byteArrayOp 处理 [...]byte。
//
// 在以太坊中，字节数组很常见，比如 common.Address（20 字节地址）、common.Hash（32 字节哈希）。RLP 编码把它们当字节序列处理
// byteArrayOp 专为这类类型优化。
type byteArrayOp struct {
	typ  types.Type // 底层数组类型。表示实际的数组类型
	name types.Type // name != typ for named byte array types (e.g. common.Address) 对于命名的字节数组类型（例如 common.Address），name != typ
}

// makeByteArrayOp 为字节数组类型创建一个 op，可以是命名的。
// common.Address 是 go-ethereum 的常用类型，底层是 [20]byte，表示账户地址。RLP 编码时，它被视为 20 字节序列，
// makeByteArrayOp 支持这种命名的特殊处理。
// 为字节数组类型（命名或匿名的）创建 byteArrayOp，支持后续生成 RLP 编码解码代码。
func (bctx *buildContext) makeByteArrayOp(name *types.Named, typ *types.Array) byteArrayOp {
	nt := types.Type(name)
	if name == nil { // 表示匿名数组（比如 [20]byte），这时 name 和 typ 相同。
		nt = typ
	}
	return byteArrayOp{typ, nt}
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
func (op byteArrayOp) genWrite(ctx *genContext, v string) string {
	// v[:] 把数组（比如 [20]byte）转为切片（[]byte），因为 WriteBytes 需要 []byte 参数。
	return fmt.Sprintf("w.WriteBytes(%s[:])\n", v)
}

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
//
// RLP 解码字节数组时，ReadBytes 从流中读取长度前缀和内容，直接填充到切片。
func (op byteArrayOp) genDecode(ctx *genContext) (string, string) {
	var resultV = ctx.temp()

	var b bytes.Buffer
	fmt.Fprintf(&b, "var %s %s\n", resultV, types.TypeString(op.name, ctx.qualify))
	fmt.Fprintf(&b, "if err := dec.ReadBytes(%s[:]); err != nil { return err }\n", resultV)
	return resultV, b.String()
}

// big.Int 在以太坊中广泛用于大整数（如 value、gasPrice），RLP 编码要求非负整数，解码返回指针类型，bigIntOp 为此量身定制。

// bigIntOp handles big.Int.
// This exists because big.Int has it's own decoder operation on rlp.Stream,
// but the decode method returns *big.Int, so it needs to be dereferenced.
//
// bigIntOp 处理 big.Int。
// 这是因为 big.Int 在 rlp.Stream 上有自己的解码操作，
// 但解码方法返回 *big.Int，因此需要解引用。
type bigIntOp struct {
	pointer bool // 如果为 true，则表示是指针类型 *big.Int  表示目标类型是指针 *big.Int（true）还是值 big.Int（false）。
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
func (op bigIntOp) genWrite(ctx *genContext, v string) string {
	var b bytes.Buffer

	// 示例：
	// 值类型
	//  if x.Sign() == -1 {
	//   return rlp.ErrNegativeBigInt
	//  }
	//  w.WriteBigInt(&x)

	fmt.Fprintf(&b, "if %s.Sign() == -1 {\n", v)        // 检查 big.Int 是否为负数。
	fmt.Fprintf(&b, "  return rlp.ErrNegativeBigInt\n") //
	fmt.Fprintf(&b, "}\n")
	dst := v
	if !op.pointer { // 如果 op.pointer 是 false（值类型），在 v 前加 &（比如 &x），因为 WriteBigInt 需要 *big.Int。
		dst = "&" + v
	}
	fmt.Fprintf(&b, "w.WriteBigInt(%s)\n", dst) // 生成 w.WriteBigInt(dst)，调用 RLP 写入方法。

	// 示例：
	// 指针类型：
	//  if x == nil {
	//    w.Write(rlp.EmptyString)
	//  } else {
	//    if x.Sign() == -1 {
	//      return rlp.ErrNegativeBigInt
	//    }
	//    w.WriteBigInt(x)
	//  }

	// Wrap with nil check.
	// 包装一个 nil 检查。
	if op.pointer { // 如果 op.pointer 是 true，包装一个 if v == nil 分支
		code := b.String()
		b.Reset()
		fmt.Fprintf(&b, "if %s == nil {\n", v) // nil 时写入 rlp.EmptyString（空字节）
		fmt.Fprintf(&b, "  w.Write(rlp.EmptyString)")
		fmt.Fprintf(&b, "} else {\n")
		fmt.Fprint(&b, code)
		fmt.Fprintf(&b, "}\n")
	}

	return b.String()
}

// RLP 解码大整数用 BigInt()，返回 *big.Int，表示非负整数。bigIntOp 处理指针和值的差异，确保结果匹配目标类型。

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
func (op bigIntOp) genDecode(ctx *genContext) (string, string) {
	var resultV = ctx.temp() // 生成临时变量名（比如 _tmp0）。

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s, err := dec.BigInt()\n", resultV) // _tmp0, err := dec.BigInt()：调用 rlp.Stream 的 BigInt 方法。
	fmt.Fprintf(&b, "if err != nil { return err }\n")     // if err != nil { return err }。

	result := resultV
	if !op.pointer { // 如果 op.pointer 是 true，result 是 _tmp0（*big.Int）。如果是 false，result 是 (*_tmp0)（解引用为 big.Int）。
		result = "(*" + resultV + ")"
	}
	return result, b.String()
}

// uint256.Int 是以太坊开发中常见的类型，用于表示 256 位整数（如智能合约中的 uint256），比标准 big.Int 更高效，RLP 编码解码需要特殊方法支持。

// uint256Op handles "github.com/holiman/uint256".Int
// uint256Op 处理 "github.com/holiman/uint256".Int
type uint256Op struct {
	pointer bool // 如果为 true，则表示是指针类型 *uint256.Int
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
// uint256.Int 是以太坊生态的高效大整数类型，RLP 编码时转为字节序列，WriteUint256 确保正确序列化。nil 检查支持可选字段（如智能合约返回值）。
func (op uint256Op) genWrite(ctx *genContext, v string) string {
	var b bytes.Buffer

	dst := v
	if !op.pointer {
		dst = "&" + v
	}
	fmt.Fprintf(&b, "w.WriteUint256(%s)\n", dst)

	// Wrap with nil check.
	// 包装一个 nil 检查。
	if op.pointer {
		code := b.String()
		b.Reset()
		fmt.Fprintf(&b, "if %s == nil {\n", v)
		fmt.Fprintf(&b, "  w.Write(rlp.EmptyString)")
		fmt.Fprintf(&b, "} else {\n")
		fmt.Fprint(&b, code)
		fmt.Fprintf(&b, "}\n")
	}

	return b.String()
}

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
// ReadUint256 从 RLP 流读取 256 位整数，填充到 *uint256.Int。这种类型在以太坊智能合约开发中常见，uint256Op 提供高效支持。
func (op uint256Op) genDecode(ctx *genContext) (string, string) {
	ctx.addImport("github.com/holiman/uint256")

	var b bytes.Buffer
	resultV := ctx.temp()
	fmt.Fprintf(&b, "var %s uint256.Int\n", resultV)
	fmt.Fprintf(&b, "if err := dec.ReadUint256(&%s); err != nil { return err }\n", resultV)

	result := resultV
	if op.pointer {
		result = "&" + resultV
	}
	return result, b.String()
}

// encoderDecoderOp handles rlp.Encoder and rlp.Decoder.
// In order to be used with this, the type must implement both interfaces.
// This restriction may be lifted in the future by creating separate ops for
// encoding and decoding.
//
// encoderDecoderOp 处理 rlp.Encoder 和 rlp.Decoder。
// 要使用这个，类型必须同时实现这两个接口。
// 将来可能会通过为编码和解码创建单独的 op 来解除此限制。
type encoderDecoderOp struct {
	typ types.Type // 要处理的类型
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
// rlp.Encoder 让类型自定义 RLP 编码，比如交易结构体可以用 EncodeRLP 序列化字段。genWrite 直接调用这个方法，高效且灵活。
func (op encoderDecoderOp) genWrite(ctx *genContext, v string) string {
	return fmt.Sprintf("if err := %s.EncodeRLP(w); err != nil { return err }\n", v)
}

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
// rlp.Decoder 的 DecodeRLP 方法（签名 DecodeRLP(*rlp.Stream) error）要求指针接收者，用于从 RLP 流恢复数据。
// genDecode 生成调用逻辑，支持自定义解码。
func (op encoderDecoderOp) genDecode(ctx *genContext) (string, string) {
	// DecodeRLP must have pointer receiver, and this is verified in makeOp.
	// DecodeRLP 必须使用指针接收者，这一点在 makeOp 中已验证。
	etyp := op.typ.(*types.Pointer).Elem()
	var resultV = ctx.temp()

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s := new(%s)\n", resultV, types.TypeString(etyp, ctx.qualify))
	fmt.Fprintf(&b, "if err := %s.DecodeRLP(dec); err != nil { return err }\n", resultV)
	return resultV, b.String()
}

// RLP 支持空值（空列表 [] 或空字符串 ""），ptrOp 适配指针的 nil 表示，常用于可选字段。

// ptrOp handles pointer types.
// ptrOp 处理指针类型。
type ptrOp struct {
	elemTyp  types.Type        // 指针指向的元素类型
	elem     op                // 元素类型的操作
	nilOK    bool              // 如果为 true，则允许 nil 指针
	nilValue rlpstruct.NilKind // nil 值的类型（列表或字符串）
}

// makePtrOp 为指针类型创建一个 op。
// 结构体标签（如 rlp:"nilOK"）在 go-ethereum 中控制 RLP 行为，makePtrOp 解析这些标签。
func (bctx *buildContext) makePtrOp(elemTyp types.Type, tags rlpstruct.Tags) (op, error) {
	elemOp, err := bctx.makeOp(nil, elemTyp, rlpstruct.Tags{})
	if err != nil {
		return nil, err
	}
	op := ptrOp{elemTyp: elemTyp, elem: elemOp}

	// Determine nil value.
	// 确定 nil 值。
	if tags.NilOK {
		op.nilOK = true
		op.nilValue = tags.NilKind
	} else {
		styp := bctx.typeToStructType(elemTyp)
		op.nilValue = styp.DefaultNilValue()
	}
	return op, nil
}

// genWrite 创建编码器。生成的代码将 v 写入 rlp.EncoderBuffer 'w'。
func (op ptrOp) genWrite(ctx *genContext, v string) string {
	// Note: in writer functions, accesses to v are read-only, i.e. v is any Go
	// expression. To make all accesses work through the pointer, we substitute
	// v with (*v). This is required for most accesses including `v`, `call(v)`,
	// and `v[index]` on slices.
	//
	// For `v.field` and `v[:]` on arrays, the dereference operation is not required.
	//
	// 注意：在写入函数中，对 v 的访问是只读的，即 v 是任意 Go 表达式。
	// 为了使所有访问通过指针工作，我们将 v 替换为 (*v)。这对于大多数访问是必需的，
	// 包括 `v`、`call(v)` 和切片上的 `v[index]`。
	//
	// 对于数组上的 `v.field` 和 `v[:]`，不需要解引用操作。
	var vv string
	_, isStruct := op.elem.(structOp)
	_, isByteArray := op.elem.(byteArrayOp)
	if isStruct || isByteArray {
		vv = v
	} else {
		vv = fmt.Sprintf("(*%s)", v)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "if %s == nil {\n", v)
	fmt.Fprintf(&b, "  w.Write([]byte{0x%X})\n", op.nilValue) // RLP 用 0x80 表示空字符串，0xC0 表示空列表，ptrOp 根据 nilValue 选择。
	fmt.Fprintf(&b, "} else {\n")
	fmt.Fprintf(&b, "  %s", op.elem.genWrite(ctx, vv))
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// genDecode 创建解码器。生成的代码从 rlp.Stream 'dec' 读取值并存储到 dst。
// RLP 解码时，Kind() 检查数据类型和长度，ptrOp 用它判断 nil。
func (op ptrOp) genDecode(ctx *genContext) (string, string) {
	result, code := op.elem.genDecode(ctx)
	if !op.nilOK {
		// If nil pointers are not allowed, we can just decode the element.
		// 如果不允许 nil 指针，我们只需解码元素即可。
		return "&" + result, code
	}

	// nil is allowed, so check the kind and size first.
	// If size is zero and kind matches the nilKind of the type,
	// the value decodes as a nil pointer.
	//
	// 如果允许 nil，则先检查种类和大小。
	// 如果大小为零且种类匹配类型的 nilKind，则值解码为 nil 指针。
	var (
		resultV  = ctx.temp()
		kindV    = ctx.temp()
		sizeV    = ctx.temp()
		wantKind string
	)
	if op.nilValue == rlpstruct.NilKindList {
		wantKind = "rlp.List"
	} else {
		wantKind = "rlp.String"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "var %s %s\n", resultV, types.TypeString(types.NewPointer(op.elemTyp), ctx.qualify))
	fmt.Fprintf(&b, "if %s, %s, err := dec.Kind(); err != nil {\n", kindV, sizeV)
	fmt.Fprintf(&b, "  return err\n")
	fmt.Fprintf(&b, "} else if %s != 0 || %s != %s {\n", sizeV, kindV, wantKind)
	fmt.Fprint(&b, code)
	fmt.Fprintf(&b, "  %s = &%s\n", resultV, result)
	fmt.Fprintf(&b, "}\n")
	return resultV, b.String()
}

// structOp handles struct types.
// structOp 处理结构体类型。
type structOp struct {
	named          *types.Named   // 命名类型（如果有）
	typ            *types.Struct  // 结构体类型
	fields         []*structField // 必需字段
	optionalFields []*structField // 可选字段
}

// structField 表示单个结构体字段。
type structField struct {
	name string     // 字段名
	typ  types.Type // 字段类型
	elem op         // 字段的操作
}

// makeStructOp 为结构体类型创建一个 op。
func (bctx *buildContext) makeStructOp(named *types.Named, typ *types.Struct) (op, error) {
	// Convert fields to []rlpstruct.Field.
	// 将字段转换为 []rlpstruct.Field。
	var allStructFields []rlpstruct.Field
	for i := 0; i < typ.NumFields(); i++ {
		f := typ.Field(i)
		allStructFields = append(allStructFields, rlpstruct.Field{
			Name:     f.Name(),
			Exported: f.Exported(),
			Index:    i,
			Tag:      typ.Tag(i),
			Type:     *bctx.typeToStructType(f.Type()),
		})
	}

	// Filter/validate fields.
	// 过滤/验证字段。
	fields, tags, err := rlpstruct.ProcessFields(allStructFields)
	if err != nil {
		return nil, err
	}

	// Create field ops.
	// 创建字段操作。
	var op = structOp{named: named, typ: typ}
	for i, field := range fields {
		// Advanced struct tags are not supported yet.
		// 高级结构体标签尚未支持。
		tag := tags[i]
		if err := checkUnsupportedTags(field.Name, tag); err != nil {
			return nil, err
		}
		typ := typ.Field(field.Index).Type()
		elem, err := bctx.makeOp(nil, typ, tags[i])
		if err != nil {
			return nil, fmt.Errorf("field %s: %v", field.Name, err)
		}
		f := &structField{name: field.Name, typ: typ, elem: elem}
		if tag.Optional {
			op.optionalFields = append(op.optionalFields, f)
		} else {
			op.fields = append(op.fields, f)
		}
	}
	return op, nil
}

// checkUnsupportedTags 验证是否使用了不支持的结构体标签。
func checkUnsupportedTags(field string, tag rlpstruct.Tags) error {
	if tag.Tail {
		return fmt.Errorf(`field %s has unsupported struct tag "tail"`, field)
	}
	return nil
}

// genWrite 方法生成写入序列化数据的代码
func (op structOp) genWrite(ctx *genContext, v string) string {
	var b bytes.Buffer
	var listMarker = ctx.temp()
	fmt.Fprintf(&b, "%s := w.List()\n", listMarker)
	for _, field := range op.fields {
		selector := v + "." + field.name
		fmt.Fprint(&b, field.elem.genWrite(ctx, selector))
	}
	op.writeOptionalFields(&b, ctx, v)
	fmt.Fprintf(&b, "w.ListEnd(%s)\n", listMarker)
	return b.String()
}

// writeOptionalFields 写入可选字段的序列化逻辑
func (op structOp) writeOptionalFields(b *bytes.Buffer, ctx *genContext, v string) {
	if len(op.optionalFields) == 0 {
		return
	}
	// First check zero-ness of all optional fields.
	// 首先检查所有可选字段是否为零值
	var zeroV = make([]string, len(op.optionalFields))
	for i, field := range op.optionalFields {
		selector := v + "." + field.name
		zeroV[i] = ctx.temp()
		fmt.Fprintf(b, "%s := %s\n", zeroV[i], nonZeroCheck(selector, field.typ, ctx.qualify))
	}
	// Now write the fields.
	// 现在写入字段
	for i, field := range op.optionalFields {
		selector := v + "." + field.name
		cond := ""
		for j := i; j < len(op.optionalFields); j++ {
			if j > i {
				cond += " || "
			}
			cond += zeroV[j]
		}
		fmt.Fprintf(b, "if %s {\n", cond)
		fmt.Fprint(b, field.elem.genWrite(ctx, selector))
		fmt.Fprintf(b, "}\n")
	}
}

// genDecode 生成解码结构体的代码，返回变量名和代码字符串
func (op structOp) genDecode(ctx *genContext) (string, string) {
	// Get the string representation of the type.
	// Here, named types are handled separately because the output
	// would contain a copy of the struct definition otherwise.
	// 获取类型的字符串表示形式
	var typeName string
	if op.named != nil {
		typeName = types.TypeString(op.named, ctx.qualify)
	} else {
		typeName = types.TypeString(op.typ, ctx.qualify)
	}

	// Create struct object.
	// 创建结构体对象
	var resultV = ctx.temp()
	var b bytes.Buffer
	fmt.Fprintf(&b, "var %s %s\n", resultV, typeName)

	// Decode fields.
	// 解码字段
	fmt.Fprintf(&b, "{\n")
	fmt.Fprintf(&b, "if _, err := dec.List(); err != nil { return err }\n")
	for _, field := range op.fields {
		result, code := field.elem.genDecode(ctx)
		fmt.Fprintf(&b, "// %s:\n", field.name)
		fmt.Fprint(&b, code)
		fmt.Fprintf(&b, "%s.%s = %s\n", resultV, field.name, result)
	}
	op.decodeOptionalFields(&b, ctx, resultV)
	fmt.Fprintf(&b, "if err := dec.ListEnd(); err != nil { return err }\n")
	fmt.Fprintf(&b, "}\n")
	return resultV, b.String()
}

// decodeOptionalFields 处理可选字段的解码逻辑
func (op structOp) decodeOptionalFields(b *bytes.Buffer, ctx *genContext, resultV string) {
	var suffix bytes.Buffer
	for _, field := range op.optionalFields {
		result, code := field.elem.genDecode(ctx)
		fmt.Fprintf(b, "// %s:\n", field.name)
		fmt.Fprintf(b, "if dec.MoreDataInList() {\n")
		fmt.Fprint(b, code)
		fmt.Fprintf(b, "%s.%s = %s\n", resultV, field.name, result)
		fmt.Fprintf(&suffix, "}\n")
	}
	suffix.WriteTo(b)
}

// sliceOp handles slice types.
// sliceOp 处理切片类型
type sliceOp struct {
	typ    *types.Slice // 切片类型信息
	elemOp op           // 元素操作处理器
}

// makeOp 根据类型和标签创建对应的操作对象
func (bctx *buildContext) makeSliceOp(typ *types.Slice) (op, error) {
	elemOp, err := bctx.makeOp(nil, typ.Elem(), rlpstruct.Tags{})
	if err != nil {
		return nil, err
	}
	return sliceOp{typ: typ, elemOp: elemOp}, nil
}

func (op sliceOp) genWrite(ctx *genContext, v string) string {
	var (
		listMarker = ctx.temp() // holds return value of w.List()
		iterElemV  = ctx.temp() // iteration variable
		elemCode   = op.elemOp.genWrite(ctx, iterElemV)
	)

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s := w.List()\n", listMarker)
	fmt.Fprintf(&b, "for _, %s := range %s {\n", iterElemV, v)
	fmt.Fprint(&b, elemCode)
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "w.ListEnd(%s)\n", listMarker)
	return b.String()
}

func (op sliceOp) genDecode(ctx *genContext) (string, string) {
	var sliceV = ctx.temp() // holds the output slice
	elemResult, elemCode := op.elemOp.genDecode(ctx)

	var b bytes.Buffer
	fmt.Fprintf(&b, "var %s %s\n", sliceV, types.TypeString(op.typ, ctx.qualify))
	fmt.Fprintf(&b, "if _, err := dec.List(); err != nil { return err }\n")
	fmt.Fprintf(&b, "for dec.MoreDataInList() {\n")
	fmt.Fprintf(&b, "  %s", elemCode)
	fmt.Fprintf(&b, "  %s = append(%s, %s)\n", sliceV, sliceV, elemResult)
	fmt.Fprintf(&b, "}\n")
	fmt.Fprintf(&b, "if err := dec.ListEnd(); err != nil { return err }\n")
	return sliceV, b.String()
}

func (bctx *buildContext) makeOp(name *types.Named, typ types.Type, tags rlpstruct.Tags) (op, error) {
	switch typ := typ.(type) {
	case *types.Named:
		if isBigInt(typ) {
			return bigIntOp{}, nil
		}
		if isUint256(typ) {
			return uint256Op{}, nil
		}
		if typ == bctx.rawValueType {
			return bctx.makeRawValueOp(), nil
		}
		if bctx.isDecoder(typ) {
			return nil, fmt.Errorf("type %v implements rlp.Decoder with non-pointer receiver", typ)
		}
		// TODO: same check for encoder?
		return bctx.makeOp(typ, typ.Underlying(), tags)
	case *types.Pointer:
		if isBigInt(typ.Elem()) {
			return bigIntOp{pointer: true}, nil
		}
		if isUint256(typ.Elem()) {
			return uint256Op{pointer: true}, nil
		}
		// Encoder/Decoder interfaces.
		// 处理编码器/解码器接口
		if bctx.isEncoder(typ) {
			if bctx.isDecoder(typ) {
				return encoderDecoderOp{typ}, nil
			}
			return nil, fmt.Errorf("type %v implements rlp.Encoder but not rlp.Decoder", typ)
		}
		if bctx.isDecoder(typ) {
			return nil, fmt.Errorf("type %v implements rlp.Decoder but not rlp.Encoder", typ)
		}
		// Default pointer handling.
		// 默认指针处理
		return bctx.makePtrOp(typ.Elem(), tags)
	case *types.Basic:
		return bctx.makeBasicOp(typ)
	case *types.Struct:
		return bctx.makeStructOp(name, typ)
	case *types.Slice:
		etyp := typ.Elem()
		if isByte(etyp) && !bctx.isEncoder(etyp) {
			return bctx.makeByteSliceOp(typ), nil
		}
		return bctx.makeSliceOp(typ)
	case *types.Array:
		etyp := typ.Elem()
		if isByte(etyp) && !bctx.isEncoder(etyp) {
			return bctx.makeByteArrayOp(name, typ), nil
		}
		return nil, fmt.Errorf("unhandled array type: %v", typ)
	default:
		return nil, fmt.Errorf("unhandled type: %v", typ)
	}
}

// rlp.Stream：
// rlp.Stream 是 go-ethereum 中用于解码 RLP 数据的流式解析器。它提供方法如 List()、Uint() 等，逐步从字节流中读取数据。
// 在以太坊中，RLP 数据可能是交易、区块头或状态树的编码形式。
//
// DecodeRLP 接口：
// rlp.Decoder 接口要求类型实现 DecodeRLP 方法，用于自定义解码逻辑。
// 例如，一个交易结构体可能通过 DecodeRLP 从字节流恢复其字段（如 Nonce、GasPrice）。

// generateDecoder generates the DecodeRLP method on 'typ'.
// generateDecoder 生成 'typ' 上的 DecodeRLP 方法
func generateDecoder(ctx *genContext, typ string, op op) []byte {
	ctx.resetTemp()
	ctx.addImport(pathOfPackageRLP)

	result, code := op.genDecode(ctx)
	var b bytes.Buffer
	fmt.Fprintf(&b, "func (obj *%s) DecodeRLP(dec *rlp.Stream) error {\n", typ)
	fmt.Fprint(&b, code)
	fmt.Fprintf(&b, "  *obj = %s\n", result)
	fmt.Fprintf(&b, "  return nil\n")
	fmt.Fprintf(&b, "}\n")
	return b.Bytes()
}

// rlp.EncoderBuffer：
// rlp.NewEncoderBuffer 是 go-ethereum 中用于高效编码的工具，避免直接操作底层 io.Writer，减少性能开销。
// Flush() 将缓冲区的内容写入输出流，通常用于网络传输或存储。
// EncodeRLP 接口：
// rlp.Encoder 接口要求类型实现 EncodeRLP 方法，用于自定义编码逻辑。
// 例如，一个区块头结构体可能通过 EncodeRLP 将其字段（如 ParentHash、Number）编码为 RLP 列表。
// RLP 编码规则：
// RLP 将数据编码为字节字符串或列表。例如，[1, "hello"] 编码为 [0xc6, 0x01, 0x85, 'h', 'e', 'l', 'l', 'o']。

// generateEncoder generates the EncodeRLP method on 'typ'.
// generateEncoder 生成 'typ' 上的 EncodeRLP 方法
func generateEncoder(ctx *genContext, typ string, op op) []byte {
	ctx.resetTemp()
	ctx.addImport("io")
	ctx.addImport(pathOfPackageRLP)

	var b bytes.Buffer
	fmt.Fprintf(&b, "func (obj *%s) EncodeRLP(_w io.Writer) error {\n", typ)
	fmt.Fprintf(&b, "  w := rlp.NewEncoderBuffer(_w)\n")
	fmt.Fprint(&b, op.genWrite(ctx, "obj"))
	fmt.Fprintf(&b, "  return w.Flush()\n")
	fmt.Fprintf(&b, "}\n")
	return b.Bytes()
}

// generate 为指定的命名类型生成编码器和解码器代码
func (bctx *buildContext) generate(typ *types.Named, encoder, decoder bool) ([]byte, error) {
	bctx.topType = typ

	pkg := typ.Obj().Pkg()
	op, err := bctx.makeOp(nil, typ, rlpstruct.Tags{})
	if err != nil {
		return nil, err
	}

	var (
		ctx       = newGenContext(pkg)
		encSource []byte
		decSource []byte
	)
	if encoder {
		encSource = generateEncoder(ctx, typ.Obj().Name(), op)
	}
	if decoder {
		decSource = generateDecoder(ctx, typ.Obj().Name(), op)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "package %s\n\n", pkg.Name())
	for _, imp := range ctx.importsList() {
		fmt.Fprintf(&b, "import %q\n", imp)
	}
	if encoder {
		fmt.Fprintln(&b)
		b.Write(encSource)
	}
	if decoder {
		fmt.Fprintln(&b)
		b.Write(decSource)
	}

	source := b.Bytes()
	// fmt.Println(string(source))
	return format.Source(source)
}
