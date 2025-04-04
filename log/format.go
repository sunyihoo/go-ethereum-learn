package log

import (
	"bytes"
	"fmt"
	"log/slog"
	"math/big"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/holiman/uint256"
)

const (
	// timeFormat        = "2006-01-02T15:04:05-0700" // Standard time format for log values if not handled specially
	timeFormat = "2006-01-02T15:04:05-0700" // 如果没有特殊处理，日志值的标准时间格式
	// floatFormat       = 'f' // Format specifier for floats
	floatFormat = 'f' // 浮点数的格式说明符
	// termMsgJust       = 40 // Width to justify the log message field when attributes are present
	termMsgJust = 40 // 当存在属性时，用于对齐日志消息字段的宽度
	// termCtxMaxPadding = 40 // Maximum padding allowed for attribute values for alignment
	termCtxMaxPadding = 40 // 为对齐属性值所允许的最大填充宽度
)

// 40 spaces, pre-allocated for padding efficiency.
// 40 个空格，为提高填充效率而预先分配。
var spaces = []byte("                                        ")

// TerminalStringer is an analogous interface to the stdlib stringer, allowing
// own types to have custom shortened serialization formats when printed to the
// screen.
// TerminalStringer 是一个类似于标准库 stringer 的接口，允许
// 自定义类型在打印到屏幕时拥有自定义的缩短序列化格式。
type TerminalStringer interface {
	TerminalString() string // Returns a concise string representation suitable for terminal output. 返回适合终端输出的简洁字符串表示。
}

func (h *TerminalHandler) format(buf []byte, r slog.Record, usecolor bool) []byte {
	// 1. Escape the main message for safe printing.
	// 1. 对主消息进行转义以便安全打印。
	msg := escapeMessage(r.Message)
	var color = "" // ANSI color code string ANSI 颜色代码字符串
	// 2. Determine color based on log level if 'usecolor' is enabled.
	// 2. 如果启用了 'usecolor'，则根据日志级别确定颜色。
	if usecolor {
		switch r.Level {
		case LevelCrit:
			color = "\x1b[35m" // Magenta 洋红色
		case slog.LevelError:
			color = "\x1b[31m" // Red 红色
		case slog.LevelWarn:
			color = "\x1b[33m" // Yellow 黄色
		case slog.LevelInfo:
			color = "\x1b[32m" // Green 绿色
		case slog.LevelDebug:
			color = "\x1b[36m" // Cyan 青色
		case LevelTrace:
			color = "\x1b[34m" // Blue 蓝色
		}
	}
	// 3. Initialize or reuse the buffer.
	// 3. 初始化或重用缓冲区。
	if buf == nil {
		buf = make([]byte, 0, 30+termMsgJust) // Preallocate buffer with estimated size 预分配具有估计大小的缓冲区
	}
	b := bytes.NewBuffer(buf) // Use bytes.Buffer for easier writing 使用 bytes.Buffer 以方便写入

	// 4. Write Level (potentially colored).
	// 4. 写入级别（可能带颜色）。
	if color != "" { // Start color 开始颜色
		b.WriteString(color)
		b.WriteString(LevelAlignedString(r.Level)) // Write fixed-width level string 写入固定宽度的级别字符串
		b.WriteString("\x1b[0m")                   // Reset color 重置颜色
	} else {
		b.WriteString(LevelAlignedString(r.Level)) // Write level without color 无颜色写入级别
	}

	// 5. Write Timestamp using custom terminal format.
	// 5. 使用自定义终端格式写入时间戳。
	b.WriteString("[")
	writeTimeTermFormat(b, r.Time) // Format time as MM-DD|HH:MM:SS.ms 将时间格式化为 MM-DD|HH:MM:SS.ms
	b.WriteString("] ")

	// 6. Write Log Source (File/Line, Function).
	// 6. 写入日志来源 (文件/行号, 函数)。
	b.WriteString(h.Source(r).String()) // Assuming Source method exists 假设 Source 方法存在
	b.WriteString(" ")

	// 7. Write the main log message.
	// 7. 写入主日志消息。
	b.WriteString(msg)

	// 8. Justify (pad) the message area if attributes follow and message is short.
	// 8. 如果后面有属性且消息较短，则对齐（填充）消息区域。
	// try to justify the log output for short messages
	// 尝试为短消息对齐日志输出
	//length := utf8.RuneCountInString(msg) // Use RuneCount for UTF8 correctness 对 UTF8 使用 RuneCount 以确保正确性 (Commented out in original code) （在原始代码中被注释掉）
	length := len(msg)                                           // Original code uses len(), potentially faster but less accurate for multi-byte chars 原始代码使用 len()，可能更快但对多字节字符不太准确
	if (r.NumAttrs()+len(h.attrs)) > 0 && length < termMsgJust { // Check if attributes exist and message is shorter than justification width 检查是否存在属性且消息长度小于对齐宽度
		b.Write(spaces[:termMsgJust-length]) // Write padding spaces 写入填充空格
	}
	// 9. Format and write attributes.
	// 9. 格式化并写入属性。
	h.formatAttributes(b, r, color) // Call helper function 调用辅助函数

	// 10. Return the formatted bytes.
	// 10. 返回格式化后的字节。
	return b.Bytes()
}

// formatAttributes formats and appends the log record's attributes to the buffer.
// formatAttributes 格式化日志记录的属性并将其附加到缓冲区。
func (h *TerminalHandler) formatAttributes(buf *bytes.Buffer, r slog.Record, color string) {
	// Internal function to write a single attribute.
	// 用于写入单个属性的内部函数。
	writeAttr := func(attr slog.Attr, last bool) {
		buf.WriteByte(' ') // Separator space 分隔符空格

		// Write Key (potentially colored and escaped)
		// 写入键（可能带颜色并转义）
		if color != "" {
			buf.WriteString(color) // Apply color 应用颜色
			// Use AvailableBuffer to potentially avoid allocation when appending escaped string.
			// 使用 AvailableBuffer 可能可以在附加转义字符串时避免分配。
			buf.Write(appendEscapeString(buf.AvailableBuffer(), attr.Key))
			buf.WriteString("\x1b[0m=") // Reset color and add separator 重置颜色并添加分隔符
		} else {
			buf.Write(appendEscapeString(buf.AvailableBuffer(), attr.Key))
			buf.WriteByte('=') // Add separator 添加分隔符
		}
		// Format Value using the dedicated function
		// 使用专用函数格式化值
		val := FormatSlogValue(attr.Value, buf.AvailableBuffer())

		// Apply padding for alignment based on stored/updated padding value
		// 根据存储/更新的填充值应用填充以进行对齐
		padding := h.fieldPadding[attr.Key] // Get stored padding 获取存储的填充值

		// Note: Using RuneCount for length calculation is more accurate for terminal alignment with multi-byte chars.
		// 注意：对于包含多字节字符的终端对齐，使用 RuneCount 计算长度更准确。
		length := utf8.RuneCount(val)                        // Calculate display length 计算显示长度
		if padding < length && length <= termCtxMaxPadding { // If current value is longer (within limit), update padding 如果当前值更长（在限制内），则更新填充值
			padding = length
			h.fieldPadding[attr.Key] = padding // Store updated padding 存储更新后的填充值
		}
		buf.Write(val)                 // Write the formatted value 写入格式化后的值
		if !last && padding > length { // If not the last attribute and padding is needed 如果不是最后一个属性且需要填充
			buf.Write(spaces[:padding-length]) // Write padding spaces 写入填充空格
		}
	}

	var n = 0                                // Counter for attribute index 属性索引计数器
	var nAttrs = len(h.attrs) + r.NumAttrs() // Total number of attributes 总属性数

	// Write handler's predefined attributes
	// 写入处理程序的预定义属性
	for _, attr := range h.attrs {
		writeAttr(attr, n == nAttrs-1) // Pass 'last' flag 传递 'last' 标志
		n++
	}
	// Write record's attributes
	// 写入记录的属性
	r.Attrs(func(attr slog.Attr) bool { // Iterate through record attributes 遍历记录属性
		writeAttr(attr, n == nAttrs-1)
		n++
		return true // Continue iteration 继续迭代
	})
	buf.WriteByte('\n') // Add newline at the end of the log entry 在日志条目末尾添加换行符
}

// FormatSlogValue formats a slog.Value for serialization to terminal.
// FormatSlogValue 格式化 slog.Value 以便序列化到终端。
// It handles various data types, including Ethereum-specific ones like big.Int and uint256.Int.
// 它处理各种数据类型，包括以太坊特定的类型，如 big.Int 和 uint256.Int。
func FormatSlogValue(v slog.Value, tmp []byte) (result []byte) {
	var value any // To hold the underlying value for reflection/panic handling 用于保存底层值以进行反射/panic 处理
	// Recover from potential panics during value processing (e.g., nil pointers)
	// 从值处理期间的潜在 panic (例如，空指针) 中恢复
	defer func() {
		if err := recover(); err != nil {
			// Check if the panic was due to a nil pointer dereference
			// 检查 panic 是否由空指针解引用引起
			if valRef := reflect.ValueOf(value); valRef.Kind() == reflect.Ptr && valRef.IsNil() {
				result = []byte("<nil>") // Output <nil> for nil pointers 对空指针输出 <nil>
			} else {
				panic(err) // Re-panic if it was something else 如果是其他原因则重新 panic
			}
		}
	}()

	// Handle basic slog kinds directly
	// 直接处理基本的 slog 类型
	switch v.Kind() {
	case slog.KindString:
		return appendEscapeString(tmp, v.String()) // Escape and append string 转义并附加字符串
	case slog.KindInt64: // All int-types (int8, int16 etc) wind up here 所有整数类型（int8、int16 等）最终都会到这里
		return appendInt64(tmp, v.Int64()) // Format with thousand separators 使用千位分隔符格式化
	case slog.KindUint64: // All uint-types (uint8, uint16 etc) wind up here 所有无符号整数类型（uint8、uint16 等）最终都会到这里
		return appendUint64(tmp, v.Uint64(), false) // Format with thousand separators 使用千位分隔符格式化
	case slog.KindFloat64:
		return strconv.AppendFloat(tmp, v.Float64(), floatFormat, 3, 64) // Format float 格式化浮点数
	case slog.KindBool:
		return strconv.AppendBool(tmp, v.Bool()) // Format boolean 格式化布尔值
	case slog.KindDuration:
		value = v.Duration() // Fall through to general handling 转到通用处理
	case slog.KindTime:
		// Performance optimization: No need for escaping since the provided
		// timeFormat doesn't have any escape characters, and escaping is
		// expensive.
		// 性能优化：无需转义，因为提供的
		// timeFormat 没有任何转义字符，而且转义成本高昂。
		return v.Time().AppendFormat(tmp, timeFormat) // Use standard time format 使用标准时间格式
	default: // KindAny, KindGroup, KindLogValuer
		value = v.Any() // Get the underlying value 获取底层值
	}
	// Handle nil value explicitly
	// 显式处理 nil 值
	if value == nil {
		return []byte("<nil>")
	}
	// Handle specific types, including common Go types and Ethereum types
	// 处理特定类型，包括常见的 Go 类型和以太坊类型
	switch v := value.(type) {
	case *big.Int: // Need to be before fmt.Stringer-clause 需要在 fmt.Stringer 子句之前
		return appendBigInt(tmp, v) // Format big.Int with separators 使用分隔符格式化 big.Int
	case *uint256.Int: // Need to be before fmt.Stringer-clause 需要在 fmt.Stringer 子句之前
		return appendU256(tmp, v) // Format uint256.Int with separators 使用分隔符格式化 uint256.Int
	case error:
		return appendEscapeString(tmp, v.Error()) // Format error message and escape 格式化错误消息并转义
	case TerminalStringer: // Check for custom terminal representation 检查自定义终端表示
		return appendEscapeString(tmp, v.TerminalString()) // Use custom format and escape 使用自定义格式并转义
	case fmt.Stringer: // Check for standard string representation 检查标准字符串表示
		return appendEscapeString(tmp, v.String()) // Use standard format and escape 使用标准格式并转义
	}

	// Fallback: Use fmt %+v for generic formatting, then escape the result
	// 回退：使用 fmt %+v 进行通用格式化，然后转义结果
	// We can use the 'tmp' as a scratch-buffer, to first format the
	// value, and in a second step do escaping.
	// 我们可以使用 'tmp' 作为暂存缓冲区，首先格式化
	// 值，然后在第二步进行转义。
	internal := fmt.Appendf(tmp, "%+v", value)           // Format using detailed representation 使用详细表示进行格式化
	return appendEscapeString(tmp[:0], string(internal)) // Escape the formatted string (reset tmp slice before use) 转义格式化后的字符串（使用前重置 tmp 切片）
}

// appendInt64 formats n with thousand separators and writes into buffer dst.
// appendInt64 使用千位分隔符格式化 n 并写入缓冲区 dst。
func appendInt64(dst []byte, n int64) []byte {
	if n < 0 {
		return appendUint64(dst, uint64(-n), true) // Handle negative numbers via uint64 helper 通过 uint64 辅助函数处理负数
	}
	return appendUint64(dst, uint64(n), false) // Handle positive numbers 处理正数
}

// appendUint64 formats n with thousand separators and writes into buffer dst.
// appendUint64 使用千位分隔符格式化 n 并写入缓冲区 dst。
func appendUint64(dst []byte, n uint64, neg bool) []byte {
	// Small numbers are fine as is
	// 小数字保持原样即可
	if n < 100000 { // Optimization: format small numbers directly 优化：直接格式化小数字
		if neg {
			return strconv.AppendInt(dst, -int64(n), 10) // Append negative 直接附加负数
		} else {
			return strconv.AppendInt(dst, int64(n), 10) // Append positive 直接附加正数
		}
	}
	// Large numbers should be split
	// 大数字应进行分割
	const maxLength = 26 // Max length for uint64 with separators uint64 带分隔符的最大长度

	var (
		out   = make([]byte, maxLength) // Temporary buffer 临时缓冲区
		i     = maxLength - 1           // Index starts from end 从末尾开始的索引
		comma = 0                       // Counter for comma placement 逗号放置计数器
	)
	// Build the string in reverse order
	// 以相反的顺序构建字符串
	for ; n > 0; i-- { // Iterate while number > 0 当数字 > 0 时迭代
		if comma == 3 { // Insert comma every 3 digits 每 3 位插入逗号
			comma = 0
			out[i] = ','
		} else {
			comma++
			out[i] = '0' + byte(n%10) // Add digit 添加数字
			n /= 10                   // Move to next digit 移动到下一位
		}
	}
	if neg { // Add negative sign if needed 如果需要，添加负号
		out[i] = '-'
		i--
	}
	// Append the formatted part of 'out' to 'dst'
	// 将 'out' 中格式化好的部分附加到 'dst'
	return append(dst, out[i+1:]...)
}

// FormatLogfmtUint64 formats n with thousand separators. (Used elsewhere for logfmt potentially)
// FormatLogfmtUint64 使用千位分隔符格式化 n。（可能在其他地方用于 logfmt）
func FormatLogfmtUint64(n uint64) string {
	return string(appendUint64(nil, n, false)) // Use helper with nil buffer 使用带有 nil 缓冲区的辅助函数
}

// appendBigInt formats n with thousand separators and writes to dst.
// appendBigInt 使用千位分隔符格式化 n 并写入 dst。
func appendBigInt(dst []byte, n *big.Int) []byte {
	// Optimization: Use faster uint64/int64 formatting if possible
	// 优化：如果可能，使用更快的 uint64/int64 格式化
	if n.IsUint64() {
		return appendUint64(dst, n.Uint64(), false)
	}
	if n.IsInt64() {
		return appendInt64(dst, n.Int64())
	}

	// Handle general big.Int
	// 处理通用的 big.Int
	var (
		text  = n.String()                          // Get standard string representation 获取标准字符串表示
		buf   = make([]byte, len(text)+len(text)/3) // Preallocate buffer with estimated size 预分配具有估计大小的缓冲区
		comma = 0                                   // Comma counter 逗号计数器
		i     = len(buf) - 1                        // Index from end 从末尾开始的索引
	)
	// Build string in reverse, inserting commas
	// 反向构建字符串，插入逗号
	for j := len(text) - 1; j >= 0; j, i = j-1, i-1 {
		c := text[j] // Current character 当前字符

		switch {
		case c == '-': // Handle negative sign 处理负号
			buf[i] = c
		case comma == 3: // Insert comma 插入逗号
			buf[i] = ','
			i-- // Move buffer index back one more 向后移动缓冲区索引一位
			comma = 0
			fallthrough // Continue to default case 继续到 default 情况
		default: // Add digit 添加数字
			buf[i] = c
			comma++
		}
	}
	// Append the formatted part to dst
	// 将格式化好的部分附加到 dst
	return append(dst, buf[i+1:]...)
}

// appendU256 formats n with thousand separators.
// appendU256 使用千位分隔符格式化 n。
func appendU256(dst []byte, n *uint256.Int) []byte {
	// Optimization: Use uint64 formatting if possible
	// 优化：如果可能，使用 uint64 格式化
	if n.IsUint64() {
		return appendUint64(dst, n.Uint64(), false)
	}
	// Use the PrettyDec method from the uint256 library which already adds separators
	// 使用 uint256 库中的 PrettyDec 方法，该方法已经添加了分隔符
	res := []byte(n.PrettyDec(',')) // Get pre-formatted string 获取预格式化字符串
	return append(dst, res...)      // Append to destination buffer 附加到目标缓冲区
}

// appendEscapeString writes the string s to the given writer, with
// escaping/quoting if needed. Used for attribute keys and values.
// appendEscapeString 将字符串 s 写入给定的写入器，并在需要时进行
// 转义/引用。用于属性键和值。
func appendEscapeString(dst []byte, s string) []byte {
	needsQuoting := false  // Flag if quoting is needed (contains space or '=') 如果需要引用（包含空格或 '='），则设置标志
	needsEscaping := false // Flag if escaping is needed (contains control chars, quotes, high bytes) 如果需要转义（包含控制字符、引号、高位字节），则设置标志
	for _, r := range s {
		// If it contains spaces or equal-sign, we need to quote it.
		// 如果包含空格或等号，我们需要引用它。
		if r == ' ' || r == '=' {
			needsQuoting = true
			continue // Check remaining characters for escaping 检查剩余字符是否需要转义
		}
		// We need to escape it, if it contains
		// - character " (0x22) and lower (except space)
		// - characters above ~ (0x7E), plus equal-sign
		// 如果它包含以下内容，我们需要对其进行转义
		// - 字符 " (0x22) 及更低（空格除外）
		// - 波浪号 ~ (0x7E) 以上的字符，以及等号
		// Note: Original check r <= '"' includes '=', so the first check isn't strictly necessary if escaping is needed.
		// 注意：原始检查 r <= '"' 包含 '='，因此如果需要转义，第一个检查并非绝对必要。
		if r <= '"' || r > '~' {
			needsEscaping = true
			break // No need to check further 无需进一步检查
		}
	}
	if needsEscaping {
		return strconv.AppendQuote(dst, s) // Use standard quoting/escaping 使用标准引用/转义
	}
	// No escaping needed, but we might have to place within quote-marks, in case
	// it contained a space
	// 不需要转义，但如果包含空格，我们可能需要将其放在引号内
	if needsQuoting {
		dst = append(dst, '"')          // Add opening quote 添加起始引号
		dst = append(dst, []byte(s)...) // Add string content 添加字符串内容
		return append(dst, '"')         // Add closing quote 添加结束引号
	}
	// No quoting or escaping needed
	// 无需引用或转义
	return append(dst, []byte(s)...)
}

// escapeMessage checks if the provided string needs escaping/quoting, similarly
// to escapeString. The difference is that this method is more lenient: it allows
// for spaces and linebreaks to occur without needing quoting. Used for the main log message.
// escapeMessage 检查提供的字符串是否需要转义/引用，类似于
// escapeString。区别在于此方法更宽松：它允许
// 出现空格和换行符而无需引用。用于主日志消息。
func escapeMessage(s string) string {
	needsQuoting := false
	for _, r := range s {
		// Allow CR/LF/TAB. This is to make multi-line messages work.
		// 允许 CR/LF/TAB。这是为了让多行消息能够工作。
		if r == '\r' || r == '\n' || r == '\t' {
			continue // Allow these characters without quoting 允许这些字符而不引用
		}
		// We quote everything below <space> (0x20) and above~ (0x7E),
		// plus equal-sign
		// 我们引用 <空格> (0x20) 以下和 ~ (0x7E) 以上的所有内容，
		// 加上等号
		if r < ' ' || r > '~' || r == '=' {
			needsQuoting = true
			break // Found character requiring quoting 找到需要引用的字符
		}
	}
	if !needsQuoting {
		return s // Return original string if no quoting needed 如果不需要引用，则返回原始字符串
	}
	return strconv.Quote(s) // Quote the entire string 引用整个字符串
}

// writeTimeTermFormat writes on the format "MM-DD|HH:MM:SS.ms" e.g., "01-02|15:04:05.123"
// writeTimeTermFormat 以 "MM-DD|HH:MM:SS.ms" 格式写入，例如 "01-02|15:04:05.123"
func writeTimeTermFormat(buf *bytes.Buffer, t time.Time) {
	_, month, day := t.Date()            // Get month and day 获取月份和日期
	writePosIntWidth(buf, int(month), 2) // Write month with padding 写入月份并填充
	buf.WriteByte('-')                   // Separator 分隔符
	writePosIntWidth(buf, day, 2)        // Write day with padding 写入日期并填充
	buf.WriteByte('|')                   // Separator 分隔符
	hour, min, sec := t.Clock()          // Get H, M, S 获取时、分、秒
	writePosIntWidth(buf, hour, 2)       // Write hour 写入小时
	buf.WriteByte(':')                   // Separator 分隔符
	writePosIntWidth(buf, min, 2)        // Write minute 写入分钟
	buf.WriteByte(':')                   // Separator 分隔符
	writePosIntWidth(buf, sec, 2)        // Write second 写入秒
	ns := t.Nanosecond()                 // Get nanoseconds 获取纳秒
	buf.WriteByte('.')                   // Millisecond separator 毫秒分隔符
	writePosIntWidth(buf, ns/1e6, 3)     // Write milliseconds (ns/1,000,000) 写入毫秒 (纳秒/1,000,000)
}

// writePosIntWidth writes non-negative integer i to the buffer, padded on the left
// by zeroes to the given width. Use a width of 0 to omit padding.
// writePosIntWidth 将非负整数 i 写入缓冲区，左侧用零填充到
// 给定宽度。使用宽度 0 省略填充。
// Adapted from pkg.go.dev/log/slog/internal/buffer (or similar standard library code)
// 改编自 pkg.go.dev/log/slog/internal/buffer（或类似的标准库代码）
func writePosIntWidth(b *bytes.Buffer, i, width int) {
	// Cheap integer to fixed-width decimal ASCII.
	// 廉价的整数到固定宽度十进制 ASCII 转换。
	// Copied from log/log.go.
	// 从 log/log.go 复制。
	if i < 0 {
		panic("negative int") // Should not happen for time components 不应发生在时间组件上
	}
	// Assemble decimal in reverse order.
	// 以相反的顺序组装十进制数。
	var bb [20]byte   // Buffer for digits 数字缓冲区
	bp := len(bb) - 1 // Pointer to last byte 指向最后一个字节的指针
	// Format digits from right to left
	// 从右到左格式化数字
	for i >= 10 || width > 1 { // Continue while number >= 10 OR padding is needed 当数字 >= 10 或需要填充时继续
		width--                       // Decrement padding width 减少填充宽度
		q := i / 10                   // Quotient 商
		bb[bp] = byte('0' + i - q*10) // Remainder is the digit 余数是数字
		bp--                          // Move pointer left 指针左移
		i = q                         // Continue with quotient 继续处理商
	}
	// i < 10
	bb[bp] = byte('0' + i) // Last digit 最后一个数字
	b.Write(bb[bp:])       // Write the formatted digits 写入格式化后的数字
}
