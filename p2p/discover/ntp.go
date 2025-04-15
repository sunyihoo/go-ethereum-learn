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

// Contains the NTP time drift detection via the SNTP protocol:
//   https://tools.ietf.org/html/rfc4330

package discover

import (
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

const (
	// ntpPool 是用于查询当前时间的 NTP 服务器地址
	ntpPool = "pool.ntp.org" // ntpPool is the NTP server to query for the current time
	// ntpChecks 是对 NTP 服务器进行的时间测量次数
	ntpChecks = 3 // Number of measurements to do against the NTP server
)

// 在以太坊客户端（如 go-ethereum）中，精确的时间同步至关重要。
// 以太坊网络依赖时间戳来验证区块和交易。例如，区块时间戳必须在合理范围内，否则节点可能会拒绝区块。
// 因此，检查时钟漂移是确保节点与网络一致性的重要步骤。

// checkClockDrift queries an NTP server for clock drifts and warns the user if
// one large enough is detected.
//
// checkClockDrift 查询 NTP 服务器以检测时钟漂移，并在检测到足够大的漂移时警告用户。
func checkClockDrift() {
	drift, err := sntpDrift(ntpChecks)
	if err != nil {
		return
	}
	if drift < -driftThreshold || drift > driftThreshold {
		// 系统时钟似乎偏离了 %v，这可能会阻止网络连接
		log.Warn(fmt.Sprintf("System clock seems off by %v, which can prevent network connectivity", drift))
		// 请在系统设置中启用网络时间同步。
		log.Warn("Please enable network time synchronisation in system settings.")
	} else {
		// NTP 健全性检查完成，时钟漂移为 drift
		log.Debug("NTP sanity check done", "drift", drift)
	}
}

// sntpDrift does a naive time resolution against an NTP server and returns the
// measured drift. This method uses the simple version of NTP. It's not precise
// but should be fine for these purposes.
//
// Note, it executes two extra measurements compared to the number of requested
// ones to be able to discard the two extremes as outliers.
//
// sntpDrift 对 NTP 服务器执行简单的时间解析并返回测量的漂移。此方法使用简化的 NTP 版本。
// 它不够精确，但对于这些用途来说已经足够。
//
// 注意，它会比请求的测量次数多执行两次测量，以便丢弃两个极端值作为离群值。
func sntpDrift(measurements int) (time.Duration, error) {
	// Resolve the address of the NTP server
	// 解析 NTP 服务器的地址
	addr, err := net.ResolveUDPAddr("udp", ntpPool+":123")
	if err != nil {
		return 0, err
	}
	// Construct the time request (empty package with only 2 fields set):
	//   Bits 3-5: Protocol version, 3
	//   Bits 6-8: Mode of operation, client, 3
	//
	// 构造时间请求（仅设置两个字段的空数据包）：
	//   第 3-5 位：协议版本，3
	//   第 6-8 位：操作模式，客户端，3
	request := make([]byte, 48)

	// request[0] 是第一个字节，包含协议版本和操作模式：
	// 3<<3：将版本号 3 左移 3 位，占据第 3-5 位，表示 NTP 协议版本 3。
	//
	// | 3：与操作模式 3（客户端模式）进行按位或运算，占据第 6-8 位。
	// request[0] 的二进制形式为 00011011（十进制 27），符合简化的 SNTP 请求格式。
	//
	// 00000011 << 3 = 00011000
	// 00011000 | 00000011 = 00011011
	request[0] = 3<<3 | 3

	// Execute each of the measurements
	// 执行每一次测量
	drifts := []time.Duration{}
	for i := 0; i < measurements+2; i++ {
		// Dial the NTP server and send the time retrieval request
		// 连接 NTP 服务器并发送时间检索请求
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			return 0, err
		}
		defer conn.Close()

		sent := time.Now()
		if _, err = conn.Write(request); err != nil {
			return 0, err
		}
		// Retrieve the reply and calculate the elapsed time
		// 接收回复并计算经过的时间
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		reply := make([]byte, 48)
		if _, err = conn.Read(reply); err != nil {
			return 0, err
		}
		elapsed := time.Since(sent)

		//提取时间：
		// sec：从回复的第 40-43 字节读取秒数（大端序）。
		// frac：从第 44-47 字节读取秒的小数部分（大端序）。
		// nanosec：将秒数转换为纳秒并加上小数部分（右移 32 位以调整精度）。
		// t：以 1900 年 1 月 1 日为基准（NTP 的时间起点），加上 nanosec，转换为本地时间。

		// Reconstruct the time from the reply data
		// 从回复数据中重建时间
		sec := uint64(reply[43]) | uint64(reply[42])<<8 | uint64(reply[41])<<16 | uint64(reply[40])<<24
		frac := uint64(reply[47]) | uint64(reply[46])<<8 | uint64(reply[45])<<16 | uint64(reply[44])<<24

		nanosec := sec*1e9 + (frac*1e9)>>32

		t := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nanosec)).Local()

		// 计算漂移：
		// sent.Sub(t)：发送请求的时间与服务器返回的时间之差。
		// elapsed/2：假设往返时间对称，服务器响应时间为 RTT 的一半。
		// 两者相加得到单次漂移。

		// Calculate the drift based on an assumed answer time of RRT/2
		// 根据假设的回答时间（往返时间 RTT/2）计算漂移
		drifts = append(drifts, sent.Sub(t)+elapsed/2)
	}
	// Calculate average drift (drop two extremities to avoid outliers)
	// 计算平均漂移（丢弃两个极端值以避免离群值）
	slices.Sort(drifts)

	drift := time.Duration(0)
	for i := 1; i < len(drifts)-1; i++ {
		drift += drifts[i]
	}
	return drift / time.Duration(measurements), nil
}
