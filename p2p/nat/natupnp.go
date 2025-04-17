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

package nat

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
)

const (
	soapRequestTimeout = 3 * time.Second        // SOAP 请求超时时间
	rateLimit          = 200 * time.Millisecond // 请求速率限制
)

type upnp struct {
	dev         *goupnp.RootDevice // UPnP 根设备
	service     string             // 服务类型
	client      upnpClient         // UPnP 客户端
	mu          sync.Mutex         // 互斥锁
	lastReqTime time.Time          // 上次请求时间
	rand        *rand.Rand         // 随机数生成器
}

type upnpClient interface {
	GetExternalIPAddress() (string, error)                                             // 获取外部 IP 地址
	AddPortMapping(string, uint16, string, uint16, string, bool, string, uint32) error // 添加端口映射
	DeletePortMapping(string, uint16, string) error                                    // 删除端口映射
	GetNATRSIPStatus() (sip bool, nat bool, err error)                                 // 获取 NAT 和 SIP 状态
}

func (n *upnp) natEnabled() bool {
	var ok bool
	var err error
	n.withRateLimit(func() error { // 使用速率限制调用
		_, ok, err = n.client.GetNATRSIPStatus() // 检查 NAT 状态
		return err
	})
	return err == nil && ok // 如果无错误且 NAT 启用则返回 true
}

func (n *upnp) ExternalIP() (addr net.IP, err error) {
	var ipString string
	n.withRateLimit(func() error { // 使用速率限制调用
		ipString, err = n.client.GetExternalIPAddress() // 获取外部 IP 地址
		return err
	})

	if err != nil {
		return nil, err // 如果出错则返回错误
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, errors.New("bad IP in response") // 如果 IP 无效则返回错误
	}
	return ip, nil // 返回解析后的 IP
}

func (n *upnp) AddMapping(protocol string, extport, intport int, desc string, lifetime time.Duration) (uint16, error) {
	ip, err := n.internalAddress() // 获取本地 IP 地址
	if err != nil {
		return 0, nil // TODO: Shouldn't we return the error?
	}
	protocol = strings.ToUpper(protocol)        // 将协议转换为大写
	lifetimeS := uint32(lifetime / time.Second) // 将生命周期转换为秒
	n.DeleteMapping(protocol, extport, intport) // 先删除现有映射

	err = n.withRateLimit(func() error { // 使用速率限制添加映射
		return n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	})
	if err == nil {
		return uint16(extport), nil // 如果成功则返回外部端口
	}

	return uint16(extport), n.withRateLimit(func() error { // 如果失败，尝试添加任意端口映射
		p, err := n.addAnyPortMapping(protocol, extport, intport, ip, desc, lifetimeS)
		if err == nil {
			extport = int(p) // 更新外部端口
		}
		return err // 返回错误（如果有）
	})
}

func (n *upnp) addAnyPortMapping(protocol string, extport, intport int, ip net.IP, desc string, lifetimeS uint32) (uint16, error) {
	if client, ok := n.client.(*internetgateway2.WANIPConnection2); ok { // 检查是否支持 WANIPConnection2
		return client.AddAnyPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	}
	// It will retry with a random port number if the client does
	// not support AddAnyPortMapping.
	// 如果客户端不支持 AddAnyPortMapping，则使用随机端口重试。
	extport = n.randomPort() // 生成随机端口
	err := n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	if err != nil {
		return 0, err // 如果出错则返回错误
	}
	return uint16(extport), nil // 返回随机映射的端口
}

func (n *upnp) randomPort() int {
	if n.rand == nil {
		n.rand = rand.New(rand.NewSource(time.Now().UnixNano())) // 初始化随机数生成器
	}
	return n.rand.Intn(math.MaxUint16-10000) + 10000 // 返回 10000 到 65535 之间的随机端口
}

func (n *upnp) internalAddress() (net.IP, error) {
	devaddr, err := net.ResolveUDPAddr("udp4", n.dev.URLBase.Host) // 解析设备地址
	if err != nil {
		return nil, err // 如果出错则返回错误
	}
	ifaces, err := net.Interfaces() // 获取网络接口
	if err != nil {
		return nil, err // 如果出错则返回错误
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs() // 获取接口地址
		if err != nil {
			return nil, err // 如果出错则返回错误
		}
		for _, addr := range addrs {
			if x, ok := addr.(*net.IPNet); ok && x.Contains(devaddr.IP) { // 检查是否包含设备 IP
				return x.IP, nil // 返回本地 IP
			}
		}
	}
	return nil, fmt.Errorf("could not find local address in same net as %v", devaddr) // 如果未找到则返回错误
}

func (n *upnp) DeleteMapping(protocol string, extport, intport int) error {
	return n.withRateLimit(func() error { // 使用速率限制删除映射
		return n.client.DeletePortMapping("", uint16(extport), strings.ToUpper(protocol))
	})
}

func (n *upnp) String() string {
	return "UPNP " + n.service // 返回 UPnP 服务字符串
}

func (n *upnp) withRateLimit(fn func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	lastreq := time.Since(n.lastReqTime) // 计算上次请求后的时间
	if lastreq < rateLimit {             // 如果小于速率限制
		time.Sleep(rateLimit - lastreq) // 等待达到限制时间
	}
	err := fn()                // 执行请求
	n.lastReqTime = time.Now() // 更新最后请求时间
	return err                 // 返回错误（如果有）
}

// discoverUPnP searches for Internet Gateway Devices
// and returns the first one it can find on the local network.
//
// discoverUPnP 搜索互联网网关设备，并返回本地网络上找到的第一个设备。
func discoverUPnP() Interface {
	found := make(chan *upnp, 2) // 创建发现通道
	// IGDv1
	go discover(found, internetgateway1.URN_WANConnectionDevice_1, func(sc goupnp.ServiceClient) *upnp {
		switch sc.Service.ServiceType {
		case internetgateway1.URN_WANIPConnection_1:
			return &upnp{service: "IGDv1-IP1", client: &internetgateway1.WANIPConnection1{ServiceClient: sc}}
		case internetgateway1.URN_WANPPPConnection_1:
			return &upnp{service: "IGDv1-PPP1", client: &internetgateway1.WANPPPConnection1{ServiceClient: sc}}
		}
		return nil
	})
	// IGDv2
	go discover(found, internetgateway2.URN_WANConnectionDevice_2, func(sc goupnp.ServiceClient) *upnp {
		switch sc.Service.ServiceType {
		case internetgateway2.URN_WANIPConnection_1:
			return &upnp{service: "IGDv2-IP1", client: &internetgateway2.WANIPConnection1{ServiceClient: sc}}
		case internetgateway2.URN_WANIPConnection_2:
			return &upnp{service: "IGDv2-IP2", client: &internetgateway2.WANIPConnection2{ServiceClient: sc}}
		case internetgateway2.URN_WANPPPConnection_1:
			return &upnp{service: "IGDv2-PPP1", client: &internetgateway2.WANPPPConnection1{ServiceClient: sc}}
		}
		return nil
	})
	for i := 0; i < cap(found); i++ {
		if c := <-found; c != nil { // 返回第一个成功的 UPnP 实例
			return c
		}
	}
	return nil // 如果未找到则返回 nil
}

// discover finds devices matching the given target and calls matcher for
// all advertised services of each device. The first non-nil service found
// is sent into out. If no service matched, nil is sent.
//
// discover 查找与给定目标匹配的设备，并对每个设备的所有广告服务调用 matcher。
// 找到的第一个非 nil 服务被发送到 out。如果没有服务匹配，则发送 nil。
func discover(out chan<- *upnp, target string, matcher func(goupnp.ServiceClient) *upnp) {
	devs, err := goupnp.DiscoverDevices(target) // 发现匹配目标的设备
	if err != nil {
		out <- nil // 如果出错则发送 nil
		return
	}
	found := false
	for i := 0; i < len(devs) && !found; i++ {
		if devs[i].Root == nil {
			continue // 跳过无根设备的实例
		}
		devs[i].Root.Device.VisitServices(func(service *goupnp.Service) { // 遍历服务
			if found {
				return // 如果已找到则退出
			}

			// todo learn what and how goupnp works

			// check for a matching IGD service
			// 检查匹配的 IGD 服务
			sc := goupnp.ServiceClient{
				SOAPClient: service.NewSOAPClient(), // 创建 SOAP 客户端
				RootDevice: devs[i].Root,            // 设置根设备
				Location:   devs[i].Location,        // 设置位置
				Service:    service,                 // 设置服务
			}
			sc.SOAPClient.HTTPClient.Timeout = soapRequestTimeout // 设置 SOAP 请求超时
			upnp := matcher(sc)                                   // 调用匹配函数
			if upnp == nil {
				return // 如果无匹配则返回
			}
			upnp.dev = devs[i].Root // 设置根设备

			// check whether port mapping is enabled
			// 检查端口映射是否启用
			if upnp.natEnabled() {
				out <- upnp  // 如果启用则发送 UPnP 实例
				found = true // 标记为已找到
			}
		})
	}
	if !found {
		out <- nil // 如果未找到则发送 nil
	}
}
