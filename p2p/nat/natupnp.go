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
	soapRequestTimeout = 3 * time.Second        // SOAP 请求超时时间 / SOAP request timeout
	rateLimit          = 200 * time.Millisecond // 请求速率限制 / Rate limit for requests
)

type upnp struct {
	dev         *goupnp.RootDevice // UPnP 根设备 / UPnP root device
	service     string             // 服务类型 / Service type
	client      upnpClient         // UPnP 客户端 / UPnP client
	mu          sync.Mutex         // 互斥锁 / Mutex for synchronization
	lastReqTime time.Time          // 上次请求时间 / Last request time
	rand        *rand.Rand         // 随机数生成器 / Random number generator
}

type upnpClient interface {
	GetExternalIPAddress() (string, error)                                             // 获取外部 IP 地址 / Get external IP address
	AddPortMapping(string, uint16, string, uint16, string, bool, string, uint32) error // 添加端口映射 / Add port mapping
	DeletePortMapping(string, uint16, string) error                                    // 删除端口映射 / Delete port mapping
	GetNATRSIPStatus() (sip bool, nat bool, err error)                                 // 获取 NAT 和 SIP 状态 / Get NAT and SIP status
}

func (n *upnp) natEnabled() bool {
	var ok bool
	var err error
	n.withRateLimit(func() error { // 使用速率限制调用 / Call with rate limiting
		_, ok, err = n.client.GetNATRSIPStatus() // 检查 NAT 状态 / Check NAT status
		return err
	})
	return err == nil && ok // 如果无错误且 NAT 启用则返回 true / Return true if no error and NAT enabled
}

func (n *upnp) ExternalIP() (addr net.IP, err error) {
	var ipString string
	n.withRateLimit(func() error { // 使用速率限制调用 / Call with rate limiting
		ipString, err = n.client.GetExternalIPAddress() // 获取外部 IP 地址 / Get external IP address
		return err
	})

	if err != nil {
		return nil, err // 如果出错则返回错误 / Return error if failed
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, errors.New("bad IP in response") // 如果 IP 无效则返回错误 / Return error if IP is invalid
	}
	return ip, nil // 返回解析后的 IP / Return parsed IP
}

func (n *upnp) AddMapping(protocol string, extport, intport int, desc string, lifetime time.Duration) (uint16, error) {
	ip, err := n.internalAddress() // 获取本地 IP 地址 / Get internal IP address
	if err != nil {
		return 0, nil // TODO: Shouldn't we return the error?                  // 如果出错则返回 0 和 nil（待改进） / Return 0 and nil if error (TODO)
	}
	protocol = strings.ToUpper(protocol)        // 将协议转换为大写 / Convert protocol to uppercase
	lifetimeS := uint32(lifetime / time.Second) // 将生命周期转换为秒 / Convert lifetime to seconds
	n.DeleteMapping(protocol, extport, intport) // 先删除现有映射 / Delete existing mapping first

	err = n.withRateLimit(func() error { // 使用速率限制添加映射 / Add mapping with rate limiting
		return n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	})
	if err == nil {
		return uint16(extport), nil // 如果成功则返回外部端口 / Return external port if successful
	}

	return uint16(extport), n.withRateLimit(func() error { // 如果失败，尝试添加任意端口映射 / If failed, try adding any port mapping
		p, err := n.addAnyPortMapping(protocol, extport, intport, ip, desc, lifetimeS)
		if err == nil {
			extport = int(p) // 更新外部端口 / Update external port
		}
		return err // 返回错误（如果有） / Return error (if any)
	})
}

func (n *upnp) addAnyPortMapping(protocol string, extport, intport int, ip net.IP, desc string, lifetimeS uint32) (uint16, error) {
	if client, ok := n.client.(*internetgateway2.WANIPConnection2); ok { // 检查是否支持 WANIPConnection2 / Check if WANIPConnection2 is supported
		return client.AddAnyPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	}
	// It will retry with a random port number if the client does
	// not support AddAnyPortMapping.
	// 如果客户端不支持 AddAnyPortMapping，则使用随机端口重试。
	extport = n.randomPort() // 生成随机端口 / Generate random port
	err := n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	if err != nil {
		return 0, err // 如果出错则返回错误 / Return error if failed
	}
	return uint16(extport), nil // 返回随机映射的端口 / Return randomly mapped port
}

func (n *upnp) randomPort() int {
	if n.rand == nil {
		n.rand = rand.New(rand.NewSource(time.Now().UnixNano())) // 初始化随机数生成器 / Initialize random number generator
	}
	return n.rand.Intn(math.MaxUint16-10000) + 10000 // 返回 10000 到 65535 之间的随机端口 / Return random port between 10000 and 65535
}

func (n *upnp) internalAddress() (net.IP, error) {
	devaddr, err := net.ResolveUDPAddr("udp4", n.dev.URLBase.Host) // 解析设备地址 / Resolve device address
	if err != nil {
		return nil, err // 如果出错则返回错误 / Return error if failed
	}
	ifaces, err := net.Interfaces() // 获取网络接口 / Get network interfaces
	if err != nil {
		return nil, err // 如果出错则返回错误 / Return error if failed
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs() // 获取接口地址 / Get interface addresses
		if err != nil {
			return nil, err // 如果出错则返回错误 / Return error if failed
		}
		for _, addr := range addrs {
			if x, ok := addr.(*net.IPNet); ok && x.Contains(devaddr.IP) { // 检查是否包含设备 IP / Check if it contains device IP
				return x.IP, nil // 返回本地 IP / Return local IP
			}
		}
	}
	return nil, fmt.Errorf("could not find local address in same net as %v", devaddr) // 如果未找到则返回错误 / Return error if not found
}

func (n *upnp) DeleteMapping(protocol string, extport, intport int) error {
	return n.withRateLimit(func() error { // 使用速率限制删除映射 / Delete mapping with rate limiting
		return n.client.DeletePortMapping("", uint16(extport), strings.ToUpper(protocol))
	})
}

func (n *upnp) String() string {
	return "UPNP " + n.service // 返回 UPnP 服务字符串 / Return UPnP service string
}

func (n *upnp) withRateLimit(fn func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	lastreq := time.Since(n.lastReqTime) // 计算上次请求后的时间 / Calculate time since last request
	if lastreq < rateLimit {             // 如果小于速率限制 / If less than rate limit
		time.Sleep(rateLimit - lastreq) // 等待达到限制时间 / Sleep to meet rate limit
	}
	err := fn()                // 执行请求 / Execute request
	n.lastReqTime = time.Now() // 更新最后请求时间 / Update last request time
	return err                 // 返回错误（如果有） / Return error (if any)
}

// discoverUPnP searches for Internet Gateway Devices
// and returns the first one it can find on the local network.
// discoverUPnP 搜索互联网网关设备，并返回本地网络上找到的第一个设备。
func discoverUPnP() Interface {
	found := make(chan *upnp, 2) // 创建发现通道 / Create discovery channel
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
		if c := <-found; c != nil { // 返回第一个成功的 UPnP 实例 / Return first successful UPnP instance
			return c
		}
	}
	return nil // 如果未找到则返回 nil / Return nil if not found
}

// discover finds devices matching the given target and calls matcher for
// all advertised services of each device. The first non-nil service found
// is sent into out. If no service matched, nil is sent.
// discover 查找与给定目标匹配的设备，并对每个设备的所有广告服务调用 matcher。
// 找到的第一个非 nil 服务被发送到 out。如果没有服务匹配，则发送 nil。
func discover(out chan<- *upnp, target string, matcher func(goupnp.ServiceClient) *upnp) {
	devs, err := goupnp.DiscoverDevices(target) // 发现匹配目标的设备 / Discover devices matching target
	if err != nil {
		out <- nil // 如果出错则发送 nil / Send nil if error
		return
	}
	found := false
	for i := 0; i < len(devs) && !found; i++ {
		if devs[i].Root == nil {
			continue // 跳过无根设备的实例 / Skip instances without root device
		}
		devs[i].Root.Device.VisitServices(func(service *goupnp.Service) { // 遍历服务 / Visit services
			if found {
				return // 如果已找到则退出 / Exit if already found
			}
			// todo learn what and how goupnp works
			// check for a matching IGD service
			// 检查匹配的 IGD 服务
			sc := goupnp.ServiceClient{
				SOAPClient: service.NewSOAPClient(), // 创建 SOAP 客户端 / Create SOAP client
				RootDevice: devs[i].Root,            // 设置根设备 / Set root device
				Location:   devs[i].Location,        // 设置位置 / Set location
				Service:    service,                 // 设置服务 / Set service
			}
			sc.SOAPClient.HTTPClient.Timeout = soapRequestTimeout // 设置 SOAP 请求超时 / Set SOAP request timeout
			upnp := matcher(sc)                                   // 调用匹配函数 / Call matcher function
			if upnp == nil {
				return // 如果无匹配则返回 / Return if no match
			}
			upnp.dev = devs[i].Root // 设置根设备 / Set root device

			// check whether port mapping is enabled
			// 检查端口映射是否启用
			if upnp.natEnabled() {
				out <- upnp  // 如果启用则发送 UPnP 实例 / Send UPnP instance if enabled
				found = true // 标记为已找到 / Mark as found
			}
		})
	}
	if !found {
		out <- nil // 如果未找到则发送 nil / Send nil if not found
	}
}
