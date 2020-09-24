// Copyright 2019 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"

	netutils "k8s.io/utils/net"
)

const (
	interfaceNameLength   = 15
	interfacePrefixLength = 8
	interfaceKeyLength    = interfaceNameLength - (interfacePrefixLength + 1)

	FamilyIPv4 uint8 = 4
	FamilyIPv6 uint8 = 6
)

func generateInterfaceName(key string, name string, useHead bool) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	io.WriteString(hash, key)
	interfaceKey := hex.EncodeToString(hash.Sum(nil))
	prefix := name
	if len(name) > interfacePrefixLength {
		if useHead {
			prefix = name[:interfacePrefixLength]
		} else {
			prefix = name[len(name)-interfacePrefixLength:]
		}
	}
	return fmt.Sprintf("%s-%s", prefix, interfaceKey[:interfaceKeyLength])
}

// GenerateContainerInterfaceKey generates a unique string for a Pod's
// interface as: container/<Container-ID>.
// We must use ContainerID instead of PodNamespace + PodName because there could
// be more than one container associated with the same Pod at some point.
// For example, when deleting a StatefulSet Pod with 0 second grace period, the
// Pod will be removed from the Kubernetes API very quickly and a new Pod will
// be created immediately, and kubelet may process the deletion of the previous
// Pod and the addition of the new Pod simultaneously.
func GenerateContainerInterfaceKey(containerID string) string {
	return fmt.Sprintf("container/%s", containerID)
}

// GenerateNodeTunnelInterfaceKey generates a unique string for a Node's
// tunnel interface as: node/<Node-name>.
func GenerateNodeTunnelInterfaceKey(nodeName string) string {
	return fmt.Sprintf("node/%s", nodeName)
}

// GenerateContainerInterfaceName generates a unique interface name using the
// Pod's namespace, name and containerID. The output should be deterministic (so that
// multiple calls to GenerateContainerInterfaceName with the same parameters
// return the same value). The output has the length of interfaceNameLength(15).
// The probability of collision should be neglectable.
func GenerateContainerInterfaceName(podName, podNamespace, containerID string) string {
	// Use the podName as the prefix and the containerID as the hashing key.
	// podNamespace is not used currently.
	return generateInterfaceName(containerID, podName, true)
}

// GenerateNodeTunnelInterfaceName generates a unique interface name for the
// tunnel to the Node, using the Node's name.
func GenerateNodeTunnelInterfaceName(nodeName string) string {
	return generateInterfaceName(GenerateNodeTunnelInterfaceKey(nodeName), nodeName, false)
}

type LinkNotFound struct {
	error
}

func newLinkNotFoundError(name string) LinkNotFound {
	return LinkNotFound{
		fmt.Errorf("link %s not found", name),
	}
}

func listenUnix(address string) (net.Listener, error) {
	return net.Listen("unix", address)
}

func dialUnix(address string) (net.Conn, error) {
	return net.Dial("unix", address)
}

// GetIPNetDeviceFromIP returns a local IP/mask and associated device from IP.
func GetIPNetDeviceFromIP(localIP net.IP) (*net.IPNet, *net.Interface, error) {
	linkList, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, link := range linkList {
		addrList, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrList {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIP) {
					return ipNet, &link, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("unable to find local IP and device")
}

func GetIPv4Addr(ips []net.IP) net.IP {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip
		}
	}
	return nil
}

func GetIPWithFamily(ips []net.IP, addrFamily uint8) (net.IP, error) {
	if addrFamily == FamilyIPv6 {
		for _, ip := range ips {
			if ip.To4() == nil {
				return ip, nil
			}
		}
		return nil, errors.New("no IP found with IPv6 AddressFamily")
	} else {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip, nil
			}
		}
		return nil, errors.New("no IP found with IPv4 AddressFamily")
	}
}

// GetAvailableNodePortIPs gets available NodePort IP addresses with config.
func GetAvailableNodePortIPs(nodePortIPsFromConfig []string, gateway string) (map[int][]net.IP, map[int][]net.IP, error) {
	var nodePortIPNets []*net.IPNet
	nodePortIPMap := make(map[int][]net.IP)
	nodePortIPv6Map := make(map[int][]net.IP)
	_, ipv6LinkLocalNet, _ := net.ParseCIDR("fe80::/64")

	// Convert every NodePort address to IPNet.
	for _, nodePortIP := range nodePortIPsFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortIP)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	// Get all interfaces.
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, itf := range interfaces {
		// Get all IPs of every interface
		addrs, err := itf.Addrs()
		if err != nil {
			return nil, nil, err
		}
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ipv6LinkLocalNet.Contains(ip) {
				continue // Skip IPv6 link local address
			}

			// If the NodePort IPNet that is converted from config contains the current IP address, then the current IP
			// address from config is available.
			var contains bool
			for _, nodePortIPNet := range nodePortIPNets {
				if nodePortIPNet.Contains(ip) {
					contains = true
					break
				}
			}
			// If option 'nodePortAddresses' is not specified in config, every IPv4/IPv6 address will be NodePort IP address.
			// An interface may has more than one IPv4/IPv6 addresses for NodePort.
			// Interface index will be used to generate Linux TC filter chain and handle ID.
			if len(nodePortIPNets) == 0 || contains {
				if netutils.IsIPv6(ip) {
					nodePortIPv6Map[itf.Index] = append(nodePortIPv6Map[itf.Index], ip)
				} else {
					nodePortIPMap[itf.Index] = append(nodePortIPMap[itf.Index], ip)
				}
			}
		}
	}
	// Gateway IP addresses can't be as NodePort IP addresses.
	gatewayItf, err := net.InterfaceByName(gateway)
	if err != nil {
		return nil, nil, err
	}
	delete(nodePortIPMap, gatewayItf.Index)
	delete(nodePortIPv6Map, gatewayItf.Index)

	if len(nodePortIPMap) == 0 {
		return nil, nil, fmt.Errorf("no qualified NodePort IPv4 addresses was found")
	}
	if len(nodePortIPv6Map) == 0 {
		return nil, nil, fmt.Errorf("no qualified NodePort IPv6 addresses was found")
	}
	return nodePortIPMap, nodePortIPv6Map, nil
}

// ExtendCIDRWithIP is used for extending an IPNet with an IP.
func ExtendCIDRWithIP(ipNet *net.IPNet, ip net.IP) (*net.IPNet, error) {
	cpl := commonPrefixLen(ipNet.IP, ip)
	if cpl == 0 {
		return nil, fmt.Errorf("invalid common prefix length")
	}
	_, newIpNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ipNet.IP.String(), cpl))
	if err != nil {
		return nil, err
	}
	return newIpNet, nil
}

/*
This is copied from net/addrselect.go as this function cannot be used outside of standard lib net.
Modifies:
- Replace argument type IP with type net.IP.
*/
func commonPrefixLen(a, b net.IP) (cpl int) {
	if a4 := a.To4(); a4 != nil {
		a = a4
	}
	if b4 := b.To4(); b4 != nil {
		b = b4
	}
	if len(a) != len(b) {
		return 0
	}
	// If IPv6, only up to the prefix (first 64 bits)
	if len(a) > 8 {
		a = a[:8]
		b = b[:8]
	}
	for len(a) > 0 {
		if a[0] == b[0] {
			cpl += 8
			a = a[1:]
			b = b[1:]
			continue
		}
		bits := 8
		ab, bb := a[0], b[0]
		for {
			ab >>= 1
			bb >>= 1
			bits--
			if ab == bb {
				cpl += bits
				return
			}
		}
	}
	return
}

func GetNameByIndex(ifIndex int) string {
	dev, _ := net.InterfaceByIndex(ifIndex)
	return dev.Name
}

func GetIndexByName(name string) int {
	dev, _ := net.InterfaceByName(name)
	return dev.Index
}
