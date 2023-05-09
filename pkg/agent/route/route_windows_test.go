//go:build windows
// +build windows

// Copyright 2020 Antrea Authors
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

package route

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/util"
)

var (
	// Leverage loopback interface for testing.
	hostGateway = "Loopback Pseudo-Interface 1"
	gwLink      = getNetLinkIndex("Loopback Pseudo-Interface 1")
	nodeConfig  = &config.NodeConfig{
		OVSBridge: "Loopback Pseudo-Interface 1",
		GatewayConfig: &config.GatewayConfig{
			Name:      hostGateway,
			LinkIndex: gwLink,
		},
	}

	externalIPv4Addr1 = "1.1.1.1"
	externalIPv4Addr2 = "1.1.1.2"
	externalIPv6Addr1 = "fd00:1234:5678:dead:beaf::1"
	externalIPv6Addr2 = "fd00:1234:5678:dead:beaf::a"

	_, externalIPv4NetAddr1, _ = net.ParseCIDR(externalIPv4Addr1)
	_, externalIPv4NetAddr2, _ = net.ParseCIDR(externalIPv4Addr2)
	_, externalIPv6NetAddr1, _ = net.ParseCIDR(externalIPv6Addr1)
	_, externalIPv6NetAddr2, _ = net.ParseCIDR(externalIPv6Addr2)

	ipv4Route1 = generateRoute(externalIPv4NetAddr1, config.VirtualServiceIPv4, 10, 256)
	ipv4Route2 = generateRoute(externalIPv4NetAddr2, config.VirtualServiceIPv4, 10, 256)
	ipv6Route1 = generateRoute(externalIPv6NetAddr1, config.VirtualServiceIPv6, 10, 256)
	ipv6Route2 = generateRoute(externalIPv6NetAddr2, config.VirtualServiceIPv6, 10, 256)
)

func getNetLinkIndex(dev string) int {
	link, err := net.InterfaceByName(dev)
	if err != nil {
		klog.Fatalf("cannot find dev %s: %v", dev, err)
	}
	return link.Index
}

func TestRouteOperation(t *testing.T) {
	peerNodeIP1 := net.ParseIP("10.0.0.2")
	peerNodeIP2 := net.ParseIP("10.0.0.3")
	gwIP1 := net.ParseIP("192.168.2.1")
	_, destCIDR1, _ := net.ParseCIDR("192.168.2.0/24")
	dest2 := "192.168.3.0/24"
	gwIP2 := net.ParseIP("192.168.3.1")
	_, destCIDR2, _ := net.ParseCIDR(dest2)

	client, err := NewClient(&config.NetworkConfig{}, true, false, false, false, nil)

	require.Nil(t, err)
	called := false
	err = client.Initialize(nodeConfig, func() { called = true })
	require.Nil(t, err)
	require.True(t, called)

	// Add initial routes.
	err = client.AddRoutes(destCIDR1, "node1", peerNodeIP1, gwIP1)
	require.Nil(t, err)
	routes1, err := util.GetNetRoutes(gwLink, destCIDR1)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes1))

	err = client.AddRoutes(destCIDR2, "node2", peerNodeIP2, gwIP2)
	require.Nil(t, err)
	routes2, err := util.GetNetRoutes(gwLink, destCIDR2)
	require.Nil(t, err)
	assert.Equal(t, 1, len(routes2))

	err = client.Reconcile([]string{dest2})
	require.Nil(t, err)

	routes5, err := util.GetNetRoutes(gwLink, destCIDR1)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes5))

	err = client.DeleteRoutes(destCIDR2)
	require.Nil(t, err)
	routes7, err := util.GetNetRoutes(gwLink, destCIDR2)
	require.Nil(t, err)
	assert.Equal(t, 0, len(routes7))
}

func TestAddAndDeleteExternalIPRoute(t *testing.T) {
	tests := []struct {
		name          string
		externalIPs   []string
		serviceRoutes map[string]*util.Route
	}{
		{
			name: "IPv4",
			serviceRoutes: map[string]*util.Route{
				externalIPv4Addr1: ipv4Route1,
				externalIPv4Addr2: ipv4Route2,
			},
			externalIPs: []string{externalIPv4Addr1, externalIPv4Addr2},
		},
		{
			name: "IPv6",
			serviceRoutes: map[string]*util.Route{
				externalIPv6Addr1: ipv6Route1,
				externalIPv6Addr2: ipv6Route2,
			},
			externalIPs: []string{externalIPv6Addr1, externalIPv6Addr2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				nodeConfig: nodeConfig,
			}
			for _, externalIP := range tt.externalIPs {
				assert.NoError(t, c.AddExternalIPRoute(net.ParseIP(externalIP)))
				_, externalIPNet, _ := net.ParseCIDR(externalIP)
				routes, err := util.GetNetRoutes(gwLink, externalIPNet)
				require.Nil(t, err)
				assert.Equal(t, 1, len(routes))

				route, ok := c.serviceRoutes.Load(externalIPNet)
				assert.True(t, ok)
				assert.Equal(t, routes[0], route.(*util.Route))
			}
		})
	}
}
