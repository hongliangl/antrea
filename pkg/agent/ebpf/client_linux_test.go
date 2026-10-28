// Copyright 2026 Antrea Authors
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

//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/ebpf/internal/objects"
	"antrea.io/antrea/v2/pkg/util/ip"
)

// TestDatapathObjects checks the generated objects against the client's data layouts and entry points.
func TestDatapathObjects(t *testing.T) {
	byName := map[string]objects.Map{}
	for _, m := range objects.Maps {
		byName[m.Name] = m
	}
	// Route keys contain a uint32 prefix length followed by the address bytes.
	require.Contains(t, byName, mapPodRoutes)
	assert.EqualValues(t, 4+net.IPv4len, byName[mapPodRoutes].KeySize)
	assert.EqualValues(t, net.IPv4len, byName[mapPodRoutes].ValueSize)
	require.Contains(t, byName, mapPodRoutes6)
	assert.EqualValues(t, 4+net.IPv6len, byName[mapPodRoutes6].KeySize)
	assert.EqualValues(t, net.IPv6len, byName[mapPodRoutes6].ValueSize)
	require.Contains(t, byName, mapNodeConfig)
	assert.EqualValues(t, 1, byName[mapNodeConfig].MaxEntries)
	assert.EqualValues(t, unsafe.Sizeof(nodeConfig{}), byName[mapNodeConfig].ValueSize,
		"nodeConfig and struct node_config have drifted apart")
	// Keep the Go layout in sync with struct node_config and its nested IP configuration structures.
	assert.EqualValues(t, 12, unsafe.Sizeof(ipConfig4{}))
	assert.EqualValues(t, 36, unsafe.Sizeof(ipConfig6{}))
	assert.EqualValues(t, 0, unsafe.Offsetof(nodeConfig{}.transportMTU))
	assert.EqualValues(t, 4, unsafe.Offsetof(nodeConfig{}.gatewayMTU))
	assert.EqualValues(t, 8, unsafe.Offsetof(nodeConfig{}.gatewayIfIndex))
	assert.EqualValues(t, 12, unsafe.Offsetof(nodeConfig{}.forwardingEnabled))
	assert.EqualValues(t, 16, unsafe.Offsetof(nodeConfig{}.ipv4))
	assert.EqualValues(t, 28, unsafe.Offsetof(nodeConfig{}.ipv6))
	assert.EqualValues(t, 4, unsafe.Offsetof(ipConfig4{}.localPodNet))
	assert.EqualValues(t, 8, unsafe.Offsetof(ipConfig4{}.gatewayIP))
	assert.EqualValues(t, 4, unsafe.Offsetof(ipConfig6{}.localPodNet))
	assert.EqualValues(t, 20, unsafe.Offsetof(ipConfig6{}.gatewayIP))
	require.Contains(t, byName, mapStats)
	assert.EqualValues(t, statCount, byName[mapStats].MaxEntries,
		"stats does not hold exactly the counters Stats reads")

	programs := map[string]objects.Program{}
	for _, p := range objects.Programs {
		programs[p.Name] = p
	}
	assert.Contains(t, programs, programForward)
	assert.Contains(t, programs, programReturn)
}

// TestRelocate checks that patching a program leaves the instructions alone apart from the map references,
// which the kernel would otherwise reject or, worse, accept pointing at the wrong map.
func TestRelocate(t *testing.T) {
	c := &client{mapFDs: map[string]int{}}
	for i, m := range objects.Maps {
		c.mapFDs[m.Name] = 100 + i
	}
	for _, def := range objects.Programs {
		t.Run(def.Name, func(t *testing.T) {
			patched, err := c.relocate(def)
			require.NoError(t, err)
			require.Len(t, patched, len(def.Instructions))

			relocated := map[int]bool{}
			for _, r := range def.Relocations {
				offset := int(r.Instruction) * instructionSize
				relocated[offset] = true
				expectedFD := 100 + int(r.MapIndex)
				assert.EqualValues(t, expectedFD, binary.LittleEndian.Uint32(patched[offset+4:]),
					"the immediate at instruction %d is not the map's descriptor", r.Instruction)
				assert.EqualValues(t, pseudoMapFD, patched[offset+1]>>4,
					"the source register at instruction %d does not say the immediate is a map", r.Instruction)
			}
			// Everything else is byte for byte what was generated.
			for offset := 0; offset < len(patched); offset += instructionSize {
				if relocated[offset] || relocated[offset-instructionSize] {
					continue
				}
				assert.Equal(t, def.Instructions[offset:offset+instructionSize],
					string(patched[offset:offset+instructionSize]),
					"instruction %d was changed and holds no map reference", offset/instructionSize)
			}
		})
	}
}

func TestRouteKeyOf(t *testing.T) {
	tests := []struct {
		name              string
		cidr              string
		expectedPrefixLen uint32
		expectedAddr      []byte
	}{
		{
			// The address is kept in the order it has on the wire, which is the one the trie
			// compares a prefix in. Storing it the other way round matches nothing.
			name:              "IPv4",
			cidr:              "10.10.1.0/24",
			expectedPrefixLen: 24,
			expectedAddr:      []byte{10, 10, 1, 0},
		},
		{
			name:              "IPv4 single address",
			cidr:              "10.10.1.5/32",
			expectedPrefixLen: 32,
			expectedAddr:      []byte{10, 10, 1, 5},
		},
		{
			name:              "IPv6",
			cidr:              "2001:db8::/64",
			expectedPrefixLen: 64,
			expectedAddr:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name:              "IPv6 single address",
			cidr:              "2001:db8::5/128",
			expectedPrefixLen: 128,
			expectedAddr:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)
			key := routeKeyOf(cidr)
			require.Len(t, key, 4+len(tt.expectedAddr))
			assert.Equal(t, tt.expectedPrefixLen, binary.NativeEndian.Uint32(key[:4]))
			assert.Equal(t, tt.expectedAddr, key[4:])
		})
	}
}

func TestNetworkOrder(t *testing.T) {
	// IPv4 addresses use four bytes, including when net.IP stores them in IPv4-mapped form.
	expected := []byte{192, 168, 50, 2}
	assert.Equal(t, expected, networkOrder(net.ParseIP("192.168.50.2")))
	assert.Equal(t, expected, networkOrder(net.IPv4(192, 168, 50, 2)), "a 16 byte IPv4 address reads the same")
	expected = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	assert.Equal(t, expected, networkOrder(net.ParseIP("2001:db8::1")))
}

// TestNotInitialized checks that the datapath is inert before initialization and after Close: the Node route controller
// mirrors every route into it whether it initialized or not, and it must not fail those calls.
func TestNotInitialized(t *testing.T) {
	c := &client{}
	_, podCIDR, err := net.ParseCIDR("10.10.1.0/24")
	require.NoError(t, err)
	assert.NoError(t, c.AddPodRoute(podCIDR, net.ParseIP("192.168.50.2")))
	assert.NoError(t, c.DeletePodRoute(podCIDR))
	stats, err := c.Stats()
	assert.NoError(t, err)
	assert.Equal(t, Stats{}, stats)
	assert.NoError(t, c.Close())
}

func TestSyncProgram(t *testing.T) {
	loopback, err := net.InterfaceByName("lo")
	require.NoError(t, err)
	tests := []struct {
		name          string
		interfaceName string
		ifIndex       int
		expectedErr   string
	}{
		{
			name:          "interface missing",
			interfaceName: "missing-ebpf",
			ifIndex:       loopback.Index,
			expectedErr:   "getting interface missing-ebpf",
		},
		{
			name:          "interface replaced",
			interfaceName: loopback.Name,
			ifIndex:       loopback.Index + 1,
			expectedErr:   "index changed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stored := storedInterfaceState{
				program: programForward,
				name:    tt.interfaceName,
				ifIndex: tt.ifIndex,
			}
			c := &client{}
			require.ErrorContains(t, c.syncProgram(&stored), tt.expectedErr)
			assert.True(t, stored.missing)
			assert.Equal(t, tt.ifIndex, stored.ifIndex, "the initial attachment target must not change")
			assert.Empty(t, c.attachments)
		})
	}
}

func TestInitializeTransportIPOverlap(t *testing.T) {
	tests := []struct {
		name        string
		nodeConfig  agentconfig.NodeConfig
		expectedErr string
	}{
		{
			name: "IPv4",
			nodeConfig: agentconfig.NodeConfig{
				PodIPv4CIDR: ip.MustParseCIDR("10.10.0.0/24"),
				NodeTransportIPv4Addr: &net.IPNet{
					IP: net.ParseIP("10.10.0.9"),
				},
			},
			expectedErr: "the Node transport address 10.10.0.9 is inside the local Pod CIDR 10.10.0.0/24",
		},
		{
			name: "IPv6",
			nodeConfig: agentconfig.NodeConfig{
				PodIPv6CIDR: ip.MustParseCIDR("fd00:10::/64"),
				NodeTransportIPv6Addr: &net.IPNet{
					IP: net.ParseIP("fd00:10::9"),
				},
			},
			expectedErr: "the Node transport address fd00:10::9 is inside the local Pod CIDR fd00:10::/64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(&agentconfig.NetworkConfig{
				TrafficEncapMode: agentconfig.TrafficEncapModeNoEncap,
			}, nil, nil)
			assert.ErrorContains(t, c.Initialize(&tt.nodeConfig), tt.expectedErr)
			assert.NoError(t, c.Close())
		})
	}
}

func TestNewClientInitialization(t *testing.T) {
	tests := []struct {
		name string
		mode agentconfig.TrafficEncapModeType
	}{
		{
			name: "noEncap",
			mode: agentconfig.TrafficEncapModeNoEncap,
		},
		{
			name: "hybrid",
			mode: agentconfig.TrafficEncapModeHybrid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construction succeeds before interfaces exist; Initialize resolves them.
			c := NewClient(&agentconfig.NetworkConfig{
				TrafficEncapMode: tt.mode,
			}, nil, nil).(*client)
			// Pod updates coalesce into one pending sync without blocking the event handler.
			for _, event := range []string{"add", "delete"} {
				c.processPodUpdate(event)
				c.processPodUpdate(event)
				require.Len(t, c.podUpdateCh, 1)
				<-c.podUpdateCh
			}
			err := c.Initialize(&agentconfig.NodeConfig{
				NodeTransportInterfaceName: "missing-ebpf-interface",
				PodIPv4CIDR:                ip.MustParseCIDR("10.10.0.0/24"),
				GatewayConfig: &agentconfig.GatewayConfig{
					Name: "antrea-gw0",
					IPv4: net.ParseIP("10.10.0.1"),
				},
			})
			require.ErrorContains(t, err, "error getting the transport interface missing-ebpf-interface")
			assert.NoError(t, c.Close())
		})
	}
}
