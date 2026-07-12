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

package hostdp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPodCIDRKeyOf(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.10.1.0/24")
	key, err := podCIDRKeyOf(cidr)
	require.NoError(t, err)
	assert.Equal(t, uint32(24), key.PrefixLen)
	// The address must be the network-order bytes so the LPM trie matches left-to-right.
	assert.Equal(t, [4]byte{10, 10, 1, 0}, key.Addr)

	_, v6, _ := net.ParseCIDR("2001:db8::/64")
	_, err = podCIDRKeyOf(v6)
	assert.Error(t, err, "IPv6 must be rejected for now")
}

func TestHostToNetU32(t *testing.T) {
	// 10.10.1.5 as a host-order uint32 becomes its network-order byte pattern when serialized
	// little-endian by the map loader.
	addr := uint32(10)<<24 | uint32(10)<<16 | uint32(1)<<8 | uint32(5)
	swapped := hostToNetU32(addr)
	assert.Equal(t, uint32(0x05010a0a), swapped)
	assert.Equal(t, addr, hostToNetU32(swapped), "byte swap must be an involution")
}

func TestIPv4Bytes(t *testing.T) {
	b, err := ipv4Bytes(net.ParseIP("192.168.50.1"))
	require.NoError(t, err)
	assert.Equal(t, [4]byte{192, 168, 50, 1}, b)

	_, err = ipv4Bytes(net.ParseIP("2001:db8::1"))
	assert.Error(t, err, "IPv6 must be rejected for now")
}

func TestNodePortEncoding(t *testing.T) {
	key := npKey{Proto: 6}
	// Port 30080 = 0x7580 must serialize big-endian to match the datapath's raw header reads.
	key.Port[0], key.Port[1] = 0x75, 0x80
	assert.Equal(t, [2]byte{0x75, 0x80}, key.Port)

	val := npBackend{Addr: [4]byte{10, 10, 1, 5}}
	val.Port[0], val.Port[1] = 0x1f, 0x90 // 8080
	assert.Equal(t, [4]byte{10, 10, 1, 5}, val.Addr)
}
