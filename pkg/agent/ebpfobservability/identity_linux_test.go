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

package ebpfobservability

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
)

func TestIdentityResolver(t *testing.T) {
	const containerID = "1234567890abcdef1234567890abcdef"
	store := interfacestore.NewInterfaceStore()
	ifConfig := interfacestore.NewContainerInterface(
		"pod-veth", containerID, "pod-a", "namespace-a", "eth0", "/proc/1/ns/net", nil,
		[]net.IP{net.ParseIP("10.10.0.2")}, 0)
	store.AddInterface(ifConfig)

	cgroupRoot := t.TempDir()
	cgroupPath := filepath.Join(cgroupRoot, "cri-containerd-"+containerID+".scope")
	require.NoError(t, os.Mkdir(cgroupPath, 0755))
	info, err := os.Stat(cgroupPath)
	require.NoError(t, err)
	cgroupID := info.Sys().(*syscall.Stat_t).Ino

	resolver := newIdentityResolver(store, cgroupRoot)
	require.NoError(t, resolver.refresh())

	resolved, found := resolver.resolve(Event{CgroupID: cgroupID})
	require.True(t, found)
	assert.Equal(t, ifConfig, resolved)

	resolved, found = resolver.resolve(Event{LocalIP: net.ParseIP("10.10.0.2")})
	require.True(t, found)
	assert.Equal(t, ifConfig, resolved)
}

func TestInterfaceForCgroupPath(t *testing.T) {
	ifConfig := &interfacestore.InterfaceConfig{}
	interfaces := map[string]*interfacestore.InterfaceConfig{
		"1234567890abcdef": ifConfig,
	}
	assert.Equal(t, ifConfig, interfaceForCgroupPath("/kubepods/cri-containerd-1234567890abcdef.scope", interfaces))
	assert.Nil(t, interfaceForCgroupPath("/system.slice/kubelet.service", interfaces))
}
