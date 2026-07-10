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
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
)

const identityRefreshInterval = time.Second

type identityResolver struct {
	interfaceStore interfacestore.InterfaceStore
	cgroupRoot     string

	mutex       sync.RWMutex
	byCgroupID  map[uint64]*interfacestore.InterfaceConfig
	lastRefresh time.Time
}

func newIdentityResolver(interfaceStore interfacestore.InterfaceStore, cgroupRoot string) *identityResolver {
	return &identityResolver{
		interfaceStore: interfaceStore,
		cgroupRoot:     cgroupRoot,
		byCgroupID:     make(map[uint64]*interfacestore.InterfaceConfig),
	}
}

func (r *identityResolver) resolve(event Event) (*interfacestore.InterfaceConfig, bool) {
	if !event.LocalIP.IsUnspecified() {
		ifConfig, found := r.interfaceStore.GetInterfaceByIP(event.LocalIP.String())
		if found && ifConfig.Type == interfacestore.ContainerInterface {
			return ifConfig, true
		}
	}
	if event.CgroupID == 0 {
		return nil, false
	}

	r.mutex.RLock()
	ifConfig, found := r.byCgroupID[event.CgroupID]
	lastRefresh := r.lastRefresh
	r.mutex.RUnlock()
	if found {
		return ifConfig, true
	}
	if time.Since(lastRefresh) < identityRefreshInterval {
		return nil, false
	}

	if err := r.refresh(); err != nil {
		klog.ErrorS(err, "Failed to refresh eBPF cgroup identity cache")
		return nil, false
	}
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	ifConfig, found = r.byCgroupID[event.CgroupID]
	return ifConfig, found
}

func (r *identityResolver) refresh() error {
	interfaces := r.interfaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	byContainerID := make(map[string]*interfacestore.InterfaceConfig, len(interfaces))
	for _, ifConfig := range interfaces {
		if ifConfig.ContainerID != "" {
			byContainerID[ifConfig.ContainerID] = ifConfig
		}
	}

	byCgroupID := make(map[uint64]*interfacestore.InterfaceConfig)
	err := filepath.WalkDir(r.cgroupRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// Cgroups can disappear while the hierarchy is being scanned.
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		ifConfig := interfaceForCgroupPath(path, byContainerID)
		if ifConfig == nil {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		byCgroupID[stat.Ino] = ifConfig
		return nil
	})
	if err != nil {
		return err
	}

	r.mutex.Lock()
	r.byCgroupID = byCgroupID
	r.lastRefresh = time.Now()
	r.mutex.Unlock()
	return nil
}

func interfaceForCgroupPath(path string, byContainerID map[string]*interfacestore.InterfaceConfig) *interfacestore.InterfaceConfig {
	base := filepath.Base(path)
	for containerID, ifConfig := range byContainerID {
		if strings.Contains(base, containerID) || (len(base) >= 12 && strings.Contains(containerID, base)) {
			return ifConfig
		}
	}
	return nil
}
