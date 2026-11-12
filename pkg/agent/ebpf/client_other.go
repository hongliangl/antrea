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

//go:build !linux

package ebpf

import (
	"fmt"
	"net"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/util/channel"
)

// NewClient prepares a client whose Initialize method reports that Linux is required.
func NewClient(
	networkConfig *agentconfig.NetworkConfig,
	interfaceStore interfaceStore,
	podUpdateSubscriber channel.Subscriber,
) Interface {
	return &client{}
}

type client struct{}

var _ Interface = (*client)(nil)

func (c *client) Initialize(nodeConfig *agentconfig.NodeConfig) error {
	return fmt.Errorf("the eBPF host datapath is only supported on Linux")
}

func (c *client) Run(stopCh <-chan struct{})                           {}
func (c *client) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error { return nil }
func (c *client) DeletePodRoute(podCIDR *net.IPNet) error              { return nil }
func (c *client) Stats() (Stats, error)                                { return Stats{}, nil }
func (c *client) Close() error                                         { return nil }
