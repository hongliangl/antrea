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

// Package ebpf forwards the traffic between the Pods of two Nodes with eBPF instead of the host network
// stack, under the EBPFHostDataPath feature gate.
//
// It accelerates cross-Node Pod traffic using direct routes in noEncap and hybrid modes. The Node route
// controller adds only directly routed peers to the BPF route maps; tunneled traffic keeps its existing path.
// Eligible packets are redirected between interfaces, bypassing host IP forwarding and netfilter. The
// masquerade of the traffic leaving the cluster, Egress, Service handling and the Node network policies stay
// where they are, in iptables and in the OVS pipeline.
//
// Those routes are still installed while this runs. This datapath comes before them and, whenever it cannot
// handle a packet, leaves it to them, so a Node keeps forwarding exactly what it forwards without it. That is
// what lets it fall back when a next hop is unresolved. The Agent registers managed neighbors so the kernel
// resolves and refreshes them even when packets bypass the host stack.
//
// The programs live in bpf/host_datapath.bpf.c. hack/gen-bpf-objects extracts their compiled instructions
// into internal/objects, so the Agent needs neither a compiler nor an ELF loader at runtime.
package ebpf

import (
	"net"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
)

// interfaceStore supplies current Pod IPs without importing the store's metrics dependencies.
type interfaceStore interface {
	GetContainerIPs() []net.IP
}

// Stats counts what the programs did, per packet. A miss or a pass is a packet the host network stack handled
// instead, not a packet which was lost.
type Stats struct {
	// Forwarded and Returned count the packets sent to a peer Node and to a local Pod.
	Forwarded uint64
	Returned  uint64
	// ForwardMisses and ReturnMisses count the packets which were meant to be forwarded but were left to
	// the stack, for example because the neighbor was not resolved yet.
	ForwardMisses uint64
	ReturnMisses  uint64
	// Passed counts the packets which are not cross-Node Pod packets.
	Passed uint64
	// TTLExpired and TooBig count the packets left to the stack so that it reports them to their sender.
	TTLExpired uint64
	TooBig     uint64
}

// Interface is the eBPF host datapath as the rest of the Agent uses it. The Pod routes mirror what the route
// client installs, and are set by the Node route controller from the same events.
type Interface interface {
	// Initialize creates the maps, loads the programs and attaches them to the Node interfaces.
	// Call it once, before other methods are used concurrently.
	Initialize(nodeConfig *agentconfig.NodeConfig) error
	// Run periodically restores missing program attachments on the original interfaces and reconciles neighbors.
	// CNI Pod updates trigger neighbor reconciliation. Interface or MTU changes require an Agent restart.
	// It must be called after Initialize succeeds.
	Run(stopCh <-chan struct{})
	// AddPodRoute records that podCIDR is reachable through nextHop.
	// Until the route is added, its traffic goes through the host stack.
	AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error
	// DeletePodRoute removes the route for podCIDR.
	DeletePodRoute(podCIDR *net.IPNet) error
	// Stats reports the counters of the programs.
	Stats() (Stats, error)
	// Close detaches the programs and releases the maps.
	Close() error
}
