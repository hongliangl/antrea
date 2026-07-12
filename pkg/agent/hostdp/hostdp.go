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

// Package hostdp implements the eBPF host-network datapath (EBPFHostDataPath feature gate): the forwarding,
// NAT and policy-routing that today live in the Linux host network stack (programmed by pkg/agent/route) are
// replaced by eBPF programs attached with tc on the Node's transport interface. OVS and the in-OVS pipeline
// are unchanged. This is a work in progress; see docs/design/ebpf-host-datapath.md.
package hostdp

import "net"

// Interface is the control surface of the eBPF host datapath. Its methods are driven by the same events that
// drive the traditional route client (Pod CIDR add/delete, Node config), so the eBPF maps stay in sync.
type Interface interface {
	// Load compiles-in the eBPF programs, attaches them to the transport interface (by index), and initializes
	// the maps. It must be called once before the other methods.
	Load(transportIfIndex int) error

	// Close detaches the programs and releases all resources.
	Close() error

	// SetNodeConfig records this Node's transport IPv4 address and subnet prefix length in the node_config map.
	SetNodeConfig(transportIP net.IP, subnetPrefixLen int) error

	// AddPodCIDR / DeletePodCIDR maintain the pod_cidrs LPM map (the eBPF equivalent of antreaPodIPSet).
	AddPodCIDR(podCIDR *net.IPNet) error
	DeletePodCIDR(podCIDR *net.IPNet) error

	// Stats returns the per-verdict packet counters, keyed by a human-readable name.
	Stats() (map[string]uint64, error)
}
