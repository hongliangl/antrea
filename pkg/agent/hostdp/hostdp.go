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
	// Load compiles-in the eBPF programs and initializes the maps. It attaches the masquerade programs to the
	// transport interface and the Pod-to-remote-Pod forwarding program to the gateway (Pod-facing) interface
	// ingress (both by index). It must be called once before the other methods.
	Load(transportIfIndex, gatewayIfIndex int) error

	// Close detaches the programs and releases all resources.
	Close() error

	// SetNodeConfig records this Node's transport IPv4 address and subnet prefix length in the node_config map.
	// The transport IP is the address Pod-to-external traffic is masqueraded to.
	SetNodeConfig(transportIP net.IP, subnetPrefixLen int) error

	// SetLocalPodCIDR records this Node's local Pod CIDR, used to match the source of traffic to masquerade
	// (the eBPF equivalent of the `-s <localPodCIDR>` match in the masquerade iptables rule).
	SetLocalPodCIDR(podCIDR *net.IPNet) error

	// AddPodCIDR / DeletePodCIDR maintain the pod_cidrs LPM map of all cluster Pod CIDRs (the eBPF equivalent of
	// antreaPodIPSet), used to exclude Pod-to-Pod traffic from masquerade.
	AddPodCIDR(podCIDR *net.IPNet) error
	DeletePodCIDR(podCIDR *net.IPNet) error

	// SetPodRoute / DeletePodRoute maintain the pod_routes LPM map of remote Pod CIDR -> peer Node next hop
	// (the eBPF equivalent of the `remotePodCIDR via peerNodeIP` route), used to forward Pod-to-remote-Pod
	// traffic in eBPF.
	SetPodRoute(podCIDR *net.IPNet, nextHop net.IP) error
	DeletePodRoute(podCIDR *net.IPNet) error

	// AddEgressSteer / DeleteEgressSteer maintain the egress_steer map on an Egress member Pod's Node: the
	// Pod's external-bound traffic is forwarded to the Egress Node untouched (the eBPF equivalent of the
	// Egress fwmark policy routing).
	AddEgressSteer(podIP, egressNodeIP net.IP) error
	DeleteEgressSteer(podIP net.IP) error

	// AddEgressSNAT / DeleteEgressSNAT maintain the egress_snat map on the Egress Node: a member Pod's (local
	// or remote) external-bound traffic is SNAT'd to the Egress IP (the eBPF equivalent of the member ipset +
	// mark-based SNAT rules).
	AddEgressSNAT(podIP, egressIP net.IP) error
	DeleteEgressSNAT(podIP net.IP) error

	// AddNodePort / DeleteNodePort maintain the nodeport DNAT map: node_ip:port/protocol is DNAT'd (address
	// and port) to the backend. protocol is the IP protocol number (6=TCP, 17=UDP).
	AddNodePort(protocol uint8, port uint16, backendIP net.IP, backendPort uint16) error
	DeleteNodePort(protocol uint8, port uint16) error

	// Stats returns the per-verdict packet counters, keyed by a human-readable name.
	Stats() (map[string]uint64, error)
}
