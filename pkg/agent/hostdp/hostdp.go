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

// Package hostdp forwards the traffic between the Pods of two Nodes with eBPF instead of the host network
// stack, under the EBPFHostDataPath feature gate.
//
// It replaces one thing and one only: the "remotePodCIDR via peerNodeIP" routes pkg/agent/route installs in
// noEncap mode. A packet of a local Pod bound for a remote Pod, and the packets coming back, are sent
// straight to the other interface instead of going through routing and netfilter. Nothing else moves: the
// masquerade of the traffic leaving the cluster, Egress, Service handling and the Node network policies stay
// where they are, in iptables and in the OVS pipeline.
//
// Those routes are still installed while this runs. This datapath comes before them and, whenever it cannot
// handle a packet, leaves it to them, so a Node keeps forwarding exactly what it forwards without it. That is
// what makes it safe to turn on, and it is also what keeps it working: the neighbor entries it reads are
// resolved and refreshed by the kernel, which only does so for the packets it forwards itself.
//
// The programs live in bpf/hostdp.bpf.c. hack/gen-bpf-objects compiles them into objects_linux.go, so that
// the Agent binary carries the instructions and needs neither a compiler nor an eBPF library to load them.
package hostdp

import (
	"fmt"
	"net"
)

// Mode is what the programs do with a packet they would forward.
type Mode uint32

const (
	// ModeObserve makes every decision ModeForward makes and counts it, but leaves every packet to the host
	// network stack untouched. It is what validates the maps and the routes mirrored into them against real
	// traffic, without changing how a single packet is forwarded.
	ModeObserve Mode = 0
	// ModeForward forwards the packets.
	ModeForward Mode = 1
)

func (m Mode) String() string {
	switch m {
	case ModeObserve:
		return "observe"
	case ModeForward:
		return "forward"
	}
	return fmt.Sprintf("Mode(%d)", uint32(m))
}

// ParseMode returns the Mode a configuration value names.
func ParseMode(value string) (Mode, error) {
	switch value {
	case ModeObserve.String():
		return ModeObserve, nil
	case ModeForward.String():
		return ModeForward, nil
	}
	return 0, fmt.Errorf("the eBPF host datapath mode %q is unknown, it must be %q or %q", value, ModeObserve,
		ModeForward)
}

// Config is what the datapath needs to know about the Node. Every field is required.
type Config struct {
	// Mode says whether the programs forward the packets or only count what they would do.
	Mode Mode
	// TransportName, TransportIfIndex and TransportMTU describe the interface the Node reaches its peers
	// through, where the packets coming back from remote Pods arrive. The name is how Run finds the
	// interface again when it is recreated with another index.
	TransportName    string
	TransportIfIndex int
	TransportMTU     int
	// GatewayName, GatewayIfIndex and GatewayMTU describe the Antrea gateway, where the packets of the local
	// Pods enter the host from OVS.
	GatewayName    string
	GatewayIfIndex int
	GatewayMTU     int
	// LocalPodCIDR is the CIDR the Pods of this Node have an address in.
	LocalPodCIDR *net.IPNet
	// GatewayIPv4 is the address of the Antrea gateway. It is inside LocalPodCIDR without belonging to a
	// Pod, and the Node sends traffic from it, so the programs exclude it from what they forward.
	GatewayIPv4 net.IP
	// NodeIPv4 is the transport address of this Node. It is only checked, as a Node whose address is
	// inside LocalPodCIDR is a configuration this datapath refuses rather than handles.
	NodeIPv4 net.IP
}

// Stats counts what the programs did, per packet. A miss or a pass is a packet the host network stack handled
// instead, not a packet which was lost.
type Stats struct {
	// Forwarded and Returned count the packets sent to a peer Node and to a local Pod.
	Forwarded uint64
	Returned  uint64
	// ForwardMisses and ReturnMisses count the packets which were meant to be forwarded but were left to
	// the stack, almost always because the neighbor was not resolved. This is expected to grow slowly
	// rather than to stay at zero: those are the packets which make the kernel resolve a neighbor and
	// keep it from ageing out.
	ForwardMisses uint64
	ReturnMisses  uint64
	// Passed counts the packets which are not cross-Node Pod packets.
	Passed uint64
	// TTLExpired and TooBig count the packets left to the stack so that it reports them to their sender.
	TTLExpired uint64
	TooBig     uint64
	// WouldForward and WouldReturn count, in observe mode, the packets which forward mode would have sent to
	// a peer Node and to a local Pod. They were left to the stack untouched, and Forwarded and Returned stay
	// at zero in that mode. The misses and the passes count the same packets in both modes.
	WouldForward uint64
	WouldReturn  uint64
}

// Interface is the eBPF host datapath as the rest of the Agent uses it. The Pod routes mirror what the route
// client installs, and are set by the Node route controller from the same events.
type Interface interface {
	// Load creates the maps, loads the programs and attaches them. Nothing is forwarded by this datapath
	// until it is called, and everything keeps working without it.
	Load(config Config) error
	// Run keeps the programs attached until stopCh is closed. It looks the two interfaces up by name
	// periodically, attaches the programs again when an interface was recreated or lost its filter, and
	// updates the MTUs the programs check against. It must be called after Load succeeded.
	Run(stopCh <-chan struct{})
	// AddPodRoute records that the Pods of podCIDR are on the Node reachable at nextHop, and
	// DeletePodRoute removes it. Until a CIDR is added, its traffic goes through the host stack.
	AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error
	DeletePodRoute(podCIDR *net.IPNet) error
	// Stats reports the counters of the programs.
	Stats() (Stats, error)
	// Close detaches the programs and releases the maps.
	Close() error
}
