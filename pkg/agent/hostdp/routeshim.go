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

package hostdp

import (
	"net"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/route"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
)

// routeShim decorates a route client so NodePort configurations are mirrored into the eBPF host datapath:
// NodePort traffic to the Node transport IP is DNAT'd in eBPF to the NodePort virtual DNAT IP (port
// preserved), which the kernel routes into OVS via the gateway for AntreaProxy's endpoint selection —
// the same model as the netfilter rules, with the reply's source restored by the eBPF np_ct map instead of
// kernel conntrack. IPv4 TCP/UDP only; other NodePort addresses/protocols are served by the netfilter rules.
type routeShim struct {
	route.Interface
	hostDP Interface
}

// NewRouteShim wraps a route client so NodePort configs are also programmed into the eBPF host datapath.
func NewRouteShim(inner route.Interface, hostDP Interface) route.Interface {
	return &routeShim{Interface: inner, hostDP: hostDP}
}

func protocolNumber(protocol binding.Protocol) (uint8, bool) {
	switch protocol {
	case binding.ProtocolTCP:
		return 6, true
	case binding.ProtocolUDP:
		return 17, true
	}
	return 0, false
}

func (s *routeShim) AddNodePortConfigs(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	if err := s.Interface.AddNodePortConfigs(nodePortAddresses, port, protocol); err != nil {
		return err
	}
	if proto, ok := protocolNumber(protocol); ok {
		return s.hostDP.AddNodePort(proto, port, config.VirtualNodePortDNATIPv4, port)
	}
	return nil
}

func (s *routeShim) DeleteNodePortConfigs(nodePortAddresses []net.IP, port uint16, protocol binding.Protocol) error {
	if err := s.Interface.DeleteNodePortConfigs(nodePortAddresses, port, protocol); err != nil {
		return err
	}
	if proto, ok := protocolNumber(protocol); ok {
		return s.hostDP.DeleteNodePort(proto, port)
	}
	return nil
}
