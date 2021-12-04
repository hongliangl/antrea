//go:build windows
// +build windows

// Copyright 2021 Antrea Authors
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

package openflow

import (
	"net"

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - func (c *client) hostBridgeUplinkFlows(localSubnetMap map[binding.Protocol]net.IPNet, category cookie.Category) (flows []binding.Flow)
// hostBridgeUplinkFlows generates the flows that forward traffic between the bridge local port and the uplink port to
// support the host traffic with outside.
func (f *featurePodConnectivity) hostBridgeUplinkFlows(localSubnetMap map[binding.Protocol]net.IPNet) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := f.hostBridgeLocalFlows()
	flows = append(flows,
		// This generates the flow to forward ARP packets from uplink port to bridge local port since uplink port is set
		// to disable flood.
		ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Done(),
		// This generates the flow to forward ARP packets from bridge local port to uplink port since uplink port is set
		// to disable flood.
		ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Done(),
	)
	if f.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		// If NoEncap is enabled, the reply packets from remote Pod can be forwarded to local Pod directly.
		// by explicitly resubmitting them to ServiceHairpinTable and marking "macRewriteMark" at same time.
		for ipProtocol, localSubnet := range localSubnetMap {
			flows = append(flows, ClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchInPort(config.UplinkOFPort).
				MatchDstIPNet(localSubnet).
				Action().LoadRegMark(FromUplinkRegMark).
				Action().LoadRegMark(RewriteMACRegMark).
				Action().GotoStage(binding.ConntrackStateStage).
				Done())
		}
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Stage: SwitchingStage
// Tables: L3ForwardingTable, L2ForwardingCalcTable
// Refactored from:
//   - func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr, category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr,
	remoteGatewayMAC net.HardwareAddr,
	peerIP net.IP,
	peerPodCIDR *net.IPNet) []binding.Flow {
	var flows []binding.Flow

	if f.networkConfig.NeedsDirectRoutingToPeer(peerIP, f.nodeConfig.NodeTransportIPv4Addr) && remoteGatewayMAC != nil {
		ipProtocol := getIPProtocol(peerIP)
		// It enhances Windows Noencap mode performance by bypassing host network.
		flows = append(flows,
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path. Otherwise,
			// Windows host will perform stateless SNAT on the reply, and the packets are possibly dropped on peer
			// Node because of the wrong source address.
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(f.cookieAllocator.Request(f.category).Raw()).
				MatchProtocol(ipProtocol).
				MatchDstIP(peerIP).
				MatchCTMark(NotServiceCTMark).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().LoadRegMark(ToUplinkRegMark).
				Action().NextTable().
				Done())
		flows = append(flows, f.l3FwdFlowToRemoteViaUplink(remoteGatewayMAC, *peerPodCIDR, false)...)
	} else {
		flows = append(flows, f.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR))
	}
	return flows
}
