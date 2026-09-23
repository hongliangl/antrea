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

package openflow

import (
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/openflow/cookie"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	crdv1alpha2 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha2"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	ovsoftest "antrea.io/antrea/v2/pkg/ovs/openflow/testing"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
	"antrea.io/antrea/v2/third_party/proxy"
)

// updatePipelineSnapshotsEnv makes TestPipelineSnapshots rewrite the snapshot files instead of comparing against them.
const updatePipelineSnapshotsEnv = "UPDATE_PIPELINE_SNAPSHOTS"

var (
	pipelineSnapshotDir = filepath.Join("..", "..", "..", "docs", "design", "ovs-pipeline", "snapshots")

	// The local Node node-a is the fake client itself, see fakeNodeIPv4, fakePodIPv4CIDR and fakeGatewayIPv4.
	snapshotNodeBName                               = "node-b"
	snapshotNodeBIP                                 = net.ParseIP("192.168.77.101")
	snapshotNodeBGatewayIP, snapshotNodeBPodCIDR, _ = net.ParseCIDR("10.10.1.1/24")
	snapshotNodeCName                               = "node-c"
	snapshotNodeCIP                                 = net.ParseIP("192.168.78.101")
	snapshotNodeCGatewayIP, snapshotNodeCPodCIDR, _ = net.ParseCIDR("10.10.2.1/24")

	snapshotClientPodName   = "client"
	snapshotClientPodIP     = net.ParseIP("10.10.0.10")
	snapshotClientPodMAC, _ = net.ParseMAC("0a:58:0a:0a:00:0a")
	snapshotClientPodOFPort = uint32(10)
	snapshotWebPodName      = "web"
	snapshotWebPodIP        = net.ParseIP("10.10.0.11")
	snapshotWebPodMAC, _    = net.ParseMAC("0a:58:0a:0a:00:0b")
	snapshotWebPodOFPort    = uint32(11)
	snapshotDBPodIP         = "10.10.1.11"

	snapshotServiceName           = "svc-web"
	snapshotServiceClusterIP      = net.ParseIP("10.96.0.10")
	snapshotServicePort           = uint16(80)
	snapshotServiceNodePort       = uint16(30080)
	snapshotServiceLoadBalancerIP = net.ParseIP("192.168.77.150")

	snapshotPolicyName      = "allow-client-to-web"
	snapshotL7PolicyName    = "allow-client-to-web-http"
	snapshotPolicyPriority  = uint16(44900)
	snapshotL7RulePriority  = uint16(44899)
	snapshotL7RuleVlanID    = uint32(1)
	snapshotL7TargetOFPort  = uint32(300)
	snapshotL7ReturnOFPort  = uint32(301)
	snapshotPolicyPort      = intstr.FromInt32(80)
	snapshotPolicyProtocol  = v1beta2.ProtocolTCP
	snapshotPolicyAllow     = crdv1beta1.RuleActionAllow
	snapshotMirrorTargetOF  = uint32(200)
	snapshotRedirectTarget  = uint32(201)
	snapshotRedirectReturn  = uint32(202)
	snapshotMulticastIP     = net.ParseIP("224.1.1.1")
	snapshotEgressSNATIP    = net.ParseIP("192.168.77.200")
	snapshotEgressMark      = uint32(1)
	snapshotEgressRateKbps  = uint32(10000)
	snapshotEgressBurstKbit = uint32(20000)
)

type pipelineSnapshotConfig struct {
	name    string
	mode    config.TrafficEncapModeType
	options []clientOptionsFn
}

type snapshotFlow struct {
	feature  string
	source   string
	tableID  uint8
	priority uint16
	text     string
}

type snapshotEntry struct {
	source string
	text   string
}

// snapshotRecorder replaces the OVS bridge behind the client. It keeps the flows under the key the client uses for its
// own caches, so that a flow which a later call modifies or deletes ends up in its final state, as it would on OVS.
type snapshotRecorder struct {
	source  string
	sources []string
	flows   map[string]*snapshotFlow
	groups  map[binding.GroupIDType]*snapshotEntry
	meters  map[binding.MeterIDType]*snapshotEntry
}

func newSnapshotRecorder() *snapshotRecorder {
	return &snapshotRecorder{
		flows:  map[string]*snapshotFlow{},
		groups: map[binding.GroupIDType]*snapshotEntry{},
		meters: map[binding.MeterIDType]*snapshotEntry{},
	}
}

func (r *snapshotRecorder) setSource(source string) {
	r.source = source
	if !slices.Contains(r.sources, source) {
		r.sources = append(r.sources, source)
	}
}

// joinSource records every object that produced the same flow, e.g. a conjunctive match flow shared by two rules.
func joinSource(previous, current string) string {
	if previous == "" || slices.Contains(strings.Split(previous, ","), current) {
		return current
	}
	return previous + "," + current
}

func (r *snapshotRecorder) storeFlows(flowMods []*openflow15.FlowMod) {
	for _, flowMod := range flowMods {
		key := getFlowModKey(flowMod)
		source := r.source
		if existing, ok := r.flows[key]; ok {
			source = joinSource(existing.source, r.source)
		}
		r.flows[key] = &snapshotFlow{
			feature:  cookie.ID(flowMod.Cookie).Category().String(),
			source:   source,
			tableID:  flowMod.TableId,
			priority: flowMod.Priority,
			text:     flowTextWithoutCookie(flowMod),
		}
	}
}

func (r *snapshotRecorder) removeFlows(flowMods []*openflow15.FlowMod) {
	for _, flowMod := range flowMods {
		delete(r.flows, getFlowModKey(flowMod))
	}
}

func (r *snapshotRecorder) storeEntries(entries []binding.OFEntry) error {
	for _, entry := range entries {
		group, ok := entry.(binding.Group)
		if !ok {
			return fmt.Errorf("unexpected OpenFlow entry type %v", entry.Type())
		}
		r.groups[group.GetID()] = &snapshotEntry{source: r.source, text: getGroupFromCache(group)}
	}
	return nil
}

func (r *snapshotRecorder) AddAll(flowMods []*openflow15.FlowMod) error {
	r.storeFlows(flowMods)
	return nil
}

func (r *snapshotRecorder) ModifyAll(flowMods []*openflow15.FlowMod) error {
	r.storeFlows(flowMods)
	return nil
}

func (r *snapshotRecorder) BundleOps(adds, mods, dels []*openflow15.FlowMod) error {
	r.removeFlows(dels)
	r.storeFlows(adds)
	r.storeFlows(mods)
	return nil
}

func (r *snapshotRecorder) DeleteAll(flowMods []*openflow15.FlowMod) error {
	r.removeFlows(flowMods)
	return nil
}

func (r *snapshotRecorder) AddOFEntries(entries []binding.OFEntry) error {
	return r.storeEntries(entries)
}

func (r *snapshotRecorder) ModifyOFEntries(entries []binding.OFEntry) error {
	return r.storeEntries(entries)
}

func (r *snapshotRecorder) DeleteOFEntries(entries []binding.OFEntry) error {
	for _, entry := range entries {
		if group, ok := entry.(binding.Group); ok {
			delete(r.groups, group.GetID())
		}
	}
	return nil
}

// snapshotBundleBridge sends to the recorder the conjunctive match flows, which featureNetworkPolicy installs through
// its bridge directly instead of through ofEntryOperations.
type snapshotBundleBridge struct {
	binding.Bridge
	recorder *snapshotRecorder
}

func (b *snapshotBundleBridge) AddFlowsInBundle(addFlows, modFlows, delFlows []*openflow15.FlowMod) error {
	return b.recorder.BundleOps(addFlows, modFlows, delFlows)
}

// expectSnapshotBridgeCalls lets the client initialize and install meters on a mock bridge. The real bridge has no
// OVS connection in unit tests, and group and meter deletion or meter installation would block on it.
func expectSnapshotBridgeCalls(ctrl *gomock.Controller, bridge *ovsoftest.MockBridge, recorder *snapshotRecorder) {
	bridge.EXPECT().DeleteGroupAll().Return(nil).AnyTimes()
	bridge.EXPECT().DeleteMeterAll().Return(nil).AnyTimes()
	bridge.EXPECT().NewMeter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(meterID binding.MeterIDType, flags ofctrl.MeterFlag) binding.Meter {
			entry := &snapshotEntry{source: recorder.source}
			recorder.meters[meterID] = entry
			var rate, burst uint32
			meter := ovsoftest.NewMockMeter(ctrl)
			bandBuilder := ovsoftest.NewMockMeterBandBuilder(ctrl)
			meter.EXPECT().MeterBand().Return(bandBuilder).AnyTimes()
			meter.EXPECT().Add().Return(nil).AnyTimes()
			meter.EXPECT().Modify().Return(nil).AnyTimes()
			bandBuilder.EXPECT().MeterType(gomock.Any()).Return(bandBuilder).AnyTimes()
			bandBuilder.EXPECT().Rate(gomock.Any()).DoAndReturn(func(value uint32) binding.MeterBandBuilder {
				rate = value
				return bandBuilder
			}).AnyTimes()
			bandBuilder.EXPECT().Burst(gomock.Any()).DoAndReturn(func(value uint32) binding.MeterBandBuilder {
				burst = value
				return bandBuilder
			}).AnyTimes()
			bandBuilder.EXPECT().Done().DoAndReturn(func() binding.Meter {
				entry.text = meterText(meterID, flags, rate, burst)
				return meter
			}).AnyTimes()
			return meter
		}).AnyTimes()
}

func meterText(meterID binding.MeterIDType, flags ofctrl.MeterFlag, rate, burst uint32) string {
	unit := "pktps"
	if flags&ofctrl.MeterKbps != 0 {
		unit = "kbps"
	}
	return fmt.Sprintf("meter=%d,%s,rate=%d,burst=%d", meterID, unit, rate, burst)
}

// flowTextWithoutCookie drops the cookie and the table. The cookie carries the agent round number, which means
// nothing here, and its category is already shown as the feature. The table is the section header.
func flowTextWithoutCookie(flowMod *openflow15.FlowMod) string {
	text := binding.FlowModToString(flowMod)
	text = strings.TrimPrefix(text, fmt.Sprintf("cookie=0x%x, ", flowMod.Cookie))
	if tableName, ok := binding.TableNameCache[flowMod.TableId]; ok {
		return strings.TrimPrefix(text, fmt.Sprintf("table=%s, ", tableName))
	}
	return strings.TrimPrefix(text, fmt.Sprintf("table=%d, ", flowMod.TableId))
}

// pipelineSnapshotConfigs has one configuration per feature only in encap mode, because the flows of optional
// features do not depend on the traffic mode, while the PodConnectivity and Egress flows do. The other modes get the
// default and all features configurations.
func pipelineSnapshotConfigs() []pipelineSnapshotConfig {
	features := []struct {
		name   string
		option clientOptionsFn
	}{
		{name: "proxy-all", option: enableProxyAll},
		{name: "l7-network-policy", option: enableL7NetworkPolicy},
		{name: "traffic-control", option: enableTrafficControl},
		{name: "multicast", option: enableMulticast},
		{name: "egress-traffic-shaping", option: enableEgressTrafficShaping},
		{name: "dsr", option: enableDSR},
	}
	var allOptions []clientOptionsFn
	for _, f := range features {
		allOptions = append(allOptions, f.option)
	}

	var configs []pipelineSnapshotConfig
	for _, m := range []struct {
		name string
		mode config.TrafficEncapModeType
	}{
		{name: "encap", mode: config.TrafficEncapModeEncap},
		{name: "noencap", mode: config.TrafficEncapModeNoEncap},
		{name: "hybrid", mode: config.TrafficEncapModeHybrid},
	} {
		configs = append(configs, pipelineSnapshotConfig{name: m.name + "-default", mode: m.mode})
		if m.mode == config.TrafficEncapModeEncap {
			for _, f := range features {
				configs = append(configs, pipelineSnapshotConfig{
					name:    m.name + "-" + f.name,
					mode:    m.mode,
					options: []clientOptionsFn{f.option},
				})
			}
		}
		configs = append(configs, pipelineSnapshotConfig{name: m.name + "-all", mode: m.mode, options: allOptions})
	}
	return configs
}

// enabledSnapshotFeatures reads the features from the client rather than from the options, so that the header shows
// what the client was built with, including options that imply others.
func enabledSnapshotFeatures(fc *client) []string {
	var features []string
	for _, f := range []struct {
		name    string
		enabled bool
	}{
		{name: "AntreaProxy", enabled: fc.enableProxy},
		{name: "ProxyAll", enabled: fc.proxyAll},
		{name: "LoadBalancerModeDSR", enabled: fc.enableDSR},
		{name: "AntreaPolicy", enabled: fc.enableAntreaPolicy},
		{name: "L7NetworkPolicy", enabled: fc.enableL7NetworkPolicy},
		{name: "Egress", enabled: fc.enableEgress},
		{name: "EgressTrafficShaping", enabled: fc.enableEgressTrafficShaping},
		{name: "TrafficControl", enabled: fc.enableTrafficControl},
		{name: "Multicast", enabled: fc.enableMulticast},
		{name: "OVSMeters", enabled: fc.ovsMetersAreSupported},
	} {
		if f.enabled {
			features = append(features, f.name)
		}
	}
	return features
}

func installSnapshotNodes(fc *client, recorder *snapshotRecorder) error {
	// The agent passes the peer transport IP and lets NeedsTunnelToPeer choose between tunnel and routing, so node-b,
	// in the subnet of node-a, is routed in hybrid mode and node-c is tunneled.
	for _, node := range []struct {
		name      string
		ip        net.IP
		gatewayIP net.IP
		podCIDR   *net.IPNet
	}{
		{name: snapshotNodeBName, ip: snapshotNodeBIP, gatewayIP: snapshotNodeBGatewayIP, podCIDR: snapshotNodeBPodCIDR},
		{name: snapshotNodeCName, ip: snapshotNodeCIP, gatewayIP: snapshotNodeCGatewayIP, podCIDR: snapshotNodeCPodCIDR},
	} {
		recorder.setSource("node:" + node.name)
		peerConfigs := map[*net.IPNet]net.IP{node.podCIDR: node.gatewayIP}
		if err := fc.InstallNodeFlows(node.name, peerConfigs, &utilip.DualStackIPs{IPv4: node.ip}, 0, nil); err != nil {
			return fmt.Errorf("failed to install flows for Node %s: %w", node.name, err)
		}
	}
	return nil
}

func installSnapshotPods(fc *client, recorder *snapshotRecorder) error {
	for _, pod := range []struct {
		name   string
		ip     net.IP
		mac    net.HardwareAddr
		ofPort uint32
	}{
		{name: snapshotClientPodName, ip: snapshotClientPodIP, mac: snapshotClientPodMAC, ofPort: snapshotClientPodOFPort},
		{name: snapshotWebPodName, ip: snapshotWebPodIP, mac: snapshotWebPodMAC, ofPort: snapshotWebPodOFPort},
	} {
		recorder.setSource("pod:" + pod.name)
		if err := fc.InstallPodFlows(pod.name, []net.IP{pod.ip}, pod.mac, pod.ofPort, 0, nil); err != nil {
			return fmt.Errorf("failed to install flows for Pod %s: %w", pod.name, err)
		}
	}
	return nil
}

// installSnapshotService follows proxier.installService: Endpoint flows first, then the cluster group, then the
// Service flows. Endpoints are installed one by one only so that each flow is attributed to its Endpoint.
func installSnapshotService(fc *client, recorder *snapshotRecorder) error {
	endpoints := []proxy.Endpoint{
		proxy.NewBaseEndpointInfo(snapshotWebPodIP.String(), int(snapshotServicePort), true, true, true, false, nil, nil),
		proxy.NewBaseEndpointInfo(snapshotDBPodIP, int(snapshotServicePort), false, true, true, false, nil, nil),
	}
	for _, endpoint := range endpoints {
		recorder.setSource("endpoint:" + endpoint.String())
		if err := fc.InstallEndpointFlows(binding.ProtocolTCP, []proxy.Endpoint{endpoint}); err != nil {
			return fmt.Errorf("failed to install flows for Endpoint %s: %w", endpoint.String(), err)
		}
	}

	recorder.setSource("service:" + snapshotServiceName)
	clusterGroupID := fc.groupIDAllocator.Allocate()
	if err := fc.InstallServiceGroup(clusterGroupID, false, endpoints); err != nil {
		return err
	}
	serviceConfigs := []*types.ServiceConfig{{
		ServiceIP:      snapshotServiceClusterIP,
		ServicePort:    snapshotServicePort,
		Protocol:       binding.ProtocolTCP,
		ClusterGroupID: clusterGroupID,
	}}
	if fc.proxyAll {
		serviceConfigs = append(serviceConfigs,
			&types.ServiceConfig{
				ServiceIP:      config.VirtualNodePortDNATIPv4,
				ServicePort:    snapshotServiceNodePort,
				Protocol:       binding.ProtocolTCP,
				ClusterGroupID: clusterGroupID,
				IsExternal:     true,
				IsNodePort:     true,
			},
			&types.ServiceConfig{
				ServiceIP:      snapshotServiceLoadBalancerIP,
				ServicePort:    snapshotServicePort,
				Protocol:       binding.ProtocolTCP,
				ClusterGroupID: clusterGroupID,
				IsExternal:     true,
				IsDSR:          fc.enableDSR,
			})
	}
	for _, serviceConfig := range serviceConfigs {
		if err := fc.InstallServiceFlows(serviceConfig); err != nil {
			return fmt.Errorf("failed to install flows for Service IP %s: %w", serviceConfig.ServiceIP, err)
		}
	}
	return nil
}

func newSnapshotPolicyRule(name string, flowID uint32, priority *uint16) *types.PolicyRule {
	return &types.PolicyRule{
		Direction: v1beta2.DirectionIn,
		From:      []types.Address{NewIPAddress(snapshotClientPodIP)},
		To:        []types.Address{NewOFPortAddress(int32(snapshotWebPodOFPort))},
		Service:   []v1beta2.Service{{Protocol: &snapshotPolicyProtocol, Port: &snapshotPolicyPort}},
		Action:    &snapshotPolicyAllow,
		Priority:  priority,
		Name:      "rule-0",
		FlowID:    flowID,
		TableID:   AntreaPolicyIngressRuleTable.GetID(),
		PolicyRef: &v1beta2.NetworkPolicyReference{
			Type:      v1beta2.AntreaNetworkPolicy,
			Namespace: "default",
			Name:      name,
		},
	}
}

func installSnapshotPolicies(fc *client, recorder *snapshotRecorder) error {
	if fc.enableL7NetworkPolicy {
		recorder.setSource("agent:l7-network-policy")
		if err := fc.InstallL7NetworkPolicyFlows(); err != nil {
			return err
		}
	}
	recorder.setSource("policy:" + snapshotPolicyName)
	rule := newSnapshotPolicyRule(snapshotPolicyName, 1, &snapshotPolicyPriority)
	if err := fc.InstallPolicyRuleFlows(rule); err != nil {
		return err
	}
	if !fc.enableL7NetworkPolicy {
		return nil
	}
	recorder.setSource("policy:" + snapshotL7PolicyName)
	rule = newSnapshotPolicyRule(snapshotL7PolicyName, 2, &snapshotL7RulePriority)
	rule.L7Protocols = []v1beta2.L7Protocol{{HTTP: &v1beta2.HTTPProtocol{Method: "GET", Path: "/"}}}
	rule.L7RuleVlanID = &snapshotL7RuleVlanID
	return fc.InstallPolicyRuleFlows(rule)
}

func installSnapshotEgress(fc *client, recorder *snapshotRecorder) error {
	if !fc.enableEgress {
		return nil
	}
	recorder.setSource("agent:egress")
	if err := fc.InstallSNATBypassServiceFlows([]*net.IPNet{fakeServiceIPv4CIDR}); err != nil {
		return err
	}
	recorder.setSource("egress:egress-client")
	if err := fc.InstallSNATMarkFlows(snapshotEgressSNATIP, snapshotEgressMark); err != nil {
		return err
	}
	if err := fc.InstallPodSNATFlows(snapshotClientPodOFPort, snapshotEgressSNATIP, snapshotEgressMark); err != nil {
		return err
	}
	if fc.enableEgressTrafficShaping {
		return fc.InstallEgressQoS(snapshotEgressMark, snapshotEgressRateKbps, snapshotEgressBurstKbit)
	}
	return nil
}

func installSnapshotTrafficControls(fc *client, recorder *snapshotRecorder) error {
	if !fc.enableTrafficControl {
		return nil
	}
	recorder.setSource("tc:mirror-web")
	if err := fc.InstallTrafficControlMarkFlows("mirror-web",
		[]uint32{snapshotWebPodOFPort},
		snapshotMirrorTargetOF,
		crdv1alpha2.DirectionBoth,
		crdv1alpha2.ActionMirror,
		types.TrafficControlFlowPriorityMedium); err != nil {
		return err
	}
	recorder.setSource("tc:redirect-client")
	if err := fc.InstallTrafficControlReturnPortFlow(snapshotRedirectReturn); err != nil {
		return err
	}
	return fc.InstallTrafficControlMarkFlows("redirect-client",
		[]uint32{snapshotClientPodOFPort},
		snapshotRedirectTarget,
		crdv1alpha2.DirectionBoth,
		crdv1alpha2.ActionRedirect,
		types.TrafficControlFlowPriorityMedium)
}

// installSnapshotMulticast follows the multicast controller: the IGMP query group and flows for all local Pods, the
// group to report to remote Nodes when encap is supported, then one group per multicast address with local receivers.
func installSnapshotMulticast(fc *client, recorder *snapshotRecorder) error {
	if !fc.enableMulticast {
		return nil
	}
	recorder.setSource("agent:multicast")
	queryGroupID := fc.groupIDAllocator.Allocate()
	localPorts := []uint32{snapshotClientPodOFPort, snapshotWebPodOFPort}
	if err := fc.InstallMulticastGroup(queryGroupID, localPorts, nil); err != nil {
		return err
	}
	if err := fc.InstallMulticastFlows(types.McastAllHosts, queryGroupID); err != nil {
		return err
	}
	if fc.networkConfig.TrafficEncapMode.SupportsEncap() {
		nodeGroupID := fc.groupIDAllocator.Allocate()
		if err := fc.InstallMulticastGroup(nodeGroupID, nil, []net.IP{snapshotNodeBIP, snapshotNodeCIP}); err != nil {
			return err
		}
		if err := fc.InstallMulticastRemoteReportFlows(nodeGroupID); err != nil {
			return err
		}
	}
	recorder.setSource("multicast:" + snapshotMulticastIP.String())
	groupID := fc.groupIDAllocator.Allocate()
	if err := fc.InstallMulticastGroup(groupID, []uint32{snapshotWebPodOFPort}, nil); err != nil {
		return err
	}
	return fc.InstallMulticastFlows(snapshotMulticastIP, groupID)
}

func installSnapshotObjects(fc *client, recorder *snapshotRecorder) error {
	if err := installSnapshotNodes(fc, recorder); err != nil {
		return err
	}
	if err := installSnapshotPods(fc, recorder); err != nil {
		return err
	}
	if err := installSnapshotService(fc, recorder); err != nil {
		return err
	}
	if err := installSnapshotPolicies(fc, recorder); err != nil {
		return err
	}
	if err := installSnapshotEgress(fc, recorder); err != nil {
		return err
	}
	if err := installSnapshotTrafficControls(fc, recorder); err != nil {
		return err
	}
	return installSnapshotMulticast(fc, recorder)
}

// renderPipelineSnapshot walks the tables in the order of the realized pipelines, which is the order in which
// packets traverse them and in which table IDs were assigned.
func renderPipelineSnapshot(fc *client,
	snapshotConfig pipelineSnapshotConfig,
	recorder *snapshotRecorder,
) (string, error) {
	var lines []string
	lines = append(lines,
		"# Antrea OVS pipeline snapshot, generated by TestPipelineSnapshots. Do not edit, run make pipeline-snapshots.",
		"# Configuration: "+snapshotConfig.name,
		"# Node: node-a, K8s Node, Linux, IPv4 only",
		"# Traffic mode: "+snapshotConfig.mode.String(),
		"# Features: "+strings.Join(enabledSnapshotFeatures(fc), ", "),
		"# Objects: "+strings.Join(recorder.sources, ", "),
	)

	flowsByTable := map[uint8][]*snapshotFlow{}
	for _, flow := range recorder.flows {
		flowsByTable[flow.tableID] = append(flowsByTable[flow.tableID], flow)
	}
	renderedTables := sets.New[uint8]()
	for pipelineID := firstPipeline; pipelineID <= lastPipeline; pipelineID++ {
		pipeline, ok := fc.pipelines[pipelineID]
		if !ok {
			continue
		}
		for _, table := range pipeline.ListAllTables() {
			renderedTables.Insert(table.GetID())
			lines = append(lines, "", fmt.Sprintf("[%s] table %d", table.GetName(), table.GetID()))
			flows := flowsByTable[table.GetID()]
			sort.Slice(flows, func(i, j int) bool {
				if flows[i].priority != flows[j].priority {
					return flows[i].priority > flows[j].priority
				}
				return flows[i].text < flows[j].text
			})
			for _, flow := range flows {
				lines = append(lines, fmt.Sprintf("%s | %s | %s", flow.feature, flow.source, flow.text))
			}
		}
	}
	for tableID := range flowsByTable {
		if !renderedTables.Has(tableID) {
			return "", fmt.Errorf("flows installed in table %d which is not in any pipeline", tableID)
		}
	}

	lines = append(lines, "", "[groups]")
	for _, groupID := range slices.Sorted(maps.Keys(recorder.groups)) {
		group := recorder.groups[groupID]
		lines = append(lines, fmt.Sprintf("%s | %s", group.source, group.text))
	}
	lines = append(lines, "", "[meters]")
	for _, meterID := range slices.Sorted(maps.Keys(recorder.meters)) {
		meter := recorder.meters[meterID]
		lines = append(lines, fmt.Sprintf("%s | %s", meter.source, meter.text))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func generatePipelineSnapshot(ctrl *gomock.Controller, snapshotConfig pipelineSnapshotConfig) (string, error) {
	recorder := newSnapshotRecorder()
	bridge := ovsoftest.NewMockBridge(ctrl)
	expectSnapshotBridgeCalls(ctrl, bridge, recorder)
	// Every snapshot is a Linux Node, and OVS supports meters on Linux. Only Windows lacks them.
	options := append([]clientOptionsFn{setEgressInNetworkConfig, setEnableOVSMeters(true)}, snapshotConfig.options...)
	fc := newFakeClientWithBridge(nil, true, false, config.K8sNode, snapshotConfig.mode, bridge, options...)
	defer resetPipelines()
	fc.ofEntryOperations = recorder
	fc.featureNetworkPolicy.bridge = &snapshotBundleBridge{Bridge: fc.featureNetworkPolicy.bridge, recorder: recorder}
	// The harness puts the L7 ports on OF ports 10 and 11, which are the ports of the client and web Pods here.
	if fc.l7NetworkPolicyConfig != nil {
		fc.l7NetworkPolicyConfig.TargetOFPort = snapshotL7TargetOFPort
		fc.l7NetworkPolicyConfig.ReturnOFPort = snapshotL7ReturnOFPort
	}

	recorder.setSource("init")
	if err := fc.initialize(); err != nil {
		return "", err
	}
	if err := installSnapshotObjects(fc, recorder); err != nil {
		return "", err
	}
	return renderPipelineSnapshot(fc, snapshotConfig, recorder)
}

// checkPipelineSnapshot reports the first differing line only, because a full diff of two files of several hundred
// long lines is unreadable in test output.
func checkPipelineSnapshot(t *testing.T, path, expected, actual string) {
	if expected == actual {
		return
	}
	expectedLines := strings.Split(expected, "\n")
	actualLines := strings.Split(actual, "\n")
	for i := 0; i < max(len(expectedLines), len(actualLines)); i++ {
		var expectedLine, actualLine string
		if i < len(expectedLines) {
			expectedLine = expectedLines[i]
		}
		if i < len(actualLines) {
			actualLine = actualLines[i]
		}
		if expectedLine != actualLine {
			t.Errorf("OVS pipeline differs from %s at line %d\n  file: %s\n  code: %s\n"+
				"If the flow change is intended, run 'make pipeline-snapshots' and commit the result.",
				path, i+1, expectedLine, actualLine)
			return
		}
	}
}

func TestPipelineSnapshots(t *testing.T) {
	skipTest(t, false, true)
	update := os.Getenv(updatePipelineSnapshotsEnv) == "1"

	snapshotConfigs := pipelineSnapshotConfigs()
	for _, tt := range snapshotConfigs {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			snapshot, err := generatePipelineSnapshot(ctrl, tt)
			require.NoError(t, err)
			path := filepath.Join(pipelineSnapshotDir, tt.name+".txt")
			if update {
				// #nosec G306: the snapshot is a checked-in document, not a secret.
				require.NoError(t, os.WriteFile(path, []byte(snapshot), 0o644))
				return
			}
			expected, err := os.ReadFile(path)
			require.NoError(t, err, "Snapshot file is missing, run 'make pipeline-snapshots'")
			checkPipelineSnapshot(t, path, string(expected), snapshot)
		})
	}

	// A configuration removed from the list would otherwise leave a stale file that nothing checks.
	files, err := filepath.Glob(filepath.Join(pipelineSnapshotDir, "*.txt"))
	require.NoError(t, err)
	expectedFiles := sets.New[string]()
	for _, snapshotConfig := range snapshotConfigs {
		expectedFiles.Insert(filepath.Join(pipelineSnapshotDir, snapshotConfig.name+".txt"))
	}
	for _, file := range files {
		assert.True(t, expectedFiles.Has(file), "Snapshot file %s has no configuration, delete it", file)
	}
}
