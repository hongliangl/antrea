// Copyright 2019 Antrea Authors
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
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/runtime"
	"antrea.io/antrea/third_party/proxy"
)

var (
	// PipelineClassifierTable is table 0. Packet is forwarded to different pipelines according to its protocol.
	PipelineClassifierTable = newFeatureTable("PipelineClassifier", 0xff, 0, 0)

	// ARP pipeline is used to process ARP packets.
	// ValidationStage
	ARPSpoofGuardTable = newFeatureTable("ARPSpoofGuard", 0x7f, binding.ValidationStage, pipelineARP)

	// OutputStage
	ARPResponderTable = newFeatureTable("ARPResponder", 0x7f, binding.OutputStage, pipelineARP)

	// IP pipeline is used to process IPv4/IPv6 packets.
	// ClassifierStage
	ClassifierTable = newFeatureTable("Classification", 0x7f, binding.ClassifierStage, pipelineIP)
	UplinkTable     = newFeatureTable("Uplink", 0x6f, binding.ClassifierStage, pipelineIP)

	// ValidationStage
	SpoofGuardTable = newFeatureTable("SpoofGuard", 0x7f, binding.ValidationStage, pipelineIP)
	IPv6Table       = newFeatureTable("IPv6", 0x6f, binding.ValidationStage, pipelineIP)

	// ConntrackStateStage
	SNATConntrackTable  = newFeatureTable("SNATConntrackZone", 0x7f, binding.ConntrackStateStage, pipelineIP)
	ConntrackTable      = newFeatureTable("ConntrackZone", 0x6f, binding.ConntrackStateStage, pipelineIP)
	ConntrackStateTable = newFeatureTable("ConntrackState", 0x5f, binding.ConntrackStateStage, pipelineIP)

	// EgressSecurityStage
	AntreaPolicyEgressRuleTable = newFeatureTable("AntreaPolicyEgressRule", 0x7f, binding.EgressSecurityStage, pipelineIP)
	EgressRuleTable             = newFeatureTable("EgressRule", 0x6f, binding.EgressSecurityStage, pipelineIP)
	EgressDefaultTable          = newFeatureTable("EgressDefaultRule", 0x5f, binding.EgressSecurityStage, pipelineIP)
	EgressMetricTable           = newFeatureTable("EgressMetric", 0x4f, binding.EgressSecurityStage, pipelineIP)

	// PreRoutingStage
	// AntreaProxy is enabled.
	NodePortProbeTable   = newFeatureTable("NodePortProbe", 0x7f, binding.PreRoutingStage, pipelineIP)
	SessionAffinityTable = newFeatureTable("SessionAffinity", 0x6f, binding.PreRoutingStage, pipelineIP)
	ServiceLBTable       = newFeatureTable("ServiceLB", 0x5f, binding.PreRoutingStage, pipelineIP)
	EndpointDNATTable    = newFeatureTable("EndpointDNAT", 0x4f, binding.PreRoutingStage, pipelineIP)
	// AntreaProxy is disabled.
	DNATTable = newFeatureTable("DNAT", 0x7f, binding.PreRoutingStage, pipelineIP)

	// RoutingStage
	L3ForwardingTable       = newFeatureTable("L3Forwarding", 0x7f, binding.RoutingStage, pipelineIP)
	ServiceHairpinMarkTable = newFeatureTable("ServiceHairpinMark", 0x6f, binding.RoutingStage, pipelineIP)
	L3DecTTLTable           = newFeatureTable("IPTTLDec", 0x5f, binding.RoutingStage, pipelineIP)

	// PostRoutingStage
	SNATTable                = newFeatureTable("SNAT", 0x7f, binding.PostRoutingStage, pipelineIP)
	SNATConntrackCommitTable = newFeatureTable("SNATConntrackCommit", 0x6f, binding.PostRoutingStage, pipelineIP)

	// SwitchingStage
	L2ForwardingCalcTable = newFeatureTable("L2Forwarding", 0x7f, binding.SwitchingStage, pipelineIP)

	// IngressSecurityStage
	IngressClassifierTable       = newFeatureTable("IngressClassifier", 0x7f, binding.IngressSecurityStage, pipelineIP)
	AntreaPolicyIngressRuleTable = newFeatureTable("AntreaPolicyIngressRule", 0x6f, binding.IngressSecurityStage, pipelineIP)
	IngressRuleTable             = newFeatureTable("IngressRule", 0x5f, binding.IngressSecurityStage, pipelineIP)
	IngressDefaultTable          = newFeatureTable("IngressDefaultRule", 0x4f, binding.IngressSecurityStage, pipelineIP)
	IngressMetricTable           = newFeatureTable("IngressMetric", 0x3f, binding.IngressSecurityStage, pipelineIP)

	// ConntrackStage
	ConntrackCommitTable = newFeatureTable("ConntrackCommit", 0x7f, binding.ConntrackStage, pipelineIP)

	// OutputStage
	L2ForwardingOutTable = newFeatureTable("L2ForwardingOut", 0x7f, binding.OutputStage, pipelineIP)

	// Flow priority level
	priorityHigh            = uint16(210)
	priorityNormal          = uint16(200)
	priorityLow             = uint16(190)
	priorityMiss            = uint16(0)
	priorityTopAntreaPolicy = uint16(64990)
	priorityDNSIntercept    = uint16(64991)
	priorityDNSBypass       = uint16(64992)

	// Index for priority cache
	priorityIndex = "priority"

	// IPv6 multicast prefix
	ipv6MulticastAddr = "FF00::/8"
	// IPv6 link-local prefix
	ipv6LinkLocalAddr = "FE80::/10"

	// Operation field values in ARP packets
	arpOpRequest = uint16(1)
	arpOpReply   = uint16(2)

	tableNameIndex = "tableNameIndex"
)

type ofAction int32

const (
	add ofAction = iota
	mod
	del
)

func (a ofAction) String() string {
	switch a {
	case add:
		return "add"
	case mod:
		return "modify"
	case del:
		return "delete"
	default:
		return "unknown"
	}
}

var (
	// egressTables map records all IDs of tables related to
	// egress rules.
	egressTables = map[uint8]struct{}{}

	// tableCache caches the OpenFlow tables used in the pipeline, and it supports using the table ID and name as the index to query the OpenFlow table.
	tableCache = cache.NewIndexer(tableIDKeyFunc, cache.Indexers{tableNameIndex: tableNameIndexFunc})
)

func tableNameIndexFunc(obj interface{}) ([]string, error) {
	ft := obj.(*FeatureTable)
	return []string{ft.GetName()}, nil
}

func tableIDKeyFunc(obj interface{}) (string, error) {
	ft := obj.(*FeatureTable)
	return fmt.Sprintf("%d", ft.GetID()), nil
}

func getTableByID(id uint8) binding.Table {
	obj, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", id))
	if !exists {
		return nil
	}
	return obj.(*FeatureTable).ofTable
}

// GetFlowTableName returns the flow table name given the table ID. An empty
// string is returned if the table cannot be found.
func GetFlowTableName(tableID uint8) string {
	table := getTableByID(tableID)
	if table == nil {
		return ""
	}
	return table.GetName()
}

// GetFlowTableID does a case insensitive lookup of the table name, and
// returns the flow table number if the table is found. Otherwise TableIDAll is
// returned if the table cannot be found.
func GetFlowTableID(tableName string) uint8 {
	objs, _ := tableCache.ByIndex(tableNameIndex, tableName)
	if len(objs) == 0 {
		return binding.TableIDAll
	}
	return objs[0].(binding.Table).GetID()
}

func GetTableList() []binding.Table {
	tables := make([]binding.Table, 0)
	for _, obj := range tableCache.List() {
		t := obj.(binding.Table)
		tables = append(tables, t)
	}
	return tables
}

func GetAntreaPolicyEgressTables() []*FeatureTable {
	return []*FeatureTable{
		AntreaPolicyEgressRuleTable,
		EgressDefaultTable,
	}
}

func GetAntreaPolicyIngressTables() []*FeatureTable {
	return []*FeatureTable{
		AntreaPolicyIngressRuleTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyBaselineTierTables() []*FeatureTable {
	return []*FeatureTable{
		EgressDefaultTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyMultiTierTables() []*FeatureTable {
	return []*FeatureTable{
		AntreaPolicyEgressRuleTable,
		AntreaPolicyIngressRuleTable,
	}
}

const (
	CtZone       = 0xfff0
	CtZoneV6     = 0xffe6
	SNATCtZone   = 0xfff1
	SNATCtZoneV6 = 0xffe7

	// disposition values used in AP
	DispositionAllow = 0b00
	DispositionDrop  = 0b01
	DispositionRej   = 0b10
	DispositionPass  = 0b11

	// CustomReasonLogging is used when send packet-in to controller indicating this
	// packet need logging.
	CustomReasonLogging = 0b01
	// CustomReasonReject is not only used when send packet-in to controller indicating
	// that this packet should be rejected, but also used in the case that when
	// controller send reject packet as packet-out, we want reject response to bypass
	// the connTrack to avoid unexpected drop.
	CustomReasonReject = 0b10
	// CustomReasonDeny is used when sending packet-in message to controller indicating
	// that the corresponding connection has been dropped or rejected. It can be consumed
	// by the Flow Exporter to export flow records for connections denied by network
	// policy rules.
	CustomReasonDeny = 0b100
	CustomReasonDNS  = 0b1000
)

var DispositionToString = map[uint32]string{
	DispositionAllow: "Allow",
	DispositionDrop:  "Drop",
	DispositionRej:   "Reject",
	DispositionPass:  "Pass",
}

var (
	// traceflowTagToSRange stores Traceflow dataplane tag to DSCP bits of
	// IP header ToS field.
	traceflowTagToSRange = binding.IPDSCPToSRange

	// snatPktMarkRange takes an 8-bit range of pkt_mark to store the ID of
	// a SNAT IP. The bit range must match SNATIPMarkMask.
	snatPktMarkRange = &binding.Range{0, 7}

	GlobalVirtualMAC, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
	hairpinIP           = net.ParseIP("169.254.169.252").To4()
	hairpinIPv6         = net.ParseIP("fc00::aabb:ccdd:eeff").To16()
)

type OFEntryOperations interface {
	Add(flow binding.Flow) error
	Modify(flow binding.Flow) error
	Delete(flow binding.Flow) error
	AddAll(flows []binding.Flow) error
	ModifyAll(flows []binding.Flow) error
	BundleOps(adds []binding.Flow, mods []binding.Flow, dels []binding.Flow) error
	DeleteAll(flows []binding.Flow) error
	AddOFEntries(ofEntries []binding.OFEntry) error
	DeleteOFEntries(ofEntries []binding.OFEntry) error
}

type flowCache map[string]binding.Flow

type flowCategoryCache struct {
	sync.Map
}

func portToUint16(port int) uint16 {
	if port > 0 && port <= math.MaxUint16 {
		return uint16(port) // lgtm[go/incorrect-integer-conversion]
	}
	klog.Errorf("Port value %d out-of-bounds", port)
	return 0
}

type client struct {
	enableProxy           bool
	proxyAll              bool
	enableAntreaPolicy    bool
	enableDenyTracking    bool
	enableEgress          bool
	enableWireGuard       bool
	connectUplinkToBridge bool
	roundInfo             types.RoundInfo
	cookieAllocator       cookie.Allocator
	bridge                binding.Bridge

	featurePodConnectivity *featurePodConnectivity
	featureService         *featureService
	featureEgress          *featureEgress
	featureNetworkPolicy   *featureNetworkPolicy
	featureTraceflow       *featureTraceflow

	pipelines   map[pipelineProtocol]binding.Pipeline
	ipProtocols []binding.Protocol

	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex   sync.RWMutex
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	egressConfig  *config.EgressConfig
	gatewayOFPort uint32
	// ovsDatapathType is the type of the datapath used by the bridge.
	ovsDatapathType ovsconfig.OVSDatapathType
	// ovsMetersAreSupported indicates whether the OVS datapath supports OpenFlow meters.
	ovsMetersAreSupported bool
	// ovsctlClient is the interface for executing OVS "ovs-ofctl" and "ovs-appctl" commands.
	ovsctlClient ovsctl.OVSCtlClient
	// deterministic represents whether to generate flows deterministically.
	// For example, if a flow has multiple actions, setting it to true can get consistent flow.
	// Enabling it may carry a performance impact. It's disabled by default and should only be used in testing.
	deterministic bool
}

func (c *client) GetTunnelVirtualMAC() net.HardwareAddr {
	return GlobalVirtualMAC
}

func (c *client) changeAll(flowsMap map[ofAction][]binding.Flow) error {
	if len(flowsMap) == 0 {
		return nil
	}

	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsLatency.WithLabelValues(k.String()).Observe(float64(d.Milliseconds()))
			}
		}
	}()

	if err := c.bridge.AddFlowsInBundle(flowsMap[add], flowsMap[mod], flowsMap[del]); err != nil {
		for k, v := range flowsMap {
			if len(v) != 0 {
				metrics.OVSFlowOpsErrorCount.WithLabelValues(k.String()).Inc()
			}
		}
		return err
	}
	for k, v := range flowsMap {
		if len(v) != 0 {
			metrics.OVSFlowOpsCount.WithLabelValues(k.String()).Inc()
		}
	}
	return nil
}

func (c *client) Add(flow binding.Flow) error {
	return c.AddAll([]binding.Flow{flow})
}

func (c *client) Modify(flow binding.Flow) error {
	return c.ModifyAll([]binding.Flow{flow})
}

func (c *client) Delete(flow binding.Flow) error {
	return c.DeleteAll([]binding.Flow{flow})
}

func (c *client) AddAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{add: flows})
}

func (c *client) ModifyAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{mod: flows})
}

func (c *client) DeleteAll(flows []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{del: flows})
}

func (c *client) BundleOps(adds []binding.Flow, mods []binding.Flow, dels []binding.Flow) error {
	return c.changeAll(map[ofAction][]binding.Flow{add: adds, mod: mods, del: dels})
}

func (c *client) changeOFEntries(ofEntries []binding.OFEntry, action ofAction) error {
	if len(ofEntries) == 0 {
		return nil
	}
	var adds, mods, dels []binding.OFEntry
	if action == add {
		adds = ofEntries
	} else if action == mod {
		mods = ofEntries
	} else if action == del {
		dels = ofEntries
	} else {
		return fmt.Errorf("OF Entries Action not exists: %s", action)
	}
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		metrics.OVSFlowOpsLatency.WithLabelValues(action.String()).Observe(float64(d.Milliseconds()))
	}()
	if err := c.bridge.AddOFEntriesInBundle(adds, mods, dels); err != nil {
		metrics.OVSFlowOpsErrorCount.WithLabelValues(action.String()).Inc()
		return err
	}
	metrics.OVSFlowOpsCount.WithLabelValues(action.String()).Inc()
	return nil
}

func (c *client) AddOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, add)
}

func (c *client) DeleteOFEntries(ofEntries []binding.OFEntry) error {
	return c.changeOFEntries(ofEntries, del)
}

func (c *client) defaultFlows(category cookie.Category) []binding.Flow {
	cookieID := c.cookieAllocator.Request(category).Raw()
	var flows []binding.Flow
	for pipelineProto, pipeline := range c.pipelines {
		// Generate default flow for every table for a pipeline.
		for _, table := range pipeline.ListAllTables() {
			flowBuilder := table.BuildFlow(priorityMiss).
				Cookie(cookieID)

			switch table.GetMissAction() {
			case binding.TableMissActionNext:
				flowBuilder = flowBuilder.Action().NextTable()
			case binding.TableMissActionNormal:
				flowBuilder = flowBuilder.Action().Normal()
			case binding.TableMissActionDrop:
				flowBuilder = flowBuilder.Action().Drop()
			case binding.TableMissActionNone:
				fallthrough
			default:
				continue
			}
			flows = append(flows, flowBuilder.Done())
		}

		// Generate flows in PipelineClassifierTable to forward traffic to different pipelines.
		switch pipelineProto {
		case pipelineIP:
			for _, ipProtocol := range c.ipProtocols {
				flows = append(flows, pipelineClassifyFlow(cookieID, ipProtocol, pipeline))
			}
		case pipelineARP:
			flows = append(flows, pipelineClassifyFlow(cookieID, binding.ProtocolARP, pipeline))
		}
	}
	return flows
}

// tunnelClassifierFlow generates the flow to mark traffic comes from the tunnelOFPort.
func (c *client) tunnelClassifierFlow(tunnelOFPort uint32, category cookie.Category) binding.Flow {
	nextTable := ConntrackTable
	if c.proxyAll {
		nextTable = ServiceConntrackTable
	}
	return ClassifierTable.BuildFlow(priorityNormal).
		MatchInPort(tunnelOFPort).
		Action().LoadRegMark(FromTunnelRegMark).
		Action().LoadRegMark(RewriteMACRegMark).
		Action().GotoTable(nextTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *client) gatewayClassifierFlow(category cookie.Category) binding.Flow {
	return ClassifierTable.BuildFlow(priorityNormal).
		MatchInPort(config.HostGatewayOFPort).
		Action().LoadRegMark(FromGatewayRegMark).
		Action().GotoTable(ClassifierTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category, isAntreaFlexibleIPAM bool) binding.Flow {
	flowBuilder := ClassifierTable.BuildFlow(priorityLow).
		MatchInPort(podOFPort).
		Action().LoadRegMark(FromLocalRegMark).
		Action().GotoTable(ClassifierTable.GetNext())
	if isAntreaFlexibleIPAM {
		// mark traffic from local AntreaFlexibleIPAM Pod
		flowBuilder = flowBuilder.Action().LoadRegMark(AntreaFlexibleIPAMRegMark)
	}
	return flowBuilder.Cookie(c.cookieAllocator.Request(category).Raw()).Done()
}

// podUplinkClassifierFlow generates the flows to mark traffic from uplink and bridge ports, which are needed when
// uplink is connected to OVS bridge when AntreaFlexibleIPAM is configured.
func (c *client) podUplinkClassifierFlows(dstMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow) {
	flows = append(flows, ClassifierTable.BuildFlow(priorityHigh).
		MatchInPort(config.UplinkOFPort).
		MatchDstMAC(dstMAC).
		Action().LoadRegMark(FromUplinkRegMark).
		Action().GotoTable(ServiceHairpinTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done())
	flows = append(flows, ClassifierTable.BuildFlow(priorityHigh).
		MatchInPort(config.BridgeOFPort).
		MatchDstMAC(dstMAC).
		Action().LoadRegMark(FromBridgeRegMark).
		Action().GotoTable(ServiceHairpinTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done())
	return
}

// connectionTrackFlows generates flows that redirect traffic to ct_zone and handle traffic according to ct_state:
// 1) commit new connections to ct_zone(0xfff0) in the ConntrackCommitTable.
// 2) Add ct_mark on the packet if it is sent to the switch from the host gateway.
// 3) Allow traffic if it hits ct_mark and is sent from the host gateway.
// 4) Drop all invalid traffic.
// 5) Let other traffic go to the SessionAffinityTable first and then the ServiceLBTable.
//    The SessionAffinityTable is a side-effect table which means traffic will not
//    be resubmitted to any table. serviceLB does Endpoint selection for traffic
//    to a Service.
// 6) Add a flow to bypass reject response packet sent by the controller.
func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow {
	flows := c.conntrackBasicFlows(category)
	if c.enableProxy {
		// Replace the default flow with multiple resubmits actions.
		if c.proxyAll {
			flows = append(flows, ConntrackStateTable.BuildFlow(priorityMiss).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().ResubmitToTable(ServiceClassifierTable.GetID()).
				Action().ResubmitToTable(SessionAffinityTable.GetID()).
				Action().ResubmitToTable(ServiceLBTable.GetID()).
				Done())
		} else {
			flows = append(flows, ConntrackStateTable.BuildFlow(priorityMiss).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Action().ResubmitToTable(SessionAffinityTable.GetID()).
				Action().ResubmitToTable(ServiceLBTable.GetID()).
				Done())
		}

		for _, proto := range c.ipProtocols {
			gatewayIP := c.nodeConfig.GatewayConfig.IPv4
			serviceVirtualIP := config.VirtualServiceIPv4
			snatZone := SNATCtZone
			ctZone := CtZone
			if proto == binding.ProtocolIPv6 {
				gatewayIP = c.nodeConfig.GatewayConfig.IPv6
				serviceVirtualIP = config.VirtualServiceIPv6
				snatZone = SNATCtZoneV6
				ctZone = CtZoneV6
			}
			flows = append(flows,
				// This flow is used to maintain DNAT conntrack for Service traffic.
				ConntrackTable.BuildFlow(priorityNormal).MatchProtocol(proto).
					Action().CT(false, ConntrackTable.GetNext(), ctZone).NAT().CTDone().
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Done(),
				ConntrackCommitTable.BuildFlow(priorityLow).MatchProtocol(proto).
					MatchCTStateTrk(true).
					MatchCTMark(ServiceCTMark).
					MatchRegMark(EpSelectedRegMark).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Action().GotoTable(ConntrackCommitTable.GetNext()).
					Done(),
			)

			if c.proxyAll {
				flows = append(flows,
					// This flow is used to match the Service traffic from Antrea gateway. The Service traffic from gateway
					// should enter table serviceConntrackCommitTable, otherwise it will be matched by other flows in
					// table connectionTrackCommit.
					ConntrackCommitTable.BuildFlow(priorityHigh).MatchProtocol(proto).
						MatchCTMark(ServiceCTMark).
						MatchRegMark(FromGatewayRegMark).
						Action().GotoTable(ServiceConntrackCommitTable.GetID()).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						Done(),
					// This flow is used to maintain SNAT conntrack for Service traffic.
					ServiceConntrackTable.BuildFlow(priorityNormal).MatchProtocol(proto).
						Action().CT(false, ServiceConntrackTable.GetNext(), snatZone).NAT().CTDone().
						Cookie(c.cookieAllocator.Request(category).Raw()).
						Done(),
					// This flow is used to match the following cases:
					// - The first packet of NodePort/LoadBalancer whose Endpoint is not on local Pod CIDR or any remote
					//   Pod CIDRs. Note that, this flow will change the behavior of the packet that NodePort/LoadBalancer
					//   whose externalTrafficPolicy is Local and the Endpoint is on host network. According to the definition
					//   of externalTrafficPolicy Local, the source IP should be retained. If the Endpoint is on host network,
					//   there should be only one backend Pod of the Service on a Node (It is impossible to have more than
					//   one Pods which listen on the same port on host network), so it is not useful to expose the Pod as
					//   NodePort Service, as it makes no difference to access it directly.
					// - The first packet of ClusterIP and the Endpoint is not on local Pod CIDR or any remote Pod CIDRs.
					// As the packet is from Antrea gateway, and it will pass through Antrea gateway, a virtual IP is used
					// to perform SNAT for the packet, rather than Antrea gateway's IP.
					ServiceConntrackCommitTable.BuildFlow(priorityHigh).MatchProtocol(proto).
						MatchRegMark(ToGatewayRegMark).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						MatchCTStateNew(true).
						MatchCTStateTrk(true).
						Action().CT(true, ServiceConntrackCommitTable.GetNext(), snatZone).
						SNAT(&binding.IPRange{StartIP: serviceVirtualIP, EndIP: serviceVirtualIP}, nil).
						CTDone().
						Done(),
					// This flow is used to match the first packet of NodePort/LoadBalancer whose output port is not
					// Antrea gateway, and externalTrafficPolicy is Cluster. This packet requires SNAT. Antrea gateway
					// IP is used to perform SNAT for the packet.
					ServiceConntrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(proto).
						MatchRegMark(ServiceNeedSNATRegMark).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						MatchCTStateNew(true).
						MatchCTStateTrk(true).
						Action().CT(true, ServiceConntrackCommitTable.GetNext(), snatZone).
						SNAT(&binding.IPRange{StartIP: gatewayIP, EndIP: gatewayIP}, nil).
						CTDone().
						Done(),
					// This flow is used to match the consequent request packets of Service traffic whose first request packet has been committed
					// and performed SNAT. For example:
					/*
							* 192.168.77.1 is the IP address of client.
							* 192.168.77.100 is the IP address of k8s node.
							* 30001 is a NodePort port.
							* 10.10.0.1 is the IP address of Antrea gateway.
							* 10.10.0.3 is the Endpoint of NodePort Service.

							* pkt 1 (request)
								* client                     192.168.77.1:12345->192.168.77.100:30001
								* ct zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
								* ct zone DNAT 65520         192.168.77.1:12345->192.168.77.100:30001
								* ct commit DNAT zone 65520  192.168.77.1:12345->192.168.77.100:30001  =>  192.168.77.1:12345->10.10.0.3:80
								* ct commit SNAT zone 65521  192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
								* output
							  * pkt 2 (response)
								* Pod                         10.10.0.3:80->10.10.0.1:12345
								* ct zone SNAT 65521          10.10.0.3:80->10.10.0.1:12345            =>  10.10.0.3:80->192.168.77.1:12345
								* ct zone DNAT 65520          10.10.0.3:80->192.168.77.1:12345         =>  192.168.77.1:30001->192.168.77.1:12345
								* output
							  * pkt 3 (request)
								* client                     192.168.77.1:12345->192.168.77.100:30001
								* ct zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
								* ct zone DNAT 65520         192.168.77.1:12345->10.10.0.3:80
								* ct zone SNAT 65521         192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
								* output
						      * pkt ...

							The source IP address of pkt 3 cannot be transformed through zone 65521 as there is no connection track about
							192.168.77.1:12345<->192.168.77.100:30001, and the source IP is still 192.168.77.100.
							Before output, pkt 3 needs SNAT, but the connection has been committed. The flow is for pkt 3 to perform SNAT.
					*/
					ServiceConntrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(proto).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						MatchCTStateNew(false).
						MatchCTStateTrk(true).
						Action().CT(false, ServiceConntrackCommitTable.GetNext(), snatZone).
						NAT().
						CTDone().
						Done(),
				)
			}
		}
	} else {
		flows = append(flows, c.kubeProxyFlows(category)...)
	}

	// TODO: following flows should move to function "kubeProxyFlows". Since another PR(#1198) is trying
	//  to polish the relevant logic, code refactoring is needed after that PR is merged.
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			// Connections initiated through the gateway are marked with FromGatewayCTMark.
			ConntrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				MatchRegMark(FromGatewayRegMark).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), ctZone).LoadToCtMark(FromGatewayCTMark).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			// Connections initiated through the bridge port are marked with FromBridgeCTMark.
			ConntrackCommitTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				MatchRegMark(FromBridgeRegMark).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), ctZone).LoadToCtMark(FromBridgeCTMark).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			// Add reject response packet bypass flow.
		)
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: ValidationStage
// Tables: SNATConntrackTable / ConntrackTable
// Refactored from:
//   - func (c *client) l3FwdFlowRouteToGW(gwMAC net.HardwareAddr, category cookie.Category) []binding.Flow`
// dnsResponseBypassConntrackFlow generates a flow which is used to bypass the dns response packetout from conntrack,
// to avoid unexpected packet drop. This flow should be on the first table of ConntrackState stage.
func (c *featureNetworkPolicy) dnsResponseBypassConntrackFlow(table binding.Table) binding.Flow {
	return table.BuildFlow(priorityHigh).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: AntreaPolicyIngressRuleTable
// Refactored from:
//   - func (c *client) dnsResponseBypassPacketInFlow() binding.Flow
// dnsResponseBypassPacketInFlow generates a flow which is used to bypass the dns packetIn conjunction flow for dns
// response packetOut. This packetOut should be sent directly to the requesting client without being intercepted again.
func (c *featureNetworkPolicy) dnsResponseBypassPacketInFlow() binding.Flow {
	// TODO: use a unified register bit to mark packetOuts. The pipeline does not need to be
	// aware of why the packetOut is being set by the controller, it just needs to be aware that
	// this is a packetOut message and that some pipeline stages (conntrack, policy enforcement)
	// should therefore be skipped.
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSBypass).
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Action().GotoStage(binding.OutputStage).
		Done()
}

func (c *client) conntrackBasicFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			ConntrackStateTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateInv(true).MatchCTStateTrk(true).
				Action().Drop().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
			ConntrackCommitTable.BuildFlow(priorityLow).MatchProtocol(proto).
				MatchCTStateNew(true).MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.GetNext(), ctZone).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

func (c *client) kubeProxyFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		flows = append(flows,
			ConntrackTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				Action().CT(false, ConntrackTable.GetNext(), ctZone).CTDone().
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

// Feature: Traceflow
// Stage: ConntrackStateStage
// Tables: ConntrackStateTable
// Stage: IngressSecurityStage
// Tables: AntreaPolicyIngressRuleTable, IngressRuleTable
// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected
// difference.
// traceflowConnectionTrackFlows generates Traceflow specific flows in the
// connectionTrackStateTable or L2ForwardingCalcTable.  When packet is not
// provided, the flows bypass the drop flow in conntrackStateFlow to avoid
// unexpected drop of the injected Traceflow packet, and to drop any Traceflow
// packet that has ct_state +rpl, which may happen when the Traceflow request
// destination is the Node's IP.
// When packet is provided, a flow is added to mark - the first packet of the
// first connection that matches the provided packet - as the Traceflow packet.
// The flow is added in connectionTrackStateTable when receiverOnly is false and
// it also matches in_port to be the provided ofPort (the sender Pod); otherwise
// when receiverOnly is true, the flow is added into L2ForwardingCalcTable and
// matches the destination MAC (the receiver Pod MAC).
func (c *featureTraceflow) traceflowConnectionTrackFlows(category cookie.Category, dataplaneTag uint8, receiverOnly bool, packet *binding.Packet, ofPort uint32, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	if packet == nil {
		for _, ipProtocol := range c.ipProtocols {
			flowBuilder := ConntrackStateTable.ofTable.BuildFlow(priorityLow + 1).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)

			if c.enableProxy {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID())
			} else {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(ConntrackStateTable.ofTable.GetNext())
			}
			flows = append(flows, flowBuilder.Done())

			flows = append(flows, ConntrackStateTable.ofTable.BuildFlow(priorityLow+2).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchIPDSCP(dataplaneTag).
				MatchCTStateTrk(true).MatchCTStateRpl(true).
				SetHardTimeout(timeout).
				Action().Drop().
				Done())
		}
	} else {
		var flowBuilder binding.FlowBuilder
		if !receiverOnly {
			flowBuilder = ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchInPort(ofPort).
				Action().LoadIPDSCP(dataplaneTag)
			if packet.DestinationIP != nil {
				flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
			}
			if c.enableProxy {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID())
			} else {
				flowBuilder = flowBuilder.
					Action().ResubmitToTables(ConntrackStateTable.ofTable.GetNext())
			}
		} else {
			var nextTable uint8
			if c.enableAntreaPolicy {
				nextTable = AntreaPolicyIngressRuleTable.GetID()
			} else {
				nextTable = IngressRuleTable.GetID()
			}
			flowBuilder = L2ForwardingCalcTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchDstMAC(packet.DestinationMAC).
				Action().LoadToRegField(TargetOFPortField, ofPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().LoadIPDSCP(dataplaneTag).
				Action().GotoTable(nextTable)
			if packet.SourceIP != nil {
				flowBuilder = flowBuilder.MatchSrcIP(packet.SourceIP)
			}
		}

		flowBuilder = flowBuilder.MatchCTStateNew(true).MatchCTStateTrk(true).
			SetHardTimeout(timeout)

		// Match transport header
		switch packet.IPProto {
		case protocol.Type_ICMP:
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMP)
		case protocol.Type_IPv6ICMP:
			flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolICMPv6)
		case protocol.Type_TCP:
			if packet.IsIPv6 {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCPv6)
			} else {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolTCP)
			}
		case protocol.Type_UDP:
			if packet.IsIPv6 {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDPv6)
			} else {
				flowBuilder = flowBuilder.MatchProtocol(binding.ProtocolUDP)
			}
		default:
			flowBuilder = flowBuilder.MatchIPProtocolValue(packet.IsIPv6, packet.IPProto)
		}
		if packet.IPProto == protocol.Type_TCP || packet.IPProto == protocol.Type_UDP {
			if packet.DestinationPort != 0 {
				flowBuilder = flowBuilder.MatchDstPort(packet.DestinationPort, nil)
			}
			if packet.SourcePort != 0 {
				flowBuilder = flowBuilder.MatchSrcPort(packet.SourcePort, nil)
			}
		}
		flows = []binding.Flow{flowBuilder.Done()}
	}
	return flows
}

// Feature: Traceflow
// Refactored from:
//   - func (c *client) traceflowNetworkPolicyFlows(dataplaneTag uint8, timeout uint16, category cookie.Category) []binding.Flow
func (c *featureTraceflow) traceflowNetworkPolicyFlows(category cookie.Category, featureNetworkPolicy *featureNetworkPolicy, dataplaneTag uint8, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	featureNetworkPolicy.conjMatchFlowLock.Lock()
	defer featureNetworkPolicy.conjMatchFlowLock.Unlock()
	// Copy default drop rules.
	for _, ctx := range featureNetworkPolicy.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			copyFlowBuilder := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
			if ctx.dropFlow.FlowProtocol() == "" {
				copyFlowBuilderIPv6 := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
				copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
				if c.ovsMetersAreSupported {
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					SetHardTimeout(timeout).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
				copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
			}
			if c.ovsMetersAreSupported {
				copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
			}
			flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				SetHardTimeout(timeout).
				Action().SendToController(uint8(PacketInReasonTF)).
				Done())
		}
	}
	// Copy Antrea NetworkPolicy drop rules.
	for _, conj := range featureNetworkPolicy.policyCache.List() {
		for _, flow := range conj.(*policyRuleConjunction).metricFlows {
			if flow.IsDropFlow() {
				copyFlowBuilder := flow.CopyToBuilder(priorityNormal+2, false)
				// Generate both IPv4 and IPv6 flows if the original drop flow doesn't match IP/IPv6.
				// DSCP field is in IP/IPv6 headers so IP/IPv6 match is required in a flow.
				if flow.FlowProtocol() == "" {
					copyFlowBuilderIPv6 := flow.CopyToBuilder(priorityNormal+2, false)
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
					if c.ovsMetersAreSupported {
						copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
					}
					flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
						SetHardTimeout(timeout).
						Cookie(c.cookieAllocator.Request(category).Raw()).
						Action().SendToController(uint8(PacketInReasonTF)).
						Done())
					copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
				}
				if c.ovsMetersAreSupported {
					copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(c.cookieAllocator.Request(category).Raw()).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
			}
		}
	}
	return flows
}

// serviceLBBypassFlows makes packets that belong to a tracked connection bypass
// service LB tables and enter egressRuleTable directly.
func (c *client) serviceLBBypassFlows(ipProtocol binding.Protocol) []binding.Flow {
	flows := []binding.Flow{
		// Tracked connections with the ServiceCTMark (load-balanced by AntreaProxy) receive
		// the macRewriteMark and are sent to egressRuleTable.
		ConntrackStateTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchCTMark(ServiceCTMark).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().LoadRegMark(RewriteMACRegMark).
			Action().GotoTable(EgressRuleTable.GetID()).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			Done(),
		// Tracked connections without the ServiceCTMark are sent to egressRuleTable
		// directly. This is meant to match connections which were load-balanced by
		// kube-proxy before AntreaProxy got enabled.
		ConntrackStateTable.BuildFlow(priorityLow).MatchProtocol(ipProtocol).
			MatchCTStateNew(false).MatchCTStateTrk(true).
			Action().GotoTable(EgressRuleTable.GetID()).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			Done(),
	}
	return flows
}

// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, skipIngressRules bool, category cookie.Category) binding.Flow {
	nextTable := L2ForwardingCalcTable.GetNext()
	if !skipIngressRules {
		// Go to ingress NetworkPolicy tables for traffic to local Pods.
		nextTable = c.ingressEntryTable
	}
	return L2ForwardingCalcTable.BuildFlow(priorityNormal).
		MatchDstMAC(dstMAC).
		Action().LoadToRegField(TargetOFPortField, ofPort).
		Action().LoadRegMark(OFPortFoundRegMark).
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
	// Broadcast, multicast, and unknown unicast packets will be dropped by
	// the default flow of L2ForwardingOutTable.
}

// Feature: Traceflow
// Stage: OutputStage
// Tables: L2ForwardingOutTable
// Refactored from:
//   - func (c *client) traceflowL2ForwardOutputFlows(dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16, category cookie.Category) []binding.Flow
// traceflowL2ForwardOutputFlows generates Traceflow specific flows that outputs traceflow packets
// to OVS port and Antrea Agent after L2forwarding calculation.
func (c *featureTraceflow) traceflowL2ForwardOutputFlows(category cookie.Category, dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		if c.supportEncap {
			// SendToController and Output if output port is tunnel port.
			fb1 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				MatchRegFieldWithValue(TargetOFPortField, config.DefaultTunOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Action().OutputToRegField(TargetOFPortField).
				Cookie(c.cookieAllocator.Request(category).Raw())
			// For injected packets, only SendToController if output port is local
			// gateway. In encapMode, a Traceflow packet going out of the gateway
			// port (i.e. exiting the overlay) essentially means that the Traceflow
			// request is complete.
			fb2 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Cookie(c.cookieAllocator.Request(category).Raw())

			// Do not send to controller if captures only dropped packet.
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb1 = fb1.Action().Meter(PacketInMeterIDTF)
					fb2 = fb2.Action().Meter(PacketInMeterIDTF)
				}
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
				fb2 = fb2.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				// Clear the loaded DSCP bits before output.
				fb2 = fb2.Action().LoadIPDSCP(0).
					Action().OutputToRegField(TargetOFPortField)
			}
			flows = append(flows, fb1.Done(), fb2.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in
			// encapMode, inter-Node Pod-to-Pod traffic is expected to go out of the
			// gateway port on the way to its destination.
			fb1 := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Action().OutputToRegField(TargetOFPortField).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb1 = fb1.Action().Meter(PacketInMeterIDTF)
				}
				fb1 = fb1.Action().SendToController(uint8(PacketInReasonTF))
			}
			flows = append(flows, fb1.Done())
		}
		// Only SendToController if output port is local gateway and destination IP is gateway.
		gatewayIP := c.gatewayIPs[ipProtocol]
		if gatewayIP != nil {
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchDstIP(gatewayIP).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				Cookie(c.cookieAllocator.Request(category).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fb = fb.Action().Meter(PacketInMeterIDTF)
				}
				fb = fb.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				fb = fb.Action().LoadIPDSCP(0).
					Action().OutputToRegField(TargetOFPortField)
			}
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is Pod port.
		fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal + 2).
			MatchIPDSCP(dataplaneTag).
			SetHardTimeout(timeout).
			MatchProtocol(ipProtocol).
			MatchRegMark(OFPortFoundRegMark).
			Cookie(c.cookieAllocator.Request(category).Raw())
		if !droppedOnly {
			if c.ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		if liveTraffic {
			fb = fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		flows = append(flows, fb.Done())
		if c.enableProxy {
			// Only SendToController for hairpin traffic.
			// This flow must have higher priority than the one installed by l2ForwardOutputServiceHairpinFlow
			fbHairpin := L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh + 2).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				MatchProtocol(ipProtocol).
				MatchRegMark(HairpinRegMark).
				Cookie(c.cookieAllocator.Request(cookie.Service).Raw())
			if !droppedOnly {
				if c.ovsMetersAreSupported {
					fbHairpin = fbHairpin.Action().Meter(PacketInMeterIDTF)
				}
				fbHairpin = fbHairpin.Action().SendToController(uint8(PacketInReasonTF))
			}
			if liveTraffic {
				fbHairpin = fbHairpin.Action().LoadIPDSCP(0).
					Action().OutputInPort()
			}
			flows = append(flows, fbHairpin.Done())
		}
	}
	return flows
}

// l2ForwardOutputServiceHairpinFlow uses in_port action for Service
// hairpin packets to avoid packets from being dropped by OVS.
func (c *client) l2ForwardOutputServiceHairpinFlow() binding.Flow {
	return L2ForwardingOutTable.BuildFlow(priorityHigh).
		MatchRegMark(HairpinRegMark).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// l2ForwardOutputFlows generates the flows that output packets to OVS port after L2 forwarding calculation.
func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	flows = append(flows,
		L2ForwardingOutTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIP).
			MatchRegMark(OFPortFoundRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		L2ForwardingOutTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchRegMark(OFPortFoundRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	)
	return flows
}

// l3FwdFlowToPod generates the L3 forward flows for traffic from tunnel to a
// local Pod. It rewrites the destination MAC (should be GlobalVirtualMAC) to
// the Pod interface MAC, and rewrites the source MAC to the gateway interface
// MAC.
func (c *client) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flowBuilder := L3ForwardingTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol)
		if !c.connectUplinkToBridge {
			// dstMAC will be overwritten always for AntreaFlexibleIPAM
			flowBuilder = flowBuilder.MatchRegMark(RewriteMACRegMark)
		}
		flow := flowBuilder.MatchDstIP(ip).
			Action().SetSrcMAC(localGatewayMAC).
			// Rewrite src MAC to local gateway MAC, and rewrite dst MAC to pod MAC
			Action().SetDstMAC(podInterfaceMAC).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done()
		flows = append(flows, flow)
	}
	return flows
}

// l3FwdFlowRouteToPod generates the flows to route the traffic to a Pod based on
// the destination IP. It rewrites the destination MAC of the packets to the Pod
// interface MAC. The flow is used in the networkPolicyOnly mode for the traffic
// from the gateway to a local Pod.
func (c *client) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, L3ForwardingTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) l3FwdFlowRouteToGW(gwMAC net.HardwareAddr, category cookie.Category) []binding.Flow
// l3FwdFlowRouteToGW generates the flows to route the traffic to the gateway interface. It rewrites the destination MAC
// of the packets to the gateway interface MAC. The flow is used in the networkPolicyOnly mode for the traffic from a
// local Pod to remote Pods, Nodes, or external network.
func (c *featureNetworkPolicy) l3FwdFlowRouteToGW(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProto := range c.ipProtocols {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProto).
			Action().LoadRegMark(ToExternalRegMark).
			Action().SetDstMAC(c.gatewayMAC).
			Action().NextTable().
			Done(),
		)
	}
	return flows
}

// l3FwdFlowToGateway generates the L3 forward flows to rewrite the destination MAC of the packets to the gateway interface
// MAC if the destination IP is the gateway IP or the connection was initiated through the gateway interface.
func (c *client) l3FwdFlowToGateway(localGatewayIPs []net.IP, localGatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range localGatewayIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, L3ForwardingTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
			MatchRegMark(RewriteMACRegMark).
			MatchDstIP(ip).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(L3ForwardingTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	// Rewrite the destination MAC address with the local host gateway MAC if the packet is in the reply direction and
	// is marked with FromGatewayCTMark. This is for connections which were initiated through the gateway, to ensure that
	// this reply traffic gets forwarded correctly (back to the host network namespace, through the gateway). In
	// particular, it is necessary in the following 2 cases:
	//  1) reply traffic for connections from a local Pod to a ClusterIP Service (when AntreaProxy is disabled and
	//  kube-proxy is used). In this case the destination IP address of the reply traffic is the Pod which initiated the
	//  connection to the Service (no SNAT). We need to make sure that these packets are sent back through the gateway
	//  so that the source IP can be rewritten (Service backend IP -> Service ClusterIP).
	//  2) when hair-pinning is involved, i.e. connections between 2 local Pods, for which NAT is performed. This
	//  applies regardless of whether AntreaProxy is enabled or not, and thus also applies to Windows Nodes (for which
	//  AntreaProxy is enabled by default). One example is a Pod accessing a NodePort Service for which
	//  externalTrafficPolicy is set to Local, using the local Node's IP address.
	for _, proto := range c.ipProtocols {
		// The following two OpenFlow entries are a workaround for issue: https://github.com/antrea-io/antrea/issues/2981.
		// The issue is a Windows OVS bug, which identifies a reply packet as "new" in conntrack, and mark the connection
		// with "FromGatewayCTMark". The OVS datapath might drop the packet if the reply packet is actually form
		// antrea-gw0 because the input_port and output port number are the same. This workaround doesn't write the
		// dst MAC if the reply packet of a connection marked with "FromGatewayCTMark" but it enters OVS from antrea-gw0.
		flows = append(flows, L3ForwardingTable.BuildFlow(priorityHigh).MatchProtocol(proto).
			MatchRegMark(FromLocalRegMark).
			MatchCTMark(FromGatewayCTMark).
			MatchCTStateRpl(true).MatchCTStateTrk(true).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(L3ForwardingTable.GetNext()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		)

		if c.networkConfig.TrafficEncapMode.SupportsEncap() {
			flows = append(flows, L3ForwardingTable.BuildFlow(priorityHigh).MatchProtocol(proto).
				MatchRegMark(FromTunnelRegMark).
				MatchCTMark(FromGatewayCTMark).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(localGatewayMAC).
				Action().GotoTable(L3ForwardingTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}

		if c.connectUplinkToBridge {
			flows = append(flows, L3ForwardingTable.BuildFlow(priorityHigh).MatchProtocol(proto).
				MatchCTMark(FromBridgeCTMark).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(c.nodeConfig.UplinkNetConfig.MAC).
				Action().GotoTable(L3ForwardingTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}
	}
	return flows
}

// l3FwdFlowToRemote generates the L3 forward flow for traffic to a remote Node
// (Pods or gateway) through the tunnel.
func (c *client) l3FwdFlowToRemote(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	tunnelPeer net.IP,
	category cookie.Category) binding.Flow {
	ipProto := getIPProtocol(peerSubnet.IP)
	return L3ForwardingTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
		MatchDstIPNet(peerSubnet).
		// Rewrite src MAC to local gateway MAC and rewrite dst MAC to virtual MAC.
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(GlobalVirtualMAC).
		// Flow based tunnel. Set tunnel destination.
		Action().SetTunnelDst(tunnelPeer).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FwdFlowToRemoteViaGW generates the L3 forward flow to support traffic to
// remote via gateway. It is used when the cross-Node traffic does not require
// encapsulation (in noEncap, networkPolicyOnly, or hybrid mode).
func (c *client) l3FwdFlowToRemoteViaGW(
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	category cookie.Category,
	isAntreaFlexibleIPAM bool) binding.Flow {
	ipProto := getIPProtocol(peerSubnet.IP)
	priority := priorityNormal
	// AntreaFlexibleIPAM Pod -> Per-Node IPAM Pod traffic will be sent to remote Gw directly.
	if isAntreaFlexibleIPAM {
		priority = priorityHigh
	}
	flowBuilder := L3ForwardingTable.BuildFlow(priority).MatchProtocol(ipProto).
		MatchDstIPNet(peerSubnet)
	if isAntreaFlexibleIPAM {
		flowBuilder = flowBuilder.MatchRegMark(AntreaFlexibleIPAMRegMark)
	}
	return flowBuilder.Action().SetDstMAC(localGatewayMAC).
		Action().GotoTable(L3ForwardingTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// l3FwdServiceDefaultFlowsViaGW generates the default L3 forward flows to support Service traffic to pass through Antrea gateway.
func (c *client) l3FwdServiceDefaultFlowsViaGW(ipProto binding.Protocol, category cookie.Category) []binding.Flow {
	gatewayMAC := c.nodeConfig.GatewayConfig.MAC

	flows := []binding.Flow{
		// This flow is used to match the packets of Service traffic:
		//	- NodePort/LoadBalancer request packets which pass through Antrea gateway and the Service Endpoint is not on
		//    local Pod CIDR or any remote Pod CIDRs.
		//	- ClusterIP request packets which are from Antrea gateway and the Service Endpoint is not on local Pod CIDR
		// 	or any remote Pod CIDRs.
		//  - NodePort/LoadBalancer/ClusterIP response packets.
		// The matched packets should leave through Antrea gateway, however, they also enter through Antrea gateway. This
		// is hairpin traffic.
		// Skip traffic from AntreaFlexibleIPAM Pods.
		L3ForwardingTable.BuildFlow(priorityLow).MatchProtocol(ipProto).
			MatchCTMark(ServiceCTMark).
			MatchCTStateTrk(true).
			MatchRegMark(RewriteMACRegMark).
			MatchRegMark(NotAntreaFlexibleIPAMRegMark).
			Action().SetDstMAC(gatewayMAC).
			Action().GotoTable(L3DecTTLTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	return flows
}

// arpResponderFlow generates the ARP responder flow entry that replies request comes from local gateway for peer
// gateway MAC.
func (c *client) arpResponderFlow(peerGatewayIP net.IP, category cookie.Category) binding.Flow {
	return arpResponderTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		MatchARPTpa(peerGatewayIP).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(GlobalVirtualMAC).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(GlobalVirtualMAC).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().SetARPSpa(peerGatewayIP).
		Action().OutputInPort().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// Feature: NetworkPolicy
// Stage: ClassifierStage
// Tables: ARPResponderTable
// Requirements: networkPolicyOnly mode.
// Refactored from:
//   - func (c *client) arpResponderStaticFlow(category cookie.Category) binding.Flow
// arpResponderStaticFlow generates ARP reply for any ARP request with the same global virtual MAC. This flow is used
// in policy-only mode, where traffic are routed via IP not MAC.
func (c *featureNetworkPolicy) arpResponderStaticFlow(category cookie.Category) binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(GlobalVirtualMAC).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(GlobalVirtualMAC).
		Action().Move(binding.NxmFieldARPTpa, SwapField.GetNXFieldName()).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().Move(SwapField.GetNXFieldName(), binding.NxmFieldARPSpa).
		Action().OutputInPort().
		Done()
}

// podIPSpoofGuardFlow generates the flow to check IP traffic sent out from local pod. Traffic from host gateway interface
// will not be checked, since it might be pod to service traffic or host namespace traffic.
func (c *client) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ifIP := range ifIPs {
		ipProtocol := getIPProtocol(ifIP)
		if ipProtocol == binding.ProtocolIP {
			flows = append(flows, SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
				MatchInPort(ifOFPort).
				MatchSrcMAC(ifMAC).
				MatchSrcIP(ifIP).
				Action().GotoTable(SpoofGuardTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		} else if ipProtocol == binding.ProtocolIPv6 {
			flows = append(flows, SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
				MatchInPort(ifOFPort).
				MatchSrcMAC(ifMAC).
				MatchSrcIP(ifIP).
				Action().GotoTable(IPv6Table.GetID()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done())
		}
	}
	return flows
}

func getIPProtocol(ip net.IP) binding.Protocol {
	var ipProtocol binding.Protocol
	if ip.To4() != nil {
		ipProtocol = binding.ProtocolIP
	} else {
		ipProtocol = binding.ProtocolIPv6
	}
	return ipProtocol
}

// serviceHairpinResponseDNATFlow generates the flow which transforms destination
// IP of the hairpin packet to the source IP.
func (c *client) serviceHairpinResponseDNATFlow(ipProtocol binding.Protocol) binding.Flow {
	hpIP := hairpinIP
	from := binding.NxmFieldSrcIPv4
	to := binding.NxmFieldDstIPv4
	if ipProtocol == binding.ProtocolIPv6 {
		hpIP = hairpinIPv6
		from = binding.NxmFieldSrcIPv6
		to = binding.NxmFieldDstIPv6
	}
	return ServiceHairpinTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
		MatchDstIP(hpIP).
		Action().Move(from, to).
		Action().LoadRegMark(HairpinRegMark).
		Action().GotoTable(ServiceHairpinTable.GetNext()).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// serviceHairpinRegSetFlows generates the flow to set the hairpin mark for the packet which is from Antrea gateway and
// its output interface is also Antrea gateway. In table L2ForwardingOutTable #110, a packet with hairpin mark will be
// sent out with action IN_PORT, otherwise the packet with action output will be dropped.
func (c *client) serviceHairpinRegSetFlows(ipProtocol binding.Protocol) binding.Flow {
	return HairpinSNATTable.BuildFlow(priorityNormal).MatchProtocol(ipProtocol).
		MatchRegMark(FromGatewayRegMark).
		MatchRegMark(ToGatewayRegMark).
		Action().LoadRegMark(HairpinRegMark).
		Action().GotoTable(L2ForwardingOutTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// gatewayARPSpoofGuardFlow generates the flow to check ARP traffic sent out from the local gateway interface.
func (c *client) gatewayARPSpoofGuardFlows(gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow) {
	flows = append(flows, SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(config.HostGatewayOFPort).
		MatchARPSha(gatewayMAC).
		MatchARPSpa(gatewayIP).
		Action().GotoTable(arpResponderTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done())
	if c.connectUplinkToBridge {
		// When the uplink bridged and NodePort/HostPort is accessed, Node will send ARP request to HostGatewayOFPort
		// with arp_spa=NodeIP. This flow is to accept these ARP requests.
		flows = append(flows, SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			MatchInPort(config.HostGatewayOFPort).
			MatchARPSha(gatewayMAC).
			MatchARPSpa(c.nodeConfig.NodeIPv4Addr.IP).
			Action().GotoTable(arpResponderTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return
}

// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces.
func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow {
	return SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().GotoTable(arpResponderTable.GetID()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// sessionAffinityReselectFlow generates the flow which resubmits the service accessing
// packet back to ServiceLBTable if there is no endpointDNAT flow matched. This
// case will occur if an Endpoint is removed and is the learned Endpoint
// selection of the Service.
func (c *client) sessionAffinityReselectFlow() binding.Flow {
	return EndpointDNATTable.BuildFlow(priorityLow).
		MatchRegMark(EpSelectedRegMark).
		Action().LoadRegMark(EpToSelectRegMark).
		Action().ResubmitToTable(ServiceLBTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// gatewayIPSpoofGuardFlow generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *client) gatewayIPSpoofGuardFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		nextTable := SpoofGuardTable.GetNext()
		if proto == binding.ProtocolIPv6 {
			nextTable = IPv6Table.GetID()
		}
		flows = append(flows,
			SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(proto).
				MatchInPort(config.HostGatewayOFPort).
				Action().GotoTable(nextTable).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		)
	}
	return flows
}

// serviceCIDRDNATFlow generates flows to match dst IP in service CIDR and output to host gateway interface directly.
func (c *client) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet) []binding.Flow {
	var flows []binding.Flow
	for _, serviceCIDR := range serviceCIDRs {
		if serviceCIDR != nil {
			ipProto := getIPProtocol(serviceCIDR.IP)
			flows = append(flows, DNATTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIPNet(*serviceCIDR).
				Action().LoadToRegField(TargetOFPortField, config.HostGatewayOFPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().GotoTable(ConntrackCommitTable.GetID()).
				Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
				Done())
		}
	}
	return flows
}

// serviceNeedLBFlow generates flows to mark packets as LB needed.
func (c *client) serviceNeedLBFlow() binding.Flow {
	return SessionAffinityTable.BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Action().LoadRegMark(EpToSelectRegMark).
		Done()
}

// arpResponderLocalFlows generates the ARP responder flow entry that replies request from local Pods for local
// gateway MAC.
// Only used in AntreaFlexibleIPAM to avoid multiple ARP replies from antrea-gw0 and uplink.
// TODO(gran): use better method to process ARP and support IPv6.
func (c *client) arpResponderLocalFlows(category cookie.Category) (flows []binding.Flow) {
	if c.connectUplinkToBridge && c.nodeConfig.GatewayConfig.IPv4 != nil {
		flows = append(flows, arpResponderTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolARP).
			MatchARPOp(1).
			MatchARPTpa(c.nodeConfig.GatewayConfig.IPv4).
			Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
			Action().SetSrcMAC(c.nodeConfig.GatewayConfig.MAC).
			Action().LoadARPOperation(2).
			Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
			Action().SetARPSha(c.nodeConfig.GatewayConfig.MAC).
			Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
			Action().SetARPSpa(c.nodeConfig.GatewayConfig.IPv4).
			Action().OutputInPort().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return
}

// arpNormalFlow generates the flow to response arp in normal way if no flow in arpResponderTable is matched.
func (c *client) arpNormalFlow(category cookie.Category) binding.Flow {
	return arpResponderTable.BuildFlow(priorityLow).MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage / EgressSecurityStage
// Tables: IngressMetricTable / EgressMetricTable.
// Refactored from:
//   - func (c *client) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow
func (c *featureNetworkPolicy) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow {
	metricTable := IngressMetricTable
	offset := 0
	// We use the 0..31 bits of the ct_label to store the ingress rule ID and use the 32..63 bits to store the
	// egress rule ID.
	field := IngressRuleCTLabel
	if !ingress {
		metricTable = EgressMetricTable
		offset = 32
		field = EgressRuleCTLabel
	}
	metricFlow := func(isCTNew bool, protocol binding.Protocol) binding.Flow {
		return metricTable.ofTable.BuildFlow(priorityNormal).
			MatchProtocol(protocol).
			Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
			MatchCTStateNew(isCTNew).
			MatchCTLabelField(0, uint64(conjunctionID)<<offset, field).
			Action().NextTable().
			Done()
	}
	var flows []binding.Flow
	// These two flows track the number of sessions in addition to the packet and byte counts.
	// The flow matching 'ct_state=+new' tracks the number of sessions and byte count of the first packet for each
	// session.
	// The flow matching 'ct_state=-new' tracks the byte/packet count of an established connection (both directions).
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows, metricFlow(true, ipProtocol), metricFlow(false, ipProtocol))
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage / EgressSecurityStage
// Tables: IngressMetricTable / EgressMetricTable.
// Refactored from:
//   - func (c *client) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow
func (c *featureNetworkPolicy) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow {
	metricTable := IngressMetricTable
	if !ingress {
		metricTable = EgressMetricTable
	}
	return metricTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		MatchRegMark(CnpDenyRegMark).
		MatchRegFieldWithValue(CNPDenyConjIDField, conjunctionID).
		Action().Drop().
		Done()
}

// ipv6Flows generates the flows to allow IPv6 packets from link-local addresses and
// handle multicast packets, Neighbor Solicitation and ND Advertisement packets properly.
func (c *client) ipv6Flows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow

	_, ipv6LinkLocalIpnet, _ := net.ParseCIDR(ipv6LinkLocalAddr)
	_, ipv6MulticastIpnet, _ := net.ParseCIDR(ipv6MulticastAddr)
	flows = append(flows,
		// Allow IPv6 packets (e.g. Multicast Listener Report Message V2) which are sent from link-local addresses in SpoofGuardTable,
		// so that these packets will not be dropped.
		SpoofGuardTable.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchSrcIPNet(*ipv6LinkLocalIpnet).
			Action().GotoTable(IPv6Table.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle IPv6 Neighbor Solicitation and Neighbor Advertisement as a regular L2 learning Switch by using normal.
		IPv6Table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(135).
			MatchICMPv6Code(0).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		IPv6Table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(136).
			MatchICMPv6Code(0).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// Handle IPv6 multicast packets as a regular L2 learning Switch by using normal.
		// It is used to ensure that all kinds of IPv6 multicast packets are properly handled (e.g. Multicast Listener Report Message V2).
		IPv6Table.BuildFlow(priorityNormal).MatchProtocol(binding.ProtocolIPv6).
			MatchDstIPNet(*ipv6MulticastIpnet).
			Action().Normal().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	)
	return flows
}

// conjunctionActionFlow generates the flow to jump to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is created at priorityLow for k8s network policies, and *priority assigned by PriorityAssigner for AntreaPolicy.
func (c *featureNetworkPolicy) conjunctionActionFlow(conjunctionID uint32, table binding.Table, nextTable uint8, priority *uint16, enableLogging bool) []binding.Flow {
	var ofPriority uint16
	if priority == nil {
		ofPriority = priorityLow
	} else {
		ofPriority = *priority
	}
	conjReg := TFIngressConjIDField
	labelField := IngressRuleCTLabel
	tableID := table.GetID()
	if _, ok := egressTables[tableID]; ok {
		conjReg = TFEgressConjIDField
		labelField = EgressRuleCTLabel
	}
	conjActionFlow := func(proto binding.Protocol) binding.Flow {
		ctZone := CtZone
		if proto == binding.ProtocolIPv6 {
			ctZone = CtZoneV6
		}
		if enableLogging {
			fb := table.BuildFlow(ofPriority).MatchProtocol(proto).
				MatchConjID(conjunctionID)
			if c.ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDNP)
			}
			return fb.
				Action().LoadToRegField(conjReg, conjunctionID).  // Traceflow.
				Action().LoadRegMark(DispositionAllowRegMark).    // AntreaPolicy.
				Action().LoadRegMark(CustomReasonLoggingRegMark). // Enable logging.
				Action().SendToController(uint8(PacketInReasonNP)).
				Action().CT(true, nextTable, ctZone). // CT action requires commit flag if actions other than NAT without arguments are specified.
				LoadToLabelField(uint64(conjunctionID), labelField).
				CTDone().
				Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
				Done()
		}
		return table.BuildFlow(ofPriority).MatchProtocol(proto).
			MatchConjID(conjunctionID).
			Action().LoadToRegField(conjReg, conjunctionID). // Traceflow.
			Action().CT(true, nextTable, ctZone).            // CT action requires commit flag if actions other than NAT without arguments are specified.
			LoadToLabelField(uint64(conjunctionID), labelField).
			CTDone().
			Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
			Done()
	}
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		flows = append(flows, conjActionFlow(proto))
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage / EgressSecurityStage
// Tables: IngressMetricTable / EgressMetricTable.
// Refactored from:
//   - 'func (c *client) conjunctionActionDenyFlow(conjunctionID uint32, table binding.Table, priority *uint16,
//     disposition uint32, enableLogging bool) binding.`
// conjunctionActionDenyFlow generates the flow to mark the packet to be denied (dropped or rejected) if policyRuleConjunction
// ID is matched. Any matched flow will be dropped in corresponding metric tables.
func (c *featureNetworkPolicy) conjunctionActionDenyFlow(conjunctionID uint32, table binding.Table, priority *uint16, disposition uint32, enableLogging bool) binding.Flow {
	ofPriority := *priority
	metricTable := IngressMetricTable
	tableID := table.GetID()
	if _, ok := egressTables[tableID]; ok {
		metricTable = EgressMetricTable
	}

	flowBuilder := table.BuildFlow(ofPriority).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CNPDenyConjIDField, conjunctionID).
		Action().LoadRegMark(CnpDenyRegMark)

	var customReason int
	if c.enableDenyTracking {
		customReason += CustomReasonDeny
		flowBuilder = flowBuilder.
			Action().LoadToRegField(APDispositionField, disposition)
	}
	if enableLogging {
		customReason += CustomReasonLogging
		flowBuilder = flowBuilder.
			Action().LoadToRegField(APDispositionField, disposition)
	}
	if disposition == DispositionRej {
		customReason += CustomReasonReject
	}

	if enableLogging || c.enableDenyTracking || disposition == DispositionRej {
		if c.ovsMetersAreSupported {
			flowBuilder = flowBuilder.Action().Meter(PacketInMeterIDNP)
		}
		flowBuilder = flowBuilder.
			Action().LoadToRegField(CustomReasonField, uint32(customReason)).
			Action().SendToController(uint8(PacketInReasonNP))
	}

	// We do not drop the packet immediately but send the packet to the metric table to update the rule metrics.
	return flowBuilder.Action().ResubmitToTables(metricTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

func (c *featureNetworkPolicy) conjunctionActionPassFlow(conjunctionID uint32, table binding.Table, priority *uint16, enableLogging bool) binding.Flow {
	ofPriority := *priority
	conjReg := TFIngressConjIDField
	nextTable := IngressRuleTable
	tableID := table.GetID()
	if _, ok := egressTables[tableID]; ok {
		conjReg = TFEgressConjIDField
		nextTable = EgressRuleTable
	}
	flowBuilder := table.BuildFlow(ofPriority).MatchConjID(conjunctionID).
		Action().LoadToRegField(conjReg, conjunctionID)
	if enableLogging {
		flowBuilder = flowBuilder.
			Action().LoadRegMark(DispositionPassRegMark).
			Action().LoadRegMark(CustomReasonLoggingRegMark).
			Action().SendToController(uint8(PacketInReasonNP))
	}
	return flowBuilder.Action().GotoTable(nextTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

func (c *client) Disconnect() error {
	return c.bridge.Disconnect()
}

func newFlowCategoryCache() *flowCategoryCache {
	return &flowCategoryCache{}
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: IngressDefaultTable, AntreaPolicyIngressRuleTable
// Stage: EgressSecurityStage
// Tables: EgressDefaultTable, AntreaPolicyEgressRuleTable
// Refactored from:
//   - func (c *client) establishedConnectionFlows(category cookie.Category) (flows []binding.Flow)
// establishedConnectionFlows generates flows to ensure established connections skip the NetworkPolicy rules.
func (c *featureNetworkPolicy) establishedConnectionFlows(category cookie.Category) []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	var allEstFlows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		egressEstFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
			Done()
		ingressEstFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
			Done()
		allEstFlows = append(allEstFlows, egressEstFlow, ingressEstFlow)
	}
	if !c.enableAntreaPolicy {
		return allEstFlows
	}
	var apFlows []binding.Flow
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range c.ipProtocols {
			apEgressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateEst(true).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			apFlows = append(apFlows, apEgressEstFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range c.ipProtocols {
			apIngressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateEst(true).
				Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
				Done()
			apFlows = append(apFlows, apIngressEstFlow)
		}
	}
	allEstFlows = append(allEstFlows, apFlows...)
	return allEstFlows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: IngressDefaultTable, AntreaPolicyIngressRuleTable
// Stage: EgressSecurityStage
// Tables: EgressDefaultTable, AntreaPolicyEgressRuleTable
// Refactored from:
//   - func (c *client) relatedConnectionFlows(category cookie.Category) (flows []binding.Flow)
// relatedConnectionFlows generates flows to ensure related connections skip the NetworkPolicy rules.
func (c *featureNetworkPolicy) relatedConnectionFlows(category cookie.Category) []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		egressRelFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().ResubmitToTables(egressDropTable.GetNext()).
			Done()
		ingressRelFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().ResubmitToTables(ingressDropTable.GetNext()).
			Done()
		flows = append(flows, egressRelFlow, ingressRelFlow)
	}
	if !c.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProto := range c.ipProtocols {
			apEgressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProto).
				MatchCTStateNew(false).
				MatchCTStateRel(true).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apEgressRelFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProto := range c.ipProtocols {
			apIngressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProto).
				MatchCTStateNew(false).
				MatchCTStateRel(true).
				Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apIngressRelFlow)
		}
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: IngressDefaultTable, AntreaPolicyIngressRuleTable
// Stage: EgressSecurityStage
// Tables: EgressDefaultTable, AntreaPolicyEgressRuleTable
// Refactored from:
//   - func (c *client) rejectBypassNetworkpolicyFlows(category cookie.Category) (flows []binding.Flow)
// rejectBypassNetworkpolicyFlows generates flows to ensure reject responses generated by the controller skip the
// NetworkPolicy rules.
func (c *featureNetworkPolicy) rejectBypassNetworkpolicyFlows(category cookie.Category) []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		egressRejFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().ResubmitToTables(egressDropTable.GetNext()).
			Done()
		ingressRejFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().ResubmitToTables(ingressDropTable.GetID()).
			Done()
		flows = append(flows, egressRejFlow, ingressRejFlow)
	}
	if !c.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range c.ipProtocols {
			apEgressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apEgressRejFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range c.ipProtocols {
			apIngressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apIngressRejFlow)
		}
	}
	return flows
}

func (c *featureNetworkPolicy) addFlowMatch(fb binding.FlowBuilder, matchKey *types.MatchKey, matchValue interface{}) binding.FlowBuilder {
	switch matchKey {
	case MatchDstOFPort:
		// ofport number in NXM_NX_REG1 is used in ingress rule to match packets sent to local Pod.
		fb = fb.MatchRegFieldWithValue(TargetOFPortField, uint32(matchValue.(int32)))
	case MatchSrcOFPort:
		fb = fb.MatchInPort(uint32(matchValue.(int32)))
	case MatchDstIP:
		fallthrough
	case MatchDstIPv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchDstIP(matchValue.(net.IP))
	case MatchDstIPNet:
		fallthrough
	case MatchDstIPNetv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchDstIPNet(matchValue.(net.IPNet))
	case MatchSrcIP:
		fallthrough
	case MatchSrcIPv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIP(matchValue.(net.IP))
	case MatchSrcIPNet:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIPNet(matchValue.(net.IPNet))
	case MatchSrcIPNetv6:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol()).MatchSrcIPNet(matchValue.(net.IPNet))
	case MatchTCPDstPort:
		fallthrough
	case MatchTCPv6DstPort:
		fallthrough
	case MatchUDPDstPort:
		fallthrough
	case MatchUDPv6DstPort:
		fallthrough
	case MatchSCTPDstPort:
		fallthrough
	case MatchSCTPv6DstPort:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		portValue := matchValue.(types.BitRange)
		if portValue.Value > 0 {
			fb = fb.MatchDstPort(portValue.Value, portValue.Mask)
		}
	case MatchTCPSrcPort:
		fallthrough
	case MatchTCPv6SrcPort:
		fallthrough
	case MatchUDPSrcPort:
		fallthrough
	case MatchUDPv6SrcPort:
		fb = fb.MatchProtocol(matchKey.GetOFProtocol())
		portValue := matchValue.(types.BitRange)
		if portValue.Value > 0 {
			fb = fb.MatchSrcPort(portValue.Value, portValue.Mask)
		}
	case MatchServiceGroupID:
		fb = fb.MatchRegFieldWithValue(ServiceGroupIDField, matchValue.(uint32))
	}
	return fb
}

// conjunctionExceptionFlow generates the flow to jump to a specific table if both policyRuleConjunction ID and except address are matched.
// Keeping this for reference to generic exception flow.
func (c *featureNetworkPolicy) conjunctionExceptionFlow(conjunctionID uint32, tableID uint8, nextTable uint8, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	conjReg := TFIngressConjIDField
	if tableID == EgressRuleTable.GetID() {
		conjReg = TFEgressConjIDField
	}
	fb := getTableByID(tableID).BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().LoadToRegField(conjReg, conjunctionID). // Traceflow.
		Action().GotoTable(nextTable).
		Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (c *featureNetworkPolicy) conjunctiveMatchFlow(tableID uint8, matchKey *types.MatchKey, matchValue interface{}, priority *uint16, actions []*conjunctiveAction) binding.Flow {
	var ofPriority uint16
	if priority != nil {
		ofPriority = *priority
	} else {
		ofPriority = priorityNormal
	}
	fb := getTableByID(tableID).BuildFlow(ofPriority)
	fb = c.addFlowMatch(fb, matchKey, matchValue)
	if c.deterministic {
		sort.Sort(conjunctiveActionsInOrder(actions))
	}
	for _, act := range actions {
		fb.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	return fb.Cookie(c.cookieAllocator.Request(cookie.Policy).Raw()).Done()
}

// defaultDropFlow generates the flow to drop packets if the match condition is matched.
func (c *featureNetworkPolicy) defaultDropFlow(table binding.Table, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	fb := table.BuildFlow(priorityNormal)
	if c.enableDenyTracking {
		return c.addFlowMatch(fb, matchKey, matchValue).
			Action().Drop().
			Action().LoadRegMark(DispositionDropRegMark).
			Action().LoadRegMark(CustomReasonDenyRegMark).
			Action().SendToController(uint8(PacketInReasonNP)).
			Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
			Done()
	}
	return c.addFlowMatch(fb, matchKey, matchValue).
		Action().Drop().
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: AntreaPolicyIngressRuleTable
// Refactored from:
//   - func (c *client) dnsPacketInFlow(conjunctionID uint32) binding.Flow
// dnsPacketInFlow generates the flow to send dns response packets of fqdn policy selected Pods to the fqdnController for
// processing.
func (c *featureNetworkPolicy) dnsPacketInFlow(conjunctionID uint32) binding.Flow {
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSIntercept).
		Cookie(c.cookieAllocator.Request(cookie.Default).Raw()).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CustomReasonField, CustomReasonDNS).
		Action().SendToController(uint8(PacketInReasonNP)).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: IngressRuleTable
// Refactored from:
//   - func (c *client) localProbeFlow(localGatewayIPs []net.IP, category cookie.Category) []binding.Flow
// localProbeFlow generates the flow to forward locally generated packets to ConntrackCommitTable, bypassing ingress
// rules of Network Policies. The packets are sent by kubelet to probe the liveness/readiness of local Pods.
// On Linux and when OVS kernel datapath is used, it identifies locally generated packets by matching the
// HostLocalSourceMark, otherwise it matches the source IP. The difference is because:
// 1. On Windows, kube-proxy userspace mode is used, and currently there is no way to distinguish kubelet generated
//    traffic from kube-proxy proxied traffic.
// 2. pkt_mark field is not properly supported for OVS userspace (netdev) datapath.
// Note that there is a defect in the latter way that NodePort Service access by external clients will be masqueraded as
// a local gateway IP to bypass Network Policies. See https://github.com/antrea-io/antrea/issues/280.
// TODO: Fix it after replacing kube-proxy with AntreaProxy.
func (c *featureNetworkPolicy) localProbeFlow(category cookie.Category, ovsDatapathType ovsconfig.OVSDatapathType) []binding.Flow {
	var flows []binding.Flow
	if runtime.IsWindowsPlatform() || ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		for ipProtocol, gatewayIP := range c.gatewayIPs {
			flows = append(flows, IngressRuleTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchSrcIP(gatewayIP).
				Action().GotoStage(binding.ConntrackStage).
				Done())
		}
	} else {
		flows = append(flows, IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchPktMark(types.HostLocalSourceMark, &types.HostLocalSourceMark).
			Action().GotoStage(binding.ConntrackStage).
			Done())
	}
	return flows
}

func (c *featureNetworkPolicy) ingressClassifierFlows(category cookie.Category) []binding.Flow {
	return []binding.Flow{
		IngressClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchRegMark(ToLocalRegMark).
			Action().NextTable().
			Done(),
		IngressClassifierTable.ofTable.BuildFlow(priorityMiss).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Action().GotoTable(IngressMetricTable.GetID()).
			Done(),
	}
}

// snatSkipNodeFlow installs a flow to skip SNAT for traffic to the transport IP of the a remote Node.
func (c *client) snatSkipNodeFlow(nodeIP net.IP, category cookie.Category) binding.Flow {
	ipProto := getIPProtocol(nodeIP)
	// This flow is for the traffic to the remote Node IP.
	return L3ForwardingTable.BuildFlow(priorityNormal).
		MatchProtocol(ipProto).
		MatchRegMark(FromLocalRegMark).
		MatchDstIP(nodeIP).
		Action().GotoTable(L3ForwardingTable.GetNext()).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Done()
}

// snatCommonFlows installs the default flows for performing SNAT for traffic to
// the external network. The flows identify the packets to external, and send
// them to SNATTable, where SNAT IPs are looked up for the packets.
func (c *client) snatCommonFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr, exceptCIDRs []net.IPNet, category cookie.Category) []binding.Flow {
	nextTable := L3ForwardingTable.GetNext()
	ipProto := getIPProtocol(localSubnet.IP)
	flows := []binding.Flow{
		// First install flows for traffic that should bypass SNAT.
		// This flow is for traffic to the local Pod subnet that don't need MAC rewriting (L2 forwarding case). Other
		// traffic to the local Pod subnet will be handled by L3 forwarding rules.
		L3ForwardingTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegFieldWithValue(RewriteMACRegMark.GetField(), 0).
			MatchDstIPNet(localSubnet).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// This flow is for the traffic to the local Node IP.
		L3ForwardingTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegMark(FromLocalRegMark).
			MatchDstIP(nodeIP).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// The return traffic of connections to a local Pod through the gateway interface (so FromGatewayCTMark is set)
		// should bypass SNAT too. But it has been covered by the gatewayCT related flow generated in l3FwdFlowToGateway
		// which forwards all reply traffic for such connections back to the gateway interface with the high priority.

		// Send the traffic to external to SNATTable.
		L3ForwardingTable.BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchRegMark(FromLocalRegMark).
			Action().GotoTable(SNATTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
		// For the traffic tunneled from remote Nodes, rewrite the
		// destination MAC to the gateway interface MAC.
		L3ForwardingTable.BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchRegMark(FromTunnelRegMark).
			Action().SetDstMAC(localGatewayMAC).
			Action().GotoTable(SNATTable.GetID()).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),

		// Drop the traffic from remote Nodes if no matched SNAT policy.
		SNATTable.BuildFlow(priorityLow).
			MatchProtocol(ipProto).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchRegMark(FromTunnelRegMark).
			Action().Drop().
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
	}
	for _, cidr := range exceptCIDRs {
		flows = append(flows, L3ForwardingTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchRegMark(FromLocalRegMark).
			MatchDstIPNet(cidr).
			Action().GotoTable(nextTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done())
	}
	return flows
}

// snatIPFromTunnelFlow generates a flow that marks SNAT packets tunnelled from
// remote Nodes. The SNAT IP matches the packet's tunnel destination IP.
func (c *client) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow {
	ipProto := getIPProtocol(snatIP)
	return SNATTable.BuildFlow(priorityNormal).
		MatchProtocol(ipProto).
		MatchCTStateNew(true).MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().LoadPktMarkRange(mark, snatPktMarkRange).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
		Done()
}

// snatRuleFlow generates a flow that applies the SNAT rule for a local Pod. If
// the SNAT IP exists on the local Node, it sets the packet mark with the ID of
// the SNAT IP, for the traffic from the ofPort to external; if the SNAT IP is
// on a remote Node, it tunnels the packets to the SNAT IP.
func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow {
	ipProto := getIPProtocol(snatIP)
	if snatMark != 0 {
		// Local SNAT IP.
		return SNATTable.BuildFlow(priorityNormal).
			MatchProtocol(ipProto).
			MatchCTStateNew(true).MatchCTStateTrk(true).
			MatchInPort(ofPort).
			Action().LoadPktMarkRange(snatMark, snatPktMarkRange).
			Action().GotoTable(SNATTable.GetNext()).
			Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
			Done()
	}
	// SNAT IP should be on a remote Node.
	return SNATTable.BuildFlow(priorityNormal).
		MatchProtocol(ipProto).
		MatchInPort(ofPort).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(GlobalVirtualMAC).
		// Set tunnel destination to the SNAT IP.
		Action().SetTunnelDst(snatIP).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Cookie(c.cookieAllocator.Request(cookie.SNAT).Raw()).
		Done()
}

// loadBalancerServiceFromOutsideFlow generates the flow to forward LoadBalancer service traffic from outside node
// to gateway. kube-proxy will then handle the traffic.
// This flow is for Windows Node only.
func (c *client) loadBalancerServiceFromOutsideFlow(svcIP net.IP, svcPort uint16, protocol binding.Protocol) binding.Flow {
	return UplinkTable.BuildFlow(priorityHigh).
		MatchProtocol(protocol).
		MatchDstPort(svcPort, nil).
		MatchRegMark(FromUplinkRegMark).
		MatchDstIP(svcIP).
		Action().Output(config.HostGatewayOFPort).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		Done()
}

// serviceClassifierFlows generate the flows to match the first packet of Service NodePort and set a bit of a register
// to mark the Service type as NodePort.
func (c *client) serviceClassifierFlows(nodePortAddresses []net.IP, ipProtocol binding.Protocol) []binding.Flow {
	virtualServiceIP := config.VirtualServiceIPv4
	if ipProtocol == binding.ProtocolIPv6 {
		virtualServiceIP = config.VirtualServiceIPv6
	}
	// Generate flows for every NodePort IP address. The flows are used to match the first packet of Service NodePort from
	// Pod.
	var flows []binding.Flow
	for i := range nodePortAddresses {
		flows = append(flows,
			ServiceClassifierTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodePortAddresses[i]).
				Action().LoadRegMark(ToNodePortAddressRegMark).
				Done())
	}
	// Generate flow for the virtual IP. The flow is used to match the first packet of Service NodePort from Antrea gateway,
	// because the destination IP of the packet has already performed DNAT with the virtual IP on host.
	flows = append(flows,
		ServiceClassifierTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			MatchProtocol(ipProtocol).
			MatchDstIP(virtualServiceIP).
			Action().LoadRegMark(ToNodePortAddressRegMark).
			Done())

	return flows
}

// serviceLearnFlow generates the flow with learn action which adds new flows in
// sessionAffinityTable according to the Endpoint selection decision.
func (c *client) serviceLearnFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := c.cookieAllocator.RequestWithObjectID(cookie.Service, uint32(groupID)).Raw()

	var flowBuilder binding.FlowBuilder
	if svcType == v1.ServiceTypeNodePort {
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToLearnRegMark.GetValue()
		flowBuilder = ServiceLBTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil)
	} else {
		flowBuilder = ServiceLBTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchRegMark(EpToLearnRegMark).
			MatchDstIP(svcIP).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil)
	}

	// affinityTimeout is used as the OpenFlow "hard timeout": learned flow will be removed from
	// OVS after that time regarding of whether traffic is still hitting the flow. This is the
	// desired behavior based on the K8s spec. Note that existing connections will keep going to
	// the same endpoint because of connection tracking; and that is also the desired behavior.
	learnFlowBuilderLearnAction := flowBuilder.
		Action().Learn(SessionAffinityTable.GetID(), priorityNormal, 0, affinityTimeout, cookieID).
		DeleteLearned()
	ipProtocol := binding.ProtocolIP
	switch protocol {
	case binding.ProtocolTCP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	case binding.ProtocolUDP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	case binding.ProtocolSCTP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	case binding.ProtocolTCPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPv6DstPort()
	case binding.ProtocolUDPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPv6DstPort()
	case binding.ProtocolSCTPv6:
		ipProtocol = binding.ProtocolIPv6
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPv6DstPort()
	}
	// If externalTrafficPolicy of NodePort/LoadBalancer is Cluster, the learned flow which
	// is used to match the first packet of NodePort/LoadBalancer also requires SNAT.
	if (svcType == v1.ServiceTypeNodePort || svcType == v1.ServiceTypeLoadBalancer) && !nodeLocalExternal {
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.LoadRegMark(ServiceNeedSNATRegMark)
	}

	if ipProtocol == binding.ProtocolIP {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIP().
			MatchLearnedSrcIP().
			LoadFieldToField(EndpointIPField, EndpointIPField).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().GotoTable(EndpointDNATTable.GetID()).
			Done()
	} else if ipProtocol == binding.ProtocolIPv6 {
		return learnFlowBuilderLearnAction.
			MatchLearnedDstIPv6().
			MatchLearnedSrcIPv6().
			LoadXXRegToXXReg(EndpointIP6Field, EndpointIP6Field).
			LoadFieldToField(EndpointPortField, EndpointPortField).
			LoadRegMark(EpSelectedRegMark).
			LoadRegMark(RewriteMACRegMark).
			Done().
			Action().LoadRegMark(EpSelectedRegMark).
			Action().GotoTable(EndpointDNATTable.GetID()).
			Done()
	}
	return nil
}

// serviceLBFlow generates the flow which uses the specific group to do Endpoint
// selection.
func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, withSessionAffinity, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow {
	var lbResultMark *binding.RegMark
	if withSessionAffinity {
		lbResultMark = EpToLearnRegMark
	} else {
		lbResultMark = EpSelectedRegMark
	}

	var flowBuilder binding.FlowBuilder
	if svcType == v1.ServiceTypeNodePort {
		// If externalTrafficPolicy of NodePort is Cluster, the first packet of NodePort requires SNAT, so nodeLocalExternal
		// will be false, and ServiceNeedSNATRegMark will be set. If externalTrafficPolicy of NodePort is Local, the first
		// packet of NodePort doesn't require SNAT, ServiceNeedSNATRegMark won't be set.
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToSelectRegMark.GetValue()
		flowBuilder = ServiceLBTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(ServiceNeedSNATRegMark)
		}
	} else {
		// If Service type is LoadBalancer, as above NodePort.
		flowBuilder = ServiceLBTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil).
			MatchDstIP(svcIP).
			MatchRegMark(EpToSelectRegMark).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if svcType == v1.ServiceTypeLoadBalancer && !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(ServiceNeedSNATRegMark)
		}
	}
	return flowBuilder.
		Action().LoadToRegField(ServiceGroupIDField, uint32(groupID)).
		Action().Group(groupID).Done()
}

// endpointDNATFlow generates the flow which transforms the Service Cluster IP
// to the Endpoint IP according to the Endpoint selection decision which is stored
// in regs.
func (c *client) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	ipProtocol := getIPProtocol(endpointIP)
	unionVal := (EpSelectedRegMark.GetValue() << EndpointPortField.GetRange().Length()) + uint32(endpointPort)

	flowBuilder := EndpointDNATTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchRegFieldWithValue(EpUnionField, unionVal).
		MatchProtocol(protocol)
	ctZone := CtZone
	if ipProtocol == binding.ProtocolIP {
		ipVal := binary.BigEndian.Uint32(endpointIP.To4())
		flowBuilder = flowBuilder.MatchRegFieldWithValue(EndpointIPField, ipVal)
	} else {
		ctZone = CtZoneV6
		ipVal := []byte(endpointIP)
		flowBuilder = flowBuilder.MatchXXReg(EndpointIP6Field.GetRegID(), ipVal)
	}
	return flowBuilder.Action().CT(true, EndpointDNATTable.GetNext(), ctZone).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToCtMark(ServiceCTMark).
		CTDone().
		Done()
}

// hairpinSNATFlow generates the flow which does SNAT for Service
// hairpin packets and loads the hairpin mark to markReg.
func (c *client) hairpinSNATFlow(endpointIP net.IP) binding.Flow {
	ipProtocol := getIPProtocol(endpointIP)
	hpIP := hairpinIP
	if ipProtocol == binding.ProtocolIPv6 {
		hpIP = hairpinIPv6
	}
	return HairpinSNATTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(cookie.Service).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIP(endpointIP).
		MatchSrcIP(endpointIP).
		Action().SetSrcIP(hpIP).
		Action().LoadRegMark(HairpinRegMark).
		Action().GotoTable(L2ForwardingOutTable.GetID()).
		Done()
}

// serviceEndpointGroup creates/modifies the group/buckets of Endpoints. If the
// withSessionAffinity is true, then buckets will resubmit packets back to
// ServiceLBTable to trigger the learn flow, the learn flow will then send packets
// to EndpointDNATTable. Otherwise, buckets will resubmit packets to
// EndpointDNATTable directly.
func (c *client) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group {
	group := c.bridge.CreateGroup(groupID).ResetBuckets()
	var resubmitTableID uint8
	if withSessionAffinity {
		resubmitTableID = ServiceLBTable.GetID()
	} else {
		resubmitTableID = EndpointDNATTable.GetID()
	}

	for _, endpoint := range endpoints {
		endpointPort, _ := endpoint.Port()
		endpointIP := net.ParseIP(endpoint.IP())
		portVal := portToUint16(endpointPort)
		ipProtocol := getIPProtocol(endpointIP)
		if ipProtocol == binding.ProtocolIP {
			ipVal := binary.BigEndian.Uint32(endpointIP.To4())
			group = group.Bucket().Weight(100).
				LoadToRegField(EndpointIPField, ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		} else if ipProtocol == binding.ProtocolIPv6 {
			ipVal := []byte(endpointIP)
			group = group.Bucket().Weight(100).
				LoadXXReg(EndpointIP6Field.GetRegID(), ipVal).
				LoadToRegField(EndpointPortField, uint32(portVal)).
				ResubmitToTable(resubmitTableID).
				Done()
		}
	}
	return group
}

// decTTLFlows decrements TTL by one for the packets forwarded across Nodes.
// The TTL decrement should be skipped for the packets which enter OVS pipeline
// from the gateway interface, as the host IP stack should have decremented the
// TTL already for such packets.
func (c *client) decTTLFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, proto := range c.ipProtocols {
		flows = append(flows,
			// Skip packets from the gateway interface.
			L3DecTTLTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(proto).
				MatchRegMark(FromGatewayRegMark).
				Action().GotoTable(L3DecTTLTable.GetNext()).
				Done(),
			L3DecTTLTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(proto).
				Action().DecTTL().
				Action().GotoTable(L3DecTTLTable.GetNext()).
				Done(),
		)
	}
	return flows
}

// externalFlows returns the flows needed to enable SNAT for external traffic.
func (c *client) externalFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr, exceptCIDRs []net.IPNet) []binding.Flow {
	if !c.enableEgress {
		return nil
	}
	return c.snatCommonFlows(nodeIP, localSubnet, localGatewayMAC, exceptCIDRs, cookie.SNAT)
}

// policyConjKeyFuncKeyFunc knows how to get key of a *policyRuleConjunction.
func policyConjKeyFunc(obj interface{}) (string, error) {
	conj := obj.(*policyRuleConjunction)
	return fmt.Sprint(conj.id), nil
}

// priorityIndexFunc knows how to get priority of actionFlows in a *policyRuleConjunction.
// It's provided to cache.Indexer to build an index of policyRuleConjunction.
func priorityIndexFunc(obj interface{}) ([]string, error) {
	conj := obj.(*policyRuleConjunction)
	return conj.ActionFlowPriorities(), nil
}

// genPacketInMeter generates a meter entry with specific meterID and rate.
// `rate` is represented as number of packets per second.
// Packets which exceed the rate will be dropped.
func (c *client) genPacketInMeter(meterID binding.MeterIDType, rate uint32) binding.Meter {
	meter := c.bridge.CreateMeter(meterID, ofctrl.MeterBurst|ofctrl.MeterPktps).ResetMeterBands()
	meter = meter.MeterBand().
		MeterType(ofctrl.MeterDrop).
		Rate(rate).
		Burst(2 * rate).
		Done()
	return meter
}

func generatePipeline(templates []*featureTemplate) binding.Pipeline {
	pipelineID := binding.NewPipelineID()
	sortedOFTableMap := make(map[binding.StageID][]binding.Table)

	// PipelineClassifierTable ID is always 0, and it is the first table for all pipelines. Create PipelineClassifierTable
	// on the bridge when building a pipeline.
	if PipelineClassifierTable.ofTable == nil {
		PipelineClassifierTable.ofTable = binding.NewOFTable(binding.NextTableID(), PipelineClassifierTable.name, 0, binding.AllPipelines)
	}

	// Iterate each stage to get a sorted FeatureTable list from every feature template.
	for stage := binding.FirstStage; stage <= binding.LastStage; stage++ {
		// tableMap is used to store all declared FeatureTables in a stage. As a FeatureTable can be declared by multiple
		// features, a map is used to avoid duplication.
		tableMap := make(map[*FeatureTable]struct{})
		for _, template := range templates {
			if tables, ok := template.stageTables[stage]; ok {
				for _, table := range tables {
					if table.stage != stage {
						klog.Errorf("table %s belongs to stage %d, and it should not be declared in stage %d", table.name, table.stage, stage)
						continue
					}
					if _, exist := tableMap[table]; !exist {
						tableMap[table] = struct{}{}
					}
				}
			}
		}
		if len(tableMap) == 0 {
			continue
		}

		// Use a slice to store all declared FeatureTables in a stage and sort them.
		tableList := make([]*FeatureTable, 0, len(tableMap))
		for tr := range tableMap {
			tableList = append(tableList, tr)
		}
		sort.Slice(tableList, func(i, j int) bool {
			return tableList[i].priority > tableList[j].priority
		})

		ofTableList := make([]binding.Table, 0, len(tableList))
		for _, table := range tableList {
			// Generate a sequencing ID for the flow table.
			tableID := binding.NextTableID()
			// Initialize a flow table.
			table.ofTable = binding.NewOFTable(tableID, table.name, stage, pipelineID)
			ofTableList = append(ofTableList, table.ofTable)
			addTableToCache(table)
		}
		sortedOFTableMap[stage] = ofTableList
	}
	return binding.NewPipeline(pipelineID, sortedOFTableMap)
}

func createPipelinesOnBridge(bridge binding.Bridge, pipelines map[pipelineProtocol]binding.Pipeline) {
	bridge.CreateTable(PipelineClassifierTable.ofTable, binding.LastTableID, binding.TableMissActionDrop)
	for _, pipeline := range pipelines {
		tables := pipeline.ListAllTables()
		for i := range tables {
			var nextID uint8
			var missAction binding.MissActionType
			if pipeline.IsLastTable(tables[i]) {
				nextID = binding.LastTableID
				missAction = binding.TableMissActionDrop
			} else {
				nextID = tables[i+1].GetID()
				missAction = binding.TableMissActionNext
			}
			tables[i].SetNext(nextID)
			tables[i].SetMissAction(missAction)
			bridge.CreateTable(tables[i], nextID, missAction)
		}
	}
}

func pipelineClassifyFlow(cookieID uint64, protocol binding.Protocol, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(protocol).
		Action().ResubmitToTables(targetTable.GetID()).
		Done()
}

// NewClient is the constructor of the Client interface.
func NewClient(bridgeName string,
	mgmtAddr string,
	ovsDatapathType ovsconfig.OVSDatapathType,
	enableProxy bool,
	enableAntreaPolicy bool,
	enableEgress bool,
	enableDenyTracking bool,
	proxyAll bool,
	connectUplinkToBridge bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	c := &client{
		bridge:                bridge,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		enableAntreaPolicy:    enableAntreaPolicy,
		enableDenyTracking:    enableDenyTracking,
		enableEgress:          enableEgress,
		connectUplinkToBridge: connectUplinkToBridge,
		pipelines:             make(map[pipelineProtocol]binding.Pipeline),
		ovsctlClient:          ovsctl.NewClient(bridgeName),
		ovsDatapathType:       ovsDatapathType,
		ovsMetersAreSupported: ovsMetersAreSupported(ovsDatapathType),
	}
	c.ofEntryOperations = c
	return c
}

type conjunctiveActionsInOrder []*conjunctiveAction

func (sl conjunctiveActionsInOrder) Len() int      { return len(sl) }
func (sl conjunctiveActionsInOrder) Swap(i, j int) { sl[i], sl[j] = sl[j], sl[i] }
func (sl conjunctiveActionsInOrder) Less(i, j int) bool {
	if sl[i].conjID != sl[j].conjID {
		return sl[i].conjID < sl[j].conjID
	}
	if sl[i].clauseID != sl[j].clauseID {
		return sl[i].clauseID < sl[j].clauseID
	}
	return sl[i].nClause < sl[j].nClause
}

func addTableToCache(ft *FeatureTable) {
	_, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", ft.GetID()))
	if !exists {
		tableCache.Add(ft)
	}
}
