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
	// PipelineClassifierTable is table 0. Packets are forwarded to different pipelines in this table.
	PipelineClassifierTable = newTable("PipelineClassifier", 0, binding.PipelineAll)

	// OVS pipeline for ARP is used to process ARP packets.
	// Tables in ValidationStage:
	ARPSpoofGuardTable = newTable("ARPSpoofGuard", binding.ValidationStage, binding.PipelineARP)

	// Tables in OutputStage:
	ARPResponderTable = newTable("ARPResponder", binding.OutputStage, binding.PipelineARP)

	// OVS pipeline for IP is used to process IPv4/IPv6 packets.
	// Tables in ClassifierStage:
	ClassifierTable = newTable("Classifier", binding.ClassifierStage, binding.PipelineIP)

	// Tables in ValidationStage:
	SpoofGuardTable   = newTable("SpoofGuard", binding.ValidationStage, binding.PipelineIP)
	IPv6Table         = newTable("IPv6", binding.ValidationStage, binding.PipelineIP)
	IPClassifierTable = newTable("IPClassifier", binding.ValidationStage, binding.PipelineIP)

	// Tables in ConntrackStateStage:
	SNATConntrackTable  = newTable("SNATConntrackZone", binding.ConntrackStateStage, binding.PipelineIP)
	ConntrackTable      = newTable("ConntrackZone", binding.ConntrackStateStage, binding.PipelineIP)
	ConntrackStateTable = newTable("ConntrackState", binding.ConntrackStateStage, binding.PipelineIP)

	// Tables in PreRoutingStage:
	// When proxy is enabled.
	PreRoutingClassifierTable = newTable("PreRoutingClassifier", binding.PreRoutingStage, binding.PipelineIP)
	NodePortMarkTable         = newTable("NodePortMark", binding.PreRoutingStage, binding.PipelineIP)
	SessionAffinityTable      = newTable("SessionAffinity", binding.PreRoutingStage, binding.PipelineIP)
	ServiceLBTable            = newTable("ServiceLB", binding.PreRoutingStage, binding.PipelineIP)
	EndpointDNATTable         = newTable("EndpointDNAT", binding.PreRoutingStage, binding.PipelineIP)
	// When proxy is disabled.
	DNATTable = newTable("DNAT", binding.PreRoutingStage, binding.PipelineIP)

	// Tables in EgressSecurityStage:
	AntreaPolicyEgressRuleTable = newTable("AntreaPolicyEgressRule", binding.EgressSecurityStage, binding.PipelineIP)
	EgressRuleTable             = newTable("EgressRule", binding.EgressSecurityStage, binding.PipelineIP)
	EgressDefaultTable          = newTable("EgressDefaultRule", binding.EgressSecurityStage, binding.PipelineIP)
	EgressMetricTable           = newTable("EgressMetric", binding.EgressSecurityStage, binding.PipelineIP)

	// Tables in RoutingStage:
	L3ForwardingTable       = newTable("L3Forwarding", binding.RoutingStage, binding.PipelineIP)
	ServiceHairpinMarkTable = newTable("ServiceHairpinMark", binding.RoutingStage, binding.PipelineIP)
	L3DecTTLTable           = newTable("L3DecTTL", binding.RoutingStage, binding.PipelineIP)

	// Tables in PostRoutingStage:
	SNATTable                = newTable("SNAT", binding.PostRoutingStage, binding.PipelineIP)
	SNATConntrackCommitTable = newTable("SNATConntrackCommit", binding.PostRoutingStage, binding.PipelineIP)

	// Tables in SwitchingStage:
	L2ForwardingCalcTable = newTable("L2ForwardingCalc", binding.SwitchingStage, binding.PipelineIP)

	// Tables in IngressSecurityStage:
	IngressSecurityClassifierTable = newTable("IngressSecurityClassifier", binding.IngressSecurityStage, binding.PipelineIP)
	AntreaPolicyIngressRuleTable   = newTable("AntreaPolicyIngressRule", binding.IngressSecurityStage, binding.PipelineIP)
	IngressRuleTable               = newTable("IngressRule", binding.IngressSecurityStage, binding.PipelineIP)
	IngressDefaultTable            = newTable("IngressDefaultRule", binding.IngressSecurityStage, binding.PipelineIP)
	IngressMetricTable             = newTable("IngressMetric", binding.IngressSecurityStage, binding.PipelineIP)

	// Tables in ConntrackStage:
	ConntrackCommitTable = newTable("ConntrackCommit", binding.ConntrackStage, binding.PipelineIP)

	// Tables in OutputStage:
	L2ForwardingOutTable = newTable("L2ForwardingOut", binding.OutputStage, binding.PipelineIP)

	// OVS pipeline for multicast is used to process multicast packets.
	// Tables in RoutingStage:
	MulticastTable = newTable("Multicast", binding.RoutingStage, binding.PipelineMulticast)

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

// tableCache caches the OpenFlow tables used in pipelines, and it supports using the table ID and name as the index to query the OpenFlow table.
var tableCache = cache.NewIndexer(tableIDKeyFunc, cache.Indexers{tableNameIndex: tableNameIndexFunc})

func tableNameIndexFunc(obj interface{}) ([]string, error) {
	table := obj.(*Table)
	return []string{table.GetName()}, nil
}

func tableIDKeyFunc(obj interface{}) (string, error) {
	table := obj.(*Table)
	return fmt.Sprintf("%d", table.GetID()), nil
}

func getTableByID(id uint8) binding.Table {
	obj, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", id))
	if !exists {
		return nil
	}
	return obj.(*Table).ofTable
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

func GetAntreaPolicyEgressTables() []*Table {
	return []*Table{
		AntreaPolicyEgressRuleTable,
		EgressDefaultTable,
	}
}

func GetAntreaPolicyIngressTables() []*Table {
	return []*Table{
		AntreaPolicyIngressRuleTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyBaselineTierTables() []*Table {
	return []*Table{
		EgressDefaultTable,
		IngressDefaultTable,
	}
}

func GetAntreaPolicyMultiTierTables() []*Table {
	return []*Table{
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
	CustomReasonIGMP = 0b10000
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
	enableMulticast       bool
	connectUplinkToBridge bool
	roundInfo             types.RoundInfo
	cookieAllocator       cookie.Allocator
	bridge                binding.Bridge

	featurePodConnectivity *featurePodConnectivity
	featureService         *featureService
	featureEgress          *featureEgress
	featureNetworkPolicy   *featureNetworkPolicy
	featureMulticast       *featureMulticast
	activeFeatures         []feature

	featureTraceflow  *featureTraceflow
	traceableFeatures []traceableFeature

	pipelines map[binding.PipelineID]binding.Pipeline

	// ofEntryOperations is a wrapper interface for OpenFlow entry Add / Modify / Delete operations. It
	// enables convenient mocking in unit tests.
	ofEntryOperations OFEntryOperations
	// replayMutex provides exclusive access to the OFSwitch to the ReplayFlows method.
	replayMutex   sync.RWMutex
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	// ovsDatapathType is the type of the datapath used by the bridge.
	ovsDatapathType ovsconfig.OVSDatapathType
	// ovsMetersAreSupported indicates whether the OVS datapath supports OpenFlow meters.
	ovsMetersAreSupported bool
	// packetInHandlers stores handler to process PacketIn event. Each packetin reason can have multiple handlers registered.
	// When a packetin arrives, openflow send packet to registered handlers in this map.
	packetInHandlers map[uint8]map[string]PacketInHandler
	// Supported IP Protocols (IP or IPv6) on the current Node.
	ipProtocols []binding.Protocol
	// ovsctlClient is the interface for executing OVS "ovs-ofctl" and "ovs-appctl" commands.
	ovsctlClient ovsctl.OVSCtlClient
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

func (c *client) defaultFlows() []binding.Flow {
	cookieID := c.cookieAllocator.Request(cookie.Default).Raw()
	var flows []binding.Flow
	for id, pipeline := range c.pipelines {
		// This generates the default flow for every table for a pipeline.
		for _, table := range pipeline.ListAllTables() {
			flowBuilder := table.BuildFlow(priorityMiss).Cookie(cookieID)
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

		// This generates the flows to forward packets to different pipelines.
		switch id {
		case binding.PipelineIP:
			// This generates the flow to forward packets to pipeline for IP in PipelineClassifierTable.
			for _, ipProtocol := range c.ipProtocols {
				flows = append(flows, pipelineClassifyFlow(cookieID, ipProtocol, pipeline))
			}
		case binding.PipelineARP:
			// This generates the flow to forward packets to pipeline for ARP in PipelineClassifierTable.
			flows = append(flows, pipelineClassifyFlow(cookieID, binding.ProtocolARP, pipeline))
		case binding.PipelineMulticast:
			// This generates the flow to forward packets to pipeline for multicast in IPClassifierTable.
			// Note that, the table is in ValidationStage of pipeline for IP. In another word, pipeline for multicast
			// shares  with pipeline for IP.
			flows = append(flows, multicastPipelineClassifyFlow(cookieID, pipeline))
		}
	}
	// This generates default the flow for PipelineClassifierTable.
	flows = append(flows, PipelineClassifierTable.ofTable.BuildFlow(priorityMiss).
		Cookie(cookieID).
		Action().Drop().
		Done())

	return flows
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - func (c *client) tunnelClassifierFlow(tunnelOFPort uint32, category cookie.Category) binding.Flow
// tunnelClassifierFlow generates the flow to mark the packets from tunnel port.
func (f *featurePodConnectivity) tunnelClassifierFlow(tunnelOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(tunnelOFPort).
		Action().LoadRegMark(FromTunnelRegMark).
		Action().LoadRegMark(RewriteMACRegMark).
		Action().GotoStage(binding.ConntrackStateStage).
		Done()
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - func (c *client) gatewayClassifierFlow(category cookie.Category) binding.Flow
// gatewayClassifierFlow generates the flow to mark the packets from the Antrea gateway port.
func (f *featurePodConnectivity) gatewayClassifierFlow() binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(config.HostGatewayOFPort).
		Action().LoadRegMark(FromGatewayRegMark).
		Action().GotoStage(binding.ValidationStage).
		Done()
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category, isAntreaFlexibleIPAM bool) binding.Flow
// podClassifierFlow generates the flow to mark the packets from a local Pod port.
func (f *featurePodConnectivity) podClassifierFlow(podOFPort uint32, isAntreaFlexibleIPAM bool) binding.Flow {
	flowBuilder := ClassifierTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(podOFPort).
		Action().LoadRegMark(FromLocalRegMark).
		Action().GotoStage(binding.ValidationStage)
	if isAntreaFlexibleIPAM {
		// This is used to mark the packets from a local Antrea IPAM Pod port.
		flowBuilder = flowBuilder.Action().LoadRegMark(AntreaFlexibleIPAMRegMark).
			Action().LoadRegMark(RewriteMACRegMark)
	}
	return flowBuilder.Done()
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - func (c *client) podUplinkClassifierFlows(dstMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow)
// podUplinkClassifierFlows generates the flows to mark the packets with target destination MAC address from uplink/bridge
// port, which are needed when uplink is connected to OVS bridge and Antrea IPAM is configured.
func (f *featurePodConnectivity) podUplinkClassifierFlows(dstMAC net.HardwareAddr) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to mark the packets from uplink port.
		ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchInPort(config.UplinkOFPort).
			MatchDstMAC(dstMAC).
			Action().LoadRegMark(FromUplinkRegMark).
			Action().GotoStage(binding.ConntrackStateStage).
			Done(),
		// This generates the flow to mark the packets from bridge local port.
		ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchInPort(config.BridgeOFPort).
			MatchDstMAC(dstMAC).
			Action().LoadRegMark(FromBridgeRegMark).
			Action().GotoStage(binding.ConntrackStateStage).
			Done(),
	}
}

// Feature: PodConnectivity
// Stage: ConntrackStateStage
// Tables: ConntrackTable, ConntrackStateTable
// Stage: ConntrackStage
// Tables: ConntrackCommitTable
// Refactored from:
//   - func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow
//   - func (c *client) conntrackBasicFlows(category cookie.Category) []binding.Flow
//   - part of func (c *client) serviceLBBypassFlows(ipProtocol binding.Protocol) []binding.Flow
// Modifications:
//   - Remove the flows related with Service since they are for feature Service.
// conntrackFlows generates the flows about conntrack for feature PodConnectivity.
func (f *featurePodConnectivity) conntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to maintain tracked connection in CT zone.
			ConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().CT(false, ConntrackTable.ofTable.GetNext(), f.ctZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
			// This generates the flow to match the packets of tracked non-Service connection and forward them to
			// EgressSecurityStage directly to bypass PreRoutingStage. The first packet of non-Service connection will
			// pass through PreRoutingStage, and the subsequent packets should go to EgressSecurityStage directly.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().GotoStage(binding.EgressSecurityStage).
				Done(),
			// This generates the flow to drop invalid packets.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateInv(true).
				MatchCTStateTrk(true).
				Action().Drop().
				Done(),
			// This generates the flow to mark the connection initiated through the Antrea gateway with FromGatewayCTMark.
			// There are two cases:
			// - When AntreaProxy is disabled and kube-proxy is used, a Pod (not host network) as client connects to a
			//   Service whose Endpoint is another Pod (not host network).
			// - When AntreaProxy is enabled or not, a Pod (not host network) as client connects to a NodePortLocal whose
			//   destination is DNATed to another Pod.
			// The source IP and the DNATed destination IP of above cases can reach each other directly within OVS. However,
			// the connection is performed DNAT in host netns. As a result, FromGatewayCTMark is used in another flow to
			// make the reply packets to be forwarded back to host netns through the Antrea gateway.
			ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromGatewayRegMark).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), f.ctZones[ipProtocol]).
				LoadToCtMark(FromGatewayCTMark).
				CTDone().
				Done(),
			// This generates the default flow to commit connection.
			ConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), f.ctZones[ipProtocol]).
				CTDone().
				Done(),
		)
		// This generates default flow to match the first packet of a new connection (including Service / non-Service connection)
		// and forward it PreRoutingStage.
		flows = append(flows,
			ConntrackStateTable.ofTable.BuildFlow(priorityMiss).
				Cookie(cookieID).
				Action().GotoStage(binding.PreRoutingStage).
				Done())
		if f.connectUplinkToBridge {
			flows = append(flows,
				// When Node bridge local port and uplink port connect to OVS bridge, this generates the flow to mark the
				// connection initiated through the bridge local port with FromBridgeCTMark. There is a case:
				// - An Antrea IPAM Pod as client connects to a NodePortLocal whose destination is DNATed to another
				//   Antrea IPAM Pod.
				// The source IP and the DNATed destination IP of above case can reach each other directly since they are
				// in the same subnet. However, the connection is performed DNAT in host netns. As a result, and FromBridgeCTMark
				// is used in another flow to make the reply packets to be forwarded back to host netns through the bridge
				// local port.
				ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchRegMark(FromBridgeRegMark).
					MatchCTStateNew(true).
					MatchCTStateTrk(true).
					Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), f.ctZones[ipProtocol]).
					LoadToCtMark(FromBridgeCTMark).
					CTDone().
					Done())
		}
	}
	return flows
}

// Feature: Service
// Stage: ConntrackStateStage
// Tables: ConntrackStateTable, ConntrackTable
// Refactored from:
//   - part of func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow
//   - part of func (c *client) serviceLBBypassFlows(ipProtocol binding.Protocol) []binding.Flow
// conntrackFlows generates the flows about conntrack for feature Service.
func (f *featureService) conntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to mark tracked DNATed Service connection with RewriteMACRegMark (load-balanced by
			// AntreaProxy) and forward the packets of the connection to EgressSecurityStage directly to bypass
			// PreRoutingStage.
			ConntrackStateTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().LoadRegMark(RewriteMACRegMark).
				Action().GotoStage(binding.EgressSecurityStage).
				Done(),
			// This generates the flow to skip ConntrackCommitTable for Service connection (with ServiceCTMark). Since
			// Service connection has been committed in EndpointDNATTable in DNAT CT zone, it's unnecessary to commit
			// Service connection in ConntrackCommitTable again (both commit operation in EndpointDNATTable and
			// ConntrackCommitTable use the same CT zone).
			ConntrackCommitTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceCTMark).
				Action().GotoStage(binding.OutputStage).
				Done(),
		)
	}
	return flows
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: SNATConntrackTable
// Stage: PostRoutingStage
// Tables: SNATConntrackCommitTable
// Refactored from:
//   - part of func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow
// snatConntrackFlows generates the flows about conntrack of SNAT connection for feature Service .
func (f *featureService) snatConntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to maintain tracked SNATed Service connection.
			SNATConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().CT(false, SNATConntrackTable.ofTable.GetNext(), f.snatCtZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
			// For the first packet of Service connection, if it requires SNAT, the packet will be committed to SNAT
			// CT zone. For reply packets of the connection, they can be transformed correctly by passing through SNAT,
			// DNAT CT zone in order. However, for consequent request packets, they can be only transformed by passing
			// DNAT CT zone, not by passing SNAT CT zone, since there is no related conntrack record in SNAT CT zone for
			// the 5-tuple of the packets before entering SNAT CT zone.
			// For the consequent request packets, they need to pass SNAT CT zone again to perform SNAT in SNATConntrackCommitTable
			// after passing DNAT CT zone. The consequent request packets should have a CT mark in DNAT CT zone to distinguish
			// them from the connection that don't require SNAT, so ServiceSNATCTMark CT mark is used DNAT CT zone.
			// To avoid adding another table, the first packet is committed to SNATConntrackCommitTable again. ServiceSNATStateField
			// is used to prevent the packet from being forked to SNATConntrackCommitTable cyclically since the status of
			// ServiceSNATStateField is changed from NotRequireSNATRegMark / RequireSNATRegMark to CTMarkedSNATRegMark.
			// The following two functions generate the flows described as above.

			// This generates the flow to match the first packet of hairpin connection. The source can be from the Antrea
			// gateway or local Pods. HairpinCTMark is used to match the consequent packets of tracked hairpin connection.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinRegMark).
				MatchRegMark(NotRequireSNATRegMark).
				Action().LoadRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetID(), f.dnatCtZones[ipProtocol]).
				LoadToCtMark(ServiceSNATCTMark).
				LoadToCtMark(HairpinCTMark).
				CTDone().
				Done(),
			// This generates the flow to match the first packet of NodePort / LoadBalancer connection which require
			// SNAT and are initiated through Antrea gateway.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchRegMark(RequireSNATRegMark).
				Action().LoadRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetID(), f.dnatCtZones[ipProtocol]).
				LoadToCtMark(ServiceSNATCTMark).
				CTDone().
				Done(),
			// For the packets of connection that require SNAT, after processing by the flows generated by above functions,
			// the status of ServiceSNATStateField changed to CTMarkedSNATRegMark and ServiceSNATCTMark is also loaded in
			// DNAT CT zone. The connection can be distinguished from other connections that don't require SNAT in DNAT
			// CT zone. Then the connection should be committed to SNAT CT zone and performed SNAT with an IP. ServiceCTMark
			// is also loaded in SNAT CT zone since ServiceCTMark loaded in DNAT CT zone is invisible in SNAT CT zone.
			// Note that, ServiceCTMark is used to skip ConntrackCommitTable.
			// The following three functions generate the flows described as above.
			// This generates the flow to mark the first packet of hairpin connection sourced from the Antrea gateway and
			// destined for the Antrea gateway. The hairpin connection requires virtual IP to perform SNAT.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinSNATWithVirtualIP).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), f.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: f.virtualIPs[ipProtocol], EndIP: f.virtualIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark).
				CTDone().
				Done(),
			// This generates the flow to mark the first packet of hairpin connection sourced from a Pod and destined
			// to the same Pod. The hairpin connection requires the Antrea gateway IP to perform SNAT.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(HairpinSNATWithGatewayIP).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), f.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: f.gatewayIPs[ipProtocol], EndIP: f.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark).
				CTDone().
				Done(),
			// This generates the flow to mark the first packet of Service NodePort / LoadBalancer connection sourced
			// from the Antrea gateway and destined for a Pod. The connection requires the Antrea gateway IP to perform SNAT.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromGatewayRegMark).
				MatchRegMark(CTMarkedSNATRegMark).
				Action().CT(true, SNATConntrackCommitTable.ofTable.GetNext(), f.snatCtZones[ipProtocol]).
				SNAT(&binding.IPRange{StartIP: f.gatewayIPs[ipProtocol], EndIP: f.gatewayIPs[ipProtocol]}, nil).
				LoadToCtMark(ServiceCTMark).
				CTDone().
				Done(),
			// This generates the flow to match the subsequent request packets of Service connection whose first request
			// packet has been committed in SNAT CT zone and commit the packets in SNAT CT zone again to perform SNAT.
			// For example:
			/*
				* 192.168.77.1 is the IP address of client.
				* 192.168.77.100 is the IP address of K8s Node.
				* 30001 is the NodePort port.
				* 10.10.0.1 is the IP address of Antrea gateway.
				* 10.10.0.3 is the IP of NodePort Service Endpoint.

				* packet 1 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* CT zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* CT zone DNAT 65520         192.168.77.1:12345->192.168.77.100:30001
					* CT commit DNAT zone 65520  192.168.77.1:12345->192.168.77.100:30001  =>  192.168.77.1:12345->10.10.0.3:80
					* CT commit SNAT zone 65521  192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * packet 2 (reply)
					* Pod                         10.10.0.3:80->10.10.0.1:12345
					* CT zone SNAT 65521          10.10.0.3:80->10.10.0.1:12345            =>  10.10.0.3:80->192.168.77.1:12345
					* CT zone DNAT 65520          10.10.0.3:80->192.168.77.1:12345         =>  192.168.77.1:30001->192.168.77.1:12345
					* output
				  * packet 3 (request)
					* client                     192.168.77.1:12345->192.168.77.100:30001
					* CT zone SNAT 65521         192.168.77.1:12345->192.168.77.100:30001
					* CT zone DNAT 65520         192.168.77.1:12345->10.10.0.3:80
					* CT zone SNAT 65521         192.168.77.1:12345->10.10.0.3:80          =>  10.10.0.1:12345->10.10.0.3:80
					* output
				  * packet ...
			*/
			// The source IP address of pkt 3 cannot be transformed through zone 65521 (SNAT CT zone) since there is no
			// conntrack record about 192.168.77.1:12345<->192.168.77.100:30001, and the source IP is still 192.168.77.100.
			// Before output, packet 3 requires SNAT.
			// This generates the flow to perform SNAT for the subsequent request packets (not the first packet) of Service
			// connection that requires SNAT.
			SNATConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(ServiceSNATCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				MatchCTStateRpl(false).
				Action().CT(false, SNATConntrackCommitTable.ofTable.GetNext(), f.snatCtZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
		)
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: ConntrackStateStage
// Tables: SNATConntrackTable / ConntrackTable
// Refactored from:
//   - func (c *client) dnsResponseBypassConntrackFlow() binding.Flow
// dnsResponseBypassConntrackFlow generates the flow to bypass the dns response packetout from conntrack, to avoid unexpected
// packet drop. This flow should be installed on the first table of ConntrackStateStage.
func (f *featureNetworkPolicy) dnsResponseBypassConntrackFlow(table binding.Table) binding.Flow {
	return table.BuildFlow(priorityHigh).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Cookie(f.cookieAllocator.Request(cookie.Default).Raw()).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: AntreaPolicyIngressRuleTable
// Refactored from:
//   - func (c *client) dnsResponseBypassPacketInFlow() binding.Flow
// dnsResponseBypassPacketInFlow generates the flow to bypass the dns packetIn conjunction flow for dns response packetOut.
// This packetOut should be sent directly to the requesting client without being intercepted again.
func (f *featureNetworkPolicy) dnsResponseBypassPacketInFlow() binding.Flow {
	// TODO: use a unified register bit to mark packetOuts. The pipeline does not need to be
	// aware of why the packetOut is being set by the controller, it just needs to be aware that
	// this is a packetOut message and that some pipeline stages (conntrack, policy enforcement)
	// should therefore be skipped.
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSBypass).
		Cookie(f.cookieAllocator.Request(cookie.Default).Raw()).
		MatchRegFieldWithValue(CustomReasonField, CustomReasonDNS).
		Action().GotoStage(binding.OutputStage).
		Done()
}

// Feature: PodConnectivity
// flowsToTrace is used to generate flows for Traceflo.
// TODO: Use DuplicateToBuilder or integrate this function into original one to avoid unexpected difference.
// traceflowConnectionTrackFlows generates Traceflow specific flows in the connectionTrackStateTable or L2ForwardingCalcTable.
// When packet is not provided, the flows bypass the drop flow in conntrackStateFlow to avoid unexpected drop of the
// injected Traceflow packet, and to drop any Traceflow packet that has ct_state +rpl, which may happen when the Traceflow
// request destination is the Node's IP. When packet is provided, a flow is added to mark - the first packet of the first
// connection that matches the provided packet - as the Traceflow packet. The flow is added in connectionTrackStateTable
// when receiverOnly is false and it also matches in_port to be the provided ofPort (the sender Pod); otherwise when
// receiverOnly is true, the flow is added into L2ForwardingCalcTable and matches the destination MAC (the receiver Pod MAC).
// Refactored from:
//   - func (c *client) traceflowConnectionTrackFlows(dataplaneTag uint8, receiverOnly bool, packet *binding.Packet, ofPort uint32, timeout uint16, category cookie.Category) []binding.Flow
//   - part of func (c *client) traceflowL2ForwardOutputFlows(dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16, category cookie.Category) []binding.Flow
func (f *featurePodConnectivity) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	if packet == nil {
		for _, ipProtocol := range f.ipProtocols {
			flows = append(flows,
				ConntrackStateTable.ofTable.BuildFlow(priorityLow+1).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Action().GotoStage(binding.PreRoutingStage).
					Done(),
				ConntrackStateTable.ofTable.BuildFlow(priorityLow+2).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchCTStateTrk(true).
					MatchCTStateRpl(true).
					MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Action().Drop().
					Done(),
			)
		}
	} else {
		var flowBuilder binding.FlowBuilder
		if !receiverOnly {
			flowBuilder = ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchInPort(ofPort).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().LoadIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().GotoStage(binding.PreRoutingStage)
			if packet.DestinationIP != nil {
				flowBuilder = flowBuilder.MatchDstIP(packet.DestinationIP)
			}
		} else {
			flowBuilder = L2ForwardingCalcTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchDstMAC(packet.DestinationMAC).
				Action().LoadToRegField(TargetOFPortField, ofPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().LoadIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().GotoStage(binding.IngressSecurityStage)
			if packet.SourceIP != nil {
				flowBuilder = flowBuilder.MatchSrcIP(packet.SourceIP)
			}
		}
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
		flows = append(flows, flowBuilder.Done())
	}

	// Do not send to controller if captures only dropped packet.
	ifDroppedOnly := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if !droppedOnly {
			if ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		return fb
	}
	// Clear the loaded DSCP bits before output.
	ifLiveTraffic := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if liveTraffic {
			return fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		return fb
	}

	// This generates Traceflow specific flows that outputs traceflow non-hairpin packets to OVS port and Antrea Agent after
	// L2forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.networkConfig.TrafficEncapMode.SupportsEncap() {
			// SendToController and Output if output port is tunnel port.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.DefaultTunOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = ifDroppedOnly(fb)
			flows = append(flows, fb.Done())
			// For injected packets, only SendToController if output port is local gateway. In encapMode, a Traceflow
			// packet going out of the gateway port (i.e. exiting the overlay) essentially means that the Traceflow
			// request is complete.
			fb = L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		} else {
			// SendToController and Output if output port is local gateway. Unlike in encapMode, inter-Node Pod-to-Pod
			// traffic is expected to go out of the gateway port on the way to its destination.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+2).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout).
				Action().OutputToRegField(TargetOFPortField)
			fb = ifDroppedOnly(fb)
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is local gateway and destination IP is gateway.
		gatewayIP := f.gatewayIPs[ipProtocol]
		if gatewayIP != nil {
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal+3).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
				MatchProtocol(ipProtocol).
				MatchDstIP(gatewayIP).
				MatchRegMark(OFPortFoundRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		}
		// Only SendToController if output port is Pod port.
		fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal + 2).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(OFPortFoundRegMark).
			MatchIPDSCP(dataplaneTag).
			SetHardTimeout(timeout)
		fb = ifDroppedOnly(fb)
		fb = ifLiveTraffic(fb)
		flows = append(flows, fb.Done())
	}

	return flows
}

// Feature: Service
// flowsToTrace is used to generate flows for Traceflow.
// Refactored from:
//   - part of func (c *client) traceflowL2ForwardOutputFlows(dataplaneTag uint8, liveTraffic, droppedOnly bool, timeout uint16, category cookie.Category) []binding.Flow
func (f *featureService) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	// Do not send to controller if captures only dropped packet.
	ifDroppedOnly := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if !droppedOnly {
			if ovsMetersAreSupported {
				fb = fb.Action().Meter(PacketInMeterIDTF)
			}
			fb = fb.Action().SendToController(uint8(PacketInReasonTF))
		}
		return fb
	}
	// Clear the loaded DSCP bits before output.
	ifLiveTraffic := func(fb binding.FlowBuilder) binding.FlowBuilder {
		if liveTraffic {
			return fb.Action().LoadIPDSCP(0).
				Action().OutputToRegField(TargetOFPortField)
		}
		return fb
	}

	// This generates Traceflow specific flows that outputs hairpin traceflow packets to OVS port and Antrea Agent after
	// L2forwarding calculation.
	for _, ipProtocol := range f.ipProtocols {
		if f.enableProxy {
			// Only SendToController for hairpin traffic.
			// This flow must have higher priority than the one installed by l2ForwardOutputHairpinServiceFlow.
			fb := L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh + 2).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(HairpinRegMark).
				MatchIPDSCP(dataplaneTag).
				SetHardTimeout(timeout)
			fb = ifDroppedOnly(fb)
			fb = ifLiveTraffic(fb)
			flows = append(flows, fb.Done())
		}
	}
	return flows
}

// Feature: NetworkPolicy
// flowsToTrace is used to generate flows for Traceflow from globalConjMatchFlowCache and policyCache.
// Refactored from:
//   - func (c *client) traceflowNetworkPolicyFlows(dataplaneTag uint8, timeout uint16, category cookie.Category) []binding.Flow
func (f *featureNetworkPolicy) flowsToTrace(dataplaneTag uint8,
	ovsMetersAreSupported,
	liveTraffic,
	droppedOnly,
	receiverOnly bool,
	packet *binding.Packet,
	ofPort uint32,
	timeout uint16) []binding.Flow {
	cookieID := f.cookieAllocator.Request(cookie.Traceflow).Raw()
	var flows []binding.Flow
	f.conjMatchFlowLock.Lock()
	defer f.conjMatchFlowLock.Unlock()
	for _, ctx := range f.globalConjMatchFlowCache {
		if ctx.dropFlow != nil {
			copyFlowBuilder := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
			if ctx.dropFlow.FlowProtocol() == "" {
				copyFlowBuilderIPv6 := ctx.dropFlow.CopyToBuilder(priorityNormal+2, false)
				copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
				if f.ovsMetersAreSupported {
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
					Cookie(cookieID).
					SetHardTimeout(timeout).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
				copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
			}
			if f.ovsMetersAreSupported {
				copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
			}
			flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
				Cookie(cookieID).
				SetHardTimeout(timeout).
				Action().SendToController(uint8(PacketInReasonTF)).
				Done())
		}
	}
	// Copy Antrea NetworkPolicy drop rules.
	for _, conj := range f.policyCache.List() {
		for _, flow := range conj.(*policyRuleConjunction).metricFlows {
			if flow.IsDropFlow() {
				copyFlowBuilder := flow.CopyToBuilder(priorityNormal+2, false)
				// Generate both IPv4 and IPv6 flows if the original drop flow doesn't match IP/IPv6.
				// DSCP field is in IP/IPv6 headers so IP/IPv6 match is required in a flow.
				if flow.FlowProtocol() == "" {
					copyFlowBuilderIPv6 := flow.CopyToBuilder(priorityNormal+2, false)
					copyFlowBuilderIPv6 = copyFlowBuilderIPv6.MatchProtocol(binding.ProtocolIPv6)
					if f.ovsMetersAreSupported {
						copyFlowBuilderIPv6 = copyFlowBuilderIPv6.Action().Meter(PacketInMeterIDTF)
					}
					flows = append(flows, copyFlowBuilderIPv6.MatchIPDSCP(dataplaneTag).
						SetHardTimeout(timeout).
						Cookie(cookieID).
						Action().SendToController(uint8(PacketInReasonTF)).
						Done())
					copyFlowBuilder = copyFlowBuilder.MatchProtocol(binding.ProtocolIP)
				}
				if f.ovsMetersAreSupported {
					copyFlowBuilder = copyFlowBuilder.Action().Meter(PacketInMeterIDTF)
				}
				flows = append(flows, copyFlowBuilder.MatchIPDSCP(dataplaneTag).
					SetHardTimeout(timeout).
					Cookie(cookieID).
					Action().SendToController(uint8(PacketInReasonTF)).
					Done())
			}
		}
	}
	return flows
}

// Feature: PodConnectivity
// Stage: SwitchingStage
// Tables: L2ForwardingCalcTable
// Refactored from:
//   - func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, skipIngressRules bool, category cookie.Category) binding.Flow
// l2ForwardCalcFlow generates the flow to match the destination MAC and load the target ofPort to TargetOFPortField.
func (f *featurePodConnectivity) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32) binding.Flow {
	return L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchDstMAC(dstMAC).
		Action().LoadToRegField(TargetOFPortField, ofPort).
		Action().LoadRegMark(OFPortFoundRegMark).
		Action().NextTable().
		Done()
}

// Feature: Service
// Stage: OutputStage
// Tables: l2ForwardOutputFlow
// Refactored from:
//   - part of func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow
// l2ForwardOutputHairpinServiceFlow generates the flow to output the packets of hairpin Service connection with IN_PORT
// action.
func (f *featureService) l2ForwardOutputHairpinServiceFlow() binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(HairpinRegMark).
		Action().OutputInPort().
		Done()
}

// Feature: PodConnectivity
// Stage: OutputStage
// Tables: l2ForwardOutputFlow
// Refactored from:
//   - func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow
// Modifications:
//   - Remove hairpin related flow since it is moved to Feature Service.
// l2ForwardOutputFlow generates the flow to output the packets to target OVS port according to the value of TargetOFPortField.
func (f *featurePodConnectivity) l2ForwardOutputFlow() binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(OFPortFoundRegMark).
		Action().OutputToRegField(TargetOFPortField).
		Done()
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr, podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow
// l3FwdFlowToPod generates the flows to forward packets to a local Pod. For per-Node IPAM Pod, the flow rewrites destination
// MAC to the Pod interface's MAC, and rewrites source MAC to the Antrea gateway interface's MAC. For Antrea IPAM Pod, the
// flow only rewrites destination MAC to the Pod interface's MAC.
func (f *featurePodConnectivity) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr,
	podInterfaceIPs []net.IP,
	podInterfaceMAC net.HardwareAddr,
	isAntreaFlexibleIPAM bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		if isAntreaFlexibleIPAM {
			// This generates the flow to forward the packets to Antrea IPAM Pod.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common conditions are:
			//   - the traffic mode is noEncap.
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                            -- Service [request/reply]             --> Antrea Pod
			//   02. Antrea Pod                     -- Service [request/reply]             --> Antrea Pod
			//   03. Antrea Pod                     -- Service [request][hairpin]          --> Antrea Pod, HairpinRegMark
			//   04. Gateway                        -- Service [request]                   --> Antrea Pod
			//   05. External(via Gateway)          -- Service [request]                   --> Antrea Pod, NotRequireSNATRegMark(+new+trk)
			//   06. External(via Gateway)          -- Service [request]                   --> Antrea Pod, RequireSNATRegMark(+new+trk)
			//   07. Pod                            -- Connect [request/reply]             --> Antrea Pod
			//   08. Antrea Pod                     -- Connect [request/reply]             --> Antrea Pod, AntreaFlexibleIPAMRegMark
			//   09. Remote Pod(via Uplink)         -- Service [request/reply]             --> Antrea Pod
			//   10. Remote Pod(via Uplink)         -- Connect [request/reply]             --> Antrea Pod
			//   11. Remote Antrea Pod(via Uplink)  -- Service [request/reply]             --> Antrea Pod
			//   12. Remote Antrea Pod(via Uplink)  -- Connect [request/reply]             --> Antrea Pod
			//   13. Node(via Bridge)               -- Connect [request]                   --> Antrea Pod
			//   14. External(via Uplink)           -- Connect [request]                   --> Antrea Pod
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(ip).
				Action().SetDstMAC(podInterfaceMAC).
				Action().LoadRegMark(ToLocalRegMark).
				Action().NextTable().
				Done())
		} else {
			// This generates the flow to match the packets to per-Node IPAM Pod.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common conditions are:
			//   - with RewriteMACRegMark.
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                            -- Service [request/reply]             --> Pod
			//   02. Pod                            -- Service [request][hairpin]          --> Pod, HairpinRegMark
			//   03. Gateway                        -- Service [request]                   --> Pod, NotRequireSNATRegMark(+new+trk)
			//   04. Gateway                        -- Service [request]                   --> Pod, RequireSNATRegMark(+new+trk)
			//   05. Node(via Gateway)              -- Service [reply]                     --> Pod
			//   06. External(via Gateway)          -- Service [request]                   --> Pod, NotRequireSNATRegMark(+new+trk)
			//   07. External(via Gateway)          -- Service [request]                   --> Pod, RequireSNATRegMark(+new+trk)
			//   08. Antrea IPAM Pod                -- Service [request/reply][noEncap]    --> Pod, AntreaFlexibleIPAMRegMark
			//   09. Remote Pod(via Uplink)         -- Service [reply][Windows][noEncap]   --> Pod
			//   10. Remote Pod(via Uplink)         -- Connect [reply][Windows][noEncap]   --> Pod
			//   11. Remote Pod(via Tunnel)         -- Service [request][reply][encap]     --> Pod
			//   12. Remote Pod(via Tunnel)         -- Egress  [reply][Linux][encap]       --> Pod
			//   13. Remote Pod(via Tunnel)         -- Connect [request/reply][encap]      --> Pod
			//   14. Antrea Pod                     -- Connect [request/reply][noEncap]    --> Pod, AntreaFlexibleIPAMRegMark
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(RewriteMACRegMark).
				MatchDstIP(ip).
				Action().SetSrcMAC(localGatewayMAC).
				Action().SetDstMAC(podInterfaceMAC).
				Action().LoadRegMark(ToLocalRegMark).
				Action().NextTable().
				Done())
		}
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Requirements: networkPolicyOnly mode
// Refactored from:
//   - func (c *client) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow
// l3FwdFlowRouteToPod generates the flows to route the packets to a Pod based on the destination IP. It rewrites destination
// MAC to the Pod interface's MAC. The flows are used in networkPolicyOnly mode to match the packets from the Antrea gateway.
func (f *featurePodConnectivity) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().LoadRegMark(ToLocalRegMark).
			Action().NextTable().
			Done())
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Requirements: networkPolicyOnly mode
// Refactored from:
//   - func (c *client) l3FwdFlowRouteToGW(gwMAC net.HardwareAddr, category cookie.Category) []binding.Flow
// l3FwdFlowRouteToGW generates the flows to route the packets to the Antrea gateway. It rewrites destination MAC to the
// Antrea gateway interface's MAC. The flows are used in networkPolicyOnly mode to match the packets sourced from a local Pod
// and destined for remote Pods, Nodes, or external network.
func (f *featurePodConnectivity) l3FwdFlowRouteToGW() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().NextTable().
			Done(),
		)
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) l3FwdFlowToGateway(localGatewayIPs []net.IP, localGatewayMAC net.HardwareAddr, category cookie.Category) []binding.Flow`
// l3FwdFlowToGateway generates the flows to match the packets destined for the Antrea gateway.
func (f *featurePodConnectivity) l3FwdFlowToGateway() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, gatewayIP := range f.gatewayIPs {
		flows = append(flows,
			// This generates the flow to match the packets destined for the Antrea gateway with RewriteMACRegMark.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common conditions are:
			//   - with RewriteMACRegMark
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                       -- Service [reply]                              --> Gateway
			//   02. Remote Pod(via Tunnel)    -- Service [reply][encap]                       --> Gateway
			//   03. Remote Pod(via Tunnel)    -- Connect [request/reply][encap]               --> Gateway
			//   04. Antrea Pod                -- Service [reply][noEncap]                     --> Gateway, AntreaFlexibleIPAMRegMark
			//   05. Node(via Gateway)         -- Service [reply][hairpin]                     --> Gateway
			//   06. External(via Gateway)     -- Service [reply][hairpin]                     --> Gateway
			//   07. Remote Pod(via Uplink)    -- Connect [request][noEncap][Windows]          --> Gateway
			//   08. Remote Pod(via Uplink)    -- Service [reply][noEncap][Windows]            --> Gateway
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(RewriteMACRegMark).
				MatchDstIP(gatewayIP).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().NextTable().
				Done(),
			// This generates the flow to match the packets destined for the Antrea gateway without RewriteMACRegMark.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common conditions are:
			//   - without RewriteMACRegMark
			//   - Pod / Antrea Pod is not in host network.
			// The traffic model is:
			//   01. Pod                            -- Connect [request/reply]                     --> Gateway
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(NotRewriteMACRegMark).
				MatchDstIP(gatewayIP).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done(),
		)
		// This generates the flow to match the reply packets of connection with FromGatewayCTMark from local Pods.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		// Corresponding traffic models are:
		//   01. Pod                       -- Service [reply]         --> Pod, AntreaProxy is disabled and kube-proxy is used.
		//   02. Pod                       -- NodePortLocal [reply]   --> Pod, AntreaProxy is enabled or not.
		flows = append(flows,
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromLocalRegMark).
				MatchCTMark(FromGatewayCTMark).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())
		// When encap mode is enabled, this generates the flow to match the reply packets of connection with FromGatewayCTMark
		// from remote Pods via tunnel.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		// Corresponding traffic models are:
		//   01. Remote Pod(via Tunnel)    -- Service [reply]         --> Pod, AntreaProxy is disabled and kube-proxy is used.
		//   02. Remote Pod(via Tunnel)    -- NodePortLocal [reply]   --> Pod, AntreaProxy is enabled or not.
		if f.networkConfig.TrafficEncapMode.SupportsEncap() {
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromTunnelRegMark).
				MatchCTMark(FromGatewayCTMark).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())
		}
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) l3FwdFlowToRemote(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP, category cookie.Category) binding.Flow
// l3FwdFlowToRemoteViaTun generates the flow to forward the packets to remote Nodes through tunnel.
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaTun(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP) binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	// For simplicity, in the following:
	//   - per-Node IPAM Pod is referred to as Pod.
	//   - Antrea IPAM Pod is referred to as Antrea Pod.
	// The common conditions are:
	//   - the traffic mode is encap.
	//   - Pod / Antrea Pod is not in host network.
	// Corresponding traffic models are:
	//   01. Pod          -- Service [request/reply]      --> Remote Pod
	//   02. Pod          -- Connect [request/reply]      --> Remote Pod
	//   03. Gateway      -- Service [request]            --> Remote Pod, RequireSNATRegMark(+new+trk)
	//   04. Gateway      -- Connect [request/reply]      --> Remote Pod
	//   05. External     -- Service [request]            --> Remote Pod, RequireSNATRegMark(+new+trk)
	//   06. External     -- Egress  [reply][Linux]       --> Remote Pod
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet).
		Action().SetSrcMAC(localGatewayMAC).  // Rewrite src MAC to local gateway MAC.
		Action().SetDstMAC(GlobalVirtualMAC). // Rewrite dst MAC to virtual MAC.
		Action().SetTunnelDst(tunnelPeer).    // Flow based tunnel. Set tunnel destination.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Done()
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) l3FwdFlowToRemoteViaGW(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, category cookie.Category, isAntreaFlexibleIPAM bool) binding.Flow
// l3FwdFlowToRemoteViaGW generates the flow to forward the packets to remote Nodes through the Antrea gateway. It is used
// when the cross-Node connections that do not require encapsulation (in noEncap, networkPolicyOnly, or hybrid mode).
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaGW(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(peerSubnet.IP)
	// For simplicity, in the following:
	//   - per-Node IPAM Pod is referred to as Pod.
	//   - Antrea IPAM Pod is referred to as Antrea Pod.
	// The common conditions are:
	//   - traffic mode is noEncap.
	//   - Pod / Antrea Pod is not in host network.
	//   - for a Linux Node, this is used to forward packets to other remote Nodes.
	//   - for a Windows Node, this is used to forward packets other Nodes whose transport interface MAC is unknown.
	// Corresponding traffic models are:
	//   01. Pod          -- Service [request/reply]      --> Remote Pod
	//   02. Pod          -- Connect [request/reply]      --> Remote Pod
	//   03. Gateway      -- Service [request][hairpin]   --> Remote Pod, RequireSNATRegMark(+new+trk)
	//   04. External     -- Service [request][hairpin]   --> Remote Pod, RequireSNATRegMark(+new+trk)
	if f.connectUplinkToBridge {
		return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(peerSubnet).
			MatchRegMark(NotAntreaFlexibleIPAMRegMark). // To distinguish the packets from Antrea IPAM Pod.
			Action().SetDstMAC(localGatewayMAC).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().NextTable().
			Done()
	}
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet).
		Action().SetDstMAC(localGatewayMAC).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().NextTable().
		Done()
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// l3FwdFlowToRemoteViaUplink generates the flow to forward the packets to remote Nodes through uplink. It is used when
// the cross-Node connections that do not require encapsulation (in noEncap, networkPolicyOnly, hybrid mode).
func (f *featurePodConnectivity) l3FwdFlowToRemoteViaUplink(remoteGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	isAntreaFlexibleIPAM bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(peerSubnet.IP)
	var flows []binding.Flow
	if !isAntreaFlexibleIPAM {
		// The following two functions generate the flows to forward the packets from per-Node IPAM Pod to remote Nodes.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		//   - Antrea IPAM Pod is referred to as Antrea Pod.
		// The common conditions are:
		//   - traffic mode is noEncap.
		//   - Pod / Antrea Pod is not in host network.
		//   - for a Windows Node, this is used to forward the packets to other Nodes whose transport interface's MAC is unknown.
		// Corresponding traffic models are:
		//   01. Pod          -- Service [request/reply]      --> Remote Pod
		//   02. Pod          -- Connect [request/reply]      --> Remote Pod
		//   03. Gateway      -- Service [reply]              --> Remote Pod, RequireSNATRegMark(+new+trk)
		//   04. Gateway      -- Connect [reply]              --> Remote Pod
		flows = append(flows,
			// This generates the flow to forward the packets to remote Nodes directly through uplink interface without
			// passing through the Antrea gateway by rewriting destination MAC to remote Node Antrea gateway's MAC. Note
			// that, this is only for per-Node IPAM Pods and used in Windows Nodes when traffic mode is noEncap.
			L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(NotAntreaFlexibleIPAMRegMark).
				MatchDstIPNet(peerSubnet).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().LoadRegMark(ToUplinkRegMark).
				Action().NextTable().
				Done(),
			// This generates the flow to forward packets to remote Nodes directly by matching destination MAC and setting
			// output interface to uplink interface.
			L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchDstMAC(remoteGatewayMAC).
				Action().LoadToRegField(TargetOFPortField, config.UplinkOFPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().GotoStage(binding.ConntrackStage).
				Done())
	} else {
		// The following function generate the flow to forward the packets from Antrea IPAM Pod to remote Nodes by rewriting
		// destination MAC to Antrea gateway's MAC of remote Nodes.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		//   - Antrea IPAM Pod is referred to as Antrea Pod.
		// The common conditions are:
		//   - traffic mode is noEncap.
		//   - Pod / Antrea Pod is not in host network.
		//   - Linux Node only.
		// Corresponding traffic models are:
		//   01. Antrea Pod          -- Service [request/reply]   --> Remote Pod
		//   02. Antrea Pod          -- Connect [request/reply]   --> Remote Pod
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(AntreaFlexibleIPAMRegMark).
			MatchDstIPNet(peerSubnet).
			Action().SetDstMAC(remoteGatewayMAC).
			Action().LoadRegMark(ToUplinkRegMark).
			Action().NextTable().
			Done())
	}
	return flows
}

// Feature: PodConnectivity
// Stage: OutputStage
// Tables: ARPResponderTable
// Refactored from:
//   - func (c *client) arpResponderFlow(peerGatewayIP net.IP, category cookie.Category) binding.Flow
// Modification:
//  - Response arp request with specific MAC address.
// arpResponderFlow generates the flow to response the ARP request with a MAC address for target IP address.
func (f *featurePodConnectivity) arpResponderFlow(ipAddr net.IP, macAddr net.HardwareAddr) binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		MatchARPTpa(ipAddr).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(macAddr).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(macAddr).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().SetARPSpa(ipAddr).
		Action().OutputInPort().
		Done()
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Tables: ARPResponderTable
// Requirements: networkPolicyOnly mode.
// Refactored from:
//   - func (c *client) arpResponderStaticFlow(category cookie.Category) binding.Flow
// arpResponderStaticFlow generates the flow to reply for any ARP request with the same global virtual MAC. It is used
// in policy-only mode, where traffic are routed via IP not MAC.
func (f *featurePodConnectivity) arpResponderStaticFlow() binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
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

// Feature: PodConnectivity
// Stage: ValidationStage
// Tables: SpoofGuardTable
// Refactored from:
//   - func (c *client) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) []binding.Flow
// podIPSpoofGuardFlow generates the flow to check IP packets from local Pods. Packets from the Antrea gateway will not be
// checked, since it might be Pod to Service connection or host namespace connection.
func (f *featurePodConnectivity) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ifIP := range ifIPs {
		ipProtocol := getIPProtocol(ifIP)
		targetTable := SpoofGuardTable.ofTable.GetNext()
		if ipProtocol == binding.ProtocolIPv6 {
			targetTable = IPv6Table.ofTable.GetID()
		}
		flows = append(flows, SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchInPort(ifOFPort).
			MatchSrcMAC(ifMAC).
			MatchSrcIP(ifIP).
			Action().ResubmitToTables(targetTable).
			Done())
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

// Feature: PodConnectivity
// Stage: ValidationStage
// Tables: ARPSpoofGuardTable
// Refactored from:
//  - func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow
//  - func (c *client) gatewayARPSpoofGuardFlows(gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow)
// Modification:
// - Removed function gatewayARPSpoofGuardFlows.
// arpSpoofGuardFlow generates the flow to check the ARP packets source from local Pods or the Antrea gateway.
func (f *featurePodConnectivity) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) binding.Flow {
	return ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().NextTable().
		Done()
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: EndpointDNATTable
// Refactored from:
//   - func (c *client) sessionAffinityReselectFlow() binding.Flow
// sessionAffinityReselectFlow generates the flow which resubmits the Service accessing packet back to ServiceLBTable
// if there is no endpointDNAT flow matched. This case will occur if an Endpoint is removed and is the learned Endpoint
// selection of the Service.
func (f *featureService) sessionAffinityReselectFlow() binding.Flow {
	return EndpointDNATTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(EpSelectedRegMark).
		Action().LoadRegMark(EpToSelectRegMark).
		Action().ResubmitToTables(ServiceLBTable.ofTable.GetID()).
		Done()
}

// Feature: PodConnectivity
// Stage: ValidationStage
// Tables: SpoofGuardTable
// Refactored from:
//   - func (c *client) gatewayIPSpoofGuardFlows(category cookie.Category) []binding.Flow
// gatewayIPSpoofGuardFlows generates the flow to skip spoof guard checking for packets from the Antrea gateway.
func (f *featurePodConnectivity) gatewayIPSpoofGuardFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		targetTable := SpoofGuardTable.ofTable.GetNext()
		if ipProtocol == binding.ProtocolIPv6 {
			targetTable = IPv6Table.ofTable.GetID()
		}
		flows = append(flows,
			SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchInPort(config.HostGatewayOFPort).
				Action().ResubmitToTables(targetTable).
				Done(),
		)
	}
	return flows
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: DNATTable
// Requirements: AntreaProxy is disabled
// Refactored from:
//   - func (c *client) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet) []binding.Flow
// serviceCIDRDNATFlows generates the flows to match destination IP in Service CIDR and output to the Antrea gateway directly.
func (f *featureService) serviceCIDRDNATFlows(serviceCIDRs []*net.IPNet) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, serviceCIDR := range serviceCIDRs {
		if serviceCIDR != nil {
			ipProtocol := getIPProtocol(serviceCIDR.IP)
			flows = append(flows, DNATTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIPNet(*serviceCIDR).
				Action().LoadToRegField(TargetOFPortField, config.HostGatewayOFPort).
				Action().LoadRegMark(OFPortFoundRegMark).
				Action().GotoStage(binding.ConntrackStage).
				Done())
		}
	}
	return flows
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: SessionAffinityTable
// Refactored from:
//   - func (c *client) serviceNeedLBFlow() binding.Flow
// serviceNeedLBFlow generates the default flow to mark packets with EpToSelectRegMark.
func (f *featureService) serviceNeedLBFlow() binding.Flow {
	return SessionAffinityTable.ofTable.BuildFlow(priorityMiss).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Action().LoadRegMark(EpToSelectRegMark).
		Done()
}

// Feature: PodConnectivity
// Stage: OutputStage
// Tables: ARPResponderTable
// Refactored from:
//   - func (c *client) arpNormalFlow(category cookie.Category) binding.Flow
// arpNormalFlow generates the flow to response the ARP request packets in normal way if no flow in ARPResponderTable is matched.
func (f *featurePodConnectivity) arpNormalFlow() binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage / EgressSecurityStage
// Tables: IngressMetricTable / EgressMetricTable.
// Refactored from:
//   - func (c *client) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow
func (f *featureNetworkPolicy) allowRulesMetricFlows(conjunctionID uint32, ingress bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
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
			Cookie(cookieID).
			MatchProtocol(protocol).
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
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows, metricFlow(true, ipProtocol), metricFlow(false, ipProtocol))
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage / EgressSecurityStage
// Tables: IngressMetricTable / EgressMetricTable.
// Refactored from:
//   - func (c *client) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow
func (f *featureNetworkPolicy) denyRuleMetricFlow(conjunctionID uint32, ingress bool) binding.Flow {
	metricTable := IngressMetricTable
	if !ingress {
		metricTable = EgressMetricTable
	}
	return metricTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(CnpDenyRegMark).
		MatchRegFieldWithValue(CNPDenyConjIDField, conjunctionID).
		Action().Drop().
		Done()
}

// Feature: PodConnectivity
// Stage: ValidationStage
// Tables: SpoofGuardTable, IPv6Table
// Refactored from:
//   - func (c *client) ipv6Flows(category cookie.Category) []binding.Flow
// ipv6Flows generates the flows to allow IPv6 packets from link-local addresses and handle multicast packets, Neighbor
// Solicitation and ND Advertisement packets properly.
func (f *featurePodConnectivity) ipv6Flows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	_, ipv6LinkLocalIpnet, _ := net.ParseCIDR(ipv6LinkLocalAddr)
	_, ipv6MulticastIpnet, _ := net.ParseCIDR(ipv6MulticastAddr)
	flows = append(flows,
		// Allow IPv6 packets (e.g. Multicast Listener Report Message V2) which are sent from link-local addresses in
		// SpoofGuardTable, so that these packets will not be dropped.
		SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIPv6).
			MatchSrcIPNet(*ipv6LinkLocalIpnet).
			Action().ResubmitToTables(IPv6Table.ofTable.GetID()).
			Done(),
		// Handle IPv6 Neighbor Solicitation and Neighbor Advertisement as a regular L2 learning Switch by using normal.
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(135).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(136).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		// Handle IPv6 multicast packets as a regular L2 learning Switch by using normal.
		// It is used to ensure that all kinds of IPv6 multicast packets are properly handled (e.g. Multicast Listener
		// Report Message V2).
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIPv6).
			MatchDstIPNet(*ipv6MulticastIpnet).
			Action().Normal().
			Done(),
	)
	return flows
}

// conjunctionActionFlow generates the flow to jump to a specific table if policyRuleConjunction ID is matched. Priority of
// conjunctionActionFlow is created at priorityLow for k8s network policies, and *priority assigned by PriorityAssigner for AntreaPolicy.
func (f *featureNetworkPolicy) conjunctionActionFlow(conjunctionID uint32, table binding.Table, nextTable uint8, priority *uint16, enableLogging bool) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var ofPriority uint16
	if priority == nil {
		ofPriority = priorityLow
	} else {
		ofPriority = *priority
	}
	conjReg := TFIngressConjIDField
	labelField := IngressRuleCTLabel
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
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
			if f.ovsMetersAreSupported {
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
				Cookie(cookieID).
				Done()
		}
		return table.BuildFlow(ofPriority).MatchProtocol(proto).
			MatchConjID(conjunctionID).
			Action().LoadToRegField(conjReg, conjunctionID). // Traceflow.
			Action().CT(true, nextTable, ctZone).            // CT action requires commit flag if actions other than NAT without arguments are specified.
			LoadToLabelField(uint64(conjunctionID), labelField).
			CTDone().
			Cookie(cookieID).
			Done()
	}
	var flows []binding.Flow
	for _, proto := range f.ipProtocols {
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
func (f *featureNetworkPolicy) conjunctionActionDenyFlow(conjunctionID uint32, table binding.Table, priority *uint16, disposition uint32, enableLogging bool) binding.Flow {
	ofPriority := *priority
	metricTable := IngressMetricTable
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
		metricTable = EgressMetricTable
	}

	flowBuilder := table.BuildFlow(ofPriority).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CNPDenyConjIDField, conjunctionID).
		Action().LoadRegMark(CnpDenyRegMark)

	var customReason int
	if f.enableDenyTracking {
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

	if enableLogging || f.enableDenyTracking || disposition == DispositionRej {
		if f.ovsMetersAreSupported {
			flowBuilder = flowBuilder.Action().Meter(PacketInMeterIDNP)
		}
		flowBuilder = flowBuilder.
			Action().LoadToRegField(CustomReasonField, uint32(customReason)).
			Action().SendToController(uint8(PacketInReasonNP))
	}

	// We do not drop the packet immediately but send the packet to the metric table to update the rule metrics.
	return flowBuilder.Action().ResubmitToTables(metricTable.GetID()).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Done()
}

func (f *featureNetworkPolicy) conjunctionActionPassFlow(conjunctionID uint32, table binding.Table, priority *uint16, enableLogging bool) binding.Flow {
	ofPriority := *priority
	conjReg := TFIngressConjIDField
	nextTable := IngressRuleTable
	tableID := table.GetID()
	if _, ok := f.egressTables[tableID]; ok {
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
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
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
func (f *featureNetworkPolicy) establishedConnectionFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the established connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var allEstFlows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressEstFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
			Done()
		ingressEstFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateEst(true).
			Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
			Done()
		allEstFlows = append(allEstFlows, egressEstFlow, ingressEstFlow)
	}
	if !f.enableAntreaPolicy {
		return allEstFlows
	}
	var apFlows []binding.Flow
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apEgressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateEst(true).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			apFlows = append(apFlows, apEgressEstFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apIngressEstFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
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
func (f *featureNetworkPolicy) relatedConnectionFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Packets in the related connections need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressRelFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().ResubmitToTables(egressDropTable.GetNext()).
			Done()
		ingressRelFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchCTStateNew(false).
			MatchCTStateRel(true).
			Action().ResubmitToTables(ingressDropTable.GetNext()).
			Done()
		flows = append(flows, egressRelFlow, ingressRelFlow)
	}
	if !f.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProto := range f.ipProtocols {
			apEgressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProto).
				MatchCTStateNew(false).
				MatchCTStateRel(true).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apEgressRelFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProto := range f.ipProtocols {
			apIngressRelFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
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
func (f *featureNetworkPolicy) rejectBypassNetworkpolicyFlows() []binding.Flow {
	// egressDropTable checks the source address of packets, and drops packets sent from the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// egressRuleTable or the egressDropTable.
	egressDropTable := EgressDefaultTable
	// ingressDropTable checks the destination address of packets, and drops packets sent to the AppliedToGroup but not
	// matching the NetworkPolicy rules. Generated reject responses need not to be checked with the
	// ingressRuleTable or ingressDropTable.
	ingressDropTable := IngressDefaultTable
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		egressRejFlow := EgressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().ResubmitToTables(egressDropTable.GetNext()).
			Done()
		ingressRejFlow := IngressRuleTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
			Action().ResubmitToTables(ingressDropTable.GetID()).
			Done()
		flows = append(flows, egressRejFlow, ingressRejFlow)
	}
	if !f.enableAntreaPolicy {
		return flows
	}
	for _, table := range GetAntreaPolicyEgressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apEgressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().ResubmitToTables(egressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apEgressRejFlow)
		}
	}
	for _, table := range GetAntreaPolicyIngressTables() {
		for _, ipProtocol := range f.ipProtocols {
			apIngressRejFlow := table.ofTable.BuildFlow(priorityTopAntreaPolicy).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegFieldWithValue(CustomReasonField, CustomReasonReject).
				Action().ResubmitToTables(ingressDropTable.ofTable.GetNext()).
				Done()
			flows = append(flows, apIngressRejFlow)
		}
	}
	return flows
}

func (f *featureNetworkPolicy) addFlowMatch(fb binding.FlowBuilder, matchKey *types.MatchKey, matchValue interface{}) binding.FlowBuilder {
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
func (f *featureNetworkPolicy) conjunctionExceptionFlow(conjunctionID uint32, tableID uint8, nextTable uint8, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	conjReg := TFIngressConjIDField
	if tableID == EgressRuleTable.GetID() {
		conjReg = TFEgressConjIDField
	}
	fb := getTableByID(tableID).BuildFlow(priorityNormal).MatchConjID(conjunctionID)
	return f.addFlowMatch(fb, matchKey, matchValue).
		Action().LoadToRegField(conjReg, conjunctionID). // Traceflow.
		Action().GotoTable(nextTable).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Done()
}

// conjunctiveMatchFlow generates the flow to set conjunctive actions if the match condition is matched.
func (f *featureNetworkPolicy) conjunctiveMatchFlow(tableID uint8, matchKey *types.MatchKey, matchValue interface{}, priority *uint16, actions []*conjunctiveAction) binding.Flow {
	var ofPriority uint16
	if priority != nil {
		ofPriority = *priority
	} else {
		ofPriority = priorityNormal
	}
	fb := getTableByID(tableID).BuildFlow(ofPriority)
	fb = f.addFlowMatch(fb, matchKey, matchValue)
	if f.deterministic {
		sort.Sort(conjunctiveActionsInOrder(actions))
	}
	for _, act := range actions {
		fb.Action().Conjunction(act.conjID, act.clauseID, act.nClause)
	}
	return fb.Cookie(f.cookieAllocator.Request(f.category).Raw()).Done()
}

// defaultDropFlow generates the flow to drop packets if the match condition is matched.
func (f *featureNetworkPolicy) defaultDropFlow(table binding.Table, matchKey *types.MatchKey, matchValue interface{}) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	fb := table.BuildFlow(priorityNormal)
	if f.enableDenyTracking {
		return f.addFlowMatch(fb, matchKey, matchValue).
			Action().Drop().
			Action().LoadRegMark(DispositionDropRegMark).
			Action().LoadRegMark(CustomReasonDenyRegMark).
			Action().SendToController(uint8(PacketInReasonNP)).
			Cookie(cookieID).
			Done()
	}
	return f.addFlowMatch(fb, matchKey, matchValue).
		Action().Drop().
		Cookie(cookieID).
		Done()
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: AntreaPolicyIngressRuleTable
// Refactored from:
//   - func (c *client) dnsPacketInFlow(conjunctionID uint32) binding.Flow
// dnsPacketInFlow generates the flow to send dns response packets of fqdn policy selected Pods to the fqdnController for
// processing.
func (f *featureNetworkPolicy) dnsPacketInFlow(conjunctionID uint32) binding.Flow {
	return AntreaPolicyIngressRuleTable.ofTable.BuildFlow(priorityDNSIntercept).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchConjID(conjunctionID).
		Action().LoadToRegField(CustomReasonField, CustomReasonDNS).
		Action().SendToController(uint8(PacketInReasonNP)).
		Done()
}

// Feature: PodConnectivity
// Stage: IngressSecurityStage
// Tables: IngressSecurityClassifierTable
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
func (f *featurePodConnectivity) localProbeFlow(ovsDatapathType ovsconfig.OVSDatapathType) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	if runtime.IsWindowsPlatform() || ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		for ipProtocol, gatewayIP := range f.gatewayIPs {
			flows = append(flows, IngressSecurityClassifierTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchSrcIP(gatewayIP).
				Action().GotoStage(binding.ConntrackStage).
				Done())
		}
	} else {
		flows = append(flows, IngressSecurityClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchPktMark(types.HostLocalSourceMark, &types.HostLocalSourceMark).
			Action().GotoStage(binding.ConntrackStage).
			Done())
	}
	return flows
}

// Feature: NetworkPolicy
// Stage: IngressSecurityStage
// Tables: IngressSecurityClassifierTable
// ingressClassifierFlows generates the flows to classify the packets from local Pods or the Antrea gateway to different
// tables within IngressSecurityStage.
func (f *featureNetworkPolicy) ingressClassifierFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to forward the packets to local Pod to next table in IngressSecurityStage.
		IngressSecurityClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(ToLocalRegMark).
			Action().NextTable().
			Done(),
		// This generates the default flow to forward the packets to the last table IngressSecurityStage.
		IngressSecurityClassifierTable.ofTable.BuildFlow(priorityMiss).
			Cookie(cookieID).
			Action().GotoTable(IngressMetricTable.GetID()).
			Done(),
	}
}

// Feature: Egress
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow
// snatSkipNodeFlow generates the flow to skip SNAT for connection destined for the transport IP of a remote Node.
func (f *featureEgress) snatSkipNodeFlow(nodeIP net.IP) binding.Flow {
	ipProtocol := getIPProtocol(nodeIP)
	// This generates the flow to match the packets to the remote Node IP.
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchRegMark(NotRewriteMACRegMark). // Excluding Service traffic.
		MatchRegMark(FromLocalRegMark).
		MatchDstIP(nodeIP).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: Egress
// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - func (c *client) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow
// snatIPFromTunnelFlow generates the flow that marks SNAT packets tunnelled from remote Nodes. The SNAT IP matches the
// packet's tunnel destination IP.
func (f *featureEgress) snatIPFromTunnelFlow(snatIP net.IP, mark uint32) binding.Flow {
	ipProtocol := getIPProtocol(snatIP)
	return SNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchRegMark(EgressRegMark).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchTunnelDst(snatIP).
		Action().SetDstMAC(f.gatewayMAC).
		Action().LoadPktMarkRange(mark, snatPktMarkRange).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: Egress
// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - func (c *client) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow
// snatRuleFlow generates the flow that applies the SNAT rule for a local Pod. If the SNAT IP exists on the local Node,
// it sets the packet mark with the ID of the SNAT IP, for the traffic from local Pod to external; if the SNAT IP is
// on a remote Node, it tunnels the packets to the remote Node.
func (f *featureEgress) snatRuleFlow(ofPort uint32, snatIP net.IP, snatMark uint32, localGatewayMAC net.HardwareAddr) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	ipProtocol := getIPProtocol(snatIP)
	if snatMark != 0 {
		// Local SNAT IP.
		return SNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchRegMark(EgressRegMark).
			MatchCTStateNew(true).
			MatchCTStateTrk(true).
			MatchInPort(ofPort).
			Action().LoadPktMarkRange(snatMark, snatPktMarkRange).
			Action().GotoStage(binding.SwitchingStage).
			Done()
	}
	// SNAT IP should be on a remote Node.
	return SNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchProtocol(ipProtocol).
		MatchRegMark(EgressRegMark).
		MatchInPort(ofPort).
		Action().SetSrcMAC(localGatewayMAC).
		Action().SetDstMAC(GlobalVirtualMAC).
		Action().SetTunnelDst(snatIP). // Set tunnel destination to the SNAT IP.
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: NodePortMarkTable
// Refactored from:
//   - func (c *client) serviceClassifierFlows(nodePortAddresses []net.IP, ipProtocol binding.Protocol) []binding.Flow
// nodePortMarkFlows generates the flows to mark the first packet of Service NodePort connection with ToNodePortAddressRegMark,
// which indicates the Service type is NodePort.
func (f *featureService) nodePortMarkFlows(nodePortAddresses []net.IP, ipProtocol binding.Protocol) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	// This generates a flow for every NodePort IP. The flows are used to mark the first packet of NodePort connections
	// from a local Pod.
	for i := range nodePortAddresses {
		flows = append(flows,
			NodePortMarkTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodePortAddresses[i]).
				Action().LoadRegMark(ToNodePortAddressRegMark).
				Done())
	}
	// This generates the flow for the virtual IP. The flow is used to mark the first packet of NodePort connection from
	// the Antrea gateway (the connection is performed DNAT with the virtual IP in host netns).
	flows = append(flows,
		NodePortMarkTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(f.virtualIPs[ipProtocol]).
			Action().LoadRegMark(ToNodePortAddressRegMark).
			Done())

	return flows
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: SessionAffinityTable
// Refactored from:
//   - func (c *client) serviceLearnFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow
// serviceLearnFlow generates the flow with learn action which adds new flows in SessionAffinityTable according to the
// Endpoint selection decision.
func (f *featureService) serviceLearnFlow(groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	affinityTimeout uint16,
	nodeLocalExternal bool,
	serviceType v1.ServiceType) binding.Flow {
	// Using unique cookie ID here to avoid learned flow cascade deletion.
	cookieID := f.cookieAllocator.RequestWithObjectID(f.category, uint32(groupID)).Raw()
	var flowBuilder binding.FlowBuilder
	if serviceType == v1.ServiceTypeNodePort {
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToLearnRegMark.GetValue()
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil)
	} else {
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegMark(EpToLearnRegMark).
			MatchDstIP(svcIP).
			MatchDstPort(svcPort, nil)
	}

	// affinityTimeout is used as the OpenFlow "hard timeout": learned flow will be removed from
	// OVS after that time regarding of whether traffic is still hitting the flow. This is the
	// desired behavior based on the K8s spec. Note that existing connections will keep going to
	// the same endpoint because of connection tracking; and that is also the desired behavior.
	learnFlowBuilderLearnAction := flowBuilder.
		Action().Learn(SessionAffinityTable.ofTable.GetID(), priorityNormal, 0, affinityTimeout, cookieID).
		DeleteLearned()
	switch protocol {
	case binding.ProtocolTCP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPDstPort()
	case binding.ProtocolUDP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPDstPort()
	case binding.ProtocolSCTP:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPDstPort()
	case binding.ProtocolTCPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedTCPv6DstPort()
	case binding.ProtocolUDPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedUDPv6DstPort()
	case binding.ProtocolSCTPv6:
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.MatchLearnedSCTPv6DstPort()
	}
	// If externalTrafficPolicy of NodePort/LoadBalancer is Cluster, the learned flow which
	// is used to match the first packet of NodePort/LoadBalancer also requires SNAT.
	if (serviceType == v1.ServiceTypeNodePort || serviceType == v1.ServiceTypeLoadBalancer) && !nodeLocalExternal {
		learnFlowBuilderLearnAction = learnFlowBuilderLearnAction.LoadRegMark(RequireSNATRegMark)
	}

	ipProtocol := getIPProtocol(svcIP)
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
			Action().NextTable().
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
			Action().NextTable().
			Done()
	}
	return nil
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: ServiceLBTable
// Refactored from:
//   - func (c *client) serviceLBFlow(groupID binding.GroupIDType, svcIP net.IP, svcPort uint16, protocol binding.Protocol, withSessionAffinity, nodeLocalExternal bool, svcType v1.ServiceType) binding.Flow
// serviceLBFlow generates the flow which uses the specific group to do Endpoint selection.
func (f *featureService) serviceLBFlow(groupID binding.GroupIDType,
	svcIP net.IP,
	svcPort uint16,
	protocol binding.Protocol,
	withSessionAffinity,
	nodeLocalExternal bool,
	serviceType v1.ServiceType) binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var lbResultMark *binding.RegMark
	if withSessionAffinity {
		lbResultMark = EpToLearnRegMark
	} else {
		lbResultMark = EpSelectedRegMark
	}
	var flowBuilder binding.FlowBuilder
	if serviceType == v1.ServiceTypeNodePort {
		// If externalTrafficPolicy of NodePort is Cluster, the first packet of NodePort requires SNAT, so nodeLocalExternal
		// will be false, and ServiceNeedSNATRegMark will be set. If externalTrafficPolicy of NodePort is Local, the first
		// packet of NodePort doesn't require SNAT, ServiceNeedSNATRegMark won't be set.
		unionVal := (ToNodePortAddressRegMark.GetValue() << ServiceEPStateField.GetRange().Length()) + EpToSelectRegMark.GetValue()
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchRegFieldWithValue(NodePortUnionField, unionVal).
			MatchDstPort(svcPort, nil).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(RequireSNATRegMark)
		}
	} else {
		// If Service type is LoadBalancer, as above NodePort.
		flowBuilder = ServiceLBTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(protocol).
			MatchDstPort(svcPort, nil).
			MatchDstIP(svcIP).
			MatchRegMark(EpToSelectRegMark).
			Action().LoadRegMark(lbResultMark).
			Action().LoadRegMark(RewriteMACRegMark)
		if serviceType == v1.ServiceTypeLoadBalancer && !nodeLocalExternal {
			flowBuilder = flowBuilder.Action().LoadRegMark(RequireSNATRegMark)
		}
	}
	return flowBuilder.
		Action().LoadToRegField(ServiceGroupIDField, uint32(groupID)).
		Action().Group(groupID).Done()
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: EndpointDNATTable
// Refactored from:
//   - func (c *client) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow
// endpointDNATFlow generates the flow which transforms the Service Cluster IP to the Endpoint IP according to the Endpoint
// selection decision which is stored in regs.
func (f *featureService) endpointDNATFlow(endpointIP net.IP, endpointPort uint16, protocol binding.Protocol) binding.Flow {
	unionVal := (EpSelectedRegMark.GetValue() << EndpointPortField.GetRange().Length()) + uint32(endpointPort)
	flowBuilder := EndpointDNATTable.ofTable.BuildFlow(priorityNormal).
		MatchProtocol(protocol).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegFieldWithValue(EpUnionField, unionVal)
	ipProtocol := getIPProtocol(endpointIP)

	if ipProtocol == binding.ProtocolIP {
		ipVal := binary.BigEndian.Uint32(endpointIP.To4())
		flowBuilder = flowBuilder.MatchRegFieldWithValue(EndpointIPField, ipVal)
	} else {
		ipVal := []byte(endpointIP)
		flowBuilder = flowBuilder.MatchXXReg(EndpointIP6Field.GetRegID(), ipVal)
	}

	return flowBuilder.Action().
		CT(true, EndpointDNATTable.ofTable.GetNext(), f.dnatCtZones[ipProtocol]).
		DNAT(
			&binding.IPRange{StartIP: endpointIP, EndIP: endpointIP},
			&binding.PortRange{StartPort: endpointPort, EndPort: endpointPort},
		).
		LoadToCtMark(ServiceCTMark).
		CTDone().
		Done()
}

// Feature: Service
// Stage: PreRoutingStage
// Service group
// Refactored from:
//   - func (c *client) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group
// serviceEndpointGroup creates/modifies the group/buckets of Endpoints. If the withSessionAffinity is true, then buckets
// will resubmit packets back to ServiceLBTable to trigger the learn flow, the learn flow will then send packets to
// EndpointDNATTable. Otherwise, buckets will resubmit packets to EndpointDNATTable directly.
func (f *featureService) serviceEndpointGroup(groupID binding.GroupIDType, withSessionAffinity bool, endpoints ...proxy.Endpoint) binding.Group {
	group := f.bridge.CreateGroup(groupID).ResetBuckets()
	var resubmitTableID uint8
	if withSessionAffinity {
		resubmitTableID = ServiceLBTable.ofTable.GetID()
	} else {
		resubmitTableID = EndpointDNATTable.ofTable.GetID()
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

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - func (c *client) decTTLFlows(category cookie.Category) []binding.Flow
// decTTLFlows generates the flow to process TTL. For the packets forwarded across Nodes, TTL should be decremented by one;
// for packets which enter OVS pipeline from the Antrea gateway, as the host IP stack should have decremented the TTL
// already for such packets, TTL should not be decremented again.
func (f *featurePodConnectivity) decTTLFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// Skip packets from the gateway interface.
			L3DecTTLTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromGatewayRegMark).
				Action().NextTable().
				Done(),
			L3DecTTLTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().DecTTL().
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

// Feature: Egress
// Stage: RoutingStage
// Tables: L3ForwardingTable
// Stage: PostRoutingStage
// Tables: SNATTable
// Refactored from:
//   - func (c *client) externalFlows(nodeIP net.IP, localSubnet net.IPNet, localGatewayMAC net.HardwareAddr, exceptCIDRs []net.IPNet) []binding.Flow
// externalFlows generates the flows to perform SNAT for the packets of connection to the external network. The flows identify
// the packets to external network, and send them to SNATTable, where SNAT IPs are looked up for the packets.
func (f *featureEgress) externalFlows(exceptCIDRs []net.IPNet) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	exceptCIDRsMap := make(map[binding.Protocol][]net.IPNet)
	for _, cidr := range exceptCIDRs {
		if cidr.IP.To4() == nil {
			exceptCIDRsMap[binding.ProtocolIPv6] = append(exceptCIDRsMap[binding.ProtocolIPv6], cidr)
		} else {
			exceptCIDRsMap[binding.ProtocolIP] = append(exceptCIDRsMap[binding.ProtocolIP], cidr)
		}
	}

	flows := []binding.Flow{
		// This generates the flow to match the packets to external network and forward them to SNATTable. The packets
		// from local Pods or remote Pods will hit the flow.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		//   - Remote Nodes' IPs are excluded by other flows.
		//   - Egress is enabled.
		// Corresponding traffic models are:
		//   01. Pod                         -- Egress [request]            --> External
		//   02. Remote Pod(via Tunnel)      -- Egress [request]            --> External
		L3ForwardingTable.ofTable.BuildFlow(priorityMiss).
			Cookie(cookieID).
			Action().LoadRegMark(EgressRegMark).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().GotoStage(binding.PostRoutingStage).
			Done(),
	}

	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to match the tracked Egress connection to SwitchingStage directly.
			SNATTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(EgressRegMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				MatchRegMark(FromTunnelRegMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().GotoStage(binding.SwitchingStage).
				Done(),
			// This generates the default flow to drop the packets from remote Nodes and there is no matched SNAT policy.
			SNATTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(EgressRegMark).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(FromTunnelRegMark).
				Action().Drop().
				Done())
		// This generates the flows to bypass the connection destined for the except CIDRs.
		for _, cidr := range exceptCIDRsMap[ipProtocol] {
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchRegMark(NotRewriteMACRegMark).
				MatchRegMark(FromLocalRegMark).
				MatchDstIPNet(cidr).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())
		}
	}
	return flows
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

func generatePipeline(pipelineID binding.PipelineID, requiredTables []*Table) binding.Pipeline {
	// PipelineClassifierTable ID is always 0, and it is the first table for all pipelines. Create PipelineClassifierTable
	// on the bridge when building a pipeline if it does not exist.
	if PipelineClassifierTable.ofTable == nil {
		PipelineClassifierTable.ofTable = binding.NewOFTable(binding.NextTableID(), PipelineClassifierTable.name, 0, binding.PipelineAll)
	}
	var ofTables []binding.Table
	for _, table := range requiredTables {
		// Generate a sequencing ID for the flow table.
		tableID := binding.NextTableID()
		// Initialize a flow table.
		table.ofTable = binding.NewOFTable(tableID, table.name, table.stage, pipelineID)
		ofTables = append(ofTables, table.ofTable)
		if _, exists, _ := tableCache.GetByKey(fmt.Sprintf("%d", table.GetID())); !exists {
			tableCache.Add(table)
		}
	}
	return binding.NewPipeline(pipelineID, ofTables)
}

func (c *client) createPipelinesOnBridge() {
	c.bridge.CreateTable(PipelineClassifierTable.ofTable, binding.LastTableID, binding.TableMissActionDrop)
	for _, pipeline := range c.pipelines {
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
			c.bridge.CreateTable(tables[i], nextID, missAction)
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

// Feature: Multicast
// Stage: RoutingStage
// Tables: MulticastTable
// Refactored from:
//   - func (c *client) igmpPktInFlows(reason uint8) []binding.Flow
// igmpPktInFlows generates the flow to load CustomReasonIGMPRegMark to mark the IGMP packet in MulticastTable and sends
// it to antrea-agent on MulticastTable.
func (f *featureMulticast) igmpPktInFlows(reason uint8) []binding.Flow {
	flows := []binding.Flow{
		// Set a custom reason for the IGMP packets, and then send it to antrea-agent and forward it normally in the
		// OVS bridge, so that the OVS multicast db cache can be updated, and antrea-agent can identify the local multicast
		// group and its members in the meanwhile.
		// Do not set dst IP address because IGMPv1 report message uses target multicast group as IP destination in
		// the packet.
		MulticastTable.ofTable.BuildFlow(priorityHigh).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIGMP).
			MatchRegMark(FromLocalRegMark).
			Action().LoadRegMark(CustomReasonIGMPRegMark).
			Action().SendToController(reason).
			Action().Normal().
			Done(),
	}
	return flows
}

// Feature: Multicast
// Stage: RoutingStage
// Tables: MulticastTable
// Refactored from:
//   - func (c *client) localMulticastForwardFlow(multicastIP net.IP) []binding.Flow
// localMulticastForwardFlow generates the flow to forward multicast packets with OVS action "normal", and outputs
// it to Antrea gateway in the meanwhile, so that the packet can be forwarded to local Pods which have joined the Multicast
// group and to the external receivers. For external multicast packets accessing to the given multicast IP also hits the
// flow, and the packet is not sent back to Antrea gateway because OVS datapath will drop it when it finds the output
// port is the same as the input port.
func (f *featureMulticast) localMulticastForwardFlow(multicastIP net.IP) []binding.Flow {
	return []binding.Flow{
		MulticastTable.ofTable.BuildFlow(priorityNormal).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIP).
			MatchDstIP(multicastIP).
			Action().Output(config.HostGatewayOFPort).
			Action().Normal().
			Done(),
	}
}

// Feature: Multicast
// Stage: RoutingStage
// Tables: MulticastTable
// Refactored from:
//   - func (c *client) externalMulticastReceiverFlow() binding.Flow
// externalMulticastReceiverFlow generates the flow to output multicast packets to Antrea gateway, so that local Pods can
// send multicast packets to access the external receivers. For the case that one or more local Pods have joined the target
// multicast group, it is handled by the flows created by function "localMulticastForwardFlow" after local Pods report the
// IGMP membership.
func (f *featureMulticast) externalMulticastReceiverFlow() binding.Flow {
	return MulticastTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(*mcastCIDR).
		Action().Output(config.HostGatewayOFPort).
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
	connectUplinkToBridge bool,
	enableMulticast bool) Client {
	bridge := binding.NewOFBridge(bridgeName, mgmtAddr)
	c := &client{
		bridge:                bridge,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		enableAntreaPolicy:    enableAntreaPolicy,
		enableDenyTracking:    enableDenyTracking,
		enableEgress:          enableEgress,
		enableMulticast:       enableMulticast,
		connectUplinkToBridge: connectUplinkToBridge,
		pipelines:             make(map[binding.PipelineID]binding.Pipeline),
		packetInHandlers:      map[uint8]map[string]PacketInHandler{},
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

// Feature: PodConnectivity
// Stage: ValidationStage
// Tables: Classification, SpoofGuardTable
// Stage: ConntrackStateStage
// Tables: ConntrackStateTable
// defaultDropFlows generates the default flows with drop action for some tables.
func (f *featurePodConnectivity) defaultDropFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		ClassifierTable.ofTable.BuildFlow(priorityMiss).
			Cookie(cookieID).
			Action().Drop().
			Done(),
		SpoofGuardTable.ofTable.BuildFlow(priorityMiss).
			Cookie(cookieID).
			Action().Drop().
			Done(),
	}
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// l3FwdFlowToLocalCIDR generates the flow to match the packets to local per-Node IPAM Pods.
func (f *featurePodConnectivity) l3FwdFlowToLocalCIDR() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, cidr := range f.localCIDRs {
		// This generates the flow to match the packets to local Pods.
		// For simplicity, in the following:
		//   - per-Node IPAM Pod is referred to as Pod.
		//   - Antrea IPAM Pod is referred to as Antrea Pod.
		// The common conditions are:
		//   - with NotRewriteMACRegMark (without RewriteMACRegMark).
		//   - Pod / Antrea Pod is not in host network.
		// Corresponding traffic models are:
		//   01. Pod                              -- Connect [request/reply]            --> Pod
		//   02. Gateway                          -- Connect [request/reply]            --> Pod
		//   03. External                         -- Egress  [reply]                    --> Pod
		//   04. External                         -- Connect [reply]                    --> Pod
		//   05. Node(via Gateway)                -- Connect [reply]                    --> Pod
		//   06. Remote Pod(via Gateway)          -- Connect [request/reply][noEncap]   --> Pod
		//   07. Remote Pod(via Gateway)          -- Service [request][noEncap]         --> Pod
		//   08. Remote Antrea Pod(via Gateway)   -- Connect [request/reply][noEncap]   --> Pod
		//   09. Remote Antrea Pod(via Gateway)   -- Service [request][noEncap]         --> Pod
		//   10. External(via Gateway)            -- Connect [reply]                    --> Pod
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityLow).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIPNet(cidr).
			MatchRegMark(NotRewriteMACRegMark).
			Action().LoadRegMark(ToLocalRegMark).
			Action().GotoStage(binding.SwitchingStage).
			Done())
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// l3FwdFlowToNode generates the flows to match the packets to local Node.
func (f *featurePodConnectivity) l3FwdFlowToNode() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for ipProtocol, nodeIP := range f.nodeIPs {
		flows = append(flows,
			// This generates the flow to match the packets with RewriteMACRegMark to local Node via the Antrea gateway.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common conditions are:
			//   - with RewriteMACRegMark。
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                     -- Service [request]            --> Node(via Gateway)
			//   02. Gateway                 -- Service [request][hairpin]   --> Node(via Gateway)
			//   03. External(via Gateway)   -- Service [request][hairpin]   --> Node(via Gateway)
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodeIP).
				MatchRegMark(RewriteMACRegMark).
				Action().SetDstMAC(f.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().NextTable().
				Done(),
			// This generates the flow to match the packets without RewriteMACRegMark to local Node via the Antrea gateway.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			//   - Antrea IPAM Pod is referred to as Antrea Pod.
			// The common condition is:
			//   - Pod / Antrea Pod is not in host network.
			// The traffic model is:
			//   01. Pod                     -- Connect [request]             --> Node(via Gateway)
			L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchDstIP(nodeIP).
				MatchRegMark(NotRewriteMACRegMark).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())

		if f.connectUplinkToBridge {
			flows = append(flows,
				// This generates the flow to match the packets to local Node via bridge local port.
				// For simplicity, in the following:
				//   - Antrea IPAM Pod is referred to as Antrea Pod.
				// The common condition is:
				//   - Pod / Antrea Pod is not in host network.
				// Corresponding traffic models are:
				//   01. Antrea Pod              -- Service [request]         --> Node(via Bridge)
				//   02. Antrea Pod              -- Connect [request/reply]   --> Node(via Bridge)
				L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchDstIP(nodeIP).
					MatchRegMark(AntreaFlexibleIPAMRegMark).
					Action().SetDstMAC(f.nodeConfig.UplinkNetConfig.MAC).
					Action().LoadRegMark(ToBridgeRegMark).
					Action().GotoStage(binding.SwitchingStage).
					Done(),
				// When Node bridge local port and uplink port connect to OVS, this generates the flow to mark the reply
				// packets of connection initiated through the bridge local port with FromBridgeCTMark.
				// For simplicity, in the following:
				//   - Antrea IPAM Pod is referred to as Antrea Pod.
				// The common condition is:
				//   - Pod / Antrea Pod is not in host network.
				// The traffic model is:
				//   01. Antrea Pod              -- NodePortLocal [reply]         --> Pod
				L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchCTMark(FromBridgeCTMark).
					MatchCTStateRpl(true).
					MatchCTStateTrk(true).
					Action().SetDstMAC(f.nodeConfig.UplinkNetConfig.MAC).
					Action().LoadRegMark(ToBridgeRegMark).
					Action().GotoStage(binding.SwitchingStage).
					Done())
		}
	}
	return flows
}

// Feature: PodConnectivity
// Stage: RoutingStage
// Tables: L3ForwardingTable
// l3FwdFlowToExternal generates the flow to forward the packets of non-Service or Egress connection to external network.
func (f *featurePodConnectivity) l3FwdFlowToExternal() binding.Flow {
	// This generates the flow to match the packets to external network.
	// For simplicity, in the following:
	//   - per-Node IPAM Pod is referred to as Pod.
	//   - Antrea IPAM Pod is referred to as Antrea Pod.
	//   - Remote Nodes' IPs are regards as External.
	// The common condition is:
	//   - Pod / Antrea Pod is not in host network.
	// Corresponding traffic models are:
	//   01. Pod            -- Connect [request]               --> External(via Gateway)
	//   02. Pod            -- Connect [request][noEncap]      --> Remote Antrea Pod(via Uplink)
	//   03. Antrea Pod     -- Connect [request][noEncap]      --> Remote Antrea Pod(via Uplink)
	//   04. Antrea Pod     -- Connect [request][noEncap]      --> External(via Uplink)
	return L3ForwardingTable.ofTable.BuildFlow(priorityMiss).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Feature: PodConnectivity
// Stage: ClassifierStage
// Table: ClassifierTable
// hostBridgeLocalFlows generates the flows to match the packets forwarded between bridge local port and uplink port.
func (f *featurePodConnectivity) hostBridgeLocalFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to forward the packets from uplink port to bridge local port.
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.UplinkOFPort).
			Action().Output(config.BridgeOFPort).
			Done(),
		// This generates the flow to forward the packets from bridge local port to uplink port.
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchInPort(config.BridgeOFPort).
			Action().Output(config.UplinkOFPort).
			Done(),
	}
}

// Feature: Service
// Stage: PreRoutingStage
// Tables: PreRoutingClassifierTable
// preRoutingClassifierFlows generates the flow to classify packets in PreRoutingStage.
func (f *featureService) preRoutingClassifierFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow

	targetTables := []uint8{SessionAffinityTable.ofTable.GetID(), ServiceLBTable.ofTable.GetID()}
	if f.proxyAll {
		targetTables = append([]uint8{NodePortMarkTable.ofTable.GetID()}, targetTables...)
	}
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the default flow to match the first packet of Service connection.
			PreRoutingClassifierTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				Action().ResubmitToTables(targetTables...).
				Done(),
		)
	}

	return flows
}

// Feature: Service
// Stage: RoutingStage
// Tables: L3ForwardingTable
// l3FwdFlowsToExternal generates the flows to forward the packets of Service connection to external network.
func (f *featureService) l3FwdFlowsToExternal() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	if f.connectUplinkToBridge {
		flows = append(flows,
			// This generates the flow to match the packets sourced from per-Node IPAM Pods and destined for external network.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			// The common conditions are:
			//   - with RewriteMACRegMark.
			//   - with NotAntreaFlexibleIPAMRegMark.
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                        -- Service [request]                    --> External(via Gateway)
			//   02. Gateway                    -- Service [request][hairpin]           --> External(via Gateway)
			//   03. Node(via Gateway)          -- Service [reply][hairpin]             --> External(via Gateway)
			//   04. External(via Gateway)      -- Service [request/reply][hairpin]     --> External(via Gateway)
			//   05. Pod                        -- Service [request][noEncap]           --> Remote Antrea Pod(via Gateway)
			//   06. Gateway                    -- Service [request][noEncap]           --> Remote Antrea Pod(via Gateway), RequireSNATRegMark(+new+trk)
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchRegMark(RewriteMACRegMark).
				MatchRegMark(NotAntreaFlexibleIPAMRegMark).
				MatchCTMark(ServiceCTMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().NextTable().
				Done())

		for _, ipProtocol := range f.ipProtocols {
			flows = append(flows,
				// This generates the flow to match packets sourced from Antrea IPAM Pod and destined for external network.
				// For simplicity, in the following:
				//   - Antrea IPAM Pod is referred to as Antrea Pod.
				// The common conditions are:
				//   - with RewriteMACRegMark.
				//   - with AntreaFlexibleIPAMRegMark.
				//   - Pod / Antrea Pod is not in host network.
				// Corresponding traffic models are:
				//   01. Antrea Pod                 -- Service [request]        --> Remote Antrea Pod(via Uplink)
				//   02. Antrea Pod                 -- Service [request]        --> External(via Uplink)
				L3ForwardingTable.ofTable.BuildFlow(priorityLow).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchCTStateRpl(false).
					MatchCTStateTrk(true).
					MatchRegMark(RewriteMACRegMark).
					MatchRegMark(AntreaFlexibleIPAMRegMark).
					MatchCTMark(ServiceCTMark).
					Action().LoadRegMark(ToUplinkRegMark).
					Action().NextTable().
					Done(),
				// This generates the flow to match packets sourced from Antrea IPAM Pod and destined for external network.
				// For simplicity, in the following:
				//   - Antrea IPAM Pod is referred to as Antrea Pod.
				// The common conditions are:
				//   - with RewriteMACRegMark.
				//   - with AntreaFlexibleIPAMRegMark.
				//   - Pod / Antrea Pod is not in host network.
				// Corresponding traffic models are:
				//   01. Antrea Pod                 -- Service [reply]        --> External(via Gateway)
				L3ForwardingTable.ofTable.BuildFlow(priorityLow).
					Cookie(cookieID).
					MatchProtocol(ipProtocol).
					MatchCTStateRpl(true).
					MatchCTStateTrk(true).
					MatchRegMark(RewriteMACRegMark).
					MatchRegMark(AntreaFlexibleIPAMRegMark).
					MatchCTMark(ServiceCTMark).
					Action().SetDstMAC(f.gatewayMAC).
					Action().LoadRegMark(ToGatewayRegMark).
					Action().NextTable().
					Done(),
			)
		}
	} else {
		flows = append(flows,
			// This generates the flow to forward the packets sourced from local Pods and destined for external network.
			// For simplicity, in the following:
			//   - per-Node IPAM Pod is referred to as Pod.
			// The common conditions are:
			//   - with RewriteMACRegMark.
			//   - Pod / Antrea Pod is not in host network.
			// Corresponding traffic models are:
			//   01. Pod                        -- Service [request]              --> External(via Gateway)
			//   02. Gateway                    -- Service [request][hairpin]     --> External(via Gateway)
			//   03. Node(via Gateway)          -- Service [reply][hairpin]       --> External(via Gateway)
			//   04. External(via Gateway)      -- Service [request][hairpin]     --> External(via Gateway)
			//   05. Pod                        -- Service [request][noEncap]     --> Remote Pod(via Gateway)
			//   06. Gateway                    -- Service [request][noEncap]     --> Remote Pod(via Gateway), RequireSNATRegMark(+new+trk)
			L3ForwardingTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchRegMark(RewriteMACRegMark).
				MatchCTMark(ServiceCTMark).
				Action().SetDstMAC(f.gatewayMAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

// Feature: Service
// Stage: RoutingStage
// Tables: ServiceHairpinMarkTable
// hairpinBypassFlows generates the flows to classify hairpin connection and non-hairpin connection.
func (f *featureService) hairpinBypassFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// This generates the flow to mark the tracked hairpin connection with HairpinRegMark.
			ServiceHairpinMarkTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTMark(HairpinCTMark).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().LoadRegMark(HairpinRegMark).
				Action().NextTable().
				Done(),
			// This generates the flow to bypass the non-hairpin connection.
			ServiceHairpinMarkTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(false).
				MatchCTStateTrk(true).
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

// Feature: Service
// Stage: RoutingStage
// Tables: ServiceHairpinMarkTable
// podHairpinFlow generates the flow to mark the first packet of hairpin connection from local Pods. Note that, value of
// ServiceSNATStateField will be overwritten to NotRequireSNATRegMark. The reason is that hairpin connection is forced to
// perform SNAT in SNATConntrackCommitTable regardless of whether the connection requires SNAT, and NotRequireSNATRegMark
// is one of match conditions to match the first packet of hairpin connection in SNATConntrackCommitTable. To make flow
// more simple in SNATConntrackCommitTable, NotRequireSNATRegMark will be loaded regardless of whether the connection
// requires SNAT. For this kind of hairpin connection, Antrea gateway IP is used to perform SNAT.
func (f *featureService) podHairpinFlow(endpoint net.IP) binding.Flow {
	ipProtocol := getIPProtocol(endpoint)
	return ServiceHairpinMarkTable.ofTable.BuildFlow(priorityLow).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchCTStateNew(true).
		MatchCTStateTrk(true).
		MatchSrcIP(endpoint).
		MatchDstIP(endpoint).
		Action().LoadRegMark(HairpinRegMark).
		Action().LoadRegMark(SNATWithGatewayIP).
		Action().LoadRegMark(NotRequireSNATRegMark).
		Action().NextTable().
		Done()
}

// Feature: Service
// Stage: RoutingStage
// Tables: ServiceHairpinMarkTable
// gatewayHairpinFlows generate the flow to mark the first packet of hairpin Service connection from the Antrea gateway.
func (f *featureService) gatewayHairpinFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows,
			// Note that, in the flows generated by the following functions, value of ServiceSNATStateField will be overwritten
			// to NotRequireSNATRegMark. The reason is that hairpin connection is forced to perform SNAT in SNATConntrackCommitTable
			// regardless of whether the connection requires SNAT, and NotRequireSNATRegMark is one of match conditions to
			// match the first packet of hairpin connection in SNATConntrackCommitTable. To make flow more simple in
			// SNATConntrackCommitTable, NotRequireSNATRegMark will be loaded regardless of whether the connection requires
			// SNAT. For this kind of hairpin connection, virtual IP is used to perform SNAT since the packets destined
			// for the Antrea gateway.

			// This generates the flow to mark the first packet of Service connection sourced from the Antrea gateway and
			// destined for the Antrea gateway.
			ServiceHairpinMarkTable.ofTable.BuildFlow(priorityLow).
				Cookie(cookieID).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchRegMark(GatewayHairpinRegMark).
				Action().LoadRegMark(HairpinRegMark).
				Action().LoadRegMark(NotRequireSNATRegMark).
				Action().LoadRegMark(SNATWithVirtualIP).
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

func getCachedFlows(cache *flowCategoryCache) []binding.Flow {
	var flows []binding.Flow
	cache.Range(func(key, value interface{}) bool {
		fCache := value.(flowCache)
		for _, flow := range fCache {
			flow.Reset()
			flows = append(flows, flow)
		}
		return true
	})
	return flows
}
