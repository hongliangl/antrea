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
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/runtime"
)

type pipelineProtocol int

const (
	pipelineARP pipelineProtocol = iota + 1
	pipelineIP

	pipelineFirst = pipelineARP
	pipelineLast  = pipelineIP
)

// A featureID is used to represent a feature which has a set of functions. Current features include:
// - PodConnectivity: functions about connectivity for Pods in Antrea.
// - NetworkPolicy: implementation of NetworkPolicy and functions of AntreaNetworkPolicy in Antrea.
// - Service: implementation of Service in Antrea.
// - Egress: implementation of Egress in Antrea.
// - Traceflow: functions of Traceflow in Antrea.
type featureID int

const (
	PodConnectivity featureID = iota
	NetworkPolicy
	Service
	Egress
	Traceflow
)

// featureTemplate is used to declare which FeatureTables will be used for this feature. Note that, if a feature wants
// to declare a FeatureTable, the FeatureTable should be defined first.
type featureTemplate struct {
	stageTables map[binding.StageID][]*FeatureTable
	feature     featureID
}

func (f *featureTemplate) addTable(stage binding.StageID, table *FeatureTable) {
	f.stageTables[stage] = append(f.stageTables[stage], table)
}

// Flexible pipeline for IPv4/IPv6 has 11 fixed stages. These stages are:
// - ClassifierStage
// - ValidationStage
// - ConntrackStateStage
// - PreRoutingStage
// - EgressSecurityStage
// - RoutingStage
// - PostRoutingStage
// - SwitchingStage
// - IngressSecurityStage
// - ConntrackStage
// - OutputStage
// Flexible pipeline for ARP has 2 fixed stages. These stages are:
// - ValidationStage
// - OutputStage
// The order of stages are fixed. A stage can be empty or have one or more flow tables. To insert a flow table to flexible
// pipeline, its corresponding FeatureTable defined first and the FeatureTable should be also declared at least by one
// feature.

// FeatureTable is the basic unit to build a flexible pipeline. A FeatureTable should only belong to a single stage and a
// single pipeline. If a FeatureTable is declared to used by one or more features, then the FeatureTable will be used to
// build a pipeline and its member struct `ofTable` will be initialized. Otherwise, it will be excluded from
// building an OVS pipeline. Note that, the order of all stages is fixed, but the order of flow tables within a stage is
// determined by priority of their corresponding FeatureTable. FeatureTable with a higher priority is assigned with a smaller
// tableID for its corresponding flow table, which means a packet should enter the flow table before others with lower
// priorities in the same stage.
type FeatureTable struct {
	name       string
	priority   uint8
	ofProtocol pipelineProtocol
	stage      binding.StageID
	ofTable    binding.Table
}

func newFeatureTable(tableName string, priority uint8, stage binding.StageID, ofProtocol pipelineProtocol) *FeatureTable {
	return &FeatureTable{
		name:       tableName,
		priority:   priority,
		stage:      stage,
		ofProtocol: ofProtocol,
	}
}

func (c *FeatureTable) GetID() uint8 {
	return c.ofTable.GetID()
}

func (c *FeatureTable) GetNext() uint8 {
	return c.ofTable.GetNext()
}

func (c *FeatureTable) GetName() string {
	return c.name
}

func (c *FeatureTable) GetMissAction() binding.MissActionType {
	return c.ofTable.GetMissAction()
}

// SetOFTable is only used for unit test.
func (c *FeatureTable) SetOFTable(id uint8, table binding.Table) {
	if table != nil {
		c.ofTable = table
	} else {
		c.ofTable = binding.NewOFTable(id, c.name, 0, 0)
	}
}

// ResetOFTable is only used for integration test.
func ResetOFTable() {
	PipelineClassifierTable.ofTable = nil
	binding.ResetTableID()
}

type feature interface {
	getTemplate(protocol pipelineProtocol) *featureTemplate
}

func (c *featurePodConnectivity) getTemplate(protocol pipelineProtocol) *featureTemplate {
	var template *featureTemplate
	switch protocol {
	case pipelineIP:
		template = &featureTemplate{
			stageTables: map[binding.StageID][]*FeatureTable{
				binding.ClassifierStage: {
					ClassifierTable,
				},
				binding.ValidationStage: {
					SpoofGuardTable,
				},
				binding.ConntrackStateStage: {
					ConntrackTable,
					ConntrackStateTable,
				},
				binding.RoutingStage: {
					L3ForwardingTable,
					L3DecTTLTable,
				},
				binding.SwitchingStage: {
					L2ForwardingCalcTable,
				},
				binding.ConntrackStage: {
					ConntrackCommitTable,
				},
				binding.OutputStage: {
					L2ForwardingOutTable,
				},
			},
		}
		for _, ipProtocol := range c.ipProtocols {
			if ipProtocol == binding.ProtocolIPv6 {
				template.addTable(binding.ValidationStage, IPv6Table)
				break
			}
		}
	case pipelineARP:
		template = &featureTemplate{
			stageTables: map[binding.StageID][]*FeatureTable{
				binding.ValidationStage: {
					ARPSpoofGuardTable,
				},
				binding.OutputStage: {
					ARPResponderTable,
				},
			},
		}
	}

	return template
}

func (c *featureNetworkPolicy) getTemplate(protocol pipelineProtocol) *featureTemplate {
	var template *featureTemplate
	if protocol != pipelineIP {
		return template
	}
	template = &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.ValidationStage: {
				SpoofGuardTable,
			},
			binding.EgressSecurityStage: {
				EgressRuleTable,
				EgressDefaultTable,
				EgressMetricTable,
			},
			binding.RoutingStage: {
				L3ForwardingTable,
			},
			binding.IngressSecurityStage: {
				IngressClassifierTable,
				IngressRuleTable,
				IngressDefaultTable,
				IngressMetricTable,
			},
			binding.ConntrackStage: {
				ConntrackCommitTable,
			},
		},
	}
	if c.enableAntreaPolicy {
		template.addTable(binding.EgressSecurityStage, AntreaPolicyEgressRuleTable)
		template.addTable(binding.IngressSecurityStage, AntreaPolicyIngressRuleTable)
	}
	return template
}

func (c *featureService) getTemplate(protocol pipelineProtocol) *featureTemplate {
	var template *featureTemplate
	if protocol != pipelineIP {
		return template
	}
	if c.enableProxy {
		template = &featureTemplate{
			stageTables: map[binding.StageID][]*FeatureTable{
				binding.ConntrackStateStage: {
					SNATConntrackTable,
				},
				binding.PreRoutingStage: {
					SessionAffinityTable,
					ServiceLBTable,
					EndpointDNATTable,
				},
				binding.RoutingStage: {
					L3ForwardingTable,
					ServiceHairpinMarkTable,
				},
				binding.PostRoutingStage: {
					SNATConntrackCommitTable,
				},
				binding.ConntrackStage: {
					ConntrackCommitTable,
				},
				binding.OutputStage: {
					L2ForwardingOutTable,
				},
			},
		}
		if runtime.IsWindowsPlatform() {
			template.addTable(binding.ClassifierStage, UplinkTable)
		}
		if c.proxyAll {
			template.addTable(binding.PreRoutingStage, NodePortProbeTable)
		}
	} else {
		template = &featureTemplate{
			stageTables: map[binding.StageID][]*FeatureTable{
				binding.PreRoutingStage: {
					DNATTable,
				},
			},
		}
	}
	return template
}

func (c *featureEgress) getTemplate(protocol pipelineProtocol) *featureTemplate {
	var template *featureTemplate
	if protocol != pipelineIP {
		return template
	}
	template = &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.RoutingStage: {
				L3ForwardingTable,
			},
			binding.PostRoutingStage: {
				SNATTable,
			},
		},
	}
	return template
}

func (c *featureTraceflow) getTemplate(protocol pipelineProtocol) *featureTemplate {
	var template *featureTemplate
	if protocol != pipelineIP {
		return template
	}
	template = &featureTemplate{}
	return template
}
