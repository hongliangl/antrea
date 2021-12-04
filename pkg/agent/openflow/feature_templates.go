// Copyright 2022 Antrea Authors
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
)

// OVS pipelines are generated by a framework called FlexiblePipeline. There are some abstractions introduced in this
// framework.
// +--------------+ +--------------+ +--------------+ +--------------+ +--------------+ +--------------+
// | FeatureTable | | FeatureTable | | FeatureTable | | FeatureTable | | FeatureTable | | FeatureTable |
// +--------------+ +--------------+ +--------------+ +--------------+ +--------------+ +--------------+
//         \               |                /                |                 \               /
//          \              |               /                 |                  \             /
//           \             |              /                  |                   \           /
//      +------------------------------------+        +--------------+       +--------------------+
//      |               stage                |        |     stage    |       |        stage       |
//      +------------------------------------+        +--------------+       +--------------------+
//              \                                          /    \                        /
//               \                                        /      \                      /
//                \                                      /        \                    /
//              +------------------------------------------+    +--------------------------+
//              |                 feature                  |    |          feature         |
//              +------------------------------------------+    +--------------------------+
//                                  |                    \                         /
//                                  |                     \                       /
//                                  |                      \                     /
//                     +------------------------+        +-------------------------+
//                     |       OVS pipeline     |        |       OVS pipeline      |
//                     +------------------------+        +-------------------------+

// FeatureTable in FlexiblePipeline is the basic unit to build OVS pipelines. It is the enhanced version of ofTable. A
// FeatureTable can be used by one or more active features. If a FeatureTable is used by any active features, then the
// FeatureTable will be used to build OVS pipelines and its member struct ofTable will be initialized and realized to
// OVS. Otherwise, it will be excluded from building OVS pipelines. Note that, the order of all stages in OVS pipelines
// is fixed, but the order of FeatureTables within a stage is determined by the FeatureTables' priority. FeatureTable
// with a higher priority will be assigned with a smaller tableID for its corresponding ofTable in the realized OVS
// pipelines. Within a stage, a packet should enter the ofTable with the highest priority first.
type FeatureTable struct {
	name     string
	priority uint8
	stage    binding.StageID
	ofTable  binding.Table
}

// How to add a new table?
// - Select a target OVS pipeline, feature and stage.
// - Define a FeatureTable with table name, stage and priority. Arrange the FeatureTable to the desired position with appropriate
//   priority value. All existing FeatureTables are located at file pkg/agent/openflow/pipeline.go. For example, there is a
//   stage which has FeatureTable Alpha (priority 200) and FeatureTable Beta (priority 100) declared by another feature.
//   To insert a FeatureTable Gamma:
//     - between Alpha and Beta, the priority of Gamma should have a priority between 101 and 199 (between Alpha and Beta's
//       priority.
//     - after Beta, the priority of Gamma should be smaller than 100 (smaller than Beta's priority)
//     - before Alpha, the priority of Gamma should be greater than 200 (greater than Alpha's priority)
// - Reference the defined FeatureTable in target feature and stage. See method `getTemplate(p pipeline) *featureTemplate`.

// Stage in FlexiblePipeline is a set of FeatureTables. The order of stages is fixed. A stage can have zero or more
// FeatureTables. Note that, a FeatureTable cannot be shared by different stages. Stages include:
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

// How to add a new stage?
// Define the new stage in file pkg/ovs/openflow/interfaces.go. Note that, adding a new stage means that the new added stage
// should have at least one FeatureTable.

type featureName string

const (
	PodConnectivity featureName = "PodConnectivity"
	NetworkPolicy   featureName = "NetworkPolicy"
	Service         featureName = "Service"
	Egress          featureName = "Egress"
	Multicast       featureName = "Multicast"
	Traceflow       featureName = "Traceflow"
)

// featureTemplate includes a map to store which stages and FeatureTables are used for a feature. For a feature,
// FeatureTables declared in featureTemplate participate in build OVS pipelines.
type featureTemplate struct {
	stageTables map[binding.StageID][]*FeatureTable
	feature     featureName
}

// feature is intended to implement a major function. Note that, a feature can have one or more stages, and a stage can
// be shared by multiple features. The following features are supported:
// - PodConnectivity, implementation of connectivity for Pods
// - NetworkPolicy, implementation of K8s NetworkPolicy and Antrea NetworkPolicy
// - Service, implementation of K8s Service
// - Egress, implementation of Egress
// - Multicast, implementation of Multicast
// - Traceflow
type feature interface {
	// getFeatureName returns the name of the feature.
	getFeatureName() featureName
	// getTemplate returns the featureTemplate  defined by the feature. For a feature, it can participate in building more
	// than one OVS pipelines. For example, when IPv4 is enabled, feature PodConnectivity needs both OVS pipelines for IP
	// and ARP.
	getTemplate(p pipeline) *featureTemplate
	// initFlows returns the initial flows of the feature.
	initFlows() []binding.Flow
	// replayFlows returns the fixed and cached flows that need to be replayed after OVS is reconnected.
	replayFlows() []binding.Flow
}

// How to add a new feature?
// If a new function of Antrea to be implemented cannot be classified to any existing features, then a new feature should
// be created. The new feature should implement the interface feature defined above.

// An OVS pipeline includes a pipeline of flows in multiple stages and tables for processing a specific type of traffic.
// Note that, an OVS pipeline can involve one or more features, and a feature can participate in building more than one
// OVS pipelines. The entry point for a packet enters any OVS pipelines should be defined in PipelineClassifierTable. For
// example, OVS pipeline for IP / ARP. The entry of an OVS pipeline can be also from another OVS pipeline. For example,
// OVS pipeline for multicast shares some stages with OVS pipeline for IP. At this moment, we have the following OVS
// pipelines:
// - OVS pipeline for IP
// - OVS pipeline for ARP
// - OVS pipeline for multicast
type pipeline int

const (
	pipelineARP pipeline = iota
	pipelineIP
	pipelineMulticast

	pipelineFirst = pipelineARP
	pipelineLast  = pipelineMulticast
)

func newFeatureTable(tableName string, priority uint8, stage binding.StageID) *FeatureTable {
	return &FeatureTable{
		name:     tableName,
		priority: priority,
		stage:    stage,
	}
}

func (f *FeatureTable) GetID() uint8 {
	return f.ofTable.GetID()
}

func (f *FeatureTable) GetNext() uint8 {
	return f.ofTable.GetNext()
}

func (f *FeatureTable) GetName() string {
	return f.name
}

func (f *FeatureTable) GetMissAction() binding.MissActionType {
	return f.ofTable.GetMissAction()
}

func (f *featureTemplate) addTable(stage binding.StageID, table *FeatureTable) {
	f.stageTables[stage] = append(f.stageTables[stage], table)
}

func (f *featurePodConnectivity) getTemplate(p pipeline) *featureTemplate {
	var template *featureTemplate
	switch p {
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
		if f.enableMulticast {
			template.addTable(binding.ValidationStage, IPClassifierTable)
		}
		for _, ipProtocol := range f.ipProtocols {
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

func (f *featureNetworkPolicy) getTemplate(p pipeline) *featureTemplate {
	if p != pipelineIP {
		return nil
	}
	template := &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.EgressSecurityStage: {
				EgressRuleTable,
				EgressDefaultTable,
				EgressMetricTable,
			},
			binding.IngressSecurityStage: {
				IngressSecurityClassifierTable,
				IngressRuleTable,
				IngressDefaultTable,
				IngressMetricTable,
			},
		},
	}
	if f.enableAntreaPolicy {
		template.addTable(binding.EgressSecurityStage, AntreaPolicyEgressRuleTable)
		template.addTable(binding.IngressSecurityStage, AntreaPolicyIngressRuleTable)
	}
	return template
}

func (f *featureService) getTemplate(p pipeline) *featureTemplate {
	if p != pipelineIP {
		return nil
	}
	if !f.enableProxy {
		return &featureTemplate{
			stageTables: map[binding.StageID][]*FeatureTable{
				binding.PreRoutingStage: {
					DNATTable,
				},
			},
		}
	}
	template := &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.ConntrackStateStage: {
				SNATConntrackTable,
			},
			binding.PreRoutingStage: {
				PreRoutingClassifierTable,
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
	if f.proxyAll {
		template.addTable(binding.PreRoutingStage, NodePortMarkTable)
	}
	return template
}

func (f *featureEgress) getTemplate(p pipeline) *featureTemplate {
	if p != pipelineIP {
		return nil
	}
	return &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.RoutingStage: {
				L3ForwardingTable,
			},
			binding.PostRoutingStage: {
				SNATTable,
			},
		},
	}
}

func (f *featureMulticast) getTemplate(p pipeline) *featureTemplate {
	if p != pipelineMulticast {
		return nil
	}
	return &featureTemplate{
		stageTables: map[binding.StageID][]*FeatureTable{
			binding.RoutingStage: {
				MulticastTable,
			},
		},
	}
}

func (f *featureTraceflow) getTemplate(p pipeline) *featureTemplate {
	return &featureTemplate{}
}

// tracedFeature is the interface intended to support feature Traceflow. Any other feature expected to trace the packet
// status with its flow entries needs to implement this interface.
type tracedFeature interface {
	// flowsToTrace returns the flows to be installed when a packet tracing request is created.
	flowsToTrace(dataplaneTag uint8,
		ovsMetersAreSupported,
		liveTraffic,
		droppedOnly,
		receiverOnly bool,
		packet *binding.Packet,
		ofPort uint32,
		timeoutSeconds uint16) []binding.Flow
}
