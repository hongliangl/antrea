//go:build linux
// +build linux

// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/util/sets"

	routetest "antrea.io/antrea/pkg/agent/route/testing"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var (
	ruleActionAllow = secv1beta1.RuleActionAllow

	ipv4Net1 = newCIDR("192.168.1.0/24")
	ipv6Net1 = newCIDR("fec0::192:168:1:0/124")
	ipv4Net2 = newCIDR("192.168.1.128/25")
	ipv6Net2 = newCIDR("fec0::192:168:1:1/125")
	ipBlocks = v1beta2.NetworkPolicyPeer{
		IPBlocks: []v1beta2.IPBlock{
			{
				CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipv4Net1.IP), PrefixLength: 24},
				Except: []v1beta2.IPNet{
					{IP: v1beta2.IPAddress(ipv4Net2.IP), PrefixLength: 25},
				},
			},
			{
				CIDR: v1beta2.IPNet{IP: v1beta2.IPAddress(ipv6Net1.IP), PrefixLength: 124},
				Except: []v1beta2.IPNet{
					{IP: v1beta2.IPAddress(ipv6Net2.IP), PrefixLength: 125},
				},
			},
		},
	}

	policyPriority1 = float64(1)
	tierPriority1   = int32(1)
	tierPriority2   = int32(2)

	ingressRuleID1 = "ingressRule1"
	ingressRuleID2 = "ingressRule2"
	ingressRuleID3 = "ingressRule3"
	egressRuleID1  = "egressRule1"
	egressRuleID2  = "egressRule2"
	ingressRule1   = &CompletedRule{
		rule: &rule{
			ID:             ingressRuleID1,
			Name:           "rule-01",
			PolicyName:     "ingress-policy",
			From:           ipBlocks,
			Direction:      v1beta2.DirectionIn,
			Services:       []v1beta2.Service{serviceTCP80, serviceTCP443},
			Action:         &ruleActionAllow,
			Priority:       1,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority1,
			SourceRef:      &cnp1,
		},
		FromAddresses: dualAddressGroup1,
		ToAddresses:   nil,
	}
	updatedIngressRule1 = &CompletedRule{
		rule: &rule{
			ID:             ingressRuleID1,
			Name:           "rule-01",
			PolicyName:     "ingress-policy",
			From:           ipBlocks,
			Direction:      v1beta2.DirectionIn,
			Services:       []v1beta2.Service{serviceTCP80, serviceTCP443},
			Action:         &ruleActionAllow,
			Priority:       1,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority1,
			SourceRef:      &cnp1,
		},
		FromAddresses: addressGroup2,
		ToAddresses:   nil,
	}
	ingressRule2 = &CompletedRule{
		rule: &rule{
			ID:             ingressRuleID2,
			Name:           "rule-02",
			PolicyName:     "ingress-policy",
			Direction:      v1beta2.DirectionIn,
			Services:       []v1beta2.Service{serviceTCP443},
			Action:         &ruleActionAllow,
			Priority:       2,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority2,
			SourceRef:      &cnp1,
		},
		FromAddresses: dualAddressGroup1,
		ToAddresses:   nil,
	}
	ingressRule3 = &CompletedRule{
		rule: &rule{
			ID:             ingressRuleID3,
			Name:           "rule-03",
			PolicyName:     "ingress-policy",
			Direction:      v1beta2.DirectionIn,
			Services:       []v1beta2.Service{serviceTCP8080},
			Action:         &ruleActionAllow,
			Priority:       3,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority2,
			SourceRef:      &cnp1,
		},
		FromAddresses: dualAddressGroup1,
		ToAddresses:   nil,
	}
	egressRule1 = &CompletedRule{
		rule: &rule{
			ID:             egressRuleID1,
			Name:           "rule-01",
			PolicyName:     "egress-policy",
			Direction:      v1beta2.DirectionOut,
			Services:       []v1beta2.Service{serviceTCP80, serviceTCP443},
			Action:         &ruleActionAllow,
			Priority:       1,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority1,
			SourceRef:      &cnp1,
		},
		ToAddresses:   dualAddressGroup1,
		FromAddresses: nil,
	}
	egressRule2 = &CompletedRule{
		rule: &rule{
			ID:             egressRuleID2,
			Name:           "rule-02",
			PolicyName:     "egress-policy",
			Direction:      v1beta2.DirectionOut,
			Services:       []v1beta2.Service{serviceTCP443},
			Action:         &ruleActionAllow,
			Priority:       2,
			PolicyPriority: &policyPriority1,
			TierPriority:   &tierPriority2,
			SourceRef:      &cnp1,
		},
		ToAddresses:   dualAddressGroup1,
		FromAddresses: nil,
	}
)

func newTestNodeReconciler(mockRouteClient *routetest.MockInterface, ipv4Enabled, ipv6Enabled bool) *nodeReconciler {
	return newNodeReconciler(mockRouteClient, ipv4Enabled, ipv6Enabled)
}

func TestNodeReconcilerReconcileAndForget(t *testing.T) {
	tests := []struct {
		name          string
		rulesToAdd    []*CompletedRule
		rulesToForget []string
		ipv4Enabled   bool
		ipv6Enabled   bool
		expectedCalls func(mockRouteClient *routetest.MockInterfaceMockRecorder)
	}{
		{
			name:        "IPv4, add an ingress rule then forget it",
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				serviceRules := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules, false).Times(1)

				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, [][]string{nil}, false).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule1,
			},
			rulesToForget: []string{
				ingressRuleID1,
			},
		},
		{
			name:        "IPv6, add an egress rule and forget it",
			ipv4Enabled: false,
			ipv6Enabled: true,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				serviceRules := [][]string{
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-6 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, serviceRules, true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, coreRules, true).Times(1)

				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", true)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, [][]string{nil}, true).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				egressRule1,
			},
			rulesToForget: []string{
				egressRuleID1,
			},
		},
		{
			name:        "Dualstack, add an ingress rule and forget it",
			ipv4Enabled: true,
			ipv6Enabled: true,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				serviceRules := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRulesIPv4 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesIPv6 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-6 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesIPv4, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128", "fec0::192:168:1:8/125"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules, true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesIPv6, true).Times(1)

				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, [][]string{nil}, false).Times(1)

				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", true)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, [][]string{nil}, true).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule1,
			},
			rulesToForget: []string{
				ingressRuleID1,
			},
		},
		{
			name:        "IPv4, add multiple ingress rules whose priorities are in ascending order, then forget some",
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				serviceRules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules1 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRules3 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDeleted3 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDelete2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules1, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules2, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE3-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules3, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDeleted3, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE3-4", false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDelete2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", false).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
				ingressRule3,
			},
			rulesToForget: []string{
				ingressRuleID3,
				ingressRuleID2,
			},
		},
		{
			name:        "IPv4, add multiple ingress rules whose priorities are in descending order, then forget some",
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				coreRules3 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				serviceRules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules1 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDelete3 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDelete1 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE3-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules3, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules2, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules1, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDelete3, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE3-4", false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDelete1, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule3,
				ingressRule2,
				ingressRule1,
			},
			rulesToForget: []string{
				ingressRuleID3,
				ingressRuleID1,
			},
		},
		{
			name:        "IPv4, add multiple ingress rules whose priorities are in random order, then forget some",
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				coreRules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				serviceRules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules1 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRules3 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDelete2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				coreRulesDelete1 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE3-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule3, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules2, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules1, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE3-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules3, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDelete2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRulesDelete1, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule2,
				ingressRule1,
				ingressRule3,
			},
			rulesToForget: []string{
				ingressRuleID2,
				ingressRuleID1,
			},
		},
		{
			name:        "IPv4, add an ingress rule, update it and forget it",
			ipv4Enabled: true,
			ipv6Enabled: false,
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				serviceRules := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
				}
				coreRules := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, serviceRules, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, coreRules, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.2/32", "192.168.1.0/25"), false).Times(1)

				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, [][]string{nil}, false).Times(1)
			},
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				updatedIngressRule1,
			},
			rulesToForget: []string{
				ingressRuleID1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockRouteClient := routetest.NewMockInterface(controller)
			r := newTestNodeReconciler(mockRouteClient, tt.ipv4Enabled, tt.ipv6Enabled)

			tt.expectedCalls(mockRouteClient.EXPECT())
			for _, rule := range tt.rulesToAdd {
				assert.NoError(t, r.Reconcile(rule))
			}
			for _, rule := range tt.rulesToForget {
				assert.NoError(t, r.Forget(rule))
			}
		})
	}
}

func TestNodeReconcilerBatchReconcileAndForget(t *testing.T) {
	tests := []struct {
		name          string
		ipv4Enabled   bool
		ipv6Enabled   bool
		rulesToAdd    []*CompletedRule
		rulesToForget []string
		expectedCalls func(mockRouteClient *routetest.MockInterfaceMockRecorder)
	}{
		{
			name:        "IPv4, only add ingress rules and forget one",
			ipv4Enabled: true,
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
			},
			rulesToForget: []string{
				ingressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-INGRESSRULE1",
					"ANTREA-POL-INGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, rules2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
			},
		},
		{
			name:        "IPv6, only add ingress rules and forget one",
			ipv6Enabled: true,
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
			},
			rulesToForget: []string{
				ingressRuleID2,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-INGRESSRULE1",
					"ANTREA-POL-INGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-6 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-6 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-6 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128", "fec0::192:168:1:8/125"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, rules2, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-6", true).Times(1)
			},
		},
		{
			name:        "dualstack, only add ingress rules and forget one",
			ipv4Enabled: true,
			ipv6Enabled: true,
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
			},
			rulesToForget: []string{
				ingressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-INGRESSRULE1",
					"ANTREA-POL-INGRESS-RULES",
				}
				ipv4Rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},

					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				ipv6Rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-6 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-6 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				ipv4Rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				ipv6Rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-6 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128", "fec0::192:168:1:8/125"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, ipv4Rules1, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, ipv6Rules1, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, ipv4Rules2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, ipv6Rules2, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, true).Times(1)
			},
		},
		{
			name:        "IPv4, only add egress rules and forget one",
			ipv4Enabled: true,
			rulesToAdd: []*CompletedRule{
				egressRule1,
				egressRule2,
			},
			rulesToForget: []string{
				egressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-EGRESSRULE1",
					"ANTREA-POL-EGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-4 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				rules2 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, rules2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, false).Times(1)
			},
		},
		{
			name:        "IPv6, only add egress rules and forget one",
			ipv6Enabled: true,
			rulesToAdd: []*CompletedRule{
				egressRule1,
				egressRule2,
			},
			rulesToForget: []string{
				egressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-EGRESSRULE1",
					"ANTREA-POL-EGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-6 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				rules2 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, rules2, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, true).Times(1)
			},
		},
		{
			name:        "dualstack, only add egress rules and forget one",
			ipv4Enabled: true,
			ipv6Enabled: true,
			rulesToAdd: []*CompletedRule{
				egressRule1,
				egressRule2,
			},
			rulesToForget: []string{
				egressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-EGRESSRULE1",
					"ANTREA-POL-EGRESS-RULES",
				}
				ipv4Rules1 := [][]string{
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-4 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				ipv6Rules1 := [][]string{
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-6 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				ipv4Rules2 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				ipv6Rules2 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, ipv4Rules1, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, ipv6Rules1, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, ipv4Rules2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, ipv6Rules2, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, true).Times(1)
			},
		},
		{
			name:        "IPv4, add ingress and egress rules and forget some rules",
			ipv4Enabled: true,
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
				egressRule1,
				egressRule2,
			},
			rulesToForget: []string{
				ingressRuleID1,
				egressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-INGRESSRULE1",
					"ANTREA-POL-EGRESSRULE1",
					"ANTREA-POL-INGRESS-RULES",
					"ANTREA-POL-EGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-4 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-4 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-4 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				rules3 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-4 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", sets.New[string]("1.1.1.1/32", "192.168.1.0/25"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-4", sets.New[string]("1.1.1.1/32"), false).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, rules2, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, false).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, rules3, false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-4", false).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, false).Times(1)
			},
		},
		{
			name:        "IPv6, add ingress and egress rules and forget some rules",
			ipv6Enabled: true,
			rulesToAdd: []*CompletedRule{
				ingressRule1,
				ingressRule2,
				egressRule1,
				egressRule2,
			},
			rulesToForget: []string{
				ingressRuleID1,
				egressRuleID1,
			},
			expectedCalls: func(mockRouteClient *routetest.MockInterfaceMockRecorder) {
				chains := []string{
					"ANTREA-POL-INGRESSRULE1",
					"ANTREA-POL-EGRESSRULE1",
					"ANTREA-POL-INGRESS-RULES",
					"ANTREA-POL-EGRESS-RULES",
				}
				rules1 := [][]string{
					{
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-INGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 80 -j ACCEPT",
						"-A ANTREA-POL-EGRESSRULE1 -p tcp --dport 443 -j ACCEPT",
					},
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE1-6 src -j ANTREA-POL-INGRESSRULE1 -m comment --comment "Antrea: for rule ingressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-6 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE1-6 dst -j ANTREA-POL-EGRESSRULE1 -m comment --comment "Antrea: for rule egressRule1, policy AntreaClusterNetworkPolicy:name1"`,
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}

				rules2 := [][]string{
					{
						`-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-INGRESSRULE2-6 src -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule ingressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				rules3 := [][]string{
					{
						`-A ANTREA-POL-EGRESS-RULES -m set --match-set ANTREA-POL-EGRESSRULE2-6 dst -p tcp --dport 443 -j ACCEPT -m comment --comment "Antrea: for rule egressRule2, policy AntreaClusterNetworkPolicy:name1"`,
					},
				}
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128", "fec0::192:168:1:8/125"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE2-6", sets.New[string]("2002:1a23:fb44::1/128"), true).Times(1)
				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables(chains, rules1, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESS-RULES"}, rules2, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-INGRESSRULE1-6", true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-INGRESSRULE1"}, true).Times(1)

				mockRouteClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESS-RULES"}, rules3, true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPSet("ANTREA-POL-EGRESSRULE1-6", true).Times(1)
				mockRouteClient.DeleteNodeNetworkPolicyIPTables([]string{"ANTREA-POL-EGRESSRULE1"}, true).Times(1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			mockRouteClient := routetest.NewMockInterface(controller)
			r := newTestNodeReconciler(mockRouteClient, tt.ipv4Enabled, tt.ipv6Enabled)

			tt.expectedCalls(mockRouteClient.EXPECT())
			assert.NoError(t, r.BatchReconcile(tt.rulesToAdd))

			for _, ruleID := range tt.rulesToForget {
				assert.NoError(t, r.Forget(ruleID))
			}
		})
	}
}
