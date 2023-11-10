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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
)

func TestMulticlusterOptions(t *testing.T) {
	tests := []struct {
		name           string
		mcConfig       agentconfig.MulticlusterConfig
		featureGate    bool
		encapMode      string
		encryptionMode string
		expectedErr    string
	}{
		{
			name:        "empty input",
			mcConfig:    agentconfig.MulticlusterConfig{},
			expectedErr: "",
		},
		{
			name:        "empty input with feature enabled",
			mcConfig:    agentconfig.MulticlusterConfig{},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "Enable",
			mcConfig: agentconfig.MulticlusterConfig{
				Enable: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "Enable and EnableGateway",
			mcConfig: agentconfig.MulticlusterConfig{
				Enable:        true,
				EnableGateway: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "EnableGateway and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway:                true,
				EnableStretchedNetworkPolicy: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "EnableGateway false and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableStretchedNetworkPolicy: true,
			},
			featureGate: true,
			expectedErr: "Multi-cluster Gateway must be enabled to enable StretchedNetworkPolicy",
		},
		{
			name: "Multicluster with in-cluster WireGuard Encryption",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway: true,
			},
			featureGate:    true,
			encapMode:      "encap",
			encryptionMode: "wireguard",
			expectedErr:    "Multi-cluster Gateway doesn't support in-cluster WireGuard encryption",
		},
		{
			name: "NoEncap and feature disabled",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway: true,
			},
			encapMode:   "noEncap",
			expectedErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &agentconfig.AgentConfig{
				FeatureGates:     map[string]bool{"Multicluster": tt.featureGate},
				TrafficEncapMode: tt.encapMode,
				Multicluster:     tt.mcConfig,
			}
			if tt.encryptionMode != "" {
				config.TrafficEncryptionMode = tt.encryptionMode
			}
			o := &Options{config: config, enableAntreaProxy: true}
			features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
			o.setDefaults()
			if tt.mcConfig.Enable && tt.featureGate {
				assert.True(t, o.config.Multicluster.EnableGateway)
			}
			if !tt.mcConfig.Enable && !tt.mcConfig.EnableGateway {
				assert.False(t, o.config.Multicluster.EnableGateway)
			}

			err := o.validate(nil)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestNodeNetworkPolicyOptions(t *testing.T) {
	tests := []struct {
		name                    string
		nodeNetworkPolicyConfig agentconfig.NodeNetworkPolicyConfig
		featureGate             bool
		expectedErr             string
	}{
		{
			name:                    "feature is not enabled",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{},
			expectedErr:             "",
		},
		{
			name: "invalid direction",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction: "in",
						Protocol:  "tcp",
						Ports:     []string{"443"},
					},
				},
			},
			featureGate: true,
			expectedErr: `direction can only be "ingress" or "egress"`,
		},
		{
			name: "invalid ip families",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction:  "ingress",
						IPFamilies: "ip",
						Protocol:   "tcp",
						Ports:      []string{"443"},
					},
				},
			},
			featureGate: true,
			expectedErr: `ip families can only be "ipv4" or "ipv6", leave it empty for both "ipv4" and "ipv6"`,
		},
		{
			name: "invalid protocol",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction: "ingress",
						Protocol:  "icmp",
						Ports:     []string{"443"},
					},
				},
			},
			featureGate: true,
			expectedErr: `protocol can only be "tcp" or "udp", leave it empty for both "tcp" and "udp"`,
		},
		{
			name: "CIDR should not be specific when IP families is empty (both for IPv4 and IPv6)",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction:  "ingress",
						IPFamilies: "",
						Protocol:   "tcp",
						CIDR:       "192.168.1.1/24",
					},
				},
			},
			featureGate: true,
			expectedErr: `CIDR should be empty when ip families is empty`,
		},
		{
			name: "invalid CIDR",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction:  "ingress",
						IPFamilies: "ipv4",
						Protocol:   "tcp",
						CIDR:       "192.168.1.1",
					},
				},
			},
			featureGate: true,
			expectedErr: `CIDR is invalid`,
		},
		{
			name: "invalid CIDR for IPv6",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction:  "ingress",
						Protocol:   "tcp",
						IPFamilies: "ipv6",
						CIDR:       "192.168.1.0/24",
					},
				},
			},
			featureGate: true,
			expectedErr: `CIDR is IPv4 but ip families is not "ipv4"`,
		},
		{
			name: "invalid CIDR for IPv4",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction:  "ingress",
						Protocol:   "tcp",
						IPFamilies: "ipv4",
						CIDR:       "fec0::/64",
					},
				},
			},
			featureGate: true,
			expectedErr: `CIDR is IPv6 but ip families is not "ipv6"`,
		},
		{
			name: "invalid port range",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction: "ingress",
						Protocol:  "tcp",
						Ports:     []string{"80-79"},
					},
				},
			},
			featureGate: true,
			expectedErr: "start port must be smaller than end port",
		},
		{
			name: "invalid port pattern",
			nodeNetworkPolicyConfig: agentconfig.NodeNetworkPolicyConfig{
				PrivilegedRules: []agentconfig.PrivilegedRule{
					{
						Direction: "ingress",
						Protocol:  "tcp",
						Ports:     []string{"79:80"},
					},
				},
			},
			featureGate: true,
			expectedErr: "invalid port pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &agentconfig.AgentConfig{
				FeatureGates:      map[string]bool{"NodeNetworkPolicy": tt.featureGate},
				NodeNetworkPolicy: tt.nodeNetworkPolicyConfig,
			}
			o := &Options{config: config}
			features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
			o.setDefaults()

			err := o.validateNodeNetworkPolicyConfig()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}
