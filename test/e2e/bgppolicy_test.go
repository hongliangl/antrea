// Copyright 2024 Antrea Authors
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

package e2e

import (
	"antrea.io/antrea/pkg/agent/bgp"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/test/e2e/providers/exec"
	"fmt"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"strings"
	"testing"
)

type BGPPolicySpecBuilder struct {
	Spec crdv1alpha1.BGPPolicySpec
	Name string
}

func TestBGPPolicy(t *testing.T) {
	var peers []bgp.PeerConfig
	for _, node := range clusterInfo.nodes {
		peer := bgp.PeerConfig{
			BGPPeer: &crdv1alpha1.BGPPeer{
				Address: node.ipv4Addr,
				ASN:     64512,
			},
			Password: node.name,
		}
		peers = append(peers, peer)
	}
	err := configureFRRRouterBGP(t, 65000, 120, peers)
	assert.NoError(t, err)

	err = cleanupFRRRouterBGP(t, 65000)
	assert.NoError(t, err)
}

// BGPPolicy builder

// Test advertise Service
// ECMP
// iTP/eTP
// Egress
// Pod CIDR

// Secret

func configureFRRRouterBGP(t *testing.T, asn int32, gracefulRestartTime int, peers []bgp.PeerConfig) error {
	var frrCommands []string
	frrCommands = append(frrCommands, "configure terminal", fmt.Sprintf("router bgp %d", asn))
	if gracefulRestartTime != 0 {
		frrCommands = append(frrCommands, fmt.Sprintf("bgp graceful-restart restart-time %d", gracefulRestartTime))
	}
	for _, peer := range peers {
		frrCommands = append(frrCommands, fmt.Sprintf("neighbor %s remote-as %d", peer.Address, peer.ASN))
		if peer.Password != "" {
			frrCommands = append(frrCommands, fmt.Sprintf("neighbor %s password %s", peer.Address, peer.Password))
		}
		if peer.Port != nil {
			frrCommands = append(frrCommands, fmt.Sprintf("neighbor %sport %d", peer.Address, *peer.Port))
		}
		if peer.MultihopTTL != nil {
			frrCommands = append(frrCommands, fmt.Sprintf("neighbor %s ebgp-multihop %d", peer.Address, *peer.MultihopTTL))
		}
	}
	frrCommands = append(frrCommands, "exit", "exit", "write memory")

	cmd := "/usr/bin/vtysh"
	stdin := strings.Join(frrCommands, "\n")

	rc, stdout, stderr, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, stdin)
	t.Log(stdout)
	t.Log(stderr)
	if err != nil || rc != 0 {
		return fmt.Errorf("error when running command '%s' stdin '%s': %v", cmd, stdin, err)
	}

	return nil
}

func cleanupFRRRouterBGP(t *testing.T, asn int32) error {
	var frrCommands []string
	frrCommands = append(frrCommands, "configure terminal", fmt.Sprintf("no router bgp %d", asn))
	frrCommands = append(frrCommands, "exit", "write memory")

	cmd := "/usr/bin/vtysh"
	stdin := strings.Join(frrCommands, "\n")

	rc, stdout, stderr, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, stdin)
	t.Log(stdout)
	t.Log(stderr)
	if err != nil || rc != 0 {
		return fmt.Errorf("error when running command '%s' stdin '%s': %v", cmd, stdin, err)
	}
	return nil
}

func (b *BGPPolicySpecBuilder) SetName(name string) *BGPPolicySpecBuilder {
	b.Name = name
	return b
}

func (b *BGPPolicySpecBuilder) SetListenPort(port int32) *BGPPolicySpecBuilder {
	b.Spec.ListenPort = ptr.To[int32](port)
	return b
}

func (b *BGPPolicySpecBuilder) SetLocalASN(asn int32) *BGPPolicySpecBuilder {
	b.Spec.LocalASN = asn
	return b
}

func (b *BGPPolicySpecBuilder) SetAdvertisements(nodeSelector map[string]string) *BGPPolicySpecBuilder {
	b.Spec.NodeSelector = metav1.LabelSelector{
		MatchLabels: nodeSelector,
	}
	return b
}

func (b *BGPPolicySpecBuilder) SetAdvertiseServiceIPs(serviceIPTypes []crdv1alpha1.ServiceIPType) *BGPPolicySpecBuilder {
	b.Spec.Advertisements.Service = &crdv1alpha1.ServiceAdvertisement{IPTypes: serviceIPTypes}
	return b
}

func (b *BGPPolicySpecBuilder) SetAdvertiseEgressIPs() *BGPPolicySpecBuilder {
	b.Spec.Advertisements.Egress = &crdv1alpha1.EgressAdvertisement{}
	return b
}

func (b *BGPPolicySpecBuilder) SetAdvertisePodIPs() *BGPPolicySpecBuilder {
	b.Spec.Advertisements.Pod = &crdv1alpha1.PodAdvertisement{}
	return b
}

func (b *BGPPolicySpecBuilder) SetBGPPeers(peers []crdv1alpha1.BGPPeer) *BGPPolicySpecBuilder {
	b.Spec.BGPPeers = peers
	return b
}

func (b *BGPPolicySpecBuilder) Get() *crdv1alpha1.BGPPolicy {
	return &crdv1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}
