// +build windows
// Copyright 2020 Antrea Authors
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

package proxy

import (
	"fmt"
	"net"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// installLoadBalancerServiceFlows installs OpenFlow entries for LoadBalancer Service.
// The rules for traffic from local Pod to LoadBalancer Service are the same with rules for Cluster Service.
// For the LoadBalancer Service traffic from outside, specific rules are install to forward the packets
// to the host network to let kube-proxy handle the traffic.
// Note that, NodePort Service is not supported on Windows currently.
func (p *proxier) installLoadBalancerService(groupID binding.GroupIDType, loadBalancerIPStrings []string,
	svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.InstallServiceFlows(groupID, net.ParseIP(ingress), svcPort, protocol, affinityTimeout); err != nil {
				return fmt.Errorf("failed to install Service LoadBalancer load balancing flows: %w", err)
			}
			if err := p.ofClient.InstallLoadBalancerServiceFromOutsideFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to install Service LoadBalancer flows: %w", err)
			}
			if err := p.ofClient.InstallServiceClassifierFlow(groupID, net.ParseIP(ingress), svcPort, protocol, affinityTimeout, nodeLocalExternal); err != nil {
				return fmt.Errorf("failed to install Service LoadBalancer classifying flows: %w", err)
			}
		}
	}
	if err := p.routeClient.AddLoadBalancer(svcPort, protocol, loadBalancerIPStrings, p.isIPv6); err != nil {
		return fmt.Errorf("failed to install Service LoadBalancer traffic redirecting flows: %w", err)
	}
	return nil
}

// uninstallLoadBalancerService removes flows and configurations for Service LoadBalancer.
func (p *proxier) uninstallLoadBalancerService(loadBalancerIPStrings []string, svcPort uint16, protocol binding.Protocol) error {
	for _, ingress := range loadBalancerIPStrings {
		if ingress != "" {
			if err := p.ofClient.UninstallServiceFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove Service LoadBalancer load balancing flows: %w", err)
			}
			if err := p.ofClient.UninstallLoadBalancerServiceFromOutsideFlows(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove Service LoadBalancer flows: %w", err)
			}
			if err := p.ofClient.UninstallServiceClassifierFlow(net.ParseIP(ingress), svcPort, protocol); err != nil {
				return fmt.Errorf("failed to remove Service LoadBalancer classifying flows: %w", err)
			}
		}
	}
	if err := p.routeClient.DeleteLoadBalancer(svcPort, protocol, loadBalancerIPStrings, p.isIPv6); err != nil {
		return fmt.Errorf("failed to remove Service LoadBalancer traffic redirecting flows: %w", err)
	}
	return nil
}

func (p *proxier) installNodePortService(groupID binding.GroupIDType, svcPort uint16, protocol binding.Protocol, affinityTimeout uint16, nodeLocalExternal bool) error {
	return nil
}

func (p *proxier) uninstallNodePortService(svcPort uint16, protocol binding.Protocol) error {
	return nil
}
