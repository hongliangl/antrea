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

package main

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"net"
	"regexp"
	"strconv"
	"strings"

	"antrea.io/antrea/pkg/agent/util"
)

var getAllNodeAddresses = util.GetAllNodeAddresses

func getAvailableNodePortAddresses(nodePortAddressesFromConfig []string, excludeDevices []string) ([]net.IP, []net.IP, error) {
	// Get all IP addresses of Node
	nodeAddressesIPv4, nodeAddressesIPv6, err := getAllNodeAddresses(excludeDevices)
	if err != nil {
		return nil, nil, err
	}
	// If option `NodePortAddresses` is not set, then all Node IP addresses will be used as NodePort IP address.
	if len(nodePortAddressesFromConfig) == 0 {
		return nodeAddressesIPv4, nodeAddressesIPv6, nil
	}

	var nodePortIPNets []*net.IPNet
	for _, nodePortIP := range nodePortAddressesFromConfig {
		_, ipNet, _ := net.ParseCIDR(nodePortIP)
		nodePortIPNets = append(nodePortIPNets, ipNet)
	}

	var nodePortAddressesIPv4, nodePortAddressesIPv6 []net.IP
	for _, nodePortIPNet := range nodePortIPNets {
		for i := range nodeAddressesIPv4 {
			if nodePortIPNet.Contains(nodeAddressesIPv4[i]) {
				nodePortAddressesIPv4 = append(nodePortAddressesIPv4, nodeAddressesIPv4[i])
			}
		}
		for i := range nodeAddressesIPv6 {
			if nodePortIPNet.Contains(nodeAddressesIPv6[i]) {
				nodePortAddressesIPv6 = append(nodePortAddressesIPv6, nodeAddressesIPv6[i])
			}
		}
	}
	return nodePortAddressesIPv4, nodePortAddressesIPv6, nil
}

// parsePortRange parses a port range ("<start>-<end>") and checks that it is valid.
func parsePortRange(portRangeStr string) (start, end int, err error) {
	portsRange := strings.Split(portRangeStr, "-")
	if len(portsRange) != 2 {
		return 0, 0, fmt.Errorf("wrong port range format: %s", portRangeStr)
	}

	if start, err = strconv.Atoi(portsRange[0]); err != nil {
		return 0, 0, err
	}

	if end, err = strconv.Atoi(portsRange[1]); err != nil {
		return 0, 0, err
	}

	if end <= start {
		return 0, 0, fmt.Errorf("start port must be smaller than end port: %s", portRangeStr)
	}

	return start, end, nil
}

func getPodCIDRs(o *Options, k8sClient clientset.Interface) []*net.IPNet {
	// Get Pod CIDR from agent config
	podCIDRStr := o.config.PodCIDR

	if podCIDRStr == "" {
		// Try kube-proxy ConfigMap
		if cidr := extractPodCIDRFromConfigMap(
			k8sClient,
			"kube-system",
			"kube-proxy",
			"config.conf",
			"clusterCIDR",
		); cidr != "" {
			podCIDRStr = cidr
		}
	}

	if podCIDRStr == "" {
		// Try kubeadm-config ConfigMap
		if cidr := extractPodCIDRFromConfigMap(k8sClient,
			"kube-system",
			"kubeadm-config",
			"ClusterConfiguration",
			"podSubnet",
		); cidr != "" {
			podCIDRStr = cidr
		}
	}

	if podCIDRStr == "" {
		klog.Info("No Pod CIDR was found")
		return nil
	}

	var podCIDRs []*net.IPNet
	for _, cidrStr := range strings.Split(podCIDRStr, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			klog.ErrorS(err, "Failed to parse Pod CIDR", "Pod CIDR", cidrStr)
			continue
		}
		podCIDRs = append(podCIDRs, cidr)
	}

	return podCIDRs
}

func extractPodCIDRFromConfigMap(client clientset.Interface, namespace, name, key, patternKey string) string {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		klog.V(2).ErrorS(err, "Failed to get ConfigMap", "namespace", namespace, "name", name)
		return ""
	}
	data, ok := cm.Data[key]
	if !ok {
		klog.V(2).InfoS("Key is not found from ConfigMap", "namespace", namespace, "name", name, "key", key)
		return ""
	}

	pattern := fmt.Sprintf(`(?m)^\s*%s\s*:\s*"?([0-9a-fA-F.:/,\s]+)"?`, patternKey)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(data)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}
