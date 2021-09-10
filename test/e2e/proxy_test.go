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

package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/features"
)

type expectTableFlows struct {
	tableID int
	flows   []string
}

// TestProxy is the top-level test which contains all subtests for
// Proxy related test cases so they can share setup, teardown.
func TestProxy(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfProxyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testProxyServiceSessionAffinityCase", func(t *testing.T) {
		skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
		testProxyServiceSessionAffinityCase(t, data)
	})
	t.Run("testProxyHairpinCase", func(t *testing.T) {
		testProxyHairpinCase(t, data)
	})
	t.Run("testProxyEndpointLifeCycleCase", func(t *testing.T) {
		testProxyEndpointLifeCycleCase(t, data)
	})
	t.Run("testProxyServiceLifeCycleCase", func(t *testing.T) {
		testProxyServiceLifeCycleCase(t, data)
	})
}

func skipIfProxyDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.AntreaProxy, true /* checkAgent */, false /* checkController */)
}

func testProxyServiceSessionAffinityCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func skipIfProxyAllDisabled(t *testing.T, data *TestData) {
	isProxyAll, err := data.isProxyAll()
	if err != nil {
		t.Fatalf("Error getting option antreaProxy.proxyAll value")
	}
	if !isProxyAll {
		t.Skipf("Skipping test because option antreaProxy.proxyAll is not enabled")
	}
}

func skipIfKubeProxyEnabled(t *testing.T, data *TestData) {
	_, err := data.clientset.AppsV1().DaemonSets(kubeNamespace).Get(context.TODO(), "kube-proxy", metav1.GetOptions{})
	if err == nil {
		t.Skipf("Skipping test because kube-proxy is running")
	}
}

func probeFromNode(node string, url string) error {
	_, _, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return err
}

func probeHostnameFromNode(node string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	_, hostname, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return hostname, err
}

func probeClientIPFromNode(node string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	_, clientIP, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return strings.Split(clientIP, ":")[0], err
}

func probeFromPod(data *TestData, podName string, url string) error {
	_, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	return err
}

func probeHostnameFromPod(data *TestData, podName string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	hostname, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	return hostname, err
}

func probeClientIPFromPod(data *TestData, podName string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	clientIP, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	return strings.Split(clientIP, ":")[0], err
}

func TestProxyLoadBalancerServiceIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyLoadBalancerService(t, false)
}

func TestProxyLoadBalancerServiceIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyLoadBalancerService(t, true)
}

func testProxyLoadBalancerService(t *testing.T, isIPv6 bool) {
	skipIfProxyDisabled(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)

	nodes := []string{nodeName(0), nodeName(1)}
	busyboxes := []string{"busybox-0", "busybox-1"}
	var busyboxIPs []string
	for idx, node := range nodes {
		podIPv4, podIPv6 := createTestClientPod(t, data, busyboxes[idx], node)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, podIPv4)
		} else {
			busyboxIPs = append(busyboxIPs, podIPv6)
		}
	}

	clusterIngressIP := []string{"169.254.169.1"}
	localIngressIP := []string{"169.254.169.2"}
	if isIPv6 {
		clusterIngressIP = []string{"fd75::aabb:ccdd:ef00"}
		localIngressIP = []string{"fd75::aabb:ccdd:ef01"}
	}
	createLoadBalancerService(t, data, "agnhost-cluster", clusterIngressIP, false, isIPv6)
	createLoadBalancerService(t, data, "agnhost-local", localIngressIP, true, isIPv6)
	port := "8080"
	clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
	localUrl := net.JoinHostPort(localIngressIP[0], port)

	agnhosts := []string{"agnhost-0", "agnhost-1"}
	for idx, node := range nodes {
		createAgnhostPod(t, data, agnhosts[idx], node, false)
	}
	t.Run("Pod CIDR Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, nodes, busyboxes, busyboxIPs, agnhosts)
	})

	hostAgnhosts := []string{"agnhost-host-0", "agnhost-host-1"}
	for idx, node := range nodes {
		require.NoError(t, data.deletePod(testNamespace, agnhosts[idx]))
		createAgnhostPod(t, data, hostAgnhosts[idx], node, true)
	}
	t.Run("Host Network Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, nodes, busyboxes, busyboxIPs, nodes)
	})
}

func loadBalancerTestCases(t *testing.T, data *TestData, clusterUrl, localUrl string, nodes, pods, podIPs, hostnames []string) {
	t.Run("ExternalTrafficPolicy:Cluster/Client:Node", func(t *testing.T) {
		testLoadBalancerClusterFromNode(t, data, nodes, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Pod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, pods, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Node", func(t *testing.T) {
		testLoadBalancerLocalFromNode(t, data, nodes, localUrl, hostnames)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, pods, localUrl, podIPs, hostnames)
	})
}

func createLoadBalancerService(t *testing.T, data *TestData, serviceName string, ingressIPs []string, nodeLoadExternal, isIPv6 bool) {
	ipProctol := corev1.IPv4Protocol
	if isIPv6 {
		ipProctol = corev1.IPv6Protocol
	}
	_, err := data.createAgnhostLoadBalancerService(serviceName, true, nodeLoadExternal, ingressIPs, &ipProctol)
	require.NoError(t, err)
}

func testLoadBalancerClusterFromNode(t *testing.T, data *TestData, nodes []string, url string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Node"
	for _, node := range nodes {
		require.NoError(t, probeFromNode(node, url), errMsg)
	}
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, pods []string, url string) {
	errMsg := "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Pod"
	for _, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, url), errMsg)
	}
}

func testLoadBalancerLocalFromNode(t *testing.T, data *TestData, nodes []string, url string, expectedHostname []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "TService LoadBalancer whose externalTrafficPolicy is Local should be able to be connected from Node"
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, url)
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostname[idx])
	}
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, pods []string, url string, expectedClientIPs, expectedHostnames []string) {
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from Pod"
	for idx, pod := range pods {
		hostname, err := probeHostnameFromPod(data, pod, url)
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostnames[idx])

		clientIP, err := probeClientIPFromPod(data, pod, url)
		require.NoError(t, err, errMsg)
		require.Equal(t, clientIP, expectedClientIPs[idx])
	}
}

func TestProxyNodePortServiceIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyNodePortService(t, false)
}

func TestProxyNodePortServiceIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyNodePortService(t, true)
}

func testProxyNodePortService(t *testing.T, isIPv6 bool) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)

	nodes := []string{nodeName(0), nodeName(1)}
	nodeIPs := []string{controlPlaneNodeIPv4(), workerNodeIPv4(1)}
	if isIPv6 {
		nodeIPs = []string{controlPlaneNodeIPv6(), workerNodeIPv6(1)}
	}

	busyboxes := []string{"busybox-0", "busybox-1"}
	var busyboxIPs []string
	for idx, node := range nodes {
		podIPv4, podIPv6 := createTestClientPod(t, data, busyboxes[idx], node)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, podIPv4)
		} else {
			busyboxIPs = append(busyboxIPs, podIPv6)
		}
	}

	portStrCluster := createNodePortServices(t, data, "agnhost-cluster", false, isIPv6)
	portStrLocal := createNodePortServices(t, data, "agnhost-local", true, isIPv6)

	agnhosts := []string{"agnhost-0", "agnhost-1"}
	for idx, node := range nodes {
		createAgnhostPod(t, data, agnhosts[idx], node, false)
	}
	t.Run("Pod CIDR Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, portStrCluster, portStrLocal, nodes, nodeIPs, busyboxes, busyboxIPs, agnhosts, false)
	})

	hostAgnhosts := []string{"agnhost-host-0", "agnhost-host-1"}
	for idx, node := range nodes {
		require.NoError(t, data.deletePod(testNamespace, agnhosts[idx]))
		createAgnhostPod(t, data, hostAgnhosts[idx], node, true)
	}
	t.Run("Host Network Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, portStrCluster, portStrLocal, nodes, nodeIPs, busyboxes, busyboxIPs, nodes, true)
	})
}

func nodePortTestCases(t *testing.T, data *TestData, portStrCluster, portStrLocal string, nodes, nodeIPs, pods, podIPs, hostnames []string, hostNetwork bool) {
	var clusterUrls, localUrls []string
	for _, nodeIP := range nodeIPs {
		clusterUrls = append(clusterUrls, net.JoinHostPort(nodeIP, portStrCluster))
		localUrls = append(localUrls, net.JoinHostPort(nodeIP, portStrLocal))
	}

	t.Run("ExternalTrafficPolicy:Cluster/Client:Remote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, data, nodes, clusterUrls)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Node", func(t *testing.T) {
		testNodePortClusterFromNode(t, data, nodes, clusterUrls)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Pod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, pods, clusterUrls)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Remote", func(t *testing.T) {
		if hostNetwork {
			t.Skipf("Skip this test as Endpoint is on host network")
		}
		testNodePortLocalFromRemote(t, data, nodes, localUrls, nodeIPs, []string{hostnames[1], hostnames[0]})
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Node", func(t *testing.T) {
		testNodePortLocalFromNode(t, data, nodes, localUrls, hostnames)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, pods, localUrls, podIPs, hostnames)
	})
}

func createAgnhostPod(t *testing.T, data *TestData, podName string, node string, hostNetwork bool) {
	args := []string{"netexec", "--http-port=8080"}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}
	require.NoError(t, data.createPodOnNode(podName, testNamespace, node, agnhostImage, []string{}, args, nil, ports, hostNetwork, nil))
	_, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, testNamespace))
}

func createTestClientPod(t *testing.T, data *TestData, client string, node string) (string, string) {
	// Create a busybox Pod on each node which is used as test client.
	require.NoError(t, data.createBusyboxPodOnNode(client, testNamespace, node, false))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, client, testNamespace))
	busybox, err := data.podWaitFor(defaultTimeout, client, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busybox.Status)

	ipv4 := busybox.Status.PodIP
	var ipv6 string
	for _, ip := range busybox.Status.PodIPs {
		if utilnet.IsIPv6String(ip.IP) {
			ipv6 = ip.IP
			break
		}
	}

	return ipv4, ipv6
}

func createNodePortServices(t *testing.T, data *TestData, serviceName string, nodeLocalExternal bool, isIPv6 bool) string {
	ipProctol := corev1.IPv4Protocol
	if isIPv6 {
		ipProctol = corev1.IPv6Protocol
	}
	nodePortSvc, err := data.createAgnhostNodePortService(serviceName, false, nodeLocalExternal, &ipProctol)
	require.NoError(t, err)

	var portStr string
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portStr = fmt.Sprint(port.NodePort)
			break
		}
	}
	return portStr
}

func testNodePortClusterFromRemote(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from remote Node"
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx]), errMsg)
	}
}

func testNodePortClusterFromNode(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "TService NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Node"
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx]), errMsg)
	}
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, pods, urls []string) {
	errMsg := "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Pod"
	for _, url := range urls {
		for _, pod := range pods {
			require.NoError(t, probeFromPod(data, pod, url), errMsg)
		}
	}
}

func testNodePortLocalFromRemote(t *testing.T, data *TestData, nodes, urls, expectedClientIPs, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from remote Node"
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostnames[idx])

		clientIP, err := probeClientIPFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, clientIP, expectedClientIPs[idx])
	}
}

func testNodePortLocalFromNode(t *testing.T, data *TestData, nodes, urls, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "There should be no errors when accessing to Service NodePort whose externalTrafficPolicy is Local from Node"
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostnames[idx])
	}
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, pods, urls, expectedClientIPs, expectedHostnames []string) {
	errMsg := "There should be no errors when accessing to Service NodePort whose externalTrafficPolicy is Local from Pod"
	for idx, pod := range pods {
		hostname, err := probeHostnameFromPod(data, pod, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostnames[idx])

		clientIP, err := probeClientIPFromPod(data, pod, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, clientIP, expectedClientIPs[idx])
	}
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceSessionAffinity(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService(nginx, true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)

	busyboxPod := randName("busybox-")
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, testNamespace, nodeName, false))
	defer data.deletePodAndWait(defaultTimeout, busyboxPod, testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyboxPod, testNamespace))
	stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", svc.Spec.ClusterIP, "-T", "1"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", ingressIP, "-T", "1"})
		require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	}

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	table40Output, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, "table=40"})
	require.NoError(t, err)
	if *ipFamily == corev1.IPv4Protocol {
		require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIP.ipv4.To4()), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[8:16]), "0")))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[0:8]), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	}
}
func testProxyHairpinCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
}

func TestProxyHairpin(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
}

func testProxyHairpin(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	busybox := randName("busybox-")
	nodeName := nodeName(1)
	err := data.createPodOnNode(busybox, testNamespace, nodeName, busyboxImage, []string{"nc", "-lk", "-p", "80"}, nil, nil, []corev1.ContainerPort{{ContainerPort: 80, Protocol: corev1.ProtocolTCP}}, false, nil)
	defer data.deletePodAndWait(defaultTimeout, busybox, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busybox, testNamespace))
	svc, err := data.createService(busybox, 80, 80, map[string]string{"antrea-e2e": busybox}, false, false, corev1.ServiceTypeClusterIP, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, busybox)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	stdout, stderr, err := data.runCommandFromPod(testNamespace, busybox, busyboxContainerName, []string{"nc", svc.Spec.ClusterIP, "80", "-w", "1", "-e", "ls", "/"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
}

func testProxyEndpointLifeCycleCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
}

func TestProxyEndpointLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
}

func testProxyEndpointLifeCycle(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")
	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService(nginx, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}

	keywords := make(map[int]string)
	keywords[42] = fmt.Sprintf("nat(dst=%s)", net.JoinHostPort(nginxIP, "80")) // endpointNATTable

	var groupKeywords []string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeywords = append(groupKeywords, fmt.Sprintf("set_field:0x%s->xxreg3", strings.TrimPrefix(hex.EncodeToString(*nginxIPs.ipv6), "0")))
	} else {
		groupKeywords = append(groupKeywords, fmt.Sprintf("0x%s->NXM_NX_REG3[]", strings.TrimPrefix(hex.EncodeToString(nginxIPs.ipv4.To4()), "0")))
	}

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.Contains(t, tableOutput, keyword)
	}

	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.Contains(t, groupOutput, k)
	}

	require.NoError(t, data.deletePodAndWait(defaultTimeout, nginx, testNamespace))

	// Wait for one second to make sure the pipeline to be updated.
	time.Sleep(time.Second)

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.NotContains(t, tableOutput, keyword)
	}

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.NotContains(t, groupOutput, k)
	}
}

func testProxyServiceLifeCycleCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func TestProxyServiceLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceLifeCycle(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}
	svc, err := data.createNginxClusterIPService(nginx, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(false, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	var svcLBflows []string
	if *ipFamily == corev1.IPv6Protocol {
		svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	}

	table42Format := "nat(dst=%s:80)"
	if *ipFamily == corev1.IPv6Protocol {
		table42Format = "nat(dst=[%s]:80)"
	}
	expectedFlows := []expectTableFlows{
		{
			41, // serviceLBTable
			svcLBflows,
		},
		{
			42,
			[]string{fmt.Sprintf(table42Format, nginxIP)}, // endpointNATTable
		},
	}

	var groupKeyword string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeyword = fmt.Sprintf("set_field:0x%s->xxreg3,load:0x%x->NXM_NX_REG4[0..15]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv6.To16()), "0"), 80)
	} else {
		groupKeyword = fmt.Sprintf("load:0x%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv4.To4()), "0"), 80)
	}
	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.Contains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.Contains(t, tableOutput, expectedFlow)
		}
	}

	require.NoError(t, data.deleteService(nginx))
	require.NoError(t, data.deleteService(nginxLBService))

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.NotContains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.NotContains(t, tableOutput, expectedFlow)
		}
	}
}
