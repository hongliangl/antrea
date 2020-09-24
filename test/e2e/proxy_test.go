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
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/features"
)

type expectTableFlows struct {
	tableID int
	flows   []string
}

func skipIfProxyDisabled(t *testing.T, data *TestData) {
	skipIfFeatureDisabled(t, data, features.AntreaProxy, true /* checkAgent */, false /* checkController */)
}

func skipIfProxyFullDisabled(t *testing.T, data *TestData) {
	skipIfFeatureDisabled(t, data, features.AntreaProxyFull, true /* checkAgent */, false /* checkController */)
}

func TestProxyLoadBalancerService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	echoServerCp := "echoserver-cp"
	echoServerWk := "echoserver-wk"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"
	ingressIPCluster := []string{"169.254.169.1"}
	ingressIPLocal := []string{"169.254.169.2"}
	port := "8080"
	busyBoxCpIP, busyBoxWkIP := createTestEchoServerPods(t, data, echoServerCp, echoServerWk, busyBoxCp, busyBoxWk, false)
	createLoadBalancerServices(t, data, ingressIPCluster, ingressIPLocal)
	nodeBalancerClusterUrl := net.JoinHostPort(ingressIPCluster[0], port)
	nodeBalancerLocalUrl := net.JoinHostPort(ingressIPLocal[0], port)

	t.Run("Case=LoadBalancerClusterClientFromLocal", func(t *testing.T) {
		testLoadBalancerClusterFromLocal(t, nodeBalancerClusterUrl)
	})
	t.Run("Case=LoadBalancerClusterClientFromPod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, nodeBalancerClusterUrl, busyBoxCp, busyBoxWk)
	})
	t.Run("Case=LoadBalancerLocalClientFromLocal", func(t *testing.T) {
		testLoadBalancerLocalFromLocal(t, nodeBalancerLocalUrl, echoServerCp, echoServerWk)
	})
	t.Run("Case=LoadBalancerLocalClientFromPod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, nodeBalancerLocalUrl, busyBoxCp, busyBoxWk, busyBoxCpIP, busyBoxWkIP, echoServerCp, echoServerWk)
	})
}

func TestProxyLoadBalancerServiceWithHostEndpoint(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	echoServerCp := "echoserver-host-cp"
	echoServerWk := "echoserver-host-wk"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"
	ingressIPCluster := []string{"169.254.169.1"}
	ingressIPLocal := []string{"169.254.169.2"}
	port := "8080"
	busyBoxCpIP, busyBoxWkIP := createTestEchoServerPods(t, data, echoServerCp, echoServerWk, busyBoxCp, busyBoxWk, true)
	createLoadBalancerServices(t, data, ingressIPCluster, ingressIPLocal)
	nodeBalancerClusterUrl := net.JoinHostPort(ingressIPCluster[0], port)
	nodeBalancerLocalUrl := net.JoinHostPort(ingressIPLocal[0], port)
	cpHostname := controlPlaneNodeName()
	wkHostname := workerNodeName(1)

	t.Run("Case=LoadBalancerClusterClientFromLocal", func(t *testing.T) {
		testLoadBalancerClusterFromLocal(t, nodeBalancerClusterUrl)
	})
	t.Run("Case=LoadBalancerClusterClientFromPod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, nodeBalancerClusterUrl, busyBoxCp, busyBoxWk)
	})
	t.Run("Case=LoadBalancerLocalClientFromLocal", func(t *testing.T) {
		testLoadBalancerLocalFromLocal(t, nodeBalancerLocalUrl, cpHostname, wkHostname)
	})
	t.Run("Case=LoadBalancerLocalClientFromPod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, nodeBalancerLocalUrl, busyBoxCp, busyBoxWk, busyBoxCpIP, busyBoxWkIP, cpHostname, wkHostname)
	})
}

func createLoadBalancerServices(t *testing.T, data *TestData, ingressIPCluster, ingressIPLocal []string) {
	ipProctol := corev1.IPv4Protocol
	_, err := data.createEchoServerLoadBalancerService("echoserver-cluster", true, false, ingressIPCluster, &ipProctol)
	require.NoError(t, err)
	_, err = data.createEchoServerLoadBalancerService("echoserver-local", true, true, ingressIPLocal, &ipProctol)
	require.NoError(t, err)
}

func testLoadBalancerClusterFromLocal(t *testing.T, lbUrl string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from localhost"
	_, _, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", lbUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", lbUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, lbUrl, busyboxCp, busyBoxWk string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from pod"
	_, _, err := data.runCommandFromPod(testNamespace, busyboxCp, busyboxContainerName, []string{"wget", "-O", "-", lbUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, busyBoxWk, busyboxContainerName, []string{"wget", "-O", "-", lbUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
}

func testLoadBalancerLocalFromLocal(t *testing.T, lbUrl, cpHostname, wkHostname string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Local should be able to be connected from local with Antrea gateway IP"
	_, output, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", lbUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))

	_, output, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", lbUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, lbUrl, busyboxCp, busyBoxWk, busyboxCpIP, busyBoxWkIP, cpHostname, wkHostname string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from pod "
	output, _, err := data.runCommandFromPod(testNamespace, busyboxCp, busyboxContainerName, []string{"wget", "-O", "-", lbUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", busyboxCpIP), fmt.Sprintf("client IP should be %s", busyboxCpIP))

	output, _, err = data.runCommandFromPod(testNamespace, busyBoxWk, busyboxContainerName, []string{"wget", "-O", "-", lbUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", busyBoxWkIP), fmt.Sprintf("client IP should be %s", busyBoxWkIP))
}

func TestProxyNodePortService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	echoServerCp := "echoserver-cp"
	echoServerWk := "echoserver-wk"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"

	busyBoxCpIP, busyBoxWkIP := createTestEchoServerPods(t, data, echoServerCp, echoServerWk, busyBoxCp, busyBoxWk, false)
	portCluster, portLocal := createNodePortServices(t, data)
	cpIP := controlPlaneNodeIP()
	wkIP := workerNodeIP(1)
	nodePortClusterCpUrl := net.JoinHostPort(cpIP, portCluster)
	nodePortClusterWkUrl := net.JoinHostPort(wkIP, portCluster)
	nodePortClusterLoUrl := net.JoinHostPort("127.0.0.1", portCluster)
	nodePortLocalCpUrl := net.JoinHostPort(cpIP, portLocal)
	nodePortLocalWkUrl := net.JoinHostPort(wkIP, portLocal)
	nodePortLocalLoUrl := net.JoinHostPort("127.0.0.1", portLocal)

	t.Run("Case=NodePortClusterClientFromRemote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, nodePortClusterCpUrl, nodePortClusterCpUrl)
	})
	t.Run("Case=NodePortClusterClientFromLocalWithNodeIP", func(t *testing.T) {
		testNodePortClusterFromLocalWithNodeIP(t, nodePortClusterCpUrl, nodePortClusterWkUrl)
	})
	t.Run("Case=NodePortClusterClientFromLocalWithLoopbackIP", func(t *testing.T) {
		testNodePortClusterFromLocalWithLoopbackIP(t, nodePortClusterLoUrl)
	})
	t.Run("Case=NodePortClusterClientFromPod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, nodePortClusterCpUrl, nodePortClusterCpUrl, busyBoxCp, busyBoxWk)
	})
	t.Run("Case=NodePortLocalClientFromRemote", func(t *testing.T) {
		testNodePortLocalFromRemote(t, nodePortLocalCpUrl, nodePortLocalWkUrl, cpIP, wkIP, echoServerCp, echoServerWk)
	})
	t.Run("Case=NodePortLocalClientFromLocalWithNodeIP", func(t *testing.T) {
		testNodePortLocalFromLocalWithNodeIP(t, nodePortLocalCpUrl, nodePortLocalWkUrl, cpIP, wkIP, echoServerCp, echoServerWk)
	})
	t.Run("Case=NodePortLocalClientFromLocalWithLoopbackIP", func(t *testing.T) {
		testNodePortLocalFromLocalWithLoopbackIP(t, nodePortLocalLoUrl, cpIP, wkIP, echoServerCp, echoServerWk)
	})
	t.Run("Case=NodePortLocalClientFromPod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, nodePortLocalCpUrl, nodePortLocalWkUrl, busyBoxCp, busyBoxWk, busyBoxCpIP, busyBoxWkIP, echoServerCp, echoServerWk)
	})
}

func TestProxyNodePortServiceWithHostEndpoints(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	echoServerCp := "echoserver-host-cp"
	echoServerWk := "echoserver-host-wk"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"

	busyBoxCpIP, busyBoxWkIP := createTestEchoServerPods(t, data, echoServerCp, echoServerWk, busyBoxCp, busyBoxWk, true)
	portCluster, portLocal := createNodePortServices(t, data)
	cpIP := controlPlaneNodeIP()
	wkIP := workerNodeIP(1)
	nodePortClusterCpUrl := net.JoinHostPort(cpIP, portCluster)
	nodePortClusterWkUrl := net.JoinHostPort(wkIP, portCluster)
	nodePortClusterLoUrl := net.JoinHostPort("127.0.0.1", portCluster)
	nodePortLocalCpUrl := net.JoinHostPort(cpIP, portLocal)
	nodePortLocalWkUrl := net.JoinHostPort(wkIP, portLocal)
	nodePortLocalLoUrl := net.JoinHostPort("127.0.0.1", portLocal)
	vIP := "169.254.169.253"

	t.Run("Case=NodePortClusterClientFromRemote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, nodePortClusterCpUrl, nodePortClusterCpUrl)
	})
	t.Run("Case=NodePortClusterClientFromLocalWithNodeIP", func(t *testing.T) {
		testNodePortClusterFromLocalWithNodeIP(t, nodePortClusterCpUrl, nodePortClusterWkUrl)
	})
	t.Run("Case=NodePortClusterClientFromLocalWithLoopbackIP", func(t *testing.T) {
		testNodePortClusterFromLocalWithLoopbackIP(t, nodePortClusterLoUrl)
	})
	t.Run("Case=NodePortClusterClientFromPod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, nodePortClusterCpUrl, nodePortClusterCpUrl, busyBoxCp, busyBoxWk)
	})
	t.Run("Case=NodePortLocalClientFromRemote", func(t *testing.T) {
		testNodePortLocalFromRemote(t, nodePortLocalCpUrl, nodePortLocalWkUrl, vIP, vIP, controlPlaneNodeName(), workerNodeName(1))
	})
	t.Run("Case=NodePortLocalClientFromLocalWithLoopbackIP", func(t *testing.T) {
		testNodePortLocalFromLocalWithLoopbackIP(t, nodePortLocalLoUrl, "dummy", "dummy", controlPlaneNodeName(), workerNodeName(1))
	})
	t.Run("Case=NodePortLocalClientFromPod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, nodePortLocalCpUrl, nodePortLocalWkUrl, busyBoxCp, busyBoxWk, busyBoxCpIP, busyBoxWkIP, controlPlaneNodeName(), workerNodeName(1))
	})
}

func createTestEchoServerPods(t *testing.T, data *TestData, echoServerCp, echoServerWk, busyBoxCp, busyBoxWk string, hostNetwork bool) (string, string) {
	// Create test echoserver pod on each node.
	if echoServerCp != "" {
		require.NoError(t, data.createEchoServerPodOnNode(echoServerCp, nodeName(0), hostNetwork))
		_, err := data.podWaitForIPs(defaultTimeout, echoServerCp, testNamespace)
		require.NoError(t, err)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, echoServerCp, testNamespace))
	}
	if echoServerWk != "" {
		require.NoError(t, data.createEchoServerPodOnNode(echoServerWk, nodeName(1), hostNetwork))
		_, err := data.podWaitForIPs(defaultTimeout, echoServerWk, testNamespace)
		require.NoError(t, err)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, echoServerWk, testNamespace))
	}

	// Create a busybox Pod on each node which is used as test client.
	require.NoError(t, data.createBusyboxPodOnNode(busyBoxCp, nodeName(0)))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyBoxCp, testNamespace))
	busyboxCpPod, err := data.podWaitFor(defaultTimeout, busyBoxCp, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busyboxCpPod.Status)
	require.NoError(t, data.createBusyboxPodOnNode(busyBoxWk, nodeName(1)))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyBoxWk, testNamespace))
	busyboxWkPod, err := data.podWaitFor(defaultTimeout, busyBoxWk, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busyboxWkPod.Status)
	return busyboxCpPod.Status.PodIP, busyboxWkPod.Status.PodIP
}

func createNodePortServices(t *testing.T, data *TestData) (string, string) {
	ipProctol := corev1.IPv4Protocol
	nodePortCluster, err := data.createEchoServerNodePortService("echoserver-cluster", true, false, &ipProctol)
	require.NoError(t, err)
	nodePortLocal, err := data.createEchoServerNodePortService("echoserver-local", true, true, &ipProctol)
	require.NoError(t, err)
	var portCluster, portLocal string
	for _, port := range nodePortCluster.Spec.Ports {
		if port.NodePort != 0 {
			portCluster = fmt.Sprint(port.NodePort)
			break
		}
	}
	for _, port := range nodePortLocal.Spec.Ports {
		if port.NodePort != 0 {
			portLocal = fmt.Sprint(port.NodePort)
			break
		}
	}
	return portCluster, portLocal
}

func testNodePortClusterFromRemote(t *testing.T, nodePortCpUrl, nodePortWkUrl string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from remote"
	_, _, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testNodePortClusterFromLocalWithNodeIP(t *testing.T, nodePortCpUrl, nodePortWkUrl string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from localhost with node IP"
	_, _, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testNodePortClusterFromLocalWithLoopbackIP(t *testing.T, nodePortloUrl string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from localhost with loopback IP"
	_, _, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortloUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortloUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, nodePortCpUrl, nodePortWkUrl, busyboxCp, busyBoxWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from pod"
	_, _, err := data.runCommandFromPod(testNamespace, busyboxCp, busyboxContainerName, []string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, busyboxCp, busyboxContainerName, []string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, busyBoxWk, busyboxContainerName, []string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, busyBoxWk, busyboxContainerName, []string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
}

func testNodePortLocalFromRemote(t *testing.T, nodePortCpUrl, nodePortWkUrl, cpIP, wkIP, cpHostname, wkHostname string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from remote"
	_, output, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", cpIP), fmt.Sprintf("client IP should be %s", cpIP))
	_, output, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", wkIP), fmt.Sprintf("client IP should be %s", wkIP))
}

func testNodePortLocalFromLocalWithNodeIP(t *testing.T, nodePortCpUrl, nodePortWkUrl, cpIP, wkIP, cpHostname, wkHostname string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from local with node IP"
	_, output, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", cpIP), fmt.Sprintf("client IP should be %s", cpIP))

	_, output, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", wkIP), fmt.Sprintf("client IP should be %s", wkIP))
}

func testNodePortLocalFromLocalWithLoopbackIP(t *testing.T, nodePortLoUrl, cpIP, wkIP, cpHostname, wkHostname string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from local with loopback IP"
	_, output, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", nodePortLoUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", cpIP), fmt.Sprintf("client IP should not be %s as loopback address will be SNATed", cpIP))

	_, output, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", nodePortLoUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", wkIP), fmt.Sprintf("client IP should not be %s as loopback address will be SNATed", wkIP))
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, nodePortCpUrl, nodePortWkUrl, busyboxCp, busyBoxWk, busyboxCpIP, busyBoxWkIP, cpHostname, wkHostname string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from pod "
	output, _, err := data.runCommandFromPod(testNamespace, busyboxCp, busyboxContainerName, []string{"wget", "-O", "-", nodePortCpUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", cpHostname), fmt.Sprintf("hostname should be %s", cpHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", busyboxCpIP), fmt.Sprintf("client IP should be %s", busyboxCpIP))

	output, _, err = data.runCommandFromPod(testNamespace, busyBoxWk, busyboxContainerName, []string{"wget", "-O", "-", nodePortWkUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", wkHostname), fmt.Sprintf("hostname should be %s", wkHostname))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", busyBoxWkIP), fmt.Sprintf("client IP should be %s", busyBoxWkIP))
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

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
	nginx := "nginx"
	require.NoError(t, data.createNginxPodOnNode(nginx, nodeName))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService("", true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)

	busyboxPod := "busybox"
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, nodeName))
	defer data.deletePodAndWait(defaultTimeout, busyboxPod)
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

func TestProxyHairpin(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

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
	busybox := "busybox"
	nodeName := nodeName(1)
	err := data.createPodOnNode(busybox, nodeName, busyboxImage, []string{"nc", "-lk", "-p", "80"}, nil, nil, []corev1.ContainerPort{{ContainerPort: 80, Protocol: corev1.ProtocolTCP}}, false, nil)
	defer data.deletePodAndWait(defaultTimeout, busybox)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busybox, testNamespace))
	svc, err := data.createService(busybox, 80, 80, map[string]string{"antrea-e2e": "busybox"}, false, false, corev1.ServiceTypeClusterIP, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, busybox)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	stdout, stderr, err := data.runCommandFromPod(testNamespace, busybox, busyboxContainerName, []string{"nc", svc.Spec.ClusterIP, "80", "-w", "1", "-e", "ls", "/"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
}

func TestProxyEndpointLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

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
	nginx := "nginx"
	require.NoError(t, data.createNginxPodOnNode(nginx, nodeName))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService("", false, ipFamily)
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

	require.NoError(t, data.deletePodAndWait(defaultTimeout, nginx))

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

func TestProxyServiceLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t, data)

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
	nginx := "nginx"
	require.NoError(t, data.createNginxPodOnNode(nginx, nodeName))
	defer data.deletePodAndWait(defaultTimeout, nginx)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}
	svc, err := data.createNginxClusterIPService("", false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(false, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	svcLBflows := make([]string, len(ingressIPs)+1)
	if *ipFamily == corev1.IPv6Protocol {
		svcLBflows[0] = fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP)
		for idx, ingressIP := range ingressIPs {
			svcLBflows[idx+1] = fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP)
		}
	} else {
		svcLBflows[0] = fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP)
		for idx, ingressIP := range ingressIPs {
			svcLBflows[idx+1] = fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP)
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
