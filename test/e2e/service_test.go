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

package e2e

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestClusterIP(t *testing.T) {
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfNumNodesLessThan(t, 2)
	echoServerCp := "echoserver-cp"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"

	// Create only on pod on control plane node.
	createTestEchoServerPods(t, data, echoServerCp, "", busyBoxCp, busyBoxWk, false)
	clusterIP := createClusterIPService(t, data)
	url := net.JoinHostPort(clusterIP, "8080")

	t.Run("ClusterIP", func(t *testing.T) {
		t.Run("Host on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfKubeProxyEnabledOnLinux(t, data, nodeName(1))
			skipIfProxyFullDisabled(t, data)
			testClusterIPFromNode(t, url, nodeName(1), echoServerCp)
		})
		t.Run("Host on the same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfKubeProxyEnabledOnLinux(t, data, nodeName(0))
			skipIfProxyFullDisabled(t, data)
			testClusterIPFromNode(t, url, nodeName(0), echoServerCp)
		})
		t.Run("Pod on same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testClusterIPFromPod(t, data, url, busyBoxCp, echoServerCp)
		})
		t.Run("Pod on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testClusterIPFromPod(t, data, url, busyBoxWk, echoServerCp)
		})
	})
}

func TestClusterIPWithHostEndpoint(t *testing.T) {
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfNumNodesLessThan(t, 2)
	echoServerCp := "echoserver-cp"
	busyBoxCp := "busybox-cp"
	busyBoxWk := "busybox-wk"
	hostname := nodeName(0)

	// Create only on pod on control plane node.
	createTestEchoServerPods(t, data, echoServerCp, "", busyBoxCp, busyBoxWk, true)
	clusterIP := createClusterIPService(t, data)
	url := net.JoinHostPort(clusterIP, "8080")

	t.Run("ClusterIP", func(t *testing.T) {
		t.Run("Host on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfKubeProxyEnabledOnLinux(t, data, nodeName(1))
			skipIfProxyFullDisabled(t, data)
			testClusterIPFromNode(t, url, nodeName(1), hostname)
		})
		t.Run("Host on the same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfKubeProxyEnabledOnLinux(t, data, nodeName(0))
			skipIfProxyFullDisabled(t, data)
			testClusterIPFromNode(t, url, nodeName(0), hostname)
		})
		t.Run("Pod on same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testClusterIPFromPod(t, data, url, busyBoxCp, hostname)
		})
		t.Run("Pod on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testClusterIPFromPod(t, data, url, busyBoxWk, hostname)
		})
	})
}

func skipIfKubeProxyEnabledOnLinux(t *testing.T, data *TestData, nodeName string) {
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Error fetching pods: %v", err)
	}
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "kube-proxy") && pod.Spec.NodeName == nodeName {
			t.Skipf("Skipping test because kube-proxy is running")
		}
	}
}

func testClusterIPFromPod(t *testing.T, data *TestData, clusteIPUrl, podName, hostname string) {
	errMsg := "Server ClusterIP should be able to be connected from pod"
	output, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", clusteIPUrl, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", hostname), fmt.Sprintf("hostname should be %s", hostname))
}

func testClusterIPFromNode(t *testing.T, clusteIPUrl, nodeName, hostname string) {
	errMsg := "Server ClusterIP should be able to be connected from node on the same k8s node"
	_, output, _, err := RunCommandOnNode(nodeName, strings.Join([]string{"wget", "-O", "-", clusteIPUrl, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", hostname), fmt.Sprintf("hostname should be %s", hostname))
}

func createClusterIPService(t *testing.T, data *TestData) string {
	ipProctol := corev1.IPv4Protocol
	clusterIP, err := data.createEchoServerClusterIPService("echoserver", false, &ipProctol)
	require.NoError(t, err)
	return clusterIP.Spec.ClusterIP
}

// TestNodePortWindows tests NodePort Service on Windows Node. It is a temporary test to replace upstream Kubernetes one:
// https://github.com/kubernetes/kubernetes/blob/ea0764452222146c47ec826977f49d7001b0ea8c/test/e2e/windows/service.go#L42
// Issue: https://github.com/antrea-io/antrea/issues/2289
func TestNodePortWindows(t *testing.T) {
	skipIfNoWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "agnhost"
	svcNode := nodeName(clusterInfo.windowsNodes[0])
	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, svcName, svcNode, corev1.ServiceTypeNodePort)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	// Unlike upstream Kubernetes Conformance, here the client is on a Linux Node (nodeName(0)).
	// It doesn't need to be the control-plane for e2e test and other Linux workers will work as well. However, in this
	// e2e framework, nodeName(0)/Control-plane Node is guaranteed to be a Linux one.
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, nodeName(0)))
	defer data.deletePodAndWait(defaultTimeout, clientName)
	_, err = data.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	require.NoError(t, err)

	nodeIP := clusterInfo.nodes[0].ip
	nodePort := int(svc.Spec.Ports[0].NodePort)
	addr := fmt.Sprintf("http://%s:%d", nodeIP, nodePort)

	cmd := append([]string{"curl", "--connect-timeout", "1", "--retry", "5", "--retry-connrefused"}, addr)
	stdout, stderr, err := data.runCommandFromPod(testNamespace, clientName, agnhostContainerName, cmd)
	if err != nil {
		t.Errorf("Error when running command '%s' from Pod '%s', stdout: %s, stderr: %s, error: %v",
			strings.Join(cmd, " "), clientName, stdout, stderr, err)
	} else {
		t.Logf("curl from Pod '%s' to '%s' succeeded", clientName, addr)
	}
}

func (data *TestData) createAgnhostServiceAndBackendPods(t *testing.T, name string, node string, svcType corev1.ServiceType) (*corev1.Service, func()) {
	ipv4Protocol := corev1.IPv4Protocol
	args := []string{"netexec", "--http-port=80", "--udp-port=80"}
	require.NoError(t, data.createPodOnNode(name, node, agnhostImage, []string{}, args, nil, []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}, false, nil))
	_, err := data.podWaitForIPs(defaultTimeout, name, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, testNamespace))
	svc, err := data.createService(name, 80, 80, map[string]string{"app": "agnhost"}, false, false, svcType, &ipv4Protocol)
	require.NoError(t, err)

	cleanup := func() {
		data.deletePodAndWait(defaultTimeout, name)
		data.deleteServiceAndWait(defaultTimeout, name)
	}

	return svc, cleanup
}
