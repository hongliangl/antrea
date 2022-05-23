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

package e2e

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

var (
	fakeExternalPod   = "fake-pod"
	fakeExternalPodNS = "fake-ns"
	fakeExternalIP    = "1.1.1.1"
	fakeExternalGW    = "1.1.1.254"

	vni           = int32(1)
	dstVXLANPort  = int32(4790)
	dstGENEVEPort = int32(6082)
	greKey        = int32(2222)

	labels = map[string]string{"tc-e2e": "agnhost"}

	testNode      string
	antreaPodName string
)

func TestTrafficControl(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv4Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	ac := func(config *agentconfig.AgentConfig) {
		config.FeatureGates["TrafficControl"] = true
	}

	if err := data.mutateAntreaConfigMap(nil, ac, true, true); err != nil {
		t.Fatalf("Failed to enable TrafficControl feature: %v", err)
	}

	testNode = controlPlaneNodeName()
	antreaPodName, err = data.getAntreaPodOnNode(testNode)
	if err != nil {
		t.Fatalf("Error when retrieving the name of the Antrea Pod running on Node '%s': %v", testNode, err)
	}

	// Create a host network Pod to fake external network.
	cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/%[4]d dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/%[4]d dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
sleep 3600`, fakeExternalPodNS, fakeExternalIP, fakeExternalGW, 24)
	if err := data.createPodOnNode(fakeExternalPod, testNamespace, testNode, agnhostImage, []string{"sh", "-c", cmd}, nil, nil, nil, true, func(pod *corev1.Pod) {
		privileged := true
		pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &privileged}
	}); err != nil {
		t.Fatalf("Failed to create client Pod: %v", err)
	}
	defer deletePodWrapper(t, data, testNamespace, fakeExternalPod)
	if err := data.podWaitForRunning(defaultTimeout, fakeExternalPod, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", fakeExternalPod)
	}

	// Create a Pod.
	podName := "test-tc-tunnel-mirror"
	require.NoError(t, createTestTCPod(t, data, podName, labels))
	defer data.deletePodAndWait(defaultTimeout, podName, testNamespace)
	podIPs, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", podName, err)
	}
	podIP := podIPs.ipv4.String()

	t.Run("TestVXLANMirror", func(t *testing.T) { testVXLANMirror(t, data, podIP) })
	t.Run("TestGENEVEMirror", func(t *testing.T) { testGENEVEMirror(t, data, podIP) })
	t.Run("TestGREMirror", func(t *testing.T) { testGREMirror(t, data, podIP) })
}

func createTestTCPod(t *testing.T, data *TestData, podName string, labels map[string]string) error {
	require.NoError(t, data.createServerPodWithLabels(podName, testNamespace, testNode, 80, labels))
	if err := data.podWaitForRunning(defaultTimeout, podName, testNamespace); err != nil {
		return fmt.Errorf("error when waiting for Pod '%s' to be in the Running state", podName)
	}
	return nil
}

func (data *TestData) createTrafficControl(t *testing.T,
	generateName string,
	matchExpressions []metav1.LabelSelectorRequirement,
	matchLabels map[string]string,
	direction v1alpha2.Direction,
	action v1alpha2.TrafficControlAction,
	targetPort interface{},
	isTargetPortVXLAN bool,
	returnPort interface{}) *v1alpha2.TrafficControl {
	tc := &v1alpha2.TrafficControl{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: v1alpha2.TrafficControlSpec{
			AppliedTo: v1alpha2.AppliedTo{
				PodSelector: &metav1.LabelSelector{
					MatchExpressions: matchExpressions,
					MatchLabels:      matchLabels,
				},
			},
			Direction:  direction,
			Action:     action,
			ReturnPort: &v1alpha2.TrafficControlPort{},
		},
	}
	switch targetPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.TargetPort.OVSInternal = targetPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.TargetPort.Device = targetPort.(*v1alpha2.NetworkDevice)
	case *v1alpha2.UDPTunnel:
		if isTargetPortVXLAN {
			tc.Spec.TargetPort.VXLAN = targetPort.(*v1alpha2.UDPTunnel)
		} else {
			tc.Spec.TargetPort.GENEVE = targetPort.(*v1alpha2.UDPTunnel)
		}
	case *v1alpha2.GRETunnel:
		tc.Spec.TargetPort.GRE = targetPort.(*v1alpha2.GRETunnel)
	case *v1alpha2.ERSPANTunnel:
		tc.Spec.TargetPort.ERSPAN = targetPort.(*v1alpha2.ERSPANTunnel)
	}

	switch returnPort.(type) {
	case *v1alpha2.OVSInternalPort:
		tc.Spec.ReturnPort.OVSInternal = returnPort.(*v1alpha2.OVSInternalPort)
	case *v1alpha2.NetworkDevice:
		tc.Spec.ReturnPort.Device = returnPort.(*v1alpha2.NetworkDevice)
	default:
		tc.Spec.ReturnPort = nil
	}

	tc, err := data.crdClient.CrdV1alpha2().TrafficControls().Create(context.TODO(), tc, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create TrafficControl")
	return tc
}

func getOFPort(t *testing.T, data *TestData, portName string) int {
	targetOFPort := -1
	cmd := []string{"ovs-ofctl", "show", defaultBridgeName}
	if err := wait.Poll(time.Second, 20*time.Second, func() (bool, error) {
		stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			return false, nil
		}
		re := regexp.MustCompile(fmt.Sprintf(`(\d+)\(%s`, portName))
		match := re.FindString(stdout)
		if match != "" {
			targetOFPort, _ = strconv.Atoi(strings.Split(match, "(")[0])
			return true, nil
		}
		return false, nil
	}); err != nil {
		t.Logf("Not found expected OF port %s in OVS port list", portName)
	}

	return targetOFPort
}

func countMirroredPackets(t *testing.T, data *TestData, targetOFPort int) int {
	var packets int
	cmd := []string{"ovs-ofctl", "dump-flows", defaultBridgeName, "table=TrafficControl"}
	stdout, _, _ := data.RunCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Split(bufio.ScanLines)
	re := regexp.MustCompile(fmt.Sprintf(`n_packets=(\d+).*load:0x%x\-\>NXM_NX_REG9`, targetOFPort))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		match := re.FindString(line)
		if match == "" {
			continue
		}
		match = strings.TrimLeft(match, "n_packets=")
		match = strings.Split(match, ",")[0]
		n, _ := strconv.Atoi(match)
		packets += n
	}
	t.Logf("The total number of packets mirrored to target tunnel on OVS is %d", packets)
	return packets
}

func countReceivedPackets(t *testing.T, data *TestData, tunnelPeer string) int {
	var packets int
	cmd := fmt.Sprintf("ip netns exec %s ifconfig %s", fakeExternalPodNS, tunnelPeer)
	stdout, _, _ := data.RunCommandFromPod(testNamespace, fakeExternalPod, agnhostContainerName, []string{"sh", "-c", cmd})
	re := regexp.MustCompile(`RX packets:\d+`)
	match := re.FindString(stdout)
	if match != "" {
		match = strings.TrimSpace(match)
		match = strings.Split(match, ":")[1]
		packets, _ = strconv.Atoi(match)
	}
	t.Logf("The total number of packets received from tunnel on fake external network is %d", packets)
	return packets
}

func verifyMirroredPackets(t *testing.T, data *TestData, podIP, tunnelPeer, tunnelPrefix string) {
	// Run command to generate some packets to the Pod, and the ingress and egress packets of the Pod applying the TrafficControl
	// will be mirrored to the target tunnel on OVS.
	data.RunCommandOnNode(testNode, fmt.Sprintf("for i in $(seq 1 5); do curl %s; done", podIP))
	// Count the packets mirrored to the target tunnel on OVS and packets received from the peer tunnel on external network.
	// Note that, the peer tunnel on external network may receive some multicast or broadcast packets from OVS, as a result,
	// the received packets should be greater than or equal to the mirrored packets.
	mirroredPackets := countMirroredPackets(t, data, getOFPort(t, data, tunnelPrefix))
	receivedPackets := countReceivedPackets(t, data, tunnelPeer)
	require.GreaterOrEqual(t, receivedPackets, mirroredPackets, "Received packets should be greater than or equal to mirrored packets")
}

func testVXLANMirror(t *testing.T, data *TestData, podIP string) {
	// Create a VXLAN tunnel on fake namespace to receive mirrored packets.
	tunnelPeer := "vxlan0"
	cmd := fmt.Sprintf(`ip netns exec %[1]s ip link add %[4]s type vxlan id %[2]d dstport %[3]d dev %[1]s-a && \
ip netns exec %[1]s ip link set %[4]s up`, fakeExternalPodNS, vni, dstVXLANPort, tunnelPeer)
	_, _, err := data.RunCommandFromPod(testNamespace, fakeExternalPod, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err, "Failed to create VXLAN tunnel on fake namespace")

	// Create a TrafficControl whose target port is VXLAN.
	targetPort := &v1alpha2.UDPTunnel{RemoteIP: fakeExternalIP, VNI: &vni, DestinationPort: &dstVXLANPort}
	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, targetPort, true, nil)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})

	// Verify the mirrored packets.
	verifyMirroredPackets(t, data, podIP, tunnelPeer, "vxlan-")
}

func testGENEVEMirror(t *testing.T, data *TestData, podIP string) {
	// Create a GENEVE tunnel on fake namespace to receive mirrored packets.
	tunnelPeer := "geneve0"
	cmd := fmt.Sprintf(`ip netns exec %[1]s ip link add %[4]s type geneve id %[2]d dstport %[3]d remote %[5]s && \
ip netns exec %[1]s ip link set %[4]s up`, fakeExternalPodNS, vni, dstGENEVEPort, tunnelPeer, fakeExternalGW)
	_, _, err := data.RunCommandFromPod(testNamespace, fakeExternalPod, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err, "Failed to create GENEVE tunnel on fake namespace")

	// Create a TrafficControl whose target port is GENEVE.
	targetPort := &v1alpha2.UDPTunnel{RemoteIP: fakeExternalIP, VNI: &vni, DestinationPort: &dstGENEVEPort}
	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, targetPort, false, nil)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})

	// Verify the mirrored packets.
	verifyMirroredPackets(t, data, podIP, tunnelPeer, "geneve-")
}

func testGREMirror(t *testing.T, data *TestData, podIP string) {
	// Create a GRE tunnel on fake namespace to receive mirrored packets.
	tunnelPeerPort := "gre1"
	cmd := fmt.Sprintf(`ip netns exec %[1]s ip tunnel add %[4]s mode gre remote %[5]s key %[3]d && \
ip netns exec %[1]s ip link set %[4]s up`, fakeExternalPodNS, vni, greKey, tunnelPeerPort, fakeExternalGW)
	_, _, err := data.RunCommandFromPod(testNamespace, fakeExternalPod, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err, "Failed to create GRE tunnel on fake namespace")

	// Create a TrafficControl whose target port is GRE.
	targetPort := &v1alpha2.GRETunnel{RemoteIP: fakeExternalIP, Key: &greKey}
	tc := data.createTrafficControl(t, "tc-", nil, labels, v1alpha2.DirectionBoth, v1alpha2.ActionMirror, targetPort, false, nil)
	defer data.crdClient.CrdV1alpha2().TrafficControls().Delete(context.TODO(), tc.Name, metav1.DeleteOptions{})

	// Verify the mirrored packets.
	verifyMirroredPackets(t, data, podIP, tunnelPeerPort, "gre-")
}
