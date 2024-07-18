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
	"context"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/test/e2e/providers/exec"
)

type BGPPolicySpecBuilder struct {
	Spec crdv1alpha1.BGPPolicySpec
	Name string
}

var (
	remoteASN = int32(65000)

	localASN        = int32(64512)
	updatedLocalASN = int32(64513)

	password                   = "password"
	defaultBGPPolicySecretName = "antrea-bgp-passwords" // #nosec G101

	bpName = "test-bp"
)

func skipIfBGPPolicyDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.BGPPolicy, true, false)
}

func getAllNodeIPs() []string {
	ips := make([]string, 0, clusterInfo.numNodes)
	for _, node := range clusterInfo.nodes {
		ips = append(ips, node.ipv4Addr)
	}
	return ips
}

type FRRRoute struct {
	Prefix   string
	Nexthops []string
}

func (f *FRRRoute) String() string {
	sort.Strings(f.Nexthops)
	return fmt.Sprintf("%s via %s", f.Prefix, strings.Join(f.Nexthops, ","))
}

func routesToStrings(routes []FRRRoute) []string {
	s := make([]string, 0, len(routes))
	for _, route := range routes {
		s = append(s, route.String())
	}
	return s
}

func TestBGPPolicy(t *testing.T) {
	skipIfBGPPolicyDisabled(t)
	skipIfProviderIsNot(t, "kind", "This test is only supported in KinD")
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Log("Configure the remote FRR router with BGP")
	configureFRRRouterBGP(t, remoteASN, localASN)
	defer cleanupFRRRouterBGP(t, remoteASN)

	t.Log("Update the specific Secret storing the passwords of BGP peers")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: kubeNamespace,
			Name:      defaultBGPPolicySecretName,
		},
		Data: map[string][]byte{
			fmt.Sprintf("%s-%d", externalInfo.externalFRRIPv4, remoteASN): []byte(password),
		},
	}
	_, err = data.clientset.CoreV1().Secrets(kubeNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Log("Create a test agnhost Pod")
	_, podIPs, cleanupFunc := createAndWaitForPod(t, data, data.createAgnhostPodWithHTTPOnNode, "agnhost-", nodeName(0), data.testNamespace, false)
	defer cleanupFunc()
	podIP := podIPs.IPv4.String()

	t.Log("Create a test Service")
	svcClusterIP, err := data.createAgnhostClusterIPService("agnhost-svc", false, ptr.To[corev1.IPFamily](corev1.IPv4Protocol))
	defer data.deleteService(svcClusterIP.Namespace, svcClusterIP.Name)
	require.NoError(t, err)
	require.NotEqual(t, "", svcClusterIP.Spec.ClusterIP, "ClusterIP should not be empty")
	clusterIP := svcClusterIP.Spec.ClusterIP

	t.Log("Create a test BGPPolicy selecting all Nodes as well as advertising ClusterIPs and Pod CIDRs")
	bpBuilder := &BGPPolicySpecBuilder{}
	bgpPolicy := bpBuilder.SetName(bpName).
		SetListenPort(179).
		SetLocalASN(localASN).
		SetNodeSelector(map[string]string{}).
		SetAdvertiseServiceIPs([]crdv1alpha1.ServiceIPType{crdv1alpha1.ServiceIPTypeClusterIP}).
		SetAdvertisePodCIDRs().
		SetBGPPeers([]crdv1alpha1.BGPPeer{{Address: externalInfo.externalFRRIPv4, ASN: remoteASN}}).
		Get()
	bgpPolicy, err = data.crdClient.CrdV1alpha1().BGPPolicies().Create(context.TODO(), bgpPolicy, metav1.CreateOptions{})
	defer data.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), bpName, metav1.DeleteOptions{})
	require.NoError(t, err)

	t.Log("Get the routes installed on remote FRR router and verify them")
	expectedRoutes := make([]FRRRoute, 0)
	for _, node := range clusterInfo.nodes {
		expectedRoutes = append(expectedRoutes, FRRRoute{Prefix: node.podV4NetworkCIDR, Nexthops: []string{node.ipv4Addr}})
	}
	expectedRoutes = append(expectedRoutes, FRRRoute{Prefix: clusterIP + "/32", Nexthops: getAllNodeIPs()})
	expectedRouteStrings := routesToStrings(expectedRoutes)
	assert.EventuallyWithT(t, func(tc *assert.CollectT) {
		gotRoutes := dumpFRRRouterBGPRoutes()
		gotRouteStrings := routesToStrings(gotRoutes)
		for _, expectedRouteString := range expectedRouteStrings {
			assert.Contains(tc, gotRouteStrings, expectedRouteString)
		}
	}, 30*time.Second, time.Second)

	t.Log("Verify the connectivity of the installed routes on remote FRR route")
	ipsToConnect := []string{podIP, clusterIP}
	for _, ip := range ipsToConnect {
		cmd := fmt.Sprintf("/usr/bin/wget -O - http://%s:8080/hostname -T 5", ip)
		rc, stdout, _, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, "")
		require.NoError(t, err)
		require.Equal(t, 0, rc)
		require.Contains(t, stdout, "agnhost-")
	}

	t.Log("Update the BGP configuration on the remote FRR router")
	configureFRRRouterBGP(t, remoteASN, updatedLocalASN)

	_, err = data.updateServiceInternalTrafficPolicy("agnhost-svc", true)
	require.NoError(t, err)

	t.Log("Update the test BGPPolicy")
	updatedBGPPolicy := bgpPolicy.DeepCopy()
	updatedBGPPolicy.Spec.LocalASN = updatedLocalASN
	updatedBGPPolicy.Spec.Advertisements.Pod = nil
	_, err = data.crdClient.CrdV1alpha1().BGPPolicies().Update(context.TODO(), updatedBGPPolicy, metav1.UpdateOptions{})
	require.NoError(t, err)

	t.Log("Get routes installed on remote FRR router and verify them")
	expectedRoutes = []FRRRoute{{Prefix: clusterIP + "/32", Nexthops: []string{nodeIPv4(0)}}}
	expectedRouteStrings = routesToStrings(expectedRoutes)
	assert.EventuallyWithT(t, func(tc *assert.CollectT) {
		gotRoutes := dumpFRRRouterBGPRoutes()
		gotRouteStrings := routesToStrings(gotRoutes)
		for _, expectedRouteString := range expectedRouteStrings {
			assert.Contains(tc, gotRouteStrings, expectedRouteString)
		}
	}, 30*time.Second, time.Second)

	t.Log("verify the connectivity of the installed routes on remote FRR route")
	ipsToConnect = []string{clusterIP}
	for _, ip := range ipsToConnect {
		cmd := fmt.Sprintf("/usr/bin/wget -O - http://%s:8080/hostname -T 5", ip)
		rc, stdout, _, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, cmd, "/", nil, "")
		require.NoError(t, err)
		require.Equal(t, 0, rc)
		require.Contains(t, stdout, "agnhost-")
	}
}

func configureFRRRouterBGP(t *testing.T, localASN, remoteASN int32) {
	frrCommands := []string{
		"configure terminal",
		fmt.Sprintf("router bgp %d", localASN),
		"no bgp ebgp-requires-policy",
		"no bgp network import-check",
	}
	for _, node := range clusterInfo.nodes {
		frrCommands = append(frrCommands, fmt.Sprintf("neighbor %s remote-as %d", node.ipv4Addr, remoteASN))
		frrCommands = append(frrCommands, fmt.Sprintf("neighbor %s password %s", node.ipv4Addr, password))
	}
	frrCommands = append(frrCommands,
		"exit",
		"exit",
		"write memory")

	rc, stdout, stderr, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, "/usr/bin/vtysh", "/", nil, strings.Join(frrCommands, "\n"))
	t.Log(stdout)
	t.Log(stderr)
	require.NoError(t, err, fmt.Sprintf("error when running FRR commands '%v'", frrCommands))
	require.Equal(t, 0, rc)
}

func cleanupFRRRouterBGP(t *testing.T, asn int32) {
	frrCommands := []string{
		"configure terminal",
		fmt.Sprintf("no router bgp %d", asn),
		"exit",
		"write memory",
	}

	rc, stdout, stderr, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, "/usr/bin/vtysh", "/", nil, strings.Join(frrCommands, "\n"))
	t.Log(stdout)
	t.Log(stderr)
	require.NoError(t, err, fmt.Sprintf("error when running FRR commands '%v'", frrCommands))
	require.Equal(t, 0, rc)
}

func dumpFRRRouterBGPRoutes() []FRRRoute {
	frrCommands := []string{"show ip route bgp"}
	rc, stdout, _, err := exec.RunDockerExecCommand(externalInfo.externalFRRCID, "/usr/bin/vtysh", "/", nil, strings.Join(frrCommands, "\n"))
	if err != nil || rc != 0 {
		log.Println(fmt.Sprintf("Error when running FRR command '%v': %v", frrCommands, err))
		return nil
	}

	routePattern := regexp.MustCompile(`B>\* ([\d\.\/]+) \[.*?\] via ([\d\.]+),`)
	nexthopPattern := regexp.MustCompile(`\* +via ([\d\.]+),`)
	var routes []FRRRoute
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		routeMatches := routePattern.FindStringSubmatch(line)
		if routeMatches != nil {
			route := FRRRoute{
				Prefix:   routeMatches[1],
				Nexthops: []string{routeMatches[2]},
			}
			routes = append(routes, route)
			continue
		}

		nexthopMatches := nexthopPattern.FindStringSubmatch(line)
		if nexthopMatches != nil && len(routes) > 0 {
			last := len(routes) - 1
			routes[last].Nexthops = append(routes[last].Nexthops, nexthopMatches[1])
		}
	}
	return routes
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

func (b *BGPPolicySpecBuilder) SetNodeSelector(nodeSelector map[string]string) *BGPPolicySpecBuilder {
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

func (b *BGPPolicySpecBuilder) SetAdvertisePodCIDRs() *BGPPolicySpecBuilder {
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
