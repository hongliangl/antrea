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

package bgp

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	netutils "k8s.io/utils/net"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/bgp"
	bgptest "antrea.io/antrea/pkg/agent/bgp/testing"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions"
	"antrea.io/antrea/pkg/util/ip"
)

var (
	podIPv4CIDR  = ip.MustParseCIDR("10.10.0.0/24")
	podIPv6CIDR  = ip.MustParseCIDR("fec0:10:10::/64")
	nodeIPv4Addr = ip.MustParseCIDR("192.168.77.100/24")

	testNodeConfig = &config.NodeConfig{
		PodIPv4CIDR:  podIPv4CIDR,
		PodIPv6CIDR:  podIPv6CIDR,
		NodeIPv4Addr: nodeIPv4Addr,
		Name:         localNodeName,
	}

	peer1ASN          = int32(65531)
	peer1AuthPassword = "bgp-peer1" // #nosec G101
	ipv4Peer1Addr     = "192.168.77.251"
	ipv6Peer1Addr     = "fec0::196:168:77:251"
	ipv4Peer1         = generateBGPPeer(ipv4Peer1Addr, peer1ASN, 179, 120)
	ipv6Peer1         = generateBGPPeer(ipv6Peer1Addr, peer1ASN, 179, 120)
	ipv4Peer1Config   = generateBGPPeerConfig(&ipv4Peer1, peer1AuthPassword)
	ipv6Peer1Config   = generateBGPPeerConfig(&ipv6Peer1, peer1AuthPassword)

	peer2ASN          = int32(65532)
	peer2AuthPassword = "bgp-peer2" // #nosec G101
	ipv4Peer2Addr     = "192.168.77.252"
	ipv6Peer2Addr     = "fec0::196:168:77:252"
	ipv4Peer2         = generateBGPPeer(ipv4Peer2Addr, peer2ASN, 179, 120)
	ipv6Peer2         = generateBGPPeer(ipv6Peer2Addr, peer2ASN, 179, 120)
	ipv4Peer2Config   = generateBGPPeerConfig(&ipv4Peer2, peer2AuthPassword)
	ipv6Peer2Config   = generateBGPPeerConfig(&ipv6Peer2, peer2AuthPassword)

	updatedIPv4Peer2       = generateBGPPeer(ipv4Peer2Addr, peer2ASN, 179, 60)
	updatedIPv6Peer2       = generateBGPPeer(ipv6Peer2Addr, peer2ASN, 179, 60)
	updatedIPv4Peer2Config = generateBGPPeerConfig(&updatedIPv4Peer2, peer2AuthPassword)
	updatedIPv6Peer2Config = generateBGPPeerConfig(&updatedIPv6Peer2, peer2AuthPassword)

	peer3ASN          = int32(65533)
	peer3AuthPassword = "bgp-peer3" // #nosec G101
	ipv4Peer3Addr     = "192.168.77.253"
	ipv6Peer3Addr     = "fec0::196:168:77:253"
	ipv4Peer3         = generateBGPPeer(ipv4Peer3Addr, peer3ASN, 179, 120)
	ipv6Peer3         = generateBGPPeer(ipv6Peer3Addr, peer3ASN, 179, 120)
	ipv4Peer3Config   = generateBGPPeerConfig(&ipv4Peer3, peer3AuthPassword)
	ipv6Peer3Config   = generateBGPPeerConfig(&ipv6Peer3, peer3AuthPassword)

	nodeLabels1      = map[string]string{"node": "control-plane"}
	nodeLabels2      = map[string]string{"os": "linux"}
	nodeLabels3      = map[string]string{"node": "control-plane", "os": "linux"}
	nodeAnnotations1 = map[string]string{types.NodeBGPPolicyRouterIDAnnotationKey: "192.168.77.100"}
	nodeAnnotations2 = map[string]string{types.NodeBGPPolicyRouterIDAnnotationKey: "10.10.0.100"}

	localNodeName = "local"
	node          = generateNode(localNodeName, nodeLabels1, nodeAnnotations1)

	ipv4EgressIP1 = "192.168.77.200"
	ipv6EgressIP1 = "fec0::192:168:77:200"
	ipv4EgressIP2 = "192.168.77.201"
	ipv6EgressIP2 = "fec0::192:168:77:2001"

	ipv4Egress1 = generateEgress("eg1-4", ipv4EgressIP1, localNodeName)
	ipv6Egress1 = generateEgress("eg1-6", ipv6EgressIP1, localNodeName)
	ipv4Egress2 = generateEgress("eg2-4", ipv4EgressIP2, "test-remote-node")
	ipv6Egress2 = generateEgress("eg2-6", ipv6EgressIP2, "test-remote-node")

	bgpPolicyName1 = "bp-1"
	bgpPolicyName2 = "bp-2"
	bgpPolicyName3 = "bp-3"

	clusterIPv4      = "10.96.10.10"
	externalIPv4     = "192.168.77.100"
	loadBalancerIPv4 = "192.168.77.150"
	endpointIPv4     = "10.10.0.10"
	clusterIPv6      = "fec0::10:96:10:10"
	externalIPv6     = "fec0::192:168:77:100"
	loadBalancerIPv6 = "fec0::192:168:77:150"
	endpointIPv6     = "fec0::10:10:0:10"

	ipv4ClusterIPName1   = "clusterip-4"
	ipv4ClusterIPName2   = "clusterip-4-local"
	ipv6ClusterIPName1   = "clusterip-6"
	ipv6ClusterIPName2   = "clusterip-6-local"
	ipv4LoadBalancerName = "loadbalancer-4"
	ipv6LoadBalancerName = "loadbalancer-6"

	ipv4ClusterIP1    = generateService(ipv4ClusterIPName1, corev1.ServiceTypeClusterIP, clusterIPv4, externalIPv4, "", false, false)
	ipv4ClusterIP1Eps = generateEndpointSlice(ipv4ClusterIPName1, false, false, endpointIPv4)
	ipv4ClusterIP2    = generateService(ipv4ClusterIPName2, corev1.ServiceTypeClusterIP, clusterIPv4, externalIPv4, "", true, true)
	ipv4ClusterIP2Eps = generateEndpointSlice(ipv4ClusterIPName2, false, false, endpointIPv4)

	ipv6ClusterIP1    = generateService(ipv6ClusterIPName1, corev1.ServiceTypeClusterIP, clusterIPv6, externalIPv6, "", false, false)
	ipv6ClusterIP1Eps = generateEndpointSlice(ipv6ClusterIPName1, false, false, endpointIPv6)
	ipv6ClusterIP2    = generateService(ipv6ClusterIPName2, corev1.ServiceTypeClusterIP, clusterIPv6, externalIPv6, "", true, true)
	ipv6ClusterIP2Eps = generateEndpointSlice(ipv6ClusterIPName2, false, false, endpointIPv6)

	ipv4LoadBalancer    = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, clusterIPv4, externalIPv4, loadBalancerIPv4, false, false)
	ipv4LoadBalancerEps = generateEndpointSlice(ipv4LoadBalancerName, false, false, endpointIPv4)
	ipv6LoadBalancer    = generateService(ipv6LoadBalancerName, corev1.ServiceTypeLoadBalancer, clusterIPv6, externalIPv6, loadBalancerIPv6, false, false)
	ipv6LoadBalancerEps = generateEndpointSlice(ipv6LoadBalancerName, false, false, endpointIPv6)

	bgpPeerPasswords = map[string]string{
		generateBGPPeerKey(ipv4Peer1Addr, peer1ASN): peer1AuthPassword,
		generateBGPPeerKey(ipv6Peer1Addr, peer1ASN): peer1AuthPassword,
		generateBGPPeerKey(ipv4Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv6Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv4Peer3Addr, peer3ASN): peer3AuthPassword,
		generateBGPPeerKey(ipv6Peer3Addr, peer3ASN): peer3AuthPassword,
	}

	ctx = context.Background()
)

type fakeController struct {
	*Controller
	mockController     *gomock.Controller
	mockBGPServer      *bgptest.MockInterface
	crdClient          *fakeversioned.Clientset
	crdInformerFactory crdinformers.SharedInformerFactory
	client             *fake.Clientset
	informerFactory    informers.SharedInformerFactory
}

func (c *fakeController) startInformers(stopCh chan struct{}) {
	c.informerFactory.Start(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
}

func newFakeController(t *testing.T, objects []runtime.Object, crdObjects []runtime.Object, ipv4Enabled, ipv6Enabled bool) *fakeController {
	ctrl := gomock.NewController(t)
	mockBGPServer := bgptest.NewMockInterface(ctrl)

	client := fake.NewSimpleClientset(objects...)
	crdClient := fakeversioned.NewSimpleClientset(crdObjects...)

	crdInformerFactory := crdinformers.NewSharedInformerFactory(crdClient, 0)
	informerFactory := informers.NewSharedInformerFactory(client, 0)

	nodeInformer := informerFactory.Core().V1().Nodes()
	serviceInformer := informerFactory.Core().V1().Services()
	egressInformer := crdInformerFactory.Crd().V1beta1().Egresses()
	endpointSliceInformer := informerFactory.Discovery().V1().EndpointSlices()
	bgpPolicyInformer := crdInformerFactory.Crd().V1alpha1().BGPPolicies()

	bgpController, _ := NewBGPPolicyController(ctx,
		nodeInformer,
		serviceInformer,
		egressInformer,
		bgpPolicyInformer,
		endpointSliceInformer,
		client,
		testNodeConfig,
		&config.NetworkConfig{
			IPv4Enabled: ipv4Enabled,
			IPv6Enabled: ipv6Enabled,
		})
	bgpController.egressEnabled = true
	bgpController.newBGPServerFn = func(_ *bgp.GlobalConfig) bgp.Interface {
		return mockBGPServer
	}

	return &fakeController{
		Controller:         bgpController,
		mockController:     ctrl,
		mockBGPServer:      mockBGPServer,
		crdClient:          crdClient,
		crdInformerFactory: crdInformerFactory,
		client:             client,
		informerFactory:    informerFactory,
	}
}

func TestBGPPolicyAdd(t *testing.T) {
	testCases := []struct {
		name          string
		ipv4Enabled   bool
		ipv6Enabled   bool
		bpToAdd       *v1alpha1.BGPPolicy
		objects       []runtime.Object
		crdObjects    []runtime.Object
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name:        "IPv4, as effective BGPPolicy, advertise ClusterIP",
			ipv4Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1}),
			objects: []runtime.Object{
				ipv4ClusterIP1,
				ipv4ClusterIP1Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4)},
				[]bgp.PeerConfig{ipv4Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, []bgp.Route{{Prefix: ipStrToPrefix(clusterIPv4)}})
			},
		},
		{
			name:        "IPv6, as effective BGPPolicy, advertise ExternalIP",
			ipv6Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				false,
				true,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv6Peer1}),
			objects: []runtime.Object{
				ipv6ClusterIP1,
				ipv6ClusterIP1Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				"192.168.77.100",
				[]string{ipStrToPrefix(externalIPv6)},
				[]bgp.PeerConfig{ipv6Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, []bgp.Route{{Prefix: ipStrToPrefix(externalIPv6)}})
			},
		},
		{
			name:        "IPv4 & IPv6, as effective BGPPolicy, advertise LoadBalancerIP",
			ipv4Enabled: true,
			ipv6Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				false,
				false,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1}),
			objects: []runtime.Object{
				ipv4LoadBalancer,
				ipv4LoadBalancerEps,
				ipv6LoadBalancer,
				ipv6LoadBalancerEps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(loadBalancerIPv4), ipStrToPrefix(loadBalancerIPv6)},
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				routesToAdvertise := []bgp.Route{
					{Prefix: ipStrToPrefix(loadBalancerIPv4)},
					{Prefix: ipStrToPrefix(loadBalancerIPv6)},
				}
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
			},
		},
		{
			name:        "IPv4, as effective BGPPolicy, advertise EgressIP",
			ipv4Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				true,
				true,
				true,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1}),
			objects: []runtime.Object{node},
			crdObjects: []runtime.Object{
				ipv4Egress1,
				ipv4Egress2,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(ipv4EgressIP1)},
				[]bgp.PeerConfig{ipv4Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, []bgp.Route{{Prefix: ipStrToPrefix(ipv4EgressIP1)}})
			},
		},
		{
			name:        "IPv6, as effective BGPPolicy, advertise Pod CIDR",
			ipv6Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				true,
				true,
				true,
				true,
				true,
				[]v1alpha1.BGPPeer{ipv6Peer1}),
			objects: []runtime.Object{node},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				"192.168.77.100",
				[]string{podIPv6CIDR.String()},
				[]bgp.PeerConfig{ipv6Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, []bgp.Route{{Prefix: podIPv6CIDR.String()}})
			},
		},
		{
			name:        "IPv4 & IPv6, as effective BGPPolicy, not advertise any Service IP due to no local Endpoint",
			ipv4Enabled: true,
			ipv6Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				1179,
				65001,
				true,
				true,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1}),
			objects: []runtime.Object{
				ipv4ClusterIP2,
				ipv4ClusterIP2Eps,
				ipv6ClusterIP2,
				ipv6ClusterIP2Eps,
				node,
			},
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				1179,
				65001,
				nodeIPv4Addr.IP.String(),
				nil,
				[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
			},
		},
		{
			name:        "IPv4, as alternative BGPPolicy",
			ipv4Enabled: true,
			bpToAdd: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				false,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1}),
			objects: []runtime.Object{ipv4ClusterIP1, ipv4ClusterIP1Eps, node},
			crdObjects: []runtime.Object{generateBGPPolicy(bgpPolicyName2,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				false,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1})},
			existingState: generateBGPPolicyState(bgpPolicyName2,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4)},
				[]bgp.PeerConfig{ipv4Peer1Config},
			),
			expectedState: generateBGPPolicyState(bgpPolicyName2,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4)},
				[]bgp.PeerConfig{ipv4Peer1Config},
			),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, tt.objects, append(tt.crdObjects, tt.bpToAdd), tt.ipv4Enabled, tt.ipv6Enabled)

			stopCh := make(chan struct{})
			defer close(stopCh)
			c.startInformers(stopCh)

			// Ignore the dummy event triggered by BGPPolicy ADD events.
			waitEvents(t, 1, c)

			// Fake the BGP state and the passwords of BGP peers.
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			c.bgpPeerPasswords = bgpPeerPasswords

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			waitEvents(t, 1, c)
			assert.NoError(t, c.syncBGPPolicy())
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestBGPPolicyUpdate(t *testing.T) {
	effectiveBP := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		})
	effectiveBPState := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeIPv4Addr.IP.String(),
		[]string{ipStrToPrefix(clusterIPv4),
			ipStrToPrefix(clusterIPv6),
			ipStrToPrefix(loadBalancerIPv4),
			ipStrToPrefix(loadBalancerIPv6),
			podIPv4CIDR.String(),
			podIPv6CIDR.String(),
		},
		[]bgp.PeerConfig{ipv4Peer1Config,
			ipv6Peer1Config,
			ipv4Peer2Config,
			ipv6Peer2Config,
		},
	)
	alternativeBP1 := generateBGPPolicy(bgpPolicyName2,
		nodeLabels1,
		179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		})
	alternativeBP2 := generateBGPPolicy(bgpPolicyName3,
		nodeLabels2,
		179,
		65000,
		true,
		false,
		true,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1,
			ipv4Peer2,
			ipv6Peer1,
			ipv6Peer2,
		})
	objects := []runtime.Object{
		ipv4ClusterIP2,
		ipv4ClusterIP2Eps,
		ipv6ClusterIP2,
		ipv6ClusterIP2Eps,
		ipv4LoadBalancer,
		ipv4LoadBalancerEps,
		ipv6LoadBalancer,
		ipv6LoadBalancerEps,
		node,
	}
	crdObjects := []runtime.Object{ipv4Egress1,
		ipv4Egress2,
		ipv6Egress1,
		ipv6Egress2,
		effectiveBP,
		alternativeBP1,
		alternativeBP2,
	}
	testCases := []struct {
		name          string
		bpToUpdate    *v1alpha1.BGPPolicy
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name: "Effective BGPPolicy, update NodeSelector (not applied to current Node), an alternative takes effect",
			bpToUpdate: generateBGPPolicy(bgpPolicyName1,
				nodeLabels2,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(ctx)
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv4Peer2Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer2Config)
				routes := []bgp.Route{
					{Prefix: ipStrToPrefix(clusterIPv4)},
					{Prefix: ipStrToPrefix(clusterIPv6)},
					{Prefix: ipStrToPrefix(loadBalancerIPv4)},
					{Prefix: ipStrToPrefix(loadBalancerIPv6)},
					{Prefix: podIPv4CIDR.String()},
					{Prefix: podIPv6CIDR.String()},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routes))
			},
			expectedState: generateBGPPolicyState(bgpPolicyName2,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4),
					ipStrToPrefix(clusterIPv6),
					ipStrToPrefix(loadBalancerIPv4),
					ipStrToPrefix(loadBalancerIPv6),
					podIPv4CIDR.String(),
					podIPv6CIDR.String(),
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
			),
		},
		{
			name: "Effective BGPPolicy, update Advertisements",
			bpToUpdate: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				false,
				true,
				false,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(externalIPv4),
					ipStrToPrefix(externalIPv6),
					ipStrToPrefix(ipv4EgressIP1),
					ipStrToPrefix(ipv6EgressIP1),
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				routesToAdvertise := []bgp.Route{
					{Prefix: ipStrToPrefix(externalIPv4)},
					{Prefix: ipStrToPrefix(ipv4EgressIP1)},
					{Prefix: ipStrToPrefix(externalIPv6)},
					{Prefix: ipStrToPrefix(ipv6EgressIP1)},
				}
				routesToWithdraw := []bgp.Route{
					{Prefix: ipStrToPrefix(clusterIPv4)},
					{Prefix: ipStrToPrefix(loadBalancerIPv4)},
					{Prefix: podIPv4CIDR.String()},
					{Prefix: ipStrToPrefix(clusterIPv6)},
					{Prefix: ipStrToPrefix(loadBalancerIPv6)},
					{Prefix: podIPv6CIDR.String()},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
				mockBGPServer.WithdrawRoutes(ctx, gomock.InAnyOrder(routesToWithdraw))
			},
		},
		{
			name: "Effective BGPPolicy, update LocalASN and Advertisements",
			bpToUpdate: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65001,
				false,
				true,
				false,
				true,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65001,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(externalIPv4),
					ipStrToPrefix(externalIPv6),
					ipStrToPrefix(ipv4EgressIP1),
					ipStrToPrefix(ipv6EgressIP1),
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.Stop(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv4Peer2Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer2Config)
				routesToAdvertise := []bgp.Route{
					{Prefix: ipStrToPrefix(externalIPv4)},
					{Prefix: ipStrToPrefix(ipv4EgressIP1)},
					{Prefix: ipStrToPrefix(externalIPv6)},
					{Prefix: ipStrToPrefix(ipv6EgressIP1)},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
			},
		},
		{
			name: "Effective BGPPolicy, update ListenPort",
			bpToUpdate: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				1179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				1179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4),
					ipStrToPrefix(clusterIPv6),
					ipStrToPrefix(loadBalancerIPv4),
					ipStrToPrefix(loadBalancerIPv6),
					podIPv4CIDR.String(),
					podIPv6CIDR.String(),
				},
				[]bgp.PeerConfig{ipv4Peer1Config,
					ipv6Peer1Config,
					ipv4Peer2Config,
					ipv6Peer2Config,
				},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.Stop(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv4Peer2Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer2Config)
				routesToAdvertise := []bgp.Route{
					{Prefix: ipStrToPrefix(clusterIPv4)},
					{Prefix: ipStrToPrefix(loadBalancerIPv4)},
					{Prefix: podIPv4CIDR.String()},
					{Prefix: ipStrToPrefix(clusterIPv6)},
					{Prefix: ipStrToPrefix(loadBalancerIPv6)},
					{Prefix: podIPv6CIDR.String()},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
			},
		},
		{
			name: "Effective BGPPolicy, update BGPPeers",
			bpToUpdate: generateBGPPolicy(bgpPolicyName1,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{updatedIPv4Peer2,
					updatedIPv6Peer2,
					ipv4Peer3,
					ipv6Peer3}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				nodeIPv4Addr.IP.String(),
				[]string{ipStrToPrefix(clusterIPv4),
					ipStrToPrefix(clusterIPv6),
					ipStrToPrefix(loadBalancerIPv4),
					ipStrToPrefix(loadBalancerIPv6),
					podIPv4CIDR.String(),
					podIPv6CIDR.String(),
				},
				[]bgp.PeerConfig{updatedIPv4Peer2Config,
					updatedIPv6Peer2Config,
					ipv4Peer3Config,
					ipv6Peer3Config,
				},
			),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.AddPeer(ctx, ipv4Peer3Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer3Config)
				mockBGPServer.RemovePeer(ctx, ipv4Peer1Config)
				mockBGPServer.RemovePeer(ctx, ipv6Peer1Config)
				mockBGPServer.UpdatePeer(ctx, updatedIPv4Peer2Config)
				mockBGPServer.UpdatePeer(ctx, updatedIPv6Peer2Config)
			},
		},
		{
			name: "Unrelated BGPPolicy, update NodeSelector (applied to current Node)",
			bpToUpdate: generateBGPPolicy(bgpPolicyName3,
				nodeLabels1,
				179,
				65000,
				true,
				false,
				true,
				false,
				true,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					ipv4Peer2,
					ipv6Peer1,
					ipv6Peer2,
				}),
			existingState: effectiveBPState,
			expectedState: effectiveBPState,
		},
		{
			name: "Alternative BGPPolicy, update Advertisements, LocalASN, ListenPort and BGPPeers",
			bpToUpdate: generateBGPPolicy(bgpPolicyName2,
				nodeLabels1,
				1179,
				65001,
				false,
				false,
				true,
				false,
				false,
				[]v1alpha1.BGPPeer{ipv4Peer1,
					updatedIPv4Peer2,
					ipv6Peer1,
					updatedIPv6Peer2,
				}),
			existingState: effectiveBPState,
			expectedState: effectiveBPState,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, objects, crdObjects, true, true)

			stopCh := make(chan struct{})
			defer close(stopCh)
			c.startInformers(stopCh)

			waitEvents(t, 1, c)
			item, _ := c.queue.Get()
			c.queue.Done(item)

			// Fake the BGPPolicy state the passwords of BGP peers.
			c.bgpPolicyState = effectiveBPState
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			c.bgpPeerPasswords = bgpPeerPasswords

			tt.bpToUpdate.Generation += 1
			_, err := c.crdClient.CrdV1alpha1().BGPPolicies().Update(context.TODO(), tt.bpToUpdate, metav1.UpdateOptions{})
			require.NoError(t, err)
			waitEvents(t, 1, c)

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			assert.NoError(t, c.syncBGPPolicy())
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestBGPPolicyDelete(t *testing.T) {
	bp1 := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{
			ipv4Peer1,
			ipv6Peer1,
		})
	bp1State := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeIPv4Addr.IP.String(),
		[]string{
			ipStrToPrefix(loadBalancerIPv4),
			ipStrToPrefix(loadBalancerIPv6),
		},
		[]bgp.PeerConfig{
			ipv4Peer1Config,
			ipv6Peer1Config,
		},
	)
	bp2 := generateBGPPolicy(bgpPolicyName2,
		nodeLabels1,
		179,
		65000,
		false,
		true,
		false,
		false,
		false,
		[]v1alpha1.BGPPeer{
			ipv4Peer2,
			ipv6Peer2,
		})
	bp2State := generateBGPPolicyState(bgpPolicyName2,
		179,
		65000,
		nodeIPv4Addr.IP.String(),
		[]string{
			ipStrToPrefix(externalIPv4),
			ipStrToPrefix(externalIPv6),
		},
		[]bgp.PeerConfig{
			ipv4Peer2Config,
			ipv6Peer2Config},
	)
	objects := []runtime.Object{
		ipv4LoadBalancer,
		ipv4LoadBalancerEps,
		ipv6LoadBalancer,
		ipv6LoadBalancerEps,
		node,
	}
	testCases := []struct {
		name          string
		bpToDelete    string
		crdObjects    []runtime.Object
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name:          "Delete effective BGPPolicy and there is no alternative one",
			bpToDelete:    bgpPolicyName1,
			crdObjects:    []runtime.Object{bp1},
			existingState: bp1State,
			expectedState: nil,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(ctx)
			},
		},
		{
			name:          "Delete effective BGPPolicy and there is an alternative one",
			bpToDelete:    bgpPolicyName1,
			crdObjects:    []runtime.Object{bp1, bp2},
			existingState: bp1State,
			expectedState: bp2State,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(ctx)
				mockBGPServer.Start(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer2Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer2Config)
				routesToAdvertise := []bgp.Route{
					{Prefix: ipStrToPrefix(externalIPv4)},
					{Prefix: ipStrToPrefix(externalIPv6)},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
			},
		},
		{
			name:          "Delete an alternative BGPPolicy",
			bpToDelete:    bgpPolicyName2,
			crdObjects:    []runtime.Object{bp1, bp2},
			existingState: bp1State,
			expectedState: bp1State,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, objects, tt.crdObjects, true, true)

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			// Ignore the BGPPolicy ADD events for the test BGPPolicy.
			waitEvents(t, 1, c)

			c.bgpPolicyState = tt.existingState
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			// Fake the passwords of BGP peers.
			c.bgpPeerPasswords = bgpPeerPasswords

			err := c.crdClient.CrdV1alpha1().BGPPolicies().Delete(context.TODO(), tt.bpToDelete, metav1.DeleteOptions{})
			require.NoError(t, err)
			waitEvents(t, 1, c)

			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			assert.NoError(t, c.syncBGPPolicy())
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestNodeUpdate(t *testing.T) {
	bp1 := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1})
	bp1State := generateBGPPolicyState(bgpPolicyName1,
		179,
		65000,
		nodeIPv4Addr.IP.String(),
		[]string{podIPv4CIDR.String(), podIPv6CIDR.String()},
		[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config})
	bp2 := generateBGPPolicy(bgpPolicyName2,
		nodeLabels2,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1})
	bp2State := generateBGPPolicyState(bgpPolicyName2,
		179,
		65000,
		nodeIPv4Addr.IP.String(),
		[]string{podIPv4CIDR.String(), podIPv6CIDR.String()},
		[]bgp.PeerConfig{ipv4Peer1Config, ipv6Peer1Config})
	bp3 := generateBGPPolicy(bgpPolicyName3,
		nodeLabels3,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv6Peer1})
	crdObjects := []runtime.Object{bp1,
		bp2,
		bp3,
	}
	testCases := []struct {
		name          string
		ipv4Enabled   bool
		ipv6Enabled   bool
		node          *corev1.Node
		updatedNode   *corev1.Node
		existingState *bgpPolicyState
		expectedState *bgpPolicyState
		expectedCalls func(mockBGPServer *bgptest.MockInterfaceMockRecorder)
	}{
		{
			name:          "Update labels, a BGPPolicy is added to alternatives",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels3, nodeAnnotations1),
			existingState: bp1State,
			expectedState: bp1State,
		},
		{
			name:          "Update labels, a BGPPolicy is removed from alternatives",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels3, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			existingState: bp1State,
			expectedState: bp1State,
		},
		{
			name:          "Update labels, effective BGPPolicy is updated to another one",
			ipv4Enabled:   true,
			ipv6Enabled:   true,
			node:          generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode:   generateNode(localNodeName, nodeLabels2, nodeAnnotations1),
			existingState: bp1State,
			expectedState: bp2State,
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.Stop(ctx)
				mockBGPServer.AddPeer(ctx, ipv4Peer1Config)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				routesToAdvertise := []bgp.Route{
					{Prefix: podIPv4CIDR.String()},
					{Prefix: podIPv6CIDR.String()},
				}
				mockBGPServer.AdvertiseRoutes(ctx, gomock.InAnyOrder(routesToAdvertise))
			},
		},
		{
			name:        "Update labels, effective BGPPolicy is updated to empty",
			ipv4Enabled: true,
			ipv6Enabled: true,
			node:        generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode: generateNode(localNodeName, nil, nodeAnnotations1),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Stop(ctx)
			},
			existingState: bp1State,
		},
		{
			name:        "IPv6 only, update annotations, effective BGPPolicy router ID is updated",
			ipv6Enabled: true,
			node:        generateNode(localNodeName, nodeLabels1, nodeAnnotations1),
			updatedNode: generateNode(localNodeName, nodeLabels1, nodeAnnotations2),
			existingState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				"192.168.77.100",
				[]string{podIPv6CIDR.String()},
				[]bgp.PeerConfig{ipv6Peer1Config}),
			expectedState: generateBGPPolicyState(bgpPolicyName1,
				179,
				65000,
				"10.10.0.100",
				[]string{podIPv6CIDR.String()},
				[]bgp.PeerConfig{ipv6Peer1Config}),
			expectedCalls: func(mockBGPServer *bgptest.MockInterfaceMockRecorder) {
				mockBGPServer.Start(ctx)
				mockBGPServer.Stop(ctx)
				mockBGPServer.AddPeer(ctx, ipv6Peer1Config)
				mockBGPServer.AdvertiseRoutes(ctx, []bgp.Route{{Prefix: podIPv6CIDR.String()}})
			},
		},
	}
	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, []runtime.Object{tt.node}, crdObjects, tt.ipv4Enabled, tt.ipv6Enabled)

			stopCh := make(chan struct{})
			defer close(stopCh)

			c.startInformers(stopCh)

			// Ignore the BGPPolicy ADD events for the test BGPPolicies.
			waitEvents(t, 1, c)

			// Fake the BGPPolicy state, effective BGPPolicy and alternative BGPPolicies.
			c.bgpPolicyState = tt.existingState
			if c.bgpPolicyState != nil {
				c.bgpPolicyState.bgpServer = c.mockBGPServer
			}
			// Fake the passwords of BGP peers.
			c.bgpPeerPasswords = bgpPeerPasswords

			_, err := c.client.CoreV1().Nodes().Update(context.TODO(), tt.updatedNode, metav1.UpdateOptions{})
			require.NoError(t, err)

			waitEvents(t, 1, c)
			if tt.expectedCalls != nil {
				tt.expectedCalls(c.mockBGPServer.EXPECT())
			}
			assert.NoError(t, c.syncBGPPolicy())
			checkBGPPolicyState(t, tt.expectedState, c.bgpPolicyState)
		})
	}
}

func TestServiceLifecycle(t *testing.T) {
	bp := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		true,
		true,
		true,
		false,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer1})
	c := newFakeController(t, []runtime.Object{node, ipv4LoadBalancerEps}, []runtime.Object{bp}, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)

	c.startInformers(stopCh)

	// Fake the passwords of BGP peers.
	c.bgpPeerPasswords = bgpPeerPasswords

	// Initialize the test BGPPolicy.
	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().Start(ctx)
	mockBGPServer.EXPECT().AddPeer(ctx, ipv4Peer1Config)
	item, _ := c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Create a Service.
	loadBalancer := generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.100", "192.168.77.150", false, false)
	_, err := c.client.CoreV1().Services("default").Create(context.TODO(), loadBalancer, metav1.CreateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "10.96.10.10/32"}, {Prefix: "192.168.77.100/32"}, {Prefix: "192.168.77.150/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update externalIPs and LoadBalancerIPs of the Service.
	updatedLoadBalancer := generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", false, false)
	_, err = c.client.CoreV1().Services("default").Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.101/32"}, {Prefix: "192.168.77.151/32"}}))
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.100/32"}, {Prefix: "192.168.77.150/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update externalTrafficPolicy of the Service from Cluster to Local.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", false, true)
	_, err = c.client.CoreV1().Services("default").Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.101/32"}, {Prefix: "192.168.77.151/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update internalTrafficPolicy of the Service from Cluster to Local.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", true, true)
	_, err = c.client.CoreV1().Services("default").Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "10.96.10.10/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update externalTrafficPolicy of the Service from Local to Cluster.
	updatedLoadBalancer = generateService(ipv4LoadBalancerName, corev1.ServiceTypeLoadBalancer, "10.96.10.10", "192.168.77.101", "192.168.77.151", true, false)
	_, err = c.client.CoreV1().Services("default").Update(context.TODO(), updatedLoadBalancer, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.101/32"}, {Prefix: "192.168.77.151/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Delete the Service.
	err = c.client.CoreV1().Services("default").Delete(context.TODO(), updatedLoadBalancer.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.101/32"}, {Prefix: "192.168.77.151/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)
}

func TestEgressLifecycle(t *testing.T) {
	bp := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		true,
		false,
		[]v1alpha1.BGPPeer{ipv4Peer1})
	c := newFakeController(t, []runtime.Object{node}, []runtime.Object{bp}, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)

	c.startInformers(stopCh)

	// Fake the passwords of BGP peers.
	c.bgpPeerPasswords = bgpPeerPasswords

	// Initialize the test BGPPolicy.
	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().Start(ctx)
	mockBGPServer.EXPECT().AddPeer(ctx, ipv4Peer1Config)
	item, _ := c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Create an Egress.
	egress := generateEgress("eg1-4", "192.168.77.200", localNodeName)
	_, err := c.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.200/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update the Egress.
	updatedEgress := generateEgress("eg1-4", "192.168.77.201", localNodeName)
	_, err = c.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), updatedEgress, metav1.UpdateOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.200/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Delete the Egress.
	err = c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), updatedEgress.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().WithdrawRoutes(ctx, gomock.InAnyOrder([]bgp.Route{{Prefix: "192.168.77.201/32"}}))
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)
}

func TestBGPSecretUpdate(t *testing.T) {
	bp := generateBGPPolicy(bgpPolicyName1,
		nodeLabels1,
		179,
		65000,
		false,
		false,
		false,
		false,
		true,
		[]v1alpha1.BGPPeer{ipv4Peer1, ipv4Peer2, ipv4Peer3})
	c := newFakeController(t, []runtime.Object{node}, []runtime.Object{bp}, true, false)
	mockBGPServer := c.mockBGPServer

	stopCh := make(chan struct{})
	defer close(stopCh)
	c.startInformers(stopCh)
	go c.watchSecretChanges(stopCh)

	// Wait the Secret watcher to be ready.
	time.Sleep(time.Second)

	// Create the Secret.
	secret := generateSecret(bgpPeerPasswords)
	_, err := c.client.CoreV1().Secrets("kube-system").Create(context.TODO(), secret, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		c.bgpPeerPasswordsMutex.RLock()
		defer c.bgpPeerPasswordsMutex.RUnlock()
		if reflect.DeepEqual(c.bgpPeerPasswords, bgpPeerPasswords) {
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)

	// Initialize the test BGPPolicy.
	waitEvents(t, 1, c)
	mockBGPServer.EXPECT().Start(ctx)
	mockBGPServer.EXPECT().AddPeer(ctx, ipv4Peer1Config)
	mockBGPServer.EXPECT().AddPeer(ctx, ipv4Peer2Config)
	mockBGPServer.EXPECT().AddPeer(ctx, ipv4Peer3Config)
	mockBGPServer.EXPECT().AdvertiseRoutes(ctx, []bgp.Route{{Prefix: podIPv4CIDR.String()}})
	item, _ := c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)

	// Update the Secret.
	updatedBGPPeerPasswords := map[string]string{
		generateBGPPeerKey(ipv4Peer1Addr, peer1ASN): "updated-" + peer1AuthPassword,
		generateBGPPeerKey(ipv4Peer2Addr, peer2ASN): peer2AuthPassword,
		generateBGPPeerKey(ipv4Peer3Addr, peer3ASN): "updated-" + peer3AuthPassword,
	}
	updatedSecret := generateSecret(updatedBGPPeerPasswords)
	_, err = c.client.CoreV1().Secrets("kube-system").Update(context.TODO(), updatedSecret, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		c.bgpPeerPasswordsMutex.RLock()
		defer c.bgpPeerPasswordsMutex.RUnlock()
		if reflect.DeepEqual(c.bgpPeerPasswords, updatedBGPPeerPasswords) {
			return true
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)

	// Process the event triggered by the update of the Secret.
	waitEvents(t, 1, c)
	updatedIPv4Peer1Config := ipv4Peer1Config
	updatedIPv4Peer3Config := ipv4Peer3Config
	updatedIPv4Peer1Config.Password = "updated-" + peer1AuthPassword
	updatedIPv4Peer3Config.Password = "updated-" + peer3AuthPassword
	mockBGPServer.EXPECT().UpdatePeer(ctx, updatedIPv4Peer1Config)
	mockBGPServer.EXPECT().UpdatePeer(ctx, updatedIPv4Peer3Config)
	item, _ = c.queue.Get()
	require.NoError(t, c.syncBGPPolicy())
	c.queue.Done(item)
}

func generateBGPPolicyState(bgpPolicyName string,
	listenPort int32,
	localASN int32,
	routerID string,
	prefixes []string,
	peerConfigs []bgp.PeerConfig) *bgpPolicyState {
	routes := sets.New[bgp.Route]()
	peerConfigMap := make(map[string]bgp.PeerConfig)

	for _, prefix := range prefixes {
		routes.Insert(bgp.Route{Prefix: prefix})
	}
	for _, peerConfig := range peerConfigs {
		peerKey := generateBGPPeerKey(peerConfig.Address, peerConfig.ASN)
		peerConfigMap[peerKey] = peerConfig
	}

	return &bgpPolicyState{
		bgpPolicy:   bgpPolicyName,
		listenPort:  listenPort,
		localASN:    localASN,
		routerID:    routerID,
		routes:      routes,
		peerConfigs: peerConfigMap,
	}
}

func checkBGPPolicyState(t *testing.T, expected, got *bgpPolicyState) {
	require.Equal(t, expected != nil, got != nil)
	if expected != nil {
		assert.Equal(t, expected.bgpPolicy, got.bgpPolicy)
		assert.Equal(t, expected.listenPort, got.listenPort)
		assert.Equal(t, expected.localASN, got.localASN)
		assert.Equal(t, expected.routerID, got.routerID)
		assert.Equal(t, expected.routes, got.routes)
		assert.Equal(t, expected.peerConfigs, got.peerConfigs)
	}
}

func generateBGPPolicy(name string,
	nodeSelector map[string]string,
	listenPort int32,
	localASN int32,
	advertiseClusterIP bool,
	advertiseExternalIP bool,
	advertiseLoadBalancerIP bool,
	advertiseEgressIP bool,
	advertisePodCIDR bool,
	externalPeers []v1alpha1.BGPPeer) *v1alpha1.BGPPolicy {
	var advertisement v1alpha1.Advertisements
	advertisement.Service = &v1alpha1.ServiceAdvertisement{}
	if advertiseClusterIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeClusterIP)
	}
	if advertiseExternalIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeExternalIP)
	}
	if advertiseLoadBalancerIP {
		advertisement.Service.IPTypes = append(advertisement.Service.IPTypes, v1alpha1.ServiceIPTypeLoadBalancerIP)
	}
	if advertiseEgressIP {
		advertisement.Egress = &v1alpha1.EgressAdvertisement{}
	}

	if advertisePodCIDR {
		advertisement.Pod = &v1alpha1.PodAdvertisement{}
	}
	return &v1alpha1.BGPPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: "test-uid"},
		Spec: v1alpha1.BGPPolicySpec{
			NodeSelector:   metav1.LabelSelector{MatchLabels: nodeSelector},
			LocalASN:       localASN,
			ListenPort:     &listenPort,
			Advertisements: advertisement,
			BGPPeers:       externalPeers,
		},
	}
}
func generateService(name string,
	svcType corev1.ServiceType,
	clusterIP string,
	externalIP string,
	LoadBalancerIP string,
	internalTrafficPolicyLocal bool,
	externalTrafficPolicyLocal bool) *corev1.Service {
	itp := corev1.ServiceInternalTrafficPolicyCluster
	if internalTrafficPolicyLocal {
		itp = corev1.ServiceInternalTrafficPolicyLocal
	}
	etp := corev1.ServiceExternalTrafficPolicyCluster
	if externalTrafficPolicyLocal {
		etp = corev1.ServiceExternalTrafficPolicyLocal
	}
	var externalIPs []string
	if externalIP != "" {
		externalIPs = append(externalIPs, externalIP)
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			UID:       "test-uid",
		},
		Spec: corev1.ServiceSpec{
			Type:      svcType,
			ClusterIP: clusterIP,
			Ports: []corev1.ServicePort{{
				Name:     "p80",
				Port:     80,
				Protocol: corev1.ProtocolTCP,
			}},
			ClusterIPs:            []string{clusterIP},
			ExternalIPs:           externalIPs,
			InternalTrafficPolicy: &itp,
			ExternalTrafficPolicy: etp,
		},
	}
	if LoadBalancerIP != "" {
		ingress := []corev1.LoadBalancerIngress{{IP: LoadBalancerIP}}
		svc.Status.LoadBalancer.Ingress = ingress
	}
	return svc
}

func generateEgress(name string, ip string, nodeName string) *crdv1b1.Egress {
	return &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  "test-uid",
		},
		Spec: crdv1b1.EgressSpec{
			EgressIP: ip,
		},
		Status: crdv1b1.EgressStatus{
			EgressIP:   ip,
			EgressNode: nodeName,
		},
	}
}

func generateNode(name string, labels, annotations map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			UID:         "test-uid",
			Labels:      labels,
			Annotations: annotations,
		},
	}
}

func generateEndpointSlice(svcName string,
	isLocal bool,
	isIPv6 bool,
	endpointIP string) *discovery.EndpointSlice {
	addrType := discovery.AddressTypeIPv4
	if isIPv6 {
		addrType = discovery.AddressTypeIPv6
	}
	var nodeName *string
	if isLocal {
		nodeName = &localNodeName
	}
	protocol := corev1.ProtocolTCP
	endpointSlice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", svcName, rand.String(5)),
			Namespace: "default",
			UID:       "test-uid",
			Labels: map[string]string{
				discovery.LabelServiceName: svcName,
			},
		},
		AddressType: addrType,
		Endpoints: []discovery.Endpoint{{
			Addresses: []string{
				endpointIP,
			},
			Conditions: discovery.EndpointConditions{
				Ready: ptr.To(true),
			},
			Hostname: nodeName,
			NodeName: nodeName,
		}},
		Ports: []discovery.EndpointPort{{
			Name:     ptr.To("p80"),
			Port:     ptr.To(int32(80)),
			Protocol: &protocol,
		}},
	}

	return endpointSlice
}

func generateBGPPeer(ip string, asn, port, gracefulRestartTimeSeconds int32) v1alpha1.BGPPeer {
	return v1alpha1.BGPPeer{
		Address:                    ip,
		Port:                       &port,
		ASN:                        asn,
		MultihopTTL:                ptr.To(int32(1)),
		GracefulRestartTimeSeconds: &gracefulRestartTimeSeconds,
	}
}

func generateBGPPeerConfig(peerConfig *v1alpha1.BGPPeer, password string) bgp.PeerConfig {
	return bgp.PeerConfig{
		BGPPeer:  peerConfig,
		Password: password,
	}
}

func generateSecret(rawData map[string]string) *corev1.Secret {
	data := make(map[string][]byte)
	for k, v := range rawData {
		data[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      types.BGPPolicySecretName,
			Namespace: "kube-system",
			UID:       "test-uid",
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

func ipStrToPrefix(ipStr string) string {
	if netutils.IsIPv4String(ipStr) {
		return ipStr + ipv4Suffix
	} else if netutils.IsIPv6String(ipStr) {
		return ipStr + ipv6Suffix
	}
	return ""
}

func waitEvents(t *testing.T, expectedEvents int, c *fakeController) {
	require.Eventually(t, func() bool {
		return c.queue.Len() == expectedEvents
	}, 5*time.Second, 10*time.Millisecond)
}
