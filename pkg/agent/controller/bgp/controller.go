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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/net"
	"k8s.io/utils/strings/slices"

	"antrea.io/antrea/pkg/agent/bgp"
	"antrea.io/antrea/pkg/agent/bgp/gobgp"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformersv1a1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdinformersv1b1 "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlistersv1a1 "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdlistersv1b1 "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/util/env"
	utilipset "antrea.io/antrea/pkg/util/sets"
)

const (
	controllerName = "BGPPolicyController"
	// How long to wait before retrying the processing of a BGPPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

const defaultBGPListenPort int32 = 179

const (
	ipv4Suffix = "/32"
	ipv6Suffix = "/128"
)

const key = "dummyKey"

type bgpPolicyState struct {
	// The name of BGPPolicy takes effect.
	bgpPolicy string
	// The local BGP server instance.
	bgpServer bgp.Interface
	// The port on which the local BGP server listens.
	listenPort int32
	// The AS number used by the local BGP server.
	localASN int32
	// The router ID used by the local BGP server.
	routerID string
	// routes stores all BGP routers advertised to BGP peers.
	routes sets.Set[bgp.Route]
	// peerConfigs is a map that stores configurations of BGP peers. The map keys are the concatenated strings of BGP
	// peer IP address and ASN (e.g., "192.168.77.100-65000", "2001::1-65000").
	peerConfigs map[string]bgp.PeerConfig
}

type Controller struct {
	ctx context.Context

	nodeInformer     cache.SharedIndexInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced

	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced

	egressInformer     cache.SharedIndexInformer
	egressLister       crdlistersv1b1.EgressLister
	egressListerSynced cache.InformerSynced

	bgpPolicyInformer     cache.SharedIndexInformer
	bgpPolicyLister       crdlistersv1a1.BGPPolicyLister
	bgpPolicyListerSynced cache.InformerSynced

	endpointSliceInformer     cache.SharedIndexInformer
	endpointSliceLister       discoverylisters.EndpointSliceLister
	endpointSliceListerSynced cache.InformerSynced

	bgpPolicyState *bgpPolicyState

	k8sClient             kubernetes.Interface
	bgpPeerPasswords      map[string]string
	bgpPeerPasswordsMutex sync.RWMutex

	nodeName     string
	enabledIPv4  bool
	enabledIPv6  bool
	podIPv4CIDR  string
	podIPv6CIDR  string
	nodeIPv4Addr string

	egressEnabled bool

	newBGPServerFn func(globalConfig *bgp.GlobalConfig) bgp.Interface

	queue workqueue.RateLimitingInterface
}

func NewBGPPolicyController(ctx context.Context,
	nodeInformer coreinformers.NodeInformer,
	serviceInformer coreinformers.ServiceInformer,
	egressInformer crdinformersv1b1.EgressInformer,
	bgpPolicyInformer crdinformersv1a1.BGPPolicyInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	k8sClient kubernetes.Interface,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig) (*Controller, error) {
	c := &Controller{
		ctx:                       ctx,
		nodeInformer:              nodeInformer.Informer(),
		nodeLister:                nodeInformer.Lister(),
		nodeListerSynced:          nodeInformer.Informer().HasSynced,
		serviceInformer:           serviceInformer.Informer(),
		serviceLister:             serviceInformer.Lister(),
		serviceListerSynced:       serviceInformer.Informer().HasSynced,
		egressInformer:            egressInformer.Informer(),
		egressLister:              egressInformer.Lister(),
		egressListerSynced:        egressInformer.Informer().HasSynced,
		bgpPolicyInformer:         bgpPolicyInformer.Informer(),
		bgpPolicyLister:           bgpPolicyInformer.Lister(),
		bgpPolicyListerSynced:     bgpPolicyInformer.Informer().HasSynced,
		endpointSliceInformer:     endpointSliceInformer.Informer(),
		endpointSliceLister:       endpointSliceInformer.Lister(),
		endpointSliceListerSynced: endpointSliceInformer.Informer().HasSynced,
		k8sClient:                 k8sClient,
		bgpPeerPasswords:          make(map[string]string),
		nodeName:                  nodeConfig.Name,
		enabledIPv4:               networkConfig.IPv4Enabled,
		enabledIPv6:               networkConfig.IPv6Enabled,
		podIPv4CIDR:               nodeConfig.PodIPv4CIDR.String(),
		podIPv6CIDR:               nodeConfig.PodIPv6CIDR.String(),
		nodeIPv4Addr:              nodeConfig.NodeIPv4Addr.IP.String(),
		egressEnabled:             features.DefaultFeatureGate.Enabled(features.Egress),
		newBGPServerFn: func(globalConfig *bgp.GlobalConfig) bgp.Interface {
			return gobgp.NewGoBGPServer(globalConfig)
		},
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "bgpPolicyGroup"),
	}
	c.bgpPolicyInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addBGPPolicy,
			UpdateFunc: c.updateBGPPolicy,
			DeleteFunc: c.deleteBGPPolicy,
		},
		resyncPeriod,
	)
	c.serviceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addService,
			UpdateFunc: c.updateService,
			DeleteFunc: c.deleteService,
		},
		resyncPeriod,
	)
	c.endpointSliceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEndpointSlice,
			UpdateFunc: c.updateEndpointSlice,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)
	if c.egressEnabled {
		c.egressInformer.AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    c.addEgress,
				UpdateFunc: c.updateEgress,
				DeleteFunc: c.deleteEgress,
			},
			resyncPeriod,
		)
	}
	c.nodeInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    nil,
			UpdateFunc: c.updateNode,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)
	return c, nil
}

// watchSecretChanges uses watch API directly to watch for the changes of the specific Secret storing passwords of BGP
// peers.
func (c *Controller) watchSecretChanges(endCh <-chan struct{}) error {
	ns := env.GetAntreaNamespace()
	watcher, err := c.k8sClient.CoreV1().Secrets(ns).Watch(context.TODO(), metav1.SingleObject(metav1.ObjectMeta{
		Namespace: ns,
		Name:      types.BGPPolicySecretName,
	}))
	if err != nil {
		return fmt.Errorf("failed to create Secret watcher: %v", err)
	}

	ch := watcher.ResultChan()
	defer watcher.Stop()
	klog.InfoS("Starting watching Secret changes", "Secret", fmt.Sprintf("%s/%s", ns, types.BGPPolicySecretName))
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			// Update BGP peer passwords.
			klog.InfoS("Processing Secret event", "Secret", fmt.Sprintf("%s/%s", ns, types.BGPPolicySecretName))
			func() {
				c.bgpPeerPasswordsMutex.Lock()
				defer c.bgpPeerPasswordsMutex.Unlock()

				secretObj := event.Object.(*corev1.Secret)
				c.bgpPeerPasswords = make(map[string]string)
				for key, data := range secretObj.Data {
					c.bgpPeerPasswords[key] = string(data)
				}
			}()
			c.queue.Add(key)
		case <-endCh:
			return nil
		}
	}
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName,
		stopCh,
		c.nodeListerSynced,
		c.serviceListerSynced,
		c.egressListerSynced,
		c.bgpPolicyListerSynced,
		c.endpointSliceListerSynced) {
		return
	}

	go wait.NonSlidingUntil(func() {
		if err := c.watchSecretChanges(stopCh); err != nil {
			klog.ErrorS(err, "Watch Secret error", "secret", types.BGPPolicySecretName)
		}
	}, time.Second*10, stopCh)

	go wait.Until(c.worker, time.Second, stopCh)

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	defer c.queue.Done(key)

	if err := c.syncBGPPolicy(); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing BGPPolicy failed, requeue")
	}
	return true
}

// filterBGPPolicies filters the BGPPolicies applied to the current Node.
func (c *Controller) filterBGPPolicies() (map[string]*v1alpha1.BGPPolicy, error) {
	allBPs, err := c.bgpPolicyLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	bpMap := make(map[string]*v1alpha1.BGPPolicy)
	for _, bp := range allBPs {
		if c.matchedCurrentNode(bp) {
			bpMap[bp.GetName()] = bp
		}
	}
	return bpMap, nil
}

func (c *Controller) syncBGPPolicy() error {
	startTime := time.Now()
	defer func() {
		klog.V(2).InfoS("Finished syncing BGPPolicy", "durationTime", time.Since(startTime))
	}()

	// Get all available BGPPolicies applied to the current Node.
	allBGPPolicies, err := c.filterBGPPolicies()
	if err != nil {
		return err
	}

	allBGPPolicyNames := sets.KeySet(allBGPPolicies)
	preState := c.bgpPolicyState
	var curState *bgpPolicyState
	var effectiveBGPPolicyName string
	var needUpdateBGPServer bool

	if preState == nil {
		if allBGPPolicyNames.Len() == 0 {
			return nil
		}
		// If there is no effective BGPPolicy in the last sync, select a random available BGPPolicy as the effective one.
		effectiveBGPPolicyName, _ = allBGPPolicyNames.PopAny()
		curState = &bgpPolicyState{bgpPolicy: effectiveBGPPolicyName}
		needUpdateBGPServer = true
	} else {
		// If there is an effective BGPPolicy in the last sync, check if it is still included in the available BGPPolicies.
		if !allBGPPolicyNames.Has(preState.bgpPolicy) {
			// If there is no available BGPPolicy, stop the previous BGP server, clean up the state and return.
			if allBGPPolicyNames.Len() == 0 {
				if err := preState.bgpServer.Stop(c.ctx); err != nil {
					return err
				}
				c.bgpPolicyState = nil
				return nil
			}
			// Select a new effective BGPPolicy from the available ones.
			effectiveBGPPolicyName, _ = allBGPPolicyNames.PopAny()
			curState = &bgpPolicyState{bgpPolicy: effectiveBGPPolicyName}
			needUpdateBGPServer = true
		} else {
			// Retain the effective BGPPolicy in the last sync.
			effectiveBGPPolicyName = preState.bgpPolicy
			curState = &bgpPolicyState{bgpPolicy: effectiveBGPPolicyName}
		}
	}
	bgpPolicy := allBGPPolicies[effectiveBGPPolicyName]

	klog.V(2).InfoS("Syncing BGPPolicy", "BGPPolicy", effectiveBGPPolicyName)
	// Retrieve the listen port, local AS number and router ID from the effective BGPPolicy, and update them to the
	// current state.
	curState.routerID, err = c.getRouterID()
	if err != nil {
		return err
	}
	if bgpPolicy.Spec.ListenPort != nil {
		curState.listenPort = *bgpPolicy.Spec.ListenPort
	} else {
		curState.listenPort = defaultBGPListenPort
	}
	curState.localASN = bgpPolicy.Spec.LocalASN

	// If any of the listen port, local AS number, or router ID have changed, mark the BGP server for an update.
	if preState != nil {
		needUpdateBGPServer = needUpdateBGPServer ||
			preState.listenPort != curState.listenPort ||
			preState.localASN != curState.localASN ||
			preState.routerID != curState.routerID
	}

	if needUpdateBGPServer {
		// Stop the stale BGP server.
		if preState != nil {
			if err := preState.bgpServer.Stop(c.ctx); err != nil {
				klog.ErrorS(err, "failed to stop stale BGP server")
			}
		}
		// Start the new BGP server.
		globalConfig := &bgp.GlobalConfig{
			ASN:        uint32(curState.localASN),
			RouterID:   curState.routerID,
			ListenPort: curState.listenPort,
		}
		bgpServer := c.newBGPServerFn(globalConfig)
		if err := bgpServer.Start(c.ctx); err != nil {
			return err
		}
		// Update the current effective BGPPolicy state.
		curState.bgpServer = bgpServer
	} else {
		curState.bgpServer = preState.bgpServer
	}

	// Reconcile BGP peers.
	curPeerConfigs, err := c.getPeerConfigs(bgpPolicy.Spec.BGPPeers)
	if err != nil {
		return err
	}
	prePeerConfigs := make(map[string]bgp.PeerConfig)
	if preState != nil {
		prePeerConfigs = preState.peerConfigs
	}
	if err := c.reconcileBGPPeers(curPeerConfigs, prePeerConfigs, curState.bgpServer, needUpdateBGPServer); err != nil {
		return err
	}

	// Reconcile BGP routes generated from advertisements.
	curRoutes, err := c.getRoutes(bgpPolicy.Spec.Advertisements)
	if err != nil {
		return err
	}
	preRoutes := sets.Set[bgp.Route]{}
	if preState != nil {
		preRoutes = preState.routes
	}
	if err := c.reconcileRoutes(curRoutes, preRoutes, curState.bgpServer, needUpdateBGPServer); err != nil {
		return err
	}

	// Update the current effective BGPPolicy state.
	curState.routes = curRoutes
	curState.peerConfigs = curPeerConfigs
	c.bgpPolicyState = curState

	return nil
}

func getPeerConfigsForKeys(peerKeys sets.Set[string], allPeerConfigs map[string]bgp.PeerConfig) []bgp.PeerConfig {
	peerConfigs := make([]bgp.PeerConfig, 0, len(peerKeys))
	for peer := range peerKeys {
		peerConfigs = append(peerConfigs, allPeerConfigs[peer])
	}
	return peerConfigs
}

func (c *Controller) reconcileBGPPeers(curPeerConfigs, prePeerConfigs map[string]bgp.PeerConfig, bgpServer bgp.Interface, bgpServerUpdated bool) error {
	prePeerKeys := sets.KeySet(prePeerConfigs)
	curPeerKeys := sets.KeySet(curPeerConfigs)

	var peerToAddKeys sets.Set[string]
	if !bgpServerUpdated {
		peerToAddKeys = curPeerKeys.Difference(prePeerKeys)
	} else {
		peerToAddKeys = curPeerKeys
	}
	peerConfigsToAdd := getPeerConfigsForKeys(peerToAddKeys, curPeerConfigs)
	for _, peer := range peerConfigsToAdd {
		if err := bgpServer.AddPeer(c.ctx, peer); err != nil {
			return err
		}
	}

	if !bgpServerUpdated {
		peerToUpdateKeys := sets.New[string]()
		remainPeerKeys := prePeerKeys.Intersection(curPeerKeys)
		for peerKey := range remainPeerKeys {
			prevPeerConfig := prePeerConfigs[peerKey]
			curPeerConfig := curPeerConfigs[peerKey]
			if !reflect.DeepEqual(prevPeerConfig, curPeerConfig) {
				peerToUpdateKeys.Insert(peerKey)
			}
		}
		peerToUpdateConfigs := getPeerConfigsForKeys(peerToUpdateKeys, curPeerConfigs)
		for _, peer := range peerToUpdateConfigs {
			if err := bgpServer.UpdatePeer(c.ctx, peer); err != nil {
				return err
			}
		}

		peerToDeleteKeys := prePeerKeys.Difference(curPeerKeys)
		peerToDeleteConfigs := getPeerConfigsForKeys(peerToDeleteKeys, prePeerConfigs)
		for _, peer := range peerToDeleteConfigs {
			if err := bgpServer.RemovePeer(c.ctx, peer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Controller) reconcileRoutes(curRoutes, preRoutes sets.Set[bgp.Route], bgpServer bgp.Interface, bgpServerUpdated bool) error {
	var routesToAdvertise sets.Set[bgp.Route]
	if !bgpServerUpdated {
		routesToAdvertise = curRoutes.Difference(preRoutes)
	} else {
		routesToAdvertise = curRoutes
	}
	if routesToAdvertise.Len() != 0 {
		if err := bgpServer.AdvertiseRoutes(c.ctx, routesToAdvertise.UnsortedList()); err != nil {
			return err
		}
	}

	if !bgpServerUpdated {
		routesToWithdraw := preRoutes.Difference(curRoutes)
		if routesToWithdraw.Len() != 0 {
			if err := bgpServer.WithdrawRoutes(c.ctx, routesToWithdraw.UnsortedList()); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Controller) getRouterID() (string, error) {
	var routerID string
	// For IPv6 only environment, the BGP routerID should be specified by K8s Node annotation `antrea.io/bgp-route-id`.
	if !c.enabledIPv4 && c.enabledIPv6 {
		nodeObj, _ := c.nodeLister.Get(c.nodeName)
		var exists bool
		if routerID, exists = nodeObj.GetAnnotations()[types.NodeBGPPolicyRouterIDAnnotationKey]; !exists {
			return "", fmt.Errorf("BGP routerID should be assigned by annotation manually when IPv6 is only enabled")
		}
		if !net.IsIPv4String(routerID) {
			return "", fmt.Errorf("BGP routerID should be an IPv4 address")
		}
	} else {
		routerID = c.nodeIPv4Addr
	}
	return routerID, nil
}

func (c *Controller) getRoutes(advertisements v1alpha1.Advertisements) (sets.Set[bgp.Route], error) {
	allRoutes := sets.New[bgp.Route]()

	if advertisements.Service != nil {
		if err := c.addServiceRoutes(advertisements.Service, allRoutes); err != nil {
			return nil, err
		}
	}
	if c.egressEnabled && advertisements.Egress != nil {
		if err := c.addEgressRoutes(allRoutes); err != nil {
			return nil, err
		}
	}
	if advertisements.Pod != nil {
		c.addPodRoutes(allRoutes)
	}

	return allRoutes, nil
}

func serviceIPTypesToAdvertise(serviceIPTypes []v1alpha1.ServiceIPType) sets.Set[v1alpha1.ServiceIPType] {
	ipTypeMap := sets.New[v1alpha1.ServiceIPType]()
	for _, ipType := range serviceIPTypes {
		ipTypeMap.Insert(ipType)
	}
	return ipTypeMap
}

func (c *Controller) addServiceRoutes(advertisement *v1alpha1.ServiceAdvertisement, allRoutes sets.Set[bgp.Route]) error {
	ipTypeMap := serviceIPTypesToAdvertise(advertisement.IPTypes)

	services, err := c.serviceLister.List(labels.Everything())
	if err != nil {
		return err
	}

	var serviceIPs []string
	for _, svc := range services {
		internalLocal := svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal
		externalLocal := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
		var hasLocalEndpoints bool
		if internalLocal || externalLocal {
			var err error
			hasLocalEndpoints, err = c.hasLocalEndpoints(svc)
			if err != nil {
				return err
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) {
			if internalLocal && hasLocalEndpoints || !internalLocal {
				for _, clusterIP := range svc.Spec.ClusterIPs {
					serviceIPs = append(serviceIPs, clusterIP)
				}
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, externalIP := range svc.Spec.ExternalIPs {
					serviceIPs = append(serviceIPs, externalIP)
				}
			}
		}
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, ingressIP := range svc.Status.LoadBalancer.Ingress {
					if ingressIP.IP != "" {
						serviceIPs = append(serviceIPs, ingressIP.IP)
					}
				}
			}
		}
	}

	for _, ip := range serviceIPs {
		if c.enabledIPv4 && net.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && net.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}

	return nil
}

func (c *Controller) addEgressRoutes(allRoutes sets.Set[bgp.Route]) error {
	egresses, err := c.egressLister.List(labels.Everything())
	if err != nil {
		return err
	}

	for _, eg := range egresses {
		if eg.Status.EgressNode != c.nodeName {
			continue
		}
		ip := eg.Status.EgressIP
		if c.enabledIPv4 && net.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && net.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}

	return nil
}

func (c *Controller) addPodRoutes(allRoutes sets.Set[bgp.Route]) {
	if c.enabledIPv4 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv4CIDR})
	}
	if c.enabledIPv6 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv6CIDR})
	}
}

func (c *Controller) hasLocalEndpoints(svc *corev1.Service) (bool, error) {
	labelSelector := labels.Set{discovery.LabelServiceName: svc.GetName()}.AsSelector()
	items, err := c.endpointSliceLister.EndpointSlices(svc.GetNamespace()).List(labelSelector)
	if err != nil {
		return false, err
	}
	for _, eps := range items {
		for _, ep := range eps.Endpoints {
			if ep.NodeName != nil && *ep.NodeName == c.nodeName {
				return true, nil
			}
		}
	}

	return false, nil
}

func (c *Controller) generateBGPPeerConfig(peer *v1alpha1.BGPPeer) bgp.PeerConfig {
	bgpPeerConfig := bgp.PeerConfig{
		BGPPeer: peer,
	}
	bgpPeerKey := generateBGPPeerKey(peer.Address, peer.ASN)
	c.bgpPeerPasswordsMutex.RLock()
	defer c.bgpPeerPasswordsMutex.RUnlock()
	if password, exists := c.bgpPeerPasswords[bgpPeerKey]; exists {
		bgpPeerConfig.Password = password
	}
	return bgpPeerConfig
}

func (c *Controller) getPeerConfigs(allPeers []v1alpha1.BGPPeer) (map[string]bgp.PeerConfig, error) {
	peerConfigs := make(map[string]bgp.PeerConfig)
	for i := range allPeers {
		if c.enabledIPv4 && net.IsIPv4String(allPeers[i].Address) ||
			c.enabledIPv6 && net.IsIPv6String(allPeers[i].Address) {
			peerKey := generateBGPPeerKey(allPeers[i].Address, allPeers[i].ASN)
			peerConfigs[peerKey] = c.generateBGPPeerConfig(&allPeers[i])
		}
	}
	return peerConfigs, nil
}

func generateBGPPeerKey(address string, asn int32) string {
	return fmt.Sprintf("%s-%d", address, asn)
}

func (c *Controller) addBGPPolicy(obj interface{}) {
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy ADD event", "BGPPolicy", klog.KObj(bp))
	c.queue.Add(key)
}

func (c *Controller) updateBGPPolicy(oldObj, obj interface{}) {
	oldBP := oldObj.(*v1alpha1.BGPPolicy)
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) && !c.matchedCurrentNode(oldBP) {
		return
	}
	if bp.GetGeneration() != oldBP.GetGeneration() {
		klog.V(2).InfoS("Processing BGPPolicy UPDATE event", "BGPPolicy", klog.KObj(bp))
		c.queue.Add(key)
	}
}

func (c *Controller) deleteBGPPolicy(obj interface{}) {
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy DELETE event", "BGPPolicy", klog.KObj(bp))
	c.queue.Add(key)
}

func getIngressIPs(svc *corev1.Service) []string {
	var ips []string
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			ips = append(ips, ingress.IP)
		}
	}
	return ips
}

func (c *Controller) matchedCurrentNode(bp *v1alpha1.BGPPolicy) bool {
	nodeSelector, _ := metav1.LabelSelectorAsSelector(&bp.Spec.NodeSelector)
	node, _ := c.nodeLister.Get(c.nodeName)
	return nodeSelector.Matches(labels.Set(node.GetLabels()))
}

func (c *Controller) matchedNode(node *corev1.Node, bp *v1alpha1.BGPPolicy) bool {
	nodeSel, _ := metav1.LabelSelectorAsSelector(&bp.Spec.NodeSelector)
	if !nodeSel.Matches(labels.Set(node.Labels)) {
		return false
	}
	return true
}

func (c *Controller) filterAffectedBPsByService(svc *corev1.Service) sets.Set[string] {
	affectedBPs := sets.New[string]()
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if bp.Spec.Advertisements.Service == nil {
			continue
		}
		ipTypeMap := serviceIPTypesToAdvertise(bp.Spec.Advertisements.Service.IPTypes)

		if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) && len(svc.Spec.ClusterIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) && len(svc.Spec.ExternalIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && len(getIngressIPs(svc)) != 0 {
			if c.matchedCurrentNode(bp) {
				affectedBPs.Insert(bp.GetName())
			}
		}
	}
	return affectedBPs
}

func (c *Controller) hasAffectedBPsByService(svc *corev1.Service) bool {
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if !c.matchedCurrentNode(bp) || bp.Spec.Advertisements.Service == nil {
			continue
		}
		ipTypeMap := serviceIPTypesToAdvertise(bp.Spec.Advertisements.Service.IPTypes)
		if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) && len(svc.Spec.ClusterIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) && len(svc.Spec.ExternalIPs) != 0 ||
			ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && len(getIngressIPs(svc)) != 0 {
			return true
		}
	}
	return false
}

func (c *Controller) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	if c.hasAffectedBPsByService(svc) {
		klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(svc))
		c.queue.Add(key)
	}
}

func (c *Controller) updateService(oldObj, obj interface{}) {
	oldSvc := oldObj.(*corev1.Service)
	svc := obj.(*corev1.Service)

	if slices.Equal(oldSvc.Spec.ClusterIPs, svc.Spec.ClusterIPs) &&
		slices.Equal(oldSvc.Spec.ExternalIPs, svc.Spec.ExternalIPs) &&
		slices.Equal(getIngressIPs(oldSvc), getIngressIPs(svc)) &&
		oldSvc.Spec.ExternalTrafficPolicy == svc.Spec.ExternalTrafficPolicy &&
		reflect.DeepEqual(oldSvc.Spec.InternalTrafficPolicy, svc.Spec.InternalTrafficPolicy) {
		return
	}
	oldAffectedBPs := c.filterAffectedBPsByService(oldSvc)
	newAffectedBPs := c.filterAffectedBPsByService(svc)
	if len(utilipset.MergeString(oldAffectedBPs, newAffectedBPs)) != 0 {
		klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(svc))
		c.queue.Add(key)
	}
}

func (c *Controller) addEndpointSlice(obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	if svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster &&
		(svc.Spec.InternalTrafficPolicy == nil || *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyCluster) {
		return
	}
	if c.hasAffectedBPsByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice ADD event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(key)
	}
}

func (c *Controller) updateEndpointSlice(oldObj, obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	if svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster &&
		(svc.Spec.InternalTrafficPolicy == nil || *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyCluster) {
		return
	}
	affectedBPs := c.filterAffectedBPsByService(svc)
	if len(affectedBPs) != 0 {
		klog.V(2).InfoS("Processing EndpointSlice UPDATE event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(key)
	}
}

func (c *Controller) deleteService(obj interface{}) {
	svc := obj.(*corev1.Service)
	affectedBPs := c.filterAffectedBPsByService(svc)
	if len(affectedBPs) != 0 {
		klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(svc))
		c.queue.Add(key)
	}
}

func (c *Controller) hasAffectedBPsByEgress() bool {
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if !c.matchedCurrentNode(bp) {
			continue
		}
		if bp.Spec.Advertisements.Egress != nil {
			return true
		}
	}
	return false
}

func (c *Controller) addEgress(obj interface{}) {
	if !c.egressEnabled {
		return
	}
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedBPsByEgress() {
		klog.V(2).InfoS("Processing Egress ADD event", "Egress", klog.KObj(eg))
		c.queue.Add(key)
	}
}

func (c *Controller) updateEgress(oldObj, obj interface{}) {
	if !c.egressEnabled {
		return
	}
	oldEg := oldObj.(*v1beta1.Egress)
	eg := obj.(*v1beta1.Egress)
	if oldEg.Status.EgressNode != c.nodeName && eg.Status.EgressNode != c.nodeName {
		return
	}
	if oldEg.Status.EgressIP == eg.Status.EgressIP {
		return
	}
	if c.hasAffectedBPsByEgress() {
		klog.V(2).InfoS("Processing Egress UPDATE event", "Egress", klog.KObj(eg))
		c.queue.Add(key)
	}
}

func (c *Controller) deleteEgress(obj interface{}) {
	if !c.egressEnabled {
		return
	}
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedBPsByEgress() {
		klog.V(2).InfoS("Processing Egress DELETE event", "Service", klog.KObj(eg))
		c.queue.Add(key)
	}
}

func (c *Controller) filterAffectedBPsByNode(node *corev1.Node) sets.Set[string] {
	affectedBPs := sets.New[string]()
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if c.matchedNode(node, bp) {
			affectedBPs.Insert(bp.GetName())
		}
	}
	return affectedBPs
}

func (c *Controller) updateNode(oldObj, obj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := obj.(*corev1.Node)
	if node.GetName() != c.nodeName {
		return
	}
	if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) &&
		reflect.DeepEqual(node.GetAnnotations(), oldNode.GetAnnotations()) {
		return
	}
	oldAffectedBPs := c.filterAffectedBPsByNode(oldNode)
	newAffectedBPs := c.filterAffectedBPsByNode(node)
	affectedBPs := utilipset.SymmetricDifferenceString(oldAffectedBPs, newAffectedBPs)
	if len(affectedBPs) != 0 {
		klog.V(2).InfoS("Processing Node UPDATE event", "Node", klog.KObj(node))
		c.queue.Add(key)
	}
}
