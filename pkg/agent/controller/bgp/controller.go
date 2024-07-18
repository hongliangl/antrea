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
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
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
	"antrea.io/antrea/pkg/util/env"
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

const dummyKey = "dummyKey"

type bgpPolicyState struct {
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
	egressEnabled bool,
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
		egressEnabled:             egressEnabled,
		newBGPServerFn: func(globalConfig *bgp.GlobalConfig) bgp.Interface {
			return gobgp.NewGoBGPServer(globalConfig)
		},
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "bgpPolicy"),
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
			DeleteFunc: c.deleteEndpointSlice,
		},
		resyncPeriod,
	)
	if c.egressEnabled {
		c.egressInformer = egressInformer.Informer()
		c.egressLister = egressInformer.Lister()
		c.egressListerSynced = egressInformer.Informer().HasSynced
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

// watchSecretChanges uses watch API directly to watch for the changes of the Secret storing passwords of BGP
// peers.
func (c *Controller) watchSecretChanges(stopCh <-chan struct{}) error {
	secretMeta := &metav1.ObjectMeta{
		Name:      types.BGPPolicySecretName,
		Namespace: env.GetAntreaNamespace(),
	}
	watcher, err := c.k8sClient.CoreV1().Secrets(secretMeta.Namespace).Watch(context.TODO(), metav1.SingleObject(*secretMeta))
	if err != nil {
		return fmt.Errorf("failed to create Secret watcher: %v", err)
	}

	ch := watcher.ResultChan()
	defer watcher.Stop()
	klog.InfoS("Starting watching Secret changes", "Secret", klog.KObj(secretMeta))
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return nil
			}
			// Update BGP peer passwords.
			klog.InfoS("Processing Secret event", "Secret", klog.KObj(secretMeta))

			switch event.Type {
			case watch.Added, watch.Modified:
				klog.V(2).InfoS("Secret added or modified", "Secret", klog.KObj(secretMeta))
				func() {
					c.bgpPeerPasswordsMutex.Lock()
					defer c.bgpPeerPasswordsMutex.Unlock()

					secretObj := event.Object.(*corev1.Secret)
					c.bgpPeerPasswords = make(map[string]string)
					for k, v := range secretObj.Data {
						c.bgpPeerPasswords[k] = string(v)
					}
				}()
				c.queue.Add(dummyKey)
			case watch.Deleted:
				klog.V(2).InfoS("Secret deleted", "Secret", klog.KObj(secretMeta))
				func() {
					c.bgpPeerPasswordsMutex.Lock()
					defer c.bgpPeerPasswordsMutex.Unlock()

					// Clear the passwords since the Secret is deleted
					c.bgpPeerPasswords = make(map[string]string)
				}()
				c.queue.Add(dummyKey)
			case watch.Bookmark:
				klog.V(2).InfoS("Received a bookmark event", "Secret", klog.KObj(secretMeta))
			case watch.Error:
				klog.V(2).InfoS("Received an error event", "Secret", klog.KObj(secretMeta))
			}
		case <-stopCh:
			return nil
		}
	}
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	cacheSyncs := []cache.InformerSynced{
		c.nodeListerSynced,
		c.serviceListerSynced,
		c.bgpPolicyListerSynced,
		c.endpointSliceListerSynced,
	}
	if c.egressEnabled {
		cacheSyncs = append(cacheSyncs, c.egressListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
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
	_, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dummyKey)

	if err := c.syncBGPPolicy(); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until another change happens.
		c.queue.Forget(dummyKey)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(dummyKey)
		klog.ErrorS(err, "Syncing BGPPolicy failed, requeue")
	}
	return true
}

func (c *Controller) getBGPPolicy() *v1alpha1.BGPPolicy {
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	var oldestBP *v1alpha1.BGPPolicy
	for _, bp := range allBPs {
		if c.matchedCurrentNode(bp) {
			if oldestBP == nil || bp.CreationTimestamp.Before(&oldestBP.CreationTimestamp) {
				oldestBP = bp
			}
		}
	}
	return oldestBP
}

func (c *Controller) syncBGPPolicy() error {
	startTime := time.Now()
	defer func() {
		klog.InfoS("Finished syncing BGPPolicy", "durationTime", time.Since(startTime))
	}()

	// Get the oldest BGPPolicy applied to the current Node as the effective BGPPolicy.
	effectiveBP := c.getBGPPolicy()

	// When the effective BGPPolicy is nil, it means that there is no available BGPPolicy.
	if effectiveBP == nil {
		// If the BGPPolicy state is nil, just return.
		if c.bgpPolicyState == nil {
			return nil
		}

		// If the BGPPolicy state is not nil, stop the BGP server and reset the state to nil, then return.
		if err := c.bgpPolicyState.bgpServer.Stop(c.ctx); err != nil {
			return err
		}
		c.bgpPolicyState = nil
		return nil
	}

	klog.V(2).InfoS("Syncing BGPPolicy", "BGPPolicy", effectiveBP)
	// Retrieve the listen port, local AS number and router ID from the effective BGPPolicy, and update them to the
	// current state.
	routerID, err := c.getRouterID()
	if err != nil {
		return err
	}
	var listenPort int32
	if effectiveBP.Spec.ListenPort != nil {
		listenPort = *effectiveBP.Spec.ListenPort
	} else {
		listenPort = defaultBGPListenPort
	}
	localASN := effectiveBP.Spec.LocalASN

	// If the BGPPolicy state is nil, a new BGP server should be started, initialize the BGPPolicy state to store the
	// latest BGP server instance, the listen port, the local ASN, and the router ID.
	// If the BGPPolicy is not nil, any of the listen port, local AS number, or router ID have changed, stop the stale
	// BGP server first and reset the stale BGPPolicy state to nil, then start a new BGP server and initialize the
	// BGPPolicy state to store the latest BGP server instance, the listen port, the local ASN, and the router ID.
	needUpdateBGPServer := c.bgpPolicyState == nil ||
		c.bgpPolicyState.listenPort != listenPort ||
		c.bgpPolicyState.localASN != localASN ||
		c.bgpPolicyState.routerID != routerID

	if needUpdateBGPServer {
		if c.bgpPolicyState != nil {
			// Stop the stale BGP server.
			if err := c.bgpPolicyState.bgpServer.Stop(c.ctx); err != nil {
				return fmt.Errorf("failed to stop stale BGP server: %w", err)
			}
			// Reset the BGPPolicy state to nil.
			c.bgpPolicyState = nil
		}

		// Create a new BGP server.
		bgpServer := c.newBGPServerFn(&bgp.GlobalConfig{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: listenPort,
		})

		// Start the new BGP server.
		if err := bgpServer.Start(c.ctx); err != nil {
			return fmt.Errorf("failed to start BGP server: %w", err)
		}

		// Initialize the BGPPolicy state to store the latest BGP server, the listen port, the local ASN, and the router ID.
		c.bgpPolicyState = &bgpPolicyState{
			bgpServer:   bgpServer,
			routerID:    routerID,
			listenPort:  listenPort,
			localASN:    localASN,
			routes:      make(sets.Set[bgp.Route]),
			peerConfigs: make(map[string]bgp.PeerConfig),
		}
	}

	// Reconcile BGP peers.
	if err := c.reconcileBGPPeers(effectiveBP.Spec.BGPPeers); err != nil {
		return err
	}

	// Reconcile BGP advertisements.
	if err := c.reconcileBGPAdvertisements(effectiveBP.Spec.Advertisements); err != nil {
		return err
	}

	return nil
}

func (c *Controller) reconcileBGPPeers(bgpPeers []v1alpha1.BGPPeer) error {
	curPeerConfigs := c.getPeerConfigs(bgpPeers)
	prePeerConfigs := c.bgpPolicyState.peerConfigs
	prePeerKeys := sets.KeySet(prePeerConfigs)
	curPeerKeys := sets.KeySet(curPeerConfigs)

	peerToAddKeys := curPeerKeys.Difference(prePeerKeys)
	peerToUpdateKeys := sets.New[string]()
	for peerKey := range prePeerKeys.Intersection(curPeerKeys) {
		prevPeerConfig := prePeerConfigs[peerKey]
		curPeerConfig := curPeerConfigs[peerKey]
		if !reflect.DeepEqual(prevPeerConfig, curPeerConfig) {
			peerToUpdateKeys.Insert(peerKey)
		}
	}
	peerToDeleteKeys := prePeerKeys.Difference(curPeerKeys)

	bgpServer := c.bgpPolicyState.bgpServer
	for key := range peerToAddKeys {
		peerConfig := curPeerConfigs[key]
		if err := bgpServer.AddPeer(c.ctx, peerConfig); err != nil {
			return err
		}
		c.bgpPolicyState.peerConfigs[key] = peerConfig
	}
	for key := range peerToUpdateKeys {
		peerConfig := curPeerConfigs[key]
		if err := bgpServer.UpdatePeer(c.ctx, peerConfig); err != nil {
			return err
		}
		c.bgpPolicyState.peerConfigs[key] = peerConfig
	}
	for key := range peerToDeleteKeys {
		peerConfig := prePeerConfigs[key]
		if err := bgpServer.RemovePeer(c.ctx, peerConfig); err != nil {
			return err
		}
		delete(c.bgpPolicyState.peerConfigs, key)
	}

	return nil
}

func (c *Controller) reconcileBGPAdvertisements(bgpAdvertisements v1alpha1.Advertisements) error {
	curRoutes, err := c.getRoutes(bgpAdvertisements)
	if err != nil {
		return err
	}
	preRoutes := c.bgpPolicyState.routes
	routesToAdvertise := curRoutes.Difference(preRoutes)
	routesToWithdraw := preRoutes.Difference(curRoutes)

	bgpServer := c.bgpPolicyState.bgpServer
	for route := range routesToAdvertise {
		if err := bgpServer.AdvertiseRoutes(c.ctx, []bgp.Route{route}); err != nil {
			return err
		}
		c.bgpPolicyState.routes.Insert(route)
	}
	for route := range routesToWithdraw {
		if err := bgpServer.WithdrawRoutes(c.ctx, []bgp.Route{route}); err != nil {
			return err
		}
		c.bgpPolicyState.routes.Delete(route)
	}

	return nil
}

func hashNodeNameToIP(s string) string {
	h := fnv.New32a() // Create a new FNV hash
	h.Write([]byte(s))
	hashValue := h.Sum32() // Get the 32-bit hash

	// Convert the hash to a 4-byte slice
	ip := make(net.IP, 4)
	ip[0] = byte(hashValue >> 24)
	ip[1] = byte(hashValue >> 16)
	ip[2] = byte(hashValue >> 8)
	ip[3] = byte(hashValue)

	return ip.String()
}

func (c *Controller) getRouterID() (string, error) {
	// According to RFC 4271:
	// BGP Identifier:
	//   This 4-octet unsigned integer indicates the BGP Identifier of
	//   the sender.  A given BGP speaker sets the value of its BGP
	//   Identifier to an IP address that is assigned to that BGP
	//   speaker.  The value of the BGP Identifier is determined upon
	//   startup and is the same for every local interface and BGP peer.
	//
	// In goBGP, only an IPv4 address can be used as the BGP Identifier (BGP router ID).
	// For IPv4-only or dual-stack Kubernetes clusters, the Node's IPv4 address is used as the BGP router ID, ensuring
	// uniqueness.
	// For IPv6-only Kubernetes clusters without a Node IPv4 address, the router ID could be specified in the Node
	// annotation `node.antrea.io/bgp-router-id`. If the annotation is not present, an IPv4 address will be generated by
	// hashing the Node name and updated to the Node annotation `node.antrea.io/bgp-router-id`. If the annotation is
	// present, its value will be used as the BGP router ID.

	if c.enabledIPv4 {
		return c.nodeIPv4Addr, nil
	}

	nodeObj, err := c.nodeLister.Get(c.nodeName)
	if err != nil {
		return "", fmt.Errorf("failed to get Node object: %w", err)
	}

	var exists bool
	var routerID string
	routerID, exists = nodeObj.GetAnnotations()[types.NodeBGPRouterIDAnnotationKey]
	if !exists {
		routerID = hashNodeNameToIP(c.nodeName)
		patch, _ := json.Marshal(map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]string{
					types.NodeBGPRouterIDAnnotationKey: routerID,
				},
			},
		})
		if _, err := c.k8sClient.CoreV1().Nodes().Patch(context.TODO(), c.nodeName, apitypes.MergePatchType, patch, metav1.PatchOptions{}, "status"); err != nil {
			return "", fmt.Errorf("failed to patch BGP router ID to Node annotation %s: %w", types.NodeBGPRouterIDAnnotationKey, err)
		}
	} else if !utilnet.IsIPv4String(routerID) {
		return "", fmt.Errorf("BGP router ID should be an IPv4 address string")
	}
	return routerID, nil
}

func (c *Controller) getRoutes(advertisements v1alpha1.Advertisements) (sets.Set[bgp.Route], error) {
	allRoutes := sets.New[bgp.Route]()

	if advertisements.Service != nil {
		c.addServiceRoutes(advertisements.Service, allRoutes)
	}
	if c.egressEnabled && advertisements.Egress != nil {
		c.addEgressRoutes(allRoutes)
	}
	if advertisements.Pod != nil {
		c.addPodRoutes(allRoutes)
	}

	return allRoutes, nil
}

func (c *Controller) addServiceRoutes(advertisement *v1alpha1.ServiceAdvertisement, allRoutes sets.Set[bgp.Route]) {
	ipTypes := sets.New(advertisement.IPTypes...)
	services, _ := c.serviceLister.List(labels.Everything())

	var serviceIPs []string
	for _, svc := range services {
		internalLocal := svc.Spec.InternalTrafficPolicy != nil && *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyLocal
		externalLocal := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal
		var hasLocalEndpoints bool
		if internalLocal || externalLocal {
			hasLocalEndpoints = c.hasLocalEndpoints(svc)
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeClusterIP) {
			if internalLocal && hasLocalEndpoints || !internalLocal {
				for _, clusterIP := range svc.Spec.ClusterIPs {
					serviceIPs = append(serviceIPs, clusterIP)
				}
			}
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeExternalIP) {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				for _, externalIP := range svc.Spec.ExternalIPs {
					serviceIPs = append(serviceIPs, externalIP)
				}
			}
		}
		if ipTypes.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
			if externalLocal && hasLocalEndpoints || !externalLocal {
				serviceIPs = append(serviceIPs, getIngressIPs(svc)...)
			}
		}
	}

	for _, ip := range serviceIPs {
		if c.enabledIPv4 && utilnet.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && utilnet.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}
}

func (c *Controller) addEgressRoutes(allRoutes sets.Set[bgp.Route]) {
	egresses, _ := c.egressLister.List(labels.Everything())
	for _, eg := range egresses {
		if eg.Status.EgressNode != c.nodeName {
			continue
		}
		ip := eg.Status.EgressIP
		if c.enabledIPv4 && utilnet.IsIPv4String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv4Suffix})
		}
		if c.enabledIPv6 && utilnet.IsIPv6String(ip) {
			allRoutes.Insert(bgp.Route{Prefix: ip + ipv6Suffix})
		}
	}
}

func (c *Controller) addPodRoutes(allRoutes sets.Set[bgp.Route]) {
	if c.enabledIPv4 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv4CIDR})
	}
	if c.enabledIPv6 {
		allRoutes.Insert(bgp.Route{Prefix: c.podIPv6CIDR})
	}
}

func (c *Controller) hasLocalEndpoints(svc *corev1.Service) bool {
	labelSelector := labels.Set{discovery.LabelServiceName: svc.GetName()}.AsSelector()
	items, _ := c.endpointSliceLister.EndpointSlices(svc.GetNamespace()).List(labelSelector)
	for _, eps := range items {
		for _, ep := range eps.Endpoints {
			if ep.NodeName != nil && *ep.NodeName == c.nodeName {
				return true
			}
		}
	}
	return false
}

func (c *Controller) getPeerConfigs(peers []v1alpha1.BGPPeer) map[string]bgp.PeerConfig {
	c.bgpPeerPasswordsMutex.RLock()
	defer c.bgpPeerPasswordsMutex.RUnlock()

	peerConfigs := make(map[string]bgp.PeerConfig)
	for i := range peers {
		if c.enabledIPv4 && utilnet.IsIPv4String(peers[i].Address) ||
			c.enabledIPv6 && utilnet.IsIPv6String(peers[i].Address) {
			peerKey := generateBGPPeerKey(peers[i].Address, peers[i].ASN)

			var password string
			if p, exists := c.bgpPeerPasswords[peerKey]; exists {
				password = p
			}

			peerConfigs[peerKey] = bgp.PeerConfig{
				BGPPeer:  &peers[i],
				Password: password,
			}
		}
	}
	return peerConfigs
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
	c.queue.Add(dummyKey)
}

func (c *Controller) updateBGPPolicy(oldObj, obj interface{}) {
	oldBP := oldObj.(*v1alpha1.BGPPolicy)
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) && !c.matchedCurrentNode(oldBP) {
		return
	}
	if bp.GetGeneration() != oldBP.GetGeneration() {
		klog.V(2).InfoS("Processing BGPPolicy UPDATE event", "BGPPolicy", klog.KObj(bp))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteBGPPolicy(obj interface{}) {
	bp := obj.(*v1alpha1.BGPPolicy)
	if !c.matchedCurrentNode(bp) {
		return
	}
	klog.V(2).InfoS("Processing BGPPolicy DELETE event", "BGPPolicy", klog.KObj(bp))
	c.queue.Add(dummyKey)
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
	node, _ := c.nodeLister.Get(c.nodeName)
	return matchedNode(node, bp)
}

func matchedNode(node *corev1.Node, bp *v1alpha1.BGPPolicy) bool {
	nodeSelector, _ := metav1.LabelSelectorAsSelector(&bp.Spec.NodeSelector)
	return nodeSelector.Matches(labels.Set(node.Labels))
}

func matchedService(svc *corev1.Service, bp *v1alpha1.BGPPolicy) bool {
	ipTypeMap := sets.New(bp.Spec.Advertisements.Service.IPTypes...)
	if ipTypeMap.Has(v1alpha1.ServiceIPTypeClusterIP) && len(svc.Spec.ClusterIPs) != 0 ||
		ipTypeMap.Has(v1alpha1.ServiceIPTypeExternalIP) && len(svc.Spec.ExternalIPs) != 0 ||
		ipTypeMap.Has(v1alpha1.ServiceIPTypeLoadBalancerIP) && len(getIngressIPs(svc)) != 0 {
		return true
	}
	return false
}

func (c *Controller) hasAffectedBPByService(svc *corev1.Service) bool {
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if bp.Spec.Advertisements.Service == nil || !c.matchedCurrentNode(bp) {
			continue
		}
		if matchedService(svc, bp) {
			return true
		}
	}
	return false
}

func (c *Controller) addService(obj interface{}) {
	svc := obj.(*corev1.Service)
	if c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing Service ADD event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
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
	if c.hasAffectedBPByService(oldSvc) || c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing Service UPDATE event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteService(obj interface{}) {
	svc := obj.(*corev1.Service)
	if c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing Service DELETE event", "Service", klog.KObj(svc))
		c.queue.Add(dummyKey)
	}
}

func noLocalTrafficPolicy(svc *corev1.Service) bool {
	internalTrafficCluster := svc.Spec.InternalTrafficPolicy == nil || *svc.Spec.InternalTrafficPolicy == corev1.ServiceInternalTrafficPolicyCluster
	if svc.Spec.Type == corev1.ServiceTypeClusterIP {
		return internalTrafficCluster
	}
	externalTrafficCluster := svc.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeCluster
	return internalTrafficCluster && externalTrafficCluster
}

func (c *Controller) addEndpointSlice(obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events for EndpointSlices dedicated to Services without a `Local` traffic policy are ignored, as the Service IPs
	// will always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice ADD event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) updateEndpointSlice(_, obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events for EndpointSlices dedicated to Services without a `Local` traffic policy are ignored, as the Service IPs
	// will always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice UPDATE event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteEndpointSlice(obj interface{}) {
	eps := obj.(*discovery.EndpointSlice)
	svc, _ := c.serviceLister.Services(eps.GetNamespace()).Get(eps.GetLabels()[discovery.LabelServiceName])
	if svc == nil {
		return
	}
	// Events for EndpointSlices dedicated to Services without a `Local` traffic policy are ignored, as the Service IPs
	// will always be advertised.
	if noLocalTrafficPolicy(svc) {
		return
	}
	if c.hasAffectedBPByService(svc) {
		klog.V(2).InfoS("Processing EndpointSlice DELETE event", "EndpointSlice", klog.KObj(eps))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) hasAffectedBPByEgress() bool {
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
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedBPByEgress() {
		klog.V(2).InfoS("Processing Egress ADD event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) updateEgress(oldObj, obj interface{}) {
	oldEg := oldObj.(*v1beta1.Egress)
	eg := obj.(*v1beta1.Egress)
	if oldEg.Status.EgressNode != c.nodeName && eg.Status.EgressNode != c.nodeName {
		return
	}
	if oldEg.Status.EgressIP == eg.Status.EgressIP {
		return
	}
	if c.hasAffectedBPByEgress() {
		klog.V(2).InfoS("Processing Egress UPDATE event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) deleteEgress(obj interface{}) {
	eg := obj.(*v1beta1.Egress)
	if eg.Status.EgressNode != c.nodeName {
		return
	}
	if c.hasAffectedBPByEgress() {
		klog.V(2).InfoS("Processing Egress DELETE event", "Egress", klog.KObj(eg))
		c.queue.Add(dummyKey)
	}
}

func (c *Controller) hasAffectedBPByNode(node *corev1.Node) bool {
	allBPs, _ := c.bgpPolicyLister.List(labels.Everything())
	for _, bp := range allBPs {
		if matchedNode(node, bp) {
			return true
		}
	}
	return false
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
	if c.hasAffectedBPByNode(oldNode) || c.hasAffectedBPByNode(node) {
		klog.V(2).InfoS("Processing Node UPDATE event", "Node", klog.KObj(node))
		c.queue.Add(dummyKey)
	}
}
